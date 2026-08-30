//! Member-side join client (§3.2): one HTTPS POST at startup and at
//! every renewal, never on a hot path. Dependency-light on purpose — a
//! hand-written HTTP/1.1 request over a rustls stream.
//!
//! TLS is always on. By default any server certificate is accepted
//! (`trust_any_cert = true`): the coordinator generates a self-signed
//! certificate on first start, and the join is still protected against
//! passive listeners. Set `trust_any_cert = false` to verify against the
//! system roots (or a `ca` file) — the strict mode for deployments that
//! do not trust the path to the coordinator.

use crate::api::{ErrorBody, JoinRequest, JoinResponse};
use crate::errors::ErrorCode;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Largest response we will read. Join responses are a few KB.
const MAX_RESPONSE: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot resolve {0}")]
    Resolve(String),
    #[error("could not connect to any address of {0}: {1}")]
    Connect(String, String),
    #[error("coordinator URL must start with https:// (got {0:?})")]
    BadUrl(String),
    #[error("tls: {0}")]
    Tls(String),
    #[error("malformed HTTP response")]
    Malformed,
    #[error("response larger than {MAX_RESPONSE} bytes")]
    TooLarge,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The coordinator rejected the join with a structured error. The
    /// code alone decides what happens next (see `ErrorCode`).
    #[error("{code}: {message} ({})", code.hint())]
    Rejected { status: u16, code: ErrorCode, message: String },
}

impl JoinError {
    /// Retrying will never help by itself: an operator must act.
    pub fn is_terminal(&self) -> bool {
        matches!(self, JoinError::Rejected { code, .. } if code.is_terminal())
    }

    pub fn code(&self) -> Option<&ErrorCode> {
        match self {
            JoinError::Rejected { code, .. } => Some(code),
            _ => None,
        }
    }
}

/// How the member verifies the coordinator's HTTPS certificate.
#[derive(Debug, Clone)]
pub struct JoinTls {
    /// Accept any certificate. The default, so a fresh deployment works
    /// with the coordinator's auto-generated certificate.
    pub trust_any_cert: bool,
    /// Extra PEM roots to trust when verifying (self-signed coordinator
    /// certificate, private CA), as a file path. Only used when
    /// `trust_any_cert` is off.
    pub ca_pem: Option<PathBuf>,
    /// Extra PEM roots inline (the coordinator's own certificate). Only
    /// used when `trust_any_cert` is off and there is no `pinned_fp`.
    pub ca_cert: Option<String>,
    /// Coordinator certificate fingerprints to trust: the token's, plus
    /// any the operator pre-staged for a rotation. When non-empty, a
    /// certificate matching any of them is accepted with no CA file.
    pub pinned_fps: Vec<String>,
}

impl JoinTls {
    /// The extra CA / self-signed certificates to trust, from the inline
    /// PEM and the file, as DER.
    pub fn extra_ca(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
        let mut out = Vec::new();
        if let Some(pem) = &self.ca_cert {
            out.extend(crate::quic::certs_from_pem(pem.as_bytes()));
        }
        if let Some(path) = &self.ca_pem {
            let pem = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
            out.extend(crate::quic::certs_from_pem(&pem));
        }
        Ok(out)
    }
}

impl Default for JoinTls {
    fn default() -> Self {
        JoinTls { trust_any_cert: true, ca_pem: None, ca_cert: None, pinned_fps: Vec::new() }
    }
}

/// `https://host[:port][/...]` -> (host, port). Only https is accepted:
/// the secret travels in this request.
pub fn parse_url(url: &str) -> Result<(String, u16), JoinError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| JoinError::BadUrl(url.to_string()))?;
    let host_port = rest.split('/').next().unwrap_or_default();
    if host_port.is_empty() {
        return Err(JoinError::BadUrl(url.to_string()));
    }
    // `[v6]:port`, `v6`, `host:port`, `host`.
    let (host, port) = if let Some(rest) = host_port.strip_prefix('[') {
        let (h, tail) = rest.split_once(']').ok_or_else(|| JoinError::BadUrl(url.to_string()))?;
        let port = tail.strip_prefix(':').map(|p| p.parse::<u16>()).transpose()
            .map_err(|_| JoinError::BadUrl(url.to_string()))?;
        (h.to_string(), port.unwrap_or(443))
    } else if host_port.matches(':').count() == 1 {
        let (h, p) = host_port.split_once(':').expect("one colon");
        (h.to_string(), p.parse().map_err(|_| JoinError::BadUrl(url.to_string()))?)
    } else {
        // A bare hostname, or a bare IPv6 literal: default port.
        (host_port.to_string(), 443)
    };
    Ok((host, port))
}

/// The address a member dials for the QUIC control plane: the API host
/// with the port the join response announced.
pub fn control_addr(api_url: &str, control_port: u16) -> Result<String, JoinError> {
    let (host, _) = parse_url(api_url)?;
    Ok(if host.contains(':') { format!("[{host}]:{control_port}") } else { format!("{host}:{control_port}") })
}

fn tls_config(tls: &JoinTls) -> Result<Arc<rustls::ClientConfig>, JoinError> {
    let provider = crate::quic::provider();
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| JoinError::Tls(e.to_string()))?;
    // The same trust decision the QUIC control plane uses, so both
    // channels trust the coordinator identically.
    let extra = tls.extra_ca().map_err(JoinError::Tls)?;
    let verifier = crate::quic::coordinator_verifier(&tls.pinned_fps, tls.trust_any_cert, &extra).map_err(|e| JoinError::Tls(e.to_string()))?;
    let cfg = builder.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Connect to the first address of `host:port` that answers, rather
/// than only the first one resolution happens to return.
fn connect_any(host: &str, port: u16) -> Result<TcpStream, JoinError> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|_| JoinError::Resolve(format!("{host}:{port}")))?
        .collect();
    if addrs.is_empty() {
        return Err(JoinError::Resolve(format!("{host}:{port}")));
    }
    let mut last = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_secs(10)) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(JoinError::Connect(format!("{host}:{port}"), last))
}

pub fn join(api: &str, req: &JoinRequest, tls: &JoinTls) -> Result<JoinResponse, JoinError> {
    let (host, port) = parse_url(api)?;
    let body = serde_json::to_string(req)?;
    let sock = connect_any(&host, port)?;
    sock.set_read_timeout(Some(Duration::from_secs(20)))?;
    sock.set_write_timeout(Some(Duration::from_secs(20)))?;

    let server_name = rustls::pki_types::ServerName::try_from(host.clone())
        .map_err(|e| JoinError::Tls(format!("server name {host:?}: {e}")))?;
    let conn = rustls::ClientConnection::new(tls_config(tls)?, server_name)
        .map_err(|e| JoinError::Tls(e.to_string()))?;
    let mut stream = rustls::StreamOwned::new(conn, sock);

    let request = format!(
        "POST /api/v1/join HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).map_err(tls_io)?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                if raw.len() > MAX_RESPONSE {
                    return Err(JoinError::TooLarge);
                }
            }
            // rustls reports a peer that closed without close_notify as
            // an error; with Connection: close that is the normal end.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(tls_io(e)),
        }
    }
    parse_response(&raw)
}

fn tls_io(e: std::io::Error) -> JoinError {
    if e.kind() == std::io::ErrorKind::InvalidData {
        JoinError::Tls(e.to_string())
    } else {
        JoinError::Io(e)
    }
}

fn parse_response(raw: &[u8]) -> Result<JoinResponse, JoinError> {
    let text = String::from_utf8_lossy(raw);
    let (head, payload) = text.split_once("\r\n\r\n").ok_or(JoinError::Malformed)?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(JoinError::Malformed)?;
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    let payload = if chunked { dechunk(payload).ok_or(JoinError::Malformed)? } else { payload.to_string() };
    if status != 200 {
        let (code, message) = match serde_json::from_str::<ErrorBody>(&payload) {
            Ok(e) => (ErrorCode::parse(&e.error.code), e.error.message),
            Err(_) => (ErrorCode::Unknown(format!("http_{status}")), payload.trim().to_string()),
        };
        return Err(JoinError::Rejected { status, code, message });
    }
    Ok(serde_json::from_str(&payload)?)
}

/// Minimal chunked-transfer decoding, in case a proxy re-chunks the body.
fn dechunk(body: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = body;
    loop {
        let (size_line, tail) = rest.split_once("\r\n")?;
        let size = usize::from_str_radix(size_line.split(';').next()?.trim(), 16).ok()?;
        if size == 0 {
            return Some(out);
        }
        out.push_str(tail.get(..size)?);
        rest = tail.get(size + 2..)?;
    }
}

/// Retry schedule for a member that has lost its coordinator session or
/// was refused.
///
/// Terminal conditions — a disabled member, a changed secret — are fixed
/// *at the coordinator*, and the member has no way to know it happened
/// except by asking again. Exiting means a human must notice and restart
/// something on every affected machine, which is the failure mode this
/// schedule exists to remove: terminal failures poll slowly and forever,
/// transient ones back off quickly.
pub fn retry_delay(terminal: bool, consecutive: u32) -> Duration {
    if terminal {
        // Refused (disabled, deleted, token regenerated): the operator
        // may simply enable the member again, so keep asking — 1, 2,
        // 4, 8, 16 seconds, then every 30 s.
        let secs = 1u64 << consecutive.clamp(1, 16).saturating_sub(1);
        return Duration::from_secs(secs.min(30));
    }
    // Tight: a member that lost its coordinator is back within seconds
    // of the coordinator being back. 1, 2, 4, 5, 5, ...
    let secs = 1u64 << consecutive.min(3);
    Duration::from_secs(secs.min(5))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_parsing() {
        assert_eq!(parse_url("https://coord.example:8443/").unwrap(), ("coord.example".into(), 8443));
        assert_eq!(parse_url("https://coord.example").unwrap(), ("coord.example".into(), 443));
        assert_eq!(parse_url("https://10.0.0.1:18443/api").unwrap(), ("10.0.0.1".into(), 18443));
        assert_eq!(parse_url("https://[fd00::1]:9/").unwrap(), ("fd00::1".into(), 9));
        assert!(matches!(parse_url("http://coord.example:8443"), Err(JoinError::BadUrl(_))));
        assert!(matches!(parse_url("coord.example:8443"), Err(JoinError::BadUrl(_))));
        assert_eq!(control_addr("https://coord.example:8443", 14433).unwrap(), "coord.example:14433");
        assert_eq!(control_addr("https://[fd00::1]:8443", 14433).unwrap(), "[fd00::1]:14433");
    }

    #[test]
    fn terminal_codes_stop_retrying() {
        let terminal = JoinError::Rejected { status: 403, code: ErrorCode::ClientDisabled, message: String::new() };
        assert!(terminal.is_terminal());
        let retryable = JoinError::Rejected { status: 429, code: ErrorCode::RateLimited, message: String::new() };
        assert!(!retryable.is_terminal());
    }

    #[test]
    fn responses_parse_including_chunked_and_errors() {
        let body = r#"{"error":{"code":"bad_credentials","message":"nope"}}"#;
        let raw = format!("HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{body}", body.len());
        match parse_response(raw.as_bytes()) {
            Err(JoinError::Rejected { status: 401, code: ErrorCode::BadCredentials, .. }) => {}
            other => panic!("{other:?}"),
        }
        let chunked = format!(
            "HTTP/1.1 401 x\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        );
        assert!(matches!(parse_response(chunked.as_bytes()), Err(JoinError::Rejected { status: 401, .. })));
        assert!(matches!(parse_response(b"garbage"), Err(JoinError::Malformed)));
    }

    #[test]
    fn a_refusal_backs_off_exponentially_and_never_gives_up() {
        assert_eq!(retry_delay(true, 1), Duration::from_secs(1));
        assert_eq!(retry_delay(true, 2), Duration::from_secs(2));
        assert_eq!(retry_delay(true, 5), Duration::from_secs(16));
        assert_eq!(retry_delay(true, 6), Duration::from_secs(30));
        assert_eq!(retry_delay(true, u32::MAX), Duration::from_secs(30));
    }

    #[test]
    fn transient_failures_back_off_but_are_capped() {
        let d = |n| retry_delay(false, n).as_secs();
        assert_eq!(d(0), 1);
        assert_eq!(d(2), 4);
        assert_eq!(d(3), 5);
        assert_eq!(d(u32::MAX), 5);
    }

    #[test]
    fn strict_mode_builds_a_root_store() {
        assert!(tls_config(&JoinTls { trust_any_cert: false, ca_pem: None, ca_cert: None, pinned_fps: Vec::new() }).is_ok());
        assert!(tls_config(&JoinTls::default()).is_ok());
    }
}
