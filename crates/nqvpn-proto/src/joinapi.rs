//! Member-side join client (§3.2). Deliberately dependency-free: a
//! blocking HTTP/1.1 POST, since join happens at startup and at renewal,
//! never on a hot path.
//!
//! v1 talks plain HTTP and expects the coordinator to sit behind a TLS
//! terminator; the `https://` scheme is accepted and stripped so configs
//! don't have to change when native TLS lands.

use crate::api::{ErrorBody, JoinRequest, JoinResponse};
use crate::errors::ErrorCode;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("cannot resolve {0}")]
    Resolve(String),
    #[error("malformed HTTP response")]
    Malformed,
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The coordinator rejected the join with a structured error. The
    /// code alone decides what happens next (see `ErrorCode`).
    #[error("{code}: {message} ({})", code.hint())]
    Rejected { status: u16, code: ErrorCode, message: String },
}

impl JoinError {
    /// Retrying will never help: stop and tell the operator (§9 startup).
    /// The decision lives on `ErrorCode` so server and members cannot
    /// disagree about which failures are fatal.
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

pub fn strip_scheme(url: &str) -> &str {
    url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url)
        .trim_end_matches('/')
}

pub fn join(api: &str, req: &JoinRequest) -> Result<JoinResponse, JoinError> {
    let host_port = strip_scheme(api);
    let body = serde_json::to_string(req)?;
    let addr: SocketAddr = host_port
        .to_socket_addrs()
        .map_err(|_| JoinError::Resolve(host_port.to_string()))?
        .next()
        .ok_or_else(|| JoinError::Resolve(host_port.to_string()))?;
    let mut sock = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    sock.set_read_timeout(Some(Duration::from_secs(20)))?;
    let host = host_port.rsplit_once(':').map(|(h, _)| h).unwrap_or(host_port);
    let request = format!(
        "POST /api/v1/join HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    sock.write_all(request.as_bytes())?;
    let mut raw = Vec::new();
    sock.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, payload) = text.split_once("\r\n\r\n").ok_or(JoinError::Malformed)?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(JoinError::Malformed)?;
    if status != 200 {
        let (code, message) = match serde_json::from_str::<ErrorBody>(payload) {
            Ok(e) => (ErrorCode::parse(&e.error.code), e.error.message),
            Err(_) => (
                ErrorCode::Unknown(format!("http_{status}")),
                payload.trim().to_string(),
            ),
        };
        return Err(JoinError::Rejected { status, code, message });
    }
    Ok(serde_json::from_str(payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_stripping() {
        assert_eq!(strip_scheme("https://coord.example:8443/"), "coord.example:8443");
        assert_eq!(strip_scheme("http://coord.example:8443"), "coord.example:8443");
        assert_eq!(strip_scheme("coord.example:8443"), "coord.example:8443");
    }

    #[test]
    fn terminal_codes_stop_retrying() {
        let terminal = JoinError::Rejected {
            status: 403,
            code: ErrorCode::PinMismatch,
            message: String::new(),
        };
        assert!(terminal.is_terminal());
        let retryable = JoinError::Rejected {
            status: 429,
            code: ErrorCode::RateLimited,
            message: String::new(),
        };
        assert!(!retryable.is_terminal());
        // An unreachable relay waits for the firewall rather than dying.
        let unreachable = JoinError::Rejected {
            status: 409,
            code: ErrorCode::RelayUnreachable,
            message: String::new(),
        };
        assert!(!unreachable.is_terminal());
    }
}

/// Retry schedule for a member that is already running and has lost its
/// coordinator session.
///
/// At startup, a terminal rejection should stop the process: the operator
/// is standing there, and failing loudly beats a daemon that silently
/// never works. Once running, the opposite is true. Every terminal
/// condition here — a pin an admin must reset, a disabled member, a
/// changed secret — is fixed *at the coordinator*, and the member has no
/// way to know it happened except by asking again. Exiting means a human
/// must notice and restart something on every affected machine, which is
/// the failure mode this schedule exists to remove.
///
/// Transient failures back off quickly; terminal ones back off to a slow
/// poll and keep going, so the member heals itself the moment the
/// operator acts.
pub fn retry_delay(terminal: bool, consecutive: u32) -> std::time::Duration {
    use std::time::Duration;
    if terminal {
        // Slow, but not so slow that a fixed pin takes an hour to take
        // effect. Constant rather than exponential: the condition is not
        // load-related, so backing off further buys nothing.
        return Duration::from_secs(60);
    }
    let secs = 1u64 << consecutive.min(5); // 1,2,4,8,16,32
    Duration::from_secs(secs.min(30))
}

#[cfg(test)]
mod retry_tests {
    use super::*;

    #[test]
    fn a_terminal_condition_keeps_retrying_slowly() {
        // The point: never give up. A pin reset or a re-enable happens at
        // the coordinator, and the member only learns of it by asking.
        let d = retry_delay(true, 0);
        assert_eq!(d, std::time::Duration::from_secs(60));
        // ...and it does not creep upward, because the condition is not
        // load-related; an hour-long backoff would just delay recovery.
        assert_eq!(retry_delay(true, 50), d);
    }

    #[test]
    fn transient_failures_back_off_but_are_capped() {
        let d = |n| retry_delay(false, n).as_secs();
        assert_eq!(d(0), 1);
        assert_eq!(d(1), 2);
        assert_eq!(d(3), 8);
        // Capped, so a long outage does not turn into a ten-minute wait
        // after the coordinator comes back.
        assert_eq!(d(10), 30);
        assert_eq!(d(u32::MAX), 30);
    }
}
