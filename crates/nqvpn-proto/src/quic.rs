//! QUIC/TLS plumbing shared by coordinator, relay, and client.
//!
//! Trust model (§3.3): certificates are self-signed and there is no PKI.
//! The TLS layer therefore accepts any well-formed peer certificate — it
//! only proves possession of the corresponding private key — and the
//! *application* compares the certificate's SHA-256 fingerprint against
//! the `cert_fp` in the coordinator-signed credential. That comparison is
//! the actual authentication step; see `peer_fingerprint`.

use std::sync::Arc;
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};

use crate::identity::{fingerprint_der, TlsIdentity};

#[derive(Debug, thiserror::Error)]
pub enum TlsSetupError {
    #[error("rustls: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("quic crypto: {0}")]
    Quic(String),
}

pub const ALPN: &[u8] = b"nqvpn/1";

/// Bytes a sealed packet adds on top of the inner IP packet:
/// routed header (15) + Noise counter (8) + AEAD tag (16).
///
/// Deliberately exact rather than padded. The usable tunnel MTU is
/// derived from this at runtime (`usable_inner_mtu`), so if the wire
/// format grows the MTU shrinks automatically — and the assertion below
/// fails the build rather than letting a stale constant silently cost
/// packets. A safety margin here would buy nothing and hide drift.
pub const FRAME_OVERHEAD: usize = 39;

// Breaks the build if the wire format and this constant disagree —
// stronger than a test, since it holds even for `cargo build`.
const _: () = assert!(
    FRAME_OVERHEAD == crate::frame::ROUTED_HEADER_LEN + 8 + 16,
    "FRAME_OVERHEAD is out of step with the frame layout; \
     update it (and re-check INITIAL_MTU) when the header changes"
);

/// What we assume the path can carry before discovery proves otherwise.
///
/// quinn defaults to 1200, which is *smaller than our own frames*: a
/// 1350-byte inner packet becomes a 1383-byte datagram, so every large
/// packet is rejected until DPLPMTUD ratchets up — seconds of loss on a
/// long path, at exactly the moment a tunnel comes up.
///
/// The arithmetic, for a 1350-byte tunnel MTU:
///   1350 inner + 33 frame overhead + 48 QUIC header/AEAD = 1431 UDP
///   payload, which on the wire is 1431 + 8 (UDP) + 40 (IPv6) = 1479,
///   inside a standard 1500-byte path.
/// 1440 covers that with slack and still fits Ethernet in both address
/// families; discovery corrects *downwards* if the real path is smaller.
pub const INITIAL_MTU: u16 = 1440;

/// Worst-case QUIC per-packet overhead (header + AEAD tag).
pub const QUIC_OVERHEAD: usize = 48;

/// Never probe below this: the QUIC-mandated floor.
pub const MIN_MTU: u16 = 1200;

/// Largest inner packet this connection can carry right now, or `None`
/// if the peer does not support datagrams. Compare against the tunnel
/// MTU to catch a path that cannot carry what we configured.
pub fn usable_inner_mtu(conn: &quinn::Connection) -> Option<usize> {
    conn.max_datagram_size()
        .map(|max| max.saturating_sub(FRAME_OVERHEAD))
}

/// Accepts any syntactically valid client certificate. Authentication is
/// the app layer's job (credential `cert_fp` vs. `peer_fingerprint`).
#[derive(Debug)]
struct AnyClientCert {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for AnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
    fn offer_client_auth(&self) -> bool {
        true
    }
    fn client_auth_mandatory(&self) -> bool {
        true
    }
}

/// Verifies the server by fingerprint when one is known (relay dials,
/// where the coordinator published what that relay presents), otherwise
/// accepts any certificate — the coordinator's control port, where the
/// credential exchange authenticates in both directions, and the join
/// API when `trust_any_cert` is set.
#[derive(Debug)]
pub struct PinnedServerCert {
    pub expected_fp: Option<String>,
    pub supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match &self.expected_fp {
            None => Ok(ServerCertVerified::assertion()),
            Some(want) => {
                let got = fingerprint_der(end_entity);
                if &got == want {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!(
                        "server certificate fingerprint mismatch: expected {want}, got {got}"
                    )))
                }
            }
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

pub fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport(keepalive_secs: u64) -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(keepalive_secs)));
    // Idle timeout comfortably above 3 keepalives so liveness is decided
    // by the coordinator's counter, not by the transport racing it.
    t.max_idle_timeout(Some(
        Duration::from_secs(keepalive_secs * 5)
            .try_into()
            .expect("idle timeout in range"),
    ));
    t.datagram_receive_buffer_size(Some(1024 * 1024));
    t.datagram_send_buffer_size(1024 * 1024);
    // Stream mode opens one unidirectional stream per lane. The limit is
    // the receiver's to set, and a sender that exceeds it blocks rather
    // than failing loudly, so allow comfortably more than MAX_LANES and
    // keep the "receiver accepts whatever arrives" property true.
    t.max_concurrent_uni_streams((crate::transport::MAX_LANES as u32 * 2).into());
    // Start where our frames actually fit; discovery corrects downward
    // if the path is smaller, and black-hole detection recovers if a
    // middlebox silently eats the bigger packets.
    t.initial_mtu(INITIAL_MTU);
    t.min_mtu(MIN_MTU);
    Arc::new(t)
}

pub fn server_config(
    id: &TlsIdentity,
    keepalive_secs: u64,
) -> Result<quinn::ServerConfig, TlsSetupError> {
    let p = provider();
    let verifier = Arc::new(AnyClientCert { supported: p.signature_verification_algorithms });
    let mut tls = rustls::ServerConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(id.cert_chain(), id.private_key())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls).map_err(|e| TlsSetupError::Quic(e.to_string()))?));
    cfg.transport_config(transport(keepalive_secs));
    Ok(cfg)
}

pub fn client_config(
    id: &TlsIdentity,
    expected_server_fp: Option<String>,
    keepalive_secs: u64,
) -> Result<quinn::ClientConfig, TlsSetupError> {
    let p = provider();
    let verifier =
        Arc::new(PinnedServerCert { expected_fp: expected_server_fp, supported: p.signature_verification_algorithms });
    let mut tls = rustls::ClientConfig::builder_with_provider(p)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(id.cert_chain(), id.private_key())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls).map_err(|e| TlsSetupError::Quic(e.to_string()))?));
    cfg.transport_config(transport(keepalive_secs));
    Ok(cfg)
}

/// SHA-256 fingerprint of the peer's end-entity certificate — the value
/// that must equal the credential's `cert_fp` (§3.3 possession proof).
pub fn peer_fingerprint(conn: &quinn::Connection) -> Option<String> {
    let certs = conn.peer_identity()?.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    certs.first().map(|c| fingerprint_der(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::TlsIdentity;

    /// The bug this constant exists to prevent: quinn's default
    /// `initial_mtu` of 1200 is smaller than a sealed 1350-byte packet,
    /// so every large packet is refused until discovery catches up.
    /// Two constraints have to hold at once, and getting either wrong
    /// costs silent packet loss:
    ///   * our own full-size frame must fit inside `initial_mtu`, or
    ///     large packets are refused until DPLPMTUD catches up;
    ///   * `initial_mtu` on the wire must fit a standard Ethernet path
    ///     in *both* families, or we black-hole until it corrects down.
    #[test]
    fn initial_mtu_fits_our_frames_and_a_standard_path() {
        const TUNNEL_MTU: usize = 1350;
        let needed = TUNNEL_MTU + FRAME_OVERHEAD + QUIC_OVERHEAD;
        assert!(
            needed <= INITIAL_MTU as usize,
            "initial_mtu {INITIAL_MTU} cannot carry a {TUNNEL_MTU}-byte inner packet \
             (needs {needed}); large packets would drop until discovery catches up"
        );
        // quinn's default really was too small for us — that was the bug.
        assert!(needed > 1200, "1200 default was genuinely below our frame size");

        // IPv6 is the tighter case: 40-byte header instead of 20.
        let on_wire_v6 = INITIAL_MTU as usize + 8 + 40;
        assert!(
            on_wire_v6 <= 1500,
            "initial_mtu {INITIAL_MTU} is {on_wire_v6} bytes on an IPv6 path; \
             a 1500-byte Ethernet path would black-hole it"
        );
        const { assert!(INITIAL_MTU > MIN_MTU, "discovery must be able to correct downward") };
    }

    #[test]
    fn frame_overhead_matches_the_wire_format() {
        // routed header (type 1 + src 4 + dst 4 + flags 1 + hop 1 + trace 4) + counter 8 + tag 16
        assert_eq!(FRAME_OVERHEAD, crate::frame::ROUTED_HEADER_LEN + 8 + 16);
    }

    #[tokio::test]
    async fn mutual_tls_exposes_both_fingerprints() {
        let server_id = TlsIdentity::generate("server").unwrap();
        let client_id = TlsIdentity::generate("client").unwrap();
        let (server_fp, client_fp) = (server_id.fingerprint(), client_id.fingerprint());

        let endpoint_server = quinn::Endpoint::server(
            server_config(&server_id, 5).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint_server.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            let incoming = endpoint_server.accept().await.unwrap();
            let conn = incoming.await.unwrap();
            let fp = peer_fingerprint(&conn).unwrap();
            // keep the connection alive until the client observes us
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            fp
        });

        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(client_config(&client_id, Some(server_fp.clone()), 5).unwrap());
        let conn = ep.connect(addr, "server").unwrap().await.unwrap();
        assert_eq!(peer_fingerprint(&conn).unwrap(), server_fp);
        assert_eq!(srv.await.unwrap(), client_fp);
    }

    #[tokio::test]
    async fn wrong_server_pin_is_rejected() {
        let server_id = TlsIdentity::generate("server").unwrap();
        let client_id = TlsIdentity::generate("client").unwrap();
        let other = TlsIdentity::generate("impostor").unwrap();

        let endpoint_server = quinn::Endpoint::server(
            server_config(&server_id, 5).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = endpoint_server.local_addr().unwrap();
        tokio::spawn(async move {
            if let Some(i) = endpoint_server.accept().await {
                let _ = i.await;
            }
        });

        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        ep.set_default_client_config(
            client_config(&client_id, Some(other.fingerprint()), 5).unwrap(),
        );
        assert!(ep.connect(addr, "server").unwrap().await.is_err());
    }
}
