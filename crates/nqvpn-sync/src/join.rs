//! Joining: the member's whole declaration, sent over HTTPS with its
//! node id and secret. Renewal is the same request again.

use nqvpn_proto::api::{JoinRequest, JoinResponse};
use nqvpn_proto::credential::Claims;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::joinapi::{self, JoinError, JoinTls};
use nqvpn_proto::seal::StaticKeys;
use std::sync::Arc;
use std::time::Duration;

/// Everything a machine holds to become a member: where the
/// coordinator is and its secret — the two things in its token. The
/// coordinator knows the rest (network, name, role, address, prefixes)
/// and hands it down at every join.
#[derive(Debug, Clone)]
pub struct MemberConfig {
    /// `https://host[:port]`
    pub coordinator: String,
    pub secret: String,
    pub tls: JoinTls,
}

impl MemberConfig {
    pub fn from_token(token: &nqvpn_proto::token::Token, tls: JoinTls) -> MemberConfig {
        MemberConfig { coordinator: token.coordinator.clone(), secret: token.secret.clone(), tls }
    }

    pub fn request(&self, identity: &TlsIdentity, keys: &StaticKeys) -> JoinRequest {
        JoinRequest { secret: self.secret.clone(), pubkey: keys.public_b64(), cert_fingerprint: identity.fingerprint() }
    }
}

pub fn join_once(cfg: &MemberConfig, identity: &TlsIdentity, keys: &StaticKeys) -> Result<JoinResponse, JoinError> {
    joinapi::join(&cfg.coordinator, &cfg.request(identity, keys), &cfg.tls)
}

/// Join, retrying until it succeeds or the coordinator says it never
/// will. Transient failures (unreachable, 5xx, rate limited) retry
/// tightly and forever: a member with a valid identity connects
/// eventually, as long as the coordinator comes back. A terminal
/// rejection — disabled, unknown, wrong secret — is returned: the
/// member has been kicked out and must stop trying (retrying can only
/// hammer the coordinator, or, after a replacement, fight the newer
/// instance). Blocking: call from `spawn_blocking`.
pub fn join_with_backoff(cfg: &MemberConfig, identity: &TlsIdentity, keys: &StaticKeys) -> Result<JoinResponse, JoinError> {
    let mut consecutive: u32 = 0;
    loop {
        match join_once(cfg, identity, keys) {
            Ok(r) => return Ok(r),
            Err(e) if e.is_terminal() => {
                tracing::error!("join rejected: {e} — this instance stops; fix it at the coordinator and restart");
                return Err(e);
            }
            Err(e) => {
                consecutive = consecutive.saturating_add(1);
                let wait = joinapi::retry_delay(false, consecutive);
                tracing::warn!("join failed ({e}); retrying in {wait:?}");
                std::thread::sleep(wait);
            }
        }
    }
}

/// As `join_with_backoff`, but the waits are async so the task can be
/// cancelled between attempts (a blocking sleep in a `spawn_blocking`
/// would pin the runtime's shutdown). Every attempt itself runs on the
/// blocking pool.
pub async fn join_with_backoff_async(cfg: Arc<MemberConfig>, identity: TlsIdentity, keys: StaticKeys) -> Result<JoinResponse, JoinError> {
    let mut consecutive: u32 = 0;
    loop {
        let (c, i, k) = (cfg.clone(), identity.clone(), keys.clone());
        let attempt = tokio::task::spawn_blocking(move || join_once(&c, &i, &k)).await;
        let wait = match attempt {
            Ok(Ok(r)) => return Ok(r),
            Ok(Err(e)) if e.is_terminal() => {
                tracing::error!("join rejected: {e} — this instance stops; fix it at the coordinator and restart");
                return Err(e);
            }
            Ok(Err(e)) => {
                consecutive = consecutive.saturating_add(1);
                let wait = joinapi::retry_delay(false, consecutive);
                tracing::warn!("join failed ({e}); retrying in {wait:?}");
                wait
            }
            Err(e) => {
                tracing::error!("join task failed: {e}");
                Duration::from_secs(5)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// The claims inside our own credential, decoded without verification —
/// the coordinator just signed them for us.
pub fn own_claims(credential: &str) -> Option<Claims> {
    use base64::Engine;
    let p = credential.split('.').nth(1)?;
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).ok()?;
    serde_json::from_slice(&json).ok()
}

/// When to renew: two thirds of the credential lifetime.
pub fn renew_after(credential: &str) -> Duration {
    Duration::from_secs(nqvpn_proto::credential::renew_after_secs(credential))
}
