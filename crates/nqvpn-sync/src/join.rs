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

/// Join, retrying until it succeeds. Never returns an error.
///
/// Transient failures (unreachable, 5xx, rate limited) retry tightly:
/// a member with a valid token connects within seconds of the
/// coordinator being back. A refusal — the member is disabled or
/// deleted, or its token was regenerated — is an operator's decision
/// that can be reversed at the coordinator, so it is retried too, with
/// exponential backoff (1 s … 30 s) and one clear log line per
/// attempt saying what was refused and when the next try is. Only a
/// *replacement* ends a member, and that is decided on the control
/// link, not here. Blocking: call from `spawn_blocking`.
pub fn join_with_backoff(cfg: &MemberConfig, identity: &TlsIdentity, keys: &StaticKeys) -> JoinResponse {
    let mut state = Retry::default();
    loop {
        match join_once(cfg, identity, keys) {
            Ok(r) => {
                state.accepted();
                return r;
            }
            Err(e) => std::thread::sleep(state.failed(&e)),
        }
    }
}

/// As `join_with_backoff`, but the waits are async so the task can be
/// cancelled between attempts (a blocking sleep in a `spawn_blocking`
/// would pin the runtime's shutdown). Every attempt itself runs on the
/// blocking pool.
pub async fn join_with_backoff_async(cfg: Arc<MemberConfig>, identity: TlsIdentity, keys: StaticKeys) -> JoinResponse {
    join_with_backoff_reporting(cfg, identity, keys, |_| {}).await
}

/// As `join_with_backoff_async`, telling the owner when the coordinator
/// starts and stops refusing it (`on_refused(true)` on the first
/// refusal, `on_refused(false)` when accepted again). A refused member
/// must not keep carrying traffic on stale facts; the owner decides
/// what to suspend.
pub async fn join_with_backoff_reporting(
    cfg: Arc<MemberConfig>,
    identity: TlsIdentity,
    keys: StaticKeys,
    on_refused: impl Fn(bool),
) -> JoinResponse {
    let mut state = Retry::default();
    loop {
        let (c, i, k) = (cfg.clone(), identity.clone(), keys.clone());
        let wait = match tokio::task::spawn_blocking(move || join_once(&c, &i, &k)).await {
            Ok(Ok(r)) => {
                if state.refused > 0 {
                    on_refused(false);
                }
                state.accepted();
                return r;
            }
            Ok(Err(e)) => {
                let first_refusal = e.is_terminal() && state.refused == 0;
                let wait = state.failed(&e);
                if first_refusal {
                    on_refused(true);
                }
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

/// The retry bookkeeping both loops share: counts, delays, and the log
/// lines an operator needs to see what is happening and why.
#[derive(Default)]
struct Retry {
    transient: u32,
    refused: u32,
}

impl Retry {
    fn failed(&mut self, e: &JoinError) -> Duration {
        if e.is_terminal() {
            self.refused = self.refused.saturating_add(1);
            let wait = joinapi::retry_delay(true, self.refused);
            tracing::error!(
                attempt = self.refused,
                next_retry_secs = wait.as_secs(),
                "join refused: {e} — keeping trying; enable the member (or give it its new token) at the coordinator"
            );
            wait
        } else {
            self.transient = self.transient.saturating_add(1);
            let wait = joinapi::retry_delay(false, self.transient);
            tracing::warn!(attempt = self.transient, next_retry_secs = wait.as_secs(), "join failed: {e}");
            wait
        }
    }

    fn accepted(&self) {
        if self.refused > 0 {
            tracing::info!(refused_attempts = self.refused, "join accepted again — the member is back");
        } else if self.transient > 0 {
            tracing::info!(failed_attempts = self.transient, "join accepted");
        }
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
