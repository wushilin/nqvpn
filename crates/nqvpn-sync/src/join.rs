//! Joining: the member's whole declaration, sent over HTTPS with its
//! node id and secret. Renewal is the same request again.

use ipnet::IpNet;
use nqvpn_proto::api::{JoinRequest, JoinResponse};
use nqvpn_proto::credential::Claims;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::joinapi::{self, JoinError, JoinTls};
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::types::{NodeId, Role};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Everything a member declares about itself.
#[derive(Debug, Clone)]
pub struct MemberConfig {
    /// `https://host[:port]`
    pub coordinator: String,
    pub network_id: String,
    pub node_id: NodeId,
    pub secret: String,
    pub tls: JoinTls,
    pub role: Role,
    pub want_vpn_ip: bool,
    pub pool: Option<String>,
    pub preferred_ip4: Option<Ipv4Addr>,
    pub preferred_ip6: Option<Ipv6Addr>,
    /// Relays only.
    pub local_cidrs: Vec<IpNet>,
    /// Relays only.
    pub relay_addr: Option<String>,
}

impl MemberConfig {
    pub fn request(&self, identity: &TlsIdentity, keys: &StaticKeys) -> JoinRequest {
        JoinRequest {
            network_id: self.network_id.clone(),
            node_id: self.node_id,
            secret: self.secret.clone(),
            pubkey: keys.public_b64(),
            role: self.role,
            want_vpn_ip: self.want_vpn_ip,
            pool: self.pool.clone(),
            preferred_ip4: self.preferred_ip4,
            preferred_ip6: self.preferred_ip6,
            local_cidrs: self.local_cidrs.clone(),
            relay_addr: self.relay_addr.clone(),
            cert_fingerprint: identity.fingerprint(),
        }
    }
}

pub fn join_once(cfg: &MemberConfig, identity: &TlsIdentity, keys: &StaticKeys) -> Result<JoinResponse, JoinError> {
    joinapi::join(&cfg.coordinator, &cfg.request(identity, keys), &cfg.tls)
}

/// Join, retrying until it succeeds. Terminal rejections — a disabled
/// member, a wrong secret — are fixed at the coordinator, and the member
/// can only learn of the fix by asking again, so they poll slowly and
/// forever rather than exiting. Blocking: call from `spawn_blocking`.
pub fn join_with_backoff(cfg: &MemberConfig, identity: &TlsIdentity, keys: &StaticKeys) -> JoinResponse {
    let mut consecutive: u32 = 0;
    loop {
        match join_once(cfg, identity, keys) {
            Ok(r) => return r,
            Err(e) if e.is_terminal() => {
                let wait = joinapi::retry_delay(true, 1);
                tracing::error!(retry_in_secs = wait.as_secs(), "join rejected: {e} — fix this at the coordinator; retrying until then");
                std::thread::sleep(wait);
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
