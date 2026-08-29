//! Relay configuration (DESIGN.md §13 appendix).

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    pub coordinator: String,
    pub network_id: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_file: Option<String>,
    /// One QUIC socket serves both attached clients and the relay mesh.
    pub listen: String,
    /// What this relay advertises; must match its coordinator config entry.
    pub relay_addr: String,
    /// Pin the coordinator's control certificate (sha256:...).
    #[serde(default)]
    pub coordinator_fp: Option<String>,
    #[serde(default)]
    pub identity: IdentityCfg,
    /// Optional: this relay is also its site's gateway.
    #[serde(default)]
    pub gateway: Option<GatewayCfg>,
    /// Take a VPN address so the relay itself is reachable in-network
    /// (SSH, metrics, admin). Set false for a pure forwarder that should
    /// only carry other members' traffic (§3.1).
    #[serde(default)]
    pub want_vpn_ip: Option<bool>,
    #[serde(default)]
    pub limits: LimitsCfg,
    /// Replace this relay's TLS identity once it has been in use for
    /// this many days, registering the new one over the authenticated
    /// control session. 0 (the default) disables it.
    ///
    /// Relays need care here: their pinned fingerprint is what dialers
    /// verify against, so the fleet must learn the new one before the
    /// relay starts presenting it. The coordinator republishes the relay
    /// list on rotation, but leave this off unless you have verified
    /// that propagation in your deployment.
    #[serde(default)]
    pub rotate_identity_after_days: u64,
    /// Requested TUN device name for the endpoint role. Linux accepts any
    /// name up to 15 characters; macOS only accepts `utunN`. Unset lets
    /// the OS pick. Ignored by a pure forwarder, which has no TUN.
    #[serde(default)]
    pub tun_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCfg {
    pub dir: PathBuf,
}

impl Default for IdentityCfg {
    fn default() -> Self {
        IdentityCfg { dir: PathBuf::from("/var/lib/nqvpn-relay") }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayCfg {
    /// Must be a subset of this relay's `allowed_cidrs` at the coordinator.
    pub local_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    /// Per attached-client session cap; 0 = unlimited (decision #6).
    #[serde(default)]
    pub max_session_mbps: u32,
    /// tokio worker threads; 0 = one per core.
    #[serde(default)]
    pub workers: usize,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg { max_session_mbps: 0, workers: 0 }
    }
}

impl RelayConfig {
    pub fn load(path: &Path) -> Result<RelayConfig> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let cfg: RelayConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    pub fn secret(&self) -> Result<String> {
        if let Some(s) = &self.client_secret {
            return Ok(s.trim().to_string());
        }
        if let Some(f) = &self.client_secret_file {
            return Ok(std::fs::read_to_string(f)
                .with_context(|| format!("reading {f}"))?
                .trim()
                .to_string());
        }
        anyhow::bail!("config must set client_secret or client_secret_file")
    }

    pub fn local_cidrs(&self) -> Vec<IpNet> {
        self.gateway.as_ref().map(|g| g.local_cidrs.clone()).unwrap_or_default()
    }

    pub fn wants_address(&self) -> bool {
        self.want_vpn_ip.unwrap_or(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_pure_forwarder() {
        let cfg: RelayConfig = toml::from_str(
            r#"
coordinator = "https://coord.example:8443"
network_id = "acme"
client_id = "home"
client_secret = "s"
listen = "0.0.0.0:4444"
relay_addr = "home.example:4444"
"#,
        )
        .unwrap();
        assert!(cfg.gateway.is_none());
        assert!(cfg.local_cidrs().is_empty());
        assert!(cfg.wants_address(), "relays are addressable by default");
        assert_eq!(cfg.limits.max_session_mbps, 0);
        assert_eq!(cfg.secret().unwrap(), "s");
    }

    #[test]
    fn parses_gateway_relay() {
        let cfg: RelayConfig = toml::from_str(
            r#"
coordinator = "coord.example:8443"
network_id = "acme"
client_id = "home"
client_secret = "s"
listen = "0.0.0.0:4444"
relay_addr = "home.example:4444"
[gateway]
local_cidrs = ["192.168.1.0/24"]
[limits]
max_session_mbps = 200
"#,
        )
        .unwrap();
        assert_eq!(cfg.local_cidrs().len(), 1);
        assert_eq!(cfg.limits.max_session_mbps, 200);
    }
}
