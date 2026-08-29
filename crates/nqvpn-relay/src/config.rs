//! Relay configuration. One process, one listening socket, any number
//! of networks — each joined with its own node id and secret.

use anyhow::{Context, Result};
use ipnet::IpNet;
use nqvpn_proto::joinapi::JoinTls;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// `https://host[:port]` of the coordinator.
    pub coordinator: String,
    /// Accept any coordinator certificate (default). Set false to
    /// verify against system roots plus `ca`.
    #[serde(default = "d_true")]
    pub trust_any_cert: bool,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// One QUIC socket serves attached clients and the relay mesh.
    pub listen: String,
    /// What this relay advertises; must match its coordinator entry.
    pub relay_addr: String,
    /// Where the auto-generated TLS certificate and X25519 key live.
    /// Safe to delete: the next join records the new ones.
    #[serde(default = "d_state")]
    pub state_dir: PathBuf,
    /// Requested TUN device name for the endpoint role.
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub limits: LimitsCfg,
    pub networks: Vec<NetworkCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCfg {
    pub network_id: String,
    /// This relay's member name at the coordinator.
    pub name: String,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// Take a VPN address so the relay is reachable in-network.
    #[serde(default = "d_true")]
    pub want_vpn_ip: bool,
    /// Gateway role: LAN prefixes this relay fronts (⊆ allowed_cidrs).
    #[serde(default)]
    pub local_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub preferred_ip4: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    /// Per attached-client session cap; 0 = unlimited.
    #[serde(default)]
    pub max_session_mbps: u32,
    /// tokio worker threads; 0 = one per core.
    #[serde(default)]
    pub workers: usize,
}

fn d_true() -> bool {
    true
}

fn d_state() -> PathBuf {
    PathBuf::from("/var/lib/nqvpn-relay")
}

impl RelayConfig {
    pub fn load(path: &Path) -> Result<RelayConfig> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: RelayConfig = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        anyhow::ensure!(!cfg.networks.is_empty(), "{}: at least one [[networks]] entry is required", path.display());
        for n in &cfg.networks {
            n.secret()?;
        }
        Ok(cfg)
    }

    pub fn tls(&self) -> JoinTls {
        JoinTls { trust_any_cert: self.trust_any_cert, ca_pem: self.ca.clone() }
    }
}

impl NetworkCfg {
    pub fn secret(&self) -> Result<String> {
        if let Some(s) = &self.secret {
            return Ok(s.trim().to_string());
        }
        if let Some(f) = &self.secret_file {
            return Ok(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?.trim().to_string());
        }
        anyhow::bail!("network {}: set secret or secret_file", self.network_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_multi_network_relay() {
        let cfg: RelayConfig = toml::from_str(
            r#"
coordinator = "https://coord.example:8443"
listen = "0.0.0.0:4444"
relay_addr = "home.example:4444"
[[networks]]
network_id = "acme"
name = "home"
secret = "s"
local_cidrs = ["192.168.1.0/24"]
[[networks]]
network_id = "lab"
name = "home"
secret = "t"
want_vpn_ip = false
"#,
        )
        .unwrap();
        assert!(cfg.trust_any_cert, "the simple default");
        assert_eq!(cfg.networks.len(), 2);
        assert_eq!(cfg.networks[0].secret().unwrap(), "s");
        assert!(cfg.networks[0].want_vpn_ip);
        assert!(!cfg.networks[1].want_vpn_ip);
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/nqvpn-relay"));
    }
}
