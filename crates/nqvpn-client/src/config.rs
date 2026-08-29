//! Client configuration — deliberately tiny: everything else
//! (addresses, MTU, relay fleet, control port) is handed down by the
//! coordinator at join time.

use anyhow::{Context, Result};
use nqvpn_proto::joinapi::JoinTls;
use nqvpn_proto::types::NodeId;
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// `https://host[:port]` of the coordinator.
    pub coordinator: String,
    /// Accept any coordinator certificate (default). Set false to
    /// verify against system roots plus `ca`.
    #[serde(default = "d_true")]
    pub trust_any_cert: bool,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    pub network_id: String,
    pub node_id: NodeId,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// Where the auto-generated TLS certificate and X25519 key live.
    /// Safe to delete: the next join records the new ones.
    #[serde(default = "d_state")]
    pub state_dir: PathBuf,
    /// Requested TUN device name (Linux: any; macOS: `utunN`).
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub relay: RelayCfg,
    #[serde(default)]
    pub address: AddressCfg,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayCfg {
    /// Attach here when reachable; otherwise pick by measured RTT.
    #[serde(default)]
    pub preferred: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressCfg {
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub preferred_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<Ipv6Addr>,
    /// Opt out of a tunnel address entirely (headless).
    #[serde(default)]
    pub want_vpn_ip: Option<bool>,
}

fn d_true() -> bool {
    true
}

fn d_state() -> PathBuf {
    PathBuf::from("/var/lib/nqvpn-client")
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<ClientConfig> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: ClientConfig = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        cfg.secret()?;
        Ok(cfg)
    }

    pub fn secret(&self) -> Result<String> {
        if let Some(s) = &self.secret {
            return Ok(s.trim().to_string());
        }
        if let Some(f) = &self.secret_file {
            return Ok(std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?.trim().to_string());
        }
        anyhow::bail!("config must set secret or secret_file")
    }

    pub fn tls(&self) -> JoinTls {
        JoinTls { trust_any_cert: self.trust_any_cert, ca_pem: self.ca.clone() }
    }

    pub fn member(&self) -> Result<nqvpn_sync::MemberConfig> {
        Ok(nqvpn_sync::MemberConfig {
            coordinator: self.coordinator.clone(),
            network_id: self.network_id.clone(),
            node_id: self.node_id,
            secret: self.secret()?,
            tls: self.tls(),
            role: nqvpn_proto::types::Role::Client,
            want_vpn_ip: self.address.want_vpn_ip.unwrap_or(true),
            pool: self.address.pool.clone(),
            preferred_ip4: self.address.preferred_ip4,
            preferred_ip6: self.address.preferred_ip6,
            local_cidrs: vec![],
            relay_addr: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_parses_with_the_simple_defaults() {
        let c: ClientConfig = toml::from_str(
            r#"
coordinator = "https://coord.example:8443"
network_id = "acme"
node_id = 10
secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(c.secret().unwrap(), "s");
        assert!(c.trust_any_cert);
        assert!(c.relay.preferred.is_none());
        assert_eq!(c.member().unwrap().node_id, 10);
    }

    #[test]
    fn full_config_parses() {
        let c: ClientConfig = toml::from_str(
            r#"
coordinator = "https://coord.example:8443"
trust_any_cert = false
ca = "/etc/nqvpn/coord-ca.pem"
network_id = "acme"
node_id = 10
secret = "s"
tun_name = "nqvpn0"
state_dir = "/tmp/x"
[relay]
preferred = "home"
[address]
pool = "default"
preferred_ip4 = "10.99.1.50"
"#,
        )
        .unwrap();
        assert_eq!(c.relay.preferred.as_deref(), Some("home"));
        assert!(!c.trust_any_cert);
        assert_eq!(c.tls().ca_pem, Some(PathBuf::from("/etc/nqvpn/coord-ca.pem")));
    }
}
