//! Client configuration (DESIGN.md §13 appendix) — deliberately tiny:
//! everything else (addresses, MTU, keepalive, relay fleet) is handed
//! down by the coordinator at join time.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub coordinator: String,
    /// Coordinator QUIC control address (host:port).
    pub coordinator_quic: String,
    pub network_id: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub client_secret_file: Option<String>,
    /// Pin the coordinator's control certificate (sha256:...).
    #[serde(default)]
    pub coordinator_fp: Option<String>,
    /// Replace this client's TLS identity once it has been in use for
    /// this many days, registering the new one over the authenticated
    /// control session. 0 (the default) disables it.
    ///
    /// Nothing dials a client, so unlike a relay it can rotate freely.
    #[serde(default)]
    pub rotate_identity_after_days: u64,
    /// Requested TUN device name. Linux accepts any name up to 15
    /// characters; macOS only accepts `utunN`. Left unset, the OS picks.
    #[serde(default)]
    pub tun_name: Option<String>,
    #[serde(default)]
    pub identity: IdentityCfg,
    #[serde(default)]
    pub relay: RelayCfg,
    #[serde(default)]
    pub address: AddressCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCfg {
    pub dir: PathBuf,
}

impl Default for IdentityCfg {
    fn default() -> Self {
        IdentityCfg { dir: PathBuf::from("/var/lib/nqvpn-client") }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayCfg {
    /// Attach here when reachable; otherwise pick by measured RTT
    /// (decision #3).
    #[serde(default)]
    pub preferred_relay_id: Option<String>,
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

impl ClientConfig {
    pub fn load(path: &Path) -> Result<ClientConfig> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_parses() {
        let c: ClientConfig = toml::from_str(
            r#"
coordinator = "https://coord.example:8443"
coordinator_quic = "coord.example:4433"
network_id = "acme"
client_id = "laptop-1"
client_secret = "s"
"#,
        )
        .unwrap();
        assert_eq!(c.secret().unwrap(), "s");
        assert!(c.relay.preferred_relay_id.is_none());
        assert!(c.address.pool.is_none());
    }

    #[test]
    fn full_config_parses() {
        let c: ClientConfig = toml::from_str(
            r#"
coordinator = "coord.example:8443"
coordinator_quic = "coord.example:4433"
network_id = "acme"
client_id = "laptop-1"
client_secret = "s"
coordinator_fp = "sha256:aa"
[identity]
dir = "/tmp/x"
[relay]
preferred_relay_id = "home"
[address]
pool = "default"
preferred_ip4 = "10.99.1.50"
"#,
        )
        .unwrap();
        assert_eq!(c.relay.preferred_relay_id.as_deref(), Some("home"));
        assert_eq!(c.address.preferred_ip4.unwrap().to_string(), "10.99.1.50");
    }

    #[test]
    fn tun_name_is_optional_and_round_trips() {
        // Absent means "let the OS pick", which must stay the default so
        // existing configs keep working untouched.
        let base = r#"
coordinator = "https://c.example:8443"
coordinator_quic = "c.example:14433"
network_id = "n"
client_id = "c"
client_secret = "s"
[identity]
dir = "/tmp/x"
"#;
        let cfg: ClientConfig = toml::from_str(base).expect("parses without tun_name");
        assert_eq!(cfg.tun_name, None);

        // tun_name is a top-level key, so in TOML it must appear before
        // any [section] header. Appended after one it is parsed as a
        // member of that section and rejected — an easy mistake to make
        // when editing an existing config, so pin both behaviours.
        let named: ClientConfig = toml::from_str(
            "tun_name = \"nqvpn0\"\n\
             coordinator = \"https://c.example:8443\"\n\
             coordinator_quic = \"c.example:14433\"\n\
             network_id = \"n\"\nclient_id = \"c\"\nclient_secret = \"s\"\n\
             [identity]\ndir = \"/tmp/x\"\n",
        )
        .expect("parses with tun_name before the first section");
        assert_eq!(named.tun_name.as_deref(), Some("nqvpn0"));

        let misplaced = toml::from_str::<ClientConfig>(&format!("{base}tun_name = \"nqvpn0\"\n"));
        assert!(misplaced.is_err(), "after a section header it belongs to that section");
    }
}
