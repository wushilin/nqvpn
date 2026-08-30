//! Relay configuration. One process, one listening socket, any number
//! of networks — each joined with its own token. Everything about the
//! relay's place in a network (its advertised address, its overlay
//! address, the LANs it routes) is configured at the coordinator and
//! handed down at join; this file holds only local facts.

use anyhow::{Context, Result};
use nqvpn_proto::joinapi::JoinTls;
use nqvpn_proto::token::Token;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Accept any coordinator certificate (default). Set false to
    /// verify against system roots plus `ca`.
    #[serde(default = "d_true")]
    pub trust_any_cert: bool,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// The coordinator's certificate inline (PEM), as the UI hands it
    /// out. Verified when `trust_any_cert = false`.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// One QUIC socket serves attached clients and the relay mesh. Its
    /// port must be the one in the coordinator's relay address.
    #[serde(default = "d_listen")]
    pub listen: String,
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

/// One network: its token, nothing else.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkCfg {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    /// Per attached-client session cap; 0 = what the coordinator says.
    #[serde(default)]
    pub max_session_mbps: u32,
    /// tokio worker threads; 0 = one per core.
    #[serde(default)]
    pub workers: usize,
}

fn d_true() -> bool {
    true
}

fn d_listen() -> String {
    "0.0.0.0:4444".to_string()
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
            n.token()?;
        }
        Ok(cfg)
    }

    pub fn tls(&self) -> JoinTls {
        JoinTls { trust_any_cert: self.trust_any_cert, ca_pem: self.ca.clone(), ca_cert: self.ca_cert.clone() }
    }
}

impl NetworkCfg {
    pub fn token(&self) -> Result<Token> {
        let raw = if let Some(t) = &self.token {
            t.clone()
        } else if let Some(f) = &self.token_file {
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?
        } else {
            anyhow::bail!("each [[networks]] entry needs token or token_file")
        };
        Token::parse(&raw).map_err(|e| anyhow::anyhow!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(secret: &str) -> String {
        Token { coordinator: "https://coord.example:8443".into(), secret: secret.into() }.encode()
    }

    #[test]
    fn parses_a_multi_network_relay() {
        let cfg: RelayConfig = toml::from_str(&format!(
            "listen = \"0.0.0.0:4444\"\n[[networks]]\ntoken = \"{}\"\n[[networks]]\ntoken = \"{}\"\n",
            tok("a"),
            tok("b")
        ))
        .unwrap();
        assert!(cfg.trust_any_cert, "the simple default");
        assert_eq!(cfg.networks.len(), 2);
        assert_eq!(cfg.networks[0].token().unwrap().secret, "a");
        assert_eq!(cfg.networks[1].token().unwrap().coordinator, "https://coord.example:8443");
        assert_eq!(cfg.state_dir, PathBuf::from("/var/lib/nqvpn-relay"));
    }

    #[test]
    fn a_bad_token_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("relay.toml");
        std::fs::write(&p, "[[networks]]\ntoken = \"nope\"\n").unwrap();
        assert!(RelayConfig::load(&p).unwrap_err().to_string().contains("prefix"));
    }

    #[test]
    fn the_shipped_sample_config_parses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        let raw = std::fs::read_to_string(root.join("relay.toml")).unwrap();
        let cfg: RelayConfig = toml::from_str(&raw).expect("relay.toml");
        assert_eq!(cfg.networks.len(), 1);
    }
}
