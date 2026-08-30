//! Client configuration — a token and local facts. Everything about the
//! client's place in the network (address, preferred relay, MTU, the
//! relay fleet, the control port) is configured at the coordinator and
//! handed down at join.

use anyhow::{Context, Result};
use nqvpn_proto::joinapi::JoinTls;
use nqvpn_proto::token::Token;
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    /// Skip coordinator certificate verification. Default false: the
    /// token pins the coordinator's certificate (self-signed) or it is
    /// verified against the system roots (CA-signed). Set true only to
    /// deliberately trust any certificate.
    #[serde(default = "d_false")]
    pub trust_any_cert: bool,
    #[serde(default)]
    pub ca: Option<PathBuf>,
    /// The coordinator's certificate inline (PEM). Verified when
    /// `trust_any_cert = false`.
    #[serde(default)]
    pub ca_cert: Option<String>,
    /// Extra coordinator certificate fingerprints to trust ("sha256:..."),
    /// on top of the one in the token. Pre-stage the next certificate's
    /// fingerprint here to rotate the coordinator without changing every
    /// member at once: add it everywhere, switch the server, then drop
    /// the old one.
    #[serde(default)]
    pub coordinator_fp: Vec<String>,
    /// Where the auto-generated TLS certificate and X25519 key live.
    /// Safe to delete: the next join records the new ones.
    #[serde(default = "d_state")]
    pub state_dir: PathBuf,
    /// Requested TUN device name (Linux: any; macOS: `utunN`).
    #[serde(default)]
    pub tun_name: Option<String>,
}

fn d_false() -> bool {
    false
}

fn d_state() -> PathBuf {
    PathBuf::from("/var/lib/nqvpn-client")
}

/// The same defaults whether or not a config file exists (`--token`
/// alone must trust any coordinator certificate, like a parsed file
/// with the key omitted would).
impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig { token: None, token_file: None, trust_any_cert: false, ca: None, ca_cert: None, coordinator_fp: Vec::new(), state_dir: d_state(), tun_name: None }
    }
}

impl ClientConfig {
    pub fn load(path: &Path) -> Result<ClientConfig> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: ClientConfig = toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    /// The token: from the command line, the config, or a file.
    pub fn token(&self, override_token: Option<&str>) -> Result<Token> {
        let raw = if let Some(t) = override_token {
            t.to_string()
        } else if let Some(t) = &self.token {
            t.clone()
        } else if let Some(f) = &self.token_file {
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?
        } else {
            anyhow::bail!("no token: pass --token, or set token / token_file in the config")
        };
        Token::parse(&raw).map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn tls(&self) -> JoinTls {
        JoinTls { trust_any_cert: self.trust_any_cert, ca_pem: self.ca.clone(), ca_cert: self.ca_cert.clone(), pinned_fps: Vec::new() }
    }

    pub fn member(&self, override_token: Option<&str>) -> Result<nqvpn_sync::MemberConfig> {
        let token = self.token(override_token)?;
        let mut tls = self.tls();
        // Trust the token's fingerprint plus any pre-staged for rotation.
        tls.pinned_fps = token.fp.iter().cloned().chain(self.coordinator_fp.iter().cloned()).collect();
        Ok(nqvpn_sync::MemberConfig::from_token(&token, tls))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok() -> String {
        Token { coordinator: "https://coord.example:8443".into(), secret: "s".into(), fp: None }.encode()
    }

    #[test]
    fn a_token_is_all_it_takes() {
        let c: ClientConfig = toml::from_str(&format!("token = \"{}\"\n", tok())).unwrap();
        assert!(!c.trust_any_cert, "verification is the default now");
        let m = c.member(None).unwrap();
        assert_eq!(m.coordinator, "https://coord.example:8443");
        assert_eq!(m.secret, "s");
    }

    #[test]
    fn the_command_line_wins_and_no_token_is_an_error() {
        let c = ClientConfig::default();
        assert!(c.member(None).is_err());
        let m = c.member(Some(&tok())).unwrap();
        assert_eq!(m.secret, "s");
        // Verification is the default; a real token from the UI carries
        // the coordinator's fingerprint (this bare test token has none).
        assert!(!m.tls.trust_any_cert);
        assert!(m.tls.pinned_fps.is_empty());
        assert_eq!(c.state_dir, d_state());
    }

    #[test]
    fn the_shipped_sample_config_parses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        let c = ClientConfig::load(&root.join("client.toml")).expect("client.toml");
        assert!(c.token_file.is_some() || c.token.is_some());
    }

    #[test]
    fn full_config_parses() {
        let c: ClientConfig = toml::from_str("token_file = \"/etc/nqvpn/laptop.token\"\ntrust_any_cert = false\nca = \"/etc/nqvpn/ca.pem\"\ntun_name = \"nqvpn0\"\nstate_dir = \"/tmp/x\"\n")
        .unwrap();
        assert!(!c.trust_any_cert);
        assert_eq!(c.tls().ca_pem, Some(PathBuf::from("/etc/nqvpn/ca.pem")));
    }
}
