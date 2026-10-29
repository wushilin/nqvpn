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
    /// Local policy over the prefixes the coordinator publishes.
    #[serde(default)]
    pub routes: RoutesConfig,
    /// Reach one relay through a forwarder (`nqvpn-forward`):
    /// `"<relay-name>=<host:port>"`. `--relay-via` overrides it.
    #[serde(default)]
    pub relay_via: Option<String>,
}

/// `[routes]`: which coordinator-published prefixes this client accepts.
///
/// The coordinator decides who owns which prefix; this is the client's
/// own limit on what it will let that pull into the tunnel. Unset, every
/// published prefix is accepted except ones wider than `/8` (IPv4) or
/// `/16` (IPv6). Set, only prefixes inside one of the listed ranges are
/// routed (OS routes) *and* accepted (the in-VPN table and its ingress
/// filter) — so list the network's own address space too, or peers become
/// unreachable. Refusals are logged as warnings. `--route-all`'s catch-all
/// is the client's own and is not affected.
///
/// ```toml
/// [routes]
/// allow = ["10.99.0.0/16", "192.168.7.0/24"]
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutesConfig {
    #[serde(default)]
    pub allow: Option<Vec<ipnet::IpNet>>,
}

/// Where the token comes from when not from the config file, in order of
/// precedence: `--token`, `--token-file`, the `NQVPN_TOKEN` environment
/// variable. Each beats the config's `token` / `token_file`.
#[derive(Debug, Clone, Default)]
pub struct TokenOverride {
    pub token: Option<String>,
    pub token_file: Option<PathBuf>,
    pub env: Option<String>,
}

impl TokenOverride {
    pub fn is_set(&self) -> bool {
        self.token.is_some() || self.token_file.is_some() || self.env.is_some()
    }
}

/// The permission bits of `path` that let group or others read it, if
/// any (Unix). A token is a bearer secret: anyone who reads it can join
/// as this member.
pub fn exposed_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).ok()?.permissions().mode() & 0o777;
        (mode & 0o044 != 0).then_some(mode)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Warn when a file holding the token is readable beyond its owner.
pub fn warn_if_exposed(path: &Path, what: &str) {
    if let Some(mode) = exposed_mode(path) {
        tracing::warn!(path = %path.display(), mode = format!("{mode:03o}"), "{what} holds the member token and is readable by other local users; chmod 600 it");
    }
}

fn d_false() -> bool {
    false
}

fn d_state() -> PathBuf {
    PathBuf::from("/var/lib/nqvpn-client")
}

/// The same defaults whether or not a config file exists: `--token`
/// alone verifies the coordinator exactly as a parsed file with the keys
/// omitted would (the token's pinned fingerprint, or the system roots).
impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            token: None,
            token_file: None,
            trust_any_cert: false,
            ca: None,
            ca_cert: None,
            coordinator_fp: Vec::new(),
            state_dir: d_state(),
            tun_name: None,
            routes: RoutesConfig::default(),
            relay_via: None,
        }
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
        self.token_from(&TokenOverride { token: override_token.map(str::to_string), ..Default::default() })
    }

    /// The token, by the precedence `TokenOverride` documents. A token
    /// file that others can read is warned about.
    pub fn token_from(&self, o: &TokenOverride) -> Result<Token> {
        let read = |f: &Path| -> Result<String> {
            warn_if_exposed(f, "the token file");
            std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))
        };
        let raw = if let Some(t) = &o.token {
            t.clone()
        } else if let Some(f) = &o.token_file {
            read(f)?
        } else if let Some(t) = &o.env {
            t.clone()
        } else if let Some(t) = &self.token {
            t.clone()
        } else if let Some(f) = &self.token_file {
            read(f)?
        } else {
            anyhow::bail!("no token: pass --token-file (or --token, or NQVPN_TOKEN), or set token / token_file in the config")
        };
        Token::parse(raw.trim()).map_err(|e| anyhow::anyhow!("{e}"))
    }

    /// The `relay_via` override, `cli` (from `--relay-via`) first.
    pub fn relay_via(&self, cli: Option<&str>) -> Result<Option<crate::client::RelayVia>> {
        match cli.or(self.relay_via.as_deref()) {
            None => Ok(None),
            Some(s) => s.parse().map(Some).map_err(|e| anyhow::anyhow!("relay_via {s:?}: {e}")),
        }
    }

    /// The route policy `[routes]` describes.
    pub fn route_policy(&self) -> nqvpn_endpoint::peers::RoutePolicy {
        match &self.routes.allow {
            Some(allow) => nqvpn_endpoint::peers::RoutePolicy::allow_list(allow.clone()),
            None => nqvpn_endpoint::peers::RoutePolicy::default(),
        }
    }

    pub fn tls(&self) -> JoinTls {
        JoinTls { trust_any_cert: self.trust_any_cert, ca_pem: self.ca.clone(), ca_cert: self.ca_cert.clone(), pinned_fps: Vec::new() }
    }

    pub fn member(&self, override_token: Option<&str>) -> Result<nqvpn_sync::MemberConfig> {
        self.member_from(&TokenOverride { token: override_token.map(str::to_string), ..Default::default() })
    }

    pub fn member_from(&self, o: &TokenOverride) -> Result<nqvpn_sync::MemberConfig> {
        let token = self.token_from(o)?;
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
    fn relay_via_is_name_equals_host_port_and_the_command_line_wins() {
        let c: ClientConfig = toml::from_str("relay_via = \"sg-relay=cn-fwd.example:44449\"\n").unwrap();
        let v = c.relay_via(None).unwrap().unwrap();
        assert_eq!((v.relay.as_str(), v.addr.as_str()), ("sg-relay", "cn-fwd.example:44449"));
        assert_eq!(c.relay_via(Some("r2=[::1]:9")).unwrap().unwrap().addr, "[::1]:9");
        assert!(ClientConfig::default().relay_via(None).unwrap().is_none());
        for bad in ["sg-relay", "=h:1", "r=host", "r=:1", "r=h:notaport"] {
            assert!(ClientConfig::default().relay_via(Some(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_shipped_sample_config_parses() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        let c = ClientConfig::load(&root.join("client.toml")).expect("client.toml");
        assert!(c.token_file.is_some() || c.token.is_some());
    }

    #[test]
    fn the_token_comes_from_the_command_line_a_file_or_the_environment_in_that_order() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t");
        let other = Token { coordinator: "https://file.example:8443".into(), secret: "f".into(), fp: None }.encode();
        std::fs::write(&file, format!("{other}\n")).unwrap();
        let env = Token { coordinator: "https://env.example:8443".into(), secret: "e".into(), fp: None }.encode();
        let c = ClientConfig { token: Some(tok()), ..ClientConfig::default() };
        let o = |token: Option<String>, token_file: Option<PathBuf>, env: Option<String>| TokenOverride { token, token_file, env };
        assert_eq!(c.member_from(&o(None, None, None)).unwrap().secret, "s", "the config's own token");
        assert_eq!(c.member_from(&o(None, None, Some(env.clone()))).unwrap().secret, "e", "NQVPN_TOKEN beats the config");
        assert_eq!(c.member_from(&o(None, Some(file.clone()), Some(env.clone()))).unwrap().secret, "f", "--token-file beats the environment (trailing newline trimmed)");
        assert_eq!(c.member_from(&o(Some(tok()), Some(file), Some(env))).unwrap().secret, "s", "--token beats everything");
    }

    #[cfg(unix)]
    #[test]
    fn a_token_file_others_can_read_is_noticed() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("t");
        std::fs::write(&f, tok()).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(exposed_mode(&f), None);
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(exposed_mode(&f), Some(0o644));
    }

    #[test]
    fn the_routes_allowlist_parses_and_becomes_a_policy() {
        let c: ClientConfig = toml::from_str("token = \"x\"\n[routes]\nallow = [\"10.99.0.0/16\", \"fd00:99::/64\"]\n").unwrap();
        let p = c.route_policy();
        assert!(p.permits(&"10.99.1.2/32".parse().unwrap()));
        assert!(!p.permits(&"10.98.0.0/16".parse().unwrap()));
        assert!(ClientConfig::default().route_policy().allow.is_none(), "unset: the default width rule only");
        assert!(toml::from_str::<ClientConfig>("[routes]\nalow = []\n").is_err(), "a typo is an error, not a silent no-op");
    }

    #[test]
    fn full_config_parses() {
        let c: ClientConfig = toml::from_str("token_file = \"/etc/nqvpn/laptop.token\"\ntrust_any_cert = false\nca = \"/etc/nqvpn/ca.pem\"\ntun_name = \"nqvpn0\"\nstate_dir = \"/tmp/x\"\n")
        .unwrap();
        assert!(!c.trust_any_cert);
        assert_eq!(c.tls().ca_pem, Some(PathBuf::from("/etc/nqvpn/ca.pem")));
    }
}
