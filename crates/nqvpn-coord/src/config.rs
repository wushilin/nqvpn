//! Coordinator + per-network config loading and validation (§3.1, §3.2).
//! The operator's TOML is the plan of record; validation failures are
//! planning bugs and fail startup (or leave the old config running on
//! reload).
//!
//! A member is a **node id + secret**. The id is chosen by the operator
//! here; the secret is either written here or minted into the managed
//! store (which wins when both exist). Nothing else authenticates.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use nqvpn_proto::lpm::overlaps;
use nqvpn_proto::types::Role;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordConfig {
    pub listen: ListenCfg,
    /// A real certificate for the HTTPS API and QUIC control port. Unset
    /// means a self-signed one is generated into the state dir on first
    /// start — members accept it by default (`trust_any_cert = true`).
    #[serde(default)]
    pub tls: Option<TlsCfg>,
    pub state: StateCfg,
    #[serde(default)]
    pub admin: AdminCfg,
    #[serde(default)]
    pub limits: LimitsCfg,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenCfg {
    /// HTTPS: `/api/v1/*` and `/ui`.
    pub api: String,
    /// QUIC control plane. Members dial the API host on this port, so
    /// it is published in the join response; nothing else configures it.
    #[serde(default = "d_quic")]
    pub quic: String,
}

fn d_quic() -> String {
    "0.0.0.0:14433".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCfg {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateCfg {
    pub dir: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCfg {
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsCfg {
    #[serde(default = "default_join_rate")]
    pub join_rate_per_min: u32,
}

impl Default for LimitsCfg {
    fn default() -> Self {
        LimitsCfg { join_rate_per_min: default_join_rate() }
    }
}

fn default_join_rate() -> u32 {
    30
}

// ---- per-network ----

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub network_id: String,
    pub cidrs: Vec<IpNet>,
    #[serde(default)]
    pub pools: BTreeMap<String, PoolCfg>,
    #[serde(default)]
    pub settings: SettingsCfg,
    #[serde(default)]
    pub relays: BTreeMap<String, MemberCfg>,
    #[serde(default)]
    pub clients: BTreeMap<String, MemberCfg>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCfg {
    pub cidr: IpNet,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsCfg {
    #[serde(default = "d_ttl")]
    pub credential_ttl_mins: u64,
    /// Seconds between member heartbeats. Convergence after a lost push
    /// is bounded by this.
    #[serde(default = "d_heartbeat")]
    pub heartbeat_secs: u16,
    /// Missed heartbeats before a member is offline.
    #[serde(default = "d_offline_after")]
    pub offline_after: u32,
    #[serde(default = "d_hold_down")]
    pub hold_down_secs: u64,
    #[serde(default = "d_mtu")]
    pub mtu: u16,
    /// What to do when a joining relay's advertised address cannot be
    /// dialed from the coordinator (§3.2): "off" | "warn" | "deny".
    #[serde(default = "d_reach_policy")]
    pub relay_reachability: String,
    /// "datagram" or "stream".
    #[serde(default = "d_transport")]
    pub transport: String,
    #[serde(default = "d_lanes")]
    pub lanes: u8,
    /// Default per-client bandwidth cap applied by relays; 0 = none.
    #[serde(default)]
    pub max_session_mbps: u32,
    /// Let relays advertise loopback addresses. Only for running a whole
    /// network on one machine (tests, demos); never in production.
    #[serde(default)]
    pub allow_loopback_relays: bool,
}

impl Default for SettingsCfg {
    fn default() -> Self {
        SettingsCfg {
            credential_ttl_mins: d_ttl(),
            heartbeat_secs: d_heartbeat(),
            offline_after: d_offline_after(),
            hold_down_secs: d_hold_down(),
            mtu: d_mtu(),
            relay_reachability: d_reach_policy(),
            transport: d_transport(),
            lanes: d_lanes(),
            max_session_mbps: 0,
            allow_loopback_relays: false,
        }
    }
}

impl SettingsCfg {
    /// Seconds without a heartbeat before a member is offline.
    pub fn liveness_window_secs(&self) -> u64 {
        (self.heartbeat_secs.max(1) as u64) * (self.offline_after.max(1) as u64)
    }
}

fn d_ttl() -> u64 {
    15
}
fn d_heartbeat() -> u16 {
    5
}
fn d_offline_after() -> u32 {
    3
}
fn d_hold_down() -> u64 {
    60
}
fn d_mtu() -> u16 {
    1350
}
fn d_reach_policy() -> String {
    "warn".to_string()
}
fn d_lanes() -> u8 {
    1
}
fn d_transport() -> String {
    "stream".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCfg {
    /// The member's secret. Optional here: a secret minted into the
    /// managed store (admin API / UI) takes precedence, and a member with
    /// neither cannot join.
    #[serde(default)]
    pub secret: Option<String>,
    /// Relays only: public address the fleet and clients dial.
    #[serde(default)]
    pub relay_addr: Option<String>,
    /// Relays only: CIDRs this member MAY register.
    #[serde(default)]
    pub allowed_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub preferred_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<Ipv6Addr>,
    /// Pin auto-allocation to this pool.
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub want_vpn_ip: Option<bool>,
    #[serde(default)]
    pub max_session_mbps: Option<u32>,
}

impl NetworkConfig {
    pub fn member_by_name(&self, name: &str) -> Option<(&MemberCfg, Role)> {
        self.clients
            .get(name)
            .map(|m| (m, Role::Client))
            .or_else(|| self.relays.get(name).map(|m| (m, Role::Relay)))
    }
}

pub fn load_coord_config(path: &Path) -> Result<CoordConfig> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    let cfg: CoordConfig = toml::from_str(&raw)
        .with_context(|| format!("parsing {}", path.display()))?;
    if let Some(t) = &cfg.tls {
        for p in [&t.cert, &t.key] {
            if !Path::new(p).exists() {
                bail!("tls file missing: {p}");
            }
        }
    }
    Ok(cfg)
}

/// Load and validate every `networks.d/<network_id>.toml`.
pub fn load_networks(dir: &Path) -> Result<Vec<NetworkConfig>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("reading networks dir {}", dir.display()))?;
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)?;
        let cfg: NetworkConfig = toml::from_str(&raw)
            .with_context(|| format!("parsing {}", path.display()))?;
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default();
        if stem != cfg.network_id {
            bail!(
                "{}: file stem {stem:?} must equal network_id {:?}",
                path.display(),
                cfg.network_id
            );
        }
        validate_network(&cfg).with_context(|| format!("validating {}", path.display()))?;
        out.push(cfg);
    }
    out.sort_by(|a, b| a.network_id.cmp(&b.network_id));
    Ok(out)
}

pub fn validate_network(cfg: &NetworkConfig) -> Result<()> {
    let s = &cfg.settings;
    if !matches!(s.relay_reachability.as_str(), "off" | "warn" | "deny") {
        bail!(
            "network {}: relay_reachability must be \"off\", \"warn\", or \"deny\" (got {:?})",
            cfg.network_id,
            s.relay_reachability
        );
    }
    if !matches!(s.transport.as_str(), "datagram" | "stream") {
        bail!("network {}: transport must be \"datagram\" or \"stream\"", cfg.network_id);
    }
    if s.lanes == 0 || s.lanes > nqvpn_proto::transport::MAX_LANES {
        bail!(
            "network {}: lanes must be between 1 and {} (got {})",
            cfg.network_id,
            nqvpn_proto::transport::MAX_LANES,
            s.lanes
        );
    }
    if s.credential_ttl_mins == 0 || s.heartbeat_secs == 0 || s.offline_after == 0 {
        bail!("network {}: credential_ttl_mins, heartbeat_secs and offline_after must be > 0", cfg.network_id);
    }
    if s.mtu < 1280 || s.mtu > 9000 {
        bail!("network {}: mtu {} is outside 1280..=9000", cfg.network_id, s.mtu);
    }
    if cfg.cidrs.is_empty() {
        bail!("network {}: cidrs must not be empty", cfg.network_id);
    }
    if !cfg.cidrs.iter().any(|c| matches!(c, IpNet::V4(_))) {
        bail!("network {}: at least one IPv4 tunnel cidr is required", cfg.network_id);
    }
    for (i, a) in cfg.cidrs.iter().enumerate() {
        for b in cfg.cidrs.iter().skip(i + 1) {
            if overlaps(a, b) {
                bail!("network cidrs overlap: {a} vs {b}");
            }
        }
    }
    // Pools: inside a network cidr (the whole pool, not just its first
    // address), pairwise disjoint.
    let pools: Vec<(&String, &PoolCfg)> = cfg.pools.iter().collect();
    for (name, p) in &pools {
        if !cfg.cidrs.iter().any(|c| c.contains(&p.cidr)) {
            bail!("pool {name}: {} is not inside any network cidr", p.cidr);
        }
    }
    for (i, (an, a)) in pools.iter().enumerate() {
        for (bn, b) in pools.iter().skip(i + 1) {
            if overlaps(&a.cidr, &b.cidr) {
                bail!("pools {an} and {bn} overlap ({} vs {})", a.cidr, b.cidr);
            }
        }
    }
    for name in cfg.clients.keys() {
        if cfg.relays.contains_key(name) {
            bail!("member {name} defined as both client and relay");
        }
    }
    let mut seen4: BTreeMap<Ipv4Addr, String> = BTreeMap::new();
    let mut seen6: BTreeMap<Ipv6Addr, String> = BTreeMap::new();
    for (name, m, is_relay) in cfg
        .clients
        .iter()
        .map(|(n, m)| (n, m, false))
        .chain(cfg.relays.iter().map(|(n, m)| (n, m, true)))
    {
        if let Some(s) = &m.secret {
            if s.trim().is_empty() {
                bail!("member {name}: secret must not be empty");
            }
        }
        if !is_relay {
            if m.relay_addr.is_some() || !m.allowed_cidrs.is_empty() {
                bail!("client {name}: relay_addr/allowed_cidrs are relay-only fields");
            }
        } else {
            let addr = m
                .relay_addr
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("relay {name}: relay_addr is required"))?;
            validate_relay_addr(name, addr, cfg)?;
            for c in &m.allowed_cidrs {
                for t in &cfg.cidrs {
                    if overlaps(c, t) {
                        bail!("relay {name}: allowed cidr {c} overlaps tunnel space {t}");
                    }
                }
            }
        }
        if let Some(pool) = &m.pool {
            if !cfg.pools.contains_key(pool) {
                bail!("member {name}: unknown pool {pool:?}");
            }
        }
        if let Some(ip) = m.preferred_ip4 {
            check_in_cidrs(&cfg.cidrs, IpAddr::V4(ip))
                .with_context(|| format!("member {name}: preferred_ip4 {ip}"))?;
            if let Some(prev) = seen4.insert(ip, name.clone()) {
                bail!("preferred_ip4 {ip} claimed by both {prev} and {name}");
            }
        }
        if let Some(ip) = m.preferred_ip6 {
            check_in_cidrs(&cfg.cidrs, IpAddr::V6(ip))
                .with_context(|| format!("member {name}: preferred_ip6 {ip}"))?;
            if let Some(prev) = seen6.insert(ip, name.clone()) {
                bail!("preferred_ip6 {ip} claimed by both {prev} and {name}");
            }
        }
    }
    Ok(())
}

fn check_in_cidrs(cidrs: &[IpNet], ip: IpAddr) -> Result<()> {
    if cidrs.iter().any(|c| c.contains(&ip)) {
        Ok(())
    } else {
        bail!("address {ip} is outside every network cidr")
    }
}

fn unroutable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Endpoint validation (§3.2): reject loopback, unspecified, multicast,
/// link-local, and anything inside VPN-routed space. Hostnames are
/// resolved here as well, so a name pointing at tunnel space is caught
/// at load rather than when every dialer loops into its own TUN.
fn validate_relay_addr(name: &str, addr: &str, cfg: &NetworkConfig) -> Result<()> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("relay {name}: relay_addr {addr:?} must be host:port"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| anyhow::anyhow!("relay {name}: bad port in relay_addr {addr:?}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let ips: Vec<IpAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![ip],
        Err(_) => {
            use std::net::ToSocketAddrs;
            match (host, port).to_socket_addrs() {
                Ok(it) => it.map(|s| s.ip()).collect(),
                // Unresolvable now is not a planning bug (DNS may be
                // down at boot); dialers will report it.
                Err(_) => Vec::new(),
            }
        }
    };
    for ip in ips {
        if cfg.settings.allow_loopback_relays && ip.is_loopback() {
            continue;
        }
        if unroutable(ip) {
            bail!("relay {name}: relay_addr {addr:?} resolves to an unroutable address {ip}");
        }
        if cfg.cidrs.iter().any(|c| c.contains(&ip)) {
            bail!("relay {name}: relay_addr {addr:?} ({ip}) lies inside tunnel space");
        }
        let in_lan = cfg
            .relays
            .values()
            .chain(cfg.clients.values())
            .flat_map(|m| m.allowed_cidrs.iter())
            .any(|c| c.contains(&ip));
        if in_lan {
            bail!("relay {name}: relay_addr {addr:?} ({ip}) lies inside a routed LAN prefix");
        }
    }
    Ok(())
}

pub fn read_bearer_token(cfg: &AdminCfg) -> Result<Option<String>> {
    if let Some(t) = &cfg.bearer_token {
        return Ok(Some(t.trim().to_string()));
    }
    if let Some(f) = &cfg.bearer_token_file {
        let t = std::fs::read_to_string(f).with_context(|| format!("reading {f}"))?;
        return Ok(Some(t.trim().to_string()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> String {
        r#"
network_id = "n1"
cidrs = ["10.99.0.0/16", "fd99::/64"]
[pools.default]
cidr = "10.99.1.0/24"
[relays.r1]
secret = "s"
relay_addr = "1.2.3.4:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
[clients.c1]
secret = "s"
pool = "default"
"#
        .to_string()
    }

    fn parse(s: &str) -> NetworkConfig {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn valid_config_passes_and_indexes_by_name() {
        let cfg = parse(&base());
        validate_network(&cfg).unwrap();
        assert_eq!(cfg.member_by_name("c1").unwrap().1, Role::Client);
        assert_eq!(cfg.member_by_name("r1").unwrap().1, Role::Relay);
        assert!(cfg.member_by_name("nope").is_none());
        assert_eq!(cfg.settings.liveness_window_secs(), 15);
    }

    #[test]
    fn pool_must_be_entirely_inside_a_cidr() {
        assert!(validate_network(&parse(&base().replace("10.99.1.0/24", "10.200.0.0/24"))).is_err());
        // Larger than its network: the old check only looked at the
        // first address and let the allocator hand out tunnel-space
        // addresses that were outside every route.
        assert!(validate_network(&parse(&base().replace("10.99.1.0/24", "10.0.0.0/8"))).is_err());
    }

    #[test]
    fn overlapping_pools_fail() {
        let mut s = base();
        s.push_str("[pools.other]\ncidr = \"10.99.1.128/25\"\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn client_with_relay_fields_fails() {
        let mut s = base();
        s.push_str("[clients.c2]\nrelay_addr = \"1.1.1.1:1\"\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn relay_without_addr_fails() {
        let mut s = base();
        s.push_str("[relays.r2]\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn relay_addr_in_tunnel_space_or_loopback_fails() {
        assert!(validate_network(&parse(&base().replace("1.2.3.4:4444", "10.99.0.7:4444"))).is_err());
        assert!(validate_network(&parse(&base().replace("1.2.3.4:4444", "127.0.0.1:4444"))).is_err());
        assert!(validate_network(&parse(&base().replace("1.2.3.4:4444", "localhost:4444"))).is_err(), "names resolve too");
    }

    #[test]
    fn duplicate_preferred_ip_fails_and_node_ids_are_not_configurable() {
        let mut s = base();
        s.push_str("[clients.c9]\npreferred_ip4 = \"10.99.0.1\"\n");
        assert!(validate_network(&parse(&s)).is_err());
        let mut d = base();
        d.push_str("[clients.c9]\nnode_id = 7\n");
        assert!(toml::from_str::<NetworkConfig>(&d).is_err(), "ids are assigned by the coordinator, never written in config");
    }

    #[test]
    fn allowed_cidr_overlapping_tunnel_fails() {
        assert!(validate_network(&parse(&base().replace("192.168.1.0/24", "10.99.5.0/24"))).is_err());
    }

    #[test]
    fn overlapping_allowed_cidrs_across_relays_ok_for_failover() {
        let mut s = base();
        s.push_str("[relays.r2]\nrelay_addr = \"5.6.7.8:4444\"\nallowed_cidrs = [\"192.168.1.0/24\"]\n");
        validate_network(&parse(&s)).unwrap();
    }

    #[test]
    fn a_secret_is_optional_but_not_empty() {
        let s = base().replace("secret = \"s\"\npool", "pool");
        validate_network(&parse(&s)).expect("managed store may hold it");
        assert!(validate_network(&parse(&base().replace("secret = \"s\"\npool", "secret = \"\"\npool"))).is_err());
    }

    #[test]
    fn settings_are_bounds_checked() {
        let mut s = base();
        s.push_str("[settings]\ncredential_ttl_mins = 0\n");
        assert!(validate_network(&parse(&s)).is_err());
        let mut s = base();
        s.push_str("[settings]\nmtu = 100\n");
        assert!(validate_network(&parse(&s)).is_err());
    }
}
