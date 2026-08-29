//! Configuration. The process-level part (`coordinator.toml`: where to
//! listen, TLS, the database, the admin token) is the only file. Every
//! network — its address space, settings, members — lives in the
//! database and is edited in the UI; the structs here are its in-memory
//! shape, and `validate_network` is the one rule set every change must
//! pass before it is committed.
//!
//! A member is a **name + secret**. The secret is generated, never
//! chosen, and is all a machine ever holds (inside its token). Nothing
//! else authenticates.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use nqvpn_proto::lpm::overlaps;
use nqvpn_proto::types::Role;
use serde::{Deserialize, Serialize};
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
    /// The URL members reach this coordinator at, written into every
    /// token. Unset: the URL the operator's browser used for the UI.
    #[serde(default)]
    pub public_url: Option<String>,
    /// The UDP port members should dial for the control plane, when it
    /// differs from `quic`'s (a port-forward). Members dial the host of
    /// their token's URL on this port.
    #[serde(default)]
    pub public_quic_port: Option<u16>,
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
    /// Holds `nqvpn.db` (networks, members, secrets, registries), the
    /// credential signing key and the auto-generated certificate.
    pub dir: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdminCfg {
    /// UI login. Either the argon2 hash (`nqvpn-coord hash-password`)
    /// or, for convenience, the password in the clear; the clear one is
    /// hashed in memory at startup and never used directly.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password_hash: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    /// A static token for scripts (`Authorization: Bearer ...`).
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    /// UI session lifetime.
    #[serde(default = "d_session_hours")]
    pub session_hours: u64,
}

fn d_session_hours() -> u64 {
    12
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    pub network_id: String,
    /// Tunnel address space: what auto-allocation draws from and what
    /// every member routes into the tunnel. Configured addresses may
    /// lie outside it; they are routed as host prefixes.
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolCfg {
    pub cidr: IpNet,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCfg {
    /// Generated at creation, rotated on request. `None` only for a
    /// member that was imported without one; it cannot join until it
    /// is rotated.
    #[serde(default)]
    pub secret: Option<String>,
    /// Relays only: the address the fleet and clients dial, or
    /// `auto:<port>` for "wherever this relay joins from".
    #[serde(default)]
    pub relay_addr: Option<String>,
    /// Relays only: LAN prefixes this relay routes. Accepted as declared
    /// when they conflict with nothing; two relays declaring the same
    /// prefix are a failover pair.
    #[serde(default)]
    pub local_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub preferred_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<Ipv6Addr>,
    /// Pin auto-allocation to this pool.
    #[serde(default)]
    pub pool: Option<String>,
    /// Default true; false is a headless member (relays: pure forwarder).
    #[serde(default)]
    pub want_vpn_ip: Option<bool>,
    #[serde(default)]
    pub max_session_mbps: Option<u32>,
    /// Clients only: the relay to attach to when reachable.
    #[serde(default)]
    pub preferred_relay: Option<String>,
}

impl NetworkConfig {
    pub fn member_by_name(&self, name: &str) -> Option<(&MemberCfg, Role)> {
        self.clients
            .get(name)
            .map(|m| (m, Role::Client))
            .or_else(|| self.relays.get(name).map(|m| (m, Role::Relay)))
    }

    pub fn member_by_name_mut(&mut self, name: &str) -> Option<(&mut MemberCfg, Role)> {
        if let Some(m) = self.clients.get_mut(name) {
            return Some((m, Role::Client));
        }
        self.relays.get_mut(name).map(|m| (m, Role::Relay))
    }

    /// Every member: (name, config, role), clients then relays.
    pub fn members(&self) -> impl Iterator<Item = (&String, &MemberCfg, Role)> {
        self.clients
            .iter()
            .map(|(n, m)| (n, m, Role::Client))
            .chain(self.relays.iter().map(|(n, m)| (n, m, Role::Relay)))
    }

    pub fn insert_member(&mut self, name: &str, role: Role, m: MemberCfg) {
        match role {
            Role::Client => self.clients.insert(name.to_string(), m),
            Role::Relay => self.relays.insert(name.to_string(), m),
        };
    }

    pub fn remove_member(&mut self, name: &str) -> bool {
        self.clients.remove(name).is_some() || self.relays.remove(name).is_some()
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
            if m.relay_addr.is_some() || !m.local_cidrs.is_empty() || m.max_session_mbps.is_some() {
                bail!("client {name}: relay_addr/local_cidrs/max_session_mbps are relay-only fields");
            }
        } else {
            if m.preferred_relay.is_some() {
                bail!("relay {name}: preferred_relay is a client-only field");
            }
            let addr = m
                .relay_addr
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("relay {name}: relay_addr is required"))?;
            validate_relay_addr(name, addr, cfg)?;
            for c in &m.local_cidrs {
                if c.addr() != c.network() {
                    bail!("relay {name}: local cidr {c} is not a network address (did you mean {}?)", c.trunc());
                }
                for t in &cfg.cidrs {
                    if overlaps(c, t) {
                        bail!("relay {name}: local cidr {c} overlaps tunnel space {t}");
                    }
                }
                // Other members' prefixes: identical is a failover pair;
                // partial overlap would make routing ambiguous.
                for (other, om, _) in cfg.members() {
                    if other == name {
                        continue;
                    }
                    for oc in &om.local_cidrs {
                        if overlaps(c, oc) && c.trunc() != oc.trunc() {
                            bail!("relay {name}: local cidr {c} partially overlaps {oc} routed by {other}");
                        }
                    }
                    for ip in [om.preferred_ip4.map(IpAddr::V4), om.preferred_ip6.map(IpAddr::V6)].into_iter().flatten() {
                        if c.contains(&ip) {
                            bail!("relay {name}: local cidr {c} contains {other}'s address {ip}");
                        }
                    }
                }
            }
        }
        if let Some(pool) = &m.pool {
            if !cfg.pools.contains_key(pool) {
                bail!("member {name}: unknown pool {pool:?}");
            }
        }
        if let Some(p) = &m.preferred_relay {
            if !cfg.relays.contains_key(p) {
                bail!("member {name}: preferred relay {p:?} is not a relay of this network");
            }
        }
        // Addresses need not lie inside the tunnel cidrs (they are
        // routed as host prefixes); they must be unique and routable.
        if let Some(ip) = m.preferred_ip4 {
            if unroutable(IpAddr::V4(ip)) {
                bail!("member {name}: preferred_ip4 {ip} is not a usable address");
            }
            if let Some(prev) = seen4.insert(ip, name.clone()) {
                bail!("preferred_ip4 {ip} claimed by both {prev} and {name}");
            }
        }
        if let Some(ip) = m.preferred_ip6 {
            if unroutable(IpAddr::V6(ip)) {
                bail!("member {name}: preferred_ip6 {ip} is not a usable address");
            }
            if let Some(prev) = seen6.insert(ip, name.clone()) {
                bail!("preferred_ip6 {ip} claimed by both {prev} and {name}");
            }
        }
    }
    Ok(())
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
    if let Some(port) = addr.strip_prefix("auto:") {
        port.parse::<u16>()
            .map_err(|_| anyhow::anyhow!("relay {name}: relay_addr {addr:?} must be auto:<port>"))?;
        return Ok(());
    }
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
            .flat_map(|m| m.local_cidrs.iter())
            .any(|c| c.contains(&ip));
        if in_lan {
            bail!("relay {name}: relay_addr {addr:?} ({ip}) lies inside a routed LAN prefix");
        }
    }
    Ok(())
}

/// Resolve a clear-text `password` into `password_hash` so the rest of
/// the coordinator only ever sees a hash. The hash wins if both exist.
pub fn resolve_admin_password(cfg: &mut AdminCfg) -> Result<()> {
    if cfg.password_hash.is_some() {
        if cfg.password.is_some() {
            tracing::warn!("[admin] has both password and password_hash; using password_hash");
        }
        return Ok(());
    }
    if let Some(pw) = cfg.password.take() {
        if pw.trim().is_empty() {
            bail!("[admin] password must not be empty");
        }
        tracing::warn!("[admin] password is in the clear in the config; prefer password_hash (nqvpn-coord hash-password)");
        cfg.password_hash = Some(crate::auth::hash_password(&pw).map_err(|e| anyhow::anyhow!("hashing admin password: {e}"))?);
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
local_cidrs = ["192.168.1.0/24"]
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
    fn local_cidr_overlapping_tunnel_fails() {
        assert!(validate_network(&parse(&base().replace("192.168.1.0/24", "10.99.5.0/24"))).is_err());
    }

    #[test]
    fn identical_local_cidrs_across_relays_ok_for_failover_but_partial_overlap_fails() {
        let mut s = base();
        s.push_str("[relays.r2]\nrelay_addr = \"5.6.7.8:4444\"\nlocal_cidrs = [\"192.168.1.0/24\"]\n");
        validate_network(&parse(&s)).unwrap();
        let mut s = base();
        s.push_str("[relays.r2]\nrelay_addr = \"5.6.7.8:4444\"\nlocal_cidrs = [\"192.168.1.128/25\"]\n");
        assert!(validate_network(&parse(&s)).is_err());
        let mut s = base();
        s.push_str("[relays.r2]\nrelay_addr = \"5.6.7.8:4444\"\nlocal_cidrs = [\"192.168.2.1/24\"]\n");
        assert!(validate_network(&parse(&s)).is_err(), "not a network address");
    }

    #[test]
    fn addresses_may_lie_outside_the_tunnel_cidrs_but_must_be_usable_and_unique() {
        validate_network(&parse(&base().replace("10.99.0.1", "172.20.0.7"))).unwrap();
        assert!(validate_network(&parse(&base().replace("10.99.0.1", "127.0.0.1"))).is_err());
        assert!(validate_network(&parse(&base().replace("10.99.0.1", "192.168.1.7"))).is_ok(), "inside its own LAN is fine");
        let mut s = base();
        s.push_str("[clients.c2]\npreferred_ip4 = \"192.168.1.9\"\n");
        assert!(validate_network(&parse(&s)).is_err(), "inside another member's routed LAN is not");
    }

    #[test]
    fn relay_addr_may_be_auto_with_a_port() {
        validate_network(&parse(&base().replace("1.2.3.4:4444", "auto:4444"))).unwrap();
        assert!(validate_network(&parse(&base().replace("1.2.3.4:4444", "auto:x"))).is_err());
    }

    #[test]
    fn a_secret_is_optional_but_not_empty() {
        let s = base().replace("secret = \"s\"\npool", "pool");
        validate_network(&parse(&s)).expect("an imported member may have none yet");
        assert!(validate_network(&parse(&base().replace("secret = \"s\"\npool", "secret = \"\"\npool"))).is_err());
    }

    #[test]
    fn preferred_relay_must_name_a_relay() {
        let mut s = base();
        s.push_str("[clients.c2]\npreferred_relay = \"r1\"\n[clients.c3]\npreferred_relay = \"nope\"\n");
        assert!(validate_network(&parse(&s)).is_err());
        let mut s = base();
        s.push_str("[clients.c2]\npreferred_relay = \"r1\"\n");
        validate_network(&parse(&s)).unwrap();
    }

    #[test]
    fn the_shipped_sample_config_is_valid_and_round_trips_as_json() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../configs");
        let c = load_coord_config(&root.join("coordinator.toml")).expect("coordinator.toml");
        assert_eq!(c.admin.user.as_deref(), Some("admin"));
        assert!(c.admin.password_hash.is_some());
        let cfg = parse(&base());
        let json = serde_json::to_string(&cfg).unwrap();
        let back: NetworkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.relays["r1"].local_cidrs, cfg.relays["r1"].local_cidrs);
        assert_eq!(back.settings.mtu, cfg.settings.mtu);
    }

    #[test]
    fn a_clear_text_admin_password_becomes_a_hash() {
        let mut a = AdminCfg { user: Some("admin".into()), password: Some("hunter2".into()), ..Default::default() };
        resolve_admin_password(&mut a).unwrap();
        assert!(a.password.is_none(), "the clear text is dropped");
        assert!(crate::auth::verify_password("hunter2", a.password_hash.as_deref().unwrap()));
        let mut e = AdminCfg { password: Some("  ".into()), ..Default::default() };
        assert!(resolve_admin_password(&mut e).is_err());
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
