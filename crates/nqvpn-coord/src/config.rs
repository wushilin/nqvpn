//! Coordinator + per-network config loading and validation (§3.1, §3.2).
//! The operator's TOML is the plan of record; validation failures are
//! planning bugs and fail startup (or leave the old config running on
//! reload).

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use nqvpn_proto::lpm::overlaps;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordConfig {
    pub listen: ListenCfg,
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
    pub api: String,
    #[serde(default)]
    pub quic: Option<String>,
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
    /// name -> argon2 hash (UI sessions; Phase 6).
    #[serde(default)]
    pub users: BTreeMap<String, String>,
    #[serde(default)]
    pub bearer_token: Option<String>,
    #[serde(default)]
    pub bearer_token_file: Option<String>,
    #[serde(default = "default_session_ttl")]
    pub session_ttl_mins: u64,
}

fn default_session_ttl() -> u64 {
    720
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
    10
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
    #[serde(default = "d_keepalive")]
    pub keepalive_secs: u16,
    #[serde(default = "d_offline_after")]
    pub offline_after: u32,
    #[serde(default = "d_hold_down")]
    pub hold_down_secs: u64,
    #[serde(default = "d_mtu")]
    pub mtu: u16,
    /// What to do when a joining relay's advertised address cannot be
    /// dialed from the coordinator (§3.2):
    ///   "off"   - do not probe at all
    ///   "warn"  - probe, record, log loudly, allow the join (default)
    ///   "deny"  - refuse the join with `relay_unreachable`
    /// Denial is opt-in because the probe is advisory: the coordinator's
    /// vantage point is not every peer's, and a source-specific firewall
    /// could reject us while the fleet reaches the relay fine.
    #[serde(default = "d_reach_policy")]
    pub relay_reachability: String,
    /// How tunneled packets cross QUIC: "datagram" (default) or
    /// "stream". A network-wide setting so every member agrees without
    /// negotiating; flip it and restart members to A/B the two.
    #[serde(default = "d_transport")]
    pub transport: String,
    /// Parallel streams the stream transport spreads flows across (§5).
    ///
    /// One stream means one stalled segment blocks every tunneled flow
    /// behind it. Endpoints hash the inner 5-tuple to pick a lane, so a
    /// flow stays on one ordered pipe while unrelated flows stop waiting
    /// on each other. Ignored in datagram mode, which has no streams.
    #[serde(default = "d_lanes")]
    pub lanes: u8,
}

impl Default for SettingsCfg {
    fn default() -> Self {
        SettingsCfg {
            credential_ttl_mins: d_ttl(),
            keepalive_secs: d_keepalive(),
            offline_after: d_offline_after(),
            hold_down_secs: d_hold_down(),
            mtu: d_mtu(),
            relay_reachability: d_reach_policy(),
            transport: d_transport(),
            lanes: d_lanes(),
        }
    }
}

fn d_ttl() -> u64 {
    15
}
fn d_keepalive() -> u16 {
    15
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
    // One lane by default — not because lanes are wrong, but because
    // their benefit is unproven on the paths measured so far and their
    // cost is not: each lane is a stream, a task, and a share of the
    // send queue, paid per connection, and a relay pays it for every
    // session it carries.
    //
    // Lanes remove head-of-line blocking between flows, so they should
    // pay where a single flow *cannot* fill the pipe and loss is the
    // limiter — long-haul or multipath links. On links a single flow
    // already saturates there is no blocking to recover and the extra
    // streams only add contention. Raise it per network where the
    // former describes the path, and measure.
    //
    // Only stream mode uses this; datagram mode has no streams.
    1
}
fn d_transport() -> String {
    // Measured, not assumed: on a real consumer uplink streams reached
    // 87 Mbit/s against datagrams' 54, because QUIC repairs loss beneath
    // the inner TCP instead of making it recover across an RTT. The
    // design argued for datagrams on head-of-line-blocking grounds, and
    // that still wins for many parallel flows over a clean backbone —
    // hence the per-network setting rather than a single answer.
    "stream".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberCfg {
    pub secret_hash: String,
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
    /// Pre-provisioned TOFU pin (base64 x25519 pubkey).
    ///
    /// Setting this removes trust-on-first-use for the member entirely:
    /// the very first join must present this key, so claiming a name you
    /// do not hold the key for fails immediately rather than succeeding
    /// once and locking the real member out.
    #[serde(default)]
    pub pinned_pubkey: Option<String>,
    /// Operator-assigned node id. Left unset the coordinator allocates
    /// one monotonically; set, it is authoritative for this member.
    ///
    /// The id is the data-plane identity — it is what peers address in
    /// frames — so it is only honoured when the member is first created.
    /// Renumbering a live member would strand every cached route and
    /// session that already refers to the old id.
    #[serde(default)]
    pub node_id: Option<nqvpn_proto::types::NodeId>,
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
    if !matches!(cfg.settings.relay_reachability.as_str(), "off" | "warn" | "deny") {
        bail!(
            "network {}: relay_reachability must be \"off\", \"warn\", or \"deny\" (got {:?})",
            cfg.network_id,
            cfg.settings.relay_reachability
        );
    }
    if !matches!(cfg.settings.transport.as_str(), "datagram" | "stream") {
        bail!(
            "network {}: transport must be \"datagram\" or \"stream\" (got {:?})",
            cfg.network_id,
            cfg.settings.transport
        );
    }
    if cfg.settings.lanes == 0
        || cfg.settings.lanes > nqvpn_proto::transport::MAX_LANES
    {
        bail!(
            "network {}: lanes must be between 1 and {} (got {})",
            cfg.network_id,
            nqvpn_proto::transport::MAX_LANES,
            cfg.settings.lanes
        );
    }
    // A node id is the wire identity. Two members sharing one would make
    // frames for either deliverable to the other, so this has to be an
    // error at load rather than something discovered on the data plane.
    let mut seen_ids: std::collections::HashMap<nqvpn_proto::types::NodeId, &str> =
        std::collections::HashMap::new();
    // Likewise a shared pinned key: it would let one member authenticate
    // as the other, which is exactly what pinning is meant to prevent.
    let mut seen_keys: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (name, m) in cfg.clients.iter().chain(cfg.relays.iter()) {
        if let Some(id) = m.node_id {
            if id == 0 {
                bail!("network {}: member {name}: node_id must not be 0", cfg.network_id);
            }
            if let Some(other) = seen_ids.insert(id, name) {
                bail!(
                    "network {}: node_id {id} is assigned to both {other} and {name}",
                    cfg.network_id
                );
            }
        }
        if let Some(k) = m.pinned_pubkey.as_deref() {
            if let Some(other) = seen_keys.insert(k, name) {
                bail!(
                    "network {}: members {other} and {name} share a pinned_pubkey, so either \
                     could authenticate as the other",
                    cfg.network_id
                );
            }
        }
    }
    if cfg.cidrs.is_empty() {
        bail!("network {}: cidrs must not be empty", cfg.network_id);
    }
    if !cfg.cidrs.iter().any(|c| matches!(c, IpNet::V4(_))) {
        bail!("network {}: at least one IPv4 tunnel cidr is required", cfg.network_id);
    }
    // Network cidrs must not overlap each other.
    for (i, a) in cfg.cidrs.iter().enumerate() {
        for b in cfg.cidrs.iter().skip(i + 1) {
            if overlaps(a, b) {
                bail!("network cidrs overlap: {a} vs {b}");
            }
        }
    }
    // Pools: inside a network cidr, pairwise disjoint.
    let pools: Vec<(&String, &PoolCfg)> = cfg.pools.iter().collect();
    for (name, p) in &pools {
        if !cfg.cidrs.iter().any(|c| c.contains(&p.cidr.network()) && overlaps(c, &p.cidr)) {
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
    // Member namespace is shared between clients and relays.
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

/// Endpoint validation (§3.2 / decision record): reject loopback,
/// unspecified, multicast, link-local, and anything inside VPN-routed
/// space. Hostnames are allowed (resolved by dialers, not here).
fn validate_relay_addr(name: &str, addr: &str, cfg: &NetworkConfig) -> Result<()> {
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("relay {name}: relay_addr {addr:?} must be host:port"))?;
    port.parse::<u16>()
        .map_err(|_| anyhow::anyhow!("relay {name}: bad port in relay_addr {addr:?}"))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        let bad = match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_unspecified() || v4.is_multicast() || v4.is_link_local()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        };
        if bad {
            bail!("relay {name}: relay_addr {addr:?} uses an unroutable address class");
        }
        if cfg.cidrs.iter().any(|c| c.contains(&ip)) {
            bail!("relay {name}: relay_addr {addr:?} lies inside tunnel space");
        }
        let in_lan = cfg
            .relays
            .values()
            .chain(cfg.clients.values())
            .flat_map(|m| m.allowed_cidrs.iter())
            .any(|c| c.contains(&ip));
        if in_lan {
            bail!("relay {name}: relay_addr {addr:?} lies inside a routed LAN prefix");
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
secret_hash = "$argon2id$x"
relay_addr = "1.2.3.4:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
[clients.c1]
secret_hash = "$argon2id$x"
pool = "default"
"#
        .to_string()
    }

    fn parse(s: &str) -> NetworkConfig {
        toml::from_str(s).unwrap()
    }

    #[test]
    fn valid_config_passes() {
        validate_network(&parse(&base())).unwrap();
    }

    #[test]
    fn reachability_policy_is_validated() {
        let mut s = base();
        s.push_str("[settings]\nrelay_reachability = \"nonsense\"\n");
        assert!(validate_network(&parse(&s)).is_err());
        for ok in ["off", "warn", "deny"] {
            let mut s = base();
            s.push_str(&format!("[settings]\nrelay_reachability = \"{ok}\"\n"));
            validate_network(&parse(&s)).unwrap();
        }
        // Default is the advisory one.
        assert_eq!(parse(&base()).settings.relay_reachability, "warn");
    }

    #[test]
    fn pool_outside_cidrs_fails() {
        let cfg = parse(&base().replace("10.99.1.0/24", "10.200.0.0/24"));
        assert!(validate_network(&cfg).is_err());
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
        s.push_str("[clients.c2]\nsecret_hash = \"x\"\nrelay_addr = \"1.1.1.1:1\"\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn relay_without_addr_fails() {
        let mut s = base();
        s.push_str("[relays.r2]\nsecret_hash = \"x\"\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn relay_addr_in_tunnel_space_fails() {
        let cfg = parse(&base().replace("1.2.3.4:4444", "10.99.0.7:4444"));
        assert!(validate_network(&cfg).is_err());
    }

    #[test]
    fn relay_addr_loopback_fails() {
        let cfg = parse(&base().replace("1.2.3.4:4444", "127.0.0.1:4444"));
        assert!(validate_network(&cfg).is_err());
    }

    #[test]
    fn duplicate_preferred_ip_fails() {
        let mut s = base();
        s.push_str("[clients.c9]\nsecret_hash = \"x\"\npreferred_ip4 = \"10.99.0.1\"\n");
        assert!(validate_network(&parse(&s)).is_err());
    }

    #[test]
    fn allowed_cidr_overlapping_tunnel_fails() {
        let cfg = parse(&base().replace("192.168.1.0/24", "10.99.5.0/24"));
        assert!(validate_network(&cfg).is_err());
    }

    #[test]
    fn unknown_pool_fails() {
        let cfg = parse(&base().replace("pool = \"default\"", "pool = \"nope\""));
        assert!(validate_network(&cfg).is_err());
    }

    #[test]
    fn overlapping_allowed_cidrs_across_relays_ok_for_failover() {
        let mut s = base();
        s.push_str(
            "[relays.r2]\nsecret_hash = \"x\"\nrelay_addr = \"5.6.7.8:4444\"\nallowed_cidrs = [\"192.168.1.0/24\"]\n",
        );
        validate_network(&parse(&s)).unwrap();
    }

    #[test]
    fn duplicate_node_id_is_rejected() {
        // Two members sharing a wire identity would make frames for
        // either deliverable to the other — a load-time error, not
        // something to discover on the data plane.
        let mut s = base();
        s = s.replace("[clients.c1]", "node_id = 7\n[clients.c1]");
        s.push_str("node_id = 7\n");
        let err = validate_network(&parse(&s)).expect_err("duplicate node_id must fail");
        let msg = format!("{err}");
        assert!(msg.contains("node_id 7"), "{msg}");
        assert!(msg.contains("r1") && msg.contains("c1"), "must name both: {msg}");
    }

    #[test]
    fn distinct_node_ids_pass_and_zero_is_rejected() {
        let mut s = base();
        s = s.replace("[clients.c1]", "node_id = 7\n[clients.c1]");
        s.push_str("node_id = 8\n");
        validate_network(&parse(&s)).expect("distinct ids are fine");

        let mut z = base();
        z = z.replace("[clients.c1]", "node_id = 0\n[clients.c1]");
        assert!(validate_network(&parse(&z)).is_err(), "0 is not a valid node id");
    }

    #[test]
    fn node_id_is_optional() {
        // Unset must stay the default, or every existing config breaks.
        let cfg = parse(&base());
        assert!(cfg.relays["r1"].node_id.is_none());
        assert!(cfg.clients["c1"].node_id.is_none());
        validate_network(&cfg).unwrap();
    }

    #[test]
    fn a_shared_pinned_pubkey_is_rejected() {
        // Pinning exists to bind a name to a key. Two names on one key
        // means either can authenticate as the other, which defeats it.
        let mut s = base();
        s = s.replace("[clients.c1]", "pinned_pubkey = \"AAAA\"\n[clients.c1]");
        s.push_str("pinned_pubkey = \"AAAA\"\n");
        let err = validate_network(&parse(&s)).expect_err("shared pin must fail");
        assert!(format!("{err}").contains("pinned_pubkey"), "{err}");

        // Distinct pins are the normal, correct case.
        let mut ok = base();
        ok = ok.replace("[clients.c1]", "pinned_pubkey = \"AAAA\"\n[clients.c1]");
        ok.push_str("pinned_pubkey = \"BBBB\"\n");
        validate_network(&parse(&ok)).expect("distinct pins are fine");
    }
}
