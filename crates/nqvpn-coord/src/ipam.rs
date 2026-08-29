//! Pooled IPAM (§3.1): named pools, preferred/reserved addresses,
//! config-static assignments. Assignments are sticky (stored in the
//! registry by the caller) and re-issued verbatim on rejoin.

use ipnet::IpNet;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::NetworkConfig;
use crate::error::ApiError;
use crate::registry::Registry;

#[derive(Debug)]
pub struct Granted {
    pub ip4: Option<Ipv4Addr>,
    pub ip6: Option<Ipv6Addr>,
}

/// Allocate (or validate a preferred) address pair for `member`.
/// The caller holds the network lock and commits the registry after.
pub fn allocate(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    member: &str,
    pool: Option<&str>,
    preferred4: Option<Ipv4Addr>,
    preferred6: Option<Ipv6Addr>,
) -> Result<Granted, ApiError> {
    // Pool pin from config must be honored by the request.
    let member_cfg = cfg
        .clients
        .get(member)
        .or_else(|| cfg.relays.get(member))
        .expect("caller verified membership");
    let effective_pool = match (pool, member_cfg.pool.as_deref()) {
        (Some(req), Some(pinned)) if req != pinned => {
            return Err(ApiError::bad_request(format!(
                "member is pinned to pool {pinned:?}, requested {req:?}"
            )))
        }
        (Some(req), _) => Some(req),
        (None, pinned) => pinned,
    };
    if let Some(p) = effective_pool {
        if !cfg.pools.contains_key(p) {
            return Err(ApiError::unknown_pool(format!("pool {p:?} does not exist")));
        }
    }

    // Reserved set: everything assigned in the registry plus every
    // config-preferred address of OTHER members.
    let mut taken4: BTreeSet<Ipv4Addr> = reg.assigned4().collect();
    let mut taken6: BTreeSet<Ipv6Addr> = reg.assigned6().collect();
    for (name, m) in cfg.clients.iter().chain(cfg.relays.iter()) {
        if name == member {
            continue;
        }
        if let Some(ip) = m.preferred_ip4 {
            taken4.insert(ip);
        }
        if let Some(ip) = m.preferred_ip6 {
            taken6.insert(ip);
        }
    }
    // The member's own current assignment never conflicts with itself.
    if let Some(rec) = reg.members.get(member) {
        if let Some(ip) = rec.ip4 {
            taken4.remove(&ip);
        }
        if let Some(ip) = rec.ip6 {
            taken6.remove(&ip);
        }
    }

    // Effective preferred: request wins, else config static.
    let want4 = preferred4.or(member_cfg.preferred_ip4);
    let want6 = preferred6.or(member_cfg.preferred_ip6);

    let ip4 = match want4 {
        Some(ip) => {
            check_in_network(cfg, IpAddr::V4(ip))?;
            if taken4.contains(&ip) {
                return Err(ApiError::address_in_use(format!("{ip} is already assigned")));
            }
            Some(ip)
        }
        None => alloc_v4(cfg, reg, &taken4, effective_pool)?,
    };
    let has_v6 = cfg.cidrs.iter().any(|c| matches!(c, IpNet::V6(_)));
    let ip6 = match want6 {
        Some(ip) => {
            check_in_network(cfg, IpAddr::V6(ip))?;
            if taken6.contains(&ip) {
                return Err(ApiError::address_in_use(format!("{ip} is already assigned")));
            }
            Some(ip)
        }
        // v6 is best-effort: only when the network defines v6 space
        // and a v6 pool exists (or none requested — stay silent).
        None if has_v6 => alloc_v6(cfg, reg, &taken6, effective_pool).ok().flatten(),
        None => None,
    };
    Ok(Granted { ip4, ip6 })
}

fn check_in_network(cfg: &NetworkConfig, ip: IpAddr) -> Result<(), ApiError> {
    if cfg.cidrs.iter().any(|c| c.contains(&ip)) {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!("{ip} is outside the network cidrs")))
    }
}

/// Scan a pool starting at its cursor and wrapping, so addresses cycle
/// forward instead of the lowest free one being reissued immediately.
fn scan_from_cursor<T: Copy + Ord>(
    hosts: Vec<T>,
    taken: &BTreeSet<T>,
    cursor: u64,
) -> Option<(T, u64)> {
    if hosts.is_empty() {
        return None;
    }
    let n = hosts.len() as u64;
    let start = cursor % n;
    for step in 0..n {
        let idx = ((start + step) % n) as usize;
        if !taken.contains(&hosts[idx]) {
            // Next allocation resumes after this one, wrapping naturally.
            return Some((hosts[idx], (idx as u64 + 1) % n));
        }
    }
    None
}

fn alloc_v4(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    taken: &BTreeSet<Ipv4Addr>,
    pool: Option<&str>,
) -> Result<Option<Ipv4Addr>, ApiError> {
    let mut candidates: Vec<(&String, &IpNet)> = cfg
        .pools
        .iter()
        .filter(|(_, p)| matches!(p.cidr, IpNet::V4(_)))
        .map(|(n, p)| (n, &p.cidr))
        .collect();
    if let Some(want) = pool {
        candidates.retain(|(n, _)| n.as_str() == want);
        if candidates.is_empty() {
            return Err(ApiError::unknown_pool(format!("pool {want:?} has no IPv4 range")));
        }
    }
    if candidates.is_empty() {
        return Err(ApiError::pool_exhausted("no IPv4 pool defined".to_string()));
    }
    for (name, net) in &candidates {
        if let IpNet::V4(v4net) = net {
            let hosts: Vec<Ipv4Addr> = v4net.hosts().collect();
            let cursor = reg.alloc_cursor.get(name.as_str()).copied().unwrap_or(0);
            if let Some((ip, next)) = scan_from_cursor(hosts, taken, cursor) {
                reg.alloc_cursor.insert((*name).clone(), next);
                return Ok(Some(ip));
            }
        }
    }
    Err(ApiError::pool_exhausted(match pool {
        Some(p) => format!("pool {p:?} has no free IPv4 address"),
        None => "all IPv4 pools are exhausted".to_string(),
    }))
}

fn alloc_v6(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    taken: &BTreeSet<Ipv6Addr>,
    pool: Option<&str>,
) -> Result<Option<Ipv6Addr>, ApiError> {
    let mut candidates: Vec<(&String, &IpNet)> = cfg
        .pools
        .iter()
        .filter(|(_, p)| matches!(p.cidr, IpNet::V6(_)))
        .map(|(n, p)| (n, &p.cidr))
        .collect();
    if let Some(want) = pool {
        // Pools are per-family, so a pin only constrains its own family:
        // a member pinned to a v4 pool still gets v6 from any v6 pool
        // rather than silently losing dual-stack.
        if candidates.iter().any(|(n, _)| n.as_str() == want) {
            candidates.retain(|(n, _)| n.as_str() == want);
        }
    }
    for (name, net) in &candidates {
        if let IpNet::V6(v6net) = net {
            // hosts() on a big v6 net is an enormous iterator; cap the
            // scan. Unlike v4 it also yields the network address, which
            // is reserved for subnet-router anycast.
            let hosts: Vec<Ipv6Addr> = v6net
                .hosts()
                .take(100_000)
                .filter(|ip| *ip != v6net.network())
                .collect();
            let key = format!("{name}/v6");
            let cursor = reg.alloc_cursor.get(&key).copied().unwrap_or(0);
            if let Some((ip, next)) = scan_from_cursor(hosts, taken, cursor) {
                reg.alloc_cursor.insert(key, next);
                return Ok(Some(ip));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;

    fn cfg() -> NetworkConfig {
        toml::from_str(
            r#"
network_id = "n1"
cidrs = ["10.99.0.0/16", "fd99::/64"]
[pools.default]
cidr = "10.99.1.0/30"
[pools.servers]
cidr = "10.99.2.0/24"
[pools.v6]
cidr = "fd99::1:0/126"
[clients.c1]
secret_hash = "x"
[clients.c2]
secret_hash = "x"
[clients.pinned]
secret_hash = "x"
pool = "servers"
[relays.r1]
secret_hash = "x"
relay_addr = "1.2.3.4:1"
preferred_ip4 = "10.99.0.1"
"#,
        )
        .unwrap()
    }

    #[test]
    fn sequential_pool_allocation() {
        let c = cfg();
        let mut reg = Registry::new();
        let g = allocate(&c, &mut reg, "c1", Some("default"), None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.1".parse().unwrap()));
    }

    #[test]
    fn pool_exhaustion() {
        let c = cfg();
        let mut reg = Registry::new();
        // /30 has hosts .1 and .2
        reg.member_mut("a", 1).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut("b", 1).ip4 = Some("10.99.1.2".parse().unwrap());
        let err = allocate(&c, &mut reg, "c1", Some("default"), None, None).unwrap_err();
        assert_eq!(err.code.as_str(), "pool_exhausted");
    }

    #[test]
    fn any_pool_when_unspecified() {
        let c = cfg();
        let mut reg = Registry::new();
        reg.member_mut("a", 1).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut("b", 1).ip4 = Some("10.99.1.2".parse().unwrap());
        // default is full; falls over to servers pool
        let g = allocate(&c, &mut reg, "c1", None, None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.2.1".parse().unwrap()));
    }

    #[test]
    fn preferred_outside_pools_ok_inside_network() {
        let c = cfg();
        let mut reg = Registry::new();
        let g =
            allocate(&c, &mut reg, "c1", None, Some("10.99.50.7".parse().unwrap()), None).unwrap();
        assert_eq!(g.ip4, Some("10.99.50.7".parse().unwrap()));
    }

    #[test]
    fn preferred_conflict_rejected() {
        let c = cfg();
        let mut reg = Registry::new();
        reg.member_mut("other", 1).ip4 = Some("10.99.50.7".parse().unwrap());
        let err = allocate(&c, &mut reg, "c1", None, Some("10.99.50.7".parse().unwrap()), None)
            .unwrap_err();
        assert_eq!(err.code.as_str(), "address_in_use");
    }

    #[test]
    fn config_preferred_of_other_member_is_reserved() {
        let c = cfg();
        let mut reg = Registry::new();
        // r1's config reserves 10.99.0.1 even though r1 never joined.
        let err = allocate(&c, &mut reg, "c1", None, Some("10.99.0.1".parse().unwrap()), None)
            .unwrap_err();
        assert_eq!(err.code.as_str(), "address_in_use");
    }

    #[test]
    fn pinned_pool_mismatch_rejected() {
        let c = cfg();
        let mut reg = Registry::new();
        let err = allocate(&c, &mut reg, "pinned", Some("default"), None, None).unwrap_err();
        assert_eq!(err.code.as_str(), "bad_request");
        let ok = allocate(&c, &mut reg, "pinned", None, None, None).unwrap();
        assert_eq!(ok.ip4, Some("10.99.2.1".parse().unwrap()));
    }

    /// A freed address must not go straight back out. The allocator
    /// cycles forward through the pool and wraps, so reuse happens only
    /// after a full lap — the DHCP behaviour operators expect.
    #[test]
    fn a_released_address_is_not_immediately_reissued() {
        let c = cfg();
        let mut reg = Registry::new();
        // Fill the whole /30 pool: hosts .1 and .2.
        let a = allocate(&c, &mut reg, "c1", Some("default"), None, None).unwrap();
        reg.member_mut("c1", 1).ip4 = a.ip4;
        let b = allocate(&c, &mut reg, "c2", Some("default"), None, None).unwrap();
        reg.member_mut("c2", 1).ip4 = b.ip4;
        assert_ne!(a.ip4, b.ip4);
        assert_eq!(a.ip4, Some("10.99.1.1".parse().unwrap()));
        assert_eq!(b.ip4, Some("10.99.1.2".parse().unwrap()));

        // An admin removes the FIRST member, freeing .1 — the lowest
        // free address. A naive allocator would hand it straight over.
        reg.members.remove("c1");
        let next = allocate(&c, &mut reg, "c1", Some("default"), None, None).unwrap();
        assert_eq!(
            next.ip4,
            Some("10.99.1.1".parse().unwrap()),
            "with only one address free the cursor must still find it"
        );

        // With room to move, the cursor keeps going forward instead of
        // backfilling the hole.
        let wide: NetworkConfig = toml::from_str(
            r#"
network_id = "n2"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/28"
[clients.x]
secret_hash = "x"
"#,
        )
        .unwrap();
        let mut r2 = Registry::new();
        let mut seen = Vec::new();
        for i in 0..4 {
            let g = allocate(&wide, &mut r2, "x", None, None, None).unwrap();
            let ip = g.ip4.unwrap();
            seen.push(ip);
            r2.member_mut(&format!("m{i}"), 1).ip4 = Some(ip);
        }
        // Free the first one, then allocate again: the cursor has moved
        // past it, so the new member gets a fresh address.
        r2.members.remove("m0");
        let after = allocate(&wide, &mut r2, "x", None, None, None).unwrap().ip4.unwrap();
        assert_ne!(after, seen[0], "the just-freed address was reissued immediately");
        assert!(!seen.contains(&after), "allocator moved forward to unused space");
    }

    #[test]
    fn cursor_survives_a_coordinator_restart() {
        let c = cfg();
        let mut reg = Registry::new();
        allocate(&c, &mut reg, "c1", Some("default"), None, None).unwrap();
        let cursor = reg.alloc_cursor.clone();
        assert!(!cursor.is_empty(), "allocation advanced a cursor");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.json");
        reg.commit(&path).unwrap();
        let back = Registry::load_or_create(&path).unwrap();
        assert_eq!(
            back.alloc_cursor, cursor,
            "a restart must not reset the cursor, or reuse starts over"
        );
    }

    #[test]
    fn v4_pool_pin_does_not_suppress_v6() {
        let c = cfg();
        let mut reg = Registry::new();
        // "pinned" is pinned to the v4-only pool "servers"; it must still
        // receive an IPv6 address from the v6 pool.
        let g = allocate(&c, &mut reg, "pinned", None, None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.2.1".parse().unwrap()));
        assert_eq!(g.ip6, Some("fd99::1:1".parse().unwrap()));
    }

    #[test]
    fn unknown_pool_rejected() {
        let c = cfg();
        let mut reg = Registry::new();
        let err = allocate(&c, &mut reg, "c1", Some("nope"), None, None).unwrap_err();
        assert_eq!(err.code.as_str(), "unknown_pool");
    }

    #[test]
    fn preferred_outside_network_rejected() {
        let c = cfg();
        let mut reg = Registry::new();
        let err = allocate(&c, &mut reg, "c1", None, Some("192.168.9.9".parse().unwrap()), None)
            .unwrap_err();
        assert_eq!(err.code.as_str(), "bad_request");
    }

    #[test]
    fn v6_allocated_alongside_v4() {
        let c = cfg();
        let mut reg = Registry::new();
        let g = allocate(&c, &mut reg, "c1", None, None, None).unwrap();
        assert!(g.ip4.is_some());
        assert_eq!(g.ip6, Some("fd99::1:1".parse().unwrap()));
    }
}
