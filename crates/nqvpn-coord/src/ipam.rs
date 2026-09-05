//! CIDR IPAM (§3.1): one range per address family, hard static
//! reservations, and soft dynamic reservations. A dynamic address follows
//! its member until its range is exhausted; then the longest-gone offline client's address
//! is reclaimed. Configured static addresses are never reclaimable.

use ipnet::IpNet;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::NetworkConfig;
use crate::error::ApiError;
use crate::leases::Leases;
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
    preferred4: Option<Ipv4Addr>,
    preferred6: Option<Ipv6Addr>,
) -> Result<Granted, ApiError> {
    allocate_inner(cfg, reg, None, member, preferred4, preferred6)
}

/// Production allocation with liveness information. During the
/// coordinator's restart grace period `allow_reclaim` is false: the fleet
/// has not had time to reconnect yet, so silence is not evidence that a
/// soft reservation is safely reusable.
pub fn allocate_for_join(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    leases: &Leases,
    allow_reclaim: bool,
    member: &str,
    preferred4: Option<Ipv4Addr>,
    preferred6: Option<Ipv6Addr>,
) -> Result<Granted, ApiError> {
    let reclaim = allow_reclaim.then_some(leases);
    allocate_inner(cfg, reg, reclaim, member, preferred4, preferred6)
}

fn allocate_inner(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    reclaim: Option<&Leases>,
    member: &str,
    preferred4: Option<Ipv4Addr>,
    preferred6: Option<Ipv6Addr>,
) -> Result<Granted, ApiError> {
    let (member_cfg, _) = cfg.member_by_name(member).expect("caller verified membership");

    // Hard reservations are configuration, not liveness. They can never
    // be handed to another member, including when an address happened to
    // have been allocated dynamically before it was configured static.
    let hard4: BTreeSet<Ipv4Addr> = cfg.members().filter_map(|(_, m, _)| m.preferred_ip4).collect();
    let hard6: BTreeSet<Ipv6Addr> = cfg.members().filter_map(|(_, m, _)| m.preferred_ip6).collect();

    // Taken starts with every durable soft reservation plus all static
    // reservations (including members that have never joined).
    let mut taken4: BTreeSet<Ipv4Addr> = reg.members.values().filter(|r| r.name != member).filter_map(|r| r.ip4).collect();
    let mut taken6: BTreeSet<Ipv6Addr> = reg.members.values().filter(|r| r.name != member).filter_map(|r| r.ip6).collect();
    taken4.extend(cfg.members().filter(|(name, _, _)| name.as_str() != member).filter_map(|(_, m, _)| m.preferred_ip4));
    taken6.extend(cfg.members().filter(|(name, _, _)| name.as_str() != member).filter_map(|(_, m, _)| m.preferred_ip6));

    // Effective preferred: request wins, else config static.
    let want4 = preferred4.or(member_cfg.preferred_ip4);
    let want6 = preferred6.or(member_cfg.preferred_ip6);

    // Validate both hard choices before an allocation can mutate a cursor
    // or reclaim another member's reservation.
    if let Some(ip) = want4 {
        check_in_network(cfg, IpAddr::V4(ip))?;
        if taken4.contains(&ip) {
            return Err(ApiError::address_in_use(format!("{ip} is already assigned")));
        }
    }
    if let Some(ip) = want6 {
        check_in_network(cfg, IpAddr::V6(ip))?;
        if taken6.contains(&ip) {
            return Err(ApiError::address_in_use(format!("{ip} is already assigned")));
        }
    }

    let current4 = reg.by_name(member).and_then(|r| r.ip4);
    let current6 = reg.by_name(member).and_then(|r| r.ip6);
    let ip4 = match want4 {
        Some(ip) => {
            Some(ip)
        }
        None if current4.is_some_and(|ip| dynamic_address_allowed(cfg, IpAddr::V4(ip))) => current4,
        None => alloc_v4(cfg, reg, &taken4, &hard4, reclaim, member)?,
    };
    let has_v6 = cfg.cidrs.iter().any(|c| matches!(c, IpNet::V6(_)));
    let ip6 = match want6 {
        Some(ip) => {
            Some(ip)
        }
        None if current6.is_some_and(|ip| dynamic_address_allowed(cfg, IpAddr::V6(ip))) => current6,
        // v6 is best-effort: only when the network defines v6 space.
        None if has_v6 => alloc_v6(cfg, reg, &taken6, &hard6, reclaim, member).ok().flatten(),
        None => None,
    };
    Ok(Granted { ip4, ip6 })
}

/// Every member address is inside the network's tunnel space.
fn check_in_network(cfg: &NetworkConfig, ip: IpAddr) -> Result<(), ApiError> {
    let bad = match ip {
        IpAddr::V4(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => v.is_loopback() || v.is_unspecified() || v.is_multicast(),
    };
    if bad {
        Err(ApiError::bad_request(format!("{ip} is not a usable address")))
    } else if !cfg.cidrs.iter().any(|c| c.contains(&ip)) {
        Err(ApiError::bad_request(format!("{ip} is outside this network's tunnel CIDRs")))
    } else {
        Ok(())
    }
}

fn dynamic_address_allowed(cfg: &NetworkConfig, ip: IpAddr) -> bool {
    cfg.cidrs.iter().any(|c| c.contains(&ip))
}

/// Oldest safely offline dynamic client holding an address in one of the
/// eligible network range. Relay addresses are not soft: a relay whose control
/// link is down may still be forwarding. Nor is an offline client that a
/// relay still declares attached.
fn reclaimable<T: Copy + Ord>(
    cfg: &NetworkConfig,
    reg: &Registry,
    leases: Option<&Leases>,
    member: &str,
    hard: &BTreeSet<T>,
    address: impl Fn(&crate::registry::MemberRecord) -> Option<T>,
    eligible: impl Fn(T) -> bool,
) -> Option<(u32, T)> {
    let leases = leases?;
    let attached = leases.attachments();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let join_guard = cfg.settings.liveness_window_secs();
    reg.members
        .iter()
        .filter(|(id, rec)| {
            rec.name != member
                && rec.role == nqvpn_proto::types::Role::Client
                && !leases.is_online(**id)
                && !attached.contains_key(id)
                && cfg.member_by_name(&rec.name).is_some()
                // A successful HTTP join precedes the control session by
                // a short gap. Until one liveness window passes, do not
                // mistake that not-yet-connected member for an abandoned
                // reservation.
                && (leases.offline_since(**id).is_some()
                    || rec.last_join_unix.unwrap_or(rec.created_unix).saturating_add(join_guard) <= now)
        })
        .filter_map(|(id, rec)| address(rec).map(|ip| (*id, rec, ip)))
        .filter(|(_, _, ip)| !hard.contains(ip) && eligible(*ip))
        .min_by_key(|(id, rec, _)| {
            (
                leases.offline_since(*id).unwrap_or_else(|| {
                    rec.last_join_unix.unwrap_or(rec.created_unix).saturating_mul(1000)
                }),
                *id,
            )
        })
        .map(|(id, _, ip)| (id, ip))
}

/// Scan a CIDR's `n` addresses starting at its cursor and wrapping, so
/// addresses cycle forward instead of the lowest free one being reissued
/// immediately. `at(i)` maps an index to the address, so no range is ever
/// materialised.
fn scan_from_cursor<T: Ord>(
    n: u64,
    at: impl Fn(u64) -> T,
    taken: &BTreeSet<T>,
    cursor: u64,
) -> Option<(T, u64)> {
    if n == 0 {
        return None;
    }
    let start = cursor % n;
    for step in 0..n {
        let idx = (start + step) % n;
        let cand = at(idx);
        if !taken.contains(&cand) {
            return Some((cand, (idx + 1) % n));
        }
    }
    None
}

/// Usable hosts of a v4 CIDR: everything but network and broadcast,
/// except for /31 and /32 where every address is a host.
fn v4_hosts(net: &ipnet::Ipv4Net) -> (u64, u32) {
    let first = u32::from(net.network());
    let last = u32::from(net.broadcast());
    if net.prefix_len() >= 31 {
        ((last - first) as u64 + 1, first)
    } else {
        ((last - first).saturating_sub(1) as u64, first + 1)
    }
}

fn alloc_v4(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    taken: &BTreeSet<Ipv4Addr>,
    hard: &BTreeSet<Ipv4Addr>,
    reclaim: Option<&Leases>,
    member: &str,
) -> Result<Option<Ipv4Addr>, ApiError> {
    let v4net = cfg.ipv4_cidr();
    let (n, first) = v4_hosts(&v4net);
    let cursor = reg.alloc_cursor.get("ipv4").copied().unwrap_or(0);
    let at = |i: u64| Ipv4Addr::from(first + i as u32);
    if let Some((ip, next)) = scan_from_cursor(n, at, taken, cursor) {
        reg.alloc_cursor.insert("ipv4".to_string(), next);
        return Ok(Some(ip));
    }
    let eligible = |ip: Ipv4Addr| v4net.contains(&ip);
    if let Some((victim, ip)) = reclaimable(cfg, reg, reclaim, member, hard, |r| r.ip4, eligible) {
        if let Some(rec) = reg.members.get_mut(&victim) {
            rec.ip4 = None;
            // Its last credential still claims this address. Bump the
            // generation so relays reject that credential if the old
            // client tries to reconnect without first rejoining here.
            rec.login_gen = rec.login_gen.saturating_add(1);
        }
        tracing::info!(victim_node = victim, %ip, member, "IPv4 range exhausted; reclaimed the longest-offline soft reservation");
        return Ok(Some(ip));
    }
    Err(ApiError::address_space_exhausted("IPv4 range is exhausted".to_string()))
}

/// IPv6 ranges are effectively unbounded; scan at most this many addresses.
const V6_SCAN_CAP: u64 = 100_000;

fn alloc_v6(
    cfg: &NetworkConfig,
    reg: &mut Registry,
    taken: &BTreeSet<Ipv6Addr>,
    hard: &BTreeSet<Ipv6Addr>,
    reclaim: Option<&Leases>,
    member: &str,
) -> Result<Option<Ipv6Addr>, ApiError> {
    let Some(v6net) = cfg.ipv6_cidr() else { return Ok(None) };
    // Skip the network address (subnet-router anycast).
    let first = u128::from(v6net.network()) + 1;
    let last = u128::from(v6net.broadcast());
    if last >= first {
        let n = ((last - first + 1).min(V6_SCAN_CAP as u128)) as u64;
        let cursor = reg.alloc_cursor.get("ipv6").copied().unwrap_or(0);
        let at = |i: u64| Ipv6Addr::from(first + i as u128);
        if let Some((ip, next)) = scan_from_cursor(n, at, taken, cursor) {
            reg.alloc_cursor.insert("ipv6".to_string(), next);
            return Ok(Some(ip));
        }
    }
    let eligible = |ip: Ipv6Addr| v6net.contains(&ip);
    if let Some((victim, ip)) = reclaimable(cfg, reg, reclaim, member, hard, |r| r.ip6, eligible) {
        if let Some(rec) = reg.members.get_mut(&victim) {
            rec.ip6 = None;
            rec.login_gen = rec.login_gen.saturating_add(1);
        }
        tracing::info!(victim_node = victim, %ip, member, "IPv6 range exhausted; reclaimed the longest-offline soft reservation");
        return Ok(Some(ip));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::Registry;
    use nqvpn_proto::types::Role;

    fn cfg() -> NetworkConfig {
        toml::from_str(
            r#"
network_id = "n1"
ipv4_cidr = "10.99.1.0/30"
ipv6_cidr = "fd99::1:0/126"
[clients.c1]
[clients.c2]
[clients.c3]
[clients.pinned]
[relays.r1]
relay_addr = "1.2.3.4:1"
"#,
        )
        .unwrap()
    }

    #[test]
    fn sequential_cidr_allocation() {
        let c = cfg();
        let mut reg = Registry::new();
        let g = allocate(&c, &mut reg, "c1", None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.1".parse().unwrap()));
    }

    #[test]
    fn cidr_exhaustion() {
        let c = cfg();
        let mut reg = Registry::new();
        // /30 has hosts .1 and .2
        reg.member_mut(101, "a", Role::Client, 1).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut(102, "b", Role::Client, 1).ip4 = Some("10.99.1.2".parse().unwrap());
        let err = allocate(&c, &mut reg, "c1", None, None).unwrap_err();
        assert_eq!(err.code.as_str(), "address_space_exhausted");
    }

    #[test]
    fn preferred_inside_network_cidr_is_accepted() {
        let c = cfg();
        let mut reg = Registry::new();
        let g = allocate(&c, &mut reg, "c1", Some("10.99.1.2".parse().unwrap()), None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.2".parse().unwrap()));
    }

    #[test]
    fn preferred_conflict_rejected() {
        let c = cfg();
        let mut reg = Registry::new();
        reg.member_mut(103, "other", Role::Client, 1).ip4 = Some("10.99.1.2".parse().unwrap());
        let err = allocate(&c, &mut reg, "c1", Some("10.99.1.2".parse().unwrap()), None)
            .unwrap_err();
        assert_eq!(err.code.as_str(), "address_in_use");
    }

    #[test]
    fn config_preferred_of_other_member_is_reserved() {
        let mut c = cfg();
        c.clients.get_mut("c2").unwrap().preferred_ip4 = Some("10.99.1.1".parse().unwrap());
        let mut reg = Registry::new();
        // c2's config reserves 10.99.1.1 even though c2 never joined.
        let err = allocate(&c, &mut reg, "c1", Some("10.99.1.1".parse().unwrap()), None)
            .unwrap_err();
        assert_eq!(err.code.as_str(), "address_in_use");
    }

    /// A freed address must not go straight back out. The allocator
    /// cycles forward through the CIDR and wraps, so reuse happens only
    /// after a full lap — the DHCP behaviour operators expect.
    #[test]
    fn a_released_address_is_not_immediately_reissued() {
        let c = cfg();
        let mut reg = Registry::new();
        // Fill the whole /30: hosts .1 and .2.
        let a = allocate(&c, &mut reg, "c1", None, None).unwrap();
        reg.member_mut(1, "c1", Role::Client, 1).ip4 = a.ip4;
        let b = allocate(&c, &mut reg, "c2", None, None).unwrap();
        reg.member_mut(2, "c2", Role::Client, 1).ip4 = b.ip4;
        assert_ne!(a.ip4, b.ip4);
        assert_eq!(a.ip4, Some("10.99.1.1".parse().unwrap()));
        assert_eq!(b.ip4, Some("10.99.1.2".parse().unwrap()));

        // An admin removes the FIRST member, freeing .1 — the lowest
        // free address. A naive allocator would hand it straight over.
        reg.members.remove(&1);
        let next = allocate(&c, &mut reg, "c1", None, None).unwrap();
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
ipv4_cidr = "10.99.1.0/28"
[clients.x]
"#,
        )
        .unwrap();
        let mut r2 = Registry::new();
        let mut seen = Vec::new();
        for i in 0..4 {
            let g = allocate(&wide, &mut r2, "x", None, None).unwrap();
            let ip = g.ip4.unwrap();
            seen.push(ip);
            r2.member_mut(50 + i, &format!("m{i}"), Role::Client, 1).ip4 = Some(ip);
        }
        // Free the first one, then allocate again: the cursor has moved
        // past it, so the new member gets a fresh address.
        r2.members.remove(&50);
        let after = allocate(&wide, &mut r2, "x", None, None).unwrap().ip4.unwrap();
        assert_ne!(after, seen[0], "the just-freed address was reissued immediately");
        assert!(!seen.contains(&after), "allocator moved forward to unused space");
    }

    #[test]
    fn cursor_survives_a_coordinator_restart() {
        let c = cfg();
        let mut reg = Registry::new();
        allocate(&c, &mut reg, "c1", None, None).unwrap();
        let cursor = reg.alloc_cursor.clone();
        assert!(!cursor.is_empty(), "allocation advanced a cursor");

        // What the database stores is this JSON; a restart reads it back.
        let json = serde_json::to_string(&reg).unwrap();
        let back: Registry = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.alloc_cursor, cursor,
            "a restart must not reset the cursor, or reuse starts over"
        );
    }

    #[test]
    fn preferred_addresses_must_be_usable_and_inside_the_tunnel_cidrs() {
        let c = cfg();
        let mut reg = Registry::new();
        let err = allocate(&c, &mut reg, "c1", Some("192.168.9.9".parse().unwrap()), None).unwrap_err();
        assert_eq!(err.code.as_str(), "bad_request");
        let err = allocate(&c, &mut reg, "c1", Some("127.0.0.1".parse().unwrap()), None).unwrap_err();
        assert_eq!(err.code.as_str(), "bad_request");
    }

    #[test]
    fn exhausted_range_reclaims_the_longest_gone_dynamic_client() {
        let c = cfg();
        let mut reg = Registry::new();
        reg.member_mut(1, "c1", Role::Client, 10).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut(2, "c2", Role::Client, 20).ip4 = Some("10.99.1.2".parse().unwrap());
        let mut leases = Leases::default();
        leases.seen(1, 100_000);
        leases.offline(1);
        leases.seen(2, 200_000);
        leases.offline(2);

        let g = allocate_for_join(&c, &mut reg, &leases, true, "c3", None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.1".parse().unwrap()));
        assert_eq!(reg.members[&1].ip4, None, "the old soft reservation is released atomically");
        assert_eq!(reg.members[&1].login_gen, 1, "the old address-bearing credential is invalidated");
        assert_eq!(reg.members[&2].ip4, Some("10.99.1.2".parse().unwrap()));
    }

    #[test]
    fn static_addresses_and_restart_grace_are_never_reclaimed() {
        let mut c = cfg();
        c.clients.get_mut("c1").unwrap().preferred_ip4 = Some("10.99.1.1".parse().unwrap());
        let mut reg = Registry::new();
        reg.member_mut(1, "c1", Role::Client, 10).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut(2, "c2", Role::Client, 20).ip4 = Some("10.99.1.2".parse().unwrap());
        let mut leases = Leases::default();
        leases.seen(1, 100_000);
        leases.offline(1);
        leases.seen(2, 200_000);
        leases.offline(2);

        let during_grace = allocate_for_join(&c, &mut reg, &leases, false, "c3", None, None).unwrap_err();
        assert_eq!(during_grace.code.as_str(), "address_space_exhausted");

        let g = allocate_for_join(&c, &mut reg, &leases, true, "c3", None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.2".parse().unwrap()), "only the dynamic reservation is reclaimable");
        assert_eq!(reg.members[&1].ip4, Some("10.99.1.1".parse().unwrap()), "static reservation remains forever");
    }

    #[test]
    fn a_client_still_attached_to_a_relay_is_not_reclaimed() {
        let c = cfg();
        let mut reg = Registry::new();
        reg.member_mut(1, "c1", Role::Client, 10).ip4 = Some("10.99.1.1".parse().unwrap());
        reg.member_mut(2, "c2", Role::Client, 20).ip4 = Some("10.99.1.2".parse().unwrap());
        let mut leases = Leases::default();
        leases.seen(1, 100_000);
        leases.offline(1);
        leases.seen(2, 200_000);
        leases.offline(2);
        leases.heartbeat(
            9,
            Role::Relay,
            &nqvpn_proto::control::Heartbeat {
                attached: vec![nqvpn_proto::control::AttachedClient { node_id: 1, session_id: 7 }],
                ..Default::default()
            },
            300_000,
        );

        let g = allocate_for_join(&c, &mut reg, &leases, true, "c3", None, None).unwrap();
        assert_eq!(g.ip4, Some("10.99.1.2".parse().unwrap()), "the detached client is reclaimed instead");
        assert_eq!(reg.members[&1].ip4, Some("10.99.1.1".parse().unwrap()));
    }

    #[test]
    fn v6_allocated_alongside_v4() {
        let c = cfg();
        let mut reg = Registry::new();
        let g = allocate(&c, &mut reg, "c1", None, None).unwrap();
        assert!(g.ip4.is_some());
        assert_eq!(g.ip6, Some("fd99::1:1".parse().unwrap()));
    }
}
