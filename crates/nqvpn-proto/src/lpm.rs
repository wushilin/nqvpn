//! Longest-prefix-match table (prefix → node id) — the lookup every
//! outbound packet performs (DESIGN.md §2, §9 hot-path invariant).
//!
//! Backed by [`prefix_trie::JointPrefixMap`], a TreeBitMap trie holding
//! one IPv4 and one IPv6 table. Lookup cost is bounded by prefix width
//! (depth ≤ 7 for IPv4, ≤ 26 for IPv6) rather than by the number of
//! prefixes, so a fleet that advertises hundreds of LANs costs the same
//! per packet as one advertising three. The previous implementation was
//! a linear scan, which was fine at a handful of routes and degraded
//! exactly where a large deployment would notice.

use ipnet::IpNet;
use prefix_trie::joint::JointPrefixMap;
use std::net::IpAddr;

use crate::types::NodeId;

/// True iff the two CIDRs share any address (always false across families).
pub fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    // Aligned CIDR blocks overlap iff one contains the other's network addr.
    a.contains(&b.network()) || b.contains(&a.network())
}

#[derive(Debug, Default)]
pub struct LpmTable {
    map: JointPrefixMap<IpNet, NodeId>,
}

impl LpmTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace a prefix. Prefixes are stored truncated, so
    /// `10.0.0.5/8` and `10.0.0.0/8` are the same entry.
    pub fn insert(&mut self, net: IpNet, node: NodeId) {
        self.map.insert(net.trunc(), node);
    }

    pub fn remove(&mut self, net: &IpNet) {
        self.map.remove(&net.trunc());
    }

    /// The owner of the longest prefix covering `ip`, if any.
    pub fn lookup(&self, ip: IpAddr) -> Option<NodeId> {
        // A host route for the address is the query: the trie returns
        // the longest stored prefix that covers it.
        let host = match ip {
            IpAddr::V4(v4) => IpNet::from(ipnet::Ipv4Net::new(v4, 32).expect("/32")),
            IpAddr::V6(v6) => IpNet::from(ipnet::Ipv6Net::new(v6, 128).expect("/128")),
        };
        self.map.get_lpm(&host).map(|(_, node)| *node)
    }

    pub fn len(&self) -> usize {
        self.map.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.map.iter().next().is_none()
    }

    /// Every (prefix, owner) pair. Order is unspecified — callers that
    /// need determinism sort the result.
    pub fn iter(&self) -> impl Iterator<Item = (IpNet, NodeId)> + '_ {
        self.map.iter().map(|(net, node)| (net, *node))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = LpmTable::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.1.0.0/16"), 2);
        t.insert(net("10.1.2.0/24"), 3);
        assert_eq!(t.lookup("10.1.2.3".parse().unwrap()), Some(3));
        assert_eq!(t.lookup("10.1.9.9".parse().unwrap()), Some(2));
        assert_eq!(t.lookup("10.9.9.9".parse().unwrap()), Some(1));
        assert_eq!(t.lookup("192.168.1.1".parse().unwrap()), None);
    }

    #[test]
    fn families_are_disjoint() {
        let mut t = LpmTable::new();
        t.insert(net("fd99::/64"), 6);
        t.insert(net("10.0.0.0/8"), 4);
        assert_eq!(t.lookup("fd99::5".parse().unwrap()), Some(6));
        assert_eq!(t.lookup("10.0.0.1".parse().unwrap()), Some(4));
        // An address of one family never matches the other's prefixes.
        assert_eq!(t.lookup("fe80::1".parse().unwrap()), None);
        assert_eq!(t.lookup("11.0.0.1".parse().unwrap()), None);
    }

    #[test]
    fn overlap_helper() {
        assert!(overlaps(&net("10.0.0.0/8"), &net("10.1.0.0/16")));
        assert!(overlaps(&net("10.1.0.0/16"), &net("10.0.0.0/8")));
        assert!(!overlaps(&net("10.0.0.0/8"), &net("11.0.0.0/8")));
        assert!(!overlaps(&net("10.0.0.0/8"), &net("fd99::/64")));
    }

    #[test]
    fn reinsert_replaces() {
        let mut t = LpmTable::new();
        t.insert(net("10.1.0.0/16"), 1);
        t.insert(net("10.1.0.0/16"), 2);
        assert_eq!(t.len(), 1);
        assert_eq!(t.lookup("10.1.0.1".parse().unwrap()), Some(2));
    }

    #[test]
    fn removal_uncovers_the_shorter_prefix() {
        let mut t = LpmTable::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("10.1.2.0/24"), 3);
        assert_eq!(t.lookup("10.1.2.3".parse().unwrap()), Some(3));
        t.remove(&net("10.1.2.0/24"));
        assert_eq!(t.lookup("10.1.2.3".parse().unwrap()), Some(1), "falls back to /8");
        t.remove(&net("10.0.0.0/8"));
        assert!(t.is_empty());
        assert_eq!(t.lookup("10.1.2.3".parse().unwrap()), None);
    }

    #[test]
    fn host_routes_and_defaults_coexist() {
        // The shapes this VPN actually stores: /32s for members and
        // wide CIDRs for gateway LANs.
        let mut t = LpmTable::new();
        t.insert(net("0.0.0.0/0"), 99);
        t.insert(net("192.168.7.0/24"), 7);
        t.insert(net("192.168.7.20/32"), 20);
        assert_eq!(t.lookup("192.168.7.20".parse().unwrap()), Some(20));
        assert_eq!(t.lookup("192.168.7.21".parse().unwrap()), Some(7));
        assert_eq!(t.lookup("8.8.8.8".parse().unwrap()), Some(99));
    }

    #[test]
    fn untruncated_input_is_normalised() {
        // A peer advertising 10.1.2.3/24 means the 10.1.2.0/24 block.
        let mut t = LpmTable::new();
        t.insert(net("10.1.2.3/24"), 5);
        assert_eq!(t.lookup("10.1.2.99".parse().unwrap()), Some(5));
        t.remove(&net("10.1.2.77/24"));
        assert!(t.is_empty(), "removal normalises the same way");
    }

    #[test]
    fn iter_yields_every_entry() {
        let mut t = LpmTable::new();
        t.insert(net("10.0.0.0/8"), 1);
        t.insert(net("fd99::/64"), 2);
        let mut got: Vec<String> = t.iter().map(|(n, _)| n.to_string()).collect();
        got.sort();
        assert_eq!(got, vec!["10.0.0.0/8", "fd99::/64"]);
        assert_eq!(t.len(), 2);
    }
}
