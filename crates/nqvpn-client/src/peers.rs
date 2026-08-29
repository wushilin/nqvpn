//! Per-peer end-to-end sessions and the inner-packet ingress filter
//! (DESIGN.md §4).
//!
//! The relay layer authenticates *hops*; this layer authenticates
//! *origins*. Two checks matter here and neither can be skipped:
//!
//!  * the peer's Noise static key must equal the key the coordinator
//!    published for that node id — otherwise a member could hand us a
//!    handshake claiming to be someone else;
//!  * the decrypted packet's own addresses must belong to the sender and
//!    to us, or an authenticated member could source-spoof another
//!    member or bounce traffic off us (confused router).

use ipnet::IpNet;
use nqvpn_proto::control::PeerInfo;
use nqvpn_proto::lpm::LpmTable;
use nqvpn_proto::seal::{decode_pubkey, PairSession, SealError, StaticKeys};
use nqvpn_proto::types::NodeId;
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Debug, PartialEq, Eq)]
pub enum IngressVerdict {
    Accept,
    Drop(&'static str),
}

/// What the client knows about the network, derived from membership.
#[derive(Default)]
pub struct PeerTable {
    peers: HashMap<NodeId, PeerInfo>,
    /// prefix -> owning node id, for outbound routing.
    lpm: LpmTable,
    /// Prefixes this node owns (inner destinations we will accept).
    mine: Vec<IpNet>,
    my_node_id: NodeId,
}

impl PeerTable {
    pub fn new(my_node_id: NodeId) -> Self {
        PeerTable { my_node_id, ..Default::default() }
    }

    pub fn set_mine(&mut self, prefixes: Vec<IpNet>) {
        self.mine = prefixes;
    }

    pub fn upsert(&mut self, p: PeerInfo) {
        if p.node_id != self.my_node_id {
            for net in &p.prefixes {
                self.lpm.insert(*net, p.node_id);
            }
        }
        // A peer's prefixes can shrink (route withdrawal, §2): drop any
        // entry that is no longer claimed by this node.
        let stale: Vec<IpNet> = self
            .lpm
            .iter()
            .filter(|(net, id)| *id == p.node_id && !p.prefixes.contains(net))
            .map(|(net, _)| net)
            .collect();
        for net in stale {
            self.lpm.remove(&net);
        }
        self.peers.insert(p.node_id, p);
    }

    pub fn remove(&mut self, id: NodeId) {
        if let Some(p) = self.peers.remove(&id) {
            for net in &p.prefixes {
                self.lpm.remove(net);
            }
        }
    }

    pub fn replace_all(&mut self, peers: Vec<PeerInfo>) {
        self.peers.clear();
        self.lpm = LpmTable::new();
        for p in peers {
            self.upsert(p);
        }
    }

    pub fn owner_of(&self, addr: IpAddr) -> Option<NodeId> {
        self.lpm.lookup(addr)
    }

    /// Is this one of our own addresses? macOS routes a host's own
    /// tunnel address *into* the utun rather than looping it back in the
    /// kernel, so without this a node cannot ping itself: the packet
    /// enters the TUN, matches no peer prefix, and is dropped.
    pub fn is_mine(&self, addr: IpAddr) -> bool {
        self.mine.iter().any(|n| n.contains(&addr))
    }

    pub fn get(&self, id: NodeId) -> Option<&PeerInfo> {
        self.peers.get(&id)
    }

    pub fn pubkey_of(&self, id: NodeId) -> Option<Vec<u8>> {
        self.peers.get(&id).and_then(|p| decode_pubkey(&p.pubkey))
    }

    /// Every prefix any peer owns — what the OS routing table should
    /// contain (our own addresses are on the device, not routed).
    pub fn all_prefixes(&self) -> Vec<IpNet> {
        let mut v: Vec<IpNet> = self.lpm.iter().map(|(net, _)| net).collect();
        v.sort_by_key(|n| n.to_string());
        v
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// §4 ingress filter, applied after unseal and before the TUN write.
    pub fn check_ingress(&self, src_id: NodeId, packet: &[u8]) -> IngressVerdict {
        let Some((src, dst)) = parse_inner_addrs(packet) else {
            return IngressVerdict::Drop("malformed_inner");
        };
        // The inner source must belong to the node that sealed it.
        match self.owner_of(src) {
            Some(owner) if owner == src_id => {}
            _ => return IngressVerdict::Drop("inner_src_not_owned"),
        }
        // The inner destination must be ours, or we would be acting as
        // an unwitting router for someone else's traffic.
        if !self.mine.iter().any(|n| n.contains(&dst)) {
            return IngressVerdict::Drop("inner_dst_not_mine");
        }
        IngressVerdict::Accept
    }
}

/// Parse source and destination out of an IPv4 or IPv6 header, checking
/// that the version nibble matches the length we can actually read.
pub fn parse_inner_addrs(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let src: [u8; 4] = packet[12..16].try_into().ok()?;
            let dst: [u8; 4] = packet[16..20].try_into().ok()?;
            Some((IpAddr::from(src), IpAddr::from(dst)))
        }
        6 if packet.len() >= 40 => {
            let src: [u8; 16] = packet[8..24].try_into().ok()?;
            let dst: [u8; 16] = packet[24..40].try_into().ok()?;
            Some((IpAddr::from(src), IpAddr::from(dst)))
        }
        _ => None,
    }
}

/// All live end-to-end sessions, keyed by peer.
#[derive(Default)]
pub struct SessionTable {
    sessions: HashMap<NodeId, PairSession>,
    /// Packets waiting for a handshake to complete (§6: bounded, never
    /// unbounded buffering).
    pending: HashMap<NodeId, Vec<Vec<u8>>>,
}

pub const PENDING_LIMIT: usize = 64;

impl SessionTable {
    pub fn get_mut(&mut self, peer: NodeId) -> Option<&mut PairSession> {
        self.sessions.get_mut(&peer)
    }

    pub fn insert(&mut self, peer: NodeId, s: PairSession) {
        self.sessions.insert(peer, s);
    }

    pub fn remove(&mut self, peer: NodeId) {
        self.sessions.remove(&peer);
        self.pending.remove(&peer);
    }

    pub fn is_ready(&self, peer: NodeId) -> bool {
        self.sessions.get(&peer).map(|s| s.is_ready()).unwrap_or(false)
    }

    pub fn has(&self, peer: NodeId) -> bool {
        self.sessions.contains_key(&peer)
    }

    /// Queue a packet while the handshake runs; oldest is dropped first.
    pub fn queue(&mut self, peer: NodeId, packet: Vec<u8>) -> bool {
        let q = self.pending.entry(peer).or_default();
        let dropped = q.len() >= PENDING_LIMIT;
        if dropped {
            q.remove(0);
        }
        q.push(packet);
        !dropped
    }

    pub fn take_pending(&mut self, peer: NodeId) -> Vec<Vec<u8>> {
        self.pending.remove(&peer).unwrap_or_default()
    }

    /// Start a session toward `peer`, returning the handshake message.
    pub fn initiate(
        &mut self,
        keys: &StaticKeys,
        peer: NodeId,
        peer_pubkey: &[u8],
        network_uuid: &str,
        me: NodeId,
        now: u64,
    ) -> Result<Vec<u8>, SealError> {
        let (s, msg) = PairSession::initiate(keys, peer, peer_pubkey, network_uuid, me, now)?;
        self.sessions.insert(peer, s);
        Ok(msg)
    }

    pub fn sessions_due_for_rekey(&self, now: u64) -> Vec<NodeId> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.is_ready() && s.needs_rekey(now))
            .map(|(id, _)| *id)
            .collect()
    }

    /// Handshakes that never completed. Dropping them is what lets the
    /// next outbound packet start a fresh one instead of queueing
    /// forever behind a session that will never be ready.
    pub fn stale_handshakes(&self, now: u64) -> Vec<NodeId> {
        self.sessions
            .iter()
            .filter(|(_, s)| s.is_stale_handshake(now))
            .map(|(id, _)| *id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: NodeId, prefixes: &[&str], pubkey: &str) -> PeerInfo {
        PeerInfo {
            node_id: id,
            name: format!("n{id}"),
            prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            pubkey: pubkey.into(),
            online: true,
        }
    }

    fn v4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    fn table() -> PeerTable {
        let mut t = PeerTable::new(1);
        t.set_mine(vec!["10.99.1.1/32".parse().unwrap()]);
        t.upsert(peer(2, &["10.99.1.2/32"], ""));
        t.upsert(peer(3, &["10.99.1.3/32", "192.168.7.0/24"], ""));
        t
    }

    #[test]
    fn routes_by_longest_prefix() {
        let t = table();
        assert_eq!(t.owner_of("10.99.1.2".parse().unwrap()), Some(2));
        assert_eq!(t.owner_of("192.168.7.20".parse().unwrap()), Some(3));
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn accepts_a_well_formed_packet_from_its_owner() {
        let t = table();
        let pkt = v4([10, 99, 1, 2], [10, 99, 1, 1]);
        assert_eq!(t.check_ingress(2, &pkt), IngressVerdict::Accept);
    }

    #[test]
    fn rejects_source_spoofing() {
        let t = table();
        // Node 3 sends a packet claiming to be node 2's address.
        let pkt = v4([10, 99, 1, 2], [10, 99, 1, 1]);
        assert_eq!(t.check_ingress(3, &pkt), IngressVerdict::Drop("inner_src_not_owned"));
    }

    #[test]
    fn rejects_being_used_as_a_router() {
        let t = table();
        // Destination belongs to node 3, not to us.
        let pkt = v4([10, 99, 1, 2], [192, 168, 7, 20]);
        assert_eq!(t.check_ingress(2, &pkt), IngressVerdict::Drop("inner_dst_not_mine"));
    }

    #[test]
    fn rejects_unroutable_and_malformed() {
        let t = table();
        assert_eq!(t.check_ingress(2, &[]), IngressVerdict::Drop("malformed_inner"));
        assert_eq!(t.check_ingress(2, &[0x45, 0, 0]), IngressVerdict::Drop("malformed_inner"));
        // Version nibble says v6 but the packet is v4-sized.
        let mut short6 = vec![0u8; 20];
        short6[0] = 0x60;
        assert_eq!(t.check_ingress(2, &short6), IngressVerdict::Drop("malformed_inner"));
    }

    #[test]
    fn withdrawn_prefixes_stop_routing() {
        let mut t = table();
        // Node 3 loses its LAN (its gateway died, §2).
        t.upsert(peer(3, &["10.99.1.3/32"], ""));
        assert_eq!(t.owner_of("192.168.7.20".parse().unwrap()), None);
        assert_eq!(t.owner_of("10.99.1.3".parse().unwrap()), Some(3));
    }

    #[test]
    fn removing_a_peer_removes_its_routes() {
        let mut t = table();
        t.remove(3);
        assert_eq!(t.owner_of("192.168.7.20".parse().unwrap()), None);
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn pending_queue_is_bounded_and_drops_oldest() {
        let mut s = SessionTable::default();
        for i in 0..(PENDING_LIMIT + 10) {
            s.queue(7, vec![i as u8]);
        }
        let q = s.take_pending(7);
        assert_eq!(q.len(), PENDING_LIMIT);
        assert_eq!(q[0], vec![10u8], "oldest packets were dropped first");
    }

    #[test]
    fn ipv6_addresses_parse() {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[8..24].copy_from_slice(&[0xfd; 16]);
        p[24..40].copy_from_slice(&[0xfe; 16]);
        let (src, dst) = parse_inner_addrs(&p).unwrap();
        assert!(src.is_ipv6() && dst.is_ipv6());
    }
}
