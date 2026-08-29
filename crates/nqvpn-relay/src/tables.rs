//! The relay's two forwarding tables and the §6 forwarding decision.
//!
//! Both are in-memory snapshots read on the hot path (§9 hot-path
//! invariant: header parse + two lookups + send, no locks held across
//! I/O, no allocation, no disk).

use nqvpn_proto::frame::Decision;
use nqvpn_proto::types::NodeId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where a datagram goes next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// Deliver to a client session attached here.
    Local(NodeId),
    /// Forward across one mesh link to the relay holding the destination.
    Mesh(NodeId),
    /// Terminates at this node (gateway relay owning the destination).
    Me,
    /// Drop, with the reason every counter and trace note uses.
    Drop(Decision),
}

impl Route {
    pub fn decision(&self) -> Decision {
        match self {
            Route::Local(_) => Decision::DeliverLocal,
            Route::Mesh(_) => Decision::ForwardMesh,
            Route::Me => Decision::TerminateHere,
            Route::Drop(d) => *d,
        }
    }
}

/// Where a datagram came from — the arriving session's kind decides
/// whether forwarding is allowed at all (the one-hop invariant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// A client attached to me, authenticated as this node id.
    Client(NodeId),
    /// A peer relay in the mesh.
    Relay(NodeId),
}

#[derive(Debug, Default)]
pub struct Tables {
    my_node_id: NodeId,
    /// node_id -> attached here (client sessions).
    local: HashMap<NodeId, ()>,
    /// node_id -> relay node_id holding it (from the coordinator).
    attachments: HashMap<NodeId, NodeId>,
    /// relay node_id -> live mesh session.
    mesh: HashMap<NodeId, ()>,
}

impl Tables {
    pub fn new(my_node_id: NodeId) -> Self {
        Tables { my_node_id, ..Default::default() }
    }

    pub fn set_local(&mut self, node: NodeId, present: bool) {
        if present {
            self.local.insert(node, ());
        } else {
            self.local.remove(&node);
        }
    }

    pub fn set_mesh(&mut self, relay: NodeId, present: bool) {
        if present {
            self.mesh.insert(relay, ());
        } else {
            self.mesh.remove(&relay);
        }
    }

    pub fn replace_attachments(&mut self, entries: impl IntoIterator<Item = (NodeId, NodeId)>) {
        self.attachments = entries.into_iter().collect();
    }

    pub fn local_count(&self) -> usize {
        self.local.len()
    }

    pub fn mesh_count(&self) -> usize {
        self.mesh.len()
    }

    /// **The entire relay data plane** (§6):
    ///
    /// ```text
    /// from a CLIENT session (src must equal the session's node id):
    ///     dst == me               -> terminate here (gateway TUN)
    ///     dst attached to me      -> deliver locally
    ///     dst is a relay          -> forward on its mesh session
    ///     dst attached to relay R -> forward on the R mesh session
    ///     otherwise               -> drop + count
    /// from a RELAY session (src must be attached to that relay, or be it):
    ///     dst == me               -> terminate here
    ///     dst attached to me      -> deliver locally
    ///     otherwise               -> drop + count   # never forward again
    /// ```
    ///
    /// That last rule is what makes loops impossible by construction: a
    /// frame crosses at most one mesh link.
    pub fn route(&self, origin: Origin, src_id: NodeId, dst_id: NodeId) -> Route {
        match origin {
            Origin::Client(session_node) if session_node != src_id => {
                return Route::Drop(Decision::DropSrcSpoofed);
            }
            Origin::Relay(relay) if src_id != relay && self.attachments.get(&src_id) != Some(&relay) => {
                // A relay may only source frames for itself or for the
                // members the coordinator says it holds.
                return Route::Drop(Decision::DropSrcSpoofed);
            }
            _ => {}
        }
        if dst_id == self.my_node_id {
            return Route::Me;
        }
        if self.local.contains_key(&dst_id) {
            return Route::Local(dst_id);
        }
        match origin {
            Origin::Relay(_) => Route::Drop(Decision::DropNoSecondHop),
            Origin::Client(_) => {
                if self.mesh.contains_key(&dst_id) {
                    return Route::Mesh(dst_id);
                }
                match self.attachments.get(&dst_id) {
                    Some(relay) if self.mesh.contains_key(relay) => Route::Mesh(*relay),
                    Some(_) => Route::Drop(Decision::DropMeshLinkDown),
                    None => Route::Drop(Decision::DropDstUnknown),
                }
            }
        }
    }
}

/// One counter per decision — the same vocabulary trace notes use, so a
/// number in status and a line in a trace can never disagree.
#[derive(Debug, Default)]
pub struct Counters {
    by_decision: [AtomicU64; Decision::ALL.len()],
}

impl Counters {
    pub fn note(&self, d: Decision) {
        if let Some(i) = Decision::ALL.iter().position(|x| *x == d) {
            self.by_decision[i].fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get(&self, d: Decision) -> u64 {
        Decision::ALL
            .iter()
            .position(|x| *x == d)
            .map(|i| self.by_decision[i].load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        Decision::ALL.iter().map(|d| (d.as_str(), self.get(*d))).collect()
    }
}

/// Bytes and packets moved in one direction.
#[derive(Debug, Default)]
pub struct ByteCounter {
    pub bytes: AtomicU64,
    pub pkts: AtomicU64,
}

impl ByteCounter {
    pub fn add(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        self.pkts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn get(&self) -> (u64, u64) {
        (self.bytes.load(Ordering::Relaxed), self.pkts.load(Ordering::Relaxed))
    }
}

/// Both directions of one mesh link, as measured by *this* relay.
#[derive(Debug, Default)]
pub struct LinkCounters {
    pub tx: ByteCounter,
    pub rx: ByteCounter,
}

/// Per-session token bucket for `max_session_mbps`.
#[derive(Debug)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    refill_per_sec: f64,
    last: std::time::Instant,
}

impl TokenBucket {
    /// `mbps == 0` means unlimited.
    pub fn new(mbps: u32) -> Option<TokenBucket> {
        if mbps == 0 {
            return None;
        }
        let bytes_per_sec = mbps as f64 * 1_000_000.0 / 8.0;
        Some(TokenBucket { capacity: bytes_per_sec, tokens: bytes_per_sec, refill_per_sec: bytes_per_sec, last: std::time::Instant::now() })
    }

    pub fn allow(&mut self, len: usize) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= len as f64 {
            self.tokens -= len as f64;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tables() -> Tables {
        // I am relay #1; client #10 is attached to me, #20 is on relay #2.
        let mut t = Tables::new(1);
        t.set_local(10, true);
        t.set_mesh(2, true);
        t.replace_attachments([(20, 2), (10, 1)]);
        t
    }

    #[test]
    fn client_to_local_client() {
        assert_eq!(tables().route(Origin::Client(30), 30, 10), Route::Local(10));
    }

    #[test]
    fn client_to_remote_client_crosses_one_mesh_link() {
        assert_eq!(tables().route(Origin::Client(10), 10, 20), Route::Mesh(2));
    }

    #[test]
    fn relay_frames_are_never_forwarded_again() {
        assert_eq!(tables().route(Origin::Relay(2), 20, 10), Route::Local(10));
        assert_eq!(tables().route(Origin::Relay(2), 20, 999), Route::Drop(Decision::DropNoSecondHop));
        let mut t = tables();
        t.set_mesh(3, true);
        t.replace_attachments([(20, 2), (10, 1), (40, 3)]);
        assert_eq!(t.route(Origin::Relay(2), 20, 40), Route::Drop(Decision::DropNoSecondHop));
    }

    #[test]
    fn spoofed_sources_are_dropped_from_clients_and_relays() {
        assert_eq!(tables().route(Origin::Client(10), 99, 20), Route::Drop(Decision::DropSrcSpoofed));
        // Relay 2 may speak for itself and for node 20, which it holds…
        assert_eq!(tables().route(Origin::Relay(2), 2, 10), Route::Local(10));
        assert_eq!(tables().route(Origin::Relay(2), 20, 10), Route::Local(10));
        // …but not for a node the coordinator says is elsewhere.
        assert_eq!(tables().route(Origin::Relay(2), 10, 10), Route::Drop(Decision::DropSrcSpoofed));
        assert_eq!(tables().route(Origin::Relay(2), 77, 10), Route::Drop(Decision::DropSrcSpoofed));
    }

    #[test]
    fn gateway_traffic_terminates_here() {
        assert_eq!(tables().route(Origin::Client(10), 10, 1), Route::Me);
        assert_eq!(tables().route(Origin::Relay(2), 20, 1), Route::Me);
    }

    #[test]
    fn an_addressed_relay_is_reachable_over_its_mesh_link() {
        let t = tables();
        assert_eq!(t.route(Origin::Client(10), 10, 2), Route::Mesh(2));
        assert_eq!(t.route(Origin::Relay(2), 20, 3), Route::Drop(Decision::DropNoSecondHop));
    }

    #[test]
    fn unknown_and_down_are_distinct_drops() {
        let mut t = tables();
        assert_eq!(t.route(Origin::Client(10), 10, 777), Route::Drop(Decision::DropDstUnknown));
        t.set_mesh(2, false);
        assert_eq!(t.route(Origin::Client(10), 10, 20), Route::Drop(Decision::DropMeshLinkDown));
    }

    #[test]
    fn local_beats_stale_attachment() {
        let mut t = tables();
        t.set_local(20, true);
        assert_eq!(t.route(Origin::Client(10), 10, 20), Route::Local(20));
    }

    #[test]
    fn token_bucket_limits_then_refills() {
        let mut b = TokenBucket::new(1).unwrap();
        assert!(b.allow(100_000));
        assert!(!b.allow(100_000));
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(b.allow(50_000));
        assert!(TokenBucket::new(0).is_none());
    }

    #[test]
    fn counters_track_every_decision() {
        let c = Counters::default();
        c.note(Decision::DeliverLocal);
        c.note(Decision::DropSrcSpoofed);
        c.note(Decision::DropSrcSpoofed);
        assert_eq!(c.get(Decision::DeliverLocal), 1);
        assert_eq!(c.get(Decision::DropSrcSpoofed), 2);
        assert_eq!(c.snapshot().len(), Decision::ALL.len());
    }
}
