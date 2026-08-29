//! The relay's two forwarding tables and the §6 forwarding decision.
//!
//! Both are in-memory snapshots read on the hot path (§9 hot-path
//! invariant: header parse + two lookups + send, no locks held across
//! I/O, no allocation, no disk).

use nqvpn_proto::types::NodeId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Where a datagram goes next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Deliver to a client session attached here.
    Local(NodeId),
    /// Forward across one mesh link to the relay holding the destination.
    Mesh(NodeId),
    /// Terminates at this node (gateway relay owning the destination).
    Me,
    /// Unknown or offline destination: drop + count.
    Drop(&'static str),
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

    pub fn set_attachment(&mut self, node: NodeId, relay: Option<NodeId>) {
        match relay {
            Some(r) => {
                self.attachments.insert(node, r);
            }
            None => {
                self.attachments.remove(&node);
            }
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
    ///     dst attached to relay R -> forward on the R mesh session
    ///     otherwise               -> drop + count
    /// from a RELAY session:
    ///     dst == me               -> terminate here
    ///     dst attached to me      -> deliver locally
    ///     otherwise               -> drop + count   # never forward again
    /// ```
    ///
    /// That last rule is what makes loops impossible by construction: a
    /// frame crosses at most one mesh link, so no TTL and no routing
    /// protocol are needed.
    pub fn route(&self, origin: Origin, src_id: NodeId, dst_id: NodeId) -> Route {
        match origin {
            Origin::Client(session_node) if session_node != src_id => {
                // Anti-spoofing: a client may only source its own id.
                return Route::Drop("src_spoofed");
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
            Origin::Relay(_) => Route::Drop("no_second_hop"),
            Origin::Client(_) => {
                // A relay is reachable *as itself* over its mesh link:
                // relays never appear in the attachment table (nothing
                // attaches them), but an addressed relay is an ordinary
                // endpoint and must be routable (§3.1).
                if self.mesh.contains_key(&dst_id) {
                    return Route::Mesh(dst_id);
                }
                match self.attachments.get(&dst_id) {
                    Some(relay) if self.mesh.contains_key(relay) => Route::Mesh(*relay),
                    Some(_) => Route::Drop("mesh_link_down"),
                    None => Route::Drop("dst_unknown"),
                }
            }
        }
    }
}

/// Named drop/forward counters — a silent drop is a bug by definition
/// (§9), so every decision above increments something visible.
#[derive(Debug, Default)]
pub struct Counters {
    pub delivered_local: AtomicU64,
    pub forwarded_mesh: AtomicU64,
    pub terminated_here: AtomicU64,
    pub drop_src_spoofed: AtomicU64,
    pub drop_no_second_hop: AtomicU64,
    pub drop_mesh_link_down: AtomicU64,
    pub drop_dst_unknown: AtomicU64,
    pub drop_malformed: AtomicU64,
    pub drop_rate_limited: AtomicU64,
    pub drop_send_failed: AtomicU64,
}

impl Counters {
    pub fn note(&self, route: &Route) {
        let c = match route {
            Route::Local(_) => &self.delivered_local,
            Route::Mesh(_) => &self.forwarded_mesh,
            Route::Me => &self.terminated_here,
            Route::Drop("src_spoofed") => &self.drop_src_spoofed,
            Route::Drop("no_second_hop") => &self.drop_no_second_hop,
            Route::Drop("mesh_link_down") => &self.drop_mesh_link_down,
            Route::Drop(_) => &self.drop_dst_unknown,
        };
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        vec![
            ("delivered_local", g(&self.delivered_local)),
            ("forwarded_mesh", g(&self.forwarded_mesh)),
            ("terminated_here", g(&self.terminated_here)),
            ("drop_src_spoofed", g(&self.drop_src_spoofed)),
            ("drop_no_second_hop", g(&self.drop_no_second_hop)),
            ("drop_mesh_link_down", g(&self.drop_mesh_link_down)),
            ("drop_dst_unknown", g(&self.drop_dst_unknown)),
            ("drop_malformed", g(&self.drop_malformed)),
            ("drop_rate_limited", g(&self.drop_rate_limited)),
            ("drop_send_failed", g(&self.drop_send_failed)),
        ]
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
///
/// Kept per peer rather than aggregated, because the fleet-wide traffic
/// matrix is assembled from every relay's own row. They outlive the
/// session they were measured on: a link that flaps should show its
/// history, not restart from zero.
#[derive(Debug, Default)]
pub struct LinkCounters {
    pub tx: ByteCounter,
    pub rx: ByteCounter,
}

/// Per-session token bucket for `max_session_mbps` (decision #6).
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
        Some(TokenBucket {
            // One second of burst.
            capacity: bytes_per_sec,
            tokens: bytes_per_sec,
            refill_per_sec: bytes_per_sec,
            last: std::time::Instant::now(),
        })
    }

    /// True if `len` bytes may pass right now.
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
        t.set_attachment(20, Some(2));
        t.set_attachment(10, Some(1));
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
        // The loop-prevention rule: a frame from the mesh may only be
        // delivered locally, never forwarded onward.
        assert_eq!(tables().route(Origin::Relay(2), 20, 10), Route::Local(10));
        assert_eq!(
            tables().route(Origin::Relay(2), 20, 999),
            Route::Drop("no_second_hop")
        );
        // Even when the destination is reachable via another mesh link.
        let mut t = tables();
        t.set_mesh(3, true);
        t.set_attachment(40, Some(3));
        assert_eq!(t.route(Origin::Relay(2), 20, 40), Route::Drop("no_second_hop"));
    }

    #[test]
    fn spoofed_source_dropped() {
        // Session authenticated as #10 claims to be #99.
        assert_eq!(tables().route(Origin::Client(10), 99, 20), Route::Drop("src_spoofed"));
    }

    #[test]
    fn gateway_traffic_terminates_here() {
        assert_eq!(tables().route(Origin::Client(10), 10, 1), Route::Me);
        assert_eq!(tables().route(Origin::Relay(2), 20, 1), Route::Me);
    }

    #[test]
    fn an_addressed_relay_is_reachable_over_its_mesh_link() {
        // Relays are never in the attachment table, so routing to one
        // has to come from the mesh session itself.
        let t = tables();
        assert_eq!(t.route(Origin::Client(10), 10, 2), Route::Mesh(2));
        // Still exactly one hop: a frame from the mesh is not forwarded on.
        assert_eq!(t.route(Origin::Relay(2), 20, 3), Route::Drop("no_second_hop"));
    }

    #[test]
    fn unknown_and_down_are_distinct_drops() {
        let mut t = tables();
        assert_eq!(t.route(Origin::Client(10), 10, 777), Route::Drop("dst_unknown"));
        t.set_mesh(2, false);
        assert_eq!(t.route(Origin::Client(10), 10, 20), Route::Drop("mesh_link_down"));
    }

    #[test]
    fn local_beats_stale_attachment() {
        // A client that just moved to me may still be listed elsewhere in
        // the coordinator's table; local delivery wins immediately.
        let mut t = tables();
        t.set_attachment(20, Some(2));
        t.set_local(20, true);
        assert_eq!(t.route(Origin::Client(10), 10, 20), Route::Local(20));
    }

    #[test]
    fn token_bucket_limits_then_refills() {
        let mut b = TokenBucket::new(1).unwrap(); // 125_000 bytes/s
        assert!(b.allow(100_000));
        assert!(!b.allow(100_000), "burst exhausted");
        std::thread::sleep(std::time::Duration::from_millis(600));
        assert!(b.allow(50_000), "refilled");
    }

    #[test]
    fn unlimited_when_zero() {
        assert!(TokenBucket::new(0).is_none());
    }

    #[test]
    fn counters_track_every_decision() {
        let c = Counters::default();
        c.note(&Route::Local(1));
        c.note(&Route::Drop("src_spoofed"));
        c.note(&Route::Drop("no_second_hop"));
        let s = c.snapshot();
        assert_eq!(s.iter().find(|(k, _)| *k == "delivered_local").unwrap().1, 1);
        assert_eq!(s.iter().find(|(k, _)| *k == "drop_src_spoofed").unwrap().1, 1);
        assert_eq!(s.iter().find(|(k, _)| *k == "drop_no_second_hop").unwrap().1, 1);
    }
}
