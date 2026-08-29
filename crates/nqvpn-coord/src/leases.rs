//! Liveness and attachment leases (§7): what members have *told* us,
//! with timestamps, and nothing set by one message and cleared by
//! another.
//!
//! Every fact here comes from a heartbeat and expires. A relay declares
//! the whole set of clients it holds; the attachment table is derived
//! from those declarations by one rule — **the most recent declaration
//! wins** — and an entry disappears only when the relay stops declaring
//! it or the member is removed. Neither side's *control* lease matters:
//! a relay that cannot reach the coordinator can still forward for its
//! clients, and a client that cannot reach the coordinator is still
//! attached to its relay. The relay's own session with the client is
//! the truth, and the relay reports it for as long as it lasts.
//!
//! All timestamps here are **milliseconds**: two relays can declare the
//! same client within one second during a move, and the later one must
//! still win.

use nqvpn_proto::control::{AttachedClient, Heartbeat};
use nqvpn_proto::types::{NodeId, Role};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Clone, Copy)]
struct Claim {
    session_id: u64,
    /// Order in which this relay first declared this client with this
    /// session id. A sequence number rather than a clock: two relays can
    /// declare the same client within one millisecond during a move,
    /// and "the most recent declaration" must still be exactly one.
    seq: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Report {
    pub gen: u64,
    pub digest: u64,
    pub at: u64,
}

#[derive(Debug, Default)]
pub struct Leases {
    last_seen: HashMap<NodeId, u64>,
    online_since: HashMap<NodeId, u64>,
    /// relay -> (client -> claim)
    declared: HashMap<NodeId, HashMap<NodeId, Claim>>,
    attached_to: HashMap<NodeId, NodeId>,
    mesh_up: HashMap<NodeId, Vec<NodeId>>,
    reported: HashMap<NodeId, Report>,
    next_seq: u64,
}

impl Leases {
    /// A member proved it is alive (a session opened, or a heartbeat
    /// arrived). Returns true if it was offline before.
    pub fn seen(&mut self, node: NodeId, now: u64) -> bool {
        let was_online = self.last_seen.contains_key(&node);
        self.last_seen.insert(node, now);
        if !was_online {
            self.online_since.insert(node, now);
        }
        !was_online
    }

    /// Fold in a heartbeat. Returns true if the derived attachment table
    /// may have changed.
    pub fn heartbeat(&mut self, node: NodeId, role: Role, hb: &Heartbeat, now: u64) -> bool {
        self.seen(node, now);
        self.reported.insert(node, Report { gen: hb.gen, digest: hb.digest, at: now });
        match role {
            Role::Relay => {
                let next_seq = &mut self.next_seq;
                let mine = self.declared.entry(node).or_default();
                let mut changed = false;
                let mut keep: HashMap<NodeId, Claim> = HashMap::new();
                for AttachedClient { node_id, session_id } in &hb.attached {
                    let claim = match mine.get(node_id) {
                        Some(c) if c.session_id == *session_id => *c,
                        _ => {
                            changed = true;
                            *next_seq += 1;
                            Claim { session_id: *session_id, seq: *next_seq }
                        }
                    };
                    keep.insert(*node_id, claim);
                }
                if keep.len() != mine.len() {
                    changed = true;
                }
                *mine = keep;
                self.mesh_up.insert(node, hb.mesh_up.clone());
                changed
            }
            Role::Client => {
                match hb.attached_to {
                    Some(r) => self.attached_to.insert(node, r),
                    None => self.attached_to.remove(&node),
                };
                false
            }
        }
    }

    /// Expire members silent for longer than `window`. Returns the ones
    /// that just went offline. Claims are untouched: the relay holding
    /// the session keeps reporting it for as long as it lasts.
    pub fn expire(&mut self, now: u64, window: u64) -> Vec<NodeId> {
        let gone: Vec<NodeId> = self
            .last_seen
            .iter()
            .filter(|(_, last)| now.saturating_sub(**last) > window)
            .map(|(n, _)| *n)
            .collect();
        for n in &gone {
            self.offline(*n);
        }
        gone
    }

    /// Forget a member entirely (deleted or disabled): its liveness and
    /// every claim on it.
    pub fn remove(&mut self, node: NodeId) {
        self.offline(node);
        self.reported.remove(&node);
        for claims in self.declared.values_mut() {
            claims.remove(&node);
        }
    }

    /// Drop everything a relay ever declared. Used when the relay is
    /// deleted or disabled — not when it merely stops heartbeating.
    pub fn remove_relay(&mut self, relay: NodeId) {
        self.declared.remove(&relay);
        self.remove(relay);
    }

    /// The control link is gone. Liveness ends; attachments do not.
    pub fn offline(&mut self, node: NodeId) {
        self.last_seen.remove(&node);
        self.online_since.remove(&node);
        self.attached_to.remove(&node);
        self.mesh_up.remove(&node);
    }

    pub fn is_online(&self, node: NodeId) -> bool {
        self.last_seen.contains_key(&node)
    }

    pub fn online_since(&self, node: NodeId) -> Option<u64> {
        self.online_since.get(&node).copied()
    }

    pub fn last_seen(&self, node: NodeId) -> Option<u64> {
        self.last_seen.get(&node).copied()
    }

    pub fn online_nodes(&self) -> Vec<NodeId> {
        self.last_seen.keys().copied().collect()
    }

    /// client -> relay, the most recent declaration winning.
    pub fn attachments(&self) -> BTreeMap<NodeId, NodeId> {
        let mut best: BTreeMap<NodeId, (u64, NodeId)> = BTreeMap::new();
        for (relay, claims) in &self.declared {
            for (client, c) in claims {
                match best.get(client) {
                    Some((seq, _)) if *seq > c.seq => {}
                    _ => {
                        best.insert(*client, (c.seq, *relay));
                    }
                }
            }
        }
        best.into_iter().map(|(c, (_, r))| (c, r)).collect()
    }

    /// (relay, client, session_id, seq) for every claim — status and
    /// debugging.
    pub fn claims(&self) -> Vec<(NodeId, NodeId, u64, u64)> {
        let mut v: Vec<_> = self
            .declared
            .iter()
            .flat_map(|(r, m)| m.iter().map(move |(c, cl)| (*r, *c, cl.session_id, cl.seq)))
            .collect();
        v.sort();
        v
    }

    pub fn declared_by(&self, relay: NodeId) -> Vec<NodeId> {
        self.declared.get(&relay).map(|m| m.keys().copied().collect()).unwrap_or_default()
    }

    pub fn attached_to(&self, client: NodeId) -> Option<NodeId> {
        self.attached_to.get(&client).copied()
    }

    pub fn mesh_up(&self, relay: NodeId) -> &[NodeId] {
        self.mesh_up.get(&relay).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn report(&self, node: NodeId) -> Option<Report> {
        self.reported.get(&node).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hb(attached: &[(NodeId, u64)]) -> Heartbeat {
        Heartbeat {
            attached: attached.iter().map(|(n, s)| AttachedClient { node_id: *n, session_id: *s }).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn declarations_are_sets_not_events() {
        let mut l = Leases::default();
        assert!(l.heartbeat(1, Role::Relay, &hb(&[(10, 1), (11, 1)]), 100));
        assert_eq!(l.attachments().get(&10), Some(&1));
        // A lost "detach" cannot exist: the next declaration omits 11.
        assert!(l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 105));
        assert!(!l.attachments().contains_key(&11));
        // Re-declaring the same set changes nothing.
        assert!(!l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 110));
    }

    #[test]
    fn a_move_is_won_by_the_most_recent_declaration() {
        let mut l = Leases::default();
        l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 100);
        // Client moves to relay 2; relay 1's stale session still lists it.
        l.heartbeat(2, Role::Relay, &hb(&[(10, 1)]), 110);
        l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 115);
        assert_eq!(l.attachments()[&10], 2, "newer declaration wins even while the old repeats");
        // Relay 1's stale session dies; nothing to detach, it just stops.
        l.heartbeat(1, Role::Relay, &hb(&[]), 120);
        assert_eq!(l.attachments()[&10], 2);
        // The client bounces back to relay 1 with a *new* session.
        l.heartbeat(1, Role::Relay, &hb(&[(10, 2)]), 130);
        assert_eq!(l.attachments()[&10], 1, "a new session id is a new declaration");
    }

    #[test]
    fn control_leases_expiring_do_not_detach_anyone() {
        let mut l = Leases::default();
        l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 100);
        l.seen(10, 100);
        let mut gone = l.expire(200, 15);
        gone.sort();
        assert_eq!(gone, vec![1, 10]);
        assert!(!l.is_online(1) && !l.is_online(10));
        // Neither the relay's nor the client's silence to *us* changes
        // the fact that the relay holds the client's session.
        assert_eq!(l.attachments().get(&10), Some(&1));
        // The relay stops declaring it: now it is gone.
        l.heartbeat(1, Role::Relay, &hb(&[]), 300);
        assert!(!l.attachments().contains_key(&10));
        // Explicit removal drops claims at once.
        l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 400);
        l.remove(10);
        assert!(!l.attachments().contains_key(&10));
    }

    #[test]
    fn explicit_removal_forgets_everything() {
        let mut l = Leases::default();
        l.heartbeat(1, Role::Relay, &hb(&[(10, 1)]), 100);
        l.remove_relay(1);
        assert!(l.attachments().is_empty());
        assert!(!l.is_online(1));
    }

    #[test]
    fn reports_and_client_facts_are_recorded() {
        let mut l = Leases::default();
        let mut h = hb(&[]);
        h.gen = 42;
        h.digest = 7;
        h.attached_to = Some(1);
        assert!(!l.heartbeat(10, Role::Client, &h, 100));
        assert_eq!(l.report(10).unwrap().gen, 42);
        assert_eq!(l.attached_to(10), Some(1));
        assert_eq!(l.online_since(10), Some(100));
        l.seen(10, 150);
        assert_eq!(l.online_since(10), Some(100), "still the same online period");
    }
}
