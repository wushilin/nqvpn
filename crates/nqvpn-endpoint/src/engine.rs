//! The endpoint data plane (DESIGN.md §9, tasks 2 and 3).
//!
//! Outbound: TUN read -> LPM -> Noise seal -> uplink frame.
//! Inbound:  frame -> replay window -> unseal -> ingress filter -> TUN.
//!
//! Everything expensive is off this path: credentials are verified at
//! session setup, membership is applied by the control task into a
//! table this loop only reads.

use nqvpn_proto::frame::{RoutedHeader, TraceNote, FLAG_TRACE, T_DATA, T_HANDSHAKE, T_TRACE_NOTE};
use nqvpn_proto::seal::{PairSession, StaticKeys};
use nqvpn_proto::types::NodeId;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::peers::{parse_inner_addrs, IngressVerdict, PeerTable, SessionTable};
use crate::tun::TunDevice;

#[derive(Debug, Default)]
pub struct Counters {
    pub sent: AtomicU64,
    pub received: AtomicU64,
    pub handshakes_started: AtomicU64,
    pub handshakes_completed: AtomicU64,
    pub handshakes_yielded: AtomicU64,
    pub drop_no_route: AtomicU64,
    pub drop_no_session: AtomicU64,
    pub drop_queue_full: AtomicU64,
    pub drop_seal_failed: AtomicU64,
    pub drop_replay: AtomicU64,
    pub drop_ingress: AtomicU64,
    pub drop_oversize: AtomicU64,
    pub drop_key_mismatch: AtomicU64,
    pub drop_stale_handshake: AtomicU64,
    pub drop_malformed: AtomicU64,
    pub handshake_timeouts: AtomicU64,
    pub looped_back: AtomicU64,
    pub trace_notes: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> Vec<(&'static str, u64)> {
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        vec![
            ("sent", g(&self.sent)),
            ("received", g(&self.received)),
            ("handshakes_started", g(&self.handshakes_started)),
            ("handshakes_completed", g(&self.handshakes_completed)),
            ("handshakes_yielded", g(&self.handshakes_yielded)),
            ("drop_no_route", g(&self.drop_no_route)),
            ("drop_no_session", g(&self.drop_no_session)),
            ("drop_queue_full", g(&self.drop_queue_full)),
            ("drop_seal_failed", g(&self.drop_seal_failed)),
            ("drop_replay", g(&self.drop_replay)),
            ("drop_ingress", g(&self.drop_ingress)),
            ("drop_oversize", g(&self.drop_oversize)),
            ("drop_key_mismatch", g(&self.drop_key_mismatch)),
            ("drop_stale_handshake", g(&self.drop_stale_handshake)),
            ("drop_malformed", g(&self.drop_malformed)),
            ("handshake_timeouts", g(&self.handshake_timeouts)),
            ("looped_back", g(&self.looped_back)),
            ("trace_notes", g(&self.trace_notes)),
        ]
    }

    pub fn get(&self, name: &str) -> u64 {
        self.snapshot().into_iter().find(|(k, _)| *k == name).map(|(_, v)| v).unwrap_or(0)
    }
}

/// Anything that can carry frames toward the network. `lane` is the
/// transport lane, chosen here from the inner flow and echoed by relays.
pub trait Uplink: Send + Sync + 'static {
    fn send(&self, datagram: Vec<u8>, lane: u8) -> bool;
}

/// Trace state: which destination to tag, and what relays said back.
#[derive(Default)]
struct Trace {
    target: Option<IpAddr>,
    notes: VecDeque<TraceNote>,
}

const TRACE_NOTES_KEPT: usize = 256;

pub struct Engine {
    pub my_node_id: NodeId,
    pub network_uuid: String,
    pub keys: StaticKeys,
    pub peers: Mutex<PeerTable>,
    pub sessions: Mutex<SessionTable>,
    pub counters: Counters,
    pub mtu: u16,
    pub lanes: u8,
    trace: Mutex<Trace>,
}

impl Engine {
    pub fn new(
        my_node_id: NodeId,
        network_uuid: String,
        keys: StaticKeys,
        peers: PeerTable,
        mtu: u16,
        lanes: u8,
    ) -> Arc<Engine> {
        Arc::new(Engine {
            my_node_id,
            network_uuid,
            keys,
            peers: Mutex::new(peers),
            sessions: Mutex::new(SessionTable::default()),
            counters: Counters::default(),
            mtu,
            lanes,
            trace: Mutex::new(Trace::default()),
        })
    }

    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Tag every packet to `target` so relays report their decisions;
    /// `None` stops. Notes arrive via `take_trace_notes`.
    pub fn set_trace(&self, target: Option<IpAddr>) {
        let mut t = self.trace.lock().unwrap();
        t.target = target;
        t.notes.clear();
    }

    pub fn take_trace_notes(&self) -> Vec<TraceNote> {
        self.trace.lock().unwrap().notes.drain(..).collect()
    }

    fn frame(&self, kind: u8, dst: NodeId, body: &[u8], ctr: Option<u64>, packet: &[u8]) -> Vec<u8> {
        let mut h = RoutedHeader::new(kind, self.my_node_id, dst, nqvpn_proto::flow::trace_id(packet));
        if let Some(target) = self.trace.lock().unwrap().target {
            if parse_inner_addrs(packet).map(|(_, d)| d == target).unwrap_or(false) {
                h.flags |= FLAG_TRACE;
            }
        }
        let mut buf = Vec::with_capacity(body.len() + 23);
        h.write(&mut buf);
        if let Some(c) = ctr {
            buf.extend_from_slice(&c.to_be_bytes());
        }
        buf.extend_from_slice(body);
        buf
    }

    /// One packet from the TUN. Seals and sends, or starts a handshake
    /// and queues, or drops with a named counter.
    pub fn outbound(&self, packet: Vec<u8>, up: &dyn Uplink, tun: &dyn TunDevice) {
        if packet.len() > self.mtu as usize {
            self.counters.drop_oversize.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some((_, dst)) = parse_inner_addrs(&packet) else {
            self.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // Traffic to one of our own *host* addresses never goes on the
        // wire: hand it back so the local stack answers it (macOS routes
        // a utun's own address into the utun). Only host addresses — a
        // gateway's LAN must go out the LAN, never back into the TUN.
        {
            let p = self.peers.lock().unwrap();
            if p.is_mine_host(dst) {
                drop(p);
                self.counters.looped_back.fetch_add(1, Ordering::Relaxed);
                tun.write(packet);
                return;
            }
        }
        let (owner, pubkey) = {
            let p = self.peers.lock().unwrap();
            match p.owner_of(dst) {
                Some(o) => (o, p.pubkey_of(o)),
                None => {
                    self.counters.drop_no_route.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };

        let mut sessions = self.sessions.lock().unwrap();
        if sessions.is_ready(owner) {
            let s = sessions.get_mut(owner).expect("checked");
            match s.seal(&packet) {
                Ok((ctr, ct)) => {
                    drop(sessions);
                    let lane = nqvpn_proto::flow::lane_for(&packet, self.lanes);
                    let f = self.frame(T_DATA, owner, &ct, Some(ctr), &packet);
                    if up.send(f, lane) {
                        self.counters.sent.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    self.counters.drop_seal_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            return;
        }

        // No session yet: queue the packet and (once) start the handshake.
        if !sessions.queue(owner, packet.clone()) {
            self.counters.drop_queue_full.fetch_add(1, Ordering::Relaxed);
        }
        if !sessions.has(owner) {
            let Some(pk) = pubkey else {
                self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
                return;
            };
            match sessions.initiate(&self.keys, owner, &pk, &self.network_uuid, self.my_node_id, self.now()) {
                Ok(msg) => {
                    drop(sessions);
                    self.counters.handshakes_started.fetch_add(1, Ordering::Relaxed);
                    let f = self.frame(T_HANDSHAKE, owner, &msg, None, &packet);
                    up.send(f, nqvpn_proto::transport::LANE_DEFAULT);
                }
                Err(_) => {
                    self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// One frame from the uplink (probes never reach here; the session
    /// layer answers them).
    pub fn inbound(&self, datagram: &[u8], up: &dyn Uplink, tun: &dyn TunDevice) {
        if datagram.first() == Some(&T_TRACE_NOTE) {
            if let Some(n) = TraceNote::parse(datagram) {
                self.counters.trace_notes.fetch_add(1, Ordering::Relaxed);
                let mut t = self.trace.lock().unwrap();
                if t.notes.len() >= TRACE_NOTES_KEPT {
                    t.notes.pop_front();
                }
                t.notes.push_back(n);
            }
            return;
        }
        let Some(h) = RoutedHeader::parse(datagram) else {
            self.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if h.dst_id != self.my_node_id {
            self.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let body = &datagram[nqvpn_proto::frame::ROUTED_HEADER_LEN..];
        match h.kind {
            T_HANDSHAKE => self.on_handshake(h.src_id, body, up),
            T_DATA => {
                if body.len() < 8 {
                    self.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let ctr = u64::from_be_bytes(body[..8].try_into().expect("checked"));
                let mut sessions = self.sessions.lock().unwrap();
                let Some(s) = sessions.get_mut(h.src_id) else {
                    self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
                    return;
                };
                match s.unseal(ctr, &body[8..]) {
                    Ok(inner) => {
                        drop(sessions);
                        let verdict = self.peers.lock().unwrap().check_ingress(h.src_id, &inner);
                        match verdict {
                            IngressVerdict::Accept => {
                                self.counters.received.fetch_add(1, Ordering::Relaxed);
                                tun.write(inner);
                            }
                            IngressVerdict::Drop(_) => {
                                self.counters.drop_ingress.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(nqvpn_proto::seal::SealError::Replay(_)) => {
                        self.counters.drop_replay.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        self.counters.drop_seal_failed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            _ => {
                self.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn on_handshake(&self, peer: NodeId, msg: &[u8], up: &dyn Uplink) {
        let now = self.now();
        let mut sessions = self.sessions.lock().unwrap();
        // An in-flight initiator session expects the responder's reply.
        let mut carried: Vec<Vec<u8>> = Vec::new();
        if let Some(s) = sessions.get_mut(peer) {
            if !s.is_ready() && s.initiator {
                if s.finish(msg).is_ok() && s.is_ready() {
                    self.counters.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                    self.flush_pending(&mut sessions, peer, up);
                    return;
                }
                // Not a reply: both sides initiated at once. Exactly one
                // yields — the lower node id — and answers the other's
                // message below, carrying its queued packets over.
                if self.my_node_id < peer {
                    self.counters.handshakes_yielded.fetch_add(1, Ordering::Relaxed);
                    carried = sessions.take_pending(peer);
                    sessions.remove(peer);
                } else {
                    return;
                }
            }
        }
        match PairSession::respond(&self.keys, peer, &self.network_uuid, self.my_node_id, msg, now) {
            Ok((s, reply, ts)) => {
                let expected = self.peers.lock().unwrap().pubkey_of(peer);
                match (s.peer_static(), expected) {
                    (Some(got), Some(want)) if got == want => {
                        // Advance the replay watermark ONLY after the
                        // static key is verified. Otherwise an untrusted
                        // relay could inject a wrong-key initiation with a
                        // far-future timestamp: the key check would reject
                        // the session, but the poisoned watermark would
                        // then refuse every real handshake from that peer
                        // until restart. A msg1 older than the last we
                        // accepted is a replay.
                        if !sessions.accept_handshake_ts(peer, ts) {
                            self.counters.drop_stale_handshake.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        sessions.insert(peer, s);
                        for p in carried {
                            sessions.queue(peer, p);
                        }
                        self.counters.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                        drop(sessions);
                        up.send(self.frame(T_HANDSHAKE, peer, &reply, None, &[]), nqvpn_proto::transport::LANE_DEFAULT);
                        let mut sessions = self.sessions.lock().unwrap();
                        self.flush_pending(&mut sessions, peer, up);
                    }
                    _ => {
                        self.counters.drop_key_mismatch.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(_) => {
                self.counters.drop_seal_failed.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Seal and send whatever waited for this peer's session. Takes the
    /// lock guard so the caller's critical section is not reopened.
    fn flush_pending(&self, sessions: &mut std::sync::MutexGuard<'_, SessionTable>, peer: NodeId, up: &dyn Uplink) {
        let queued = sessions.take_pending(peer);
        let mut frames = Vec::new();
        if let Some(s) = sessions.get_mut(peer) {
            for pkt in queued {
                let lane = nqvpn_proto::flow::lane_for(&pkt, self.lanes);
                if let Ok((ctr, ct)) = s.seal(&pkt) {
                    frames.push((self.frame(T_DATA, peer, &ct, Some(ctr), &pkt), lane));
                }
            }
        }
        for (f, lane) in frames {
            if up.send(f, lane) {
                self.counters.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Drop sessions past their rekey deadline; the next packet starts a
    /// fresh handshake, which is also what gives forward secrecy.
    pub fn expire_sessions(&self) {
        let now = self.now();
        let mut s = self.sessions.lock().unwrap();
        for peer in s.sessions_due_for_rekey(now) {
            s.remove(peer);
        }
        for peer in s.stale_handshakes(now) {
            tracing::debug!(peer, "handshake timed out; will retry");
            s.remove(peer);
            self.counters.handshake_timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn status_line(&self) -> String {
        let peers = self.peers.lock().unwrap().len();
        let c = self
            .counters
            .snapshot()
            .into_iter()
            .filter(|(_, v)| *v > 0)
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!("node={} peers={peers} {c}", self.my_node_id)
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::*;
    use nqvpn_proto::control::PeerInfo;
    use nqvpn_proto::seal::decode_pubkey;
    use nqvpn_proto::types::Role;

    struct NoUplink;
    impl Uplink for NoUplink {
        fn send(&self, _d: Vec<u8>, _l: u8) -> bool {
            true
        }
    }

    fn peer_info(id: NodeId, pubkey_b64: &str) -> PeerInfo {
        PeerInfo {
            node_id: id,
            name: format!("n{id}"),
            role: Role::Client,
            prefixes: vec![],
            pubkey: pubkey_b64.to_string(),
            online: true,
            login_gen: 0,
        }
    }

    /// Regression: a relay-injected handshake made with the *wrong*
    /// static key and a far-future timestamp must not poison the replay
    /// watermark. Before the fix it did, and every real handshake from
    /// that peer was then refused as stale until restart.
    #[test]
    fn a_wrong_key_handshake_cannot_poison_the_replay_watermark() {
        const ME: NodeId = 1;
        const PEER: NodeId = 2;
        let uuid = "test-uuid";

        let our_keys = StaticKeys::generate().unwrap();
        let our_pub = decode_pubkey(&our_keys.public_b64()).unwrap();
        let peer_keys = StaticKeys::generate().unwrap();
        let attacker_keys = StaticKeys::generate().unwrap();

        let mut table = PeerTable::new(ME);
        // The coordinator-published key for PEER is its real one.
        table.upsert(peer_info(PEER, &peer_keys.public_b64()));
        let engine = Engine::new(ME, uuid.to_string(), our_keys, table, 1350, 1);
        let up = NoUplink;

        // Attacker (relay) forges a msg1 as PEER but with its own static
        // key and timestamp u64::MAX.
        let (_att, att_msg1) = PairSession::initiate(&attacker_keys, ME, &our_pub, uuid, PEER, u64::MAX).unwrap();
        engine.on_handshake(PEER, &att_msg1, &up);
        assert_eq!(engine.counters.drop_key_mismatch.load(Ordering::Relaxed), 1, "wrong static key is rejected");
        assert_eq!(engine.counters.handshakes_completed.load(Ordering::Relaxed), 0);

        // The real PEER now handshakes with a normal timestamp. It must
        // succeed — the watermark was not poisoned.
        let (_p, p_msg1) = PairSession::initiate(&peer_keys, ME, &our_pub, uuid, PEER, 1000).unwrap();
        engine.on_handshake(PEER, &p_msg1, &up);
        assert_eq!(engine.counters.drop_stale_handshake.load(Ordering::Relaxed), 0, "real handshake is not refused as stale");
        assert_eq!(engine.counters.handshakes_completed.load(Ordering::Relaxed), 1, "the real peer establishes a session");
    }
}
