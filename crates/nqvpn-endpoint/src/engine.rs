//! The endpoint data plane (DESIGN.md §9, tasks 2 and 3).
//!
//! Outbound: TUN read -> LPM -> Noise seal -> uplink frame.
//! Inbound:  frame -> replay window -> unseal -> ingress filter -> TUN.
//!
//! Everything expensive is off this path: credentials are verified at
//! session setup, membership is applied by the control task into a
//! table this loop only reads.

use nqvpn_proto::frame::{RoutedHeader, TraceNote, FLAG_TRACE, T_DATA, T_HANDSHAKE, T_TRACE_NOTE};
use nqvpn_proto::control::PeerInfo;
use nqvpn_proto::seal::{decode_pubkey, PairSession, StaticKeys, Tai64n};
use nqvpn_proto::types::NodeId;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
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
    pub rekeys_completed: AtomicU64,
    pub sessions_dropped_by_view: AtomicU64,
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
            ("rekeys_completed", g(&self.rekeys_completed)),
            ("sessions_dropped_by_view", g(&self.sessions_dropped_by_view)),
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
    /// The inner MTU; the coordinator may lower it at runtime.
    mtu: AtomicU16,
    pub lanes: u8,
    trace: Mutex<Trace>,
    /// Seconds to use instead of the system clock, when non-zero (tests
    /// drive rekey deadlines with it).
    clock: AtomicU64,
    /// The last msg1 timestamp we sent: each new one is strictly later,
    /// even within one clock tick or across a clock step backwards, so
    /// the peer's replay check never refuses our own fresh handshake.
    last_ts: Mutex<Tai64n>,
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
            mtu: AtomicU16::new(mtu),
            lanes,
            trace: Mutex::new(Trace::default()),
            clock: AtomicU64::new(0),
            last_ts: Mutex::new(Tai64n::default()),
        })
    }

    fn now(&self) -> u64 {
        match self.clock.load(Ordering::Relaxed) {
            0 => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            fake => fake,
        }
    }

    /// Pin the engine's clock to `secs` (0 returns to the system clock).
    /// For tests that need to cross rekey deadlines without waiting.
    #[doc(hidden)]
    pub fn set_clock(&self, secs: u64) {
        self.clock.store(secs, Ordering::Relaxed);
    }

    /// A msg1 timestamp strictly after every one we sent before.
    fn next_ts(&self) -> Tai64n {
        let mut last = self.last_ts.lock().unwrap();
        let mut ts = match self.clock.load(Ordering::Relaxed) {
            0 => Tai64n::now(),
            fake => Tai64n::new(fake, 0),
        };
        if ts <= *last {
            ts = last.succ();
        }
        *last = ts;
        ts
    }

    pub fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    /// Apply a new inner MTU (the network's, as the coordinator now
    /// publishes it). Packets larger than this are dropped as oversize.
    pub fn set_mtu(&self, mtu: u16) {
        self.mtu.store(mtu, Ordering::Relaxed);
    }

    /// Apply the published membership: the peer table is replaced, and
    /// every session, queue and handshake watermark that no longer
    /// matches it is dropped (see `SessionTable::sync_view`). A peer
    /// whose login generation changed has its watermark reset, so a
    /// re-joined machine is judged by its own clock.
    pub fn sync_peers(&self, members: Vec<PeerInfo>) {
        let mut relogged = Vec::new();
        let published: HashMap<NodeId, Option<Vec<u8>>> = {
            let mut peers = self.peers.lock().unwrap();
            for m in &members {
                if let Some(old) = peers.get(m.node_id) {
                    if old.login_gen != m.login_gen || old.pubkey != m.pubkey {
                        relogged.push(m.node_id);
                    }
                }
            }
            let published = members
                .iter()
                .filter(|m| m.node_id != self.my_node_id)
                .map(|m| (m.node_id, decode_pubkey(&m.pubkey)))
                .collect();
            peers.replace_all(members);
            published
        };
        let mut sessions = self.sessions.lock().unwrap();
        for id in relogged {
            sessions.forget_handshake_ts(id);
        }
        let dropped = sessions.sync_view(&published);
        drop(sessions);
        for id in dropped {
            tracing::debug!(peer = id, "dropping a session the view no longer vouches for");
            self.counters.sessions_dropped_by_view.fetch_add(1, Ordering::Relaxed);
        }
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
        if packet.len() > self.mtu() as usize {
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
        let owner = {
            let p = self.peers.lock().unwrap();
            match p.owner_of(dst) {
                Some(o) => o,
                None => {
                    self.counters.drop_no_route.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        };

        let mut sessions = self.sessions.lock().unwrap();
        if sessions.is_ready(owner) {
            let now = self.now();
            let s = sessions.get_mut(owner).expect("checked");
            let sealed = s.seal(&packet);
            sessions.note_sent(owner, now);
            // Past the soft deadline (or unanswered for too long): negotiate the replacement now, while
            // this session keeps carrying traffic, instead of dropping it
            // and losing packets to a fresh handshake.
            let rekey = if sessions.rekey_due(owner, now) { self.start_rekey(&mut sessions, owner, now) } else { None };
            drop(sessions);
            match sealed {
                Ok((ctr, ct)) => {
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
            if let Some(msg) = rekey {
                self.counters.handshakes_started.fetch_add(1, Ordering::Relaxed);
                up.send(self.frame(T_HANDSHAKE, owner, &msg, None, &packet), nqvpn_proto::transport::LANE_DEFAULT);
            }
            return;
        }

        // No session yet. The peer's static key is needed only to start a
        // handshake — once per session, not per packet. Fetch (and decode)
        // it lazily here, holding the sessions lock, in the sessions→peers
        // order on_handshake already uses. The steady-state path above
        // never touches it, so no per-packet decode/allocation.
        let starting = !sessions.has(owner);
        let pk = if starting { self.peers.lock().unwrap().pubkey_of(owner) } else { None };
        if starting && pk.is_none() {
            // No usable key: no handshake can ever drain a queue for this
            // peer, so keep none.
            sessions.take_pending(owner);
            self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // Queue the packet and (once) start the handshake.
        if !sessions.queue(owner, packet.clone()) {
            self.counters.drop_queue_full.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(pk) = pk {
            match sessions.initiate_at(&self.keys, owner, &pk, &self.network_uuid, self.my_node_id, self.now(), self.next_ts()) {
                Ok(msg) => {
                    drop(sessions);
                    self.counters.handshakes_started.fetch_add(1, Ordering::Relaxed);
                    let f = self.frame(T_HANDSHAKE, owner, &msg, None, &packet);
                    up.send(f, nqvpn_proto::transport::LANE_DEFAULT);
                }
                Err(_) => {
                    sessions.take_pending(owner);
                    self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Begin replacing `peer`'s working session; returns the msg1 to send.
    fn start_rekey(&self, sessions: &mut SessionTable, peer: NodeId, now: u64) -> Option<Vec<u8>> {
        let pk = self.peers.lock().unwrap().pubkey_of(peer)?;
        sessions.initiate_rekey(&self.keys, peer, &pk, &self.network_uuid, self.my_node_id, now, self.next_ts()).ok()
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
                let now = self.now();
                let mut sessions = self.sessions.lock().unwrap();
                match sessions.unseal(h.src_id, ctr, &body[8..], now) {
                    // An empty payload is a keepalive: a rekey initiator's
                    // proof that it holds the new keys. Nothing to deliver.
                    Ok(inner) if inner.is_empty() => {}
                    Ok(inner) => {
                        // Quiet toward this peer for a while: answer with a
                        // keepalive so its sender knows the session lives.
                        let keepalive = if sessions.keepalive_due(h.src_id, now) {
                            sessions.note_sent(h.src_id, now);
                            sessions.get_mut(h.src_id).and_then(|s| s.seal(&[]).ok())
                        } else {
                            None
                        };
                        drop(sessions);
                        if let Some((ctr, ct)) = keepalive {
                            up.send(self.frame(T_DATA, h.src_id, &ct, Some(ctr), &[]), nqvpn_proto::transport::LANE_DEFAULT);
                        }
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
                    Err(nqvpn_proto::seal::SealError::NoSession(_)) => {
                        self.counters.drop_no_session.fetch_add(1, Ordering::Relaxed);
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
        // Our rekey in flight expects the responder's reply.
        if let Some(n) = sessions.next_in_flight(peer) {
            if n.finish(msg).is_ok() && n.is_ready() {
                sessions.promote(peer, now);
                self.counters.handshakes_completed.fetch_add(1, Ordering::Relaxed);
                self.counters.rekeys_completed.fetch_add(1, Ordering::Relaxed);
                // Tell the responder at once that we hold the new keys: it
                // keeps sealing to the old ones until a frame arrives on
                // the new, and our old ones only last the grace period.
                let keepalive = sessions.get_mut(peer).and_then(|s| s.seal(&[]).ok());
                sessions.note_sent(peer, now);
                self.flush_pending(&mut sessions, peer, up);
                drop(sessions);
                if let Some((ctr, ct)) = keepalive {
                    up.send(self.frame(T_DATA, peer, &ct, Some(ctr), &[]), nqvpn_proto::transport::LANE_DEFAULT);
                }
                return;
            }
            // Not a reply: both sides started a rekey at once. The same
            // rule as a crossed first handshake — the lower id yields and
            // answers the other's message below.
            if self.my_node_id < peer {
                self.counters.handshakes_yielded.fetch_add(1, Ordering::Relaxed);
                sessions.drop_next(peer);
            } else {
                return;
            }
        }
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
                        // until restart. A msg1 not newer than the last we
                        // accepted under this key is a replay.
                        if !sessions.accept_handshake_ts(peer, &got, ts) {
                            self.counters.drop_stale_handshake.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        // With a working session this is the peer's rekey:
                        // the new session waits for the peer's first frame
                        // on it, and we keep sending on the old meanwhile.
                        sessions.install_responder(peer, s);
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
        if !sessions.is_ready(peer) {
            return;
        }
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
        if !frames.is_empty() {
            sessions.note_sent(peer, self.now());
        }
        for (f, lane) in frames {
            if up.send(f, lane) {
                self.counters.sent.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// The periodic sweep: drop sessions past their hard deadline (the
    /// soft one is handled on the send path, which starts the replacement
    /// while the old session still works), handshakes that never
    /// completed, and previous sessions whose receive grace ran out.
    pub fn expire_sessions(&self) {
        let now = self.now();
        let timed_out = self.sessions.lock().unwrap().expire(now);
        for peer in timed_out {
            tracing::debug!(peer, "handshake timed out; will retry");
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
        let (_att, att_msg1) = PairSession::initiate_at(&attacker_keys, ME, &our_pub, uuid, PEER, 0, Tai64n::new(u64::MAX, 999_999_999)).unwrap();
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

    struct NullTun;
    impl TunDevice for NullTun {
        fn reader(&self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
            tokio::sync::mpsc::channel(1).1
        }
        fn write(&self, _p: Vec<u8>) -> bool {
            true
        }
        fn mtu(&self) -> u16 {
            1350
        }
        fn name(&self) -> String {
            "null".into()
        }
    }

    fn v4_to(dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&dst);
        p
    }

    /// The first packet to a peer with no session starts a handshake. The
    /// peer's static key is needed only here — fetched lazily off the
    /// steady-state path — so this exercises that the lazy fetch works and
    /// that a peer whose key does not decode cannot start one.
    #[test]
    fn outbound_to_a_new_peer_starts_a_handshake_and_a_bad_key_cannot() {
        const ME: NodeId = 1;
        let peer_keys = StaticKeys::generate().unwrap();

        let mut table = PeerTable::new(ME);
        // #2 is routable and has a real key; #3 is routable but its key is
        // not decodable (as if the coordinator sent a malformed pubkey).
        let mut good = peer_info(2, &peer_keys.public_b64());
        good.prefixes = vec!["10.9.0.2/32".parse().unwrap()];
        table.upsert(good);
        let mut bad = peer_info(3, "not-base64!!");
        bad.prefixes = vec!["10.9.0.3/32".parse().unwrap()];
        table.upsert(bad);

        let engine = Engine::new(ME, "uuid".to_string(), StaticKeys::generate().unwrap(), table, 1350, 1);
        let (up, tun) = (NoUplink, NullTun);

        engine.outbound(v4_to([10, 9, 0, 2]), &up, &tun);
        assert_eq!(engine.counters.handshakes_started.load(Ordering::Relaxed), 1, "a routable peer's first packet starts a handshake");
        assert_eq!(engine.counters.drop_no_route.load(Ordering::Relaxed), 0);

        engine.outbound(v4_to([10, 9, 0, 3]), &up, &tun);
        assert_eq!(engine.counters.handshakes_started.load(Ordering::Relaxed), 1, "an undecodable key cannot start a handshake");
        assert_eq!(engine.counters.drop_no_session.load(Ordering::Relaxed), 1, "it is dropped for want of a session");

        // A packet to nowhere is a no-route drop, not a handshake.
        engine.outbound(v4_to([10, 9, 0, 9]), &up, &tun);
        assert_eq!(engine.counters.drop_no_route.load(Ordering::Relaxed), 1);
        assert_eq!(engine.counters.handshakes_started.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod rekey_tests {
    use super::*;
    use nqvpn_proto::control::PeerInfo;
    use nqvpn_proto::seal::{REJECT_AFTER_SECS, REKEY_AFTER_SECS, RESPONDER_REKEY_DELAY_SECS};
    use nqvpn_proto::types::Role;

    /// Captures what an engine sends, for delivery by hand.
    #[derive(Default)]
    struct Wire(Mutex<Vec<Vec<u8>>>);
    impl Uplink for Wire {
        fn send(&self, d: Vec<u8>, _l: u8) -> bool {
            self.0.lock().unwrap().push(d);
            true
        }
    }
    impl Wire {
        fn take(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    #[derive(Default)]
    struct RecTun(Mutex<Vec<Vec<u8>>>);
    impl TunDevice for RecTun {
        fn reader(&self) -> tokio::sync::mpsc::Receiver<Vec<u8>> {
            tokio::sync::mpsc::channel(1).1
        }
        fn write(&self, p: Vec<u8>) -> bool {
            self.0.lock().unwrap().push(p);
            true
        }
        fn mtu(&self) -> u16 {
            1350
        }
        fn name(&self) -> String {
            "rec".into()
        }
    }

    struct Node {
        engine: Arc<Engine>,
        wire: Wire,
        tun: RecTun,
        ip: [u8; 4],
    }

    fn info(id: NodeId, ip: [u8; 4], keys: &StaticKeys) -> PeerInfo {
        PeerInfo {
            node_id: id,
            name: format!("n{id}"),
            role: Role::Client,
            prefixes: vec![format!("{}.{}.{}.{}/32", ip[0], ip[1], ip[2], ip[3]).parse().unwrap()],
            pubkey: keys.public_b64(),
            online: true,
            login_gen: 0,
        }
    }

    /// Two engines, 1 and 2, that know each other, on a fixed clock.
    fn pair(now: u64) -> (Node, Node) {
        let (ka, kb) = (StaticKeys::generate().unwrap(), StaticKeys::generate().unwrap());
        let (ipa, ipb) = ([10, 9, 0, 1], [10, 9, 0, 2]);
        let mk = |me: NodeId, ip: [u8; 4], keys: &StaticKeys, other: PeerInfo| {
            let mut t = PeerTable::new(me);
            t.set_mine(vec![format!("{}.{}.{}.{}/32", ip[0], ip[1], ip[2], ip[3]).parse().unwrap()], vec![]);
            t.upsert(other);
            let e = Engine::new(me, "uuid".into(), keys.clone(), t, 1350, 1);
            e.set_clock(now);
            Node { engine: e, wire: Wire::default(), tun: RecTun::default(), ip }
        };
        let a = mk(1, ipa, &ka, info(2, ipb, &kb));
        let b = mk(2, ipb, &kb, info(1, ipa, &ka));
        (a, b)
    }

    fn pkt(src: [u8; 4], dst: [u8; 4], tag: u8) -> Vec<u8> {
        let mut p = vec![0u8; 21];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20] = tag;
        p
    }

    fn send(from: &Node, to: &Node, tag: u8) {
        from.engine.outbound(pkt(from.ip, to.ip, tag), &from.wire, &from.tun);
    }

    fn deliver(frames: Vec<Vec<u8>>, to: &Node) {
        for f in frames {
            to.engine.inbound(&f, &to.wire, &to.tun);
        }
    }

    /// Deliver both ways until nothing is in flight.
    fn settle(a: &Node, b: &Node) {
        for _ in 0..10 {
            let (fa, fb) = (a.wire.take(), b.wire.take());
            if fa.is_empty() && fb.is_empty() {
                return;
            }
            deliver(fa, b);
            deliver(fb, a);
        }
    }

    fn tags(n: &Node) -> Vec<u8> {
        n.tun.0.lock().unwrap().iter().map(|p| p[20]).collect()
    }

    fn clock(a: &Node, b: &Node, t: u64) {
        a.engine.set_clock(t);
        b.engine.set_clock(t);
    }

    fn no_losses(n: &Node) {
        for c in ["drop_seal_failed", "drop_no_session", "drop_replay", "drop_ingress", "drop_stale_handshake"] {
            assert_eq!(n.engine.counters.get(c), 0, "node {}: {c}", n.engine.my_node_id);
        }
    }

    /// The rekey race this guards: at the soft deadline the old code
    /// dropped the session outright, and the responder sealed to new keys
    /// the initiator did not hold yet. Here frames cross the switch in the
    /// worst order and none is lost.
    #[test]
    fn a_rekey_loses_no_packets_in_either_direction() {
        let t0 = 1_000_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1]);

        // Soft deadline: A (the initiator) seals on the old session and
        // starts the replacement in the same breath.
        clock(&a, &b, t0 + REKEY_AFTER_SECS);
        send(&a, &b, 2);
        let a_out = a.wire.take();
        assert_eq!(a_out.len(), 2, "data on the old keys, then the rekey msg1");
        deliver(a_out, &b);
        assert_eq!(tags(&b), vec![1, 2]);
        // B answered. Before its reply reaches A, B sends: still on the
        // old keys, since A cannot hold the new ones yet.
        send(&b, &a, 3);
        let b_out = b.wire.take();
        // The reply, the data frame, and a keepalive (B had been silent
        // toward A since the first exchange), all on the old keys but the reply.
        assert_eq!(b_out.len(), 3, "the reply, a keepalive and one data frame");
        let (reply, b_data): (Vec<_>, Vec<_>) = b_out.into_iter().partition(|f| f[0] == T_HANDSHAKE);
        // The reply reaches A first: A switches and confirms with a keepalive.
        deliver(reply, &a);
        assert_eq!(a.engine.counters.get("rekeys_completed"), 1);
        // B's old-key frame arrives after A switched: the previous session
        // still opens it.
        deliver(b_data, &a);
        assert_eq!(tags(&a), vec![3]);
        // A's new-key traffic overtakes its keepalive: the frame itself
        // confirms the new session at B.
        send(&a, &b, 4);
        let mut a_out = a.wire.take();
        a_out.reverse();
        deliver(a_out, &b);
        assert_eq!(tags(&b), vec![1, 2, 4]);
        // B now seals on the new keys, which A holds.
        send(&b, &a, 5);
        settle(&a, &b);
        assert_eq!(tags(&a), vec![3, 5]);
        no_losses(&a);
        no_losses(&b);

        // The old keys are forgotten once the grace is over, and the new
        // session carries on.
        clock(&a, &b, t0 + REKEY_AFTER_SECS + nqvpn_proto::seal::PREVIOUS_GRACE_SECS);
        a.engine.expire_sessions();
        b.engine.expire_sessions();
        send(&a, &b, 6);
        send(&b, &a, 7);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1, 2, 4, 6]);
        assert_eq!(tags(&a), vec![3, 5, 7]);
        no_losses(&a);
        no_losses(&b);
    }

    #[test]
    fn a_crossed_rekey_resolves_to_one_session() {
        let t0 = 2_000_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        // Both deadlines have passed (the responder's later one too): each
        // side sends and starts a rekey at the same moment.
        clock(&a, &b, t0 + REKEY_AFTER_SECS + RESPONDER_REKEY_DELAY_SECS);
        send(&a, &b, 2);
        send(&b, &a, 3);
        settle(&a, &b);
        assert_eq!(a.engine.counters.get("handshakes_yielded"), 1, "the lower id yields");
        assert_eq!(b.engine.counters.get("handshakes_yielded"), 0);
        for i in 4..8 {
            send(&a, &b, i);
            send(&b, &a, i + 10);
        }
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1, 2, 4, 5, 6, 7]);
        assert_eq!(tags(&a), vec![3, 14, 15, 16, 17]);
        no_losses(&a);
        no_losses(&b);
    }

    /// A session only one side still holds (the peer dropped it when the
    /// view briefly lost us, or restarted) must not stay silent until the
    /// rekey deadline: the sender, hearing nothing back, re-handshakes.
    #[test]
    fn a_session_the_peer_dropped_is_repaired_by_the_silence() {
        let t0 = 2_500_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        b.engine.sessions.lock().unwrap().remove(1);
        send(&a, &b, 2);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1], "sealed to keys B no longer holds");
        clock(&a, &b, t0 + crate::peers::UNANSWERED_REKEY_SECS);
        send(&a, &b, 3);
        settle(&a, &b);
        send(&a, &b, 4);
        settle(&a, &b);
        assert!(tags(&b).ends_with(&[4]), "back after one handshake, got {:?}", tags(&b));
    }

    /// A live one-way flow never trips that: the receiver's keepalives
    /// prove the session to the sender.
    #[test]
    fn a_one_way_flow_does_not_rehandshake() {
        let t0 = 2_600_000;
        let (a, b) = pair(t0);
        for i in 0..30u64 {
            clock(&a, &b, t0 + i);
            send(&a, &b, i as u8);
            settle(&a, &b);
        }
        assert_eq!(a.engine.counters.get("handshakes_started"), 1, "one handshake, no repair rekeys");
        assert_eq!(tags(&b).len(), 30);
    }

    #[test]
    fn a_session_is_dropped_at_the_hard_deadline() {
        let t0 = 3_000_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        clock(&a, &b, t0 + REJECT_AFTER_SECS);
        a.engine.expire_sessions();
        b.engine.expire_sessions();
        assert_eq!(a.engine.sessions.lock().unwrap().session_count(), 0);
        assert_eq!(b.engine.sessions.lock().unwrap().session_count(), 0);
        // And the next packet simply starts over.
        send(&a, &b, 2);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1, 2]);
    }

    #[test]
    fn a_handshake_in_the_same_second_is_not_refused_as_a_replay() {
        // Seconds-granularity timestamps refused a second handshake from
        // the same peer within one second (a restart, a crossed rekey).
        let t0 = 4_000_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        a.engine.sessions.lock().unwrap().remove(2);
        send(&a, &b, 2);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![1, 2]);
        assert_eq!(b.engine.counters.get("drop_stale_handshake"), 0);
    }

    #[test]
    fn view_changes_drop_stale_sessions_and_queues() {
        let t0 = 5_000_000;
        let (a, b) = pair(t0);
        send(&a, &b, 1);
        settle(&a, &b);
        assert!(a.engine.sessions.lock().unwrap().is_ready(2));
        let b_info = a.engine.peers.lock().unwrap().get(2).cloned().unwrap();

        // 2 is re-keyed at the coordinator (a replacement machine): the
        // session authenticated under the old key must go.
        let mut rekeyed = b_info.clone();
        rekeyed.pubkey = StaticKeys::generate().unwrap().public_b64();
        a.engine.sync_peers(vec![rekeyed.clone()]);
        assert!(!a.engine.sessions.lock().unwrap().has(2));

        // A packet for it queues behind a fresh handshake; when it then
        // leaves the view the queue goes with it.
        send(&a, &b, 2);
        assert_eq!(a.engine.sessions.lock().unwrap().pending_len(2), 1);
        a.engine.sync_peers(vec![]);
        assert_eq!(a.engine.sessions.lock().unwrap().pending_len(2), 0);
        assert_eq!(a.engine.sessions.lock().unwrap().session_count(), 0);

        // A peer whose published key does not decode never holds a queue.
        let mut broken = b_info;
        broken.pubkey = "not base64!!".into();
        a.engine.sync_peers(vec![broken]);
        send(&a, &b, 3);
        assert_eq!(a.engine.sessions.lock().unwrap().pending_len(2), 0);
        assert!(a.engine.counters.get("sessions_dropped_by_view") >= 1);
    }

    #[test]
    fn the_mtu_can_be_lowered_at_runtime() {
        let (a, b) = pair(6_000_000);
        a.engine.set_mtu(20);
        send(&a, &b, 1); // 21 bytes
        assert_eq!(a.engine.counters.get("drop_oversize"), 1);
        a.engine.set_mtu(1350);
        send(&a, &b, 2);
        settle(&a, &b);
        assert_eq!(tags(&b), vec![2]);
    }
}
