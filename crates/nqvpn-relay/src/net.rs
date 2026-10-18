//! One network as seen by this relay: its view, the sessions attached
//! to it, the forwarding tables, the mesh dialers, and the data plane.
//!
//! Every table here has exactly one writer:
//!  * `clients` / `mesh` are written only by the session tasks' own
//!    lifecycle (open → insert, end → remove), and `tables`' local and
//!    mesh sets are updated under the same write lock, so the two never
//!    disagree about a node. Lock order: `clients`/`mesh` before
//!    `tables`; nothing takes `tables` and then a session map;
//!  * `attachments`, the dialer set, and eviction decisions are written
//!    only by `reconcile`, from the coordinator's view;
//!  * counters are atomic.
//!
//! The coordinator never touches a session. When the view says a member
//! is gone or replaced, `reconcile` closes its session and the session
//! task removes itself — the same path as any other end.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::VerifyingKey;
use nqvpn_proto::control::{AttachedClient, Heartbeat, LinkTraffic, RelayEndpoint, Snapshot, TrafficReport};
use nqvpn_proto::credential::{self, Claims, Expected};
use nqvpn_proto::frame::{bump_hop, Decision, RoutedHeader, TraceNote, ROUTED_HEADER_LEN, T_TRACE_NOTE};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::transport::{Mode, PacketChannel};
use nqvpn_proto::types::{NodeId, Role};
use nqvpn_session::{End, Refused, Session, SessionConfig, StaleLogin, Verifier, CLOSE_EVICTED, CLOSE_REPLACED, CLOSE_STALE_LOGIN};
use nqvpn_sync::{LinkHandle, LocalFacts, Reconcile, View};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::endpoint::LocalEndpoint;
use crate::tables::{ByteCounter, Counters, LinkCounters, Origin, Route, Tables, TokenBucket};

pub const COORD_ISS: &str = "nqvpn-coord";

struct Held {
    id: u64,
    session: Arc<Session>,
    /// Mesh only: we dialed it (so our credential is what it verifies).
    /// Such a session carries *our* claims, not the peer's: the peer is
    /// authenticated by the fingerprint we pinned (`session.peer_fp`),
    /// and that — not a login generation — is what the view can revoke.
    dialed: bool,
}

/// Bytes a frame may carry beyond the inner MTU: the routed header, the
/// counter and the AEAD tag, plus slack for a member whose TUN still
/// uses an older (larger) MTU than the one the view now publishes.
const FRAME_SLACK: usize = ROUTED_HEADER_LEN + 8 + 16 + 256;

/// How long a relay admits members without a view of its network (just
/// started, first snapshot not in yet). After that, no view means no
/// admission: a coordinator path that lets us join but withholds the
/// view must not leave us vouching for any unexpired credential.
pub const NO_VIEW_GRACE: Duration = Duration::from_secs(20);

/// Trace notes accepted per second from one mesh link. A trace yields
/// at most one note per relay per traced frame; this only stops a peer
/// relay from using notes as a free channel to our clients.
const TRACE_NOTES_PER_SEC: u32 = 64;

/// A per-session budget for trace notes; lives with the session task.
struct NoteBudget {
    window: Instant,
    used: u32,
}

impl NoteBudget {
    fn new() -> NoteBudget {
        NoteBudget { window: Instant::now(), used: 0 }
    }

    fn allow(&mut self) -> bool {
        if self.window.elapsed() >= Duration::from_secs(1) {
            self.window = Instant::now();
            self.used = 0;
        }
        self.used += 1;
        self.used <= TRACE_NOTES_PER_SEC
    }
}

struct Dialer {
    sig: String,
    task: tokio::task::JoinHandle<()>,
}

/// Fault injection for tests: what a misbehaving relay might do to the
/// frames it forwards. Endpoints must survive all of it, since relays
/// are untrusted by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chaos {
    /// Forward every frame twice.
    Duplicate,
    /// Damage a byte of the sealed payload of every `n`th frame.
    Corrupt(u64),
    /// Silently drop every `n`th frame.
    Drop(u64),
}

pub struct RelayNet {
    pub network_id: String,
    pub network_uuid: String,
    pub my_node_id: NodeId,
    pub view: Arc<View>,
    pub link: Arc<LinkHandle>,
    identity: TlsIdentity,
    credential: RwLock<String>,
    mode: Mode,
    lanes: u8,
    max_mbps: u32,
    keepalive_secs: u64,
    keys: RwLock<Vec<(String, VerifyingKey)>>,
    tables: RwLock<Tables>,
    clients: RwLock<HashMap<NodeId, Held>>,
    mesh: RwLock<HashMap<NodeId, Held>>,
    dialers: Mutex<HashMap<NodeId, Dialer>>,
    session_seq: AtomicU64,
    pub counters: Counters,
    traffic: RwLock<HashMap<NodeId, Arc<LinkCounters>>>,
    local_switched: ByteCounter,
    terminated: ByteCounter,
    endpoint: RwLock<Option<Arc<LocalEndpoint>>>,
    chaos: RwLock<Option<Chaos>>,
    chaos_seq: AtomicU64,
    /// This relay is a designated internet exit (granted a default route).
    exit_designated: AtomicBool,
    /// The last self-check of egress readiness, refreshed on a slow timer
    /// and carried in each heartbeat (never re-run per heartbeat).
    exit_ready: RwLock<Option<nqvpn_proto::control::ExitReadiness>>,
    /// When this network was set up; bounds admission without a view.
    created: Instant,
    /// The MTU the coordinator configured (from the join), 0 if unknown.
    mtu_ceiling: AtomicU32,
    /// Largest frame forwarded (inner MTU + `FRAME_SLACK`); 0 = no cap
    /// known yet. Recomputed on every reconcile.
    max_frame: AtomicU32,
}

impl RelayNet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network_id: String,
        network_uuid: String,
        my_node_id: NodeId,
        identity: TlsIdentity,
        credential: String,
        mode: Mode,
        lanes: u8,
        max_mbps: u32,
        keepalive_secs: u64,
    ) -> Arc<RelayNet> {
        Arc::new(RelayNet {
            network_id,
            network_uuid,
            my_node_id,
            view: Arc::new(View::new()),
            link: Arc::new(LinkHandle::default()),
            identity,
            credential: RwLock::new(credential),
            mode,
            lanes,
            max_mbps,
            keepalive_secs,
            keys: RwLock::new(Vec::new()),
            tables: RwLock::new(Tables::new(my_node_id)),
            clients: RwLock::new(HashMap::new()),
            mesh: RwLock::new(HashMap::new()),
            dialers: Mutex::new(HashMap::new()),
            session_seq: AtomicU64::new(1),
            counters: Counters::default(),
            traffic: RwLock::new(HashMap::new()),
            local_switched: ByteCounter::default(),
            terminated: ByteCounter::default(),
            endpoint: RwLock::new(None),
            chaos: RwLock::new(None),
            chaos_seq: AtomicU64::new(0),
            exit_designated: AtomicBool::new(false),
            exit_ready: RwLock::new(None),
            created: Instant::now(),
            mtu_ceiling: AtomicU32::new(0),
            max_frame: AtomicU32::new(0),
        })
    }

    /// Learn from a join whether this relay is an internet exit gateway
    /// (the coordinator grants it a default route). Drives the periodic
    /// egress self-check.
    pub fn set_exit_designated(&self, granted_cidrs: &[ipnet::IpNet]) {
        let is_exit = granted_cidrs.iter().any(|c| c.prefix_len() == 0);
        self.exit_designated.store(is_exit, Ordering::Relaxed);
        if !is_exit {
            *self.exit_ready.write().unwrap() = None;
        }
    }

    /// Re-run the egress readiness self-check (IP forwarding + masquerade)
    /// if this relay is a designated exit; otherwise clear it. Called on a
    /// slow timer so the link only ever reads the cached value. The check
    /// spawns processes, so it runs on the blocking pool.
    pub async fn refresh_exit_readiness(&self) {
        let designated = self.exit_designated.load(Ordering::Relaxed);
        let next = if designated { tokio::task::spawn_blocking(crate::exitcheck::detect).await.ok() } else { None };
        // Designation may have been withdrawn while the check ran.
        let next = next.filter(|_| self.exit_designated.load(Ordering::Relaxed));
        *self.exit_ready.write().unwrap() = next;
    }

    /// The network MTU the coordinator configured (from a join): with the
    /// view's published MTU, it bounds the frames this relay forwards.
    pub fn set_mtu_ceiling(&self, mtu: u16) {
        self.mtu_ceiling.store(mtu as u32, Ordering::Relaxed);
    }

    /// Record a readiness reading directly (tests, or a host whose check
    /// is done elsewhere). Ignored unless this relay is a designated exit.
    pub fn set_exit_readiness(&self, reading: nqvpn_proto::control::ExitReadiness) {
        if self.exit_designated.load(Ordering::Relaxed) {
            *self.exit_ready.write().unwrap() = Some(reading);
        }
    }

    /// Misbehave on purpose (tests only).
    pub fn set_chaos(&self, mode: Option<Chaos>) {
        *self.chaos.write().unwrap() = mode;
    }

    /// The coordinator refuses this relay (disabled, deleted, token
    /// regenerated): everything it knows is stale, so it carries nothing
    /// until accepted again — every session is closed and new ones are
    /// refused at `verify`. Members re-attach elsewhere at once. Dialers
    /// stay idle meanwhile (see `dialer`).
    pub fn suspend(&self, why: &str) {
        let clients: Vec<Arc<Session>> = self.clients.read().unwrap().values().map(|h| h.session.clone()).collect();
        let mesh: Vec<Arc<Session>> = self.mesh.read().unwrap().values().map(|h| h.session.clone()).collect();
        tracing::warn!(network = %self.network_id, clients = clients.len(), mesh = mesh.len(), "suspending: {why}");
        for s in clients.into_iter().chain(mesh) {
            s.close(CLOSE_EVICTED, why);
        }
    }

    /// This network's member loop has ended for good: another instance
    /// holds our identity in it (`MemberExit::Replaced`). We carry
    /// nothing for it again — sessions are closed, dialers stopped, and
    /// `verify` refuses everyone. Other networks this process serves
    /// are unaffected.
    pub fn retire(&self, why: &str) {
        for (_, d) in self.dialers.lock().unwrap().drain() {
            d.task.abort();
        }
        // Called on every reconcile once retired: quiet when nothing is
        // left to close.
        if !self.clients.read().unwrap().is_empty() || !self.mesh.read().unwrap().is_empty() {
            self.suspend(why);
        }
    }

    /// Replaced in this network (see `retire`): the member loop has
    /// recorded a stop, which is never cleared.
    pub fn is_retired(&self) -> bool {
        self.link.stop_reason().is_some()
    }

    /// A peer relay refused or closed our mesh session as a stale login.
    /// That is only a hint: any holder of a relay credential in this
    /// network can send that code. We are replaced only if our own
    /// coordinator says so — the control link closes with
    /// `CLOSE_REPLACED` (the member loop handles that), or the view
    /// lists us with a newer login generation than our credential.
    fn peer_says_stale(&self, peer: &str, reason: &str) {
        let ours = nqvpn_sync::join::own_claims(&self.credential()).map(|c| c.login_gen);
        let published = self.view.with(|s| s.member(self.my_node_id).map(|m| m.login_gen));
        match (ours, published) {
            (Some(ours), Some(published)) if published > ours => {
                self.link.replaced(format!("relay {peer} says: {reason} (the view agrees: login_gen {published} > ours {ours})"));
            }
            _ => {
                tracing::warn!(network = %self.network_id, %peer, ?ours, ?published, "a peer relay calls our login stale, but our view does not: {reason}");
                // Heartbeat now: if we really were replaced, the
                // coordinator answers on the control link.
                self.link.kick();
            }
        }
    }

    /// Close the mesh link to `peer` from this side, as a link failure
    /// would. The dialer (whichever side dials) re-establishes it.
    pub fn close_mesh(&self, peer: NodeId) -> bool {
        match self.mesh.read().unwrap().get(&peer) {
            Some(h) => {
                h.session.close(CLOSE_EVICTED, "link cut");
                true
            }
            None => false,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn lanes(&self) -> u8 {
        self.lanes
    }

    /// Signing keys straight from the join response, before the first
    /// snapshot arrives.
    pub fn set_signing_keys(&self, infos: &[nqvpn_proto::control::KeyInfo]) {
        let parsed: Vec<(String, VerifyingKey)> = infos
            .iter()
            .filter_map(|k| {
                let bytes: [u8; 32] = B64.decode(&k.key).ok()?.try_into().ok()?;
                Some((k.kid.clone(), VerifyingKey::from_bytes(&bytes).ok()?))
            })
            .collect();
        *self.keys.write().unwrap() = parsed;
    }

    /// A renewed credential: dialed mesh sessions present it to their
    /// far end so those sessions outlive the old expiry.
    pub fn set_credential(self: &Arc<Self>, credential: &str) {
        *self.credential.write().unwrap() = credential.to_string();
        let dialed: Vec<Arc<Session>> = self.mesh.read().unwrap().values().filter(|h| h.dialed).map(|h| h.session.clone()).collect();
        let cred = credential.to_string();
        tokio::spawn(async move {
            for s in dialed {
                if let Err(e) = s.refresh(&cred).await {
                    tracing::debug!("refreshing mesh session: {e}");
                }
            }
        });
    }

    pub fn credential(&self) -> String {
        self.credential.read().unwrap().clone()
    }

    pub fn set_endpoint(&self, ep: Arc<LocalEndpoint>) {
        *self.endpoint.write().unwrap() = Some(ep);
    }

    pub fn endpoint(&self) -> Option<Arc<LocalEndpoint>> {
        self.endpoint.read().unwrap().clone()
    }

    fn probe_cfg(&self, dialer: bool) -> SessionConfig {
        // The dialing side probes; the accepting side answers. Both
        // enforce expiry.
        SessionConfig { probe_secs: if dialer { 2 } else { 0 }, probe_misses: 5 }
    }

    // ---- session lifecycle (the only writers of clients/mesh) ----

    /// Hold a client session for its whole life.
    pub async fn run_client(self: Arc<Self>, session: Arc<Session>) -> End {
        let node = session.node_id();
        let reg = Registration::client(self.clone(), node, session.clone());
        tracing::info!(network = %self.network_id, node, mode = self.mode.as_str(), "client attached");
        let me = self.clone();
        let chan = session.chan.clone();
        let mut bucket = TokenBucket::new(self.max_mbps);
        let end = session
            .run(&self.probe_cfg(false), Some(self.as_ref()), move |d, lane| {
                me.forward_limited(Origin::Client(node), Some(&chan), d, lane, &mut bucket)
            })
            .await;
        drop(reg);
        tracing::info!(network = %self.network_id, node, ?end, "client detached");
        end
    }

    /// Hold a mesh session for its whole life.
    pub async fn run_mesh(self: Arc<Self>, session: Arc<Session>, dialed: bool) -> End {
        let peer = session.node_id();
        let reg = Registration::mesh(self.clone(), peer, session.clone(), dialed);
        tracing::info!(network = %self.network_id, peer, dialed, "mesh link up");
        let me = self.clone();
        let chan = session.chan.clone();
        let mut notes = NoteBudget::new();
        let end = session
            .run(&self.probe_cfg(dialed), Some(self.as_ref()), move |d, lane| {
                if d.first() == Some(&T_TRACE_NOTE) && !notes.allow() {
                    return;
                }
                me.forward(Origin::Relay(peer), Some(&chan), d, lane)
            })
            .await;
        drop(reg);
        tracing::info!(network = %self.network_id, peer, ?end, "mesh link down");
        // Only a session that carried our credential can be stale on our
        // side; one we accepted carried the peer's.
        if let (true, Some((CLOSE_STALE_LOGIN, reason))) = (dialed, session.close_reason()) {
            self.peer_says_stale(&peer.to_string(), &reason);
        }
        end
    }

    pub fn has_mesh(&self, peer: NodeId) -> bool {
        self.mesh.read().unwrap().contains_key(&peer)
    }

    pub fn local_clients(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self.clients.read().unwrap().keys().copied().collect();
        v.sort();
        v
    }

    pub fn mesh_peers(&self) -> Vec<NodeId> {
        let mut v: Vec<NodeId> = self.mesh.read().unwrap().keys().copied().collect();
        v.sort();
        v
    }

    /// Dial one peer relay until told to stop: connect, hold the session,
    /// back off, repeat. Aborted by `reconcile` when the peer leaves the
    /// fleet or its address changes. Idle while this relay is refused
    /// (it carries nothing then, and the peer would refuse us anyway);
    /// done once it is retired.
    async fn dialer(self: Arc<Self>, entry: RelayEndpoint) {
        let mut delay = Duration::from_secs(1);
        loop {
            if self.is_retired() {
                return;
            }
            if self.link.is_refused() || self.has_mesh(entry.relay_id) {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
            let credential = self.credential();
            let Some(claims) = nqvpn_sync::join::own_claims(&credential) else {
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            };
            match nqvpn_session::dial(&entry.addr, &self.identity, Some(entry.cert_fp.clone()), &credential, self.keepalive_secs, self.mode, self.lanes, entry.relay_id, Role::Relay, claims).await {
                Ok(session) => {
                    delay = Duration::from_secs(1);
                    // Its own task: aborting this dialer must not kill a
                    // session mid-teardown.
                    let _ = tokio::spawn(self.clone().run_mesh(session, true)).await;
                }
                Err(e) => {
                    if let Some(Refused { code: CLOSE_STALE_LOGIN, reason }) = e.downcast_ref::<Refused>() {
                        self.peer_says_stale(&entry.name, reason);
                    } else {
                        tracing::warn!(network = %self.network_id, peer = %entry.name, addr = %entry.addr, "mesh dial failed: {e:#}");
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }

    // ---- data plane ----

    fn link_counters(&self, peer: NodeId) -> Arc<LinkCounters> {
        if let Some(c) = self.traffic.read().unwrap().get(&peer) {
            return c.clone();
        }
        self.traffic.write().unwrap().entry(peer).or_default().clone()
    }

    fn channel_for(&self, route: &Route) -> Option<Arc<PacketChannel>> {
        match route {
            Route::Local(id) => self.clients.read().unwrap().get(id).map(|h| h.session.chan.clone()),
            Route::Mesh(id) => self.mesh.read().unwrap().get(id).map(|h| h.session.chan.clone()),
            _ => None,
        }
    }

    /// The entire relay data plane for one frame: parse, decide, send,
    /// and — if the origin asked — say what we did. `arrived_on` is the
    /// session the frame came in on; `None` for our own endpoint's
    /// frames, whose trace notes go straight to it.
    pub fn forward(&self, origin: Origin, arrived_on: Option<&PacketChannel>, datagram: Bytes, lane: u8) {
        let bytes = datagram.len() as u64;
        if let Origin::Relay(peer) = origin {
            self.link_counters(peer).rx.add(bytes);
        }
        let max = self.max_frame.load(Ordering::Relaxed) as usize;
        if max > 0 && datagram.len() > max {
            // No member of this network seals a frame this large.
            self.counters.note(Decision::DropMalformed);
            tracing::debug!(network = %self.network_id, ?origin, len = datagram.len(), max, "dropping oversized frame");
            return;
        }
        if datagram.first() == Some(&T_TRACE_NOTE) {
            // A note travelling back toward the origin, from the mesh
            // peer that handled the traced frame: pass it to the client
            // that sent it if attached here, or to our own endpoint.
            if let (Origin::Relay(peer), Some(note)) = (origin, TraceNote::parse(&datagram)) {
                if note.relay_id != peer {
                    return;
                }
                if note.origin == self.my_node_id {
                    if let Some(ep) = self.endpoint() {
                        ep.deliver(&datagram);
                    }
                } else if let Some(chan) = self.channel_for(&Route::Local(note.origin)) {
                    let _ = chan.send(datagram);
                }
            }
            return;
        }
        let Some(h) = RoutedHeader::parse(&datagram) else {
            self.counters.note(Decision::DropMalformed);
            return;
        };
        let mut buf = datagram.to_vec();
        let hop = match bump_hop(&mut buf) {
            Some(hop) => hop,
            None => {
                self.counters.note(Decision::DropTooManyHops);
                self.trace(&h, h.hop, arrived_on, Decision::DropTooManyHops, 0);
                return;
            }
        };
        let route = self.tables.read().unwrap().route(origin, h.src_id, h.dst_id);
        let decision = route.decision();
        self.counters.note(decision);
        let detail = match route {
            Route::Local(id) | Route::Mesh(id) => id,
            _ => 0,
        };
        match route {
            Route::Local(_) | Route::Mesh(_) => {
                let chaos = *self.chaos.read().unwrap();
                let seq = self.chaos_seq.fetch_add(1, Ordering::Relaxed);
                match chaos {
                    Some(Chaos::Drop(n)) if n > 0 && seq.is_multiple_of(n) => return,
                    Some(Chaos::Corrupt(n)) if n > 0 && seq.is_multiple_of(n) => {
                        // Per-relay damage: two byzantine relays in lockstep
                        // must not cancel each other out with a symmetric flip.
                        if let Some(b) = buf.last_mut() {
                            *b = b.wrapping_add(1 + (self.my_node_id % 200) as u8);
                        }
                    }
                    _ => {}
                }
                let sent = match self.channel_for(&route) {
                    Some(c) => {
                        if chaos == Some(Chaos::Duplicate) {
                            let _ = c.send_on(Bytes::from(buf.clone()), lane);
                        }
                        c.send_on(Bytes::from(buf), lane)
                    }
                    None => false,
                };
                if sent {
                    match (&route, origin) {
                        (Route::Mesh(id), _) => self.link_counters(*id).tx.add(bytes),
                        (Route::Local(_), Origin::Client(_)) => self.local_switched.add(bytes),
                        _ => {}
                    }
                    self.trace(&h, hop, arrived_on, decision, detail);
                } else {
                    self.counters.note(Decision::DropSendFailed);
                    self.trace(&h, hop, arrived_on, Decision::DropSendFailed, detail);
                }
            }
            Route::Me => match self.endpoint() {
                Some(ep) => {
                    self.terminated.add(bytes);
                    self.trace(&h, hop, arrived_on, decision, self.my_node_id);
                    ep.deliver(&buf);
                }
                None => {
                    self.counters.note(Decision::DropNoEndpoint);
                    self.trace(&h, hop, arrived_on, Decision::DropNoEndpoint, 0);
                }
            },
            Route::Drop(d) => self.trace(&h, hop, arrived_on, d, 0),
        }
    }

    /// Answer a traced frame on the session it arrived on (for our own
    /// endpoint's frames: to the endpoint directly).
    fn trace(&self, h: &RoutedHeader, hop: u8, arrived_on: Option<&PacketChannel>, decision: Decision, detail: u32) {
        if !h.traced() {
            return;
        }
        let note = TraceNote { origin: h.src_id, trace: h.trace, hop, relay_id: self.my_node_id, decision, detail }.encode();
        match arrived_on {
            Some(chan) => {
                let _ = chan.send(note.into());
            }
            None => {
                if let Some(ep) = self.endpoint() {
                    ep.deliver(&note);
                }
            }
        }
    }

    /// Rate-limited variant for client origins; the bucket lives with
    /// the session task, not in shared state.
    pub fn forward_limited(&self, origin: Origin, arrived_on: Option<&PacketChannel>, datagram: Bytes, lane: u8, bucket: &mut Option<TokenBucket>) {
        if let Some(b) = bucket.as_mut() {
            if !b.allow(datagram.len()) {
                self.counters.note(Decision::DropRateLimited);
                return;
            }
        }
        self.forward(origin, arrived_on, datagram, lane)
    }

    /// This relay's row of the fleet traffic matrix.
    fn traffic_report(&self) -> TrafficReport {
        let mesh = self.mesh.read().unwrap();
        for peer in mesh.keys() {
            if !self.traffic.read().unwrap().contains_key(peer) {
                self.traffic.write().unwrap().entry(*peer).or_default();
            }
        }
        let mut links: Vec<LinkTraffic> = self
            .traffic
            .read()
            .unwrap()
            .iter()
            .map(|(peer, c)| {
                let (tx_bytes, tx_pkts) = c.tx.get();
                let (rx_bytes, rx_pkts) = c.rx.get();
                LinkTraffic { peer_id: *peer, tx_bytes, tx_pkts, rx_bytes, rx_pkts, up: mesh.contains_key(peer) }
            })
            .collect();
        drop(mesh);
        links.sort_by_key(|l| l.peer_id);
        let (local_bytes, local_pkts) = self.local_switched.get();
        let (terminated_bytes, terminated_pkts) = self.terminated.get();
        TrafficReport { links, local_bytes, local_pkts, terminated_bytes, terminated_pkts }
    }

    pub fn status_line(&self) -> String {
        let t = self.tables.read().unwrap();
        let counters = self
            .counters
            .snapshot()
            .into_iter()
            .filter(|(_, v)| *v > 0)
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "network={} node={} clients={} mesh={} gen={} {}",
            self.network_id,
            self.my_node_id,
            t.local_count(),
            t.mesh_count(),
            self.view.gen(),
            counters
        )
    }
}

impl Verifier for RelayNet {
    fn verify(&self, credential: &str, presented_fp: &str) -> Result<Claims> {
        let keys = self.keys.read().unwrap().clone();
        anyhow::ensure!(!keys.is_empty(), "no coordinator signing keys yet");
        let claims = credential::verify(
            credential,
            &keys,
            &Expected { iss: COORD_ISS, network_id: &self.network_id, network_uuid: &self.network_uuid },
            now_unix(),
        )
        .map_err(|e| anyhow!("credential rejected: {e}"))?;
        anyhow::ensure!(claims.cert_fp == presented_fp, "cert_fp mismatch: credential {} vs TLS {presented_fp}", claims.cert_fp);
        anyhow::ensure!(claims.node_id != self.my_node_id, "a member may not connect to itself");
        anyhow::ensure!(!self.link.is_refused(), "this relay is currently refused by the coordinator");
        anyhow::ensure!(!self.is_retired(), "this relay was replaced in this network");
        // The view is the authority once we have one: a node it does not
        // list (deleted, disabled, or simply not yet pushed — the member
        // retries in a second) is refused, and one it lists with a newer
        // login generation is a replaced instance. Its role must match
        // the view's, and a relay gets a mesh slot only if the fleet
        // lists it.
        let (known, member, in_fleet) = self.view.with(|s| {
            (!s.members.is_empty(), s.member(claims.node_id).cloned(), s.relays.iter().any(|r| r.relay_id == claims.node_id))
        });
        match member {
            Some(m) if claims.login_gen < m.login_gen => {
                return Err(StaleLogin(format!("node {} was replaced by a newer join", claims.node_id)).into());
            }
            Some(m) => {
                anyhow::ensure!(m.role == claims.role, "node {} is a {} in the view, not a {}", claims.node_id, m.role, claims.role);
                anyhow::ensure!(claims.role != Role::Relay || in_fleet, "relay {} is not in the published fleet", claims.node_id);
            }
            None if known => anyhow::bail!("node {} is not in the network view", claims.node_id),
            // No view yet: admit for a short grace (the first reconcile
            // evicts whatever the view does not vouch for), then refuse.
            None => anyhow::ensure!(self.created.elapsed() < NO_VIEW_GRACE, "no network view yet"),
        }
        Ok(claims)
    }
}

impl LocalFacts for RelayNet {
    fn heartbeat(&self) -> Heartbeat {
        let attached: Vec<AttachedClient> = self
            .clients
            .read()
            .unwrap()
            .iter()
            .map(|(n, h)| AttachedClient { node_id: *n, session_id: h.id })
            .collect();
        Heartbeat {
            gen: 0,
            digest: 0,
            attached,
            mesh_up: self.mesh_peers(),
            attached_to: None,
            usable_mtu: 0,
            traffic: Some(self.traffic_report()),
        }
    }

    /// The cached egress self-check, only while designated an exit. The
    /// link sends it as its own message kind, never in the heartbeat.
    fn exit_readiness(&self) -> Option<nqvpn_proto::control::ExitReadiness> {
        *self.exit_ready.read().unwrap()
    }
}

/// The reconciler handle for one network.
pub struct NetReconciler(pub Arc<RelayNet>);

impl Reconcile for NetReconciler {
    fn reconcile(&self, view: &Snapshot) {
        RelayNet::reconcile(&self.0, view)
    }
}

impl RelayNet {
    /// Bring local state in line with the view: keys, the attachment
    /// table, evictions, the dialer set, and the endpoint's peers and
    /// routes. Diff-based against what we actually hold; idempotent.
    pub fn reconcile(self: &Arc<Self>, view: &Snapshot) {
        if !view.keys.is_empty() {
            self.set_signing_keys(&view.keys);
        }
        if self.is_retired() {
            // Replaced in this network: nothing to dial, nobody to hold.
            self.retire("this relay was replaced in this network");
            return;
        }
        self.tables.write().unwrap().replace_attachments(view.attachments.iter().map(|a| (a.node_id, a.relay_id)));
        let mtu = self.mtu_ceiling.load(Ordering::Relaxed).max(view.mtu.mtu as u32);
        self.max_frame.store(if mtu > 0 { mtu + FRAME_SLACK as u32 } else { 0 }, Ordering::Relaxed);

        // Evict sessions the view no longer vouches for. An empty view
        // (nothing received yet) vouches for nobody and evicts nobody.
        // A session we accepted carries the member's credential: a login
        // generation older than the view's is a replaced instance. A
        // mesh session we dialed carries *our* credential, so its login
        // generation says nothing about the peer; the peer proved the
        // fingerprint we pinned, so the link is stale once the fleet
        // publishes a different one.
        let stale: Vec<(Arc<Session>, u32, &'static str)> = {
            let mut v = Vec::new();
            if !view.members.is_empty() {
                for held in self.clients.read().unwrap().values().chain(self.mesh.read().unwrap().values()) {
                    let node = held.session.node_id();
                    match view.member(node) {
                        None => v.push((held.session.clone(), CLOSE_EVICTED, "no longer a member")),
                        Some(_) if held.dialed => {
                            let published = view.relays.iter().find(|r| r.relay_id == node).map(|r| r.cert_fp.as_str());
                            if matches!(published, Some(fp) if fp != held.session.peer_fp) {
                                v.push((held.session.clone(), CLOSE_EVICTED, "relay certificate changed"));
                            }
                        }
                        Some(m) if held.session.login_gen() < m.login_gen => {
                            v.push((held.session.clone(), CLOSE_STALE_LOGIN, "replaced by a newer join"))
                        }
                        _ => {}
                    }
                }
            }
            v
        };
        for (s, code, why) in stale {
            tracing::info!(network = %self.network_id, node = s.node_id(), why, "evicting session");
            s.close(code, why);
        }

        // Dialer set: one task per peer we are responsible for dialing
        // (the lower id dials). New or changed → (re)spawn; gone → abort.
        {
            let mut dialers = self.dialers.lock().unwrap();
            let wanted: HashMap<NodeId, &RelayEndpoint> =
                view.relays.iter().filter(|r| r.relay_id > self.my_node_id).map(|r| (r.relay_id, r)).collect();
            let gone: Vec<NodeId> = dialers.keys().filter(|id| !wanted.contains_key(id)).copied().collect();
            for id in gone {
                if let Some(d) = dialers.remove(&id) {
                    d.task.abort();
                }
                if let Some(h) = self.mesh.read().unwrap().get(&id) {
                    h.session.close(CLOSE_EVICTED, "relay left the fleet");
                }
            }
            for (id, entry) in wanted {
                let sig = format!("{}|{}", entry.addr, entry.cert_fp);
                let stale = dialers.get(&id).map(|d| d.sig != sig).unwrap_or(true);
                if stale {
                    if let Some(d) = dialers.remove(&id) {
                        d.task.abort();
                        if let Some(h) = self.mesh.read().unwrap().get(&id) {
                            h.session.close(CLOSE_EVICTED, "relay address changed");
                        }
                    }
                    tracing::info!(network = %self.network_id, peer = %entry.name, addr = %entry.addr, "starting mesh dialer");
                    let task = tokio::spawn(self.clone().dialer(entry.clone()));
                    dialers.insert(id, Dialer { sig, task });
                }
            }
        }
        // Relays the fleet no longer lists, that dialed *us*, go too.
        if !view.relays.is_empty() {
            let fleet: Vec<NodeId> = view.relays.iter().map(|r| r.relay_id).collect();
            let dropped: Vec<Arc<Session>> = self
                .mesh
                .read()
                .unwrap()
                .iter()
                .filter(|(id, _)| !fleet.contains(id))
                .map(|(_, h)| h.session.clone())
                .collect();
            for s in dropped {
                s.close(CLOSE_EVICTED, "relay left the fleet");
            }
        }

        // Prune per-peer traffic counters for peers we no longer hold —
        // otherwise they accumulate for every node id ever seen. Keep the
        // live set (attached clients + mesh peers) only.
        {
            let live: std::collections::HashSet<NodeId> = self
                .clients
                .read()
                .unwrap()
                .keys()
                .chain(self.mesh.read().unwrap().keys())
                .copied()
                .collect();
            let mut traffic = self.traffic.write().unwrap();
            let before = traffic.len();
            traffic.retain(|peer, _| live.contains(peer));
            let dropped = before - traffic.len();
            if dropped > 0 {
                tracing::debug!(network = %self.network_id, dropped, kept = traffic.len(), "pruned stale traffic counters");
            }
        }

        if let Some(ep) = self.endpoint() {
            ep.sync(view);
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// A session's place in the tables, removed when dropped — however the
/// task holding it ends, including by abort. Inserting replaces (and
/// closes) any older session for the same node: the newest wins.
struct Registration {
    net: Arc<RelayNet>,
    node: NodeId,
    id: u64,
    mesh: bool,
}

impl Registration {
    fn client(net: Arc<RelayNet>, node: NodeId, session: Arc<Session>) -> Registration {
        Self::insert(net, node, session, false, false)
    }

    fn mesh(net: Arc<RelayNet>, peer: NodeId, session: Arc<Session>, dialed: bool) -> Registration {
        Self::insert(net, peer, session, dialed, true)
    }

    /// The session map and the forwarding table change together, under
    /// the map's write lock: an older session's teardown can never land
    /// between our insert and our table update.
    fn insert(net: Arc<RelayNet>, node: NodeId, session: Arc<Session>, dialed: bool, mesh: bool) -> Registration {
        let id = net.session_seq.fetch_add(1, Ordering::Relaxed);
        let old = {
            let mut map = if mesh { net.mesh.write().unwrap() } else { net.clients.write().unwrap() };
            let old = map.insert(node, Held { id, session, dialed });
            let mut tables = net.tables.write().unwrap();
            if mesh {
                tables.set_mesh(node, true);
            } else {
                tables.set_local(node, true);
            }
            old
        };
        if let Some(old) = old {
            old.session.close(CLOSE_REPLACED, if mesh { "replaced by a newer mesh session" } else { "replaced by a newer session" });
        }
        net.link.kick();
        Registration { net, node, id, mesh }
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let table = if self.mesh { &self.net.mesh } else { &self.net.clients };
        let mine = {
            let mut t = table.write().unwrap();
            match t.get(&self.node) {
                Some(h) if h.id == self.id => {
                    t.remove(&self.node);
                    // Still under the map's lock: see `insert`.
                    let mut tables = self.net.tables.write().unwrap();
                    if self.mesh {
                        tables.set_mesh(self.node, false);
                    } else {
                        tables.set_local(self.node, false);
                    }
                    true
                }
                _ => false,
            }
        };
        if mine {
            self.net.link.kick();
        }
    }
}

/// A relay that serves several networks answers `Hello` per network.
pub struct Fleet {
    pub nets: HashMap<String, Arc<RelayNet>>,
}

impl nqvpn_session::Acceptor for Fleet {
    fn params_for(&self, network_id: &str) -> Option<nqvpn_session::AcceptParams> {
        let n = self.nets.get(network_id)?;
        Some(nqvpn_session::AcceptParams { verifier: n.clone(), mode: n.mode(), lanes: n.lanes(), ack_gen: n.view.gen() })
    }
}

impl Fleet {
    /// Accept loop: authenticate, then hand the session to its network
    /// by the role in its credential.
    pub async fn accept_loop(self: Arc<Self>, endpoint: quinn::Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            let fleet = self.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::debug!("handshake failed: {e}");
                        return;
                    }
                };
                let session = match nqvpn_session::accept(conn, fleet.as_ref()).await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::debug!("session refused: {e:#}");
                        return;
                    }
                };
                let Some(net) = fleet.nets.get(&session.claims.network_id).cloned() else { return };
                match session.claims.role {
                    Role::Relay => {
                        net.run_mesh(session, false).await;
                    }
                    Role::Client => {
                        net.run_client(session).await;
                    }
                }
            });
        }
    }
}
