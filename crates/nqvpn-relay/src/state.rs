//! Relay runtime state: forwarding tables, live sessions, and the
//! coordinator-derived view. Reads on the data path take the table lock
//! only long enough to decide a route (§9 hot-path invariant).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use nqvpn_proto::control::*;
use nqvpn_proto::transport::{Mode, PacketChannel};
use nqvpn_proto::types::{NodeId, Revision};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::mpsc;

use crate::tables::{ByteCounter, Counters, LinkCounters, Origin, Route, Tables};

pub struct RelayState {
    pub my_node_id: NodeId,
    pub network_id: String,
    pub network_uuid: String,
    pub coord_quic: String,
    pub counters: Counters,

    tables: RwLock<Tables>,
    /// Live QUIC connections we can send datagrams on.
    /// (session id, connection). The id lets a stale session's delayed
    /// teardown recognise that it no longer owns the entry — otherwise
    /// it evicts the *current* session for the same node id.
    clients: RwLock<HashMap<NodeId, (u64, Arc<PacketChannel>)>>,
    mesh: RwLock<HashMap<NodeId, (u64, Arc<PacketChannel>)>>,
    /// Packet transport this network uses (§5); set from the join.
    mode: RwLock<Mode>,
    session_seq: AtomicU64,
    /// Coordinator signing keys (kid -> verifying key).
    keys: RwLock<Vec<(String, VerifyingKey)>>,
    /// Membership as pushed (used for status and, later, the gateway TUN).
    peers: RwLock<HashMap<NodeId, PeerInfo>>,
    membership_rev: AtomicU64,
    snapshot_buf: Mutex<Vec<PeerInfo>>,
    attach_tx: Mutex<Option<mpsc::Sender<Attach>>>,
    /// Relay fleet we have already started dialers for.
    known_relays: Mutex<HashMap<NodeId, String>>,
    /// Set when this relay also plays the endpoint role (§3.1): it has
    /// a VPN address and/or gateway prefixes, so frames addressed to it
    /// terminate here instead of being dropped.
    endpoint: RwLock<Option<Arc<crate::endpoint::LocalEndpoint>>>,
    /// Current credential. Renewed on a timer (§3.3): a dialer must
    /// never present a stale one, or peers reject it as expired.
    credential: RwLock<String>,
    /// Bytes moved per mesh peer, for the fleet traffic matrix. Entries
    /// are never removed, so a link that goes down keeps its totals.
    traffic: RwLock<HashMap<NodeId, Arc<LinkCounters>>>,
    /// Switched between two members attached here — the matrix diagonal.
    local_switched: ByteCounter,
    /// Terminated at our own endpoint role.
    terminated: ByteCounter,
    /// Lanes this network's transport uses (§5); set from the join.
    lanes: RwLock<u8>,
}

impl RelayState {
    pub fn new(
        my_node_id: NodeId,
        network_id: String,
        network_uuid: String,
        coord_quic: String,
    ) -> Self {
        RelayState {
            my_node_id,
            network_id,
            network_uuid,
            coord_quic,
            counters: Counters::default(),
            tables: RwLock::new(Tables::new(my_node_id)),
            clients: RwLock::new(HashMap::new()),
            mesh: RwLock::new(HashMap::new()),
            keys: RwLock::new(Vec::new()),
            peers: RwLock::new(HashMap::new()),
            membership_rev: AtomicU64::new(0),
            session_seq: AtomicU64::new(1),
            mode: RwLock::new(Mode::Datagram),
            snapshot_buf: Mutex::new(Vec::new()),
            attach_tx: Mutex::new(None),
            known_relays: Mutex::new(HashMap::new()),
            endpoint: RwLock::new(None),
            credential: RwLock::new(String::new()),
            traffic: RwLock::new(HashMap::new()),
            local_switched: ByteCounter::default(),
            terminated: ByteCounter::default(),
            lanes: RwLock::new(1),
        }
    }

    // ---- coordinator-driven state ----

    pub fn set_signing_keys(&self, infos: &[KeyInfo]) {
        let parsed: Vec<(String, VerifyingKey)> = infos
            .iter()
            .filter_map(|k| {
                let bytes: [u8; 32] = B64.decode(&k.key).ok()?.try_into().ok()?;
                Some((k.kid.clone(), VerifyingKey::from_bytes(&bytes).ok()?))
            })
            .collect();
        *self.keys.write().unwrap() = parsed;
    }

    pub fn set_endpoint(&self, ep: Arc<crate::endpoint::LocalEndpoint>) {
        *self.endpoint.write().unwrap() = Some(ep);
    }

    pub fn endpoint(&self) -> Option<Arc<crate::endpoint::LocalEndpoint>> {
        self.endpoint.read().unwrap().clone()
    }

    /// Feed coordinator membership into the endpoint's peer table, so it
    /// can route outbound packets and validate inbound ones (§4).
    pub fn sync_endpoint_peers(&self) {
        if let Some(ep) = self.endpoint() {
            let peers: Vec<PeerInfo> = self.peers.read().unwrap().values().cloned().collect();
            ep.engine.peers.lock().unwrap().replace_all(peers);
            // Routes must track membership, or return traffic has no way
            // back into the tunnel.
            ep.apply_routes();
        }
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.write().unwrap() = mode;
    }

    pub fn mode(&self) -> Mode {
        *self.mode.read().unwrap()
    }

    pub fn set_lanes(&self, lanes: u8) {
        *self.lanes.write().unwrap() = lanes;
    }

    pub fn lanes(&self) -> u8 {
        *self.lanes.read().unwrap()
    }

    pub fn set_credential(&self, credential: &str) {
        *self.credential.write().unwrap() = credential.to_string();
    }

    pub fn credential(&self) -> String {
        self.credential.read().unwrap().clone()
    }

    pub fn verifying_keys(&self) -> Vec<(String, VerifyingKey)> {
        self.keys.read().unwrap().clone()
    }

    pub fn apply_snapshot_chunk(&self, s: MembershipSnapshot) {
        let mut buf = self.snapshot_buf.lock().unwrap();
        if s.chunk_i == 0 {
            buf.clear();
        }
        buf.extend(s.peers);
        // Install atomically only once the snapshot is complete (§3.2).
        if s.chunk_i + 1 == s.chunk_n {
            let map: HashMap<NodeId, PeerInfo> =
                buf.drain(..).map(|p| (p.node_id, p)).collect();
            *self.peers.write().unwrap() = map;
            self.membership_rev.store(s.snapshot_rev, Ordering::Relaxed);
            drop(buf);
            self.sync_endpoint_peers();
            tracing::info!(rev = s.snapshot_rev, "membership snapshot installed");
        }
    }

    /// Returns false if the delta does not apply to our revision — the
    /// caller should request a fresh snapshot (gap rule, §3.2).
    pub fn apply_membership_delta(&self, d: MembershipDelta) -> bool {
        let cur = self.membership_rev.load(Ordering::Relaxed);
        // Already applied (a delta that predates our snapshot): ignore.
        if d.new_rev <= cur {
            return true;
        }
        if cur != 0 && d.base_rev != cur {
            tracing::warn!(have = cur, base = d.base_rev, "membership delta gap");
            return false;
        }
        let mut offline: Vec<NodeId> = Vec::new();
        {
            let mut peers = self.peers.write().unwrap();
            for p in d.changed {
                if !p.online {
                    offline.push(p.node_id);
                }
                peers.insert(p.node_id, p);
            }
            for id in d.removed {
                peers.remove(&id);
                offline.push(id);
            }
        }
        self.drop_offline_sessions(&offline);
        let peers = self.peers.write().unwrap();
        self.membership_rev.store(d.new_rev, Ordering::Relaxed);
        drop(peers);
        self.sync_endpoint_peers();
        true
    }

    /// Record the current fleet and return the entries that are new to
    /// us (or whose address/pin changed), so the caller can dial them.
    pub fn take_new_relays(
        &self,
        fleet: &[RelayEndpoint],
    ) -> Vec<nqvpn_proto::api::RelayEntry> {
        let mut known = self.known_relays.lock().unwrap();
        let mut fresh = Vec::new();
        for r in fleet {
            if r.relay_id == self.my_node_id {
                continue;
            }
            let sig = format!("{}|{}", r.addr, r.cert_fp);
            if known.get(&r.relay_id) != Some(&sig) {
                known.insert(r.relay_id, sig);
                fresh.push(nqvpn_proto::api::RelayEntry {
                    relay_id: r.relay_id,
                    name: r.name.clone(),
                    addr: r.addr.clone(),
                    cert_fp: r.cert_fp.clone(),
                });
            }
        }
        fresh
    }

    pub fn replace_attachments(&self, entries: Vec<AttachmentEntry>) {
        let mut t = self.tables.write().unwrap();
        t.replace_attachments(entries.into_iter().map(|e| (e.node_id, e.relay_id)));
    }

    pub fn apply_attachment_delta(&self, d: AttachmentDelta) {
        let mut t = self.tables.write().unwrap();
        for e in d.changed {
            t.set_attachment(e.node_id, Some(e.relay_id));
        }
        for id in d.detached {
            t.set_attachment(id, None);
        }
    }

    // ---- session registration ----

    /// Register a client session. Returns its id, which the caller must
    /// hand back at teardown.
    pub fn add_client(&self, node: NodeId, chan: Arc<PacketChannel>) -> u64 {
        let id = self.session_seq.fetch_add(1, Ordering::Relaxed);
        self.clients.write().unwrap().insert(node, (id, chan));
        self.tables.write().unwrap().set_local(node, true);
        self.report_attach(node, true);
        id
    }

    /// Tear down a client session — but only if it is still the live one
    /// for that node. A superseded session must not evict its successor.
    pub fn remove_client(&self, node: NodeId, session_id: u64) {
        {
            let mut c = self.clients.write().unwrap();
            match c.get(&node) {
                Some((id, _)) if *id == session_id => {
                    c.remove(&node);
                }
                _ => return, // already replaced by a newer session
            }
        }
        self.tables.write().unwrap().set_local(node, false);
        self.report_attach(node, false);
    }

    pub fn add_mesh(&self, relay: NodeId, chan: Arc<PacketChannel>) -> u64 {
        let id = self.session_seq.fetch_add(1, Ordering::Relaxed);
        self.mesh.write().unwrap().insert(relay, (id, chan));
        self.tables.write().unwrap().set_mesh(relay, true);
        id
    }

    pub fn remove_mesh(&self, relay: NodeId, session_id: u64) {
        {
            let mut m = self.mesh.write().unwrap();
            match m.get(&relay) {
                Some((id, _)) if *id == session_id => {
                    m.remove(&relay);
                }
                _ => return,
            }
        }
        self.tables.write().unwrap().set_mesh(relay, false);
    }

    /// Every client currently attached here. Used to resync the
    /// coordinator's attachment registry when a control session comes
    /// (back) up — edge-triggered reports alone lose everything that
    /// attached while the link was down.
    pub fn local_clients(&self) -> Vec<NodeId> {
        self.clients.read().unwrap().keys().copied().collect()
    }

    /// Close sessions for members the coordinator has declared offline.
    /// Our own QUIC idle timeout is longer than the coordinator's
    /// liveness window, so without this a dead client stays in our
    /// tables and the periodic attachment resync keeps re-announcing it.
    pub fn drop_offline_sessions(&self, offline: &[NodeId]) {
        for node in offline {
            let closed = {
                let mut c = self.clients.write().unwrap();
                c.remove(node).map(|(_, chan)| chan)
            };
            if closed.is_some() {
                self.tables.write().unwrap().set_local(*node, false);
                self.report_attach(*node, false);
                tracing::info!(peer = node, "coordinator says offline; session dropped");
            }
        }
    }

    pub fn has_mesh(&self, relay: NodeId) -> bool {
        self.mesh.read().unwrap().contains_key(&relay)
    }

    pub fn set_attach_sender(&self, tx: Option<mpsc::Sender<Attach>>) {
        *self.attach_tx.lock().unwrap() = tx;
    }

    fn report_attach(&self, node_id: NodeId, attached: bool) {
        if let Some(tx) = self.attach_tx.lock().unwrap().as_ref() {
            let _ = tx.try_send(Attach { node_id, attached });
        }
    }

    // ---- data path ----

    /// Counters for one mesh peer, created on first use.
    fn link(&self, peer: NodeId) -> Arc<LinkCounters> {
        if let Some(c) = self.traffic.read().unwrap().get(&peer) {
            return c.clone();
        }
        self.traffic.write().unwrap().entry(peer).or_default().clone()
    }

    /// Bytes arriving from a peer relay.
    pub fn note_mesh_rx(&self, peer: NodeId, bytes: u64) {
        self.link(peer).rx.add(bytes);
    }

    /// Bytes handed between two members attached to this relay, which
    /// cross no mesh link at all.
    pub fn note_local_switch(&self, bytes: u64) {
        self.local_switched.add(bytes);
    }

    pub fn note_terminated(&self, bytes: u64) {
        self.terminated.add(bytes);
    }

    /// This relay's row of the fleet traffic matrix.
    pub fn traffic_report(&self) -> TrafficReport {
        let mesh = self.mesh.read().unwrap();
        // Give every live peer a counter entry first. Counters are
        // created lazily by traffic, so a link that is up but idle would
        // otherwise be absent from the report entirely — indistinguishable
        // from a link that does not exist. "up, 0 bytes" is a fact worth
        // reporting; silence is not.
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
                LinkTraffic {
                    peer_id: *peer,
                    tx_bytes,
                    tx_pkts,
                    rx_bytes,
                    rx_pkts,
                    up: mesh.contains_key(peer),
                }
            })
            .collect();
        drop(mesh);
        links.sort_by_key(|l| l.peer_id);
        let (local_bytes, local_pkts) = self.local_switched.get();
        let (terminated_bytes, terminated_pkts) = self.terminated.get();
        TrafficReport { links, local_bytes, local_pkts, terminated_bytes, terminated_pkts }
    }

    pub fn route(&self, origin: Origin, src_id: NodeId, dst_id: NodeId) -> Route {
        let r = self.tables.read().unwrap().route(origin, src_id, dst_id);
        self.counters.note(&r);
        r
    }

    /// Send a datagram verbatim on the chosen next hop, staying on the
    /// lane it arrived on — the endpoint chose that lane from the inner
    /// flow, which is something we are not able to see.
    pub fn send(&self, route: &Route, packet: bytes::Bytes, lane: u8) -> bool {
        let chan = match route {
            Route::Local(id) => self.clients.read().unwrap().get(id).map(|(_, c)| c.clone()),
            Route::Mesh(id) => self.mesh.read().unwrap().get(id).map(|(_, c)| c.clone()),
            _ => None,
        };
        let bytes = packet.len() as u64;
        match chan {
            Some(c) if c.send_on(packet, lane) => {
                if let Route::Mesh(id) = route {
                    self.link(*id).tx.add(bytes);
                }
                true
            }
            _ => {
                self.counters.drop_send_failed.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
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
            "node={} clients={} mesh={} rev={} {}",
            self.my_node_id,
            t.local_count(),
            t.mesh_count(),
            self.membership_rev.load(Ordering::Relaxed),
            counters
        )
    }

    pub fn membership_revision(&self) -> Revision {
        self.membership_rev.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(id: NodeId, addr: &str, fp: &str) -> RelayEndpoint {
        RelayEndpoint {
            relay_id: id,
            name: format!("r{id}"),
            addr: addr.to_string(),
            cert_fp: fp.to_string(),
        }
    }

    #[test]
    fn a_relay_is_only_handed_out_for_dialing_once() {
        // Each dialer task loops forever, so handing the same peer out
        // twice leaves two tasks polling one link. Re-joining used to do
        // exactly that for the whole fleet, once per reconnect.
        let st = RelayState::new(1, "n".into(), "u".into(), "127.0.0.1:1".into());
        let fleet = vec![ep(2, "a:1", "fp2"), ep(3, "b:1", "fp3")];
        assert_eq!(st.take_new_relays(&fleet).len(), 2);
        assert!(
            st.take_new_relays(&fleet).is_empty(),
            "a reconnect must not re-dial peers that already have a dialer"
        );
    }

    #[test]
    fn a_genuinely_new_peer_is_still_dialed() {
        let st = RelayState::new(1, "n".into(), "u".into(), "127.0.0.1:1".into());
        st.take_new_relays(&[ep(2, "a:1", "fp2")]);
        let grown = vec![ep(2, "a:1", "fp2"), ep(3, "b:1", "fp3")];
        let fresh = st.take_new_relays(&grown);
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].relay_id, 3);
    }

    #[test]
    fn a_peer_that_moved_or_rotated_is_dialed_again() {
        // Address or pin changing means the old dialer is aiming at
        // something that no longer answers, so a new one is warranted.
        let st = RelayState::new(1, "n".into(), "u".into(), "127.0.0.1:1".into());
        st.take_new_relays(&[ep(2, "a:1", "fp2")]);
        assert_eq!(st.take_new_relays(&[ep(2, "moved:1", "fp2")]).len(), 1);
        assert_eq!(st.take_new_relays(&[ep(2, "moved:1", "rotated")]).len(), 1);
    }

    #[test]
    fn we_never_dial_ourselves() {
        let st = RelayState::new(7, "n".into(), "u".into(), "127.0.0.1:1".into());
        assert!(st.take_new_relays(&[ep(7, "me:1", "fp")]).is_empty());
    }
}
