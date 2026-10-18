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
use nqvpn_proto::seal::{decode_pubkey, PairSession, SealError, StaticKeys, Tai64n, PREVIOUS_GRACE_SECS, RESPONDER_REKEY_DELAY_SECS};
use nqvpn_proto::types::NodeId;
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

/// Is this published prefix the internet-exit designation (`0.0.0.0/0` or
/// `::/0`) rather than space a member owns?
pub fn is_exit_marker(net: &IpNet) -> bool {
    net.prefix_len() == 0
}

/// Which coordinator-published prefixes this node is willing to route.
///
/// The coordinator decides who owns what, but a member need not take its
/// word for *everything*: a compromised or misconfigured coordinator that
/// publishes `8.8.8.0/24` as some member's LAN would otherwise pull that
/// traffic into the tunnel (and, through the ingress filter, accept
/// packets sourced from it). The policy is applied to the OS routes and
/// to the in-VPN table (outbound LPM and ingress) alike, so a refused
/// prefix is neither routed nor accepted.
///
///  * With an allowlist, a prefix is accepted only if it lies inside one
///    of its entries. The allowlist must then cover the network's own
///    address space too, or peers become unreachable.
///  * Without one, anything wider than `/8` (IPv4) or `/16` (IPv6) is
///    refused: a real site gateway publishes `10.0.0.0/8` or
///    `172.16.0.0/12`, never a slice of the whole internet. The default
///    (`/0`) is not judged here — it is the internet-exit marker, acted
///    on only by route-all, which installs its own catch-all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePolicy {
    pub allow: Option<Vec<IpNet>>,
}

/// The widest prefix accepted per family when no allowlist is set.
pub const MIN_PREFIX_V4: u8 = 8;
pub const MIN_PREFIX_V6: u8 = 16;

impl RoutePolicy {
    pub fn allow_list(allow: Vec<IpNet>) -> Self {
        RoutePolicy { allow: Some(allow.into_iter().map(|n| n.trunc()).collect()) }
    }

    /// `None` when `net` may be routed; otherwise why not. Exit markers
    /// (`/0`) always pass: they are never routes by themselves.
    pub fn refusal(&self, net: &IpNet) -> Option<&'static str> {
        if is_exit_marker(net) {
            return None;
        }
        match &self.allow {
            Some(allow) => (!allow.iter().any(|a| a.contains(net))).then_some("outside the configured [routes] allow list"),
            None => {
                let min = if net.addr().is_ipv4() { MIN_PREFIX_V4 } else { MIN_PREFIX_V6 };
                (net.prefix_len() < min).then_some("wider than /8 (IPv4) or /16 (IPv6); list it in [routes] allow to accept it")
            }
        }
    }

    pub fn permits(&self, net: &IpNet) -> bool {
        self.refusal(net).is_none()
    }
}

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
    /// Our own host addresses (/32, /128): looped back, and accepted.
    mine_hosts: Vec<IpNet>,
    /// LANs we front as a gateway: accepted, never looped back.
    mine_nets: Vec<IpNet>,
    my_node_id: NodeId,
    /// Published prefixes outside this are kept out of the LPM table.
    policy: RoutePolicy,
}

impl PeerTable {
    pub fn new(my_node_id: NodeId) -> Self {
        PeerTable { my_node_id, ..Default::default() }
    }

    /// What this node answers for: its host addresses and, for a
    /// gateway, the LANs behind it.
    pub fn set_mine(&mut self, hosts: Vec<IpNet>, nets: Vec<IpNet>) {
        self.mine_hosts = hosts;
        self.mine_nets = nets;
    }

    /// Apply a route policy; takes effect from the next `upsert` /
    /// `replace_all` (the caller re-applies the view right after).
    pub fn set_policy(&mut self, policy: RoutePolicy) {
        self.policy = policy;
    }

    pub fn policy(&self) -> &RoutePolicy {
        &self.policy
    }

    /// Everything this node owns, for route exclusion.
    pub fn mine(&self) -> Vec<IpNet> {
        self.mine_hosts.iter().chain(self.mine_nets.iter()).copied().collect()
    }

    pub fn upsert(&mut self, p: PeerInfo) {
        if p.node_id != self.my_node_id {
            // A published default is a marker ("this node is an internet
            // exit"), not a route: only a route-all client acts on it, by
            // choosing one exit with `set_default_exit`. Everyone else must
            // neither seal internet-bound traffic to an exit nor accept
            // internet-sourced packets from one.
            for net in p.prefixes.iter().filter(|n| !is_exit_marker(n) && self.policy.permits(n)) {
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
        if self.peers.remove(&id).is_some() {
            // Only entries this node holds: a prefix it also listed may
            // have been taken over by someone else since.
            let held: Vec<IpNet> = self.lpm.iter().filter(|(_, owner)| *owner == id).map(|(net, _)| net).collect();
            for net in held {
                self.lpm.remove(&net);
            }
        }
    }

    pub fn replace_all(&mut self, peers: Vec<PeerInfo>) {
        // Snapshot the prefix -> owner map before and after so the
        // in-VPN routing table's changes are logged with detail: what
        // prefix, which member gained/lost/took it over. No change,
        // no log.
        let before: BTreeMap<IpNet, NodeId> = self.lpm.iter().collect();
        let name_before: HashMap<NodeId, String> =
            self.peers.iter().map(|(id, p)| (*id, p.name.clone())).collect();
        let members_before = self.peers.len();

        self.peers.clear();
        self.lpm = LpmTable::new();
        for p in peers {
            self.upsert(p);
        }

        let after: BTreeMap<IpNet, NodeId> = self.lpm.iter().collect();
        let name = |id: NodeId| -> String {
            self.peers
                .get(&id)
                .map(|p| p.name.clone())
                .or_else(|| name_before.get(&id).cloned())
                .unwrap_or_default()
        };
        let (mut added, mut removed, mut moved) = (0u32, 0u32, 0u32);
        for (net, owner) in &after {
            match before.get(net) {
                None => {
                    added += 1;
                    tracing::info!(target: "nqvpn::vpn_routes", prefix = %net, owner = %name(*owner), node = owner, "vpn route added");
                }
                Some(prev) if prev != owner => {
                    moved += 1;
                    tracing::info!(target: "nqvpn::vpn_routes", prefix = %net, from = %name(*prev), to = %name(*owner), "vpn route owner changed");
                }
                _ => {}
            }
        }
        for (net, prev) in &before {
            if !after.contains_key(net) {
                removed += 1;
                tracing::info!(target: "nqvpn::vpn_routes", prefix = %net, was = %name(*prev), "vpn route withdrawn");
            }
        }
        if added + removed + moved > 0 {
            tracing::info!(
                target: "nqvpn::vpn_routes",
                added, removed, moved,
                members = self.peers.len(),
                prev_members = members_before,
                total_prefixes = after.len(),
                "in-vpn routing table updated"
            );
        }
    }

    pub fn owner_of(&self, addr: IpAddr) -> Option<NodeId> {
        self.lpm.lookup(addr)
    }

    /// Point a family's default (`0.0.0.0/0` / `::/0`) at `node` in the
    /// outbound table, overriding whatever the published prefixes resolved
    /// it to. This is how a route-all client selects its internet exit
    /// gateway — and picks deterministically when several nodes advertise a
    /// default. A no-op for our own id (we never route the default back at
    /// ourselves). `replace_all` wipes it, so the caller re-asserts it
    /// every reconcile.
    pub fn set_default_exit(&mut self, net: IpNet, node: NodeId) {
        if node != self.my_node_id {
            self.lpm.insert(net, node);
        }
    }

    /// Is this one of our own host addresses? macOS routes a host's own
    /// tunnel address *into* the utun rather than looping it back in the
    /// kernel, so without this a node cannot ping itself.
    pub fn is_mine_host(&self, addr: IpAddr) -> bool {
        self.mine_hosts.iter().any(|n| n.contains(&addr))
    }

    /// Is this address ours to accept: a host address, or inside a LAN
    /// we front?
    pub fn owns(&self, addr: IpAddr) -> bool {
        self.is_mine_host(addr) || self.mine_nets.iter().any(|n| n.contains(&addr))
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
        if !self.owns(dst) {
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

/// One peer's sessions across a rekey.
///
/// Frames carry no session index, so a receiver tells keys apart by
/// trial: `current`, then a `next` that is ready, then `previous` while
/// its grace lasts. Each keeps its own replay window, so trying one never
/// moves another's, and a frame that fails authentication moves none.
#[derive(Default)]
pub struct PeerSessions {
    /// What we send on once ready; before that, the first handshake.
    current: Option<PairSession>,
    /// A replacement negotiated while `current` keeps carrying traffic:
    /// our own rekey initiation in flight, or — as responder — a ready
    /// session we do not send on until the peer's first frame arrives on
    /// it (our reply may still be on the wire; sealing to keys the
    /// initiator does not hold yet would lose those packets).
    next: Option<PairSession>,
    /// The session `current` replaced, receive-only, and when it was
    /// retired.
    previous: Option<(PairSession, u64)>,
    /// When we first sent to this peer without hearing anything back
    /// since; cleared by any frame from it that authenticates.
    awaiting_since: Option<u64>,
    /// When we last sent it anything (data or keepalive).
    last_sent: u64,
}

impl PeerSessions {
    fn is_empty(&self) -> bool {
        self.current.is_none() && self.next.is_none() && self.previous.is_none()
    }

    /// `next` becomes `current`; a ready `current` is kept receive-only.
    /// Completing a handshake is itself word from the peer.
    fn promote(&mut self, now: u64) {
        if let Some(new) = self.next.take() {
            self.awaiting_since = None;
            if let Some(old) = self.current.take().filter(|s| s.is_ready()) {
                self.previous = Some((old, now));
            }
            self.current = Some(new);
        }
    }
}

/// All live end-to-end sessions, keyed by peer.
#[derive(Default)]
pub struct SessionTable {
    sessions: HashMap<NodeId, PeerSessions>,
    /// Packets waiting for a handshake to complete (§6: bounded, never
    /// unbounded buffering).
    pending: HashMap<NodeId, Vec<Vec<u8>>>,
    /// Newest initiator timestamp accepted per peer and static key: a
    /// replayed msg1 carries an older one and is refused. Keyed by the
    /// key too, so a replacement machine (a new key under the same node
    /// id) is not held to its predecessor's clock.
    last_handshake_ts: HashMap<(NodeId, Vec<u8>), Tai64n>,
}

pub const PENDING_LIMIT: usize = 64;

/// A receiver that has sent nothing to a peer for this long answers its
/// next data frame with an empty keepalive, so a one-way flow still
/// proves to the sender that its session is alive.
pub const KEEPALIVE_SECS: u64 = 5;

/// A sender that has heard nothing back for this long, while sending,
/// starts a new handshake. This is what repairs a session only one side
/// still holds — the peer restarted, or dropped it when the view briefly
/// lost us — which would otherwise stay silent until the rekey deadline.
/// Larger than `KEEPALIVE_SECS` plus a round trip, so a live one-way flow
/// never trips it.
pub const UNANSWERED_REKEY_SECS: u64 = 10;

impl SessionTable {
    /// The session we send on (or the first handshake in flight).
    pub fn get_mut(&mut self, peer: NodeId) -> Option<&mut PairSession> {
        self.sessions.get_mut(&peer).and_then(|p| p.current.as_mut())
    }

    /// Install `s` as the session to send on, replacing whatever was.
    pub fn insert(&mut self, peer: NodeId, s: PairSession) {
        self.sessions.entry(peer).or_default().current = Some(s);
    }

    pub fn remove(&mut self, peer: NodeId) {
        self.sessions.remove(&peer);
        self.pending.remove(&peer);
    }

    pub fn is_ready(&self, peer: NodeId) -> bool {
        self.sessions.get(&peer).and_then(|p| p.current.as_ref()).map(|s| s.is_ready()).unwrap_or(false)
    }

    /// Is a session — or a replacement being negotiated — on its way?
    pub fn has(&self, peer: NodeId) -> bool {
        self.sessions.get(&peer).map(|p| p.current.is_some() || p.next.is_some()).unwrap_or(false)
    }

    /// Our own rekey initiation for `peer`, if one is in flight.
    pub fn next_in_flight(&mut self, peer: NodeId) -> Option<&mut PairSession> {
        self.sessions.get_mut(&peer).and_then(|p| p.next.as_mut()).filter(|s| s.initiator && !s.is_ready())
    }

    /// Abandon a replacement in flight (a crossed rekey we yield on).
    pub fn drop_next(&mut self, peer: NodeId) {
        if let Some(p) = self.sessions.get_mut(&peer) {
            p.next = None;
        }
    }

    /// Our rekey completed: switch to it, keeping the old keys for the
    /// receive grace.
    pub fn promote(&mut self, peer: NodeId, now: u64) {
        if let Some(p) = self.sessions.get_mut(&peer) {
            p.promote(now);
        }
    }

    /// A handshake we answered. With a working session in place this is
    /// a rekey: the new one waits in `next` until the peer's first frame
    /// on it proves the peer holds it, and `false` says we keep sending on
    /// the old one meanwhile. With none, it is used at once (`true`).
    pub fn install_responder(&mut self, peer: NodeId, s: PairSession) -> bool {
        let p = self.sessions.entry(peer).or_default();
        // An authenticated msg1 is word from the peer.
        p.awaiting_since = None;
        if p.current.as_ref().is_some_and(|c| c.is_ready()) {
            p.next = Some(s);
            false
        } else {
            p.current = Some(s);
            true
        }
    }

    /// Is it time for us to start replacing `peer`'s session? The side
    /// that initiated it rekeys at the soft deadline; the responder only
    /// a little later, as a backstop for an initiator that went quiet.
    pub fn rekey_due(&self, peer: NodeId, now: u64) -> bool {
        let Some(p) = self.sessions.get(&peer) else { return false };
        let Some(c) = p.current.as_ref().filter(|c| c.is_ready()) else { return false };
        if p.next.is_some() {
            return false;
        }
        if p.awaiting_since.is_some_and(|t| now.saturating_sub(t) >= UNANSWERED_REKEY_SECS) {
            return true;
        }
        let at = if c.initiator { now } else { now.saturating_sub(RESPONDER_REKEY_DELAY_SECS) };
        c.needs_rekey(at)
    }

    /// Record that we sent `peer` something.
    pub fn note_sent(&mut self, peer: NodeId, now: u64) {
        if let Some(p) = self.sessions.get_mut(&peer) {
            p.awaiting_since.get_or_insert(now);
            p.last_sent = now;
        }
    }

    /// Have we been silent toward `peer` long enough that the data frame
    /// just received should be answered with a keepalive?
    pub fn keepalive_due(&self, peer: NodeId, now: u64) -> bool {
        self.is_ready(peer) && self.sessions.get(&peer).is_some_and(|p| now.saturating_sub(p.last_sent) >= KEEPALIVE_SECS)
    }

    /// Start replacing a working session: the handshake goes in `next`
    /// and `current` keeps sending until it completes.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_rekey(
        &mut self,
        keys: &StaticKeys,
        peer: NodeId,
        peer_pubkey: &[u8],
        network_uuid: &str,
        me: NodeId,
        now: u64,
        ts: Tai64n,
    ) -> Result<Vec<u8>, SealError> {
        let (s, msg) = PairSession::initiate_at(keys, peer, peer_pubkey, network_uuid, me, now, ts)?;
        self.sessions.entry(peer).or_default().next = Some(s);
        Ok(msg)
    }

    /// Decrypt a frame from `peer` under whichever of its sessions it was
    /// sealed with. A frame that opens `next` is the peer's confirmation
    /// that it holds those keys: `next` becomes the session we send on.
    pub fn unseal(&mut self, peer: NodeId, ctr: u64, ciphertext: &[u8], now: u64) -> Result<Vec<u8>, SealError> {
        let Some(p) = self.sessions.get_mut(&peer) else {
            return Err(SealError::NoSession(peer));
        };
        let r = Self::unseal_any(p, ctr, ciphertext, now);
        if r.is_ok() {
            p.awaiting_since = None;
        }
        r.map_err(|e| match e {
            SealError::NoSession(_) => SealError::NoSession(peer),
            e => e,
        })
    }

    fn unseal_any(p: &mut PeerSessions, ctr: u64, ciphertext: &[u8], now: u64) -> Result<Vec<u8>, SealError> {
        let mut errs: Vec<SealError> = Vec::new();
        if let Some(s) = p.current.as_mut().filter(|s| s.is_ready()) {
            match s.unseal(ctr, ciphertext) {
                Ok(v) => return Ok(v),
                Err(e) => errs.push(e),
            }
        }
        if let Some(s) = p.next.as_mut().filter(|s| s.is_ready()) {
            match s.unseal(ctr, ciphertext) {
                Ok(v) => {
                    p.promote(now);
                    return Ok(v);
                }
                Err(e) => errs.push(e),
            }
        }
        if let Some((s, retired)) = p.previous.as_mut() {
            if now.saturating_sub(*retired) < PREVIOUS_GRACE_SECS {
                match s.unseal(ctr, ciphertext) {
                    Ok(v) => return Ok(v),
                    Err(e) => errs.push(e),
                }
            }
        }
        // A replay under any of them is the interesting verdict; else the
        // first failure (normally the current session's).
        match errs.iter().position(|e| matches!(e, SealError::Replay(_))) {
            Some(i) => Err(errs.swap_remove(i)),
            None if !errs.is_empty() => Err(errs.swap_remove(0)),
            None => Err(SealError::NoSession(0)),
        }
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

    pub fn pending_len(&self, peer: NodeId) -> usize {
        self.pending.get(&peer).map(|q| q.len()).unwrap_or(0)
    }

    /// Accept an initiator timestamp if it is newer than the last one
    /// seen from this peer under this static key. A restarted peer's
    /// clock still moves forward, so for the same key this only ever
    /// refuses a replay; a clock that stepped back is refused too — the
    /// price of replay protection, as in WireGuard — until the view resets
    /// the watermark (`forget_handshake_ts`) or the key changes.
    pub fn accept_handshake_ts(&mut self, peer: NodeId, static_key: &[u8], ts: Tai64n) -> bool {
        let k = (peer, static_key.to_vec());
        match self.last_handshake_ts.get(&k) {
            Some(last) if ts <= *last => false,
            _ => {
                self.last_handshake_ts.insert(k, ts);
                true
            }
        }
    }

    /// Forget every watermark held for `peer` (its login changed: a new
    /// machine or a re-issued identity starts from its own clock).
    pub fn forget_handshake_ts(&mut self, peer: NodeId) {
        self.last_handshake_ts.retain(|(id, _), _| *id != peer);
    }

    /// Start a session toward `peer`, returning the handshake message.
    /// Anything half-negotiated for it is abandoned: this is a fresh start.
    pub fn initiate(
        &mut self,
        keys: &StaticKeys,
        peer: NodeId,
        peer_pubkey: &[u8],
        network_uuid: &str,
        me: NodeId,
        now: u64,
    ) -> Result<Vec<u8>, SealError> {
        self.initiate_at(keys, peer, peer_pubkey, network_uuid, me, now, Tai64n::new(now, 0))
    }

    /// `initiate` with an explicit msg1 timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn initiate_at(
        &mut self,
        keys: &StaticKeys,
        peer: NodeId,
        peer_pubkey: &[u8],
        network_uuid: &str,
        me: NodeId,
        now: u64,
        ts: Tai64n,
    ) -> Result<Vec<u8>, SealError> {
        let (s, msg) = PairSession::initiate_at(keys, peer, peer_pubkey, network_uuid, me, now, ts)?;
        let p = self.sessions.entry(peer).or_default();
        p.current = Some(s);
        p.next = None;
        p.awaiting_since = None;
        Ok(msg)
    }

    /// The periodic sweep. Drops sessions past the hard deadline,
    /// handshakes that never completed (dropping them is what lets the
    /// next outbound packet start a fresh one instead of queueing forever
    /// behind a session that will never be ready), and previous sessions
    /// whose grace ran out. Returns the peers whose handshake timed out.
    pub fn expire(&mut self, now: u64) -> Vec<NodeId> {
        let mut timed_out = Vec::new();
        for (id, p) in self.sessions.iter_mut() {
            match p.current.as_ref() {
                Some(c) if c.is_ready() && c.must_expire(now) => p.current = None,
                Some(c) if c.is_stale_handshake(now) => {
                    p.current = None;
                    timed_out.push(*id);
                }
                _ => {}
            }
            match p.next.as_ref() {
                Some(n) if n.is_stale_handshake(now) => {
                    p.next = None;
                    timed_out.push(*id);
                }
                Some(n) if n.is_ready() && n.must_expire(now) => p.next = None,
                _ => {}
            }
            // Nothing left to send on but a ready, unconfirmed answer:
            // there is no older session to protect, so use it.
            if p.current.is_none() && p.next.as_ref().is_some_and(|n| n.is_ready()) {
                p.promote(now);
            }
            if p.previous.as_ref().is_some_and(|(_, at)| now.saturating_sub(*at) >= PREVIOUS_GRACE_SECS) {
                p.previous = None;
            }
        }
        self.sessions.retain(|_, p| !p.is_empty());
        timed_out.sort_unstable();
        timed_out.dedup();
        timed_out
    }

    /// Bring sessions in line with the published membership: every
    /// session — current, next, previous — whose peer left the view, or
    /// whose authenticated static key is not the one now published for
    /// it, is dropped, along with its queued packets; a peer whose key is
    /// missing or undecodable keeps no queue (no handshake can ever drain
    /// it); and watermarks are kept only for members still present under
    /// the key they were taken with. `published` maps every member to its
    /// decoded key (`None` when it does not decode). Returns the peers
    /// that lost a session.
    pub fn sync_view(&mut self, published: &HashMap<NodeId, Option<Vec<u8>>>) -> Vec<NodeId> {
        let mut dropped = Vec::new();
        for (id, p) in self.sessions.iter_mut() {
            let want = published.get(id).cloned().flatten();
            let stale = |s: &PairSession| match (&want, s.peer_static()) {
                (Some(w), Some(got)) => *w != got,
                _ => true,
            };
            let before = (p.current.is_some(), p.next.is_some(), p.previous.is_some());
            if p.current.as_ref().is_some_and(stale) {
                p.current = None;
            }
            if p.next.as_ref().is_some_and(stale) {
                p.next = None;
            }
            if p.previous.as_ref().is_some_and(|(s, _)| stale(s)) {
                p.previous = None;
            }
            if before != (p.current.is_some(), p.next.is_some(), p.previous.is_some()) {
                dropped.push(*id);
            }
        }
        self.sessions.retain(|_, p| !p.is_empty());
        let sessions = &self.sessions;
        self.pending.retain(|id, _| published.get(id).is_some_and(|k| k.is_some()) && (sessions.contains_key(id) || !dropped.contains(id)));
        self.last_handshake_ts.retain(|(id, key), _| published.get(id).is_some_and(|k| k.as_deref() == Some(key.as_slice())));
        dropped.sort_unstable();
        dropped
    }

    /// Peers holding any session state (for status and tests).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: NodeId, prefixes: &[&str], pubkey: &str) -> PeerInfo {
        PeerInfo {
            node_id: id,
            name: format!("n{id}"),
            role: nqvpn_proto::types::Role::Client,
            prefixes: prefixes.iter().map(|p| p.parse().unwrap()).collect(),
            pubkey: pubkey.into(),
            online: true,
            login_gen: 0,
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
        t.set_mine(vec!["10.99.1.1/32".parse().unwrap()], vec![]);
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
    fn a_published_default_routes_nothing_until_an_exit_is_chosen() {
        // Node 3 is an internet exit. Without route-all choosing it, the
        // marker neither routes internet traffic to it nor lets it source
        // internet packets at us.
        let mut t = table();
        t.upsert(peer(3, &["10.99.1.3/32", "192.168.7.0/24", "0.0.0.0/0"], ""));
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), None, "the marker is not a route");
        let reply = v4([8, 8, 8, 8], [10, 99, 1, 1]);
        assert_eq!(t.check_ingress(3, &reply), IngressVerdict::Drop("inner_src_not_owned"));
        // Choosing it (route-all) is what makes it the default.
        t.set_default_exit("0.0.0.0/0".parse().unwrap(), 3);
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), Some(3));
        assert_eq!(t.check_ingress(3, &reply), IngressVerdict::Accept);
    }

    #[test]
    fn a_default_exit_routes_the_unrouted_but_a_specific_peer_still_wins() {
        let mut t = table();
        // Without an exit, internet-bound traffic has no owner (drops).
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), None);
        // Selecting node 3 as the exit routes the otherwise-unrouted there.
        t.set_default_exit("0.0.0.0/0".parse().unwrap(), 3);
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), Some(3), "internet goes to the exit");
        assert_eq!(t.owner_of("10.99.1.2".parse().unwrap()), Some(2), "a member is unaffected by the default");
        assert_eq!(t.owner_of("192.168.7.20".parse().unwrap()), Some(3), "a gateway LAN still wins by longest match");
        // Re-selecting a different exit overrides deterministically.
        t.set_default_exit("0.0.0.0/0".parse().unwrap(), 2);
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), Some(2));
        // Never at ourselves (node 1): the default is left as it was.
        t.set_default_exit("0.0.0.0/0".parse().unwrap(), 1);
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), Some(2), "a self-exit is ignored");
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
    fn a_gateway_accepts_its_lan_but_does_not_loop_it_back() {
        let mut t = PeerTable::new(1);
        t.set_mine(vec!["10.99.0.1/32".parse().unwrap()], vec!["192.168.1.0/24".parse().unwrap()]);
        t.upsert(peer(2, &["10.99.1.2/32"], ""));
        let lan_host: IpAddr = "192.168.1.50".parse().unwrap();
        assert!(t.owns(lan_host));
        assert!(!t.is_mine_host(lan_host), "a LAN packet must leave via the LAN, not re-enter the TUN");
        assert!(t.is_mine_host("10.99.0.1".parse().unwrap()));
        let pkt = v4([10, 99, 1, 2], [192, 168, 1, 50]);
        assert_eq!(t.check_ingress(2, &pkt), IngressVerdict::Accept);
    }

    #[test]
    fn a_replayed_handshake_timestamp_is_refused() {
        let mut s = SessionTable::default();
        let (k, k2) = (b"key-one".as_slice(), b"key-two".as_slice());
        let t = Tai64n::new;
        assert!(s.accept_handshake_ts(7, k, t(100, 0)));
        assert!(!s.accept_handshake_ts(7, k, t(100, 0)), "same msg1 again");
        assert!(!s.accept_handshake_ts(7, k, t(50, 0)), "older");
        assert!(s.accept_handshake_ts(7, k, t(100, 1)), "nanoseconds order two handshakes in one second");
        assert!(s.accept_handshake_ts(8, k, t(1, 0)), "per peer");
        // A replacement machine under the same node id has a new key and
        // its own clock: the predecessor's watermark does not bind it.
        assert!(s.accept_handshake_ts(7, k2, t(60, 0)), "per static key");
        assert!(!s.accept_handshake_ts(7, k2, t(60, 0)), "and replay-protected under it");
        // A re-login resets the watermark for that node.
        s.forget_handshake_ts(7);
        assert!(s.accept_handshake_ts(7, k, t(90, 0)));
    }

    #[test]
    fn the_route_policy_refuses_what_a_site_would_never_publish() {
        let open = RoutePolicy::default();
        assert!(open.permits(&"10.0.0.0/8".parse().unwrap()), "a real site's wide range");
        assert!(open.permits(&"172.16.0.0/12".parse().unwrap()));
        assert!(!open.permits(&"8.0.0.0/7".parse().unwrap()), "a slice of the internet");
        assert!(!open.permits(&"0.0.0.0/1".parse().unwrap()));
        assert!(open.permits(&"fd00::/16".parse().unwrap()));
        assert!(!open.permits(&"2000::/3".parse().unwrap()));
        assert!(open.permits(&"0.0.0.0/0".parse().unwrap()), "the exit marker is judged by route-all, not here");
        let listed = RoutePolicy::allow_list(vec!["10.99.0.0/16".parse().unwrap(), "192.168.7.0/24".parse().unwrap()]);
        assert!(listed.permits(&"10.99.1.2/32".parse().unwrap()));
        assert!(listed.permits(&"192.168.7.0/24".parse().unwrap()));
        assert!(!listed.permits(&"192.168.0.0/16".parse().unwrap()), "wider than the entry");
        assert!(!listed.permits(&"8.8.8.0/24".parse().unwrap()));
    }

    #[test]
    fn a_refused_prefix_is_neither_routed_nor_accepted() {
        let mut t = PeerTable::new(1);
        t.set_policy(RoutePolicy::allow_list(vec!["10.99.0.0/16".parse().unwrap()]));
        t.set_mine(vec!["10.99.1.1/32".parse().unwrap()], vec![]);
        t.replace_all(vec![peer(3, &["10.99.1.3/32", "8.8.8.0/24"], "")]);
        assert_eq!(t.owner_of("10.99.1.3".parse().unwrap()), Some(3));
        assert_eq!(t.owner_of("8.8.8.8".parse().unwrap()), None, "not routed into the tunnel");
        let spoofed = v4([8, 8, 8, 8], [10, 99, 1, 1]);
        assert_eq!(t.check_ingress(3, &spoofed), IngressVerdict::Drop("inner_src_not_owned"), "and not accepted from it");
    }

    #[test]
    fn removing_a_peer_leaves_a_prefix_someone_else_took_over() {
        let mut t = table();
        t.upsert(peer(2, &["10.99.1.2/32", "192.168.7.0/24"], ""));
        // 192.168.7.0/24 now resolves to whichever inserted last (2).
        assert_eq!(t.owner_of("192.168.7.1".parse().unwrap()), Some(2));
        t.remove(3);
        assert_eq!(t.owner_of("192.168.7.1".parse().unwrap()), Some(2), "3 leaving does not take 2's route with it");
    }

    /// A ready pair of sessions between 10 (initiator) and 20, at time `now`.
    fn ready_pair(a: &StaticKeys, b: &StaticKeys, now: u64, ts: Tai64n) -> (PairSession, PairSession) {
        let (mut i, m1) = PairSession::initiate_at(a, 20, &b.public, "u", 10, now, ts).unwrap();
        let (r, m2, _) = PairSession::respond(b, 10, "u", 20, &m1, now).unwrap();
        i.finish(&m2).unwrap();
        (i, r)
    }

    #[test]
    fn the_previous_session_still_decrypts_during_its_grace_and_not_after() {
        let (a, b) = (StaticKeys::generate().unwrap(), StaticKeys::generate().unwrap());
        // Receiver side (20) holds an old session, then a new one replaces it.
        let (mut old_tx, old_rx) = ready_pair(&a, &b, 0, Tai64n::new(1, 0));
        let (mut new_tx, new_rx) = ready_pair(&a, &b, 100, Tai64n::new(2, 0));
        let mut t = SessionTable::default();
        t.insert(10, old_rx);
        assert!(!t.install_responder(10, new_rx), "a rekey waits in next");
        // A frame on the old keys still opens the current (old) session.
        let (c, ct) = old_tx.seal(b"old-1").unwrap();
        assert_eq!(t.unseal(10, c, &ct, 100).unwrap(), b"old-1");
        // The first frame on the new keys confirms and promotes it.
        let (c, ct) = new_tx.seal(b"new-1").unwrap();
        assert_eq!(t.unseal(10, c, &ct, 101).unwrap(), b"new-1");
        // A straggler on the old keys, inside the grace: still delivered,
        // and still replay-protected under its own window.
        let (c, ct) = old_tx.seal(b"old-2").unwrap();
        assert_eq!(t.unseal(10, c, &ct, 105).unwrap(), b"old-2");
        assert!(matches!(t.unseal(10, c, &ct, 105), Err(SealError::Replay(_))), "a replay is still a replay");
        // After the grace the old keys are gone for good.
        let (c, ct) = old_tx.seal(b"old-3").unwrap();
        t.expire(101 + PREVIOUS_GRACE_SECS);
        assert!(t.unseal(10, c, &ct, 101 + PREVIOUS_GRACE_SECS).is_err());
        // The new session is unaffected.
        let (c, ct) = new_tx.seal(b"new-2").unwrap();
        assert_eq!(t.unseal(10, c, &ct, 120).unwrap(), b"new-2");
    }

    #[test]
    fn sessions_and_queues_follow_the_view() {
        let (a, b, c) = (StaticKeys::generate().unwrap(), StaticKeys::generate().unwrap(), StaticKeys::generate().unwrap());
        let (_, rx_from_10) = ready_pair(&a, &b, 0, Tai64n::new(1, 0));
        let mut t = SessionTable::default();
        t.insert(10, rx_from_10);
        t.queue(11, vec![1]);
        t.queue(12, vec![2]);
        assert!(t.accept_handshake_ts(10, &a.public, Tai64n::new(5, 0)));
        // 10 still publishes the key its session authenticated: kept.
        let mut published: HashMap<NodeId, Option<Vec<u8>>> = HashMap::new();
        published.insert(10, Some(a.public.clone()));
        published.insert(11, None); // key does not decode
        assert!(t.sync_view(&published).is_empty());
        assert!(t.is_ready(10));
        assert_eq!(t.pending_len(11), 0, "an undecodable key can never drain its queue");
        assert_eq!(t.pending_len(12), 0, "a peer that left the view keeps nothing");
        // 10 now publishes a different key (replaced machine): dropped,
        // and the old key's watermark with it.
        published.insert(10, Some(c.public.clone()));
        assert_eq!(t.sync_view(&published), vec![10]);
        assert!(!t.has(10));
        assert!(t.accept_handshake_ts(10, &a.public, Tai64n::new(1, 0)), "the old key's watermark was forgotten");
        // And a peer that left the view entirely loses its session.
        let (_, again) = ready_pair(&c, &b, 0, Tai64n::new(1, 0));
        t.insert(10, again);
        published.clear();
        assert_eq!(t.sync_view(&published), vec![10]);
        assert_eq!(t.session_count(), 0);
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
