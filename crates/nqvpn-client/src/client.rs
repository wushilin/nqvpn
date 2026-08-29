//! The client proper: an endpoint, a relay uplink, and a control link,
//! wired together. Everything here is usable in-process on a fake TUN,
//! which is how the chaos tests run many clients at once.

use anyhow::Result;
use nqvpn_endpoint::engine::{Engine, Uplink};
use nqvpn_endpoint::peers::PeerTable;
use nqvpn_endpoint::routes::{exclude_local, wanted_routes};
use nqvpn_endpoint::tun::TunDevice;
use nqvpn_proto::api::{JoinResponse, RelayEntry};
use nqvpn_proto::control::{Heartbeat, Snapshot};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::transport::{Mode, PacketChannel};
use nqvpn_proto::types::NodeId;
use nqvpn_session::{End, Session, SessionConfig};
use nqvpn_sync::link::MemberHooks;
use nqvpn_sync::{LinkHandle, LocalFacts, Reconcile, View};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Route programming behind one method, so the harness can record.
pub trait RouteSink: Send + Sync {
    fn reconcile(&self, wanted: &[ipnet::IpNet]) -> Result<()>;
    fn reassert(&self) -> Result<()>;
}

impl<P: nqvpn_endpoint::routes::RouteProgrammer + 'static> RouteSink for nqvpn_endpoint::routes::RouteSet<P> {
    fn reconcile(&self, wanted: &[ipnet::IpNet]) -> Result<()> {
        nqvpn_endpoint::routes::RouteSet::reconcile(self, wanted)
    }
    fn reassert(&self) -> Result<()> {
        nqvpn_endpoint::routes::RouteSet::reassert(self)
    }
}

/// The live uplink, swappable underneath the pumps so a re-attach is
/// invisible to everything above.
#[derive(Default)]
pub struct RelayUplink {
    session: Mutex<Option<Arc<Session>>>,
    pub attached_to: Mutex<Option<(NodeId, String)>>,
    pub drops: AtomicU64,
}

impl RelayUplink {
    pub fn set(&self, s: Option<Arc<Session>>, relay: Option<(NodeId, String)>) {
        *self.session.lock().unwrap() = s;
        *self.attached_to.lock().unwrap() = relay;
    }

    pub fn session(&self) -> Option<Arc<Session>> {
        self.session.lock().unwrap().clone()
    }

    pub fn is_up(&self) -> bool {
        self.session.lock().unwrap().is_some()
    }

    pub fn channel(&self) -> Option<Arc<PacketChannel>> {
        self.session().map(|s| s.chan.clone())
    }
}

impl Uplink for RelayUplink {
    fn send(&self, packet: Vec<u8>, lane: u8) -> bool {
        match self.channel() {
            Some(c) if c.send_on(packet.into(), lane) => true,
            _ => {
                self.drops.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

pub struct Client {
    pub node_id: NodeId,
    pub engine: Arc<Engine>,
    pub tun: Arc<dyn TunDevice>,
    pub uplink: Arc<RelayUplink>,
    pub view: Arc<View>,
    pub link: Arc<LinkHandle>,
    pub identity: TlsIdentity,
    credential: Mutex<String>,
    routes: Arc<dyn RouteSink>,
    mine: Vec<ipnet::IpNet>,
    device: String,
    mode: Mode,
    lanes: u8,
    keepalive_secs: u64,
    preferred_relay: Option<String>,
    /// Underlay addresses that must never be routed into the tunnel.
    underlay: Mutex<Vec<IpAddr>>,
    pub counters: ClientCounters,
}

#[derive(Default)]
pub struct ClientCounters {
    pub attaches: AtomicU64,
    pub attach_failures: AtomicU64,
    pub uplink_ends: AtomicU64,
}

impl Client {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        joined: &JoinResponse,
        identity: TlsIdentity,
        keys: StaticKeys,
        tun: Arc<dyn TunDevice>,
        routes: Arc<dyn RouteSink>,
        preferred_relay: Option<String>,
    ) -> Arc<Client> {
        let mut hosts = Vec::new();
        if let Some(ip) = joined.ip4 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
        }
        if let Some(ip) = joined.ip6 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
        }
        let mut table = PeerTable::new(joined.node_id);
        table.set_mine(hosts.clone(), vec![]);
        let engine = Engine::new(joined.node_id, joined.network_uuid.clone(), keys, table, joined.mtu, joined.lanes.max(1));
        let device = tun.name();
        Arc::new(Client {
            node_id: joined.node_id,
            engine,
            tun,
            uplink: Arc::new(RelayUplink::default()),
            view: Arc::new(View::new()),
            link: Arc::new(LinkHandle::default()),
            identity,
            credential: Mutex::new(joined.credential.clone()),
            routes,
            mine: hosts,
            device,
            mode: Mode::parse(&joined.transport),
            lanes: joined.lanes.max(1),
            keepalive_secs: joined.keepalive_secs.max(1) as u64,
            preferred_relay,
            underlay: Mutex::new(Vec::new()),
            counters: ClientCounters::default(),
        })
    }

    pub fn credential(&self) -> String {
        self.credential.lock().unwrap().clone()
    }

    /// Start the pumps: TUN -> engine -> uplink, and the rekey sweep.
    pub fn spawn_pumps(self: &Arc<Self>) {
        let mut reader = self.tun.reader();
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(pkt) = reader.recv().await {
                me.engine.outbound(pkt, me.uplink.as_ref(), me.tun.as_ref());
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                me.engine.expire_sessions();
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(20));
            loop {
                t.tick().await;
                if let Err(e) = me.routes.reassert() {
                    tracing::warn!("route re-assert failed: {e:#}");
                }
            }
        });
    }

    /// The uplink manager: choose a relay, attach, hold the session,
    /// re-attach elsewhere when it ends. Runs forever.
    pub async fn run_uplink(self: Arc<Self>) {
        let mut failures: u32 = 0;
        loop {
            let candidates: Vec<RelayEntry> = self.view.with(|s| {
                s.relays.iter().map(|r| RelayEntry { relay_id: r.relay_id, name: r.name.clone(), addr: r.addr.clone(), cert_fp: r.cert_fp.clone() }).collect()
            });
            if candidates.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let Some(entry) = choose_relay(&candidates, self.preferred_relay.as_deref(), &self.identity, self.keepalive_secs).await else {
                failures = failures.saturating_add(1);
                let wait = nqvpn_proto::joinapi::retry_delay(false, failures);
                tracing::warn!(retry_in_secs = wait.as_secs(), "no reachable relay");
                tokio::time::sleep(wait).await;
                continue;
            };
            let credential = self.credential();
            let Some(claims) = nqvpn_sync::join::own_claims(&credential) else {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            };
            match nqvpn_session::dial(&entry.addr, &self.identity, Some(entry.cert_fp.clone()), &credential, self.keepalive_secs, self.mode, self.lanes, entry.relay_id, nqvpn_proto::types::Role::Relay, claims).await {
                Ok(session) => {
                    self.counters.attaches.fetch_add(1, Ordering::Relaxed);
                    tracing::info!(relay = %entry.name, addr = %entry.addr, "attached");
                    self.uplink.set(Some(session.clone()), Some((entry.relay_id, entry.name.clone())));
                    self.link.kick();
                    let attached_at = std::time::Instant::now();
                    let me = self.clone();
                    let end: End = session
                        .run(&SessionConfig { probe_secs: 2, probe_misses: 5 }, None, move |d, _lane| {
                            me.engine.inbound(&d, me.uplink.as_ref(), me.tun.as_ref());
                        })
                        .await;
                    self.counters.uplink_ends.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(relay = %entry.name, ?end, "uplink ended; re-attaching");
                    self.uplink.set(None, None);
                    self.link.kick();
                    failures = if attached_at.elapsed() >= Duration::from_secs(30) { 0 } else { failures.saturating_add(1) };
                    // A session the relay ended on purpose (evicted,
                    // replaced) is not a reason to hammer it.
                    if end == End::Closed && attached_at.elapsed() < Duration::from_secs(5) {
                        tokio::time::sleep(nqvpn_proto::joinapi::retry_delay(false, failures)).await;
                    }
                }
                Err(err) => {
                    self.counters.attach_failures.fetch_add(1, Ordering::Relaxed);
                    failures = failures.saturating_add(1);
                    let wait = nqvpn_proto::joinapi::retry_delay(false, failures);
                    tracing::warn!(relay = %entry.name, retry_in_secs = wait.as_secs(), "attach failed: {err:#}");
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    pub fn status_line(&self) -> String {
        let relay = self.uplink.attached_to.lock().unwrap().clone().map(|(_, n)| n);
        format!(
            "{} relay={:?} gen={} attaches={} uplink_drops={}",
            self.engine.status_line(),
            relay,
            self.view.gen(),
            self.counters.attaches.load(Ordering::Relaxed),
            self.uplink.drops.load(Ordering::Relaxed)
        )
    }
}

impl LocalFacts for Client {
    fn heartbeat(&self) -> Heartbeat {
        let attached_to = self.uplink.attached_to.lock().unwrap().as_ref().map(|(id, _)| *id);
        let usable_mtu = self.uplink.channel().and_then(|c| c.usable_inner_mtu()).map(|m| m as u16).unwrap_or(0);
        Heartbeat { attached_to, usable_mtu, ..Default::default() }
    }
}

impl MemberHooks for Client {
    fn joined(&self, r: &JoinResponse) {
        *self.credential.lock().unwrap() = r.credential.clone();
        if let Some(s) = self.uplink.session() {
            let cred = r.credential.clone();
            tokio::spawn(async move {
                if let Err(e) = s.refresh(&cred).await {
                    tracing::debug!("refreshing uplink: {e}");
                }
            });
        }
    }
}

impl Client {
    /// Remember underlay addresses (coordinator, relays) so no member
    /// prefix can ever capture them.
    pub fn set_underlay(&self, addrs: Vec<IpAddr>) {
        *self.underlay.lock().unwrap() = addrs;
    }
}

/// The reconciler handle: peers and routes from the view.
pub struct ClientReconciler(pub Arc<Client>);

impl Reconcile for ClientReconciler {
    fn reconcile(&self, view: &Snapshot) {
        let c = &self.0;
        {
            let mut peers = c.engine.peers.lock().unwrap();
            // A peer whose key changed must not keep using the old session.
            let mut changed_keys = Vec::new();
            for m in &view.members {
                if let Some(old) = peers.get(m.node_id) {
                    if old.pubkey != m.pubkey {
                        changed_keys.push(m.node_id);
                    }
                }
            }
            peers.replace_all(view.members.clone());
            drop(peers);
            let mut sessions = c.engine.sessions.lock().unwrap();
            for id in changed_keys {
                sessions.remove(id);
            }
        }
        let wanted = wanted_routes(view, c.node_id, &c.mine);
        let local = nqvpn_endpoint::ifaces::local_prefixes(&c.device);
        let mut underlay = c.underlay.lock().unwrap().clone();
        // Relay addresses from the view, resolved once per address.
        use std::net::ToSocketAddrs;
        for r in &view.relays {
            if let Ok(it) = r.addr.to_socket_addrs() {
                underlay.extend(it.map(|s| s.ip()));
            }
        }
        let (keep, excluded) = exclude_local(wanted, &local, &underlay);
        for (net, why) in excluded {
            tracing::warn!(prefix = %net, %why, "not routing member prefix into the tunnel");
        }
        if let Err(e) = c.routes.reconcile(&keep) {
            tracing::warn!("route reconcile: {e:#}");
        }
        // The relay I am attached to left the fleet or changed: the
        // session will end on its own (the relay closes, or probes
        // fail); nothing to do here beyond making candidates current.
    }
}

/// Rank the fleet: the preferred relay (by name) when reachable,
/// otherwise lowest RTT. Probes run in parallel so one dead relay costs
/// one timeout, not one per relay.
pub async fn choose_relay(fleet: &[RelayEntry], preferred: Option<&str>, identity: &TlsIdentity, keepalive: u64) -> Option<RelayEntry> {
    if let Some(name) = preferred {
        if let Some(e) = fleet.iter().find(|r| r.name == name) {
            if probe_rtt(e, identity, keepalive).await.is_some() {
                return Some(e.clone());
            }
            tracing::warn!(relay = %name, "preferred relay unreachable; falling back to RTT");
        } else {
            tracing::warn!(relay = %name, "preferred relay is not in the fleet");
        }
    }
    let mut set = tokio::task::JoinSet::new();
    for e in fleet.iter().cloned() {
        let identity = identity.clone();
        set.spawn(async move { probe_rtt(&e, &identity, keepalive).await.map(|rtt| (rtt, e)) });
    }
    let mut results = Vec::new();
    while let Some(r) = set.join_next().await {
        if let Ok(Some(r)) = r {
            results.push(r);
        }
    }
    results
        .into_iter()
        .min_by_key(|(rtt, _)| *rtt)
        .map(|(rtt, e)| {
            tracing::info!(relay = %e.name, rtt_ms = rtt, "selected relay");
            e
        })
}

/// One-shot reachability + latency check against a relay.
async fn probe_rtt(entry: &RelayEntry, identity: &TlsIdentity, keepalive: u64) -> Option<u128> {
    use std::net::ToSocketAddrs;
    let addr = entry.addr.to_socket_addrs().ok()?.next()?;
    let bind: std::net::SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
    let mut ep = quinn::Endpoint::client(bind).ok()?;
    ep.set_default_client_config(nqvpn_proto::quic::client_config(identity, Some(entry.cert_fp.clone()), keepalive).ok()?);
    let started = std::time::Instant::now();
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']')).unwrap_or("relay");
    let conn = tokio::time::timeout(Duration::from_secs(5), ep.connect(addr, host).ok()?).await.ok()?.ok()?;
    let rtt = started.elapsed().as_millis();
    conn.close(0u32.into(), b"probe");
    Some(rtt)
}
