//! The client proper: an endpoint, a relay uplink, and a control link,
//! wired together. Everything here is usable in-process on a fake TUN,
//! which is how the chaos tests run many clients at once.

use anyhow::Result;
use nqvpn_endpoint::engine::{Engine, Uplink};
use nqvpn_endpoint::peers::{PeerTable, RoutePolicy};
use nqvpn_endpoint::routes::{exclude_local, refused_prefixes, wanted_routes_with};
use nqvpn_endpoint::tun::TunDevice;
use nqvpn_proto::api::{JoinResponse, RelayEntry};
use nqvpn_proto::control::{Heartbeat, Snapshot};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::transport::{Mode, PacketChannel};
use nqvpn_proto::types::NodeId;
use nqvpn_session::{End, Session, SessionConfig};
use nqvpn_sync::link::MemberHooks;
use nqvpn_session::{Refused, CLOSE_EVICTED, CLOSE_STALE_LOGIN};
use nqvpn_sync::{LinkHandle, LocalFacts, Reconcile, View};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Route programming behind one method, so the harness can record.
pub trait RouteSink: Send + Sync {
    fn reconcile(&self, wanted: &[ipnet::IpNet], mine: &[ipnet::IpNet]) -> Result<()>;
    fn reassert(&self) -> Result<()>;
    /// Pin the underlay transport hosts to the real gateway (route-all);
    /// returns those actually pinned. Default pretends success so a
    /// recording sink still surfaces the catch-all routes.
    fn pin_underlay(&self, ips: &[std::net::IpAddr]) -> Result<Vec<std::net::IpAddr>> {
        Ok(ips.to_vec())
    }
}

impl<P: nqvpn_endpoint::routes::RouteProgrammer + 'static> RouteSink for nqvpn_endpoint::routes::RouteSet<P> {
    fn pin_underlay(&self, ips: &[std::net::IpAddr]) -> Result<Vec<std::net::IpAddr>> {
        nqvpn_endpoint::routes::RouteSet::pin_underlay(self, ips)
    }
    fn reconcile(&self, wanted: &[ipnet::IpNet], mine: &[ipnet::IpNet]) -> Result<()> {
        // Prefer diffing against the kernel's own table; fall back to the
        // cache path when it can't be read (the recording programmer).
        if nqvpn_endpoint::routes::RouteSet::reconcile_via_kernel(self, wanted, mine)? {
            Ok(())
        } else {
            nqvpn_endpoint::routes::RouteSet::reconcile(self, wanted, mine)
        }
    }
    fn reassert(&self) -> Result<()> {
        if nqvpn_endpoint::routes::RouteSet::reassert_via_kernel(self)? {
            Ok(())
        } else {
            nqvpn_endpoint::routes::RouteSet::reassert(self)
        }
    }
}

/// The live uplink, swappable underneath the pumps so a re-attach is
/// invisible to everything above.
#[derive(Default)]
pub struct RelayUplink {
    session: Mutex<Option<Arc<Session>>>,
    pub attached_to: Mutex<Option<Attached>>,
    pub drops: AtomicU64,
}

/// The fleet entry the uplink was dialed from. Reconcile compares it
/// with the entry the coordinator publishes now: a relay that
/// re-registered from elsewhere is a zombie even if it still answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attached {
    pub relay_id: NodeId,
    pub name: String,
    /// The relay's published address — what reconcile compares.
    pub addr: String,
    pub cert_fp: String,
    /// What was actually dialed: `addr`, or a forwarder (`--relay-via`).
    pub dialed: String,
}

/// `--relay-via <relay>=<host:port>`: reach the fleet relay named `relay`
/// through a forwarder at `addr` (`nqvpn-forward`) instead of its published
/// address. Local to this client; the coordinator never hears of it. The
/// session is still pinned to the relay's own certificate, so the
/// forwarder is trusted with nothing but delivery.
///
/// It outranks the coordinator's preferred relay. While the forwarder is
/// unreachable the uplink falls back to the fleet as usual, and returns
/// through the forwarder once it answers again.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayVia {
    pub relay: String,
    pub addr: String,
}

impl std::str::FromStr for RelayVia {
    type Err = String;
    fn from_str(s: &str) -> Result<RelayVia, String> {
        let (relay, addr) = s.split_once('=').ok_or("expected <relay-name>=<host:port>")?;
        let (relay, addr) = (relay.trim(), addr.trim());
        if relay.is_empty() {
            return Err("missing the relay name before '='".into());
        }
        match addr.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
            _ => return Err(format!("{addr:?} is not host:port")),
        }
        Ok(RelayVia { relay: relay.to_string(), addr: addr.to_string() })
    }
}

impl RelayUplink {
    pub fn set(&self, s: Option<Arc<Session>>, relay: Option<Attached>) {
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
    mine: Mutex<Vec<ipnet::IpNet>>,
    device: String,
    mode: Mode,
    lanes: u8,
    keepalive_secs: u64,
    /// Configured at the coordinator; applied at every join.
    preferred_relay: Mutex<Option<String>>,
    /// While attached to a fallback relay, how often to check whether
    /// the preferred one (or the `relay_via` forwarder) is reachable again.
    pub prefer_recheck: Mutex<Duration>,
    /// Local override: dial this relay through a forwarder.
    relay_via: Mutex<Option<RelayVia>>,
    /// Underlay addresses that must never be routed into the tunnel.
    underlay: Mutex<Vec<IpAddr>>,
    /// The exit each family is currently sealed to, so a change of exit is
    /// reported once rather than every reconcile.
    exit_chosen: Mutex<std::collections::BTreeMap<bool, NodeId>>,
    /// Relay transport address -> its resolved IPs.
    ///
    /// Under route-all these are the hosts we pin to the real gateway, so
    /// re-resolving them on every reconcile would make the tunnel depend on
    /// working DNS *forever* — and DNS is one of the things the tunnel
    /// captures. A result, once had, is therefore never given up: it is
    /// refreshed after `RELAY_ADDR_TTL`, but a refresh that fails keeps
    /// the old addresses. Lookups run off the reconcile path (see
    /// `RelayAddrs`), so a slow resolver never stalls the runtime.
    relay_addrs: Arc<Mutex<HashMap<String, RelayAddr>>>,
    /// What the route policy (`[routes] allow`) refuses, as last logged,
    /// so a refusal is warned about once per change, not per reconcile.
    route_policy: Mutex<RoutePolicy>,
    refused_seen: Mutex<BTreeSet<(ipnet::IpNet, Option<NodeId>)>>,
    /// Route-all families last reported as failed closed / withheld.
    route_all_reported: Mutex<(Vec<bool>, Vec<bool>)>,
    /// Signalled when the TUN's reader ends: the device is gone and the
    /// process must exit so its supervisor restarts it.
    tun_gone: tokio::sync::Notify,
    pub counters: ClientCounters,
    /// `--route-all`: send all traffic through the tunnel (the two-/1
    /// default override), pinning the underlay transport to the real
    /// gateway so it is not swallowed.
    route_all: bool,
    /// `--via <name>`: with route-all, the exit gateway to seal
    /// internet-bound traffic to, by member name. `None` picks whichever
    /// online node advertises a default (lowest id, deterministically).
    via: Option<String>,
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
        route_all: bool,
        via: Option<String>,
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
            mine: Mutex::new(hosts),
            device,
            mode: Mode::parse(&joined.transport),
            lanes: joined.lanes.max(1),
            keepalive_secs: joined.keepalive_secs.max(1) as u64,
            preferred_relay: Mutex::new(preferred_relay.or_else(|| joined.preferred_relay.clone())),
            prefer_recheck: Mutex::new(Duration::from_secs(30)),
            relay_via: Mutex::new(None),
            underlay: Mutex::new(Vec::new()),
            relay_addrs: Arc::new(Mutex::new(HashMap::new())),
            route_policy: Mutex::new(RoutePolicy::default()),
            refused_seen: Mutex::new(BTreeSet::new()),
            route_all_reported: Mutex::new((Vec::new(), Vec::new())),
            tun_gone: tokio::sync::Notify::new(),
            exit_chosen: Mutex::new(std::collections::BTreeMap::new()),
            counters: ClientCounters::default(),
            route_all,
            via,
        })
    }

    pub fn credential(&self) -> String {
        self.credential.lock().unwrap().clone()
    }

    /// Resolves when the TUN device has failed for good (its reader ended).
    pub async fn tun_failed(&self) {
        self.tun_gone.notified().await
    }

    /// Apply a route policy (the config's `[routes] allow`) to the OS
    /// routes and the in-VPN table. Takes effect at the next reconcile,
    /// which this triggers.
    pub fn set_route_policy(&self, policy: RoutePolicy) {
        *self.route_policy.lock().unwrap() = policy.clone();
        self.engine.peers.lock().unwrap().set_policy(policy);
        self.view.poke();
    }

    /// Reach a relay through a forwarder (`--relay-via`). Takes effect at
    /// the next attach; an uplink already held elsewhere moves once the
    /// forwarder answers.
    pub fn set_relay_via(&self, via: Option<RelayVia>) {
        *self.relay_via.lock().unwrap() = via;
    }

    /// The `relay_via` relay as a dialable entry — the fleet entry with the
    /// forwarder's address — when it is in the view.
    fn via_entry(&self) -> Option<RelayEntry> {
        let via = self.relay_via.lock().unwrap().clone()?;
        self.view.with(|s| {
            s.relays.iter().find(|r| r.name == via.relay).map(|r| RelayEntry {
                relay_id: r.relay_id,
                name: r.name.clone(),
                addr: via.addr.clone(),
                cert_fp: r.cert_fp.clone(),
            })
        })
    }

    /// Start the pumps: TUN -> engine -> uplink, and the rekey sweep.
    pub fn spawn_pumps(self: &Arc<Self>) {
        let mut reader = self.tun.reader();
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(pkt) = reader.recv().await {
                me.engine.outbound(pkt, me.uplink.as_ref(), me.tun.as_ref());
            }
            // The device's reader only ends when the device is unusable.
            // Running on would leave a process that looks alive but sends
            // nothing; `tun_failed` lets the owner exit instead.
            tracing::error!(device = %me.device, "the TUN device stopped delivering packets");
            me.tun_gone.notify_one();
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
            if self.link.stop_reason().is_some() {
                // Replaced by another instance: the process exits.
                return;
            }
            if self.link.is_refused() {
                // Disabled (or similar) at the coordinator: nothing to
                // attach to until it accepts us again.
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let candidates: Vec<RelayEntry> = self.view.with(|s| {
                s.relays.iter().map(|r| RelayEntry { relay_id: r.relay_id, name: r.name.clone(), addr: r.addr.clone(), cert_fp: r.cert_fp.clone() }).collect()
            });
            if candidates.is_empty() {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            let preferred = self.preferred_relay.lock().unwrap().clone();
            let via = self.relay_via.lock().unwrap().clone();
            // The forwarder first, when configured and it answers; then the
            // fleet as usual.
            let mut picked = None;
            if let Some(v) = &via {
                match self.via_entry() {
                    Some(e) if probe_rtt(&e, &self.identity, self.keepalive_secs).await.is_some() => picked = Some(e),
                    Some(_) => tracing::warn!(relay = %v.relay, forwarder = %v.addr, "relay forwarder unreachable; falling back to the fleet"),
                    None => tracing::warn!(relay = %v.relay, "relay_via names a relay that is not in the fleet; ignoring it"),
                }
            }
            let picked = match picked {
                Some(e) => Some(e),
                None => choose_relay(&candidates, preferred.as_deref(), &self.identity, self.keepalive_secs).await,
            };
            let Some(entry) = picked else {
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
                    // Reconcile compares the relay's published address, not
                    // the forwarder's, or every pass would call it stale.
                    let published = candidates.iter().find(|r| r.relay_id == entry.relay_id).map(|r| r.addr.clone()).unwrap_or_else(|| entry.addr.clone());
                    let through_via = published != entry.addr;
                    if through_via {
                        tracing::info!(relay = %entry.name, forwarder = %entry.addr, "attached through the forwarder");
                    } else {
                        tracing::info!(relay = %entry.name, addr = %entry.addr, "attached");
                    }
                    self.uplink.set(
                        Some(session.clone()),
                        Some(Attached { relay_id: entry.relay_id, name: entry.name.clone(), addr: published, cert_fp: entry.cert_fp.clone(), dialed: entry.addr.clone() }),
                    );
                    self.link.kick();
                    let attached_at = std::time::Instant::now();
                    // Not where we would rather be (the forwarder, else the
                    // preferred relay): keep checking, and move as soon as
                    // it is reachable again.
                    let away = match &via {
                        Some(_) => !through_via,
                        None => preferred.as_deref().is_some_and(|p| p != entry.name),
                    };
                    let _return_watch = away.then(|| AbortGuard(tokio::spawn(self.clone().watch_for_return(session.clone()))));
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
                    if let Some((CLOSE_STALE_LOGIN, reason)) = session.close_reason() {
                        self.link.replaced(format!("relay {} says: {reason}", entry.name));
                        return;
                    }
                    failures = if attached_at.elapsed() >= Duration::from_secs(30) { 0 } else { failures.saturating_add(1) };
                    // A session the relay ended on purpose (evicted,
                    // replaced) is not a reason to hammer it.
                    if end == End::Closed && attached_at.elapsed() < Duration::from_secs(5) {
                        tokio::time::sleep(nqvpn_proto::joinapi::retry_delay(false, failures)).await;
                    }
                }
                Err(err) => {
                    if let Some(Refused { code: CLOSE_STALE_LOGIN, reason }) = err.downcast_ref::<Refused>() {
                        self.link.replaced(format!("relay {} says: {reason}", entry.name));
                        return;
                    }
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
        let relay = self.uplink.attached_to.lock().unwrap().clone().map(|a| if a.dialed != a.addr { format!("{} via {}", a.name, a.dialed) } else { a.name });
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
        let attached_to = self.uplink.attached_to.lock().unwrap().as_ref().map(|a| a.relay_id);
        let usable_mtu = self.uplink.channel().and_then(|c| c.usable_inner_mtu()).map(|m| m as u16).unwrap_or(0);
        Heartbeat { attached_to, usable_mtu, ..Default::default() }
    }
}

impl MemberHooks for Client {
    fn refused(&self, refused: bool) {
        if refused {
            tracing::warn!("refused by the coordinator; dropping the uplink until accepted again");
            // Take the session before clearing the slot: once cleared there
            // is nothing left to close, and the relay keeps it open.
            let held = self.uplink.session();
            self.uplink.set(None, None);
            if let Some(s) = held {
                s.close(CLOSE_EVICTED, "refused by the coordinator");
            }
        }
    }

    /// Every join is the coordinator's current word on who we are:
    /// credential, address, preferred relay. Applied by diff, so a
    /// join that changed nothing changes nothing.
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
        self.apply_facts(r);
    }
}

impl Client {
    /// The addresses this client currently holds (as of its last join).
    pub fn addresses(&self) -> Vec<ipnet::IpNet> {
        self.mine.lock().unwrap().clone()
    }

    pub fn apply_facts(&self, r: &JoinResponse) {
        let mut hosts = Vec::new();
        if let Some(ip) = r.ip4 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
        }
        if let Some(ip) = r.ip6 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
        }
        let changed_addr = *self.mine.lock().unwrap() != hosts;
        if changed_addr {
            tracing::info!(addresses = ?hosts, "addresses changed at the coordinator; applying");
            if let Err(e) = self.tun.set_addresses(&hosts) {
                tracing::warn!("applying new addresses to the TUN: {e:#}");
            }
            self.engine.peers.lock().unwrap().set_mine(hosts.clone(), vec![]);
            *self.mine.lock().unwrap() = hosts;
        }
        let mut pref = self.preferred_relay.lock().unwrap();
        if *pref != r.preferred_relay {
            tracing::info!(preferred = ?r.preferred_relay, "preferred relay changed at the coordinator");
            *pref = r.preferred_relay.clone();
            drop(pref);
            // Attached somewhere the new preference does not point:
            // the uplink loop re-evaluates when this session ends. A local
            // relay_via outranks the preference, so it stays put.
            let attached = self.uplink.attached_to.lock().unwrap().clone();
            let want = self.preferred_relay.lock().unwrap().clone().filter(|_| self.relay_via.lock().unwrap().is_none());
            if let (Some(a), Some(w)) = (attached, want) {
                if a.name != w {
                    if let Some(s) = self.uplink.session() {
                        s.close(CLOSE_EVICTED, "preferred relay changed");
                    }
                }
            }
        } else {
            drop(pref);
        }
        if changed_addr {
            let view = self.view.get();
            self.reconcile_view(&view);
            self.link.kick();
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
        self.0.reconcile_view(view)
    }
}

impl Client {
    /// Peers, routes and the uplink, reconciled against the view.
    pub fn reconcile_view(&self, view: &Snapshot) {
        let c = self;
        // Peers and sessions: a session whose peer left the view, or whose
        // authenticated key is no longer the published one, is dropped,
        // with its queue (see `Engine::sync_peers`).
        c.engine.sync_peers(view.members.clone());
        c.apply_mtu(view.mtu.mtu);
        let mine = c.mine.lock().unwrap().clone();
        let policy = c.route_policy.lock().unwrap().clone();
        c.report_refused(view, &policy);
        let wanted = wanted_routes_with(view, c.node_id, &mine, &policy);
        let local = nqvpn_endpoint::ifaces::local_prefixes(&c.device);
        let mut underlay = c.underlay.lock().unwrap().clone();
        // Relay addresses from the view, from the resolver cache: a relay
        // that joins later is looked up in the background and pinned on
        // the reconcile its result triggers.
        let (relay_ips, resolving) = c.relay_ips(view);
        underlay.extend(relay_ips);
        let (mut keep, excluded) = exclude_local(wanted, &local, &underlay);
        for (net, why) in excluded {
            tracing::warn!(prefix = %net, %why, "not routing member prefix into the tunnel");
        }
        // --route-all: pin the underlay transport to the real gateway, then
        // for each family that has both a safe transport and a reachable
        // exit gateway, install the catch-all halves (so all other traffic
        // enters the tunnel) and point that family's in-VPN default at the
        // exit (so it is sealed there rather than dropped as no-route).
        if c.route_all {
            // The transports we must keep reachable over the real gateway,
            // plus the resolvers: route-all leaves DNS alone, so an off-LAN
            // resolver must not fall into the tunnel or nothing resolves.
            let mut keep_off_tunnel = underlay.clone();
            keep_off_tunnel.extend(nqvpn_endpoint::routes::system_resolvers());
            let to_pin = nqvpn_endpoint::routes::underlay_to_pin(&keep_off_tunnel, &local);
            let pinned = c.routes.pin_underlay(&to_pin).unwrap_or_else(|e| {
                tracing::warn!("route-all: pinning underlay failed: {e:#}");
                Vec::new()
            });
            // With no usable preference, the relay we already hold a session
            // to is the best exit there is: no mesh hop, and it moves only
            // when our attachment does.
            let attached_relay = c.uplink.attached_to.lock().unwrap().as_ref().map(|a| a.relay_id);
            let plan = nqvpn_endpoint::routes::route_all_plan(view, c.via.as_deref(), attached_relay, &underlay, &to_pin, &pinned);
            // Not armed yet and a relay's first lookup is still running:
            // wait for it (it pokes the view when done), or the catch-all
            // would go up before that relay's pin and swallow its dial.
            let plan = if resolving && c.exit_chosen.lock().unwrap().is_empty() {
                tracing::info!("route-all: waiting for relay addresses to resolve before arming the catch-all");
                nqvpn_endpoint::routes::RouteAllPlan::default()
            } else {
                plan
            };
            c.report_route_all(view, attached_relay, &plan, &to_pin, &pinned);
            if plan.nets.is_empty() {
                tracing::warn!(
                    via = ?c.via,
                    "route-all: no family has both a pinned transport and a reachable exit gateway (an online node owning 0.0.0.0/0 or ::/0); leaving the default route in place"
                );
            }
            // Assert the chosen exit(s) in the outbound table, overriding the
            // published default's owner. `replace_all` above wiped any prior
            // assertion, so this runs every reconcile.
            if !plan.exits.is_empty() {
                let mut peers = c.engine.peers.lock().unwrap();
                for (v6, node) in &plan.exits {
                    let d: ipnet::IpNet = if *v6 { "::/0".parse().unwrap() } else { "0.0.0.0/0".parse().unwrap() };
                    peers.set_default_exit(d, *node);
                }
            }
            // Say which exit we are on, but only when it changes: --via is a
            // preference, so falling back and returning are both normal and
            // both worth seeing in the log.
            {
                let mut chosen = c.exit_chosen.lock().unwrap();
                let families: Vec<bool> = plan.exits.iter().map(|(v6, _)| *v6).collect();
                chosen.retain(|v6, _| families.contains(v6));
                for (v6, node) in &plan.exits {
                    if chosen.insert(*v6, *node) == Some(*node) {
                        continue;
                    }
                    let family = if *v6 { "v6" } else { "v4" };
                    let name = view.members.iter().find(|m| m.node_id == *node).map(|m| m.name.as_str()).unwrap_or("?");
                    match c.via.as_deref() {
                        Some(pref) if pref != name => {
                            tracing::warn!(family, preferred = pref, using = name, node = node, "preferred internet exit is not available; using another")
                        }
                        Some(pref) => tracing::info!(family, exit = pref, node = node, "on the preferred internet exit"),
                        None => tracing::info!(family, exit = name, node = node, "internet exit selected"),
                    }
                }
            }
            keep.extend(plan.nets);
        }
        if let Err(e) = c.routes.reconcile(&keep, &mine) {
            tracing::warn!("route reconcile: {e:#}");
        }
        // The relay I am attached to re-registered from somewhere else
        // (a new address or session certificate under the same name):
        // what I hold is a zombie even if it still answers, and the
        // coordinator no longer lists me behind it. Drop it; the
        // uplink loop re-attaches to the fleet as published. A relay
        // that merely left the fleet closes its sessions itself.
        // Likewise a relay the coordinator no longer lists at all
        // (disabled, deleted): it may still answer, but nothing routes
        // through it any more. The fleet list does not depend on a
        // relay's liveness, so "gone" is never a transient.
        let attached = c.uplink.attached_to.lock().unwrap().clone();
        if let Some(a) = attached {
            let stale = match view.relays.iter().find(|r| r.relay_id == a.relay_id) {
                Some(r) if r.addr != a.addr || r.cert_fp != a.cert_fp => Some("relay re-registered elsewhere"),
                None if !view.members.is_empty() => Some("relay left the fleet"),
                _ => None,
            };
            if let Some(why) = stale {
                tracing::warn!(relay = %a.name, %why, "re-attaching");
                if let Some(s) = c.uplink.session() {
                    s.close(CLOSE_EVICTED, why);
                }
            }
        }
    }
}

/// How long a resolver gets before a lookup counts as failed.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// A relay address that resolved is looked up again after this long.
const RELAY_ADDR_TTL: Duration = Duration::from_secs(3600);
/// Retry delay after a failed lookup: doubles per failure up to the cap.
const RELAY_ADDR_RETRY_MIN: Duration = Duration::from_secs(5);
const RELAY_ADDR_RETRY_MAX: Duration = Duration::from_secs(300);

/// One relay transport address in the resolver cache.
#[derive(Debug, Clone)]
pub struct RelayAddr {
    /// The last successful result; kept through failed refreshes.
    pub ips: Vec<IpAddr>,
    /// When to look it up (again).
    due: Instant,
    /// Consecutive failures, for the backoff.
    failures: u32,
    in_flight: bool,
}

impl Client {
    /// The IPs of every relay in the view, from the cache. Addresses not
    /// yet resolved, or due a refresh, are looked up in the background —
    /// never here: this runs on the reconcile path of a single-threaded
    /// runtime, where a blocking lookup would stall probes, heartbeats
    /// and the data pumps for the resolver's whole timeout. A finished
    /// lookup pokes the view, so its result is pinned on the next pass.
    ///
    /// Also says whether some relay's *first* lookup has not finished yet.
    fn relay_ips(&self, view: &Snapshot) -> (Vec<IpAddr>, bool) {
        let now = Instant::now();
        let (mut out, mut resolving) = (Vec::new(), false);
        // Every relay, plus the relay_via forwarder: under route-all it is
        // a transport host like any other and must stay off the tunnel.
        let mut targets: Vec<(String, String)> = view.relays.iter().map(|r| (r.addr.clone(), r.name.clone())).collect();
        if let Some(v) = self.relay_via.lock().unwrap().clone() {
            targets.push((v.addr, format!("{} (forwarder)", v.relay)));
        }
        let mut cache = self.relay_addrs.lock().unwrap();
        cache.retain(|addr, _| targets.iter().any(|(a, _)| a == addr));
        for (addr, name) in &targets {
            let e = cache.entry(addr.clone()).or_insert_with(|| RelayAddr { ips: Vec::new(), due: now, failures: 0, in_flight: false });
            out.extend(e.ips.iter().copied());
            resolving |= e.ips.is_empty() && e.failures == 0;
            if e.in_flight || e.due > now {
                continue;
            }
            let Ok(rt) = tokio::runtime::Handle::try_current() else { continue };
            e.in_flight = true;
            let (addr, name) = (addr.clone(), name.clone());
            let (cache, view) = (self.relay_addrs.clone(), self.view.clone());
            rt.spawn(async move {
                let got = match tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(addr.as_str())).await {
                    Ok(Ok(it)) => Ok(it.map(|s| s.ip()).collect::<Vec<_>>()),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(_) => Err("timed out".to_string()),
                };
                let changed = {
                    let mut cache = cache.lock().unwrap();
                    let Some(e) = cache.get_mut(&addr) else { return };
                    e.in_flight = false;
                    match got {
                        Ok(mut ips) if !ips.is_empty() => {
                            ips.sort();
                            ips.dedup();
                            e.failures = 0;
                            e.due = Instant::now() + RELAY_ADDR_TTL;
                            let changed = e.ips != ips;
                            e.ips = ips;
                            changed
                        }
                        other => {
                            e.failures = e.failures.saturating_add(1);
                            let backoff = RELAY_ADDR_RETRY_MIN.saturating_mul(1u32 << e.failures.min(16).saturating_sub(1)).min(RELAY_ADDR_RETRY_MAX);
                            e.due = Instant::now() + backoff;
                            let why = other.err().unwrap_or_else(|| "no addresses".into());
                            if e.ips.is_empty() {
                                // Unpinned, this relay's transport falls into
                                // the catch-all and is unreachable under
                                // route-all, so say so rather than failing mutely.
                                tracing::warn!(relay = %name, %addr, retry_in_secs = backoff.as_secs(), "cannot resolve this relay's address; it will not be pinned and may be unreachable under route-all: {why}");
                            } else {
                                tracing::debug!(relay = %name, %addr, "refreshing this relay's address failed; keeping the last result: {why}");
                            }
                            false
                        }
                    }
                };
                if changed {
                    view.poke();
                }
            });
        }
        (out, resolving)
    }

    /// Follow the network MTU the coordinator publishes: the engine's
    /// oversize check and the device both move with it.
    fn apply_mtu(&self, mtu: u16) {
        // 0 is "not published yet"; anything below IPv6's minimum is not
        // a value a coordinator hands out (it clamps to 1280).
        if mtu < 1280 || mtu == self.engine.mtu() {
            return;
        }
        tracing::info!(from = self.engine.mtu(), to = mtu, device = %self.device, "network MTU changed at the coordinator; applying");
        self.engine.set_mtu(mtu);
        if let Err(e) = self.tun.set_mtu(mtu) {
            tracing::warn!("setting the TUN's MTU to {mtu}: {e:#}");
        }
    }

    /// Warn — once per change, not every reconcile — about published
    /// prefixes the route policy refuses. They are neither routed nor
    /// accepted, which an operator will want to know about loudly.
    fn report_refused(&self, view: &Snapshot, policy: &RoutePolicy) {
        let refused = refused_prefixes(view, self.node_id, policy);
        let now: BTreeSet<(ipnet::IpNet, Option<NodeId>)> = refused.iter().map(|(n, o, _)| (*n, *o)).collect();
        let mut seen = self.refused_seen.lock().unwrap();
        for (net, owner, why) in &refused {
            if seen.contains(&(*net, *owner)) {
                continue;
            }
            match owner {
                Some(id) => {
                    let name = view.members.iter().find(|m| m.node_id == *id).map(|m| m.name.as_str()).unwrap_or("?");
                    tracing::warn!(prefix = %net, member = name, node = id, %why, "refusing a prefix the coordinator published for a member; it is not routed and not accepted")
                }
                None => tracing::warn!(prefix = %net, %why, "refusing a reserved prefix the coordinator published; it is not routed"),
            }
        }
        for (net, owner) in seen.difference(&now) {
            tracing::info!(prefix = %net, node = ?owner, "a previously refused prefix is no longer published");
        }
        *seen = now;
    }

    /// Route-all's exceptions, logged once per change: a family armed
    /// although some of its hosts could not be pinned (failed closed), and
    /// a family left outside the tunnel although an exit exists — the one
    /// case where route-all does not hold, said as loudly as it is.
    fn report_route_all(
        &self,
        view: &Snapshot,
        attached: Option<NodeId>,
        plan: &nqvpn_endpoint::routes::RouteAllPlan,
        to_pin: &[IpAddr],
        pinned: &[IpAddr],
    ) {
        let withheld: Vec<bool> = [false, true]
            .into_iter()
            .filter(|v6| {
                nqvpn_endpoint::routes::exit_gateway(view, self.via.as_deref(), attached, *v6).is_some()
                    && !plan.exits.iter().any(|(f, _)| f == v6)
            })
            .collect();
        let mut last = self.route_all_reported.lock().unwrap();
        if (plan.failed_closed.clone(), withheld.clone()) == *last {
            return;
        }
        let unpinned = |v6: bool| to_pin.iter().filter(|ip| ip.is_ipv6() == v6 && !pinned.contains(ip)).map(|ip| ip.to_string()).collect::<Vec<_>>().join(", ");
        for v6 in &plan.failed_closed {
            let family = if *v6 { "IPv6" } else { "IPv4" };
            tracing::warn!(family, unpinned = %unpinned(*v6), "route-all: some underlay hosts could not be pinned; this family's traffic goes through the tunnel anyway (fail closed), so traffic to those hosts enters it too");
        }
        for v6 in &withheld {
            let family = if *v6 { "IPv6" } else { "IPv4" };
            tracing::error!(family, unpinned = %unpinned(*v6), "route-all: the coordinator/relay transport of this family could not be pinned and the other family cannot carry the tunnel; this family's traffic is NOT going through the tunnel");
        }
        *last = (plan.failed_closed.clone(), withheld);
    }
}

struct AbortGuard(tokio::task::JoinHandle<()>);

impl Drop for AbortGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Client {
    /// Attached to a fallback while the relay_via forwarder (or else a
    /// preferred relay) is named: go back once it answers. Both are
    /// non-binding.
    async fn watch_for_return(self: Arc<Self>, session: Arc<Session>) {
        loop {
            let every = *self.prefer_recheck.lock().unwrap();
            tokio::time::sleep(every).await;
            let (entry, what) = if self.relay_via.lock().unwrap().is_some() {
                (self.via_entry(), "relay forwarder")
            } else {
                let Some(name) = self.preferred_relay.lock().unwrap().clone() else { return };
                let entry = self.view.with(|s| {
                    s.relays
                        .iter()
                        .find(|r| r.name == name)
                        .map(|r| RelayEntry { relay_id: r.relay_id, name: r.name.clone(), addr: r.addr.clone(), cert_fp: r.cert_fp.clone() })
                });
                (entry, "preferred relay")
            };
            if let Some(e) = entry {
                if probe_rtt(&e, &self.identity, self.keepalive_secs).await.is_some() {
                    tracing::info!(relay = %e.name, addr = %e.addr, "{what} is reachable again; moving to it");
                    session.close(CLOSE_EVICTED, "moving to the preferred relay");
                    return;
                }
            }
        }
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

/// One-shot reachability + latency check against a relay. The lookup is
/// async (a blocking one would stall the whole single-threaded runtime
/// for the resolver's timeout), and every address is tried in turn, so a
/// relay whose first address family is blackholed (route-all failing
/// closed) is still reached on the other.
async fn probe_rtt(entry: &RelayEntry, identity: &TlsIdentity, keepalive: u64) -> Option<u128> {
    let addrs: Vec<std::net::SocketAddr> =
        tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(entry.addr.as_str())).await.ok()?.ok()?.collect();
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']')).unwrap_or("relay");
    let config = nqvpn_proto::quic::client_config(identity, Some(entry.cert_fp.clone()), keepalive).ok()?;
    for addr in addrs {
        let bind: std::net::SocketAddr = if addr.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
        let Ok(mut ep) = quinn::Endpoint::client(bind) else { continue };
        ep.set_default_client_config(config.clone());
        let started = std::time::Instant::now();
        let Ok(connecting) = ep.connect(addr, host) else { continue };
        if let Ok(Ok(conn)) = tokio::time::timeout(Duration::from_secs(5), connecting).await {
            let rtt = started.elapsed().as_millis();
            conn.close(0u32.into(), b"probe");
            return Some(rtt);
        }
    }
    None
}
