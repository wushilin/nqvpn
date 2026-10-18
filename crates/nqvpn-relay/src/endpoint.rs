//! The relay's optional **endpoint role** (DESIGN.md §1, §3.1): a relay
//! that took an address, or fronts a LAN, terminates frames addressed
//! to its own node id exactly as a client does — same engine, same
//! ingress filter, same route reconciliation — with its own forwarding
//! table as the uplink.

use nqvpn_endpoint::engine::{Engine, Uplink};
use nqvpn_endpoint::peers::PeerTable;
use nqvpn_endpoint::routes::{exclude_local, wanted_routes, RouteProgrammer, RouteSet};
use nqvpn_endpoint::tun::TunDevice;
use nqvpn_proto::control::Snapshot;
use nqvpn_proto::frame::RoutedHeader;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::net::RelayNet;
use crate::tables::Origin;

/// How long a resolved relay hostname is trusted.
const UNDERLAY_TTL: Duration = Duration::from_secs(300);
/// How soon a failed lookup is tried again (the old answer, if any, is
/// kept meanwhile).
const UNDERLAY_RETRY: Duration = Duration::from_secs(30);
const UNDERLAY_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// One relay hostname's resolution.
#[derive(Default)]
struct Resolved {
    ips: Vec<IpAddr>,
    /// Look it up again after this.
    until: Option<Instant>,
    /// A lookup is in flight.
    pending: bool,
}

type UnderlayCache = Arc<Mutex<HashMap<String, Resolved>>>;

pub struct LocalEndpoint {
    pub engine: Arc<Engine>,
    pub tun: Arc<dyn TunDevice>,
    pub uplink: Arc<SelfUplink>,
    routes: Arc<dyn RouteSink>,
    mine: Mutex<Vec<ipnet::IpNet>>,
    /// Resolved relay addresses, so their routes are never captured.
    /// Hostnames are looked up off the reconcile path, with a TTL.
    underlay: UnderlayCache,
    device: String,
}

/// Route programming behind one method, so tests can record.
pub trait RouteSink: Send + Sync {
    fn reconcile(&self, wanted: &[ipnet::IpNet], mine: &[ipnet::IpNet]) -> anyhow::Result<()>;
    fn reassert(&self) -> anyhow::Result<()>;
}

impl<P: RouteProgrammer + 'static> RouteSink for RouteSet<P> {
    fn reconcile(&self, wanted: &[ipnet::IpNet], mine: &[ipnet::IpNet]) -> anyhow::Result<()> {
        if RouteSet::reconcile_via_kernel(self, wanted, mine)? {
            Ok(())
        } else {
            RouteSet::reconcile(self, wanted, mine)
        }
    }
    fn reassert(&self) -> anyhow::Result<()> {
        if RouteSet::reassert_via_kernel(self)? {
            Ok(())
        } else {
            RouteSet::reassert(self)
        }
    }
}

/// Sends our own sealed frames through our own forwarding table. Trace
/// notes for them come straight back to the engine (`RelayNet::trace`).
pub struct SelfUplink {
    net: Mutex<Option<Arc<RelayNet>>>,
}

impl SelfUplink {
    fn new() -> Arc<SelfUplink> {
        Arc::new(SelfUplink { net: Mutex::new(None) })
    }
}

impl Uplink for SelfUplink {
    fn send(&self, datagram: Vec<u8>, lane: u8) -> bool {
        let Some(net) = self.net.lock().unwrap().clone() else { return false };
        if RoutedHeader::parse(&datagram).is_none() {
            return false;
        }
        // Origin is ourselves: the anti-spoofing rule holds trivially.
        net.forward(Origin::Client(net.my_node_id), None, datagram.into(), lane);
        true
    }
}

impl LocalEndpoint {
    /// `hosts` are our VPN addresses, `nets` the LAN prefixes we front.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        my_node_id: nqvpn_proto::types::NodeId,
        network_uuid: String,
        tun: Arc<dyn TunDevice>,
        keys: nqvpn_proto::seal::StaticKeys,
        hosts: Vec<ipnet::IpNet>,
        nets: Vec<ipnet::IpNet>,
        mtu: u16,
        lanes: u8,
        routes: Arc<dyn RouteSink>,
    ) -> Arc<LocalEndpoint> {
        let mut table = PeerTable::new(my_node_id);
        table.set_mine(hosts.clone(), nets.clone());
        let engine = Engine::new(my_node_id, network_uuid, keys, table, mtu, lanes);
        let device = tun.name();
        Arc::new(LocalEndpoint {
            engine,
            tun,
            uplink: SelfUplink::new(),
            routes,
            mine: Mutex::new(hosts.into_iter().chain(nets).collect()),
            underlay: Arc::new(Mutex::new(HashMap::new())),
            device,
        })
    }

    /// A re-join brought new facts: our addresses and the LANs we
    /// front. Applied to the device, the ingress filter, and the
    /// route exclusion set; the next reconcile does the rest.
    pub fn set_facts(&self, hosts: Vec<ipnet::IpNet>, nets: Vec<ipnet::IpNet>) {
        if let Err(e) = self.tun.set_addresses(&hosts) {
            tracing::warn!("applying new addresses to the TUN: {e:#}");
        }
        self.engine.peers.lock().unwrap().set_mine(hosts.clone(), nets.clone());
        *self.mine.lock().unwrap() = hosts.into_iter().chain(nets).collect();
    }

    /// Wire the uplink to its relay. Separate from `new` because the
    /// relay holds the endpoint and the endpoint sends through the relay.
    pub fn bind(&self, net: Arc<RelayNet>) {
        *self.uplink.net.lock().unwrap() = Some(net);
    }

    pub fn usable_mtu(&self) -> Option<u16> {
        None
    }

    /// Peers and routes from the view. Routes wait while a relay
    /// hostname is being resolved for the first time (bounded by the
    /// lookup timeout): installing them blind could capture the path to
    /// that relay. The lookup's completion triggers another reconcile.
    pub fn sync(&self, view: &Snapshot) {
        self.engine.peers.lock().unwrap().replace_all(view.members.clone());
        let Some(underlay) = self.underlay_addrs(view) else {
            tracing::debug!("relay addresses still resolving; routes follow");
            return;
        };
        let mine = self.mine.lock().unwrap().clone();
        let wanted = wanted_routes(view, self.engine.my_node_id, &mine);
        let local = nqvpn_endpoint::ifaces::local_prefixes(&self.device);
        let (keep, excluded) = exclude_local(wanted, &local, &underlay);
        for (net, why) in excluded {
            tracing::warn!(prefix = %net, %why, "not routing member prefix into the tunnel");
        }
        if let Err(e) = self.routes.reconcile(&keep, &mine) {
            tracing::warn!("route reconcile: {e:#}");
        }
    }

    /// Every relay's underlay address. Literal addresses are parsed in
    /// place; hostnames come from a cache filled by background lookups
    /// (never on this, the reconcile, path), refreshed after
    /// `UNDERLAY_TTL`, retried after `UNDERLAY_RETRY` on failure. `None`
    /// while some hostname has no answer yet and its first lookup is in
    /// flight.
    fn underlay_addrs(&self, view: &Snapshot) -> Option<Vec<IpAddr>> {
        let mut cache = self.underlay.lock().unwrap();
        cache.retain(|addr, _| view.relays.iter().any(|r| &r.addr == addr));
        let mut out = Vec::new();
        let mut complete = true;
        let now = Instant::now();
        for r in &view.relays {
            if let Ok(sock) = r.addr.parse::<SocketAddr>() {
                out.push(sock.ip());
                continue;
            }
            let entry = cache.entry(r.addr.clone()).or_default();
            if !entry.pending && entry.until.is_none_or(|t| now >= t) {
                if self.spawn_lookup(r.addr.clone()) {
                    entry.pending = true;
                } else {
                    // No runtime (never in the relay): next reconcile.
                    entry.until = Some(now + UNDERLAY_RETRY);
                }
            }
            if entry.pending && entry.until.is_none() {
                complete = false;
            }
            out.extend(entry.ips.iter().copied());
        }
        complete.then_some(out)
    }

    /// Resolve one relay hostname off the reconcile path, record the
    /// answer, and wake the reconciler so routes are recomputed. Called
    /// with the cache locked; false if there is no runtime to run on.
    fn spawn_lookup(&self, addr: String) -> bool {
        let (cache, uplink) = (self.underlay.clone(), self.uplink.clone());
        let Ok(rt) = tokio::runtime::Handle::try_current() else { return false };
        rt.spawn(async move {
            let answer = match tokio::time::timeout(UNDERLAY_LOOKUP_TIMEOUT, tokio::net::lookup_host(addr.as_str())).await {
                Ok(Ok(it)) => it.map(|s| s.ip()).collect::<Vec<_>>(),
                Ok(Err(e)) => {
                    tracing::warn!(%addr, "resolving relay address: {e}");
                    Vec::new()
                }
                Err(_) => {
                    tracing::warn!(%addr, "resolving relay address: timed out");
                    Vec::new()
                }
            };
            if let Some(e) = cache.lock().unwrap().get_mut(&addr) {
                e.pending = false;
                if answer.is_empty() {
                    // Keep the last good answer, if any, until a retry.
                    e.until = Some(Instant::now() + UNDERLAY_RETRY);
                } else {
                    e.ips = answer;
                    e.until = Some(Instant::now() + UNDERLAY_TTL);
                }
            }
            let net = uplink.net.lock().unwrap().clone();
            if let Some(net) = net {
                net.view.poke();
            }
        });
        true
    }

    /// A frame addressed to us: unseal, filter, write to the TUN.
    pub fn deliver(&self, datagram: &[u8]) {
        self.engine.inbound(datagram, self.uplink.as_ref(), self.tun.as_ref());
    }

    /// Start the TUN reader pump, the rekey sweep, and the route watchdog.
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
            let mut t = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                t.tick().await;
                me.engine.expire_sessions();
            }
        });
        let me = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                t.tick().await;
                if let Err(e) = me.routes.reassert() {
                    tracing::warn!("route re-assert failed: {e:#}");
                }
            }
        });
    }
}
