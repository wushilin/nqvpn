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
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::net::RelayNet;
use crate::tables::Origin;

pub struct LocalEndpoint {
    pub engine: Arc<Engine>,
    pub tun: Arc<dyn TunDevice>,
    pub uplink: Arc<SelfUplink>,
    routes: Arc<dyn RouteSink>,
    mine: Mutex<Vec<ipnet::IpNet>>,
    /// Resolved relay addresses, so their routes are never captured.
    underlay: Mutex<HashMap<String, Vec<IpAddr>>>,
    device: String,
}

/// Route programming behind one method, so tests can record.
pub trait RouteSink: Send + Sync {
    fn reconcile(&self, wanted: &[ipnet::IpNet]) -> anyhow::Result<()>;
    fn reassert(&self) -> anyhow::Result<()>;
}

impl<P: RouteProgrammer + 'static> RouteSink for RouteSet<P> {
    fn reconcile(&self, wanted: &[ipnet::IpNet]) -> anyhow::Result<()> {
        RouteSet::reconcile(self, wanted)
    }
    fn reassert(&self) -> anyhow::Result<()> {
        RouteSet::reassert(self)
    }
}

/// Sends our own sealed frames through our own forwarding table.
pub struct SelfUplink {
    net: Mutex<Option<Arc<RelayNet>>>,
    loopback: Arc<nqvpn_proto::transport::PacketChannel>,
}

impl SelfUplink {
    fn new(loopback: Arc<nqvpn_proto::transport::PacketChannel>) -> Arc<SelfUplink> {
        Arc::new(SelfUplink { net: Mutex::new(None), loopback })
    }
}

impl Uplink for SelfUplink {
    fn send(&self, datagram: Vec<u8>, lane: u8) -> bool {
        let Some(net) = self.net.lock().unwrap().clone() else { return false };
        if RoutedHeader::parse(&datagram).is_none() {
            return false;
        }
        // Origin is ourselves: the anti-spoofing rule holds trivially.
        net.forward(Origin::Client(net.my_node_id), &self.loopback, datagram.into(), lane);
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
        loopback: Arc<nqvpn_proto::transport::PacketChannel>,
    ) -> Arc<LocalEndpoint> {
        let mut table = PeerTable::new(my_node_id);
        table.set_mine(hosts.clone(), nets.clone());
        let engine = Engine::new(my_node_id, network_uuid, keys, table, mtu, lanes);
        let device = tun.name();
        Arc::new(LocalEndpoint {
            engine,
            tun,
            uplink: SelfUplink::new(loopback),
            routes,
            mine: Mutex::new(hosts.into_iter().chain(nets).collect()),
            underlay: Mutex::new(HashMap::new()),
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

    /// Peers and routes from the view. Trace notes for our own frames
    /// come back on the loopback channel and are drained here too.
    pub fn sync(&self, view: &Snapshot) {
        self.engine.peers.lock().unwrap().replace_all(view.members.clone());
        let mine = self.mine.lock().unwrap().clone();
        let wanted = wanted_routes(view, self.engine.my_node_id, &mine);
        let local = nqvpn_endpoint::ifaces::local_prefixes(&self.device);
        let underlay = self.underlay_addrs(view);
        let (keep, excluded) = exclude_local(wanted, &local, &underlay);
        for (net, why) in excluded {
            tracing::warn!(prefix = %net, %why, "not routing member prefix into the tunnel");
        }
        if let Err(e) = self.routes.reconcile(&keep) {
            tracing::warn!("route reconcile: {e:#}");
        }
    }

    fn underlay_addrs(&self, view: &Snapshot) -> Vec<IpAddr> {
        use std::net::ToSocketAddrs;
        let mut cache = self.underlay.lock().unwrap();
        let mut out = Vec::new();
        for r in &view.relays {
            let ips = cache.entry(r.addr.clone()).or_insert_with(|| {
                r.addr.to_socket_addrs().map(|it| it.map(|s| s.ip()).collect()).unwrap_or_default()
            });
            out.extend(ips.iter().copied());
        }
        out
    }

    /// A frame addressed to us: unseal, filter, write to the TUN.
    pub fn deliver(&self, datagram: &[u8]) {
        self.engine.inbound(datagram, self.uplink.as_ref(), self.tun.as_ref());
    }

    /// Start the TUN reader pump, the rekey sweep, the route watchdog,
    /// and the loopback drain (trace notes for our own traced frames).
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
        let me = self.clone();
        tokio::spawn(async move {
            while let Some((d, _)) = me.uplink.loopback.recv().await {
                me.engine.inbound(&d, me.uplink.as_ref(), me.tun.as_ref());
            }
        });
    }
}
