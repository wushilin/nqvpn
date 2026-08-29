//! The relay's optional **endpoint role** (DESIGN.md §1, §3.1).
//!
//! A relay is a forwarder by default. When it takes a VPN address, or
//! registers LAN prefixes as its site's gateway, it also becomes an
//! ordinary member of the data plane: it terminates frames addressed to
//! its own node id, unsealing them end-to-end exactly as a client does.
//!
//! The relay is its own uplink. A client hands packets to the relay it
//! is attached to; a gateway relay instead consults its own forwarding
//! table, so the same `Engine` drives both without knowing the
//! difference.

use nqvpn_client::engine::{Engine, Uplink};
use nqvpn_client::peers::PeerTable;
use nqvpn_client::tun::TunDevice;
use nqvpn_proto::frame::RoutedHeader;
use std::sync::Arc;

use crate::state::RelayState;
use crate::tables::Origin;

/// Everything the endpoint role needs, kept together so the forwarding
/// loop can hand `Route::Me` frames somewhere in one step.
pub struct LocalEndpoint {
    pub engine: Arc<Engine>,
    pub tun: Arc<dyn TunDevice>,
    pub uplink: Arc<SelfUplink>,
    /// Programs OS routes for member prefixes via our TUN. Without it
    /// the kernel has no way to send replies back into the tunnel, so
    /// traffic arrives here and the answer leaks out the default route.
    routes: Box<dyn Fn(Vec<ipnet::IpNet>) + Send + Sync>,
    /// Re-assert the routes we own, repairing any that were removed or
    /// stolen by another writer on this host.
    reassert: Box<dyn Fn() + Send + Sync>,
    /// Rebuild the table from a fresh snapshot after a control-session
    /// gap, when membership may have changed arbitrarily.
    reconcile: Box<dyn Fn(Vec<ipnet::IpNet>) + Send + Sync>,
}

/// Sends our own sealed frames through our own forwarding table —
/// locally if the destination is attached here, otherwise across one
/// mesh link. Same one-hop rule as anyone else's traffic.
pub struct SelfUplink {
    state: Arc<RelayState>,
}

impl SelfUplink {
    pub fn new(state: Arc<RelayState>) -> Arc<SelfUplink> {
        Arc::new(SelfUplink { state })
    }
}

impl Uplink for SelfUplink {
    fn send(&self, datagram: Vec<u8>, lane: u8) -> bool {
        let Some(h) = RoutedHeader::parse(&datagram) else {
            return false;
        };
        // Origin is ourselves: the anti-spoofing rule holds trivially
        // because we only ever emit our own node id as the source.
        let route = self
            .state
            .route(Origin::Client(self.state.my_node_id), h.src_id, h.dst_id);
        self.state.send(&route, datagram.into(), lane)
    }
}

impl LocalEndpoint {
    /// Build the endpoint role. `mine` is everything this node answers
    /// for: its VPN addresses plus any granted LAN prefixes.
    pub fn new(
        state: Arc<RelayState>,
        tun: Arc<dyn TunDevice>,
        keys: nqvpn_proto::seal::StaticKeys,
        mine: Vec<ipnet::IpNet>,
        mtu: u16,
        lanes: u8,
    ) -> Arc<LocalEndpoint> {
        let mut table = PeerTable::new(state.my_node_id);
        table.set_mine(mine);
        let engine = Engine::new(
            state.my_node_id,
            state.network_uuid.clone(),
            keys,
            table,
            mtu,
            lanes,
        );
        let device = tun.name();
        let set = std::sync::Arc::new(nqvpn_client::routes::RouteSet::new(
            nqvpn_client::routes::SystemProgrammer { device },
        ));
        let reasserter = set.clone();
        let reconciler = set.clone();
        let routes = Box::new(move |wanted: Vec<ipnet::IpNet>| {
            if let Err(e) = set.apply(&wanted) {
                tracing::warn!("route apply failed: {e:#}");
            }
        });
        let reassert = Box::new(move || {
            if let Err(e) = reasserter.reassert() {
                tracing::warn!("route re-assert failed: {e:#}");
            }
        });
        let reconcile = Box::new(move |wanted: Vec<ipnet::IpNet>| {
            if let Err(e) = reconciler.reconcile(&wanted) {
                tracing::warn!("route reconcile failed: {e:#}");
            }
        });
        Arc::new(LocalEndpoint {
            engine,
            tun,
            uplink: SelfUplink::new(state),
            routes,
            reassert,
            reconcile,
        })
    }

    /// Rebuild OS routes from scratch against the current peer table.
    ///
    /// Called after a control-session gap: the cheap diff in
    /// `apply_routes` assumes our cache still matches the kernel, and a
    /// reconnect is exactly when that assumption is least safe.
    pub fn reconcile_routes(&self) {
        let wanted = self.engine.peers.lock().unwrap().all_prefixes();
        (self.reconcile)(wanted);
    }

    /// Re-program OS routes from the current peer table.
    pub fn apply_routes(&self) {
        let wanted = self.engine.peers.lock().unwrap().all_prefixes();
        (self.routes)(wanted);
    }

    /// A frame addressed to us: unseal, filter, write to the TUN.
    pub fn deliver(&self, datagram: &[u8]) {
        self.engine.inbound(datagram, self.uplink.as_ref(), self.tun.as_ref());
    }

    /// Start the TUN reader pump and the rekey sweep.
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
        // Repair routes another writer removed. Without this a relay
        // sharing a host with a client loses member routes the moment
        // the client's TUN goes away, and never gets them back.
        let me = self.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(std::time::Duration::from_secs(20));
            loop {
                t.tick().await;
                (me.reassert)();
            }
        });
    }
}
