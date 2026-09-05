//! Whole-system chaos tests: a real coordinator (HTTPS join + QUIC
//! control), real relays, and many clients on fake TUNs, all in one
//! process. Nothing touches the kernel. Each test breaks something and
//! checks that traffic converges back without anyone being restarted by
//! hand — the property the design is built around.

use anyhow::Result;
use nqvpn_client::client::{Client, ClientReconciler};
use nqvpn_coord::admin::MemberSpec;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::db::Db;
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState, NetState};
use nqvpn_endpoint::routes::{RecordingProgrammer, RouteSet};
use nqvpn_endpoint::tun::{FakeTun, TunDevice};
use nqvpn_proto::api::JoinResponse;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::transport::Mode;
use nqvpn_proto::types::{NodeId, Role};
use nqvpn_relay::net::{Fleet, NetReconciler, RelayNet};
use nqvpn_sync::join::MemberConfig;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NET: &str = "n1";
const SECRET: &str = "chaos-secret";

/// Ports are allocated from a moving base so tests can run in parallel
/// and a restarted coordinator can rebind the same ones.
static NEXT_PORT: AtomicU16 = AtomicU16::new(24000);
fn port() -> u16 {
    NEXT_PORT.fetch_add(1, Ordering::Relaxed)
}

fn net_toml(relays: &[(NodeId, u16)], clients: &[NodeId]) -> String {
    let mut s = format!(
        "network_id = \"{NET}\"\ncidrs = [\"10.99.0.0/16\"]\n[pools.default]\ncidr = \"10.99.1.0/24\"\n\
         [settings]\nheartbeat_secs = 1\noffline_after = 3\nhold_down_secs = 0\nrestart_grace_secs = 2\nallow_loopback_relays = true\ntransport = \"datagram\"\n"
    );
    for (id, p) in relays {
        s.push_str(&format!("[relays.r{id}]\nsecret = \"{}\"\nrelay_addr = \"127.0.0.1:{p}\"\nwant_vpn_ip = false\n", secret_of(&format!("r{id}"))));
    }
    for id in clients {
        s.push_str(&format!("[clients.c{id}]\nsecret = \"{}\"\n", secret_of(&format!("c{id}"))));
    }
    s
}

/// The secret is the lookup key, so every member has its own.
fn secret_of(name: &str) -> String {
    format!("{SECRET}-{name}")
}

struct Coord {
    state: Arc<AppState>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Coord {
    async fn start(dir: &Path, api_port: u16, quic_port: u16, toml: &str) -> Coord {
        static PROVIDER: std::sync::Once = std::sync::Once::new();
        PROVIDER.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()))
                .with_test_writer()
                .try_init();
        });
        // The database is the coordinator's memory across restarts: the
        // network is seeded into it once, and a restart reloads it.
        let mut cfg: NetworkConfig = toml::from_str(toml).unwrap();
        nqvpn_coord::config::validate_network(&mut cfg).unwrap();
        let coord: CoordConfig = toml::from_str(&format!(
            "[listen]\napi = \"127.0.0.1:{api_port}\"\nquic = \"127.0.0.1:{quic_port}\"\n[state]\ndir = \"{}\"\n",
            dir.display()
        ))
        .unwrap();
        let keyring = Keyring::load_or_create(&dir.join("signing.json"), now_unix()).unwrap();
        let db = Arc::new(Db::open(&dir.join("nqvpn.db")).unwrap());
        let state = Arc::new(AppState::new(coord, Some("tok".into()), keyring, db.clone(), quic_port));
        let loaded = db.load_all().unwrap();
        if loaded.is_empty() {
            let reg = Registry::new();
            db.save_network_and_registry(&cfg, &reg).unwrap();
            state.add_network(cfg, reg);
        } else {
            for (cfg, reg) in loaded {
                state.add_network(cfg, reg);
            }
        }
        let identity = TlsIdentity::generate("coord").unwrap();
        let mut tasks = Vec::new();
        let ep = nqvpn_coord::control::bind(format!("127.0.0.1:{quic_port}").parse().unwrap(), &identity).unwrap();
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            let _ = nqvpn_coord::control::serve(s, ep).await;
        }));
        tasks.push(tokio::spawn(nqvpn_coord::control::liveness_sweep(state.clone())));
        let app = nqvpn_coord::api::router(state.clone());
        let tls = axum_server::tls_rustls::RustlsConfig::from_der(vec![identity.cert_der.clone()], identity.private_key().secret_der().to_vec()).await.unwrap();
        let listener = std::net::TcpListener::bind(format!("127.0.0.1:{api_port}")).unwrap();
        tasks.push(tokio::spawn(async move {
            let _ = axum_server::from_tcp_rustls(listener, tls).serve(app.into_make_service_with_connect_info::<SocketAddr>()).await;
        }));
        Coord { state, tasks }
    }

    /// Stop everything: sessions drop, ports free.
    fn stop(self) {
        for t in self.tasks {
            t.abort();
        }
        for (_, net) in self.state.nets() {
            let ns = net.lock().unwrap();
            for s in ns.sessions.values() {
                s.conn.close(0u32.into(), b"coordinator stopping");
            }
        }
    }

    fn net(&self) -> Arc<Mutex<NetState>> {
        self.state.net(NET).expect("the test network")
    }

    fn attachment_of(&self, node: NodeId) -> Option<NodeId> {
        self.net().lock().unwrap().directory.published.attachment_of(node)
    }

    fn online(&self, node: NodeId) -> bool {
        self.net().lock().unwrap().leases.is_online(node)
    }

    fn gen(&self) -> u64 {
        self.net().lock().unwrap().directory.gen
    }

    /// Edit a member as the UI would.
    fn configure(&self, name: &str, f: impl FnOnce(&mut MemberSpec)) {
        let mut spec = {
            let net = self.net();
            let ns = net.lock().unwrap();
            MemberSpec::from_cfg(ns.cfg.member_by_name(name).expect("configured member").0)
        };
        f(&mut spec);
        self.state.update_member(NET, name, &spec).expect("valid change");
    }
}

/// What a machine holds: the coordinator and its secret (its token).
fn member(coord_url: &str, node_id: NodeId, role: Role) -> Arc<MemberConfig> {
    let name = match role {
        Role::Relay => format!("r{node_id}"),
        Role::Client => format!("c{node_id}"),
    };
    Arc::new(MemberConfig { coordinator: coord_url.to_string(), secret: secret_of(&name), tls: nqvpn_proto::joinapi::JoinTls::default() })
}

async fn join(cfg: &Arc<MemberConfig>, id: &TlsIdentity, keys: &StaticKeys) -> JoinResponse {
    nqvpn_sync::join_with_backoff_async(cfg.clone(), id.clone(), keys.clone()).await
}

struct RelayHandle {
    net: Arc<RelayNet>,
    node_id: NodeId,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    sync: Option<tokio::task::JoinHandle<MemberExit>>,
    endpoint: quinn::Endpoint,
    cfg: Arc<MemberConfig>,
    identity: TlsIdentity,
    keys: StaticKeys,
}

use nqvpn_sync::MemberExit;

struct RelayHooks(Arc<RelayNet>);
impl nqvpn_sync::link::MemberHooks for RelayHooks {
    fn joined(&self, r: &JoinResponse) {
        self.0.set_credential(&r.credential);
        self.0.set_signing_keys(&r.coordinator_signing_keys);
    }
}

impl RelayHandle {
    async fn start(coord_url: &str, node_id: NodeId, listen_port: u16) -> RelayHandle {
        let identity = TlsIdentity::generate(&format!("relay{node_id}")).unwrap();
        let keys = StaticKeys::generate().unwrap();
        let cfg = member(coord_url, node_id, Role::Relay);
        let endpoint = quinn::Endpoint::server(
            nqvpn_proto::quic::server_config(&identity, 1).unwrap(),
            format!("127.0.0.1:{listen_port}").parse().unwrap(),
        )
        .unwrap();
        let joined = join(&cfg, &identity, &keys).await;
        let node_id = joined.node_id;
        let net = RelayNet::new(NET.into(), joined.network_uuid.clone(), node_id, identity.clone(), joined.credential.clone(), Mode::parse(&joined.transport), 1, 0, 1);
        net.set_signing_keys(&joined.coordinator_signing_keys);
        // A relay granted the default is an internet exit; this host is
        // not one for real, so stand in for the egress self-check: ready
        // unless a test says otherwise.
        net.set_exit_designated(&joined.granted_cidrs);
        net.set_exit_readiness(nqvpn_proto::control::ExitReadiness { ip_forward: true, masquerade: true });
        let mut nets = HashMap::new();
        nets.insert(NET.to_string(), net.clone());
        let tasks = vec![
            tokio::spawn(Arc::new(Fleet { nets }).accept_loop(endpoint.clone())),
            nqvpn_sync::spawn_reconciler(net.view.clone(), Arc::new(NetReconciler(net.clone())), Duration::from_secs(1)),
        ];
        let mut h = RelayHandle { net, node_id, tasks, sync: None, endpoint, cfg, identity, keys };
        h.start_sync(joined);
        h
    }

    fn start_sync(&mut self, joined: JoinResponse) {
        let net = self.net.clone();
        self.sync = Some(tokio::spawn(nqvpn_sync::run_member(
            self.cfg.clone(),
            self.identity.clone(),
            self.keys.clone(),
            joined,
            net.view.clone(),
            net.clone(),
            net.link.clone(),
            Arc::new(RelayHooks(net.clone())),
        )));
    }

    fn stop_reason(&self) -> Option<MemberExit> {
        self.net.link.stop_reason()
    }

    fn control_finished(&self) -> bool {
        self.sync.as_ref().map(|t| t.is_finished()).unwrap_or(true)
    }

    /// Cut the relay's control link (its data plane keeps running).
    fn cut_control(&mut self) {
        if let Some(t) = self.sync.take() {
            t.abort();
        }
    }

    async fn restore_control(&mut self) {
        let joined = join(&self.cfg, &self.identity, &self.keys).await;
        self.net.set_credential(&joined.credential);
        self.start_sync(joined);
    }

    /// Crash: everything stops, all sessions die.
    #[allow(dead_code)]
    fn kill(self) {
        for t in self.tasks {
            t.abort();
        }
        if let Some(t) = self.sync {
            t.abort();
        }
        self.endpoint.close(0u32.into(), b"relay killed");
    }
}

struct ClientHandle {
    client: Arc<Client>,
    tun: Arc<FakeTun>,
    routes: Arc<RouteSet<RecordingProgrammer>>,
    node_id: NodeId,
    /// Pumps and reconciler; they end with the handle.
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    sync: Option<tokio::task::JoinHandle<MemberExit>>,
    cfg: Arc<MemberConfig>,
    identity: TlsIdentity,
    keys: StaticKeys,
}

impl ClientHandle {
    async fn start(coord_url: &str, node_id: NodeId) -> ClientHandle {
        Self::start_inner(coord_url, node_id).await
    }

    /// With a preferred relay, configured at the coordinator as the UI
    /// would. The preference is re-checked every 2 s here (30 s in
    /// production).
    async fn start_preferring(w: &World, node_id: NodeId, preferred: Option<&str>) -> ClientHandle {
        w.coord().configure(&format!("c{node_id}"), |s| s.preferred_relay = preferred.map(str::to_string));
        Self::start_inner(&w.url(), node_id).await
    }

    async fn start_inner(coord_url: &str, node_id: NodeId) -> ClientHandle {
        Self::start_with_secret(coord_url, node_id, &secret_of(&format!("c{node_id}"))).await
    }

    /// With a specific token secret (after a rotation).
    async fn start_with_secret(coord_url: &str, node_id: NodeId, secret: &str) -> ClientHandle {
        let identity = TlsIdentity::generate(&format!("client{node_id}")).unwrap();
        let keys = StaticKeys::generate().unwrap();
        let mut m = (*member(coord_url, node_id, Role::Client)).clone();
        m.secret = secret.to_string();
        let cfg = Arc::new(m);
        let joined = join(&cfg, &identity, &keys).await;
        let tun = FakeTun::new(joined.mtu);
        let routes = Arc::new(RouteSet::new(RecordingProgrammer::default()));
        let client = Client::new(&joined, identity.clone(), keys.clone(), tun.clone(), routes.clone(), None, false, None);
        *client.prefer_recheck.lock().unwrap() = Duration::from_secs(2);
        client.spawn_pumps();
        let tasks = vec![
            nqvpn_sync::spawn_reconciler(client.view.clone(), Arc::new(ClientReconciler(client.clone())), Duration::from_secs(1)),
            tokio::spawn(client.clone().run_uplink()),
        ];
        let node_id = joined.node_id;
        let mut h = ClientHandle { client, tun, routes, node_id, _tasks: tasks, sync: None, cfg, identity, keys };
        h.start_sync(joined);
        h
    }

    fn start_sync(&mut self, joined: JoinResponse) {
        let c = self.client.clone();
        self.sync = Some(tokio::spawn(nqvpn_sync::run_member(
            self.cfg.clone(),
            self.identity.clone(),
            self.keys.clone(),
            joined,
            c.view.clone(),
            c.clone(),
            c.link.clone(),
            c.clone(),
        )));
    }

    /// Cut the control link; the uplink and its traffic are untouched.
    fn cut_control(&mut self) {
        if let Some(t) = self.sync.take() {
            t.abort();
        }
    }

    async fn restore_control(&mut self) {
        let joined = join(&self.cfg, &self.identity, &self.keys).await;
        self.start_sync(joined);
    }

    fn attached_to(&self) -> Option<NodeId> {
        self.client.uplink.attached_to.lock().unwrap().as_ref().map(|a| a.relay_id)
    }

    /// The client's current IPv4 address, as of its latest join.
    fn ip4(&self) -> Ipv4Addr {
        self.client
            .addresses()
            .iter()
            .find_map(|n| match n {
                ipnet::IpNet::V4(v) => Some(v.addr()),
                _ => None,
            })
            .expect("client has an address")
    }

    /// Set once this instance learned it was kicked out. A real process
    /// exits with `exit.exit_code()` at that point.
    fn stop_reason(&self) -> Option<MemberExit> {
        self.client.link.stop_reason()
    }

    /// The control loop has returned (the process would be exiting).
    fn control_finished(&self) -> bool {
        self.sync.as_ref().map(|t| t.is_finished()).unwrap_or(true)
    }

    fn uplink_ends(&self) -> u64 {
        self.client.counters.uplink_ends.load(Ordering::Relaxed)
    }
}

impl ClientHandle {
    /// A route-all client, optionally pinned to a named exit gateway.
    async fn start_route_all(coord_url: &str, node_id: NodeId, via: Option<&str>) -> ClientHandle {
        let identity = TlsIdentity::generate(&format!("client{node_id}")).unwrap();
        let keys = StaticKeys::generate().unwrap();
        let mut m = (*member(coord_url, node_id, Role::Client)).clone();
        m.secret = secret_of(&format!("c{node_id}"));
        let cfg = Arc::new(m);
        let joined = join(&cfg, &identity, &keys).await;
        let tun = FakeTun::new(joined.mtu);
        let routes = Arc::new(RouteSet::new(RecordingProgrammer::default()));
        let client = Client::new(&joined, identity.clone(), keys.clone(), tun.clone(), routes.clone(), None, true, via.map(str::to_string));
        client.spawn_pumps();
        let tasks = vec![
            nqvpn_sync::spawn_reconciler(client.view.clone(), Arc::new(ClientReconciler(client.clone())), Duration::from_secs(1)),
            tokio::spawn(client.clone().run_uplink()),
        ];
        let node_id = joined.node_id;
        let mut h = ClientHandle { client, tun, routes, node_id, _tasks: tasks, sync: None, cfg, identity, keys };
        h.start_sync(joined);
        h
    }

    /// Is this CIDR installed in the (recorded) OS routing table?
    fn os_has(&self, cidr: &str) -> bool {
        self.routes.installed().iter().any(|n| n.to_string() == cidr)
    }

    /// Which node does the in-VPN table seal traffic for `dst` to?
    fn exit_for(&self, dst: &str) -> Option<NodeId> {
        self.client.engine.peers.lock().unwrap().owner_of(dst.parse().unwrap())
    }
}

fn v4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[12..16].copy_from_slice(&src.octets());
    p[16..20].copy_from_slice(&dst.octets());
    p.extend_from_slice(payload);
    p
}

/// One packet from `a` to `b`, delivered within `timeout`? Retries the
/// send every 300 ms: during a handshake or a re-attach the first ones
/// are queued or dropped by design.
async fn ping(a: &ClientHandle, b: &ClientHandle, timeout: Duration) -> bool {
    static SEQ: AtomicU16 = AtomicU16::new(0);
    let tag = format!("ping-{}-{}-{}", a.node_id, b.node_id, SEQ.fetch_add(1, Ordering::Relaxed));
    let pkt = v4_packet(a.ip4(), b.ip4(), tag.as_bytes());
    let deadline = std::time::Instant::now() + timeout;
    loop {
        a.tun.inject(pkt.clone()).await;
        let step = std::time::Instant::now() + Duration::from_millis(300);
        while std::time::Instant::now() < step {
            if b.tun.written().iter().any(|w| w.ends_with(tag.as_bytes())) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        if std::time::Instant::now() > deadline {
            return false;
        }
    }
}

async fn all_pairs_reach(clients: &[&ClientHandle], timeout: Duration) -> Result<()> {
    for a in clients {
        for b in clients {
            if a.node_id != b.node_id {
                anyhow::ensure!(ping(a, b, timeout).await, "{} -> {} never arrived", a.node_id, b.node_id);
            }
        }
    }
    Ok(())
}

async fn wait_until(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    while !f() {
        anyhow::ensure!(std::time::Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

struct World {
    dir: tempfile::TempDir,
    coord: Option<Coord>,
    api_port: u16,
    quic_port: u16,
    toml: String,
}

impl World {
    async fn new(relays: &[NodeId], clients: &[NodeId]) -> (World, Vec<(NodeId, u16)>) {
        let dir = tempfile::tempdir().unwrap();
        let (api_port, quic_port) = (port(), port());
        let relay_ports: Vec<(NodeId, u16)> = relays.iter().map(|r| (*r, port())).collect();
        let toml = net_toml(&relay_ports, clients);
        let coord = Coord::start(dir.path(), api_port, quic_port, &toml).await;
        // Skip the restart grace for the first start.
        coord.net().lock().unwrap().started_at = 0;
        (World { dir, coord: Some(coord), api_port, quic_port, toml }, relay_ports)
    }

    fn url(&self) -> String {
        format!("https://127.0.0.1:{}", self.api_port)
    }

    fn coord(&self) -> &Coord {
        self.coord.as_ref().expect("coordinator running")
    }

    async fn restart_coordinator(&mut self) {
        self.stop_coordinator();
        tokio::time::sleep(Duration::from_millis(300)).await;
        self.start_coordinator().await;
    }

    fn stop_coordinator(&mut self) {
        if let Some(c) = self.coord.take() {
            c.stop();
        }
    }

    async fn start_coordinator(&mut self) {
        self.coord = Some(Coord::start(self.dir.path(), self.api_port, self.quic_port, &self.toml).await);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_clients_across_two_relays_all_reach_each_other() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 11, 20, 21]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let clients = [
        ClientHandle::start(&w.url(), 10).await,
        ClientHandle::start(&w.url(), 11).await,
        ClientHandle::start(&w.url(), 20).await,
        ClientHandle::start(&w.url(), 21).await,
    ];
    let refs: Vec<&ClientHandle> = clients.iter().collect();
    all_pairs_reach(&refs, Duration::from_secs(20)).await?;
    wait_until("coordinator and clients agree on attachments", Duration::from_secs(10), || {
        clients.iter().all(|c| w.coord().attachment_of(c.node_id) == c.attached_to() && c.attached_to().is_some())
    })
    .await?;
    wait_until("mesh formed", Duration::from_secs(10), || r1.net.mesh_peers() == vec![r2.node_id] && r2.net.mesh_peers() == vec![r1.node_id]).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_crash_moves_its_clients_and_traffic_resumes() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Kill whichever relay `a` is on.
    let dead = a.attached_to().expect("attached");
    if dead == r1.node_id {
        r1.kill();
        std::mem::forget(r2);
    } else {
        r2.kill();
        std::mem::forget(r1);
    }
    wait_until("clients leave the dead relay", Duration::from_secs(30), || a.attached_to() != Some(dead) && b.attached_to() != Some(dead)).await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(30)).await?;
    wait_until("coordinator sees the new attachments", Duration::from_secs(10), || {
        w.coord().attachment_of(a.node_id) == a.attached_to() && w.coord().attachment_of(b.node_id) == b.attached_to()
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_loses_its_coordinator_link_keeps_forwarding_both_ways() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let _r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let mut a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    a.cut_control();
    wait_until("coordinator marks a offline", Duration::from_secs(15), || !w.coord().online(a.node_id)).await?;
    // The scenario that used to end in permanent one-way traffic.
    for _ in 0..3 {
        assert!(ping(&a, &b, Duration::from_secs(5)).await, "a -> b while a's control link is down");
        assert!(ping(&b, &a, Duration::from_secs(5)).await, "b -> a while a's control link is down");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(w.coord().attachment_of(a.node_id), a.attached_to(), "the relay's declaration outlives the client's lease");
    a.restore_control().await;
    wait_until("a is back online", Duration::from_secs(15), || w.coord().online(a.node_id)).await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relays_that_lose_their_coordinator_link_keep_forwarding() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let mut r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let mut r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Cut *both* relays' control links: the coordinator now hears nothing
    // from the data plane at all.
    r1.cut_control();
    r2.cut_control();
    wait_until("coordinator marks both relays offline", Duration::from_secs(15), || !w.coord().online(r1.node_id) && !w.coord().online(r2.node_id)).await?;
    for _ in 0..3 {
        all_pairs_reach(&[&a, &b], Duration::from_secs(5)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(w.coord().attachment_of(a.node_id).is_some(), "attachments survive a relay's lease expiring");
    r1.restore_control().await;
    r2.restore_control().await;
    wait_until("relays back online", Duration::from_secs(15), || w.coord().online(r1.node_id) && w.coord().online(r2.node_id)).await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_coordinator_restart_never_interrupts_traffic() -> Result<()> {
    let (mut w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    let gen_before = w.coord().gen();

    w.restart_coordinator().await;
    // While members reconnect and the new coordinator collects, the data
    // plane must not notice.
    for _ in 0..6 {
        all_pairs_reach(&[&a, &b], Duration::from_secs(5)).await?;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    wait_until("everyone re-registered with the new coordinator", Duration::from_secs(30), || {
        w.coord().online(r1.node_id) && w.coord().online(r2.node_id) && w.coord().online(a.node_id) && w.coord().online(b.node_id)
            && w.coord().attachment_of(a.node_id).is_some() && w.coord().attachment_of(b.node_id).is_some()
    })
    .await?;
    assert!(w.coord().gen() > gen_before, "generations never go backwards across a restart");
    wait_until("views converge", Duration::from_secs(15), || {
        let g = w.coord().gen();
        a.client.view.gen() == g && b.client.view.gen() == g
    })
    .await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_different_machine_joining_as_the_same_node_replaces_it() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let mut a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Stop the old instance renewing (or the two would take turns
    // replacing each other every renewal — by design), keep its uplink.
    a.cut_control();
    let ends_before = a.uplink_ends();
    // Same node id and secret, from a machine with different keys.
    let a2 = ClientHandle::start(&w.url(), 10).await;
    wait_until("the old instance is thrown off its relay", Duration::from_secs(15), || a.uplink_ends() > ends_before).await?;
    all_pairs_reach(&[&a2, &b], Duration::from_secs(20)).await?;
    // Its control link is gone, so the relay is what tells it (a
    // stale-login refusal). It stops re-attaching — a real process
    // exits here — and never carries traffic again.
    wait_until("the old instance learns it from the relay", Duration::from_secs(15), || {
        matches!(a.stop_reason(), Some(MemberExit::Replaced(_)))
    })
    .await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!ping(&a, &b, Duration::from_secs(3)).await, "the replaced instance must not keep forwarding");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabling_a_relay_moves_its_clients_and_reenabling_brings_it_back() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Disable whichever relay `a` is attached to. The relay keeps its
    // process (disable is a lever) but must stop carrying traffic, and
    // `a` must move to the survivor quickly — not wait for a session to
    // time out.
    let disabled_id = a.attached_to().expect("attached");
    let disabled = format!("r{disabled_id}");
    w.coord().state.set_disabled(NET, &disabled, true).unwrap();
    wait_until("clients leave the disabled relay", Duration::from_secs(15), || {
        a.attached_to() != Some(disabled_id) && b.attached_to() != Some(disabled_id)
    })
    .await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    // The disabled relay is refused, not stopped: it keeps retrying.
    assert!(r1.stop_reason().is_none() && r2.stop_reason().is_none());

    // Enable it again: it is accepted, serves once more, and clients may
    // attach to it — nobody restarted anything.
    w.coord().state.set_disabled(NET, &disabled, false).unwrap();
    wait_until("the relay is dialable again", Duration::from_secs(30), || {
        w.coord().net().lock().unwrap().directory.published.relays.iter().any(|r| r.name == disabled)
    })
    .await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    std::mem::forget(r1);
    std::mem::forget(r2);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabling_a_member_evicts_it_from_the_data_plane() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    let ends_before = a.uplink_ends();
    w.coord().state.set_disabled(NET, "c10", true).unwrap();
    wait_until("a loses its uplink", Duration::from_secs(15), || a.uplink_ends() > ends_before).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!ping(&a, &b, Duration::from_secs(3)).await, "disabled member must not reach anyone");
    assert!(!ping(&b, &a, Duration::from_secs(3)).await, "nor be reachable");
    // Disable is a lever, not a kill switch: the instance keeps asking
    // (with backoff) and never stops on its own...
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(a.stop_reason().is_none() && !a.control_finished(), "a disabled member keeps retrying");
    // ...so enabling it again brings it back without anyone touching it.
    w.coord().state.set_disabled(NET, "c10", false).unwrap();
    wait_until("a re-joins and re-attaches", Duration::from_secs(45), || a.attached_to().is_some()).await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_flapping_converges() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20, 30]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let _r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    let c = ClientHandle::start(&w.url(), 30).await;
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(20)).await?;

    // r1 crashes and comes back twice, under load.
    let mut r1 = Some(r1);
    for _ in 0..2 {
        r1.take().unwrap().kill();
        tokio::time::sleep(Duration::from_secs(2)).await;
        r1 = Some(RelayHandle::start(&w.url(), 1, rp[0].1).await);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(30)).await?;
    wait_until("the coordinator's attachments match the clients'", Duration::from_secs(15), || {
        [&a, &b, &c].iter().all(|x| w.coord().attachment_of(x.node_id) == x.attached_to() && x.attached_to().is_some())
    })
    .await?;
    let r1 = r1.take().unwrap();
    wait_until("mesh re-formed", Duration::from_secs(10), || r1.net.mesh_peers() == vec![_r2.node_id]).await?;
    Ok(())
}

// ---------------------------------------------------------------------
// More ways to break it.

impl RelayHandle {
    /// Cut this relay's mesh link to `peer` (from this side).
    fn cut_mesh(&self, peer: NodeId) -> bool {
        self.net.close_mesh(peer)
    }
}

impl ClientHandle {
    /// Restart the same member on the same machine (same keys): rejoin,
    /// new uplink, no replacement.
    async fn restart(self, coord_url: &str) -> ClientHandle {
        let (identity, keys) = (self.identity.clone(), self.keys.clone());
        // Same machine: same keys, same token.
        let cfg = Arc::new(MemberConfig { coordinator: coord_url.to_string(), ..(*self.cfg).clone() });
        let joined = join(&cfg, &identity, &keys).await;
        let tun = FakeTun::new(joined.mtu);
        let routes = Arc::new(RouteSet::new(RecordingProgrammer::default()));
        let client = Client::new(&joined, identity.clone(), keys.clone(), tun.clone(), routes.clone(), None, false, None);
        client.spawn_pumps();
        let tasks = vec![
            nqvpn_sync::spawn_reconciler(client.view.clone(), Arc::new(ClientReconciler(client.clone())), Duration::from_secs(1)),
            tokio::spawn(client.clone().run_uplink()),
        ];
        let node_id = joined.node_id;
        let mut h = ClientHandle { client, tun, routes, node_id, _tasks: tasks, sync: None, cfg, identity, keys };
        h.start_sync(joined);
        h
    }

    #[allow(dead_code)]
    fn kill(self) {
        for t in self._tasks {
            t.abort();
        }
        if let Some(t) = self.sync {
            t.abort();
        }
        if let Some(s) = self.client.uplink.session() {
            s.close(0, "client killed");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cut_mesh_link_heals_and_cross_relay_traffic_resumes() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    wait_until("mesh up", Duration::from_secs(10), || r1.net.mesh_peers() == vec![r2.node_id]).await?;

    for i in 0..3 {
        // Cut from alternating sides; the dialer side must redial either way.
        let cut = if i % 2 == 0 { r1.cut_mesh(r2.node_id) } else { r2.cut_mesh(r1.node_id) };
        assert!(cut, "there was a link to cut");
        wait_until("link re-formed", Duration::from_secs(15), || {
            r1.net.mesh_peers() == vec![r2.node_id] && r2.net.mesh_peers() == vec![r1.node_id]
        })
        .await?;
        all_pairs_reach(&[&a, &b], Duration::from_secs(15)).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_restart_on_the_same_machine_keeps_its_identity() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    let (id, ip) = (a.node_id, a.ip4());
    let login_gen_before = w.coord().net().lock().unwrap().registry.members[&id].login_gen;

    let a = a.restart(&w.url()).await;
    assert_eq!(a.node_id, id, "same name, same wire identity");
    assert_eq!(a.ip4(), ip, "same address");
    let login_gen_after = w.coord().net().lock().unwrap().registry.members[&id].login_gen;
    assert_eq!(login_gen_after, login_gen_before, "same keys: not a replacement");
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_byzantine_relay_cannot_break_end_to_end_traffic() -> Result<()> {
    use nqvpn_relay::net::Chaos;
    let (w, rp) = World::new(&[1, 2], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    for mode in [Chaos::Duplicate, Chaos::Corrupt(2), Chaos::Drop(3)] {
        r1.net.set_chaos(Some(mode));
        r2.net.set_chaos(Some(mode));
        for _ in 0..8 {
            all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
        }
        r1.net.set_chaos(None);
        r2.net.set_chaos(None);
    }
    // The endpoints saw the abuse and named it, instead of failing.
    let (ca, cb) = (a.engine_counters(), b.engine_counters());
    let n = |k: &str| ca.get(k).copied().unwrap_or(0) + cb.get(k).copied().unwrap_or(0);
    let c = (&ca, &cb);
    assert!(n("drop_replay") > 0, "duplicates were refused by the replay window: {c:?}");
    assert!(n("drop_seal_failed") > 0, "corrupted frames failed authentication: {c:?}");
    assert!(n("received") > 20, "and real traffic kept flowing: {c:?}");
    Ok(())
}

impl ClientHandle {
    fn engine_counters(&self) -> std::collections::HashMap<&'static str, u64> {
        self.client.engine.counters.snapshot().into_iter().collect()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nine_clients_three_relays_all_reach_each_other() -> Result<()> {
    let (w, rp) = World::new(&[1, 2, 3], &[10, 11, 12, 20, 21, 22, 30, 31, 32]).await;
    let relays: Vec<RelayHandle> = {
        let mut v = Vec::new();
        for (id, p) in &rp {
            v.push(RelayHandle::start(&w.url(), *id, *p).await);
        }
        v
    };
    let mut clients = Vec::new();
    for id in [10, 11, 12, 20, 21, 22, 30, 31, 32] {
        clients.push(ClientHandle::start(&w.url(), id).await);
    }
    let refs: Vec<&ClientHandle> = clients.iter().collect();
    all_pairs_reach(&refs, Duration::from_secs(30)).await?;
    wait_until("full mesh", Duration::from_secs(15), || relays.iter().all(|r| r.net.mesh_peers().len() == 2)).await?;
    wait_until("coordinator agrees with every client", Duration::from_secs(15), || {
        clients.iter().all(|c| w.coord().attachment_of(c.node_id) == c.attached_to() && c.attached_to().is_some())
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotating_a_token_throws_the_old_holder_out_at_once() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Rotate a's token: the running instance holds the old secret.
    let new_secret = w.coord().state.rotate_member(NET, "c10").unwrap();
    wait_until("the old holder is thrown out and stops", Duration::from_secs(15), || a.stop_reason().is_some() && a.attached_to().is_none()).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!ping(&a, &b, Duration::from_secs(3)).await, "the old secret's holder is out");
    // A machine with the new token is that member again.
    let a2 = ClientHandle::start_with_secret(&w.url(), 10, &new_secret).await;
    all_pairs_reach(&[&a2, &b], Duration::from_secs(20)).await?;
    Ok(())
}

// ---- Kicked out: learn why, stop, never fight back ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_replaced_from_elsewhere_stops_and_its_clients_move() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    let (ends_a, ends_b) = (a.uplink_ends(), b.uplink_ends());

    // The operator moves r1 to another machine: the configured address
    // is updated and a fresh process (new keys) joins from there. The
    // old process was never stopped and is still up and answering.
    let new_port = port();
    {
        // Straight into the config, without the "re-join now" the UI
        // path would send: the old process must not be told anything.
        let net = w.coord().net();
        let mut ns = net.lock().unwrap();
        ns.cfg.relays.get_mut("r1").unwrap().relay_addr = Some(format!("127.0.0.1:{new_port}"));
    }
    let r1b = RelayHandle::start(&w.url(), 1, new_port).await;
    wait_until("the old relay learns it was replaced", Duration::from_secs(15), || {
        matches!(r1.stop_reason(), Some(MemberExit::Replaced(_)))
    })
    .await?;
    wait_until("and its control loop returns", Duration::from_secs(5), || r1.control_finished()).await?;
    assert!(r1.stop_reason().unwrap().reason().contains("replaced"));
    // Its clients see the fleet entry change under them and leave the
    // zombie without being told by it.
    wait_until("clients leave the zombie", Duration::from_secs(15), || a.uplink_ends() > ends_a && b.uplink_ends() > ends_b).await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(30)).await?;
    // The old instance does not re-join, so the replacement is not
    // replaced back.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(r1b.stop_reason().is_none(), "the replacement keeps its identity");
    all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
    r1.kill();
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replaced_client_is_told_by_the_coordinator_and_stops() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;

    // Control link intact this time: the coordinator itself tells it.
    let a2 = ClientHandle::start(&w.url(), 10).await;
    wait_until("the old instance is told", Duration::from_secs(15), || matches!(a.stop_reason(), Some(MemberExit::Replaced(_)))).await?;
    wait_until("and its control loop returns", Duration::from_secs(5), || a.control_finished()).await?;
    all_pairs_reach(&[&a2, &b], Duration::from_secs(20)).await?;
    // Before, any lost session was followed by a re-join, which would
    // have made a2 the replaced one by now.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(a2.stop_reason().is_none(), "the replacement keeps its identity");
    all_pairs_reach(&[&a2, &b], Duration::from_secs(10)).await?;
    assert!(!ping(&a, &b, Duration::from_secs(3)).await, "the replaced instance is out");
    Ok(())
}

// ---- Preferred relay: used when available, never required ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_preferred_relay_is_used_when_available_and_not_required() -> Result<()> {
    let (w, rp) = World::new(&[1, 2], &[10, 20, 30]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    // r2 is configured but not running yet.
    let b = ClientHandle::start(&w.url(), 20).await;
    let a = ClientHandle::start_preferring(&w, 10, Some("r2")).await;
    // A preferred relay that does not exist at all is no different.
    let c = ClientHandle::start_preferring(&w, 30, None).await;
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(20)).await?;
    assert_eq!(a.attached_to(), Some(r1.node_id), "falls back while the preferred relay is absent");
    assert_eq!(c.attached_to(), Some(r1.node_id), "no preference: lowest RTT, which is the only relay");
    // A preference for something that is not a relay cannot even be configured.
    let bad = MemberSpec { preferred_relay: Some("nope".into()), ..Default::default() };
    assert!(w.coord().state.update_member(NET, "c30", &bad).is_err());

    // The preferred relay shows up: a moves to it without being told.
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    wait_until("a moves to its preferred relay", Duration::from_secs(20), || a.attached_to() == Some(r2.node_id)).await?;
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(20)).await?;
    assert_eq!(c.attached_to(), Some(r1.node_id), "no preference, no reason to move");

    // And it dies: a falls back again; nothing waits for it.
    r2.kill();
    wait_until("a falls back", Duration::from_secs(30), || a.attached_to() == Some(r1.node_id)).await?;
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(20)).await?;
    Ok(())
}

// ---- route-all: pick the internet exit gateway, never blackhole ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_all_via_names_the_internet_exit_gateway() -> Result<()> {
    // Two relays both front the internet default (0.0.0.0/0): each is a
    // valid exit. A route-all client with --via must pick the named one,
    // install the def1 catch-all halves, and seal internet-bound traffic
    // to that node — not the other.
    let (w, rp) = World::new(&[1, 2], &[10]).await;
    // A relay registers (and thus owns) its routed cidrs at join time, so
    // grant the default before the relays start.
    w.coord().configure("r1", |s| s.internet_gateway = Some(true));
    w.coord().configure("r2", |s| s.internet_gateway = Some(true));
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;

    let a = ClientHandle::start_route_all(&w.url(), 10, Some("r2")).await;
    wait_until("route-all routes the internet to the named exit", Duration::from_secs(20), || {
        a.exit_for("8.8.8.8") == Some(r2.node_id) && a.os_has("0.0.0.0/1") && a.os_has("128.0.0.0/1")
    })
    .await?;
    assert_ne!(a.exit_for("8.8.8.8"), Some(r1.node_id), "the unnamed exit is not chosen");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_preferred_exit_falls_back_when_it_goes_away_and_is_returned_to_when_it_comes_back() -> Result<()> {
    // --via names a preference, not a pin. Losing the preferred exit must
    // cost the client nothing but the preference, and getting it back must
    // need no restart: the exit is recomputed every reconcile, never stored.
    use nqvpn_proto::control::ExitReadiness;
    let (w, rp) = World::new(&[1, 2], &[10]).await;
    w.coord().configure("r1", |s| s.internet_gateway = Some(true));
    w.coord().configure("r2", |s| s.internet_gateway = Some(true));
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;

    let a = ClientHandle::start_route_all(&w.url(), 10, Some("r2")).await;
    wait_until("the preferred exit is chosen", Duration::from_secs(20), || {
        a.exit_for("8.8.8.8") == Some(r2.node_id) && a.os_has("0.0.0.0/1")
    })
    .await?;

    // The preferred exit stops being a usable exit (its host stopped
    // masquerading), so the coordinator withdraws its default.
    r2.net.set_exit_readiness(ExitReadiness { ip_forward: true, masquerade: false });
    wait_until("falls back to the other exit rather than losing the internet", Duration::from_secs(20), || {
        a.exit_for("8.8.8.8") == Some(r1.node_id)
    })
    .await?;
    assert!(a.os_has("0.0.0.0/1") && a.os_has("128.0.0.0/1"), "the catch-all stays armed on the fallback exit");

    // It becomes usable again: the preference returns on its own.
    r2.net.set_exit_readiness(ExitReadiness { ip_forward: true, masquerade: true });
    wait_until("the preference is restored without a restart", Duration::from_secs(20), || {
        a.exit_for("8.8.8.8") == Some(r2.node_id)
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_all_withholds_the_catch_all_until_the_named_exit_reports_ready() -> Result<()> {
    // r2 is designated an exit but its host is not masquerading: the
    // coordinator must not publish its default, so the client neither
    // picks it nor installs the catch-all. Once the host reports ready
    // the exit appears — no restart of anything.
    use nqvpn_proto::control::ExitReadiness;
    let (w, rp) = World::new(&[1, 2], &[10]).await;
    // r1 is a plain forwarder; r2 is the only designated exit.
    w.coord().configure("r2", |s| s.internet_gateway = Some(true));
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let r2 = RelayHandle::start(&w.url(), 2, rp[1].1).await;
    r2.net.set_exit_readiness(ExitReadiness { ip_forward: true, masquerade: false });

    let a = ClientHandle::start_route_all(&w.url(), 10, Some("r2")).await;
    wait_until("the client attaches and reconciles", Duration::from_secs(20), || a.attached_to().is_some()).await?;
    wait_until("the unready exit is withdrawn", Duration::from_secs(20), || a.exit_for("8.8.8.8").is_none()).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!a.os_has("0.0.0.0/1") && !a.os_has("128.0.0.0/1"), "no ready exit: the catch-all is withheld");
    assert_eq!(a.exit_for("8.8.8.8"), None, "an exit that is not ready is not an exit");

    r2.net.set_exit_readiness(ExitReadiness { ip_forward: true, masquerade: true });
    wait_until("the exit appears once its host reports ready", Duration::from_secs(20), || {
        a.exit_for("8.8.8.8") == Some(r2.node_id) && a.os_has("0.0.0.0/1") && a.os_has("128.0.0.0/1")
    })
    .await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn route_all_withholds_the_catch_all_when_no_exit_owns_the_default() -> Result<()> {
    // --via names a node that fronts no default (r1 is a plain forwarder):
    // route-all must leave the real default route in place rather than
    // blackholing every packet into a tunnel that has nowhere to send it.
    let (w, rp) = World::new(&[1], &[10]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start_route_all(&w.url(), 10, Some("r1")).await;
    wait_until("the client attaches and reconciles", Duration::from_secs(20), || a.attached_to().is_some()).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!a.os_has("0.0.0.0/1") && !a.os_has("128.0.0.0/1"), "no exit owns 0.0.0.0/0: the catch-all is withheld");
    assert_eq!(a.exit_for("8.8.8.8"), None, "and internet-bound traffic is not pulled into the tunnel");
    Ok(())
}

// ---- Valid members connect eventually; nothing else is needed ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_connect_eventually_when_the_coordinator_comes_up_late() -> Result<()> {
    let (mut w, rp) = World::new(&[1], &[10, 20]).await;
    w.stop_coordinator();

    // Both start against a dead coordinator and keep trying.
    let r1 = tokio::spawn({
        let url = w.url();
        async move { RelayHandle::start(&url, 1, rp[0].1).await }
    });
    let a = tokio::spawn({
        let url = w.url();
        async move { ClientHandle::start(&url, 10).await }
    });
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!r1.is_finished() && !a.is_finished(), "nothing joins while the coordinator is down");

    w.start_coordinator().await;
    let up = std::time::Instant::now();
    let r1 = tokio::time::timeout(Duration::from_secs(15), r1).await??;
    let a = tokio::time::timeout(Duration::from_secs(15), a).await??;
    assert!(up.elapsed() < Duration::from_secs(10), "joined {:?} after the coordinator came up", up.elapsed());
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    drop(r1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn members_are_back_within_seconds_of_a_coordinator_restart() -> Result<()> {
    let (mut w, rp) = World::new(&[1], &[10]).await;
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    wait_until("both online", Duration::from_secs(15), || w.coord().online(r1.node_id) && w.coord().online(a.node_id)).await?;

    w.restart_coordinator().await;
    let up = std::time::Instant::now();
    wait_until("both back", Duration::from_secs(15), || w.coord().online(r1.node_id) && w.coord().online(a.node_id)).await?;
    assert!(up.elapsed() < Duration::from_secs(10), "reconnect took {:?}", up.elapsed());
    Ok(())
}

// ---- Configuration lives at the coordinator; a change is applied live ----

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn editing_a_member_at_the_coordinator_reconfigures_it_live() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    let old_ip = a.ip4();

    // A new static address for a, inside the network CIDR. The
    // coordinator tells a to re-join and apply it, while every endpoint
    // keeps only the single covering network route in its OS table.
    let new_ip: Ipv4Addr = "10.99.0.7".parse().unwrap();
    w.coord().configure("c10", |s| s.preferred_ip4 = Some(new_ip));
    wait_until("a carries its new address", Duration::from_secs(15), || a.ip4() == new_ip).await?;
    assert_eq!(a.tun.addresses(), vec![ipnet::IpNet::from(ipnet::Ipv4Net::new(new_ip, 32).unwrap())]);
    assert!(b.routes.installed().iter().any(|n| n.to_string() == "10.99.0.0/16"));
    assert!(!b.routes.installed().iter().any(|n| n.to_string() == "10.99.0.7/32"), "the covering CIDR replaces per-member OS routes");
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    assert!(!b.routes.installed().iter().any(|n| n.to_string() == format!("{old_ip}/32")), "member host routes are never needed");

    // The relay starts fronting a LAN: every client learns the route.
    w.coord().configure("r1", |s| s.local_cidrs = vec!["100.64.77.0/24".parse().unwrap()]);
    wait_until("clients route the relay's LAN", Duration::from_secs(15), || {
        [&a, &b].iter().all(|c| c.routes.installed().iter().any(|n| n.to_string() == "100.64.77.0/24"))
    })
    .await?;
    // And stops: the route is withdrawn.
    w.coord().configure("r1", |s| s.local_cidrs.clear());
    wait_until("the route is withdrawn", Duration::from_secs(15), || {
        [&a, &b].iter().all(|c| !c.routes.installed().iter().any(|n| n.to_string() == "100.64.77.0/24"))
    })
    .await?;
    all_pairs_reach(&[&a, &b], Duration::from_secs(10)).await?;
    assert!(a.stop_reason().is_none() && b.stop_reason().is_none(), "reconfiguration is not a kick-out");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_with_an_auto_address_is_dialed_where_it_joined_from() -> Result<()> {
    let (w, rp) = World::new(&[1], &[10, 20]).await;
    w.coord().configure("r1", |s| s.relay_addr = Some(format!("auto:{}", rp[0].1)));
    let r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    assert_eq!(a.attached_to(), Some(r1.node_id));
    let fleet = w.coord().net().lock().unwrap().directory.published.relays.clone();
    assert_eq!(fleet[0].addr, format!("127.0.0.1:{}", rp[0].1), "resolved from the join's source address");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_coordinator_reloads_everything_from_its_database() -> Result<()> {
    let (mut w, rp) = World::new(&[1], &[10, 20]).await;
    let _r1 = RelayHandle::start(&w.url(), 1, rp[0].1).await;
    let a = ClientHandle::start(&w.url(), 10).await;
    let b = ClientHandle::start(&w.url(), 20).await;
    all_pairs_reach(&[&a, &b], Duration::from_secs(20)).await?;
    // A member created in the UI, with a token, before the restart.
    let secret = w.coord().state.create_member(NET, "c30", Role::Client, &MemberSpec::default()).unwrap();
    let ip_a = a.ip4();

    w.restart_coordinator().await;
    // Members, addresses, secrets and node ids all came back from the
    // database: the same identities, and the new member's token works.
    wait_until("members reconnect", Duration::from_secs(15), || w.coord().online(a.node_id) && w.coord().online(b.node_id)).await?;
    assert_eq!(a.ip4(), ip_a);
    let c = ClientHandle::start_with_secret(&w.url(), 30, &secret).await;
    all_pairs_reach(&[&a, &b, &c], Duration::from_secs(20)).await?;
    Ok(())
}
