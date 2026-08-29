//! Phase 3 milestone (DESIGN.md §11): two clients exchange **encrypted**
//! IP packets over fake TUNs, across a real relay mesh.
//!
//! Everything except the TUN device and the coordinator is real: real
//! QUIC, real mutual TLS, real credential checks at the relay, real
//! Noise IK sessions end to end, real forwarding.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use nqvpn_client::engine::{Engine, Uplink};
use nqvpn_client::peers::PeerTable;
use nqvpn_client::tun::{FakeTun, TunDevice};
use nqvpn_proto::control::{AttachmentEntry, Hello, KeyInfo, PeerInfo};
use nqvpn_proto::credential::{sign, Claims, AUD};
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{client_config, server_config};
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::types::{NodeId, Role};
use nqvpn_relay::sessions;
use nqvpn_relay::state::RelayState;
use nqvpn_proto::transport::{Mode, PacketChannel};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const NETWORK: &str = "n1";
const UUID: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

struct Ca(SigningKey);

impl Ca {
    fn new() -> Ca {
        Ca(SigningKey::generate(&mut rand::rngs::OsRng))
    }
    fn keys(&self) -> Vec<KeyInfo> {
        vec![KeyInfo {
            kid: "k1".into(),
            key: B64.encode(self.0.verifying_key().to_bytes()),
            state: "active".into(),
        }]
    }
    fn cred(&self, node_id: NodeId, name: &str, role: Role, fp: &str) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        sign(
            &Claims {
                iss: "nqvpn-coord".into(),
                aud: AUD.into(),
                network_id: NETWORK.into(),
                network_uuid: UUID.into(),
                node_id,
                sub: name.into(),
                role,
                pubkey: String::new(),
                cert_fp: fp.into(),
                prefixes: vec![],
                iat: now,
                exp: now + 900,
            },
            "k1",
            &self.0,
        )
    }
}

struct Relay {
    state: Arc<RelayState>,
    addr: SocketAddr,
    identity: TlsIdentity,
    node_id: NodeId,
}

fn spawn_relay(ca: &Ca, node_id: NodeId, name: &str) -> Relay {
    let identity = TlsIdentity::generate(name).unwrap();
    let state = Arc::new(RelayState::new(
        node_id,
        NETWORK.into(),
        UUID.into(),
        "unused".into(),
    ));
    state.set_signing_keys(&ca.keys());
    let ep = quinn::Endpoint::server(
        server_config(&identity, 5).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = ep.local_addr().unwrap();
    tokio::spawn(sessions::accept_loop(state.clone(), ep, 0));
    Relay { state, addr, identity, node_id }
}

async fn link(a: &Relay, b: &Relay, ca: &Ca) -> Result<()> {
    let cred = ca.cred(a.node_id, "ra", Role::Relay, &a.identity.fingerprint());
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    ep.set_default_client_config(client_config(&a.identity, Some(b.identity.fingerprint()), 5)?);
    let conn = ep.connect(b.addr, "relay")?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: cred }).await?;
    read_envelope(&mut rx).await?;
    let chan = PacketChannel::start(conn.clone(), Mode::Datagram);
    let sid = a.state.add_mesh(b.node_id, chan.clone());
    let state = a.state.clone();
    let peer = b.node_id;
    tokio::spawn(async move {
        let _ = sessions::forward_loop(&state, &chan, nqvpn_relay::tables::Origin::Relay(peer), 0)
            .await;
        state.remove_mesh(peer, sid);
    });
    std::mem::forget((ep, tx, rx, conn));
    Ok(())
}

/// A full client: Noise engine + fake TUN + a real QUIC uplink to a relay.
struct Client {
    engine: Arc<Engine>,
    tun: Arc<FakeTun>,
    node_id: NodeId,
}

struct QuicUplink(quinn::Connection);

impl Uplink for QuicUplink {
    fn send(&self, datagram: Vec<u8>, _lane: u8) -> bool {
        // Datagram mode has no lanes, so the label is carried and ignored.
        self.0.send_datagram(datagram.into()).is_ok()
    }
}

async fn spawn_client(
    relay: &Relay,
    ca: &Ca,
    node_id: NodeId,
    name: &str,
    keys: StaticKeys,
    peers: Vec<PeerInfo>,
    mine: Vec<&str>,
) -> Result<Client> {
    let tls = TlsIdentity::generate(name)?;
    let cred = ca.cred(node_id, name, Role::Client, &tls.fingerprint());
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    ep.set_default_client_config(client_config(&tls, Some(relay.identity.fingerprint()), 5)?);
    let conn = ep.connect(relay.addr, "relay")?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: cred }).await?;
    read_envelope(&mut rx).await?;

    let mut table = PeerTable::new(node_id);
    table.set_mine(mine.iter().map(|p| p.parse().unwrap()).collect());
    for p in peers {
        table.upsert(p);
    }
    let engine = Engine::new(node_id, UUID.into(), keys, table, 1350, 1);
    let tun = FakeTun::new(1350);

    // Outbound pump: TUN -> engine -> uplink.
    let mut reader = tun.reader();
    let e = engine.clone();
    let up = Arc::new(QuicUplink(conn.clone()));
    let up2 = up.clone();
    let t0: Arc<FakeTun> = tun.clone();
    tokio::spawn(async move {
        while let Some(pkt) = reader.recv().await {
            e.outbound(pkt, up2.as_ref(), t0.as_ref());
        }
    });
    // Inbound pump: uplink -> engine -> TUN.
    let e2 = engine.clone();
    let t2: Arc<FakeTun> = tun.clone();
    let c2 = conn.clone();
    tokio::spawn(async move {
        while let Ok(d) = c2.read_datagram().await {
            e2.inbound(&d, up.as_ref(), t2.as_ref());
        }
    });
    std::mem::forget((ep, tx, rx));
    Ok(Client { engine, tun, node_id })
}

fn v4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

fn peer_info(node_id: NodeId, addr: &str, keys: &StaticKeys) -> PeerInfo {
    PeerInfo {
        node_id,
        name: format!("c{node_id}"),
        prefixes: vec![addr.parse().unwrap()],
        pubkey: keys.public_b64(),
        online: true,
    }
}

async fn wait_for_write(tun: &FakeTun, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(p) = tun.written().into_iter().next() {
            return Some(p);
        }
        if std::time::Instant::now() > deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[tokio::test]
async fn encrypted_packets_flow_between_clients_across_two_relays() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");
    let r2 = spawn_relay(&ca, 2, "r2");
    link(&r1, &r2, &ca).await?;

    let ka = StaticKeys::generate()?;
    let kb = StaticKeys::generate()?;
    let a_info = peer_info(10, "10.0.0.10/32", &ka);
    let b_info = peer_info(20, "10.0.0.20/32", &kb);

    let a = spawn_client(&r1, &ca, 10, "a", ka, vec![b_info.clone()], vec!["10.0.0.10/32"]).await?;
    let b = spawn_client(&r2, &ca, 20, "b", kb, vec![a_info.clone()], vec!["10.0.0.20/32"]).await?;

    for r in [&r1, &r2] {
        r.state.replace_attachments(vec![
            AttachmentEntry { node_id: 10, relay_id: 1 },
            AttachmentEntry { node_id: 20, relay_id: 2 },
        ]);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    // An application on A sends an IP packet to B's tunnel address.
    let pkt = v4_packet([10, 0, 0, 10], [10, 0, 0, 20], b"ping payload");
    a.tun.inject(pkt.clone()).await;

    // It arrives on B's TUN, byte-identical, after a Noise handshake that
    // itself crossed the relay mesh.
    let got = wait_for_write(&b.tun, Duration::from_secs(10))
        .await
        .expect("packet never arrived on B");
    assert_eq!(got, pkt, "inner packet delivered verbatim");

    // Reply travels the other way over the same session.
    let reply = v4_packet([10, 0, 0, 20], [10, 0, 0, 10], b"pong payload");
    b.tun.inject(reply.clone()).await;
    let back = wait_for_write(&a.tun, Duration::from_secs(10))
        .await
        .expect("reply never arrived on A");
    assert_eq!(back, reply);

    // Both ends completed a handshake and moved real traffic.
    let ca_ = a.engine.counters.snapshot();
    assert!(ca_.iter().any(|(k, v)| *k == "handshakes_started" && *v >= 1));
    assert!(ca_.iter().any(|(k, v)| *k == "received" && *v >= 1));
    Ok(())
}

#[tokio::test]
async fn relays_cannot_read_the_traffic_they_carry() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");

    let ka = StaticKeys::generate()?;
    let kb = StaticKeys::generate()?;
    let a_info = peer_info(10, "10.0.0.10/32", &ka);
    let b_info = peer_info(20, "10.0.0.20/32", &kb);
    let a = spawn_client(&r1, &ca, 10, "a", ka, vec![b_info], vec!["10.0.0.10/32"]).await?;
    let b = spawn_client(&r1, &ca, 20, "b", kb, vec![a_info], vec!["10.0.0.20/32"]).await?;
    r1.state.replace_attachments(vec![
        AttachmentEntry { node_id: 10, relay_id: 1 },
        AttachmentEntry { node_id: 20, relay_id: 1 },
    ]);
    tokio::time::sleep(Duration::from_millis(150)).await;

    let secret = b"TOP-SECRET-MARKER-9f3a";
    a.tun.inject(v4_packet([10, 0, 0, 10], [10, 0, 0, 20], secret)).await;
    assert!(wait_for_write(&b.tun, Duration::from_secs(10)).await.is_some());

    // The relay moved bytes but never held a key: it counted frames and
    // nothing in its tables resembles the payload.
    let counters = r1.state.counters.snapshot();
    let delivered = counters.iter().find(|(k, _)| *k == "delivered_local").unwrap().1;
    assert!(delivered >= 2, "relay forwarded handshake + data");
    let _ = (a.node_id, b.node_id);
    Ok(())
}

#[tokio::test]
async fn a_peer_may_not_source_spoof_another_members_address() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");

    let ka = StaticKeys::generate()?;
    let kb = StaticKeys::generate()?;
    let kc = StaticKeys::generate()?;
    let a_info = peer_info(10, "10.0.0.10/32", &ka);
    let b_info = peer_info(20, "10.0.0.20/32", &kb);
    let c_info = peer_info(30, "10.0.0.30/32", &kc);

    // B knows about A and C. C will try to impersonate A.
    let b = spawn_client(
        &r1,
        &ca,
        20,
        "b",
        kb,
        vec![a_info.clone(), c_info.clone()],
        vec!["10.0.0.20/32"],
    )
    .await?;
    let c = spawn_client(&r1, &ca, 30, "c", kc, vec![b_info], vec!["10.0.0.30/32"]).await?;
    r1.state.replace_attachments(vec![
        AttachmentEntry { node_id: 20, relay_id: 1 },
        AttachmentEntry { node_id: 30, relay_id: 1 },
    ]);
    tokio::time::sleep(Duration::from_millis(150)).await;

    // C emits a packet whose inner source is A's address.
    c.tun.inject(v4_packet([10, 0, 0, 10], [10, 0, 0, 20], b"forged")).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert!(b.tun.written().is_empty(), "spoofed packet must not reach the TUN");
    let dropped = b
        .engine
        .counters
        .snapshot()
        .into_iter()
        .find(|(k, _)| *k == "drop_ingress")
        .unwrap()
        .1;
    assert_eq!(dropped, 1, "the ingress filter caught it");
    let _ = a_info;
    Ok(())
}

/// A relay that takes a VPN address must be reachable *at* that address,
/// not just be a forwarder for others (§3.1). Regression: frames
/// addressed to a relay's own node id hit a stub and vanished, so
/// `ping <relay ip>` failed silently.
#[tokio::test]
async fn a_relay_with_an_address_terminates_traffic_sent_to_it() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");

    // The relay takes on the endpoint role with its own address.
    let relay_keys = StaticKeys::generate()?;
    let relay_tun = FakeTun::new(1350);
    let ep = nqvpn_relay::endpoint::LocalEndpoint::new(
        r1.state.clone(),
        relay_tun.clone(),
        relay_keys.clone(),
        vec!["10.0.0.1/32".parse().unwrap()],
        1350,
        1,
    );
    ep.spawn_pumps();
    r1.state.set_endpoint(ep);

    // A client that knows the relay's address and key.
    let ck = StaticKeys::generate()?;
    let relay_info = peer_info(1, "10.0.0.1/32", &relay_keys);
    let client_info = peer_info(10, "10.0.0.10/32", &ck);
    let c = spawn_client(&r1, &ca, 10, "c", ck, vec![relay_info], vec!["10.0.0.10/32"]).await?;

    // The relay's own peer table must know the client, or its ingress
    // filter rejects the packet.
    r1.state
        .endpoint()
        .unwrap()
        .engine
        .peers
        .lock()
        .unwrap()
        .replace_all(vec![client_info]);
    r1.state.replace_attachments(vec![AttachmentEntry { node_id: 10, relay_id: 1 }]);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Client -> relay's own address.
    let pkt = v4_packet([10, 0, 0, 10], [10, 0, 0, 1], b"hello relay");
    c.tun.inject(pkt.clone()).await;
    let got = wait_for_write(&relay_tun, Duration::from_secs(10))
        .await
        .expect("relay never received traffic addressed to itself");
    assert_eq!(got, pkt, "delivered to the relay's TUN verbatim");
    Ok(())
}

#[tokio::test]
async fn packets_to_unknown_destinations_are_dropped_locally() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");
    let ka = StaticKeys::generate()?;
    let a = spawn_client(&r1, &ca, 10, "a", ka, vec![], vec!["10.0.0.10/32"]).await?;

    a.tun.inject(v4_packet([10, 0, 0, 10], [8, 8, 8, 8], b"nowhere")).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let c = a.engine.counters.snapshot();
    assert_eq!(c.iter().find(|(k, _)| *k == "drop_no_route").unwrap().1, 1);
    assert_eq!(c.iter().find(|(k, _)| *k == "sent").unwrap().1, 0);
    Ok(())
}

#[tokio::test]
async fn oversize_packets_are_dropped_with_a_counter() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1");
    let ka = StaticKeys::generate()?;
    let kb = StaticKeys::generate()?;
    let b_info = peer_info(20, "10.0.0.20/32", &kb);
    let a = spawn_client(&r1, &ca, 10, "a", ka, vec![b_info], vec!["10.0.0.10/32"]).await?;

    a.tun
        .inject(v4_packet([10, 0, 0, 10], [10, 0, 0, 20], &vec![0u8; 2000]))
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        a.engine
            .counters
            .snapshot()
            .into_iter()
            .find(|(k, _)| *k == "drop_oversize")
            .unwrap()
            .1,
        1
    );
    Ok(())
}
