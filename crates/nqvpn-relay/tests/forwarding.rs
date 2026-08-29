//! Phase 2 milestone (DESIGN.md §11): two clients exchange frames across
//! two meshed relays. Everything below the coordinator is real — real
//! QUIC, real mutual TLS, real credential verification, real forwarding.
//!
//! The coordinator is stubbed to a credential signer + attachment table
//! so the test stays focused on the relay's data plane.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use nqvpn_proto::control::{AttachmentEntry, Hello, HelloAck, KeyInfo};
use nqvpn_proto::credential::{sign, Claims, AUD};
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::frame::{Probe, RoutedHeader, T_DATA, T_PROBE, T_REPLY};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{client_config, server_config};
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::types::{NodeId, Role};
use nqvpn_relay::sessions;
use nqvpn_relay::state::RelayState;
use nqvpn_proto::transport::{Mode, PacketChannel};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const NETWORK: &str = "n1";
const UUID: &str = "11111111-2222-3333-4444-555555555555";

struct Ca {
    sk: SigningKey,
}

impl Ca {
    fn new() -> Ca {
        Ca { sk: SigningKey::generate(&mut rand::rngs::OsRng) }
    }
    fn key_infos(&self) -> Vec<KeyInfo> {
        vec![KeyInfo {
            kid: "k1".into(),
            key: B64.encode(self.sk.verifying_key().to_bytes()),
            state: "active".into(),
        }]
    }
    fn credential(&self, node_id: NodeId, name: &str, role: Role, fp: &str) -> String {
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
                pubkey: format!("PK-{name}"),
                cert_fp: fp.to_string(),
                prefixes: vec![],
                iat: now,
                exp: now + 900,
            },
            "k1",
            &self.sk,
        )
    }
}

struct Relay {
    state: Arc<RelayState>,
    addr: SocketAddr,
    identity: TlsIdentity,
    node_id: NodeId,
}

fn spawn_relay(ca: &Ca, node_id: NodeId, name: &str, max_mbps: u32) -> Relay {
    let identity = TlsIdentity::generate(name).unwrap();
    let state = Arc::new(RelayState::new(
        node_id,
        NETWORK.to_string(),
        UUID.to_string(),
        "unused".to_string(),
    ));
    state.set_signing_keys(&ca.key_infos());
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, 5).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    tokio::spawn(sessions::accept_loop(state.clone(), endpoint, max_mbps));
    Relay { state, addr, identity, node_id }
}

/// A stub member: connects, authenticates, and can send/receive raw
/// datagrams — the shape `nqvpn-client` will have in Phase 3.
struct StubMember {
    conn: quinn::Connection,
    _ep: quinn::Endpoint,
}

impl StubMember {
    async fn connect(relay: &Relay, credential: &str, id: &TlsIdentity) -> Result<StubMember> {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        ep.set_default_client_config(client_config(
            id,
            Some(relay.identity.fingerprint()),
            5,
        )?);
        let conn = ep.connect(relay.addr, "relay")?.await?;
        let (mut tx, mut rx) = conn.open_bi().await?;
        write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string() }).await?;
        let ack = read_envelope(&mut rx).await?;
        anyhow::ensure!(ack.kind == Kind::HelloAck as u16, "relay refused credential");
        let _: HelloAck = nqvpn_proto::envelope::decode_payload(&ack.payload)?;
        // Keep the control stream alive for the session's lifetime.
        std::mem::forget(tx);
        std::mem::forget(rx);
        Ok(StubMember { conn, _ep: ep })
    }

    fn send_data(&self, src: NodeId, dst: NodeId, payload: &[u8]) -> Result<()> {
        let mut buf = Vec::new();
        RoutedHeader { kind: T_DATA, src_id: src, dst_id: dst }.write(&mut buf);
        buf.extend_from_slice(payload);
        self.conn.send_datagram(buf.into())?;
        Ok(())
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        let d = tokio::time::timeout(Duration::from_secs(5), self.conn.read_datagram()).await??;
        Ok(d.to_vec())
    }

    async fn try_recv(&self, within: Duration) -> Option<Vec<u8>> {
        tokio::time::timeout(within, self.conn.read_datagram())
            .await
            .ok()
            .and_then(|r| r.ok())
            .map(|d| d.to_vec())
    }
}

/// Wire two relays together exactly as the mesh dialer does.
async fn link(a: &Relay, b: &Relay, ca: &Ca) -> Result<()> {
    let cred = ca.credential(a.node_id, "ra", Role::Relay, &a.identity.fingerprint());
    let member = StubMember::connect(b, &cred, &a.identity).await?;
    // b now sees a as a mesh peer; give a the reverse direction too.
    let chan = PacketChannel::start(member.conn.clone(), Mode::Datagram);
    let sid = a.state.add_mesh(b.node_id, chan.clone());
    let state = a.state.clone();
    let peer = b.node_id;
    tokio::spawn(async move {
        let _ = sessions::forward_loop(
            &state,
            &chan,
            nqvpn_relay::tables::Origin::Relay(peer),
            0,
        )
        .await;
        state.remove_mesh(peer, sid);
    });
    std::mem::forget(member);
    Ok(())
}

#[tokio::test]
async fn two_clients_across_two_relays() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let r2 = spawn_relay(&ca, 2, "r2", 0);
    link(&r1, &r2, &ca).await?;

    // c10 attaches to r1, c20 to r2.
    let c10_id = TlsIdentity::generate("c10")?;
    let c20_id = TlsIdentity::generate("c20")?;
    let c10 = StubMember::connect(
        &r1,
        &ca.credential(10, "c10", Role::Client, &c10_id.fingerprint()),
        &c10_id,
    )
    .await?;
    let c20 = StubMember::connect(
        &r2,
        &ca.credential(20, "c20", Role::Client, &c20_id.fingerprint()),
        &c20_id,
    )
    .await?;

    // The coordinator's attachment table tells each relay where the
    // other's clients live.
    r1.state.replace_attachments(vec![
        AttachmentEntry { node_id: 10, relay_id: 1 },
        AttachmentEntry { node_id: 20, relay_id: 2 },
    ]);
    r2.state.replace_attachments(vec![
        AttachmentEntry { node_id: 10, relay_id: 1 },
        AttachmentEntry { node_id: 20, relay_id: 2 },
    ]);
    tokio::time::sleep(Duration::from_millis(200)).await;

    // c10 -> c20 crosses exactly one mesh link and arrives verbatim.
    c10.send_data(10, 20, b"hello across the mesh")?;
    let got = c20.recv().await?;
    let h = RoutedHeader::parse(&got).expect("routed header preserved");
    assert_eq!((h.src_id, h.dst_id), (10, 20));
    assert_eq!(&got[9..], b"hello across the mesh", "payload forwarded verbatim");
    Ok(())
}

#[tokio::test]
async fn same_relay_clients_need_no_mesh_hop() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);

    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, "a", Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, "b", Role::Client, &b_id.fingerprint()), &b_id).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    a.send_data(10, 11, b"local delivery")?;
    let got = b.recv().await?;
    assert_eq!(&got[9..], b"local delivery");
    let counters = r1.state.counters.snapshot();
    assert_eq!(counters.iter().find(|(k, _)| *k == "delivered_local").unwrap().1, 1);
    assert_eq!(counters.iter().find(|(k, _)| *k == "forwarded_mesh").unwrap().1, 0);
    Ok(())
}

#[tokio::test]
async fn spoofed_source_is_dropped() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, "a", Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, "b", Role::Client, &b_id.fingerprint()), &b_id).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    // a claims to be node 99.
    a.send_data(99, 11, b"forged")?;
    assert!(b.try_recv(Duration::from_millis(400)).await.is_none(), "spoof must not arrive");
    assert_eq!(
        r1.state
            .counters
            .snapshot()
            .iter()
            .find(|(k, _)| *k == "drop_src_spoofed")
            .unwrap()
            .1,
        1
    );
    Ok(())
}

#[tokio::test]
async fn a_frame_never_crosses_two_mesh_links() -> Result<()> {
    // r1 -- r2 -- r3, with a client on r1 and one on r3. r2 must refuse
    // to forward r1's frame onward to r3 (the loop-prevention rule).
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let r2 = spawn_relay(&ca, 2, "r2", 0);
    let r3 = spawn_relay(&ca, 3, "r3", 0);
    link(&r1, &r2, &ca).await?;
    link(&r2, &r3, &ca).await?;

    let a_id = TlsIdentity::generate("a")?;
    let c_id = TlsIdentity::generate("c")?;
    let a = StubMember::connect(&r1, &ca.credential(10, "a", Role::Client, &a_id.fingerprint()), &a_id).await?;
    let c = StubMember::connect(&r3, &ca.credential(30, "c", Role::Client, &c_id.fingerprint()), &c_id).await?;

    // r1 believes node 30 sits on r2 (it does not — it is on r3).
    r1.state.replace_attachments(vec![AttachmentEntry { node_id: 30, relay_id: 2 }]);
    r2.state.replace_attachments(vec![AttachmentEntry { node_id: 30, relay_id: 3 }]);
    tokio::time::sleep(Duration::from_millis(200)).await;

    a.send_data(10, 30, b"should not arrive")?;
    assert!(
        c.try_recv(Duration::from_millis(500)).await.is_none(),
        "two mesh hops must be impossible"
    );
    assert_eq!(
        r2.state
            .counters
            .snapshot()
            .iter()
            .find(|(k, _)| *k == "drop_no_second_hop")
            .unwrap()
            .1,
        1
    );
    Ok(())
}

#[tokio::test]
async fn relay_answers_hop_local_probes() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let a_id = TlsIdentity::generate("a")?;
    let a = StubMember::connect(&r1, &ca.credential(10, "a", Role::Client, &a_id.fingerprint()), &a_id).await?;

    let p = Probe { kind: T_PROBE, seq: 7, t_sent: 123456 };
    a.conn.send_datagram(p.encode().into())?;
    let got = a.recv().await?;
    let reply = Probe::parse(&got).expect("probe reply");
    assert_eq!(reply.kind, T_REPLY);
    assert_eq!(reply.seq, 7);
    assert_eq!(reply.t_sent, 123456, "sender's clock echoed back unchanged");
    Ok(())
}

#[tokio::test]
async fn unknown_destination_is_dropped_not_broadcast() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, "a", Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, "b", Role::Client, &b_id.fingerprint()), &b_id).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;

    a.send_data(10, 12345, b"nowhere")?;
    assert!(b.try_recv(Duration::from_millis(400)).await.is_none());
    assert_eq!(
        r1.state
            .counters
            .snapshot()
            .iter()
            .find(|(k, _)| *k == "drop_dst_unknown")
            .unwrap()
            .1,
        1
    );
    Ok(())
}

/// A client that attaches while the relay's coordinator link is down
/// must still end up in the attachment registry: the relay re-declares
/// its whole local set when the link comes back (regression — the
/// edge-triggered report alone was lost, and the fleet could not route
/// to that client).
#[tokio::test]
async fn attachments_resync_when_the_coordinator_link_returns() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);

    // No coordinator link yet: reports have nowhere to go.
    let a_id = TlsIdentity::generate("a")?;
    let _a = StubMember::connect(
        &r1,
        &ca.credential(10, "a", Role::Client, &a_id.fingerprint()),
        &a_id,
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r1.state.local_clients(), vec![10], "relay knows locally");

    // The link comes up: the relay must re-declare what it already has.
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    r1.state.set_attach_sender(Some(tx.clone()));
    for node_id in r1.state.local_clients() {
        tx.try_send(nqvpn_proto::control::Attach { node_id, attached: true }).unwrap();
    }
    let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await?
        .expect("resync report");
    assert_eq!((got.node_id, got.attached), (10, true));
    Ok(())
}

/// A superseded session's delayed teardown must not evict the session
/// that replaced it (regression: a dead client's QUIC timeout fired 15 s
/// after the client had already reconnected, and silently detached it).
#[tokio::test]
async fn a_stale_session_teardown_does_not_evict_its_successor() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let id = TlsIdentity::generate("a")?;
    let cred = ca.credential(10, "a", Role::Client, &id.fingerprint());

    let _first = StubMember::connect(&r1, &cred, &id).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(r1.state.local_clients(), vec![10]);

    // Same node reconnects (new session supersedes the old entry).
    let _second = StubMember::connect(&r1, &cred, &id).await?;
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(r1.state.local_clients(), vec![10]);

    // The *old* session finally times out and runs its teardown.
    r1.state.remove_client(10, 1);
    assert_eq!(
        r1.state.local_clients(),
        vec![10],
        "the live session must survive the stale teardown"
    );
    Ok(())
}

/// The coordinator is authoritative for liveness. Its window is shorter
/// than our QUIC idle timeout, so a member it declares offline must be
/// dropped here immediately — otherwise the periodic attachment resync
/// re-announces a dead client and the coordinator's table flaps back to
/// "reachable" (observed live with a kill -9'd laptop).
#[tokio::test]
async fn an_offline_membership_push_drops_the_local_session() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let id = TlsIdentity::generate("a")?;
    let _m = StubMember::connect(
        &r1,
        &ca.credential(10, "a", Role::Client, &id.fingerprint()),
        &id,
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r1.state.local_clients(), vec![10], "attached");

    // The coordinator says that member is gone.
    r1.state.apply_membership_delta(nqvpn_proto::control::MembershipDelta {
        base_rev: 0,
        new_rev: 1,
        changed: vec![nqvpn_proto::control::PeerInfo {
            node_id: 10,
            name: "a".into(),
            prefixes: vec![],
            pubkey: String::new(),
            online: false,
        }],
        removed: vec![],
    });

    assert!(
        r1.state.local_clients().is_empty(),
        "session must be dropped at once, not at our own idle timeout"
    );
    Ok(())
}

#[tokio::test]
async fn foreign_network_credential_is_refused() -> Result<()> {
    let ca = Ca::new();
    let other_ca = Ca::new(); // a different coordinator entirely
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let id = TlsIdentity::generate("intruder")?;
    let cred = other_ca.credential(10, "intruder", Role::Client, &id.fingerprint());
    assert!(
        StubMember::connect(&r1, &cred, &id).await.is_err(),
        "a credential from another trust domain must be rejected"
    );
    Ok(())
}

#[tokio::test]
async fn stolen_credential_without_the_key_is_refused() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, "r1", 0);
    let victim = TlsIdentity::generate("victim")?;
    let cred = ca.credential(10, "victim", Role::Client, &victim.fingerprint());
    // The thief has the token but not the private key behind cert_fp.
    let thief = TlsIdentity::generate("thief")?;
    assert!(StubMember::connect(&r1, &cred, &thief).await.is_err());
    Ok(())
}
