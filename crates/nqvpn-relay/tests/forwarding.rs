//! The relay data plane end to end: real QUIC, real mutual TLS, real
//! credential verification, real forwarding — with the coordinator
//! stubbed to a signer plus a hand-fed view.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use nqvpn_proto::control::{AttachmentEntry, KeyInfo, NetworkMtu, PeerInfo, RelayEndpoint, Snapshot};
use nqvpn_proto::credential::{sign, Claims, AUD};
use nqvpn_proto::frame::{Decision, Probe, RoutedHeader, TraceNote, FLAG_TRACE, T_DATA, T_PROBE, T_REPLY};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::server_config;
use nqvpn_proto::transport::Mode;
use nqvpn_proto::types::{NodeId, Role};
use nqvpn_relay::net::{Fleet, RelayNet};
use nqvpn_session::Session;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

const NETWORK: &str = "n1";
const UUID: &str = "11111111-2222-3333-4444-555555555555";

pub struct Ca {
    sk: SigningKey,
}

impl Ca {
    fn new() -> Ca {
        Ca { sk: SigningKey::generate(&mut rand::rngs::OsRng) }
    }
    fn key_infos(&self) -> Vec<KeyInfo> {
        vec![KeyInfo { kid: "k1".into(), key: B64.encode(self.sk.verifying_key().to_bytes()), state: "active".into() }]
    }
    fn claims(&self, node_id: NodeId, role: Role, fp: &str, login_gen: u64) -> Claims {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        Claims {
            iss: "nqvpn-coord".into(),
            aud: AUD.into(),
            network_id: NETWORK.into(),
            network_uuid: UUID.into(),
            node_id,
            sub: format!("n{node_id}"),
            role,
            pubkey: B64.encode([node_id as u8; 32]),
            cert_fp: fp.to_string(),
            prefixes: vec![],
            login_gen,
            iat: now,
            exp: now + 900,
        }
    }
    fn credential(&self, node_id: NodeId, role: Role, fp: &str) -> String {
        sign(&self.claims(node_id, role, fp, 0), "k1", &self.sk)
    }
    fn credential_gen(&self, node_id: NodeId, role: Role, fp: &str, login_gen: u64) -> String {
        sign(&self.claims(node_id, role, fp, login_gen), "k1", &self.sk)
    }
}

struct Relay {
    net: Arc<RelayNet>,
    addr: SocketAddr,
    identity: TlsIdentity,
    node_id: NodeId,
}

fn spawn_relay(ca: &Ca, node_id: NodeId, max_mbps: u32) -> Relay {
    let identity = TlsIdentity::generate(&format!("r{node_id}")).unwrap();
    let cred = ca.credential(node_id, Role::Relay, &identity.fingerprint());
    let net = RelayNet::new(NETWORK.into(), UUID.into(), node_id, identity.clone(), cred, Mode::Datagram, 1, max_mbps, 5);
    net.set_signing_keys(&ca.key_infos());
    let endpoint = quinn::Endpoint::server(server_config(&identity, 5).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let mut nets = HashMap::new();
    nets.insert(NETWORK.to_string(), net.clone());
    tokio::spawn(Arc::new(Fleet { nets }).accept_loop(endpoint));
    Relay { net, addr, identity, node_id }
}

fn peer(node_id: NodeId, login_gen: u64) -> PeerInfo {
    PeerInfo { node_id, name: format!("n{node_id}"), role: Role::Client, prefixes: vec![], pubkey: B64.encode([node_id as u8; 32]), online: true, login_gen }
}

/// Feed a relay the coordinator's view: members, attachments, fleet.
fn feed(r: &Relay, members: &[(NodeId, u64)], attachments: &[(NodeId, NodeId)], relays: &[&Relay]) {
    let mut s = Snapshot {
        gen: 1,
        members: members.iter().map(|(n, g)| peer(*n, *g)).collect(),
        attachments: attachments.iter().map(|(n, r)| AttachmentEntry { node_id: *n, relay_id: *r }).collect(),
        relays: relays
            .iter()
            .map(|x| RelayEndpoint { relay_id: x.node_id, name: format!("r{}", x.node_id), addr: x.addr.to_string(), cert_fp: x.identity.fingerprint() })
            .collect(),
        mtu: NetworkMtu { mtu: 1350, limited_by: "config".into() },
        keys: vec![],
        reserved_prefixes: vec![],
    };
    // Relays are members too (so the eviction rule knows them).
    for x in relays {
        s.members.push(PeerInfo { role: Role::Relay, ..peer(x.node_id, 0) });
    }
    s.normalize();
    r.net.view.replace(s.clone());
    r.net.reconcile(&s);
}

/// A stub member: authenticates and speaks raw frames.
struct StubMember {
    session: Arc<Session>,
}

impl StubMember {
    async fn connect(relay: &Relay, credential: &str, id: &TlsIdentity) -> Result<StubMember> {
        let claims = nqvpn_sync::join::own_claims(credential).unwrap_or_else(|| Claims {
            iss: String::new(), aud: String::new(), network_id: String::new(), network_uuid: String::new(),
            node_id: 0, sub: String::new(), role: Role::Client, pubkey: String::new(), cert_fp: String::new(),
            prefixes: vec![], login_gen: 0, iat: 0, exp: 0,
        });
        let session = nqvpn_session::dial(&relay.addr.to_string(), id, Some(relay.identity.fingerprint()), credential, 5, Mode::Datagram, 1, relay.node_id, Role::Relay, claims).await?;
        Ok(StubMember { session })
    }

    fn frame(src: NodeId, dst: NodeId, payload: &[u8], traced: bool) -> Vec<u8> {
        let mut h = RoutedHeader::new(T_DATA, src, dst, 7);
        if traced {
            h.flags |= FLAG_TRACE;
        }
        let mut buf = Vec::new();
        h.write(&mut buf);
        buf.extend_from_slice(payload);
        buf
    }

    fn send_data(&self, src: NodeId, dst: NodeId, payload: &[u8]) -> bool {
        self.session.chan.send(Bytes::from(Self::frame(src, dst, payload, false)))
    }

    async fn recv(&self) -> Result<Vec<u8>> {
        let (d, _) = tokio::time::timeout(Duration::from_secs(5), self.session.chan.recv()).await?.ok_or_else(|| anyhow::anyhow!("closed"))?;
        Ok(d.to_vec())
    }

    async fn try_recv(&self, within: Duration) -> Option<Vec<u8>> {
        tokio::time::timeout(within, self.session.chan.recv()).await.ok().flatten().map(|(d, _)| d.to_vec())
    }

    async fn closed(&self, within: Duration) -> bool {
        tokio::time::timeout(within, self.session.conn.closed()).await.is_ok()
    }
}

/// Wire two relays together exactly as the mesh dialer does: `a` dials `b`.
async fn link(a: &Relay, b: &Relay, ca: &Ca) -> Result<()> {
    let cred = ca.credential(a.node_id, Role::Relay, &a.identity.fingerprint());
    let claims = nqvpn_sync::join::own_claims(&cred).unwrap();
    let session = nqvpn_session::dial(&b.addr.to_string(), &a.identity, Some(b.identity.fingerprint()), &cred, 5, Mode::Datagram, 1, b.node_id, Role::Relay, claims).await?;
    tokio::spawn(a.net.clone().run_mesh(session, true));
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(())
}

async fn attached(r: &Relay, node: NodeId) -> bool {
    for _ in 0..40 {
        if r.net.local_clients().contains(&node) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn two_clients_across_two_relays_with_a_trace() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let r2 = spawn_relay(&ca, 2, 0);
    link(&r1, &r2, &ca).await?;
    let c10_id = TlsIdentity::generate("c10")?;
    let c20_id = TlsIdentity::generate("c20")?;
    let c10 = StubMember::connect(&r1, &ca.credential(10, Role::Client, &c10_id.fingerprint()), &c10_id).await?;
    let c20 = StubMember::connect(&r2, &ca.credential(20, Role::Client, &c20_id.fingerprint()), &c20_id).await?;
    assert!(attached(&r1, 10).await && attached(&r2, 20).await);
    feed(&r1, &[(10, 0), (20, 0)], &[(10, 1), (20, 2)], &[&r1, &r2]);
    feed(&r2, &[(10, 0), (20, 0)], &[(10, 1), (20, 2)], &[&r1, &r2]);

    assert!(c10.send_data(10, 20, b"hello across the mesh"));
    let got = c20.recv().await?;
    let h = RoutedHeader::parse(&got).expect("routed header preserved");
    assert_eq!((h.src_id, h.dst_id), (10, 20));
    assert_eq!(h.hop, 2, "one hop per relay");
    assert_eq!(&got[nqvpn_proto::frame::ROUTED_HEADER_LEN..], b"hello across the mesh");

    // A traced frame comes back with one note per relay it crossed.
    assert!(c10.session.chan.send(Bytes::from(StubMember::frame(10, 20, b"traced", true))));
    let mut notes = Vec::new();
    for _ in 0..3 {
        if let Some(d) = c10.try_recv(Duration::from_secs(2)).await {
            if let Some(n) = TraceNote::parse(&d) {
                notes.push(n);
            }
        }
    }
    notes.sort_by_key(|n| n.hop);
    assert_eq!(notes.len(), 2, "{notes:?}");
    assert_eq!((notes[0].relay_id, notes[0].decision, notes[0].detail), (1, Decision::ForwardMesh, 2));
    assert_eq!((notes[1].relay_id, notes[1].decision, notes[1].detail), (2, Decision::DeliverLocal, 20));
    assert_eq!(notes[0].origin, 10);
    Ok(())
}

#[tokio::test]
async fn same_relay_clients_need_no_mesh_hop() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, Role::Client, &b_id.fingerprint()), &b_id).await?;
    assert!(attached(&r1, 10).await && attached(&r1, 11).await);
    a.send_data(10, 11, b"local delivery");
    let got = b.recv().await?;
    assert_eq!(&got[nqvpn_proto::frame::ROUTED_HEADER_LEN..], b"local delivery");
    assert_eq!(r1.net.counters.get(Decision::DeliverLocal), 1);
    assert_eq!(r1.net.counters.get(Decision::ForwardMesh), 0);
    Ok(())
}

#[tokio::test]
async fn spoofed_sources_are_dropped_from_clients_and_relays() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let r2 = spawn_relay(&ca, 2, 0);
    link(&r1, &r2, &ca).await?;
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, Role::Client, &b_id.fingerprint()), &b_id).await?;
    assert!(attached(&r1, 10).await && attached(&r1, 11).await);
    feed(&r1, &[(10, 0), (11, 0), (30, 0)], &[(10, 1), (11, 1), (30, 2)], &[&r1, &r2]);
    feed(&r2, &[(10, 0), (11, 0), (30, 0)], &[(10, 1), (11, 1), (30, 2)], &[&r1, &r2]);

    // a claims to be node 99.
    a.send_data(99, 11, b"forged");
    assert!(b.try_recv(Duration::from_millis(400)).await.is_none(), "spoof must not arrive");
    assert_eq!(r1.net.counters.get(Decision::DropSrcSpoofed), 1);

    // r2 (a relay) may only speak for nodes attached to it: node 30 is,
    // node 10 is not.
    let r2_as_member = StubMember::connect(&r1, &ca.credential(2, Role::Relay, &r2.identity.fingerprint()), &r2.identity).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    r2_as_member.send_data(10, 11, b"relay forging a local client");
    assert!(b.try_recv(Duration::from_millis(400)).await.is_none());
    r2_as_member.send_data(30, 11, b"legit from behind r2");
    assert!(b.recv().await.is_ok());
    Ok(())
}

#[tokio::test]
async fn a_frame_never_crosses_two_mesh_links_and_the_hop_guard_is_hard() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let r2 = spawn_relay(&ca, 2, 0);
    let r3 = spawn_relay(&ca, 3, 0);
    link(&r1, &r2, &ca).await?;
    link(&r2, &r3, &ca).await?;
    let a_id = TlsIdentity::generate("a")?;
    let c_id = TlsIdentity::generate("c")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let c = StubMember::connect(&r3, &ca.credential(30, Role::Client, &c_id.fingerprint()), &c_id).await?;
    assert!(attached(&r1, 10).await && attached(&r3, 30).await);
    // r1 believes node 30 sits on r2 (it does not — it is on r3).
    feed(&r1, &[(10, 0), (30, 0)], &[(10, 1), (30, 2)], &[&r1, &r2, &r3]);
    feed(&r2, &[(10, 0), (30, 0)], &[(10, 1), (30, 3)], &[&r1, &r2, &r3]);
    a.send_data(10, 30, b"should not arrive");
    assert!(c.try_recv(Duration::from_millis(500)).await.is_none(), "two mesh hops must be impossible");
    assert_eq!(r2.net.counters.get(Decision::DropNoSecondHop), 1);

    // Even with a lying table, a frame that already travelled two hops
    // is dropped by the counter alone.
    let mut buf = StubMember::frame(10, 30, b"looped", false);
    buf[10] = 2; // hop = 2 already
    a.session.chan.send(Bytes::from(buf));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(r1.net.counters.get(Decision::DropTooManyHops), 1);
    Ok(())
}

#[tokio::test]
async fn relay_answers_hop_local_probes() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let a_id = TlsIdentity::generate("a")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let p = Probe { kind: T_PROBE, seq: 7, t_sent: 123456 };
    a.session.chan.send(p.encode().into());
    let got = a.recv().await?;
    let reply = Probe::parse(&got).expect("probe reply");
    assert_eq!((reply.kind, reply.seq, reply.t_sent), (T_REPLY, 7, 123456));
    Ok(())
}

#[tokio::test]
async fn unknown_destination_is_dropped_not_broadcast() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential(11, Role::Client, &b_id.fingerprint()), &b_id).await?;
    assert!(attached(&r1, 10).await && attached(&r1, 11).await);
    a.send_data(10, 12345, b"nowhere");
    assert!(b.try_recv(Duration::from_millis(400)).await.is_none());
    assert_eq!(r1.net.counters.get(Decision::DropDstUnknown), 1);
    Ok(())
}

/// A member's reconnecting session replaces the old one *and closes it*:
/// the old connection cannot linger as a half-dead attachment.
#[tokio::test]
async fn a_newer_session_replaces_and_closes_the_old_one() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let id = TlsIdentity::generate("a")?;
    let cred = ca.credential(10, Role::Client, &id.fingerprint());
    let first = StubMember::connect(&r1, &cred, &id).await?;
    assert!(attached(&r1, 10).await);
    let second = StubMember::connect(&r1, &cred, &id).await?;
    assert!(first.closed(Duration::from_secs(3)).await, "the superseded session is closed, not left dangling");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r1.net.local_clients(), vec![10], "the live session survives the old one's teardown");
    assert!(!second.closed(Duration::from_millis(200)).await);
    Ok(())
}

/// The view says a member is gone, or was replaced by a newer join: its
/// session is closed here — on the wire, not merely in a table — so the
/// member re-attaches (or, if replaced, stays out).
#[tokio::test]
async fn the_view_evicts_removed_and_replaced_members_on_the_wire() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let a_id = TlsIdentity::generate("a")?;
    let b_id = TlsIdentity::generate("b")?;
    let a = StubMember::connect(&r1, &ca.credential(10, Role::Client, &a_id.fingerprint()), &a_id).await?;
    let b = StubMember::connect(&r1, &ca.credential_gen(11, Role::Client, &b_id.fingerprint(), 0), &b_id).await?;
    assert!(attached(&r1, 10).await && attached(&r1, 11).await);
    // Node 10 is no longer a member; node 11 was replaced (login_gen 1).
    feed(&r1, &[(11, 1)], &[], &[&r1]);
    assert!(a.closed(Duration::from_secs(3)).await, "removed member is disconnected");
    assert!(b.closed(Duration::from_secs(3)).await, "replaced instance is disconnected");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(r1.net.local_clients().is_empty());
    // The replaced instance's credential no longer opens a session…
    assert!(StubMember::connect(&r1, &ca.credential_gen(11, Role::Client, &b_id.fingerprint(), 0), &b_id).await.is_err());
    // …but the new instance's does.
    let b2 = StubMember::connect(&r1, &ca.credential_gen(11, Role::Client, &b_id.fingerprint(), 1), &b_id).await?;
    assert!(attached(&r1, 11).await);
    drop(b2);
    Ok(())
}

#[tokio::test]
async fn a_relay_leaving_the_fleet_loses_its_mesh_link() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let r2 = spawn_relay(&ca, 2, 0);
    link(&r1, &r2, &ca).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r2.net.mesh_peers(), vec![1]);
    // r2's view: the fleet is just r2 now.
    feed(&r2, &[], &[], &[&r2]);
    for _ in 0..30 {
        if r2.net.mesh_peers().is_empty() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("mesh session to a departed relay was not closed");
}

#[tokio::test]
async fn the_dialer_set_follows_the_view() -> Result<()> {
    let ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let r2 = spawn_relay(&ca, 2, 0);
    let r3 = spawn_relay(&ca, 3, 0);
    // r1 learns of r2 and r3: it dials both (lower id dials).
    feed(&r1, &[], &[], &[&r1, &r2, &r3]);
    for _ in 0..50 {
        if r1.net.mesh_peers() == vec![2, 3] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(r1.net.mesh_peers(), vec![2, 3]);
    assert_eq!(r2.net.mesh_peers(), vec![1]);
    // r3 leaves: its dialer is aborted and the link closed.
    feed(&r1, &[], &[], &[&r1, &r2]);
    for _ in 0..50 {
        if r1.net.mesh_peers() == vec![2] {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("dialer/link to a departed relay survived: {:?}", r1.net.mesh_peers());
}

#[tokio::test]
async fn foreign_and_stolen_credentials_are_refused() -> Result<()> {
    let ca = Ca::new();
    let other_ca = Ca::new();
    let r1 = spawn_relay(&ca, 1, 0);
    let id = TlsIdentity::generate("intruder")?;
    assert!(StubMember::connect(&r1, &other_ca.credential(10, Role::Client, &id.fingerprint()), &id).await.is_err());
    let victim = TlsIdentity::generate("victim")?;
    let thief = TlsIdentity::generate("thief")?;
    assert!(StubMember::connect(&r1, &ca.credential(10, Role::Client, &victim.fingerprint()), &thief).await.is_err());
    Ok(())
}
