//! Integration tests for the QUIC control plane (§3.2): authenticated
//! sessions, revisioned push, attachment registry, liveness-bound route
//! withdrawal, and Refresh identity continuity.

use anyhow::Result;
use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::Argon2;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::control;
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState, NetState};
use nqvpn_proto::control::*;
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::api::JoinRequest;
use nqvpn_proto::types::Role;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const SECRET: &str = "s3cret";

fn hash(s: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(s.as_bytes(), &salt).unwrap().to_string()
}

fn net_toml() -> String {
    let h = hash(SECRET);
    format!(
        r#"
network_id = "n1"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/24"
[settings]
keepalive_secs = 1
offline_after = 3
hold_down_secs = 0
[relays.r1]
secret_hash = '{h}'
relay_addr = "1.2.3.4:4444"
allowed_cidrs = ["192.168.1.0/24"]
[relays.r2]
secret_hash = '{h}'
relay_addr = "5.6.7.8:4444"
allowed_cidrs = ["192.168.1.0/24"]
[clients.c1]
secret_hash = '{h}'
"#
    )
}

struct Env {
    state: Arc<AppState>,
    addr: SocketAddr,
    server_fp: String,
    _dir: tempfile::TempDir,
}

async fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig =
        toml::from_str("[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"x\"\n").unwrap();
    let cfg: NetworkConfig = toml::from_str(&net_toml()).unwrap();
    let registry_path = dir.path().join("reg.json");
    let mut networks = HashMap::new();
    networks.insert(
        "n1".to_string(),
        Mutex::new(NetState::new(cfg, Registry::load_or_create(&registry_path).unwrap(), registry_path)),
    );
    let state = Arc::new(AppState {
        coord,
        admin_token: Some("tok".into()),
        networks,
        keyring: Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap(),
        join_rate: Mutex::new(HashMap::new()),
        networks_dir: None,
        secrets: Mutex::new(nqvpn_coord::secrets::SecretStore::default()),
        secrets_path: std::path::PathBuf::from("/nonexistent/secrets.toml"),
    });
    let id = TlsIdentity::generate("coord").unwrap();
    let server_fp = id.fingerprint();
    let endpoint = control::bind("127.0.0.1:0".parse().unwrap(), &id).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let s = state.clone();
    tokio::spawn(async move {
        let _ = control::serve(s, endpoint).await;
    });
    Env { state, addr, server_fp, _dir: dir }
}

/// A minimal member-side control client — the shape `nqvpn-relay` and
/// `nqvpn-client` will use in later phases.
struct Member {
    tx: quinn::SendStream,
    rx: quinn::RecvStream,
    _conn: quinn::Connection,
    id: TlsIdentity,
}

impl Member {
    async fn connect(env: &Env, credential: &str, id: TlsIdentity) -> Result<Member> {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        ep.set_default_client_config(client_config(&id, Some(env.server_fp.clone()), 5).unwrap());
        let conn = ep.connect(env.addr, "coord")?.await?;
        let (mut tx, rx) = conn.open_bi().await?;
        write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string() }).await?;
        Ok(Member { tx, rx, _conn: conn, id })
    }

    async fn next(&mut self) -> Result<(u16, Vec<u8>)> {
        let env = tokio::time::timeout(Duration::from_secs(5), read_envelope(&mut self.rx))
            .await??;
        Ok((env.kind, env.payload))
    }

    /// Read until a message of `kind` arrives (skipping others).
    async fn wait_for(&mut self, kind: Kind) -> Result<Vec<u8>> {
        loop {
            let (k, payload) = self.next().await?;
            if k == kind as u16 {
                return Ok(payload);
            }
        }
    }

    /// The server must tear this session down. Queued pushes may still
    /// arrive first, so drain until the stream errors.
    async fn expect_closed(&mut self) {
        for _ in 0..20 {
            if self.next().await.is_err() {
                return;
            }
        }
        panic!("session stayed open but should have been closed");
    }
}

fn join(env: &Env, name: &str, role: Role, id: &TlsIdentity, cidrs: Vec<&str>) -> (String, u32) {
    let req = JoinRequest {
        network_id: "n1".into(),
        client_id: name.into(),
        client_secret: SECRET.into(),
        pubkey: format!("PK-{name}"),
        role,
        want_vpn_ip: true,
        pool: None,
        preferred_ip4: None,
        preferred_ip6: None,
        local_cidrs: cidrs.iter().map(|c| c.parse().unwrap()).collect(),
        relay_addr: match (role, name) {
            (Role::Relay, "r2") => Some("5.6.7.8:4444".to_string()),
            (Role::Relay, _) => Some("1.2.3.4:4444".to_string()),
            _ => None,
        },
        cert_fingerprint: id.fingerprint(),
    };
    let r = env.state.join(&req, "1.1.1.1").unwrap();
    (r.credential, r.node_id)
}

#[tokio::test]
async fn hello_gets_ack_keyset_and_snapshot() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("c1")?;
    let (cred, node_id) = join(&env, "c1", Role::Client, &id, vec![]);

    let mut m = Member::connect(&env, &cred, id).await?;
    let ack: HelloAck = nqvpn_proto::envelope::decode_payload(&m.wait_for(Kind::HelloAck).await?)?;
    assert!(ack.revision > 0);

    let keys: KeySet = nqvpn_proto::envelope::decode_payload(&m.wait_for(Kind::KeySet).await?)?;
    assert_eq!(keys.keys.len(), 1);
    assert_eq!(keys.keys[0].state, "active");

    let snap: MembershipSnapshot =
        nqvpn_proto::envelope::decode_payload(&m.wait_for(Kind::MembershipSnapshot).await?)?;
    assert_eq!(snap.chunk_n, 1);
    let me = snap.peers.iter().find(|p| p.node_id == node_id).expect("I am in the snapshot");
    assert!(me.online, "my own session marks me online");
    assert!(me.prefixes.iter().any(|p| p.to_string().ends_with("/32")));
    Ok(())
}

#[tokio::test]
async fn bad_credential_and_wrong_cert_are_rejected() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("c1")?;
    let (cred, _) = join(&env, "c1", Role::Client, &id, vec![]);

    // Garbage credential.
    let mut m = Member::connect(&env, "not-a-token", TlsIdentity::generate("x")?).await?;
    m.expect_closed().await;

    // Valid credential presented with a *different* TLS identity: the
    // possession proof fails (this is the stolen-bearer-token case).
    let stolen = TlsIdentity::generate("thief")?;
    let mut m2 = Member::connect(&env, &cred, stolen).await?;
    m2.expect_closed().await;
    Ok(())
}

#[tokio::test]
async fn membership_delta_is_pushed_when_a_peer_joins() -> Result<()> {
    let env = setup().await;
    let rid = TlsIdentity::generate("r1")?;
    let (rcred, _) = join(&env, "r1", Role::Relay, &rid, vec!["192.168.1.0/24"]);
    let mut relay = Member::connect(&env, &rcred, rid).await?;
    relay.wait_for(Kind::MembershipSnapshot).await?;

    // A client joins over HTTP; the live relay session must be told.
    let cid = TlsIdentity::generate("c1")?;
    let (_, c_node) = join(&env, "c1", Role::Client, &cid, vec![]);

    // The relay's own online-transition delta may be queued ahead of the
    // one we care about; read until c1 shows up.
    loop {
        let delta: MembershipDelta =
            nqvpn_proto::envelope::decode_payload(&relay.wait_for(Kind::MembershipDelta).await?)?;
        assert!(delta.new_rev > delta.base_rev);
        if delta.changed.iter().any(|p| p.node_id == c_node) {
            return Ok(());
        }
    }
}

#[tokio::test]
async fn attach_is_relayed_to_relays_only() -> Result<()> {
    let env = setup().await;
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, r1_node) = join(&env, "r1", Role::Relay, &r1id, vec![]);
    let mut r1 = Member::connect(&env, &r1cred, r1id).await?;
    r1.wait_for(Kind::AttachmentSnapshot).await?;

    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, _) = join(&env, "r2", Role::Relay, &r2id, vec![]);
    let mut r2 = Member::connect(&env, &r2cred, r2id).await?;
    r2.wait_for(Kind::AttachmentSnapshot).await?;

    let cid = TlsIdentity::generate("c1")?;
    let (_, c_node) = join(&env, "c1", Role::Client, &cid, vec![]);

    // r1 reports that c1 attached to it.
    write_msg(&mut r1.tx, Kind::Attach, &Attach { node_id: c_node, attached: true }).await?;

    // r2 (a relay) learns the attachment.
    let d: AttachmentDelta =
        nqvpn_proto::envelope::decode_payload(&r2.wait_for(Kind::AttachmentDelta).await?)?;
    assert_eq!(d.changed, vec![AttachmentEntry { node_id: c_node, relay_id: r1_node }]);
    Ok(())
}

#[tokio::test]
async fn client_may_not_send_attach() -> Result<()> {
    let env = setup().await;
    let cid = TlsIdentity::generate("c1")?;
    let (cred, node) = join(&env, "c1", Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, cid).await?;
    c.wait_for(Kind::MembershipSnapshot).await?;
    write_msg(&mut c.tx, Kind::Attach, &Attach { node_id: node, attached: true }).await?;
    c.expect_closed().await;
    Ok(())
}

#[tokio::test]
async fn death_withdraws_routes_and_fails_over() -> Result<()> {
    let env = setup().await;
    // r1 registers the LAN first, so it owns it.
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join(&env, "r1", Role::Relay, &r1id, vec!["192.168.1.0/24"]);
    let mut r1 = Member::connect(&env, &r1cred, r1id).await?;
    r1.wait_for(Kind::MembershipSnapshot).await?;

    // r2 registers the same LAN: standby.
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, r2_node) = join(&env, "r2", Role::Relay, &r2id, vec!["192.168.1.0/24"]);
    let mut r2 = Member::connect(&env, &r2cred, r2id).await?;
    r2.wait_for(Kind::MembershipSnapshot).await?;

    {
        let ns = env.state.networks["n1"].lock().unwrap();
        assert_eq!(ns.directory.owners["192.168.1.0/24"], "r1", "oldest live registrant owns");
    }

    // r1 dies.
    drop(r1);

    // r2's PeerInfo gains the LAN prefix — automatic site failover.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let d: MembershipDelta =
            nqvpn_proto::envelope::decode_payload(&r2.wait_for(Kind::MembershipDelta).await?)?;
        let took_over = d
            .changed
            .iter()
            .any(|p| p.node_id == r2_node && p.prefixes.iter().any(|x| x.to_string() == "192.168.1.0/24"));
        if took_over {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "failover never happened");
    }
    let ns = env.state.networks["n1"].lock().unwrap();
    assert_eq!(ns.directory.owners["192.168.1.0/24"], "r2");
    Ok(())
}

#[tokio::test]
async fn refresh_requires_identity_continuity() -> Result<()> {
    let env = setup().await;
    let c1id = TlsIdentity::generate("c1")?;
    let (c1cred, _) = join(&env, "c1", Role::Client, &c1id, vec![]);
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join(&env, "r1", Role::Relay, &r1id, vec![]);

    let mut c1 = Member::connect(&env, &c1cred, c1id).await?;
    c1.wait_for(Kind::MembershipSnapshot).await?;

    // Refreshing with my own credential is fine.
    write_msg(&mut c1.tx, Kind::Refresh, &Refresh { credential: c1cred.clone() }).await?;
    write_msg(&mut c1.tx, Kind::Ping, &()).await?;

    // Refreshing with *another member's* valid credential must not
    // rebind this session (§3.3 identity continuity).
    write_msg(&mut c1.tx, Kind::Refresh, &Refresh { credential: r1cred }).await?;
    c1.expect_closed().await;
    Ok(())
}

/// A member that stops sending keepalives must be torn down by the
/// liveness sweep — not left "online" until the QUIC idle timeout.
/// (Regression: closing only the writer left the reader, and therefore
/// the member's online state, hanging.)
#[tokio::test]
async fn silent_member_is_reaped_by_liveness_sweep() -> Result<()> {
    let env = setup().await;
    tokio::spawn(control::liveness_sweep(env.state.clone()));

    let cid = TlsIdentity::generate("c1")?;
    let (cred, node) = join(&env, "c1", Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, cid).await?;
    c.wait_for(Kind::MembershipSnapshot).await?;

    // One ping establishes last_seen, then we go silent. keepalive_secs
    // = 1 and offline_after = 3, so the sweep should reap us in ~4 s.
    write_msg(&mut c.tx, Kind::Ping, &()).await?;

    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        {
            let ns = env.state.networks["n1"].lock().unwrap();
            if !ns.directory.peers[&node].online {
                return Ok(());
            }
        }
        assert!(std::time::Instant::now() < deadline, "silent member was never reaped");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Ownership can fall due purely by elapsed time: once a returning
/// older registrant's hold-down expires it must reclaim, even though no
/// membership event occurs at that moment.
#[tokio::test]
async fn hold_down_expiry_reclaims_without_an_event() -> Result<()> {
    let env = setup().await;
    {
        // 2-second hold-down for the test.
        let mut ns = env.state.networks["n1"].lock().unwrap();
        ns.directory.set_hold_down(2);
    }
    tokio::spawn(control::liveness_sweep(env.state.clone()));

    // r1 registers first (older), r2 second.
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join(&env, "r1", Role::Relay, &r1id, vec!["192.168.1.0/24"]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, _) = join(&env, "r2", Role::Relay, &r2id, vec!["192.168.1.0/24"]);

    // Only r2 is online: it owns.
    let mut r2 = Member::connect(&env, &r2cred, r2id).await?;
    r2.wait_for(Kind::MembershipSnapshot).await?;
    {
        let ns = env.state.networks["n1"].lock().unwrap();
        assert_eq!(ns.directory.owners["192.168.1.0/24"], "r2");
    }

    // r1 (older) returns. No further events occur — only time passes.
    let mut r1 = Member::connect(&env, &r1cred, r1id).await?;
    r1.wait_for(Kind::MembershipSnapshot).await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        {
            let ns = env.state.networks["n1"].lock().unwrap();
            if ns.directory.owners["192.168.1.0/24"] == "r1" {
                return Ok(());
            }
        }
        assert!(std::time::Instant::now() < deadline, "hold-down never expired into a reclaim");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// The MTU loop end to end on the wire: a member reports what its
/// uplink can carry, and the coordinator publishes a network-wide value
/// that no hop will drop — naming the member that set the floor.
#[tokio::test]
async fn an_mtu_report_produces_a_network_wide_minimum() -> Result<()> {
    let env = setup().await;
    let aid = TlsIdentity::generate("r1")?;
    let (acred, _) = join(&env, "r1", Role::Relay, &aid, vec![]);
    let mut a = Member::connect(&env, &acred, aid).await?;
    // Every session is told the current MTU at setup.
    let first: NetworkMtu =
        nqvpn_proto::envelope::decode_payload(&a.wait_for(Kind::NetworkMtu).await?)?;
    assert_eq!(first.mtu, 1350, "starts at the configured ceiling");
    assert_eq!(first.limited_by, "config");

    // A second member joins and reports a *smaller* usable MTU.
    let bid = TlsIdentity::generate("c1")?;
    let (bcred, _) = join(&env, "c1", Role::Client, &bid, vec![]);
    let mut b = Member::connect(&env, &bcred, bid).await?;
    b.wait_for(Kind::NetworkMtu).await?;
    write_msg(&mut b.tx, Kind::MtuReport, &MtuReport { usable_mtu: 1300 }).await?;

    // Both members must learn the new floor, not just the one that
    // reported it — otherwise the other keeps sending oversized packets.
    for m in [&mut a, &mut b] {
        let got: NetworkMtu =
            nqvpn_proto::envelope::decode_payload(&m.wait_for(Kind::NetworkMtu).await?)?;
        assert_eq!(got.mtu, 1300, "the network drops to the smallest uplink");
        assert_eq!(got.limited_by, "c1", "and says which member set it");
    }
    Ok(())
}

/// A member that leaves must stop constraining everyone else, or one
/// departed laptop pins the whole network to its old uplink forever.
#[tokio::test]
async fn a_departing_member_stops_limiting_the_mtu() -> Result<()> {
    let env = setup().await;
    let aid = TlsIdentity::generate("r1")?;
    let (acred, _) = join(&env, "r1", Role::Relay, &aid, vec![]);
    let mut a = Member::connect(&env, &acred, aid).await?;
    a.wait_for(Kind::NetworkMtu).await?;

    let bid = TlsIdentity::generate("c1")?;
    let (bcred, _) = join(&env, "c1", Role::Client, &bid, vec![]);
    let mut b = Member::connect(&env, &bcred, bid).await?;
    b.wait_for(Kind::NetworkMtu).await?;
    write_msg(&mut b.tx, Kind::MtuReport, &MtuReport { usable_mtu: 1290 }).await?;

    loop {
        let m: NetworkMtu =
            nqvpn_proto::envelope::decode_payload(&a.wait_for(Kind::NetworkMtu).await?)?;
        if m.mtu == 1290 {
            break;
        }
    }
    drop(b); // the constrained member goes away

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let m: NetworkMtu =
            nqvpn_proto::envelope::decode_payload(&a.wait_for(Kind::NetworkMtu).await?)?;
        if m.mtu == 1350 && m.limited_by == "config" {
            return Ok(());
        }
        assert!(std::time::Instant::now() < deadline, "MTU never recovered: {m:?}");
    }
}

#[tokio::test]
async fn disconnect_marks_offline() -> Result<()> {
    let env = setup().await;
    let cid = TlsIdentity::generate("c1")?;
    let (cred, node) = join(&env, "c1", Role::Client, &cid, vec![]);
    let c = Member::connect(&env, &cred, cid).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let ns = env.state.networks["n1"].lock().unwrap();
        assert!(ns.directory.peers[&node].online);
    }
    drop(c);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        {
            let ns = env.state.networks["n1"].lock().unwrap();
            if !ns.directory.peers[&node].online {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "never went offline");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(())
}

/// The RPC layer over a real control session.
///
/// The unit tests in `nqvpn-proto` wire two peers to each other in
/// memory. This checks the part they cannot: that requests survive the
/// actual QUIC stream, share it with the coordinator's pushes without
/// either corrupting the other, and come back correlated.
#[tokio::test]
async fn rpc_api_versions_over_a_real_control_session() -> Result<()> {
    use nqvpn_proto::envelope::{decode_payload, encode_msg};
    use nqvpn_proto::rpc::{ApiVersions, Request, Response, VerbSupport, verb};

    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let (cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);
    let mut m = Member::connect(&env, &cred, id).await?;

    // Ask the coordinator what it implements. Sent by hand rather than
    // through RpcPeer so the test pins the actual bytes on the wire.
    let req = Request { req_id: 77, verb: verb::API_VERSIONS, version: 1, payload: Vec::new() };
    let bytes = encode_msg(Kind::Request, &req)?;
    m.tx.write_all(&bytes).await?;

    // The reply has to be found among the membership pushes that arrive
    // unprompted on the same stream — which is the real test.
    let payload = m.wait_for(Kind::Response).await?;
    let resp: Response = decode_payload(&payload)?;
    assert_eq!(resp.req_id, 77, "reply must carry the request id");
    assert_eq!(resp.code, None, "api_versions must succeed");
    let versions: ApiVersions = decode_payload(&resp.payload)?;
    assert!(
        versions.verbs.contains(&VerbSupport { verb: verb::API_VERSIONS, min: 1, max: 1 }),
        "api_versions must always advertise itself, got {:?}",
        versions.verbs
    );

    // An unknown verb is answered, and the session keeps working after —
    // the property that makes adding verbs safe.
    let req = Request { req_id: 78, verb: 60000, version: 1, payload: Vec::new() };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;
    let payload = m.wait_for(Kind::Response).await?;
    let resp: Response = decode_payload(&payload)?;
    assert_eq!(resp.req_id, 78);
    assert_eq!(resp.code.as_deref(), Some("unsupported_verb"));

    // Still alive: a Ping must still be accepted afterwards.
    write_msg(&mut m.tx, Kind::Ping, &()).await?;
    let req = Request { req_id: 79, verb: verb::API_VERSIONS, version: 1, payload: Vec::new() };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;
    let payload = m.wait_for(Kind::Response).await?;
    let resp: Response = decode_payload(&payload)?;
    assert_eq!(resp.req_id, 79, "session must survive an unknown verb");
    Ok(())
}

/// Identity rotation over the control session.
///
/// The security-critical property is the overlap: after rotating, *both*
/// identities must authenticate until the window closes, so a member that
/// crashes before switching is not locked out and forced through an admin
/// `reset-pin` — the one operation that reopens the trust window.
#[tokio::test]
async fn rotate_identity_keeps_the_old_key_working_during_the_overlap() -> Result<()> {
    use nqvpn_proto::envelope::{decode_payload, encode_msg, encode_payload};
    use nqvpn_proto::rpc::{Request, Response, RotateIdentity, RotateIdentityOk, verb};

    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let old_fp = id.fingerprint();
    let (cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);
    let mut m = Member::connect(&env, &cred, id.clone()).await?;

    // A second identity, as a member would generate before rotating.
    let new_id = TlsIdentity::generate("r1-rotated").unwrap();
    let new_fp = new_id.fingerprint();
    assert_ne!(old_fp, new_fp);

    let body = encode_payload(&RotateIdentity {
        new_pubkey: String::new(), // leave the Noise key alone
        new_cert_fp: new_fp.clone(),
    })?;
    let req = Request { req_id: 1, verb: verb::ROTATE_IDENTITY, version: 1, payload: body };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;

    let payload = m.wait_for(Kind::Response).await?;
    let resp: Response = decode_payload(&payload)?;
    assert_eq!(resp.code, None, "rotation should succeed: {:?}", resp.code);
    let ok: RotateIdentityOk = decode_payload(&resp.payload)?;
    assert!(ok.old_retires_unix > now_unix(), "the overlap must be in the future");

    // Both fingerprints authenticate right now.
    {
        let ns = env.state.networks.get("n1").unwrap().lock().unwrap();
        let rec = ns.registry.members.get("r1").expect("member");
        let now = now_unix();
        assert!(rec.cert_fps.accepts(&new_fp, now), "new identity must be accepted");
        assert!(
            rec.cert_fps.accepts(&old_fp, now),
            "old identity must still work — a member that crashes mid-rotation \
             must not need an admin reset-pin"
        );
        // ...and the old one really does expire.
        assert!(!rec.cert_fps.accepts(&old_fp, ok.old_retires_unix));
        // The advertised pin follows the new identity, since that is what
        // dialers verify against.
        assert_eq!(rec.cert_fp.as_deref(), Some(new_fp.as_str()));
    }

    // Rejoining with the OLD identity still works during the overlap.
    let (cred2, _) = join(&env, "r1", Role::Relay, &id, vec![]);
    assert!(!cred2.is_empty(), "old identity must still be able to join");
    Ok(())
}

/// Rejoining with the new identity retires the old one immediately —
/// once the member demonstrably holds the new key, leaving the old one
/// valid for the rest of the window only widens the exposure.
#[tokio::test]
async fn using_the_new_identity_retires_the_old_one_early() -> Result<()> {
    use nqvpn_proto::envelope::{encode_msg, encode_payload};
    use nqvpn_proto::rpc::{Request, RotateIdentity, verb};

    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let old_fp = id.fingerprint();
    let (cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);
    let mut m = Member::connect(&env, &cred, id).await?;

    let new_id = TlsIdentity::generate("r1-rotated").unwrap();
    let new_fp = new_id.fingerprint();
    let body = encode_payload(&RotateIdentity {
        new_pubkey: String::new(),
        new_cert_fp: new_fp.clone(),
    })?;
    let req = Request { req_id: 1, verb: verb::ROTATE_IDENTITY, version: 1, payload: body };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;
    let _ = m.wait_for(Kind::Response).await?;

    // Join with the new identity: that confirms it is in use.
    let (_cred, _) = join(&env, "r1", Role::Relay, &new_id, vec![]);
    {
        let ns = env.state.networks.get("n1").unwrap().lock().unwrap();
        let rec = ns.registry.members.get("r1").expect("member");
        assert!(rec.cert_fps.accepts(&new_fp, now_unix()));
        assert!(
            !rec.cert_fps.accepts(&old_fp, now_unix()),
            "the old identity should retire as soon as the new one is seen in use"
        );
    }
    Ok(())
}

/// An unrelated third key must never authenticate — rotation widens the
/// accepted set deliberately, and only to keys the member registered.
#[tokio::test]
async fn rotation_does_not_accept_an_unregistered_key() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let (_cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);

    let stranger = TlsIdentity::generate("attacker").unwrap();
    let ns = env.state.networks.get("n1").unwrap().lock().unwrap();
    let rec = ns.registry.members.get("r1").expect("member");
    assert!(
        !rec.cert_fps.accepts(&stranger.fingerprint(), now_unix()),
        "only registered identities may authenticate"
    );
    Ok(())
}

/// A peer speaking a different protocol version is refused at Hello.
///
/// The check exists because the previous framing change desynced
/// silently: both sides stayed connected and simply misread each other.
/// A refusal that names both versions is the difference between a
/// five-minute diagnosis and an afternoon.
#[tokio::test]
async fn a_wrong_protocol_version_is_refused_at_hello() -> Result<()> {
    use nqvpn_proto::envelope::{Envelope, PROTO_MINOR};

    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let (cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);

    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    ep.set_default_client_config(client_config(&id, Some(env.server_fp.clone()), 5).unwrap());
    let conn = ep.connect(env.addr, "coord")?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;

    // A Hello from a peer one minor version ahead.
    let payload = nqvpn_proto::envelope::encode_payload(&Hello { credential: cred })?;
    let mut wrong = Envelope::new(Kind::Hello, payload);
    wrong.minor = PROTO_MINOR.wrapping_add(1);
    tx.write_all(&wrong.encode()).await?;

    // The session must not proceed: reading yields an error rather than
    // the HelloAck a compatible peer would get.
    let outcome = tokio::time::timeout(Duration::from_secs(5), read_envelope(&mut rx)).await?;
    assert!(
        outcome.is_err(),
        "a version-mismatched peer must be refused, but the session continued"
    );
    Ok(())
}

/// ...and the ordinary case still works, so the check is not simply
/// rejecting everything.
#[tokio::test]
async fn a_matching_protocol_version_is_accepted() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("r1").unwrap();
    let (cred, _node) = join(&env, "r1", Role::Relay, &id, vec![]);
    let mut m = Member::connect(&env, &cred, id).await?;
    m.wait_for(Kind::HelloAck).await?;
    Ok(())
}
