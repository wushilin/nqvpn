//! Integration tests for the QUIC control plane (§3.2): authenticated
//! sessions, the generation-numbered view, heartbeat leases, catch-up
//! by delta or snapshot, replacement, and liveness-bound routes.

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::control;
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState};
use nqvpn_proto::api::JoinRequest;
use nqvpn_proto::control::*;
use nqvpn_proto::envelope::{decode_payload, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::types::{NodeId, Role};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;


fn net_toml() -> String {
    r#"
network_id = "n1"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/24"
[settings]
heartbeat_secs = 1
offline_after = 3
hold_down_secs = 0
restart_grace_secs = 2
[relays.r1]
secret = "s-r1"
relay_addr = "1.2.3.4:4444"
local_cidrs = ["192.168.1.0/24"]
[relays.r2]
secret = "s-r2"
relay_addr = "5.6.7.8:4444"
local_cidrs = ["192.168.1.0/24"]
[clients.c1]
secret = "s-c1"
[clients.c2]
secret = "s-c2"
"#.to_string()
}

struct Env {
    state: Arc<AppState>,
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn setup() -> Env {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig =
        toml::from_str("[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"x\"\n").unwrap();
    let cfg: NetworkConfig = toml::from_str(&net_toml()).unwrap();
    let db = Arc::new(nqvpn_coord::db::Db::open_memory().unwrap());
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let state = Arc::new(AppState::new(coord, Some("tok".into()), keyring, db.clone(), 0));
    let reg = Registry::new();
    db.save_network_and_registry(&cfg, &reg).unwrap();
    let ns = state.add_network(cfg, reg);
    // Tests are not a restart: skip the collect-before-publish grace.
    ns.lock().unwrap().started_at = 0;
    let id = TlsIdentity::generate("coord").unwrap();
    let endpoint = control::bind("127.0.0.1:0".parse().unwrap(), &id).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let s = state.clone();
    tokio::spawn(async move {
        let _ = control::serve(s, endpoint).await;
    });
    Env { state, addr, _dir: dir }
}

/// A minimal member-side control client.
struct Member {
    tx: quinn::SendStream,
    rx: quinn::RecvStream,
    _conn: quinn::Connection,
    _ep: quinn::Endpoint,
}

impl Member {
    async fn connect(env: &Env, credential: &str, id: &TlsIdentity, have_gen: u64) -> Result<Member> {
        let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        ep.set_default_client_config(client_config(id, None, 5).unwrap());
        let conn = ep.connect(env.addr, "coord")?.await?;
        let (mut tx, rx) = conn.open_bi().await?;
        write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string(), have_gen }).await?;
        Ok(Member { tx, rx, _conn: conn, _ep: ep })
    }

    async fn next(&mut self) -> Result<(u16, Vec<u8>)> {
        let env = tokio::time::timeout(Duration::from_secs(5), read_envelope(&mut self.rx)).await??;
        Ok((env.kind, env.payload))
    }

    async fn wait_for(&mut self, kind: Kind) -> Result<Vec<u8>> {
        loop {
            let (k, payload) = self.next().await?;
            if k == kind as u16 {
                return Ok(payload);
            }
        }
    }

    async fn snapshot(&mut self) -> Result<Snapshot> {
        Ok(decode_payload(&self.wait_for(Kind::Snapshot).await?)?)
    }

    /// Apply pushes until `pred` holds on the tracked view.
    async fn until(&mut self, view: &mut Snapshot, pred: impl Fn(&Snapshot) -> bool) -> Result<()> {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !pred(view) {
            anyhow::ensure!(std::time::Instant::now() < deadline, "condition never held; view = {view:?}");
            let (k, payload) = self.next().await?;
            if k == Kind::Snapshot as u16 {
                *view = decode_payload(&payload)?;
            } else if k == Kind::Delta as u16 {
                let d: Delta = decode_payload(&payload)?;
                view.apply(&d)?;
            }
        }
        Ok(())
    }

    async fn heartbeat(&mut self, hb: &Heartbeat) -> Result<()> {
        write_msg(&mut self.tx, Kind::Heartbeat, hb).await?;
        Ok(())
    }

    async fn expect_closed(&mut self) {
        for _ in 0..30 {
            if self.next().await.is_err() {
                return;
            }
        }
        panic!("session stayed open but should have been closed");
    }
}

fn hb_of(view: &Snapshot) -> Heartbeat {
    Heartbeat { gen: view.gen, digest: view.digest(), ..Default::default() }
}

fn join_as(env: &Env, node_id: NodeId, role: Role, id: &TlsIdentity, cidrs: Vec<&str>) -> (String, u32) {
    let name = match node_id {
        1 => "r1",
        2 => "r2",
        10 => "c1",
        11 => "c2",
        _ => panic!("unknown test member"),
    };
    // Routes are configured at the coordinator, not requested.
    if role == Role::Relay {
        let net = env.state.net("n1").unwrap();
        let mut spec = {
            let ns = net.lock().unwrap();
            nqvpn_coord::admin::MemberSpec::from_cfg(ns.cfg.member_by_name(name).unwrap().0)
        };
        spec.local_cidrs = cidrs.iter().map(|c| c.parse().unwrap()).collect();
        env.state.update_member("n1", name, &spec).unwrap();
    }
    let req = JoinRequest { secret: format!("s-{name}"), pubkey: B64.encode([node_id as u8; 32]), cert_fingerprint: id.fingerprint() };
    let r = env.state.join(&req, "1.1.1.1").unwrap();
    (r.credential, r.node_id)
}

fn attached(pairs: &[(NodeId, u64)]) -> Vec<AttachedClient> {
    pairs.iter().map(|(n, s)| AttachedClient { node_id: *n, session_id: *s }).collect()
}

#[tokio::test]
async fn hello_gets_ack_and_a_snapshot_that_matches_the_digest() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("c1")?;
    let (cred, node) = join_as(&env, 10, Role::Client, &id, vec![]);
    let mut m = Member::connect(&env, &cred, &id, 0).await?;
    let ack: HelloAck = decode_payload(&m.wait_for(Kind::HelloAck).await?)?;
    let snap = m.snapshot().await?;
    assert_eq!(snap.gen, ack.gen);
    let me = snap.member(node).expect("I am in the snapshot");
    assert!(me.online);
    assert!(me.prefixes.iter().any(|p| p.to_string().ends_with("/32")));
    assert_eq!(snap.keys.len(), 1);
    assert_eq!(snap.mtu.mtu, 1350);
    let net = env.state.net("n1").unwrap();
    let ns = net.lock().unwrap();
    assert_eq!(snap.digest(), ns.directory.published_digest, "member and coordinator agree bit for bit");
    Ok(())
}

#[tokio::test]
async fn bad_credential_and_wrong_cert_are_rejected() -> Result<()> {
    let env = setup().await;
    let id = TlsIdentity::generate("c1")?;
    let (cred, _) = join_as(&env, 10, Role::Client, &id, vec![]);
    let mut m = Member::connect(&env, "not-a-token", &TlsIdentity::generate("x")?, 0).await?;
    m.expect_closed().await;
    // Valid credential, different TLS key: the possession proof fails.
    let mut m2 = Member::connect(&env, &cred, &TlsIdentity::generate("thief")?, 0).await?;
    m2.expect_closed().await;
    Ok(())
}

#[tokio::test]
async fn a_change_is_pushed_as_a_delta_that_applies_cleanly() -> Result<()> {
    let env = setup().await;
    let rid = TlsIdentity::generate("r1")?;
    let (rcred, _) = join_as(&env, 1, Role::Relay, &rid, vec!["192.168.1.0/24"]);
    let mut relay = Member::connect(&env, &rcred, &rid, 0).await?;
    let mut view = relay.snapshot().await?;

    let cid = TlsIdentity::generate("c1")?;
    let (_, c_node) = join_as(&env, 10, Role::Client, &cid, vec![]);
    relay.until(&mut view, |v| v.member(c_node).is_some()).await?;
    let (gen, digest) = {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        (ns.directory.gen, ns.directory.published_digest)
    };
    assert_eq!(view.gen, gen);
    assert_eq!(view.digest(), digest, "deltas reproduce the coordinator's view exactly");
    Ok(())
}

#[tokio::test]
async fn a_relay_declares_attachments_as_a_set_and_moves_win_by_recency() -> Result<()> {
    let env = setup().await;
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join_as(&env, 1, Role::Relay, &r1id, vec![]);
    let mut r1 = Member::connect(&env, &r1cred, &r1id, 0).await?;
    let mut v1 = r1.snapshot().await?;
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, _) = join_as(&env, 2, Role::Relay, &r2id, vec![]);
    let mut r2 = Member::connect(&env, &r2cred, &r2id, 0).await?;
    let mut v2 = r2.snapshot().await?;
    let cid = TlsIdentity::generate("c1")?;
    let (ccred, c) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut client = Member::connect(&env, &ccred, &cid, 0).await?;
    let _ = client.snapshot().await?;

    // r1 holds the client.
    let mut h = hb_of(&v1);
    h.attached = attached(&[(c, 1)]);
    r1.heartbeat(&h).await?;
    r2.until(&mut v2, |v| v.attachment_of(c) == Some(1)).await?;

    // The client moves to r2; r1's stale session still lists it.
    let mut h2 = hb_of(&v2);
    h2.attached = attached(&[(c, 7)]);
    r2.heartbeat(&h2).await?;
    r1.until(&mut v1, |v| v.attachment_of(c) == Some(2)).await?;
    let mut h = hb_of(&v1);
    h.attached = attached(&[(c, 1)]);
    r1.heartbeat(&h).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        assert_eq!(ns.directory.published.attachment_of(c), Some(2), "a repeated stale declaration does not win");
    }

    // r1's stale session ends: it simply stops declaring. Nothing to detach.
    let mut h = hb_of(&v1);
    h.attached = vec![];
    r1.heartbeat(&h).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let net = env.state.net("n1").unwrap();
    let ns = net.lock().unwrap();
    assert_eq!(ns.directory.published.attachment_of(c), Some(2));
    Ok(())
}

#[tokio::test]
async fn a_client_heartbeat_cannot_declare_attachments() -> Result<()> {
    let env = setup().await;
    let cid = TlsIdentity::generate("c1")?;
    let (cred, node) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, &cid, 0).await?;
    let view = c.snapshot().await?;
    let mut h = hb_of(&view);
    h.attached = attached(&[(node, 1)]);
    c.heartbeat(&h).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let net = env.state.net("n1").unwrap();
    let ns = net.lock().unwrap();
    assert!(ns.directory.published.attachments.is_empty(), "only relays hold clients");
    assert!(ns.sessions.contains_key(&node), "and it is not fatal");
    Ok(())
}

#[tokio::test]
async fn death_withdraws_routes_and_fails_over() -> Result<()> {
    let env = setup().await;
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join_as(&env, 1, Role::Relay, &r1id, vec!["192.168.1.0/24"]);
    let r1 = Member::connect(&env, &r1cred, &r1id, 0).await?;
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, r2_node) = join_as(&env, 2, Role::Relay, &r2id, vec!["192.168.1.0/24"]);
    let mut r2 = Member::connect(&env, &r2cred, &r2id, 0).await?;
    let mut view = r2.snapshot().await?;
    {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        assert_eq!(ns.directory.owners["192.168.1.0/24"], 1, "oldest live registrant owns");
    }
    drop(r1);
    r2.until(&mut view, |v| {
        v.member(r2_node).map(|p| p.prefixes.iter().any(|x| x.to_string() == "192.168.1.0/24")).unwrap_or(false)
    })
    .await?;
    let net = env.state.net("n1").unwrap();
    let ns = net.lock().unwrap();
    assert_eq!(ns.directory.owners["192.168.1.0/24"], 2);
    Ok(())
}

#[tokio::test]
async fn a_relay_losing_its_control_link_keeps_its_attachments() -> Result<()> {
    let env = setup().await;
    tokio::spawn(control::liveness_sweep(env.state.clone()));
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join_as(&env, 1, Role::Relay, &r1id, vec![]);
    let mut r1 = Member::connect(&env, &r1cred, &r1id, 0).await?;
    let v1 = r1.snapshot().await?;
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, _) = join_as(&env, 2, Role::Relay, &r2id, vec![]);
    let mut r2 = Member::connect(&env, &r2cred, &r2id, 0).await?;
    let mut v2 = r2.snapshot().await?;
    let cid = TlsIdentity::generate("c1")?;
    let (ccred, c) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut client = Member::connect(&env, &ccred, &cid, 0).await?;
    let mut cv = client.snapshot().await?;

    let mut h = hb_of(&v1);
    h.attached = attached(&[(c, 1)]);
    r1.heartbeat(&h).await?;
    r2.until(&mut v2, |v| v.attachment_of(c) == Some(1)).await?;

    // r1's control link dies. The client keeps heartbeating.
    drop(r1);
    for _ in 0..6 {
        client.heartbeat(&hb_of(&cv)).await?;
        tokio::time::sleep(Duration::from_millis(700)).await;
        // drain pushes so the client's view stays current
        client.until(&mut cv, |_| true).await?;
    }
    {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        assert!(!ns.leases.is_online(1), "the relay is offline to the coordinator");
        assert!(ns.leases.is_online(c), "the client is not");
        assert_eq!(ns.directory.published.attachment_of(c), Some(1), "so its attachment outlives the relay's lease");
    }

    // The client's own control link going silent changes nothing either:
    // the relay holds its session, and only the relay's word ends it.
    drop(client);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let (online, att) = {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        (ns.leases.is_online(c), ns.directory.published.attachment_of(c))
    };
    assert!(!online);
    assert_eq!(att, Some(1), "still attached: the relay never stopped declaring it");
    Ok(())
}

#[tokio::test]
async fn silent_member_is_reaped_by_liveness_sweep() -> Result<()> {
    let env = setup().await;
    tokio::spawn(control::liveness_sweep(env.state.clone()));
    let cid = TlsIdentity::generate("c1")?;
    let (cred, node) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, &cid, 0).await?;
    let view = c.snapshot().await?;
    c.heartbeat(&hb_of(&view)).await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        {
            let net = env.state.net("n1").unwrap();
            let ns = net.lock().unwrap();
            if !ns.directory.published.member(node).unwrap().online {
                assert!(!ns.sessions.contains_key(&node), "and the session was closed");
                return Ok(());
            }
        }
        assert!(std::time::Instant::now() < deadline, "silent member was never reaped");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test]
async fn hold_down_expiry_reclaims_without_an_event() -> Result<()> {
    let env = setup().await;
    env.state.net("n1").unwrap().lock().unwrap().directory.hold_down_secs = 2;
    tokio::spawn(control::liveness_sweep(env.state.clone()));
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join_as(&env, 1, Role::Relay, &r1id, vec!["192.168.1.0/24"]);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r2id = TlsIdentity::generate("r2")?;
    let (r2cred, _) = join_as(&env, 2, Role::Relay, &r2id, vec!["192.168.1.0/24"]);
    let mut r2 = Member::connect(&env, &r2cred, &r2id, 0).await?;
    let v2 = r2.snapshot().await?;
    assert_eq!(env.state.net("n1").unwrap().lock().unwrap().directory.owners["192.168.1.0/24"], 2);
    let mut r1 = Member::connect(&env, &r1cred, &r1id, 0).await?;
    let v1 = r1.snapshot().await?;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        r1.heartbeat(&hb_of(&v1)).await?;
        r2.heartbeat(&hb_of(&v2)).await?;
        if env.state.net("n1").unwrap().lock().unwrap().directory.owners["192.168.1.0/24"] == 1 {
            return Ok(());
        }
        assert!(std::time::Instant::now() < deadline, "hold-down never expired into a reclaim");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

#[tokio::test]
async fn mtu_is_the_network_minimum_and_recovers_when_the_limiter_leaves() -> Result<()> {
    let env = setup().await;
    let aid = TlsIdentity::generate("r1")?;
    let (acred, _) = join_as(&env, 1, Role::Relay, &aid, vec![]);
    let mut a = Member::connect(&env, &acred, &aid, 0).await?;
    let mut av = a.snapshot().await?;
    assert_eq!(av.mtu.mtu, 1350);
    let bid = TlsIdentity::generate("c1")?;
    let (bcred, b_node) = join_as(&env, 10, Role::Client, &bid, vec![]);
    let mut b = Member::connect(&env, &bcred, &bid, 0).await?;
    let bv = b.snapshot().await?;
    let mut h = hb_of(&bv);
    h.usable_mtu = 1300;
    b.heartbeat(&h).await?;
    a.until(&mut av, |v| v.mtu.mtu == 1300).await?;
    assert_eq!(av.mtu.limited_by, format!("#{b_node}"));
    drop(b);
    a.until(&mut av, |v| v.mtu.mtu == 1350).await?;
    assert_eq!(av.mtu.limited_by, "config");
    Ok(())
}

#[tokio::test]
async fn a_member_behind_is_caught_up_by_deltas_and_a_stranger_by_snapshot() -> Result<()> {
    let env = setup().await;
    let cid = TlsIdentity::generate("c1")?;
    let (cred, _) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, &cid, 0).await?;
    let mut view = c.snapshot().await?;
    let g0 = view.gen;

    // Two changes happen while we are away.
    drop(c);
    let r1id = TlsIdentity::generate("r1")?;
    join_as(&env, 1, Role::Relay, &r1id, vec![]);
    let r2id = TlsIdentity::generate("r2")?;
    join_as(&env, 2, Role::Relay, &r2id, vec![]);

    // Reconnect saying what we hold: deltas, not a snapshot.
    let mut c = Member::connect(&env, &cred, &cid, g0).await?;
    let (k, payload) = c.next().await?;
    assert_eq!(k, Kind::HelloAck as u16);
    let (k, payload2) = c.next().await?;
    assert_eq!(k, Kind::Delta as u16, "a known generation is caught up by deltas");
    let d: Delta = decode_payload(&payload2)?;
    assert_eq!(d.base_gen, g0);
    view.apply(&d)?;
    let st = env.state.clone();
    let (r1n, r2n) = {
        let net = st.net("n1").unwrap();
        let ns = net.lock().unwrap();
        (ns.registry.id_of("r1").unwrap(), ns.registry.id_of("r2").unwrap())
    };
    c.until(&mut view, |v| {
        let net = st.net("n1").unwrap();
        let ns = net.lock().unwrap();
        v.gen == ns.directory.gen && v.member(r1n).is_some() && v.member(r2n).is_some()
    })
    .await?;
    let _ = payload;
    {
        let net = env.state.net("n1").unwrap();
        let ns = net.lock().unwrap();
        assert_eq!(view.digest(), ns.directory.published_digest);
    }

    // A heartbeat claiming an unknown generation gets a snapshot.
    let mut h = hb_of(&view);
    h.gen = 12345;
    c.heartbeat(&h).await?;
    let snap = c.snapshot().await?;
    assert_eq!(snap.digest(), view.digest());

    // Same generation, different digest: a bug — resynced, and loudly.
    let mut h = hb_of(&view);
    h.digest ^= 1;
    c.heartbeat(&h).await?;
    let snap = c.snapshot().await?;
    assert_eq!(snap.gen, view.gen);

    // An explicit Resync works the same way.
    write_msg(&mut c.tx, Kind::Resync, &Resync { have_gen: 0 }).await?;
    c.snapshot().await?;
    Ok(())
}

#[tokio::test]
async fn a_replaced_instance_is_closed_and_refused() -> Result<()> {
    let env = setup().await;
    let old_id = TlsIdentity::generate("laptop-old")?;
    let (old_cred, node) = join_as(&env, 10, Role::Client, &old_id, vec![]);
    let mut old = Member::connect(&env, &old_cred, &old_id, 0).await?;
    old.snapshot().await?;

    // A different machine joins as the same node.
    let new_id = TlsIdentity::generate("laptop-new")?;
    let (new_cred, _) = join_as(&env, 10, Role::Client, &new_id, vec![]);
    old.expect_closed().await;
    // Its credential no longer opens a session, even before expiry.
    let mut again = Member::connect(&env, &old_cred, &old_id, 0).await?;
    again.expect_closed().await;
    // The new instance is fine, and everyone sees the new login_gen.
    let mut new = Member::connect(&env, &new_cred, &new_id, 0).await?;
    let snap = new.snapshot().await?;
    assert_eq!(snap.member(node).unwrap().login_gen, 1);
    Ok(())
}

#[tokio::test]
async fn disabling_evicts_the_member_everywhere() -> Result<()> {
    let env = setup().await;
    let rid = TlsIdentity::generate("r1")?;
    let (rcred, _) = join_as(&env, 1, Role::Relay, &rid, vec![]);
    let mut relay = Member::connect(&env, &rcred, &rid, 0).await?;
    let mut rv = relay.snapshot().await?;
    let cid = TlsIdentity::generate("c1")?;
    let (ccred, node) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &ccred, &cid, 0).await?;
    c.snapshot().await?;
    relay.until(&mut rv, |v| v.member(node).is_some()).await?;

    {
        let net = env.state.net("n1").unwrap();
        let mut ns = net.lock().unwrap();
        ns.registry.members.get_mut(&node).unwrap().disabled = true;
        ns.close_session(node, "disabled");
        ns.leases.remove(node);
        env.state.publish(&mut ns);
    }
    c.expect_closed().await;
    relay.until(&mut rv, |v| v.member(node).is_none()).await?;
    let mut again = Member::connect(&env, &ccred, &cid, 0).await?;
    again.expect_closed().await;
    Ok(())
}

#[tokio::test]
async fn refresh_extends_the_session_but_never_rebinds_it() -> Result<()> {
    let env = setup().await;
    let c1id = TlsIdentity::generate("c1")?;
    let (c1cred, node) = join_as(&env, 10, Role::Client, &c1id, vec![]);
    let r1id = TlsIdentity::generate("r1")?;
    let (r1cred, _) = join_as(&env, 1, Role::Relay, &r1id, vec![]);
    let mut c1 = Member::connect(&env, &c1cred, &c1id, 0).await?;
    let view = c1.snapshot().await?;
    let exp_before = env.state.net("n1").unwrap().lock().unwrap().sessions[&node].exp;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (renewed, _) = join_as(&env, 10, Role::Client, &c1id, vec![]);
    write_msg(&mut c1.tx, Kind::Refresh, &Refresh { credential: renewed }).await?;
    c1.heartbeat(&hb_of(&view)).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(env.state.net("n1").unwrap().lock().unwrap().sessions[&node].exp > exp_before);
    write_msg(&mut c1.tx, Kind::Refresh, &Refresh { credential: r1cred }).await?;
    c1.expect_closed().await;
    Ok(())
}

#[tokio::test]
async fn a_restarted_coordinator_collects_before_publishing() -> Result<()> {
    let env = setup().await;
    env.state.net("n1").unwrap().lock().unwrap().started_at = now_unix(); // grace = restart_grace_secs = 2 s
    let cid = TlsIdentity::generate("c1")?;
    let (cred, _) = join_as(&env, 10, Role::Client, &cid, vec![]);
    let mut c = Member::connect(&env, &cred, &cid, 0).await?;
    let (k, _) = c.next().await?;
    assert_eq!(k, Kind::HelloAck as u16);
    // Nothing else during the grace; the member keeps its old view.
    assert!(tokio::time::timeout(Duration::from_millis(800), c.next()).await.is_err());
    tokio::time::sleep(Duration::from_millis(1500)).await;
    c.heartbeat(&Heartbeat::default()).await?;
    c.snapshot().await?;
    Ok(())
}

#[tokio::test]
async fn rpc_api_versions_over_a_real_control_session() -> Result<()> {
    use nqvpn_proto::envelope::encode_msg;
    use nqvpn_proto::rpc::{verb, ApiVersions, Request, Response, VerbSupport};
    let env = setup().await;
    let id = TlsIdentity::generate("r1")?;
    let (cred, _) = join_as(&env, 1, Role::Relay, &id, vec![]);
    let mut m = Member::connect(&env, &cred, &id, 0).await?;
    let req = Request { req_id: 77, verb: verb::API_VERSIONS, version: 1, payload: Vec::new() };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;
    let resp: Response = decode_payload(&m.wait_for(Kind::Response).await?)?;
    assert_eq!(resp.req_id, 77);
    let versions: ApiVersions = decode_payload(&resp.payload)?;
    assert!(versions.verbs.contains(&VerbSupport { verb: verb::API_VERSIONS, min: 1, max: 1 }));
    let req = Request { req_id: 78, verb: 60000, version: 1, payload: Vec::new() };
    m.tx.write_all(&encode_msg(Kind::Request, &req)?).await?;
    let resp: Response = decode_payload(&m.wait_for(Kind::Response).await?)?;
    assert_eq!(resp.code.as_deref(), Some("unsupported_verb"), "answered, not fatal");
    Ok(())
}

#[tokio::test]
async fn a_wrong_protocol_version_is_refused_at_hello() -> Result<()> {
    use nqvpn_proto::envelope::{Envelope, PROTO_MINOR};
    let env = setup().await;
    let id = TlsIdentity::generate("r1")?;
    let (cred, _) = join_as(&env, 1, Role::Relay, &id, vec![]);
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    ep.set_default_client_config(client_config(&id, None, 5).unwrap());
    let conn = ep.connect(env.addr, "coord")?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    let payload = nqvpn_proto::envelope::encode_payload(&Hello { credential: cred, have_gen: 0 })?;
    let mut wrong = Envelope::new(Kind::Hello, payload);
    wrong.minor = PROTO_MINOR.wrapping_add(1);
    tx.write_all(&wrong.encode()).await?;
    let outcome = tokio::time::timeout(Duration::from_secs(5), read_envelope(&mut rx)).await?;
    assert!(outcome.is_err(), "a version-mismatched peer must be refused");
    Ok(())
}

// ---- restart storm: what a fleet reconnecting actually costs ----

/// A coordinator serving `n` client members, with a chosen restart grace.
/// `fresh_restart` = true keeps the collect-before-publish window active
/// (started_at = now); false skips it (started_at = 0) to show the storm.
async fn setup_fleet(n: usize, grace_secs: u64, fresh_restart: bool) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig = toml::from_str("[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"x\"\n").unwrap();
    let mut toml = format!(
        "network_id = \"n1\"\ncidrs = [\"10.99.0.0/16\"]\n[pools.default]\ncidr = \"10.99.1.0/24\"\n\
         [settings]\nheartbeat_secs = 1\noffline_after = 30\nhold_down_secs = 0\nrestart_grace_secs = {grace_secs}\n"
    );
    for i in 0..n {
        toml.push_str(&format!("[clients.c{i}]\nsecret = \"s-c{i}\"\n"));
    }
    let cfg: NetworkConfig = toml::from_str(&toml).unwrap();
    let db = Arc::new(nqvpn_coord::db::Db::open_memory().unwrap());
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let state = Arc::new(AppState::new(coord, Some("tok".into()), keyring, db.clone(), 0));
    let reg = Registry::new();
    db.save_network_and_registry(&cfg, &reg).unwrap();
    let ns = state.add_network(cfg, reg);
    ns.lock().unwrap().started_at = if fresh_restart { now_unix() } else { 0 };
    let id = TlsIdentity::generate("coord").unwrap();
    let endpoint = control::bind("127.0.0.1:0".parse().unwrap(), &id).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let s = state.clone();
    tokio::spawn(async move {
        let _ = control::serve(s, endpoint).await;
    });
    Env { state, addr, _dir: dir }
}

/// A member joining the fleet as client `i` (node id 100 + i).
fn join_fleet(env: &Env, i: usize, id: &TlsIdentity) -> String {
    let node_id = 100 + i as u32;
    let req = JoinRequest {
        secret: format!("s-c{i}"),
        pubkey: B64.encode([node_id as u8; 32]),
        cert_fingerprint: id.fingerprint(),
    };
    env.state.join(&req, "1.1.1.1").unwrap().credential
}

/// Count the Snapshot and Delta pushes waiting on a member's stream,
/// draining until quiet for `quiet`.
async fn drain_pushes(m: &mut Member, quiet: Duration) -> (u32, u32) {
    let (mut snaps, mut deltas) = (0u32, 0u32);
    // Drain until a quiet period elapses or the stream ends.
    while let Ok(Ok(env)) = tokio::time::timeout(quiet, read_envelope(&mut m.rx)).await {
        if env.kind == Kind::Snapshot as u16 {
            snaps += 1;
        } else if env.kind == Kind::Delta as u16 {
            deltas += 1;
        }
    }
    (snaps, deltas)
}

/// Without the grace, every reconnection broadcasts a delta to everyone
/// already synced: the fleet pays O(N^2) pushes. This is the storm the
/// grace exists to prevent — measured, so the fix is not just asserted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fleet_reconnecting_without_the_grace_storms() -> Result<()> {
    const N: usize = 12;
    let env = setup_fleet(N, 0, false).await; // grace off, not a fresh restart
    let ids: Vec<TlsIdentity> = (0..N).map(|i| TlsIdentity::generate(&format!("c{i}")).unwrap()).collect();
    let mut members = Vec::new();
    // Sequential connects, as a reconnect wave arrives.
    for (i, id) in ids.iter().enumerate() {
        let cred = join_fleet(&env, i, id);
        members.push(Member::connect(&env, &cred, id, 0).await?);
    }
    let mut total_snaps = 0u32;
    let mut total_deltas = 0u32;
    for m in &mut members {
        let (s, d) = drain_pushes(m, Duration::from_millis(300)).await;
        total_snaps += s;
        total_deltas += d;
    }
    // Each member is caught up once (a snapshot), and then receives a
    // delta for every member that connected after it: ~N*(N-1)/2 total.
    assert_eq!(total_snaps, N as u32, "each member is caught up once");
    assert!(
        total_deltas >= (N * (N - 1) / 2) as u32 / 2,
        "without the grace the fleet pays O(N^2) deltas — got {total_deltas} for N={N}"
    );
    Ok(())
}

/// With the grace, a reconnecting fleet gets zero broadcasts during the
/// window, then one snapshot each of the settled view: O(N), not O(N^2).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_grace_turns_a_reconnect_storm_into_one_snapshot_each() -> Result<()> {
    const N: usize = 12;
    // A long-enough grace that the whole wave lands inside it.
    let env = setup_fleet(N, 3, true).await;
    let ids: Vec<TlsIdentity> = (0..N).map(|i| TlsIdentity::generate(&format!("c{i}")).unwrap()).collect();
    let mut members = Vec::new();
    for (i, id) in ids.iter().enumerate() {
        let cred = join_fleet(&env, i, id);
        members.push(Member::connect(&env, &cred, id, 0).await?);
    }
    // During the grace: nothing is pushed to anyone (all sessions are
    // unsynced, so broadcasts are held and catch-up is deferred).
    let mut during_snaps = 0u32;
    let mut during_deltas = 0u32;
    for m in &mut members {
        let (s, d) = drain_pushes(m, Duration::from_millis(150)).await;
        during_snaps += s;
        during_deltas += d;
    }
    assert_eq!((during_snaps, during_deltas), (0, 0), "no pushes at all while the fleet reconnects");

    // Let the grace end, then each member heartbeats once. It gets exactly
    // one snapshot of the settled view — never a per-reconnection delta.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (mut after_snaps, mut after_deltas) = (0u32, 0u32);
    for m in &mut members {
        m.heartbeat(&Heartbeat { gen: 0, ..Default::default() }).await?;
        let (s, d) = drain_pushes(m, Duration::from_millis(400)).await;
        after_snaps += s;
        after_deltas += d;
    }
    assert_eq!(after_snaps, N as u32, "exactly one snapshot per member after the grace");
    assert_eq!(after_deltas, 0, "and no per-reconnection deltas");
    Ok(())
}
