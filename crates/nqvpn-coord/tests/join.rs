//! Integration tests for the join transaction: a secret names the
//! member, the operator's configuration is the declaration, replacement
//! by a different machine, route registration, offline credential
//! verification.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use nqvpn_coord::admin::MemberSpec;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::db::Db;
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState, ISS};
use nqvpn_proto::api::JoinRequest;
use nqvpn_proto::credential::{self, Expected};
use nqvpn_proto::types::{NodeId, Role};
use std::sync::Arc;

/// Every member's secret is `s-<name>`: the secret is the lookup key.
fn secret_of(name: &str) -> String {
    format!("s-{name}")
}

fn network_toml() -> String {
    r#"
network_id = "n1"
cidrs = ["10.99.0.0/16", "fd99::/64"]
[pools.default]
cidr = "10.99.1.0/24"
[pools.v6]
cidr = "fd99::1:0/112"
[settings]
credential_ttl_mins = 15
[relays.r1]
secret = "s-r1"
relay_addr = "1.2.3.4:4444"
local_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
[relays.r2]
secret = "s-r2"
relay_addr = "5.6.7.8:4444"
[relays.r3]
secret = "s-r3"
relay_addr = "auto:4444"
[clients.c1]
secret = "s-c1"
[clients.nosecret]
[clients.auto]
secret = "s-auto"
"#.to_string()
}

struct Harness {
    state: AppState,
    db: Arc<Db>,
    _dir: tempfile::TempDir,
}

fn harness_with(toml: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig =
        toml::from_str("[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"unused\"\n").unwrap();
    let mut net_cfg: NetworkConfig = toml::from_str(toml).unwrap();
    nqvpn_coord::config::validate_network(&mut net_cfg).unwrap();
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let db = Arc::new(Db::open_memory().unwrap());
    let state = AppState::new(coord, Some("tok".into()), keyring, db.clone(), 14433);
    let registry = Registry::new();
    db.save_network_and_registry(&net_cfg, &registry).unwrap();
    state.add_network(net_cfg, registry);
    Harness { state, db, _dir: dir }
}

fn net(h: &Harness) -> Arc<std::sync::Mutex<nqvpn_coord::state::NetState>> {
    h.state.net("n1").unwrap()
}

fn harness() -> Harness {
    harness_with(&network_toml())
}

fn pubkey(seed: u8) -> String {
    B64.encode([seed; 32])
}

fn fp(seed: u8) -> String {
    format!("sha256:{}", hex::encode([seed; 32]))
}

fn name_of(node_id: NodeId) -> String {
    match node_id {
        1 => "r1".into(),
        2 => "r2".into(),
        3 => "r3".into(),
        10 => "c1".into(),
        11 => "nosecret".into(),
        99 => "ghost".into(),
        n => format!("c{n}"),
    }
}

fn req(node_id: NodeId, _role: Role) -> JoinRequest {
    JoinRequest { secret: secret_of(&name_of(node_id)), pubkey: pubkey(node_id as u8), cert_fingerprint: fp(node_id as u8) }
}

/// The operator edits a member (as the UI would).
fn configure(h: &Harness, name: &str, f: impl FnOnce(&mut MemberSpec)) {
    let cur = {
        let n = net(h);
        let ns = n.lock().unwrap();
        MemberSpec::from_cfg(ns.cfg.member_by_name(name).unwrap().0)
    };
    let mut spec = cur;
    f(&mut spec);
    h.state.update_member("n1", name, &spec).unwrap();
}

#[test]
fn client_join_happy_path_and_offline_verification() {
    let h = harness();
    let resp = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert!(resp.ip4.is_some());
    assert!(resp.ip6.is_some());
    assert_eq!(resp.subnet4, Some("10.99.0.0/16".parse().unwrap()));
    assert_eq!(resp.mtu, 1350);
    assert_eq!(resp.name, "c1");
    assert_eq!(resp.control_port, 14433);
    assert_eq!(resp.heartbeat_secs, 5);
    assert_eq!(resp.login_gen, 0);
    assert!(resp.relays.is_empty(), "no relay has joined yet");

    let keys: Vec<(String, VerifyingKey)> = resp
        .coordinator_signing_keys
        .iter()
        .map(|k| {
            let bytes: [u8; 32] = B64.decode(&k.key).unwrap().try_into().unwrap();
            (k.kid.clone(), VerifyingKey::from_bytes(&bytes).unwrap())
        })
        .collect();
    let claims = credential::verify(
        &resp.credential,
        &keys,
        &Expected { iss: ISS, network_id: "n1", network_uuid: &resp.network_uuid },
        now_unix(),
    )
    .unwrap();
    assert_eq!(claims.sub, "c1");
    assert_eq!(claims.node_id, resp.node_id, "the id the coordinator assigned");
    assert_eq!(claims.cert_fp, fp(10));
    assert!(claims.prefixes.contains(&format!("{}/32", resp.ip4.unwrap())));
}

#[test]
fn rejoin_from_the_same_machine_is_idempotent_and_sticky() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let b = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(a.node_id, b.node_id);
    assert_eq!(a.ip4, b.ip4);
    assert_eq!(a.ip6, b.ip6);
    assert_eq!(a.login_gen, b.login_gen, "same keys: not a replacement");
    assert_eq!(a.network_uuid, b.network_uuid);
}

#[test]
fn a_different_machine_replaces_the_previous_instance() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let mut other = req(10, Role::Client);
    other.pubkey = pubkey(200);
    other.cert_fingerprint = fp(200);
    let b = h.state.join(&other, "9.9.9.9").unwrap();
    assert_eq!(b.node_id, a.node_id, "same identity");
    assert_eq!(b.ip4, a.ip4, "same address: identity, not declaration");
    assert_eq!(b.login_gen, a.login_gen + 1, "but a new login generation");
    let n_ = net(&h);
    let ns = n_.lock().unwrap();
    let rec = ns.registry.by_name("c1").unwrap();
    assert_eq!(rec.pubkey.as_deref(), Some(pubkey(200).as_str()), "latest keys are recorded, never judged");
    assert_eq!(rec.replaced_from.as_deref(), Some("1.1.1.1"));
    assert!(rec.replaced_unix.is_some());
    assert_eq!(ns.directory.published.member(a.node_id).unwrap().login_gen, 1, "published so acceptors evict the old one");
}

#[test]
fn a_wrong_or_unknown_secret_is_indistinguishable_from_no_member() {
    let h = harness();
    let mut r = req(10, Role::Client);
    r.secret = "wrong".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    assert_eq!(h.state.join(&req(99, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    let mut r = req(10, Role::Client);
    r.secret = String::new();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    // A member with no secret cannot join at all (nothing to present).
    assert_eq!(h.state.join(&req(11, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
}

#[test]
fn rotating_a_secret_evicts_the_old_one_immediately_and_survives_reload() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let rotated = h.state.rotate_member("n1", "c1").unwrap();
    assert_eq!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    let mut r = req(10, Role::Client);
    r.secret = rotated.clone();
    let b = h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(b.node_id, a.node_id, "same member");
    assert!(b.login_gen > a.login_gen, "every acceptor drops the old holder's sessions");
    // Durable: the database holds the new secret.
    let saved = h.db.load_all().unwrap();
    assert_eq!(saved[0].0.clients["c1"].secret.as_deref(), Some(rotated.as_str()));
    // A member without a secret gets one by rotating.
    let s = h.state.rotate_member("n1", "nosecret").unwrap();
    let mut r = req(11, Role::Client);
    r.secret = s;
    assert!(h.state.join(&r, "1.1.1.1").is_ok());
}

#[test]
fn a_member_created_by_the_operator_joins_with_its_token_only() {
    let h = harness();
    let spec = MemberSpec {
        relay_addr: Some("auto:5555".into()),
        local_cidrs: vec!["172.20.5.0/24".parse().unwrap()],
        preferred_ip4: Some("10.99.0.7".parse().unwrap()),
        ..Default::default()
    };
    let secret = h.state.create_member("n1", "cloud-3", Role::Relay, &spec).unwrap();
    let (token, role) = h.state.member_token("n1", "cloud-3", "https://coord.example:8443").unwrap();
    assert_eq!(role, Role::Relay);
    let parsed = nqvpn_proto::token::Token::parse(&token.encode()).unwrap();
    assert_eq!(parsed.secret, secret);
    assert_eq!(parsed.coordinator, "https://coord.example:8443");

    let r = JoinRequest { secret, pubkey: pubkey(77), cert_fingerprint: fp(77) };
    let resp = h.state.join(&r, "203.0.113.9").unwrap();
    assert_eq!(resp.role, Role::Relay);
    assert_eq!(resp.network_id, "n1");
    assert_eq!(resp.name, "cloud-3");
    assert_eq!(resp.ip4, Some("10.99.0.7".parse().unwrap()));
    assert_eq!(resp.subnet4, Some("10.99.0.0/16".parse().unwrap()), "every assigned address has a containing tunnel CIDR");
    assert_eq!(resp.granted_cidrs, vec!["172.20.5.0/24".parse::<ipnet::IpNet>().unwrap()]);
    assert_eq!(resp.relay_addr.as_deref(), Some("203.0.113.9:5555"), "auto resolves to where it joined from");
    // And it is in the fleet at that address.
    let c = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert!(c.relays.iter().any(|r| r.name == "cloud-3" && r.addr == "203.0.113.9:5555"));
    // Names are unique; the creation is durable.
    assert!(h.state.create_member("n1", "cloud-3", Role::Client, &MemberSpec::default()).is_err());
    assert!(h.db.load_all().unwrap()[0].0.relays.contains_key("cloud-3"));
}

#[test]
fn a_name_is_assigned_a_durable_id_at_first_join() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let r = h.state.join(&req(1, Role::Relay), "1.1.1.1").unwrap();
    assert!(a.node_id != 0 && r.node_id != 0 && a.node_id != r.node_id);
    let again = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(again.node_id, a.node_id, "durable across joins");
    let n_ = net(&h);
    let reg = n_.lock().unwrap();
    assert_eq!(reg.registry.id_of("c1"), Some(a.node_id));
    assert_eq!(reg.registry.members[&a.node_id].name, "c1");
}

#[test]
fn bad_keys_are_rejected() {
    let h = harness();
    let mut r = req(10, Role::Client);
    r.pubkey = "not-a-key".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
    let mut r = req(10, Role::Client);
    r.cert_fingerprint = "sha256:short".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn a_client_cannot_be_configured_with_routes() {
    let h = harness();
    let spec = MemberSpec { local_cidrs: vec!["192.168.5.0/24".parse().unwrap()], ..Default::default() };
    assert!(h.state.update_member("n1", "c1", &spec).is_err());
}

#[test]
fn relay_join_registers_routes_and_becomes_visible() {
    let h = harness();
    let r = req(1, Role::Relay);
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(resp.ip4, Some("10.99.0.1".parse().unwrap()), "config preferred honoured");
    assert_eq!(resp.granted_cidrs, vec!["192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()]);

    let c = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(c.relays.len(), 1);
    assert_eq!(c.relays[0].name, "r1");
    assert_eq!(c.relays[0].cert_fp, fp(1), "what the relay presented at its join");
    // The CIDR is reserved network-wide even before anyone owns it.
    let n_ = net(&h);
    let ns = n_.lock().unwrap();
    assert!(ns.directory.published.reserved_prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
}

#[test]
fn a_join_applies_the_current_configuration_in_full() {
    let h = harness();
    let r = req(1, Role::Relay);
    h.state.join(&r, "1.1.1.1").unwrap();
    let age1 = net(&h).lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix;

    // Renewal with the same CIDR keeps its age.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(net(&h).lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix, age1);

    // The operator removes the prefix: withdrawn at the next join, not
    // "at the next renewal".
    configure(&h, "r1", |s| s.local_cidrs.clear());
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert!(resp.granted_cidrs.is_empty());
    assert!(net(&h).lock().unwrap().registry.by_name("r1").unwrap().routes.is_empty());

    // Declaring it again is a fresh registration with a fresh age.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    configure(&h, "r1", |s| s.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()]);
    h.state.join(&r, "1.1.1.1").unwrap();
    let age2 = net(&h).lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix;
    assert!(age2 > age1, "left and came back: young again");
}

#[test]
fn a_changed_preferred_address_is_honoured_and_the_old_one_released() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    configure(&h, "c1", |s| s.preferred_ip4 = Some("10.99.50.7".parse().unwrap()));
    let b = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(b.ip4, Some("10.99.50.7".parse().unwrap()));
    assert_ne!(a.ip4, b.ip4);
    // The old address is free for someone else now.
    configure(&h, "r2", |s| s.preferred_ip4 = a.ip4);
    assert_eq!(h.state.join(&req(2, Role::Relay), "1.1.1.1").unwrap().ip4, a.ip4);
    // Two members may not be configured with the same address.
    let clash = MemberSpec { preferred_ip4: a.ip4, ..Default::default() };
    assert!(h.state.update_member("n1", "auto", &clash).is_err());
    // Going headless releases everything; coming back allocates again.
    configure(&h, "c1", |s| {
        s.want_vpn_ip = Some(false);
        s.preferred_ip4 = None;
    });
    assert!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap().ip4.is_none());
    configure(&h, "c1", |s| s.want_vpn_ip = None);
    assert!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap().ip4.is_some());
}

#[test]
fn a_relay_address_is_whatever_the_operator_configured() {
    let h = harness();
    // Concrete: as configured. Auto: where the join came from.
    assert_eq!(h.state.join(&req(1, Role::Relay), "1.1.1.1").unwrap().relay_addr.as_deref(), Some("1.2.3.4:4444"));
    assert_eq!(h.state.join(&req(3, Role::Relay), "9.9.9.9").unwrap().relay_addr.as_deref(), Some("9.9.9.9:4444"));
    assert_eq!(h.state.join(&req(3, Role::Relay), "2001:db8::1").unwrap().relay_addr.as_deref(), Some("[2001:db8::1]:4444"));
    // A relay configured without an address cannot be created.
    let spec = MemberSpec { relay_addr: None, ..Default::default() };
    assert!(h.state.create_member("n1", "r9", Role::Relay, &spec).is_err());
}

#[test]
fn conflicting_prefixes_are_refused_at_configuration_time() {
    let h = harness();
    let mut spec = {
        let n_ = net(&h);
        let ns = n_.lock().unwrap();
        MemberSpec::from_cfg(&ns.cfg.relays["r2"])
    };
    spec.local_cidrs = vec!["192.168.1.128/25".parse().unwrap()];
    let e = h.state.update_member("n1", "r2", &spec).unwrap_err();
    assert_eq!(e.code.as_str(), "bad_request");
    assert!(e.message.contains("overlaps"), "{}", e.message);
    spec.local_cidrs = vec!["10.99.7.0/24".parse().unwrap()];
    assert!(h.state.update_member("n1", "r2", &spec).is_err(), "tunnel space");
}

#[test]
fn overlapping_registration_age_resolves() {
    let h = harness();
    h.state.join(&req(1, Role::Relay), "1.1.1.1").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    configure(&h, "r2", |s| s.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()]);
    h.state.join(&req(2, Role::Relay), "1.1.1.1").unwrap();
    let n_ = net(&h);
    let ns = n_.lock().unwrap();
    let owners = ns.registry.resolve_owners();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].1[0].0, ns.registry.id_of("r1").unwrap(), "older registration owns");
    assert_eq!(owners[0].1[1].0, ns.registry.id_of("r2").unwrap(), "younger is standby");
}

#[test]
fn disabled_member_rejected_then_enable_restores() {
    let h = harness();
    h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let id = net(&h).lock().unwrap().registry.id_of("c1").unwrap();
    net(&h).lock().unwrap().registry.members.get_mut(&id).unwrap().disabled = true;
    assert_eq!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "client_disabled");
    net(&h).lock().unwrap().registry.members.get_mut(&id).unwrap().disabled = false;
    h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
}

#[test]
fn registry_survives_reload_including_the_generation_mark() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let (uuid, gen) = {
        let n_ = net(&h);
        let ns = n_.lock().unwrap();
        (ns.registry.network_uuid, ns.directory.gen)
    };
    let reloaded = h.db.load_registry("n1").unwrap().expect("saved");
    assert_eq!(reloaded.network_uuid, uuid);
    assert_eq!(reloaded.members[&a.node_id].ip4, a.ip4);
    assert_eq!(reloaded.members[&a.node_id].name, "c1");
    assert!(reloaded.gen_hwm > gen, "the high-water mark is ahead of anything handed out");
    assert!(reloaded.initial_gen(0) > gen, "a restart continues above the old generation");
}

/// The embedded UI must be self-contained (no external hosts, no
/// embedded credential), drive the admin API, and speak the model:
/// members are names with tokens; nothing about keys or pinning.
#[test]
fn embedded_ui_is_self_contained_and_shows_no_pins() {
    let html = include_str!("../ui/index.html");
    assert!(html.contains("<title>NetQ VPN coordinator</title>"));
    const SVG_NS: &str = "http://www.w3.org/2000/svg";
    let external = html.replace(SVG_NS, "");
    assert!(!external.contains("http://") && !external.contains("https://"), "UI must not reference external hosts");
    assert!(!html.contains("<script src") && !html.contains("<link rel=\"stylesheet\""));
    assert!(html.contains("<meta name=\"viewport\""), "responsive");
    for frag in [
        "/api/v1/login",
        "/api/v1/logout",
        "/api/v1/me",
        "/api/v1/ws",
        "/api/v1/networks",
        "/api/v1/export",
        "/api/v1/import",
        "/members",
        "/token",
        "'enable' : 'disable'",
        "relay_traffic",
        "tx_bytes",
        "attached_relay",
        "prefix_table",
        "topologyPane",
        "matrixPane",
        "settingsPane",
        "memberForm",
        "newNetworkModal",
        "confirmModal",
        "Delete member",
        "Regenerate",
        "stops working immediately",
        "digest_ok",
        "reported_gen",
        "replaced_from",
        "new WebSocket",
        "@media (max-width",
    ] {
        assert!(html.contains(frag), "UI should exercise {frag}");
    }
    let lower = html.to_ascii_lowercase();
    // Member cert internals (X25519 pubkeys) must stay hidden; the
    // coordinator's cert and fingerprint are now legit config concepts.
    assert!(!lower.contains("pubkey"), "UI must not mention member pubkeys");
}

#[test]
fn concurrent_joins_never_hand_out_the_same_address() {
    use std::collections::HashSet;
    use std::sync::Arc;
    const N: usize = 24;
    let toml = format!(
        "network_id = \"n1\"\ncidrs = [\"10.99.0.0/16\"]\n[pools.default]\ncidr = \"10.99.1.0/24\"\n[settings]\n{}",
        (0..N).map(|i| format!("[clients.c{}]\nsecret = \"s-c{}\"\n", 100 + i, 100 + i)).collect::<String>()
    );
    let toml = toml.replace("[settings]\n", "");
    let h = harness_with(&toml);
    let state = Arc::new(h.state);
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let st = state.clone();
            std::thread::spawn(move || st.join(&req(100 + i as u32, Role::Client), "1.1.1.1").map(|r| (r.node_id, r.ip4)))
        })
        .collect();
    let mut ips = HashSet::new();
    for hd in handles {
        let (_, ip4) = hd.join().unwrap().expect("join failed");
        assert!(ips.insert(ip4.unwrap()), "address handed out twice");
    }
    assert_eq!(ips.len(), N);
}

#[test]
fn rate_limit_kicks_in() {
    let h = harness();
    let mut r = req(10, Role::Client);
    r.secret = "wrong".into();
    let mut codes = Vec::new();
    for _ in 0..40 {
        codes.push(h.state.join(&r, "2.2.2.2").unwrap_err().code.as_str().to_string());
    }
    assert!(codes.iter().any(|c| c == "rate_limited"), "expected the limiter to refuse some attempts, got {codes:?}");
}

#[test]
fn headless_join_gets_no_address() {
    let h = harness();
    configure(&h, "c1", |s| s.want_vpn_ip = Some(false));
    let resp = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert!(resp.ip4.is_none());
    assert!(resp.subnet4.is_none());
}
