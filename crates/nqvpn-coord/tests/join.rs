//! Integration tests for the join transaction (§3.2, §3.3): node id +
//! secret, full re-declaration, replacement by a different machine,
//! route registration, and offline credential verification.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState, NetState, ISS};
use nqvpn_proto::api::JoinRequest;
use nqvpn_proto::credential::{self, Expected};
use nqvpn_proto::types::{NodeId, Role};
use std::collections::HashMap;
use std::sync::Mutex;

const SECRET: &str = "s3cret";

fn network_toml() -> String {
    format!(
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
secret = "{SECRET}"
relay_addr = "1.2.3.4:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
[relays.r2]
secret = "{SECRET}"
relay_addr = "5.6.7.8:4444"
allowed_cidrs = ["192.168.1.0/24"]
[clients.c1]
secret = "{SECRET}"
[clients.nosecret]
[clients.auto]
secret = "{SECRET}"
"#
    )
}

struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

fn harness_with(toml: &str) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig =
        toml::from_str("[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"unused\"\n").unwrap();
    let net_cfg: NetworkConfig = toml::from_str(toml).unwrap();
    nqvpn_coord::config::validate_network(&net_cfg).unwrap();
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let registry_path = dir.path().join("registry-n1.json");
    let registry = Registry::load_or_create(&registry_path).unwrap();
    let mut networks = HashMap::new();
    networks.insert("n1".to_string(), Mutex::new(NetState::new(net_cfg, registry, registry_path)));
    Harness {
        state: AppState {
            coord,
            admin_token: Some("tok".into()),
            networks,
            keyring,
            join_rate: Mutex::new(Default::default()),
            networks_dir: None,
            secrets: Mutex::new(nqvpn_coord::secrets::SecretStore::default()),
            secrets_path: dir.path().join("secrets.toml"),
            control_port: 14433,
        },
        _dir: dir,
    }
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
        10 => "c1".into(),
        11 => "nosecret".into(),
        99 => "ghost".into(),
        n => format!("c{n}"),
    }
}

fn req(node_id: NodeId, role: Role) -> JoinRequest {
    JoinRequest {
        network_id: "n1".into(),
        name: name_of(node_id),
        secret: SECRET.into(),
        pubkey: pubkey(node_id as u8),
        role,
        want_vpn_ip: true,
        pool: None,
        preferred_ip4: None,
        preferred_ip6: None,
        local_cidrs: vec![],
        relay_addr: match (role, node_id) {
            (Role::Relay, 1) => Some("1.2.3.4:4444".into()),
            (Role::Relay, 2) => Some("5.6.7.8:4444".into()),
            _ => None,
        },
        cert_fingerprint: fp(node_id as u8),
    }
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
    let ns = h.state.networks["n1"].lock().unwrap();
    let rec = ns.registry.by_name("c1").unwrap();
    assert_eq!(rec.pubkey.as_deref(), Some(pubkey(200).as_str()), "latest keys are recorded, never judged");
    assert_eq!(rec.replaced_from.as_deref(), Some("1.1.1.1"));
    assert!(rec.replaced_unix.is_some());
    assert_eq!(ns.directory.published.member(a.node_id).unwrap().login_gen, 1, "published so acceptors evict the old one");
}

#[test]
fn wrong_secret_unknown_node_and_unknown_network_are_indistinguishable() {
    let h = harness();
    let mut r = req(10, Role::Client);
    r.secret = "wrong".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    assert_eq!(h.state.join(&req(99, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    let mut r = req(10, Role::Client);
    r.network_id = "nope".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    // A configured member with no secret anywhere cannot join at all.
    assert_eq!(h.state.join(&req(11, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
}

#[test]
fn a_managed_secret_wins_over_the_config_secret_and_rotates() {
    let h = harness();
    let minted = h.state.secrets.lock().unwrap().mint("n1", "c1", 100);
    let mut r = req(10, Role::Client);
    r.secret = minted.clone();
    assert!(h.state.join(&r, "1.1.1.1").is_ok(), "managed secret authenticates");
    assert_eq!(
        h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap_err().code.as_str(),
        "bad_credentials",
        "the config secret must stop working once a managed one exists"
    );
    // A member with no managed secret keeps using config: migration path.
    assert!(h.state.join(&req(2, Role::Relay), "1.1.1.1").is_ok());
    // Minting again is rotation.
    let rotated = h.state.secrets.lock().unwrap().mint("n1", "c1", 200);
    r.secret = minted;
    assert!(h.state.join(&r, "1.1.1.1").is_err());
    r.secret = rotated;
    assert!(h.state.join(&r, "1.1.1.1").is_ok());
    // A member with no config secret can be given a managed one.
    let s = h.state.secrets.lock().unwrap().mint("n1", "nosecret", 300);
    let mut r = req(11, Role::Client);
    r.secret = s;
    assert!(h.state.join(&r, "1.1.1.1").is_ok());
}

#[test]
fn a_name_is_assigned_a_durable_id_at_first_join() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let r = h.state.join(&req(1, Role::Relay), "1.1.1.1").unwrap();
    assert!(a.node_id != 0 && r.node_id != 0 && a.node_id != r.node_id);
    let again = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(again.node_id, a.node_id, "durable across joins");
    let reg = h.state.networks["n1"].lock().unwrap();
    assert_eq!(reg.registry.id_of("c1"), Some(a.node_id));
    assert_eq!(reg.registry.members[&a.node_id].name, "c1");
}

#[test]
fn role_mismatch_and_bad_keys_are_rejected() {
    let h = harness();
    assert_eq!(h.state.join(&req(10, Role::Relay), "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
    let mut r = req(10, Role::Client);
    r.pubkey = "not-a-key".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
    let mut r = req(10, Role::Client);
    r.cert_fingerprint = "sha256:short".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn client_cannot_register_routes() {
    let h = harness();
    let mut r = req(10, Role::Client);
    r.local_cidrs = vec!["192.168.5.0/24".parse().unwrap()];
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn relay_join_registers_routes_and_becomes_visible() {
    let h = harness();
    let mut r = req(1, Role::Relay);
    r.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(resp.ip4, Some("10.99.0.1".parse().unwrap()), "config preferred honoured");
    assert_eq!(resp.granted_cidrs, vec!["192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()]);

    let c = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    assert_eq!(c.relays.len(), 1);
    assert_eq!(c.relays[0].name, "r1");
    assert_eq!(c.relays[0].cert_fp, fp(1), "what the relay presented at its join");
    // The CIDR is reserved network-wide even before anyone owns it.
    let ns = h.state.networks["n1"].lock().unwrap();
    assert!(ns.directory.published.reserved_prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
}

#[test]
fn a_join_replaces_the_previous_declaration() {
    let h = harness();
    let mut r = req(1, Role::Relay);
    r.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    h.state.join(&r, "1.1.1.1").unwrap();
    let age1 = h.state.networks["n1"].lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix;

    // Renewal with the same CIDR keeps its age.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(h.state.networks["n1"].lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix, age1);

    // A join without it withdraws it at once — not "at the next renewal".
    let plain = req(1, Role::Relay);
    let resp = h.state.join(&plain, "1.1.1.1").unwrap();
    assert!(resp.granted_cidrs.is_empty());
    assert!(h.state.networks["n1"].lock().unwrap().registry.by_name("r1").unwrap().routes.is_empty());

    // Declaring it again is a fresh registration with a fresh age.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    h.state.join(&r, "1.1.1.1").unwrap();
    let age2 = h.state.networks["n1"].lock().unwrap().registry.by_name("r1").unwrap().routes[0].first_granted_unix;
    assert!(age2 > age1, "left and came back: young again");
}

#[test]
fn a_changed_preferred_address_is_honoured_and_the_old_one_released() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let mut r = req(10, Role::Client);
    r.preferred_ip4 = Some("10.99.50.7".parse().unwrap());
    let b = h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(b.ip4, Some("10.99.50.7".parse().unwrap()));
    assert_ne!(a.ip4, b.ip4);
    // The old address is free for someone else now.
    let mut other = req(2, Role::Relay);
    other.preferred_ip4 = a.ip4;
    assert_eq!(h.state.join(&other, "1.1.1.1").unwrap().ip4, a.ip4);
    // Going headless releases everything; coming back allocates again.
    let mut headless = req(10, Role::Client);
    headless.want_vpn_ip = false;
    assert!(h.state.join(&headless, "1.1.1.1").unwrap().ip4.is_none());
    assert!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap().ip4.is_some());
}

#[test]
fn relay_addr_must_match_the_plan_of_record() {
    let h = harness();
    let mut r = req(1, Role::Relay);
    r.relay_addr = Some("198.51.100.5:9999".into());
    let e = h.state.join(&r, "1.1.1.1").unwrap_err();
    assert_eq!(e.code.as_str(), "bad_request");
    assert!(e.message.contains("does not match"), "{}", e.message);
    let mut r2 = req(1, Role::Relay);
    r2.relay_addr = None;
    assert_eq!(h.state.join(&r2, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn relay_cidr_outside_allowed_rejected() {
    let h = harness();
    let mut r = req(1, Role::Relay);
    r.local_cidrs = vec!["192.168.99.0/24".parse().unwrap()];
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "prefix_conflict");
}

#[test]
fn overlapping_registration_age_resolves() {
    let h = harness();
    let mut r1 = req(1, Role::Relay);
    r1.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    h.state.join(&r1, "1.1.1.1").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut r2 = req(2, Role::Relay);
    r2.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    h.state.join(&r2, "1.1.1.1").unwrap();
    let ns = h.state.networks["n1"].lock().unwrap();
    let owners = ns.registry.resolve_owners();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].1[0].0, ns.registry.id_of("r1").unwrap(), "older registration owns");
    assert_eq!(owners[0].1[1].0, ns.registry.id_of("r2").unwrap(), "younger is standby");
}

#[test]
fn disabled_member_rejected_then_enable_restores() {
    let h = harness();
    h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let id = h.state.networks["n1"].lock().unwrap().registry.id_of("c1").unwrap();
    h.state.networks["n1"].lock().unwrap().registry.members.get_mut(&id).unwrap().disabled = true;
    assert_eq!(h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "client_disabled");
    h.state.networks["n1"].lock().unwrap().registry.members.get_mut(&id).unwrap().disabled = false;
    h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
}

#[test]
fn registry_survives_reload_including_the_generation_mark() {
    let h = harness();
    let a = h.state.join(&req(10, Role::Client), "1.1.1.1").unwrap();
    let (path, uuid, gen) = {
        let ns = h.state.networks["n1"].lock().unwrap();
        (ns.registry_path.clone(), ns.registry.network_uuid, ns.directory.gen)
    };
    let reloaded = Registry::load_or_create(&path).unwrap();
    assert_eq!(reloaded.network_uuid, uuid);
    assert_eq!(reloaded.members[&a.node_id].ip4, a.ip4);
    assert_eq!(reloaded.members[&a.node_id].name, "c1");
    assert!(reloaded.gen_hwm > gen, "the high-water mark is ahead of anything handed out");
    assert!(reloaded.initial_gen(0) > gen, "a restart continues above the old generation");
}

/// The embedded UI must be served, self-contained, token-free, and speak
/// the security model: node id + secret, nothing about keys.
#[test]
fn embedded_ui_is_self_contained_and_shows_no_pins() {
    let html = include_str!("../ui/index.html");
    assert!(html.contains("<title>nqvpn control plane</title>"));
    const SVG_NS: &str = "http://www.w3.org/2000/svg";
    let external = html.replace(SVG_NS, "");
    assert!(!external.contains("http://") && !external.contains("https://"), "UI must not reference external hosts");
    assert!(!html.contains("<script src") && !html.contains("<link rel=\"stylesheet\""));
    assert!(!html.contains("dev-admin-token"), "UI must not embed a credential");
    for frag in [
        "/api/v1/status",
        "/api/v1/reload",
        "/api/v1/networks/",
        "/status`",
        "'enable' : 'disable'",
        "/members/",
        "/secret",
        "relay_traffic",
        "tx_bytes",
        "attached_relay",
        "data-tab=\"stats\"",
        "data-tab=\"topology\"",
        "confirmModal",
        "Delete member",
        "Regenerate",
        "stops working immediately",
        "digest_ok",
        "reported_gen",
        "replaced_from",
    ] {
        assert!(html.contains(frag), "UI should exercise {frag}");
    }
    let lower = html.to_ascii_lowercase();
    for banned in ["pin", "fingerprint", "rotation", "rotate", "cert", "pubkey", "identity"] {
        assert!(!lower.contains(banned), "UI must not mention {banned:?}: there is no such concept for users");
    }
}

#[test]
fn concurrent_joins_never_hand_out_the_same_address() {
    use std::collections::HashSet;
    use std::sync::Arc;
    const N: usize = 24;
    let toml = format!(
        "network_id = \"n1\"\ncidrs = [\"10.99.0.0/16\"]\n[pools.default]\ncidr = \"10.99.1.0/24\"\n[settings]\n{}",
        (0..N).map(|i| format!("[clients.c{}]\nsecret = \"{SECRET}\"\n", 100 + i)).collect::<String>()
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
    let mut r = req(10, Role::Client);
    r.want_vpn_ip = false;
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert!(resp.ip4.is_none());
    assert!(resp.subnet4.is_none());
}
