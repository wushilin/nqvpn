//! Integration tests for the join transaction (§3.2, §3.3): happy path,
//! TOFU pinning, disable, stickiness, route registration, and offline
//! credential verification against the returned keyset.

use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use nqvpn_coord::config::{CoordConfig, NetworkConfig};
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState, NetState, ISS};
use nqvpn_proto::api::JoinRequest;
use nqvpn_proto::credential::{self, Expected};
use nqvpn_proto::types::Role;
use std::collections::HashMap;
use std::sync::Mutex;

const SECRET: &str = "s3cret";

fn hash(secret: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(secret.as_bytes(), &salt).unwrap().to_string()
}

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
secret_hash = '{h}'
relay_addr = "1.2.3.4:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
[relays.r2]
secret_hash = '{h}'
relay_addr = "5.6.7.8:4444"
allowed_cidrs = ["192.168.1.0/24"]
[clients.c1]
secret_hash = '{h}'
"#,
        h = hash(SECRET)
    )
}

struct Harness {
    state: AppState,
    _dir: tempfile::TempDir,
}

fn harness() -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let coord: CoordConfig = toml::from_str(
        r#"
[listen]
api = "127.0.0.1:0"
[state]
dir = "unused"
"#,
    )
    .unwrap();
    let net_cfg: NetworkConfig = toml::from_str(&network_toml()).unwrap();
    nqvpn_coord::config::validate_network(&net_cfg).unwrap();
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let registry_path = dir.path().join("registry-n1.json");
    let registry = Registry::load_or_create(&registry_path).unwrap();
    let mut networks = HashMap::new();
    networks.insert(
        "n1".to_string(),
        Mutex::new(NetState::new(net_cfg, registry, registry_path)),
    );
    Harness {
        state: AppState {
            coord,
            admin_token: Some("tok".into()),
            networks,
            keyring,
            join_rate: Mutex::new(HashMap::new()),
            networks_dir: None,
            secrets: Mutex::new(nqvpn_coord::secrets::SecretStore::default()),
            secrets_path: std::path::PathBuf::from("/nonexistent/secrets.toml"),
        },
        _dir: dir,
    }
}

fn req(name: &str, role: Role) -> JoinRequest {
    JoinRequest {
        network_id: "n1".into(),
        client_id: name.into(),
        client_secret: SECRET.into(),
        pubkey: format!("PK-{name}"),
        role,
        want_vpn_ip: true,
        pool: None,
        preferred_ip4: None,
        preferred_ip6: None,
        local_cidrs: vec![],
        relay_addr: match (role, name) {
            (Role::Relay, "r1") => Some("1.2.3.4:4444".into()),
            (Role::Relay, "r2") => Some("5.6.7.8:4444".into()),
            _ => None,
        },
        cert_fingerprint: format!("sha256:{name}"),
    }
}

#[test]
fn client_join_happy_path_and_offline_verification() {
    let h = harness();
    let resp = h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();

    assert!(resp.ip4.is_some());
    assert!(resp.ip6.is_some());
    assert_eq!(resp.subnet4, Some("10.99.0.0/16".parse().unwrap()));
    assert_eq!(resp.mtu, 1350);
    assert!(resp.relays.is_empty(), "no relay has joined yet");

    // Offline verification exactly as a relay would do it.
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
    assert_eq!(claims.node_id, resp.node_id);
    assert_eq!(claims.cert_fp, "sha256:c1");
    assert!(claims.prefixes.contains(&format!("{}/32", resp.ip4.unwrap())));
}

#[test]
fn rejoin_is_idempotent_and_sticky() {
    let h = harness();
    let a = h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    let b = h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    assert_eq!(a.node_id, b.node_id);
    assert_eq!(a.ip4, b.ip4);
    assert_eq!(a.ip6, b.ip6);
    assert_eq!(a.network_uuid, b.network_uuid);
}

#[test]
fn wrong_secret_rejected() {
    let h = harness();
    let mut r = req("c1", Role::Client);
    r.client_secret = "wrong".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
}

#[test]
fn unknown_member_and_unknown_network_are_indistinguishable() {
    let h = harness();
    let mut r = req("ghost", Role::Client);
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
    r = req("c1", Role::Client);
    r.network_id = "nope".into();
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_credentials");
}

#[test]
fn tofu_pin_blocks_key_swap() {
    let h = harness();
    h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    let mut evil = req("c1", Role::Client);
    evil.pubkey = "PK-stolen".into();
    assert_eq!(h.state.join(&evil, "9.9.9.9").unwrap_err().code.as_str(), "pin_mismatch");
    // Same key but different TLS cert is equally rejected.
    let mut evil2 = req("c1", Role::Client);
    evil2.cert_fingerprint = "sha256:other".into();
    assert_eq!(h.state.join(&evil2, "9.9.9.9").unwrap_err().code.as_str(), "pin_mismatch");
}

#[test]
fn role_mismatch_rejected() {
    let h = harness();
    assert_eq!(
        h.state.join(&req("c1", Role::Relay), "1.1.1.1").unwrap_err().code.as_str(), "bad_request"
    );
}

#[test]
fn client_cannot_register_routes() {
    let h = harness();
    let mut r = req("c1", Role::Client);
    r.local_cidrs = vec!["192.168.5.0/24".parse().unwrap()];
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn relay_join_registers_routes_and_becomes_visible() {
    let h = harness();
    let mut r = req("r1", Role::Relay);
    r.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    r.relay_addr = Some("1.2.3.4:4444".into());
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert_eq!(resp.ip4, Some("10.99.0.1".parse().unwrap()), "config preferred honored");
    assert_eq!(resp.granted_cidrs, vec!["192.168.1.0/24".parse::<ipnet::IpNet>().unwrap()]);

    // Now visible to clients.
    let c = h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    assert_eq!(c.relays.len(), 1);
    assert_eq!(c.relays[0].name, "r1");
    assert_eq!(c.relays[0].cert_fp, "sha256:r1");
}

#[test]
fn relay_addr_must_match_the_plan_of_record() {
    let h = harness();
    let mut r = req("r1", Role::Relay);
    r.relay_addr = Some("198.51.100.5:9999".into()); // not what config says
    let e = h.state.join(&r, "1.1.1.1").unwrap_err();
    assert_eq!(e.code.as_str(), "bad_request");
    assert!(e.message.contains("does not match"), "{}", e.message);

    // Omitting it entirely is equally rejected.
    let mut r2 = req("r1", Role::Relay);
    r2.relay_addr = None;
    assert_eq!(h.state.join(&r2, "1.1.1.1").unwrap_err().code.as_str(), "bad_request");
}

#[test]
fn relay_cidr_outside_allowed_rejected() {
    let h = harness();
    let mut r = req("r1", Role::Relay);
    r.local_cidrs = vec!["192.168.99.0/24".parse().unwrap()];
    assert_eq!(h.state.join(&r, "1.1.1.1").unwrap_err().code.as_str(), "prefix_conflict");
}

#[test]
fn overlapping_registration_age_resolves() {
    let h = harness();
    let mut r1 = req("r1", Role::Relay);
    r1.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    h.state.join(&r1, "1.1.1.1").unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut r2 = req("r2", Role::Relay);
    r2.local_cidrs = vec!["192.168.1.0/24".parse().unwrap()];
    h.state.join(&r2, "1.1.1.1").unwrap();

    let ns = h.state.networks["n1"].lock().unwrap();
    let owners = ns.registry.resolve_owners();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].1[0].0, "r1", "older registration owns");
    assert_eq!(owners[0].1[1].0, "r2", "younger is standby");
}

#[test]
fn disabled_member_rejected_then_enable_restores() {
    let h = harness();
    h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    {
        let mut ns = h.state.networks["n1"].lock().unwrap();
        ns.registry.members.get_mut("c1").unwrap().disabled = true;
    }
    assert_eq!(
        h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap_err().code.as_str(), "client_disabled"
    );
    {
        let mut ns = h.state.networks["n1"].lock().unwrap();
        ns.registry.members.get_mut("c1").unwrap().disabled = false;
    }
    h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
}

#[test]
fn registry_survives_reload() {
    let h = harness();
    let a = h.state.join(&req("c1", Role::Client), "1.1.1.1").unwrap();
    let (path, uuid) = {
        let ns = h.state.networks["n1"].lock().unwrap();
        (ns.registry_path.clone(), ns.registry.network_uuid)
    };
    let reloaded = Registry::load_or_create(&path).unwrap();
    assert_eq!(reloaded.network_uuid, uuid);
    assert_eq!(reloaded.members["c1"].ip4, a.ip4);
    assert_eq!(reloaded.members["c1"].node_id, a.node_id);
    assert_eq!(reloaded.members["c1"].pubkey.as_deref(), Some("PK-c1"));
}

/// The embedded UI must actually be served, be self-contained (a strict
/// air-gapped deployment has no CDN), and never carry a baked-in token.
#[test]
fn embedded_ui_is_self_contained() {
    let html = include_str!("../ui/index.html");
    assert!(html.contains("<title>nqvpn control plane</title>"));
    // The SVG namespace is an identifier, not an address — nothing ever
    // fetches it — so it is the one URL-shaped string allowed through.
    const SVG_NS: &str = "http://www.w3.org/2000/svg";
    let external = html.replace(SVG_NS, "");
    assert!(
        !external.contains("http://") && !external.contains("https://"),
        "UI must not reference external hosts"
    );
    assert!(
        !html.contains("<script src") && !html.contains("<link rel=\"stylesheet\""),
        "UI must not load external assets"
    );
    assert!(!html.contains("dev-admin-token"), "UI must not embed a credential");
    // Every admin capability must be reachable from the UI. Paths are
    // built from templates, so check the distinctive fragments.
    for frag in [
        "/api/v1/status",
        "/api/v1/reload",
        "/api/v1/networks/",
        "/status`",
        "'enable' : 'disable'",
        "/reset-pin",
        // The stats and topology tabs read these; a schema rename that
        // silently empties them should fail here, not in a browser.
        "relay_traffic",
        "tx_bytes",
        "attached_relay",
        "data-tab=\"stats\"",
        "data-tab=\"topology\"",
        // Rotation state must stay visible: a member with two live pins
        // is mid-rotation, and that is not something to hide behind the
        // word "pinned".
        "showPins",
        // The secrets tab must stay wired to the API, and must never
        // grow a way to read a secret back.
        "data-tab=\"secrets\"",
        "/api/v1/secrets",
        "/mint",
        "shown once",
        // Deletion must stay behind an explanatory confirm, and the
        // secrets form must not be rebuilt by the refresh timer.
        "confirmModal",
        "Delete member",
        "renderSecrets",
        "Issue credential",
        "config fallback",
        "retires_unix",
        "rotating",
    ] {
        assert!(html.contains(frag), "UI should exercise {frag}");
    }
}

/// Allocation must be atomic under contention: many members joining at
/// once must never receive the same address. The read-decide-write is
/// one critical section per network, so this is a property test of that
/// invariant rather than of any single code path.
const COORD_TOML: &str = r#"
[listen]
api = "127.0.0.1:0"
[state]
dir = "x"
"#;

#[test]
fn concurrent_joins_never_hand_out_the_same_address() {
    use std::collections::HashSet;
    use std::sync::Arc;

    const N: usize = 24;
    let dir = tempfile::tempdir().unwrap();
    // A network with room for everyone, and a pool small enough that a
    // race would collide immediately rather than by luck.
    let toml = format!(
        r#"
network_id = "n1"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/24"
{}
"#,
        (0..N)
            .map(|i| format!("[clients.c{i}]
secret_hash = '{}'
", hash(SECRET)))
            .collect::<String>()
    );
    let net_cfg: NetworkConfig = toml::from_str(&toml).unwrap();
    let registry_path = dir.path().join("registry-n1.json");
    let registry = Registry::load_or_create(&registry_path).unwrap();
    let mut networks = HashMap::new();
    networks.insert("n1".to_string(), Mutex::new(NetState::new(net_cfg, registry, registry_path)));
    let state = Arc::new(AppState {
        coord: toml::from_str(COORD_TOML).unwrap(),
        admin_token: None,
        networks,
        keyring: Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap(),
        join_rate: Mutex::new(HashMap::new()),
        networks_dir: None,
        secrets: Mutex::new(nqvpn_coord::secrets::SecretStore::default()),
        secrets_path: std::path::PathBuf::from("/nonexistent/secrets.toml"),
    });

    let handles: Vec<_> = (0..N)
        .map(|i| {
            let st = state.clone();
            std::thread::spawn(move || {
                let mut r = req(&format!("c{i}"), Role::Client);
                r.cert_fingerprint = format!("sha256:c{i}");
                r.pubkey = format!("PK-c{i}");
                st.join(&r, "1.1.1.1").map(|resp| (resp.node_id, resp.ip4))
            })
        })
        .collect();

    let mut ips = HashSet::new();
    let mut ids = HashSet::new();
    for h in handles {
        let (node_id, ip4) = h.join().expect("thread panicked").expect("join failed");
        let ip = ip4.expect("every member should get an address");
        assert!(ips.insert(ip), "address {ip} was handed out twice");
        assert!(ids.insert(node_id), "node id {node_id} was handed out twice");
    }
    assert_eq!(ips.len(), N, "every concurrent joiner got a distinct address");
}

#[test]
fn rate_limit_kicks_in() {
    let h = harness();
    let mut r = req("c1", Role::Client);
    r.client_secret = "wrong".into();
    // The limiter uses a fixed window, so a run that straddles a window
    // boundary gets a fresh budget — assert that the limit bites at all
    // rather than that a particular attempt is the one refused.
    let mut codes = Vec::new();
    for _ in 0..25 {
        codes.push(h.state.join(&r, "2.2.2.2").unwrap_err().code.as_str().to_string());
    }
    assert!(
        codes.iter().any(|c| c == "rate_limited"),
        "expected the limiter to refuse some attempts, got {codes:?}"
    );
}

#[test]
fn headless_join_gets_no_address() {
    let h = harness();
    let mut r = req("c1", Role::Client);
    r.want_vpn_ip = false;
    let resp = h.state.join(&r, "1.1.1.1").unwrap();
    assert!(resp.ip4.is_none());
    assert!(resp.subnet4.is_none());
}

/// A member authenticating with a coordinator-managed secret, and the
/// blast-radius rule that comes with it.
///
/// This is the path that fixes shared secrets: minting is a one-liner, so
/// per-member credentials stop being the painful option.
#[test]
fn a_managed_secret_authenticates_and_carries_its_own_blast_radius() {
    use nqvpn_coord::secrets::{SecretKind, SecretStore};

    let h = harness();
    // c1 is configured with the shared config secret; give it its own.
    let minted = {
        let mut store = h.state.secrets.lock().unwrap();
        store.mint("c1", SecretKind::Client, Some("n1"), 100).unwrap()
    };

    // The managed secret works...
    let mut r = req("c1", Role::Client);
    r.client_secret = minted.secret.clone();
    assert!(h.state.join(&r, "127.0.0.1").is_ok(), "managed secret must authenticate");

    // ...and the old shared config secret no longer does, because the
    // store refuses rather than deferring to the fallback.
    let r = req("c1", Role::Client);
    assert!(
        h.state.join(&r, "127.0.0.1").is_err(),
        "once a member has a managed secret, the config secret must stop working"
    );

    // A member with no managed secret still uses the config: that is the
    // migration path, one member at a time.
    let r = req("r2", Role::Relay);
    assert!(h.state.join(&r, "127.0.0.1").is_ok(), "unmigrated members keep working");
}

/// A client credential must never be usable for a relay join, which is
/// what would let it register routes.
#[test]
fn a_client_secret_cannot_join_as_a_relay() {
    use nqvpn_coord::secrets::{SecretKind, SecretStore};

    let h = harness();
    let minted = {
        let mut store = h.state.secrets.lock().unwrap();
        // Mint a *client* secret under a name configured as a relay.
        store.mint("r1", SecretKind::Client, Some("n1"), 100).unwrap()
    };
    let mut r = req("r1", Role::Relay);
    r.client_secret = minted.secret.clone();
    assert!(
        h.state.join(&r, "127.0.0.1").is_err(),
        "a client credential must not authenticate a relay join"
    );
    let _ = SecretStore::default();
}
