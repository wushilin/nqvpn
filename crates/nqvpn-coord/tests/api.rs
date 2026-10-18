//! Real HTTP integration tests for the admin API — the exact surface the
//! web UI drives. The UI is API-first: it only ever calls `/api/v1/*`,
//! so exercising these endpoints over a real socket is exercising the
//! UI's every capability. The coordinator's router is served on a
//! plain localhost port here (TLS is orthogonal to the API logic); a
//! tiny HTTP/1.1 client drives it, covering auth (bearer + session
//! cookie), network and member CRUD, tokens, disable/enable, the join
//! flow, and export/import.

use nqvpn_coord::config::CoordConfig;
use nqvpn_coord::db::Db;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState};
use nqvpn_proto::token::Token;
use std::net::SocketAddr;
use std::sync::Arc;

const USER: &str = "admin";
const PASSWORD: &str = "s3cr3t-pw";
const BEARER: &str = "script-token";

struct Api {
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}

async fn spawn() -> Api {
    let dir = tempfile::tempdir().unwrap();
    let hash = nqvpn_coord::auth::hash_password(PASSWORD).unwrap();
    let coord: CoordConfig = toml::from_str(&format!(
        "[listen]\napi = \"127.0.0.1:0\"\n[state]\ndir = \"x\"\n[admin]\nuser = \"{USER}\"\npassword_hash = \"{hash}\"\n"
    ))
    .unwrap();
    let db = Arc::new(Db::open_memory().unwrap());
    let keyring = Keyring::load_or_create(&dir.path().join("signing.json"), now_unix()).unwrap();
    let state = Arc::new(AppState::new(coord, Some(BEARER.into()), keyring, db, 14433));
    let app = nqvpn_coord::api::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });
    Api { addr, _dir: dir }
}

struct Resp {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Resp {
    fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).unwrap_or(serde_json::Value::Null)
    }
    fn cookie(&self) -> Option<String> {
        self.headers.iter().find(|(k, _)| k == "set-cookie").map(|(_, v)| {
            v.split(';').next().unwrap_or(v).to_string()
        })
    }
}

/// One request over a fresh connection (`Connection: close`, so the body
/// is everything up to EOF — no chunked/Content-Length parsing needed).
async fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: Option<&str>) -> Resp {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let body = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text.as_str(), ""));
    let mut lines = head.lines();
    let status: u16 = lines.next().unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    Resp { status, headers, body: body.to_string() }
}

fn bearer() -> Vec<(&'static str, &'static str)> {
    vec![("Authorization", "Bearer script-token")]
}

async fn get(a: SocketAddr, path: &str, h: &[(&str, &str)]) -> Resp {
    http(a, "GET", path, h, None).await
}
async fn post(a: SocketAddr, path: &str, h: &[(&str, &str)], body: &str) -> Resp {
    let mut hh = h.to_vec();
    hh.push(("Content-Type", "application/json"));
    http(a, "POST", path, &hh, Some(body)).await
}
async fn put(a: SocketAddr, path: &str, h: &[(&str, &str)], body: &str) -> Resp {
    let mut hh = h.to_vec();
    hh.push(("Content-Type", "application/json"));
    http(a, "PUT", path, &hh, Some(body)).await
}
async fn delete(a: SocketAddr, path: &str, h: &[(&str, &str)]) -> Resp {
    http(a, "DELETE", path, h, None).await
}

#[tokio::test]
async fn admin_endpoints_require_auth_and_the_bearer_token_works() {
    let api = spawn().await;
    assert_eq!(get(api.addr, "/api/v1/status", &[]).await.status, 401, "no auth");
    assert_eq!(get(api.addr, "/api/v1/status", &[("Authorization", "Bearer wrong")]).await.status, 401);
    let r = get(api.addr, "/api/v1/status", &bearer()).await;
    assert_eq!(r.status, 200);
    assert!(r.json()["networks"].is_array());
}

#[tokio::test]
async fn login_yields_a_session_cookie_that_authorizes() {
    let api = spawn().await;
    let bad = post(api.addr, "/api/v1/login", &[], r#"{"user":"admin","password":"nope"}"#).await;
    assert_eq!(bad.status, 401, "wrong password");
    let ok = post(api.addr, "/api/v1/login", &[], r#"{"user":"admin","password":"s3cr3t-pw"}"#).await;
    assert_eq!(ok.status, 200);
    let cookie = ok.cookie().expect("a session cookie is set");
    assert!(cookie.starts_with("nqvpn_session="));
    // The cookie alone authorizes, and /me reports who we are.
    let me = get(api.addr, "/api/v1/me", &[("Cookie", &cookie)]).await;
    assert_eq!(me.status, 200);
    assert_eq!(me.json()["user"], "admin");
    // Logging out invalidates it.
    let out = post(api.addr, "/api/v1/logout", &[("Cookie", &cookie)], "").await;
    assert_eq!(out.status, 200);
    assert_eq!(get(api.addr, "/api/v1/me", &[("Cookie", &cookie)]).await.status, 401, "cookie is dead after logout");
}

#[tokio::test]
async fn an_internet_exit_is_a_capability_on_the_member_not_a_row_in_the_prefix_table() {
    // The prefix table is the LAN active/standby view: one owner, the rest
    // on standby. A default route is neither — every ready exit publishes
    // it and clients choose among them — so listing it there would tell the
    // operator the exact opposite of how exits behave. It belongs on the
    // member row, as the internet_gateway flag.
    let api = spawn().await;
    let a = api.addr;
    let net = r#"{"network_id":"acme","ipv4_cidr":"10.9.0.0/16","settings":{}}"#;
    assert_eq!(post(a, "/api/v1/networks", &bearer(), net).await.status, 200);
    // Both must actually join: routes (the LAN and the internally granted
    // default) are registered at join time, not at configuration time.
    for (i, name) in ["exit-a", "exit-b"].iter().enumerate() {
        let body = format!(
            r#"{{"name":"{name}","role":"relay","relay_addr":"203.0.113.7:4444","local_cidrs":["192.168.1.0/24"],"internet_gateway":true}}"#
        );
        let create = post(a, "/api/v1/networks/acme/members", &bearer(), &body).await;
        assert_eq!(create.status, 200);
        let token = create.json()["token"].as_str().unwrap().to_string();
        let secret = Token::parse(&token).unwrap().secret;
        let k = [7u8 + i as u8; 32];
        let join_body = format!(
            r#"{{"secret":"{secret}","pubkey":"{}","cert_fingerprint":"sha256:{}"}}"#,
            base64_std(&k),
            hex::encode(k)
        );
        let j = post(a, "/api/v1/join", &[], &join_body).await;
        assert_eq!(j.status, 200, "join body: {}", j.body);
        // The default is granted internally, never as a typed CIDR.
        let granted = j.json()["granted_cidrs"].as_array().cloned().unwrap_or_default();
        assert!(granted.iter().any(|c| c == "0.0.0.0/0"), "{name} is granted the default by the flag");
    }

    let net = get(a, "/api/v1/networks/acme/status", &bearer()).await.json();

    for row in net["prefix_table"].as_array().unwrap() {
        let cidr = row["cidr"].as_str().unwrap();
        assert!(cidr != "0.0.0.0/0" && cidr != "::/0", "a default must not be shown as an owned prefix, got {cidr}");
    }
    // The real LAN still is, with one owner and the other on standby.
    assert!(
        net["prefix_table"].as_array().unwrap().iter().any(|r| r["cidr"] == "192.168.1.0/24"),
        "a genuine site prefix is still listed"
    );
    // Both exits carry the capability on their own row, neither as standby.
    let members = net["members"].as_array().unwrap();
    for name in ["exit-a", "exit-b"] {
        let m = members.iter().find(|m| m["name"] == name).unwrap();
        assert_eq!(m["internet_gateway"], true, "{name} is an exit on its own row");
        assert!(
            !m["registered_cidrs"].as_array().unwrap().iter().any(|c| c == "0.0.0.0/0" || c == "::/0"),
            "{name} never surfaces the default as one of its CIDRs"
        );
    }
}

/// The whole operator lifecycle over HTTP, then a member actually
/// joining with the token the API handed out.
#[tokio::test]
async fn network_and_member_lifecycle_over_http() {
    let api = spawn().await;
    let a = api.addr;

    // Create a network.
    let net = r#"{"network_id":"acme","ipv4_cidr":"10.9.0.0/16","settings":{}}"#;
    assert_eq!(post(a, "/api/v1/networks", &bearer(), net).await.status, 200);
    assert!(get(a, "/api/v1/status", &bearer()).await.json()["networks"].as_array().unwrap().iter().any(|n| n["network_id"] == "acme"));

    // Add a relay member; the response carries its token.
    let create = post(
        a,
        "/api/v1/networks/acme/members",
        &bearer(),
        r#"{"name":"home","role":"relay","relay_addr":"203.0.113.7:4444","local_cidrs":["192.168.1.0/24"],"preferred_ip4":"10.9.0.1"}"#,
    )
    .await;
    assert_eq!(create.status, 200);
    let token = create.json()["token"].as_str().unwrap().to_string();
    let secret = Token::parse(&token).unwrap().secret;

    // It shows up in the network config the UI reads.
    let cfg = get(a, "/api/v1/networks/acme/config", &bearer()).await.json();
    assert_eq!(cfg["ipv4_cidr"], "10.9.0.0/16");
    assert!(cfg["ipv6_cidr"].is_null());
    assert!(cfg.get("cidrs").is_none() && cfg.get("pools").is_none());
    assert!(cfg["members"].as_array().unwrap().iter().any(|m| m["name"] == "home" && m["role"] == "relay"));

    // A real join with that secret is accepted and gets its configured facts.
    let join_body = format!(
        r#"{{"secret":"{secret}","pubkey":"{}","cert_fingerprint":"sha256:{}"}}"#,
        base64_std(&[7u8; 32]),
        hex::encode([7u8; 32])
    );
    let joined = post(a, "/api/v1/join", &[], &join_body).await;
    assert_eq!(joined.status, 200, "join body: {}", joined.body);
    let j = joined.json();
    assert_eq!(j["role"], "relay");
    assert_eq!(j["network_id"], "acme");
    assert_eq!(j["name"], "home");
    assert_eq!(j["ip4"], "10.9.0.1");
    assert!(j["granted_cidrs"].as_array().unwrap().iter().any(|c| c == "192.168.1.0/24"));
    assert_eq!(j["relay_addr"], "203.0.113.7:4444");

    // Rotate the token: the old secret stops working, the new one works.
    let rot = post(a, "/api/v1/networks/acme/members/home/token", &bearer(), "").await;
    assert_eq!(rot.status, 200);
    let new_secret = Token::parse(rot.json()["token"].as_str().unwrap()).unwrap().secret;
    assert_ne!(new_secret, secret);
    assert_eq!(post(a, "/api/v1/join", &[], &join_body).await.status, 401, "old secret is dead");
    let join2 = format!(
        r#"{{"secret":"{new_secret}","pubkey":"{}","cert_fingerprint":"sha256:{}"}}"#,
        base64_std(&[7u8; 32]),
        hex::encode([7u8; 32])
    );
    assert_eq!(post(a, "/api/v1/join", &[], &join2).await.status, 200, "new secret works");

    // Disable → join refused; enable → accepted again.
    assert_eq!(post(a, "/api/v1/networks/acme/members/home/disable", &bearer(), "").await.status, 200);
    let refused = post(a, "/api/v1/join", &[], &join2).await;
    assert_eq!(refused.status, 403);
    assert_eq!(refused.json()["error"]["code"], "client_disabled");
    assert_eq!(post(a, "/api/v1/networks/acme/members/home/enable", &bearer(), "").await.status, 200);
    assert_eq!(post(a, "/api/v1/join", &[], &join2).await.status, 200);

    // Edit the member (the UI's PUT), then delete it, then the network.
    assert_eq!(
        put(a, "/api/v1/networks/acme/members/home", &bearer(), r#"{"relay_addr":"auto:4444","local_cidrs":[]}"#).await.status,
        200
    );
    assert_eq!(delete(a, "/api/v1/networks/acme/members/home", &bearer()).await.status, 200);
    assert_eq!(delete(a, "/api/v1/networks/acme", &bearer()).await.status, 200);
    assert!(get(a, "/api/v1/status", &bearer()).await.json()["networks"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn export_import_round_trips() {
    let api = spawn().await;
    let a = api.addr;
    post(a, "/api/v1/networks", &bearer(), r#"{"network_id":"n","ipv4_cidr":"10.0.0.0/16","settings":{}}"#).await;
    post(a, "/api/v1/networks/n/members", &bearer(), r#"{"name":"c1","role":"client"}"#).await;
    let export = get(a, "/api/v1/export", &bearer()).await;
    assert_eq!(export.status, 200);
    assert_eq!(delete(a, "/api/v1/networks/n", &bearer()).await.status, 200);
    assert!(get(a, "/api/v1/status", &bearer()).await.json()["networks"].as_array().unwrap().is_empty());
    let imp = post(a, "/api/v1/import", &bearer(), &export.body).await;
    assert_eq!(imp.status, 200);
    let cfg = get(a, "/api/v1/networks/n/config", &bearer()).await.json();
    assert!(cfg["members"].as_array().unwrap().iter().any(|m| m["name"] == "c1"));
}

#[tokio::test]
async fn bad_requests_are_reported_with_a_code() {
    let api = spawn().await;
    let a = api.addr;
    // A relay without an address is refused at creation.
    post(a, "/api/v1/networks", &bearer(), r#"{"network_id":"n","ipv4_cidr":"10.0.0.0/16","settings":{}}"#).await;
    let bad = post(a, "/api/v1/networks/n/members", &bearer(), r#"{"name":"r","role":"relay"}"#).await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.json()["error"]["code"], "bad_request");
    // Unknown network is a 404.
    assert_eq!(get(a, "/api/v1/networks/nope/config", &bearer()).await.status, 404);
}

#[tokio::test]
async fn assigning_an_address_held_by_another_member_is_rejected_atomically() {
    let api = spawn().await;
    let a = api.addr;
    let net = r#"{"network_id":"n","ipv4_cidr":"10.8.1.0/29","settings":{}}"#;
    assert_eq!(post(a, "/api/v1/networks", &bearer(), net).await.status, 200);

    let mut assigned = Vec::new();
    for (i, name) in ["alice", "bob"].iter().enumerate() {
        let create = post(
            a,
            "/api/v1/networks/n/members",
            &bearer(),
            &format!(r#"{{"name":"{name}","role":"client"}}"#),
        )
        .await;
        assert_eq!(create.status, 200);
        let secret = Token::parse(create.json()["token"].as_str().unwrap()).unwrap().secret;
        let key = [20 + i as u8; 32];
        let join = post(
            a,
            "/api/v1/join",
            &[],
            &format!(
                r#"{{"secret":"{secret}","pubkey":"{}","cert_fingerprint":"sha256:{}"}}"#,
                base64_std(&key),
                hex::encode(key)
            ),
        )
        .await;
        assert_eq!(join.status, 200, "join body: {}", join.body);
        assigned.push(join.json()["ip4"].as_str().unwrap().to_string());
    }

    let edit = put(
        a,
        "/api/v1/networks/n/members/alice",
        &bearer(),
        &format!(r#"{{"preferred_ip4":"{}"}}"#, assigned[1]),
    )
    .await;
    assert_eq!(edit.status, 409, "conflicting edit must fail: {}", edit.body);
    assert_eq!(edit.json()["error"]["code"], "address_in_use");
    assert!(edit.json()["error"]["message"].as_str().unwrap().contains("bob"));

    // Validation happens before both the in-memory swap and the database
    // commit, so a failed Save cannot linger and take effect later.
    let cfg = get(a, "/api/v1/networks/n/members/alice", &bearer()).await.json();
    assert!(cfg["preferred_ip4"].is_null());
    let status = get(a, "/api/v1/networks/n/status", &bearer()).await.json();
    let alice = status["members"].as_array().unwrap().iter().find(|m| m["name"] == "alice").unwrap();
    assert_eq!(alice["ip4"], assigned[0]);
}

#[tokio::test]
async fn an_empty_bearer_token_is_never_a_credential() {
    let api = spawn().await;
    for h in ["Bearer ", "Bearer    ", "Bearer"] {
        assert_eq!(get(api.addr, "/api/v1/status", &[("Authorization", h)]).await.status, 401, "{h:?}");
    }
}

#[tokio::test]
async fn a_cross_origin_request_with_the_session_cookie_is_refused() {
    let api = spawn().await;
    let a = api.addr;
    let ok = post(a, "/api/v1/login", &[], r#"{"user":"admin","password":"s3cr3t-pw"}"#).await;
    let cookie = ok.cookie().unwrap();
    let net = r#"{"network_id":"x","ipv4_cidr":"10.7.0.0/16","settings":{}}"#;
    let evil = post(a, "/api/v1/networks", &[("Cookie", &cookie), ("Origin", "https://evil.example")], net).await;
    assert_eq!(evil.status, 403, "{}", evil.body);
    assert!(get(a, "/api/v1/status", &bearer()).await.json()["networks"].as_array().unwrap().is_empty());
    // The coordinator's own page (Origin = the Host it was served from) is fine,
    // and so is a request with no Origin at all.
    let own = post(a, "/api/v1/networks", &[("Cookie", &cookie), ("Origin", "https://localhost")], net).await;
    assert_eq!(own.status, 200, "{}", own.body);
    let net2 = r#"{"network_id":"y","ipv4_cidr":"10.6.0.0/16","settings":{}}"#;
    assert_eq!(post(a, "/api/v1/networks", &[("Cookie", &cookie)], net2).await.status, 200);
    // A script with the bearer token is not judged by Origin.
    let net3 = r#"{"network_id":"z","ipv4_cidr":"10.5.0.0/16","settings":{}}"#;
    let mut h = bearer();
    h.push(("Origin", "https://dashboard.example"));
    assert_eq!(post(a, "/api/v1/networks", &h, net3).await.status, 200);
    // The live feed's upgrade is checked the same way.
    let ws = get(
        a,
        "/api/v1/ws",
        &[
            ("Cookie", &cookie),
            ("Origin", "https://evil.example"),
            ("Upgrade", "websocket"),
            ("Connection", "upgrade"),
            ("Sec-WebSocket-Version", "13"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ],
    )
    .await;
    assert_eq!(ws.status, 403);
}

#[tokio::test]
async fn login_attempts_are_counted_before_the_password_is_checked() {
    let api = spawn().await;
    let a = api.addr;
    // Fire more concurrent wrong guesses than the per-minute allowance:
    // counting first means some are refused outright, however they race.
    let window = now_unix() / 60;
    let n = nqvpn_coord::auth::MAX_LOGIN_ATTEMPTS_PER_MIN as usize + 6;
    let tasks: Vec<_> = (0..n)
        .map(|_| tokio::spawn(async move { post(a, "/api/v1/login", &[], r#"{"user":"admin","password":"nope"}"#).await.status }))
        .collect();
    let mut codes = Vec::new();
    for t in tasks {
        codes.push(t.await.unwrap());
    }
    let late = post(a, "/api/v1/login", &[], r#"{"user":"admin","password":"s3cr3t-pw"}"#).await;
    if now_unix() / 60 != window {
        return; // the one-minute window rolled mid-test (argon2 is slow in debug builds)
    }
    let unauthorized = codes.iter().filter(|c| **c == 401).count();
    assert!(unauthorized <= nqvpn_coord::auth::MAX_LOGIN_ATTEMPTS_PER_MIN as usize, "{codes:?}");
    assert!(codes.contains(&429), "{codes:?}");
    // The right password is refused too, now: the source is out of attempts.
    assert_eq!(late.status, 429);
}

#[tokio::test]
async fn an_invalid_import_changes_nothing() {
    let api = spawn().await;
    let a = api.addr;
    post(a, "/api/v1/networks", &bearer(), r#"{"network_id":"n","ipv4_cidr":"10.0.0.0/16","settings":{}}"#).await;
    post(a, "/api/v1/networks/n/members", &bearer(), r#"{"name":"c1","role":"client"}"#).await;
    let export = get(a, "/api/v1/export", &bearer()).await.json();
    // One good network and one with an invalid id: neither is applied.
    let mut fresh = export[0].clone();
    fresh["network_id"] = "fresh".into();
    fresh["clients"] = serde_json::json!({});
    let mut bad = export[0].clone();
    bad["network_id"] = "../etc".into();
    bad["clients"] = serde_json::json!({});
    let body = serde_json::to_string(&serde_json::json!([fresh, bad])).unwrap();
    let r = post(a, "/api/v1/import", &bearer(), &body).await;
    assert_eq!(r.status, 400, "{}", r.body);
    let nets = get(a, "/api/v1/status", &bearer()).await.json();
    assert_eq!(nets["networks"].as_array().unwrap().len(), 1, "the valid network in a refused import is not created");
}

fn base64_std(b: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(b)
}
