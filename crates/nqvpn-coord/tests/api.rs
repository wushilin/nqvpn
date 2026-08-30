//! Real HTTP integration tests for the admin API — the exact surface the
//! web UI drives. The UI is API-first: it only ever calls `/api/v1/*`,
//! so exercising these endpoints over a real socket is exercising the
//! UI's every capability. The coordinator's router is served on a
//! plain localhost port here (TLS is orthogonal to the API logic); a
//! tiny HTTP/1.1 client drives it, covering auth (bearer + session
//! cookie), network and member CRUD, tokens, disable/enable, the join
//! flow, and export/import.

use nqvpn_coord::config::{CoordConfig, NetworkConfig};
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

/// The whole operator lifecycle over HTTP, then a member actually
/// joining with the token the API handed out.
#[tokio::test]
async fn network_and_member_lifecycle_over_http() {
    let api = spawn().await;
    let a = api.addr;

    // Create a network.
    let net = r#"{"network_id":"acme","cidrs":["10.9.0.0/16"],"pools":{"default":{"cidr":"10.9.1.0/24"}},"settings":{}}"#;
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
    post(a, "/api/v1/networks", &bearer(), r#"{"network_id":"n","cidrs":["10.0.0.0/16"],"pools":{},"settings":{}}"#).await;
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
    post(a, "/api/v1/networks", &bearer(), r#"{"network_id":"n","cidrs":["10.0.0.0/16"],"pools":{},"settings":{}}"#).await;
    let bad = post(a, "/api/v1/networks/n/members", &bearer(), r#"{"name":"r","role":"relay"}"#).await;
    assert_eq!(bad.status, 400);
    assert_eq!(bad.json()["error"]["code"], "bad_request");
    // Unknown network is a 404.
    assert_eq!(get(a, "/api/v1/networks/nope/config", &bearer()).await.status, 404);
}

fn base64_std(b: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(b)
}
