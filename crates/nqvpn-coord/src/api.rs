//! Axum router: the member realm (`/join`) and the admin realm — the UI
//! is a client of the admin API and nothing more. Admin auth is a
//! bearer token from `coordinator.toml`.

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use nqvpn_proto::api::*;
use nqvpn_proto::types::{NodeId, Role};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::admin::{MemberSpec, NetworkSpec};
use crate::config::NetworkConfig;
use crate::error::ApiError;
use crate::state::{lock_for_sweep, now_unix, rate_key, AppState};

/// A join or login request is a few hundred bytes; nothing bigger is
/// read.
const SMALL_BODY_LIMIT: usize = 8 * 1024;

/// The admin UI, compiled into the binary: no separate deployment, no
/// external assets, works air-gapped. Strictly a client of the API.
const UI_HTML: &str = include_str!("../ui/index.html");

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/join", post(join).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)))
        .route("/api/v1/login", post(login).layer(DefaultBodyLimit::max(SMALL_BODY_LIMIT)))
        .route("/api/v1/logout", post(logout))
        .route("/api/v1/me", get(me))
        .route("/api/v1/ws", get(ws_upgrade))
        .route("/api/v1/ca", get(coordinator_ca))
        .route("/api/v1/status", get(global_status))
        .route("/api/v1/networks", get(list_networks).post(create_network))
        .route("/api/v1/networks/{id}", put(update_network).delete(delete_network))
        .route("/api/v1/networks/{id}/status", get(network_status))
        .route("/api/v1/networks/{id}/config", get(network_config))
        .route("/api/v1/networks/{id}/members", post(create_member))
        .route("/api/v1/networks/{id}/members/{name}", get(member_config).put(update_member).delete(delete_member))
        .route("/api/v1/networks/{id}/members/{name}/disable", post(|s, p| set_disabled(s, p, true)))
        .route("/api/v1/networks/{id}/members/{name}/enable", post(|s, p| set_disabled(s, p, false)))
        .route("/api/v1/networks/{id}/members/{name}/token", get(member_token).post(rotate_member))
        .route("/api/v1/networks/{id}/members/{name}/reconnect", post(reconnect_member))
        .route("/api/v1/export", get(export))
        .route("/api/v1/import", post(import))
        .route("/ui", get(ui))
        .route("/ui/", get(ui))
        .route("/", get(|| async { axum::response::Redirect::temporary("/ui") }))
        .layer(axum::middleware::from_fn_with_state(state.clone(), origin_guard))
        .with_state(state)
}

/// CSRF defense in depth (the session cookie is already SameSite=Strict):
/// a browser request that carries the session cookie and changes state —
/// or opens the live feed — must come from this coordinator's own page.
/// Browsers always send `Origin` on such requests; scripts using the
/// bearer token send no cookie and are not affected.
async fn origin_guard(State(state): State<Arc<AppState>>, req: Request, next: Next) -> Result<Response, ApiError> {
    let changes_state = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let is_ws = req.uri().path() == "/api/v1/ws";
    if (changes_state || is_ws) && crate::auth::cookie_token(req.headers()).is_some() {
        if let Some(origin) = req.headers().get("origin") {
            let origin = origin.to_str().unwrap_or("null");
            if !same_origin(&state, origin, req.headers(), req.uri()) {
                tracing::warn!(%origin, path = %req.uri().path(), "refusing a cross-origin request carrying the admin session cookie");
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    nqvpn_proto::errors::ErrorCode::AdminAuthRequired,
                    "cross-origin request refused",
                ));
            }
        }
    }
    Ok(next.run(req).await)
}

/// Whether an `Origin` names the host this request was sent to (or the
/// configured public URL).
fn same_origin(state: &AppState, origin: &str, headers: &HeaderMap, uri: &axum::http::Uri) -> bool {
    fn authority(url: &str) -> Option<String> {
        let (scheme, rest) = url.split_once("://")?;
        let host = rest.split('/').next()?.to_ascii_lowercase();
        let default = match scheme {
            "https" => ":443",
            "http" => ":80",
            _ => return None,
        };
        Some(host.strip_suffix(default).map(str::to_string).unwrap_or(host))
    }
    fn strip_default(host: &str) -> String {
        let h = host.to_ascii_lowercase();
        h.strip_suffix(":443").map(str::to_string).unwrap_or(h)
    }
    let Some(origin) = authority(origin) else { return false };
    let mut candidates: Vec<String> = Vec::new();
    for h in ["host", "x-forwarded-host"] {
        if let Some(v) = headers.get(h).and_then(|v| v.to_str().ok()) {
            candidates.push(strip_default(v));
        }
    }
    if let Some(a) = uri.authority() {
        candidates.push(strip_default(a.as_str()));
    }
    if let Some(u) = state.coord.listen.public_url.as_deref().and_then(authority) {
        candidates.push(u);
    }
    candidates.contains(&origin)
}

/// Admin access: a UI session (cookie, or the session token as a
/// bearer) or the static bearer token from the config.
pub(crate) fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let bearer = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());
    if let Some(t) = &bearer {
        if let Some(cfg) = state.admin_token.as_deref().filter(|c| !c.is_empty()) {
            if crate::secrets::constant_time_eq(t, cfg) {
                return Ok(());
            }
        }
        if state.auth.lookup(t).is_some() {
            return Ok(());
        }
    }
    if let Some(c) = crate::auth::cookie_token(headers) {
        if state.auth.lookup(&c).is_some() {
            return Ok(());
        }
    }
    if state.admin_token.is_none() && state.coord.admin.password_hash.is_none() {
        return Err(ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            nqvpn_proto::errors::ErrorCode::Unknown("admin_disabled".into()),
            "no admin login configured: set [admin] user + password_hash (nqvpn-coord hash-password) or bearer_token",
        ));
    }
    Err(ApiError::unauthorized_admin())
}

#[derive(Debug, Deserialize)]
struct LoginReq {
    user: String,
    password: String,
}

/// UI login: argon2 check (on the blocking pool — it is meant to be
/// slow), then a session cookie. Attempts are limited per address and
/// counted before the check; at most `LOGIN_SLOTS` checks run at once
/// (each takes 19 MiB), and a login that finds none free is refused.
async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Result<Response, ApiError> {
    let ip = peer.ip().to_string();
    let key = rate_key(&ip);
    let (user, hash) = match (&state.coord.admin.user, &state.coord.admin.password_hash) {
        (Some(u), Some(h)) => (u.clone(), h.clone()),
        _ => {
            return Err(ApiError::new(
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                nqvpn_proto::errors::ErrorCode::Unknown("admin_disabled".into()),
                "no admin login configured: set [admin] user and password_hash (nqvpn-coord hash-password)",
            ))
        }
    };
    // Count first: concurrent guesses all land in the counter before any
    // of them is checked. A success is refunded below.
    let allowed = state
        .login_rate
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .check(key.clone(), crate::auth::MAX_LOGIN_ATTEMPTS_PER_MIN, now_unix());
    if !allowed {
        return Err(ApiError::rate_limited());
    }
    let Ok(slot) = state.login_slots.clone().try_acquire_owned() else {
        return Err(ApiError::rate_limited());
    };
    // The password is checked whatever the user name, so a wrong name
    // takes as long as a wrong password.
    let user_ok = crate::secrets::constant_time_eq(&user, &req.user);
    let password = req.password;
    let password_ok = tokio::task::spawn_blocking(move || {
        let _slot = slot; // held until the hash is done, even if the request is dropped
        crate::auth::verify_password(&password, &hash)
    })
    .await
    .unwrap_or(false);
    if !(user_ok && password_ok) {
        tracing::warn!(%ip, user = %req.user, "admin login failed");
        return Err(ApiError::new(axum::http::StatusCode::UNAUTHORIZED, nqvpn_proto::errors::ErrorCode::AdminAuthRequired, "wrong user or password"));
    }
    state.login_rate.lock().unwrap_or_else(|e| e.into_inner()).refund(&key);
    let ttl = state.coord.admin.session_hours.max(1) * 3600;
    let (token, expires) = state.auth.open(&user, ttl);
    tracing::info!(%ip, %user, "admin logged in");
    let cookie = format!("{}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={ttl}", crate::auth::COOKIE);
    let body = Json(serde_json::json!({ "ok": true, "user": user, "expires_unix": expires }));
    Ok(([("set-cookie", cookie)], body).into_response())
}

async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(c) = crate::auth::cookie_token(&headers) {
        state.auth.close(&c);
    }
    let cookie = format!("{}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", crate::auth::COOKIE);
    ([("set-cookie", cookie)], Json(serde_json::json!({ "ok": true }))).into_response()
}

/// Who am I (for the page to know whether it needs to log in).
async fn me(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let user = crate::auth::cookie_token(&headers)
        .and_then(|c| state.auth.lookup(&c))
        .map(|s| s.user)
        .unwrap_or_else(|| "token".into());
    Ok(Json(serde_json::json!({ "user": user, "login_configured": state.coord.admin.password_hash.is_some() })))
}

/// The coordinator's own certificate (public), so the UI can hand
/// members a config that verifies it. No auth: a certificate is public.
async fn coordinator_ca(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    let cert = state.coord_cert.lock().unwrap().clone();
    match cert {
        Some((pem, self_signed)) => Ok(Json(serde_json::json!({ "pem": pem, "self_signed": self_signed }))),
        None => Err(ApiError::not_found("coordinator certificate is not available")),
    }
}

async fn ws_upgrade(State(state): State<Arc<AppState>>, headers: HeaderMap, ws: WebSocketUpgrade) -> Result<Response, ApiError> {
    check_admin(&state, &headers)?;
    // The feed re-checks these credentials on every frame: logging out
    // (or the session expiring) ends it.
    Ok(ws.on_upgrade(move |socket| crate::ws::serve(state, socket, headers)))
}

/// One frame of the live feed: every network's summary and status.
pub fn live_frame(state: &AppState) -> Result<String, ApiError> {
    let mut networks = Vec::new();
    let mut status = serde_json::Map::new();
    for (id, net) in state.nets() {
        let Some(ns) = lock_for_sweep(&id, &net) else { continue };
        networks.push(NetworkSummary {
            network_id: id.clone(),
            members_total: ns.cfg.members().count(),
            relays_total: ns.cfg.relays.len(),
            members_online: ns.leases.online_nodes().len(),
            gen: ns.directory.gen,
        });
        status.insert(id.clone(), serde_json::to_value(status_of(&ns, &id)).unwrap_or_default());
    }
    serde_json::to_string(&serde_json::json!({ "type": "status", "networks": networks, "status": status, "now_unix": now_unix() }))
        .map_err(|e| ApiError::internal(e.to_string()))
}

/// The URL that goes into tokens: configured, else the one the admin's
/// browser used to reach us — which is what members can reach too, in
/// the common case.
fn public_url(state: &AppState, headers: &HeaderMap, uri: &axum::http::Uri) -> String {
    if let Some(u) = &state.coord.listen.public_url {
        return u.trim_end_matches('/').to_string();
    }
    // HTTP/1.1 carries the host in a header; HTTP/2 in the :authority
    // pseudo-header, which hyper exposes on the URI.
    let host = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| uri.authority().map(|a| a.to_string()))
        .unwrap_or_else(|| "localhost".into());
    format!("https://{host}")
}

async fn join(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, ApiError> {
    let ip = peer.ip().to_string();
    let state2 = state.clone();
    let req2 = req.clone();
    // The join fsyncs the registry: keep the reactor responsive.
    let resp = tokio::task::spawn_blocking(move || state2.join(&req2, &ip))
        .await
        .map_err(|e| ApiError::internal(format!("join task: {e}")))??;

    // A relay binds its listener before joining, so its advertised
    // address must answer by now. Probed only after authentication, and
    // only the address the *operator* configured (or, for `auto:`, the
    // address the join came from) — never one the request named — so
    // this is not an open port scanner. "warn" probes in the background
    // and only reports; "deny" probes first and refuses the join (the
    // relay retries) if nothing answers.
    if resp.role == Role::Relay {
        let policy = state
            .net(&resp.network_id)
            .and_then(|n| n.lock().ok().map(|ns| ns.cfg.settings.relay_reachability.clone()));
        if let (Some(policy), Some(addr)) = (policy, resp.relay_addr.clone()) {
            let (st, netid, node) = (state.clone(), resp.network_id.clone(), resp.node_id);
            let probe = async move {
                let verdict = crate::reach::probe(&addr, std::time::Duration::from_secs(5)).await;
                if verdict == crate::reach::Reachability::Unreachable {
                    tracing::warn!(network = %netid, node_id = node, %addr, "advertised relay address is not dialable from the coordinator");
                }
                if let Some(net) = st.net(&netid) {
                    if let Ok(mut ns) = net.lock() {
                        ns.directory.reachability.insert(node, verdict);
                    }
                }
                verdict
            };
            match policy.as_str() {
                "off" => {}
                "deny" => {
                    if probe.await == crate::reach::Reachability::Unreachable {
                        return Err(ApiError::relay_unreachable(resp.relay_addr.as_deref().unwrap_or_default()));
                    }
                }
                _ => {
                    tokio::spawn(probe);
                }
            }
        }
    }
    Ok(Json(resp))
}

async fn global_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<GlobalStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let mut networks = Vec::new();
    for (id, net) in state.nets() {
        let Some(ns) = lock_for_sweep(&id, &net) else { continue };
        networks.push(NetworkSummary {
            network_id: id.clone(),
            members_total: ns.cfg.members().count(),
            relays_total: ns.cfg.relays.len(),
            members_online: ns.leases.online_nodes().len(),
            gen: ns.directory.gen,
        });
    }
    Ok(Json(GlobalStatus { networks }))
}

async fn list_networks(state: State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<GlobalStatus>, ApiError> {
    global_status(state, headers).await
}

async fn create_network(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(spec): Json<NetworkSpec>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let id = spec.network_id.clone();
    state.create_network(spec)?;
    Ok(Json(serde_json::json!({ "ok": true, "network_id": id })))
}

async fn update_network(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(spec): Json<NetworkSpec>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.update_network(&id, spec)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn delete_network(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.delete_network(&id)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// The network's configuration as the UI edits it. Secrets are not
/// included; tokens have their own endpoint.
async fn network_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.net(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();
    let c = &ns.cfg;
    let members: Vec<serde_json::Value> = c
        .members()
        .map(|(name, m, role)| {
            let mut v = serde_json::to_value(MemberSpec::from_cfg(m)).unwrap_or_default();
            v["name"] = serde_json::Value::String(name.clone());
            v["role"] = serde_json::Value::String(role.to_string());
            v["has_secret"] = serde_json::Value::Bool(m.secret.is_some());
            v
        })
        .collect();
    Ok(Json(serde_json::json!({
        "network_id": c.network_id,
        "ipv4_cidr": c.ipv4_cidr(),
        "ipv6_cidr": c.ipv6_cidr(),
        "settings": c.settings,
        "members": members,
    })))
}

async fn network_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NetworkStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.net(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();
    Ok(Json(status_of(&ns, &id)))
}

pub fn status_of(ns: &crate::state::NetState, id: &str) -> NetworkStatus {
    let now = now_unix();
    let attachments = ns.leases.attachments();
    let name_of = |node_id: NodeId| -> String {
        ns.registry.members.get(&node_id).map(|r| r.name.clone()).unwrap_or_else(|| format!("#{node_id}"))
    };

    let mut members = Vec::new();
    // Every configured member, joined or not; plus registry-only
    // leftovers (a member deleted from config but not yet forgotten).
    for (name, m, role) in ns.cfg.members() {
        let rec = ns.registry.by_name(name);
        let node_id = rec.map(|r| r.node_id).unwrap_or(0);
        let report = ns.leases.report(node_id);
        members.push(MemberStatus {
            name: name.clone(),
            node_id,
            role,
            online: rec.is_some() && ns.leases.is_online(node_id),
            disabled: rec.map(|r| r.disabled).unwrap_or(false),
            ip4: rec.and_then(|r| r.ip4).or(m.preferred_ip4),
            ip6: rec.and_then(|r| r.ip6).or(m.preferred_ip6),
            // The internally-granted default route (the internet-gateway
            // mechanism) is surfaced via `internet_gateway`, not as a CIDR.
            registered_cidrs: rec
                .map(|r| r.routes.iter().map(|x| x.cidr).filter(|c| c.prefix_len() != 0).collect())
                .unwrap_or_else(|| m.local_cidrs.clone()),
            attached_relay: attachments.get(&node_id).map(|r| name_of(*r)),
            advertised_reachable: (role == Role::Relay)
                .then(|| ns.directory.reachability.get(&node_id).copied())
                .flatten()
                .map(|r| r.as_str().to_string()),
            last_join_unix: rec.and_then(|r| r.last_join_unix),
            last_join_from: rec.and_then(|r| r.last_join_from.clone()),
            login_gen: rec.map(|r| r.login_gen).unwrap_or(0),
            replaced_unix: rec.and_then(|r| r.replaced_unix),
            replaced_from: rec.and_then(|r| r.replaced_from.clone()),
            reported_gen: report.map(|r| r.gen),
            digest_ok: report.map(|r| r.gen == ns.directory.gen && r.digest == ns.directory.published_digest).unwrap_or(false),
            last_heartbeat_unix: ns.leases.last_seen(node_id).map(|ms| ms / 1000),
            internet_gateway: role == Role::Relay && m.internet_gateway == Some(true),
            exit_ready: (role == Role::Relay && m.internet_gateway == Some(true))
                .then(|| ns.directory.exit_readiness.get(&node_id).copied())
                .flatten(),
        });
    }

    let mut prefix_table = Vec::new();
    for (cidr, regs) in ns.registry.resolve_owners() {
        // A default route is an internet-exit designation, not a site, and
        // ownership of it is not exclusive: every ready exit publishes it,
        // and clients pick among them. Showing it here would run it through
        // the LAN active/standby lens and claim one owner with the rest on
        // standby — the exact opposite of how exits are actually used. The
        // member rows carry it as the `internet_gateway` pill instead.
        if cidr.prefix_len() == 0 {
            continue;
        }
        let key = cidr.to_string();
        match ns.directory.owners.get(&key) {
            None => prefix_table.push(PrefixOwner {
                cidr,
                owner: "(withdrawn)".into(),
                owner_node_id: 0,
                standby: regs.iter().map(|(n, _)| name_of(*n)).collect(),
            }),
            Some(owner) => prefix_table.push(PrefixOwner {
                cidr,
                owner: name_of(*owner),
                owner_node_id: *owner,
                standby: regs.iter().map(|(n, _)| *n).filter(|n| n != owner).map(name_of).collect(),
            }),
        }
    }
    for (node_id, rec) in &ns.registry.members {
        for cidr in [rec.ip4.map(|ip| format!("{ip}/32")), rec.ip6.map(|ip| format!("{ip}/128"))].into_iter().flatten() {
            prefix_table.push(PrefixOwner {
                cidr: cidr.parse().expect("host route"),
                owner: rec.name.clone(),
                owner_node_id: *node_id,
                standby: vec![],
            });
        }
    }

    let mut relay_traffic: Vec<RelayTraffic> = ns
        .directory
        .traffic
        .iter()
        .map(|(relay, sample)| RelayTraffic {
            relay: name_of(*relay),
            node_id: *relay,
            age_secs: now.saturating_sub(sample.at),
            links: sample
                .report
                .links
                .iter()
                .map(|l| RelayLink {
                    peer: name_of(l.peer_id),
                    peer_node_id: l.peer_id,
                    tx_bytes: l.tx_bytes,
                    tx_pkts: l.tx_pkts,
                    rx_bytes: l.rx_bytes,
                    rx_pkts: l.rx_pkts,
                    tx_bps: sample.rate(l, true),
                    rx_bps: sample.rate(l, false),
                    up: l.up,
                })
                .collect(),
            local_bytes: sample.report.local_bytes,
            local_pkts: sample.report.local_pkts,
            terminated_bytes: sample.report.terminated_bytes,
            terminated_pkts: sample.report.terminated_pkts,
        })
        .collect();
    relay_traffic.sort_by_key(|r| r.node_id);

    NetworkStatus {
        network_id: id.to_string(),
        network_uuid: ns.registry.network_uuid.to_string(),
        gen: ns.directory.gen,
        members,
        prefix_table,
        relay_traffic,
        transport: ns.cfg.settings.transport.clone(),
        lanes: ns.cfg.settings.lanes,
    }
}

type MemberPath = Path<(String, String)>;

#[derive(Debug, Deserialize)]
struct NewMember {
    name: String,
    role: Role,
    #[serde(flatten)]
    spec: MemberSpec,
}

fn token_json(state: &AppState, headers: &HeaderMap, uri: &axum::http::Uri, id: &str, name: &str) -> Result<serde_json::Value, ApiError> {
    let endpoint = public_url(state, headers, uri);
    let (token, role) = state.member_token(id, name, &endpoint)?;
    Ok(serde_json::json!({
        "network_id": id, "name": name, "role": role.to_string(),
        "token": token.encode(), "coordinator": token.coordinator,
    }))
}

/// Declare a member and hand back its token.
async fn create_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path(id): Path<String>,
    Json(m): Json<NewMember>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.create_member(&id, &m.name, m.role, &m.spec)?;
    Ok(Json(token_json(&state, &headers, &uri, &id, &m.name)?))
}

async fn member_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.net(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();
    let (m, role) = ns.cfg.member_by_name(&name).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
    let mut v = serde_json::to_value(MemberSpec::from_cfg(m)).unwrap_or_default();
    v["name"] = serde_json::Value::String(name.clone());
    v["role"] = serde_json::Value::String(role.to_string());
    Ok(Json(v))
}

/// Change a member's facts; a connected member re-joins and applies.
async fn update_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
    Json(spec): Json<MemberSpec>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.update_member(&id, &name, &spec)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn set_disabled(
    state: State<Arc<AppState>>,
    (headers, Path((id, name))): (HeaderMap, MemberPath),
    disabled: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let State(state) = state;
    check_admin(&state, &headers)?;
    state.set_disabled(&id, &name, disabled)?;
    Ok(Json(serde_json::json!({ "ok": true, "disabled": disabled })))
}

async fn delete_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.delete_member(&id, &name)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// The member's token, shown again for a new machine.
async fn member_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    Ok(Json(token_json(&state, &headers, &uri, &id, &name)?))
}

/// Rotate: a new token; the old one stops working immediately and its
/// holder is thrown off.
async fn rotate_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    state.rotate_member(&id, &name)?;
    Ok(Json(token_json(&state, &headers, &uri, &id, &name)?))
}

/// Make a member re-join now (it applies whatever is configured).
async fn reconnect_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.net(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let mut ns = net.lock().unwrap();
    let node = ns.registry.id_of(&name).ok_or_else(|| ApiError::not_found(format!("member {name:?} has never joined")))?;
    let connected = ns.sessions.contains_key(&node);
    ns.reconfigure(node, "reconnect requested");
    Ok(Json(serde_json::json!({ "ok": true, "was_connected": connected })))
}

async fn export(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<Vec<NetworkConfig>>, ApiError> {
    check_admin(&state, &headers)?;
    Ok(Json(state.export()))
}

async fn import(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(cfgs): Json<Vec<NetworkConfig>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let applied = state.import(cfgs)?;
    Ok(Json(serde_json::json!({ "ok": true, "applied": applied })))
}
