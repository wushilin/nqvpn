//! Axum router: the member realm (`/join`) and the admin realm — the UI
//! is a client of the admin API and nothing more. Admin auth is a
//! bearer token from `coordinator.toml`.

use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
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
use crate::state::{now_unix, AppState};

/// The admin UI, compiled into the binary: no separate deployment, no
/// external assets, works air-gapped. Strictly a client of the API.
const UI_HTML: &str = include_str!("../ui/index.html");

async fn ui() -> Html<&'static str> {
    Html(UI_HTML)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/api/v1/join", post(join))
        .route("/api/v1/login", post(login))
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
        .with_state(state)
}

/// Admin access: a UI session (cookie, or the session token as a
/// bearer) or the static bearer token from the config.
fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let bearer = headers.get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).map(|v| v.trim().to_string());
    if let Some(t) = &bearer {
        if let Some(cfg) = state.admin_token.as_deref() {
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
/// slow), then a session cookie. Failures are throttled per address.
async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<LoginReq>,
) -> Result<Response, ApiError> {
    let ip = peer.ip().to_string();
    if state.auth.throttled(&ip) {
        return Err(ApiError::rate_limited());
    }
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
    let ok = user == req.user
        && tokio::task::spawn_blocking(move || crate::auth::verify_password(&req.password, &hash))
            .await
            .unwrap_or(false);
    if !ok {
        state.auth.note_failure(&ip);
        tracing::warn!(%ip, user = %req.user, "admin login failed");
        return Err(ApiError::new(axum::http::StatusCode::UNAUTHORIZED, nqvpn_proto::errors::ErrorCode::AdminAuthRequired, "wrong user or password"));
    }
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
    Ok(ws.on_upgrade(move |socket| crate::ws::serve(state, socket)))
}

/// One frame of the live feed: every network's summary and status.
pub fn live_frame(state: &AppState) -> Result<String, ApiError> {
    let mut networks = Vec::new();
    let mut status = serde_json::Map::new();
    for (id, net) in state.nets() {
        let ns = net.lock().unwrap();
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
    // only the address the *operator* configured — never one the
    // request named — so this is not an open port scanner.
    if resp.role == Role::Relay {
        let policy = state.net(&resp.network_id).map(|n| n.lock().unwrap().cfg.settings.relay_reachability.clone());
        if let (Some(policy), Some(addr)) = (policy, resp.relay_addr.clone()) {
            if policy != "off" {
                let (st, netid, node) = (state.clone(), resp.network_id.clone(), resp.node_id);
                tokio::spawn(async move {
                    let verdict = crate::reach::probe(&addr, std::time::Duration::from_secs(5)).await;
                    if verdict == crate::reach::Reachability::Unreachable {
                        tracing::warn!(network = %netid, node_id = node, %addr, "advertised relay address is not dialable from the coordinator");
                    }
                    if let Some(net) = st.net(&netid) {
                        net.lock().unwrap().directory.reachability.insert(node, verdict);
                    }
                });
            }
        }
    }
    Ok(Json(resp))
}

async fn global_status(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<GlobalStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let mut networks = Vec::new();
    for (id, net) in state.nets() {
        let ns = net.lock().unwrap();
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
        "cidrs": c.cidrs,
        "pools": c.pools,
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
            registered_cidrs: rec.map(|r| r.routes.iter().map(|x| x.cidr).collect()).unwrap_or_else(|| m.local_cidrs.clone()),
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
        });
    }

    let mut prefix_table = Vec::new();
    for (cidr, regs) in ns.registry.resolve_owners() {
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
                    tx_bps: sample.rate(l.peer_id, true),
                    rx_bps: sample.rate(l.peer_id, false),
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
