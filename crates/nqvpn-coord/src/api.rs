//! Axum router: member realm (/join) + admin realm (§3.4).
//! Admin auth is a bearer token from the coordinator config.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use nqvpn_proto::api::*;
use nqvpn_proto::types::{NodeId, Role};
use std::net::SocketAddr;
use std::sync::Arc;

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
        .route("/api/v1/status", get(global_status))
        .route("/api/v1/networks", get(list_networks))
        .route("/api/v1/networks/{id}/status", get(network_status))
        .route("/api/v1/networks/{id}/members/{name}/disable", post(|s, p| set_disabled(s, p, true)))
        .route("/api/v1/networks/{id}/members/{name}/enable", post(|s, p| set_disabled(s, p, false)))
        .route(
            "/api/v1/networks/{id}/members/{name}/secret",
            get(show_secret).post(mint_secret).delete(delete_secret),
        )
        .route("/api/v1/networks/{id}/members/{name}", axum::routing::delete(delete_member))
        .route("/api/v1/reload", post(reload))
        .route("/ui", get(ui))
        .route("/ui/", get(ui))
        .route("/", get(|| async { axum::response::Redirect::temporary("/ui") }))
        .with_state(state)
}

fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = state.admin_token.as_deref().ok_or_else(|| {
        ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            nqvpn_proto::errors::ErrorCode::Unknown("admin_disabled".into()),
            "no admin bearer token configured",
        )
    })?;
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized_admin)?;
    if !crate::secrets::constant_time_eq(presented.trim(), configured) {
        return Err(ApiError::unauthorized_admin());
    }
    Ok(())
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

    // A relay binds its listener before joining, so its *configured*
    // address must answer by now. Probed only after authentication, and
    // never the address the request named — that is what would make
    // this an open port scanner.
    if req.role == Role::Relay {
        let (policy, addr) = {
            let net = state.networks.get(&req.network_id).expect("joined");
            let ns = net.lock().unwrap();
            let addr = ns.cfg.member_by_name(&req.name).and_then(|(m, _)| m.relay_addr.clone());
            (ns.cfg.settings.relay_reachability.clone(), addr)
        };
        if let (true, Some(addr)) = (policy != "off", addr) {
            let (st, netid, node) = (state.clone(), req.network_id.clone(), resp.node_id);
            tokio::spawn(async move {
                let verdict = crate::reach::probe(&addr, std::time::Duration::from_secs(5)).await;
                if verdict == crate::reach::Reachability::Unreachable {
                    tracing::warn!(network = %netid, node_id = node, %addr, "advertised relay address is not dialable from the coordinator");
                }
                if let Some(net) = st.networks.get(&netid) {
                    net.lock().unwrap().directory.reachability.insert(node, verdict);
                }
            });
        }
    }
    Ok(Json(resp))
}

async fn global_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GlobalStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let mut networks = Vec::new();
    for (id, net) in &state.networks {
        let ns = net.lock().unwrap();
        networks.push(NetworkSummary {
            network_id: id.clone(),
            members_total: ns.registry.members.len(),
            relays_total: ns.registry.members.values().filter(|m| m.role == Role::Relay).count(),
            members_online: ns.leases.online_nodes().len(),
            gen: ns.directory.gen,
        });
    }
    networks.sort_by(|a, b| a.network_id.cmp(&b.network_id));
    Ok(Json(GlobalStatus { networks }))
}

async fn list_networks(state: State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<GlobalStatus>, ApiError> {
    global_status(state, headers).await
}

async fn network_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NetworkStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.networks.get(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();
    let now = now_unix();
    let attachments = ns.leases.attachments();
    let name_of = |node_id: NodeId| -> String {
        ns.registry.members.get(&node_id).map(|r| r.name.clone()).unwrap_or_else(|| format!("#{node_id}"))
    };

    let mut members = Vec::new();
    for (node_id, rec) in &ns.registry.members {
        let report = ns.leases.report(*node_id);
        members.push(MemberStatus {
            name: rec.name.clone(),
            node_id: *node_id,
            role: rec.role,
            online: ns.leases.is_online(*node_id),
            disabled: rec.disabled,
            ip4: rec.ip4,
            ip6: rec.ip6,
            registered_cidrs: rec.routes.iter().map(|r| r.cidr).collect(),
            attached_relay: attachments.get(node_id).map(|r| name_of(*r)),
            advertised_reachable: (rec.role == Role::Relay)
                .then(|| ns.directory.reachability.get(node_id).copied())
                .flatten()
                .map(|r| r.as_str().to_string()),
            last_join_unix: rec.last_join_unix,
            last_join_from: rec.last_join_from.clone(),
            login_gen: rec.login_gen,
            replaced_unix: rec.replaced_unix,
            replaced_from: rec.replaced_from.clone(),
            reported_gen: report.map(|r| r.gen),
            digest_ok: report.map(|r| r.gen == ns.directory.gen && r.digest == ns.directory.published_digest).unwrap_or(false),
            last_heartbeat_unix: ns.leases.last_seen(*node_id).map(|ms| ms / 1000),
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

    Ok(Json(NetworkStatus {
        network_id: id.clone(),
        network_uuid: ns.registry.network_uuid.to_string(),
        gen: ns.directory.gen,
        members,
        prefix_table,
        relay_traffic,
        transport: ns.cfg.settings.transport.clone(),
        lanes: ns.cfg.settings.lanes,
    }))
}

type MemberPath = Path<(String, String)>;

/// Members are addressed by name in the API; the registry resolves it.
fn node_of(ns: &crate::state::NetState, name: &str) -> Result<NodeId, ApiError> {
    ns.registry.id_of(name).ok_or_else(|| ApiError::not_found(format!("member {name:?} has never joined")))
}

async fn set_disabled(
    state: State<Arc<AppState>>,
    (headers, Path((id, name))): (HeaderMap, MemberPath),
    disabled: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let State(state) = state;
    check_admin(&state, &headers)?;
    let net = state.networks.get(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let mut ns = net.lock().unwrap();
    let node = node_of(&ns, &name)?;
    let rec = ns.registry.members.get_mut(&node).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
    rec.disabled = disabled;
    let role = rec.role;
    ns.commit()?;
    if disabled {
        // Evict now: the control session, the lease, its declarations.
        // Relays and peers drop it as soon as the delta arrives; its
        // credential stops renewing at the API.
        ns.close_session(node, "member disabled");
        if role == Role::Relay {
            ns.leases.remove_relay(node);
        } else {
            ns.leases.remove(node);
        }
    }
    state.publish(&mut ns);
    Ok(Json(serde_json::json!({ "ok": true, "disabled": disabled })))
}

/// Forget a member: registry record, address, routes, and any managed
/// secret. It can join again only if its config entry survives.
async fn delete_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state.networks.get(&id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let (freed4, freed6, still_configured) = {
        let mut ns = net.lock().unwrap();
        let node = node_of(&ns, &name)?;
        let rec = ns.registry.members.remove(&node).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
        ns.commit()?;
        ns.close_session(node, "member deleted");
        ns.leases.remove_relay(node);
        ns.directory.traffic.remove(&node);
        ns.directory.reported_mtu.remove(&node);
        state.publish(&mut ns);
        (rec.ip4, rec.ip6, ns.cfg.member_by_name(&name).is_some())
    };
    let secret_removed = {
        let mut store = state.secrets.lock().unwrap();
        let removed = store.remove(&id, &name);
        if removed {
            store.commit(&state.secrets_path).map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
        }
        removed
    };
    tracing::info!(network = %id, member = %name, still_configured, "member deleted");
    Ok(Json(serde_json::json!({
        "ok": true, "freed_ip4": freed4, "freed_ip6": freed6,
        "secret_removed": secret_removed, "still_in_config": still_configured,
    })))
}

fn member_exists(state: &AppState, id: &str, name: &str) -> Result<(), ApiError> {
    let net = state.networks.get(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();
    if ns.cfg.member_by_name(name).is_none() {
        return Err(ApiError::not_found(format!("member {name:?} is not configured in {id:?}")));
    }
    Ok(())
}

/// The member's current secret: the managed one if minted, else what
/// the network config says. Shown, not hashed — see `secrets.rs`.
async fn show_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    member_exists(&state, &id, &name)?;
    let managed = state.secrets.lock().unwrap().find(&id, &name).cloned();
    let (secret, source, disabled) = match managed {
        Some(m) => (Some(m.secret), "managed", m.disabled),
        None => {
            let ns = state.networks[&id].lock().unwrap();
            let s = ns.cfg.member_by_name(&name).and_then(|(m, _)| m.secret.clone());
            (s, "config", false)
        }
    };
    Ok(Json(serde_json::json!({ "name": name, "secret": secret, "source": source, "disabled": disabled })))
}

/// Mint (or replace) a member's secret. Replacing is rotation: the
/// previous secret stops working immediately; running sessions end at
/// their credential's expiry.
async fn mint_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    member_exists(&state, &id, &name)?;
    let secret = {
        let mut store = state.secrets.lock().unwrap();
        let s = store.mint(&id, &name, now_unix());
        store.commit(&state.secrets_path).map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
        s
    };
    tracing::info!(network = %id, member = %name, "secret minted");
    Ok(Json(serde_json::json!({ "ok": true, "name": name, "secret": secret })))
}

/// Remove the managed secret; the member falls back to its config
/// secret if it has one, otherwise it can no longer join.
async fn delete_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, name)): MemberPath,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let mut store = state.secrets.lock().unwrap();
    if !store.remove(&id, &name) {
        return Err(ApiError::not_found(format!("no managed secret for {name:?}")));
    }
    store.commit(&state.secrets_path).map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Config reload as an atomic reconciliation (§3.3): validate everything
/// first — any error leaves the running config untouched — then swap in
/// the new per-network config and republish.
async fn reload(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let dir = state.networks_dir.clone().ok_or_else(|| ApiError::internal("networks dir unknown"))?;
    let cfgs = crate::config::load_networks(&dir)
        .map_err(|e| ApiError::bad_request(format!("reload rejected, old config still running: {e:#}")))?;
    let mut applied = Vec::new();
    let mut warnings = Vec::new();
    let mut unknown = Vec::new();
    for cfg in cfgs {
        match state.networks.get(&cfg.network_id) {
            Some(net) => {
                let mut ns = net.lock().unwrap();
                warnings.extend(
                    crate::state::config_matches_registry(&cfg, &ns.registry)
                        .into_iter()
                        .map(|w| format!("{}: {w}", cfg.network_id)),
                );
                ns.directory.hold_down_secs = cfg.settings.hold_down_secs;
                applied.push(cfg.network_id.clone());
                ns.cfg = cfg;
                state.publish(&mut ns);
            }
            None => unknown.push(cfg.network_id.clone()),
        }
    }
    Ok(Json(serde_json::json!({
        "ok": true, "reloaded": applied,
        "ignored_new_networks": unknown, // adding a network needs a restart in v1
        "warnings": warnings,
    })))
}
