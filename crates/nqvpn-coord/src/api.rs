//! Axum router: member realm (/join) + admin realm (§3.4).
//! Phase 1 admin auth = bearer token; argon2 UI sessions land with the
//! web UI phase.

use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use nqvpn_proto::api::*;
use nqvpn_proto::types::Role;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::response::Html;
use crate::error::ApiError;
use crate::state::{relay_entries, AppState};

/// The admin UI, compiled into the binary (§3.4: no separate deployment,
/// no external assets, works air-gapped). It is strictly a client of the
/// admin API below — anything it can do is equally curl-able.
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
        .route(
            "/api/v1/networks/{id}/clients/{client_id}/disable",
            post(|s, p| set_disabled(s, p, true)),
        )
        .route(
            "/api/v1/networks/{id}/clients/{client_id}/enable",
            post(|s, p| set_disabled(s, p, false)),
        )
        .route("/api/v1/networks/{id}/clients/{client_id}/reset-pin", post(reset_pin))
        .route(
            "/api/v1/networks/{id}/clients/{client_id}",
            axum::routing::delete(delete_member),
        )
        .route("/api/v1/reload", post(reload))
        .route("/api/v1/secrets", get(list_secrets))
        .route("/api/v1/secrets/{network}/{client_id}/mint", post(mint_secret))
        .route("/api/v1/secrets/{network}/{client_id}/revoke", post(revoke_secret))
        .route("/api/v1/secrets/{network}/{client_id}", axum::routing::delete(delete_secret))
        .route("/ui", get(ui))
        .route("/ui/", get(ui))
        .route("/", get(|| async { axum::response::Redirect::temporary("/ui") }))
        .with_state(state)
}

fn check_admin(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let configured = state
        .admin_token
        .as_deref()
        .ok_or_else(|| ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            nqvpn_proto::errors::ErrorCode::Unknown("admin_disabled".into()),
            "no admin bearer token configured",
        ))?;
    let presented = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(ApiError::unauthorized_admin)?;
    if presented.trim() != configured {
        return Err(ApiError::unauthorized_admin());
    }
    Ok(())
}

async fn join(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(req): Json<JoinRequest>,
) -> Result<Json<JoinResponse>, ApiError> {
    // A relay binds its listener before joining (§9 startup), so by the
    // time we see this request the advertised address must already be
    // accepting. Probe it here, before any state is committed, so a
    // denied join changes nothing.
    if req.role == Role::Relay {
        if let Some(addr) = req.relay_addr.clone() {
            let policy = state
                .networks
                .get(&req.network_id)
                .map(|n| n.lock().unwrap().cfg.settings.relay_reachability.clone())
                .unwrap_or_else(|| "off".to_string());
            if policy != "off" {
                let verdict =
                    crate::reach::probe(&addr, std::time::Duration::from_secs(5)).await;
                if verdict == crate::reach::Reachability::Unreachable {
                    tracing::warn!(
                        network = %req.network_id, relay = %req.client_id, %addr, %policy,
                        "advertised relay address is not dialable from the coordinator"
                    );
                    if policy == "deny" {
                        return Err(ApiError::relay_unreachable(&addr));
                    }
                }
                if let Some(net) = state.networks.get(&req.network_id) {
                    net.lock()
                        .unwrap()
                        .directory
                        .reachability
                        .insert(req.client_id.clone(), verdict);
                }
            }
        }
    }

    // argon2 is CPU-heavy: keep the reactor responsive.
    let ip = peer.ip().to_string();
    let state2 = state.clone();
    let resp = tokio::task::spawn_blocking(move || state2.join(&req, &ip))
        .await
        .map_err(|e| ApiError::internal(format!("join task: {e}")))??;
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
            relays_total: ns
                .registry
                .members
                .keys()
                .filter(|n| ns.cfg.relays.contains_key(*n))
                .count(),
            members_online: ns.directory.online.len(),
        });
    }
    networks.sort_by(|a, b| a.network_id.cmp(&b.network_id));
    Ok(Json(GlobalStatus { networks }))
}

async fn list_networks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GlobalStatus>, ApiError> {
    global_status(State(state), headers).await
}

async fn network_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<NetworkStatus>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state
        .networks
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let ns = net.lock().unwrap();

    let mut members = Vec::new();
    for (name, rec) in &ns.registry.members {
        let role = if ns.cfg.relays.contains_key(name) { Role::Relay } else { Role::Client };
        members.push(MemberStatus {
            name: name.clone(),
            node_id: rec.node_id,
            role,
            online: ns.directory.online.contains(name),
            disabled: rec.disabled,
            ip4: rec.ip4,
            ip6: rec.ip6,
            registered_cidrs: rec.routes.iter().map(|r| r.cidr).collect(),
            attached_relay: ns
                .directory
                .attachments
                .get(&rec.node_id)
                .and_then(|relay_id| {
                    ns.registry
                        .members
                        .iter()
                        .find(|(_, r)| r.node_id == *relay_id)
                        .map(|(n, _)| n.clone())
                }),
            pinned: rec.pubkey.is_some(),
            advertised_reachable: (role == Role::Relay)
                .then(|| ns.directory.reachability.get(name).copied())
                .flatten()
                .map(|r| r.as_str().to_string()),
            last_join_unix: rec.last_join_unix,
            pins: {
                let short = |k: &str| {
                    // Fingerprints are long and only the tail
                    // distinguishes them in practice.
                    let t = k.strip_prefix("sha256:").unwrap_or(k);
                    t.chars().take(12).collect::<String>()
                };
                let mut v: Vec<PinStatus> = Vec::new();
                for p in &rec.cert_fps.pins {
                    v.push(PinStatus {
                        kind: "cert_fp".into(),
                        key: short(&p.key),
                        retires_unix: p.retires_unix,
                    });
                }
                for p in &rec.pubkeys.pins {
                    v.push(PinStatus {
                        kind: "pubkey".into(),
                        key: short(&p.key),
                        retires_unix: p.retires_unix,
                    });
                }
                v
            },
        });
    }

    // Report the *live* directory ownership (liveness-bound, §2), not the
    // raw registry: a dead registrant is not the owner, whatever its age.
    let mut prefix_table = Vec::new();
    for (cidr, regs) in ns.registry.resolve_owners() {
        let key = cidr.to_string();
        let Some(owner) = ns.directory.owners.get(&key) else {
            // Every registrant is offline: the prefix is withdrawn.
            prefix_table.push(PrefixOwner {
                cidr,
                owner: "(withdrawn)".into(),
                owner_node_id: 0,
                standby: regs.iter().map(|(n, _)| n.clone()).collect(),
            });
            continue;
        };
        let owner_node_id = ns.registry.members.get(owner).map(|r| r.node_id).unwrap_or_default();
        prefix_table.push(PrefixOwner {
            cidr,
            owner: owner.clone(),
            owner_node_id,
            standby: regs.iter().map(|(n, _)| n.clone()).filter(|n| n != owner).collect(),
        });
    }
    // VPN /32s and /128s are implicit single-owner prefixes.
    for (name, rec) in &ns.registry.members {
        if let Some(ip) = rec.ip4 {
            prefix_table.push(PrefixOwner {
                cidr: format!("{ip}/32").parse().unwrap(),
                owner: name.clone(),
                owner_node_id: rec.node_id,
                standby: vec![],
            });
        }
        if let Some(ip) = rec.ip6 {
            prefix_table.push(PrefixOwner {
                cidr: format!("{ip}/128").parse().unwrap(),
                owner: name.clone(),
                owner_node_id: rec.node_id,
                standby: vec![],
            });
        }
    }

    // The traffic matrix. Each relay reports its own row, so a link
    // appears twice — as the sender's tx and the receiver's rx — and the
    // difference between the two is loss on that link.
    let name_of = |node_id: nqvpn_proto::types::NodeId| -> String {
        ns.registry
            .members
            .iter()
            .find(|(_, r)| r.node_id == node_id)
            .map(|(n, _)| n.clone())
            .unwrap_or_else(|| format!("#{node_id}"))
    };
    let now = crate::state::now_unix();
    let mut relay_traffic: Vec<RelayTraffic> = ns
        .directory
        .traffic
        .iter()
        .map(|(relay, sample)| RelayTraffic {
            relay: relay.clone(),
            node_id: ns.registry.members.get(relay).map(|r| r.node_id).unwrap_or_default(),
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
    relay_traffic.sort_by(|a, b| a.node_id.cmp(&b.node_id));

    Ok(Json(NetworkStatus {
        network_id: id.clone(),
        network_uuid: ns.registry.network_uuid.to_string(),
        members,
        prefix_table,
        relay_traffic,
        transport: ns.cfg.settings.transport.clone(),
        lanes: ns.cfg.settings.lanes,
    }))
}

async fn set_disabled(
    state: State<Arc<AppState>>,
    (headers, Path((id, client_id))): (HeaderMap, Path<(String, String)>),
    disabled: bool,
) -> Result<Json<serde_json::Value>, ApiError> {
    let State(state) = state;
    check_admin(&state, &headers)?;
    let net = state
        .networks
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let mut ns = net.lock().unwrap();
    let rec = ns
        .registry
        .members
        .get_mut(&client_id)
        .ok_or_else(|| ApiError::not_found(format!("member {client_id:?}")))?;
    rec.disabled = disabled;
    ns.registry
        .commit(&ns.registry_path)
        .map_err(|e| ApiError::internal(format!("registry commit: {e:#}")))?;
    Ok(Json(serde_json::json!({ "ok": true, "disabled": disabled })))
}

async fn reset_pin(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, client_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state
        .networks
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
    let mut ns = net.lock().unwrap();
    let rec = ns
        .registry
        .members
        .get_mut(&client_id)
        .ok_or_else(|| ApiError::not_found(format!("member {client_id:?}")))?;
    // Clear the pin *sets*, not just the legacy mirrors. Rotation made
    // the sets authoritative, so clearing only the old fields left the
    // member locked out with no way back — silently defeating the one
    // escape hatch an operator has when a machine's keys change.
    rec.pubkeys = Default::default();
    rec.cert_fps = Default::default();
    rec.pubkey = None;
    rec.cert_fp = None;
    ns.registry
        .commit(&ns.registry_path)
        .map_err(|e| ApiError::internal(format!("registry commit: {e:#}")))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Forget a member entirely: registry record, pins, routes, address, and
/// any managed secret.
///
/// This does **not** remove it from the network config, so a member whose
/// config entry survives can join again — and, having no pins, would be
/// re-pinned by trust-on-first-use. Deleting is therefore "forget", not
/// "ban"; disabling is what prevents a rejoin. The UI says so before
/// asking for confirmation.
async fn delete_member(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, client_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = state
        .networks
        .get(&id)
        .ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;

    let (existed, freed4, freed6, still_configured) = {
        let mut ns = net.lock().unwrap();
        let rec = ns.registry.members.remove(&client_id);
        let (a, b) = rec.as_ref().map(|r| (r.ip4, r.ip6)).unwrap_or((None, None));
        let configured = crate::state::AppState::member_cfg(&ns.cfg, &client_id).is_some();
        if rec.is_some() {
            ns.registry
                .commit(&ns.registry_path)
                .map_err(|e| ApiError::internal(format!("registry commit: {e:#}")))?;
            // Withdraw it from everyone's view, and drop the session if
            // it is connected — otherwise it lingers until the liveness
            // sweep notices.
            let now = crate::state::now_unix();
            ns.directory.set_online(&client_id, false, now);
            ns.directory.traffic.remove(&client_id);
            if let Some(s) = ns.sessions.get(&client_id) {
                let _ = s.tx.try_send(crate::control::Push::Close("member deleted".into()));
                s.conn.close(4u32.into(), b"member deleted");
            }
            if let Some(d) = ns.refresh_directory(now) {
                crate::control::broadcast(&ns, crate::control::Push::Membership(d));
            }
            crate::control::publish_relays_if_changed(&mut ns);
        }
        (rec.is_some(), a, b, configured)
    };

    if !existed {
        return Err(ApiError::not_found(format!("member {client_id:?}")));
    }

    // A managed secret for a member that no longer exists is a loose end.
    let secret_removed = {
        let mut store = state.secrets.lock().unwrap();
        let removed = store.remove(&client_id, Some(&id));
        if removed {
            store
                .commit(&state.secrets_path)
                .map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
        }
        removed
    };

    tracing::info!(network = %id, member = %client_id, still_configured, "member deleted");
    Ok(Json(serde_json::json!({
        "ok": true,
        "freed_ip4": freed4,
        "freed_ip6": freed6,
        "secret_removed": secret_removed,
        // The operator needs to know a rejoin is still possible.
        "still_in_config": still_configured,
    })))
}

/// Managed secrets, without the secrets: only what a hash can tell you.
async fn list_secrets(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let store = state.secrets.lock().unwrap();
    let rows: Vec<serde_json::Value> = store
        .secrets
        .iter()
        .map(|s| {
            serde_json::json!({
                "client_id": s.client_id,
                "kind": s.kind.as_str(),
                "network": s.network,
                "created_unix": s.created_unix,
                "disabled": s.disabled,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({ "secrets": rows })))
}

/// Mint (or replace) a secret. The plaintext is returned exactly once —
/// there is no endpoint that can read it back, because only the hash is
/// stored. Replacing is also the rotation path: the previous secret stops
/// working immediately.
async fn mint_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((network, client_id)): Path<(String, String)>,
    body: Option<Json<serde_json::Value>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let kind_str = body
        .as_ref()
        .and_then(|b| b.get("kind"))
        .and_then(|v| v.as_str())
        .unwrap_or("client");
    let kind = match kind_str {
        "admin" => crate::secrets::SecretKind::Admin,
        "relay" => crate::secrets::SecretKind::Relay,
        "client" => crate::secrets::SecretKind::Client,
        other => {
            return Err(ApiError::bad_request(format!(
                "kind must be admin, relay or client (got {other:?})"
            )))
        }
    };
    // "-" means "not scoped to a network", which is how an admin
    // credential is expressed in a path that always has the segment.
    let net = (network != "-").then_some(network.as_str());
    if kind == crate::secrets::SecretKind::Admin && net.is_some() {
        return Err(ApiError::bad_request(
            "an admin secret belongs to no network; use '-' as the network",
        ));
    }
    if kind != crate::secrets::SecretKind::Admin && net.is_none() {
        return Err(ApiError::bad_request("a member secret must name its network"));
    }

    let minted = {
        let mut store = state.secrets.lock().unwrap();
        let m = store
            .mint(&client_id, kind, net, crate::state::now_unix())
            .map_err(|e| ApiError::internal(format!("minting: {e:#}")))?;
        store
            .commit(&state.secrets_path)
            .map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
        m
    };
    tracing::info!(member = %client_id, kind = kind.as_str(), "secret minted");
    Ok(Json(serde_json::json!({
        "ok": true,
        "client_id": minted.client_id,
        "kind": minted.kind.as_str(),
        "secret": minted.secret,
        "note": "shown once — it is not stored and cannot be retrieved",
    })))
}

async fn revoke_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((network, client_id)): Path<(String, String)>,
    body: Option<Json<serde_json::Value>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let disabled = body
        .as_ref()
        .and_then(|b| b.get("disabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let net = (network != "-").then_some(network.as_str());
    let mut store = state.secrets.lock().unwrap();
    if !store.set_disabled(&client_id, net, disabled) {
        return Err(ApiError::not_found(format!("no managed secret for {client_id:?}")));
    }
    store
        .commit(&state.secrets_path)
        .map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
    Ok(Json(serde_json::json!({ "ok": true, "disabled": disabled })))
}

/// Delete a managed secret. The member falls back to its network config
/// `secret_hash` if it has one, so this is "unmigrate", not "lock out".
async fn delete_secret(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((network, client_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let net = (network != "-").then_some(network.as_str());
    let mut store = state.secrets.lock().unwrap();
    if !store.remove(&client_id, net) {
        return Err(ApiError::not_found(format!("no managed secret for {client_id:?}")));
    }
    store
        .commit(&state.secrets_path)
        .map_err(|e| ApiError::internal(format!("secrets commit: {e:#}")))?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// Config reload as an atomic reconciliation (§3.3): validate everything
/// first — any error leaves the running config untouched — then swap in
/// the new per-network config and republish. Registry state (ids, pins,
/// addresses, registration ages) is untouched by design.
async fn reload(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    check_admin(&state, &headers)?;
    let dir = state
        .networks_dir
        .clone()
        .ok_or_else(|| ApiError::internal("networks dir unknown"))?;

    // Phase 1: parse + validate every file. Failure changes nothing.
    let cfgs = crate::config::load_networks(&dir)
        .map_err(|e| ApiError::bad_request(format!("reload rejected, old config still running: {e:#}")))?;

    // Phase 2: apply. Networks that vanished from disk keep running
    // (removing a network is an explicit admin action, not a side effect
    // of a missing file).
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
                ns.directory.set_hold_down(cfg.settings.hold_down_secs);
                applied.push(cfg.network_id.clone());
                ns.cfg = cfg;
                // The MTU ceiling is a config value, so a reload can
                // change the network-wide minimum even though no member
                // reported anything new.
                crate::control::publish_mtu_if_changed(&mut ns);
                // Permission changes can move route ownership.
                let now = crate::state::now_unix();
                if let Some(d) = ns.refresh_directory(now) {
                    crate::control::broadcast(&ns, crate::control::Push::Membership(d));
                }
            }
            None => unknown.push(cfg.network_id.clone()),
        }
    }
    Ok(Json(serde_json::json!({
        "ok": true,
        "reloaded": applied,
        "ignored_new_networks": unknown,   // adding a network needs a restart in v1
        "warnings": warnings,
    })))
}

// Exposed for integration tests: relays visible to joiners.
pub fn visible_relays(state: &AppState, network: &str) -> Vec<RelayEntry> {
    state
        .networks
        .get(network)
        .map(|n| relay_entries(&n.lock().unwrap()))
        .unwrap_or_default()
}
