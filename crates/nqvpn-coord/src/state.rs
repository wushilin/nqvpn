//! Application state and the join transaction (§3.2, §3.3).
//!
//! One serialized owner per network: every mutation for a network runs
//! under its mutex, and the registry is durably committed *before* the
//! credential is returned (durability precedes visibility).
//!
//! A join is the member's whole declaration. The coordinator replaces
//! what it recorded before, keeps only identity (node id, address, the
//! ages of routes that stay continuously declared), and — when a
//! different machine took over the id — bumps `login_gen` so every
//! acceptor closes the previous instance.

use ipnet::IpNet;
use nqvpn_proto::api::{JoinRequest, JoinResponse, RelayEntry};
use nqvpn_proto::control::KeyInfo;
use nqvpn_proto::credential::{self, Claims, AUD};
use nqvpn_proto::types::{NodeId, Role};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{CoordConfig, MemberCfg, NetworkConfig};
use crate::control::{self, Push, Session};
use crate::directory::Directory;
use crate::error::ApiError;
use crate::leases::Leases;
use crate::registry::{Registry, RouteReg};
use crate::secrets::{constant_time_eq, SecretStore, Verdict};
use crate::signer::Keyring;

pub const ISS: &str = "nqvpn-coord";

pub struct NetState {
    pub cfg: NetworkConfig,
    pub registry: Registry,
    pub registry_path: PathBuf,
    pub directory: Directory,
    pub leases: Leases,
    /// Live control sessions by node id.
    pub sessions: HashMap<NodeId, Session>,
    /// When this process started serving the network; snapshots are
    /// withheld for a short grace after it, so a coordinator restart
    /// first hears everyone's declarations before publishing a view.
    pub started_at: u64,
}

impl NetState {
    pub fn new(cfg: NetworkConfig, registry: Registry, registry_path: PathBuf) -> Self {
        let now = now_unix();
        let gen0 = registry.initial_gen(now_ms());
        let hold = cfg.settings.hold_down_secs;
        NetState {
            cfg,
            registry,
            registry_path,
            directory: Directory::new(gen0, hold),
            leases: Leases::default(),
            sessions: HashMap::new(),
            started_at: now,
        }
    }

    /// Collecting before publishing: members that reconnect after a
    /// coordinator restart keep their last view until the fleet has had
    /// two heartbeats to re-declare what it holds.
    pub fn in_grace(&self, now: u64) -> bool {
        now < self.started_at + 2 * self.cfg.settings.heartbeat_secs.max(1) as u64
    }

    /// Recompute the view and, if it changed, push the delta to every
    /// synced session. The one place generations are minted.
    pub fn publish(&mut self, keys: &[KeyInfo], now: u64) {
        let NetState { cfg, registry, directory, leases, .. } = self;
        let Some(delta) = directory.recompute(cfg, registry, leases, keys, now) else {
            return;
        };
        if registry.note_gen(directory.gen) {
            if let Err(e) = registry.commit(&self.registry_path) {
                tracing::error!(network = %cfg.network_id, "persisting generation mark: {e:#}");
            }
        }
        control::broadcast_delta(self, delta);
    }

    /// Commit the registry, mapping failure to an API error.
    pub fn commit(&self) -> Result<(), ApiError> {
        self.registry
            .commit(&self.registry_path)
            .map_err(|e| ApiError::internal(format!("registry commit failed: {e:#}")))
    }

    /// Close a member's control session, if any.
    pub fn close_session(&mut self, node: NodeId, reason: &str) {
        self.close_session_with(node, control::CLOSE_EVICTED, reason);
    }

    pub fn close_session_with(&mut self, node: NodeId, code: u32, reason: &str) {
        if let Some(s) = self.sessions.remove(&node) {
            let _ = s.tx.try_send(Push::Close(reason.to_string()));
            s.conn.close(code.into(), reason.as_bytes());
        }
    }
}

/// Fixed-window per-(member, ip) limiter, pruned as it goes.
#[derive(Default)]
pub struct RateLimiter {
    map: HashMap<(String, String), (u64, u32)>,
}

impl RateLimiter {
    pub fn check(&mut self, key: String, ip: String, limit: u32, now: u64) -> bool {
        let window = now / 60;
        if self.map.len() > 4096 {
            self.map.retain(|_, (w, _)| *w == window);
        }
        let entry = self.map.entry((key, ip)).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        entry.1 <= limit
    }
}

pub struct AppState {
    pub coord: CoordConfig,
    pub admin_token: Option<String>,
    pub networks: HashMap<String, Mutex<NetState>>,
    pub keyring: Keyring,
    pub join_rate: Mutex<RateLimiter>,
    /// Where `networks.d/` lives, for `POST /api/v1/reload`.
    pub networks_dir: Option<PathBuf>,
    pub secrets: Mutex<SecretStore>,
    pub secrets_path: PathBuf,
    /// Published in join responses: the QUIC control port.
    pub control_port: u16,
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn valid_pubkey(b64: &str) -> bool {
    nqvpn_proto::seal::decode_pubkey(b64).is_some()
}

fn valid_fingerprint(fp: &str) -> bool {
    fp.strip_prefix("sha256:")
        .map(|h| h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

impl AppState {
    fn check_rate(&self, key: String, ip: String) -> Result<(), ApiError> {
        let limit = self.coord.limits.join_rate_per_min;
        if self.join_rate.lock().unwrap().check(key, ip, limit, now_unix()) {
            Ok(())
        } else {
            Err(ApiError::rate_limited())
        }
    }

    /// The whole join transaction.
    pub fn join(&self, req: &JoinRequest, peer_ip: &str) -> Result<JoinResponse, ApiError> {
        self.check_rate(format!("{}@{}", req.name, req.network_id), peer_ip.to_string())?;

        let net = self
            .networks
            .get(&req.network_id)
            .ok_or_else(ApiError::bad_credentials)?; // unknown network == unknown member

        // ---- phase 1: authenticate against immutable config ----
        let (name, member_cfg, role): (String, MemberCfg, Role) = {
            let ns = net.lock().unwrap();
            match ns.cfg.member_by_name(&req.name) {
                Some((m, r)) => (req.name.clone(), m.clone(), r),
                None => return Err(ApiError::bad_credentials()),
            }
        };
        let verdict = self.secrets.lock().unwrap().verify(&req.network_id, &name, &req.secret);
        match verdict {
            Verdict::Match => {}
            Verdict::Mismatch | Verdict::Disabled => return Err(ApiError::bad_credentials()),
            Verdict::Unknown => match &member_cfg.secret {
                Some(s) if constant_time_eq(s.trim(), req.secret.trim()) => {}
                _ => return Err(ApiError::bad_credentials()),
            },
        }
        if role != req.role {
            return Err(ApiError::bad_request(format!("{name} is configured as {role}, joined as {}", req.role)));
        }
        if !valid_pubkey(&req.pubkey) {
            return Err(ApiError::bad_request("pubkey must be a base64 32-byte X25519 key"));
        }
        if !valid_fingerprint(&req.cert_fingerprint) {
            return Err(ApiError::bad_request("cert_fingerprint must be sha256:<64 hex>"));
        }
        if role == Role::Client && (!req.local_cidrs.is_empty() || req.relay_addr.is_some()) {
            return Err(ApiError::bad_request("clients cannot register routes or a relay address"));
        }
        if role == Role::Relay {
            let configured = member_cfg.relay_addr.as_deref().unwrap_or_default();
            match req.relay_addr.as_deref() {
                Some(a) if a == configured => {}
                Some(a) => {
                    return Err(ApiError::bad_request(format!(
                        "relay_addr {a:?} does not match the configured {configured:?}"
                    )))
                }
                None => return Err(ApiError::bad_request("relays must present relay_addr")),
            }
            for c in &req.local_cidrs {
                let allowed = member_cfg
                    .allowed_cidrs
                    .iter()
                    .any(|a| a.contains(&c.network()) && a.prefix_len() <= c.prefix_len());
                if !allowed {
                    return Err(ApiError::prefix_conflict(format!(
                        "cidr {c} is not within this relay's allowed_cidrs"
                    )));
                }
            }
        }

        // ---- phase 2: serialized mutation under the network lock ----
        let mut ns = net.lock().unwrap();
        let now = now_unix();
        let ttl_secs = ns.cfg.settings.credential_ttl_mins * 60;

        let existing = ns.registry.by_name(&name).cloned();
        if let Some(rec) = &existing {
            if rec.disabled {
                return Err(ApiError::client_disabled());
            }
        }

        // Addresses are identity: sticky, unless this join asks for
        // something else (a new preferred address, or none at all).
        let (ip4, ip6) = if req.want_vpn_ip {
            let (have4, have6) = existing.as_ref().map(|r| (r.ip4, r.ip6)).unwrap_or((None, None));
            let want4 = req.preferred_ip4.or(member_cfg.preferred_ip4);
            let want6 = req.preferred_ip6.or(member_cfg.preferred_ip6);
            let keep4 = have4.is_some() && (want4.is_none() || want4 == have4);
            let keep6 = have6.is_some() && (want6.is_none() || want6 == have6);
            if keep4 && (keep6 || have6.is_none() && want6.is_none()) {
                (have4, have6)
            } else {
                let NetState { cfg, registry, .. } = &mut *ns;
                let granted = crate::ipam::allocate(
                    cfg,
                    registry,
                    &name,
                    req.pool.as_deref(),
                    want4.or(have4),
                    want6.or(have6),
                )?;
                (granted.ip4, granted.ip6)
            }
        } else {
            (None, None)
        };

        // Routes: exactly what this join declares; ages survive for
        // CIDRs that stay continuously declared.
        let mut routes: Vec<RouteReg> = existing.as_ref().map(|r| r.routes.clone()).unwrap_or_default();
        routes.retain(|r| req.local_cidrs.iter().any(|c| c.trunc() == r.cidr));
        for c in &req.local_cidrs {
            let c = c.trunc();
            if !routes.iter().any(|r| r.cidr == c) {
                routes.push(RouteReg { cidr: c, first_granted_unix: now });
            }
        }

        // A different machine: previous keys recorded, and this join
        // presents different ones.
        let replaced = existing
            .as_ref()
            .map(|r| {
                r.pubkey.is_some()
                    && (r.pubkey.as_deref() != Some(req.pubkey.as_str())
                        || r.cert_fp.as_deref() != Some(req.cert_fingerprint.as_str()))
            })
            .unwrap_or(false);

        let rec = ns.registry.member_by_name_mut(&name, role, now);
        if replaced {
            rec.login_gen += 1;
            rec.replaced_unix = Some(now);
            rec.replaced_from = rec.last_join_from.clone();
        }
        rec.pubkey = Some(req.pubkey.clone());
        rec.cert_fp = Some(req.cert_fingerprint.clone());
        rec.ip4 = ip4;
        rec.ip6 = ip6;
        rec.routes = routes.clone();
        rec.last_join_unix = Some(now);
        rec.last_join_from = Some(peer_ip.to_string());
        let login_gen = rec.login_gen;
        let node_id = rec.node_id;

        // Durability precedes visibility.
        ns.commit()?;

        if replaced {
            tracing::info!(
                network = %req.network_id, member = %name, node_id, from = peer_ip, login_gen,
                "a different machine joined as this node; the previous instance is being replaced"
            );
            // Its control session is stale now; data sessions follow
            // once relays see the new login_gen in the snapshot.
            let stale = ns.sessions.get(&node_id).map(|s| s.login_gen < login_gen).unwrap_or(false);
            if stale {
                ns.close_session_with(
                    node_id,
                    control::CLOSE_REPLACED,
                    &format!("replaced by a newer join as {name} from {peer_ip}"),
                );
            }
        }

        let keys = self.keyring.key_infos();
        ns.publish(&keys, now);

        // ---- phase 3: build credential + response ----
        let mut prefixes: Vec<String> = Vec::new();
        if let Some(ip) = ip4 {
            prefixes.push(format!("{ip}/32"));
        }
        if let Some(ip) = ip6 {
            prefixes.push(format!("{ip}/128"));
        }
        for r in &routes {
            prefixes.push(r.cidr.to_string());
        }
        let claims = Claims {
            iss: ISS.into(),
            aud: AUD.into(),
            network_id: ns.cfg.network_id.clone(),
            network_uuid: ns.registry.network_uuid.to_string(),
            node_id,
            sub: name.clone(),
            role,
            pubkey: req.pubkey.clone(),
            cert_fp: req.cert_fingerprint.clone(),
            prefixes,
            login_gen,
            iat: now,
            exp: now + ttl_secs,
        };
        let (kid, sk) = self.keyring.active();
        let token = credential::sign(&claims, kid, sk);

        let subnet4 = ns.cfg.cidrs.iter().find(|c| matches!(c, IpNet::V4(_))).cloned();
        let subnet6 = ns.cfg.cidrs.iter().find(|c| matches!(c, IpNet::V6(_))).cloned();

        Ok(JoinResponse {
            credential: token,
            network_uuid: ns.registry.network_uuid.to_string(),
            coordinator_signing_keys: keys,
            node_id,
            name,
            login_gen,
            ip4,
            subnet4: if ip4.is_some() { subnet4 } else { None },
            ip6,
            subnet6: if ip6.is_some() { subnet6 } else { None },
            granted_cidrs: routes.iter().map(|r| r.cidr).collect(),
            relays: relay_entries(&ns),
            mtu: ns.cfg.settings.mtu,
            keepalive_secs: ns.cfg.settings.heartbeat_secs,
            transport: ns.cfg.settings.transport.clone(),
            lanes: ns.cfg.settings.lanes,
            control_port: self.control_port,
            heartbeat_secs: ns.cfg.settings.heartbeat_secs,
        })
    }

    /// Recompute and push for one network (admin actions, sweeps).
    pub fn publish(&self, ns: &mut NetState) {
        let keys = self.keyring.key_infos();
        ns.publish(&keys, now_unix());
    }
}

/// Relays a joiner can attach to.
pub fn relay_entries(ns: &NetState) -> Vec<RelayEntry> {
    crate::directory::relay_endpoints(&ns.cfg, &ns.registry)
        .into_iter()
        .map(|r| RelayEntry { relay_id: r.relay_id, name: r.name, addr: r.addr, cert_fp: r.cert_fp })
        .collect()
}

/// Sanity check used by reload: a config change may not silently keep a
/// registration a member is no longer allowed to hold.
pub fn config_matches_registry(cfg: &NetworkConfig, reg: &Registry) -> Vec<String> {
    let mut warnings = Vec::new();
    for (id, rec) in &reg.members {
        let name = rec.name.as_str();
        let Some((m, _)) = cfg.member_by_name(name) else {
            warnings.push(format!(
                "node {id} ({name}) is in the registry but no longer in config; it cannot join until re-added or deleted"
            ));
            continue;
        };

        for r in &rec.routes {
            let ok = m.allowed_cidrs.iter().any(|a| a.contains(&r.cidr.network()) && a.prefix_len() <= r.cidr.prefix_len());
            if !ok {
                warnings.push(format!(
                    "member {name} holds registration {} no longer allowed by config (dropped at its next join)",
                    r.cidr
                ));
            }
        }
    }
    warnings
}
