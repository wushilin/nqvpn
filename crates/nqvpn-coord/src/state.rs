//! Application state and the join transaction.
//!
//! One serialized owner per network: every mutation for a network runs
//! under its mutex, and the registry is durably committed *before* the
//! credential is returned (durability precedes visibility).
//!
//! A join carries nothing about the member but its secret and its keys.
//! The secret names the member; everything the member *is* — network,
//! name, role, address, routed prefixes, relay address — is the
//! operator's configuration, kept here and handed down in the response.
//! Every join re-applies that configuration in full, so a change made
//! in the UI takes effect at the member's next join, which the
//! coordinator triggers by closing its control session.

use ipnet::IpNet;
use nqvpn_proto::api::{JoinRequest, JoinResponse, RelayEntry};
use nqvpn_proto::control::KeyInfo;
use nqvpn_proto::credential::{self, Claims, AUD};
use nqvpn_proto::types::{NodeId, Role};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{CoordConfig, MemberCfg, NetworkConfig};
use crate::control::{self, Push, Session};
use crate::db::Db;
use crate::directory::Directory;
use crate::error::ApiError;
use crate::leases::Leases;
use crate::registry::{Registry, RouteReg};
use crate::secrets::constant_time_eq;
use crate::signer::Keyring;

pub const ISS: &str = "nqvpn-coord";

pub struct NetState {
    pub cfg: NetworkConfig,
    pub registry: Registry,
    pub directory: Directory,
    pub leases: Leases,
    /// Live control sessions by node id.
    pub sessions: HashMap<NodeId, Session>,
    /// When this process started serving the network; snapshots are
    /// withheld for a short grace after it, so a coordinator restart
    /// first hears everyone's declarations before publishing a view.
    pub started_at: u64,
    db: Arc<Db>,
    /// Every published generation is announced here (the UI listens).
    events: tokio::sync::broadcast::Sender<String>,
}

impl NetState {
    pub fn new(cfg: NetworkConfig, registry: Registry, db: Arc<Db>, events: tokio::sync::broadcast::Sender<String>) -> Self {
        let now = now_unix();
        let gen0 = registry.initial_gen(now_ms());
        let hold = cfg.settings.hold_down_secs;
        NetState {
            cfg,
            registry,
            directory: Directory::new(gen0, hold),
            leases: Leases::default(),
            sessions: HashMap::new(),
            started_at: now,
            db,
            events,
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
            if let Err(e) = self.db.save_registry(&cfg.network_id, registry) {
                tracing::error!(network = %cfg.network_id, "persisting generation mark: {e:#}");
            }
        }
        control::broadcast_delta(self, delta);
        let _ = self.events.send(self.cfg.network_id.clone());
    }

    /// Something the UI shows changed without a new generation.
    pub fn notify(&self) {
        let _ = self.events.send(self.cfg.network_id.clone());
    }

    /// Commit the registry, mapping failure to an API error.
    pub fn commit(&self) -> Result<(), ApiError> {
        self.db
            .save_registry(&self.cfg.network_id, &self.registry)
            .map_err(|e| ApiError::internal(format!("registry commit failed: {e:#}")))
    }

    /// Commit the configuration (an operator's change).
    pub fn save_config(&self) -> Result<(), ApiError> {
        self.db
            .save_network(&self.cfg)
            .map_err(|e| ApiError::internal(format!("config commit failed: {e:#}")))
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

    /// The member's configuration changed: make it re-join and apply.
    pub fn reconfigure(&mut self, node: NodeId, why: &str) {
        self.close_session_with(node, control::CLOSE_RECONFIGURED, why);
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
    /// Networks come and go at runtime (the UI creates them); each is
    /// its own serialized owner.
    networks: RwLock<HashMap<String, Arc<Mutex<NetState>>>>,
    pub keyring: Keyring,
    pub join_rate: Mutex<RateLimiter>,
    pub db: Arc<Db>,
    /// Published in join responses: the QUIC control port.
    pub control_port: u16,
    /// Network ids whose published state changed; the UI's live feed.
    pub events: tokio::sync::broadcast::Sender<String>,
    /// UI login sessions.
    pub auth: crate::auth::Sessions,
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

/// What a secret resolved to.
pub struct Resolved {
    pub net: Arc<Mutex<NetState>>,
    pub network_id: String,
    pub name: String,
    pub role: Role,
    pub member: MemberCfg,
}

impl AppState {
    pub fn new(coord: CoordConfig, admin_token: Option<String>, keyring: Keyring, db: Arc<Db>, control_port: u16) -> AppState {
        AppState {
            coord,
            admin_token,
            networks: RwLock::new(HashMap::new()),
            keyring,
            join_rate: Mutex::new(RateLimiter::default()),
            db,
            control_port,
            events: tokio::sync::broadcast::channel(256).0,
            auth: crate::auth::Sessions::default(),
        }
    }

    /// Serve a network (loaded from the database, or just created).
    pub fn add_network(&self, cfg: NetworkConfig, registry: Registry) -> Arc<Mutex<NetState>> {
        let id = cfg.network_id.clone();
        let ns = Arc::new(Mutex::new(NetState::new(cfg, registry, self.db.clone(), self.events.clone())));
        let _ = self.events.send(id.clone());
        self.networks.write().unwrap().insert(id, ns.clone());
        ns
    }

    pub fn remove_network(&self, id: &str) -> Option<Arc<Mutex<NetState>>> {
        let removed = self.networks.write().unwrap().remove(id);
        let _ = self.events.send(id.to_string());
        removed
    }

    pub fn net(&self, id: &str) -> Option<Arc<Mutex<NetState>>> {
        self.networks.read().unwrap().get(id).cloned()
    }

    /// Every network, sorted by id. Cloned handles: callers lock each
    /// network on its own, never the map.
    pub fn nets(&self) -> Vec<(String, Arc<Mutex<NetState>>)> {
        let mut v: Vec<_> = self.networks.read().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    fn check_rate(&self, key: String, ip: String) -> Result<(), ApiError> {
        let limit = self.coord.limits.join_rate_per_min;
        if self.join_rate.lock().unwrap().check(key, ip, limit, now_unix()) {
            Ok(())
        } else {
            Err(ApiError::rate_limited())
        }
    }

    /// The member a secret belongs to, across every network. Compared
    /// in constant time against every member's secret, so a wrong
    /// secret costs the same whatever it almost matched.
    pub fn resolve_secret(&self, secret: &str) -> Option<Resolved> {
        let secret = secret.trim();
        if secret.is_empty() {
            return None;
        }
        let mut found = None;
        for (network_id, net) in self.nets() {
            let ns = net.lock().unwrap();
            for (name, m, role) in ns.cfg.members() {
                let Some(s) = &m.secret else { continue };
                if constant_time_eq(s.trim(), secret) && found.is_none() {
                    found = Some(Resolved {
                        net: net.clone(),
                        network_id: network_id.clone(),
                        name: name.clone(),
                        role,
                        member: m.clone(),
                    });
                }
            }
        }
        found
    }

    /// The whole join transaction.
    pub fn join(&self, req: &JoinRequest, peer_ip: &str) -> Result<JoinResponse, ApiError> {
        // Rate limited by the secret's prefix, so a guessing client is
        // throttled before any comparison work is spent on it.
        let key: String = req.secret.chars().take(8).collect();
        self.check_rate(key, peer_ip.to_string())?;

        // ---- phase 1: the secret names the member ----
        let Resolved { net, network_id, name, role, member: member_cfg } =
            self.resolve_secret(&req.secret).ok_or_else(ApiError::bad_credentials)?;
        if !valid_pubkey(&req.pubkey) {
            return Err(ApiError::bad_request("pubkey must be a base64 32-byte X25519 key"));
        }
        if !valid_fingerprint(&req.cert_fingerprint) {
            return Err(ApiError::bad_request("cert_fingerprint must be sha256:<64 hex>"));
        }
        // The operator's configuration is the member's declaration.
        let want_vpn_ip = member_cfg.want_vpn_ip.unwrap_or(true);
        let local_cidrs: Vec<IpNet> = if role == Role::Relay { member_cfg.local_cidrs.clone() } else { vec![] };
        let relay_addr = if role == Role::Relay {
            let configured = member_cfg
                .relay_addr
                .as_deref()
                .ok_or_else(|| ApiError::bad_request(format!("relay {name} has no relay_addr configured")))?;
            Some(effective_relay_addr(configured, peer_ip))
        } else {
            None
        };

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

        // Addresses are identity: sticky, unless the configuration now
        // asks for something else (a new preferred address, or none).
        let (ip4, ip6) = if want_vpn_ip {
            let (have4, have6) = existing.as_ref().map(|r| (r.ip4, r.ip6)).unwrap_or((None, None));
            let want4 = member_cfg.preferred_ip4;
            let want6 = member_cfg.preferred_ip6;
            let keep4 = have4.is_some() && (want4.is_none() || want4 == have4);
            let keep6 = have6.is_some() && (want6.is_none() || want6 == have6);
            if keep4 && (keep6 || have6.is_none() && want6.is_none()) {
                (have4, have6)
            } else {
                let NetState { cfg, registry, .. } = &mut *ns;
                let granted = crate::ipam::allocate(cfg, registry, &name, None, want4.or(have4), want6.or(have6))?;
                (granted.ip4, granted.ip6)
            }
        } else {
            (None, None)
        };

        // Routes: exactly what the configuration declares; ages survive
        // for CIDRs that stay continuously declared.
        let mut routes: Vec<RouteReg> = existing.as_ref().map(|r| r.routes.clone()).unwrap_or_default();
        routes.retain(|r| local_cidrs.iter().any(|c| c.trunc() == r.cidr));
        for c in &local_cidrs {
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
        rec.relay_addr = relay_addr.clone();
        rec.last_join_unix = Some(now);
        rec.last_join_from = Some(peer_ip.to_string());
        let login_gen = rec.login_gen;
        let node_id = rec.node_id;

        // Durability precedes visibility.
        ns.commit()?;

        if replaced {
            tracing::info!(
                network = %network_id, member = %name, node_id, from = peer_ip, login_gen,
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

        let subnet4 = ip4.and_then(|ip| ns.cfg.cidrs.iter().find(|c| c.contains(&IpAddr::V4(ip))).cloned());
        let subnet6 = ip6.and_then(|ip| ns.cfg.cidrs.iter().find(|c| c.contains(&IpAddr::V6(ip))).cloned());

        Ok(JoinResponse {
            credential: token,
            network_id: ns.cfg.network_id.clone(),
            role,
            network_uuid: ns.registry.network_uuid.to_string(),
            coordinator_signing_keys: keys,
            node_id,
            name,
            login_gen,
            ip4,
            subnet4,
            ip6,
            subnet6,
            granted_cidrs: routes.iter().map(|r| r.cidr).collect(),
            relay_addr,
            preferred_relay: member_cfg.preferred_relay.clone(),
            max_session_mbps: member_cfg.max_session_mbps.unwrap_or(ns.cfg.settings.max_session_mbps),
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

/// `auto:<port>` means "the address this join came from"; anything else
/// is taken as configured.
pub fn effective_relay_addr(configured: &str, peer_ip: &str) -> String {
    match configured.strip_prefix("auto:") {
        Some(port) => match peer_ip.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
            _ => format!("{peer_ip}:{port}"),
        },
        None => configured.to_string(),
    }
}

/// Relays a joiner can attach to.
pub fn relay_entries(ns: &NetState) -> Vec<RelayEntry> {
    crate::directory::relay_endpoints(&ns.cfg, &ns.registry)
        .into_iter()
        .map(|r| RelayEntry { relay_id: r.relay_id, name: r.name, addr: r.addr, cert_fp: r.cert_fp })
        .collect()
}
