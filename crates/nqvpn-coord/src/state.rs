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
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
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

/// Minimum spacing between heartbeat-driven recomputes of one network.
pub const PUBLISH_DEBOUNCE_MS: u64 = 150;

/// Concurrent admin password verifications.
pub const LOGIN_SLOTS: usize = 4;

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
    /// Set (under this lock) when the network is deleted: anything that
    /// resolved it before the deletion and then waited for the lock must
    /// not act on it.
    pub deleted: bool,
    /// When the view was last recomputed (epoch ms), and whether a
    /// trailing heartbeat-driven publish is already scheduled.
    last_publish_ms: u64,
    flush_scheduled: bool,
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
            deleted: false,
            last_publish_ms: 0,
            flush_scheduled: false,
            db,
            events,
        }
    }

    /// Collecting before publishing: members that reconnect after a
    /// coordinator restart keep their last view until the fleet has had
    /// two heartbeats to re-declare what it holds.
    /// Within the post-restart collect window: hold view pushes while the
    /// fleet reconnects, then send each member one snapshot of the
    /// settled view (see `restart_grace_secs`).
    pub fn in_grace(&self, now: u64) -> bool {
        now < self.started_at.saturating_add(self.cfg.settings.restart_grace_secs)
    }

    /// Recompute the view and, if it changed, push the delta to every
    /// synced session. The one place generations are minted.
    pub fn publish(&mut self, keys: &[KeyInfo], now: u64) {
        let now_ms = now_ms();
        self.last_publish_ms = now_ms;
        let NetState { cfg, registry, directory, leases, .. } = self;
        let Some(delta) = directory.recompute(cfg, registry, leases, keys, now, now_ms) else {
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

    /// A heartbeat changed something the view is derived from. Publish
    /// now unless the view was recomputed within `PUBLISH_DEBOUNCE_MS`;
    /// then return the delay after which the caller must publish (once:
    /// `None` while a trailing publish is already scheduled). Bounds the
    /// recompute rate per network however fast members heartbeat, and
    /// loses nothing: the trailing publish sees every fact folded in.
    pub fn publish_soon(&mut self, keys: &[KeyInfo], now: u64) -> Option<u64> {
        let since = now_ms().saturating_sub(self.last_publish_ms);
        if since >= PUBLISH_DEBOUNCE_MS {
            self.publish(keys, now);
            None
        } else if self.flush_scheduled {
            None
        } else {
            self.flush_scheduled = true;
            Some(PUBLISH_DEBOUNCE_MS - since)
        }
    }

    /// Something the UI shows changed without a new generation.
    pub fn notify(&self) {
        let _ = self.events.send(self.cfg.network_id.clone());
    }

    /// Commit the registry, mapping failure to an API error.
    pub fn commit(&mut self) -> Result<(), ApiError> {
        match self.db.save_registry(&self.cfg.network_id, &self.registry) {
            Ok(()) => Ok(()),
            Err(e) => {
                // Durability precedes visibility: if the save failed, drop
                // the in-memory mutation so no later publish can expose an
                // unsaved change. Reload the last durable registry.
                match self.db.load_registry(&self.cfg.network_id) {
                    Ok(Some(reg)) => self.registry = reg,
                    _ => tracing::error!(network = %self.cfg.network_id, "registry commit AND its rollback failed; in-memory state may be ahead of disk"),
                }
                Err(ApiError::internal(format!("registry commit failed (change discarded): {e:#}")))
            }
        }
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

    /// Make every connected member re-join (a change every member holds).
    /// Returns how many were connected.
    pub fn reconfigure_all(&mut self, why: &str) -> usize {
        let nodes: Vec<NodeId> = self.sessions.keys().copied().collect();
        let n = nodes.len();
        for node in nodes {
            self.reconfigure(node, why);
        }
        n
    }
}

/// The key a source address is rate limited under: an IPv4 address as
/// is (an IPv4-mapped IPv6 address counts as its IPv4 address), an IPv6
/// address by its /64 — one subscriber's allocation, so rotating through
/// a prefix's privacy addresses earns no fresh allowance.
pub fn rate_key(ip: &str) -> String {
    match ip.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

/// Fixed-window per-source limiter, hard-capped so it cannot be grown
/// without bound. Keyed by source address alone (see `rate_key`) — not
/// by anything the client chooses (the secret) — so an attacker cannot
/// mint a fresh allowance per request, and the limit applies before the
/// secret is resolved (which scans every member).
#[derive(Default)]
pub struct RateLimiter {
    /// key -> (window, count, insertion order)
    map: HashMap<String, (u64, u32, u64)>,
    /// Insertion order -> key, for evicting the oldest entry.
    order: BTreeMap<u64, String>,
    seq: u64,
    /// Evictions in `evict_window`. Past `RATE_LIMIT_MAX_KEYS` of them the
    /// table has been churned through once this window, and new sources
    /// are refused until it rolls.
    evictions: usize,
    evict_window: u64,
}

/// Upper bound on distinct sources tracked at once. When full, the
/// oldest entry is evicted, so newcomers are not locked out by a table
/// full of strangers; churning the table resets only the churner's own
/// earlier counters, and at most this many times a window before the
/// fallback refuses unknown sources outright.
const RATE_LIMIT_MAX_KEYS: usize = 65_536;

impl RateLimiter {
    /// Count one attempt from `key`; true if it is within `limit` this
    /// minute.
    pub fn check(&mut self, key: String, limit: u32, now: u64) -> bool {
        let window = now / 60;
        if self.evict_window != window {
            self.evict_window = window;
            self.evictions = 0;
        }
        if !self.map.contains_key(&key) && self.map.len() >= RATE_LIMIT_MAX_KEYS {
            // Last window's entries go first; then the oldest of this one.
            let stale: Vec<String> =
                self.map.iter().filter(|(_, (w, _, _))| *w != window).map(|(k, _)| k.clone()).collect();
            for k in stale {
                if let Some((_, _, seq)) = self.map.remove(&k) {
                    self.order.remove(&seq);
                }
            }
            if self.map.len() >= RATE_LIMIT_MAX_KEYS {
                if self.evictions >= RATE_LIMIT_MAX_KEYS {
                    return false;
                }
                if let Some((_, oldest)) = self.order.pop_first() {
                    self.map.remove(&oldest);
                    self.evictions += 1;
                }
            }
        }
        if !self.map.contains_key(&key) {
            self.seq += 1;
            self.order.insert(self.seq, key.clone());
            self.map.insert(key.clone(), (window, 0, self.seq));
        }
        let entry = self.map.get_mut(&key).expect("inserted above");
        if entry.0 != window {
            entry.0 = window;
            entry.1 = 0;
        }
        entry.1 = entry.1.saturating_add(1);
        entry.1 <= limit
    }

    /// Give back one attempt (a login that succeeded).
    pub fn refund(&mut self, key: &str) {
        if let Some(e) = self.map.get_mut(key) {
            e.1 = e.1.saturating_sub(1);
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Lock a network during a pass over *every* network. A poisoned lock
/// (a panic while it was held) leaves that network's state suspect: it
/// is skipped, loudly, instead of taking every other network down with
/// it — joins scan every network, and one liveness sweep serves all.
pub fn lock_for_sweep<'a>(id: &str, net: &'a Mutex<NetState>) -> Option<MutexGuard<'a, NetState>> {
    match net.lock() {
        Ok(g) => Some(g),
        Err(_) => {
            tracing::error!(network = %id, "network state is poisoned by an earlier panic; skipping it (restart the coordinator)");
            None
        }
    }
}

/// Lock one network for a request: a poisoned lock is an internal
/// error, never a panic.
pub fn lock_net(net: &Mutex<NetState>) -> Result<MutexGuard<'_, NetState>, ApiError> {
    net.lock().map_err(|_| ApiError::internal("network state is poisoned by an earlier panic; restart the coordinator"))
}

pub struct AppState {
    pub coord: CoordConfig,
    pub admin_token: Option<String>,
    /// Networks come and go at runtime (the UI creates them); each is
    /// its own serialized owner.
    networks: RwLock<HashMap<String, Arc<Mutex<NetState>>>>,
    pub keyring: Keyring,
    pub join_rate: Mutex<RateLimiter>,
    /// Admin login attempts per source (see `rate_key`).
    pub login_rate: Mutex<RateLimiter>,
    /// Concurrent argon2 verifications (19 MiB each, on the blocking
    /// pool): a login that finds none free is refused, not queued.
    pub login_slots: Arc<tokio::sync::Semaphore>,
    /// Serializes operations that add or remove whole networks (create,
    /// delete, import), so an existence check and the change it guards
    /// cannot interleave with another such operation.
    pub admin_lock: Mutex<()>,
    pub db: Arc<Db>,
    /// Published in join responses: the QUIC control port.
    pub control_port: u16,
    /// The coordinator's own certificate (PEM) and whether it is the
    /// auto-generated self-signed one, so the UI can hand members a
    /// config that verifies it. Set once at startup.
    pub coord_cert: Mutex<Option<(String, bool)>>,
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
            login_rate: Mutex::new(RateLimiter::default()),
            login_slots: Arc::new(tokio::sync::Semaphore::new(LOGIN_SLOTS)),
            admin_lock: Mutex::new(()),
            db,
            control_port,
            coord_cert: Mutex::new(None),
            events: tokio::sync::broadcast::channel(256).0,
            auth: crate::auth::Sessions::default(),
        }
    }

    pub fn set_coord_cert(&self, pem: String, self_signed: bool) {
        *self.coord_cert.lock().unwrap() = Some((pem, self_signed));
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

    fn check_rate(&self, ip: &str) -> Result<(), ApiError> {
        let limit = self.coord.limits.join_rate_per_min;
        let mut rl = self.join_rate.lock().unwrap_or_else(|e| e.into_inner());
        if rl.check(rate_key(ip), limit, now_unix()) {
            Ok(())
        } else {
            Err(ApiError::rate_limited())
        }
    }

    /// The member a secret belongs to, across every network. Compared
    /// in constant time against every member's secret, so a wrong
    /// secret costs the same whatever it almost matched.
    ///
    /// A hint, not a decision: the network lock is released before the
    /// caller acts, so `join` re-checks the member under the lock.
    pub fn resolve_secret(&self, secret: &str) -> Option<Resolved> {
        let secret = secret.trim();
        // Only something shaped like a secret is compared at all: an
        // empty or oversized one costs nothing to refuse.
        if !crate::secrets::plausible_secret(secret) {
            return None;
        }
        let mut found = None;
        for (network_id, net) in self.nets() {
            let Some(ns) = lock_for_sweep(&network_id, &net) else { continue };
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
        // Rate limited per source, before any secret comparison, so a
        // client cannot mint a fresh allowance by varying the secret and
        // cannot make us scan every member for free.
        self.check_rate(peer_ip)?;

        // ---- phase 1: the secret names the member ----
        let presented = req.secret.trim();
        let Resolved { net, network_id, name, .. } =
            self.resolve_secret(presented).ok_or_else(ApiError::bad_credentials)?;
        if !valid_pubkey(&req.pubkey) {
            return Err(ApiError::bad_request("pubkey must be a base64 32-byte X25519 key"));
        }
        if !valid_fingerprint(&req.cert_fingerprint) {
            return Err(ApiError::bad_request("cert_fingerprint must be sha256:<64 hex>"));
        }

        // ---- phase 2: serialized mutation under the network lock ----
        let mut ns = lock_net(&net)?;
        if ns.deleted {
            return Err(ApiError::bad_credentials());
        }
        // Phase 1 looked under a lock it has since released: the member
        // may have been deleted, imported away, or had its secret rotated
        // in between. Only what holds *now* counts — otherwise a stale
        // join would be handed a credential at the post-rotation
        // login_gen, or re-create a deleted member's record.
        let (member_cfg, role) = match ns.cfg.member_by_name(&name) {
            Some((m, role)) if m.secret.as_deref().is_some_and(|s| constant_time_eq(s.trim(), presented)) => {
                (m.clone(), role)
            }
            _ => return Err(ApiError::bad_credentials()),
        };
        let now = now_unix();
        let ttl_secs = ns.cfg.settings.credential_ttl_mins.saturating_mul(60);

        // The operator's configuration is the member's declaration.
        let want_vpn_ip = member_cfg.want_vpn_ip.unwrap_or(true);
        let local_cidrs: Vec<IpNet> = if role == Role::Relay { member_cfg.local_cidrs.clone() } else { vec![] };
        let relay_addr = if role == Role::Relay {
            let configured = member_cfg
                .relay_addr
                .as_deref()
                .ok_or_else(|| ApiError::bad_request(format!("relay {name} has no relay_addr configured")))?;
            Some(checked_relay_addr(&name, configured, peer_ip, &ns.cfg)?)
        } else {
            None
        };

        let existing = ns.registry.by_name(&name).cloned();
        if let Some(rec) = &existing {
            if rec.disabled {
                return Err(ApiError::client_disabled());
            }
        }

        // Configured addresses are hard reservations. Dynamic addresses
        // are durable soft reservations: the allocator returns this
        // member's existing address while it remains valid, but may take
        // the longest-gone offline client's reservation when a range is
        // otherwise exhausted. Never reclaim during restart grace, while
        // the fleet has not yet had time to prove which members are live.
        let (ip4, ip6) = if want_vpn_ip {
            let want4 = member_cfg.preferred_ip4;
            let want6 = member_cfg.preferred_ip6;
            let allow_reclaim = !ns.in_grace(now);
            let NetState { cfg, registry, leases, .. } = &mut *ns;
            let granted = crate::ipam::allocate_for_join(
                cfg,
                registry,
                leases,
                allow_reclaim,
                &name,
                want4,
                want6,
            )?;
            (granted.ip4, granted.ip6)
        } else {
            (None, None)
        };

        // Routes: exactly what the configuration declares; ages survive
        // for CIDRs that stay continuously declared. An internet-gateway
        // relay is granted the default route (v4 + v6) internally — the
        // operator sets a flag, never types `0.0.0.0/0`.
        let mut declared: Vec<IpNet> = local_cidrs.iter().map(|c| c.trunc()).collect();
        if role == Role::Relay && member_cfg.internet_gateway == Some(true) {
            declared.push("0.0.0.0/0".parse().expect("v4 default"));
            declared.push("::/0".parse().expect("v6 default"));
        }
        let mut routes: Vec<RouteReg> = existing.as_ref().map(|r| r.routes.clone()).unwrap_or_default();
        routes.retain(|r| declared.contains(&r.cidr));
        for c in &declared {
            if !routes.iter().any(|r| r.cidr == *c) {
                routes.push(RouteReg { cidr: *c, first_granted_unix: now });
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
            exp: now.saturating_add(ttl_secs),
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

    /// Heartbeat-driven publish, rate limited per network (see
    /// `NetState::publish_soon`): a deferred publish runs on a timer.
    pub fn publish_soon(self: &Arc<Self>, network_id: &str, ns: &mut NetState) {
        let keys = self.keyring.key_infos();
        let Some(delay) = ns.publish_soon(&keys, now_unix()) else { return };
        let (state, id) = (self.clone(), network_id.to_string());
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
            let Some(net) = state.net(&id) else { return };
            let Some(mut ns) = lock_for_sweep(&id, &net) else { return };
            ns.flush_scheduled = false;
            state.publish(&mut ns);
        });
    }
}

/// `auto:<port>` means "the address this join came from"; anything else
/// is taken as configured. An IPv4-mapped IPv6 source is its IPv4
/// address.
pub fn effective_relay_addr(configured: &str, peer_ip: &str) -> String {
    match configured.strip_prefix("auto:") {
        Some(port) => match peer_ip.parse::<IpAddr>().map(|ip| ip.to_canonical()) {
            Ok(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
            Ok(IpAddr::V4(v4)) => format!("{v4}:{port}"),
            Err(_) => format!("{peer_ip}:{port}"),
        },
        None => configured.to_string(),
    }
}

/// The relay address a join publishes. A configured address was checked
/// when it was configured; `auto:<port>` is only known now, so the
/// source address gets the same endpoint rules here (no loopback,
/// unspecified, multicast, tunnel space or routed LAN).
fn checked_relay_addr(name: &str, configured: &str, peer_ip: &str, cfg: &NetworkConfig) -> Result<String, ApiError> {
    if configured.starts_with("auto:") {
        let ip = peer_ip
            .parse::<IpAddr>()
            .map_err(|_| ApiError::bad_request(format!("relay {name}: cannot derive relay_addr from source {peer_ip:?}")))?
            .to_canonical();
        crate::config::check_relay_ip(name, configured, ip, cfg).map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    }
    Ok(effective_relay_addr(configured, peer_ip))
}

/// Relays a joiner can attach to.
pub fn relay_entries(ns: &NetState) -> Vec<RelayEntry> {
    crate::directory::relay_endpoints(&ns.cfg, &ns.registry)
        .into_iter()
        .map(|r| RelayEntry { relay_id: r.relay_id, name: r.name, addr: r.addr, cert_fp: r.cert_fp })
        .collect()
}


#[cfg(test)]
mod rate_tests {
    use super::*;

    #[test]
    fn join_limit_is_per_ip_and_cannot_be_bypassed_or_grown_unbounded() {
        let mut rl = RateLimiter::default();
        // One IP is capped at the limit within a window, regardless of
        // what the client varies (the key is the IP alone).
        for i in 0..5 {
            assert!(rl.check("1.1.1.1".into(), 5, 100), "attempt {i} within limit");
        }
        assert!(!rl.check("1.1.1.1".into(), 5, 100), "over the limit for this IP");
        // A different IP has its own allowance.
        assert!(rl.check("2.2.2.2".into(), 5, 100));
        // The window rolls: the allowance resets.
        assert!(rl.check("1.1.1.1".into(), 5, 160));
    }

    #[test]
    fn ipv6_sources_share_their_64_and_mapped_v4_is_v4() {
        assert_eq!(rate_key("2001:db8:1:2:aaaa::1"), rate_key("2001:db8:1:2:bbbb::2"));
        assert_ne!(rate_key("2001:db8:1:2::1"), rate_key("2001:db8:1:3::1"));
        assert_eq!(rate_key("::ffff:1.2.3.4"), "1.2.3.4");
        assert_eq!(rate_key("1.2.3.4"), "1.2.3.4");
    }

    #[test]
    fn a_full_table_evicts_the_oldest_instead_of_refusing_newcomers() {
        let mut rl = RateLimiter::default();
        for i in 0..RATE_LIMIT_MAX_KEYS {
            assert!(rl.check(format!("k{i}"), 5, 100));
        }
        assert_eq!(rl.len(), RATE_LIMIT_MAX_KEYS);
        assert!(rl.check("newcomer".into(), 5, 100), "a new source is admitted");
        assert_eq!(rl.len(), RATE_LIMIT_MAX_KEYS, "still bounded");
        // The newest entries survive; the oldest was evicted.
        for _ in 0..4 {
            assert!(rl.check("newcomer".into(), 5, 100));
        }
        assert!(!rl.check("newcomer".into(), 5, 100), "and its own count is kept");
    }

    #[test]
    fn a_refund_gives_one_attempt_back() {
        let mut rl = RateLimiter::default();
        assert!(rl.check("a".into(), 1, 100));
        rl.refund("a");
        assert!(rl.check("a".into(), 1, 100));
        assert!(!rl.check("a".into(), 1, 100));
    }
}
