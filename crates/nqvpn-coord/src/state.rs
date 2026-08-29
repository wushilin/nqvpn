//! Application state and the join transaction (§3.2, §3.3).
//!
//! One serialized owner per network: every mutation for a network runs
//! under its mutex, and the registry is durably committed *before* the
//! credential is returned (durability precedes visibility).

use argon2::password_hash::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use ipnet::IpNet;
use nqvpn_proto::api::{JoinRequest, JoinResponse, RelayEntry};
use nqvpn_proto::credential::{self, Claims, AUD};
use nqvpn_proto::lpm::overlaps;
use nqvpn_proto::types::Role;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{CoordConfig, MemberCfg, NetworkConfig};
use crate::control::{broadcast, Push, Session};
use crate::directory::Directory;
use crate::error::ApiError;
use crate::registry::{Registry, RouteReg};
use crate::signer::Keyring;

pub const ISS: &str = "nqvpn-coord";

pub struct NetState {
    pub cfg: NetworkConfig,
    pub registry: Registry,
    pub registry_path: PathBuf,
    /// Derived, revisioned view pushed to members (§3.2).
    pub directory: Directory,
    /// Live control sessions by member name.
    pub sessions: HashMap<String, Session>,
    /// Last application-level keepalive per member.
    pub last_seen: HashMap<String, u64>,
    /// Last relay fleet pushed, so we only publish real changes.
    pub published_relays: Option<Vec<nqvpn_proto::control::RelayEndpoint>>,
}

impl NetState {
    /// Recompute the directory. Split-borrow helper: `directory`,
    /// `cfg`, and `registry` are disjoint fields, but the borrow checker
    /// needs that spelled out.
    pub fn refresh_directory(
        &mut self,
        now: u64,
    ) -> Option<nqvpn_proto::control::MembershipDelta> {
        let NetState { cfg, registry, directory, .. } = self;
        directory.recompute(cfg, registry, now)
    }

    pub fn new(cfg: NetworkConfig, registry: Registry, registry_path: PathBuf) -> Self {
        let directory = Directory::with_hold_down(cfg.settings.hold_down_secs);
        NetState {
            cfg,
            registry,
            registry_path,
            directory,
            sessions: HashMap::new(),
            last_seen: HashMap::new(),
            published_relays: None,
        }
    }
}

pub struct AppState {
    pub coord: CoordConfig,
    pub admin_token: Option<String>,
    pub networks: HashMap<String, Mutex<NetState>>,
    pub keyring: Keyring,
    /// (client_id@network, ip) -> fixed-window join counter.
    pub join_rate: Mutex<HashMap<(String, String), (u64, u32)>>,
    /// Where `networks.d/` lives, for `POST /api/v1/reload`.
    pub networks_dir: Option<PathBuf>,
    /// Coordinator-managed secrets, consulted before the network config.
    pub secrets: Mutex<crate::secrets::SecretStore>,
    pub secrets_path: PathBuf,
}

pub fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

impl AppState {
    pub fn member_cfg<'a>(
        cfg: &'a NetworkConfig,
        name: &str,
    ) -> Option<(&'a MemberCfg, Role)> {
        if let Some(m) = cfg.clients.get(name) {
            return Some((m, Role::Client));
        }
        if let Some(m) = cfg.relays.get(name) {
            return Some((m, Role::Relay));
        }
        None
    }

    /// Fixed-window per-(member, ip) rate limit for /join and admin login.
    pub fn check_rate(&self, key: String, ip: String) -> Result<(), ApiError> {
        let limit = self.coord.limits.join_rate_per_min;
        let now = now_unix();
        let window = now / 60;
        let mut map = self.join_rate.lock().unwrap();
        let entry = map.entry((key, ip)).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        entry.1 += 1;
        if entry.1 > limit {
            return Err(ApiError::rate_limited());
        }
        Ok(())
    }

    /// The whole join transaction. Secret verification (argon2, slow)
    /// happens before the network lock is taken.
    pub fn join(&self, req: &JoinRequest, peer_ip: &str) -> Result<JoinResponse, ApiError> {
        self.check_rate(format!("{}@{}", req.client_id, req.network_id), peer_ip.to_string())?;

        let net = self
            .networks
            .get(&req.network_id)
            .ok_or_else(ApiError::bad_credentials)?; // unknown network == unknown member

        // ---- phase 1: checks that need only immutable config ----
        let (member_cfg, role) = {
            let ns = net.lock().unwrap();
            match Self::member_cfg(&ns.cfg, &req.client_id) {
                Some((m, r)) => (m.clone(), r),
                None => return Err(ApiError::bad_credentials()),
            }
        };
        if role != req.role {
            return Err(ApiError::bad_request(format!(
                "member is configured as {role}, joined as {}",
                req.role
            )));
        }
        // Authenticate against the managed store first. A refusal there
        // is final: falling through to the config on a *wrong* secret
        // would let a member the operator believes they re-keyed carry on
        // using a stale shared one.
        let want_kind = match role {
            Role::Relay => crate::secrets::SecretKind::Relay,
            Role::Client => crate::secrets::SecretKind::Client,
        };
        let store_verdict = {
            let store = self.secrets.lock().unwrap();
            store.verify(
                &req.client_id,
                &req.client_secret,
                Some(&req.network_id),
                want_kind,
            )
        };
        match store_verdict {
            Ok(true) => {}
            Err(e) => {
                tracing::warn!(
                    member = %req.client_id, network = %req.network_id,
                    "join refused by the secret store: {e}"
                );
                return Err(ApiError::bad_credentials());
            }
            // No managed secret for this identity: the network config is
            // still authoritative, so an existing deployment keeps working
            // and migrates one member at a time.
            Ok(false) => {
                let parsed = PasswordHash::new(&member_cfg.secret_hash)
                    .map_err(|_| ApiError::bad_credentials())?;
                Argon2::default()
                    .verify_password(req.client_secret.as_bytes(), &parsed)
                    .map_err(|_| ApiError::bad_credentials())?;
            }
        }

        if role == Role::Client && (!req.local_cidrs.is_empty() || req.relay_addr.is_some()) {
            return Err(ApiError::bad_request(
                "clients cannot register routes or a relay address",
            ));
        }
        if role == Role::Relay {
            // The coordinator config is the plan of record: a relay must
            // advertise exactly the address the fleet was told to dial,
            // or peers silently dial the wrong place (§3.2).
            let configured = member_cfg.relay_addr.as_deref().unwrap_or_default();
            match req.relay_addr.as_deref() {
                Some(a) if a == configured => {}
                Some(a) => {
                    return Err(ApiError::bad_request(format!(
                        "relay_addr {a:?} does not match the configured {configured:?}"
                    )))
                }
                None => {
                    return Err(ApiError::bad_request(
                        "relays must present relay_addr".to_string(),
                    ))
                }
            }
            for c in &req.local_cidrs {
                let allowed = member_cfg.allowed_cidrs.iter().any(|a| {
                    a.contains(&c.network()) && a.prefix_len() <= c.prefix_len()
                });
                if !allowed {
                    return Err(ApiError::prefix_conflict(format!(
                        "cidr {c} is not within this relay's allowed_cidrs"
                    )));
                }
            }
        }
        if let Some(pin) = &member_cfg.pinned_pubkey {
            if pin != &req.pubkey {
                return Err(ApiError::pin_mismatch());
            }
        }

        // ---- phase 2: serialized mutation under the network lock ----
        let mut ns = net.lock().unwrap();
        let now = now_unix();
        let ttl_secs = ns.cfg.settings.credential_ttl_mins * 60;

        let rec = ns.registry.members.get(&req.client_id);
        if let Some(rec) = rec {
            if rec.disabled {
                return Err(ApiError::client_disabled());
            }
            // TOFU: after first join, key and cert must match a *live*
            // pin. Any unexpired pin counts, which is what lets a member
            // mid-rotation join with either the new key or the old one —
            // and a retired pin does not, so the window really closes.
            if !rec.pubkeys.is_empty() && !rec.pubkeys.accepts(&req.pubkey, now) {
                return Err(ApiError::pin_mismatch());
            }
            if !rec.cert_fps.is_empty()
                && !rec.cert_fps.accepts(&req.cert_fingerprint, now)
            {
                return Err(ApiError::pin_mismatch());
            }
        }

        // Address allocation (sticky: reuse existing assignment).
        let (ip4, ip6) = if req.want_vpn_ip {
            let existing = ns.registry.members.get(&req.client_id);
            let (have4, have6) = existing.map(|r| (r.ip4, r.ip6)).unwrap_or((None, None));
            // A preferred request that contradicts a sticky assignment
            // is a config-change request — reject it explicitly.
            if let (Some(want), Some(have)) = (req.preferred_ip4, have4) {
                if want != have {
                    return Err(ApiError::address_in_use(format!(
                        "member already holds {have}; release it first (admin)"
                    )));
                }
            }
            if have4.is_some() {
                (have4, have6)
            } else {
                // Split borrow: cfg is read, registry is mutated (the
                // allocator advances the pool cursor).
                let NetState { cfg, registry, .. } = &mut *ns;
                let granted = crate::ipam::allocate(
                    cfg,
                    registry,
                    &req.client_id,
                    req.pool.as_deref(),
                    req.preferred_ip4,
                    req.preferred_ip6,
                )?;
                (granted.ip4, granted.ip6)
            }
        } else {
            (None, None)
        };

        // Route registrations: keep existing first-grant ages, add new.
        let mut routes: Vec<RouteReg> = ns
            .registry
            .members
            .get(&req.client_id)
            .map(|r| r.routes.clone())
            .unwrap_or_default();
        routes.retain(|r| req.local_cidrs.iter().any(|c| c.trunc() == r.cidr));
        for c in &req.local_cidrs {
            let c = c.trunc();
            if !routes.iter().any(|r| r.cidr == c) {
                routes.push(RouteReg { cidr: c, first_granted_unix: now });
            }
        }

        // Mutate the record.
        let rec = ns.registry.member_mut_with_id(&req.client_id, now, member_cfg.node_id);
        let node_id = rec.node_id;
        if rec.pubkeys.is_empty() {
            rec.pubkeys.pin_first(req.pubkey.clone());
        } else {
            // Joining with a key that is already pinned confirms it. If
            // that is the post-rotation key, the predecessor retires now
            // rather than lingering for the rest of the overlap.
            rec.pubkeys.confirm(&req.pubkey);
        }
        if rec.cert_fps.is_empty() {
            rec.cert_fps.pin_first(req.cert_fingerprint.clone());
        } else {
            rec.cert_fps.confirm(&req.cert_fingerprint);
        }
        rec.pubkeys.prune(now);
        rec.cert_fps.prune(now);
        rec.mirror_legacy_pins();
        rec.ip4 = ip4;
        rec.ip6 = ip6;
        rec.routes = routes.clone();
        rec.last_join_unix = Some(now);

        // Durability precedes visibility.
        ns.registry
            .commit(&ns.registry_path)
            .map_err(|e| ApiError::internal(format!("registry commit failed: {e:#}")))?;

        // Publish the resulting membership change to live sessions.
        if let Some(d) = ns.refresh_directory(now) {
            broadcast(&ns, Push::Membership(d));
        }
        // A first-time relay join makes the fleet dialable: tell everyone.
        crate::control::publish_relays_if_changed(&mut ns);

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
            sub: req.client_id.clone(),
            role,
            pubkey: req.pubkey.clone(),
            cert_fp: req.cert_fingerprint.clone(),
            prefixes,
            iat: now,
            exp: now + ttl_secs,
        };
        let (kid, sk) = self.keyring.active();
        let token = credential::sign(&claims, kid, sk);

        let relays = relay_entries(&ns);
        let subnet4 = ns.cfg.cidrs.iter().find(|c| matches!(c, IpNet::V4(_))).cloned();
        let subnet6 = ns.cfg.cidrs.iter().find(|c| matches!(c, IpNet::V6(_))).cloned();

        Ok(JoinResponse {
            credential: token,
            network_uuid: ns.registry.network_uuid.to_string(),
            coordinator_signing_keys: self.keyring.key_infos(),
            node_id,
            ip4,
            subnet4: if ip4.is_some() { subnet4 } else { None },
            ip6,
            subnet6: if ip6.is_some() { subnet6 } else { None },
            granted_cidrs: routes.iter().map(|r| r.cidr).collect(),
            relays,
            mtu: ns.cfg.settings.mtu,
            keepalive_secs: ns.cfg.settings.keepalive_secs,
            transport: ns.cfg.settings.transport.clone(),
            lanes: ns.cfg.settings.lanes,
        })
    }
}

/// Relays a joiner can attach to: only those that have joined at least
/// once (their cert_fp is pinned, so dialers can verify them).
pub fn relay_entries(ns: &NetState) -> Vec<RelayEntry> {
    let mut out = Vec::new();
    for (name, m) in &ns.cfg.relays {
        if let (Some(rec), Some(addr)) = (ns.registry.members.get(name), m.relay_addr.clone()) {
            if let Some(fp) = &rec.cert_fp {
                out.push(RelayEntry {
                    relay_id: rec.node_id,
                    name: name.clone(),
                    addr,
                    cert_fp: fp.clone(),
                });
            }
        }
    }
    out
}

/// Sanity check used by reload: a config change may not silently steal a
/// currently-registered prefix for a member that no longer may hold it.
pub fn config_matches_registry(cfg: &NetworkConfig, reg: &Registry) -> Vec<String> {
    let mut warnings = Vec::new();
    for (name, rec) in &reg.members {
        // A configured id only applies at creation, so a later change is
        // silently ineffective unless we say so.
        if let Some((m, _)) = AppState::member_cfg(cfg, name) {
            if let Some(want) = m.node_id {
                if want != rec.node_id {
                    warnings.push(format!(
                        "member {name} is configured with node_id {want} but was registered as \
                         {}; the id is fixed at first join and was not changed (remove the \
                         member from the registry to renumber it)",
                        rec.node_id
                    ));
                }
            }
        }
        let allowed: Vec<IpNet> = AppState::member_cfg(cfg, name)
            .map(|(m, _)| m.allowed_cidrs.clone())
            .unwrap_or_default();
        for r in &rec.routes {
            let ok = allowed.iter().any(|a| a.contains(&r.cidr.network()) && overlaps(a, &r.cidr));
            if !ok {
                warnings.push(format!(
                    "member {name} holds registration {} no longer allowed by config \
                     (kept until it re-joins; renewal will drop it)",
                    r.cidr
                ));
            }
        }
    }
    warnings
}
