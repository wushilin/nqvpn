//! Operator mutations: networks and members are created, changed and
//! removed here, from the UI or the API. Every change is validated as a
//! whole network first (an invalid change leaves the running one
//! untouched), committed to the database, and then applied — including
//! telling affected members to re-join so they pick it up.

use ipnet::IpNet;
use nqvpn_proto::token::Token;
use nqvpn_proto::types::{NodeId, Role};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::config::{validate_network, MemberCfg, NetworkConfig, PoolCfg, SettingsCfg};
use crate::error::ApiError;
use crate::registry::Registry;
use crate::secrets::generate_secret;
use crate::state::{now_unix, AppState, NetState};

/// A network as the operator creates or edits it: no members.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSpec {
    pub network_id: String,
    pub cidrs: Vec<IpNet>,
    #[serde(default)]
    pub pools: BTreeMap<String, PoolCfg>,
    #[serde(default)]
    pub settings: SettingsCfg,
}

/// A member as the operator creates or edits it. The secret is never
/// part of it: it is generated, and rotated on request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberSpec {
    #[serde(default)]
    pub relay_addr: Option<String>,
    #[serde(default)]
    pub local_cidrs: Vec<IpNet>,
    #[serde(default)]
    pub preferred_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<Ipv6Addr>,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub want_vpn_ip: Option<bool>,
    #[serde(default)]
    pub max_session_mbps: Option<u32>,
    #[serde(default)]
    pub preferred_relay: Option<String>,
}

impl MemberSpec {
    fn apply(&self, m: &mut MemberCfg) {
        m.relay_addr = self.relay_addr.clone();
        m.local_cidrs = self.local_cidrs.clone();
        m.preferred_ip4 = self.preferred_ip4;
        m.preferred_ip6 = self.preferred_ip6;
        m.pool = self.pool.clone();
        m.want_vpn_ip = self.want_vpn_ip;
        m.max_session_mbps = self.max_session_mbps;
        m.preferred_relay = self.preferred_relay.clone();
    }

    pub fn from_cfg(m: &MemberCfg) -> MemberSpec {
        MemberSpec {
            relay_addr: m.relay_addr.clone(),
            local_cidrs: m.local_cidrs.clone(),
            preferred_ip4: m.preferred_ip4,
            preferred_ip6: m.preferred_ip6,
            pool: m.pool.clone(),
            want_vpn_ip: m.want_vpn_ip,
            max_session_mbps: m.max_session_mbps,
            preferred_relay: m.preferred_relay.clone(),
        }
    }
}

fn invalid(e: anyhow::Error) -> ApiError {
    ApiError::bad_request(format!("{e:#}"))
}

fn valid_name(name: &str) -> Result<(), ApiError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
    if ok {
        Ok(())
    } else {
        Err(ApiError::bad_request("names are 1-64 characters of [A-Za-z0-9._-]"))
    }
}

/// Which members' facts changed between two configurations of the same
/// network: those get told to re-join.
fn changed_members(old: &NetworkConfig, new: &NetworkConfig) -> Vec<String> {
    let mut out = Vec::new();
    for (name, m, _) in new.members() {
        match old.member_by_name(name) {
            Some((o, _)) if o.facts_equal(m) => {}
            _ => out.push(name.clone()),
        }
    }
    out
}

impl AppState {
    pub fn create_network(&self, spec: NetworkSpec) -> Result<(), ApiError> {
        valid_name(&spec.network_id)?;
        if self.net(&spec.network_id).is_some() {
            return Err(ApiError::bad_request(format!("network {:?} already exists", spec.network_id)));
        }
        let cfg = NetworkConfig {
            network_id: spec.network_id.clone(),
            cidrs: spec.cidrs,
            pools: spec.pools,
            settings: spec.settings,
            relays: BTreeMap::new(),
            clients: BTreeMap::new(),
        };
        validate_network(&cfg).map_err(invalid)?;
        let registry = Registry::new();
        self.db
            .save_network_and_registry(&cfg, &registry)
            .map_err(|e| ApiError::internal(format!("saving network: {e:#}")))?;
        let ns = self.add_network(cfg, registry);
        // Not a restart: nothing to collect before publishing.
        ns.lock().unwrap().started_at = 0;
        tracing::info!(network = %spec.network_id, "network created");
        Ok(())
    }

    /// Replace a network's address space, pools and settings; members
    /// are untouched. Settings every member holds (MTU, transport,
    /// lanes, heartbeat) make everyone re-join.
    pub fn update_network(&self, id: &str, spec: NetworkSpec) -> Result<(), ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        let mut cfg = ns.cfg.clone();
        cfg.cidrs = spec.cidrs;
        cfg.pools = spec.pools;
        cfg.settings = spec.settings;
        validate_network(&cfg).map_err(invalid)?;
        let s_old = &ns.cfg.settings;
        let s_new = &cfg.settings;
        let everyone = s_old.mtu != s_new.mtu
            || s_old.transport != s_new.transport
            || s_old.lanes != s_new.lanes
            || s_old.heartbeat_secs != s_new.heartbeat_secs
            || s_old.credential_ttl_mins != s_new.credential_ttl_mins
            || s_old.max_session_mbps != s_new.max_session_mbps;
        ns.cfg = cfg;
        ns.save_config()?;
        ns.directory.hold_down_secs = ns.cfg.settings.hold_down_secs;
        let reconnected = if everyone {
            let nodes: Vec<NodeId> = ns.sessions.keys().copied().collect();
            let n = nodes.len();
            for node in nodes {
                ns.reconfigure(node, "network settings changed");
            }
            n
        } else {
            0
        };
        self.publish(&mut ns);
        tracing::info!(network = %id, reconnected, "network settings updated");
        Ok(())
    }

    pub fn delete_network(&self, id: &str) -> Result<(), ApiError> {
        let net = self.remove_network(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        {
            let mut ns = net.lock().unwrap();
            let nodes: Vec<NodeId> = ns.sessions.keys().copied().collect();
            for n in nodes {
                ns.close_session(n, "network deleted");
            }
        }
        self.db.delete_network(id).map_err(|e| ApiError::internal(format!("deleting network: {e:#}")))?;
        tracing::info!(network = %id, "network deleted");
        Ok(())
    }

    /// Declare a member. Returns its secret; the caller wraps it in a
    /// token with the coordinator's endpoint.
    pub fn create_member(&self, id: &str, name: &str, role: Role, spec: &MemberSpec) -> Result<String, ApiError> {
        valid_name(name)?;
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        if ns.cfg.member_by_name(name).is_some() {
            return Err(ApiError::bad_request(format!("member {name:?} already exists")));
        }
        let mut m = MemberCfg::default();
        spec.apply(&mut m);
        let secret = generate_secret();
        m.secret = Some(secret.clone());
        let mut cfg = ns.cfg.clone();
        cfg.insert_member(name, role, m);
        validate_network(&cfg).map_err(invalid)?;
        ns.cfg = cfg;
        ns.save_config()?;
        ns.notify();
        tracing::info!(network = %id, member = %name, %role, "member created");
        Ok(secret)
    }

    /// Change a member's facts. If it is connected it is told to
    /// re-join, and comes back with the new ones.
    pub fn update_member(&self, id: &str, name: &str, spec: &MemberSpec) -> Result<(), ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        let mut cfg = ns.cfg.clone();
        let (m, _) = cfg.member_by_name_mut(name).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
        spec.apply(m);
        validate_network(&cfg).map_err(invalid)?;
        let changed = changed_members(&ns.cfg, &cfg);
        ns.cfg = cfg;
        ns.save_config()?;
        let mut reconnected = false;
        for n in &changed {
            if let Some(node) = ns.registry.id_of(n) {
                ns.reconfigure(node, "configuration changed");
                reconnected = true;
            }
        }
        self.publish(&mut ns);
        ns.notify();
        tracing::info!(network = %id, member = %name, changed = ?changed, reconnected, "member configuration updated");
        Ok(())
    }

    /// A new secret; the old one stops working now. Whoever holds the
    /// old one is thrown off everywhere: its next join is refused, and
    /// every acceptor closes its sessions.
    pub fn rotate_member(&self, id: &str, name: &str) -> Result<String, ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        let secret = generate_secret();
        {
            let (m, _) = ns.cfg.member_by_name_mut(name).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
            m.secret = Some(secret.clone());
        }
        ns.save_config()?;
        if let Some(node) = ns.registry.id_of(name) {
            if let Some(rec) = ns.registry.members.get_mut(&node) {
                rec.login_gen += 1;
                rec.replaced_unix = Some(now_unix());
                rec.replaced_from = Some("secret rotated".into());
            }
            ns.commit()?;
            ns.close_session(node, "secret rotated");
            self.publish(&mut ns);
        }
        tracing::info!(network = %id, member = %name, "secret rotated");
        Ok(secret)
    }

    /// Forget a member: configuration, registry record, address, routes.
    pub fn delete_member(&self, id: &str, name: &str) -> Result<(), ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        let in_cfg = ns.cfg.remove_member(name);
        let node = ns.registry.id_of(name);
        if !in_cfg && node.is_none() {
            return Err(ApiError::not_found(format!("member {name:?}")));
        }
        ns.save_config()?;
        if let Some(node) = node {
            ns.registry.members.remove(&node);
            ns.commit()?;
            ns.close_session(node, "member deleted");
            ns.leases.remove_relay(node);
            ns.directory.traffic.remove(&node);
            ns.directory.reported_mtu.remove(&node);
        }
        self.publish(&mut ns);
        tracing::info!(network = %id, member = %name, "member deleted");
        Ok(())
    }

    pub fn set_disabled(&self, id: &str, name: &str, disabled: bool) -> Result<(), ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let mut ns = net.lock().unwrap();
        let node = ns.registry.id_of(name).ok_or_else(|| ApiError::not_found(format!("member {name:?} has never joined")))?;
        let rec = ns.registry.members.get_mut(&node).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
        rec.disabled = disabled;
        let role = rec.role;
        ns.commit()?;
        if disabled {
            ns.close_session(node, "member disabled");
            if role == Role::Relay {
                ns.leases.remove_relay(node);
            } else {
                ns.leases.remove(node);
            }
        }
        self.publish(&mut ns);
        tracing::info!(network = %id, member = %name, %role, disabled, "member {}", if disabled { "disabled" } else { "enabled" });
        Ok(())
    }

    /// The member's token, for the UI to show and the operator to copy.
    pub fn member_token(&self, id: &str, name: &str, endpoint: &str) -> Result<(Token, Role), ApiError> {
        let net = self.net(id).ok_or_else(|| ApiError::not_found(format!("network {id:?}")))?;
        let ns = net.lock().unwrap();
        let (m, role) = ns.cfg.member_by_name(name).ok_or_else(|| ApiError::not_found(format!("member {name:?}")))?;
        let secret = m.secret.clone().ok_or_else(|| ApiError::not_found(format!("member {name:?} has no secret; rotate to mint one")))?;
        Ok((Token { coordinator: endpoint.to_string(), secret }, role))
    }

    /// All configuration, for backup or for keeping in version control.
    pub fn export(&self) -> Vec<NetworkConfig> {
        self.nets().into_iter().map(|(_, n)| n.lock().unwrap().cfg.clone()).collect()
    }

    /// Restore configuration: networks that exist are replaced whole
    /// (members included), others are created. Registries are kept.
    pub fn import(&self, cfgs: Vec<NetworkConfig>) -> Result<Vec<String>, ApiError> {
        for cfg in &cfgs {
            validate_network(cfg).map_err(invalid)?;
        }
        let mut applied = Vec::new();
        for cfg in cfgs {
            let id = cfg.network_id.clone();
            match self.net(&id) {
                Some(net) => {
                    let mut ns = net.lock().unwrap();
                    let changed = changed_members(&ns.cfg, &cfg);
                    ns.cfg = cfg;
                    ns.save_config()?;
                    ns.directory.hold_down_secs = ns.cfg.settings.hold_down_secs;
                    for n in changed {
                        if let Some(node) = ns.registry.id_of(&n) {
                            ns.reconfigure(node, "configuration imported");
                        }
                    }
                    self.publish(&mut ns);
                }
                None => {
                    let registry = self
                        .db
                        .load_registry(&id)
                        .map_err(|e| ApiError::internal(format!("{e:#}")))?
                        .unwrap_or_else(Registry::new);
                    self.db
                        .save_network_and_registry(&cfg, &registry)
                        .map_err(|e| ApiError::internal(format!("saving network: {e:#}")))?;
                    let ns = self.add_network(cfg, registry);
                    ns.lock().unwrap().started_at = 0;
                }
            }
            applied.push(id);
        }
        tracing::info!(networks = ?applied, "configuration imported");
        Ok(applied)
    }
}

/// Members whose facts differ, for the "who must re-join" decision.
impl MemberCfg {
    pub fn facts_equal(&self, other: &MemberCfg) -> bool {
        self.relay_addr == other.relay_addr
            && self.local_cidrs == other.local_cidrs
            && self.preferred_ip4 == other.preferred_ip4
            && self.preferred_ip6 == other.preferred_ip6
            && self.pool == other.pool
            && self.want_vpn_ip == other.want_vpn_ip
            && self.max_session_mbps == other.max_session_mbps
            && self.preferred_relay == other.preferred_relay
    }
}

#[allow(dead_code)]
fn _ns_type_check(_: &NetState) {}
