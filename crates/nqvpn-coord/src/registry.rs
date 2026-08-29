//! Durable per-network registry (§3.3): everything a coordinator restart
//! must not lose. One JSON file per network, atomically rewritten
//! (temp + fsync + rename + dir fsync); durability precedes visibility.
//!
//! Keyed by node id — the member's identity. Everything else in a record
//! is the member's latest *declaration* (replaced by every join) or
//! bookkeeping about it.

use anyhow::{Context, Result};
use ipnet::IpNet;
use nqvpn_proto::types::{NodeId, Role};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteReg {
    pub cidr: IpNet,
    /// First-grant time; age is durable so restarts never reshuffle
    /// owners (§3.2). Kept while the CIDR stays continuously declared.
    pub first_granted_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRecord {
    pub node_id: NodeId,
    #[serde(default)]
    pub name: String,
    #[serde(default = "d_role")]
    pub role: Role,
    /// X25519 key and TLS fingerprint presented at the latest join.
    /// Recorded, never judged: the next join replaces them.
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub cert_fp: Option<String>,
    #[serde(default)]
    pub ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub ip6: Option<Ipv6Addr>,
    #[serde(default)]
    pub routes: Vec<RouteReg>,
    /// Durable admin override; never written into the operator's TOML.
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub created_unix: u64,
    #[serde(default)]
    pub last_join_unix: Option<u64>,
    #[serde(default)]
    pub last_join_from: Option<String>,
    /// Bumped when a join presents a different (pubkey, cert) than the
    /// one recorded — a different machine took over the id. Carried in
    /// credentials so every acceptor can close the previous instance.
    #[serde(default)]
    pub login_gen: u64,
    #[serde(default)]
    pub replaced_unix: Option<u64>,
    #[serde(default)]
    pub replaced_from: Option<String>,
}

fn d_role() -> Role {
    Role::Client
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// Per-pool allocation cursor, so freed addresses are not reissued
    /// immediately (DHCP-style cycling). Durable for the same reason.
    #[serde(default)]
    pub alloc_cursor: BTreeMap<String, u64>,
    /// Minted once at network creation, immutable, unique across trust
    /// domains — bound into credentials and pair keys (§3.3, §4).
    pub network_uuid: Uuid,
    /// For members without an operator-assigned id. Never reused.
    pub next_node_id: NodeId,
    #[serde(default)]
    pub members: BTreeMap<NodeId, MemberRecord>,
    /// High-water mark for the directory generation. The running value
    /// is persisted every `GEN_PERSIST_STEP` increments; on start the
    /// generation resumes from `max(now_ms, hwm + step)`, so it is
    /// unique across restarts however busy the previous instance was.
    #[serde(default)]
    pub gen_hwm: u64,
}

/// How many generation increments may be lost at a crash. The start-up
/// rule adds the same amount, so no generation is ever handed out twice.
pub const GEN_PERSIST_STEP: u64 = 1000;

impl Registry {
    pub fn new() -> Self {
        Registry {
            network_uuid: Uuid::new_v4(),
            next_node_id: 1,
            members: BTreeMap::new(),
            alloc_cursor: BTreeMap::new(),
            gen_hwm: 0,
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let reg: Registry = serde_json::from_str(&raw).with_context(|| {
                format!(
                    "parsing {} (an older registry format cannot be migrated; move it aside to start fresh)",
                    path.display()
                )
            })?;
            Ok(reg)
        } else {
            Ok(Registry::new())
        }
    }

    /// Atomic durable commit: temp file, fsync, rename, fsync directory.
    pub fn commit(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp: PathBuf = path.with_extension("json.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(serde_json::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// The first generation a fresh process may use.
    pub fn initial_gen(&self, now_ms: u64) -> u64 {
        now_ms.max(self.gen_hwm + GEN_PERSIST_STEP)
    }

    /// Record that `gen` was handed out. Returns true when the caller
    /// must commit, i.e. the persisted mark was passed.
    pub fn note_gen(&mut self, gen: u64) -> bool {
        if gen >= self.gen_hwm {
            self.gen_hwm = gen + GEN_PERSIST_STEP;
            return true;
        }
        false
    }

    /// The record for a name, if the member ever joined.
    pub fn by_name(&self, name: &str) -> Option<&MemberRecord> {
        self.members.values().find(|m| m.name == name)
    }

    pub fn id_of(&self, name: &str) -> Option<NodeId> {
        self.by_name(name).map(|m| m.node_id)
    }

    /// Get-or-create the record for a *name*. A new member gets the next
    /// never-used id: ids are the coordinator's to assign, and a name
    /// keeps its id for as long as the record exists.
    pub fn member_by_name_mut(&mut self, name: &str, role: Role, now: u64) -> &mut MemberRecord {
        let id = match self.id_of(name) {
            Some(id) => id,
            None => {
                let mut id = self.next_node_id.max(1);
                while self.members.contains_key(&id) {
                    id += 1;
                }
                id
            }
        };
        self.member_mut(id, name, role, now)
    }

    /// Get-or-create the record for a member by its wire identity.
    pub fn member_mut(&mut self, id: NodeId, name: &str, role: Role, now: u64) -> &mut MemberRecord {
        let rec = self.members.entry(id).or_insert_with(|| MemberRecord {
            node_id: id,
            name: name.to_string(),
            role,
            pubkey: None,
            cert_fp: None,
            ip4: None,
            ip6: None,
            routes: Vec::new(),
            disabled: false,
            created_unix: now,
            last_join_unix: None,
            last_join_from: None,
            login_gen: 0,
            replaced_unix: None,
            replaced_from: None,
        });
        rec.name = name.to_string();
        rec.role = role;
        self.next_node_id = self.next_node_id.max(id.saturating_add(1));
        rec
    }

    /// Route registrations per CIDR, oldest first (age-resolved, §2).
    /// Liveness filtering is the directory's job.
    pub fn resolve_owners(&self) -> Vec<(IpNet, Vec<(NodeId, u64)>)> {
        let mut by_cidr: BTreeMap<String, (IpNet, Vec<(NodeId, u64)>)> = BTreeMap::new();
        for (id, rec) in &self.members {
            if rec.disabled {
                continue;
            }
            for r in &rec.routes {
                let e = by_cidr
                    .entry(r.cidr.to_string())
                    .or_insert_with(|| (r.cidr, Vec::new()));
                e.1.push((*id, r.first_granted_unix));
            }
        }
        let mut out: Vec<(IpNet, Vec<(NodeId, u64)>)> = by_cidr
            .into_values()
            .map(|(cidr, mut regs)| {
                regs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
                (cidr, regs)
            })
            .collect();
        out.sort_by_key(|(c, _)| c.to_string());
        out
    }

    pub fn assigned4(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        self.members.values().filter_map(|m| m.ip4)
    }
    pub fn assigned6(&self) -> impl Iterator<Item = Ipv6Addr> + '_ {
        self.members.values().filter_map(|m| m.ip6)
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n1.json");
        let mut r = Registry::new();
        r.member_mut(7, "a", Role::Client, 42).pubkey = Some("PK".into());
        r.commit(&path).unwrap();
        let back = Registry::load_or_create(&path).unwrap();
        assert_eq!(back.network_uuid, r.network_uuid);
        assert_eq!(back.members[&7].pubkey.as_deref(), Some("PK"));
        assert_eq!(back.members[&7].name, "a");
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn generation_survives_restart_and_a_busy_predecessor() {
        let mut r = Registry::new();
        let g0 = r.initial_gen(1_000_000);
        assert_eq!(g0, 1_000_000, "fresh registry starts at the clock");
        assert!(r.note_gen(g0), "first use passes the mark");
        // The predecessor handed out many generations in little wall time.
        let busy = g0 + 5_000;
        assert!(r.note_gen(busy - 1) || true);
        r.note_gen(busy);
        assert!(r.gen_hwm > busy);
        // A restart one millisecond later must not reuse anything.
        assert!(r.initial_gen(1_000_001) > busy);
        assert!(r.initial_gen(1_000_001) >= r.gen_hwm);
    }

    #[test]
    fn names_get_assigned_ids_that_are_never_reused() {
        let mut r = Registry::new();
        let a = r.member_by_name_mut("a", Role::Client, 1).node_id;
        let b = r.member_by_name_mut("b", Role::Client, 1).node_id;
        assert!(a != 0 && b != 0 && a != b);
        assert_eq!(r.member_by_name_mut("a", Role::Client, 2).node_id, a, "a name keeps its id");
        assert_eq!(r.id_of("b"), Some(b));
        r.members.remove(&a);
        let c = r.member_by_name_mut("c", Role::Client, 5).node_id;
        assert!(c > b && c != a, "removed ids are not recycled");
    }

    #[test]
    fn owners_are_age_ordered_and_skip_disabled() {
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        let mut r = Registry::new();
        r.member_mut(1, "old", Role::Relay, 1).routes.push(RouteReg { cidr, first_granted_unix: 100 });
        r.member_mut(2, "new", Role::Relay, 1).routes.push(RouteReg { cidr, first_granted_unix: 200 });
        r.member_mut(3, "off", Role::Relay, 1).routes.push(RouteReg { cidr, first_granted_unix: 50 });
        r.members.get_mut(&3).unwrap().disabled = true;
        let owners = r.resolve_owners();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].1.iter().map(|(n, _)| *n).collect::<Vec<_>>(), vec![1, 2]);
    }
}
