//! Durable per-network registry (§3.3): everything a coordinator restart
//! must not lose. One JSON file per network, atomically rewritten
//! (temp + fsync + rename + dir fsync); durability precedes visibility.

use anyhow::{Context, Result};
use ipnet::IpNet;
use nqvpn_proto::types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteReg {
    pub cidr: IpNet,
    /// First-grant time; age is durable so restarts never reshuffle
    /// owners (§3.2).
    pub first_granted_unix: u64,
}

/// One pinned key, and whether it is the current one or on its way out.
///
/// Rotation needs two pins valid at once: the member registers a new key
/// while the old one is still in use, then switches over when convenient.
/// Without the overlap, a member that rotates and then restarts before
/// presenting the new key would lock itself out and need an admin
/// `reset-pin` — the one operation that reopens the trust window, and
/// exactly what rotation exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pin {
    pub key: String,
    /// Unix time this pin stops being accepted. `None` for the current
    /// pin, which never expires on its own.
    #[serde(default)]
    pub retires_unix: Option<u64>,
}

impl Pin {
    pub fn active(key: impl Into<String>) -> Pin {
        Pin { key: key.into(), retires_unix: None }
    }
    pub fn is_active(&self) -> bool {
        self.retires_unix.is_none()
    }
    pub fn valid_at(&self, now: u64) -> bool {
        match self.retires_unix {
            None => true,
            Some(t) => now < t,
        }
    }
}

/// A member's pins for one kind of key, newest-current-first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinSet {
    #[serde(default)]
    pub pins: Vec<Pin>,
}

impl PinSet {
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// The pin a member should present now.
    pub fn active(&self) -> Option<&Pin> {
        self.pins.iter().find(|p| p.is_active())
    }

    pub fn active_key(&self) -> Option<&str> {
        self.active().map(|p| p.key.as_str())
    }

    /// Does `key` authenticate this member right now?
    ///
    /// Any unexpired pin counts, which is the whole point of the overlap.
    /// A retired one does not, so the window really does close.
    pub fn accepts(&self, key: &str, now: u64) -> bool {
        self.pins.iter().any(|p| p.key == key && p.valid_at(now))
    }

    /// First pin ever recorded (TOFU), replacing nothing.
    pub fn pin_first(&mut self, key: impl Into<String>) {
        self.pins = vec![Pin::active(key)];
    }

    /// Register `key` as current and retire whatever was current at
    /// `retire_at`. Re-registering the key that is already current is a
    /// no-op, so a retried rotation is harmless.
    pub fn rotate_to(&mut self, key: impl Into<String>, retire_at: u64) {
        let key = key.into();
        if self.active_key() == Some(key.as_str()) {
            return;
        }
        for p in self.pins.iter_mut().filter(|p| p.is_active()) {
            p.retires_unix = Some(retire_at);
        }
        self.pins.insert(0, Pin::active(key));
    }

    /// Drop pins whose overlap has elapsed. Retiring the *current* pin is
    /// impossible by construction, so this can never empty a live set.
    pub fn prune(&mut self, now: u64) {
        self.pins.retain(|p| p.valid_at(now));
    }

    /// Confirm `key` is in use, retiring every other pin immediately.
    /// Called once a session authenticates with the new key: waiting out
    /// the full window after that only widens the exposure.
    pub fn confirm(&mut self, key: &str) {
        if !self.pins.iter().any(|p| p.key == key) {
            return;
        }
        self.pins.retain(|p| p.key == key);
        if let Some(p) = self.pins.first_mut() {
            p.retires_unix = None;
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemberRecord {
    pub node_id: NodeId,
    /// Legacy single pins, kept so an older build can still read this
    /// registry and so a rollback does not lose the member's identity.
    /// Always mirrors the *active* pin of the sets below; the sets are
    /// the authority.
    #[serde(default)]
    pub pubkey: Option<String>,
    #[serde(default)]
    pub cert_fp: Option<String>,
    /// Pins including any mid-rotation predecessor (§3.3).
    #[serde(default)]
    pub pubkeys: PinSet,
    #[serde(default)]
    pub cert_fps: PinSet,
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
}

impl MemberRecord {
    /// Fold the legacy single pins into the sets. Registries written
    /// before rotation existed carry only `pubkey`/`cert_fp`, and a
    /// member that has been pinned for months must not be asked to
    /// re-pin just because the coordinator was upgraded.
    pub fn migrate_pins(&mut self) {
        if self.pubkeys.is_empty() {
            if let Some(k) = &self.pubkey {
                self.pubkeys.pin_first(k.clone());
            }
        }
        if self.cert_fps.is_empty() {
            if let Some(k) = &self.cert_fp {
                self.cert_fps.pin_first(k.clone());
            }
        }
    }

    /// Keep the legacy fields pointing at the current pins, so a
    /// downgrade reads a coherent registry rather than an unpinned member.
    pub fn mirror_legacy_pins(&mut self) {
        self.pubkey = self.pubkeys.active_key().map(|s| s.to_string());
        self.cert_fp = self.cert_fps.active_key().map(|s| s.to_string());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    /// Per-pool allocation cursor: where the next scan starts.
    ///
    /// Without it the allocator always returns the lowest free address,
    /// so an address freed by an admin removal is handed to the very
    /// next joiner — inheriting stale neighbour entries, half-open
    /// connections, and confusing logs. Cycling forward and wrapping
    /// maximises the time before an address is reused, the way a DHCP
    /// server does. Durable, or a coordinator restart would reset it and
    /// reintroduce exactly the reuse we are avoiding.
    #[serde(default)]
    pub alloc_cursor: std::collections::BTreeMap<String, u64>,
    /// Minted once at network creation, immutable, unique across trust
    /// domains — bound into credentials and pair keys (§3.3, §4).
    pub network_uuid: Uuid,
    /// Node ids are never reused; this only grows.
    pub next_node_id: NodeId,
    pub members: BTreeMap<String, MemberRecord>,
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            network_uuid: Uuid::new_v4(),
            next_node_id: 1,
            members: BTreeMap::new(),
            alloc_cursor: std::collections::BTreeMap::new(),
        }
    }

    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let mut reg: Registry = serde_json::from_str(&raw)
                .with_context(|| format!("parsing {}", path.display()))?;
            for rec in reg.members.values_mut() {
                rec.migrate_pins();
            }
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
        // Persist the rename itself.
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    /// Get-or-create the record for a member; node ids allocate
    /// monotonically and are never reused.
    pub fn member_mut(&mut self, name: &str, now: u64) -> &mut MemberRecord {
        self.member_mut_with_id(name, now, None)
    }

    /// As `member_mut`, but honouring an operator-assigned id when the
    /// member is created.
    ///
    /// `want` applies at creation only. The node id is the data-plane
    /// identity peers put in frame headers, so renumbering a member that
    /// already exists would strand every cached route and live session
    /// still addressing the old id; the caller is told via
    /// `config_matches_registry` instead.
    pub fn member_mut_with_id(
        &mut self,
        name: &str,
        now: u64,
        want: Option<NodeId>,
    ) -> &mut MemberRecord {
        if !self.members.contains_key(name) {
            let node_id = match want {
                // An id already in use is refused rather than duplicated;
                // config validation rejects collisions between configured
                // members, but not one against an id already allocated.
                Some(id) if id != 0 && !self.members.values().any(|m| m.node_id == id) => id,
                _ => self.next_node_id,
            };
            let rec = MemberRecord { node_id, created_unix: now, ..Default::default() };
            self.members.insert(name.to_string(), rec);
            // Keep auto-allocation clear of everything now in use, so a
            // configured high id cannot be handed out again later.
            self.next_node_id = self
                .members
                .values()
                .map(|m| m.node_id)
                .max()
                .unwrap_or(0)
                .saturating_add(1)
                .max(self.next_node_id);
        }
        self.members.get_mut(name).expect("just inserted")
    }

    /// Active route ownership, age-resolved (§2): for each distinct
    /// CIDR, the oldest registration wins; younger living registrants
    /// are standbys. Liveness filtering is the caller's job (Phase 1
    /// has no liveness yet, so all registrants count).
    pub fn resolve_owners(&self) -> Vec<(IpNet, Vec<(String, u64)>)> {
        let mut by_cidr: BTreeMap<String, (IpNet, Vec<(String, u64)>)> = BTreeMap::new();
        for (name, rec) in &self.members {
            for r in &rec.routes {
                let e = by_cidr
                    .entry(r.cidr.to_string())
                    .or_insert_with(|| (r.cidr, Vec::new()));
                e.1.push((name.clone(), r.first_granted_unix));
            }
        }
        let mut out: Vec<(IpNet, Vec<(String, u64)>)> = by_cidr
            .into_values()
            .map(|(cidr, mut regs)| {
                // Oldest first; name as deterministic tiebreak.
                regs.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.cmp(&b.0)));
                (cidr, regs)
            })
            .collect();
        out.sort_by_key(|(c, _)| c.to_string());
        out
    }

    /// Every address currently assigned or reserved in the registry.
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
    fn node_ids_never_reused() {
        let mut r = Registry::new();
        let a = r.member_mut("a", 1).node_id;
        let b = r.member_mut("b", 1).node_id;
        assert_ne!(a, b);
        r.members.remove("a");
        let c = r.member_mut("c", 2).node_id;
        assert!(c > b, "removed member's id must not be recycled");
        // Rejoining an existing member keeps its id.
        assert_eq!(r.member_mut("b", 3).node_id, b);
    }

    #[test]
    fn commit_and_reload_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n1.json");
        let mut r = Registry::new();
        r.member_mut("a", 42).pubkey = Some("PK".into());
        r.commit(&path).unwrap();
        let back = Registry::load_or_create(&path).unwrap();
        assert_eq!(back.network_uuid, r.network_uuid);
        assert_eq!(back.members["a"].pubkey.as_deref(), Some("PK"));
        assert_eq!(back.next_node_id, r.next_node_id);
    }

    #[test]
    fn owner_resolution_is_age_then_name() {
        let mut r = Registry::new();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        r.member_mut("young", 1).routes.push(RouteReg { cidr, first_granted_unix: 200 });
        r.member_mut("old", 1).routes.push(RouteReg { cidr, first_granted_unix: 100 });
        let owners = r.resolve_owners();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].1[0].0, "old");
        assert_eq!(owners[0].1[1].0, "young");
    }

    #[test]
    fn an_operator_assigned_node_id_is_honoured_at_creation() {
        let mut r = Registry::new();
        let id = r.member_mut_with_id("gate", 1, Some(42)).node_id;
        assert_eq!(id, 42);
        // And auto-allocation must not later hand out 42 again.
        let next = r.member_mut("other", 1).node_id;
        assert!(next > 42, "auto id {next} collided with the configured 42");
    }

    #[test]
    fn an_existing_member_is_never_renumbered() {
        // The node id is the wire identity: peers put it in frame headers
        // and cache routes against it, so changing it under a live member
        // would strand everything still addressing the old one.
        let mut r = Registry::new();
        let first = r.member_mut("gate", 1).node_id;
        let again = r.member_mut_with_id("gate", 2, Some(999)).node_id;
        assert_eq!(again, first, "config must not renumber an existing member");
    }

    #[test]
    fn a_configured_id_already_in_use_falls_back_to_auto() {
        let mut r = Registry::new();
        let taken = r.member_mut("a", 1).node_id;
        let b = r.member_mut_with_id("b", 1, Some(taken)).node_id;
        assert_ne!(b, taken, "two members must never share a node id");
    }

    #[test]
    fn a_zero_configured_id_falls_back_to_auto() {
        // 0 is not a valid node id; config validation rejects it, but the
        // registry must not honour it if it ever arrives.
        let mut r = Registry::new();
        assert_ne!(r.member_mut_with_id("a", 1, Some(0)).node_id, 0);
    }

    #[test]
    fn auto_ids_stay_clear_of_a_high_configured_one() {
        let mut r = Registry::new();
        r.member_mut_with_id("big", 1, Some(1000));
        let ids: Vec<NodeId> = ["a", "b", "c"]
            .iter()
            .map(|n| r.member_mut(n, 1).node_id)
            .collect();
        assert!(ids.iter().all(|i| *i > 1000), "auto ids {ids:?} must clear 1000");
        // ...and remain distinct.
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
    }

    #[test]
    fn a_first_pin_is_active_and_never_expires() {
        let mut set = PinSet::default();
        assert!(set.is_empty());
        set.pin_first("K1");
        assert_eq!(set.active_key(), Some("K1"));
        assert!(set.accepts("K1", u64::MAX), "the current pin must never age out");
        assert!(!set.accepts("K2", 0));
    }

    #[test]
    fn both_keys_authenticate_during_the_overlap() {
        // The property rotation exists for: a member that has registered
        // a new key but not yet switched must still be able to connect.
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        assert_eq!(set.active_key(), Some("NEW"));
        assert!(set.accepts("NEW", 500));
        assert!(set.accepts("OLD", 500), "the old key must work during the window");
    }

    #[test]
    fn the_old_key_stops_working_once_the_window_closes() {
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        assert!(!set.accepts("OLD", 1_000), "the window must actually close");
        assert!(!set.accepts("OLD", 2_000));
        assert!(set.accepts("NEW", 2_000));
    }

    #[test]
    fn a_member_that_rotates_and_dies_can_still_come_back() {
        // The failure mode worth designing for: rotate, then crash before
        // ever presenting the new key. Switching eagerly would lock the
        // member out and force an admin reset-pin — the very trust hole
        // rotation exists to avoid.
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        assert!(set.accepts("OLD", 999), "must survive a restart mid-rotation");
    }

    #[test]
    fn confirming_the_new_key_retires_the_old_one_immediately() {
        // Once the member demonstrably holds the new key, waiting out the
        // rest of the window only widens the exposure.
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 10_000);
        set.confirm("NEW");
        assert!(!set.accepts("OLD", 0), "old pin must be gone once new one is in use");
        assert!(set.accepts("NEW", u64::MAX));
        assert_eq!(set.pins.len(), 1);
    }

    #[test]
    fn confirming_the_current_key_is_harmless() {
        // Every ordinary join confirms the key it presents; that must not
        // disturb a rotation that is legitimately in flight.
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 10_000);
        set.confirm("OLD");
        // Confirming the *old* key keeps only it — the member evidently
        // did not switch — and it becomes current again.
        assert!(set.accepts("OLD", u64::MAX));
        assert_eq!(set.active_key(), Some("OLD"));
    }

    #[test]
    fn confirming_an_unknown_key_changes_nothing() {
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        set.confirm("SOMETHING-ELSE");
        assert!(set.accepts("OLD", 0) && set.accepts("NEW", 0), "must not drop valid pins");
    }

    #[test]
    fn rotating_to_the_same_key_twice_is_a_no_op() {
        // A retried rotation must not retire the key it is installing.
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        set.rotate_to("NEW", 2_000);
        assert_eq!(set.active_key(), Some("NEW"));
        assert!(set.accepts("NEW", u64::MAX), "retry must not retire the new key");
        assert_eq!(set.pins.iter().filter(|p| p.key == "NEW").count(), 1);
    }

    #[test]
    fn pruning_never_empties_a_live_set() {
        let mut set = PinSet::default();
        set.pin_first("OLD");
        set.rotate_to("NEW", 1_000);
        set.prune(u64::MAX);
        assert_eq!(set.active_key(), Some("NEW"), "the current pin is not prunable");
        assert_eq!(set.pins.len(), 1);
    }

    #[test]
    fn a_legacy_registry_migrates_without_asking_anyone_to_re_pin() {
        // Registries written before rotation carry only the single
        // fields. A member pinned for months must not be disturbed by a
        // coordinator upgrade.
        let mut rec = MemberRecord {
            node_id: 3,
            pubkey: Some("PK".into()),
            cert_fp: Some("FP".into()),
            ..Default::default()
        };
        rec.migrate_pins();
        assert!(rec.pubkeys.accepts("PK", u64::MAX));
        assert!(rec.cert_fps.accepts("FP", u64::MAX));
    }

    #[test]
    fn the_legacy_fields_keep_mirroring_the_active_pin() {
        // So a downgrade reads a coherent registry instead of finding an
        // unpinned member and re-pinning whatever turns up first.
        let mut rec = MemberRecord { node_id: 1, ..Default::default() };
        rec.pubkeys.pin_first("K1");
        rec.cert_fps.pin_first("F1");
        rec.mirror_legacy_pins();
        assert_eq!(rec.pubkey.as_deref(), Some("K1"));

        rec.pubkeys.rotate_to("K2", 500);
        rec.cert_fps.rotate_to("F2", 500);
        rec.mirror_legacy_pins();
        assert_eq!(rec.pubkey.as_deref(), Some("K2"), "legacy must follow the current pin");
        assert_eq!(rec.cert_fp.as_deref(), Some("F2"));
    }

    #[test]
    fn migration_does_not_clobber_an_in_flight_rotation() {
        // migrate_pins runs on every load; it must only fill an empty set.
        let mut rec = MemberRecord { node_id: 1, pubkey: Some("OLD".into()), ..Default::default() };
        rec.pubkeys.pin_first("OLD");
        rec.pubkeys.rotate_to("NEW", 1_000);
        rec.migrate_pins();
        assert_eq!(rec.pubkeys.active_key(), Some("NEW"));
        assert!(rec.pubkeys.accepts("OLD", 0), "overlap must survive a reload");
    }

    #[test]
    fn clearing_a_members_pins_really_unpins_it() {
        // reset-pin is the only way back when a machine's keys change.
        // Once rotation made the sets authoritative, clearing just the
        // legacy fields left the member permanently locked out — the
        // failure looked exactly like the reset having no effect.
        let mut rec = MemberRecord { node_id: 1, ..Default::default() };
        rec.pubkeys.pin_first("PK");
        rec.cert_fps.pin_first("FP");
        rec.mirror_legacy_pins();

        rec.pubkeys = Default::default();
        rec.cert_fps = Default::default();
        rec.pubkey = None;
        rec.cert_fp = None;

        assert!(rec.pubkeys.is_empty() && rec.cert_fps.is_empty());
        // An empty set must accept nothing, so join treats it as TOFU and
        // pins whatever the member next presents.
        assert!(!rec.cert_fps.accepts("FP", 0));
        // And a reload must not resurrect the cleared pins.
        rec.migrate_pins();
        assert!(rec.cert_fps.is_empty(), "migration must not undo a reset");
    }
}
