//! Control-plane messages and the network view they carry (§3.2).
//!
//! The coordinator publishes one value per network: a [`Snapshot`], the
//! whole view at one **generation**. Members hold a copy and keep it
//! current by three rules and nothing else:
//!
//!  * a [`Delta`] applies iff its `base_gen` equals the copy's `gen`;
//!    otherwise the member sends [`Resync`] and waits for a snapshot;
//!  * a [`Heartbeat`] carries the copy's `gen` and a [`digest`] of its
//!    content, so the coordinator can see a member that is behind or —
//!    at the same generation — holds something different, which is a bug
//!    to log, not a state to reason about;
//!  * the heartbeat also carries the member's *local facts* (what is
//!    attached to it) as a whole set. There are no attach/detach events;
//!    a relay that no longer holds a client simply stops listing it.
//!
//! Diff, apply and digest live here so the coordinator and every member
//! run exactly the same code over exactly the same type.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::types::{NodeId, Role};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub credential: String,
    /// Generation of the snapshot the member already holds, or 0.
    #[serde(default)]
    pub have_gen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    /// The coordinator's current generation.
    pub gen: u64,
}

/// One member as pushed to every other member. Clients receive no
/// endpoint information — members never learn each other's IPs (§1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    /// Member name, for status/debugging only.
    pub name: String,
    #[serde(default = "d_role")]
    pub role: Role,
    /// Active owned prefixes: VPN /32s + /128s, and for gateway relays
    /// the local CIDRs they currently own (age-resolved, §2).
    pub prefixes: Vec<IpNet>,
    /// X25519 public key, base64.
    pub pubkey: String,
    pub online: bool,
    /// See `credential::Claims::login_gen`. A session presenting an
    /// older value belongs to a replaced instance and is closed.
    #[serde(default)]
    pub login_gen: u64,
}

fn d_role() -> Role {
    Role::Client
}

/// Coordinator -> relays: which member is reachable through which relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentEntry {
    pub node_id: NodeId,
    pub relay_id: NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    pub relay_id: NodeId,
    pub name: String,
    pub addr: String,
    /// What this relay presented at its last join — what dialers verify.
    pub cert_fp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMtu {
    pub mtu: u16,
    pub limited_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub kid: String,
    /// Ed25519 verifying key, base64.
    pub key: String,
    /// "active" | "retiring"
    pub state: String,
}

/// The whole network view at one generation. Canonically ordered so
/// two holders of the same content produce the same digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub gen: u64,
    pub members: Vec<PeerInfo>,
    pub attachments: Vec<AttachmentEntry>,
    pub relays: Vec<RelayEndpoint>,
    pub mtu: NetworkMtu,
    pub keys: Vec<KeyInfo>,
    /// Every prefix that belongs to this network whether or not someone
    /// currently owns it: the tunnel CIDRs and every registered gateway
    /// CIDR. Members route all of them into the tunnel, so traffic to a
    /// site that is down is dropped rather than leaked to the underlay.
    #[serde(default)]
    pub reserved_prefixes: Vec<IpNet>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot {
            gen: 0,
            members: Vec::new(),
            attachments: Vec::new(),
            relays: Vec::new(),
            mtu: NetworkMtu { mtu: 0, limited_by: String::new() },
            keys: Vec::new(),
            reserved_prefixes: Vec::new(),
        }
    }
}

/// What changed between two generations. `None` for a field means it is
/// unchanged; a `Some` replaces it wholesale (those fields are small).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delta {
    pub base_gen: u64,
    pub gen: u64,
    pub members_changed: Vec<PeerInfo>,
    pub members_removed: Vec<NodeId>,
    pub attachments_changed: Vec<AttachmentEntry>,
    pub attachments_removed: Vec<NodeId>,
    pub relays: Option<Vec<RelayEndpoint>>,
    pub mtu: Option<NetworkMtu>,
    pub keys: Option<Vec<KeyInfo>>,
    pub reserved_prefixes: Option<Vec<IpNet>>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("delta is based on generation {base} but I hold {have}")]
pub struct GenerationGap {
    pub base: u64,
    pub have: u64,
}

impl Snapshot {
    /// Put every list in canonical order. Diff, apply and digest all
    /// assume it; the coordinator normalises before publishing and apply
    /// keeps the invariant.
    ///
    /// Of two entries with the same key the *last* wins — the same rule
    /// `diff` and `apply` get from collecting into a map, so all three
    /// agree on what a list with duplicates means.
    pub fn normalize(&mut self) {
        keep_last_sorted(&mut self.members, |m| m.node_id);
        keep_last_sorted(&mut self.attachments, |a| a.node_id);
        keep_last_sorted(&mut self.relays, |r| r.relay_id);
        keep_last_sorted(&mut self.keys, |k| k.kid.clone());
        self.reserved_prefixes.sort_by_key(prefix_order);
        self.reserved_prefixes.dedup();
    }

    /// Content digest, independent of `gen`. Same content, same digest,
    /// on every build: FNV-1a over the canonical bincode encoding.
    pub fn digest(&self) -> u64 {
        let mut c = self.clone();
        c.gen = 0;
        c.normalize();
        // Unbounded: a size cap here would not make a large view smaller,
        // only make every large view hash alike. A value this type can
        // hold always encodes; a failure would be a bug worth a panic.
        let bytes = crate::envelope::encode_unbounded(&c).expect("a snapshot always encodes");
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        h
    }

    /// The delta that turns `self` into `newer`. Both must be normalised.
    pub fn diff(&self, newer: &Snapshot) -> Delta {
        let old_m: BTreeMap<NodeId, &PeerInfo> = self.members.iter().map(|m| (m.node_id, m)).collect();
        let new_m: BTreeMap<NodeId, &PeerInfo> = newer.members.iter().map(|m| (m.node_id, m)).collect();
        let members_changed = new_m
            .values()
            .filter(|m| old_m.get(&m.node_id) != Some(m))
            .map(|m| (*m).clone())
            .collect();
        let members_removed = old_m.keys().filter(|id| !new_m.contains_key(id)).copied().collect();

        let old_a: BTreeMap<NodeId, NodeId> = self.attachments.iter().map(|a| (a.node_id, a.relay_id)).collect();
        let new_a: BTreeMap<NodeId, NodeId> = newer.attachments.iter().map(|a| (a.node_id, a.relay_id)).collect();
        let attachments_changed = new_a
            .iter()
            .filter(|(n, r)| old_a.get(n) != Some(r))
            .map(|(n, r)| AttachmentEntry { node_id: *n, relay_id: *r })
            .collect();
        let attachments_removed = old_a.keys().filter(|n| !new_a.contains_key(n)).copied().collect();

        Delta {
            base_gen: self.gen,
            gen: newer.gen,
            members_changed,
            members_removed,
            attachments_changed,
            attachments_removed,
            relays: (self.relays != newer.relays).then(|| newer.relays.clone()),
            mtu: (self.mtu != newer.mtu).then(|| newer.mtu.clone()),
            keys: (self.keys != newer.keys).then(|| newer.keys.clone()),
            reserved_prefixes: (self.reserved_prefixes != newer.reserved_prefixes)
                .then(|| newer.reserved_prefixes.clone()),
        }
    }

    /// Apply a delta in place. A delta up to a generation already held is
    /// a harmless duplicate (a catch-up can race a push already queued);
    /// one not based on exactly the generation held is a gap — the
    /// caller then resyncs; it never guesses.
    pub fn apply(&mut self, d: &Delta) -> Result<(), GenerationGap> {
        if d.gen <= self.gen {
            return Ok(());
        }
        if d.base_gen != self.gen {
            return Err(GenerationGap { base: d.base_gen, have: self.gen });
        }
        let mut members: BTreeMap<NodeId, PeerInfo> =
            self.members.drain(..).map(|m| (m.node_id, m)).collect();
        for id in &d.members_removed {
            members.remove(id);
        }
        for m in &d.members_changed {
            members.insert(m.node_id, m.clone());
        }
        self.members = members.into_values().collect();

        let mut attachments: BTreeMap<NodeId, NodeId> =
            self.attachments.drain(..).map(|a| (a.node_id, a.relay_id)).collect();
        for id in &d.attachments_removed {
            attachments.remove(id);
        }
        for a in &d.attachments_changed {
            attachments.insert(a.node_id, a.relay_id);
        }
        self.attachments = attachments
            .into_iter()
            .map(|(node_id, relay_id)| AttachmentEntry { node_id, relay_id })
            .collect();

        if let Some(r) = &d.relays {
            self.relays = r.clone();
        }
        if let Some(m) = &d.mtu {
            self.mtu = m.clone();
        }
        if let Some(k) = &d.keys {
            self.keys = k.clone();
        }
        if let Some(p) = &d.reserved_prefixes {
            self.reserved_prefixes = p.clone();
        }
        self.gen = d.gen;
        self.normalize();
        Ok(())
    }

    pub fn member(&self, id: NodeId) -> Option<&PeerInfo> {
        self.members.binary_search_by_key(&id, |m| m.node_id).ok().map(|i| &self.members[i])
    }

    pub fn attachment_of(&self, id: NodeId) -> Option<NodeId> {
        self.attachments
            .binary_search_by_key(&id, |a| a.node_id)
            .ok()
            .map(|i| self.attachments[i].relay_id)
    }
}

/// Sort by key and drop duplicates, keeping the one that came last.
/// Reversing first makes the stable sort put the last occurrence of each
/// key ahead of the others, which `dedup_by_key` then keeps.
fn keep_last_sorted<T, K: Ord>(v: &mut Vec<T>, key: impl Fn(&T) -> K) {
    v.reverse();
    v.sort_by_key(|x| key(x));
    v.dedup_by(|a, b| key(a) == key(b));
}

/// Canonical prefix order: family, then address numerically, then
/// length. Not the string form, which puts 10.0.0.0/8 before 9.0.0.0/8.
fn prefix_order(p: &IpNet) -> (u8, u128, u8) {
    match p {
        IpNet::V4(n) => (4, u32::from(n.addr()) as u128, n.prefix_len()),
        IpNet::V6(n) => (6, u128::from(n.addr()), n.prefix_len()),
    }
}

/// A client a relay currently holds a live data session with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachedClient {
    pub node_id: NodeId,
    /// The relay's own session counter, so the coordinator can tell a
    /// newer declaration from an older one when two relays both claim
    /// a client during a move.
    pub session_id: u64,
}

/// Member -> coordinator, every `heartbeat_secs` and immediately when a
/// local fact changes. Always the whole truth; never an event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Generation of the snapshot this member holds.
    pub gen: u64,
    /// `Snapshot::digest()` of that copy.
    pub digest: u64,
    /// Relays: every client with a live session here.
    pub attached: Vec<AttachedClient>,
    /// Relays: every peer relay with a live mesh session.
    pub mesh_up: Vec<NodeId>,
    /// Clients: the relay this member is attached to, for status only —
    /// the relay's declaration is the authority.
    pub attached_to: Option<NodeId>,
    /// Largest inner packet this member's uplink can carry; 0 = unknown.
    pub usable_mtu: u16,
    /// Relays: cumulative data-plane counters for the traffic matrix.
    pub traffic: Option<TrafficReport>,
    // NOTE: the control payload is bincode (not self-describing), so a
    // trailing field is NOT wire-compatible even with #[serde(default)] —
    // an older peer that omits it makes the new decoder hit EOF. Exit
    // readiness is therefore NOT carried on the heartbeat; it is reported
    // out of band (a dedicated Kind) so it never breaks a mixed-version
    // fleet. Do not append fields to this struct; add a new Kind instead.
}

/// A designated internet-exit node's self-assessment of whether the host
/// is configured to forward and masquerade VPN traffic to the internet.
/// Checked on a slow timer and cached, then sent under its own
/// `Kind::ExitReadiness` whenever it changes — never on the heartbeat,
/// whose wire must not grow (see the note above).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitReadiness {
    /// `net.ipv4.ip_forward` (or the v6 equivalent) is enabled.
    pub ip_forward: bool,
    /// A MASQUERADE/SNAT rule covers tun-sourced traffic leaving the
    /// internet uplink.
    pub masquerade: bool,
}

impl ExitReadiness {
    /// Both prerequisites are in place.
    pub fn ok(&self) -> bool {
        self.ip_forward && self.masquerade
    }
}

/// Member -> coordinator: my generation cannot be caught up by deltas;
/// send me a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resync {
    pub have_gen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refresh {
    pub credential: String,
}

/// Cumulative data-plane bytes, per mesh peer and for traffic that never
/// crosses the mesh. Counters are cumulative since the relay process
/// started, so they drop to zero on restart rather than wrapping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficReport {
    pub links: Vec<LinkTraffic>,
    pub local_bytes: u64,
    pub local_pkts: u64,
    pub terminated_bytes: u64,
    pub terminated_pkts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkTraffic {
    pub peer_id: NodeId,
    pub tx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_pkts: u64,
    pub up: bool,
}

/// QUIC application close code the coordinator uses when it closes a
/// member's control connection because another instance joined as the
/// same member. The member must not re-join: it would only take the
/// identity back, and the two instances would replace each other
/// forever. It exits instead (see `nqvpn_sync::EXIT_REPLACED`).
pub const CLOSE_REPLACED: u32 = 7;
/// The member's configuration changed at the coordinator: re-join now
/// and apply what the new join response says. Not a kick-out.
pub const CLOSE_RECONFIGURED: u32 = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{decode_payload, encode_msg, Envelope, Kind};

    fn peer(id: NodeId, prefix: &str, online: bool) -> PeerInfo {
        PeerInfo {
            node_id: id,
            name: format!("n{id}"),
            role: Role::Client,
            prefixes: vec![prefix.parse().unwrap()],
            pubkey: format!("PK{id}"),
            online,
            login_gen: 1,
        }
    }

    fn snap(gen: u64) -> Snapshot {
        let mut s = Snapshot {
            gen,
            members: vec![peer(2, "10.0.0.2/32", true), peer(1, "10.0.0.1/32", true)],
            attachments: vec![AttachmentEntry { node_id: 2, relay_id: 9 }],
            relays: vec![RelayEndpoint { relay_id: 9, name: "r".into(), addr: "a:1".into(), cert_fp: "f".into() }],
            mtu: NetworkMtu { mtu: 1350, limited_by: "config".into() },
            keys: vec![KeyInfo { kid: "k1".into(), key: "K".into(), state: "active".into() }],
            reserved_prefixes: vec!["10.0.0.0/16".parse().unwrap()],
        };
        s.normalize();
        s
    }

    #[test]
    fn snapshot_round_trips_through_envelope() {
        let s = snap(7);
        let bytes = encode_msg(Kind::Snapshot, &s).unwrap();
        let (env, _) = Envelope::decode(&bytes).unwrap();
        let back: Snapshot = decode_payload(&env.payload).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn digest_ignores_generation_and_order_but_not_content() {
        let a = snap(1);
        let mut b = snap(99);
        b.members.reverse();
        assert_eq!(a.digest(), b.digest(), "same content, different gen/order");
        let mut c = snap(1);
        c.members[0].online = false;
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn diff_then_apply_reproduces_the_newer_snapshot() {
        let old = snap(1);
        let mut new = snap(2);
        new.members[0].online = false; // node 1 goes offline
        new.members.push(peer(3, "10.0.0.3/32", true));
        new.members.retain(|m| m.node_id != 2); // node 2 removed
        new.attachments = vec![AttachmentEntry { node_id: 3, relay_id: 9 }];
        new.mtu.mtu = 1300;
        new.normalize();

        let d = old.diff(&new);
        assert_eq!(d.base_gen, 1);
        assert_eq!(d.gen, 2);
        assert_eq!(d.members_removed, vec![2]);
        assert_eq!(d.attachments_removed, vec![2]);
        assert!(d.relays.is_none(), "unchanged fields stay None");
        assert!(d.mtu.is_some());

        let mut applied = old.clone();
        applied.apply(&d).unwrap();
        assert_eq!(applied, new);
        assert_eq!(applied.digest(), new.digest());
    }

    #[test]
    fn a_delta_from_the_wrong_base_is_refused_untouched() {
        let mut s = snap(5);
        let d = Delta { base_gen: 4, gen: 6, ..Default::default() };
        assert_eq!(s.apply(&d), Err(GenerationGap { base: 4, have: 5 }));
        assert_eq!(s.gen, 5, "nothing applied");
        assert_eq!(s, snap(5));
    }

    #[test]
    fn a_duplicate_or_older_delta_is_a_no_op() {
        let old = snap(1);
        let mut new = snap(2);
        new.members[0].online = false;
        new.normalize();
        let d = old.diff(&new);
        let mut s = old.clone();
        s.apply(&d).unwrap();
        s.apply(&d).unwrap();
        assert_eq!(s, new, "applying twice changes nothing");
        let stale = Delta { base_gen: 0, gen: 1, ..Default::default() };
        s.apply(&stale).unwrap();
        assert_eq!(s.gen, 2);
    }

    #[test]
    fn identical_snapshots_produce_an_empty_delta() {
        let a = snap(3);
        let mut b = snap(4);
        b.normalize();
        let d = a.diff(&b);
        assert!(d.members_changed.is_empty() && d.members_removed.is_empty());
        assert!(d.attachments_changed.is_empty() && d.attachments_removed.is_empty());
        assert!(d.relays.is_none() && d.mtu.is_none() && d.keys.is_none());
    }

    #[test]
    fn diff_then_apply_agrees_with_normalize_even_with_duplicates() {
        // Deterministic pseudo-random inputs (no RNG dependency in the
        // property): every list gets duplicate keys with differing
        // content, in arbitrary order, on both sides.
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let random_snap = |gen: u64, next: &mut dyn FnMut(u64) -> u64| {
            let mut s = Snapshot { gen, ..Default::default() };
            for _ in 0..next(12) {
                let id = next(6) as NodeId;
                s.members.push(peer(id, &format!("10.0.0.{}/32", next(250)), next(2) == 0));
            }
            for _ in 0..next(8) {
                s.attachments.push(AttachmentEntry { node_id: next(6) as NodeId, relay_id: next(3) as NodeId });
            }
            for _ in 0..next(4) {
                let id = next(3) as NodeId;
                s.relays.push(RelayEndpoint { relay_id: id, name: format!("r{}", next(9)), addr: "a:1".into(), cert_fp: "f".into() });
            }
            for _ in 0..next(4) {
                s.keys.push(KeyInfo { kid: format!("k{}", next(3)), key: format!("K{}", next(9)), state: "active".into() });
            }
            for _ in 0..next(5) {
                let p: IpNet = match next(3) {
                    0 => format!("{}.0.0.0/8", 1 + next(20)).parse().unwrap(),
                    1 => format!("10.{}.0.0/16", next(4)).parse().unwrap(),
                    _ => format!("fd00:{:x}::/48", next(4)).parse().unwrap(),
                };
                s.reserved_prefixes.push(p);
            }
            s
        };
        for round in 0..500 {
            let a_raw = random_snap(round * 2 + 1, &mut next);
            let b_raw = random_snap(round * 2 + 2, &mut next);
            let mut a = a_raw.clone();
            a.normalize();
            let mut b = b_raw.clone();
            b.normalize();
            // Diff over the raw (duplicate-laden) lists must mean the same
            // as diff over normalised ones.
            let mut applied = a.clone();
            applied.apply(&a_raw.diff(&b_raw)).unwrap();
            assert_eq!(applied, b, "round {round}: raw diff");
            let mut applied = a.clone();
            applied.apply(&a.diff(&b)).unwrap();
            assert_eq!(applied, b, "round {round}: normalised diff");
            assert_eq!(applied.digest(), b.digest());
            // Normalising is idempotent.
            let mut again = b.clone();
            again.normalize();
            assert_eq!(again, b);
        }
    }

    #[test]
    fn duplicates_keep_the_last_entry_and_prefixes_sort_numerically() {
        let mut s = Snapshot {
            members: vec![peer(1, "10.0.0.1/32", true), peer(1, "10.0.0.1/32", false)],
            ..Default::default()
        };
        s.keys = vec![
            KeyInfo { kid: "k1".into(), key: "old".into(), state: "active".into() },
            KeyInfo { kid: "k1".into(), key: "new".into(), state: "active".into() },
        ];
        s.reserved_prefixes = vec![
            "fd00::/48".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
            "9.0.0.0/8".parse().unwrap(),
            "10.0.0.0/8".parse().unwrap(),
        ];
        s.normalize();
        assert_eq!(s.members.len(), 1);
        assert!(!s.members[0].online, "the later duplicate wins, as in diff/apply");
        assert_eq!(s.keys.len(), 1);
        assert_eq!(s.keys[0].key, "new");
        let order: Vec<String> = s.reserved_prefixes.iter().map(|p| p.to_string()).collect();
        assert_eq!(order, vec!["9.0.0.0/8", "10.0.0.0/8", "fd00::/48"]);
    }

    #[test]
    fn a_view_past_one_mib_still_encodes_and_digests_by_content() {
        // ~12k members is well past the old 1 MiB cap. It must still go
        // on the wire, and two different large views must not collide on
        // the hash of an empty encoding.
        let mut a = Snapshot { gen: 1, ..Default::default() };
        for id in 0..12_000u32 {
            let mut p = peer(id, "10.0.0.1/32", true);
            p.pubkey = format!("{id:0>44}");
            p.name = format!("member-{id:06}-with-a-longer-name");
            a.members.push(p);
        }
        a.normalize();
        let bytes = encode_msg(Kind::Snapshot, &a).unwrap();
        assert!(bytes.len() > crate::envelope::MAX_PAYLOAD as usize, "test must exceed the small cap");
        let (env, _) = Envelope::decode(&bytes).unwrap();
        let back: Snapshot = decode_payload(&env.payload).unwrap();
        assert_eq!(back, a);
        let mut b = a.clone();
        b.members[5].online = false;
        assert_ne!(a.digest(), b.digest(), "large views hash by content");
        assert_ne!(a.digest(), 0xcbf2_9ce4_8422_2325, "never the hash of nothing");
    }

    #[test]
    fn lookups_use_the_canonical_order() {
        let s = snap(1);
        assert_eq!(s.member(2).unwrap().name, "n2");
        assert_eq!(s.attachment_of(2), Some(9));
        assert_eq!(s.attachment_of(1), None);
    }

    /// Wire-stability tripwire for the member->coordinator Heartbeat.
    ///
    /// The control payload is bincode, which is NOT self-describing: a
    /// struct is a bare concatenation of its fields with no names, tags or
    /// count. Appending a field (even `Option` + `#[serde(default)]`)
    /// therefore shifts the wire, and a peer that predates the field makes
    /// the new decoder run past the end of the buffer — a decode error
    /// that drops the control session. That is exactly how adding
    /// `exit_ready` to this struct knocked every not-yet-upgraded client
    /// into a reconnect loop in prod.
    ///
    /// So this size is load-bearing: if you changed it, you changed the
    /// heartbeat wire and will break a mixed-version fleet. Carry new
    /// facts in a NEW `Kind` (old peers skip an unknown kind) instead of a
    /// new field here, and only then update the constant.
    #[test]
    fn exit_readiness_wire_is_stable() {
        let er = ExitReadiness { ip_forward: true, masquerade: false };
        let bytes = crate::envelope::encode_payload(&er).unwrap();
        assert_eq!(bytes, vec![1, 0], "ExitReadiness wire changed: carry new facts in a new Kind, never a new field");
    }

    #[test]
    fn heartbeat_wire_is_stable_so_a_field_append_cannot_slip_through() {
        let hb = Heartbeat {
            gen: 42,
            digest: 7,
            attached: vec![AttachedClient { node_id: 3, session_id: 11 }],
            mesh_up: vec![9, 4],
            attached_to: Some(9),
            usable_mtu: 1350,
            traffic: Some(TrafficReport {
                links: vec![LinkTraffic { peer_id: 9, tx_bytes: 100, tx_pkts: 1, rx_bytes: 200, rx_pkts: 2, up: true }],
                local_bytes: 0,
                local_pkts: 0,
                terminated_bytes: 0,
                terminated_pkts: 0,
            }),
        };
        let bytes = crate::envelope::encode_payload(&hb).unwrap();
        assert_eq!(
            bytes.len(),
            25,
            "Heartbeat wire size changed — a field was added/removed. bincode is not \
             self-describing, so this breaks not-yet-upgraded peers. Use a new Kind, \
             not a new field (see the doc comment on this test)."
        );
        let back: Heartbeat = crate::envelope::decode_payload(&bytes).unwrap();
        assert_eq!(back.gen, hb.gen);
        assert_eq!(back.attached_to, Some(9));
    }
}
