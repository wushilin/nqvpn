//! The per-network directory: the derived, revisioned view that gets
//! pushed to members (§3.2). Registry + liveness in, `PeerInfo` out.
//!
//! Two rules from the design live here:
//!  * **routes are liveness-bound, identity is not** (§2/§7) — an offline
//!    member keeps its addresses but its route registrations are
//!    withdrawn, so the next-oldest living registrant takes over;
//!  * **flap damping** (§2) — a returning registrant waits `hold_down`
//!    before reclaiming ownership from a live standby.

use ipnet::IpNet;
use nqvpn_proto::control::{AttachmentEntry, MembershipDelta, PeerInfo};
use nqvpn_proto::types::{NodeId, Revision};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::config::NetworkConfig;
use crate::registry::Registry;

#[derive(Debug, Default)]
pub struct Directory {
    pub revision: Revision,
    /// Last published view, by node id.
    pub peers: BTreeMap<NodeId, PeerInfo>,
    /// Member names with a live control connection.
    pub online: BTreeSet<String>,
    /// When each member last came online (for hold-down).
    pub online_since: HashMap<String, u64>,
    /// cidr string -> owning member name (sticky until death/hold-down).
    pub owners: BTreeMap<String, String>,
    /// member node id -> relay node id (relays only consumer).
    pub attachments: BTreeMap<NodeId, NodeId>,
    pub attach_revision: Revision,
    /// Flap damping window (§2, decision #13); 0 disables.
    pub hold_down_secs: u64,
    /// Last reachability verdict per relay name (§3.2, advisory).
    pub reachability: HashMap<String, crate::reach::Reachability>,
    /// Usable inner MTU each member reported for its own uplink.
    pub reported_mtu: HashMap<String, u16>,
    /// Last MTU published to the network, so we only push on change.
    pub published_mtu: Option<nqvpn_proto::control::NetworkMtu>,
    /// Latest traffic sample per relay, plus the one before it. Two
    /// samples are all a rate needs, and keeping only two means the
    /// coordinator carries no history it would have to bound.
    pub traffic: HashMap<String, TrafficSample>,
}

#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub at: u64,
    pub report: nqvpn_proto::control::TrafficReport,
    pub prev_at: u64,
    pub prev: Option<nqvpn_proto::control::TrafficReport>,
}

impl TrafficSample {
    /// Bytes per second on one link since the previous sample.
    ///
    /// Counters are cumulative since the relay started, so a restart
    /// makes the new value smaller than the old. `saturating_sub` reports
    /// that as zero rather than as an enormous negative-turned-positive
    /// spike; one interval of understatement beats a garbage number.
    pub fn rate(&self, peer_id: NodeId, tx: bool) -> u64 {
        let (Some(prev), true) = (&self.prev, self.at > self.prev_at) else {
            return 0;
        };
        let pick = |r: &nqvpn_proto::control::TrafficReport| {
            r.links
                .iter()
                .find(|l| l.peer_id == peer_id)
                .map(|l| if tx { l.tx_bytes } else { l.rx_bytes })
                .unwrap_or(0)
        };
        let now = pick(&self.report);
        let then = pick(prev);
        now.saturating_sub(then) / (self.at - self.prev_at)
    }
}

/// How long a relay's last report stays in the matrix after it goes
/// quiet. Reports arrive every few seconds, so minutes of silence means
/// the relay is gone, not slow — and a row that never expires would keep
/// a decommissioned relay in the fleet view forever.
const TRAFFIC_RETENTION_SECS: u64 = 300;

impl Directory {
    /// Fold in a relay's latest report, keeping the previous one so a
    /// rate can be derived.
    pub fn record_traffic(
        &mut self,
        relay: &str,
        report: nqvpn_proto::control::TrafficReport,
        now: u64,
    ) {
        let (prev, prev_at) = match self.traffic.get(relay) {
            Some(s) => (Some(s.report.clone()), s.at),
            None => (None, now),
        };
        self.traffic
            .insert(relay.to_string(), TrafficSample { at: now, report, prev_at, prev });
        self.prune_traffic(now);
    }

    /// Drop reports from relays that have stopped talking to us. Pruning
    /// on write rather than on a timer keeps this free: the only thing
    /// that grows the map is a report arriving.
    pub fn prune_traffic(&mut self, now: u64) {
        self.traffic.retain(|_, s| now.saturating_sub(s.at) <= TRAFFIC_RETENTION_SECS);
    }
}

impl Directory {
    /// Recompute the peer view. Returns a delta if anything changed.
    pub fn recompute(
        &mut self,
        cfg: &NetworkConfig,
        reg: &Registry,
        now: u64,
    ) -> Option<MembershipDelta> {
        self.resolve_owners(cfg, reg, now);

        let mut next: BTreeMap<NodeId, PeerInfo> = BTreeMap::new();
        for (name, rec) in &reg.members {
            let online = self.online.contains(name);
            let mut prefixes: Vec<IpNet> = Vec::new();
            // Addresses are identity: they persist across death.
            if let Some(ip) = rec.ip4 {
                prefixes.push(IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
            }
            if let Some(ip) = rec.ip6 {
                prefixes.push(IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
            }
            // Routes are liveness-bound and singly-owned.
            for (cidr, owner) in &self.owners {
                if owner == name {
                    if let Ok(net) = cidr.parse::<IpNet>() {
                        prefixes.push(net);
                    }
                }
            }
            prefixes.sort_by_key(|p| p.to_string());
            next.insert(
                rec.node_id,
                PeerInfo {
                    node_id: rec.node_id,
                    name: name.clone(),
                    prefixes,
                    pubkey: rec.pubkey.clone().unwrap_or_default(),
                    online,
                },
            );
        }

        let mut changed: Vec<PeerInfo> = Vec::new();
        for (id, p) in &next {
            if self.peers.get(id) != Some(p) {
                changed.push(p.clone());
            }
        }
        let removed: Vec<NodeId> =
            self.peers.keys().filter(|id| !next.contains_key(id)).copied().collect();

        if changed.is_empty() && removed.is_empty() {
            return None;
        }
        let base_rev = self.revision;
        self.revision += 1;
        self.peers = next;
        Some(MembershipDelta { base_rev, new_rev: self.revision, changed, removed })
    }

    /// Age-resolved ownership over *live* registrants, with hold-down.
    fn resolve_owners(&mut self, _cfg: &NetworkConfig, reg: &Registry, now: u64) {
        let hold_down = self.hold_down_secs;
        let mut new_owners: BTreeMap<String, String> = BTreeMap::new();
        for (cidr, regs) in reg.resolve_owners() {
            let key = cidr.to_string();
            // Registrants that are currently online, oldest first.
            let live: Vec<&(String, u64)> =
                regs.iter().filter(|(n, _)| self.online.contains(n)).collect();
            let best = live.first().map(|(n, _)| n.clone());
            let current = self.owners.get(&key).cloned();
            let owner = match (current, best) {
                (Some(cur), Some(best)) if cur == best => Some(cur),
                (Some(cur), Some(best)) if self.online.contains(&cur) => {
                    // A better (older) registrant is back. Make it wait
                    // out hold-down so a flapping site doesn't oscillate.
                    let since = self.online_since.get(&best).copied().unwrap_or(0);
                    if now.saturating_sub(since) >= hold_down {
                        Some(best)
                    } else {
                        Some(cur)
                    }
                }
                // Current owner died (or never existed): take the best
                // living registrant immediately — this is site failover.
                (_, best) => best,
            };
            if let Some(o) = owner {
                new_owners.insert(key, o);
            }
        }
        self.owners = new_owners;
    }

    pub fn set_online(&mut self, name: &str, online: bool, now: u64) {
        if online {
            if self.online.insert(name.to_string()) {
                self.online_since.insert(name.to_string(), now);
            }
        } else {
            self.online.remove(name);
            self.online_since.remove(name);
        }
    }

    pub fn attachment_entries(&self) -> Vec<AttachmentEntry> {
        self.attachments
            .iter()
            .map(|(node_id, relay_id)| AttachmentEntry { node_id: *node_id, relay_id: *relay_id })
            .collect()
    }

    pub fn set_attachment(&mut self, node_id: NodeId, relay_id: Option<NodeId>) -> bool {
        let changed = match relay_id {
            Some(r) => self.attachments.insert(node_id, r) != Some(r),
            None => self.attachments.remove(&node_id).is_some(),
        };
        if changed {
            self.attach_revision += 1;
        }
        changed
    }

    /// Snapshot chunks for a joining session (§3.2: assembled off-path,
    /// installed atomically).
    pub fn snapshot_chunks(&self, chunk_size: usize) -> Vec<Vec<PeerInfo>> {
        let all: Vec<PeerInfo> = self.peers.values().cloned().collect();
        if all.is_empty() {
            return vec![vec![]];
        }
        all.chunks(chunk_size).map(|c| c.to_vec()).collect()
    }
}

/// Never go below the IPv6 minimum: a smaller MTU breaks v6 outright,
/// so a member reporting something absurd must not drag the network
/// under the floor.
pub const MIN_TUNNEL_MTU: u16 = 1280;

impl Directory {
    /// The safe tunnel MTU for the whole network: the smallest usable
    /// MTU any member reported, clamped to the v6 floor and to the
    /// configured ceiling. Returns the limiting member too.
    pub fn network_mtu(&self, ceiling: u16) -> nqvpn_proto::control::NetworkMtu {
        let mut best = ceiling;
        let mut who = "config".to_string();
        for (name, reported) in &self.reported_mtu {
            if *reported < best {
                best = *reported;
                who = name.clone();
            }
        }
        nqvpn_proto::control::NetworkMtu {
            mtu: best.max(MIN_TUNNEL_MTU),
            limited_by: who,
        }
    }

    pub fn with_hold_down(hold_down_secs: u64) -> Self {
        Directory { hold_down_secs, ..Default::default() }
    }

    pub fn set_hold_down(&mut self, secs: u64) {
        self.hold_down_secs = secs;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RouteReg;

    fn cfg() -> NetworkConfig {
        toml::from_str(
            r#"
network_id = "n1"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/24"
[relays.old]
secret_hash = "x"
relay_addr = "1.2.3.4:1"
allowed_cidrs = ["192.168.1.0/24"]
[relays.new]
secret_hash = "x"
relay_addr = "5.6.7.8:1"
allowed_cidrs = ["192.168.1.0/24"]
"#,
        )
        .unwrap()
    }

    fn registry_with_two_registrants() -> Registry {
        let mut reg = Registry::new();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        {
            let r = reg.member_mut("old", 1);
            r.pubkey = Some("PK".into());
            r.routes.push(RouteReg { cidr, first_granted_unix: 100 });
        }
        {
            let r = reg.member_mut("new", 1);
            r.pubkey = Some("PK".into());
            r.routes.push(RouteReg { cidr, first_granted_unix: 200 });
        }
        reg
    }

    #[test]
    fn network_mtu_is_the_minimum_over_all_members() {
        let mut d = Directory::with_hold_down(0);
        // Nobody has reported yet: the configured value stands.
        assert_eq!(d.network_mtu(1350).mtu, 1350);
        assert_eq!(d.network_mtu(1350).limited_by, "config");

        d.reported_mtu.insert("fast".into(), 1400);
        d.reported_mtu.insert("slow".into(), 1300);
        let m = d.network_mtu(1350);
        assert_eq!(m.mtu, 1300, "one small uplink limits the whole network");
        assert_eq!(m.limited_by, "slow", "and the operator can see which");

        // A member cannot raise the network above the configured ceiling.
        d.reported_mtu.clear();
        d.reported_mtu.insert("huge".into(), 9000);
        assert_eq!(d.network_mtu(1350).mtu, 1350);

        // Nor drag it below the IPv6 floor.
        d.reported_mtu.insert("broken".into(), 500);
        assert_eq!(d.network_mtu(1350).mtu, MIN_TUNNEL_MTU);
    }

    #[test]
    fn oldest_live_registrant_owns() {
        let (c, reg) = (cfg(), registry_with_two_registrants());
        let mut d = Directory::with_hold_down(60);
        d.set_online("old", true, 1000);
        d.set_online("new", true, 1000);
        d.recompute(&c, &reg, 1000);
        assert_eq!(d.owners["192.168.1.0/24"], "old");
    }

    #[test]
    fn death_fails_over_immediately() {
        let (c, reg) = (cfg(), registry_with_two_registrants());
        let mut d = Directory::with_hold_down(60);
        d.set_online("old", true, 1000);
        d.set_online("new", true, 1000);
        d.recompute(&c, &reg, 1000);

        d.set_online("old", false, 1100);
        let delta = d.recompute(&c, &reg, 1100).expect("ownership moved");
        assert_eq!(d.owners["192.168.1.0/24"], "new");
        // The standby's PeerInfo now carries the LAN prefix.
        let new_peer = delta.changed.iter().find(|p| p.name == "new").unwrap();
        assert!(new_peer.prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
        // The dead owner keeps no route.
        let old = d.peers.values().find(|p| p.name == "old").unwrap();
        assert!(!old.prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
        assert!(!old.online);
    }

    #[test]
    fn returning_owner_waits_out_hold_down() {
        let (c, reg) = (cfg(), registry_with_two_registrants());
        let mut d = Directory::with_hold_down(60);
        d.set_online("new", true, 1000);
        d.recompute(&c, &reg, 1000);
        assert_eq!(d.owners["192.168.1.0/24"], "new");

        // "old" comes back at t=1100; it is the older registration but
        // must not reclaim until hold_down elapses.
        d.set_online("old", true, 1100);
        d.recompute(&c, &reg, 1110);
        assert_eq!(d.owners["192.168.1.0/24"], "new", "hold-down still active");

        d.recompute(&c, &reg, 1100 + 60);
        assert_eq!(d.owners["192.168.1.0/24"], "old", "reclaimed after hold-down");
    }

    #[test]
    fn addresses_survive_death_but_routes_do_not() {
        let c = cfg();
        let mut reg = registry_with_two_registrants();
        reg.member_mut("old", 1).ip4 = Some("10.99.0.1".parse().unwrap());
        let mut d = Directory::with_hold_down(0);
        d.set_online("old", true, 1000);
        d.recompute(&c, &reg, 1000);
        d.set_online("old", false, 1100);
        d.recompute(&c, &reg, 1100);
        let old = d.peers.values().find(|p| p.name == "old").unwrap();
        assert!(old.prefixes.iter().any(|p| p.to_string() == "10.99.0.1/32"));
        assert_eq!(old.prefixes.len(), 1);
    }

    #[test]
    fn revision_advances_only_on_change() {
        let (c, reg) = (cfg(), registry_with_two_registrants());
        let mut d = Directory::with_hold_down(60);
        d.set_online("old", true, 1000);
        assert!(d.recompute(&c, &reg, 1000).is_some());
        let rev = d.revision;
        assert!(d.recompute(&c, &reg, 1001).is_none(), "no change, no revision bump");
        assert_eq!(d.revision, rev);
    }

    fn report(peer: NodeId, tx: u64, rx: u64) -> nqvpn_proto::control::TrafficReport {
        nqvpn_proto::control::TrafficReport {
            links: vec![nqvpn_proto::control::LinkTraffic {
                peer_id: peer,
                tx_bytes: tx,
                tx_pkts: tx / 1000,
                rx_bytes: rx,
                rx_pkts: rx / 1000,
                up: true,
            }],
            local_bytes: 0,
            local_pkts: 0,
            terminated_bytes: 0,
            terminated_pkts: 0,
        }
    }

    #[test]
    fn rate_is_derived_from_consecutive_samples() {
        let mut d = Directory::default();
        d.record_traffic("r1", report(2, 1_000, 500), 100);
        // The first sample has nothing to compare against.
        assert_eq!(d.traffic["r1"].rate(2, true), 0);

        d.record_traffic("r1", report(2, 11_000, 5_500), 110);
        // 10_000 bytes over 10 seconds.
        assert_eq!(d.traffic["r1"].rate(2, true), 1_000);
        assert_eq!(d.traffic["r1"].rate(2, false), 500);
    }

    #[test]
    fn a_relay_restart_reports_zero_not_a_spike() {
        // Counters are cumulative since process start, so a restart makes
        // the new value smaller. Reporting the wrapped difference would
        // put an absurd spike on the graph forever.
        let mut d = Directory::default();
        d.record_traffic("r1", report(2, 9_000_000, 0), 100);
        d.record_traffic("r1", report(2, 12_000, 0), 110);
        assert_eq!(d.traffic["r1"].rate(2, true), 0);
    }

    #[test]
    fn unknown_peer_and_zero_window_are_not_divisions_by_zero() {
        let mut d = Directory::default();
        d.record_traffic("r1", report(2, 1_000, 0), 100);
        d.record_traffic("r1", report(2, 5_000, 0), 100); // same second
        assert_eq!(d.traffic["r1"].rate(2, true), 0);
        // A peer this relay never reported on has no rate, not a panic.
        assert_eq!(d.traffic["r1"].rate(99, true), 0);
    }

    #[test]
    fn each_relay_keeps_its_own_row() {
        let mut d = Directory::default();
        d.record_traffic("r1", report(2, 1_000, 0), 100);
        d.record_traffic("r2", report(1, 7_000, 0), 100);
        assert_eq!(d.traffic.len(), 2);
        assert_eq!(d.traffic["r2"].report.links[0].tx_bytes, 7_000);
    }

    #[test]
    fn a_relay_that_stops_reporting_drops_out_of_the_matrix() {
        // cp sat in the fleet view for eight hours after being stopped
        // and removed from config, because nothing ever expired its last
        // sample.
        let mut d = Directory::default();
        d.record_traffic("cp", report(2, 1_000, 0), 100);
        assert!(d.traffic.contains_key("cp"));

        // Still present while merely quiet for a short while.
        d.prune_traffic(100 + TRAFFIC_RETENTION_SECS);
        assert!(d.traffic.contains_key("cp"), "must survive a brief silence");

        // Gone once the silence is long enough to mean "decommissioned".
        d.prune_traffic(100 + TRAFFIC_RETENTION_SECS + 1);
        assert!(!d.traffic.contains_key("cp"));
    }

    #[test]
    fn pruning_keeps_relays_that_are_still_reporting() {
        let mut d = Directory::default();
        d.record_traffic("gone", report(2, 1, 0), 100);
        // A live relay reporting much later must not be swept away with
        // the dead one — and its own arrival is what triggers the prune.
        d.record_traffic("live", report(2, 1, 0), 100 + TRAFFIC_RETENTION_SECS + 50);
        assert!(d.traffic.contains_key("live"));
        assert!(!d.traffic.contains_key("gone"));
    }
}
