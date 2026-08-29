//! The per-network directory: the derived, generation-numbered view that
//! gets pushed to members (§3.2). Registry + leases in, `Snapshot` out.
//!
//! Three rules from the design live here:
//!  * **routes are liveness-bound, identity is not** (§2/§7) — an offline
//!    member keeps its addresses but its route registrations are
//!    withdrawn, so the next-oldest living registrant takes over;
//!  * **flap damping** (§2) — a returning registrant waits `hold_down`
//!    before reclaiming ownership from a live standby;
//!  * **one generation per change** — the published snapshot only moves
//!    when its content does, every move gets a new generation, and the
//!    last few deltas are kept so a member one or two behind can catch
//!    up without a full snapshot.

use ipnet::IpNet;
use nqvpn_proto::control::{AttachmentEntry, Delta, KeyInfo, NetworkMtu, PeerInfo, RelayEndpoint, Snapshot};
use nqvpn_proto::types::{NodeId, Role};
use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::config::NetworkConfig;
use crate::leases::Leases;
use crate::registry::Registry;

/// Deltas kept for catch-up. A member further behind gets a snapshot.
pub const RING: usize = 512;

/// Never go below the IPv6 minimum: a smaller MTU breaks v6 outright.
pub const MIN_TUNNEL_MTU: u16 = 1280;

/// How long a relay's last traffic report stays in the matrix after it
/// goes quiet.
const TRAFFIC_RETENTION_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct TrafficSample {
    pub at: u64,
    pub report: nqvpn_proto::control::TrafficReport,
    pub prev_at: u64,
    pub prev: Option<nqvpn_proto::control::TrafficReport>,
}

impl TrafficSample {
    /// Bytes per second on one link since the previous sample. A relay
    /// restart makes the counter smaller; that reads as zero, not a spike.
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
        pick(&self.report).saturating_sub(pick(prev)) / (self.at - self.prev_at)
    }
}

#[derive(Debug)]
pub struct Directory {
    /// Current generation; `published.gen` equals it.
    pub gen: u64,
    pub published: Snapshot,
    pub published_digest: u64,
    ring: VecDeque<Delta>,
    /// cidr string -> owning node id (sticky until death/hold-down).
    pub owners: BTreeMap<String, NodeId>,
    pub hold_down_secs: u64,
    pub reachability: HashMap<NodeId, crate::reach::Reachability>,
    pub reported_mtu: HashMap<NodeId, u16>,
    pub traffic: HashMap<NodeId, TrafficSample>,
}

impl Directory {
    pub fn new(initial_gen: u64, hold_down_secs: u64) -> Self {
        let published = Snapshot { gen: initial_gen, ..Snapshot::default() };
        let published_digest = published.digest();
        Directory {
            gen: initial_gen,
            published,
            published_digest,
            ring: VecDeque::new(),
            owners: BTreeMap::new(),
            hold_down_secs,
            reachability: HashMap::new(),
            reported_mtu: HashMap::new(),
            traffic: HashMap::new(),
        }
    }

    /// Recompute the view. Returns the delta if anything changed, in
    /// which case `gen` has advanced and the delta is in the ring.
    pub fn recompute(
        &mut self,
        cfg: &NetworkConfig,
        reg: &Registry,
        leases: &Leases,
        keys: &[KeyInfo],
        now: u64,
    ) -> Option<Delta> {
        self.resolve_owners(reg, leases, now);

        let mut members = Vec::new();
        for (id, rec) in &reg.members {
            if rec.disabled {
                continue;
            }
            let mut prefixes: Vec<IpNet> = Vec::new();
            if let Some(ip) = rec.ip4 {
                prefixes.push(IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
            }
            if let Some(ip) = rec.ip6 {
                prefixes.push(IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
            }
            for (cidr, owner) in &self.owners {
                if owner == id {
                    if let Ok(net) = cidr.parse::<IpNet>() {
                        prefixes.push(net);
                    }
                }
            }
            prefixes.sort_by_key(|p| p.to_string());
            members.push(PeerInfo {
                node_id: *id,
                name: rec.name.clone(),
                role: rec.role,
                prefixes,
                pubkey: rec.pubkey.clone().unwrap_or_default(),
                online: leases.is_online(*id),
                login_gen: rec.login_gen,
            });
        }

        let attachments: Vec<AttachmentEntry> = leases
            .attachments()
            .into_iter()
            .filter(|(c, r)| {
                let ok = |n: &NodeId| reg.members.get(n).map(|m| !m.disabled).unwrap_or(false);
                ok(c) && ok(r)
            })
            .map(|(node_id, relay_id)| AttachmentEntry { node_id, relay_id })
            .collect();

        let mut reserved: Vec<IpNet> = cfg.cidrs.clone();
        for rec in reg.members.values().filter(|m| !m.disabled) {
            reserved.extend(rec.routes.iter().map(|r| r.cidr));
        }

        let mut next = Snapshot {
            gen: self.gen,
            members,
            attachments,
            relays: relay_endpoints(cfg, reg),
            mtu: self.network_mtu(cfg.settings.mtu),
            keys: keys.to_vec(),
            reserved_prefixes: reserved,
        };
        next.normalize();
        if next == self.published {
            return None;
        }
        next.gen = self.gen + 1;
        let delta = self.published.diff(&next);
        self.gen = next.gen;
        self.published = next;
        self.published_digest = self.published.digest();
        self.ring.push_back(delta.clone());
        while self.ring.len() > RING {
            self.ring.pop_front();
        }
        Some(delta)
    }

    /// The contiguous chain of deltas from `have_gen` to the current
    /// generation, if the ring still holds it.
    pub fn deltas_since(&self, have_gen: u64) -> Option<Vec<Delta>> {
        if have_gen == self.gen {
            return Some(Vec::new());
        }
        let start = self.ring.iter().position(|d| d.base_gen == have_gen)?;
        let chain: Vec<Delta> = self.ring.iter().skip(start).cloned().collect();
        // Sanity: contiguous and ends at the current generation.
        let mut expect = have_gen;
        for d in &chain {
            if d.base_gen != expect {
                return None;
            }
            expect = d.gen;
        }
        (expect == self.gen).then_some(chain)
    }

    /// Age-resolved ownership over *live* registrants, with hold-down.
    fn resolve_owners(&mut self, reg: &Registry, leases: &Leases, now: u64) {
        let hold_down = self.hold_down_secs;
        let mut new_owners: BTreeMap<String, NodeId> = BTreeMap::new();
        for (cidr, regs) in reg.resolve_owners() {
            let key = cidr.to_string();
            let live: Vec<NodeId> =
                regs.iter().filter(|(n, _)| leases.is_online(*n)).map(|(n, _)| *n).collect();
            let best = live.first().copied();
            let current = self.owners.get(&key).copied();
            let owner = match (current, best) {
                (Some(cur), Some(best)) if cur == best => Some(cur),
                (Some(cur), Some(best)) if leases.is_online(cur) => {
                    // A better (older) registrant is back. Make it wait
                    // out hold-down so a flapping site doesn't oscillate.
                    let since = leases.online_since(best).unwrap_or(0) / 1000;
                    if now.saturating_sub(since) >= hold_down {
                        Some(best)
                    } else {
                        Some(cur)
                    }
                }
                // Current owner died (or never existed): the best living
                // registrant takes over immediately — site failover.
                (_, best) => best,
            };
            if let Some(o) = owner {
                new_owners.insert(key, o);
            }
        }
        self.owners = new_owners;
    }

    /// The safe tunnel MTU for the whole network: the smallest usable
    /// MTU any member reported, clamped to the v6 floor and to the
    /// configured ceiling, naming the limiting member.
    pub fn network_mtu(&self, ceiling: u16) -> NetworkMtu {
        let mut best = ceiling;
        let mut who = "config".to_string();
        let mut limiting: Vec<(&NodeId, &u16)> = self.reported_mtu.iter().collect();
        limiting.sort();
        for (node, reported) in limiting {
            if *reported > 0 && *reported < best {
                best = *reported;
                who = format!("#{node}");
            }
        }
        NetworkMtu { mtu: best.max(MIN_TUNNEL_MTU), limited_by: who }
    }

    pub fn record_traffic(&mut self, relay: NodeId, report: nqvpn_proto::control::TrafficReport, now: u64) {
        let (prev, prev_at) = match self.traffic.get(&relay) {
            Some(s) => (Some(s.report.clone()), s.at),
            None => (None, now),
        };
        self.traffic.insert(relay, TrafficSample { at: now, report, prev_at, prev });
        self.prune_traffic(now);
    }

    pub fn prune_traffic(&mut self, now: u64) {
        self.traffic.retain(|_, s| now.saturating_sub(s.at) <= TRAFFIC_RETENTION_SECS);
    }
}

/// The dialable relay fleet: configured relays that have joined at least
/// once, so their address and certificate fingerprint are known.
pub fn relay_endpoints(cfg: &NetworkConfig, reg: &Registry) -> Vec<RelayEndpoint> {
    let mut out = Vec::new();
    for (name, m) in &cfg.relays {
        let Some(rec) = reg.by_name(name) else { continue };
        if rec.disabled || rec.role != Role::Relay {
            continue;
        }
        if let (Some(fp), Some(addr)) = (&rec.cert_fp, &m.relay_addr) {
            out.push(RelayEndpoint {
                relay_id: rec.node_id,
                name: name.clone(),
                addr: addr.clone(),
                cert_fp: fp.clone(),
            });
        }
    }
    out.sort_by_key(|r| r.relay_id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::RouteReg;
    use nqvpn_proto::control::{AttachedClient, Heartbeat};

    fn cfg() -> NetworkConfig {
        toml::from_str(
            r#"
network_id = "n1"
cidrs = ["10.99.0.0/16"]
[pools.default]
cidr = "10.99.1.0/24"
[relays.old]
relay_addr = "1.2.3.4:1"
allowed_cidrs = ["192.168.1.0/24"]
[relays.new]
relay_addr = "5.6.7.8:1"
allowed_cidrs = ["192.168.1.0/24"]
[clients.c]
"#,
        )
        .unwrap()
    }

    fn registry() -> Registry {
        let mut reg = Registry::new();
        let cidr: IpNet = "192.168.1.0/24".parse().unwrap();
        for (id, name, age) in [(1, "old", 100), (2, "new", 200)] {
            let r = reg.member_mut(id, name, Role::Relay, 1);
            r.pubkey = Some("PK".into());
            r.cert_fp = Some("fp".into());
            r.routes.push(RouteReg { cidr, first_granted_unix: age });
        }
        reg.member_mut(10, "c", Role::Client, 1).ip4 = Some("10.99.1.5".parse().unwrap());
        reg
    }

    fn online(l: &mut Leases, ids: &[NodeId], now: u64) {
        for id in ids {
            l.seen(*id, now);
        }
    }

    #[test]
    fn every_change_is_one_generation_and_deltas_chain() {
        let (c, reg) = (cfg(), registry());
        let mut l = Leases::default();
        let mut d = Directory::new(1000, 0);
        let d1 = d.recompute(&c, &reg, &l, &[], 1).expect("first view");
        assert_eq!(d1.base_gen, 1000);
        assert_eq!(d.gen, 1001);
        assert!(d.recompute(&c, &reg, &l, &[], 2).is_none(), "no change, no generation");

        online(&mut l, &[1], 10);
        let d2 = d.recompute(&c, &reg, &l, &[], 10).expect("relay 1 came online");
        assert_eq!((d2.base_gen, d2.gen), (1001, 1002));
        online(&mut l, &[10], 11);
        d.recompute(&c, &reg, &l, &[], 11).expect("client online");
        assert_eq!(d.gen, 1003);

        // A member at 1001 catches up with two deltas; at 1000 with three.
        let chain = d.deltas_since(1001).unwrap();
        assert_eq!(chain.len(), 2);
        // Reconstruct: apply d1 onto empty at 1000, then the chain.
        let mut copy = Snapshot { gen: 1000, ..Snapshot::default() };
        copy.apply(&d1).unwrap();
        for dl in &chain {
            copy.apply(dl).unwrap();
        }
        assert_eq!(copy, d.published);
        assert_eq!(copy.digest(), d.published_digest);
        assert!(d.deltas_since(999).is_none(), "unknown base needs a snapshot");
        assert!(d.deltas_since(1003).unwrap().is_empty(), "current: nothing to send");
    }

    #[test]
    fn oldest_live_registrant_owns_and_death_fails_over() {
        let (c, reg) = (cfg(), registry());
        let mut l = Leases::default();
        let mut d = Directory::new(1, 60);
        online(&mut l, &[1, 2], 1000);
        d.recompute(&c, &reg, &l, &[], 1000);
        assert_eq!(d.owners["192.168.1.0/24"], 1);
        l.offline(1);
        let delta = d.recompute(&c, &reg, &l, &[], 1100).expect("ownership moved");
        assert_eq!(d.owners["192.168.1.0/24"], 2);
        let new_peer = delta.members_changed.iter().find(|p| p.node_id == 2).unwrap();
        assert!(new_peer.prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
        let old = d.published.member(1).unwrap();
        assert!(!old.prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
        assert!(!old.online);
        // The CIDR stays reserved so members keep routing it into the tunnel.
        assert!(d.published.reserved_prefixes.iter().any(|p| p.to_string() == "192.168.1.0/24"));
    }

    #[test]
    fn returning_owner_waits_out_hold_down() {
        let (c, reg) = (cfg(), registry());
        let mut l = Leases::default();
        let mut d = Directory::new(1, 60);
        online(&mut l, &[2], 1000);
        d.recompute(&c, &reg, &l, &[], 1000);
        assert_eq!(d.owners["192.168.1.0/24"], 2);
        online(&mut l, &[1], 1_100_000);
        d.recompute(&c, &reg, &l, &[], 1110);
        assert_eq!(d.owners["192.168.1.0/24"], 2, "hold-down still active");
        d.recompute(&c, &reg, &l, &[], 1160);
        assert_eq!(d.owners["192.168.1.0/24"], 1, "reclaimed after hold-down");
    }

    #[test]
    fn disabled_members_vanish_from_the_view() {
        let (c, mut reg) = (cfg(), registry());
        let mut l = Leases::default();
        online(&mut l, &[1, 10], 5);
        l.heartbeat(1, Role::Relay, &Heartbeat { attached: vec![AttachedClient { node_id: 10, session_id: 1 }], ..Default::default() }, 5);
        let mut d = Directory::new(1, 0);
        d.recompute(&c, &reg, &l, &[], 5);
        assert!(d.published.member(10).is_some());
        assert_eq!(d.published.attachment_of(10), Some(1));
        reg.members.get_mut(&10).unwrap().disabled = true;
        let delta = d.recompute(&c, &reg, &l, &[], 6).unwrap();
        assert_eq!(delta.members_removed, vec![10]);
        assert_eq!(delta.attachments_removed, vec![10]);
        assert!(d.published.member(10).is_none());
    }

    #[test]
    fn network_mtu_is_the_minimum_over_all_members() {
        let mut d = Directory::new(1, 0);
        assert_eq!(d.network_mtu(1350).mtu, 1350);
        d.reported_mtu.insert(1, 1400);
        d.reported_mtu.insert(2, 1300);
        let m = d.network_mtu(1350);
        assert_eq!(m.mtu, 1300);
        assert_eq!(m.limited_by, "#2");
        d.reported_mtu.insert(3, 500);
        assert_eq!(d.network_mtu(1350).mtu, MIN_TUNNEL_MTU);
    }

    fn report(peer: NodeId, tx: u64) -> nqvpn_proto::control::TrafficReport {
        nqvpn_proto::control::TrafficReport {
            links: vec![nqvpn_proto::control::LinkTraffic { peer_id: peer, tx_bytes: tx, tx_pkts: 0, rx_bytes: 0, rx_pkts: 0, up: true }],
            ..Default::default()
        }
    }

    #[test]
    fn rates_derive_from_samples_and_stale_rows_are_pruned() {
        let mut d = Directory::new(1, 0);
        d.record_traffic(1, report(2, 1_000), 100);
        assert_eq!(d.traffic[&1].rate(2, true), 0);
        d.record_traffic(1, report(2, 11_000), 110);
        assert_eq!(d.traffic[&1].rate(2, true), 1_000);
        d.record_traffic(1, report(2, 12), 120);
        assert_eq!(d.traffic[&1].rate(2, true), 0, "restart reads as zero");
        d.prune_traffic(120 + TRAFFIC_RETENTION_SECS + 1);
        assert!(d.traffic.is_empty());
    }
}
