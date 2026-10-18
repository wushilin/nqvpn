//! OS route programming (DESIGN.md §8), behind a trait so the engine and
//! CI stay platform-free.
//!
//! The routing table is a pure function of the network view:
//!
//! Ownership is structural: every route we install goes out our TUN
//! device (`dev <tun>`), and nothing else routes through that device, so
//! "a route whose output interface is our TUN" == "a route we own". The
//! kernel is the source of truth — we read it back (via the `net-route`
//! crate, not by parsing CLI output) and reconcile against it, so a
//! route another writer deleted reappears and a stale one is removed.
//! The only routes on our device we must not touch are the kernel's own
//! connected routes for the addresses we assigned; those are exactly
//! `mine`, and we exclude them.
//!
//!  * **wanted** = every reserved prefix of the network (tunnel CIDRs and
//!    every registered gateway CIDR, owned or not) plus every member's
//!    prefixes — minus anything this node owns itself;
//!  * **excluded** = anything that would capture something this host
//!    already routes: a prefix equal to or inside a local interface
//!    prefix, or one containing an underlay address (the coordinator, a
//!    relay) with no more-specific local route protecting it.
//!
//! Reserved-but-unowned prefixes stay pointed at the TUN on purpose: a
//! packet for a site that is down enters the tunnel, matches no peer, and
//! is dropped as `drop_no_route` — instead of falling through to the
//! default route and leaving in cleartext for a range like 192.168.1.0/24
//! that very often exists somewhere real.
//!
//! `reconcile` diffs wanted against what we installed and issues only the
//! difference, so a snapshot that changes one member touches one route.

use anyhow::Result;
use ipnet::IpNet;
use crate::peers::RoutePolicy;
use nqvpn_proto::control::Snapshot;
use nqvpn_proto::types::NodeId;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Mutex;

pub trait RouteProgrammer: Send + Sync {
    fn add_via_tun(&self, net: IpNet) -> Result<()>;
    fn remove(&self, net: IpNet) -> Result<()>;

    /// Every prefix the kernel currently routes out our device, as
    /// ground truth for `reconcile_via_kernel`. `None` means the table
    /// cannot be read here (the recording/dry-run programmer), and the
    /// caller falls back to the cache-based `reconcile`.
    fn list_via_dev(&self) -> Option<Vec<IpNet>> {
        None
    }

    /// For `--route-all`: pin each underlay host (the coordinator and the
    /// relays this node dials) to the real default gateway with a host
    /// route, so the catch-all halves below do not swallow the tunnel's
    /// own transport. Reconciles to exactly `ips` (adds new, drops gone)
    /// and returns those actually pinned. The default pretends success so
    /// the recording/dry-run programmer still reports the catch-all routes;
    /// the real programmer overrides it.
    fn pin_underlay(&self, ips: &[IpAddr]) -> Result<Vec<IpAddr>> {
        Ok(ips.to_vec())
    }
}

/// The two halves that together cover a whole address family. Each is one
/// bit longer than the default route, so the kernel prefers them over
/// `0.0.0.0/0` without deleting it — OpenVPN's `redirect-gateway def1`.
pub fn catch_all_halves(v6: bool) -> [IpNet; 2] {
    if v6 {
        ["::/1".parse().unwrap(), "8000::/1".parse().unwrap()]
    } else {
        ["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()]
    }
}

/// The resolvers this host uses, from `/etc/resolv.conf`.
///
/// route-all does not take DNS over, so name resolution must keep working
/// exactly as it did — and it cannot work *through* the tunnel before the
/// tunnel exists: resolving the coordinator and the relays is what brings
/// the tunnel up. An off-LAN resolver (8.8.8.8, say) therefore has to stay
/// reachable over the real gateway, or route-all deadlocks: DNS into a
/// tunnel that has no relay, and no relay without DNS.
///
/// Only resolvers that a pin can actually keep off the tunnel are
/// returned. A loopback stub (systemd-resolved's `127.0.0.53`, dnsmasq's
/// `127.0.0.1`) is never captured by the catch-all — and pinning it via
/// the gateway would be wrong — so in its place we pin the upstreams the
/// stub forwards to, from systemd-resolved's own list when it exists. A
/// link-local resolver (`fe80::1%eth0`, `169.254.x`) lives on the LAN and
/// its connected route already outranks the catch-all; with its scope
/// stripped it could not be pinned anyway.
pub fn system_resolvers() -> Vec<IpAddr> {
    let read = |path: &str| std::fs::read_to_string(path).map(|t| parse_resolvers(&t)).unwrap_or_default();
    let listed = read("/etc/resolv.conf");
    let mut out: Vec<IpAddr> = listed.iter().copied().filter(|ip| pinnable_resolver(*ip)).collect();
    if listed.iter().any(|ip| ip.is_loopback()) {
        out.extend(read("/run/systemd/resolve/resolv.conf").into_iter().filter(|ip| pinnable_resolver(*ip)));
    }
    out.sort();
    out.dedup();
    out
}

/// Every `nameserver` address in a resolv.conf, scope suffix stripped.
pub fn parse_resolvers(text: &str) -> Vec<IpAddr> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter_map(|l| l.strip_prefix("nameserver"))
        .filter_map(|rest| rest.trim().split('%').next().unwrap_or("").parse::<IpAddr>().ok())
        .collect()
}

/// Can a host route via the default gateway keep this resolver reachable
/// — and does it need one? Not for loopback, link-local or unspecified
/// addresses.
pub fn pinnable_resolver(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !(v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()),
        IpAddr::V6(v6) => !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80),
    }
}

/// A next hop: the gateway address and, where known, the interface it is
/// reached through. The interface is part of the identity — an IPv6
/// default gateway is almost always link-local (`fe80::1`), which means
/// nothing without one (Linux refuses such a route outright), and the
/// same IPv4 gateway address on a different interface (wired → wifi on
/// one LAN) is a different route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gateway {
    pub addr: IpAddr,
    pub ifindex: Option<u32>,
}

impl Gateway {
    pub fn new(addr: IpAddr, ifindex: Option<u32>) -> Self {
        Gateway { addr, ifindex }
    }
}

impl From<IpAddr> for Gateway {
    fn from(addr: IpAddr) -> Self {
        Gateway { addr, ifindex: None }
    }
}

/// `addr` or `addr%ifindex` — the journal's spelling.
impl std::fmt::Display for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ifindex {
            Some(i) => write!(f, "{}%{i}", self.addr),
            None => write!(f, "{}", self.addr),
        }
    }
}

impl std::str::FromStr for Gateway {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> {
        match s.split_once('%') {
            Some((a, i)) => Ok(Gateway { addr: a.parse().map_err(|_| ())?, ifindex: Some(i.parse().map_err(|_| ())?) }),
            None => Ok(Gateway { addr: s.parse().map_err(|_| ())?, ifindex: None }),
        }
    }
}

/// The routing-table operations underlay pinning needs, behind a trait so
/// the rules in `reconcile_pins` are exercised without touching an OS.
pub trait HostRouteTable {
    fn default_gateway(&self, v6: bool) -> Option<Gateway>;
    /// `Ok(true)` when this call created the route; `Ok(false)` when an
    /// identical one was already present, and so is not ours to remove.
    fn add_host_route(&self, ip: IpAddr, gw: Gateway) -> std::io::Result<bool>;
    fn del_host_route(&self, ip: IpAddr, gw: Gateway);
}

/// The pins we created — `ip -> gateway` — optionally journaled to a file
/// so a process that dies without running its teardown can be cleaned up
/// by the next one. The pins are the only routes this node installs that
/// are not bound to the TUN: every tunnel route dies with the device, but
/// a host route via the real gateway outlives a `kill -9`, and on a
/// laptop that then moves networks it points at a gateway that no longer
/// exists — the relays and the coordinator become unreachable through a
/// route nothing knows it owns.
///
/// The journal is **write-ahead** and never under-records: an entry is
/// written *before* the kernel gains the route and removed *after* the
/// kernel loses it, so a crash at any instant leaves at worst a phantom
/// entry, and deleting a route that is not there is a no-op. An entry is
/// removed on its own only when the add reports the route was already
/// present (someone else's), so the file lists exactly what we own.
///
/// Format: one `ip gateway` per line, the gateway optionally suffixed
/// `%ifindex` (older journals have none); an empty journal is no file at
/// all, which is what a clean exit leaves behind.
pub struct PinJournal {
    path: Option<std::path::PathBuf>,
    map: std::collections::BTreeMap<IpAddr, Gateway>,
}

impl PinJournal {
    /// No file: the pins live and die with the process (relays, dry runs, tests).
    pub fn in_memory() -> Self {
        PinJournal { path: None, map: Default::default() }
    }

    /// Load the journal at `path`, creating none if absent. Entries left by
    /// a previous run are inherited as pins and dealt with by the first
    /// `reconcile_pins`, which the caller runs with an empty want set to
    /// remove them before doing anything that needs the underlay.
    pub fn load(path: std::path::PathBuf) -> Self {
        let mut map = std::collections::BTreeMap::new();
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    let parsed = line.split_once(' ').and_then(|(a, b)| Some((a.trim().parse().ok()?, b.trim().parse().ok()?)));
                    match parsed {
                        Some((ip, gw)) => {
                            map.insert(ip, gw);
                        }
                        None => tracing::warn!(path = %path.display(), line, "ignoring a malformed pin journal line"),
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!(path = %path.display(), "cannot read the pin journal (leftover pins, if any, will not be removed): {e}"),
        }
        PinJournal { path: Some(path), map }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn get(&self, ip: &IpAddr) -> Option<Gateway> {
        self.map.get(ip).copied()
    }
    pub fn contains_key(&self, ip: &IpAddr) -> bool {
        self.map.contains_key(ip)
    }
    pub fn keys(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.map.keys().copied()
    }

    /// Journal a pin. Called *before* the route is added.
    pub fn record(&mut self, ip: IpAddr, gw: Gateway) {
        self.map.insert(ip, gw);
        self.persist();
    }

    /// Drop a pin from the journal. Called *after* the route is deleted
    /// (or when it turned out never to be ours).
    pub fn forget(&mut self, ip: &IpAddr) -> Option<Gateway> {
        let had = self.map.remove(ip);
        self.persist();
        had
    }

    /// Write the whole map atomically (temp file + rename); an empty map
    /// removes the file. A failure is logged, not fatal: the pin is still
    /// programmed, we just lose the crash-safety for it, which is no worse
    /// than having no journal.
    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let r = if self.map.is_empty() {
            match std::fs::remove_file(path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        } else {
            let body: String = self.map.iter().map(|(ip, gw)| format!("{ip} {gw}\n")).collect();
            write_file_atomic(path, body.as_bytes())
        };
        if let Err(e) = r {
            tracing::warn!(path = %path.display(), "cannot write the pin journal: {e}");
        }
    }
}

/// Write `bytes` to `path` atomically, root-safe in a directory others
/// might write to: a stale temp is unlinked (never followed), the new one
/// is created exclusively (`O_EXCL` refuses a symlink, and `O_NOFOLLOW`
/// says so twice) with its mode set at creation, and the file and its
/// directory are fsynced before and after the rename.
fn write_file_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)?;
    #[cfg(unix)]
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Bring the underlay pins in line with `want` and the *current* default
/// gateway, returning the hosts route-all may now count as reachable off
/// the tunnel. Three rules, and the pin journal is the whole state:
///
///  * `pinned` records only routes **we** created, so tearing down can
///    never delete a route the host already had;
///  * a pin is only correct while it names the current default gateway —
///    after a DHCP change or a move to another network, one left on the old
///    gateway silently blackholes exactly the hosts route-all cannot lose;
///  * a host that drops out of `want` (a relay left the fleet) loses its pin.
///
/// The same three rules do teardown and crash recovery: run with an empty
/// `want`, everything pinned — including what a dead predecessor left in
/// the journal — is stale and removed. There is no separate cleanup path.
///
/// Ordering against the journal is write-ahead throughout: record, then
/// add; delete, then forget. See [`PinJournal`].
pub fn reconcile_pins(table: &dyn HostRouteTable, want: &[IpAddr], pinned: &mut PinJournal) -> Vec<IpAddr> {
    let want: BTreeSet<IpAddr> = want.iter().copied().collect();
    let stale: Vec<IpAddr> = pinned.keys().filter(|ip| !want.contains(ip)).collect();
    for ip in stale {
        if let Some(gw) = pinned.get(&ip) {
            table.del_host_route(ip, gw);
            pinned.forget(&ip);
        }
    }
    let mut ok = Vec::new();
    for ip in want {
        let Some(gw) = table.default_gateway(ip.is_ipv6()) else {
            tracing::warn!(%ip, "route-all: no default gateway to pin this underlay host through; it is reported unpinned");
            continue;
        };
        match pinned.get(&ip) {
            Some(had) if had == gw => {
                ok.push(ip);
                continue;
            }
            Some(had) => {
                table.del_host_route(ip, had);
                pinned.forget(&ip);
                tracing::info!(target: "nqvpn::os_routes", %ip, old_gateway = %had, new_gateway = %gw, "route-all: default gateway moved; re-pinning underlay host");
            }
            None => {}
        }
        pinned.record(ip, gw);
        match table.add_host_route(ip, gw) {
            Ok(true) => {
                tracing::info!(target: "nqvpn::os_routes", %ip, %gw, "route-all: pinned underlay host to gateway");
                ok.push(ip);
            }
            // Already routed the way we want, by someone else: usable, but
            // not ours, so it is not recorded and never torn down.
            Ok(false) => {
                pinned.forget(&ip);
                ok.push(ip);
            }
            Err(e) => {
                pinned.forget(&ip);
                tracing::warn!(%ip, %gw, "route-all: pinning underlay host failed: {e}");
            }
        }
    }
    ok
}

/// Which underlay hosts need pinning under route-all: those NOT already
/// carried by a connected local route (a relay on the same LAN is reached
/// by its own more-specific connected route, which already outranks the
/// catch-all — pinning it via the gateway would be wrong).
pub fn underlay_to_pin(underlay: &[IpAddr], local: &[IpNet]) -> Vec<IpAddr> {
    let s: BTreeSet<IpAddr> = underlay
        .iter()
        .copied()
        .filter(|ip| !local.iter().any(|l| l.contains(ip)))
        .collect();
    s.into_iter().collect()
}

/// The exit gateway a route-all client seals otherwise-unrouted (internet)
/// traffic to, for one address family. A candidate must be online and own
/// the family's default route (`0.0.0.0/0` or `::/0`) — the exact prefix
/// that makes *its* ingress filter accept internet-bound packets, so a
/// client never seals traffic to a node that would only drop it.
///
/// `via` is a **preference, not a pin**: the node of that name is used
/// whenever it qualifies, and another usable exit is taken when it does
/// not, because being on the operator's preferred exit matters less than
/// having internet at all.
///
/// With no preference — or when the preferred one is unusable — the exit
/// we are **already attached to** wins if it is one. Internet traffic then
/// terminates on the relay holding our only session, crossing no mesh
/// link at all, where any other exit costs a hop (§6). It is also the
/// stablest choice: it changes only when our attachment does.
///
/// Deliberately not by ping. A probe measures the *underlay* path to an
/// exit's transport, which is not the path this traffic takes (client →
/// attached relay → mesh → exit), and RTT jitter would reshuffle the
/// choice — while changing exits costs a fresh end-to-end handshake and a
/// visible gap. Stability is worth more here than a few milliseconds.
/// Failing all that, the lowest node id, so the choice is deterministic.
///
/// Nothing here is sticky — this is recomputed from the view on every
/// reconcile, so the preference is restored by itself the moment the
/// preferred node is online and owning the default again.
///
/// `None` means no usable exit for this family — the caller must withhold
/// its catch-all so route-all cannot blackhole.
pub fn exit_gateway(view: &Snapshot, via: Option<&str>, attached: Option<NodeId>, v6: bool) -> Option<NodeId> {
    let default: IpNet = if v6 { "::/0" } else { "0.0.0.0/0" }.parse().unwrap();
    let owns_default =
        |m: &nqvpn_proto::control::PeerInfo| m.online && m.prefixes.iter().any(|p| p.trunc() == default);
    let usable = |id: NodeId| view.members.iter().any(|m| m.node_id == id && owns_default(m));
    via.and_then(|name| view.members.iter().find(|m| m.name == name && owns_default(m)).map(|m| m.node_id))
        .or_else(|| attached.filter(|id| usable(*id)))
        .or_else(|| view.members.iter().filter(|m| owns_default(m)).map(|m| m.node_id).min())
}

/// The route-all decision for both families at once: which catch-all
/// halves to install in the OS table (they point at the TUN), and which
/// exit each family's otherwise-unrouted traffic is sealed to.
///
/// A family needs a usable exit gateway; without one it is left on the
/// real default route (sealing to no exit would blackhole everything, and
/// that is the operator's choice of exits, not a failure). With an exit,
/// the family is activated when its pins hold — and, **failing closed**,
/// also when they do not, as long as the tunnel survives it:
///
///  * every host of the family pinned: activated;
///  * only resolvers failed to pin: activated anyway. Leaving the family
///    on the real default route would leak *all* of its traffic (the
///    classic IPv6 leak) to save one resolver path; DNS to that resolver
///    now enters the tunnel and goes out the exit instead;
///  * a transport host (coordinator, relay) failed to pin: activated only
///    if the *other* family carries a complete, pinned transport. Its
///    unpinned addresses of this family then break visibly — dialing
///    falls through to the other family's addresses — instead of this
///    family's traffic leaking. With no such fallback, activating would
///    cut the tunnel's own path, so the family is withheld (and the caller
///    warns loudly).
///
/// `transport` are the coordinator/relay addresses; `to_pin` is
/// everything that needed a pin (transport plus resolvers, minus what a
/// connected route already carries); `pinned` is what got one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RouteAllPlan {
    /// Catch-all halves to add to the OS routing table.
    pub nets: Vec<IpNet>,
    /// `(is_v6, exit node)` defaults to assert in the in-VPN routing table.
    pub exits: Vec<(bool, NodeId)>,
    /// Families activated although some of their hosts could not be
    /// pinned (fail closed): traffic to those hosts now enters the tunnel.
    pub failed_closed: Vec<bool>,
}

pub fn route_all_plan(
    view: &Snapshot,
    via: Option<&str>,
    attached: Option<NodeId>,
    transport: &[IpAddr],
    to_pin: &[IpAddr],
    pinned: &[IpAddr],
) -> RouteAllPlan {
    let unpinned = |v6: bool| to_pin.iter().filter(move |ip| ip.is_ipv6() == v6 && !pinned.contains(ip));
    let transport_lost = |v6: bool| unpinned(v6).any(|ip| transport.contains(ip));
    // A family's transport is complete off-tunnel when it has some, and
    // every one of them is pinned or carried by a connected route.
    let transport_whole = |v6: bool| {
        let mut fam = transport.iter().filter(|ip| ip.is_ipv6() == v6).peekable();
        fam.peek().is_some() && fam.all(|ip| !to_pin.contains(ip) || pinned.contains(ip))
    };
    let mut plan = RouteAllPlan::default();
    for v6 in [false, true] {
        let Some(node) = exit_gateway(view, via, attached, v6) else { continue };
        let safe = !transport_lost(v6) || transport_whole(!v6);
        if safe {
            plan.nets.extend(catch_all_halves(v6));
            plan.exits.push((v6, node));
            if unpinned(v6).next().is_some() {
                plan.failed_closed.push(v6);
            }
        }
    }
    plan
}

/// Routes the view says this node should have, before local exclusion.
pub fn wanted_routes(view: &Snapshot, my_node_id: NodeId, mine: &[IpNet]) -> Vec<IpNet> {
    wanted(view, my_node_id, mine, None)
}

/// `wanted_routes` with a route policy: a reserved or member prefix the
/// policy refuses is not routed (see [`refused_prefixes`] for what and
/// why). The member's own /32 under a refused reserved range is then
/// routed by itself if the policy permits it, so a peer the policy allows
/// stays reachable when its covering range is refused.
pub fn wanted_routes_with(view: &Snapshot, my_node_id: NodeId, mine: &[IpNet], policy: &RoutePolicy) -> Vec<IpNet> {
    wanted(view, my_node_id, mine, Some(policy))
}

/// Every published prefix — reserved, or a member's — that `policy`
/// refuses, with the member that published it (`None` for a reserved
/// prefix) and the reason. Exit markers are never refused here.
pub fn refused_prefixes(view: &Snapshot, my_node_id: NodeId, policy: &RoutePolicy) -> Vec<(IpNet, Option<NodeId>, &'static str)> {
    let mut out: Vec<(IpNet, Option<NodeId>, &'static str)> = view
        .reserved_prefixes
        .iter()
        .filter_map(|p| policy.refusal(&p.trunc()).map(|why| (p.trunc(), None, why)))
        .collect();
    for m in view.members.iter().filter(|m| m.node_id != my_node_id) {
        for p in &m.prefixes {
            if let Some(why) = policy.refusal(&p.trunc()) {
                out.push((p.trunc(), Some(m.node_id), why));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn wanted(view: &Snapshot, my_node_id: NodeId, mine: &[IpNet], policy: Option<&RoutePolicy>) -> Vec<IpNet> {
    let permitted = |p: &IpNet| policy.map(|pol| pol.permits(p)).unwrap_or(true);
    let mut set: BTreeSet<IpNet> = view.reserved_prefixes.iter().map(|p| p.trunc()).filter(|p| permitted(p)).collect();
    let covers: Vec<IpNet> = set.iter().copied().collect();
    for m in &view.members {
        if m.node_id == my_node_id {
            continue;
        }
        // Member /32 and /128 prefixes remain in the in-tunnel LPM table
        // so packets select the right peer, but every member address is
        // now inside a reserved network CIDR. The host routing table needs
        // only that covering CIDR, not one route per member.
        //
        // A member's default is the internet-exit marker, never a route:
        // route-all installs its own catch-all halves when it chooses an
        // exit, and nobody else wants the internet in the tunnel.
        for prefix in m.prefixes.iter().filter(|p| !crate::peers::is_exit_marker(p)).map(|p| p.trunc()).filter(|p| permitted(p)) {
            if !covers.iter().any(|cover| cover.contains(&prefix)) {
                set.insert(prefix);
            }
        }
    }
    // Never route our own space into the tunnel: our host addresses live
    // on the device, and a gateway's own LAN is the wire behind it. A
    // wider prefix that merely contains something of ours is fine — the
    // kernel prefers our more specific connected route for that part.
    //
    // An internet exit owns the default (`0.0.0.0/0` / `::/0`), which
    // "contains" every member prefix — but the default is the space
    // *behind* us, not ours. Replies from the internet (and from our own
    // address) to a member must still enter the tunnel, so the default
    // never excludes anything.
    set.retain(|w| !mine.iter().any(|m| m.prefix_len() > 0 && m.contains(w)));
    set.into_iter().collect()
}

/// Why a wanted prefix must not be installed, if it must not.
pub fn exclusion_reason(w: &IpNet, local: &[IpNet], underlay: &[IpAddr]) -> Option<String> {
    for l in local {
        // Equal to, or a slice of, a connected network: the TUN route
        // would win over (or tie with) the LAN and steal it.
        if l.contains(w) {
            return Some(format!("inside local interface prefix {l}"));
        }
    }
    for u in underlay {
        let protected = local.iter().any(|l| l.contains(u) && l.prefix_len() > w.prefix_len());
        if w.contains(u) && !protected {
            return Some(format!("would capture underlay address {u}"));
        }
    }
    None
}

/// Split wanted routes into installable and excluded (with reasons).
pub fn exclude_local(
    wanted: Vec<IpNet>,
    local: &[IpNet],
    underlay: &[IpAddr],
) -> (Vec<IpNet>, Vec<(IpNet, String)>) {
    let mut keep = Vec::new();
    let mut out = Vec::new();
    for w in wanted {
        match exclusion_reason(&w, local, underlay) {
            Some(r) => out.push((w, r)),
            None => keep.push(w),
        }
    }
    (keep, out)
}

/// Applies a wanted set to whatever programmer it is given, by diff.
pub struct RouteSet<P: RouteProgrammer> {
    programmer: P,
    installed: Mutex<BTreeSet<IpNet>>,
    /// The last (wanted, mine) applied, so `reassert` can re-run the
    /// kernel reconcile without the caller repeating them.
    last: Mutex<(Vec<IpNet>, Vec<IpNet>)>,
    /// Our own addresses when the routes on the device were programmed.
    /// `None` until the first reconcile.
    bound_to: Mutex<Option<BTreeSet<IpNet>>>,
}

impl<P: RouteProgrammer> RouteSet<P> {
    pub fn new(programmer: P) -> Self {
        RouteSet {
            programmer,
            installed: Mutex::new(BTreeSet::new()),
            last: Mutex::new((Vec::new(), Vec::new())),
            bound_to: Mutex::new(None),
        }
    }

    /// Did our own addresses change since the routes were programmed?
    /// A route on the device is bound to them: macOS and the BSDs record
    /// the interface address a route is added under and source traffic
    /// from it for as long as the route lives, even after that address
    /// is gone, so locally originated packets leave with the old address
    /// and every peer drops them as spoofed. Linux picks the source at
    /// send time, but re-programming there is harmless and keeps one
    /// rule for every platform: a change of address re-binds every route.
    fn readdressed(&self, mine: &BTreeSet<IpNet>) -> bool {
        let mut bound = self.bound_to.lock().unwrap();
        let changed = bound.as_ref().is_some_and(|b| b != mine);
        *bound = Some(mine.clone());
        changed
    }

    /// Pin the underlay transport hosts to the real gateway (route-all).
    /// Delegates to the programmer; returns those actually pinned.
    pub fn pin_underlay(&self, ips: &[IpAddr]) -> Result<Vec<IpAddr>> {
        self.programmer.pin_underlay(ips)
    }

    /// Reconcile against the **kernel's** own view of our device — the
    /// path used in production.
    ///
    /// Ownership is structural (a route on our TUN is ours), with the
    /// single exception of the kernel's connected routes for our own
    /// addresses (`mine`), which we exclude:
    ///
    ///   ours   = routes on our dev  −  mine
    ///   remove = ours    − wanted
    ///   add    = wanted  − present
    ///
    /// Self-healing: the diff is against reality, not a cache, so a
    /// route another writer deleted reappears and a stale one is
    /// removed. Returns `Ok(false)` when the table cannot be read (the
    /// recording programmer), so the caller can fall back to `reconcile`.
    pub fn reconcile_via_kernel(&self, wanted: &[IpNet], mine: &[IpNet]) -> Result<bool> {
        *self.last.lock().unwrap() = (wanted.to_vec(), mine.to_vec());
        let Some(present) = self.programmer.list_via_dev() else {
            return Ok(false);
        };
        let wanted: BTreeSet<IpNet> = wanted.iter().map(|n| n.trunc()).collect();
        let mine: BTreeSet<IpNet> = mine.iter().map(|n| n.trunc()).collect();
        let mut ours: BTreeSet<IpNet> =
            present.into_iter().map(|n| n.trunc()).filter(|n| !mine.contains(n)).collect();

        let (mut added, mut removed, mut failed) = (0u32, 0u32, 0u32);
        if self.readdressed(&mine) && !ours.is_empty() {
            // Everything on the device goes and what is wanted comes back,
            // bound to the addresses we hold now.
            tracing::info!(target: "nqvpn::os_routes", routes = ours.len(), "our addresses changed; re-binding every route on the device");
            for net in std::mem::take(&mut ours) {
                if let Err(e) = self.programmer.remove(net) {
                    tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route remove failed: {e:#}");
                }
            }
        }
        for net in ours.difference(&wanted) {
            match self.programmer.remove(*net) {
                Ok(()) => {
                    removed += 1;
                    tracing::info!(target: "nqvpn::os_routes", prefix = %net, "os route removed");
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route remove failed: {e:#}");
                }
            }
        }
        let mut first_err = None;
        for net in wanted.difference(&ours) {
            // Idempotent add, so a route that reappeared between the read
            // and now is not an error.
            match self.programmer.add_via_tun(*net) {
                Ok(()) => {
                    added += 1;
                    tracing::info!(target: "nqvpn::os_routes", prefix = %net, "os route added");
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route add failed: {e:#}");
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if added + removed + failed > 0 {
            tracing::info!(
                target: "nqvpn::os_routes",
                added, removed, failed,
                total = wanted.len(),
                "os routing table reconciled (against the kernel)"
            );
        }
        *self.installed.lock().unwrap() = wanted;
        match first_err {
            Some(e) => Err(e),
            None => Ok(true),
        }
    }

    /// Re-run the kernel reconcile with the last desired set. Returns
    /// `Ok(false)` when the table cannot be read.
    pub fn reassert_via_kernel(&self) -> Result<bool> {
        let (wanted, mine) = self.last.lock().unwrap().clone();
        self.reconcile_via_kernel(&wanted, &mine)
    }

    /// Make the kernel hold exactly `wanted`: add what is missing, remove
    /// what is extra. A removal that fails because the route is already
    /// gone is not an error; an add that fails is, and leaves the set
    /// consistent (the route is not recorded as installed).
    ///
    /// `mine` are our own addresses: when they change, every installed
    /// route is re-bound (see `readdressed`).
    pub fn reconcile(&self, wanted: &[IpNet], mine: &[IpNet]) -> Result<()> {
        let wanted: BTreeSet<IpNet> = wanted.iter().map(|n| n.trunc()).collect();
        let mine: BTreeSet<IpNet> = mine.iter().map(|n| n.trunc()).collect();
        let mut installed = self.installed.lock().unwrap();
        if self.readdressed(&mine) && !installed.is_empty() {
            tracing::info!(target: "nqvpn::os_routes", routes = installed.len(), "our addresses changed; re-binding every route on the device");
            for net in std::mem::take(&mut *installed) {
                if let Err(e) = self.programmer.remove(net) {
                    tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route remove failed: {e:#}");
                }
            }
        }
        let extra: Vec<IpNet> = installed.difference(&wanted).copied().collect();
        let (mut added, mut removed, mut failed) = (0u32, 0u32, 0u32);
        for net in extra {
            match self.programmer.remove(net) {
                Ok(()) => tracing::info!(target: "nqvpn::os_routes", prefix = %net, "os route removed"),
                Err(e) => tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route remove failed: {e:#}"),
            }
            removed += 1;
            installed.remove(&net);
        }
        let missing: Vec<IpNet> = wanted.difference(&installed).copied().collect();
        let mut first_err = None;
        for net in missing {
            match self.programmer.add_via_tun(net) {
                Ok(()) => {
                    added += 1;
                    tracing::info!(target: "nqvpn::os_routes", prefix = %net, "os route added");
                    installed.insert(net);
                }
                Err(e) => {
                    failed += 1;
                    tracing::warn!(target: "nqvpn::os_routes", prefix = %net, "os route add failed: {e:#}");
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
        }
        if added + removed + failed > 0 {
            tracing::info!(
                target: "nqvpn::os_routes",
                added, removed, failed,
                total = wanted.len(),
                "os routing table reconciled (cache)"
            );
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Re-program every route we believe we own, whether or not our
    /// cache thinks it is already there. `reconcile` diffs against that
    /// cache, which assumes we are the only writer; a second endpoint on
    /// the host, an admin, or a vanishing TUN can all prove it wrong.
    pub fn reassert(&self) -> Result<()> {
        let installed: Vec<IpNet> = self.installed.lock().unwrap().iter().copied().collect();
        for net in installed {
            self.programmer.add_via_tun(net)?;
        }
        Ok(())
    }

    pub fn installed(&self) -> Vec<IpNet> {
        self.installed.lock().unwrap().iter().copied().collect()
    }
}

/// On a graceful shutdown, best-effort remove the routes we installed so
/// the table is left clean. This is a backstop, not the primary path: a
/// process killed outright never runs Drop, and there the kernel drops
/// every route via our TUN when the device's fd closes on death.
impl<P: RouteProgrammer> Drop for RouteSet<P> {
    fn drop(&mut self) {
        let installed: Vec<IpNet> = self.installed.lock().unwrap().iter().copied().collect();
        if installed.is_empty() {
            return;
        }
        let mut removed = 0u32;
        for net in &installed {
            if self.programmer.remove(*net).is_ok() {
                removed += 1;
            }
        }
        tracing::info!(target: "nqvpn::os_routes", removed, total = installed.len(), "removed our routes on shutdown");
    }
}

/// Change a live TUN device's MTU.
pub fn set_device_mtu(device: &str, mtu: u16) -> Result<()> {
    let mtu_s = mtu.to_string();
    #[cfg(target_os = "linux")]
    let args = ["ip", "link", "set", "dev", device, "mtu", mtu_s.as_str()];
    #[cfg(target_os = "macos")]
    let args = ["ifconfig", device, "mtu", mtu_s.as_str()];
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let args: Vec<&str> = {
        let _ = (device, &mtu_s);
        anyhow::bail!("setting MTU is not implemented on this platform")
    };
    let out = std::process::Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        anyhow::bail!("{} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// Records calls instead of touching the kernel — CI and `--dry-run`.
#[derive(Debug, Default)]
pub struct RecordingProgrammer {
    pub calls: Mutex<Vec<String>>,
    /// A simulated kernel table for exercising `reconcile_via_kernel`;
    /// `None` (the default) means "readback unsupported".
    pub kernel: Mutex<Option<BTreeSet<IpNet>>>,
}

impl RecordingProgrammer {
    /// A recorder whose simulated kernel starts holding `initial` and
    /// tracks every add/remove, so `list_via_dev` reflects reality.
    pub fn with_kernel(initial: &[IpNet]) -> Self {
        RecordingProgrammer {
            calls: Mutex::new(Vec::new()),
            kernel: Mutex::new(Some(initial.iter().map(|n| n.trunc()).collect())),
        }
    }

    pub fn kernel_now(&self) -> Option<Vec<IpNet>> {
        self.kernel.lock().unwrap().as_ref().map(|s| s.iter().copied().collect())
    }
}

impl RouteProgrammer for RecordingProgrammer {
    fn add_via_tun(&self, net: IpNet) -> Result<()> {
        self.calls.lock().unwrap().push(format!("add {net}"));
        if let Some(k) = self.kernel.lock().unwrap().as_mut() {
            k.insert(net.trunc());
        }
        Ok(())
    }
    fn remove(&self, net: IpNet) -> Result<()> {
        self.calls.lock().unwrap().push(format!("remove {net}"));
        if let Some(k) = self.kernel.lock().unwrap().as_mut() {
            k.remove(&net.trunc());
        }
        Ok(())
    }
    fn list_via_dev(&self) -> Option<Vec<IpNet>> {
        self.kernel_now()
    }
}

/// Programs and reads the OS routing table through the `route_manager`
/// crate (Linux netlink, macOS/BSD PF_ROUTE, Windows IP Helper) — no
/// shelling out and no CLI parsing. The crate is synchronous, so this is
/// just a `RouteManager` behind a lock. Every route is bound to our TUN
/// by interface, which is also how `list_via_dev` selects what is ours.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub struct NetRouteProgrammer {
    /// Empty until `set_device`: a programmer is opened before the TUN
    /// exists so a dead predecessor's pins can be removed before the join
    /// that needs the underlay reachable.
    device: Mutex<String>,
    mgr: Mutex<route_manager::RouteManager>,
    /// Underlay host routes we added via the real gateway (route-all), so
    /// we can reconcile and tear them down. ip -> the gateway used.
    pinned: Mutex<PinJournal>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl NetRouteProgrammer {
    /// Open the table for `device`, with no pin journal (the pins live and
    /// die with the process — fine for a relay, which pins nothing).
    pub fn new(device: String) -> Result<Self> {
        let p = Self::open(PinJournal::in_memory())?;
        p.set_device(&device);
        Ok(p)
    }

    /// Open the table with a pin journal and, before anything else, remove
    /// every pin a previous run left behind in it: a run that exits
    /// cleanly leaves no journal, so any entry here is from a process that
    /// died without its teardown. This is `reconcile_pins` with an empty
    /// want set — the ordinary "no longer wanted" rule — not a separate
    /// cleanup path. The device is set later, once the TUN exists.
    pub fn open(journal: PinJournal) -> Result<Self> {
        let mgr = route_manager::RouteManager::new()
            .map_err(|e| anyhow::anyhow!("opening the OS routing table: {e}"))?;
        let p = NetRouteProgrammer { device: Mutex::new(String::new()), mgr: Mutex::new(mgr), pinned: Mutex::new(journal) };
        {
            let mut pinned = p.pinned.lock().unwrap();
            if !pinned.is_empty() {
                tracing::warn!(
                    target: "nqvpn::os_routes",
                    pins = pinned.len(),
                    "a previous run did not exit cleanly and left underlay pins behind; removing them"
                );
                reconcile_pins(&p, &[], &mut pinned);
            }
        }
        Ok(p)
    }

    /// Name the TUN whose routes this programmer owns.
    pub fn set_device(&self, device: &str) {
        *self.device.lock().unwrap() = device.to_string();
    }

    fn device(&self) -> String {
        self.device.lock().unwrap().clone()
    }

    /// The current default route's gateway — and the interface it is
    /// reached through — for a family, ignoring any default that points
    /// at our own TUN or lives in a policy-routing table. With several
    /// defaults (wired and wifi), the one the kernel prefers: lowest
    /// metric on Linux. `None` if there is none.
    fn current_default_gateway(&self, v6: bool) -> Option<Gateway> {
        let mytun = self.ifindex();
        let routes = self.mgr.lock().unwrap().list().ok()?;
        let candidates = routes.into_iter().filter(|r| {
            r.prefix() == 0 && r.destination().is_ipv6() == v6 && r.gateway().is_some() && in_main_table(r) && !self.ours(r, mytun)
        });
        #[cfg(target_os = "linux")]
        let best = candidates.min_by_key(|r| r.metric().unwrap_or(0));
        #[cfg(not(target_os = "linux"))]
        let best = { let mut c = candidates; c.next() };
        best.and_then(|r| Some(Gateway::new(r.gateway()?, r.if_index())))
    }

    /// Our TUN's kernel interface index, resolved fresh each call so a
    /// device that did not exist at construction, or was renamed, is
    /// still matched as long as the name is stable. `None` means the
    /// device is gone (its routes went with it).
    fn ifindex(&self) -> Option<u32> {
        let device = self.device();
        if device.is_empty() {
            return None;
        }
        let c = std::ffi::CString::new(device).ok()?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (idx != 0).then_some(idx)
    }

    fn route(&self, net: IpNet) -> route_manager::Route {
        let mut r = route_manager::Route::new(net.addr(), net.prefix_len());
        match self.ifindex() {
            Some(i) => r = r.with_if_index(i),
            None => r = r.with_if_name(self.device()),
        }
        r
    }

    /// Is this kernel route one on our device?
    fn ours(&self, r: &route_manager::Route, idx: Option<u32>) -> bool {
        let device = self.device();
        (!device.is_empty() && r.if_name().map(|n| n == &device).unwrap_or(false)) || (idx.is_some() && r.if_index() == idx)
    }

    /// Does the kernel hold exactly this host route via exactly this
    /// gateway (and interface, when we know it)? `None` when the table
    /// cannot be read.
    fn has_host_route(&self, ip: IpAddr, gw: Gateway) -> Option<bool> {
        let bits = if ip.is_ipv6() { 128 } else { 32 };
        let routes = self.mgr.lock().unwrap().list().ok()?;
        Some(routes.iter().any(|r| {
            r.destination() == ip
                && r.prefix() == bits
                && r.gateway() == Some(gw.addr)
                && (gw.ifindex.is_none() || r.if_index() == gw.ifindex)
        }))
    }
}

/// Is this kernel route in the main table? Linux keeps the kernel's
/// `local`/`broadcast`/multicast entries for every interface — ours
/// included — in the `local` table, and policy routing (VPNs, containers)
/// adds defaults in tables of its own; none of those are routes we own,
/// nor the default the host actually uses. `route_manager` reports the
/// table but not the route type, so the type is filtered by prefix
/// (`kernel_housekeeping`). macOS and the BSDs have one table, and
/// `route_manager` already drops their local/broadcast entries.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn in_main_table(r: &route_manager::Route) -> bool {
    #[cfg(target_os = "linux")]
    {
        const RT_TABLE_MAIN: u8 = 254;
        r.table() == RT_TABLE_MAIN
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = r;
        true
    }
}

/// Routes the kernel itself keeps on any interface — multicast
/// (`224.0.0.0/4`, `ff00::/8`) and IPv6 link-local (`fe80::/10`) — which
/// we never install and must never remove as "stale".
pub fn kernel_housekeeping(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.addr().is_multicast(),
        IpNet::V6(n) => n.addr().is_multicast() || (n.addr().segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// A `/32` or `/128` host route for `ip` via `gw`, bound to the
/// gateway's interface when known — without it Linux refuses a
/// link-local (`fe80::`) gateway, which is what nearly every IPv6
/// default route has.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn host_route(ip: IpAddr, gw: Gateway) -> route_manager::Route {
    let bits = if ip.is_ipv6() { 128 } else { 32 };
    let mut r = route_manager::Route::new(ip, bits).with_gateway(gateway_for_kernel(gw));
    if let Some(i) = gw.ifindex {
        r = r.with_if_index(i);
    }
    r
}

/// The gateway address as the routing socket expects it. macOS (KAME)
/// carries a link-local address's scope inside the address itself, in
/// bytes 2–3, which is what `route add -inet6 … fe80::1%en0` sends;
/// `route_manager` strips it on the way back in, so readback compares
/// against the plain address. Linux takes the interface separately.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn gateway_for_kernel(gw: Gateway) -> IpAddr {
    #[cfg(target_os = "macos")]
    if let (IpAddr::V6(a), Some(idx)) = (gw.addr, gw.ifindex) {
        let s = a.segments();
        if (s[0] & 0xffc0) == 0xfe80 && idx <= u16::MAX as u32 {
            return IpAddr::V6(std::net::Ipv6Addr::new(s[0], idx as u16, s[2], s[3], s[4], s[5], s[6], s[7]));
        }
    }
    gw.addr
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RouteProgrammer for NetRouteProgrammer {
    fn add_via_tun(&self, net: IpNet) -> Result<()> {
        let r = self.route(net.trunc());
        match self.mgr.lock().unwrap().add(&r) {
            Ok(()) => Ok(()),
            // Idempotent: a route that already exists is fine.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(anyhow::anyhow!("adding route {net}: {e}")),
        }
    }
    fn remove(&self, net: IpNet) -> Result<()> {
        let r = self.route(net.trunc());
        // Deleting an already-absent route is not an error.
        let _ = self.mgr.lock().unwrap().delete(&r);
        Ok(())
    }
    fn list_via_dev(&self) -> Option<Vec<IpNet>> {
        let idx = self.ifindex();
        let routes = self.mgr.lock().unwrap().list().ok()?;
        Some(
            routes
                .into_iter()
                .filter(|r| self.ours(r, idx) && r.gateway().is_none() && in_main_table(r))
                .filter_map(|r| IpNet::new(r.destination(), r.prefix()).ok().map(|n| n.trunc()))
                .filter(|n| !kernel_housekeeping(n))
                .collect(),
        )
    }

    fn pin_underlay(&self, ips: &[IpAddr]) -> Result<Vec<IpAddr>> {
        let mut pinned = self.pinned.lock().unwrap();
        Ok(reconcile_pins(self, ips, &mut pinned))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl HostRouteTable for NetRouteProgrammer {
    fn default_gateway(&self, v6: bool) -> Option<Gateway> {
        self.current_default_gateway(v6)
    }
    fn add_host_route(&self, ip: IpAddr, gw: Gateway) -> std::io::Result<bool> {
        match self.mgr.lock().unwrap().add(&host_route(ip, gw)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => Err(e),
        }
    }
    fn del_host_route(&self, ip: IpAddr, gw: Gateway) {
        // Only the exact pair we recorded. A route to the same host via
        // another gateway is someone else's (or the kernel already replaced
        // ours when the network changed) and is left alone; the BSD delete
        // matches on destination, so this check is what makes that true.
        if self.has_host_route(ip, gw) == Some(false) {
            return;
        }
        let _ = self.mgr.lock().unwrap().delete(&host_route(ip, gw));
    }
}

/// Clean teardown: every pin is now unwanted, so the same reconcile that
/// added them removes them and empties the journal (which deletes the
/// file). A process that never gets here leaves the journal for `open`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for NetRouteProgrammer {
    fn drop(&mut self) {
        let mut pinned = self.pinned.lock().unwrap();
        if pinned.is_empty() {
            return;
        }
        let n = pinned.len();
        reconcile_pins(self, &[], &mut pinned);
        tracing::info!(target: "nqvpn::os_routes", pins = n, "removed our underlay pins on shutdown");
    }
}

/// Where there is no TUN backend there is no route backend either, and
/// nothing to program: opening one fails, so this type is never
/// constructed and its methods are provably unreachable. Callers stay the
/// same on every platform.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub enum NetRouteProgrammer {}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl NetRouteProgrammer {
    pub fn new(_device: String) -> Result<Self> {
        anyhow::bail!("this platform has no route backend yet")
    }
    pub fn open(_journal: PinJournal) -> Result<Self> {
        anyhow::bail!("this platform has no route backend yet; use --dry-run")
    }
    pub fn set_device(&self, _device: &str) {
        match *self {}
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl RouteProgrammer for NetRouteProgrammer {
    fn add_via_tun(&self, _net: IpNet) -> Result<()> {
        match *self {}
    }
    fn remove(&self, _net: IpNet) -> Result<()> {
        match *self {}
    }
}

impl RouteSet<RecordingProgrammer> {
    /// Every add/remove issued so far, in order (for harnesses).
    pub fn recorded_calls(&self) -> Vec<String> {
        self.programmer.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
impl RouteSet<RecordingProgrammer> {
    fn programmer_kernel(&self) -> BTreeSet<IpNet> {
        self.programmer.kernel.lock().unwrap().clone().unwrap_or_default()
    }
    fn programmer_kernel_remove(&self, net: IpNet) {
        if let Some(k) = self.programmer.kernel.lock().unwrap().as_mut() {
            k.remove(&net.trunc());
        }
    }
    fn programmer_calls(&self) -> Vec<String> {
        self.programmer.calls.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nqvpn_proto::control::{NetworkMtu, PeerInfo};
    use nqvpn_proto::types::Role;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn route_all_pins_only_underlay_not_carried_by_a_local_route() {
        // The coordinator/relay on the public internet need pinning; a
        // relay that sits on our own LAN is already carried by the
        // connected route and must NOT be pinned via the gateway.
        let underlay = [ip("203.0.113.7"), ip("192.168.1.9"), ip("2001:db8::5")];
        let local = [net("192.168.1.0/24"), net("10.0.0.5/32")];
        let to_pin = underlay_to_pin(&underlay, &local);
        assert_eq!(to_pin, vec![ip("203.0.113.7"), ip("2001:db8::5")], "LAN-local underlay is left to its connected route");
    }

    #[test]
    fn exit_gateway_requires_an_online_owner_of_the_default() {
        let mut s = view(); // node 3 = "gw", a relay; no default owner yet
        assert_eq!(exit_gateway(&s, None, None, false), None, "no default owner, no exit");
        // Make the relay front the v4 default: it becomes an internet exit.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.push(net("0.0.0.0/0"));
        assert_eq!(exit_gateway(&s, None, None, false), Some(3));
        assert_eq!(exit_gateway(&s, None, None, true), None, "it owns no v6 default");
        // An offline owner is not a candidate.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().online = false;
        assert_eq!(exit_gateway(&s, None, None, false), None, "offline exits do not count");
    }

    #[test]
    fn via_selects_the_named_exit_among_several_and_rejects_a_non_owner() {
        let mut s = view();
        // Two nodes own the v4 default (names: 2 = "b", 3 = "gw").
        for id in [2, 3] {
            s.members.iter_mut().find(|m| m.node_id == id).unwrap().prefixes.push(net("0.0.0.0/0"));
        }
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), Some(3), "the named exit wins over the lowest id");
        assert_eq!(exit_gateway(&s, None, None, false), Some(2), "no name: lowest id, deterministically");
        // --via is a preference: a name that is not a usable exit falls back
        // to one that is, rather than leaving the client with no internet.
        assert_eq!(exit_gateway(&s, Some("me"), None, false), Some(2), "a named non-owner falls back to a real exit");
        assert_eq!(exit_gateway(&s, Some("nope"), None, false), Some(2), "an unknown name falls back too");
    }

    #[test]
    fn with_no_preference_our_own_relay_is_the_exit_because_it_costs_no_mesh_hop() {
        // Both 2 ("b") and 3 ("gw") are exits; 3 is the relay we hold our
        // session to. Picking it means internet traffic terminates on the
        // node we are already talking to — no mesh link — where node-id
        // order would have sent it to 2 and paid a hop.
        let mut s = view();
        for id in [2, 3] {
            s.members.iter_mut().find(|m| m.node_id == id).unwrap().prefixes.push(net("0.0.0.0/0"));
        }
        assert_eq!(exit_gateway(&s, None, Some(3), false), Some(3), "our own relay, no hop");
        assert_eq!(exit_gateway(&s, None, None, false), Some(2), "unattached: lowest id, deterministic");
        // An attachment to a relay that is not an exit changes nothing.
        assert_eq!(exit_gateway(&s, None, Some(1), false), Some(2), "our relay is no exit: fall through");
        // A named preference still outranks our own relay.
        assert_eq!(exit_gateway(&s, Some("b"), Some(3), false), Some(2), "the operator's choice wins");
        // And our relay is only preferred while it really is a usable exit.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().online = false;
        assert_eq!(exit_gateway(&s, None, Some(3), false), Some(2), "offline: not an exit, hop or not");
    }

    #[test]
    fn a_preferred_exit_is_fallen_back_from_and_returned_to_by_itself() {
        // The operator prefers "gw"; "b" is the other exit. Losing the
        // preferred one must not cost the client its internet, and getting
        // it back must not need a restart or any sticky state.
        let mut s = view();
        for id in [2, 3] {
            s.members.iter_mut().find(|m| m.node_id == id).unwrap().prefixes.push(net("0.0.0.0/0"));
        }
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), Some(3), "preferred while it qualifies");

        // It goes offline (the coordinator stops vouching for it).
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().online = false;
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), Some(2), "falls back to the remaining exit");

        // Its default is withdrawn instead (an exit that stopped being ready).
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().online = true;
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.retain(|p| p.prefix_len() != 0);
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), Some(2), "owning no default is not an exit either");

        // Back online and owning the default again: the preference returns
        // on its own, because the choice is recomputed, never remembered.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.push(net("0.0.0.0/0"));
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), Some(3), "preference restores itself");

        // With no exit at all the caller still gets None and withholds.
        for id in [2, 3] {
            s.members.iter_mut().find(|m| m.node_id == id).unwrap().prefixes.retain(|p| p.prefix_len() != 0);
        }
        assert_eq!(exit_gateway(&s, Some("gw"), None, false), None, "no exits: nothing to fall back to");
    }

    #[test]
    fn route_all_plan_needs_both_a_pinned_transport_and_an_exit() {
        let mut s = view();
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.push(net("0.0.0.0/0"));
        let to_pin = [ip("203.0.113.7")];
        // Pinned transport + an exit -> the v4 halves and that exit.
        let p = route_all_plan(&s, Some("gw"), None, &to_pin, &to_pin, &to_pin);
        assert_eq!(p.nets, vec![net("0.0.0.0/1"), net("128.0.0.0/1")]);
        assert_eq!(p.exits, vec![(false, 3)]);
        // Transport not pinned -> nothing at all, even with an exit, so
        // route-all never severs the tunnel's own path.
        let p = route_all_plan(&s, Some("gw"), None, &to_pin, &to_pin, &[]);
        assert_eq!(p, RouteAllPlan::default());
        // The preferred node is not a usable exit -> fall back to one that
        // is, rather than leaving the client with no internet at all.
        let p = route_all_plan(&s, Some("nope"), None, &to_pin, &to_pin, &to_pin);
        assert_eq!(p.exits, vec![(false, 3)], "--via is a preference, not a pin");
        // Nothing owns a default anywhere -> withheld (no blackhole).
        let p = route_all_plan(&view(), Some("gw"), None, &to_pin, &to_pin, &to_pin);
        assert_eq!(p, RouteAllPlan::default());
        // v4 has an exit, v6 does not: only v4 activates.
        let p = route_all_plan(&s, None, None, &to_pin, &to_pin, &to_pin);
        assert_eq!(p.exits, vec![(false, 3)], "the v6 family is left alone");
    }

    fn view() -> Snapshot {
        let mut s = Snapshot {
            gen: 1,
            members: vec![
                PeerInfo { node_id: 1, name: "me".into(), role: Role::Client, prefixes: vec![net("10.99.1.1/32")], pubkey: String::new(), online: true, login_gen: 0 },
                PeerInfo { node_id: 2, name: "b".into(), role: Role::Client, prefixes: vec![net("10.99.1.2/32")], pubkey: String::new(), online: true, login_gen: 0 },
                PeerInfo { node_id: 3, name: "gw".into(), role: Role::Relay, prefixes: vec![net("10.99.0.1/32"), net("192.168.7.0/24")], pubkey: String::new(), online: true, login_gen: 0 },
            ],
            attachments: vec![],
            relays: vec![],
            mtu: NetworkMtu { mtu: 1350, limited_by: "config".into() },
            keys: vec![],
            reserved_prefixes: vec![net("10.99.0.0/16"), net("192.168.7.0/24"), net("192.168.9.0/24")],
        };
        s.normalize();
        s
    }

    #[test]
    fn a_published_default_is_an_exit_marker_never_an_os_route() {
        // gw is an internet exit. A client that did not ask for route-all
        // must not be handed the internet as a tunnel route — it would
        // either capture the underlay or be refused with a warning on
        // every reconcile. Route-all adds its own catch-all halves.
        let mut s = view();
        let gw = s.members.iter_mut().find(|m| m.node_id == 3).unwrap();
        gw.prefixes.extend([net("0.0.0.0/0"), net("::/0")]);
        let w = wanted_routes(&s, 1, &[net("10.99.1.1/32")]);
        assert!(w.iter().all(|p| p.prefix_len() != 0), "no default in the wanted set, got {w:?}");
        assert!(w.contains(&net("192.168.7.0/24")), "the exit's real LAN is still routed");
    }

    #[test]
    fn wanted_is_a_function_of_the_view_minus_my_own_space() {
        let w = wanted_routes(&view(), 1, &[net("10.99.1.1/32")]);
        assert!(w.contains(&net("10.99.0.0/16")), "covering tunnel route");
        assert!(w.contains(&net("192.168.9.0/24")), "a reserved but unowned site stays blackholed into the tunnel");
        assert!(!w.contains(&net("10.99.1.2/32")), "the covering tunnel CIDR makes per-member OS routes redundant");
        assert!(!w.contains(&net("10.99.1.1/32")), "never my own host address");
        // A gateway never routes its own LAN into the tunnel, even when
        // another node currently owns it.
        let gw = wanted_routes(&view(), 9, &[net("10.99.0.4/32"), net("192.168.7.0/24")]);
        assert!(!gw.contains(&net("192.168.7.0/24")));
        assert!(gw.contains(&net("192.168.9.0/24")));
    }

    /// A routing table that records what was asked of it. `preexisting`
    /// are host routes the machine already had, which we must never claim.
    struct FakeTable {
        gw: Mutex<Option<IpAddr>>,
        preexisting: Mutex<BTreeSet<(IpAddr, IpAddr)>>,
        added: Mutex<Vec<(IpAddr, IpAddr)>>,
        deleted: Mutex<Vec<(IpAddr, IpAddr)>>,
        /// When set, every add/del also records whether the journal file
        /// listed the pair *at that instant* — the write-ahead invariant.
        journal: Option<std::path::PathBuf>,
        journaled_at_add: Mutex<Vec<bool>>,
        journaled_at_del: Mutex<Vec<bool>>,
    }

    impl FakeTable {
        fn with_gateway(gw: &str) -> Self {
            FakeTable {
                gw: Mutex::new(Some(ip(gw))),
                preexisting: Mutex::new(BTreeSet::new()),
                added: Mutex::new(Vec::new()),
                deleted: Mutex::new(Vec::new()),
                journal: None,
                journaled_at_add: Mutex::new(Vec::new()),
                journaled_at_del: Mutex::new(Vec::new()),
            }
        }
        fn watching(mut self, journal: &std::path::Path) -> Self {
            self.journal = Some(journal.to_path_buf());
            self
        }
        fn journal_lists(&self, i: IpAddr, gw: IpAddr) -> bool {
            let Some(p) = &self.journal else { return false };
            std::fs::read_to_string(p).unwrap_or_default().lines().any(|l| l.trim() == format!("{i} {gw}"))
        }
    }

    impl HostRouteTable for FakeTable {
        fn default_gateway(&self, _v6: bool) -> Option<Gateway> {
            self.gw.lock().unwrap().map(Gateway::from)
        }
        fn add_host_route(&self, i: IpAddr, gw: Gateway) -> std::io::Result<bool> {
            self.journaled_at_add.lock().unwrap().push(self.journal_lists(i, gw.addr));
            if self.preexisting.lock().unwrap().contains(&(i, gw.addr)) {
                return Ok(false);
            }
            self.added.lock().unwrap().push((i, gw.addr));
            Ok(true)
        }
        fn del_host_route(&self, i: IpAddr, gw: Gateway) {
            self.journaled_at_del.lock().unwrap().push(self.journal_lists(i, gw.addr));
            self.deleted.lock().unwrap().push((i, gw.addr));
        }
    }

    fn journal_lines(p: &std::path::Path) -> Vec<String> {
        std::fs::read_to_string(p).unwrap_or_default().lines().map(str::to_string).collect()
    }

    #[test]
    fn a_pin_follows_the_default_gateway_when_the_network_moves() {
        // The bug this exists for: a laptop that changes networks while the
        // client runs kept its pins on the old gateway, blackholing the
        // relays and resolvers — no crash needed.
        let t = FakeTable::with_gateway("192.168.1.1");
        let mut pinned = PinJournal::in_memory();
        let want = [ip("3.1.237.225"), ip("8.8.8.8")];
        let ok = reconcile_pins(&t, &want, &mut pinned);
        assert_eq!(ok.len(), 2);
        assert_eq!(pinned.get(&ip("8.8.8.8")), Some(ip("192.168.1.1").into()));

        // Same want set, new gateway: every pin is re-pointed, not skipped.
        *t.gw.lock().unwrap() = Some(ip("10.0.0.1"));
        let ok = reconcile_pins(&t, &want, &mut pinned);
        assert_eq!(ok.len(), 2);
        for host in want {
            assert!(t.deleted.lock().unwrap().contains(&(host, ip("192.168.1.1"))), "{host} unpinned from the old gateway");
            assert!(t.added.lock().unwrap().contains(&(host, ip("10.0.0.1"))), "{host} re-pinned to the new gateway");
            assert_eq!(pinned.get(&host), Some(ip("10.0.0.1").into()));
        }

        // Steady state: nothing is touched when the gateway is unchanged.
        let (a, d) = (t.added.lock().unwrap().len(), t.deleted.lock().unwrap().len());
        reconcile_pins(&t, &want, &mut pinned);
        assert_eq!((t.added.lock().unwrap().len(), t.deleted.lock().unwrap().len()), (a, d));
    }

    #[test]
    fn tearing_down_never_deletes_a_host_route_we_did_not_create() {
        // The host already routes this relay via the gateway. We may use it,
        // but it is not ours, so it must not be recorded and must survive us.
        let t = FakeTable::with_gateway("192.168.1.1");
        t.preexisting.lock().unwrap().insert((ip("3.1.237.225"), ip("192.168.1.1")));
        let mut pinned = PinJournal::in_memory();
        let ok = reconcile_pins(&t, &[ip("3.1.237.225"), ip("8.8.8.8")], &mut pinned);
        assert!(ok.contains(&ip("3.1.237.225")), "a route already in place still counts as reachable");
        assert!(!pinned.contains_key(&ip("3.1.237.225")), "not ours: never recorded, so never torn down");
        assert_eq!(pinned.keys().collect::<Vec<_>>(), vec![ip("8.8.8.8")], "only what we created");
    }

    #[test]
    fn a_relay_that_leaves_the_fleet_loses_its_pin() {
        let t = FakeTable::with_gateway("192.168.1.1");
        let mut pinned = PinJournal::in_memory();
        reconcile_pins(&t, &[ip("3.1.237.225"), ip("47.237.120.106")], &mut pinned);
        // A new snapshot drops one relay and adds another.
        let ok = reconcile_pins(&t, &[ip("3.1.237.225"), ip("43.230.99.31")], &mut pinned);
        assert!(t.deleted.lock().unwrap().contains(&(ip("47.237.120.106"), ip("192.168.1.1"))), "the departed relay is unpinned");
        assert!(ok.contains(&ip("43.230.99.31")), "a relay added later is pinned on the reconcile its snapshot triggers");
        assert_eq!(pinned.len(), 2);
    }

    #[test]
    fn without_a_default_gateway_nothing_is_pinned_and_the_caller_arms_nothing() {
        // No gateway to pin through: report the host as unpinned so
        // route_all_plan withholds the catch-all rather than cutting the box off.
        let t = FakeTable::with_gateway("192.168.1.1");
        *t.gw.lock().unwrap() = None;
        let mut pinned = PinJournal::in_memory();
        let ok = reconcile_pins(&t, &[ip("3.1.237.225")], &mut pinned);
        assert!(ok.is_empty() && pinned.is_empty());
        let plan = route_all_plan(&view(), None, None, &[ip("3.1.237.225")], &[ip("3.1.237.225")], &ok);
        assert!(plan.nets.is_empty(), "an unpinned transport must never arm a catch-all");
    }

    #[test]
    fn a_dead_predecessors_pins_are_removed_by_the_first_reconcile_and_the_journal_with_them() {
        // The bug this exists for: a route-all laptop client killed -9 (or
        // crashed) leaves its pins — the only routes not bound to the TUN —
        // pointing at a gateway that, after a move to another network, no
        // longer exists. The next run must remove them before it joins, or
        // the coordinator is unreachable through a route nothing knows it
        // owns. A malformed line must not stop the rest being honoured.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        std::fs::write(&path, "3.1.237.225 192.168.1.1\ngarbage line\n8.8.8.8 192.168.1.1\n").unwrap();
        let mut pinned = PinJournal::load(path.clone());
        assert_eq!(pinned.len(), 2, "the inherited pins, minus the malformed line");

        // The startup pass is the ordinary reconcile with nothing wanted.
        let t = FakeTable::with_gateway("10.0.0.1").watching(&path);
        let ok = reconcile_pins(&t, &[], &mut pinned);
        assert!(ok.is_empty());
        let deleted = t.deleted.lock().unwrap().clone();
        assert!(deleted.contains(&(ip("3.1.237.225"), ip("192.168.1.1"))), "removed via the gateway it was recorded with, not today's");
        assert!(deleted.contains(&(ip("8.8.8.8"), ip("192.168.1.1"))));
        assert!(t.added.lock().unwrap().is_empty(), "cleanup adds nothing");
        assert!(pinned.is_empty());
        assert!(!path.exists(), "an empty journal is no file: the next start has nothing to inherit");
    }

    #[test]
    fn the_journal_is_written_before_the_kernel_gains_a_pin_and_after_it_loses_one() {
        // Write-ahead in both directions, so a crash at any instant leaves
        // at worst a phantom entry (deleting an absent route is a no-op) and
        // never an unrecorded live route.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        let mut pinned = PinJournal::load(path.clone());
        let t = FakeTable::with_gateway("192.168.1.1").watching(&path);
        let want = [ip("3.1.237.225"), ip("8.8.8.8")];

        reconcile_pins(&t, &want, &mut pinned);
        assert_eq!(*t.journaled_at_add.lock().unwrap(), vec![true, true], "each pair was in the journal when the kernel add ran");
        let mut lines = journal_lines(&path);
        lines.sort();
        assert_eq!(lines, vec!["3.1.237.225 192.168.1.1", "8.8.8.8 192.168.1.1"]);

        // The gateway moves: each pin is deleted while still journaled, then
        // re-recorded before it is re-added.
        *t.gw.lock().unwrap() = Some(ip("10.0.0.1"));
        reconcile_pins(&t, &want, &mut pinned);
        assert_eq!(*t.journaled_at_del.lock().unwrap(), vec![true, true], "each pair was still in the journal when the kernel delete ran");
        assert_eq!(*t.journaled_at_add.lock().unwrap(), vec![true, true, true, true]);
        let mut lines = journal_lines(&path);
        lines.sort();
        assert_eq!(lines, vec!["3.1.237.225 10.0.0.1", "8.8.8.8 10.0.0.1"], "the journal names the gateway now in use");

        // A relay leaves the fleet: deleted while journaled, then forgotten.
        reconcile_pins(&t, &[ip("8.8.8.8")], &mut pinned);
        assert_eq!(t.journaled_at_del.lock().unwrap().len(), 3);
        assert!(t.journaled_at_del.lock().unwrap().iter().all(|b| *b));
        assert_eq!(journal_lines(&path), vec!["8.8.8.8 10.0.0.1"]);
    }

    #[test]
    fn a_route_someone_else_owns_is_never_left_in_the_journal() {
        // The write-ahead entry for a pin that turns out to be already
        // present is withdrawn: the journal lists exactly what we own, so a
        // successor cleaning up after us cannot delete the host's own route.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        let mut pinned = PinJournal::load(path.clone());
        let t = FakeTable::with_gateway("192.168.1.1").watching(&path);
        t.preexisting.lock().unwrap().insert((ip("3.1.237.225"), ip("192.168.1.1")));
        let ok = reconcile_pins(&t, &[ip("3.1.237.225"), ip("8.8.8.8")], &mut pinned);
        assert_eq!(ok.len(), 2, "usable either way");
        assert_eq!(journal_lines(&path), vec!["8.8.8.8 192.168.1.1"], "only the pin we created");
    }

    #[test]
    fn a_clean_teardown_leaves_no_journal() {
        // Shutdown is the same reconcile with nothing wanted (what the
        // programmer's Drop runs): every pin goes, and with the last one
        // the file, so the next start inherits nothing.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        let mut pinned = PinJournal::load(path.clone());
        let t = FakeTable::with_gateway("192.168.1.1").watching(&path);
        reconcile_pins(&t, &[ip("3.1.237.225"), ip("8.8.8.8")], &mut pinned);
        assert!(path.exists());
        reconcile_pins(&t, &[], &mut pinned);
        assert_eq!(t.deleted.lock().unwrap().len(), 2);
        assert!(pinned.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn route_all_pins_off_lan_resolvers_so_dns_cannot_deadlock_the_tunnel() {
        // The client merges its resolvers into the pin set. An off-LAN
        // resolver must be pinned to the real gateway: route-all leaves
        // DNS alone, and resolving the coordinator/relays is what brings
        // the tunnel up, so a resolver inside the catch-all deadlocks it.
        let local = [net("172.20.54.0/24")];
        let underlay = [ip("3.1.237.225")];
        let resolvers = [ip("8.8.8.8"), ip("1.1.1.1")];
        let all: Vec<IpAddr> = underlay.iter().chain(resolvers.iter()).copied().collect();
        let pinned = underlay_to_pin(&all, &local);
        for r in resolvers {
            assert!(pinned.contains(&r), "{r} must be pinned or DNS dies under route-all");
        }
        assert!(pinned.contains(&ip("3.1.237.225")), "the transport is still pinned");

        // A resolver on our own LAN is reached by its connected route and
        // is never pinned — same rule as a relay on the LAN.
        let pinned = underlay_to_pin(&[ip("172.20.54.53")], &local);
        assert!(pinned.is_empty(), "an on-LAN resolver needs no pin");
    }

    #[test]
    fn an_internet_exit_owning_the_default_still_routes_every_member_into_the_tunnel() {
        // The exit's own space is its address plus the default it fronts.
        // The default contains every member prefix, yet replies from the
        // internet (and from the exit itself) must re-enter the tunnel:
        // without these routes the kernel sends them out the uplink.
        let mine = [net("10.99.0.4/32"), net("0.0.0.0/0"), net("::/0")];
        let w = wanted_routes(&view(), 9, &mine);
        for p in ["10.99.0.0/16", "192.168.7.0/24", "192.168.9.0/24"] {
            assert!(w.contains(&net(p)), "{p} must be routed into the tunnel on an internet exit");
        }
        assert!(!w.contains(&net("10.99.1.1/32")) && !w.contains(&net("10.99.1.2/32")), "member host routes are covered by tunnel CIDR");
        assert!(!w.contains(&net("10.99.0.4/32")), "never my own host address");
        // A real LAN of ours is still excluded; the default just never is.
        let w = wanted_routes(&view(), 9, &[net("10.99.0.4/32"), net("192.168.7.0/24"), net("0.0.0.0/0")]);
        assert!(!w.contains(&net("192.168.7.0/24")));
        assert!(w.contains(&net("10.99.0.0/16")));
    }

    #[test]
    fn a_prefix_that_is_my_own_lan_is_excluded() {
        // The colliding-LAN case: the client sits on 192.168.7.0/24 too.
        let local = vec![net("192.168.7.0/24"), net("172.16.5.0/24")];
        let (keep, out) = exclude_local(vec![net("192.168.7.0/24"), net("192.168.7.128/25"), net("10.99.1.2/32")], &local, &[]);
        assert_eq!(keep, vec![net("10.99.1.2/32")]);
        assert_eq!(out.len(), 2, "equal to, or a slice of, a connected network");
        assert!(out[0].1.contains("local interface"));
    }

    #[test]
    fn a_wider_prefix_than_a_local_lan_is_allowed() {
        // 10.0.0.0/8 via the VPN with a local 10.1.2.0/24 is normal: the
        // kernel's longest match keeps the LAN local.
        let (keep, out) = exclude_local(vec![net("10.0.0.0/8")], &[net("10.1.2.0/24")], &[]);
        assert_eq!(keep, vec![net("10.0.0.0/8")]);
        assert!(out.is_empty());
    }

    #[test]
    fn a_prefix_covering_the_underlay_is_excluded_unless_a_local_route_protects_it() {
        let relay: IpAddr = "203.0.113.7".parse().unwrap();
        let (keep, out) = exclude_local(vec![net("203.0.113.0/24")], &[], &[relay]);
        assert!(keep.is_empty());
        assert!(out[0].1.contains("underlay"));
        // The same prefix is fine if the relay sits on a connected LAN
        // more specific than it: the kernel keeps the relay local.
        let (keep, _) = exclude_local(vec![net("203.0.113.0/24")], &[net("203.0.113.0/25")], &[relay]);
        assert_eq!(keep, vec![net("203.0.113.0/24")]);
        let (keep, _) = exclude_local(vec![net("203.0.0.0/16")], &[net("203.0.113.0/24")], &[relay]);
        assert_eq!(keep, vec![net("203.0.0.0/16")]);
    }

    #[test]
    fn kernel_reconcile_deletes_stale_adds_missing_and_leaves_our_addresses() {
        // Kernel starts with a stale route, a wanted route already
        // present, and our own host address (a connected route).
        let mine = net("10.99.1.1/32");
        let p = RecordingProgrammer::with_kernel(&[net("10.0.9.0/24"), net("10.0.2.0/24"), mine]);
        let set = RouteSet::new(p);
        let ok = set
            .reconcile_via_kernel(&[net("10.0.2.0/24"), net("10.0.3.0/24")], &[mine])
            .unwrap();
        assert!(ok, "readback was available");
        let kernel = set.programmer_kernel();
        // stale removed, missing added, present untouched, ours kept.
        assert!(!kernel.contains(&net("10.0.9.0/24")), "stale removed");
        assert!(kernel.contains(&net("10.0.3.0/24")), "missing added");
        assert!(kernel.contains(&net("10.0.2.0/24")), "present kept");
        assert!(kernel.contains(&mine), "our own address is never touched");
    }

    #[test]
    fn kernel_reconcile_self_heals_an_externally_deleted_route() {
        let p = RecordingProgrammer::with_kernel(&[net("10.0.1.0/24")]);
        let set = RouteSet::new(p);
        set.reconcile_via_kernel(&[net("10.0.1.0/24")], &[]).unwrap();
        // Someone else deletes it out from under us.
        set.programmer_kernel_remove(net("10.0.1.0/24"));
        // A cache-only reconcile would not notice; the kernel one does.
        set.reassert_via_kernel().unwrap();
        assert!(set.programmer_kernel().contains(&net("10.0.1.0/24")), "re-added from truth");
    }

    #[test]
    fn an_identical_resnapshot_programs_nothing_the_no_op_after_a_coordinator_restart() {
        // The routes a member holds after a coordinator restart: some
        // peers and a couple of gateway LANs.
        let set = RouteSet::new(RecordingProgrammer::with_kernel(&[]));
        let wanted = [net("10.99.1.5/32"), net("10.99.1.6/32"), net("192.168.9.0/24")];
        let mine = [net("10.99.1.1/32")];
        assert!(set.reconcile_via_kernel(&wanted, &mine).unwrap());
        assert_eq!(set.programmer_calls().len(), 3, "the first apply installs three routes");

        // The coordinator comes back and pushes a snapshot with the SAME
        // content (only the generation changed). Re-applying it must
        // touch the routing table zero times — no churn, no flap.
        set.reconcile_via_kernel(&wanted, &mine).unwrap();
        assert_eq!(set.programmer_calls().len(), 3, "an identical resnapshot programs nothing new");
        // And the kernel still holds exactly the same set.
        let mut k = set.programmer_kernel().into_iter().collect::<Vec<_>>();
        k.sort();
        let mut w: Vec<IpNet> = wanted.to_vec();
        w.sort();
        assert_eq!(k, w);
    }

    #[test]
    fn kernel_reconcile_reports_unsupported_so_the_caller_can_fall_back() {
        // The default recorder has no simulated kernel.
        let set = RouteSet::new(RecordingProgrammer::default());
        assert!(!set.reconcile_via_kernel(&[net("10.0.1.0/24")], &[]).unwrap(), "readback unavailable");
        assert!(set.programmer_calls().is_empty(), "did nothing; caller uses the cache path");
    }

    #[test]
    fn reconcile_issues_only_the_difference() {
        let set = RouteSet::new(RecordingProgrammer::default());
        set.reconcile(&[net("10.0.1.0/24"), net("10.0.2.0/24")], &[]).unwrap();
        assert_eq!(set.installed().len(), 2);
        set.programmer.calls.lock().unwrap().clear();
        set.reconcile(&[net("10.0.1.0/24"), net("10.0.2.0/24")], &[]).unwrap();
        assert!(set.programmer.calls.lock().unwrap().is_empty(), "no change, no calls");
        set.reconcile(&[net("10.0.2.0/24"), net("10.0.3.0/24")], &[]).unwrap();
        let calls = set.programmer.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["remove 10.0.1.0/24", "add 10.0.3.0/24"]);
    }

    #[test]
    fn a_failed_remove_does_not_abort_and_a_failed_add_is_not_recorded() {
        struct Flaky;
        impl RouteProgrammer for Flaky {
            fn add_via_tun(&self, net: IpNet) -> Result<()> {
                if net.prefix_len() == 8 { anyhow::bail!("nope") } else { Ok(()) }
            }
            fn remove(&self, _net: IpNet) -> Result<()> {
                anyhow::bail!("no such process")
            }
        }
        let set = RouteSet::new(Flaky);
        set.reconcile(&[net("10.0.1.0/24")], &[]).unwrap();
        assert!(set.reconcile(&[net("10.0.0.0/8"), net("10.0.5.0/24")], &[]).is_err());
        let mut got = set.installed();
        got.sort_by_key(|n| n.to_string());
        assert_eq!(got, vec![net("10.0.5.0/24")], "the failed add is retried next time; the failed remove is forgotten");
    }

    /// Rule: when our own address changes, every route on the device is
    /// re-programmed, so none stays bound to the old source address
    /// (macOS/BSD keep a route's interface address for its lifetime).
    #[test]
    fn a_new_address_rebinds_every_route_on_the_device() {
        let (old, new) = (net("10.99.1.1/32"), net("10.99.1.27/32"));
        let wanted = [net("10.99.0.0/16"), net("192.168.9.0/24")];
        // Kernel readback path.
        let set = RouteSet::new(RecordingProgrammer::with_kernel(&[old]));
        set.reconcile_via_kernel(&wanted, &[old]).unwrap();
        set.reconcile_via_kernel(&wanted, &[old]).unwrap();
        assert_eq!(set.programmer_calls().len(), 2, "same address: nothing re-programmed");
        set.programmer_kernel_remove(old);
        set.programmer.kernel.lock().unwrap().as_mut().unwrap().insert(new);
        set.reconcile_via_kernel(&wanted, &[new]).unwrap();
        assert_eq!(
            set.programmer_calls()[2..],
            ["remove 10.99.0.0/16", "remove 192.168.9.0/24", "add 10.99.0.0/16", "add 192.168.9.0/24"],
            "removed and re-added under the new address"
        );
        assert!(set.programmer_kernel().contains(&new), "our own address is never touched");
        // Cache path.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.reconcile(&wanted, &[old]).unwrap();
        set.reconcile(&wanted, &[old]).unwrap();
        assert_eq!(set.programmer_calls().len(), 2);
        set.reconcile(&wanted, &[new]).unwrap();
        assert_eq!(
            set.programmer_calls()[2..],
            ["remove 10.99.0.0/16", "remove 192.168.9.0/24", "add 10.99.0.0/16", "add 192.168.9.0/24"]
        );
        assert_eq!(set.installed().len(), 2);
    }

    #[test]
    fn reassert_reprograms_everything_owned() {
        let set = RouteSet::new(RecordingProgrammer::default());
        set.reconcile(&[net("10.99.1.1/32"), net("10.99.1.2/32")], &[]).unwrap();
        set.programmer.calls.lock().unwrap().clear();
        set.reassert().unwrap();
        assert_eq!(set.programmer.calls.lock().unwrap().clone(), vec!["add 10.99.1.1/32", "add 10.99.1.2/32"]);
    }

    /// The IPv6 leak this guards: every IPv6 pin failed (a link-local
    /// gateway with no interface), so route-all withheld the v6 halves and
    /// all IPv6 left outside the tunnel. A family whose failed pins are
    /// only resolvers — or whose transport the other family can carry —
    /// now fails closed instead.
    #[test]
    fn route_all_fails_closed_for_a_family_whose_pins_failed_when_the_tunnel_survives_it() {
        let mut s = view();
        let gw = s.members.iter_mut().find(|m| m.node_id == 3).unwrap();
        gw.prefixes.extend([net("0.0.0.0/0"), net("::/0")]);
        let (relay4, relay6, dns6) = (ip("203.0.113.7"), ip("2001:db8::7"), ip("2001:4860:4860::8888"));

        // Only a v6 resolver failed: v6 is activated anyway, and said so.
        let to_pin = [relay4, dns6];
        let p = route_all_plan(&s, None, None, &[relay4], &to_pin, &[relay4]);
        assert!(p.nets.contains(&net("::/1")) && p.nets.contains(&net("8000::/1")), "v6 fails closed: {p:?}");
        assert_eq!(p.failed_closed, vec![true]);

        // The v6 relay address failed but v4 carries a whole transport:
        // v6 is activated; dialing falls through to the v4 address.
        let to_pin = [relay4, relay6];
        let p = route_all_plan(&s, None, None, &[relay4, relay6], &to_pin, &[relay4]);
        assert_eq!(p.exits, vec![(false, 3), (true, 3)]);
        assert_eq!(p.failed_closed, vec![true]);

        // The only transport is v6 and it failed: activating v6 would cut
        // the tunnel's own path, so v6 is withheld.
        let p = route_all_plan(&s, None, None, &[relay6], &[relay6], &[]);
        assert!(p.exits.iter().all(|(v6, _)| !v6), "no fallback transport: withheld, {p:?}");

        // Both families' transport failed: nothing can be armed safely.
        let p = route_all_plan(&s, None, None, &[relay4, relay6], &[relay4, relay6], &[]);
        assert_eq!(p, RouteAllPlan::default());

        // A transport host on the LAN needs no pin and counts as whole.
        let lan_relay = ip("192.168.1.9");
        let p = route_all_plan(&s, None, None, &[lan_relay, relay6], &[relay6], &[]);
        assert_eq!(p.exits, vec![(false, 3), (true, 3)], "v6 falls back onto the LAN-local v4 relay");
    }

    #[test]
    fn loopback_and_link_local_resolvers_are_never_pinned() {
        let conf = "# generated\nnameserver 127.0.0.53\nnameserver 8.8.8.8 # upstream\nnameserver fe80::1%eth0\nnameserver 169.254.169.254\nnameserver ::1\nnameserver 2001:4860:4860::8888\noptions edns0\n";
        let all = parse_resolvers(conf);
        assert_eq!(all.len(), 6);
        let pinnable: Vec<IpAddr> = all.into_iter().filter(|ip| pinnable_resolver(*ip)).collect();
        assert_eq!(pinnable, vec![ip("8.8.8.8"), ip("2001:4860:4860::8888")]);
    }

    #[test]
    fn a_gateway_round_trips_through_the_journal_with_its_interface() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins");
        let mut j = PinJournal::load(path.clone());
        let ll = Gateway::new(ip("fe80::1"), Some(3));
        j.record(ip("2001:db8::7"), ll);
        j.record(ip("203.0.113.7"), Gateway::new(ip("192.168.1.1"), Some(2)));
        let mut lines = journal_lines(&path);
        lines.sort();
        assert_eq!(lines, vec!["2001:db8::7 fe80::1%3", "203.0.113.7 192.168.1.1%2"]);
        let back = PinJournal::load(path.clone());
        assert_eq!(back.get(&ip("2001:db8::7")), Some(ll));
        // An older journal, gateways without an interface, still loads.
        std::fs::write(&path, "8.8.8.8 192.168.1.1\n").unwrap();
        assert_eq!(PinJournal::load(path).get(&ip("8.8.8.8")), Some(ip("192.168.1.1").into()));
    }

    #[test]
    fn a_pin_moves_when_the_gateway_is_the_same_address_on_another_interface() {
        // Wired -> wifi on the same LAN: same gateway address, different
        // interface. The old pin is bound to the interface that went away.
        struct IfTable {
            gw: Mutex<Gateway>,
            added: Mutex<Vec<(IpAddr, Gateway)>>,
            deleted: Mutex<Vec<(IpAddr, Gateway)>>,
        }
        impl HostRouteTable for IfTable {
            fn default_gateway(&self, _v6: bool) -> Option<Gateway> {
                Some(*self.gw.lock().unwrap())
            }
            fn add_host_route(&self, i: IpAddr, gw: Gateway) -> std::io::Result<bool> {
                self.added.lock().unwrap().push((i, gw));
                Ok(true)
            }
            fn del_host_route(&self, i: IpAddr, gw: Gateway) {
                self.deleted.lock().unwrap().push((i, gw));
            }
        }
        let wired = Gateway::new(ip("192.168.1.1"), Some(2));
        let wifi = Gateway::new(ip("192.168.1.1"), Some(3));
        let t = IfTable { gw: Mutex::new(wired), added: Mutex::new(vec![]), deleted: Mutex::new(vec![]) };
        let mut pinned = PinJournal::in_memory();
        reconcile_pins(&t, &[ip("8.8.8.8")], &mut pinned);
        *t.gw.lock().unwrap() = wifi;
        reconcile_pins(&t, &[ip("8.8.8.8")], &mut pinned);
        assert_eq!(*t.deleted.lock().unwrap(), vec![(ip("8.8.8.8"), wired)]);
        assert_eq!(t.added.lock().unwrap().last(), Some(&(ip("8.8.8.8"), wifi)));
    }

    #[test]
    fn the_route_policy_shapes_os_routes_and_says_what_it_refused() {
        let mut s = view();
        // gw also claims a slice of the internet and an unlisted range.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.extend([net("8.0.0.0/7"), net("172.16.0.0/12")]);
        s.reserved_prefixes.push(net("100.0.0.0/6"));
        let mine = [net("10.99.1.1/32")];

        // No allowlist: only what is wider than /8 is refused.
        let open = RoutePolicy::default();
        let w = wanted_routes_with(&s, 1, &mine, &open);
        assert!(w.contains(&net("172.16.0.0/12")), "a site gateway's wide range is fine");
        assert!(!w.contains(&net("8.0.0.0/7")) && !w.contains(&net("100.0.0.0/6")));
        let refused: Vec<IpNet> = refused_prefixes(&s, 1, &open).into_iter().map(|(n, _, _)| n).collect();
        assert_eq!(refused, vec![net("8.0.0.0/7"), net("100.0.0.0/6")]);
        // The unfiltered function (used by relays) is unchanged.
        assert!(wanted_routes(&s, 1, &mine).contains(&net("8.0.0.0/7")));

        // An allowlist: only what lies inside it, reserved or member. A
        // member host under a refused reserved range is routed by itself.
        let listed = RoutePolicy::allow_list(vec![net("10.99.1.0/24"), net("192.168.7.0/24")]);
        let w = wanted_routes_with(&s, 1, &mine, &listed);
        assert!(!w.contains(&net("10.99.0.0/16")), "the reserved range is wider than the allowlist");
        assert!(w.contains(&net("10.99.1.2/32")), "but the allowed peer inside it stays reachable");
        assert!(w.contains(&net("192.168.7.0/24")));
        assert!(!w.contains(&net("172.16.0.0/12")) && !w.contains(&net("192.168.9.0/24")));
    }

    #[test]
    fn kernel_housekeeping_routes_on_the_tun_are_not_ours() {
        assert!(kernel_housekeeping(&net("ff00::/8")));
        assert!(kernel_housekeeping(&net("fe80::/64")));
        assert!(kernel_housekeeping(&net("224.0.0.0/4")));
        assert!(!kernel_housekeeping(&net("fd00:99::/64")));
        assert!(!kernel_housekeeping(&net("10.99.0.0/16")));
    }

    #[cfg(unix)]
    #[test]
    fn the_pin_journal_is_never_written_through_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let path = dir.path().join("pins");
        std::os::unix::fs::symlink(&victim, path.with_extension("tmp")).unwrap();
        let mut j = PinJournal::load(path.clone());
        j.record(ip("8.8.8.8"), ip("192.168.1.1").into());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
        assert_eq!(journal_lines(&path), vec!["8.8.8.8 192.168.1.1"]);
        assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_file());
    }
}
