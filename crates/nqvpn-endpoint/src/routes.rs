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
/// client never seals traffic to a node that would only drop it. With
/// `via` set, only the node of that name qualifies (and only if it owns
/// the default); without it, the lowest node id among candidates is picked
/// so the choice is deterministic when several nodes advertise a default.
/// `None` means no usable exit for this family — the caller must withhold
/// its catch-all so route-all cannot blackhole.
pub fn exit_gateway(view: &Snapshot, via: Option<&str>, v6: bool) -> Option<NodeId> {
    let default: IpNet = if v6 { "::/0" } else { "0.0.0.0/0" }.parse().unwrap();
    let owns_default =
        |m: &nqvpn_proto::control::PeerInfo| m.online && m.prefixes.iter().any(|p| p.trunc() == default);
    match via {
        Some(name) => view.members.iter().find(|m| m.name == name && owns_default(m)).map(|m| m.node_id),
        None => view.members.iter().filter(|m| owns_default(m)).map(|m| m.node_id).min(),
    }
}

/// The route-all decision for both families at once: which catch-all
/// halves to install in the OS table (they point at the TUN), and which
/// exit each family's otherwise-unrouted traffic is sealed to. A family is
/// activated only when BOTH its transport is pinned (so the tunnel's own
/// path to the coordinator/relays is safe) AND a usable exit gateway
/// exists for it (so traffic is not blackholed) — otherwise that family is
/// left on the real default route, untouched.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RouteAllPlan {
    /// Catch-all halves to add to the OS routing table.
    pub nets: Vec<IpNet>,
    /// `(is_v6, exit node)` defaults to assert in the in-VPN routing table.
    pub exits: Vec<(bool, NodeId)>,
}

pub fn route_all_plan(view: &Snapshot, via: Option<&str>, to_pin: &[IpAddr], pinned: &[IpAddr]) -> RouteAllPlan {
    let pinned_ok = |v6: bool| to_pin.iter().filter(|ip| ip.is_ipv6() == v6).all(|ip| pinned.contains(ip));
    let mut plan = RouteAllPlan::default();
    for v6 in [false, true] {
        if let (true, Some(node)) = (pinned_ok(v6), exit_gateway(view, via, v6)) {
            plan.nets.extend(catch_all_halves(v6));
            plan.exits.push((v6, node));
        }
    }
    plan
}

/// Routes the view says this node should have, before local exclusion.
pub fn wanted_routes(view: &Snapshot, my_node_id: NodeId, mine: &[IpNet]) -> Vec<IpNet> {
    let mut set: BTreeSet<IpNet> = view.reserved_prefixes.iter().map(|p| p.trunc()).collect();
    for m in &view.members {
        if m.node_id == my_node_id {
            continue;
        }
        set.extend(m.prefixes.iter().map(|p| p.trunc()));
    }
    // Never route our own space into the tunnel: our host addresses live
    // on the device, and a gateway's own LAN is the wire behind it. A
    // wider prefix that merely contains something of ours is fine — the
    // kernel prefers our more specific connected route for that part.
    set.retain(|w| !mine.iter().any(|m| m.contains(w)));
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
}

impl<P: RouteProgrammer> RouteSet<P> {
    pub fn new(programmer: P) -> Self {
        RouteSet { programmer, installed: Mutex::new(BTreeSet::new()), last: Mutex::new((Vec::new(), Vec::new())) }
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
        let ours: BTreeSet<IpNet> =
            present.into_iter().map(|n| n.trunc()).filter(|n| !mine.contains(n)).collect();

        let (mut added, mut removed, mut failed) = (0u32, 0u32, 0u32);
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
    pub fn reconcile(&self, wanted: &[IpNet]) -> Result<()> {
        let wanted: BTreeSet<IpNet> = wanted.iter().map(|n| n.trunc()).collect();
        let mut installed = self.installed.lock().unwrap();
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
pub struct NetRouteProgrammer {
    device: String,
    mgr: Mutex<route_manager::RouteManager>,
    /// Underlay host routes we added via the real gateway (route-all), so
    /// we can reconcile and tear them down. ip -> the gateway used.
    pinned: Mutex<std::collections::BTreeMap<IpAddr, IpAddr>>,
}

impl NetRouteProgrammer {
    pub fn new(device: String) -> Result<Self> {
        let mgr = route_manager::RouteManager::new()
            .map_err(|e| anyhow::anyhow!("opening the OS routing table: {e}"))?;
        Ok(NetRouteProgrammer { device, mgr: Mutex::new(mgr), pinned: Mutex::new(std::collections::BTreeMap::new()) })
    }

    /// The current default route's gateway for a family, ignoring any
    /// default that points at our own TUN. `None` if there is none.
    fn default_gateway(&self, v6: bool) -> Option<IpAddr> {
        let mytun = self.ifindex();
        let routes = self.mgr.lock().unwrap().list().ok()?;
        routes
            .into_iter()
            .find(|r| r.prefix() == 0 && r.destination().is_ipv6() == v6 && r.gateway().is_some() && !self.ours(r, mytun))
            .and_then(|r| r.gateway())
    }

    /// Our TUN's kernel interface index, resolved fresh each call so a
    /// device that did not exist at construction, or was renamed, is
    /// still matched as long as the name is stable. `None` means the
    /// device is gone (its routes went with it).
    fn ifindex(&self) -> Option<u32> {
        let c = std::ffi::CString::new(self.device.as_str()).ok()?;
        let idx = unsafe { libc::if_nametoindex(c.as_ptr()) };
        (idx != 0).then_some(idx)
    }

    fn route(&self, net: IpNet) -> route_manager::Route {
        let mut r = route_manager::Route::new(net.addr(), net.prefix_len());
        match self.ifindex() {
            Some(i) => r = r.with_if_index(i),
            None => r = r.with_if_name(self.device.clone()),
        }
        r
    }

    /// Is this kernel route one on our device?
    fn ours(&self, r: &route_manager::Route, idx: Option<u32>) -> bool {
        r.if_name().map(|n| n == &self.device).unwrap_or(false) || (idx.is_some() && r.if_index() == idx)
    }
}

/// A `/32` or `/128` host route for `ip` (no interface/gateway set yet).
fn host_route(ip: IpAddr) -> route_manager::Route {
    let bits = if ip.is_ipv6() { 128 } else { 32 };
    route_manager::Route::new(ip, bits)
}

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
                .filter(|r| self.ours(r, idx) && r.gateway().is_none())
                .filter_map(|r| IpNet::new(r.destination(), r.prefix()).ok().map(|n| n.trunc()))
                .collect(),
        )
    }

    fn pin_underlay(&self, ips: &[IpAddr]) -> Result<Vec<IpAddr>> {
        let want: BTreeSet<IpAddr> = ips.iter().copied().collect();
        let mut pinned = self.pinned.lock().unwrap();
        // Drop pins no longer wanted (a relay left the fleet).
        let stale: Vec<IpAddr> = pinned.keys().copied().filter(|ip| !want.contains(ip)).collect();
        for ip in stale {
            if let Some(gw) = pinned.remove(&ip) {
                let _ = self.mgr.lock().unwrap().delete(&host_route(ip).with_gateway(gw));
            }
        }
        // Add pins we don't have yet, via the family's real gateway.
        let mut ok = Vec::new();
        for ip in want {
            if pinned.contains_key(&ip) {
                ok.push(ip);
                continue;
            }
            let Some(gw) = self.default_gateway(ip.is_ipv6()) else {
                tracing::warn!(%ip, "route-all: no default gateway to pin this underlay host; withholding its family's catch-all so the tunnel is not cut off");
                continue;
            };
            match self.mgr.lock().unwrap().add(&host_route(ip).with_gateway(gw)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    tracing::warn!(%ip, %gw, "route-all: pinning underlay host failed: {e}");
                    continue;
                }
            }
            tracing::info!(target: "nqvpn::os_routes", %ip, %gw, "route-all: pinned underlay host to gateway");
            pinned.insert(ip, gw);
            ok.push(ip);
        }
        Ok(ok)
    }
}

impl Drop for NetRouteProgrammer {
    fn drop(&mut self) {
        let pinned = std::mem::take(&mut *self.pinned.lock().unwrap());
        for (ip, gw) in pinned {
            let _ = self.mgr.lock().unwrap().delete(&host_route(ip).with_gateway(gw));
        }
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
        assert_eq!(exit_gateway(&s, None, false), None, "no default owner, no exit");
        // Make the relay front the v4 default: it becomes an internet exit.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.push(net("0.0.0.0/0"));
        assert_eq!(exit_gateway(&s, None, false), Some(3));
        assert_eq!(exit_gateway(&s, None, true), None, "it owns no v6 default");
        // An offline owner is not a candidate.
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().online = false;
        assert_eq!(exit_gateway(&s, None, false), None, "offline exits do not count");
    }

    #[test]
    fn via_selects_the_named_exit_among_several_and_rejects_a_non_owner() {
        let mut s = view();
        // Two nodes own the v4 default (names: 2 = "b", 3 = "gw").
        for id in [2, 3] {
            s.members.iter_mut().find(|m| m.node_id == id).unwrap().prefixes.push(net("0.0.0.0/0"));
        }
        assert_eq!(exit_gateway(&s, Some("gw"), false), Some(3), "the named exit wins over the lowest id");
        assert_eq!(exit_gateway(&s, None, false), Some(2), "no name: lowest id, deterministically");
        assert_eq!(exit_gateway(&s, Some("me"), false), None, "a named node that owns no default is not an exit");
        assert_eq!(exit_gateway(&s, Some("nope"), false), None, "a named node that does not exist is not an exit");
    }

    #[test]
    fn route_all_plan_needs_both_a_pinned_transport_and_an_exit() {
        let mut s = view();
        s.members.iter_mut().find(|m| m.node_id == 3).unwrap().prefixes.push(net("0.0.0.0/0"));
        let to_pin = [ip("203.0.113.7")];
        // Pinned transport + an exit -> the v4 halves and that exit.
        let p = route_all_plan(&s, Some("gw"), &to_pin, &to_pin);
        assert_eq!(p.nets, vec![net("0.0.0.0/1"), net("128.0.0.0/1")]);
        assert_eq!(p.exits, vec![(false, 3)]);
        // Transport not pinned -> nothing at all, even with an exit, so
        // route-all never severs the tunnel's own path.
        let p = route_all_plan(&s, Some("gw"), &to_pin, &[]);
        assert_eq!(p, RouteAllPlan::default());
        // No exit for the named node -> withheld (no blackhole).
        let p = route_all_plan(&s, Some("nope"), &to_pin, &to_pin);
        assert_eq!(p, RouteAllPlan::default());
        // v4 has an exit, v6 does not: only v4 activates.
        let p = route_all_plan(&s, None, &to_pin, &to_pin);
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
    fn wanted_is_a_function_of_the_view_minus_my_own_space() {
        let w = wanted_routes(&view(), 1, &[net("10.99.1.1/32")]);
        assert!(w.contains(&net("10.99.0.0/16")), "covering tunnel route");
        assert!(w.contains(&net("192.168.9.0/24")), "a reserved but unowned site stays blackholed into the tunnel");
        assert!(w.contains(&net("10.99.1.2/32")));
        assert!(!w.contains(&net("10.99.1.1/32")), "never my own host address");
        // A gateway never routes its own LAN into the tunnel, even when
        // another node currently owns it.
        let gw = wanted_routes(&view(), 9, &[net("10.99.0.4/32"), net("192.168.7.0/24")]);
        assert!(!gw.contains(&net("192.168.7.0/24")));
        assert!(gw.contains(&net("192.168.9.0/24")));
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
        set.reconcile(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        assert_eq!(set.installed().len(), 2);
        set.programmer.calls.lock().unwrap().clear();
        set.reconcile(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        assert!(set.programmer.calls.lock().unwrap().is_empty(), "no change, no calls");
        set.reconcile(&[net("10.0.2.0/24"), net("10.0.3.0/24")]).unwrap();
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
        set.reconcile(&[net("10.0.1.0/24")]).unwrap();
        assert!(set.reconcile(&[net("10.0.0.0/8"), net("10.0.5.0/24")]).is_err());
        let mut got = set.installed();
        got.sort_by_key(|n| n.to_string());
        assert_eq!(got, vec![net("10.0.5.0/24")], "the failed add is retried next time; the failed remove is forgotten");
    }

    #[test]
    fn reassert_reprograms_everything_owned() {
        let set = RouteSet::new(RecordingProgrammer::default());
        set.reconcile(&[net("10.99.1.1/32"), net("10.99.1.2/32")]).unwrap();
        set.programmer.calls.lock().unwrap().clear();
        set.reassert().unwrap();
        assert_eq!(set.programmer.calls.lock().unwrap().clone(), vec!["add 10.99.1.1/32", "add 10.99.1.2/32"]);
    }

}
