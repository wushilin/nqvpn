//! OS route programming (DESIGN.md §8), behind a trait so the engine and
//! CI stay platform-free.
//!
//! The routing table is a pure function of the network view:
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
}

impl<P: RouteProgrammer> RouteSet<P> {
    pub fn new(programmer: P) -> Self {
        RouteSet { programmer, installed: Mutex::new(BTreeSet::new()) }
    }

    /// Make the kernel hold exactly `wanted`: add what is missing, remove
    /// what is extra. A removal that fails because the route is already
    /// gone is not an error; an add that fails is, and leaves the set
    /// consistent (the route is not recorded as installed).
    pub fn reconcile(&self, wanted: &[IpNet]) -> Result<()> {
        let wanted: BTreeSet<IpNet> = wanted.iter().map(|n| n.trunc()).collect();
        let mut installed = self.installed.lock().unwrap();
        let extra: Vec<IpNet> = installed.difference(&wanted).copied().collect();
        for net in extra {
            let _ = self.programmer.remove(net);
            installed.remove(&net);
        }
        let missing: Vec<IpNet> = wanted.difference(&installed).copied().collect();
        let mut first_err = None;
        for net in missing {
            match self.programmer.add_via_tun(net) {
                Ok(()) => {
                    installed.insert(net);
                }
                Err(e) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
            }
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

/// Build a macOS `route` invocation. IPv6 needs an explicit -prefixlen:
/// `-net fd00::/64` silently installs a *default* route.
#[cfg(any(target_os = "macos", test))]
pub fn macos_route_args(verb: &str, net: IpNet, device: &str) -> Vec<String> {
    let own = |s: &str| s.to_string();
    if net.addr().is_ipv6() {
        vec![
            own("route"), own("-n"), own(verb), own("-inet6"),
            net.addr().to_string(),
            own("-prefixlen"), net.prefix_len().to_string(),
            own("-interface"), own(device),
        ]
    } else {
        vec![
            own("route"), own("-n"), own(verb), own("-inet"),
            own("-net"), net.to_string(),
            own("-interface"), own(device),
        ]
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
}

impl RouteProgrammer for RecordingProgrammer {
    fn add_via_tun(&self, net: IpNet) -> Result<()> {
        self.calls.lock().unwrap().push(format!("add {net}"));
        Ok(())
    }
    fn remove(&self, net: IpNet) -> Result<()> {
        self.calls.lock().unwrap().push(format!("remove {net}"));
        Ok(())
    }
}

/// Programs routes with the platform's command-line tools: `ip` on
/// Linux, `route` on macOS.
pub struct SystemProgrammer {
    pub device: String,
}

impl SystemProgrammer {
    fn run(&self, args: &[&str]) -> Result<()> {
        let out = std::process::Command::new(args[0]).args(&args[1..]).output()?;
        if !out.status.success() {
            anyhow::bail!("{} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(())
    }
}

impl RouteProgrammer for SystemProgrammer {
    #[cfg(target_os = "linux")]
    fn add_via_tun(&self, net: IpNet) -> Result<()> {
        let n = net.to_string();
        let fam = if net.addr().is_ipv6() { "-6" } else { "-4" };
        self.run(&["ip", fam, "route", "replace", &n, "dev", &self.device])
    }
    #[cfg(target_os = "macos")]
    fn add_via_tun(&self, net: IpNet) -> Result<()> {
        let args = macos_route_args("add", net, &self.device);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        // `add` fails when the route exists; `change` makes this behave
        // like Linux's `replace` so re-asserting is a no-op.
        self.run(&refs).or_else(|_| {
            let chg = macos_route_args("change", net, &self.device);
            let refs: Vec<&str> = chg.iter().map(|s| s.as_str()).collect();
            self.run(&refs)
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn add_via_tun(&self, _net: IpNet) -> Result<()> {
        anyhow::bail!("route programming is not implemented on this platform yet")
    }

    #[cfg(target_os = "linux")]
    fn remove(&self, net: IpNet) -> Result<()> {
        let n = net.to_string();
        let fam = if net.addr().is_ipv6() { "-6" } else { "-4" };
        self.run(&["ip", fam, "route", "del", &n, "dev", &self.device])
    }
    #[cfg(target_os = "macos")]
    fn remove(&self, net: IpNet) -> Result<()> {
        let args = macos_route_args("delete", net, &self.device);
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        self.run(&refs)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn remove(&self, _net: IpNet) -> Result<()> {
        anyhow::bail!("route programming is not implemented on this platform yet")
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

    #[test]
    fn macos_ipv6_routes_carry_an_explicit_prefix_length() {
        let a = macos_route_args("add", net("fd99::1:1/128"), "utun10");
        assert!(a.contains(&"-prefixlen".to_string()));
        assert!(a.contains(&"128".to_string()));
        assert!(!a.contains(&"-net".to_string()));
        let v4 = macos_route_args("add", net("10.99.1.0/24"), "utun10");
        assert!(v4.contains(&"-net".to_string()));
        let del = macos_route_args("delete", net("fd99::/64"), "utun10");
        assert_eq!(del[2], "delete");
    }
}
