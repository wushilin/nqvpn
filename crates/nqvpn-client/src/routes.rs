//! OS route programming (DESIGN.md §8), behind a trait so the engine and
//! CI stay platform-free.
//!
//! Two rules from the design live here:
//!  * **pin the underlay** — host routes to the coordinator and every
//!    relay go via the physical gateway, or the tunnel would try to carry
//!    its own transport (mandatory loop prevention);
//!  * **keep it on the device, don't leak** — when a member prefix is
//!    withdrawn its route stays pointed at the TUN rather than being
//!    deleted. The packet enters the tunnel, matches no peer, and is
//!    dropped as `drop_no_route`. Deleting instead would let traffic to a
//!    dead site fall through to the default route and leave in cleartext
//!    — and ranges like 192.168.1.0/24 very often exist on the local
//!    network too, so it would go somewhere real.
//!
//!    This replaced an explicit blackhole route, which achieved the same
//!    thing but was the *only* route we installed that carried no device.
//!    That made it invisible to "show me everything on tunX", so cleanup
//!    needed either a Linux-only `proto` tag or tearing the interface
//!    down. Keeping every route on the device makes the device itself the
//!    complete inventory, on both platforms. It is also what WireGuard
//!    does: routes point at the interface and the module drops packets
//!    with no matching peer.

use anyhow::Result;
use ipnet::IpNet;
use std::collections::BTreeSet;
use std::sync::Mutex;

pub trait RouteProgrammer: Send + Sync {
    fn add_via_tun(&self, net: IpNet) -> Result<()>;
    fn remove(&self, net: IpNet) -> Result<()>;
    /// Pin a transport peer's real address via the physical gateway.
    fn pin_underlay(&self, host: std::net::IpAddr) -> Result<()>;
}

/// Applies membership diffs to whatever programmer it is given.
pub struct RouteSet<P: RouteProgrammer> {
    programmer: P,
    installed: Mutex<BTreeSet<IpNet>>,
}

impl<P: RouteProgrammer> RouteSet<P> {
    pub fn new(programmer: P) -> Self {
        RouteSet {
            programmer,
            installed: Mutex::new(BTreeSet::new()),
        }
    }

    /// Install everything in `wanted` that is not already installed.
    ///
    /// Withdrawn prefixes are deliberately **not** removed: their route
    /// stays on the TUN so traffic to a briefly-dead site is dropped by
    /// the engine instead of leaking to the underlay. That means the
    /// installed set only grows during a session; `reconcile` is what
    /// collapses it back to the truth.
    pub fn apply(&self, wanted: &[IpNet]) -> Result<()> {
        let wanted: BTreeSet<IpNet> = wanted.iter().copied().collect();
        let mut installed = self.installed.lock().unwrap();
        for net in wanted.difference(&installed).copied().collect::<Vec<_>>() {
            self.programmer.add_via_tun(net)?;
            installed.insert(net);
        }
        Ok(())
    }

    /// Delete everything we own, then install exactly `wanted`.
    ///
    /// Used when the control session comes back: membership may have
    /// changed arbitrarily while we were away, and this returns the table
    /// to the snapshot without trusting anything we cached. It also drops
    /// the prefixes `apply` kept around for leak protection but which are
    /// no longer part of the network at all — otherwise a site that left
    /// permanently would capture its range forever, and a user could not
    /// reach their own machines on it.
    ///
    /// Deletes are driven from the set we installed rather than by
    /// parsing the kernel's table back: `netstat` output on macOS is
    /// awkward enough that it renders a /128 host route as `.../0`, and
    /// building correctness on that is asking for trouble. A delete that
    /// fails because the route is already gone is not an error here.
    pub fn reconcile(&self, wanted: &[IpNet]) -> Result<()> {
        let previous: Vec<IpNet> = {
            let mut installed = self.installed.lock().unwrap();
            let all = installed.iter().copied().collect();
            installed.clear();
            all
        };
        for net in previous {
            // Best effort: something else may have removed it already,
            // which is exactly the drift this exists to survive.
            let _ = self.programmer.remove(net);
        }
        self.apply(wanted)
    }

    /// Re-program every route we believe we own, whether or not our
    /// cache thinks it is already there.
    ///
    /// `apply` diffs against that cache, which silently assumes we are
    /// the only writer of these routes. We are not: a second nqvpn
    /// endpoint on the same host claims the same member prefixes, an
    /// admin can delete one, and a vanishing TUN takes every route
    /// pointing at it with it. In all three cases the cache still says
    /// "installed" and the diff has nothing to do, so the hole never
    /// heals and traffic to those members black-holes indefinitely.
    ///
    /// Both platforms' add paths are idempotent replaces, so re-asserting
    /// is safe to run on a timer.
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

    pub fn pin_underlay(&self, host: std::net::IpAddr) -> Result<()> {
        self.programmer.pin_underlay(host)
    }
}

/// Build a macOS `route` invocation.
///
/// Split out so the argument shape can be tested: the IPv6 form is easy
/// to get subtly wrong and fails *silently* rather than erroring.
#[cfg(any(target_os = "macos", test))]
pub fn macos_route_args(verb: &str, net: IpNet, device: &str) -> Vec<String> {
    let own = |s: &str| s.to_string();
    if net.addr().is_ipv6() {
        // Explicit -prefixlen. macOS accepts `-net fd00::/64` and then
        // installs a *default* route, ignoring the length in the string —
        // so a relay's IPv6 site prefix would capture all IPv6 traffic on
        // every member instead of just that prefix.
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

/// Change a live TUN device's MTU. The value is dynamic: QUIC keeps
/// running path-MTU discovery, so the network-wide minimum can move up
/// or down while the tunnel is running, and the device follows it
/// without being torn down.
pub fn set_device_mtu(device: &str, mtu: u16) -> Result<()> {
    let mtu_s = mtu.to_string();
    #[cfg(target_os = "linux")]
    let args = vec!["ip", "link", "set", "dev", device, "mtu", mtu_s.as_str()];
    #[cfg(target_os = "macos")]
    let args = vec!["ifconfig", device, "mtu", mtu_s.as_str()];
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let args: Vec<&str> = {
        let _ = (device, &mtu_s);
        anyhow::bail!("setting MTU is not implemented on this platform")
    };
    let out = std::process::Command::new(args[0]).args(&args[1..]).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Records calls instead of touching the kernel — used by CI and by
/// `--dry-run`.
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
    fn pin_underlay(&self, host: std::net::IpAddr) -> Result<()> {
        self.calls.lock().unwrap().push(format!("pin {host}"));
        Ok(())
    }
}

/// Programs routes with the platform's command-line tools. Kept
/// deliberately boring: `ip` on Linux, `route` on macOS.
pub struct SystemProgrammer {
    pub device: String,
}

impl SystemProgrammer {
    fn run(&self, args: &[&str]) -> Result<()> {
        let out = std::process::Command::new(args[0]).args(&args[1..]).output()?;
        if !out.status.success() {
            anyhow::bail!(
                "{} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
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
        return self.run(&refs).or_else(|_| {
            let chg = macos_route_args("change", net, &self.device);
            let refs: Vec<&str> = chg.iter().map(|s| s.as_str()).collect();
            self.run(&refs)
        });
        #[allow(unreachable_code)]
        {
        // IPv6 gets an explicit -prefixlen rather than slash notation.
        // macOS accepts `-net fd00::/64` and then quietly installs a
        // *default* route — the prefix length in the string is not
        // honoured. Member /128s survive that by accident (the
        // destination still matches), but a relay registering an IPv6
        // site prefix would silently capture all IPv6 traffic on every
        // member. Being explicit costs one argument.
        let fam = if net.addr().is_ipv6() { "-inet6" } else { "-inet" };
        let plen = net.prefix_len().to_string();
        let addr = net.addr().to_string();
        let n = net.to_string();
        let args: Vec<&str> = if net.addr().is_ipv6() {
            vec!["route", "-n", "add", fam, &addr, "-prefixlen", &plen,
                 "-interface", &self.device]
        } else {
            vec!["route", "-n", "add", fam, "-net", &n, "-interface", &self.device]
        };
        // `route add` fails when the route already exists, which would
        // make re-asserting an error instead of a no-op; fall back to
        // `change` so this behaves like Linux's `replace`.
        self.run(&args).or_else(|_| {
            let mut chg = args.clone();
            chg[2] = "change";
            self.run(&chg)
        })
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn add_via_tun(&self, _net: IpNet) -> Result<()> {
        anyhow::bail!("route programming is not implemented on this platform yet")
    }

    #[cfg(target_os = "linux")]
    fn remove(&self, net: IpNet) -> Result<()> {
        let n = net.to_string();
        let fam = if net.addr().is_ipv6() { "-6" } else { "-4" };
        self.run(&["ip", fam, "route", "del", &n])
    }
    #[cfg(target_os = "macos")]
    fn remove(&self, net: IpNet) -> Result<()> {
        let n = net.to_string();
        let fam = if net.addr().is_ipv6() { "-inet6" } else { "-inet" };
        self.run(&["route", "-n", "delete", fam, "-net", &n])
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn remove(&self, _net: IpNet) -> Result<()> {
        anyhow::bail!("route programming is not implemented on this platform yet")
    }

    fn pin_underlay(&self, _host: std::net::IpAddr) -> Result<()> {
        // With split routes (only member prefixes go via the TUN) the
        // underlay is already reachable through the default route; the
        // pin becomes mandatory only for full-tunnel mode, which is out
        // of scope for v1 (§8).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn installs_and_diffs() {
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        assert_eq!(set.installed().len(), 2);
        // Re-applying the same set is a no-op.
        set.apply(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        assert_eq!(set.programmer.calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_withdrawn_prefix_keeps_its_route_so_traffic_cannot_leak() {
        // Deleting it would let traffic to a dead site fall through to
        // the default route and leave in cleartext — and 192.168.x is
        // very often a real local network, so it would go somewhere.
        // Keeping the route on the TUN means the engine drops it.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("192.168.7.0/24")]).unwrap();
        set.programmer.calls.lock().unwrap().clear();

        set.apply(&[]).unwrap();
        assert!(
            set.programmer.calls.lock().unwrap().is_empty(),
            "a withdrawal must not touch the routing table at all"
        );
        assert_eq!(set.installed(), vec![net("192.168.7.0/24")], "the route stays");
    }

    #[test]
    fn a_returning_site_needs_no_route_change() {
        // The former blackhole/active split meant a returning member had
        // to be transitioned back. With one state there is nothing to do,
        // which is the point of collapsing them.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("192.168.7.0/24")]).unwrap();
        set.apply(&[]).unwrap();
        set.programmer.calls.lock().unwrap().clear();
        set.apply(&[net("192.168.7.0/24")]).unwrap();
        assert!(
            set.programmer.calls.lock().unwrap().is_empty(),
            "the route was never removed, so coming back is free"
        );
    }

    #[test]
    fn reconcile_returns_the_table_to_the_snapshot() {
        // On reconnect membership may have changed arbitrarily. Reconcile
        // must not trust anything cached: everything we own goes, then
        // exactly the snapshot is installed.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("10.0.1.0/24"), net("10.0.2.0/24")]).unwrap();
        set.apply(&[]).unwrap(); // both withdrawn, both kept
        set.programmer.calls.lock().unwrap().clear();

        set.reconcile(&[net("10.0.2.0/24"), net("10.0.9.0/24")]).unwrap();
        let calls = set.programmer.calls.lock().unwrap().clone();
        // Everything previously owned is deleted first...
        assert!(calls.contains(&"remove 10.0.1.0/24".to_string()), "{calls:?}");
        assert!(calls.contains(&"remove 10.0.2.0/24".to_string()), "{calls:?}");
        // ...then the snapshot is installed, including the re-added one.
        assert!(calls.contains(&"add 10.0.2.0/24".to_string()), "{calls:?}");
        assert!(calls.contains(&"add 10.0.9.0/24".to_string()), "{calls:?}");
        let mut got = set.installed();
        got.sort_by_key(|n| n.to_string());
        assert_eq!(got, vec![net("10.0.2.0/24"), net("10.0.9.0/24")]);
    }

    #[test]
    fn reconcile_clears_a_prefix_that_left_the_network_for_good() {
        // The stranding hazard: a site that never returns must not keep
        // capturing its range, or the user cannot reach their own
        // machines on it and nothing explains why.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("192.168.7.0/24")]).unwrap();
        set.apply(&[]).unwrap();
        set.reconcile(&[]).unwrap();
        assert!(set.installed().is_empty(), "a departed prefix must not be held forever");
    }

    #[test]
    fn reconcile_survives_routes_something_else_already_removed() {
        // Exactly the drift this exists for: another writer took a route
        // and its interface vanished. The delete fails; reconcile must
        // still install the snapshot rather than bailing out.
        struct Flaky(Mutex<Vec<String>>);
        impl RouteProgrammer for Flaky {
            fn add_via_tun(&self, net: IpNet) -> Result<()> {
                self.0.lock().unwrap().push(format!("add {net}"));
                Ok(())
            }
            fn remove(&self, _net: IpNet) -> Result<()> {
                anyhow::bail!("no such process")
            }
            fn pin_underlay(&self, _h: std::net::IpAddr) -> Result<()> {
                Ok(())
            }
        }
        let set = RouteSet::new(Flaky(Mutex::new(Vec::new())));
        set.apply(&[net("10.0.1.0/24")]).unwrap();
        set.reconcile(&[net("10.0.5.0/24")]).expect("a failed delete must not abort");
        assert!(set.programmer.0.lock().unwrap().contains(&"add 10.0.5.0/24".to_string()));
    }


    #[test]
    fn reassert_reprograms_routes_another_writer_removed() {
        // The real failure this guards: a second endpoint on the same
        // host claims these prefixes, then its TUN disappears and takes
        // the routes with it. Our cache still says "installed", so
        // `apply` sees no diff and the hole never heals.
        let set = RouteSet::new(RecordingProgrammer::default());
        set.apply(&[net("10.99.1.1/32"), net("10.99.1.2/32")]).unwrap();
        set.programmer.calls.lock().unwrap().clear();

        // A no-op apply must stay a no-op — we still rely on the diff.
        set.apply(&[net("10.99.1.1/32"), net("10.99.1.2/32")]).unwrap();
        assert!(set.programmer.calls.lock().unwrap().is_empty());

        // Re-assert must re-issue every route regardless of the cache.
        set.reassert().unwrap();
        let calls = set.programmer.calls.lock().unwrap().clone();
        assert_eq!(calls, vec!["add 10.99.1.1/32", "add 10.99.1.2/32"]);
    }


    #[test]
    fn reassert_on_an_empty_set_does_nothing() {
        let set = RouteSet::new(RecordingProgrammer::default());
        set.reassert().unwrap();
        assert!(set.programmer.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn macos_ipv6_routes_carry_an_explicit_prefix_length() {
        // The bug this guards: macOS accepts `-net fd00::/64` and then
        // installs a DEFAULT route, ignoring the length in the string.
        // A relay's IPv6 site prefix would then capture all IPv6 traffic
        // on every member — and it fails silently, so nothing would say
        // so until someone lost connectivity.
        let a = macos_route_args("add", net("fd99::1:1/128"), "utun10");
        assert!(a.contains(&"-prefixlen".to_string()), "{a:?}");
        assert!(a.contains(&"128".to_string()), "{a:?}");
        // The destination must be the bare address; a slash form here is
        // exactly what gets misread.
        assert!(a.contains(&"fd99::1:1".to_string()), "{a:?}");
        assert!(!a.iter().any(|s| s.contains("::1:1/")), "no slash form: {a:?}");
        assert!(!a.contains(&"-net".to_string()), "-net is the form that misparses: {a:?}");

        let b = macos_route_args("add", net("fd00::/64"), "utun10");
        assert!(b.contains(&"64".to_string()), "a real prefix must keep its length: {b:?}");
    }

    #[test]
    fn macos_ipv4_routes_keep_the_slash_form() {
        // v4 has never had the problem, and -net a.b.c.d/len is the
        // documented spelling.
        let a = macos_route_args("add", net("10.99.1.0/24"), "utun10");
        assert!(a.contains(&"-net".to_string()), "{a:?}");
        assert!(a.contains(&"10.99.1.0/24".to_string()), "{a:?}");
        assert!(!a.contains(&"-prefixlen".to_string()), "{a:?}");
    }

    #[test]
    fn the_verb_is_the_only_difference_between_add_and_change() {
        // add falls back to change when the route already exists; if the
        // two ever diverged, re-asserting would install something else.
        let add = macos_route_args("add", net("fd99::1:1/128"), "utun10");
        let chg = macos_route_args("change", net("fd99::1:1/128"), "utun10");
        assert_eq!(add.len(), chg.len());
        let diffs: Vec<_> = add.iter().zip(&chg).filter(|(a, b)| a != b).collect();
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0], (&"add".to_string(), &"change".to_string()));
    }
}
