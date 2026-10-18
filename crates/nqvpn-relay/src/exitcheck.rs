//! Best-effort self-check for an internet-exit relay: is the host actually
//! configured to egress VPN traffic to the internet — IP forwarding on,
//! and a masquerade rule covering tun-sourced traffic leaving the internet
//! uplink? The reading is reported to the coordinator as its own control
//! message; the coordinator publishes this relay's default route only
//! while both are true, so a designated-but-misconfigured host never
//! attracts traffic it would drop. The admin view shows which check is
//! missing. Runs as root on a relay, so the firewall is readable; a host
//! whose masquerade is configured in a way this cannot see is treated as
//! not ready. Linux-only; elsewhere it reports "unknown" (both false).

use nqvpn_proto::control::ExitReadiness;
use std::path::PathBuf;
use std::process::Command;

/// Where the tools below may live. Searched in this order instead of
/// `$PATH`: this runs as root, and must not run whatever a writable
/// directory early in the environment's path happens to provide.
const TOOL_DIRS: [&str; 4] = ["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// The absolute path of a system tool, if installed in a system
/// directory.
fn tool(name: &str) -> Option<PathBuf> {
    TOOL_DIRS.iter().map(|d| PathBuf::from(d).join(name)).find(|p| p.is_file())
}

/// Run a system tool by absolute path; its stdout, or nothing.
fn run(name: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(tool(name)?).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// One reading of egress readiness. Cheap enough for a ~30s timer; not
/// meant to run per-heartbeat. It spawns processes: call it from a
/// blocking context (`spawn_blocking`), never on an async worker.
pub fn detect() -> ExitReadiness {
    ExitReadiness { ip_forward: ip_forward_on(), masquerade: masquerade_covers_egress() }
}

#[cfg(target_os = "linux")]
fn ip_forward_on() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward").map(|s| s.trim() == "1").unwrap_or(false)
}

#[cfg(not(target_os = "linux"))]
fn ip_forward_on() -> bool {
    false
}

/// The interface of the default (internet) route, if any — the path
/// forwarded tun traffic takes on its way out.
fn egress_iface() -> Option<String> {
    let s = run("ip", &["route", "show", "default"])?;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev" {
                return it.next().map(str::to_string);
            }
        }
    }
    None
}

/// Is there a masquerade rule that would apply to forwarded traffic
/// leaving the internet uplink? Best-effort across nft and iptables
/// (nft-backed or legacy). We accept a masquerade rule that names the
/// egress interface, or that names no output interface at all (e.g. a
/// source-scoped rule) — both cover tun-sourced, internet-bound traffic in
/// a normal gateway. A rule scoped to a *different* interface is ignored.
fn masquerade_covers_egress() -> bool {
    let egress = egress_iface();
    let mut text = String::new();
    for cmd in [
        ["nft", "list", "ruleset"].as_slice(),
        ["iptables-save", "-t", "nat"].as_slice(),
        ["iptables-legacy-save", "-t", "nat"].as_slice(),
        ["ip6tables-save", "-t", "nat"].as_slice(),
    ] {
        if let Some(o) = run(cmd[0], &cmd[1..]) {
            text.push_str(&o);
            text.push('\n');
        }
    }
    for line in text.lines() {
        let l = line.to_ascii_lowercase();
        if !l.contains("masquerade") {
            continue;
        }
        // A rule naming our egress interface certainly applies.
        if let Some(dev) = &egress {
            let dev = dev.to_ascii_lowercase();
            if l.contains(&format!("oifname \"{dev}\"")) || l.contains(&format!("-o {dev} ")) || l.ends_with(&format!("-o {dev}")) {
                return true;
            }
        }
        // A masquerade with no output-interface qualifier applies broadly
        // (e.g. a source-scoped `-s <lan> -j MASQUERADE`).
        if !l.contains("oifname") && !l.contains("-o ") {
            return true;
        }
    }
    false
}
