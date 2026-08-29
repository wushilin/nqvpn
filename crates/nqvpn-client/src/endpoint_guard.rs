//! One endpoint per network per host (DESIGN.md §8).
//!
//! A host has a single routing table, but every endpoint — a client, or a
//! relay in its endpoint role — installs a route for *every* member
//! prefix pointing at its own TUN. That is correct in isolation and
//! mutually destructive in pairs: two endpoints on one host overwrite
//! each other's routes prefix by prefix, so a reply leaves through the
//! wrong tunnel and the peer's ingress filter then correctly drops it as
//! a source-spoof. Nothing logs an error; traffic simply stops.
//!
//! The configuration that causes it has no purpose anyway. A relay with
//! the endpoint role already *is* a full member — address, TUN, sessions,
//! ingress filter — so a client beside it duplicates the whole thing.
//! The one legitimate pairing is a **pure forwarder** relay
//! (`want_vpn_ip = false`, no gateway CIDRs): it takes no address and no
//! TUN, so it never claims the lock and never collides.
//!
//! This makes the broken shape refuse to start instead of failing
//! silently later.
//!
//! The exclusion is a real `flock`, not a pid file. The kernel drops an
//! flock when the holding process dies however it dies, so there is no
//! stale lock to reason about and — the reason a pid file will not do —
//! no chance of the holder's id being recycled to an unrelated process
//! and blocking startup forever.

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// Held for the life of the process. Dropping it (or dying) releases the
/// lock, because the kernel releases it when the descriptor closes.
#[derive(Debug)]
pub struct EndpointGuard {
    _file: File,
    path: PathBuf,
}

/// Where the lock lives.
///
/// `/var/run` is root-owned and not world-writable, which matters: an
/// endpoint runs as root for its TUN, and a predictable filename in a
/// world-writable directory that root opens for writing is a symlink
/// redirect waiting to happen. `/tmp` is only a fallback for unprivileged
/// runs and tests, where there is nothing to escalate to.
fn lock_dir() -> PathBuf {
    for candidate in ["/var/run", "/run"] {
        let dir = Path::new(candidate);
        if dir.is_dir() && faccess_write(dir) {
            return dir.to_path_buf();
        }
    }
    std::env::temp_dir()
}

fn faccess_write(dir: &Path) -> bool {
    // Probe rather than reason about uid/mode: the answer we need is
    // simply "can this process create a file here".
    let probe = dir.join(format!(".nqvpn-write-probe-{}", std::process::id()));
    match File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

impl EndpointGuard {
    /// Claim the endpoint role for `network_id` on this host.
    pub fn acquire(network_id: &str, who: &str) -> Result<EndpointGuard> {
        EndpointGuard::acquire_in(&lock_dir(), network_id, who)
    }

    /// Testable form: the caller chooses the directory.
    pub fn acquire_in(dir: &Path, network_id: &str, who: &str) -> Result<EndpointGuard> {
        // One lock per network, not per host: endpoints on different
        // networks own disjoint prefixes and do not fight. The id comes
        // from config, so strip anything that could name a path.
        let safe: String = network_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
            .collect();
        let path = dir.join(format!("nqvpn-{safe}.lock"));

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening endpoint lock {}", path.display()))?;

        // SAFETY: `file` owns the descriptor for the whole call, and
        // flock only ever touches kernel-side lock state for it.
        let locked = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        if !locked {
            let mut held_by = String::new();
            let _ = file.read_to_string(&mut held_by);
            let held_by = held_by.trim();
            let held_by = if held_by.is_empty() { "unknown" } else { held_by };
            bail!(
                "another nqvpn endpoint for network {network_id} is already running on this \
                 host ({held_by}).\n\
                 \n\
                 Two endpoints on one host overwrite each other's routes, and traffic then \
                 stops silently in one direction. A relay that has a VPN address is already \
                 a full member of the network, so running a client beside it is redundant — \
                 stop one of them.\n\
                 \n\
                 If that relay is meant to be a pure forwarder, set want_vpn_ip = false and \
                 give it no gateway CIDRs; it will then take no address and never conflict.\n\
                 \n\
                 Lock: {}",
                path.display()
            );
        }

        // Record who holds it, purely so the message above can be useful.
        // The lock itself is the flock, not this text.
        file.set_len(0).ok();
        file.seek(SeekFrom::Start(0)).ok();
        let _ = writeln!(file, "pid {} — {}", std::process::id(), who);
        let _ = file.flush();

        tracing::debug!(lock = %path.display(), "endpoint lock acquired");
        Ok(EndpointGuard { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // flock is per open file description, so two guards in one process
    // exercise the same exclusion a second process would hit.
    #[test]
    fn a_second_endpoint_on_the_same_network_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let _first = EndpointGuard::acquire_in(dir.path(), "acme-prod", "relay aws").unwrap();
        let err = EndpointGuard::acquire_in(dir.path(), "acme-prod", "client laptop-1")
            .expect_err("second endpoint must be refused");
        let msg = format!("{err}");
        assert!(msg.contains("already running"), "{msg}");
        // Naming the holder is the difference between a useful error and
        // a puzzle.
        assert!(msg.contains("relay aws"), "message must name the holder: {msg}");
        // And it must say what to do, not merely that something is wrong.
        assert!(msg.contains("want_vpn_ip = false"), "{msg}");
    }

    #[test]
    fn different_networks_do_not_conflict() {
        // Disjoint prefixes, so no route contention and no reason to block.
        let dir = tempfile::tempdir().unwrap();
        let _a = EndpointGuard::acquire_in(dir.path(), "acme-prod", "client a").unwrap();
        let _b = EndpointGuard::acquire_in(dir.path(), "other-net", "client b").unwrap();
    }

    #[test]
    fn releasing_lets_the_next_one_in() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _g = EndpointGuard::acquire_in(dir.path(), "acme-prod", "client a").unwrap();
        }
        EndpointGuard::acquire_in(dir.path(), "acme-prod", "client b")
            .expect("lock must be released on drop");
    }

    #[test]
    fn a_leftover_file_does_not_block_startup() {
        // The crash case. With flock there is nothing to clean up: the
        // file may survive, but the lock did not, so the next endpoint
        // starts. A pid file would have needed liveness checks here, and
        // would still have been wrong under pid reuse.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nqvpn-acme-prod.lock");
        std::fs::write(&path, "pid 999999 — ghost from a kill -9\n").unwrap();
        let g = EndpointGuard::acquire_in(dir.path(), "acme-prod", "client a")
            .expect("a leftover file must not block startup");
        // And the record is replaced, not appended to.
        let contents = std::fs::read_to_string(g.path()).unwrap();
        assert!(contents.contains("client a"), "{contents}");
        assert!(!contents.contains("ghost"), "stale text must be truncated: {contents}");
    }

    #[test]
    fn network_id_cannot_escape_the_lock_directory() {
        let dir = tempfile::tempdir().unwrap();
        let _g = EndpointGuard::acquire_in(dir.path(), "../../etc/evil", "client a").unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().flatten().collect();
        assert_eq!(entries.len(), 1);
        let name = entries[0].file_name().into_string().unwrap();
        assert!(!name.contains('/'), "{name}");
        assert!(name.starts_with("nqvpn-"), "{name}");
    }
}
