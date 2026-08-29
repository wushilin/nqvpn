//! Coordinator-managed member secrets (`secrets.toml`, 0600).
//!
//! A member is a node id and a secret, nothing more, so the secret is
//! kept in the clear: an operator can show it again, put it on a new
//! machine, or rotate it, without a one-shot "copy it now" step. Secrets
//! are generated (32 random bytes), never chosen, so there is nothing to
//! guess and no hash to slow an attacker down with. What protects this
//! file is the file: it lives in the state directory, not beside the
//! network config that ends up in version control.
//!
//! A managed secret wins over the `secret` in the network TOML. That is
//! how a member is re-keyed without touching config: mint a new one and
//! the old stops working at once.

use anyhow::{Context, Result};
use nqvpn_proto::types::NodeId;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub network: String,
    pub node_id: NodeId,
    pub secret: String,
    #[serde(default)]
    pub created_unix: u64,
    /// Refused without being deleted, so the history stays.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretStore {
    #[serde(default)]
    pub members: Vec<SecretRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The store holds this member and the secret matches.
    Match,
    /// The store holds this member and the secret does not match. Final:
    /// the config secret must not be consulted.
    Mismatch,
    /// The store holds this member but it was revoked.
    Disabled,
    /// The store has no opinion; fall back to the network config.
    Unknown,
}

/// A secret with enough entropy that guessing is not a threat model.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(raw)
}

/// Compare two secrets without leaking where they differ.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

impl SecretStore {
    pub fn load_or_create(path: &Path) -> Result<SecretStore> {
        if !path.exists() {
            return Ok(SecretStore::default());
        }
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    /// Atomic durable commit, 0600: a secret the operator has already
    /// been shown must survive a crash.
    pub fn commit(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp: PathBuf = path.with_extension("toml.tmp");
        {
            let mut opts = OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn find(&self, network: &str, node_id: NodeId) -> Option<&SecretRecord> {
        self.members.iter().find(|s| s.network == network && s.node_id == node_id)
    }

    /// Mint a secret, replacing any existing one for the same member.
    /// This is also rotation: the previous secret stops working now.
    pub fn mint(&mut self, network: &str, node_id: NodeId, now: u64) -> String {
        let secret = generate_secret();
        self.members.retain(|s| !(s.network == network && s.node_id == node_id));
        self.members.push(SecretRecord {
            network: network.to_string(),
            node_id,
            secret: secret.clone(),
            created_unix: now,
            disabled: false,
        });
        secret
    }

    pub fn remove(&mut self, network: &str, node_id: NodeId) -> bool {
        let before = self.members.len();
        self.members.retain(|s| !(s.network == network && s.node_id == node_id));
        self.members.len() != before
    }

    pub fn set_disabled(&mut self, network: &str, node_id: NodeId, disabled: bool) -> bool {
        match self.members.iter_mut().find(|s| s.network == network && s.node_id == node_id) {
            Some(s) => {
                s.disabled = disabled;
                true
            }
            None => false,
        }
    }

    pub fn verify(&self, network: &str, node_id: NodeId, secret: &str) -> Verdict {
        let Some(rec) = self.find(network, node_id) else {
            return Verdict::Unknown;
        };
        if rec.disabled {
            return Verdict::Disabled;
        }
        if constant_time_eq(&rec.secret, secret) {
            Verdict::Match
        } else {
            Verdict::Mismatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_verify_rotate() {
        let mut s = SecretStore::default();
        let a = s.mint("n1", 7, 100);
        assert_eq!(s.verify("n1", 7, &a), Verdict::Match);
        assert_eq!(s.verify("n1", 7, "wrong"), Verdict::Mismatch, "must not fall through");
        assert_eq!(s.verify("n1", 8, &a), Verdict::Unknown);
        assert_eq!(s.verify("n2", 7, &a), Verdict::Unknown, "networks are namespaces");
        let b = s.mint("n1", 7, 200);
        assert_ne!(a, b);
        assert_eq!(s.verify("n1", 7, &a), Verdict::Mismatch);
        assert_eq!(s.verify("n1", 7, &b), Verdict::Match);
        assert_eq!(s.members.len(), 1);
        assert!(s.set_disabled("n1", 7, true));
        assert_eq!(s.verify("n1", 7, &b), Verdict::Disabled);
        assert!(s.remove("n1", 7));
        assert_eq!(s.verify("n1", 7, &b), Verdict::Unknown);
    }

    #[test]
    fn constant_time_eq_is_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn the_store_round_trips_through_disk_with_tight_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.toml");
        let mut s = SecretStore::default();
        let secret = s.mint("n1", 3, 1);
        s.commit(&path).unwrap();
        let back = SecretStore::load_or_create(&path).unwrap();
        assert_eq!(back.verify("n1", 3, &secret), Verdict::Match);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "an auth database must not be group/world readable");
        }
        assert!(SecretStore::load_or_create(&dir.path().join("nope.toml")).unwrap().members.is_empty());
    }
}
