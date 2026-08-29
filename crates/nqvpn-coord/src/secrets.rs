//! Coordinator-managed member and admin secrets (`secrets.toml`).
//!
//! Secrets used to live only in the network config, which meant adding a
//! member required hand-running argon2. That friction is why every member
//! in a deployment ends up sharing one secret — and a shared secret turns
//! trust-on-first-use into a land grab, where whoever holds it can claim
//! any name that has not been pinned yet. Making per-member secrets the
//! *easy* path is the point of this file.
//!
//! Two rules the store exists to enforce:
//!
//!   * **only the hash is kept.** A secret is shown once, at creation,
//!     and cannot be read back. There is no "reveal" endpoint to leak,
//!     and a stolen store yields argon2 hashes rather than credentials.
//!   * **a secret carries its own blast radius.** A `client` secret can
//!     never join as a relay, and an `admin` secret can never join a
//!     network at all. The kind travels with the credential, so a leaked
//!     client secret cannot be escalated by claiming a different role.
//!
//! The store is coordinator-owned mutable state, like the registry — not
//! operator-edited config. Network config `secret_hash` entries still
//! work and are consulted as a fallback, so an existing deployment keeps
//! running and migrates one member at a time.

use anyhow::{Context, Result};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// What a secret may be used for. This *is* the blast radius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecretKind {
    /// Signs in to the admin UI. Never valid for joining a network.
    Admin,
    /// Joins as a relay: may forward, and may register routes.
    Relay,
    /// Joins as a client. Cannot register routes or advertise an address.
    Client,
}

impl SecretKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SecretKind::Admin => "admin",
            SecretKind::Relay => "relay",
            SecretKind::Client => "client",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretRecord {
    pub client_id: String,
    pub kind: SecretKind,
    /// argon2 hash. The secret itself is never stored anywhere.
    pub secret_hash: String,
    /// Which network this credential belongs to. `None` for admins,
    /// who are not members of any network.
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub created_unix: u64,
    /// Revoked without being deleted, so the name stays reserved and the
    /// history of who held it is not silently erased.
    #[serde(default)]
    pub disabled: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretStore {
    #[serde(default)]
    pub secrets: Vec<SecretRecord>,
}

/// A freshly minted secret. The plaintext exists only in this value, on
/// its way to the operator — it is never written down.
#[derive(Debug, Clone)]
pub struct MintedSecret {
    pub client_id: String,
    pub kind: SecretKind,
    pub secret: String,
}

pub fn hash_secret(secret: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing secret: {e}"))
}

/// A secret with enough entropy that guessing is not a threat model.
pub fn generate_secret() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    // URL-safe and no padding, so it survives being pasted into a config,
    // a shell, or a query string without escaping.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(raw)
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

    /// Atomic durable commit, same discipline as the registry: a secret
    /// the operator has already been shown must survive a crash, or they
    /// hold a credential the coordinator has never heard of.
    pub fn commit(&self, path: &Path) -> Result<()> {
        let dir = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(dir)?;
        let tmp: PathBuf = path.with_extension("toml.tmp");
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            // The file holds argon2 hashes rather than secrets, but it is
            // still an authentication database and has no business being
            // world-readable.
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            }
            f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn find(&self, client_id: &str, network: Option<&str>) -> Option<&SecretRecord> {
        self.secrets
            .iter()
            .find(|s| s.client_id == client_id && s.network.as_deref() == network)
    }

    /// Mint a secret, replacing any existing one for the same identity.
    ///
    /// Replacing rather than refusing makes this the rotation path too:
    /// an operator who has lost a secret mints a new one, and the old one
    /// stops working immediately.
    pub fn mint(
        &mut self,
        client_id: &str,
        kind: SecretKind,
        network: Option<&str>,
        now: u64,
    ) -> Result<MintedSecret> {
        let secret = generate_secret();
        let hash = hash_secret(&secret)?;
        self.secrets
            .retain(|s| !(s.client_id == client_id && s.network.as_deref() == network));
        self.secrets.push(SecretRecord {
            client_id: client_id.to_string(),
            kind,
            secret_hash: hash,
            network: network.map(|s| s.to_string()),
            created_unix: now,
            disabled: false,
        });
        Ok(MintedSecret { client_id: client_id.to_string(), kind, secret: secret.clone() })
    }

    pub fn remove(&mut self, client_id: &str, network: Option<&str>) -> bool {
        let before = self.secrets.len();
        self.secrets
            .retain(|s| !(s.client_id == client_id && s.network.as_deref() == network));
        self.secrets.len() != before
    }

    pub fn set_disabled(&mut self, client_id: &str, network: Option<&str>, disabled: bool) -> bool {
        match self
            .secrets
            .iter_mut()
            .find(|s| s.client_id == client_id && s.network.as_deref() == network)
        {
            Some(s) => {
                s.disabled = disabled;
                true
            }
            None => false,
        }
    }

    /// Verify a secret against this store.
    ///
    /// `Ok(true)` means the store authenticated it. `Ok(false)` means the
    /// store has no opinion — the caller falls back to the network
    /// config. `Err` means the store *does* know this identity and
    /// refused it, which must never fall through to the fallback.
    pub fn verify(
        &self,
        client_id: &str,
        secret: &str,
        network: Option<&str>,
        want: SecretKind,
    ) -> Result<bool, SecretRefusal> {
        let Some(rec) = self.find(client_id, network) else {
            return Ok(false);
        };
        if rec.disabled {
            return Err(SecretRefusal::Disabled);
        }
        // The kind is checked before the secret, so a client credential
        // presented for a relay join is refused even if it is correct.
        if rec.kind != want {
            return Err(SecretRefusal::WrongKind { have: rec.kind, want });
        }
        let parsed = PasswordHash::new(&rec.secret_hash).map_err(|_| SecretRefusal::Malformed)?;
        Argon2::default()
            .verify_password(secret.as_bytes(), &parsed)
            .map_err(|_| SecretRefusal::BadSecret)?;
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretRefusal {
    #[error("secret is administratively disabled")]
    Disabled,
    #[error("this is a {} secret, not a {} secret", .have.as_str(), .want.as_str())]
    WrongKind { have: SecretKind, want: SecretKind },
    #[error("secret does not match")]
    BadSecret,
    #[error("stored hash is malformed")]
    Malformed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_with(kind: SecretKind, net: Option<&str>) -> (SecretStore, String) {
        let mut s = SecretStore::default();
        let m = s.mint("m1", kind, net, 100).unwrap();
        (s, m.secret)
    }

    #[test]
    fn a_minted_secret_verifies_and_is_never_stored_in_the_clear() {
        let (store, secret) = store_with(SecretKind::Client, Some("n1"));
        assert_eq!(store.verify("m1", &secret, Some("n1"), SecretKind::Client), Ok(true));

        // The plaintext must appear nowhere in what gets written to disk.
        let serialized = toml::to_string_pretty(&store).unwrap();
        assert!(!serialized.contains(&secret), "the secret must not be persisted");
        assert!(serialized.contains("$argon2"), "only the hash is kept");
    }

    #[test]
    fn a_wrong_secret_is_refused_and_does_not_fall_through() {
        // The dangerous failure would be returning Ok(false) here: the
        // caller would then try the network config and might authenticate
        // against a stale shared secret the operator thought they had
        // replaced.
        let (store, _secret) = store_with(SecretKind::Client, Some("n1"));
        assert_eq!(
            store.verify("m1", "wrong", Some("n1"), SecretKind::Client),
            Err(SecretRefusal::BadSecret)
        );
    }

    #[test]
    fn an_unknown_identity_defers_to_the_fallback() {
        let (store, _secret) = store_with(SecretKind::Client, Some("n1"));
        assert_eq!(store.verify("someone-else", "x", Some("n1"), SecretKind::Client), Ok(false));
    }

    #[test]
    fn a_client_secret_cannot_be_used_for_a_relay_join() {
        // The blast-radius rule: the kind travels with the credential, so
        // a leaked client secret cannot be escalated by claiming to be a
        // relay — which would let it register routes.
        let (store, secret) = store_with(SecretKind::Client, Some("n1"));
        assert_eq!(
            store.verify("m1", &secret, Some("n1"), SecretKind::Relay),
            Err(SecretRefusal::WrongKind {
                have: SecretKind::Client,
                want: SecretKind::Relay
            })
        );
    }

    #[test]
    fn an_admin_secret_can_never_join_a_network() {
        let mut store = SecretStore::default();
        let m = store.mint("root", SecretKind::Admin, None, 100).unwrap();
        for want in [SecretKind::Client, SecretKind::Relay] {
            assert!(
                store.verify("root", &m.secret, None, want).is_err(),
                "an admin credential must never authenticate a join"
            );
        }
        assert_eq!(store.verify("root", &m.secret, None, SecretKind::Admin), Ok(true));
    }

    #[test]
    fn networks_are_separate_namespaces() {
        // The same member name in two networks is legitimate and must not
        // share a credential.
        let (store, secret) = store_with(SecretKind::Client, Some("n1"));
        assert_eq!(store.verify("m1", &secret, Some("n2"), SecretKind::Client), Ok(false));
    }

    #[test]
    fn disabling_revokes_without_deleting() {
        let (mut store, secret) = store_with(SecretKind::Client, Some("n1"));
        assert!(store.set_disabled("m1", Some("n1"), true));
        assert_eq!(
            store.verify("m1", &secret, Some("n1"), SecretKind::Client),
            Err(SecretRefusal::Disabled),
            "a disabled secret must be refused, not merely ignored"
        );
        // Still present, so the name stays reserved.
        assert!(store.find("m1", Some("n1")).is_some());
        assert!(store.set_disabled("m1", Some("n1"), false));
        assert_eq!(store.verify("m1", &secret, Some("n1"), SecretKind::Client), Ok(true));
    }

    #[test]
    fn minting_again_replaces_and_invalidates_the_old_secret() {
        // This is the rotation path: the previous secret must stop
        // working the moment a new one is issued.
        let (mut store, old) = store_with(SecretKind::Client, Some("n1"));
        let new = store.mint("m1", SecretKind::Client, Some("n1"), 200).unwrap().secret;
        assert_ne!(old, new);
        assert_eq!(store.verify("m1", &new, Some("n1"), SecretKind::Client), Ok(true));
        assert_eq!(
            store.verify("m1", &old, Some("n1"), SecretKind::Client),
            Err(SecretRefusal::BadSecret)
        );
        assert_eq!(store.secrets.len(), 1, "replacing must not leave a duplicate");
    }

    #[test]
    fn two_mints_never_produce_the_same_secret() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        assert!(a.len() >= 40, "32 random bytes should not encode this short: {}", a.len());
    }

    #[test]
    fn the_store_round_trips_through_disk_with_tight_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.toml");
        let (store, secret) = store_with(SecretKind::Relay, Some("n1"));
        store.commit(&path).unwrap();

        let back = SecretStore::load_or_create(&path).unwrap();
        assert_eq!(back.verify("m1", &secret, Some("n1"), SecretKind::Relay), Ok(true));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "an auth database must not be group/world readable");
        }
    }

    #[test]
    fn a_missing_store_is_empty_rather_than_an_error() {
        // A deployment that has never minted anything must still start,
        // falling back to the network config for every member.
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::load_or_create(&dir.path().join("nope.toml")).unwrap();
        assert!(store.secrets.is_empty());
        assert_eq!(store.verify("anyone", "x", Some("n1"), SecretKind::Client), Ok(false));
    }
}
