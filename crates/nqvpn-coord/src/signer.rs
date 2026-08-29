//! Signing keyring (§3.3): active/retiring Ed25519 keys with `kid`s,
//! persisted 0600 in the state dir, restart-safe at every rotation stage.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nqvpn_proto::control::KeyInfo;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKey {
    kid: String,
    /// base64(32-byte ed25519 secret)
    secret: String,
    /// "active" | "retiring"
    state: String,
    created_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredKeyring {
    keys: Vec<StoredKey>,
}

pub struct Keyring {
    keys: Vec<(StoredKey, SigningKey)>,
}

impl Keyring {
    /// Load the keyring, generating a first active key if none exists.
    pub fn load_or_create(path: &Path, now: u64) -> Result<Self> {
        let stored: StoredKeyring = if path.exists() {
            serde_json::from_str(&std::fs::read_to_string(path)?)
                .with_context(|| format!("parsing {}", path.display()))?
        } else {
            let sk = SigningKey::generate(&mut rand::rngs::OsRng);
            let stored = StoredKeyring {
                keys: vec![StoredKey {
                    kid: format!("k{now}"),
                    secret: B64.encode(sk.to_bytes()),
                    state: "active".into(),
                    created_unix: now,
                }],
            };
            write_0600(path, &serde_json::to_string_pretty(&stored)?)?;
            stored
        };
        let mut keys = Vec::new();
        for k in stored.keys {
            let bytes: [u8; 32] = B64
                .decode(&k.secret)
                .ok()
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("keyring: bad secret for kid {}", k.kid))?;
            let sk = SigningKey::from_bytes(&bytes);
            keys.push((k, sk));
        }
        if !keys.iter().any(|(k, _)| k.state == "active") {
            anyhow::bail!("keyring has no active key");
        }
        Ok(Keyring { keys })
    }

    pub fn active(&self) -> (&str, &SigningKey) {
        let (meta, sk) = self
            .keys
            .iter()
            .find(|(k, _)| k.state == "active")
            .expect("validated at load");
        (&meta.kid, sk)
    }

    /// Full verify set (active + retiring) for join responses / KeySet.
    pub fn key_infos(&self) -> Vec<KeyInfo> {
        self.keys
            .iter()
            .map(|(k, sk)| KeyInfo {
                kid: k.kid.clone(),
                key: B64.encode(sk.verifying_key().to_bytes()),
                state: k.state.clone(),
            })
            .collect()
    }

    pub fn verifying_keys(&self) -> Vec<(String, VerifyingKey)> {
        self.keys
            .iter()
            .map(|(k, sk)| (k.kid.clone(), sk.verifying_key()))
            .collect()
    }
}

fn write_0600(path: &Path, contents: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reloads_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.json");
        let k1 = Keyring::load_or_create(&path, 1000).unwrap();
        let (kid1, _) = k1.active();
        let infos1 = k1.key_infos();
        let k2 = Keyring::load_or_create(&path, 2000).unwrap();
        let (kid2, _) = k2.active();
        assert_eq!(kid1, kid2);
        assert_eq!(infos1, k2.key_infos());
    }

    #[cfg(unix)]
    #[test]
    fn keyring_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("signing.json");
        Keyring::load_or_create(&path, 1000).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
