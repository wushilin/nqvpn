//! Node TLS identity (§3.3): a persistent self-signed certificate whose
//! SHA-256 fingerprint is pinned by the coordinator and carried in every
//! credential as `cert_fp`. The QUIC handshake is therefore the proof of
//! key possession — a stolen bearer credential is useless without the
//! matching private key.

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("certificate generation: {0}")]
    Gen(String),
    #[error("malformed stored identity: {0}")]
    Malformed(String),
}

/// A member's long-lived TLS identity: cert DER + PKCS#8 key DER.
#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

impl TlsIdentity {
    /// Generate a fresh self-signed identity. `name` is cosmetic (the
    /// fingerprint is what's verified), but useful in packet captures.
    pub fn generate(name: &str) -> Result<Self, IdentityError> {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()])
            .map_err(|e| IdentityError::Gen(e.to_string()))?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name.to_string());
        let key = rcgen::KeyPair::generate().map_err(|e| IdentityError::Gen(e.to_string()))?;
        let cert = params
            .self_signed(&key)
            .map_err(|e| IdentityError::Gen(e.to_string()))?;
        Ok(TlsIdentity {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        })
    }

    /// Load from `<dir>/tls.crt` + `<dir>/tls.key`, generating and
    /// persisting them on first use. Losing these files means the
    /// coordinator's pin no longer matches: admin reset required.
    pub fn load_or_create(dir: &Path, name: &str) -> Result<Self, IdentityError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        if cert_path.exists() && key_path.exists() {
            let cert_der = std::fs::read(&cert_path)?;
            let key_der = std::fs::read(&key_path)?;
            if cert_der.is_empty() || key_der.is_empty() {
                return Err(IdentityError::Malformed("empty cert or key file".into()));
            }
            return Ok(TlsIdentity { cert_der, key_der });
        }
        let id = TlsIdentity::generate(name)?;
        std::fs::write(&cert_path, &id.cert_der)?;
        write_private(&key_path, &id.key_der)?;
        Ok(id)
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_der(&self.cert_der)
    }

    /// How long this identity's files have existed, in seconds.
    ///
    /// Taken from the certificate file's mtime rather than the
    /// certificate's own validity: our verifiers authenticate by
    /// fingerprint and never look at `notAfter`, so "when did we start
    /// using this key" is the question that actually matters for
    /// rotation. Returns `None` if the age cannot be determined, which
    /// callers must read as "do not rotate" — guessing would rotate
    /// needlessly, and rotation is not free.
    pub fn age_secs(dir: &Path) -> Option<u64> {
        let meta = std::fs::metadata(dir.join("tls.crt")).ok()?;
        let created = meta.modified().ok()?;
        std::time::SystemTime::now().duration_since(created).ok().map(|d| d.as_secs())
    }

    /// Generate a replacement identity beside the live one, without
    /// touching it.
    ///
    /// The two-step exists so rotation is transactional. The new key is
    /// staged, registered with the coordinator, and only then promoted;
    /// a crash at any point leaves the old identity in place and still
    /// working, because the coordinator keeps accepting it for the whole
    /// overlap. Promoting first would risk a member holding a key nobody
    /// has been told about.
    pub fn stage_replacement(dir: &Path, name: &str) -> Result<Self, IdentityError> {
        let id = TlsIdentity::generate(name)?;
        std::fs::write(dir.join("tls.crt.staged"), &id.cert_der)?;
        write_private(&dir.join("tls.key.staged"), &id.key_der)?;
        Ok(id)
    }

    /// Promote a staged identity to the live one.
    ///
    /// Rename, not copy: on the same filesystem it is atomic, so there is
    /// no instant where the identity is half-replaced. The key moves
    /// first — a cert without its key is unusable, whereas a key without
    /// its cert is merely unused.
    pub fn promote_staged(dir: &Path) -> Result<(), IdentityError> {
        let staged_key = dir.join("tls.key.staged");
        let staged_crt = dir.join("tls.crt.staged");
        if !staged_key.exists() || !staged_crt.exists() {
            return Err(IdentityError::Malformed("no staged identity to promote".into()));
        }
        std::fs::rename(&staged_key, dir.join("tls.key"))?;
        std::fs::rename(&staged_crt, dir.join("tls.crt"))?;
        Ok(())
    }

    /// Throw away a staged identity that was never registered.
    pub fn discard_staged(dir: &Path) {
        let _ = std::fs::remove_file(dir.join("tls.key.staged"));
        let _ = std::fs::remove_file(dir.join("tls.crt.staged"));
    }

    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.clone())
            .expect("stored key is valid PKCS#8 DER")
    }
}

/// Canonical fingerprint form used everywhere: `sha256:<lowercase hex>`.
pub fn fingerprint_der(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    format!("sha256:{}", hex::encode(digest))
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), IdentityError> {
    std::fs::write(path, bytes)?;
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
    fn generate_has_stable_fingerprint() {
        let id = TlsIdentity::generate("node-a").unwrap();
        assert!(id.fingerprint().starts_with("sha256:"));
        assert_eq!(id.fingerprint(), id.fingerprint());
        assert_eq!(id.fingerprint(), fingerprint_der(&id.cert_der));
    }

    #[test]
    fn distinct_identities_differ() {
        let a = TlsIdentity::generate("a").unwrap();
        let b = TlsIdentity::generate("b").unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn persists_and_reloads_identically() {
        let dir = tempfile::tempdir().unwrap();
        let a = TlsIdentity::load_or_create(dir.path(), "node-a").unwrap();
        let b = TlsIdentity::load_or_create(dir.path(), "node-a").unwrap();
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.cert_der, b.cert_der);
    }

    #[cfg(unix)]
    #[test]
    fn key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        TlsIdentity::load_or_create(dir.path(), "node-a").unwrap();
        let mode = std::fs::metadata(dir.path().join("tls.key")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_staged_identity_does_not_disturb_the_live_one() {
        // The transactional property: staging must be invisible until it
        // is promoted, so a crash between the two leaves a member with
        // the identity the coordinator still accepts.
        let dir = tempfile::tempdir().unwrap();
        let live = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        let staged = TlsIdentity::stage_replacement(dir.path(), "m").unwrap();
        assert_ne!(live.fingerprint(), staged.fingerprint());

        let reloaded = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        assert_eq!(
            reloaded.fingerprint(),
            live.fingerprint(),
            "staging must not change what a restart loads"
        );
    }

    #[test]
    fn promoting_swaps_the_identity_for_good() {
        let dir = tempfile::tempdir().unwrap();
        let live = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        let staged = TlsIdentity::stage_replacement(dir.path(), "m").unwrap();
        TlsIdentity::promote_staged(dir.path()).unwrap();

        let reloaded = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        assert_eq!(reloaded.fingerprint(), staged.fingerprint());
        assert_ne!(reloaded.fingerprint(), live.fingerprint());
        // The staged files are consumed, not left to be promoted twice.
        assert!(!dir.path().join("tls.crt.staged").exists());
        assert!(TlsIdentity::promote_staged(dir.path()).is_err());
    }

    #[test]
    fn a_discarded_staging_leaves_the_live_identity_alone() {
        // The abort path: registration failed, so the new key is thrown
        // away and the member carries on with the one that works.
        let dir = tempfile::tempdir().unwrap();
        let live = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        TlsIdentity::stage_replacement(dir.path(), "m").unwrap();
        TlsIdentity::discard_staged(dir.path());
        assert!(TlsIdentity::promote_staged(dir.path()).is_err());
        assert_eq!(
            TlsIdentity::load_or_create(dir.path(), "m").unwrap().fingerprint(),
            live.fingerprint()
        );
    }

    #[test]
    fn a_fresh_identity_reports_an_age() {
        let dir = tempfile::tempdir().unwrap();
        assert!(TlsIdentity::age_secs(dir.path()).is_none(), "nothing there yet");
        TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        let age = TlsIdentity::age_secs(dir.path()).expect("age after creation");
        assert!(age < 60, "a just-created identity should be seconds old, got {age}");
    }
}
