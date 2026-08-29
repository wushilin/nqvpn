//! Node TLS identity: a self-signed certificate generated on first run
//! and kept in the node's state directory. Its SHA-256 fingerprint is
//! recorded by the coordinator at every join and carried in the
//! credential as `cert_fp`, so a QUIC handshake proves the peer holds
//! the key behind the credential it presents.
//!
//! Nothing pins it. Delete the files and the node simply has a new
//! certificate at its next join; the coordinator records that one
//! instead. This is deliberately not an identity the operator manages —
//! the node id and secret are.

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

/// A node's TLS identity: cert DER + PKCS#8 key DER, validated at load.
#[derive(Clone)]
pub struct TlsIdentity {
    pub cert_der: Vec<u8>,
    key_der: Vec<u8>,
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
        TlsIdentity::from_der(cert.der().to_vec(), key.serialize_der())
    }

    pub fn from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self, IdentityError> {
        if cert_der.is_empty() {
            return Err(IdentityError::Malformed("empty certificate".into()));
        }
        PrivateKeyDer::try_from(key_der.as_slice())
            .map_err(|e| IdentityError::Malformed(format!("private key: {e}")))?;
        Ok(TlsIdentity { cert_der, key_der })
    }

    /// Load from `<dir>/tls.crt` + `<dir>/tls.key`, generating and
    /// persisting them on first use — or when what is there cannot be
    /// read. A corrupt file is replaced rather than fatal: a certificate
    /// is cheap, and the coordinator learns the new one at the next join.
    pub fn load_or_create(dir: &Path, name: &str) -> Result<Self, IdentityError> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("tls.crt");
        let key_path = dir.join("tls.key");
        if let (Ok(c), Ok(k)) = (std::fs::read(&cert_path), std::fs::read(&key_path)) {
            match TlsIdentity::from_der(c, k) {
                Ok(id) => return Ok(id),
                Err(e) => tracing::warn!("stored TLS identity unusable ({e}); generating a new one"),
            }
        }
        let id = TlsIdentity::generate(name)?;
        write_atomic(&cert_path, &id.cert_der, 0o644)?;
        write_atomic(&key_path, &id.key_der, 0o600)?;
        Ok(id)
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_der(&self.cert_der)
    }

    pub fn cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.cert_der.clone())]
    }

    pub fn private_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::try_from(self.key_der.clone()).expect("validated in from_der")
    }

    /// PEM forms, for handing to an HTTPS server that wants files.
    pub fn cert_pem(&self) -> String {
        pem("CERTIFICATE", &self.cert_der)
    }

    pub fn key_pem(&self) -> String {
        pem("PRIVATE KEY", &self.key_der)
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Canonical fingerprint form used everywhere: `sha256:<lowercase hex>`.
pub fn fingerprint_der(cert_der: &[u8]) -> String {
    let digest = Sha256::digest(cert_der);
    format!("sha256:{}", hex::encode(digest))
}

fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), IdentityError> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_has_stable_fingerprint() {
        let id = TlsIdentity::generate("node-a").unwrap();
        assert!(id.fingerprint().starts_with("sha256:"));
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
    fn a_corrupt_key_is_replaced_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let a = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        std::fs::write(dir.path().join("tls.key"), b"garbage").unwrap();
        let b = TlsIdentity::load_or_create(dir.path(), "m").unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        // And the replacement is what a further restart loads.
        assert_eq!(TlsIdentity::load_or_create(dir.path(), "m").unwrap().fingerprint(), b.fingerprint());
    }

    #[test]
    fn pem_forms_are_well_formed() {
        let id = TlsIdentity::generate("x").unwrap();
        assert!(id.cert_pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(id.key_pem().contains("-----END PRIVATE KEY-----"));
        let parsed = rustls_pemfile::certs(&mut id.cert_pem().as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].as_ref(), id.cert_der.as_slice());
    }
}
