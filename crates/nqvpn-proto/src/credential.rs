//! Member credential: a compact JWS (JWT) signed EdDSA/Ed25519 by the
//! coordinator keyring, verified offline everywhere (DESIGN.md §3.3).
//!
//! Hand-rolled compact serialization (header.payload.signature, all
//! base64url-no-pad) — no PEM juggling, exact control over `kid`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::types::{NodeId, Role};

pub const AUD: &str = "nqvpn-v1";

/// Clock skew tolerated between a member and the coordinator. A relay a
/// couple of minutes ahead used to reject every freshly renewed
/// credential and take its whole site off the mesh.
pub const LEEWAY_SECS: u64 = 120;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub network_id: String,
    /// Random 128-bit network identity, unique across trust domains (§4).
    pub network_uuid: String,
    pub node_id: NodeId,
    /// Member name, for logs and status only.
    pub sub: String,
    pub role: Role,
    /// X25519 public key, base64.
    pub pubkey: String,
    /// SHA-256 fingerprint of the TLS cert the member presented at this
    /// join ("sha256:<hex>"). Every QUIC acceptor requires the peer's live
    /// certificate to match, so the credential is useless without the
    /// private key — this is a session binding, not a pin: the next join
    /// simply records whatever certificate the member presents then.
    pub cert_fp: String,
    /// Prefixes this member may own right now (VPN addrs + granted CIDRs).
    pub prefixes: Vec<String>,
    /// Bumped by the coordinator whenever a *different* machine joins as
    /// this node. Sessions holding an older value are closed everywhere,
    /// which is what makes "join from somewhere else" replace the
    /// previous instance immediately rather than at credential expiry.
    #[serde(default)]
    pub login_gen: u64,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("malformed token")]
    Malformed,
    #[error("unsupported algorithm {0}")]
    BadAlg(String),
    #[error("unknown signing key id {0}")]
    UnknownKid(String),
    #[error("bad signature")]
    BadSignature,
    #[error("expired at {exp}, now {now}")]
    Expired { exp: u64, now: u64 },
    #[error("issued at {iat}, which is more than {LEEWAY_SECS}s ahead of now {now} — check clocks")]
    NotYetValid { iat: u64, now: u64 },
    #[error("audience mismatch: {0}")]
    BadAud(String),
    #[error("issuer mismatch: {0}")]
    BadIss(String),
    #[error("network mismatch: {0}")]
    BadNetwork(String),
}

pub fn sign(claims: &Claims, kid: &str, key: &SigningKey) -> String {
    let header = Header { alg: "EdDSA".into(), typ: "JWT".into(), kid: kid.into() };
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header json"));
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims json"));
    let signing_input = format!("{h}.{p}");
    let sig = key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Read a claim from an **unverified** token. Used only to decide which
/// network's uuid and keyset to verify against — `verify` then binds
/// every field cryptographically, so a lie here changes nothing.
fn peek(token: &str, field: &str) -> Option<serde_json::Value> {
    let p = token.split('.').nth(1)?;
    let json = URL_SAFE_NO_PAD.decode(p).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&json).ok()?;
    v.get(field).cloned()
}

pub fn peek_network(token: &str) -> Option<String> {
    peek(token, "network_id")?.as_str().map(|s| s.to_string())
}

pub fn peek_node_id(token: &str) -> Option<NodeId> {
    peek(token, "node_id")?.as_u64().and_then(|v| u32::try_from(v).ok())
}

fn peek_u64(token: &str, field: &str) -> Option<u64> {
    peek(token, field)?.as_u64()
}

/// Seconds to wait before renewing: two thirds of the credential's
/// lifetime (§9 task 1). Returns a conservative default if the token
/// cannot be read.
pub fn renew_after_secs(token: &str) -> u64 {
    match (peek_u64(token, "iat"), peek_u64(token, "exp")) {
        (Some(iat), Some(exp)) if exp > iat => ((exp - iat) * 2 / 3).max(30),
        _ => 300,
    }
}

/// Expiry as written in the token, unverified — for a session that has
/// already verified it and only needs to know when to close.
pub fn peek_exp(token: &str) -> Option<u64> {
    peek_u64(token, "exp")
}

/// What the acceptor requires the credential to bind to (§3.3).
pub struct Expected<'a> {
    pub iss: &'a str,
    pub network_id: &'a str,
    pub network_uuid: &'a str,
}

/// Full offline verification: signature (by kid, against the keyset),
/// expiry with leeway, audience, issuer, and network binding. The
/// cert_fp possession check is the transport layer's job (mutual TLS)
/// and is not done here.
pub fn verify(
    token: &str,
    keys: &[(String, VerifyingKey)],
    expected: &Expected<'_>,
    now: u64,
) -> Result<Claims, CredError> {
    let mut parts = token.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(CredError::Malformed),
    };
    let header: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(h).map_err(|_| CredError::Malformed)?,
    )
    .map_err(|_| CredError::Malformed)?;
    if header.alg != "EdDSA" {
        return Err(CredError::BadAlg(header.alg));
    }
    let key = keys
        .iter()
        .find(|(kid, _)| *kid == header.kid)
        .map(|(_, k)| k)
        .ok_or_else(|| CredError::UnknownKid(header.kid.clone()))?;

    let sig_bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| CredError::Malformed)?;
    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| CredError::Malformed)?;
    let sig = Signature::from_bytes(&sig_arr);
    let signing_input = format!("{h}.{p}");
    key.verify_strict(signing_input.as_bytes(), &sig).map_err(|_| CredError::BadSignature)?;

    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD.decode(p).map_err(|_| CredError::Malformed)?,
    )
    .map_err(|_| CredError::Malformed)?;

    if claims.exp + LEEWAY_SECS <= now {
        return Err(CredError::Expired { exp: claims.exp, now });
    }
    if claims.iat > now + LEEWAY_SECS {
        return Err(CredError::NotYetValid { iat: claims.iat, now });
    }
    if claims.aud != AUD {
        return Err(CredError::BadAud(claims.aud));
    }
    if claims.iss != expected.iss {
        return Err(CredError::BadIss(claims.iss));
    }
    if claims.network_id != expected.network_id || claims.network_uuid != expected.network_uuid {
        return Err(CredError::BadNetwork(claims.network_id));
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn claims(exp: u64) -> Claims {
        Claims {
            iss: "coord".into(),
            aud: AUD.into(),
            network_id: "acme".into(),
            network_uuid: "u-1".into(),
            node_id: 7,
            sub: "laptop-1".into(),
            role: Role::Client,
            pubkey: "PK".into(),
            cert_fp: "sha256:aa".into(),
            prefixes: vec!["10.99.1.5/32".into()],
            login_gen: 3,
            iat: 100,
            exp,
        }
    }

    fn expected() -> Expected<'static> {
        Expected { iss: "coord", network_id: "acme", network_uuid: "u-1" }
    }

    #[test]
    fn renewal_lands_at_two_thirds_of_the_lifetime() {
        let sk = SigningKey::generate(&mut OsRng);
        let mut c = claims(1000);
        c.iat = 100;
        c.exp = 1000;
        let token = sign(&c, "k1", &sk);
        assert_eq!(renew_after_secs(&token), 600);
        assert_eq!(renew_after_secs("garbage"), 300);
        assert_eq!(peek_exp(&token), Some(1000));
        assert_eq!(peek_node_id(&token), Some(7));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        let c = verify(&token, &keys, &expected(), 500).unwrap();
        assert_eq!(c.node_id, 7);
        assert_eq!(c.login_gen, 3);
    }

    #[test]
    fn expired_rejected_with_leeway() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        assert!(verify(&token, &keys, &expected(), 1000 + LEEWAY_SECS - 1).is_ok(), "inside leeway");
        assert!(matches!(
            verify(&token, &keys, &expected(), 1000 + LEEWAY_SECS),
            Err(CredError::Expired { .. })
        ));
    }

    #[test]
    fn a_token_from_the_future_is_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let mut c = claims(10_000);
        c.iat = 5000;
        let token = sign(&c, "k1", &sk);
        assert!(verify(&token, &keys, &expected(), 5000 - LEEWAY_SECS).is_ok());
        assert!(matches!(
            verify(&token, &keys, &expected(), 5000 - LEEWAY_SECS - 1),
            Err(CredError::NotYetValid { .. })
        ));
    }

    #[test]
    fn wrong_key_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let other = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), other.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        assert!(matches!(verify(&token, &keys, &expected(), 500), Err(CredError::BadSignature)));
    }

    #[test]
    fn unknown_kid_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("other".to_string(), sk.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        assert!(matches!(verify(&token, &keys, &expected(), 500), Err(CredError::UnknownKid(_))));
    }

    #[test]
    fn network_binding_enforced() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        let wrong = Expected { iss: "coord", network_id: "acme", network_uuid: "u-2" };
        assert!(matches!(verify(&token, &keys, &wrong, 500), Err(CredError::BadNetwork(_))));
    }

    #[test]
    fn tampered_payload_rejected() {
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let token = sign(&claims(1000), "k1", &sk);
        let mut parts: Vec<&str> = token.split('.').collect();
        let mut evil = claims(1000);
        evil.node_id = 9;
        let forged = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&evil).unwrap());
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert!(matches!(verify(&tampered, &keys, &expected(), 500), Err(CredError::BadSignature)));
    }

    #[test]
    fn a_token_without_login_gen_still_parses() {
        // Older coordinators never wrote the field; it defaults to 0.
        let sk = SigningKey::generate(&mut OsRng);
        let keys = vec![("k1".to_string(), sk.verifying_key())];
        let mut v = serde_json::to_value(claims(1000)).unwrap();
        v.as_object_mut().unwrap().remove("login_gen");
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&Header { alg: "EdDSA".into(), typ: "JWT".into(), kid: "k1".into() }).unwrap());
        let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap());
        let input = format!("{h}.{p}");
        let sig = sk.sign(input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()));
        assert_eq!(verify(&token, &keys, &expected(), 500).unwrap().login_gen, 0);
    }
}
