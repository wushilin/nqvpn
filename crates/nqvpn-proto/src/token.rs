//! The member token: everything a machine needs to become a member,
//! in one opaque string an operator copies from the coordinator's UI.
//!
//! `nqv1.<base64url(endpoint=https://coord:8443;secret=...)>`
//!
//! It is a *lookup key*, not a bearer of configuration: the coordinator
//! maps the secret to the member (network, name, role) and hands down
//! everything else at join — address, routed prefixes, relays, MTU.
//! Changing the member's configuration on the coordinator never means
//! touching the machine. Tokens do not expire; they are rotated.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

pub const PREFIX: &str = "nqv1.";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// `https://host[:port]` of the coordinator.
    pub coordinator: String,
    pub secret: String,
    /// The coordinator's certificate fingerprint ("sha256:<hex>"), when
    /// it uses a self-signed certificate. The member pins both the HTTPS
    /// join and the QUIC control plane to it, so verification is the
    /// default with no CA file. Absent for a CA-signed coordinator (the
    /// member verifies against the platform roots instead).
    pub fp: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("not a member token (expected the {PREFIX} prefix)")]
    Prefix,
    #[error("malformed token")]
    Malformed,
    #[error("token has no coordinator endpoint")]
    NoEndpoint,
    #[error("token has no secret")]
    NoSecret,
}

impl Token {
    pub fn encode(&self) -> String {
        let mut body = format!("endpoint={};secret={}", self.coordinator, self.secret);
        if let Some(fp) = &self.fp {
            body.push_str(";fp=");
            body.push_str(fp);
        }
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(body.as_bytes()))
    }

    pub fn parse(s: &str) -> Result<Token, TokenError> {
        let s = s.trim();
        let body = s.strip_prefix(PREFIX).ok_or(TokenError::Prefix)?;
        let raw = URL_SAFE_NO_PAD.decode(body.as_bytes()).map_err(|_| TokenError::Malformed)?;
        let text = String::from_utf8(raw).map_err(|_| TokenError::Malformed)?;
        let mut coordinator = None;
        let mut secret = None;
        let mut fp = None;
        for part in text.split(';') {
            match part.split_once('=') {
                Some(("endpoint", v)) => coordinator = Some(v.trim().to_string()),
                Some(("secret", v)) => secret = Some(v.trim().to_string()),
                Some(("fp", v)) => fp = Some(v.trim().to_string()).filter(|s| !s.is_empty()),
                _ => {} // forward compatible: unknown fields are ignored
            }
        }
        let coordinator = coordinator.filter(|c| !c.is_empty()).ok_or(TokenError::NoEndpoint)?;
        let secret = secret.filter(|c| !c.is_empty()).ok_or(TokenError::NoSecret)?;
        Ok(Token { coordinator, secret, fp })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let t = Token { coordinator: "https://coord.example:8443".into(), secret: "abc_-123".into(), fp: None };
        let s = t.encode();
        assert!(s.starts_with("nqv1."));
        assert_eq!(Token::parse(&s).unwrap(), t);
        assert_eq!(Token::parse(&format!("  {s}\n")).unwrap(), t, "whitespace tolerated");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Token::parse("hello").unwrap_err(), TokenError::Prefix);
        assert_eq!(Token::parse("nqv1.!!!").unwrap_err(), TokenError::Malformed);
        let no_secret = format!("nqv1.{}", URL_SAFE_NO_PAD.encode(b"endpoint=https://x"));
        assert_eq!(Token::parse(&no_secret).unwrap_err(), TokenError::NoSecret);
        let no_ep = format!("nqv1.{}", URL_SAFE_NO_PAD.encode(b"secret=x"));
        assert_eq!(Token::parse(&no_ep).unwrap_err(), TokenError::NoEndpoint);
    }

    #[test]
    fn a_fingerprint_round_trips() {
        let t = Token { coordinator: "https://c:8443".into(), secret: "s".into(), fp: Some("sha256:abcd".into()) };
        assert_eq!(Token::parse(&t.encode()).unwrap(), t);
        assert!(t.encode().contains("nqv1."));
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let s = format!("nqv1.{}", URL_SAFE_NO_PAD.encode(b"endpoint=https://x;future=1;secret=y"));
        assert_eq!(Token::parse(&s).unwrap(), Token { coordinator: "https://x".into(), secret: "y".into(), fp: None });
    }
}
