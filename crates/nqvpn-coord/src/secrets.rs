//! Member secrets: generated, never chosen, kept in the clear inside the
//! coordinator's database so an operator can show a token again or put
//! it on a new machine. 32 random bytes: nothing to guess, no hash to
//! slow an attacker down with. What protects a secret is the database
//! file, not a digest.

/// Length of a generated secret: 32 bytes, base64url without padding.
pub const SECRET_LEN: usize = 43;

/// The longest secret ever compared. Generated secrets are `SECRET_LEN`;
/// the slack admits secrets imported from elsewhere (and test fixtures)
/// while keeping a presented secret from costing more than a few dozen
/// bytes per member to compare.
pub const MAX_SECRET_LEN: usize = 64;

/// A secret with enough entropy that guessing is not a threat model.
pub fn generate_secret() -> String {
    use rand::TryRng;
    let mut raw = [0u8; 32];
    rand::rngs::SysRng.try_fill_bytes(&mut raw).expect("the OS random source failed");
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    URL_SAFE_NO_PAD.encode(raw)
}

/// Shaped like a secret: 1..=`MAX_SECRET_LEN` base64url characters.
/// Anything else is refused before it is compared with anything, and
/// cannot be configured either.
pub fn plausible_secret(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SECRET_LEN && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// Compare two secrets without leaking where they differ. The length is
/// compared in full (not truncated), and the content loop runs over the
/// longer input whatever the lengths.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let mut diff: usize = a.len() ^ b.len();
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_are_long_random_and_url_safe() {
        let a = generate_secret();
        let b = generate_secret();
        assert_ne!(a, b);
        assert_eq!(a.len(), SECRET_LEN);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
        assert!(plausible_secret(&a));
    }

    #[test]
    fn constant_time_eq_is_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("", "a"));
        assert!(constant_time_eq("", ""));
        // Lengths differing by a multiple of 256, with a zero-padded tail.
        let long = format!("abc{}", "\0".repeat(256));
        assert!(!constant_time_eq("abc", &long));
    }

    #[test]
    fn only_secret_shaped_strings_are_plausible() {
        assert!(plausible_secret("s-c1"));
        assert!(!plausible_secret(""));
        assert!(!plausible_secret(&"a".repeat(MAX_SECRET_LEN + 1)));
        assert!(!plausible_secret("has space"));
        assert!(!plausible_secret("ünïcode"));
    }
}
