//! When a member should replace its identity, and how (DESIGN-RPC.md).
//!
//! Our certificates do not expire in any enforced sense: `generate` never
//! sets `notAfter`, and both verifiers authenticate by fingerprint rather
//! than validating a chain. So this is key *hygiene*, not a deadline —
//! which is why it is off unless an operator turns it on, and why the
//! policy is expressed in terms of how long a key has been in use rather
//! than when a certificate says it lapses.
//!
//! The value is that a planned rotation never needs `reset-pin`. That
//! admin operation clears a member's pins so the next join re-pins
//! whatever turns up — the one moment the trust model is open. Rotation
//! replaces a key while proving continuous possession of the old one, so
//! the window is never opened at all.
//!
//! The sequence is deliberately ordered so every interruption is safe:
//!
//! 1. **stage** a new identity beside the live one (live one untouched)
//! 2. **register** it over the authenticated control session
//! 3. **promote** it only after the coordinator has acknowledged
//!
//! A crash before step 3 leaves the old identity in place, and the
//! coordinator still accepts it for the whole overlap. Promoting first
//! would instead risk holding a key nobody was told about.

/// Decision for one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationAction {
    /// Nothing to do.
    Keep,
    /// The key has been in use long enough; replace it.
    Rotate,
}

/// Should a member with a key this old rotate now?
///
/// `after_secs == 0` disables rotation entirely, which is the default: a
/// deployment that has never thought about key hygiene should not have
/// its identities changed underneath it by an upgrade.
///
/// `age` of `None` means the age could not be determined, and is treated
/// as "do not rotate" — an unnecessary rotation costs a registration and
/// an overlap window, so guessing is the wrong bias.
pub fn decide(age_secs: Option<u64>, after_secs: u64) -> RotationAction {
    if after_secs == 0 {
        return RotationAction::Keep;
    }
    match age_secs {
        Some(age) if age >= after_secs => RotationAction::Rotate,
        _ => RotationAction::Keep,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_is_off_unless_configured() {
        // The default has to be inert: upgrading a coordinator must not
        // start replacing every member's identity on its own.
        assert_eq!(decide(Some(u64::MAX), 0), RotationAction::Keep);
        assert_eq!(decide(None, 0), RotationAction::Keep);
    }

    #[test]
    fn a_key_older_than_the_policy_rotates() {
        let year = 365 * 24 * 3600;
        assert_eq!(decide(Some(year + 1), year), RotationAction::Rotate);
        assert_eq!(decide(Some(year), year), RotationAction::Rotate);
        assert_eq!(decide(Some(year - 1), year), RotationAction::Keep);
    }

    #[test]
    fn an_unknown_age_never_rotates() {
        // Better to leave a working identity alone than to churn it on a
        // filesystem that will not tell us when the key was written.
        assert_eq!(decide(None, 60), RotationAction::Keep);
    }

    #[test]
    fn a_brand_new_key_is_left_alone() {
        assert_eq!(decide(Some(0), 60), RotationAction::Keep);
    }
}
