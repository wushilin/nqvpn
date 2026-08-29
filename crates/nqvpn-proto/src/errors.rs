//! The error vocabulary shared by the coordinator and every member
//! (DESIGN.md §3.4).
//!
//! These codes are protocol, not prose: a member decides whether to
//! retry, back off, or stop and tell the operator based on the code
//! alone. Keeping them in one enum here — rather than as string literals
//! written on the server and matched on the client — means the two sides
//! cannot drift apart, and adding a code forces both to consider it.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCode {
    /// Unknown node id, wrong secret, or unknown network — deliberately
    /// indistinguishable, so probing cannot enumerate members.
    BadCredentials,
    /// Administratively disabled.
    ClientDisabled,
    /// A requested prefix is not permitted, or is already owned.
    PrefixConflict,
    /// The requested address is assigned to someone else.
    AddressInUse,
    /// The pool has no free address of that family.
    PoolExhausted,
    /// No such pool in this network.
    UnknownPool,
    /// The coordinator cannot dial the relay address being advertised,
    /// and this network requires relays to be dialable (§3.2).
    RelayUnreachable,
    /// Malformed or self-inconsistent request.
    BadRequest,
    /// Too many attempts; slow down.
    RateLimited,
    /// Admin endpoint without valid admin credentials.
    AdminAuthRequired,
    NotFound,
    Internal,
    /// The peer does not implement this RPC verb. Answered, not fatal.
    UnsupportedVerb,
    /// The peer implements the verb but not at the requested version.
    UnsupportedVersion,
    /// A code this build does not know — forward compatibility, so an
    /// older member meets a newer coordinator without panicking.
    Unknown(String),
}

impl ErrorCode {
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::BadCredentials => "bad_credentials",
            ErrorCode::ClientDisabled => "client_disabled",
            ErrorCode::PrefixConflict => "prefix_conflict",
            ErrorCode::AddressInUse => "address_in_use",
            ErrorCode::PoolExhausted => "pool_exhausted",
            ErrorCode::UnknownPool => "unknown_pool",
            ErrorCode::RelayUnreachable => "relay_unreachable",
            ErrorCode::BadRequest => "bad_request",
            ErrorCode::RateLimited => "rate_limited",
            ErrorCode::AdminAuthRequired => "admin_auth_required",
            ErrorCode::UnsupportedVerb => "unsupported_verb",
            ErrorCode::UnsupportedVersion => "unsupported_version",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Internal => "internal",
            ErrorCode::Unknown(s) => s,
        }
    }

    pub fn parse(s: &str) -> ErrorCode {
        match s {
            "bad_credentials" => ErrorCode::BadCredentials,
            "client_disabled" => ErrorCode::ClientDisabled,
            "prefix_conflict" => ErrorCode::PrefixConflict,
            "address_in_use" => ErrorCode::AddressInUse,
            "pool_exhausted" => ErrorCode::PoolExhausted,
            "unknown_pool" => ErrorCode::UnknownPool,
            "relay_unreachable" => ErrorCode::RelayUnreachable,
            "bad_request" => ErrorCode::BadRequest,
            "rate_limited" => ErrorCode::RateLimited,
            "admin_auth_required" => ErrorCode::AdminAuthRequired,
            "unsupported_verb" => ErrorCode::UnsupportedVerb,
            "unsupported_version" => ErrorCode::UnsupportedVersion,
            "not_found" => ErrorCode::NotFound,
            "internal" => ErrorCode::Internal,
            other => ErrorCode::Unknown(other.to_string()),
        }
    }

    /// Retrying will never succeed on its own: only an operator can fix
    /// it. Everything else is transient, including reachability — a
    /// firewall can be opened without restarting the member.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ErrorCode::BadCredentials
                | ErrorCode::ClientDisabled
                | ErrorCode::PrefixConflict
                | ErrorCode::AddressInUse
                | ErrorCode::UnknownPool
                | ErrorCode::BadRequest
                | ErrorCode::UnsupportedVerb
                | ErrorCode::UnsupportedVersion
        )
    }

    /// One line an operator can act on, so members do not have to
    /// invent their own wording for the server's failures.
    pub fn hint(&self) -> &'static str {
        match self {
            ErrorCode::BadCredentials => "check node_id and secret against the coordinator",
            ErrorCode::ClientDisabled => "an admin disabled this member; enable it to rejoin",
            ErrorCode::PrefixConflict => "the requested CIDR is not allowed here, or another member owns it",
            ErrorCode::AddressInUse => "that address is assigned elsewhere; release it or pick another",
            ErrorCode::PoolExhausted => "the address pool is full; widen it or free addresses",
            ErrorCode::UnknownPool => "no such pool in this network's config",
            ErrorCode::RelayUnreachable => "nothing answered on the advertised relay_addr; check the firewall and the address",
            ErrorCode::BadRequest => "the request contradicts this member's configuration",
            ErrorCode::RateLimited => "too many attempts; retrying with backoff",
            ErrorCode::AdminAuthRequired => "admin credentials are missing or wrong",
            ErrorCode::UnsupportedVerb => "the peer does not implement this call; upgrade it or skip the feature",
            ErrorCode::UnsupportedVersion => "the peer implements this call at a different version; see the range it returned",
            ErrorCode::NotFound => "no such network or member",
            ErrorCode::Internal => "the coordinator failed internally; check its logs",
            ErrorCode::Unknown(_) => "unrecognised error code from a newer coordinator",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: &[ErrorCode] = &[
        ErrorCode::BadCredentials,
        ErrorCode::ClientDisabled,
        ErrorCode::PrefixConflict,
        ErrorCode::AddressInUse,
        ErrorCode::PoolExhausted,
        ErrorCode::UnknownPool,
        ErrorCode::RelayUnreachable,
        ErrorCode::BadRequest,
        ErrorCode::RateLimited,
        ErrorCode::AdminAuthRequired,
        ErrorCode::UnsupportedVerb,
        ErrorCode::UnsupportedVersion,
        ErrorCode::NotFound,
        ErrorCode::Internal,
    ];

    #[test]
    fn every_code_round_trips() {
        for c in ALL {
            assert_eq!(&ErrorCode::parse(c.as_str()), c, "round trip failed for {c}");
            assert!(!c.hint().is_empty());
        }
    }

    #[test]
    fn unknown_codes_survive_a_version_skew() {
        let c = ErrorCode::parse("some_future_code");
        assert_eq!(c.as_str(), "some_future_code");
        assert!(!c.is_terminal(), "unknown codes must be retryable, not fatal");
    }

    #[test]
    fn terminal_codes_are_the_ones_a_human_must_fix() {
        assert!(ErrorCode::ClientDisabled.is_terminal());
        assert!(ErrorCode::BadCredentials.is_terminal());
        assert!(!ErrorCode::RateLimited.is_terminal());
        assert!(!ErrorCode::Internal.is_terminal());
        assert!(!ErrorCode::RelayUnreachable.is_terminal());
    }
}
