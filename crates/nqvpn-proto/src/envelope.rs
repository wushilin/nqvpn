//! Control-message envelope (DESIGN.md §5). Fixed layout, frozen forever:
//!
//! ```text
//! [major u8][minor u8][kind u16 BE][len u32 BE][payload: len bytes]
//! ```
//!
//! Version bytes sit outside the payload, readable before any
//! deserializer runs. Within a major version, unknown kinds are skipped
//! by length; payload schemas are frozen — evolution is a new kind.

use serde::{de::DeserializeOwned, Serialize};

pub const PROTO_MAJOR: u8 = 1;
/// Bump on **any** change to what goes on the wire — control payloads or
/// data-plane framing alike.
///
/// This is the protocol's version, deliberately not the crate's: a patch
/// release that changes nothing on the wire must not force a fleet-wide
/// restart, and a wire change in a patch release must. Tying it to the
/// build version would get both of those backwards.
pub const PROTO_MINOR: u8 = 1;
pub const HEADER_LEN: usize = 8;
/// Hard cap for a single control message payload (1 MiB) — every kind
/// except the two that carry the network view.
pub const MAX_PAYLOAD: u32 = 1024 * 1024;
/// Cap for `Snapshot` and `Delta` (16 MiB). The view grows with the
/// network: at ~100 bytes a member, 1 MiB stops at roughly 10k members,
/// and a coordinator that cannot encode its own snapshot cannot sync
/// anyone. Only the coordinator sends these, and only after the member
/// authenticated it, so the larger cap is not a pre-auth exposure.
pub const MAX_VIEW_PAYLOAD: u32 = 16 * 1024 * 1024;

/// The payload cap for one message kind, applied on encode and decode
/// alike so a sender can never produce what a receiver must refuse.
pub fn max_payload_for(kind: u16) -> u32 {
    if kind == Kind::Snapshot as u16 || kind == Kind::Delta as u16 {
        MAX_VIEW_PAYLOAD
    } else {
        MAX_PAYLOAD
    }
}

/// Well-known message kinds. Unknown values are skipped, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    /// Member -> coordinator or relay: `Hello { credential, have_gen }`.
    Hello = 1,
    /// `HelloAck { gen }`, followed by a Snapshot or Deltas.
    HelloAck = 2,
    /// Coordinator -> member: the whole network view at one generation.
    Snapshot = 3,
    /// Coordinator -> member: what changed between two generations.
    Delta = 4,
    /// Member -> coordinator: local facts, periodically and on change.
    Heartbeat = 5,
    /// Member -> coordinator: my generation is behind, send a snapshot.
    Resync = 6,
    /// Member -> any acceptor: a renewed credential for this session.
    Refresh = 7,
    /// Relay -> coordinator: `ExitReadiness`, the internet-exit egress
    /// self-check. Its own kind (not a heartbeat field) so peers on
    /// either side that predate it simply skip it — see the wire note
    /// on `Heartbeat`.
    ExitReadiness = 8,
    /// Correlated request/response (see DESIGN-RPC.md).
    Request = 16,
    Response = 17,
}

/// Refuse a peer speaking a different protocol version.
///
/// Checked once per session, at `Hello`, rather than per message: both
/// session kinds — the coordinator's control stream and a relay's data
/// session — open with an enveloped `Hello`, so one check covers both.
///
/// Equality, not a floor. Peers are built and deployed together, so a
/// mismatch means a half-finished rollout, and the useful response is to
/// say so plainly instead of running two protocols against each other
/// and desyncing somewhere less obvious.
pub fn check_version(major: u8, minor: u8) -> Result<(), VersionMismatch> {
    if major == PROTO_MAJOR && minor == PROTO_MINOR {
        return Ok(());
    }
    Err(VersionMismatch {
        peer: (major, minor),
        ours: (PROTO_MAJOR, PROTO_MINOR),
    })
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("peer speaks protocol {}.{}, we speak {}.{} — upgrade both ends together",
        .peer.0, .peer.1, .ours.0, .ours.1)]
pub struct VersionMismatch {
    pub peer: (u8, u8),
    pub ours: (u8, u8),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Peer speaks an incompatible major version: close the connection.
    #[error("incompatible protocol major {0} (ours: {PROTO_MAJOR})")]
    IncompatibleMajor(u8),
    /// Declared length exceeds the hard cap: close the connection.
    #[error("payload length {0} exceeds the cap for its kind")]
    TooLarge(u32),
    /// Not enough bytes yet — read more and retry.
    #[error("truncated (need {0} more bytes)")]
    Truncated(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub major: u8,
    pub minor: u8,
    pub kind: u16,
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn new(kind: Kind, payload: Vec<u8>) -> Self {
        Envelope { major: PROTO_MAJOR, minor: PROTO_MINOR, kind: kind as u16, payload }
    }

    /// Serialize header + payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.push(self.major);
        out.push(self.minor);
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Try to decode one envelope from the front of `buf`.
    /// Returns the envelope and the number of bytes consumed.
    pub fn decode(buf: &[u8]) -> Result<(Envelope, usize), EnvelopeError> {
        if buf.len() < HEADER_LEN {
            return Err(EnvelopeError::Truncated(HEADER_LEN - buf.len()));
        }
        let major = buf[0];
        if major != PROTO_MAJOR {
            return Err(EnvelopeError::IncompatibleMajor(major));
        }
        let minor = buf[1];
        let kind = u16::from_be_bytes([buf[2], buf[3]]);
        let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if len > max_payload_for(kind) {
            return Err(EnvelopeError::TooLarge(len));
        }
        let total = HEADER_LEN + len as usize;
        if buf.len() < total {
            return Err(EnvelopeError::Truncated(total - buf.len()));
        }
        let payload = buf[HEADER_LEN..total].to_vec();
        Ok((Envelope { major, minor, kind, payload }, total))
    }
}

/// bincode options used for every control payload: size-limited so an
/// authenticated but malicious member cannot exhaust memory.
fn bincode_opts(limit: u32) -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new().with_limit(limit as u64)
}

pub fn encode_msg<T: Serialize>(kind: Kind, msg: &T) -> Result<Vec<u8>, bincode::Error> {
    use bincode::Options;
    let payload = bincode_opts(max_payload_for(kind as u16)).serialize(msg)?;
    Ok(Envelope::new(kind, payload).encode())
}

/// Serialize a value as a bare payload, without an envelope. Used by the
/// RPC layer, which nests a typed body inside its own request frame.
pub fn encode_payload<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    use bincode::Options;
    bincode_opts(MAX_PAYLOAD).serialize(msg)
}

/// The same encoding with no size limit, for hashing a value that is
/// never sent as-is (`Snapshot::digest`). Never put this on the wire.
pub(crate) fn encode_unbounded<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    use bincode::Options;
    bincode::DefaultOptions::new().with_no_limit().serialize(msg)
}

/// Decode a payload. The limit is the largest any kind may carry; what
/// bounds a given message is the per-kind cap its envelope was read
/// under, and bincode never reads past the slice it is handed.
pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, bincode::Error> {
    use bincode::Options;
    bincode_opts(MAX_VIEW_PAYLOAD).deserialize(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let env = Envelope::new(Kind::Heartbeat, b"hello".to_vec());
        let bytes = env.encode();
        let (back, used) = Envelope::decode(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, env);
    }

    #[test]
    fn truncated_then_complete() {
        let bytes = Envelope::new(Kind::Heartbeat, vec![0u8; 100]).encode();
        assert!(matches!(Envelope::decode(&bytes[..4]), Err(EnvelopeError::Truncated(_))));
        assert!(matches!(Envelope::decode(&bytes[..50]), Err(EnvelopeError::Truncated(_))));
        assert!(Envelope::decode(&bytes).is_ok());
    }

    #[test]
    fn unknown_kind_is_decodable_and_skippable() {
        let mut env = Envelope::new(Kind::Heartbeat, vec![1, 2, 3]);
        env.kind = 0x7777; // future kind
        let bytes = env.encode();
        let (back, used) = Envelope::decode(&bytes).unwrap();
        assert_eq!(back.kind, 0x7777);
        assert_eq!(used, bytes.len()); // caller skips by consuming `used`
    }

    #[test]
    fn major_mismatch_rejected() {
        let mut bytes = Envelope::new(Kind::Heartbeat, vec![]).encode();
        bytes[0] = 2;
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::IncompatibleMajor(2)));
    }

    #[test]
    fn oversized_rejected() {
        let mut bytes = Envelope::new(Kind::Heartbeat, vec![]).encode();
        bytes[4..8].copy_from_slice(&(MAX_PAYLOAD + 1).to_be_bytes());
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::TooLarge(MAX_PAYLOAD + 1)));
    }

    #[test]
    fn view_kinds_get_the_larger_cap_and_nothing_else_does() {
        let mut bytes = Envelope::new(Kind::Snapshot, vec![]).encode();
        bytes[4..8].copy_from_slice(&(MAX_PAYLOAD + 1).to_be_bytes());
        assert!(matches!(Envelope::decode(&bytes), Err(EnvelopeError::Truncated(_))), "a 1 MiB+ snapshot is legal");
        bytes[4..8].copy_from_slice(&(MAX_VIEW_PAYLOAD + 1).to_be_bytes());
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::TooLarge(MAX_VIEW_PAYLOAD + 1)));

        // Encode honours the same caps: a 2 MiB body is a Snapshot's
        // business and nobody else's.
        let big = vec![7u8; 2 * 1024 * 1024];
        assert!(encode_msg(Kind::Snapshot, &big).is_ok());
        assert!(encode_msg(Kind::Delta, &big).is_ok());
        assert!(encode_msg(Kind::Heartbeat, &big).is_err());
        assert!(encode_msg(Kind::Hello, &big).is_err());
    }

    #[test]
    fn a_matching_version_is_accepted_and_any_other_is_not() {
        check_version(PROTO_MAJOR, PROTO_MINOR).expect("our own version must pass");
        // A minor bump is a wire change, so it must be refused just as
        // firmly as a major one — that is the whole point of enforcing it.
        assert!(check_version(PROTO_MAJOR, PROTO_MINOR.wrapping_add(1)).is_err());
        assert!(check_version(PROTO_MAJOR.wrapping_add(1), PROTO_MINOR).is_err());
    }

    #[test]
    fn the_mismatch_message_names_both_versions() {
        // An operator mid-rollout needs to see which side is behind, not
        // just that something is wrong.
        let err = check_version(1, 9).expect_err("must mismatch");
        let msg = format!("{err}");
        assert!(msg.contains("1.9"), "{msg}");
        assert!(msg.contains(&format!("{PROTO_MAJOR}.{PROTO_MINOR}")), "{msg}");
        assert!(msg.contains("upgrade both ends"), "{msg}");
    }
}
