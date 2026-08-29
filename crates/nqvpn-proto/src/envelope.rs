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
pub const PROTO_MINOR: u8 = 0;
pub const HEADER_LEN: usize = 8;
/// Hard cap for a single control message payload (1 MiB).
pub const MAX_PAYLOAD: u32 = 1024 * 1024;

/// Well-known message kinds. Unknown values are skipped, not errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Kind {
    Hello = 1,
    HelloAck = 2,
    MembershipSnapshot = 3,
    MembershipDelta = 4,
    Attach = 5,
    Refresh = 6,
    KeySet = 7,
    Ping = 8,
    Pong = 9,
    AttachmentSnapshot = 10,
    AttachmentDelta = 11,
    RelayList = 12,
    MtuReport = 13,
    NetworkMtu = 14,
    TrafficReport = 15,
    /// Correlated request/response (see DESIGN-RPC.md). Verbs live in
    /// their own registry in `rpc`, kept separate from these kinds so the
    /// two namespaces do not get conflated.
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
    #[error("payload length {0} exceeds cap {MAX_PAYLOAD}")]
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
        if len > MAX_PAYLOAD {
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
fn bincode_opts() -> impl bincode::Options {
    use bincode::Options;
    bincode::DefaultOptions::new().with_limit(MAX_PAYLOAD as u64)
}

pub fn encode_msg<T: Serialize>(kind: Kind, msg: &T) -> Result<Vec<u8>, bincode::Error> {
    use bincode::Options;
    let payload = bincode_opts().serialize(msg)?;
    Ok(Envelope::new(kind, payload).encode())
}

/// Serialize a value as a bare payload, without an envelope. Used by the
/// RPC layer, which nests a typed body inside its own request frame.
pub fn encode_payload<T: Serialize>(msg: &T) -> Result<Vec<u8>, bincode::Error> {
    use bincode::Options;
    bincode_opts().serialize(msg)
}

pub fn decode_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, bincode::Error> {
    use bincode::Options;
    bincode_opts().deserialize(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let env = Envelope::new(Kind::Ping, b"hello".to_vec());
        let bytes = env.encode();
        let (back, used) = Envelope::decode(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(back, env);
    }

    #[test]
    fn truncated_then_complete() {
        let bytes = Envelope::new(Kind::Ping, vec![0u8; 100]).encode();
        assert!(matches!(Envelope::decode(&bytes[..4]), Err(EnvelopeError::Truncated(_))));
        assert!(matches!(Envelope::decode(&bytes[..50]), Err(EnvelopeError::Truncated(_))));
        assert!(Envelope::decode(&bytes).is_ok());
    }

    #[test]
    fn unknown_kind_is_decodable_and_skippable() {
        let mut env = Envelope::new(Kind::Ping, vec![1, 2, 3]);
        env.kind = 0x7777; // future kind
        let bytes = env.encode();
        let (back, used) = Envelope::decode(&bytes).unwrap();
        assert_eq!(back.kind, 0x7777);
        assert_eq!(used, bytes.len()); // caller skips by consuming `used`
    }

    #[test]
    fn major_mismatch_rejected() {
        let mut bytes = Envelope::new(Kind::Ping, vec![]).encode();
        bytes[0] = 2;
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::IncompatibleMajor(2)));
    }

    #[test]
    fn oversized_rejected() {
        let mut bytes = Envelope::new(Kind::Ping, vec![]).encode();
        bytes[4..8].copy_from_slice(&(MAX_PAYLOAD + 1).to_be_bytes());
        assert_eq!(Envelope::decode(&bytes), Err(EnvelopeError::TooLarge(MAX_PAYLOAD + 1)));
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
