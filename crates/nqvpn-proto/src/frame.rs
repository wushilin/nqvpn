//! Data-plane frame headers (DESIGN.md §5).
//!
//! ```text
//! 0x01 Data       [type 1][src_id 4][dst_id 4][ctr 8][AEAD ciphertext]
//! 0x02 Handshake  [type 1][src_id 4][dst_id 4][noise handshake message]
//! 0xF1 Probe      [type 1][seq 8][t_sent 8]      client <-> its relay only
//! 0xF2 Reply      probe echoed by the relay
//! ```
//!
//! A relay parses only the 9-byte routed header and forwards the
//! datagram **verbatim** — it never inspects the counter or ciphertext,
//! and it holds no key that could decrypt them.

use crate::types::NodeId;

pub const T_DATA: u8 = 0x01;
pub const T_HANDSHAKE: u8 = 0x02;
pub const T_PROBE: u8 = 0xF1;
pub const T_REPLY: u8 = 0xF2;

/// type + src_id + dst_id
pub const ROUTED_HEADER_LEN: usize = 9;
/// type + seq + t_sent
pub const PROBE_LEN: usize = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedHeader {
    pub kind: u8,
    pub src_id: NodeId,
    pub dst_id: NodeId,
}

impl RoutedHeader {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.src_id.to_be_bytes());
        out.extend_from_slice(&self.dst_id.to_be_bytes());
    }

    /// Parse the routed header of a `Data`/`Handshake` datagram.
    pub fn parse(buf: &[u8]) -> Option<RoutedHeader> {
        if buf.len() < ROUTED_HEADER_LEN {
            return None;
        }
        let kind = buf[0];
        if kind != T_DATA && kind != T_HANDSHAKE {
            return None;
        }
        Some(RoutedHeader {
            kind,
            src_id: u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]),
            dst_id: u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]),
        })
    }
}

/// A hop-local latency probe (never crosses the relay mesh).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    pub kind: u8,
    pub seq: u64,
    pub t_sent: u64,
}

impl Probe {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROBE_LEN);
        out.push(self.kind);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.t_sent.to_be_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Option<Probe> {
        if buf.len() < PROBE_LEN || (buf[0] != T_PROBE && buf[0] != T_REPLY) {
            return None;
        }
        let seq = u64::from_be_bytes(buf[1..9].try_into().ok()?);
        let t_sent = u64::from_be_bytes(buf[9..17].try_into().ok()?);
        Some(Probe { kind: buf[0], seq, t_sent })
    }

    pub fn into_reply(mut self) -> Probe {
        self.kind = T_REPLY;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_header_roundtrip() {
        let h = RoutedHeader { kind: T_DATA, src_id: 7, dst_id: 9 };
        let mut buf = Vec::new();
        h.write(&mut buf);
        buf.extend_from_slice(b"ciphertext");
        let back = RoutedHeader::parse(&buf).unwrap();
        assert_eq!(back, h);
        assert_eq!(&buf[ROUTED_HEADER_LEN..], b"ciphertext");
    }

    #[test]
    fn rejects_short_and_foreign_types() {
        assert!(RoutedHeader::parse(&[T_DATA, 0, 0, 0]).is_none());
        let mut buf = vec![0xEE];
        buf.extend_from_slice(&[0u8; 8]);
        assert!(RoutedHeader::parse(&buf).is_none());
    }

    #[test]
    fn probe_roundtrip_and_reply() {
        let p = Probe { kind: T_PROBE, seq: 42, t_sent: 1234567 };
        let back = Probe::parse(&p.encode()).unwrap();
        assert_eq!(back, p);
        let r = back.into_reply();
        assert_eq!(r.kind, T_REPLY);
        assert_eq!(Probe::parse(&r.encode()).unwrap(), r);
    }

    #[test]
    fn handshake_frames_route_like_data() {
        let h = RoutedHeader { kind: T_HANDSHAKE, src_id: 1, dst_id: 2 };
        let mut buf = Vec::new();
        h.write(&mut buf);
        assert_eq!(RoutedHeader::parse(&buf).unwrap().kind, T_HANDSHAKE);
    }
}
