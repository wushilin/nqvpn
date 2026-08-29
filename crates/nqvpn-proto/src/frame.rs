//! Data-plane frame headers (DESIGN.md §5).
//!
//! ```text
//! 0x01 Data       [type 1][src_id 4][dst_id 4][flags 1][hop 1][trace 4][ctr 8][AEAD ciphertext]
//! 0x02 Handshake  [type 1][src_id 4][dst_id 4][flags 1][hop 1][trace 4][noise handshake message]
//! 0xF1 Probe      [type 1][seq 8][t_sent 8]      hop-local, never forwarded
//! 0xF2 Reply      probe echoed by the far end of the hop
//! 0xF3 TraceNote  [type 1][trace 4][hop 1][relay_id 4][decision 1][detail 4]
//!                 sent by a relay back on the session a traced frame
//!                 arrived on, so the origin can reconstruct the path
//! ```
//!
//! A relay parses only the routed header and forwards the datagram
//! verbatim apart from two bytes it owns: it increments `hop` (and drops
//! the frame if that exceeds `MAX_HOPS`, a loop guard that does not depend
//! on any table being right) and, when `flags` asks for a trace, it
//! reports its decision. It never inspects the counter or ciphertext and
//! holds no key that could decrypt them.
//!
//! `trace` is chosen by the origin endpoint per flow. It costs six bytes
//! per packet and turns every drop counter into something attributable.

use crate::types::NodeId;

pub const T_DATA: u8 = 0x01;
pub const T_HANDSHAKE: u8 = 0x02;
pub const T_PROBE: u8 = 0xF1;
pub const T_REPLY: u8 = 0xF2;
pub const T_TRACE_NOTE: u8 = 0xF3;

/// type + src_id + dst_id + flags + hop + trace
pub const ROUTED_HEADER_LEN: usize = 15;
/// type + seq + t_sent
pub const PROBE_LEN: usize = 17;
/// type + trace + hop + relay_id + decision + detail
pub const TRACE_NOTE_LEN: usize = 15;

/// Ask every relay on the path to report what it did with this frame.
pub const FLAG_TRACE: u8 = 0x01;

/// A frame crosses at most one mesh link: origin -> relay (hop 1) ->
/// relay (hop 2) -> destination. Anything beyond that is a loop.
pub const MAX_HOPS: u8 = 2;

const OFF_FLAGS: usize = 9;
const OFF_HOP: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedHeader {
    pub kind: u8,
    pub src_id: NodeId,
    pub dst_id: NodeId,
    pub flags: u8,
    pub hop: u8,
    pub trace: u32,
}

impl RoutedHeader {
    pub fn new(kind: u8, src_id: NodeId, dst_id: NodeId, trace: u32) -> RoutedHeader {
        RoutedHeader { kind, src_id, dst_id, flags: 0, hop: 0, trace }
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.kind);
        out.extend_from_slice(&self.src_id.to_be_bytes());
        out.extend_from_slice(&self.dst_id.to_be_bytes());
        out.push(self.flags);
        out.push(self.hop);
        out.extend_from_slice(&self.trace.to_be_bytes());
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
            flags: buf[OFF_FLAGS],
            hop: buf[OFF_HOP],
            trace: u32::from_be_bytes([buf[11], buf[12], buf[13], buf[14]]),
        })
    }

    pub fn traced(&self) -> bool {
        self.flags & FLAG_TRACE != 0
    }
}

/// Relay-side: count one more hop in place. Returns the new hop count, or
/// `None` if the frame has already travelled as far as any legitimate
/// path allows and must be dropped.
pub fn bump_hop(buf: &mut [u8]) -> Option<u8> {
    if buf.len() < ROUTED_HEADER_LEN {
        return None;
    }
    let next = buf[OFF_HOP].saturating_add(1);
    if next > MAX_HOPS {
        return None;
    }
    buf[OFF_HOP] = next;
    Some(next)
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

/// What a relay did with a frame. Carried in trace notes and used as the
/// key of every relay drop counter, so the two can never disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Decision {
    DeliverLocal = 1,
    ForwardMesh = 2,
    TerminateHere = 3,
    DropSrcSpoofed = 16,
    DropNoSecondHop = 17,
    DropMeshLinkDown = 18,
    DropDstUnknown = 19,
    DropNoEndpoint = 20,
    DropTooManyHops = 21,
    DropSendFailed = 22,
    DropRateLimited = 23,
    DropMalformed = 24,
}

impl Decision {
    pub fn from_u8(v: u8) -> Option<Decision> {
        Some(match v {
            1 => Decision::DeliverLocal,
            2 => Decision::ForwardMesh,
            3 => Decision::TerminateHere,
            16 => Decision::DropSrcSpoofed,
            17 => Decision::DropNoSecondHop,
            18 => Decision::DropMeshLinkDown,
            19 => Decision::DropDstUnknown,
            20 => Decision::DropNoEndpoint,
            21 => Decision::DropTooManyHops,
            22 => Decision::DropSendFailed,
            23 => Decision::DropRateLimited,
            24 => Decision::DropMalformed,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Decision::DeliverLocal => "deliver_local",
            Decision::ForwardMesh => "forward_mesh",
            Decision::TerminateHere => "terminate_here",
            Decision::DropSrcSpoofed => "drop_src_spoofed",
            Decision::DropNoSecondHop => "drop_no_second_hop",
            Decision::DropMeshLinkDown => "drop_mesh_link_down",
            Decision::DropDstUnknown => "drop_dst_unknown",
            Decision::DropNoEndpoint => "drop_no_endpoint",
            Decision::DropTooManyHops => "drop_too_many_hops",
            Decision::DropSendFailed => "drop_send_failed",
            Decision::DropRateLimited => "drop_rate_limited",
            Decision::DropMalformed => "drop_malformed",
        }
    }

    pub fn is_drop(&self) -> bool {
        (*self as u8) >= 16
    }

    /// Every decision, for building counter tables.
    pub const ALL: [Decision; 12] = [
        Decision::DeliverLocal,
        Decision::ForwardMesh,
        Decision::TerminateHere,
        Decision::DropSrcSpoofed,
        Decision::DropNoSecondHop,
        Decision::DropMeshLinkDown,
        Decision::DropDstUnknown,
        Decision::DropNoEndpoint,
        Decision::DropTooManyHops,
        Decision::DropSendFailed,
        Decision::DropRateLimited,
        Decision::DropMalformed,
    ];
}

/// A relay's report about one traced frame, sent back on the session
/// the frame arrived on. `detail` is the next-hop relay id for a forward,
/// the delivered node id for a local delivery, and 0 otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceNote {
    pub trace: u32,
    pub hop: u8,
    pub relay_id: NodeId,
    pub decision: Decision,
    pub detail: u32,
}

impl TraceNote {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRACE_NOTE_LEN);
        out.push(T_TRACE_NOTE);
        out.extend_from_slice(&self.trace.to_be_bytes());
        out.push(self.hop);
        out.extend_from_slice(&self.relay_id.to_be_bytes());
        out.push(self.decision as u8);
        out.extend_from_slice(&self.detail.to_be_bytes());
        out
    }

    pub fn parse(buf: &[u8]) -> Option<TraceNote> {
        if buf.len() < TRACE_NOTE_LEN || buf[0] != T_TRACE_NOTE {
            return None;
        }
        Some(TraceNote {
            trace: u32::from_be_bytes(buf[1..5].try_into().ok()?),
            hop: buf[5],
            relay_id: u32::from_be_bytes(buf[6..10].try_into().ok()?),
            decision: Decision::from_u8(buf[10])?,
            detail: u32::from_be_bytes(buf[11..15].try_into().ok()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routed_header_roundtrip() {
        let mut h = RoutedHeader::new(T_DATA, 7, 9, 0xdead_beef);
        h.flags = FLAG_TRACE;
        h.hop = 1;
        let mut buf = Vec::new();
        h.write(&mut buf);
        buf.extend_from_slice(b"ciphertext");
        let back = RoutedHeader::parse(&buf).unwrap();
        assert_eq!(back, h);
        assert!(back.traced());
        assert_eq!(&buf[ROUTED_HEADER_LEN..], b"ciphertext");
    }

    #[test]
    fn rejects_short_and_foreign_types() {
        assert!(RoutedHeader::parse(&[T_DATA, 0, 0, 0]).is_none());
        let mut buf = vec![0xEE];
        buf.extend_from_slice(&[0u8; 14]);
        assert!(RoutedHeader::parse(&buf).is_none());
    }

    #[test]
    fn hop_counter_is_a_hard_loop_guard() {
        let mut buf = Vec::new();
        RoutedHeader::new(T_DATA, 1, 2, 0).write(&mut buf);
        assert_eq!(bump_hop(&mut buf), Some(1));
        assert_eq!(bump_hop(&mut buf), Some(2));
        assert_eq!(bump_hop(&mut buf), None, "a third hop is a loop");
        assert_eq!(RoutedHeader::parse(&buf).unwrap().hop, 2, "not incremented past the cap");
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
        let mut buf = Vec::new();
        RoutedHeader::new(T_HANDSHAKE, 1, 2, 0).write(&mut buf);
        assert_eq!(RoutedHeader::parse(&buf).unwrap().kind, T_HANDSHAKE);
    }

    #[test]
    fn trace_note_roundtrip() {
        let n = TraceNote { trace: 77, hop: 2, relay_id: 5, decision: Decision::ForwardMesh, detail: 9 };
        let back = TraceNote::parse(&n.encode()).unwrap();
        assert_eq!(back, n);
        // Not a routed frame: a relay must not try to forward it.
        assert!(RoutedHeader::parse(&n.encode()).is_none());
    }

    #[test]
    fn every_decision_round_trips_and_is_named() {
        for d in Decision::ALL {
            assert_eq!(Decision::from_u8(d as u8), Some(d));
            assert!(!d.as_str().is_empty());
            assert_eq!(d.is_drop(), d.as_str().starts_with("drop_"));
        }
        assert_eq!(Decision::from_u8(0), None);
    }
}
