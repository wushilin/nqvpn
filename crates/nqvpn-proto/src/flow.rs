//! Flow identity for lane selection (§5).
//!
//! An endpoint spreads tunneled packets across the stream transport's
//! lanes so one stalled flow cannot block the others. Which lane a packet
//! takes is decided here, from the inner 5-tuple, with two properties
//! that matter more than the hash quality:
//!
//!  * **sticky** — every packet of a connection picks the same lane, so a
//!    flow is never reordered by being split across streams;
//!  * **local** — only an endpoint can compute it. Relays see sealed
//!    payloads with no ports in them, so they forward a frame on the lane
//!    it arrived on rather than re-deriving anything.
//!
//! Packets we cannot parse (fragments, exotic protocols, truncated
//! headers) fall back to hashing whatever is available, down to lane 0.
//! That is a fairness loss, never a correctness one.

/// FNV-1a: no allocation, no state, and stable across processes — which
/// a `DefaultHasher` is explicitly not, and lanes must agree with
/// themselves across restarts to stay sticky.
const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x1000_0000_01b3;

fn mix(h: u64, bytes: &[u8]) -> u64 {
    let mut h = h;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Hash an inner IP packet's flow identity.
///
/// Returns `None` when the buffer is not an IP packet at all, so a caller
/// can tell "no flow" from "flow that hashed to 0".
pub fn flow_hash(packet: &[u8]) -> Option<u64> {
    let version = packet.first()? >> 4;
    let (proto, addrs, l4) = match version {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            // A non-zero fragment offset means this packet has no L4
            // header to read; MF alone still leaves ports on fragment 0.
            let frag_offset = u16::from_be_bytes([packet[6] & 0x1f, packet[7]]);
            let l4 = (frag_offset == 0 && packet.len() >= ihl + 4).then(|| &packet[ihl..ihl + 4]);
            (packet[9], &packet[12..20], l4)
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            // Extension headers are not walked: a packet carrying them
            // hashes on addresses alone, which is still sticky.
            let l4 = (packet.len() >= 44).then(|| &packet[40..44]);
            (packet[6], &packet[8..40], l4)
        }
        _ => return None,
    };

    let mut h = mix(FNV_OFFSET, addrs);
    h = mix(h, &[proto]);
    // Ports only for protocols where those four bytes really are ports.
    if let (Some(l4), true) = (l4, matches!(proto, 6 | 17 | 132 | 136)) {
        h = mix(h, l4);
    }
    Some(h)
}

/// Pick a lane for an inner packet. `lanes == 0` or `1` always yields 0.
pub fn lane_for(packet: &[u8], lanes: u8) -> u8 {
    if lanes <= 1 {
        return 0;
    }
    match flow_hash(packet) {
        // Fold the whole 64-bit hash down, so lane choice depends on
        // every byte of the tuple rather than the low bits alone.
        Some(h) => (((h >> 32) ^ h) % lanes as u64) as u8,
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal IPv4 + TCP header.
    fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16) -> Vec<u8> {
        let mut p = vec![0u8; 24];
        p[0] = 0x45;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p
    }

    #[test]
    fn same_flow_always_picks_the_same_lane() {
        let a = v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 1234, 80);
        let b = v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 1234, 80);
        assert_eq!(lane_for(&a, 8), lane_for(&b, 8));
        // Stickiness is the whole point: reordering a TCP flow across
        // lanes would be worse than the blocking lanes exist to avoid.
        for _ in 0..100 {
            assert_eq!(lane_for(&a, 8), lane_for(&a, 8));
        }
    }

    #[test]
    fn different_ports_spread_across_lanes() {
        let lanes: std::collections::HashSet<u8> = (1000..1100u16)
            .map(|port| lane_for(&v4([10, 0, 0, 1], [10, 0, 0, 2], 6, port, 80), 8))
            .collect();
        // 100 flows over 8 lanes should touch most of them; a hash that
        // collapses everything onto one lane is the bug this catches.
        assert!(lanes.len() >= 6, "poor spread: only {} lanes used", lanes.len());
    }

    #[test]
    fn lane_is_always_in_range() {
        for lanes in 1..=32u8 {
            for port in 0..200u16 {
                let l = lane_for(&v4([10, 0, 0, 1], [10, 0, 0, 2], 6, port, 443), lanes);
                assert!(l < lanes, "lane {l} out of range for {lanes}");
            }
        }
    }

    #[test]
    fn single_lane_is_always_zero() {
        assert_eq!(lane_for(&v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 9, 9), 1), 0);
        assert_eq!(lane_for(&v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 9, 9), 0), 0);
    }

    #[test]
    fn icmp_hashes_on_addresses_without_reading_ports() {
        // Bytes 20..24 are an ICMP header, not ports: two pings that
        // differ only there must still share a lane.
        let mut a = v4([10, 0, 0, 1], [10, 0, 0, 2], 1, 0, 0);
        let mut b = a.clone();
        a[20..24].copy_from_slice(&[8, 0, 1, 1]);
        b[20..24].copy_from_slice(&[8, 0, 9, 9]);
        assert_eq!(lane_for(&a, 8), lane_for(&b, 8));
    }

    #[test]
    fn fragments_ignore_the_l4_window() {
        let mut frag = v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 1234, 80);
        frag[6] = 0x00;
        frag[7] = 0x10; // non-zero fragment offset
        // Those four bytes are payload, not ports, so they must not be
        // hashed — every fragment of a datagram belongs on one lane.
        let mut other = frag.clone();
        other[20..24].copy_from_slice(&[9, 9, 9, 9]);
        assert_eq!(lane_for(&frag, 8), lane_for(&other, 8));
    }

    #[test]
    fn ipv6_is_parsed_and_non_ip_is_rejected() {
        let mut p = vec![0u8; 44];
        p[0] = 0x60;
        p[6] = 17;
        p[8] = 0xfd;
        p[24] = 0xfd;
        p[40..44].copy_from_slice(&[0x30, 0x39, 0x00, 0x50]);
        assert!(flow_hash(&p).is_some());
        assert!(flow_hash(&[]).is_none());
        assert!(flow_hash(&[0x00; 8]).is_none(), "version 0 is not IP");
        assert!(flow_hash(&[0x45, 0x00]).is_none(), "truncated v4 header");
    }

    #[test]
    fn direction_is_allowed_to_differ() {
        // Each direction is its own set of streams, so a reversed tuple
        // landing on a different lane is fine — this test just pins the
        // behaviour so nobody "fixes" it into a symmetric hash by
        // accident and quietly halves the spread.
        let fwd = v4([10, 0, 0, 1], [10, 0, 0, 2], 6, 1234, 80);
        let rev = v4([10, 0, 0, 2], [10, 0, 0, 1], 6, 80, 1234);
        assert_ne!(flow_hash(&fwd), flow_hash(&rev));
    }
}
