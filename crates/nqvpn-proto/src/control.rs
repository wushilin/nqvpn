//! Control-stream message payloads (DESIGN.md §3.2). Schemas are frozen
//! within a protocol major — evolution adds a new envelope kind.

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::types::{NodeId, Revision};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    pub credential: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloAck {
    /// Directory revision the pusher will start from.
    pub revision: Revision,
}

/// One member as pushed to relays and clients. Clients receive no
/// endpoint information — members never learn each other's IPs (§1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    /// Member name (`client_id`), for status/debugging only.
    pub name: String,
    /// Active owned prefixes: VPN /32s + /128s, and for gateway relays
    /// the local CIDRs they currently own (age-resolved, §2).
    pub prefixes: Vec<IpNet>,
    /// X25519 public key, base64.
    pub pubkey: String,
    pub online: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipSnapshot {
    pub snapshot_rev: Revision,
    pub chunk_i: u32,
    pub chunk_n: u32,
    pub peers: Vec<PeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipDelta {
    pub base_rev: Revision,
    pub new_rev: Revision,
    pub changed: Vec<PeerInfo>,
    pub removed: Vec<NodeId>,
}

/// Relay → coordinator: a member authenticated a data session with me.
/// The coordinator folds this into the attachment registry push.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attach {
    pub node_id: NodeId,
    /// True on attach, false on detach (session closed).
    pub attached: bool,
}

/// Coordinator → relays: which member is reachable through which relay.
/// Relays only; clients never see it (§1: members never learn each
/// other's locations).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentEntry {
    pub node_id: NodeId,
    pub relay_id: NodeId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentSnapshot {
    pub snapshot_rev: Revision,
    pub entries: Vec<AttachmentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentDelta {
    pub base_rev: Revision,
    pub new_rev: Revision,
    pub changed: Vec<AttachmentEntry>,
    pub detached: Vec<NodeId>,
}

/// Member -> coordinator: the largest inner packet this member's uplink
/// can currently carry, measured from QUIC's own path-MTU discovery.
/// Sent periodically, so a path that changes is picked up without any
/// special event handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuReport {
    pub usable_mtu: u16,
}

/// Coordinator -> all members: the tunnel MTU for this network.
///
/// A packet crosses client -> relay -> mesh -> relay -> client, so the
/// safe MTU is the *minimum* over every member's uplink, not each
/// member's own. `limited_by` names the member setting that floor, so an
/// operator can see which link is holding the network back instead of
/// guessing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMtu {
    pub mtu: u16,
    pub limited_by: String,
}

/// Relay -> coordinator: cumulative data-plane bytes, per mesh peer and
/// for traffic that never crosses the mesh. Reported on a timer.
///
/// Every relay reports its *own* view, so the coordinator can assemble an
/// N x N matrix in which each link appears twice — once as the sender's
/// tx and once as the receiver's rx. That redundancy is the point: the
/// gap between the two halves is loss on that link, visible without any
/// extra instrumentation.
///
/// Counters are cumulative since the relay process started, so they drop
/// to zero on restart rather than wrapping.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficReport {
    pub links: Vec<LinkTraffic>,
    /// Switched between two members attached to this same relay — the
    /// matrix diagonal, since these frames cross no mesh link.
    pub local_bytes: u64,
    pub local_pkts: u64,
    /// Terminated at this relay's own endpoint (gateway role).
    pub terminated_bytes: u64,
    pub terminated_pkts: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkTraffic {
    pub peer_id: NodeId,
    pub tx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_pkts: u64,
    /// Whether the mesh session is live right now. Counters outlive the
    /// session they were measured on, so without this a long-dead link
    /// looks identical to a busy one.
    pub up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Refresh {
    pub credential: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyInfo {
    pub kid: String,
    /// Ed25519 verifying key, base64.
    pub key: String,
    /// "active" | "retiring"
    pub state: String,
}

/// Coordinator -> all members: the current dialable relay fleet.
/// Pushed whenever it changes, so the mesh (and clients' attach
/// candidates) converge without waiting for a re-join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayList {
    pub relays: Vec<RelayEndpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEndpoint {
    pub relay_id: NodeId,
    pub name: String,
    pub addr: String,
    pub cert_fp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeySet {
    pub keys: Vec<KeyInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{decode_payload, encode_msg, Envelope, Kind};

    #[test]
    fn control_roundtrip_through_envelope() {
        let snap = MembershipSnapshot {
            snapshot_rev: 7,
            chunk_i: 0,
            chunk_n: 1,
            peers: vec![PeerInfo {
                node_id: 3,
                name: "laptop-1".into(),
                prefixes: vec!["10.99.1.5/32".parse().unwrap()],
                pubkey: "AAAA".into(),
                online: true,
            }],
        };
        let bytes = encode_msg(Kind::MembershipSnapshot, &snap).unwrap();
        let (env, _) = Envelope::decode(&bytes).unwrap();
        assert_eq!(env.kind, Kind::MembershipSnapshot as u16);
        let back: MembershipSnapshot = decode_payload(&env.payload).unwrap();
        assert_eq!(back.snapshot_rev, 7);
        assert_eq!(back.peers, snap.peers);
    }
}
