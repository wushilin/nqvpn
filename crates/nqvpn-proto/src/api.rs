//! REST request/response types for the coordinator HTTP API (§3.2, §3.4).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::control::KeyInfo;
use crate::types::{NodeId, Role};

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub network_id: String,
    pub client_id: String,
    pub client_secret: String,
    /// X25519 public key, base64.
    pub pubkey: String,
    pub role: Role,
    /// Defaults to true for both roles (decision #1); headless opt-out.
    #[serde(default = "default_true")]
    pub want_vpn_ip: bool,
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub preferred_ip4: Option<Ipv4Addr>,
    #[serde(default)]
    pub preferred_ip6: Option<Ipv6Addr>,
    /// Relays only: local CIDRs to register (⊆ allowed_cidrs).
    #[serde(default)]
    pub local_cidrs: Vec<IpNet>,
    /// Relays only: the public address fleet and clients dial.
    #[serde(default)]
    pub relay_addr: Option<String>,
    /// SHA-256 of the member's self-signed TLS cert ("sha256:<hex>").
    pub cert_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEntry {
    pub relay_id: NodeId,
    pub name: String,
    pub addr: String,
    pub cert_fp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinResponse {
    pub credential: String,
    pub network_uuid: String,
    pub coordinator_signing_keys: Vec<KeyInfo>,
    pub node_id: NodeId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet4: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip6: Option<Ipv6Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet6: Option<IpNet>,
    /// Granted route registrations (relays; empty for clients).
    pub granted_cidrs: Vec<IpNet>,
    pub relays: Vec<RelayEntry>,
    pub mtu: u16,
    pub keepalive_secs: u16,
    /// Packet transport for this network: "datagram" or "stream".
    #[serde(default)]
    pub transport: String,
    /// Parallel stream lanes to spread flows across. Absent or 0 from an
    /// older coordinator means one lane, i.e. the original behaviour.
    #[serde(default)]
    pub lanes: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

// ---- status DTOs (admin) ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStatus {
    pub networks: Vec<NetworkSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    pub network_id: String,
    pub members_total: usize,
    pub relays_total: usize,
    pub members_online: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub network_id: String,
    pub network_uuid: String,
    pub members: Vec<MemberStatus>,
    pub prefix_table: Vec<PrefixOwner>,
    /// Fleet traffic matrix, one row per reporting relay.
    #[serde(default)]
    pub relay_traffic: Vec<RelayTraffic>,
    /// Transport in force, echoed so the UI can explain what it shows.
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub lanes: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberStatus {
    pub name: String,
    pub node_id: NodeId,
    pub role: Role,
    pub online: bool,
    pub disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip6: Option<Ipv6Addr>,
    pub registered_cidrs: Vec<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attached_relay: Option<String>,
    pub pinned: bool,
    /// Relays only: can the coordinator dial the address this member
    /// advertises? "reachable" | "unreachable" | "unknown" (§3.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_reachable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_join_unix: Option<u64>,
    /// Pinned identities. More than one means a rotation is in flight:
    /// the member registered a new key and the previous one still works
    /// until its overlap ends.
    #[serde(default)]
    pub pins: Vec<PinStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinStatus {
    /// "pubkey" or "cert_fp".
    pub kind: String,
    /// Truncated: enough to recognise, not enough to fill a table.
    pub key: String,
    /// None for the current pin; otherwise when it stops being accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retires_unix: Option<u64>,
}

/// One relay's row of the fleet traffic matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTraffic {
    pub relay: String,
    pub node_id: NodeId,
    /// Seconds since this report arrived; a stale row is not a live one.
    pub age_secs: u64,
    pub links: Vec<RelayLink>,
    /// Diagonal: switched between two members attached to this relay.
    pub local_bytes: u64,
    pub local_pkts: u64,
    pub terminated_bytes: u64,
    pub terminated_pkts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayLink {
    pub peer: String,
    pub peer_node_id: NodeId,
    pub tx_bytes: u64,
    pub tx_pkts: u64,
    pub rx_bytes: u64,
    pub rx_pkts: u64,
    /// Derived from the previous sample, so the view shows what is
    /// happening now rather than only what has happened since boot.
    pub tx_bps: u64,
    pub rx_bps: u64,
    pub up: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefixOwner {
    pub cidr: IpNet,
    pub owner: String,
    pub owner_node_id: NodeId,
    /// Other living registrants standing by (age order).
    pub standby: Vec<String>,
}
