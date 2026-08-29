//! REST request/response types for the coordinator HTTPS API (§3.2, §3.4).

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::control::KeyInfo;
use crate::types::{NodeId, Role};

fn default_true() -> bool {
    true
}

/// A join is the member's **entire current declaration**. Whatever it
/// says replaces whatever the coordinator recorded before: keys, routes,
/// address requests, relay address. Renewal is the same request again.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinRequest {
    pub network_id: String,
    /// The member's name, as configured at the coordinator. Names are
    /// what people use everywhere; the coordinator assigns the wire
    /// identity (`node_id`) and returns it.
    pub name: String,
    pub secret: String,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// The member's name, from the coordinator's config.
    #[serde(default)]
    pub name: String,
    /// See `Claims::login_gen`.
    #[serde(default)]
    pub login_gen: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip4: Option<Ipv4Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet4: Option<IpNet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip6: Option<Ipv6Addr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet6: Option<IpNet>,
    /// Granted route registrations (relays; empty for clients).
    #[serde(default)]
    pub granted_cidrs: Vec<IpNet>,
    pub relays: Vec<RelayEntry>,
    pub mtu: u16,
    pub keepalive_secs: u16,
    /// Packet transport for this network: "datagram" or "stream".
    #[serde(default)]
    pub transport: String,
    /// Parallel stream lanes to spread flows across. 0 means one.
    #[serde(default)]
    pub lanes: u8,
    /// UDP port of the coordinator's QUIC control plane, on the same host
    /// the member reached this API at. One URL in the member's config.
    #[serde(default)]
    pub control_port: u16,
    /// Seconds between heartbeats; the coordinator's liveness window is a
    /// small multiple of this.
    #[serde(default)]
    pub heartbeat_secs: u16,
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
    /// Current directory generation, so an operator can compare it with
    /// what members report.
    #[serde(default)]
    pub gen: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub network_id: String,
    pub network_uuid: String,
    #[serde(default)]
    pub gen: u64,
    pub members: Vec<MemberStatus>,
    pub prefix_table: Vec<PrefixOwner>,
    /// Fleet traffic matrix, one row per reporting relay.
    #[serde(default)]
    pub relay_traffic: Vec<RelayTraffic>,
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
    /// Relays only: can the coordinator dial the address this member
    /// advertises? "reachable" | "unreachable" | "unknown" (§3.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertised_reachable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_join_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_join_from: Option<String>,
    /// How many times a *different* machine has joined as this node.
    #[serde(default)]
    pub login_gen: u64,
    /// When and from where the previous instance was replaced, if ever.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaced_from: Option<String>,
    /// The generation this member last reported holding, and whether its
    /// digest agreed with ours at that generation. A member behind for
    /// more than a heartbeat or two, or disagreeing, is a bug to look at.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reported_gen: Option<u64>,
    #[serde(default)]
    pub digest_ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_heartbeat_unix: Option<u64>,
}

/// One relay's row of the fleet traffic matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTraffic {
    pub relay: String,
    pub node_id: NodeId,
    /// Seconds since this report arrived; a stale row is not a live one.
    pub age_secs: u64,
    pub links: Vec<RelayLink>,
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
