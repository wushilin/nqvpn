use serde::{Deserialize, Serialize};

/// Stable per-network member identifier, assigned by the coordinator,
/// never reused (DESIGN.md §2).
pub type NodeId = u32;

/// Monotonically increasing per-network directory revision (§3.2).
pub type Revision = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Client,
    Relay,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Client => write!(f, "client"),
            Role::Relay => write!(f, "relay"),
        }
    }
}
