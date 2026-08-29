//! The member side of the control plane, shared by client and relay
//! (DESIGN.md §3.2): join + renewal, the generation protocol, and the
//! reconciler that turns a view into local actions.
//!
//! Three rules, and nothing else:
//!  * a `Delta` applies only onto exactly the generation held; otherwise
//!    the member asks for a snapshot (`Resync`) and waits;
//!  * every heartbeat carries the held generation and a digest of it, so
//!    the coordinator catches up a member that missed a push within one
//!    heartbeat period;
//!  * heartbeats carry the member's whole local truth, never events.

pub mod join;
pub mod link;
pub mod reconcile;

pub use join::{join_with_backoff, join_with_backoff_async, MemberConfig};
pub use link::{run_member, run_session, LinkHandle, LocalFacts, MemberExit, SessionParams, View, EXIT_REPLACED};
pub use reconcile::{spawn_reconciler, Reconcile};
