//! Shared protocol crate: everything coordinator, relay, and client must
//! agree on. Depends on nothing internal (DESIGN.md §10).

pub mod api;
pub mod control;
pub mod credential;
pub mod envelope;
pub mod errors;
pub mod flow;
pub mod frame;
pub mod identity;
pub mod joinapi;
pub mod lpm;
pub mod quic;
pub mod rotation;
pub mod rpc;
pub mod seal;
pub mod stream;
pub mod transport;
pub mod types;
