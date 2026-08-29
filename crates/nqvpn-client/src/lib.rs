//! `nqvpn-client` — a leaf: one TUN, one upstream relay, one control
//! link. The library exposes the pieces so an in-process harness can run
//! many clients on fake TUNs for chaos tests.

pub mod client;
pub mod config;
