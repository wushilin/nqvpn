//! Client library — exposed for the binary and integration tests.

pub mod config;
pub mod coordlink;
pub mod uplink;
pub mod endpoint_guard;
pub mod engine;
pub mod routes;
pub mod peers;
pub mod tun;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod tun_real;
