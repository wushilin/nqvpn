//! Everything that terminates traffic (DESIGN.md §4, §8): the Noise
//! engine, the peer table with its ingress filter, the TUN device, OS
//! route programming with local-overlap exclusion, and the one-endpoint-
//! per-host guard. A client is one of these plus an uplink; a gateway
//! relay is one of these behind `Route::Me`.

pub mod endpoint_guard;
pub mod engine;
pub mod ifaces;
pub mod peers;
pub mod routes;
pub mod tun;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod tun_real;
