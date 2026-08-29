//! Coordinator: control plane only (DESIGN.md §3). One module per
//! concern; all mutation of a network goes through its `NetState` lock.

pub mod api;
pub mod auth;
pub mod admin;
pub mod config;
pub mod db;
pub mod control;
pub mod directory;
pub mod error;
pub mod ipam;
pub mod leases;
pub mod reach;
pub mod registry;
pub mod secrets;
pub mod signer;
pub mod state;
pub mod ws;
