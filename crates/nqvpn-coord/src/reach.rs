//! Relay reachability probing (§3.2).
//!
//! A relay that advertises an address nobody can dial joins happily,
//! reports healthy, and then silently fails to mesh — the failure only
//! shows up as timeouts in *other* relays' logs. Since the relay binds
//! its listener before joining, the coordinator can simply try the
//! advertised address and say so immediately.
//!
//! This is advisory, never a rejection: the coordinator's vantage point
//! is not every peer's, firewalls can be source-specific, and a slow
//! start-up would produce false negatives. It converts an invisible
//! partial mesh into a visible warning, which is the whole point.

use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use std::net::ToSocketAddrs;
use std::time::Duration;

/// What the coordinator learned about an advertised relay address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// Never probed (probe disabled, or the relay has not joined yet).
    Unknown,
    Reachable,
    /// Dialed and failed — almost always a firewall or a wrong
    /// advertised address.
    Unreachable,
}

impl Reachability {
    pub fn as_str(&self) -> &'static str {
        match self {
            Reachability::Unknown => "unknown",
            Reachability::Reachable => "reachable",
            Reachability::Unreachable => "unreachable",
        }
    }
}

/// Try to reach a relay's advertised address. Success means the QUIC
/// handshake completed, which proves a listener is accepting there —
/// we deliberately do not authenticate, since we only care about
/// reachability, and the relay will reject us at the app layer anyway.
pub async fn probe(addr: &str, timeout: Duration) -> Reachability {
    let Ok(mut resolved) = addr.to_socket_addrs() else {
        return Reachability::Unreachable;
    };
    let Some(sock) = resolved.next() else {
        return Reachability::Unreachable;
    };
    // A throwaway identity: the peer refuses our credential, but only
    // after the transport handshake we are measuring has succeeded.
    let Ok(id) = TlsIdentity::generate("coordinator-probe") else {
        return Reachability::Unknown;
    };
    let Ok(cfg) = client_config(&id, None, 5) else {
        return Reachability::Unknown;
    };
    let Ok(mut ep) = quinn::Endpoint::client("0.0.0.0:0".parse().expect("wildcard")) else {
        return Reachability::Unknown;
    };
    ep.set_default_client_config(cfg);
    let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("relay");
    let connecting = match ep.connect(sock, host) {
        Ok(c) => c,
        Err(_) => return Reachability::Unreachable,
    };
    let result = match tokio::time::timeout(timeout, connecting).await {
        Ok(Ok(conn)) => {
            conn.close(0u32.into(), b"probe");
            Reachability::Reachable
        }
        // A refused/aborted handshake still proves something is
        // listening; only a timeout means "nothing answered".
        Ok(Err(quinn::ConnectionError::TimedOut)) => Reachability::Unreachable,
        Ok(Err(_)) => Reachability::Reachable,
        Err(_) => Reachability::Unreachable,
    };
    ep.close(0u32.into(), b"done");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use nqvpn_proto::quic::server_config;

    #[tokio::test]
    async fn a_live_listener_is_reachable() {
        let id = TlsIdentity::generate("relay").unwrap();
        let ep = quinn::Endpoint::server(
            server_config(&id, 5).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = ep.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(i) = ep.accept().await {
                let _ = i.await;
            }
        });
        assert_eq!(
            probe(&addr.to_string(), Duration::from_secs(3)).await,
            Reachability::Reachable
        );
    }

    #[tokio::test]
    async fn a_dead_port_is_unreachable() {
        // Nothing is listening here; the handshake gets no answer.
        // (A blackholed port is exactly what a firewall looks like.)
        let r = probe("127.0.0.1:9", Duration::from_millis(800)).await;
        assert_eq!(r, Reachability::Unreachable);
    }

    #[tokio::test]
    async fn an_unresolvable_address_is_unreachable() {
        assert_eq!(
            probe("no-such-host.invalid:4444", Duration::from_secs(1)).await,
            Reachability::Unreachable
        );
    }
}
