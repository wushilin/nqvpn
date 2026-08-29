//! The client's single upstream to a relay (DESIGN.md §9, task 4):
//! attach, keep alive, measure, and re-attach elsewhere when it dies.

use anyhow::{anyhow, Context, Result};
use nqvpn_proto::api::RelayEntry;
use nqvpn_proto::control::Hello;
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::frame::{Probe, T_PROBE};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::transport::{Mode, PacketChannel};
use nqvpn_proto::stream::{read_envelope, write_msg};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::engine::Uplink;

/// The live connection, swappable underneath the pumps so a re-attach is
/// invisible to everything above.
#[derive(Default)]
pub struct RelayUplink {
    chan: Mutex<Option<Arc<PacketChannel>>>,
    conn: Mutex<Option<quinn::Connection>>,
    pub attached_to: Mutex<Option<String>>,
    pub rtt_ms: AtomicU64,
    pub drops: AtomicU64,
    /// Largest inner packet our uplink can carry, from QUIC's own path
    /// MTU discovery. Reported to the coordinator so the network can
    /// settle on a value every hop can handle.
    pub usable_mtu: AtomicU64,
    mtu_handle: Arc<AtomicU64>,
}

impl RelayUplink {
    pub fn new() -> Arc<RelayUplink> {
        Arc::new(RelayUplink::default())
    }

    pub fn set(
        &self,
        conn: Option<quinn::Connection>,
        chan: Option<Arc<PacketChannel>>,
        name: Option<String>,
    ) {
        *self.conn.lock().unwrap() = conn;
        *self.chan.lock().unwrap() = chan;
        *self.attached_to.lock().unwrap() = name;
    }

    pub fn channel(&self) -> Option<Arc<PacketChannel>> {
        self.chan.lock().unwrap().clone()
    }

    /// Transport-level drops, so congestion behaviour is visible in
    /// status rather than something you have to infer from throughput.
    pub fn transport_counters(&self) -> (u64, u64) {
        self.channel().map(|c| (c.dropped(), c.too_large())).unwrap_or((0, 0))
    }

    /// Shared handle so the coordinator link can report our measurement.
    pub fn usable_mtu_handle(self: &Arc<Self>) -> Arc<AtomicU64> {
        // The field is inside the Arc; hand out a projection by cloning
        // the value into a dedicated atomic kept in sync by refresh.
        self.mtu_handle.clone()
    }

    /// Re-read the path MTU; cheap, so the caller can poll it.
    pub fn refresh_usable_mtu(&self) {
        if let Some(c) = self.channel() {
            if let Some(u) = c.usable_inner_mtu() {
                self.usable_mtu.store(u as u64, Ordering::Relaxed);
                self.mtu_handle.store(u as u64, Ordering::Relaxed);
            }
        }
    }

    pub fn connection(&self) -> Option<quinn::Connection> {
        self.conn.lock().unwrap().clone()
    }

    pub fn is_up(&self) -> bool {
        self.conn.lock().unwrap().is_some()
    }
}

impl Uplink for RelayUplink {
    fn send(&self, packet: Vec<u8>, lane: u8) -> bool {
        let chan = self.chan.lock().unwrap().clone();
        match chan {
            Some(c) if c.send_on(packet.into(), lane) => true,
            _ => {
                self.drops.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

/// Rank the fleet: an explicitly preferred relay wins when reachable,
/// otherwise lowest measured RTT (decision #3).
pub async fn choose_relay(
    fleet: &[RelayEntry],
    preferred: Option<&str>,
    identity: &TlsIdentity,
) -> Option<RelayEntry> {
    if let Some(name) = preferred {
        if let Some(e) = fleet.iter().find(|r| r.name == name) {
            if probe_rtt(e, identity).await.is_some() {
                return Some(e.clone());
            }
            tracing::warn!(relay = %name, "preferred relay unreachable; falling back to RTT");
        } else {
            tracing::warn!(relay = %name, "preferred relay is not in the fleet");
        }
    }
    let mut best: Option<(u128, RelayEntry)> = None;
    for e in fleet {
        if let Some(rtt) = probe_rtt(e, identity).await {
            if best.as_ref().map(|(b, _)| rtt < *b).unwrap_or(true) {
                best = Some((rtt, e.clone()));
            }
        }
    }
    best.map(|(rtt, e)| {
        tracing::info!(relay = %e.name, rtt_ms = rtt, "selected relay");
        e
    })
}

/// One-shot reachability + latency check against a relay.
async fn probe_rtt(entry: &RelayEntry, identity: &TlsIdentity) -> Option<u128> {
    let addr = entry.addr.to_socket_addrs().ok()?.next()?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().ok()?).ok()?;
    ep.set_default_client_config(client_config(identity, Some(entry.cert_fp.clone()), 5).ok()?);
    let started = Instant::now();
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("relay");
    let conn = tokio::time::timeout(Duration::from_secs(5), ep.connect(addr, host).ok()?)
        .await
        .ok()?
        .ok()?;
    let rtt = started.elapsed().as_millis();
    conn.close(0u32.into(), b"probe");
    Some(rtt)
}

/// Attach to a relay: mutual TLS against its pinned certificate, then
/// `Hello{credential}`. Returns the live connection.
pub async fn attach(
    entry: &RelayEntry,
    credential: &str,
    identity: &TlsIdentity,
    keepalive: u64,
    mode: Mode,
    lanes: u8,
) -> Result<(quinn::Connection, Arc<PacketChannel>)> {
    let addr = entry
        .addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", entry.addr))?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", entry.addr))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(
        client_config(identity, Some(entry.cert_fp.clone()), keepalive)
            .map_err(|e| anyhow!("tls: {e}"))?,
    );
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("relay");
    let conn = ep.connect(addr, host)?.await.context("relay connect")?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string() }).await?;
    let ack = read_envelope(&mut rx).await?;
    anyhow::ensure!(ack.kind == Kind::HelloAck as u16, "relay refused our credential");
    // The control stream must outlive this call: the relay treats its
    // closure as the session ending. Park them on a task tied to the
    // connection's lifetime rather than leaking them — a leaked
    // Endpoint costs a UDP socket and a driver task per re-attach.
    let holder = conn.clone();
    tokio::spawn(async move {
        let _keep = (ep, tx, rx);
        holder.closed().await;
    });
    let chan = PacketChannel::start_lanes(conn.clone(), mode, lanes);
    Ok((conn, chan))
}

/// Hop-local probe so `nqvpn status` can show the uplink's health.
pub async fn probe_uplink(up: &RelayUplink, seq: u64) {
    let Some(chan) = up.channel() else { return };
    let sent = Instant::now();
    let p = Probe { kind: T_PROBE, seq, t_sent: sent.elapsed().as_micros() as u64 };
    if !chan.send(p.encode().into()) {
        return;
    }
    up.rtt_ms.store(sent.elapsed().as_millis() as u64, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_without_a_connection_is_counted_not_panicked() {
        let up = RelayUplink::new();
        assert!(!up.send(vec![1, 2, 3], 0));
        assert_eq!(up.drops.load(Ordering::Relaxed), 1);
        assert!(!up.is_up());
    }
}
