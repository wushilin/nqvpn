//! Pluggable packet transport: QUIC datagrams or a QUIC stream.
//!
//! The design argues for datagrams (no head-of-line blocking, no second
//! loss-recovery loop under the inner TCP). Practice sometimes disagrees:
//! quinn's stream path is far more exercised than its datagram path,
//! streams get flow control and backpressure instead of hard drops, and
//! QUIC's own loss recovery can beat an inner TCP that has to wait a
//! full RTT to notice. Rather than argue, both are implemented behind
//! one interface so a deployment can measure and choose.
//!
//! The mode is a *network* setting handed out at join, so every member
//! of a network agrees without negotiating on the wire.
//!
//! Stream mode carries packets over N parallel **lanes**. One stream for
//! everything means one lost segment stalls every tunneled flow behind
//! it — the head-of-line blocking that argued for datagrams in the first
//! place. Splitting flows across lanes confines a stall to the flows
//! sharing that lane, while each flow still gets its own ordered pipe.
//!
//! An endpoint picks a lane by hashing the inner 5-tuple, so a given
//! connection is sticky to one lane and never reorders. Relays cannot do
//! that themselves — the payload is sealed end to end and they can see no
//! ports — so a frame is forwarded on the lane it arrived on, making the
//! lane an opaque label chosen by the endpoint and echoed by the relay.
//!
//! Lane count needs no negotiation: a receiver accepts however many
//! streams arrive, so only the sender needs a number, and the coordinator
//! publishes one per network. A peer still on one lane interoperates with
//! a peer on eight, in both directions, which is what makes a rolling
//! upgrade safe.

use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// How tunneled packets cross a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// RFC 9221 datagrams: unreliable, unordered, never retransmitted.
    Datagram,
    /// Length-framed packets over a unidirectional QUIC stream:
    /// reliable, ordered, flow-controlled.
    Stream,
}

impl Mode {
    pub fn parse(s: &str) -> Mode {
        match s {
            "stream" => Mode::Stream,
            _ => Mode::Datagram,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Datagram => "datagram",
            Mode::Stream => "stream",
        }
    }
}

/// Bounded queue toward the stream writer. Overflow drops the newest
/// packet rather than growing memory — the same rule the datagram path
/// follows when QUIC refuses a send (§9).
const SEND_QUEUE: usize = 1024;
/// Packets are MTU-sized, so a 16-bit length prefix is ample.
const LEN_PREFIX: usize = 2;
/// Largest tunnel MTU a network may be configured with (the coordinator
/// refuses more).
pub const MAX_TUNNEL_MTU: usize = 9000;
/// Largest frame a lane carries: a full-size sealed packet plus slack
/// for the small control frames (handshakes, trace notes). The 16-bit
/// prefix could say 65535; nothing legitimate comes near that, and a
/// reader must not allocate what a peer merely declares.
pub const MAX_LANE_FRAME: usize = MAX_TUNNEL_MTU + crate::quic::FRAME_OVERHEAD + 256;
/// Upper bound on lanes, so a bad config cannot open unbounded streams.
pub const MAX_LANES: u8 = 32;

/// Lane a frame that carries no flow identity travels on. Datagram mode
/// has no streams at all and always reports this.
pub const LANE_DEFAULT: u8 = 0;

/// One connection's packet channel, in whichever mode the network uses.
pub struct PacketChannel {
    mode: Mode,
    conn: quinn::Connection,
    /// Stream mode only: one writer queue per lane. Empty in datagram
    /// mode, where sends go straight onto the connection.
    lanes: Vec<mpsc::Sender<Bytes>>,
    /// Inbound packets and the lane each arrived on, fed by reader tasks
    /// in both modes so callers see one interface.
    inbox: Mutex<mpsc::Receiver<(Bytes, u8)>>,
    /// Shared with the lane tasks, which drop frames too.
    counters: Arc<Counters>,
}

#[derive(Default)]
struct Counters {
    dropped: AtomicU64,
    /// Packets refused because they exceeded the path MTU (datagrams) or
    /// the lane frame cap (streams), in either direction. Counted apart
    /// from ordinary drops: this one means a tunnel MTU is misconfigured,
    /// which a human must fix, whereas a generic drop is congestion doing
    /// its job.
    too_large: AtomicU64,
}

impl Counters {
    fn oversized(&self) {
        self.too_large.fetch_add(1, Ordering::Relaxed);
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

impl PacketChannel {
    /// Start carrying packets on `conn` with a single lane.
    pub fn start(conn: quinn::Connection, mode: Mode) -> Arc<PacketChannel> {
        PacketChannel::start_lanes(conn, mode, 1)
    }

    /// Start carrying packets on `conn`. Both sides call this; in stream
    /// mode each opens its own outbound lanes and accepts the peer's, so
    /// neither has to go first and the two directions are independent.
    pub fn start_lanes(
        conn: quinn::Connection,
        mode: Mode,
        lanes: u8,
    ) -> Arc<PacketChannel> {
        let (in_tx, in_rx) = mpsc::channel::<(Bytes, u8)>(SEND_QUEUE);
        let counters = Arc::new(Counters::default());
        let out = match mode {
            Mode::Datagram => {
                let c = conn.clone();
                let tx = in_tx.clone();
                tokio::spawn(async move {
                    while let Ok(d) = c.read_datagram().await {
                        if tx.send((d, LANE_DEFAULT)).await.is_err() {
                            return;
                        }
                    }
                });
                // Datagrams are sent inline, not through a writer task.
                //
                // Backpressure was tried here — a bounded queue drained
                // by a task awaiting `send_datagram_wait`, so congestion
                // would slow the source instead of discarding packets.
                // It measured 28x WORSE (1.9 vs 54 Mbit/s upload):
                // awaiting each send serially turns the path into a
                // one-packet-in-flight pipeline, and a task wakeup per
                // packet cannot keep a link full. The theory was sound;
                // this shape of it is not.
                //
                // The primitive for a better attempt does exist:
                // `Connection::datagram_send_buffer_space()` reports
                // remaining room without blocking, so the source can be
                // throttled on a readiness *signal* instead of stalling
                // on a per-packet await. That keeps sends pipelined,
                // which is the property this version destroyed. Untested
                // — do not adopt it without a measurement.
                Vec::new()
            }
            Mode::Stream => {
                // Reader: accept every lane the peer opens and pump them
                // all into one inbox. Accepting in a loop (rather than
                // taking a fixed count) is what lets a peer with a
                // different lane count interoperate without negotiating.
                let c = conn.clone();
                let tx = in_tx.clone();
                let ctr = counters.clone();
                tokio::spawn(async move {
                    while let Ok(mut rx) = c.accept_uni().await {
                        let tx = tx.clone();
                        let ctr = ctr.clone();
                        tokio::spawn(async move {
                            // Each lane names itself once, at open. Accept
                            // order would not be reliable enough to infer
                            // it, and the relay has to forward a frame on
                            // the lane it came in on.
                            let mut lane = [0u8; 1];
                            if rx.read_exact(&mut lane).await.is_err() {
                                return;
                            }
                            let lane = lane[0];
                            let mut header = [0u8; LEN_PREFIX];
                            loop {
                                if rx.read_exact(&mut header).await.is_err() {
                                    return;
                                }
                                let len = u16::from_be_bytes(header) as usize;
                                if len > MAX_LANE_FRAME {
                                    // Skip it without buffering it: the
                                    // lane stays in sync and the rest of
                                    // its flows keep moving.
                                    ctr.oversized();
                                    tracing::debug!(len, lane, "dropping oversized lane frame");
                                    if skip(&mut rx, len).await.is_err() {
                                        return;
                                    }
                                    continue;
                                }
                                let mut buf = vec![0u8; len];
                                if len > 0 && rx.read_exact(&mut buf).await.is_err() {
                                    return;
                                }
                                if tx.send((Bytes::from(buf), lane)).await.is_err() {
                                    return;
                                }
                            }
                        });
                    }
                });
                // Writers: one task per lane owns that lane's stream, so
                // callers stay non-blocking and order holds within a lane.
                let n = lanes.clamp(1, MAX_LANES);
                // Split the queue across lanes rather than giving each
                // its own full depth: the buffer is a per-connection
                // budget, and multiplying it by the lane count would
                // multiply a relay's worst-case memory by the same
                // factor for every session it holds. Floored so a high
                // lane count still leaves each lane usable.
                let per_lane = (SEND_QUEUE / n as usize).max(64);
                (0..n)
                    .map(|lane| {
                        let (out_tx, mut out_rx) = mpsc::channel::<Bytes>(per_lane);
                        let c = conn.clone();
                        let ctr = counters.clone();
                        tokio::spawn(async move {
                            let Ok(mut tx) = c.open_uni().await else { return };
                            if tx.write_all(&[lane]).await.is_err() {
                                return;
                            }
                            while let Some(pkt) = out_rx.recv().await {
                                // `send_on` already refuses these; never
                                // truncate one into a corrupt frame.
                                let Ok(len) = u16::try_from(pkt.len()) else {
                                    ctr.oversized();
                                    continue;
                                };
                                if tx.write_all(&len.to_be_bytes()).await.is_err() {
                                    return;
                                }
                                if tx.write_all(&pkt).await.is_err() {
                                    return;
                                }
                            }
                        });
                        out_tx
                    })
                    .collect()
            }
        };
        Arc::new(PacketChannel {
            mode,
            conn,
            lanes: out,
            inbox: Mutex::new(in_rx),
            counters,
        })
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Close the underlying connection. Every reader ends, so whoever is
    /// pumping this channel sees `recv()` return `None` and runs its
    /// ordinary teardown — the one path a session ever leaves by.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(code.into(), reason);
    }

    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Outbound lanes in use. 0 in datagram mode, which has no streams.
    pub fn lane_count(&self) -> usize {
        self.lanes.len()
    }

    pub fn dropped(&self) -> u64 {
        self.counters.dropped.load(Ordering::Relaxed)
    }

    pub fn too_large(&self) -> u64 {
        self.counters.too_large.load(Ordering::Relaxed)
    }

    /// Largest inner packet this connection can carry right now.
    pub fn usable_inner_mtu(&self) -> Option<usize> {
        crate::quic::usable_inner_mtu(&self.conn)
    }

    /// Queue a packet on lane 0 — for callers with no flow identity to
    /// hash (probes, and datagram mode, which has no lanes at all).
    pub fn send(&self, packet: Bytes) -> bool {
        self.send_on(packet, LANE_DEFAULT)
    }

    /// Queue a packet on a chosen lane. Never blocks and never buffers
    /// without bound: a full queue (or a QUIC refusal) drops and counts.
    ///
    /// The lane wraps rather than erroring, so a frame relayed from a
    /// peer with more lanes than this connection has still goes out. It
    /// lands on a busier lane, which costs some isolation; dropping it
    /// would cost the packet.
    pub fn send_on(&self, packet: Bytes, lane: u8) -> bool {
        // Oversized packets can never be sent, whatever the queue does,
        // so they are rejected here with their own counter — an MTU
        // misconfiguration must not hide inside a generic drop.
        if self.mode == Mode::Datagram {
            if let Some(max) = self.conn.max_datagram_size() {
                if packet.len() > max {
                    self.counters.oversized();
                    return false;
                }
            }
        } else if packet.len() > MAX_LANE_FRAME {
            // The peer would only skip it; do not spend the bandwidth.
            self.counters.oversized();
            return false;
        }
        let ok = if self.lanes.is_empty() {
            self.mode == Mode::Datagram && self.conn.send_datagram(packet).is_ok()
        } else {
            self.lanes[lane as usize % self.lanes.len()].try_send(packet).is_ok()
        };
        if !ok {
            self.counters.dropped.fetch_add(1, Ordering::Relaxed);
        }
        ok
    }

    /// Warn if the tunnel MTU we were configured with cannot actually
    /// cross this path. Called once per attach, where an operator can
    /// still act on it.
    pub fn check_mtu(&self, tunnel_mtu: u16) {
        if self.mode != Mode::Datagram {
            return; // streams fragment across the byte pipe; no limit
        }
        match self.usable_inner_mtu() {
            Some(usable) if usable < tunnel_mtu as usize => {
                tracing::warn!(
                    tunnel_mtu,
                    usable,
                    "path cannot carry the configured tunnel MTU — packets above \
                     {usable} bytes will be dropped; lower the network's mtu setting"
                );
            }
            Some(usable) => {
                tracing::info!(tunnel_mtu, usable, "path MTU is sufficient");
            }
            None => tracing::warn!("peer does not support QUIC datagrams"),
        }
    }

    /// Next inbound packet with the lane it arrived on, or `None` once
    /// the connection is finished.
    pub async fn recv(&self) -> Option<(Bytes, u8)> {
        // The receiver is owned by whichever task is pumping; only one
        // caller reads at a time, which is how both pumps are written.
        // A tokio mutex, because the guard is held across the await.
        let mut rx = self.inbox.lock().await;
        rx.recv().await
    }
}

/// Read and discard `n` bytes of a lane without buffering them.
async fn skip(rx: &mut quinn::RecvStream, mut n: usize) -> Result<(), ()> {
    while n > 0 {
        match rx.read_chunk(n, true).await {
            Ok(Some(chunk)) => n -= chunk.bytes.len(),
            _ => return Err(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_round_trips_and_defaults_safely() {
        assert_eq!(Mode::parse("stream"), Mode::Stream);
        assert_eq!(Mode::parse("datagram"), Mode::Datagram);
        // An unknown value falls back to the design's default rather
        // than failing a join.
        assert_eq!(Mode::parse("nonsense"), Mode::Datagram);
        assert_eq!(Mode::Stream.as_str(), "stream");
        assert_eq!(Mode::Datagram.as_str(), "datagram");
    }
}
