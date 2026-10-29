//! A byte-for-byte UDP forwarder to one fixed target.
//!
//! Every client source address is a *flow*: its own upstream socket,
//! connected to the target, so replies find their way back to the right
//! client. That is the whole state. Datagrams are copied, never parsed —
//! the QUIC session inside runs end to end between client and relay, so
//! the forwarder can neither read nor forge anything (the client pins the
//! relay's certificate fingerprint as it does on a direct dial).
//!
//! Flows end after `idle` without traffic in either direction. QUIC's
//! keepalives hold a live session's flow open, so `idle` only has to
//! exceed the session's own idle timeout (keepalive × 5).
//!
//! The target is a fixed host:port, so this is not an open proxy. A full
//! flow table drops datagrams from new sources rather than evicting live
//! ones: an attacker spraying source addresses cannot push real clients
//! out. QUIC's 3× anti-amplification limit bounds what a spoofed source
//! can make the relay send back through us.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Large enough for any UDP payload.
const BUF: usize = 65_535;

#[derive(Debug, Clone)]
pub struct Options {
    /// Where every datagram goes: `host:port`, looked up again every
    /// `resolve_every` so a relay that moves is followed.
    pub target: String,
    /// A flow with no traffic either way for this long is closed.
    pub idle: Duration,
    /// Flows beyond this are refused (their datagrams dropped).
    pub max_flows: usize,
    pub resolve_every: Duration,
}

impl Options {
    pub fn new(target: impl Into<String>) -> Options {
        Options { target: target.into(), idle: Duration::from_secs(120), max_flows: 4096, resolve_every: Duration::from_secs(60) }
    }
}

struct Flow {
    upstream: Arc<UdpSocket>,
    /// Milliseconds since `Forwarder::epoch`, either direction.
    last_seen: Arc<AtomicU64>,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[derive(Default)]
pub struct Counters {
    pub flows_opened: AtomicU64,
    pub flows_refused: AtomicU64,
    pub datagrams_up: AtomicU64,
    pub datagrams_down: AtomicU64,
}

pub struct Forwarder {
    listen: Arc<UdpSocket>,
    opts: Options,
    target: Mutex<SocketAddr>,
    flows: Mutex<HashMap<SocketAddr, Flow>>,
    epoch: Instant,
    pub counters: Counters,
}

impl Forwarder {
    /// Bind `listen` and resolve the target once; failing either is fatal.
    pub async fn bind(listen: SocketAddr, opts: Options) -> Result<Arc<Forwarder>> {
        let target = resolve(&opts.target).await?;
        let sock = UdpSocket::bind(listen).await.with_context(|| format!("binding {listen}"))?;
        Ok(Arc::new(Forwarder {
            listen: Arc::new(sock),
            opts,
            target: Mutex::new(target),
            flows: Mutex::new(HashMap::new()),
            epoch: Instant::now(),
            counters: Counters::default(),
        }))
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listen.local_addr()?)
    }

    pub fn flows(&self) -> usize {
        self.flows.lock().unwrap().len()
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    /// Forward until the socket fails. Also runs the idle sweep and the
    /// periodic re-resolution of the target.
    pub async fn run(self: Arc<Self>) -> Result<()> {
        // Stopping `run` (an error, or its task aborted) stops everything:
        // housekeeping and every flow's reader, whose `Arc`s would
        // otherwise keep the listening socket open.
        let _stop = Stop { fwd: self.clone(), housekeeping: tokio::spawn(self.clone().housekeeping()) };
        let mut buf = vec![0u8; BUF];
        loop {
            let (n, from) = self.listen.recv_from(&mut buf).await.context("receiving")?;
            let Some((upstream, last_seen)) = self.flow_for(from).await else { continue };
            last_seen.store(self.now_ms(), Ordering::Relaxed);
            self.counters.datagrams_up.fetch_add(1, Ordering::Relaxed);
            // A failed send is a lost datagram, which UDP allows; QUIC
            // retransmits.
            if let Err(e) = upstream.send(&buf[..n]).await {
                tracing::debug!(client = %from, "upstream send: {e}");
            }
        }
    }

    /// The flow for `from`, opened if new and there is room.
    async fn flow_for(self: &Arc<Self>, from: SocketAddr) -> Option<(Arc<UdpSocket>, Arc<AtomicU64>)> {
        if let Some(f) = self.flows.lock().unwrap().get(&from) {
            return Some((f.upstream.clone(), f.last_seen.clone()));
        }
        if self.flows() >= self.opts.max_flows {
            if self.counters.flows_refused.fetch_add(1, Ordering::Relaxed).is_multiple_of(1000) {
                tracing::warn!(client = %from, max_flows = self.opts.max_flows, "flow table full; dropping datagrams from new clients");
            }
            return None;
        }
        let target = *self.target.lock().unwrap();
        let bind: SocketAddr = if target.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let upstream = match UdpSocket::bind(bind).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(client = %from, "opening an upstream socket: {e}");
                return None;
            }
        };
        if let Err(e) = upstream.connect(target).await {
            tracing::warn!(client = %from, %target, "connecting upstream: {e}");
            return None;
        }
        let upstream = Arc::new(upstream);
        let last_seen = Arc::new(AtomicU64::new(self.now_ms()));
        let reader = tokio::spawn(self.clone().pump_down(from, upstream.clone(), last_seen.clone()));
        let flow = Flow { upstream: upstream.clone(), last_seen: last_seen.clone(), reader };
        let mut flows = self.flows.lock().unwrap();
        // Lost a race with another datagram from the same client: keep the
        // first flow (ours is dropped, aborting its reader).
        if let Some(f) = flows.get(&from) {
            return Some((f.upstream.clone(), f.last_seen.clone()));
        }
        flows.insert(from, flow);
        drop(flows);
        self.counters.flows_opened.fetch_add(1, Ordering::Relaxed);
        tracing::info!(client = %from, %target, "flow opened");
        Some((upstream, last_seen))
    }

    /// Target → client for one flow.
    async fn pump_down(self: Arc<Self>, client: SocketAddr, upstream: Arc<UdpSocket>, last_seen: Arc<AtomicU64>) {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = match upstream.recv(&mut buf).await {
                Ok(n) => n,
                // ICMP unreachable surfaces here as ECONNREFUSED on a
                // connected socket: the relay is down for now. Keep the
                // flow; QUIC decides when to give up.
                Err(e) => {
                    tracing::debug!(%client, "upstream receive: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            last_seen.store(self.now_ms(), Ordering::Relaxed);
            self.counters.datagrams_down.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = self.listen.send_to(&buf[..n], client).await {
                tracing::debug!(%client, "downstream send: {e}");
            }
        }
    }

    async fn housekeeping(self: Arc<Self>) {
        let tick = (self.opts.idle / 4).clamp(Duration::from_millis(100), Duration::from_secs(10));
        let mut next_resolve = Instant::now() + self.opts.resolve_every;
        loop {
            tokio::time::sleep(tick).await;
            self.sweep();
            if Instant::now() >= next_resolve {
                next_resolve = Instant::now() + self.opts.resolve_every;
                match resolve(&self.opts.target).await {
                    Ok(addr) => {
                        let mut t = self.target.lock().unwrap();
                        if *t != addr {
                            // Existing flows keep their address: moving a
                            // live QUIC session mid-flight would only break it.
                            tracing::info!(old = %*t, new = %addr, "target address changed; new flows use the new one");
                            *t = addr;
                        }
                    }
                    Err(e) => tracing::warn!(target = %self.opts.target, "re-resolving the target failed; keeping the last address: {e:#}"),
                }
            }
        }
    }

    /// Close flows idle for longer than `idle`.
    pub fn sweep(&self) {
        let now = self.now_ms();
        let idle = self.opts.idle.as_millis() as u64;
        self.flows.lock().unwrap().retain(|client, f| {
            let keep = now.saturating_sub(f.last_seen.load(Ordering::Relaxed)) < idle;
            if !keep {
                tracing::info!(%client, "flow closed (idle)");
            }
            keep
        });
    }

    pub fn status_line(&self) -> String {
        let c = &self.counters;
        format!(
            "target={} flows={} opened={} refused={} up={} down={}",
            *self.target.lock().unwrap(),
            self.flows(),
            c.flows_opened.load(Ordering::Relaxed),
            c.flows_refused.load(Ordering::Relaxed),
            c.datagrams_up.load(Ordering::Relaxed),
            c.datagrams_down.load(Ordering::Relaxed),
        )
    }
}

struct Stop {
    fwd: Arc<Forwarder>,
    housekeeping: tokio::task::JoinHandle<()>,
}

impl Drop for Stop {
    fn drop(&mut self) {
        self.housekeeping.abort();
        self.fwd.flows.lock().unwrap().clear();
    }
}

/// The first address `host:port` resolves to.
async fn resolve(target: &str) -> Result<SocketAddr> {
    let mut it = tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host(target))
        .await
        .with_context(|| format!("resolving {target}: timed out"))?
        .with_context(|| format!("resolving {target}"))?;
    it.next().with_context(|| format!("{target} resolves to no address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        let t = tokio::spawn(async move {
            let mut buf = vec![0u8; BUF];
            loop {
                let (n, from) = s.recv_from(&mut buf).await.unwrap();
                s.send_to(&buf[..n], from).await.unwrap();
            }
        });
        (addr, t)
    }

    async fn start(opts: Options) -> (Arc<Forwarder>, SocketAddr) {
        let f = Forwarder::bind("127.0.0.1:0".parse().unwrap(), opts).await.unwrap();
        let addr = f.local_addr().unwrap();
        tokio::spawn(f.clone().run());
        (f, addr)
    }

    async fn roundtrip(via: SocketAddr, msg: &[u8]) -> Option<Vec<u8>> {
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.send_to(msg, via).await.unwrap();
        let mut buf = vec![0u8; BUF];
        let n = tokio::time::timeout(Duration::from_millis(500), c.recv(&mut buf)).await.ok()?.ok()?;
        Some(buf[..n].to_vec())
    }

    #[tokio::test]
    async fn datagrams_go_through_unchanged_and_each_client_gets_its_own_flow() {
        let (target, _t) = echo().await;
        let (f, via) = start(Options::new(target.to_string())).await;
        let big = vec![0xabu8; 1440];
        assert_eq!(roundtrip(via, b"hello").await.as_deref(), Some(&b"hello"[..]));
        assert_eq!(roundtrip(via, &big).await, Some(big));
        assert_eq!(f.flows(), 2, "two client sockets, two flows");
    }

    #[tokio::test]
    async fn a_full_table_refuses_new_clients_and_keeps_live_ones() {
        let (target, _t) = echo().await;
        let (f, via) = start(Options { max_flows: 1, ..Options::new(target.to_string()) }).await;
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        first.send_to(b"a", via).await.unwrap();
        let mut buf = [0u8; 16];
        tokio::time::timeout(Duration::from_millis(500), first.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(roundtrip(via, b"b").await, None, "second client refused");
        first.send_to(b"c", via).await.unwrap();
        let n = tokio::time::timeout(Duration::from_millis(500), first.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(&buf[..n], b"c", "first client unaffected");
        assert_eq!(f.counters.flows_refused.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn idle_flows_are_closed() {
        let (target, _t) = echo().await;
        let (f, via) = start(Options { idle: Duration::from_millis(300), ..Options::new(target.to_string()) }).await;
        roundtrip(via, b"x").await.unwrap();
        assert_eq!(f.flows(), 1);
        tokio::time::sleep(Duration::from_millis(800)).await;
        assert_eq!(f.flows(), 0);
    }
}
