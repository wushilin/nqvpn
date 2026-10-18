//! Coordinator QUIC control plane (§3.2): the persistent two-way channel
//! every member holds. Mutual TLS + credential verification at `Hello`,
//! then a generation-numbered view downstream and heartbeats upstream.
//!
//! Push for speed, generation for continuity, heartbeat for safety:
//!  * every change is pushed as a delta the moment it happens;
//!  * a member applies a delta only onto exactly the generation it
//!    holds, otherwise it asks for a snapshot;
//!  * every heartbeat says which generation the member holds and a
//!    digest of it, so a member that missed a push is caught up within
//!    one heartbeat, and one that disagrees at the same generation is
//!    logged as the bug it is and resynced.

use anyhow::{anyhow, Context, Result};
use nqvpn_proto::control::*;
use nqvpn_proto::credential::{self, Claims, Expected};
use nqvpn_proto::envelope::{Envelope, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{peer_fingerprint, server_config};
use nqvpn_proto::stream::{parse, read_envelope, read_envelope_max, write_bytes, write_msg, StreamError};
use nqvpn_proto::types::{NodeId, Role};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};

use crate::directory::quantize_mtu;
use crate::state::{lock_for_sweep, now_ms, now_unix, AppState, NetState, ISS};

/// Bounded per-session push queue: a stalled member must not grow the
/// coordinator's memory. Overflow closes that session; it reconnects and
/// catches up from its generation.
const PUSH_QUEUE: usize = 256;

/// From the first packet to a verified `Hello`: the TLS handshake, the
/// control stream and the `Hello` itself, all under one deadline.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Cap on the one message read before the peer is authenticated.
const MAX_HELLO: u32 = 16 * 1024;

/// Connections between the first packet and a verified `Hello`. Past
/// this, new connections are refused until some authenticate or time
/// out: unauthenticated peers cannot hold an unbounded number of tasks.
const MAX_UNAUTHENTICATED: usize = 256;

/// Heartbeats a session may send in a burst, and per second sustained.
/// Members heartbeat every few seconds plus once per attach/detach;
/// beyond the budget, heartbeats are coalesced — the latest is applied
/// as soon as the budget allows — so nothing is lost, only delayed.
const HEARTBEAT_BURST: f64 = 8.0;
const HEARTBEATS_PER_SEC: f64 = 4.0;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// What a session's writer task can be asked to send.
#[derive(Debug, Clone)]
pub enum Push {
    Delta(Delta),
    Snapshot(Snapshot),
    /// An already-encoded envelope (RPC responses), written verbatim.
    Raw(Vec<u8>),
    Close(String),
}

pub struct Session {
    pub id: u64,
    pub node_id: NodeId,
    pub role: Role,
    /// Credential expiry; refreshed by `Refresh`. The sweep closes the
    /// session when it passes.
    pub exp: u64,
    pub login_gen: u64,
    /// Whether this session holds the current view (a snapshot or a
    /// complete delta chain was queued). Deltas are only pushed to
    /// synced sessions; the others are caught up by their heartbeat.
    pub synced: bool,
    pub tx: mpsc::Sender<Push>,
    pub conn: quinn::Connection,
    pub remote: String,
}

/// Application close codes.
pub const CLOSE_TIMEOUT: u32 = 1;
pub const CLOSE_SUPERSEDED: u32 = 2;
pub const CLOSE_VERSION: u32 = 3;
pub const CLOSE_EVICTED: u32 = 4;
pub const CLOSE_OVERFLOW: u32 = 5;
pub const CLOSE_EXPIRED: u32 = 6;
pub const CLOSE_REPLACED: u32 = nqvpn_proto::control::CLOSE_REPLACED;
pub const CLOSE_RECONFIGURED: u32 = nqvpn_proto::control::CLOSE_RECONFIGURED;

/// The credential belongs to an instance that has since been replaced
/// by a newer join under the same name.
#[derive(Debug)]
pub struct Replaced(pub String);

impl std::fmt::Display for Replaced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Replaced {}

pub fn bind(addr: SocketAddr, id: &TlsIdentity) -> Result<quinn::Endpoint> {
    let cfg = server_config(id, 15).map_err(|e| anyhow!("quic server config: {e}"))?;
    let endpoint = quinn::Endpoint::server(cfg, addr).context("binding QUIC control port")?;
    tracing::info!(addr = %endpoint.local_addr()?, "QUIC control listening");
    Ok(endpoint)
}

pub async fn run(state: Arc<AppState>, addr: SocketAddr, id: TlsIdentity) -> Result<()> {
    serve(state, bind(addr, &id)?).await
}

pub async fn serve(state: Arc<AppState>, endpoint: quinn::Endpoint) -> Result<()> {
    let unauthenticated = Arc::new(Semaphore::new(MAX_UNAUTHENTICATED));
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = unauthenticated.clone().try_acquire_owned() else {
            tracing::warn!(remote = %incoming.remote_address(), "too many unauthenticated control connections; refusing");
            incoming.refuse();
            continue;
        };
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(state, incoming, permit).await {
                tracing::debug!("control session ended: {e:#}");
            }
        });
    }
    Ok(())
}

/// The network a live session belongs to. Networks can be deleted under
/// live sessions: that ends the session, it is not a bug.
fn net_of(state: &AppState, network_id: &str) -> Result<Arc<Mutex<NetState>>> {
    state.net(network_id).ok_or_else(|| anyhow!("network {network_id} was deleted"))
}

fn lock(net: &Mutex<NetState>) -> Result<MutexGuard<'_, NetState>> {
    let ns = net.lock().map_err(|_| anyhow!("network state is poisoned"))?;
    if ns.deleted {
        anyhow::bail!("network {} was deleted", ns.cfg.network_id);
    }
    Ok(ns)
}

async fn handle_conn(state: Arc<AppState>, incoming: quinn::Incoming, permit: tokio::sync::OwnedSemaphorePermit) -> Result<()> {
    // A peer that connects and never says Hello must not hold a task:
    // handshake, stream and Hello share one deadline.
    let (conn, mut tx, rx, env) = tokio::time::timeout(HELLO_TIMEOUT, async {
        let conn = incoming.await.context("handshake")?;
        let (tx, mut rx) = conn.accept_bi().await.context("accepting control stream")?;
        let env = read_envelope_max(&mut rx, MAX_HELLO).await?;
        Ok::<_, anyhow::Error>((conn, tx, rx, env))
    })
    .await
    .context("waiting for Hello")??;
    let remote = conn.remote_address();
    let fp = peer_fingerprint(&conn).ok_or_else(|| anyhow!("peer presented no certificate"))?;
    if let Err(e) = nqvpn_proto::envelope::check_version(env.major, env.minor) {
        tracing::warn!(%remote, "refusing session: {e}");
        conn.close(CLOSE_VERSION.into(), e.to_string().as_bytes());
        anyhow::bail!("{e}");
    }
    if env.kind != Kind::Hello as u16 {
        anyhow::bail!("first message must be Hello, got kind {}", env.kind);
    }
    let hello: Hello = parse(&env)?;

    let (claims, network_id) = match verify_credential(&state, &hello.credential, &fp) {
        Ok(v) => v,
        Err(e) => {
            // Tell a replaced instance so in a way it can act on: it
            // must stop re-joining and exit.
            if e.downcast_ref::<Replaced>().is_some() {
                tracing::warn!(%remote, "refusing session: {e}");
                conn.close(CLOSE_REPLACED.into(), e.to_string().as_bytes());
            }
            return Err(e);
        }
    };
    // Authenticated: no longer counts against the unauthenticated cap.
    drop(permit);
    let node_id = claims.node_id;
    let role = claims.role;
    let name = claims.sub.clone();
    let session_id = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);
    tracing::info!(%remote, network = %network_id, member = %name, node_id, %role, have_gen = hello.have_gen, "control session authenticated");

    let (push_tx, mut push_rx) = mpsc::channel::<Push>(PUSH_QUEUE);
    let (rpc_out, mut rpc_rx) = mpsc::channel::<Vec<u8>>(PUSH_QUEUE);
    let rpc = nqvpn_proto::rpc::RpcPeer::new(rpc_out, Arc::new(nqvpn_proto::rpc::NoVerbs));
    {
        let push_tx = push_tx.clone();
        tokio::spawn(async move {
            while let Some(bytes) = rpc_rx.recv().await {
                if push_tx.send(Push::Raw(bytes)).await.is_err() {
                    return;
                }
            }
        });
    }

    // Register: supersede any older session for this node, mark alive,
    // publish, and decide what this session needs to be current.
    let (superseded, gen) = {
        let net = net_of(&state, &network_id)?;
        let mut ns = lock(&net)?;
        let now = now_unix();
        let superseded = ns.sessions.insert(
            node_id,
            Session {
                id: session_id,
                node_id,
                role,
                exp: claims.exp,
                login_gen: claims.login_gen,
                synced: false,
                tx: push_tx.clone(),
                conn: conn.clone(),
                remote: remote.to_string(),
            },
        );
        ns.leases.seen(node_id, now_ms());
        state.publish(&mut ns);
        let gen = ns.directory.gen;
        if !ns.in_grace(now) {
            catch_up(&mut ns, node_id, hello.have_gen);
        }
        (superseded, gen)
    };
    if let Some(old) = superseded {
        let _ = old.tx.try_send(Push::Close("superseded".into()));
        old.conn.close(CLOSE_SUPERSEDED.into(), b"superseded by a newer session");
    }

    let writer = tokio::spawn(async move {
        write_msg(&mut tx, Kind::HelloAck, &HelloAck { gen }).await?;
        while let Some(push) = push_rx.recv().await {
            match push {
                Push::Delta(d) => write_msg(&mut tx, Kind::Delta, &d).await?,
                Push::Snapshot(s) => write_msg(&mut tx, Kind::Snapshot, &s).await?,
                Push::Raw(bytes) => write_bytes(&mut tx, &bytes).await?,
                Push::Close(reason) => {
                    tracing::debug!("closing session: {reason}");
                    break;
                }
            }
        }
        Ok::<_, StreamError>(())
    });

    // Envelopes are read by a task of their own and handed over a
    // channel: the session loop also waits on a timer (coalesced
    // heartbeats), and a read abandoned by `select!` mid-frame would
    // lose bytes. Receiving from a channel is cancel-safe.
    let (env_tx, env_rx) = mpsc::channel::<Result<Envelope, StreamError>>(16);
    let reader = tokio::spawn(async move {
        let mut rx = rx;
        loop {
            let r = read_envelope(&mut rx).await;
            let end = r.is_err();
            if env_tx.send(r).await.is_err() || end {
                return;
            }
        }
    });

    let result = session_loop(&state, &network_id, node_id, role, &fp, env_rx, &rpc).await;
    rpc.close();
    reader.abort();

    // Teardown: drop the session (unless already superseded) and let the
    // lease decide what that means. A deleted network has nothing left
    // to tear down.
    if let Some(net) = state.net(&network_id) {
        if let Ok(mut ns) = lock(&net) {
            let still_mine = ns.sessions.get(&node_id).map(|s| s.id) == Some(session_id);
            if still_mine {
                ns.sessions.remove(&node_id);
                // A lost session is not proof of death; the lease expires on
                // its own if no new session or heartbeat follows. Marking it
                // offline immediately is what a clean close means, though,
                // and a member that is merely reconnecting is back before
                // anyone acts on it.
                ns.leases.offline(node_id);
                // A member that left should stop constraining everyone else,
                // and an exit that left is no exit until it reports again.
                ns.directory.reported_mtu.remove(&node_id);
                ns.directory.exit_readiness.remove(&node_id);
                state.publish(&mut ns);
                tracing::info!(network = %network_id, node_id, "control session closed");
            }
        }
    }
    writer.abort();
    result
}

/// Queue whatever brings `node`'s session from `have_gen` to current:
/// nothing, a delta chain, or a snapshot. Marks the session synced.
fn catch_up(ns: &mut NetState, node: NodeId, have_gen: u64) {
    let Some(s) = ns.sessions.get_mut(&node) else { return };
    match ns.directory.deltas_since(have_gen) {
        Some(chain) => {
            for d in chain {
                if s.tx.try_send(Push::Delta(d)).is_err() {
                    overflow(s);
                    return;
                }
            }
        }
        None => {
            if s.tx.try_send(Push::Snapshot(ns.directory.published.clone())).is_err() {
                overflow(s);
                return;
            }
        }
    }
    s.synced = true;
}

fn overflow(s: &mut Session) {
    tracing::warn!(node_id = s.node_id, "push queue full; closing session so it resyncs");
    s.synced = false;
    s.conn.close(CLOSE_OVERFLOW.into(), b"push queue overflow");
}

/// Push a delta to every synced session. A session whose queue is full
/// is closed: it reconnects and catches up from its generation.
pub fn broadcast_delta(ns: &mut NetState, d: Delta) {
    for s in ns.sessions.values_mut() {
        if !s.synced {
            continue;
        }
        if s.tx.try_send(Push::Delta(d.clone())).is_err() {
            overflow(s);
        }
    }
}

/// Token bucket for one session's heartbeats.
struct HeartbeatBudget {
    tokens: f64,
    at: Instant,
}

impl HeartbeatBudget {
    fn new() -> Self {
        HeartbeatBudget { tokens: HEARTBEAT_BURST, at: Instant::now() }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.at).as_secs_f64() * HEARTBEATS_PER_SEC).min(HEARTBEAT_BURST);
        self.at = now;
    }

    fn try_take(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Until the next heartbeat may be applied.
    fn wait(&self) -> Duration {
        let missing = (1.0 - self.tokens).max(0.0);
        Duration::from_secs_f64(missing / HEARTBEATS_PER_SEC).saturating_sub(self.at.elapsed())
    }
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    state: &Arc<AppState>,
    network_id: &str,
    node_id: NodeId,
    role: Role,
    fp: &str,
    mut envelopes: mpsc::Receiver<Result<Envelope, StreamError>>,
    rpc: &Arc<nqvpn_proto::rpc::RpcPeer>,
) -> Result<()> {
    let mut budget = HeartbeatBudget::new();
    // A heartbeat over budget, waiting for the next token. Heartbeats are
    // whole declarations, so a newer one simply replaces it.
    let mut pending: Option<Heartbeat> = None;
    loop {
        let next = tokio::select! {
            m = envelopes.recv() => m,
            _ = tokio::time::sleep(budget.wait()), if pending.is_some() => {
                if budget.try_take() {
                    if let Some(hb) = pending.take() {
                        on_heartbeat(state, network_id, node_id, role, hb)?;
                    }
                }
                continue;
            }
        };
        let env = match next {
            Some(Ok(e)) => e,
            Some(Err(StreamError::Closed)) | None => return Ok(()),
            Some(Err(e)) => return Err(e.into()),
        };
        if rpc.on_envelope(&env) {
            // A peer that floods requests without reading its replies
            // stops the RPC layer; end the session rather than hold it.
            if rpc.is_stopped() {
                return Err(anyhow!("rpc reply queue full"));
            }
            continue;
        }
        match env.kind {
            k if k == Kind::Heartbeat as u16 => {
                let hb: Heartbeat = parse(&env)?;
                if pending.is_none() && budget.try_take() {
                    on_heartbeat(state, network_id, node_id, role, hb)?;
                } else {
                    pending = Some(hb);
                }
            }
            k if k == Kind::ExitReadiness as u16 => {
                let er: nqvpn_proto::control::ExitReadiness = parse(&env)?;
                if role != Role::Relay {
                    anyhow::bail!("ExitReadiness from non-relay node {node_id}");
                }
                let net = net_of(state, network_id)?;
                let mut ns = lock(&net)?;
                // The default route is published for this exit only while
                // it reports ready, so a change is a view change.
                if ns.directory.exit_readiness.insert(node_id, er) != Some(er) {
                    tracing::info!(
                        network = %network_id, node_id, ip_forward = er.ip_forward, masquerade = er.masquerade,
                        "internet exit readiness reported"
                    );
                    state.publish_soon(network_id, &mut ns);
                }
            }
            k if k == Kind::Resync as u16 => {
                let r: Resync = parse(&env)?;
                let net = net_of(state, network_id)?;
                let mut ns = lock(&net)?;
                if !ns.in_grace(now_unix()) {
                    catch_up(&mut ns, node_id, r.have_gen);
                }
            }
            k if k == Kind::Refresh as u16 => {
                let r: Refresh = parse(&env)?;
                let (claims, net_id) = verify_credential(state, &r.credential, fp)?;
                // A Refresh extends this session; it never rebinds it.
                if net_id != network_id || claims.node_id != node_id || claims.role != role || claims.cert_fp != fp {
                    anyhow::bail!("Refresh identity mismatch for node {node_id}");
                }
                let net = net_of(state, network_id)?;
                let mut ns = lock(&net)?;
                if let Some(s) = ns.sessions.get_mut(&node_id) {
                    s.exp = claims.exp;
                    s.login_gen = claims.login_gen;
                }
                ns.leases.seen(node_id, now_ms());
            }
            other => tracing::debug!(kind = other, "ignoring unknown control message"),
        }
    }
}

/// Fold one heartbeat in. Only a change to something the view is derived
/// from (liveness, attachments, the network MTU) publishes, and then at
/// most once per debounce interval per network.
fn on_heartbeat(state: &Arc<AppState>, network_id: &str, node_id: NodeId, role: Role, hb: Heartbeat) -> Result<()> {
    let net = net_of(state, network_id)?;
    let mut ns = lock(&net)?;
    let now = now_unix();
    let changed = {
        let NetState { leases, registry, .. } = &mut *ns;
        let is_client = |n: NodeId| registry.members.get(&n).is_some_and(|r| r.role == Role::Client);
        leases.heartbeat(node_id, role, &hb, now_ms(), &is_client, registry.members.len())
    };
    let mut mtu_changed = false;
    if hb.usable_mtu > 0 {
        let q = quantize_mtu(hb.usable_mtu, ns.cfg.settings.mtu);
        mtu_changed = ns.directory.reported_mtu.insert(node_id, q) != Some(q);
    }
    if let Some(t) = hb.traffic {
        if role == Role::Relay {
            let NetState { directory, registry, .. } = &mut *ns;
            let known = |n: NodeId| registry.members.contains_key(&n);
            directory.record_traffic(node_id, t, now, &known, registry.members.len());
        }
    }
    if changed || mtu_changed {
        state.publish_soon(network_id, &mut ns);
    }
    if ns.in_grace(now) {
        return Ok(());
    }
    let (cur, digest) = (ns.directory.gen, ns.directory.published_digest);
    if hb.gen != cur {
        // Behind (a lost push, or a fresh coordinator): catch it up now
        // rather than at its next reconnect.
        catch_up(&mut ns, node_id, hb.gen);
    } else if hb.digest != digest {
        tracing::error!(
            network = %network_id, node_id, gen = cur, theirs = hb.digest, ours = digest,
            "member holds a different view at the same generation — resyncing (this is a bug)"
        );
        catch_up(&mut ns, node_id, 0);
    }
    Ok(())
}

/// Verify a credential offline and confirm the TLS possession proof.
fn verify_credential(state: &AppState, token: &str, presented_fp: &str) -> Result<(Claims, String)> {
    let unverified_net = credential::peek_network(token).ok_or_else(|| anyhow!("malformed credential"))?;
    let net = state.net(&unverified_net).ok_or_else(|| anyhow!("unknown network {unverified_net}"))?;
    let keys = state.keyring.verifying_keys();
    let (uuid, rec) = {
        let ns = lock(&net)?;
        let id = credential::peek_node_id(token).unwrap_or(0);
        (ns.registry.network_uuid.to_string(), ns.registry.members.get(&id).cloned())
    };
    let claims = credential::verify(
        token,
        &keys,
        &Expected { iss: ISS, network_id: &unverified_net, network_uuid: &uuid },
        now_unix(),
    )
    .map_err(|e| anyhow!("credential rejected: {e}"))?;
    let Some(rec) = rec else { anyhow::bail!("node {} is unknown", claims.node_id) };
    // The record was picked by the *unverified* node id; it must be the
    // verified one's.
    if rec.node_id != claims.node_id {
        anyhow::bail!("credential node id {} does not match its record {}", claims.node_id, rec.node_id);
    }
    if rec.disabled {
        anyhow::bail!("node {} is disabled", claims.node_id);
    }
    if claims.login_gen < rec.login_gen {
        let from = rec.replaced_from.clone().unwrap_or_else(|| "an unknown address".into());
        return Err(Replaced(format!(
            "node {} ({}) was replaced by a newer join from {from} (credential login_gen {} < {})",
            claims.node_id, claims.sub, claims.login_gen, rec.login_gen
        ))
        .into());
    }
    if claims.cert_fp != presented_fp {
        anyhow::bail!("cert_fp mismatch: credential says {}, TLS presented {presented_fp}", claims.cert_fp);
    }
    Ok((claims, unverified_net))
}

/// Liveness sweep (§7): expire silent members, withdraw their routes,
/// close sessions whose credential expired, and re-evaluate anything that
/// falls due purely by time (hold-down).
pub async fn liveness_sweep(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        let now = now_unix();
        for (id, net) in state.nets() {
            let Some(mut ns) = lock_for_sweep(&id, &net) else { continue };
            ns.directory.prune_traffic(now);
            let window = ns.cfg.settings.liveness_window_secs();
            let gone = ns.leases.expire(now_ms(), window * 1000);
            for node in gone {
                tracing::info!(network = %ns.cfg.network_id, node_id = node, "no heartbeat for {window}s; offline");
                ns.directory.reported_mtu.remove(&node);
                if let Some(s) = ns.sessions.remove(&node) {
                    let _ = s.tx.try_send(Push::Close("keepalive timeout".into()));
                    s.conn.close(CLOSE_TIMEOUT.into(), b"keepalive timeout");
                }
            }
            let expired: Vec<NodeId> =
                ns.sessions.values().filter(|s| s.exp <= now).map(|s| s.node_id).collect();
            for node in expired {
                tracing::info!(network = %ns.cfg.network_id, node_id = node, "credential expired without Refresh; closing");
                if let Some(s) = ns.sessions.remove(&node) {
                    let _ = s.tx.try_send(Push::Close("credential expired".into()));
                    s.conn.close(CLOSE_EXPIRED.into(), b"credential expired");
                }
            }
            state.publish(&mut ns);
        }
    }
}
