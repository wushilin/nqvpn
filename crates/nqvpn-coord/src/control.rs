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
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{peer_fingerprint, server_config};
use nqvpn_proto::stream::{parse, read_envelope, write_bytes, write_msg, StreamError};
use nqvpn_proto::types::{NodeId, Role};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::state::{now_ms, now_unix, AppState, NetState, ISS};

/// Bounded per-session push queue: a stalled member must not grow the
/// coordinator's memory. Overflow closes that session; it reconnects and
/// catches up from its generation.
const PUSH_QUEUE: usize = 256;

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
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_conn(state, conn).await {
                        tracing::debug!("control session ended: {e:#}");
                    }
                }
                Err(e) => tracing::debug!("handshake failed: {e}"),
            }
        });
    }
    Ok(())
}

async fn handle_conn(state: Arc<AppState>, conn: quinn::Connection) -> Result<()> {
    let remote = conn.remote_address();
    let fp = peer_fingerprint(&conn).ok_or_else(|| anyhow!("peer presented no certificate"))?;
    let (mut tx, mut rx) = conn.accept_bi().await.context("accepting control stream")?;

    // A peer that connects and never says Hello must not hold a task.
    let env = tokio::time::timeout(std::time::Duration::from_secs(10), read_envelope(&mut rx))
        .await
        .context("waiting for Hello")??;
    if let Err(e) = nqvpn_proto::envelope::check_version(env.major, env.minor) {
        tracing::warn!(%remote, "refusing session: {e}");
        conn.close(CLOSE_VERSION.into(), e.to_string().as_bytes());
        anyhow::bail!("{e}");
    }
    if env.kind != Kind::Hello as u16 {
        anyhow::bail!("first message must be Hello, got kind {}", env.kind);
    }
    let hello: Hello = parse(&env)?;

    let (claims, network_id) = verify_credential(&state, &hello.credential, &fp)?;
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
        let net = state.networks.get(&network_id).expect("verified above");
        let mut ns = net.lock().unwrap();
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

    let result = reader_loop(&state, &network_id, node_id, role, &fp, &mut rx, &rpc).await;
    rpc.close();

    // Teardown: drop the session (unless already superseded) and let the
    // lease decide what that means.
    {
        let net = state.networks.get(&network_id).expect("verified above");
        let mut ns = net.lock().unwrap();
        let still_mine = ns.sessions.get(&node_id).map(|s| s.id) == Some(session_id);
        if still_mine {
            ns.sessions.remove(&node_id);
            // A lost session is not proof of death; the lease expires on
            // its own if no new session or heartbeat follows. Marking it
            // offline immediately is what a clean close means, though,
            // and a member that is merely reconnecting is back before
            // anyone acts on it.
            ns.leases.offline(node_id);
            // A member that left should stop constraining everyone else.
            ns.directory.reported_mtu.remove(&node_id);
            state.publish(&mut ns);
            tracing::info!(network = %network_id, node_id, "control session closed");
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

#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    state: &Arc<AppState>,
    network_id: &str,
    node_id: NodeId,
    role: Role,
    fp: &str,
    rx: &mut quinn::RecvStream,
    rpc: &Arc<nqvpn_proto::rpc::RpcPeer>,
) -> Result<()> {
    loop {
        let env = match read_envelope(rx).await {
            Ok(e) => e,
            Err(StreamError::Closed) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if rpc.on_envelope(&env) {
            continue;
        }
        match env.kind {
            k if k == Kind::Heartbeat as u16 => {
                let hb: Heartbeat = parse(&env)?;
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                let now = now_unix();
                ns.leases.heartbeat(node_id, role, &hb, now_ms());
                if hb.usable_mtu > 0 {
                    ns.directory.reported_mtu.insert(node_id, hb.usable_mtu);
                }
                if let Some(t) = &hb.traffic {
                    if role == Role::Relay {
                        ns.directory.record_traffic(node_id, t.clone(), now);
                    }
                }
                state.publish(&mut ns);
                if ns.in_grace(now) {
                    continue;
                }
                let (cur, digest) = (ns.directory.gen, ns.directory.published_digest);
                if hb.gen != cur {
                    // Behind (a lost push, or a fresh coordinator): catch
                    // it up now rather than at its next reconnect.
                    catch_up(&mut ns, node_id, hb.gen);
                } else if hb.digest != digest {
                    tracing::error!(
                        network = %network_id, node_id, gen = cur, theirs = hb.digest, ours = digest,
                        "member holds a different view at the same generation — resyncing (this is a bug)"
                    );
                    catch_up(&mut ns, node_id, 0);
                }
            }
            k if k == Kind::Resync as u16 => {
                let r: Resync = parse(&env)?;
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
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
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
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

/// Verify a credential offline and confirm the TLS possession proof.
fn verify_credential(state: &AppState, token: &str, presented_fp: &str) -> Result<(Claims, String)> {
    let unverified_net = credential::peek_network(token).ok_or_else(|| anyhow!("malformed credential"))?;
    let net = state
        .networks
        .get(&unverified_net)
        .ok_or_else(|| anyhow!("unknown network {unverified_net}"))?;
    let keys = state.keyring.verifying_keys();
    let (uuid, rec) = {
        let ns = net.lock().unwrap();
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
    if rec.disabled {
        anyhow::bail!("node {} is disabled", claims.node_id);
    }
    if claims.login_gen < rec.login_gen {
        anyhow::bail!(
            "node {} was replaced by a newer join (credential login_gen {} < {})",
            claims.node_id,
            claims.login_gen,
            rec.login_gen
        );
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
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        let now = now_unix();
        for net in state.networks.values() {
            let mut ns = net.lock().unwrap();
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
