//! Accepting members, dialing the relay mesh, and the forwarding loop.
//!
//! One QUIC socket serves both: what a connection *is* gets decided by
//! the role in the credential it presents at `PeerHello`.

use anyhow::{anyhow, Context, Result};
use nqvpn_proto::control::{Hello, HelloAck};
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::frame::{Probe, RoutedHeader, T_PROBE};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{client_config, peer_fingerprint};
use nqvpn_proto::transport::PacketChannel;
use nqvpn_proto::stream::{parse, read_envelope, write_msg};
use nqvpn_proto::types::{NodeId, Role};
use std::net::ToSocketAddrs;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::coordlink::verify_peer;
use crate::state::RelayState;
use crate::tables::{Origin, Route, TokenBucket};

/// Accept loop for member and mesh connections.
pub async fn accept_loop(state: Arc<RelayState>, endpoint: quinn::Endpoint, max_mbps: u32) {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    if let Err(e) = handle_incoming(state, conn, max_mbps).await {
                        tracing::debug!("session ended: {e:#}");
                    }
                }
                Err(e) => tracing::debug!("handshake failed: {e}"),
            }
        });
    }
}

async fn handle_incoming(
    state: Arc<RelayState>,
    conn: quinn::Connection,
    max_mbps: u32,
) -> Result<()> {
    let fp = peer_fingerprint(&conn).ok_or_else(|| anyhow!("peer presented no certificate"))?;
    let (mut tx, mut rx) = conn.accept_bi().await.context("accepting control stream")?;
    let env = read_envelope(&mut rx).await?;
    // Data sessions open with an enveloped Hello too, so this one check
    // covers the framing as well as the control payloads — it is exactly
    // the incompatibility that previously desynced silently.
    if let Err(e) = nqvpn_proto::envelope::check_version(env.major, env.minor) {
        tracing::warn!("refusing peer session: {e}");
        conn.close(3u32.into(), e.to_string().as_bytes());
        anyhow::bail!("{e}");
    }
    anyhow::ensure!(env.kind == Kind::Hello as u16, "expected Hello, got {}", env.kind);
    let hello: Hello = parse(&env)?;

    let claims = verify_peer(&state, &hello.credential, &fp, &state.network_id)?;
    let peer = claims.node_id;
    anyhow::ensure!(peer != state.my_node_id, "a member may not connect to itself");

    write_msg(&mut tx, Kind::HelloAck, &HelloAck { revision: state.membership_revision() })
        .await?;

    let chan = PacketChannel::start_lanes(conn.clone(), state.mode(), state.lanes());
    let (origin, session_id) = match claims.role {
        Role::Relay => {
            tracing::info!(peer, mode = chan.mode().as_str(), "mesh session accepted");
            (Origin::Relay(peer), state.add_mesh(peer, chan.clone()))
        }
        Role::Client => {
            tracing::info!(peer, mode = chan.mode().as_str(), "client attached");
            (Origin::Client(peer), state.add_client(peer, chan.clone()))
        }
    };

    // Forward packets until the connection dies.
    let result = forward_loop(&state, &chan, origin, max_mbps).await;

    match claims.role {
        Role::Relay => {
            state.remove_mesh(peer, session_id);
            tracing::info!(peer, "mesh session closed");
        }
        Role::Client => {
            state.remove_client(peer, session_id);
            tracing::info!(peer, "client detached");
        }
    }
    result
}

/// The relay data plane: parse header, decide, send. No unseal, no
/// allocation beyond what quinn hands us, no lock held across a send.
pub async fn forward_loop(
    state: &RelayState,
    chan: &PacketChannel,
    origin: Origin,
    max_mbps: u32,
) -> Result<()> {
    // Caps apply to attached clients only; mesh links are never capped.
    let mut bucket = match origin {
        Origin::Client(_) => TokenBucket::new(max_mbps),
        Origin::Relay(_) => None,
    };
    loop {
        let Some((datagram, lane)) = chan.recv().await else {
            return Err(anyhow!("packet channel closed"));
        };
        // Account for everything a mesh peer sends us, including frames
        // we go on to drop: the matrix compares this against the peer's
        // own tx, and silently omitting drops would hide the gap.
        if let Origin::Relay(peer) = origin {
            state.note_mesh_rx(peer, datagram.len() as u64);
        }
        if datagram.is_empty() {
            state.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // Hop-local probes never enter the forwarding path (§5).
        if datagram[0] == T_PROBE {
            if let Some(p) = Probe::parse(&datagram) {
                let _ = chan.send(p.into_reply().encode().into());
            } else {
                state.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            }
            continue;
        }
        let Some(h) = RoutedHeader::parse(&datagram) else {
            state.counters.drop_malformed.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if let Some(b) = bucket.as_mut() {
            if !b.allow(datagram.len()) {
                state.counters.drop_rate_limited.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        }
        let bytes = datagram.len() as u64;
        let route = state.route(origin, h.src_id, h.dst_id);
        match route {
            Route::Local(_) | Route::Mesh(_) => {
                if state.send(&route, datagram, lane) {
                    // A local hand-off from a locally attached client is
                    // the diagonal; one from the mesh is the far end of
                    // someone else's link and is already counted there.
                    if matches!((&route, origin), (Route::Local(_), Origin::Client(_))) {
                        state.note_local_switch(bytes);
                    }
                }
            }
            // Addressed to us: terminate it at our own TUN if we play
            // the endpoint role, otherwise it has nowhere to go.
            Route::Me => match state.endpoint() {
                Some(ep) => {
                    state.note_terminated(bytes);
                    ep.deliver(&datagram)
                }
                None => {
                    tracing::debug!("frame addressed to a relay with no endpoint role; dropped");
                }
            },
            Route::Drop(_) => {}
        }
    }
}

/// Dial every relay we should hold a mesh session with. The lower node
/// id dials, so exactly one side initiates each link (§6).
pub async fn mesh_dialer(
    state: Arc<RelayState>,
    id: TlsIdentity,
    peers: Vec<nqvpn_proto::api::RelayEntry>,
    keepalive: u64,
) {
    for entry in peers {
        if entry.relay_id == state.my_node_id || state.my_node_id > entry.relay_id {
            // Higher id waits to be dialed.
            tracing::info!(
                peer = %entry.name,
                peer_id = entry.relay_id,
                me = state.my_node_id,
                "not dialing (peer dials us, or it is me)"
            );
            continue;
        }
        tracing::info!(peer = %entry.name, peer_id = entry.relay_id, addr = %entry.addr, "starting mesh dialer");
        let state = state.clone();
        let id = id.clone();
        tokio::spawn(async move {
            let mut delay = Duration::from_secs(1);
            loop {
                if state.has_mesh(entry.relay_id) {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                // Read the credential fresh each attempt: renewal must
                // reach dialers that have been retrying for a while.
                let credential = state.credential();
                match dial_relay(&state, &id, &credential, &entry, keepalive).await {
                    Ok(()) => delay = Duration::from_secs(1),
                    Err(e) => {
                        tracing::warn!(peer = %entry.name, addr = %entry.addr, "mesh dial failed: {e:#}");
                        tokio::time::sleep(delay).await;
                        delay = (delay * 2).min(Duration::from_secs(30));
                    }
                }
            }
        });
    }
}

async fn dial_relay(
    state: &Arc<RelayState>,
    id: &TlsIdentity,
    credential: &str,
    entry: &nqvpn_proto::api::RelayEntry,
    keepalive: u64,
) -> Result<()> {
    let addr = entry
        .addr
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", entry.addr))?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", entry.addr))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    // The peer relay's certificate is pinned by the coordinator.
    ep.set_default_client_config(
        client_config(id, Some(entry.cert_fp.clone()), keepalive)
            .map_err(|e| anyhow!("tls: {e}"))?,
    );
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("relay");
    let conn = ep.connect(addr, host)?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string() }).await?;
    let ack = read_envelope(&mut rx).await?;
    anyhow::ensure!(ack.kind == Kind::HelloAck as u16, "peer relay refused our credential");

    tracing::info!(peer = %entry.name, id = entry.relay_id, "mesh link up (dialed)");
    let chan = PacketChannel::start_lanes(conn.clone(), state.mode(), state.lanes());
    let session_id = state.add_mesh(entry.relay_id, chan.clone());
    let r = forward_loop(state, &chan, Origin::Relay(entry.relay_id), 0).await;
    state.remove_mesh(entry.relay_id, session_id);
    tracing::info!(peer = %entry.name, "mesh link down");
    r.map(|_| ())
}

/// Helper for `NodeId` formatting in logs.
pub fn fmt_node(id: NodeId) -> String {
    format!("#{id}")
}
