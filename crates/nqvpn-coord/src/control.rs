//! Coordinator QUIC control plane (§3.2): the persistent two-way push
//! channel every member holds. Mutual TLS + credential verification at
//! `Hello`, then revisioned membership snapshots and deltas downstream,
//! `Attach`/`Refresh`/`Ping` upstream.
//!
//! No polling anywhere: the coordinator writes deltas to live sessions
//! the moment state changes.

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

use crate::state::{now_unix, AppState, ISS};

/// Peers per membership snapshot chunk (§3.2: chunked well below the
/// 1 MiB envelope cap).
const SNAPSHOT_CHUNK: usize = 256;
/// Bounded per-session push queue: a stalled member must not grow the
/// coordinator's memory. Overflow closes that session; it re-syncs with
/// a fresh snapshot on reconnect.
const PUSH_QUEUE: usize = 256;

static SESSION_SEQ: AtomicU64 = AtomicU64::new(1);

/// What a session's writer task can be asked to send.
#[derive(Debug, Clone)]
pub enum Push {
    Membership(MembershipDelta),
    Relays(RelayList),
    Mtu(NetworkMtu),
    Attachment(AttachmentDelta),
    Keys(KeySet),
    /// An already-encoded envelope, written verbatim. The RPC layer
    /// produces these; routing them through this writer keeps a single
    /// owner of the send stream.
    Raw(Vec<u8>),
    Close(String),
}

pub struct Session {
    pub id: u64,
    pub name: String,
    pub node_id: NodeId,
    pub role: Role,
    pub tx: mpsc::Sender<Push>,
    /// Held so the liveness sweep can actually tear the session down —
    /// stopping the writer alone would leave the reader (and therefore
    /// the member's "online" state) hanging until the QUIC idle timeout.
    pub conn: quinn::Connection,
}

/// Application close codes.
const CLOSE_TIMEOUT: u32 = 1;
const CLOSE_SUPERSEDED: u32 = 2;
/// Closed because the peer speaks a different protocol version. Sent
/// with a readable reason so the operator sees both versions rather than
/// an unexplained disconnect.
const CLOSE_VERSION: u32 = 3;

/// Bind the control port. Split from `serve` so tests (and future
/// socket-activation) can learn the bound address first.
pub fn bind(addr: SocketAddr, id: &TlsIdentity) -> Result<quinn::Endpoint> {
    // A conservative keepalive: per-network settings drive liveness, this
    // only keeps NAT bindings and the QUIC connection itself alive.
    let cfg = server_config(id, 15).map_err(|e| anyhow!("quic server config: {e}"))?;
    let endpoint = quinn::Endpoint::server(cfg, addr).context("binding QUIC control port")?;
    tracing::info!(
        addr = %endpoint.local_addr()?, fingerprint = %id.fingerprint(),
        "QUIC control listening"
    );
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
    let fp = peer_fingerprint(&conn)
        .ok_or_else(|| anyhow!("peer presented no certificate"))?;

    // One bidirectional control stream per connection.
    let (mut tx, mut rx) = conn.accept_bi().await.context("accepting control stream")?;

    let env = read_envelope(&mut rx).await.context("reading Hello")?;
    // One check per session, at the first message. A mismatch means a
    // half-finished rollout, and saying so plainly beats running two
    // protocols against each other and desyncing somewhere less obvious.
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
    let name = claims.sub.clone();
    let node_id = claims.node_id;
    let role = claims.role;
    let session_id = SESSION_SEQ.fetch_add(1, Ordering::Relaxed);

    tracing::info!(
        %remote, network = %network_id, member = %name, node_id, %role,
        "control session authenticated"
    );

    let (push_tx, mut push_rx) = mpsc::channel::<Push>(PUSH_QUEUE);

    // RPC output is forwarded into the same push queue, so the writer
    // task remains the only thing that touches the send stream.
    let (rpc_out, mut rpc_rx) = mpsc::channel::<Vec<u8>>(PUSH_QUEUE);
    // The handler is bound to this session, so a verb never has to ask
    // who is calling: mutual TLS and the verified cert_fp already
    // established that at Hello.
    let rpc = nqvpn_proto::rpc::RpcPeer::new(
        rpc_out,
        std::sync::Arc::new(crate::verbs::SessionVerbs {
            state: state.clone(),
            network_id: network_id.clone(),
            member: name.clone(),
        }),
    );
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

    // Register the session, mark online, publish the resulting delta.
    let (revision, snapshot, attach_snapshot, superseded, relay_list, network_mtu) = {
        let net = state.networks.get(&network_id).expect("verified above");
        let mut ns = net.lock().unwrap();
        let now = now_unix();

        let superseded = ns.sessions.insert(
            name.clone(),
            Session {
                id: session_id,
                name: name.clone(),
                node_id,
                role,
                tx: push_tx.clone(),
                conn: conn.clone(),
            },
        );

        ns.directory.set_online(&name, true, now);
        let delta = ns.refresh_directory(now);
        let chunks = ns.directory.snapshot_chunks(SNAPSHOT_CHUNK);
        let rev = ns.directory.revision;
        let attach = (role == Role::Relay).then(|| AttachmentSnapshot {
            snapshot_rev: ns.directory.attach_revision,
            entries: ns.directory.attachment_entries(),
        });
        // The joining session must NOT receive this delta: its snapshot
        // already contains the change, and a delta whose base predates
        // the snapshot would look like a revision gap.
        if let Some(d) = delta {
            broadcast_except(&ns, Push::Membership(d), &name);
        }
        let relays = RelayList { relays: relay_endpoints(&ns) };
        let mtu = ns.directory.network_mtu(ns.cfg.settings.mtu);
        (rev, chunks, attach, superseded, relays, mtu)
    };
    if let Some(old) = superseded {
        let _ = old.tx.try_send(Push::Close("superseded".into()));
        old.conn.close(CLOSE_SUPERSEDED.into(), b"superseded by a newer session");
    }

    // A relay that advertises an address nobody can dial joins fine and
    // then silently fails to mesh (§3.2). Probe it now that its
    // listener is necessarily up, and record the verdict for status.
    if role == Role::Relay {
        let advertised = {
            let net = state.networks.get(&network_id).expect("verified above");
            let ns = net.lock().unwrap();
            ns.cfg.relays.get(&name).and_then(|m| m.relay_addr.clone())
        };
        if let Some(addr) = advertised {
            let (st, netid, member) = (state.clone(), network_id.clone(), name.clone());
            tokio::spawn(async move {
                let verdict =
                    crate::reach::probe(&addr, std::time::Duration::from_secs(5)).await;
                if verdict == crate::reach::Reachability::Unreachable {
                    tracing::warn!(
                        network = %netid, relay = %member, %addr,
                        "advertised relay address is NOT reachable from the coordinator —                          other relays will fail to mesh with it (check the firewall and                          that relay_addr is correct)"
                    );
                } else {
                    tracing::info!(relay = %member, %addr, "advertised address reachable");
                }
                if let Some(net) = st.networks.get(&netid) {
                    net.lock().unwrap().directory.reachability.insert(member, verdict);
                }
            });
        }
    }

    // Writer task: HelloAck, snapshot, then pushes forever.
    let keys = state.keyring.key_infos();
    let writer = tokio::spawn(async move {
        write_msg(&mut tx, Kind::HelloAck, &HelloAck { revision }).await?;
        write_msg(&mut tx, Kind::KeySet, &KeySet { keys }).await?;
        let n = snapshot.len() as u32;
        for (i, peers) in snapshot.into_iter().enumerate() {
            write_msg(
                &mut tx,
                Kind::MembershipSnapshot,
                &MembershipSnapshot {
                    snapshot_rev: revision,
                    chunk_i: i as u32,
                    chunk_n: n,
                    peers,
                },
            )
            .await?;
        }
        if let Some(a) = attach_snapshot {
            write_msg(&mut tx, Kind::AttachmentSnapshot, &a).await?;
        }
        write_msg(&mut tx, Kind::RelayList, &relay_list).await?;
        write_msg(&mut tx, Kind::NetworkMtu, &network_mtu).await?;
        while let Some(push) = push_rx.recv().await {
            match push {
                Push::Membership(d) => write_msg(&mut tx, Kind::MembershipDelta, &d).await?,
                Push::Attachment(d) => write_msg(&mut tx, Kind::AttachmentDelta, &d).await?,
                Push::Keys(k) => write_msg(&mut tx, Kind::KeySet, &k).await?,
                Push::Relays(r) => write_msg(&mut tx, Kind::RelayList, &r).await?,
                Push::Mtu(m) => write_msg(&mut tx, Kind::NetworkMtu, &m).await?,
                Push::Raw(bytes) => write_bytes(&mut tx, &bytes).await?,
                Push::Close(reason) => {
                    tracing::debug!("closing session: {reason}");
                    break;
                }
            }
        }
        Ok::<_, StreamError>(())
    });

    // Reader loop: upstream messages until the member goes away.
    let result =
        reader_loop(&state, &network_id, &name, node_id, role, session_id, &fp, &mut rx, &rpc)
            .await;
    // Nothing can answer an outstanding call once the session is over.
    rpc.close();

    // Teardown: drop the session (unless already superseded), mark
    // offline, withdraw its routes, and publish the delta.
    {
        let net = state.networks.get(&network_id).expect("verified above");
        let mut ns = net.lock().unwrap();
        let still_mine = ns.sessions.get(&name).map(|s| s.id) == Some(session_id);
        if still_mine {
            ns.sessions.remove(&name);
            let now = now_unix();
            ns.directory.set_online(&name, false, now);

            // A relay going away detaches everyone it carried.
            let mut attach_changed = Vec::new();
            if role == Role::Relay {
                let orphans: Vec<NodeId> = ns
                    .directory
                    .attachments
                    .iter()
                    .filter(|(_, r)| **r == node_id)
                    .map(|(n, _)| *n)
                    .collect();
                for o in orphans {
                    if ns.directory.set_attachment(o, None) {
                        attach_changed.push(o);
                    }
                }
            }
            if ns.directory.set_attachment(node_id, None) {
                attach_changed.push(node_id);
            }
            if !attach_changed.is_empty() {
                let rev = ns.directory.attach_revision;
                broadcast_relays(
                    &ns,
                    Push::Attachment(AttachmentDelta {
                        base_rev: rev.saturating_sub(1),
                        new_rev: rev,
                        changed: vec![],
                        detached: attach_changed,
                    }),
                );
            }
            if let Some(d) = ns.refresh_directory(now) {
                broadcast(&ns, Push::Membership(d));
            }
            // A member that left should stop constraining everyone else.
            if ns.directory.reported_mtu.remove(&name).is_some() {
                publish_mtu_if_changed(&mut ns);
            }
            tracing::info!(network = %network_id, member = %name, "control session closed");
        }
    }
    writer.abort();
    result
}

#[allow(clippy::too_many_arguments)]
async fn reader_loop(
    state: &Arc<AppState>,
    network_id: &str,
    name: &str,
    node_id: NodeId,
    role: Role,
    session_id: u64,
    fp: &str,
    rx: &mut quinn::RecvStream,
    rpc: &std::sync::Arc<nqvpn_proto::rpc::RpcPeer>,
) -> Result<()> {
    loop {
        let env = match read_envelope(rx).await {
            Ok(e) => e,
            Err(StreamError::Closed) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // RPC first; it answers what it owns and leaves pushes alone.
        if rpc.on_envelope(&env) {
            continue;
        }
        match env.kind {
            k if k == Kind::Ping as u16 => {
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                ns.last_seen.insert(name.to_string(), now_unix());
            }
            k if k == Kind::Attach as u16 => {
                if role != Role::Relay {
                    anyhow::bail!("only relays may send Attach");
                }
                let a: Attach = parse(&env)?;
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                let changed = ns
                    .directory
                    .set_attachment(a.node_id, a.attached.then_some(node_id));
                if changed {
                    let rev = ns.directory.attach_revision;
                    let (changed_v, detached) = if a.attached {
                        (vec![AttachmentEntry { node_id: a.node_id, relay_id: node_id }], vec![])
                    } else {
                        (vec![], vec![a.node_id])
                    };
                    broadcast_relays(
                        &ns,
                        Push::Attachment(AttachmentDelta {
                            base_rev: rev.saturating_sub(1),
                            new_rev: rev,
                            changed: changed_v,
                            detached,
                        }),
                    );
                }
            }
            k if k == Kind::TrafficReport as u16 => {
                if role != Role::Relay {
                    anyhow::bail!("only relays may send TrafficReport");
                }
                let r: TrafficReport = parse(&env)?;
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                ns.directory.record_traffic(name, r, now_unix());
            }
            k if k == Kind::MtuReport as u16 => {
                let r: MtuReport = parse(&env)?;
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                let changed = ns
                    .directory
                    .reported_mtu
                    .insert(name.to_string(), r.usable_mtu)
                    != Some(r.usable_mtu);
                if changed {
                    publish_mtu_if_changed(&mut ns);
                }
            }
            k if k == Kind::Refresh as u16 => {
                let r: Refresh = parse(&env)?;
                let (claims, net_id) = verify_credential(state, &r.credential, fp)?;
                // Identity continuity (§3.3): a Refresh may update
                // authorization, never who the session belongs to.
                if net_id != network_id
                    || claims.sub != name
                    || claims.node_id != node_id
                    || claims.role != role
                    || claims.cert_fp != fp
                {
                    anyhow::bail!(
                        "Refresh identity mismatch: session is {name}/{node_id}, \
                         credential is {}/{}",
                        claims.sub,
                        claims.node_id
                    );
                }
                let net = state.networks.get(network_id).expect("verified");
                let mut ns = net.lock().unwrap();
                ns.last_seen.insert(name.to_string(), now_unix());
                tracing::debug!(member = %name, session_id, "credential refreshed");
            }
            other => {
                // Unknown kinds are skipped, not fatal (§5 rolling upgrades).
                tracing::debug!(kind = other, "ignoring unknown control message");
            }
        }
    }
}

/// Verify a credential offline and confirm the TLS possession proof.
fn verify_credential(
    state: &AppState,
    token: &str,
    presented_fp: &str,
) -> Result<(Claims, String)> {
    // The network is named inside the credential; find it, then verify
    // against that network's uuid.
    let unverified_net = credential::peek_network(token)
        .ok_or_else(|| anyhow!("malformed credential"))?;
    let net = state
        .networks
        .get(&unverified_net)
        .ok_or_else(|| anyhow!("unknown network {unverified_net}"))?;
    let (uuid, disabled_or_missing) = {
        let ns = net.lock().unwrap();
        let uuid = ns.registry.network_uuid.to_string();
        let sub = credential::peek_subject(token).unwrap_or_default();
        let bad = ns.registry.members.get(&sub).map(|m| m.disabled).unwrap_or(true);
        (uuid, bad)
    };
    let keys = state.keyring.verifying_keys();
    let claims = credential::verify(
        token,
        &keys,
        &Expected { iss: ISS, network_id: &unverified_net, network_uuid: &uuid },
        now_unix(),
    )
    .map_err(|e| anyhow!("credential rejected: {e}"))?;

    if disabled_or_missing {
        anyhow::bail!("member {} is disabled or unknown", claims.sub);
    }
    if claims.cert_fp != presented_fp {
        anyhow::bail!(
            "cert_fp mismatch: credential says {}, TLS presented {presented_fp}",
            claims.cert_fp
        );
    }
    Ok((claims, unverified_net))
}

/// Fan out to every live session in the network.
pub fn broadcast(ns: &crate::state::NetState, push: Push) {
    for s in ns.sessions.values() {
        if s.tx.try_send(push.clone()).is_err() {
            tracing::warn!(member = %s.name, "push queue full or closed; session will resync");
        }
    }
}

/// Fan out to every live session except one (used when that session is
/// about to receive an equivalent snapshot).
pub fn broadcast_except(ns: &crate::state::NetState, push: Push, skip: &str) {
    for s in ns.sessions.values().filter(|s| s.name != skip) {
        let _ = s.tx.try_send(push.clone());
    }
}

/// The dialable relay fleet: relays that have joined at least once, so
/// their address and certificate pin are known.
pub fn relay_endpoints(ns: &crate::state::NetState) -> Vec<RelayEndpoint> {
    let mut out = Vec::new();
    for (name, m) in &ns.cfg.relays {
        if let (Some(rec), Some(addr)) = (ns.registry.members.get(name), m.relay_addr.clone()) {
            if let Some(fp) = &rec.cert_fp {
                out.push(RelayEndpoint {
                    relay_id: rec.node_id,
                    name: name.clone(),
                    addr,
                    cert_fp: fp.clone(),
                });
            }
        }
    }
    out.sort_by_key(|r| r.relay_id);
    out
}

/// Publish the relay fleet if it changed since the last push.
pub fn publish_relays_if_changed(ns: &mut crate::state::NetState) {
    let now = relay_endpoints(ns);
    if ns.published_relays.as_ref() == Some(&now) {
        return;
    }
    ns.published_relays = Some(now.clone());
    broadcast(ns, Push::Relays(RelayList { relays: now }));
}

/// Publish the network-wide tunnel MTU if the minimum moved. Members
/// that cannot carry it would otherwise black-hole large packets at a
/// hop nobody is watching (§8).
pub fn publish_mtu_if_changed(ns: &mut crate::state::NetState) {
    let now = ns.directory.network_mtu(ns.cfg.settings.mtu);
    if ns.directory.published_mtu.as_ref() == Some(&now) {
        return;
    }
    tracing::info!(
        mtu = now.mtu,
        limited_by = %now.limited_by,
        "network tunnel MTU updated"
    );
    ns.directory.published_mtu = Some(now.clone());
    broadcast(ns, Push::Mtu(now));
}

/// Fan out to relay sessions only (attachment registry is relay-only).
pub fn broadcast_relays(ns: &crate::state::NetState, push: Push) {
    for s in ns.sessions.values().filter(|s| s.role == Role::Relay) {
        let _ = s.tx.try_send(push.clone());
    }
}

/// Liveness sweep (§7): mark members offline after `offline_after`
/// missed keepalives and withdraw their routes.
pub async fn liveness_sweep(state: Arc<AppState>) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tick.tick().await;
        let now = now_unix();
        for net in state.networks.values() {
            let mut ns = net.lock().unwrap();

            // A relay that stops reporting leaves its last sample behind.
            // Pruning here as well as on write means a fleet that goes
            // quiet clears out instead of freezing at its final state.
            ns.directory.prune_traffic(now);

            // Route ownership can become due purely by the passage of
            // time (a returning registrant's hold-down expiring, §2), so
            // re-evaluate on the tick as well as on events. recompute()
            // is a no-op unless something actually changed.
            if let Some(d) = ns.refresh_directory(now) {
                broadcast(&ns, Push::Membership(d));
            }
            let window =
                ns.cfg.settings.keepalive_secs as u64 * ns.cfg.settings.offline_after as u64;
            let stale: Vec<String> = ns
                .sessions
                .values()
                .filter(|s| {
                    let last = ns.last_seen.get(&s.name).copied().unwrap_or(0);
                    last != 0 && now.saturating_sub(last) > window
                })
                .map(|s| s.name.clone())
                .collect();
            for name in stale {
                tracing::info!(member = %name, "liveness timeout; closing session");
                if let Some(s) = ns.sessions.get(&name) {
                    let _ = s.tx.try_send(Push::Close("keepalive timeout".into()));
                    // Closing the connection is what makes the reader
                    // return and the teardown (offline + route
                    // withdrawal) actually run.
                    s.conn.close(CLOSE_TIMEOUT.into(), b"keepalive timeout");
                }
            }
        }
    }
}
