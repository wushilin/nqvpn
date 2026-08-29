//! The relay's link to the coordinator (§3.2 member side): join, hold a
//! control session, consume membership + attachment pushes, report
//! `Attach`, renew the credential, and reconnect with backoff.

use anyhow::{anyhow, Context, Result};
use nqvpn_proto::api::{JoinRequest, JoinResponse};
use nqvpn_proto::control::*;
use nqvpn_proto::credential::{self, Expected};
use nqvpn_proto::envelope::{decode_payload, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::joinapi;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::stream::{read_envelope, write_msg, StreamError};
use nqvpn_proto::types::{NodeId, Role};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::config::RelayConfig;
use crate::state::RelayState;

pub const COORD_ISS: &str = "nqvpn-coord";
/// How often a relay re-declares its full attachment set (§3.2).
pub const RESYNC_SECS: u64 = 15;
/// How often a relay reports its traffic counters. Also the window the
/// coordinator derives rates over, so it sets the resolution of the
/// admin view — short enough to be live, long enough to stay cheap.
pub const TRAFFIC_SECS: u64 = 5;

/// Perform the HTTP join, retrying until it succeeds.
///
/// Terminal rejections — a pin an admin must reset, a disabled member, a
/// changed secret — used to abort, on the reasoning that a human has to
/// intervene so hammering the API will not help. That was wrong for a
/// daemon: exiting means the member stays down until somebody notices and
/// restarts it, on every affected machine, even though the fix happens
/// entirely at the coordinator. A member that keeps asking heals itself
/// the moment the operator acts.
///
/// Terminal conditions are logged at error level with the retry interval,
/// so they remain as diagnosable as an exit would have been — the
/// difference is only that recovery no longer needs a human on this end.
pub fn join_with_backoff(
    cfg: &RelayConfig,
    id: &TlsIdentity,
    pubkey: &str,
) -> Result<JoinResponse> {
    // `pubkey` must be the relay's real X25519 key: peers derive their
    // end-to-end session from it, so a placeholder makes the relay
    // unreachable as an endpoint even though it forwards fine.
    let req = JoinRequest {
        network_id: cfg.network_id.clone(),
        client_id: cfg.client_id.clone(),
        client_secret: cfg.secret()?,
        pubkey: pubkey.to_string(),
        role: Role::Relay,
        want_vpn_ip: cfg.wants_address(),
        pool: None,
        preferred_ip4: None,
        preferred_ip6: None,
        local_cidrs: cfg.local_cidrs(),
        relay_addr: Some(cfg.relay_addr.clone()),
        cert_fingerprint: id.fingerprint(),
    };
    let mut delay = Duration::from_secs(1);
    loop {
        match joinapi::join(&cfg.coordinator, &req) {
            Ok(r) => return Ok(r),
            Err(e) if e.is_terminal() => {
                let wait = joinapi::retry_delay(true, 1);
                tracing::error!(
                    retry_in_secs = wait.as_secs(),
                    "join rejected: {e} — fix this at the coordinator; retrying until then"
                );
                std::thread::sleep(wait);
            }
            Err(e) => {
                tracing::warn!("join failed ({e}); retrying in {:?}", delay);
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }
}

/// Everything the relay needs from a successful join.
pub struct Joined {
    pub node_id: NodeId,
    /// Our own VPN addresses, if we asked for and were granted them.
    pub addresses: Vec<ipnet::IpNet>,
    /// LAN prefixes the coordinator granted us (gateway relays).
    pub granted_cidrs: Vec<ipnet::IpNet>,
    pub mtu: u16,
    pub credential: String,
    pub network_uuid: String,
    pub relays: Vec<nqvpn_proto::api::RelayEntry>,
    pub keepalive_secs: u16,
    pub signing_keys: Vec<KeyInfo>,
    pub transport: String,
    pub lanes: u8,
}

impl From<JoinResponse> for Joined {
    fn from(r: JoinResponse) -> Self {
        let mut addresses = Vec::new();
        if let Some(ip) = r.ip4 {
            addresses.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
        }
        if let Some(ip) = r.ip6 {
            addresses.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
        }
        Joined {
            node_id: r.node_id,
            addresses,
            granted_cidrs: r.granted_cidrs.clone(),
            mtu: r.mtu,
            credential: r.credential,
            network_uuid: r.network_uuid,
            relays: r.relays,
            keepalive_secs: r.keepalive_secs,
            signing_keys: r.coordinator_signing_keys,
            transport: r.transport.clone(),
            lanes: r.lanes.max(1),
        }
    }
}

/// Run one control session to completion; the caller reconnects.
pub async fn run_session(
    state: Arc<RelayState>,
    cfg: Arc<RelayConfig>,
    id: TlsIdentity,
    joined: &Joined,
) -> Result<()> {
    let api_host = joinapi::strip_scheme(&cfg.coordinator);
    let host = api_host.rsplit_once(':').map(|(h, _)| h).unwrap_or(api_host);
    // The control port is announced by config; default to the API host.
    let quic_addr = state
        .coord_quic
        .clone()
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", state.coord_quic))?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", state.coord_quic))?;

    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(
        client_config(&id, cfg.coordinator_fp.clone(), joined.keepalive_secs.max(1) as u64)
            .map_err(|e| anyhow!("tls: {e}"))?,
    );
    let conn = ep.connect(quic_addr, host)?.await.context("coordinator QUIC connect")?;
    tracing::info!(%quic_addr, "coordinator control connected");

    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: joined.credential.clone() }).await?;

    // Attach reports flow from the session acceptor to here.
    let (attach_tx, mut attach_rx) = mpsc::channel::<Attach>(256);
    state.set_attach_sender(Some(attach_tx.clone()));

    // Resync: declare everyone already attached here. A client that
    // arrived while this link was down would otherwise stay invisible to
    // the rest of the fleet, and nobody could route to it.
    let existing = state.local_clients();
    if !existing.is_empty() {
        tracing::info!(count = existing.len(), "resyncing attachments to coordinator");
    }
    for node_id in existing {
        let _ = attach_tx.try_send(Attach { node_id, attached: true });
    }

    // RPC over the same control stream. Output joins the writer's select!
    // rather than touching the stream directly.
    let (rpc_out, mut rpc_rx) = mpsc::channel::<Vec<u8>>(256);
    let rpc = nqvpn_proto::rpc::RpcPeer::new(
        rpc_out,
        std::sync::Arc::new(nqvpn_proto::rpc::NoVerbs),
    );

    let ka = joined.keepalive_secs.max(1) as u64;
    let resync_state = state.clone();
    let writer = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(ka));
        // The attachment registry is the one piece of coordinator state
        // derived from *our* local facts, so make it self-healing: a
        // periodic full declaration means a single dropped edge report
        // costs one interval of staleness instead of permanent
        // invisibility. The coordinator ignores unchanged entries, so
        // this is free when nothing moved.
        let mut resync = tokio::time::interval(Duration::from_secs(RESYNC_SECS));
        let mut traffic = tokio::time::interval(Duration::from_secs(TRAFFIC_SECS));
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    write_msg(&mut tx, Kind::Ping, &()).await?;
                }
                _ = traffic.tick() => {
                    write_msg(
                        &mut tx,
                        Kind::TrafficReport,
                        &resync_state.traffic_report(),
                    )
                    .await?;
                }
                _ = resync.tick() => {
                    for node_id in resync_state.local_clients() {
                        write_msg(&mut tx, Kind::Attach, &Attach { node_id, attached: true })
                            .await?;
                    }
                }
                Some(a) = attach_rx.recv() => {
                    write_msg(&mut tx, Kind::Attach, &a).await?;
                }
                Some(bytes) = rpc_rx.recv() => {
                    nqvpn_proto::stream::write_bytes(&mut tx, &bytes).await?;
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, StreamError>(())
    });

    // Identity rotation, if the operator enabled it. Ordered so that
    // every interruption is safe: stage, register, then promote. A crash
    // before the promotion leaves the working identity in place, and the
    // coordinator keeps accepting it for the whole overlap.
    if cfg.rotate_identity_after_days > 0 {
        let after = cfg.rotate_identity_after_days * 24 * 3600;
        let age = nqvpn_proto::identity::TlsIdentity::age_secs(&cfg.identity.dir);
        if nqvpn_proto::rotation::decide(age, after) == nqvpn_proto::rotation::RotationAction::Rotate
        {
            let dir = cfg.identity.dir.clone();
            let name = cfg.client_id.clone();
            let rpc2 = rpc.clone();
            tokio::spawn(async move {
                match nqvpn_proto::identity::TlsIdentity::stage_replacement(&dir, &name) {
                    Ok(staged) => {
                        let req = nqvpn_proto::rpc::RotateIdentity {
                            new_pubkey: String::new(),
                            new_cert_fp: staged.fingerprint(),
                        };
                        match rpc2.call(req).await {
                            Ok(ok) => {
                                // Registered and durable at the far end;
                                // only now is it safe to switch.
                                if let Err(e) =
                                    nqvpn_proto::identity::TlsIdentity::promote_staged(&dir)
                                {
                                    tracing::error!("promoting rotated identity failed: {e}");
                                    return;
                                }
                                tracing::info!(
                                    old_retires_unix = ok.old_retires_unix,
                                    "identity rotated; restart to begin using it — the \
                                     previous identity keeps working until the overlap ends"
                                );
                            }
                            Err(e) => {
                                // Never registered, so it must never be
                                // promoted: keep the identity that works.
                                nqvpn_proto::identity::TlsIdentity::discard_staged(&dir);
                                tracing::warn!("identity rotation refused, keeping current identity: {e}");
                            }
                        }
                    }
                    Err(e) => tracing::warn!("staging a replacement identity failed: {e}"),
                }
            });
        }
    }

    let expected_uuid = joined.network_uuid.clone();
    let keepalive = joined.keepalive_secs.max(1) as u64;
    let result = loop {
        let env = match read_envelope(&mut rx).await {
            Ok(e) => e,
            Err(e) => break Err(anyhow!("control stream ended: {e}")),
        };
        // RPC first; it consumes only what it owns.
        if rpc.on_envelope(&env) {
            continue;
        }
        match env.kind {
            k if k == Kind::HelloAck as u16 => {
                let a: HelloAck = decode_payload(&env.payload)?;
                tracing::info!(revision = a.revision, "coordinator accepted control session");
            }
            k if k == Kind::KeySet as u16 => {
                let s: KeySet = decode_payload(&env.payload)?;
                state.set_signing_keys(&s.keys);
                tracing::debug!(keys = s.keys.len(), "signing keyset updated");
            }
            k if k == Kind::MembershipSnapshot as u16 => {
                let s: MembershipSnapshot = decode_payload(&env.payload)?;
                state.apply_snapshot_chunk(s);
            }
            k if k == Kind::MembershipDelta as u16 => {
                let d: MembershipDelta = decode_payload(&env.payload)?;
                state.apply_membership_delta(d);
            }
            k if k == Kind::RelayList as u16 => {
                let l: RelayList = decode_payload(&env.payload)?;
                let fresh = state.take_new_relays(&l.relays);
                if !fresh.is_empty() {
                    tracing::info!(
                        new = fresh.len(),
                        total = l.relays.len(),
                        "relay fleet updated; dialing new peers"
                    );
                    tokio::spawn(crate::sessions::mesh_dialer(
                        state.clone(),
                        id.clone(),
                        fresh,
                        keepalive,
                    ));
                }
            }
            k if k == Kind::AttachmentSnapshot as u16 => {
                let s: AttachmentSnapshot = decode_payload(&env.payload)?;
                tracing::info!(entries = s.entries.len(), "attachment table installed");
                state.replace_attachments(s.entries);
            }
            k if k == Kind::AttachmentDelta as u16 => {
                let d: AttachmentDelta = decode_payload(&env.payload)?;
                state.apply_attachment_delta(d);
            }
            other => tracing::debug!(kind = other, "ignoring unknown control message"),
        }
        let _ = &expected_uuid;
    };

    state.set_attach_sender(None);
    rpc.close();
    writer.abort();
    conn.close(0u32.into(), b"session ended");
    result
}

/// Verify a peer's credential offline, exactly as §3.3 requires:
/// signature against the coordinator keyset, expiry, issuer, network,
/// and the TLS possession proof.
pub fn verify_peer(
    state: &RelayState,
    token: &str,
    presented_fp: &str,
    network_id: &str,
) -> Result<credential::Claims> {
    let keys = state.verifying_keys();
    anyhow::ensure!(!keys.is_empty(), "no coordinator signing keys yet");
    let claims = credential::verify(
        token,
        &keys,
        &Expected {
            iss: COORD_ISS,
            network_id,
            network_uuid: &state.network_uuid,
        },
        now_unix(),
    )
    .map_err(|e| anyhow!("credential rejected: {e}"))?;
    anyhow::ensure!(
        claims.cert_fp == presented_fp,
        "cert_fp mismatch: credential {} vs TLS {presented_fp}",
        claims.cert_fp
    );
    Ok(claims)
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
