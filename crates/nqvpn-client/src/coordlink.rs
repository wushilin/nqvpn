//! The client's coordinator link (DESIGN.md §9, task 1): join, hold the
//! control session, apply membership, renew the credential.

use anyhow::{anyhow, Context, Result};
use ipnet::IpNet;
use nqvpn_proto::api::{JoinRequest, JoinResponse, RelayEntry};
use nqvpn_proto::control::*;
use nqvpn_proto::envelope::{decode_payload, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::joinapi;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::types::{NodeId, Role};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use crate::config::ClientConfig;
use crate::engine::Engine;

pub struct Joined {
    pub node_id: NodeId,
    pub credential: String,
    pub network_uuid: String,
    pub relays: Vec<RelayEntry>,
    pub keepalive_secs: u16,
    pub mtu: u16,
    pub addresses: Vec<IpNet>,
    pub transport: String,
    pub lanes: u8,
}

impl Joined {
    fn from(r: JoinResponse) -> Joined {
        let mut addresses = Vec::new();
        if let Some(ip) = r.ip4 {
            addresses.push(IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
        }
        if let Some(ip) = r.ip6 {
            addresses.push(IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
        }
        Joined {
            node_id: r.node_id,
            credential: r.credential,
            network_uuid: r.network_uuid,
            relays: r.relays,
            keepalive_secs: r.keepalive_secs,
            mtu: r.mtu,
            addresses,
            transport: r.transport.clone(),
            lanes: r.lanes.max(1),
        }
    }
}

/// Join, retrying transient failures. Terminal rejections abort with an
/// operator-readable error rather than looping forever (§9 startup).
pub fn join_with_backoff(
    cfg: &ClientConfig,
    tls: &TlsIdentity,
    keys: &StaticKeys,
) -> Result<Joined> {
    let req = JoinRequest {
        network_id: cfg.network_id.clone(),
        client_id: cfg.client_id.clone(),
        client_secret: cfg.secret()?,
        pubkey: keys.public_b64(),
        role: Role::Client,
        want_vpn_ip: cfg.address.want_vpn_ip.unwrap_or(true),
        pool: cfg.address.pool.clone(),
        preferred_ip4: cfg.address.preferred_ip4,
        preferred_ip6: cfg.address.preferred_ip6,
        local_cidrs: vec![],
        relay_addr: None,
        cert_fingerprint: tls.fingerprint(),
    };
    let mut delay = Duration::from_secs(1);
    loop {
        match joinapi::join(&cfg.coordinator, &req) {
            Ok(r) => return Ok(Joined::from(r)),
            Err(e) if e.is_terminal() => {
                let wait = joinapi::retry_delay(true, 1);
                tracing::error!(
                    retry_in_secs = wait.as_secs(),
                    "join rejected: {e} — fix this at the coordinator; retrying until then"
                );
                std::thread::sleep(wait);
            }
            Err(e) => {
                tracing::warn!("join failed ({e}); retrying in {delay:?}");
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_secs(60));
            }
        }
    }
}

/// Hold one control session, applying pushes into the engine's peer
/// table. Returns when the session ends; the caller reconnects.
pub async fn run_session(
    cfg: Arc<ClientConfig>,
    tls: TlsIdentity,
    engine: Arc<Engine>,
    joined: &Joined,
    on_relays: impl Fn(Vec<RelayEntry>) + Send + 'static,
    // on_mtu: called with the network-wide tunnel MTU whenever it changes.
    // usable_mtu: our own measured uplink MTU, polled for the report.
    on_mtu: impl Fn(NetworkMtu) + Send + 'static,
    usable_mtu: Arc<std::sync::atomic::AtomicU64>,
    // Called after *every* membership change: routes must track peers
    // that join later, not just the set present at startup.
    apply_routes: Arc<dyn Fn(Vec<IpNet>) + Send + Sync>,
) -> Result<()> {
    let addr = cfg
        .coordinator_quic
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", cfg.coordinator_quic))?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", cfg.coordinator_quic))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(
        client_config(&tls, cfg.coordinator_fp.clone(), joined.keepalive_secs.max(1) as u64)
            .map_err(|e| anyhow!("tls: {e}"))?,
    );
    let host = cfg.coordinator_quic.rsplit_once(':').map(|(h, _)| h).unwrap_or("coord");
    let conn = ep.connect(addr, host)?.await.context("coordinator connect")?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: joined.credential.clone() }).await?;
    tracing::info!("coordinator control connected");

    let ka = joined.keepalive_secs.max(1) as u64;
    let writer = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(ka));
        // Report the measured MTU periodically rather than on an event:
        // a path that silently shrinks is picked up on the next tick.
        let mut mtu_tick = tokio::time::interval(Duration::from_secs(30));
        let mut last_reported = 0u64;
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    if write_msg(&mut tx, Kind::Ping, &()).await.is_err() {
                        return;
                    }
                }
                _ = mtu_tick.tick() => {
                    let m = usable_mtu.load(std::sync::atomic::Ordering::Relaxed);
                    if m > 0 && m != last_reported {
                        last_reported = m;
                        let r = MtuReport { usable_mtu: m as u16 };
                        if write_msg(&mut tx, Kind::MtuReport, &r).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });

    let mut snapshot: Vec<PeerInfo> = Vec::new();
    let result = loop {
        let env = match read_envelope(&mut rx).await {
            Ok(e) => e,
            Err(e) => break Err(anyhow!("control stream ended: {e}")),
        };
        match env.kind {
            k if k == Kind::MembershipSnapshot as u16 => {
                let s: MembershipSnapshot = decode_payload(&env.payload)?;
                if s.chunk_i == 0 {
                    snapshot.clear();
                }
                snapshot.extend(s.peers);
                if s.chunk_i + 1 == s.chunk_n {
                    // Installed atomically, only once complete (§3.2).
                    engine.peers.lock().unwrap().replace_all(std::mem::take(&mut snapshot));
                    tracing::info!(
                        rev = s.snapshot_rev,
                        peers = engine.peers.lock().unwrap().len(),
                        "membership installed"
                    );
                    let wanted = engine.peers.lock().unwrap().all_prefixes();
                    apply_routes(wanted);
                }
            }
            k if k == Kind::MembershipDelta as u16 => {
                let d: MembershipDelta = decode_payload(&env.payload)?;
                let mut p = engine.peers.lock().unwrap();
                for peer in d.changed {
                    // A peer whose key changed (admin pin reset) must not
                    // keep using the old session.
                    let key_changed = p
                        .get(peer.node_id)
                        .map(|old| old.pubkey != peer.pubkey)
                        .unwrap_or(false);
                    let id = peer.node_id;
                    p.upsert(peer);
                    if key_changed {
                        engine.sessions.lock().unwrap().remove(id);
                        tracing::info!(peer = id, "peer key changed; dropped its session");
                    }
                }
                for id in d.removed {
                    p.remove(id);
                    engine.sessions.lock().unwrap().remove(id);
                }
                let wanted = p.all_prefixes();
                drop(p);
                // A peer that just appeared (or lost a prefix) has to be
                // routable now, not at the next relay-list push.
                apply_routes(wanted);
            }
            k if k == Kind::NetworkMtu as u16 => {
                let m: NetworkMtu = decode_payload(&env.payload)?;
                on_mtu(m);
            }
            k if k == Kind::RelayList as u16 => {
                let l: RelayList = decode_payload(&env.payload)?;
                on_relays(
                    l.relays
                        .into_iter()
                        .map(|r| RelayEntry {
                            relay_id: r.relay_id,
                            name: r.name,
                            addr: r.addr,
                            cert_fp: r.cert_fp,
                        })
                        .collect(),
                );
            }
            other => tracing::debug!(kind = other, "ignoring control message"),
        }
    };
    writer.abort();
    conn.close(0u32.into(), b"bye");
    result
}
