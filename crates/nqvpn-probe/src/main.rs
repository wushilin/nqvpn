//! `nqvpn-probe` — a development member: joins over HTTP, then holds a
//! QUIC control session and prints everything the coordinator pushes.
//!
//! This is the member side of §3.2 in miniature; `nqvpn-relay` and
//! `nqvpn-client` grow out of it in the next phases.

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use nqvpn_proto::api::{JoinRequest, JoinResponse};
use nqvpn_proto::control::*;
use nqvpn_proto::envelope::{decode_payload, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::stream::{read_envelope, write_msg};
use nqvpn_proto::types::Role;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "nqvpn-probe", about = "dev member: join + hold a control session")]
struct Cli {
    /// Coordinator HTTP API, e.g. baba2.example.net:18443
    #[arg(long)]
    api: String,
    /// Coordinator QUIC control, e.g. baba2.example.net:14433
    #[arg(long)]
    quic: String,
    #[arg(long)]
    network: String,
    #[arg(long)]
    id: String,
    #[arg(long)]
    secret: String,
    #[arg(long, default_value = "client")]
    role: String,
    /// Relay only: CIDRs to register.
    #[arg(long)]
    cidr: Vec<String>,
    /// Relay only: advertised address.
    #[arg(long)]
    relay_addr: Option<String>,
    /// Where to persist this member's TLS + identity files.
    #[arg(long, default_value = "./probe-state")]
    state: PathBuf,
    /// Pin the coordinator's control certificate (sha256:...).
    #[arg(long)]
    coord_fp: Option<String>,
    /// Seconds to stay connected (0 = forever).
    #[arg(long, default_value_t = 60)]
    seconds: u64,
    /// Also attach to this relay (by name from the relay list) and run
    /// the data-plane test.
    #[arg(long)]
    attach: Option<String>,
    /// Send a data frame to this node id once attached.
    #[arg(long)]
    send_to: Option<u32>,
    /// Payload for --send-to.
    #[arg(long, default_value = "ping-over-the-mesh")]
    payload: String,
}

/// Attach to a relay exactly as `nqvpn-client` will: mutual TLS with the
/// relay's coordinator-pinned certificate, `Hello{credential}`, then raw
/// data frames.
async fn attach_and_run(
    entry: nqvpn_proto::api::RelayEntry,
    credential: String,
    id: TlsIdentity,
    my_node_id: u32,
    send_to: Option<u32>,
    payload: String,
) -> Result<()> {
    use nqvpn_proto::frame::{RoutedHeader, T_DATA};
    let addr: SocketAddr = entry
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", entry.addr))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(
        client_config(&id, Some(entry.cert_fp.clone()), 5).map_err(|e| anyhow!("tls: {e}"))?,
    );
    let host = entry.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or("relay");
    let conn = ep.connect(addr, host)?.await?;
    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential }).await?;
    let ack = read_envelope(&mut rx).await?;
    anyhow::ensure!(ack.kind == Kind::HelloAck as u16, "relay refused our credential");
    println!("ATTACHED to relay {} (#{}) at {}", entry.name, entry.relay_id, entry.addr);

    if let Some(dst) = send_to {
        // Give the coordinator a moment to publish our attachment.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut buf = Vec::new();
        RoutedHeader { kind: T_DATA, src_id: my_node_id, dst_id: dst }.write(&mut buf);
        buf.extend_from_slice(payload.as_bytes());
        for i in 0..5 {
            conn.send_datagram(buf.clone().into())?;
            println!("SENT #{i} -> node {dst}: {payload:?}");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    loop {
        let d = conn.read_datagram().await?;
        match RoutedHeader::parse(&d) {
            Some(h) => println!(
                "RECEIVED from node {} -> {}: {:?}",
                h.src_id,
                h.dst_id,
                String::from_utf8_lossy(&d[9..])
            ),
            None => println!("RECEIVED non-data datagram ({} bytes)", d.len()),
        }
    }
}

fn http_post_json(api: &str, path: &str, body: &str) -> Result<String> {
    let addr: SocketAddr = api
        .to_socket_addrs()
        .with_context(|| format!("resolving {api}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {api}"))?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(10))?;
    let host = api.split(':').next().unwrap_or("localhost");
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes())?;
    let mut resp = String::new();
    s.read_to_string(&mut resp)?;
    let (head, payload) = resp
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let status = head.lines().next().unwrap_or_default();
    if !status.contains(" 200 ") {
        anyhow::bail!("join failed: {status}\n{payload}");
    }
    Ok(payload.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let role = match cli.role.as_str() {
        "relay" => Role::Relay,
        _ => Role::Client,
    };

    // Persistent identity: the fingerprint is what the coordinator pins.
    let identity = TlsIdentity::load_or_create(&cli.state, &cli.id)?;
    println!("identity fingerprint: {}", identity.fingerprint());

    let req = JoinRequest {
        network_id: cli.network.clone(),
        client_id: cli.id.clone(),
        client_secret: cli.secret.clone(),
        // Placeholder until the Noise layer lands (Phase 3).
        pubkey: format!("PK-{}", cli.id),
        role,
        want_vpn_ip: true,
        pool: None,
        preferred_ip4: None,
        preferred_ip6: None,
        local_cidrs: cli.cidr.iter().map(|c| c.parse()).collect::<Result<_, _>>()?,
        relay_addr: cli.relay_addr.clone(),
        cert_fingerprint: identity.fingerprint(),
    };
    let body = serde_json::to_string(&req)?;
    let raw = http_post_json(&cli.api, "/api/v1/join", &body)?;
    let join: JoinResponse = serde_json::from_str(&raw).context("parsing join response")?;
    println!(
        "joined: node_id={} ip4={:?} ip6={:?} mtu={} relays={} keys={}",
        join.node_id,
        join.ip4,
        join.ip6,
        join.mtu,
        join.relays.len(),
        join.coordinator_signing_keys.len()
    );
    for r in &join.relays {
        println!("  relay {} (#{}) at {} fp={}", r.name, r.relay_id, r.addr, r.cert_fp);
    }

    // Control session.
    let addr: SocketAddr = cli
        .quic
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow!("no address for {}", cli.quic))?;
    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    ep.set_default_client_config(
        client_config(&identity, cli.coord_fp.clone(), join.keepalive_secs as u64)
            .map_err(|e| anyhow!("tls config: {e}"))?,
    );
    let server_name = cli.quic.split(':').next().unwrap_or("coord").to_string();
    let conn = ep.connect(addr, &server_name)?.await.context("QUIC connect")?;
    println!("QUIC connected to {addr} (server fp {:?})", nqvpn_proto::quic::peer_fingerprint(&conn));

    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: join.credential.clone() }).await?;

    // Keepalive pings so the coordinator's liveness sweep keeps us.
    let ka = join.keepalive_secs.max(1) as u64;
    tokio::spawn(async move {
        let mut t = tokio::time::interval(Duration::from_secs(ka));
        loop {
            t.tick().await;
            if write_msg(&mut tx, Kind::Ping, &()).await.is_err() {
                return;
            }
        }
    });

    // Optional data-plane leg: attach to a relay and send/receive frames.
    if let Some(relay_name) = &cli.attach {
        let entry = join
            .relays
            .iter()
            .find(|r| &r.name == relay_name)
            .ok_or_else(|| anyhow!("relay {relay_name:?} not in the fleet"))?
            .clone();
        let cred = join.credential.clone();
        let id2 = identity.clone();
        let my_id = join.node_id;
        let send_to = cli.send_to;
        let payload = cli.payload.clone();
        tokio::spawn(async move {
            if let Err(e) = attach_and_run(entry, cred, id2, my_id, send_to, payload).await {
                println!("attach failed: {e:#}");
            }
        });
    }

    let deadline = (cli.seconds > 0)
        .then(|| tokio::time::Instant::now() + Duration::from_secs(cli.seconds));
    loop {
        let read = read_envelope(&mut rx);
        let env = match deadline {
            Some(d) => match tokio::time::timeout_at(d, read).await {
                Err(_) => {
                    println!("done (timer elapsed)");
                    return Ok(());
                }
                Ok(r) => r?,
            },
            None => read.await?,
        };
        match env.kind {
            k if k == Kind::HelloAck as u16 => {
                let a: HelloAck = decode_payload(&env.payload)?;
                println!("HelloAck: directory revision {}", a.revision);
            }
            k if k == Kind::KeySet as u16 => {
                let s: KeySet = decode_payload(&env.payload)?;
                println!("KeySet: {:?}", s.keys.iter().map(|k| (&k.kid, &k.state)).collect::<Vec<_>>());
            }
            k if k == Kind::MembershipSnapshot as u16 => {
                let s: MembershipSnapshot = decode_payload(&env.payload)?;
                println!(
                    "Snapshot rev={} chunk {}/{}:",
                    s.snapshot_rev,
                    s.chunk_i + 1,
                    s.chunk_n
                );
                for p in &s.peers {
                    println!(
                        "    #{} {:12} online={} prefixes={:?}",
                        p.node_id,
                        p.name,
                        p.online,
                        p.prefixes.iter().map(|x| x.to_string()).collect::<Vec<_>>()
                    );
                }
            }
            k if k == Kind::MembershipDelta as u16 => {
                let d: MembershipDelta = decode_payload(&env.payload)?;
                println!("Delta {} -> {}:", d.base_rev, d.new_rev);
                for p in &d.changed {
                    println!(
                        "    changed #{} {:12} online={} prefixes={:?}",
                        p.node_id,
                        p.name,
                        p.online,
                        p.prefixes.iter().map(|x| x.to_string()).collect::<Vec<_>>()
                    );
                }
                for id in &d.removed {
                    println!("    removed #{id}");
                }
            }
            k if k == Kind::AttachmentSnapshot as u16 => {
                let s: AttachmentSnapshot = decode_payload(&env.payload)?;
                println!("Attachments rev={}: {:?}", s.snapshot_rev, s.entries);
            }
            k if k == Kind::AttachmentDelta as u16 => {
                let d: AttachmentDelta = decode_payload(&env.payload)?;
                println!("AttachDelta {} -> {}: +{:?} -{:?}", d.base_rev, d.new_rev, d.changed, d.detached);
            }
            other => println!("(ignoring unknown kind {other})"),
        }
    }
}
