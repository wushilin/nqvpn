use anyhow::{Context, Result};
use clap::Parser;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::server_config;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::transport::Mode;
use nqvpn_proto::types::Role;
use nqvpn_sync::join::MemberConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nqvpn_relay::config::RelayConfig;
use nqvpn_relay::endpoint::LocalEndpoint;
use nqvpn_relay::net::{Fleet, RelayNet};

#[derive(Parser)]
#[command(name = "nqvpn-relay", about = "nqvpn relay: forwarding service + optional site gateway")]
struct Cli {
    #[arg(long, default_value = "/etc/nqvpn/relay.toml")]
    config: PathBuf,
    /// Print a status line every N seconds (0 = off).
    #[arg(long, default_value_t = 0)]
    status_secs: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cfg = Arc::new(RelayConfig::load(&cli.config)?);
    let workers = if cfg.limits.workers == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
    } else {
        cfg.limits.workers
    };
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(workers).enable_all().build()?;
    let code = rt.block_on(run(cfg, cli))?;
    // Guards (TUN, routes, addresses) are dropped by now; the runtime goes last.
    drop(rt);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

/// After every join: the credential moves to the dialed mesh sessions.
struct Hooks {
    net: Arc<RelayNet>,
}

impl nqvpn_sync::link::MemberHooks for Hooks {
    fn joined(&self, r: &nqvpn_proto::api::JoinResponse) {
        self.net.set_credential(&r.credential);
        self.net.set_signing_keys(&r.coordinator_signing_keys);
        // Facts the operator may have changed since the last join.
        let hosts = host_prefixes(r);
        match self.net.endpoint() {
            Some(ep) => ep.set_facts(hosts, r.granted_cidrs.clone()),
            None if !hosts.is_empty() || !r.granted_cidrs.is_empty() => {
                tracing::warn!(network = %r.network_id, "this relay now has an endpoint role (an address or LAN prefixes); restart it to activate");
            }
            None => {}
        }
    }
}

fn host_prefixes(r: &nqvpn_proto::api::JoinResponse) -> Vec<ipnet::IpNet> {
    let mut hosts = Vec::new();
    if let Some(ip) = r.ip4 {
        hosts.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
    }
    if let Some(ip) = r.ip6 {
        hosts.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
    }
    hosts
}

async fn run(cfg: Arc<RelayConfig>, cli: Cli) -> Result<i32> {
    let identity = TlsIdentity::load_or_create(&cfg.state_dir, "nqvpn-relay").context("loading relay TLS certificate")?;
    let keys = StaticKeys::load_or_create(&cfg.state_dir).map_err(|e| anyhow::anyhow!("loading static keys: {e}"))?;
    // Each network's member loop returns only when this relay has been
    // replaced under that name; the first one to do so ends the process.
    let (exit_tx, mut exit_rx) = tokio::sync::mpsc::channel::<(String, nqvpn_sync::MemberExit)>(4);

    // Bind before joining: the coordinator may probe the advertised
    // address during the join, and a port conflict should fail early.
    let listen: SocketAddr = cfg.listen.parse().context("parsing listen")?;
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, 15).map_err(|e| anyhow::anyhow!("quic server config: {e}"))?,
        listen,
    )
    .with_context(|| format!("binding relay port {listen}"))?;
    tracing::info!(%listen, "relay listening (clients + mesh)");

    let mut nets: HashMap<String, Arc<RelayNet>> = HashMap::new();
    let mut guards = Vec::new();
    for (i, ncfg) in cfg.networks.iter().enumerate() {
        let member = Arc::new(MemberConfig::from_token(&ncfg.token()?, cfg.tls()));
        let joined = match nqvpn_sync::join_with_backoff_async(member.clone(), identity.clone(), keys.clone()).await {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(token = i, "not joining: {e}");
                return Ok(nqvpn_sync::EXIT_REFUSED);
            }
        };
        if joined.role != Role::Relay {
            tracing::error!(network = %joined.network_id, name = %joined.name, "this token belongs to a {} member, not a relay", joined.role);
            return Ok(nqvpn_sync::EXIT_REFUSED);
        }
        let network_id = joined.network_id.clone();
        tracing::info!(network = %network_id, name = %joined.name, node_id = joined.node_id, relay_addr = ?joined.relay_addr, relays = joined.relays.len(), "joined");
        if let Some(addr) = &joined.relay_addr {
            let advertised_port = addr.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
            if advertised_port.is_some() && advertised_port != Some(listen.port()) {
                tracing::warn!(advertised = %addr, %listen, "the coordinator advertises a different port than this relay listens on");
            }
        }
        if nets.contains_key(&network_id) {
            anyhow::bail!("two tokens for network {network_id}");
        }

        let cap = if cfg.limits.max_session_mbps > 0 { cfg.limits.max_session_mbps } else { joined.max_session_mbps };
        let net = RelayNet::new(
            network_id.clone(),
            joined.network_uuid.clone(),
            joined.node_id,
            identity.clone(),
            joined.credential.clone(),
            Mode::parse(&joined.transport),
            joined.lanes.max(1),
            cap,
            joined.keepalive_secs.max(1) as u64,
        );
        net.set_signing_keys(&joined.coordinator_signing_keys);

        // Endpoint role: an address, or a LAN to front.
        let hosts = host_prefixes(&joined);
        if !hosts.is_empty() || !joined.granted_cidrs.is_empty() {
            guards.push(nqvpn_endpoint::endpoint_guard::EndpointGuard::acquire(&network_id, &format!("relay node {}", joined.node_id))?);
            let tun: Arc<dyn nqvpn_endpoint::tun::TunDevice> = {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    nqvpn_endpoint::tun_real::RealTun::create(&hosts, joined.mtu, cfg.tun_name.as_deref())
                        .context("creating TUN (needs root/elevation)")?
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    anyhow::bail!("endpoint role needs a TUN backend; set want_vpn_ip = false and no local_cidrs")
                }
            };
            let device = tun.name();
            let routes = Arc::new(nqvpn_endpoint::routes::RouteSet::new(nqvpn_endpoint::routes::SystemProgrammer { device }));
            // The endpoint's own frames loop through the relay's tables;
            // a local channel carries trace notes back to it.
            let loopback = nqvpn_proto::transport::PacketChannel::start_lanes(
                loopback_connection(&identity).await?,
                Mode::Datagram,
                1,
            );
            let ep = LocalEndpoint::new(
                joined.node_id,
                joined.network_uuid.clone(),
                tun,
                keys.clone(),
                hosts.clone(),
                joined.granted_cidrs.clone(),
                joined.mtu,
                joined.lanes.max(1),
                routes,
                loopback,
            );
            ep.bind(net.clone());
            ep.spawn_pumps();
            net.set_endpoint(ep);
            tracing::info!(network = %network_id, addresses = ?hosts, gateway_cidrs = ?joined.granted_cidrs, "endpoint role active");
        } else {
            tracing::info!(network = %network_id, "pure forwarder: no address, no gateway prefixes, no TUN");
        }

        nqvpn_sync::spawn_reconciler(net.view.clone(), Arc::new(nqvpn_relay::net::NetReconciler(net.clone())), Duration::from_secs(20));
        tokio::spawn({
            let (exit_tx, network_id) = (exit_tx.clone(), network_id.clone());
            let member_loop = nqvpn_sync::run_member(
                member,
                identity.clone(),
                keys.clone(),
                joined,
                net.view.clone(),
                net.clone(),
                net.link.clone(),
                Arc::new(Hooks { net: net.clone() }),
            );
            async move {
                let exit = member_loop.await;
                let _ = exit_tx.send((network_id, exit)).await;
            }
        });
        nets.insert(network_id, net);
    }

    let fleet = Arc::new(Fleet { nets: nets.clone() });
    tokio::spawn(fleet.accept_loop(endpoint));

    if cli.status_secs > 0 {
        let nets = nets.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(cli.status_secs));
            loop {
                t.tick().await;
                for n in nets.values() {
                    tracing::info!("status: {}", n.status_line());
                }
            }
        });
    }
    let _guards = guards;
    match exit_rx.recv().await {
        Some((network, exit)) => {
            match &exit {
                nqvpn_sync::MemberExit::Replaced(reason) => tracing::error!(
                    %network,
                    %reason,
                    "another instance joined as this relay; exiting with code {} and not re-joining. If that was not you, rotate this member's secret at the coordinator.",
                    exit.exit_code()
                ),
                nqvpn_sync::MemberExit::Refused(reason) => tracing::error!(
                    %network,
                    %reason,
                    "the coordinator refused this relay; exiting with code {}. Fix it at the coordinator and restart.",
                    exit.exit_code()
                ),
            }
            Ok(exit.exit_code())
        }
        None => std::future::pending().await,
    }
}

/// A QUIC connection to ourselves, used only as a channel the endpoint
/// role's trace notes ride back on. Cheap, and it keeps every packet
/// path a `PacketChannel`.
async fn loopback_connection(identity: &TlsIdentity) -> Result<quinn::Connection> {
    let server = quinn::Endpoint::server(
        server_config(identity, 15).map_err(|e| anyhow::anyhow!("{e}"))?,
        "127.0.0.1:0".parse().unwrap(),
    )?;
    let addr = server.local_addr()?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap())?;
    client.set_default_client_config(nqvpn_proto::quic::client_config(identity, None, 15).map_err(|e| anyhow::anyhow!("{e}"))?);
    let accept = tokio::spawn(async move {
        let inc = server.accept().await.ok_or_else(|| anyhow::anyhow!("no loopback accept"))?;
        let conn = inc.await?;
        // Keep the server side alive for the process lifetime.
        tokio::spawn(async move {
            let _keep = server;
            conn.closed().await;
        });
        Ok::<(), anyhow::Error>(())
    });
    let conn = client.connect(addr, "loopback")?.await?;
    accept.await??;
    tokio::spawn(async move {
        let _keep = client;
        std::future::pending::<()>().await;
    });
    Ok(conn)
}
