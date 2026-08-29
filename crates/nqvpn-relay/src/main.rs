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

use nqvpn_relay::config::{NetworkCfg, RelayConfig};
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
    rt.block_on(run(cfg, cli))
}

/// After every join: the credential moves to the dialed mesh sessions.
struct Hooks {
    net: Arc<RelayNet>,
}

impl nqvpn_sync::link::MemberHooks for Hooks {
    fn joined(&self, r: &nqvpn_proto::api::JoinResponse) {
        self.net.set_credential(&r.credential);
        self.net.set_signing_keys(&r.coordinator_signing_keys);
    }
}

async fn run(cfg: Arc<RelayConfig>, cli: Cli) -> Result<()> {
    let identity = TlsIdentity::load_or_create(&cfg.state_dir, "nqvpn-relay").context("loading relay TLS certificate")?;
    let keys = StaticKeys::load_or_create(&cfg.state_dir).map_err(|e| anyhow::anyhow!("loading static keys: {e}"))?;

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
    for ncfg in &cfg.networks {
        let member = Arc::new(member_config(&cfg, ncfg)?);
        let joined = nqvpn_sync::join_with_backoff_async(member.clone(), identity.clone(), keys.clone()).await;
        tracing::info!(network = %ncfg.network_id, node_id = joined.node_id, relays = joined.relays.len(), "joined");

        let net = RelayNet::new(
            ncfg.network_id.clone(),
            joined.network_uuid.clone(),
            joined.node_id,
            identity.clone(),
            joined.credential.clone(),
            Mode::parse(&joined.transport),
            joined.lanes.max(1),
            cfg.limits.max_session_mbps,
            joined.keepalive_secs.max(1) as u64,
        );
        net.set_signing_keys(&joined.coordinator_signing_keys);

        // Endpoint role: an address, or a LAN to front.
        let mut hosts = Vec::new();
        if let Some(ip) = joined.ip4 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
        }
        if let Some(ip) = joined.ip6 {
            hosts.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
        }
        if !hosts.is_empty() || !joined.granted_cidrs.is_empty() {
            guards.push(nqvpn_endpoint::endpoint_guard::EndpointGuard::acquire(&ncfg.network_id, &format!("relay node {}", joined.node_id))?);
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
            tracing::info!(network = %ncfg.network_id, addresses = ?hosts, gateway_cidrs = ?joined.granted_cidrs, "endpoint role active");
        } else {
            tracing::info!(network = %ncfg.network_id, "pure forwarder: no address, no gateway prefixes, no TUN");
        }

        nqvpn_sync::spawn_reconciler(net.view.clone(), Arc::new(nqvpn_relay::net::NetReconciler(net.clone())), Duration::from_secs(20));
        tokio::spawn(nqvpn_sync::run_member(
            member,
            identity.clone(),
            keys.clone(),
            joined,
            net.view.clone(),
            net.clone(),
            net.link.clone(),
            Arc::new(Hooks { net: net.clone() }),
        ));
        nets.insert(ncfg.network_id.clone(), net);
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
    std::future::pending::<()>().await;
    Ok(())
}

fn member_config(cfg: &RelayConfig, n: &NetworkCfg) -> Result<MemberConfig> {
    Ok(MemberConfig {
        coordinator: cfg.coordinator.clone(),
        network_id: n.network_id.clone(),
        name: n.name.clone(),
        secret: n.secret()?,
        tls: cfg.tls(),
        role: Role::Relay,
        want_vpn_ip: n.want_vpn_ip,
        pool: n.pool.clone(),
        preferred_ip4: n.preferred_ip4,
        preferred_ip6: n.preferred_ip6,
        local_cidrs: n.local_cidrs.clone(),
        relay_addr: Some(cfg.relay_addr.clone()),
    })
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
