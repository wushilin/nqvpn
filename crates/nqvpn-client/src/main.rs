//! `nqvpn-client` — join, create the TUN, attach to a relay, and keep
//! the view current. Everything interesting is in `client.rs` and the
//! shared crates; this file is the wiring.

use anyhow::{Context, Result};
use clap::Parser;
use nqvpn_client::client::{Client, ClientReconciler};
use nqvpn_client::config::ClientConfig;
use nqvpn_endpoint::tun::TunDevice;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::seal::StaticKeys;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "nqvpn-client", about = "nqvpn client (leaf node)")]
struct Cli {
    #[arg(long, default_value = "/etc/nqvpn/client.toml")]
    config: PathBuf,
    /// Print a status line every N seconds (0 = off).
    #[arg(long, default_value_t = 30)]
    status_secs: u64,
    /// Do everything except create a TUN or touch the routing table.
    #[arg(long)]
    dry_run: bool,
    /// Tag every packet to this destination so relays report what they
    /// did with it; the notes are logged as they arrive.
    #[arg(long)]
    trace: Option<IpAddr>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let code = rt.block_on(run(cli))?;
    // Guards (TUN, routes) are dropped by now; the runtime goes last.
    drop(rt);
    if code != 0 {
        std::process::exit(code);
    }
    Ok(())
}

async fn run(cli: Cli) -> Result<i32> {
    let cfg = Arc::new(ClientConfig::load(&cli.config)?);
    let member = Arc::new(cfg.member()?);
    let identity = TlsIdentity::load_or_create(&cfg.state_dir, "nqvpn-client").context("loading TLS certificate")?;
    let keys = StaticKeys::load_or_create(&cfg.state_dir).map_err(|e| anyhow::anyhow!("loading static keys: {e}"))?;

    let joined = match nqvpn_sync::join_with_backoff_async(member.clone(), identity.clone(), keys.clone()).await {
        Ok(j) => j,
        Err(e) => {
            tracing::error!("not joining: {e}");
            return Ok(nqvpn_sync::EXIT_REFUSED);
        }
    };
    tracing::info!(node_id = joined.node_id, name = %joined.name, ip4 = ?joined.ip4, relays = joined.relays.len(), "joined {}", cfg.network_id);

    let _guard = if cli.dry_run {
        None
    } else {
        Some(nqvpn_endpoint::endpoint_guard::EndpointGuard::acquire(&cfg.network_id, &format!("client node {}", joined.node_id))?)
    };

    let mut hosts = Vec::new();
    if let Some(ip) = joined.ip4 {
        hosts.push(ipnet::IpNet::from(ipnet::Ipv4Net::new(ip, 32).expect("/32")));
    }
    if let Some(ip) = joined.ip6 {
        hosts.push(ipnet::IpNet::from(ipnet::Ipv6Net::new(ip, 128).expect("/128")));
    }
    let tun: Arc<dyn TunDevice> = if cli.dry_run {
        tracing::warn!("--dry-run: using an in-memory TUN, no kernel state touched");
        nqvpn_endpoint::tun::FakeTun::new(joined.mtu)
    } else {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            nqvpn_endpoint::tun_real::RealTun::create(&hosts, joined.mtu, cfg.tun_name.as_deref())
                .context("creating TUN (needs root/elevation)")?
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            anyhow::bail!("this platform has no TUN backend yet; use --dry-run")
        }
    };
    tracing::info!(device = %tun.name(), mtu = joined.mtu, transport = %joined.transport, "TUN ready");

    let routes: Arc<dyn nqvpn_client::client::RouteSink> = if cli.dry_run {
        Arc::new(nqvpn_endpoint::routes::RouteSet::new(nqvpn_endpoint::routes::RecordingProgrammer::default()))
    } else {
        Arc::new(nqvpn_endpoint::routes::RouteSet::new(nqvpn_endpoint::routes::SystemProgrammer { device: tun.name() }))
    };

    let client = Client::new(&joined, identity.clone(), keys.clone(), tun, routes, cfg.relay.preferred.clone());
    if let Ok((host, _)) = nqvpn_proto::joinapi::parse_url(&cfg.coordinator) {
        use std::net::ToSocketAddrs;
        if let Ok(it) = (host.as_str(), 443u16).to_socket_addrs() {
            client.set_underlay(it.map(|s| s.ip()).collect());
        }
    }
    if let Some(t) = cli.trace {
        client.engine.set_trace(Some(t));
        tracing::info!(target = %t, "tracing packets to this destination");
    }
    client.spawn_pumps();
    nqvpn_sync::spawn_reconciler(client.view.clone(), Arc::new(ClientReconciler(client.clone())), Duration::from_secs(20));
    tokio::spawn(client.clone().run_uplink());

    if cli.status_secs > 0 {
        let c = client.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(cli.status_secs));
            loop {
                t.tick().await;
                tracing::info!("status: {}", c.status_line());
                for n in c.engine.take_trace_notes() {
                    tracing::info!(trace = n.trace, hop = n.hop, relay = n.relay_id, decision = n.decision.as_str(), detail = n.detail, "trace");
                }
            }
        });
    }

    let exit = nqvpn_sync::run_member(member, identity, keys, joined, client.view.clone(), client.clone(), client.link.clone(), client.clone()).await;
    report_exit(&exit);
    Ok(exit.exit_code())
}

fn report_exit(exit: &nqvpn_sync::MemberExit) {
    match exit {
        nqvpn_sync::MemberExit::Replaced(reason) => tracing::error!(
            %reason,
            "another instance joined as this node; exiting with code {} and not re-joining. If that was not you, rotate this member's secret at the coordinator.",
            exit.exit_code()
        ),
        nqvpn_sync::MemberExit::Refused(reason) => tracing::error!(
            %reason,
            "the coordinator refused this node; exiting with code {}. Fix it at the coordinator and restart.",
            exit.exit_code()
        ),
    }
}
