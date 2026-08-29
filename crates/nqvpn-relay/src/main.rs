use anyhow::{Context, Result};
use clap::Parser;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::server_config;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use nqvpn_relay::config::RelayConfig;
use nqvpn_relay::state::RelayState;
use nqvpn_relay::{coordlink, sessions};

#[derive(Parser)]
#[command(name = "nqvpn-relay", about = "nqvpn relay: forwarding service + optional site gateway")]
struct Cli {
    #[arg(long, default_value = "/etc/nqvpn/relay.toml")]
    config: PathBuf,
    /// Coordinator QUIC control address (host:port).
    #[arg(long)]
    coord_quic: String,
    /// Print a status line every N seconds (0 = off).
    #[arg(long, default_value_t = 0)]
    status_secs: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Arc::new(RelayConfig::load(&cli.config)?);
    let workers = if cfg.limits.workers == 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2)
    } else {
        cfg.limits.workers
    };
    // Multi-threaded reactor: the OS event queue (epoll/kqueue) feeding
    // worker threads — see DESIGN.md §9.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()?;
    rt.block_on(run(cfg, cli))
}

async fn run(cfg: Arc<RelayConfig>, cli: Cli) -> Result<()> {
    let identity = TlsIdentity::load_or_create(&cfg.identity.dir, &cfg.client_id)
        .context("loading relay TLS identity")?;
    tracing::info!(fingerprint = %identity.fingerprint(), "relay identity");

    // Placeholder until the Noise layer lands (Phase 3): the relay
    // forwards sealed frames and never needs a data key of its own.
    // Bind the listener BEFORE joining. The coordinator probes our
    // advertised address during the join (§3.2), so the socket has to be
    // accepting by then — and a port conflict should be discovered
    // before we announce ourselves to the control plane.
    let listen: SocketAddr = cfg.listen.parse().context("parsing listen")?;
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, 15)
            .map_err(|e| anyhow::anyhow!("quic server config: {e}"))?,
        listen,
    )
    .with_context(|| format!("binding relay port {listen}"))?;
    tracing::info!(%listen, "relay listening (clients + mesh)");

    // A relay needs a real X25519 identity, not a placeholder: peers
    // derive their end-to-end session from the key we publish, so a fake
    // one makes us unreachable as an endpoint (§3.1, §4).
    let keys = nqvpn_proto::seal::StaticKeys::load_or_create(&cfg.identity.dir)
        .map_err(|e| anyhow::anyhow!("loading static keys: {e}"))?;
    let pubkey = keys.public_b64();
    let joined: coordlink::Joined = {
        let cfg = cfg.clone();
        let id = identity.clone();
        tokio::task::spawn_blocking(move || coordlink::join_with_backoff(&cfg, &id, &pubkey))
            .await??
            .into()
    };
    tracing::info!(
        node_id = joined.node_id,
        relays = joined.relays.len(),
        "joined network {}",
        cfg.network_id
    );

    let state = Arc::new(RelayState::new(
        joined.node_id,
        cfg.network_id.clone(),
        joined.network_uuid.clone(),
        cli.coord_quic.clone(),
    ));
    state.set_signing_keys(&joined.signing_keys);
    state.set_credential(&joined.credential);
    state.set_mode(nqvpn_proto::transport::Mode::parse(&joined.transport));
    state.set_lanes(joined.lanes);
    tracing::info!(transport = %joined.transport, "packet transport for this network");

    // Endpoint role: a relay that took an address, or that fronts a LAN,
    // also terminates traffic addressed to it (§3.1). A pure forwarder
    // skips all of this and never touches a TUN.
    let mine: Vec<ipnet::IpNet> = joined
        .addresses
        .iter()
        .chain(joined.granted_cidrs.iter())
        .copied()
        .collect();
    // Declared out here on purpose: an flock lives exactly as long as the
    // descriptor holding it, so a guard bound inside the block below
    // would be dropped at the end of it and release the lock while the
    // relay kept running. It has to outlive the setup that claimed it.
    let _endpoint_lock;
    if mine.is_empty() {
        tracing::info!("pure forwarder: no address, no gateway prefixes, no TUN");
    } else {
        // Only the endpoint role programs routes, so only it claims the
        // per-network lock. A pure forwarder (want_vpn_ip = false) never
        // reaches here and can legitimately share a host with a client.
        _endpoint_lock = nqvpn_client::endpoint_guard::EndpointGuard::acquire(
            &cfg.network_id,
            &format!("relay {}", cfg.client_id),
        )?;
        let tun: std::sync::Arc<dyn nqvpn_client::tun::TunDevice> = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                nqvpn_client::tun_real::RealTun::create(
                    &joined.addresses,
                    joined.mtu,
                    cfg.tun_name.as_deref(),
                )
                    .context("creating TUN (needs root/elevation)")?
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                anyhow::bail!("endpoint role needs a TUN backend; set want_vpn_ip = false")
            }
        };
        tracing::info!(
            device = %tun.name(),
            addresses = ?joined.addresses,
            gateway_cidrs = ?joined.granted_cidrs,
            "endpoint role active — traffic addressed here terminates locally"
        );
        let ep = nqvpn_relay::endpoint::LocalEndpoint::new(
            state.clone(),
            tun,
            keys.clone(),
            mine,
            joined.mtu,
            joined.lanes,
        );
        ep.spawn_pumps();
        state.set_endpoint(ep);
        state.sync_endpoint_peers();
    }

    tokio::spawn(sessions::accept_loop(
        state.clone(),
        endpoint,
        cfg.limits.max_session_mbps,
    ));
    tokio::spawn(sessions::mesh_dialer(
        state.clone(),
        identity.clone(),
        joined.relays.clone(),
        joined.keepalive_secs.max(1) as u64,
    ));

    // Credential renewal (§3.3, §9 task 1). Without this a long-running
    // relay keeps a credential that peers will reject as expired, and
    // new mesh links stop forming even though everything looks healthy.
    {
        let (state, cfg2, id2) = (state.clone(), cfg.clone(), identity.clone());
        let keys_for_renewal = keys.clone();
        let ka = joined.keepalive_secs.max(1) as u64;
        let mut wait = nqvpn_proto::credential::renew_after_secs(&joined.credential);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(wait)).await;
                let (c, i) = (cfg2.clone(), id2.clone());
                let pk = keys_for_renewal.public_b64();
                match tokio::task::spawn_blocking(move || {
                    coordlink::join_with_backoff(&c, &i, &pk)
                })
                .await
                {
                    Ok(Ok(r)) => {
                        let j: coordlink::Joined = r.into();
                        state.set_credential(&j.credential);
                        state.set_signing_keys(&j.signing_keys);
                        wait = nqvpn_proto::credential::renew_after_secs(&j.credential);
                        tracing::info!(next_in_secs = wait, "credential renewed");
                        let fresh = state.take_new_relays(
                            &j.relays
                                .iter()
                                .map(|r| nqvpn_proto::control::RelayEndpoint {
                                    relay_id: r.relay_id,
                                    name: r.name.clone(),
                                    addr: r.addr.clone(),
                                    cert_fp: r.cert_fp.clone(),
                                })
                                .collect::<Vec<_>>(),
                        );
                        if !fresh.is_empty() {
                            tokio::spawn(sessions::mesh_dialer(state.clone(), id2.clone(), fresh, ka));
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("credential renewal failed: {e:#}; retrying in 60s");
                        wait = 60;
                    }
                    Err(e) => {
                        tracing::error!("renewal task failed: {e}; retrying in 60s");
                        wait = 60;
                    }
                }
            }
        });
    }

    if cli.status_secs > 0 {
        let s = state.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(cli.status_secs));
            loop {
                t.tick().await;
                tracing::info!("status: {}", s.status_line());
            }
        });
    }

    // Hold the coordinator control session, reconnecting with backoff.
    let mut joined = joined;
    let mut delay = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        match coordlink::run_session(state.clone(), cfg.clone(), identity.clone(), &joined).await {
            Ok(()) => tracing::warn!("coordinator session ended cleanly; reconnecting"),
            Err(e) => tracing::warn!("coordinator session lost: {e:#}"),
        }
        let was_healthy = started.elapsed() >= Duration::from_secs(30);
        tokio::time::sleep(delay).await;
        delay = if was_healthy {
            Duration::from_secs(1)
        } else {
            (delay * 2).min(Duration::from_secs(30))
        };

        // Re-join to refresh the credential and the relay list (§3.3).
        let c = cfg.clone();
        let id = identity.clone();
        let pk = keys.public_b64();
        match tokio::task::spawn_blocking(move || coordlink::join_with_backoff(&c, &id, &pk))
            .await?
        {
            Ok(r) => {
                joined = r.into();
                state.set_signing_keys(&joined.signing_keys);
                state.set_credential(&joined.credential);
                // Membership may have moved while we were away; rebuild
                // rather than diffing against a possibly-stale cache.
                if let Some(ep) = state.endpoint() {
                    ep.reconcile_routes();
                }
                // New relays may have appeared while we were away — but
                // only *new* ones get a dialer. A dialer task loops
                // forever, so re-spawning the whole fleet on every
                // reconnect left one task per peer per reconnect, all
                // polling the same link. `take_new_relays` remembers what
                // it has already handed out; the existing dialers are
                // still alive and reconnecting on their own.
                let fresh = state.take_new_relays(
                    &joined
                        .relays
                        .iter()
                        .map(|r| nqvpn_proto::control::RelayEndpoint {
                            relay_id: r.relay_id,
                            name: r.name.clone(),
                            addr: r.addr.clone(),
                            cert_fp: r.cert_fp.clone(),
                        })
                        .collect::<Vec<_>>(),
                );
                if !fresh.is_empty() {
                    tracing::info!(new = fresh.len(), "dialing relays new since we left");
                    tokio::spawn(sessions::mesh_dialer(
                        state.clone(),
                        identity.clone(),
                        fresh,
                        joined.keepalive_secs.max(1) as u64,
                    ));
                }
            }
            Err(e) => {
                // Never exit on a condition only the coordinator can fix.
                // A relay that dies on a reset pin takes its whole site
                // off the mesh until a human notices; retrying means it
                // heals itself the moment the operator acts.
                let wait = nqvpn_proto::joinapi::retry_delay(true, 1);
                tracing::error!(
                    retry_in_secs = wait.as_secs(),
                    "re-join rejected: {e:#} — this needs fixing at the coordinator; \
                     retrying until it is"
                );
                tokio::time::sleep(wait).await;
                continue;
            }
        }
    }
}
