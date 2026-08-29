//! `nqvpn-client` — a leaf: one TUN, one upstream relay, one control
//! connection. Five loops, no per-peer transport state (DESIGN.md §9).

use anyhow::{Context, Result};
use clap::Parser;
use nqvpn_proto::api::RelayEntry;
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::seal::StaticKeys;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nqvpn_client::config::ClientConfig;
use nqvpn_client::engine::Engine;
use nqvpn_client::peers::PeerTable;
use nqvpn_client::routes::{RecordingProgrammer, RouteSet, SystemProgrammer};

/// Set once during startup so the reconnect loop can rebuild the routing
/// table from a fresh snapshot. A OnceLock rather than threading it
/// through: the reconnect loop is far from where routes are constructed.
static RECONCILE: std::sync::OnceLock<Box<dyn Fn(Vec<ipnet::IpNet>) + Send + Sync>> =
    std::sync::OnceLock::new();
use nqvpn_client::tun::TunDevice;
use nqvpn_client::{coordlink, uplink};

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // One network thread; the TUN backend adds its own two (§9).
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let cfg = Arc::new(ClientConfig::load(&cli.config)?);
    let tls = TlsIdentity::load_or_create(&cfg.identity.dir, &cfg.client_id)
        .context("loading TLS identity")?;
    let keys = StaticKeys::load_or_create(&cfg.identity.dir)
        .map_err(|e| anyhow::anyhow!("loading static keys: {e}"))?;
    tracing::info!(
        cert_fp = %tls.fingerprint(),
        pubkey = %keys.public_b64(),
        "client identity"
    );

    let joined = {
        let cfg = cfg.clone();
        let tls = tls.clone();
        let keys = keys.clone();
        tokio::task::spawn_blocking(move || coordlink::join_with_backoff(&cfg, &tls, &keys))
            .await??
    };
    tracing::info!(
        node_id = joined.node_id,
        addresses = ?joined.addresses,
        relays = joined.relays.len(),
        "joined {}",
        cfg.network_id
    );

    // Claim the endpoint role for this network on this host before
    // touching any kernel state. A second endpoint would silently
    // overwrite our routes, so failing loudly here beats debugging
    // one-way traffic later. Held for the process lifetime; --dry-run
    // touches nothing and so needs no claim.
    let _endpoint_lock = if cli.dry_run {
        None
    } else {
        Some(nqvpn_client::endpoint_guard::EndpointGuard::acquire(
            &cfg.network_id,
            &format!("client {}", cfg.client_id),
        )?)
    };

    // TUN + routes.
    let tun: Arc<dyn TunDevice> = if cli.dry_run {
        tracing::warn!("--dry-run: using an in-memory TUN, no kernel state touched");
        nqvpn_client::tun::FakeTun::new(joined.mtu)
    } else {
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
            anyhow::bail!("this platform has no TUN backend yet; use --dry-run")
        }
    };

    tracing::info!(
        device = %tun.name(), mtu = joined.mtu, transport = %joined.transport,
        "TUN ready"
    );

    let mut table = PeerTable::new(joined.node_id);
    table.set_mine(joined.addresses.clone());
    let engine = Engine::new(
        joined.node_id,
        joined.network_uuid.clone(),
        keys,
        table,
        joined.mtu,
        joined.lanes.max(1),
    );

    let routes: Arc<dyn Fn(Vec<ipnet::IpNet>) + Send + Sync> = if cli.dry_run {
        let set = Arc::new(RouteSet::new(RecordingProgrammer::default()));
        Arc::new(move |wanted| {
            if let Err(e) = set.apply(&wanted) {
                tracing::warn!("route apply failed: {e:#}");
            }
        })
    } else {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let device = tun.name();
            let set = Arc::new(RouteSet::new(SystemProgrammer { device }));
            // Repair routes another writer removed or stole. A second
            // nqvpn endpoint on this host claims the same member
            // prefixes, and a vanishing TUN takes every route pointing
            // at it — in both cases our cache still says "installed", so
            // the diff in `apply` has nothing to fix.
            let reconciler = set.clone();
            let watchdog = set.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_secs(20));
                loop {
                    t.tick().await;
                    if let Err(e) = watchdog.reassert() {
                        tracing::warn!("route re-assert failed: {e:#}");
                    }
                }
            });
            RECONCILE.set(Box::new(move |wanted: Vec<ipnet::IpNet>| {
                // Membership may have changed arbitrarily while the
                // control session was down, so return the table to the
                // snapshot instead of trusting anything cached.
                if let Err(e) = reconciler.reconcile(&wanted) {
                    tracing::warn!("route reconcile failed: {e:#}");
                }
            }))
            .ok();
            Arc::new(move |wanted| {
                if let Err(e) = set.apply(&wanted) {
                    tracing::warn!("route apply failed: {e:#}");
                }
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            Arc::new(|_| {})
        }
    };

    // Credential lives behind a lock so renewal reaches the uplink
    // manager, which may be mid-retry when it fires (§3.3).
    let credential = Arc::new(Mutex::new(joined.credential.clone()));
    let up = uplink::RelayUplink::new();
    // Last MTU we applied to the device, so a repeated push is a no-op.
    let applied_mtu = Arc::new(std::sync::atomic::AtomicU64::new(joined.mtu as u64));

    // Keep the measured uplink MTU fresh: QUIC's discovery is ongoing,
    // so this can move while we run.
    {
        let u = up.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(10));
            loop {
                t.tick().await;
                u.refresh_usable_mtu();
            }
        });
    }
    let fleet: Arc<Mutex<Vec<RelayEntry>>> = Arc::new(Mutex::new(joined.relays.clone()));

    // Task 2: outbound pump (TUN -> engine -> uplink).
    {
        let mut reader = tun.reader();
        let e = engine.clone();
        let u = up.clone();
        let t = tun.clone();
        tokio::spawn(async move {
            while let Some(pkt) = reader.recv().await {
                e.outbound(pkt, u.as_ref(), t.as_ref());
            }
        });
    }

    // Task 4: uplink manager — attach, watch, re-attach elsewhere.
    {
        let (e, u, f, t) = (engine.clone(), up.clone(), fleet.clone(), tun.clone());
        let (tls2, cred, ka) =
            (tls.clone(), credential.clone(), joined.keepalive_secs.max(1) as u64);
        let preferred = cfg.relay.preferred_relay_id.clone();
        let mode = nqvpn_proto::transport::Mode::parse(&joined.transport);
        let lanes = joined.lanes.max(1);
        let mtu = joined.mtu;
        tokio::spawn(async move {
            // Consecutive failures, for backoff. Reset by an attach that
            // actually carried traffic, not merely one that connected —
            // a relay that accepts and immediately drops us should not
            // look like success.
            let mut failures: u32 = 0;
            loop {
                let candidates = f.lock().unwrap().clone();
                if candidates.is_empty() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let Some(entry) =
                    uplink::choose_relay(&candidates, preferred.as_deref(), &tls2).await
                else {
                    tracing::warn!("no reachable relay; retrying");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    continue;
                };
                let token = cred.lock().unwrap().clone();
                match uplink::attach(&entry, &token, &tls2, ka, mode, lanes).await {
                    Ok((conn, chan)) => {
                        tracing::info!(
                            relay = %entry.name, addr = %entry.addr,
                            transport = chan.mode().as_str(), "attached"
                        );
                        chan.check_mtu(mtu);
                        let attached_at = std::time::Instant::now();
                        u.set(Some(conn.clone()), Some(chan.clone()), Some(entry.name.clone()));
                        // Task 3: inbound pump, for this connection's life.
                        // The lane a frame arrived on carries no meaning
                        // for an endpoint: it is the peer's choice, and
                        // we are the destination, not a forwarder.
                        while let Some((d, _lane)) = chan.recv().await {
                            e.inbound(&d, u.as_ref(), t.as_ref());
                        }
                        tracing::warn!(relay = %entry.name, "uplink lost; re-attaching");
                        u.set(None, None, None);
                        // An attach that lasted is evidence the relay is
                        // healthy, so start the next search fresh.
                        if attached_at.elapsed() >= Duration::from_secs(30) {
                            failures = 0;
                        } else {
                            failures = failures.saturating_add(1);
                        }
                    }
                    Err(err) => {
                        // Back off rather than hammering a relay that is
                        // down: with several relays in the fleet, a flat
                        // retry means every client re-probing all of them
                        // twice a second for the whole outage.
                        failures = failures.saturating_add(1);
                        let wait = nqvpn_proto::joinapi::retry_delay(false, failures);
                        tracing::warn!(
                            relay = %entry.name, retry_in_secs = wait.as_secs(),
                            "attach failed: {err:#}"
                        );
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        });
    }

    // Credential renewal (§9 task 1): a client that never renews keeps
    // working on its existing uplink but cannot attach anywhere new.
    {
        let (cfg2, tls2, keys2, cred2) =
            (cfg.clone(), tls.clone(), engine.keys.clone(), credential.clone());
        let mut wait = nqvpn_proto::credential::renew_after_secs(&joined.credential);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(wait)).await;
                let (c, t, k) = (cfg2.clone(), tls2.clone(), keys2.clone());
                match tokio::task::spawn_blocking(move || {
                    coordlink::join_with_backoff(&c, &t, &k)
                })
                .await
                {
                    Ok(Ok(j)) => {
                        wait = nqvpn_proto::credential::renew_after_secs(&j.credential);
                        *cred2.lock().unwrap() = j.credential;
                        tracing::info!(next_in_secs = wait, "credential renewed");
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

    // Rekey sweep (§4: sessions are replaced, never repaired).
    {
        let e = engine.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(2));
            loop {
                t.tick().await;
                e.expire_sessions();
            }
        });
    }

    // Task 5: status.
    if cli.status_secs > 0 {
        let (e, u) = (engine.clone(), up.clone());
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(cli.status_secs));
            loop {
                t.tick().await;
                let attached = u.attached_to.lock().unwrap().clone();
                let (tx_dropped, tx_too_large) = u.transport_counters();
                tracing::info!(
                    "status: {} relay={:?} tx_dropped={} tx_too_large={}",
                    e.status_line(), attached, tx_dropped, tx_too_large
                );
            }
        });
    }

    // Task 1: coordinator link, reconnecting with backoff.
    let mut joined = joined;
    let mut delay = Duration::from_secs(1);
    loop {
        let started = std::time::Instant::now();
        let f = fleet.clone();
        let on_relays = move |relays: Vec<RelayEntry>| {
            *f.lock().unwrap() = relays;
        };
        let device = tun.name();
        let current_mtu = applied_mtu.clone();
        let on_mtu = move |m: nqvpn_proto::control::NetworkMtu| {
            let prev = current_mtu.swap(m.mtu as u64, std::sync::atomic::Ordering::Relaxed);
            if prev == m.mtu as u64 {
                return;
            }
            match nqvpn_client::routes::set_device_mtu(&device, m.mtu) {
                Ok(()) => tracing::info!(
                    device = %device, mtu = m.mtu, limited_by = %m.limited_by,
                    "tunnel MTU updated from the network minimum"
                ),
                Err(e) => tracing::warn!("could not set MTU on {device}: {e:#}"),
            }
        };
        match coordlink::run_session(
            cfg.clone(),
            tls.clone(),
            engine.clone(),
            &joined,
            on_relays,
            on_mtu,
            up.usable_mtu_handle(),
            routes.clone(),
        )
        .await
        {
            Ok(()) => tracing::warn!("coordinator session ended; reconnecting"),
            Err(e) => tracing::warn!("coordinator session lost: {e:#}"),
        }
        // Reset the backoff only after a session that actually lasted.
        // Re-joining always succeeds while the coordinator is up, so
        // resetting on the join alone meant a control session failing
        // instantly retried once a second forever, and the exponential
        // backoff was dead code.
        let was_healthy = started.elapsed() >= Duration::from_secs(30);
        tokio::time::sleep(delay).await;
        delay = if was_healthy {
            Duration::from_secs(1)
        } else {
            (delay * 2).min(Duration::from_secs(30))
        };

        // Re-join, and never give up.
        //
        // A terminal rejection here used to propagate out of `run` and
        // end the process — so a client whose pin an admin reset, or who
        // was briefly disabled, died and stayed dead until somebody
        // noticed and restarted it by hand. Every one of those conditions
        // is fixed at the coordinator, and the only way to learn of the
        // fix is to ask again.
        let mut terminal_attempts: u32 = 0;
        loop {
            let (c, t2, k) = (cfg.clone(), tls.clone(), engine.keys.clone());
            match tokio::task::spawn_blocking(move || coordlink::join_with_backoff(&c, &t2, &k))
                .await?
            {
                Ok(j) => {
                    if terminal_attempts > 0 {
                        tracing::info!(
                            attempts = terminal_attempts,
                            "re-join succeeded; the coordinator-side problem was resolved"
                        );
                    }
                    joined = j;
                    break;
                }
                Err(e) => {
                    terminal_attempts += 1;
                    let wait = nqvpn_proto::joinapi::retry_delay(true, terminal_attempts);
                    tracing::error!(
                        attempt = terminal_attempts, retry_in_secs = wait.as_secs(),
                        "re-join rejected: {e:#} — this needs fixing at the coordinator; \
                         retrying until it is"
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
        *credential.lock().unwrap() = joined.credential.clone();

        // Fresh membership in hand: rebuild the routing table rather than
        // diffing against a cache that may no longer match the kernel.
        // This is the only place a reset is warranted — losing the relay
        // uplink changes the path, not the routes.
        if let Some(reconcile) = RECONCILE.get() {
            let wanted = engine.peers.lock().unwrap().all_prefixes();
            reconcile(wanted);
        }
    }
}
