//! `nqvpn-forward` — a UDP forwarder in front of one relay. See `lib.rs`.

use anyhow::Result;
use clap::Parser;
use nqvpn_forward::{Forwarder, Options};
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "nqvpn-forward",
    version,
    about = "nqvpn forwarder: relays UDP byte for byte to one relay, for clients that reach this host more easily",
    after_help = "Clients use it with --relay-via <relay-name>=<this-host>:<port>; they still verify the relay's certificate."
)]
struct Cli {
    /// The relay to forward to, host:port (its advertised QUIC address).
    #[arg(required_unless_present_any = ["self_update", "check_update"])]
    target: Option<String>,
    /// Where to listen for clients.
    #[arg(long, default_value = "0.0.0.0:44449")]
    bind: SocketAddr,
    /// Close a flow after this many seconds without traffic. Keep it above
    /// the network's keepalive × 5 (the QUIC idle timeout).
    #[arg(long, default_value_t = 120)]
    idle_secs: u64,
    /// At most this many concurrent clients; datagrams from more are dropped.
    #[arg(long, default_value_t = 4096)]
    max_flows: usize,
    /// Look the target up again this often, so a relay that moves is followed.
    #[arg(long, default_value_t = 60)]
    resolve_secs: u64,
    /// Print a status line every N seconds (0 = off).
    #[arg(long, default_value_t = 0)]
    status_secs: u64,
    #[command(flatten)]
    update: nqvpn_update::UpdateArgs,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Some(done) = nqvpn_update::run_if_requested(&cli.update, "nqvpn-forward", env!("CARGO_PKG_VERSION")) {
        return done;
    }
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> Result<()> {
    let target = cli.target.expect("clap requires it");
    let opts = Options {
        target: target.clone(),
        idle: Duration::from_secs(cli.idle_secs.max(1)),
        max_flows: cli.max_flows.max(1),
        resolve_every: Duration::from_secs(cli.resolve_secs.max(1)),
    };
    let fwd = Forwarder::bind(cli.bind, opts).await?;
    tracing::info!(listen = %fwd.local_addr()?, %target, "forwarding");
    if cli.status_secs > 0 {
        let f = fwd.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(cli.status_secs));
            loop {
                t.tick().await;
                tracing::info!("status: {}", f.status_line());
            }
        });
    }
    tokio::select! {
        r = fwd.run() => r,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
