use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nqvpn_coord::config::{load_coord_config, load_networks, read_bearer_token};
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{self, now_unix, AppState, NetState};
use nqvpn_coord::api;
use nqvpn_proto::identity::TlsIdentity;

#[derive(Parser)]
#[command(name = "nqvpn-coord", about = "nqvpn coordinator (control plane)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the coordinator.
    Run {
        /// Path to coordinator.toml
        #[arg(long, default_value = "/etc/nqvpn/coordinator.toml")]
        config: PathBuf,
        /// Path to networks.d/ (default: <config dir>/networks.d)
        #[arg(long)]
        networks: Option<PathBuf>,
    },
    /// Argon2-hash a secret for config files (reads one line from stdin).
    Hash,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Hash => hash_secret(),
        Cmd::Run { config, networks } => run(config, networks).await,
    }
}

fn hash_secret() -> Result<()> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    use argon2::Argon2;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let secret = line.trim_end_matches(['\r', '\n']);
    anyhow::ensure!(!secret.is_empty(), "empty secret");
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing: {e}"))?;
    println!("{hash}");
    Ok(())
}

async fn run(config_path: PathBuf, networks_dir: Option<PathBuf>) -> Result<()> {
    let coord = load_coord_config(&config_path)?;
    let networks_dir = networks_dir.unwrap_or_else(|| {
        config_path.parent().unwrap_or(std::path::Path::new(".")).join("networks.d")
    });
    let net_cfgs = load_networks(&networks_dir)?;
    anyhow::ensure!(!net_cfgs.is_empty(), "no networks defined in {}", networks_dir.display());

    let state_dir = PathBuf::from(&coord.state.dir);
    std::fs::create_dir_all(&state_dir)
        .with_context(|| format!("creating state dir {}", state_dir.display()))?;

    let keyring = Keyring::load_or_create(&state_dir.join("signing.json"), now_unix())?;

    let mut networks = HashMap::new();
    for cfg in net_cfgs {
        let registry_path = state_dir.join(format!("registry-{}.json", cfg.network_id));
        let registry = Registry::load_or_create(&registry_path)?;
        for w in state::config_matches_registry(&cfg, &registry) {
            tracing::warn!("{}: {w}", cfg.network_id);
        }
        tracing::info!(
            network = %cfg.network_id,
            members = registry.members.len(),
            uuid = %registry.network_uuid,
            "network loaded"
        );
        networks.insert(
            cfg.network_id.clone(),
            Mutex::new(NetState::new(cfg, registry, registry_path)),
        );
    }

    let admin_token = read_bearer_token(&coord.admin)?;
    if admin_token.is_none() {
        tracing::warn!("no admin bearer token configured — admin endpoints disabled");
    }
    if coord.tls.is_some() {
        tracing::warn!(
            "[tls] configured but Phase 1 serves plain HTTP — terminate TLS with a \
             reverse proxy for now (native TLS lands with the QUIC control phase)"
        );
    }

    let api_addr: SocketAddr = coord.listen.api.parse().context("parsing listen.api")?;
    let quic_addr: Option<SocketAddr> = match &coord.listen.quic {
        Some(a) => Some(a.parse().context("parsing listen.quic")?),
        None => None,
    };
    // Managed secrets live beside the registry: coordinator-owned state,
    // not operator-edited config.
    let secrets_path = state_dir.join("secrets.toml");
    let secrets = nqvpn_coord::secrets::SecretStore::load_or_create(&secrets_path)
        .context("loading secrets.toml")?;
    tracing::info!(
        path = %secrets_path.display(),
        count = secrets.secrets.len(),
        "secret store loaded (network config secret_hash remains the fallback)"
    );

    let state = Arc::new(AppState {
        coord,
        admin_token,
        networks,
        keyring,
        join_rate: Mutex::new(HashMap::new()),
        networks_dir: Some(networks_dir.clone()),
        secrets: Mutex::new(secrets),
        secrets_path,
    });

    // QUIC control plane: the persistent push channel (§3.2).
    if let Some(addr) = quic_addr {
        let identity = TlsIdentity::load_or_create(&state_dir, "nqvpn-coordinator")
            .context("loading coordinator TLS identity")?;
        tracing::info!(
            "coordinator control fingerprint: {} (members pin this)",
            identity.fingerprint()
        );
        let s = state.clone();
        tokio::spawn(async move {
            if let Err(e) = nqvpn_coord::control::run(s, addr, identity).await {
                tracing::error!("control plane stopped: {e:#}");
            }
        });
        tokio::spawn(nqvpn_coord::control::liveness_sweep(state.clone()));
    } else {
        tracing::warn!("listen.quic not configured — control plane disabled (API only)");
    }

    let app = api::router(state);
    tracing::info!(%api_addr, "coordinator API listening");
    let listener = tokio::net::TcpListener::bind(api_addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
