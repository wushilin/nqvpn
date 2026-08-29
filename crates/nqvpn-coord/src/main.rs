use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use nqvpn_coord::api;
use nqvpn_coord::config::{load_coord_config, load_networks, read_bearer_token};
use nqvpn_coord::registry::Registry;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{self, now_unix, AppState, NetState};
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
    /// Print a freshly generated member secret.
    Secret,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Secret => {
            println!("{}", nqvpn_coord::secrets::generate_secret());
            Ok(())
        }
        Cmd::Run { config, networks } => run(config, networks).await,
    }
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
        networks.insert(cfg.network_id.clone(), Mutex::new(NetState::new(cfg, registry, registry_path)));
    }

    let admin_token = read_bearer_token(&coord.admin)?;
    if admin_token.is_none() {
        tracing::warn!("no admin bearer token configured — admin endpoints disabled");
    }

    // One identity for both the HTTPS API and the QUIC control port:
    // from [tls] if the operator has a real certificate, else generated
    // into the state dir. Members accept it by default.
    let identity = match &coord.tls {
        Some(t) => load_pem_identity(&t.cert, &t.key)?,
        None => {
            let id = TlsIdentity::load_or_create(&state_dir, "nqvpn-coordinator")
                .context("loading coordinator TLS identity")?;
            tracing::info!(
                fingerprint = %id.fingerprint(),
                "no [tls] configured: serving a self-signed certificate (members accept it by default)"
            );
            id
        }
    };

    let api_addr: SocketAddr = coord.listen.api.parse().context("parsing listen.api")?;
    let quic_addr: SocketAddr = coord.listen.quic.parse().context("parsing listen.quic")?;
    let secrets_path = state_dir.join("secrets.toml");
    let secrets = nqvpn_coord::secrets::SecretStore::load_or_create(&secrets_path).context("loading secrets.toml")?;
    tracing::info!(path = %secrets_path.display(), count = secrets.members.len(), "secret store loaded");

    let state = Arc::new(AppState {
        coord,
        admin_token,
        networks,
        keyring,
        join_rate: Mutex::new(Default::default()),
        networks_dir: Some(networks_dir.clone()),
        secrets: Mutex::new(secrets),
        secrets_path,
        control_port: quic_addr.port(),
    });

    {
        let s = state.clone();
        let id = identity.clone();
        tokio::spawn(async move {
            if let Err(e) = nqvpn_coord::control::run(s, quic_addr, id).await {
                tracing::error!("control plane stopped: {e:#}");
            }
        });
        tokio::spawn(nqvpn_coord::control::liveness_sweep(state.clone()));
    }

    let app = api::router(state);
    let tls = axum_server::tls_rustls::RustlsConfig::from_der(
        vec![identity.cert_der.clone()],
        identity.private_key().secret_der().to_vec(),
    )
    .await
    .context("building HTTPS config")?;
    tracing::info!(%api_addr, "coordinator HTTPS API listening");
    axum_server::bind_rustls(api_addr, tls)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
    Ok(())
}

fn load_pem_identity(cert: &str, key: &str) -> Result<TlsIdentity> {
    let cert_pem = std::fs::read(cert).with_context(|| format!("reading {cert}"))?;
    let key_pem = std::fs::read(key).with_context(|| format!("reading {key}"))?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {cert}"))?;
    let leaf = certs.first().context("no certificate in [tls].cert")?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .with_context(|| format!("parsing {key}"))?
        .context("no private key in [tls].key")?;
    TlsIdentity::from_der(leaf.to_vec(), key.secret_der().to_vec()).map_err(|e| anyhow::anyhow!("{e}"))
}
