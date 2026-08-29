use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nqvpn_coord::api;
use nqvpn_coord::config::{load_coord_config, read_bearer_token};
use nqvpn_coord::db::Db;
use nqvpn_coord::signer::Keyring;
use nqvpn_coord::state::{now_unix, AppState};
use nqvpn_proto::identity::TlsIdentity;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "nqvpn-coord", about = "NetQ VPN coordinator")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the coordinator. Networks and members are created in the UI
    /// (or the API) and kept in the database; nothing else to configure.
    Run {
        /// Path to coordinator.toml
        #[arg(long, default_value = "/etc/nqvpn/coordinator.toml")]
        config: PathBuf,
    },
    /// Hash a password for `[admin] password_hash` (reads it from stdin
    /// if not given).
    HashPassword {
        #[arg(long)]
        password: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls is built with both ring and aws-lc-rs available (via
    // axum-server); pick ring process-wide so every TLS config agrees.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run { config } => run(config).await,
        Cmd::HashPassword { password } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    eprint!("password: ");
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s.trim_end_matches(['\r', '\n']).to_string()
                }
            };
            anyhow::ensure!(!pw.is_empty(), "empty password");
            println!("{}", nqvpn_coord::auth::hash_password(&pw).map_err(|e| anyhow::anyhow!(e))?);
            Ok(())
        }
    }
}

async fn run(config_path: PathBuf) -> Result<()> {
    let coord = load_coord_config(&config_path)?;
    let state_dir = PathBuf::from(&coord.state.dir);
    std::fs::create_dir_all(&state_dir).with_context(|| format!("creating state dir {}", state_dir.display()))?;

    let keyring = Keyring::load_or_create(&state_dir.join("signing.json"), now_unix())?;
    let db_path = state_dir.join("nqvpn.db");
    let db = Arc::new(Db::open(&db_path).with_context(|| format!("opening {}", db_path.display()))?);

    let admin_token = read_bearer_token(&coord.admin)?;
    match (&coord.admin.user, &coord.admin.password_hash, &admin_token) {
        (Some(u), Some(_), _) => tracing::info!(user = %u, "UI login enabled"),
        (_, _, Some(_)) => tracing::warn!("no [admin] user/password_hash: the UI cannot log in (the API accepts the bearer token)"),
        _ => tracing::warn!("no admin login configured — the UI and admin API are disabled"),
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

    let state = Arc::new(AppState::new(coord, admin_token, keyring, db.clone(), quic_addr.port()));
    let loaded = db.load_all().context("loading networks from the database")?;
    if loaded.is_empty() {
        tracing::info!(db = %db_path.display(), "no networks yet — create one in the UI at /ui");
    }
    for (cfg, registry) in loaded {
        tracing::info!(
            network = %cfg.network_id,
            members = cfg.members().count(),
            joined = registry.members.len(),
            uuid = %registry.network_uuid,
            "network loaded"
        );
        state.add_network(cfg, registry);
    }

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
