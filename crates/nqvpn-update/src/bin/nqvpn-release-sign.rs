//! Release signing for `--self-update`.
//!
//!   nqvpn-release-sign keygen [--out nqvpn-release.key]
//!   nqvpn-release-sign sign --version X.Y.Z ARCHIVE...
//!
//! `keygen` makes an Ed25519 key: the secret goes to a new 0600 file (and
//! is printed once, for the CI secret), the public key is printed for
//! `crates/nqvpn-update/release-keys.txt`. `sign` writes `<archive>.sig`
//! beside each archive (see `nqvpn_update::Manifest`), with the secret
//! from `--key-file`, `$NQVPN_RELEASE_KEY_FILE` or `$NQVPN_RELEASE_KEY`
//! (the base64 secret itself, as CI passes it).

use anyhow::{bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use nqvpn_update::{trusted_keys, verify_manifest, Manifest};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(version, about = "Sign nqvpn release archives for --self-update")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a release signing key.
    Keygen {
        /// Where to write the secret key (must not exist).
        #[arg(long, default_value = "nqvpn-release.key")]
        out: PathBuf,
    },
    /// Write <archive>.sig for each archive.
    Sign {
        /// The release version (a leading `v` is ignored).
        #[arg(long)]
        version: String,
        /// File holding the base64 secret key; default $NQVPN_RELEASE_KEY_FILE,
        /// then the key itself from $NQVPN_RELEASE_KEY.
        #[arg(long)]
        key_file: Option<PathBuf>,
        #[arg(required = true)]
        archives: Vec<PathBuf>,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { out } => keygen(&out),
        Cmd::Sign { version, key_file, archives } => sign(version.trim_start_matches('v'), key_file, &archives),
    }
}

fn keygen(out: &Path) -> Result<()> {
    let sk = SigningKey::generate(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng));
    let secret = B64.encode(sk.to_bytes());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(out).with_context(|| format!("creating {}", out.display()))?;
    writeln!(f, "{secret}")?;
    f.sync_all()?;
    println!("secret key written to {} (mode 0600); keep it offline.", out.display());
    println!("secret key (for the NQVPN_RELEASE_KEY repository secret):\n  {secret}");
    println!("public key (add this line to crates/nqvpn-update/release-keys.txt):\n  {}", B64.encode(sk.verifying_key().to_bytes()));
    Ok(())
}

fn load_key(key_file: Option<PathBuf>) -> Result<SigningKey> {
    let file = key_file.or_else(|| std::env::var_os("NQVPN_RELEASE_KEY_FILE").filter(|v| !v.is_empty()).map(PathBuf::from));
    let text = match file {
        Some(p) => std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?,
        None => match std::env::var("NQVPN_RELEASE_KEY") {
            Ok(k) if !k.trim().is_empty() => k,
            _ => bail!("no signing key: pass --key-file, or set NQVPN_RELEASE_KEY_FILE or NQVPN_RELEASE_KEY"),
        },
    };
    let bytes: [u8; 32] = B64
        .decode(text.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .context("the signing key is not a base64 32-byte Ed25519 secret")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn sign(version: &str, key_file: Option<PathBuf>, archives: &[PathBuf]) -> Result<()> {
    let sk = load_key(key_file)?;
    let pk = sk.verifying_key();
    // Signing with a key the binaries do not trust would publish a release
    // no one can update to; catch it here rather than on every host.
    ensure!(
        trusted_keys().unwrap_or_default().contains(&pk),
        "this key's public half ({}) is not in crates/nqvpn-update/release-keys.txt: add it, commit, and rebuild",
        B64.encode(pk.to_bytes())
    );
    for path in archives {
        let name = path.file_name().and_then(|n| n.to_str()).with_context(|| format!("{}: no file name", path.display()))?;
        ensure!(
            name.starts_with(&format!("nqvpn-{version}-")) && name.ends_with(".tar.gz"),
            "{name} is not a {version} release archive (nqvpn-{version}-<os>-<arch>.tar.gz)"
        );
        let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let manifest = Manifest::new(version, name, &bytes);
        let sig = manifest.sign(&sk);
        ensure!(verify_manifest(&sig, &[pk])? == manifest, "signature did not round-trip");
        let out = path.with_file_name(format!("{name}.sig"));
        std::fs::write(&out, sig).with_context(|| format!("writing {}", out.display()))?;
        println!("{}  {}", out.display(), manifest.sha256);
    }
    Ok(())
}
