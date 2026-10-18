//! Self-update from GitHub releases.
//!
//! `--check-update` asks GitHub for the latest release and says whether it
//! is newer than this binary. `--self-update` then downloads this
//! platform's signed manifest (`nqvpn-<version>-<os>-<arch>.tar.gz.sig`)
//! and checks its Ed25519 signature against the release keys compiled into
//! this binary (`release-keys.txt`) before anything else: the manifest must
//! name exactly this release's version and this platform's archive, and
//! only then is the archive downloaded and checked against the signed
//! SHA-256. From there it takes out the one binary it replaces, runs it
//! once (`--version`) to prove it executes here, and renames it over the
//! current executable. The rename is atomic and leaves the running process
//! on the old inode, exactly like a manual `mv` deploy: the new code runs
//! from the next restart. The previous binary is kept beside it as
//! `<name>.old`.
//!
//! The release's `.sha256` files are for people; they come from the same
//! place as the archive, so they prove nothing about who built it and are
//! not consulted. With no release key compiled in, `--self-update` refuses
//! to install anything.
//!
//! HTTPS is blocking std I/O over rustls against the public CA roots — the
//! same shape as the member join client — so the static binaries carry no
//! HTTP stack for a once-in-a-while download.

use anyhow::{bail, ensure, Context, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// The GitHub repository releases are published to.
pub const REPO: &str = "wushilin/nqvpn";
const MAX_API_BYTES: usize = 1 << 20;
const MAX_ASSET_BYTES: usize = 128 << 20;
const MAX_REDIRECTS: usize = 5;

/// The first line of every release manifest: what the signature is for, so
/// a release key's signature over anything else can never pass as one.
pub const RELEASE_CONTEXT: &str = "nqvpn-release-v1";
/// The trusted release public keys, one per line (see the file).
const RELEASE_KEYS: &str = include_str!("../release-keys.txt");

/// The update flags, shared by every binary (`#[command(flatten)]`).
#[derive(clap::Args, Debug, Clone, Default)]
pub struct UpdateArgs {
    /// Replace this binary with the latest GitHub release, then exit. The
    /// old binary is kept as <name>.old; a running service keeps the old
    /// code until it is restarted.
    #[arg(long)]
    pub self_update: bool,
    /// Report whether a newer release exists on GitHub, then exit.
    /// Changes nothing.
    #[arg(long, conflicts_with = "self_update")]
    pub check_update: bool,
}

impl UpdateArgs {
    pub fn requested(&self) -> bool {
        self.self_update || self.check_update
    }
}

/// Run the requested update action for `bin` (e.g. "nqvpn-relay") at
/// version `current`; `None` when no update flag was given.
pub fn run_if_requested(args: &UpdateArgs, bin: &str, current: &str) -> Option<Result<()>> {
    args.requested().then(|| run(args, bin, current))
}

fn run(args: &UpdateArgs, bin: &str, current: &str) -> Result<()> {
    let ua = format!("{bin}/{current} (+https://github.com/{REPO})");
    let (os, arch) = platform()?;
    let release = latest_release(REPO, &ua)?;
    let latest = release.version().to_string();
    let newer = compare_versions(&latest, current)? == Ordering::Greater;
    if args.check_update {
        if newer {
            println!("{bin} {current}: {latest} is available ({}); run with --self-update to install it", release.html_url);
        } else {
            println!("{bin} {current} is up to date (latest release {latest})");
        }
        return Ok(());
    }
    if !newer {
        println!("{bin} {current} is up to date (latest release {latest}); nothing to do");
        return Ok(());
    }
    // Before any download: an update that cannot be authenticated is
    // refused, never installed on the strength of a checksum alone.
    let keys = trusted_keys()?;
    let exe = std::env::current_exe()
        .context("locating this executable")?
        .canonicalize()
        .context("resolving this executable's path")?;
    let archive_name = asset_name(&latest, os, arch);
    let archive = release.asset(&archive_name).with_context(|| {
        format!("release {} has no build for {os}-{arch} (expected {archive_name})", release.tag_name)
    })?;
    let signature = release
        .asset(&format!("{archive_name}.sig"))
        .with_context(|| format!("release {} has no {archive_name}.sig: it is not signed", release.tag_name))?;
    let sig = get(&signature.browser_download_url, &ua, "application/octet-stream", MAX_API_BYTES)?;
    let manifest = verify_manifest(&String::from_utf8_lossy(&sig), &keys)?;
    manifest.check(&latest, &archive_name)?;
    ensure!(
        compare_versions(&manifest.version, current)? == Ordering::Greater,
        "signed release {} is not newer than {current}",
        manifest.version
    );
    println!("{bin} {current} -> {latest}: downloading {archive_name} (signature verified)");
    let bytes = get(&archive.browser_download_url, &ua, "application/octet-stream", MAX_ASSET_BYTES)?;
    manifest.check_archive(&bytes)?;
    let binary = extract(&bytes, bin)?;
    let old = replace_binary(&exe, &binary, &latest)?;
    println!("installed {latest} at {} (previous binary kept as {})", exe.display(), old.display());
    println!("restart the service to run it");
    Ok(())
}

// ---------------------------------------------------------------- releases

#[derive(Debug, serde::Deserialize)]
pub struct Release {
    pub tag_name: String,
    #[serde(default)]
    pub html_url: String,
    #[serde(default)]
    pub assets: Vec<Asset>,
}

#[derive(Debug, serde::Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
}

impl Release {
    /// The tag without its leading `v`.
    pub fn version(&self) -> &str {
        self.tag_name.strip_prefix('v').unwrap_or(&self.tag_name)
    }
    fn asset(&self, name: &str) -> Option<&Asset> {
        self.assets.iter().find(|a| a.name == name)
    }
}

/// The newest published (non-draft, non-prerelease) release.
pub fn latest_release(repo: &str, user_agent: &str) -> Result<Release> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let body = get(&url, user_agent, "application/vnd.github+json", MAX_API_BYTES)?;
    serde_json::from_slice(&body).context("reading the GitHub release")
}

/// This build's `(os, arch)` as release archives name them.
pub fn platform() -> Result<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        os @ ("linux" | "macos" | "freebsd") => os,
        other => bail!("no release builds for {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => bail!("no release builds for {other}"),
    };
    Ok((os, arch))
}

pub fn asset_name(version: &str, os: &str, arch: &str) -> String {
    format!("nqvpn-{version}-{os}-{arch}.tar.gz")
}

/// Compare dotted numeric versions (`0.10.0` > `0.9.3`); a pre-release or
/// build suffix after `-` / `+` is ignored.
pub fn compare_versions(a: &str, b: &str) -> Result<Ordering> {
    fn parts(v: &str) -> Result<Vec<u64>> {
        let core = v.split(['-', '+']).next().unwrap_or(v);
        core.split('.').map(|p| p.parse::<u64>().with_context(|| format!("not a version: {v:?}"))).collect()
    }
    let (mut x, mut y) = (parts(a)?, parts(b)?);
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    Ok(x.cmp(&y))
}

// ------------------------------------------------------------- verification

/// What a release signature vouches for: one archive of one version. The
/// `.sig` file is the signed text followed by the signature line:
///
/// ```text
/// nqvpn-release-v1
/// version 0.6.1
/// file nqvpn-0.6.1-linux-amd64.tar.gz
/// sha256 <64 lowercase hex>
/// signature <base64 Ed25519 signature over the four lines above>
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub file: String,
    pub sha256: String,
}

impl Manifest {
    /// The manifest for `archive` (its bytes) named `file`.
    pub fn new(version: &str, file: &str, archive: &[u8]) -> Self {
        Manifest { version: version.into(), file: file.into(), sha256: hex::encode(Sha256::digest(archive)) }
    }

    /// The exact bytes that are signed, newline-terminated.
    pub fn signed_text(&self) -> String {
        format!("{RELEASE_CONTEXT}\nversion {}\nfile {}\nsha256 {}\n", self.version, self.file, self.sha256)
    }

    /// The `.sig` file contents for this manifest, signed with `key`.
    pub fn sign(&self, key: &SigningKey) -> String {
        let text = self.signed_text();
        let sig = key.sign(text.as_bytes());
        format!("{text}signature {}\n", B64.encode(sig.to_bytes()))
    }

    /// The manifest is for exactly this version and this archive name —
    /// a validly signed manifest for another release or platform (an old
    /// one replayed, a mix-and-match of assets) is refused.
    pub fn check(&self, version: &str, file: &str) -> Result<()> {
        ensure!(self.version == version, "signed manifest is for version {}, the release is {version}", self.version);
        ensure!(self.file == file, "signed manifest is for {}, expected {file}", self.file);
        Ok(())
    }

    /// The downloaded archive is the one that was signed.
    pub fn check_archive(&self, archive: &[u8]) -> Result<()> {
        let actual = hex::encode(Sha256::digest(archive));
        ensure!(actual == self.sha256, "checksum mismatch: downloaded {actual}, signed manifest says {}", self.sha256);
        Ok(())
    }
}

/// The release keys compiled into this binary; an error when there are
/// none, so self-update fails closed.
pub fn trusted_keys() -> Result<Vec<VerifyingKey>> {
    parse_keys(RELEASE_KEYS)
}

/// One Ed25519 public key per line, base64 or hex; `#` comments and blank
/// lines ignored. A malformed line is an error, not skipped.
pub fn parse_keys(text: &str) -> Result<Vec<VerifyingKey>> {
    let mut keys = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        keys.push(parse_public_key(line).with_context(|| format!("release-keys.txt line {}", n + 1))?);
    }
    ensure!(
        !keys.is_empty(),
        "this build has no release signing key, so it cannot verify updates and will not install any. \
         Configure one: run `nqvpn-release-sign keygen`, add the public key it prints to \
         crates/nqvpn-update/release-keys.txt, and rebuild (or update by hand from a release you trust)"
    );
    Ok(keys)
}

/// A public key as base64 or 64 hex digits.
pub fn parse_public_key(s: &str) -> Result<VerifyingKey> {
    let raw = if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(s).ok()
    } else {
        B64.decode(s).ok()
    };
    let bytes: [u8; 32] = raw.and_then(|v| v.try_into().ok()).context("not a 32-byte Ed25519 public key")?;
    VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 public key")
}

/// Check a `.sig` file's signature against `keys` (any one suffices) and
/// return the manifest it signs. Nothing in it is trusted before the
/// signature verifies.
pub fn verify_manifest(sig_file: &str, keys: &[VerifyingKey]) -> Result<Manifest> {
    ensure!(!keys.is_empty(), "no release signing key to verify the update with");
    let body = sig_file.strip_suffix('\n').unwrap_or(sig_file);
    let (signed, last) = body.rsplit_once('\n').context("malformed .sig file")?;
    let signed = format!("{signed}\n");
    let sig = last.strip_prefix("signature ").context("malformed .sig file: no signature line")?;
    let sig = B64.decode(sig.trim()).ok().and_then(|b| Signature::from_slice(&b).ok());
    let sig = sig.context("malformed .sig file: bad signature encoding")?;
    ensure!(
        keys.iter().any(|k| k.verify_strict(signed.as_bytes(), &sig).is_ok()),
        "the release signature does not verify against any trusted release key: refusing to install"
    );
    // Signed, so these are the signer's words; still parse them strictly
    // and insist on the one canonical form.
    let mut lines = signed.lines();
    ensure!(lines.next() == Some(RELEASE_CONTEXT), "signed text is not an nqvpn release manifest");
    let mut field = |name: &str| -> Result<String> {
        let line = lines.next().unwrap_or("");
        let v = line.strip_prefix(name).and_then(|r| r.strip_prefix(' '));
        v.map(str::to_string).with_context(|| format!("signed manifest: expected {name:?}, got {line:?}"))
    };
    let m = Manifest { version: field("version")?, file: field("file")?, sha256: field("sha256")? };
    ensure!(
        m.sha256.len() == 64 && m.sha256.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
        "signed manifest: malformed sha256"
    );
    ensure!(m.signed_text() == signed, "signed manifest is not in canonical form");
    Ok(m)
}

/// The file named `bin` from a `.tar.gz`, wherever it sits in the archive.
pub fn extract(targz: &[u8], bin: &str) -> Result<Vec<u8>> {
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(targz));
    for entry in archive.entries().context("reading the archive")? {
        let mut entry = entry.context("reading the archive")?;
        if entry.path()?.file_name().and_then(|n| n.to_str()) == Some(bin) {
            let mut out = Vec::new();
            entry.read_to_end(&mut out).context("unpacking")?;
            return Ok(out);
        }
    }
    bail!("the archive does not contain {bin}")
}

// ------------------------------------------------------------- installation

/// Swap `new` in for the executable at `exe`, after proving it runs and
/// reports `version`. Returns where the previous binary was kept.
pub fn replace_binary(exe: &Path, new: &[u8], version: &str) -> Result<PathBuf> {
    let name = exe.file_name().and_then(|n| n.to_str()).context("executable has no file name")?;
    // A fresh random name, created exclusively: a file or symlink someone
    // planted at a predictable `<name>.new` can never be written through.
    let mut nonce = [0u8; 8];
    rand::TryRng::try_fill_bytes(&mut rand::rngs::SysRng, &mut nonce).context("the OS random source failed")?;
    let staged = exe.with_file_name(format!(".{name}.new-{}", hex::encode(nonce)));
    let old = exe.with_file_name(format!("{name}.old"));
    let denied = |e: std::io::Error| {
        let dir = exe.parent().map(|d| d.display().to_string()).unwrap_or_default();
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!("no permission to write in {dir}: run as the user that owns the binary (e.g. with sudo)")
        } else {
            anyhow::Error::new(e).context(format!("writing in {dir}"))
        }
    };
    let mut opts = std::fs::OpenOptions::new();
    // create_new is O_CREAT|O_EXCL: it fails on anything already there,
    // a dangling symlink included, rather than following it.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o700);
    let mut f = opts.open(&staged).map_err(denied)?;
    let written = (|| {
        f.write_all(new)?;
        // On the open file, so the umask cannot narrow it.
        #[cfg(unix)]
        f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
        f.sync_all()
    })();
    drop(f);
    if let Err(e) = written {
        let _ = std::fs::remove_file(&staged);
        return Err(denied(e));
    }
    // A binary that cannot start here (wrong libc, arch, a truncated
    // file) must never replace one that can.
    let ran = std::process::Command::new(&staged).arg("--version").output();
    let reported = ran.as_ref().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if !ran.as_ref().is_ok_and(|o| o.status.success()) || !reported.split_whitespace().any(|w| w == version) {
        let _ = std::fs::remove_file(&staged);
        bail!("the downloaded binary does not run here or is not {version} (it said {:?})", reported.trim());
    }
    let swapped = (|| {
        let _ = std::fs::remove_file(&old);
        if std::fs::hard_link(exe, &old).is_err() {
            std::fs::copy(exe, &old)?;
        }
        std::fs::rename(&staged, exe)
    })();
    if let Err(e) = swapped {
        let _ = std::fs::remove_file(&staged);
        return Err(denied(e));
    }
    Ok(old)
}

// -------------------------------------------------------------------- https

/// GET `url`, following redirects (release assets redirect to GitHub's
/// object store), and return the body of the final 200.
fn get(url: &str, user_agent: &str, accept: &str, limit: usize) -> Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..=MAX_REDIRECTS {
        let resp = get_once(&url, user_agent, accept, limit)?;
        match resp.status {
            200 => return Ok(resp.body),
            301 | 302 | 303 | 307 | 308 => {
                url = resp.location.with_context(|| format!("GET {url}: redirect without a Location"))?;
            }
            s => {
                let text = String::from_utf8_lossy(&resp.body[..resp.body.len().min(300)]).trim().to_string();
                bail!("GET {url}: HTTP {s} {text}");
            }
        }
    }
    bail!("GET {url}: too many redirects")
}

struct Response {
    status: u16,
    location: Option<String>,
    body: Vec<u8>,
}

fn tls() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

fn get_once(url: &str, user_agent: &str, accept: &str, limit: usize) -> Result<Response> {
    let (host, port, path) = parse_url(url)?;
    let addrs: Vec<_> = (host.as_str(), port).to_socket_addrs().with_context(|| format!("resolving {host}"))?.collect();
    let mut sock = None;
    let mut last = None;
    for a in &addrs {
        match TcpStream::connect_timeout(a, Duration::from_secs(15)) {
            Ok(s) => {
                sock = Some(s);
                break;
            }
            Err(e) => last = Some(e),
        }
    }
    let sock = match (sock, last) {
        (Some(s), _) => s,
        (None, Some(e)) => return Err(e).with_context(|| format!("connecting to {host}:{port}")),
        (None, None) => bail!("{host} did not resolve"),
    };
    sock.set_read_timeout(Some(Duration::from_secs(60)))?;
    sock.set_write_timeout(Some(Duration::from_secs(30)))?;
    let name = rustls::pki_types::ServerName::try_from(host.clone()).with_context(|| format!("server name {host:?}"))?;
    let conn = rustls::ClientConnection::new(tls(), name)?;
    let mut stream = rustls::StreamOwned::new(conn, sock);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nAccept: {accept}\r\n\
         X-GitHub-Api-Version: 2022-11-28\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).with_context(|| format!("GET {url}"))?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                ensure!(raw.len() <= limit + 64 * 1024, "GET {url}: response larger than {limit} bytes");
            }
            // A peer that closes without close_notify: with Connection:
            // close that is the normal end of the body.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e).with_context(|| format!("GET {url}")),
        }
    }
    parse_response(&raw).with_context(|| format!("GET {url}"))
}

/// `https://host[:port]/path` -> (host, port, path).
fn parse_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url.strip_prefix("https://").with_context(|| format!("not an https URL: {url}"))?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().with_context(|| format!("bad port in {url}"))?),
        None => (authority, 443),
    };
    ensure!(!host.is_empty(), "no host in {url}");
    Ok((host.to_string(), port, path.to_string()))
}

fn parse_response(raw: &[u8]) -> Result<Response> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").context("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let body = &raw[split + 4..];
    let mut lines = head.lines();
    let status: u16 = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .context("malformed HTTP status line")?;
    let mut location = None;
    let mut chunked = false;
    let mut length = None;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match k.as_str() {
            "location" => location = Some(v.to_string()),
            "transfer-encoding" => chunked = v.to_ascii_lowercase().contains("chunked"),
            "content-length" => length = v.parse::<usize>().ok(),
            _ => {}
        }
    }
    let body = if chunked {
        dechunk(body).context("malformed chunked body")?
    } else if let Some(n) = length {
        ensure!(body.len() >= n, "body truncated: got {} of {n} bytes", body.len());
        body[..n].to_vec()
    } else {
        body.to_vec()
    };
    Ok(Response { status, location, body })
}

fn dechunk(mut rest: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let eol = rest.windows(2).position(|w| w == b"\r\n")?;
        let line = std::str::from_utf8(&rest[..eol]).ok()?;
        let size = usize::from_str_radix(line.split(';').next()?.trim(), 16).ok()?;
        rest = &rest[eol + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(rest.get(..size)?);
        rest = rest.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_compare_numerically() {
        assert_eq!(compare_versions("0.10.0", "0.9.3").unwrap(), Ordering::Greater);
        assert_eq!(compare_versions("0.5.0", "0.5.0").unwrap(), Ordering::Equal);
        assert_eq!(compare_versions("0.5", "0.5.0").unwrap(), Ordering::Equal);
        assert_eq!(compare_versions("0.4.9", "0.5.0").unwrap(), Ordering::Less);
        assert_eq!(compare_versions("1.0.0-rc1", "1.0.0").unwrap(), Ordering::Equal);
        assert!(compare_versions("latest", "0.5.0").is_err());
    }

    #[test]
    fn archives_are_named_per_platform() {
        assert_eq!(asset_name("0.5.0", "linux", "arm64"), "nqvpn-0.5.0-linux-arm64.tar.gz");
        let (os, arch) = platform().unwrap();
        assert!(["linux", "macos", "freebsd"].contains(&os) && ["amd64", "arm64"].contains(&arch));
    }

    #[test]
    fn urls_split_into_host_port_and_path() {
        assert_eq!(parse_url("https://api.github.com/repos/a/b").unwrap(), ("api.github.com".into(), 443, "/repos/a/b".into()));
        assert_eq!(parse_url("https://h:8443").unwrap(), ("h".into(), 8443, "/".into()));
        assert!(parse_url("http://plain.example/").is_err());
    }

    #[test]
    fn responses_parse_with_length_chunking_and_redirects() {
        let r = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA").unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"hello"[..]));
        let r = parse_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n").unwrap();
        assert_eq!(r.body, b"abcde");
        let r = parse_response(b"HTTP/1.1 302 Found\r\nLocation: https://objects.example/x\r\n\r\n").unwrap();
        assert_eq!((r.status, r.location.as_deref()), (302, Some("https://objects.example/x")));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
    }

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rand_core::UnwrapErr(rand::rngs::SysRng))
    }

    const FILE: &str = "nqvpn-0.6.1-linux-amd64.tar.gz";

    /// The whole client-side check, in the order `run` does it.
    fn accept(sig: &str, keys: &[VerifyingKey], version: &str, file: &str, archive: &[u8]) -> Result<Manifest> {
        let m = verify_manifest(sig, keys)?;
        m.check(version, file)?;
        m.check_archive(archive)?;
        Ok(m)
    }

    #[test]
    fn a_signed_release_is_accepted() {
        let sk = key();
        let sig = Manifest::new("0.6.1", FILE, b"archive").sign(&sk);
        assert!(sig.starts_with("nqvpn-release-v1\nversion 0.6.1\nfile nqvpn-0.6.1-linux-amd64.tar.gz\nsha256 "));
        let m = accept(&sig, &[sk.verifying_key()], "0.6.1", FILE, b"archive").unwrap();
        assert_eq!((m.version.as_str(), m.file.as_str()), ("0.6.1", FILE));
        // Any one of several trusted keys (rotation) is enough.
        let keys = [key().verifying_key(), sk.verifying_key()];
        accept(&sig, &keys, "0.6.1", FILE, b"archive").unwrap();
    }

    #[test]
    fn a_tampered_archive_is_rejected() {
        let sk = key();
        let sig = Manifest::new("0.6.1", FILE, b"archive").sign(&sk);
        assert!(accept(&sig, &[sk.verifying_key()], "0.6.1", FILE, b"archivE").is_err());
    }

    #[test]
    fn a_manifest_for_another_version_or_file_is_rejected() {
        let sk = key();
        let keys = [sk.verifying_key()];
        // A genuine old release replayed as the new one.
        let old = Manifest::new("0.6.0", "nqvpn-0.6.0-linux-amd64.tar.gz", b"archive").sign(&sk);
        assert!(accept(&old, &keys, "0.6.1", FILE, b"archive").is_err());
        // Another platform's archive in this platform's place.
        let other = Manifest::new("0.6.1", "nqvpn-0.6.1-linux-arm64.tar.gz", b"archive").sign(&sk);
        assert!(accept(&other, &keys, "0.6.1", FILE, b"archive").is_err());
    }

    #[test]
    fn edited_manifests_and_unknown_keys_are_rejected() {
        let sk = key();
        let sig = Manifest::new("0.6.1", FILE, b"archive").sign(&sk);
        assert!(accept(&sig, &[key().verifying_key()], "0.6.1", FILE, b"archive").is_err());
        // Any edit to the signed text breaks the signature.
        let edited = sig.replace("version 0.6.1", "version 0.6.2");
        assert!(verify_manifest(&edited, &[sk.verifying_key()]).is_err());
        let forged_hash = sig.replace(&Manifest::new("0.6.1", FILE, b"archive").sha256, &"0".repeat(64));
        assert!(verify_manifest(&forged_hash, &[sk.verifying_key()]).is_err());
        // A signature by a trusted key over something that is not a manifest.
        let text = "something else\n";
        let foreign = format!("{text}signature {}\n", B64.encode(sk.sign(text.as_bytes()).to_bytes()));
        assert!(verify_manifest(&foreign, &[sk.verifying_key()]).is_err());
        assert!(verify_manifest("garbage", &[sk.verifying_key()]).is_err());
    }

    #[test]
    fn without_a_release_key_nothing_verifies() {
        let sk = key();
        let sig = Manifest::new("0.6.1", FILE, b"archive").sign(&sk);
        assert!(verify_manifest(&sig, &[]).is_err());
        // A key file with only comments (as shipped) fails closed, with
        // directions.
        let e = parse_keys("# no keys yet\n\n  # really\n").unwrap_err().to_string();
        assert!(e.contains("release-keys.txt") && e.contains("keygen"), "{e}");
    }

    #[test]
    fn release_keys_parse_as_base64_or_hex() {
        let pk = key().verifying_key();
        let text = format!("# comment\n{}  # current\n\n{}\n", B64.encode(pk.to_bytes()), hex::encode(pk.to_bytes()));
        assert_eq!(parse_keys(&text).unwrap(), vec![pk, pk]);
        assert!(parse_keys("not-a-key\n").is_err());
        assert!(parse_keys(&B64.encode([1u8; 16])).is_err());
    }

    fn targz(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast()));
        for (name, data) in files {
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            builder.append_data(&mut h, name, *data).unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap()
    }

    #[test]
    fn the_named_binary_is_taken_from_the_archive() {
        let a = targz(&[("nqvpn-coord", b"coord"), ("nqvpn-relay", b"relay")]);
        assert_eq!(extract(&a, "nqvpn-relay").unwrap(), b"relay");
        assert!(extract(&a, "nqvpn-client").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_binary_is_replaced_only_by_one_that_runs_and_reports_the_version() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("nqvpn-relay");
        std::fs::write(&exe, "#!/bin/sh\necho nqvpn-relay 0.4.0\n").unwrap();
        std::fs::set_permissions(&exe, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

        // Wrong version: refused, nothing touched, nothing left behind.
        let wrong = b"#!/bin/sh\necho nqvpn-relay 0.4.1\n";
        assert!(replace_binary(&exe, wrong, "0.5.0").is_err());
        assert!(std::fs::read_to_string(&exe).unwrap().contains("0.4.0"));
        let names = || {
            let mut v: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
            v.sort();
            v
        };
        assert_eq!(names(), ["nqvpn-relay"]);

        // Does not run at all: refused.
        assert!(replace_binary(&exe, b"\x7fELF garbage", "0.5.0").is_err());

        // A stale or planted `<name>.new` symlink is never written through.
        let victim = dir.path().join("victim");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("nqvpn-relay.new")).unwrap();

        let good = b"#!/bin/sh\necho nqvpn-relay 0.5.0\n";
        let old = replace_binary(&exe, good, "0.5.0").unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("0.5.0"));
        assert!(std::fs::read_to_string(old).unwrap().contains("0.4.0"));
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777, 0o755);
        assert_eq!(names(), ["nqvpn-relay", "nqvpn-relay.new", "nqvpn-relay.old", "victim"]);
    }

    /// Talks to GitHub: `cargo test -p nqvpn-update -- --ignored`.
    #[test]
    #[ignore]
    fn the_latest_release_is_readable_from_github() {
        let r = latest_release(REPO, "nqvpn-update-test").unwrap();
        compare_versions(r.version(), "0.0.1").unwrap();
        assert!(!r.assets.is_empty());
    }
}
