//! Self-update from GitHub releases.
//!
//! `--check-update` asks GitHub for the latest release and says whether it
//! is newer than this binary. `--self-update` then downloads this
//! platform's archive (`nqvpn-<version>-<os>-<arch>.tar.gz`), checks it
//! against the release's `.sha256`, takes out the one binary it replaces,
//! runs it once (`--version`) to prove it executes here, and renames it
//! over the current executable. The rename is atomic and leaves the
//! running process on the old inode, exactly like a manual `mv` deploy:
//! the new code runs from the next restart. The previous binary is kept
//! beside it as `<name>.old`.
//!
//! HTTPS is blocking std I/O over rustls against the public CA roots — the
//! same shape as the member join client — so the static binaries carry no
//! HTTP stack for a once-in-a-while download.

use anyhow::{bail, ensure, Context, Result};
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
    let exe = std::env::current_exe()
        .context("locating this executable")?
        .canonicalize()
        .context("resolving this executable's path")?;
    let archive_name = asset_name(&latest, os, arch);
    let archive = release.asset(&archive_name).with_context(|| {
        format!("release {} has no build for {os}-{arch} (expected {archive_name})", release.tag_name)
    })?;
    let checksum = release
        .asset(&format!("{archive_name}.sha256"))
        .with_context(|| format!("release {} has no {archive_name}.sha256", release.tag_name))?;
    println!("{bin} {current} -> {latest}: downloading {archive_name}");
    let bytes = get(&archive.browser_download_url, &ua, "application/octet-stream", MAX_ASSET_BYTES)?;
    let sums = get(&checksum.browser_download_url, &ua, "application/octet-stream", MAX_API_BYTES)?;
    verify_sha256(&bytes, &String::from_utf8_lossy(&sums))?;
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

/// Check `bytes` against a `shasum -a 256` line ("<hex>  <file>").
pub fn verify_sha256(bytes: &[u8], sums: &str) -> Result<()> {
    let expected = sums.split_whitespace().next().unwrap_or("").to_ascii_lowercase();
    ensure!(expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit()), "malformed .sha256 file");
    let actual = hex::encode(Sha256::digest(bytes));
    ensure!(actual == expected, "checksum mismatch: downloaded {actual}, release says {expected}");
    Ok(())
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
    let staged = exe.with_file_name(format!("{name}.new"));
    let old = exe.with_file_name(format!("{name}.old"));
    let denied = |e: std::io::Error| {
        let dir = exe.parent().map(|d| d.display().to_string()).unwrap_or_default();
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            anyhow::anyhow!("no permission to write in {dir}: run as the user that owns the binary (e.g. with sudo)")
        } else {
            anyhow::Error::new(e).context(format!("writing in {dir}"))
        }
    };
    {
        let mut f = std::fs::File::create(&staged).map_err(denied)?;
        f.write_all(new).map_err(denied)?;
        f.sync_all().map_err(denied)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(exe).map(|m| m.permissions().mode()).unwrap_or(0o755) | 0o555;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode)).map_err(denied)?;
    }
    // A binary that cannot start here (wrong libc, arch, a truncated
    // file) must never replace one that can.
    let ran = std::process::Command::new(&staged).arg("--version").output();
    let reported = ran.as_ref().map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    if !ran.as_ref().is_ok_and(|o| o.status.success()) || !reported.split_whitespace().any(|w| w == version) {
        let _ = std::fs::remove_file(&staged);
        bail!("the downloaded binary does not run here or is not {version} (it said {:?})", reported.trim());
    }
    let _ = std::fs::remove_file(&old);
    if std::fs::hard_link(exe, &old).is_err() {
        std::fs::copy(exe, &old).map_err(denied)?;
    }
    std::fs::rename(&staged, exe).map_err(denied)?;
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

    #[test]
    fn checksums_must_match() {
        let data = b"nqvpn";
        let good = format!("{}  nqvpn-0.5.0-linux-amd64.tar.gz\n", hex::encode(Sha256::digest(data)));
        verify_sha256(data, &good).unwrap();
        assert!(verify_sha256(b"tampered", &good).is_err());
        assert!(verify_sha256(data, "not-a-sum file").is_err());
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
        assert!(!dir.path().join("nqvpn-relay.new").exists());

        // Does not run at all: refused.
        assert!(replace_binary(&exe, b"\x7fELF garbage", "0.5.0").is_err());

        let good = b"#!/bin/sh\necho nqvpn-relay 0.5.0\n";
        let old = replace_binary(&exe, good, "0.5.0").unwrap();
        assert!(std::fs::read_to_string(&exe).unwrap().contains("0.5.0"));
        assert!(std::fs::read_to_string(old).unwrap().contains("0.4.0"));
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
