//! One task owns one QUIC connection (DESIGN.md §6, §7).
//!
//! Every hop — client↔relay and relay↔relay — is the same object from
//! both ends: a credential exchange at `Hello`, a control stream that
//! carries `Refresh` and hop-local probes, a credential expiry after
//! which the session ends, and a probe timeout that ends it when the far
//! end stops answering. There is exactly one way a session leaves any
//! table: this task returns. Nothing else evicts a session from outside.

use anyhow::{anyhow, Context, Result};
use bytes::Bytes;
use nqvpn_proto::control::{Hello, HelloAck, Refresh};
use nqvpn_proto::credential::Claims;
use nqvpn_proto::envelope::Kind;
use nqvpn_proto::frame::{Probe, T_PROBE, T_REPLY};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{client_config, peer_fingerprint};
use nqvpn_proto::stream::{parse, read_envelope, write_msg};
use nqvpn_proto::transport::{Mode, PacketChannel};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// Verifies a credential against the acceptor's knowledge of the network
/// (keys, uuid, disabled members, current login generation) and binds it
/// to the certificate the peer presented.
pub trait Verifier: Send + Sync {
    fn verify(&self, credential: &str, presented_fp: &str) -> Result<Claims>;
}

/// Application close codes, so a log line says why a session ended.
pub const CLOSE_EXPIRED: u32 = 6;
pub const CLOSE_PROBE_TIMEOUT: u32 = 7;
pub const CLOSE_REPLACED: u32 = 8;
pub const CLOSE_EVICTED: u32 = 9;
pub const CLOSE_SHUTDOWN: u32 = 10;
/// The peer's credential carries an older login generation than the
/// network's: another instance has joined as that member since.
pub const CLOSE_STALE_LOGIN: u32 = 11;

/// Returned by a [`Verifier`] for a credential whose login generation
/// is behind. `accept` turns it into a `CLOSE_STALE_LOGIN` close so the
/// far end can tell it apart from any other refusal and exit.
#[derive(Debug)]
pub struct StaleLogin(pub String);

impl std::fmt::Display for StaleLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for StaleLogin {}

/// `dial` failed because the far end closed the connection during the
/// handshake and said why.
#[derive(Debug)]
pub struct Refused {
    pub code: u32,
    pub reason: String,
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "refused (code {}): {}", self.code, self.reason)
    }
}

impl std::error::Error for Refused {}

fn app_close(conn: &quinn::Connection) -> Option<(u32, String)> {
    match conn.close_reason()? {
        quinn::ConnectionError::ApplicationClosed(a) => {
            Some((a.error_code.into_inner() as u32, String::from_utf8_lossy(&a.reason).into_owned()))
        }
        _ => None,
    }
}

/// Why `run` returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum End {
    /// The connection ended (peer closed it, transport died, or we
    /// closed it via `Session::close`).
    Closed,
    /// Credential expiry passed without a Refresh.
    Expired,
    /// The far end stopped answering probes.
    ProbeTimeout,
    /// The control stream carried something unacceptable.
    Protocol(String),
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Seconds between probes; 0 disables probing (the acceptor side
    /// usually answers probes rather than sending them).
    pub probe_secs: u64,
    /// Unanswered probes before the session is declared dead.
    pub probe_misses: u32,
}

impl Default for SessionConfig {
    fn default() -> Self {
        SessionConfig { probe_secs: 2, probe_misses: 5 }
    }
}

/// An authenticated connection with its control stream.
///
/// `peer` is who is on the other end. On the accepting side it comes
/// from the credential the peer presented (`claims`); on the dialing
/// side the caller already knows whom it dialed, and `claims` are its
/// own (what the far end holds for this session).
pub struct Session {
    pub conn: quinn::Connection,
    pub chan: Arc<PacketChannel>,
    pub peer: nqvpn_proto::types::NodeId,
    pub peer_role: nqvpn_proto::types::Role,
    pub claims: Claims,
    /// The peer's certificate fingerprint as presented.
    pub peer_fp: String,
    control_tx: Mutex<quinn::SendStream>,
    control_rx: Mutex<quinn::RecvStream>,
    exp: AtomicU64,
    login_gen: AtomicU64,
    /// Round-trip of the last answered probe, microseconds.
    pub rtt_us: AtomicU64,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    fn new(
        conn: quinn::Connection,
        chan: Arc<PacketChannel>,
        peer: nqvpn_proto::types::NodeId,
        peer_role: nqvpn_proto::types::Role,
        claims: Claims,
        peer_fp: String,
        tx: quinn::SendStream,
        rx: quinn::RecvStream,
    ) -> Arc<Session> {
        Arc::new(Session {
            conn,
            chan,
            peer,
            peer_role,
            exp: AtomicU64::new(claims.exp),
            login_gen: AtomicU64::new(claims.login_gen),
            claims,
            peer_fp,
            control_tx: Mutex::new(tx),
            control_rx: Mutex::new(rx),
            rtt_us: AtomicU64::new(0),
        })
    }

    /// The node on the other end of this session.
    pub fn node_id(&self) -> nqvpn_proto::types::NodeId {
        self.peer
    }

    /// Current credential expiry (unix seconds), as last refreshed.
    pub fn exp(&self) -> u64 {
        self.exp.load(Ordering::Relaxed)
    }

    /// Login generation of the credential currently bound to this
    /// session. A snapshot showing a newer one means this is a replaced
    /// instance.
    pub fn login_gen(&self) -> u64 {
        self.login_gen.load(Ordering::Relaxed)
    }

    /// End the session from outside; `run` returns `End::Closed`.
    /// Why the far end closed this session, if it did so deliberately:
    /// the application close code and reason it sent.
    pub fn close_reason(&self) -> Option<(u32, String)> {
        app_close(&self.conn)
    }

    pub fn close(&self, code: u32, reason: &str) {
        self.conn.close(code.into(), reason.as_bytes());
    }

    /// Member side: present a renewed credential so the far end extends
    /// this session's expiry.
    pub async fn refresh(&self, credential: &str) -> Result<()> {
        let mut tx = self.control_tx.lock().await;
        write_msg(&mut tx, Kind::Refresh, &Refresh { credential: credential.to_string() }).await?;
        if let Some(exp) = nqvpn_proto::credential::peek_exp(credential) {
            self.exp.store(exp, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Drive the session until it ends. `on_packet` receives every data
    /// frame (probes and their replies are consumed here). `verifier`
    /// is the acceptor's — it validates inbound `Refresh`; a dialer
    /// passes `None` and ignores inbound Refresh.
    pub async fn run(
        self: &Arc<Self>,
        cfg: &SessionConfig,
        verifier: Option<&dyn Verifier>,
        mut on_packet: impl FnMut(Bytes, u8),
    ) -> End {
        let mut rx = self.control_rx.lock().await;
        let mut probe_tick = tokio::time::interval(Duration::from_secs(cfg.probe_secs.max(1)));
        probe_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut outstanding: u32 = 0;
        let mut seq: u64 = 0;
        let started = Instant::now();
        loop {
            let exp_in = Duration::from_secs(self.exp().saturating_sub(now_unix()));
            tokio::select! {
                pkt = self.chan.recv() => {
                    let Some((d, lane)) = pkt else { return End::Closed };
                    match d.first().copied() {
                        Some(T_PROBE) => {
                            if let Some(p) = Probe::parse(&d) {
                                let _ = self.chan.send(p.into_reply().encode().into());
                            }
                        }
                        Some(T_REPLY) => {
                            if let Some(p) = Probe::parse(&d) {
                                outstanding = 0;
                                let now_us = started.elapsed().as_micros() as u64;
                                self.rtt_us.store(now_us.saturating_sub(p.t_sent), Ordering::Relaxed);
                            }
                        }
                        _ => on_packet(d, lane),
                    }
                }
                env = read_envelope(&mut rx) => {
                    let env = match env {
                        Ok(e) => e,
                        Err(_) => return End::Closed,
                    };
                    if env.kind == Kind::Refresh as u16 {
                        let Some(v) = verifier else { continue };
                        let r: Refresh = match parse(&env) {
                            Ok(r) => r,
                            Err(e) => return End::Protocol(format!("bad Refresh: {e}")),
                        };
                        match v.verify(&r.credential, &self.peer_fp) {
                            Ok(c) if c.node_id == self.claims.node_id && c.role == self.claims.role => {
                                self.exp.store(c.exp, Ordering::Relaxed);
                                self.login_gen.store(c.login_gen, Ordering::Relaxed);
                            }
                            Ok(c) => return End::Protocol(format!("Refresh for another member ({})", c.node_id)),
                            Err(e) => return End::Protocol(format!("Refresh rejected: {e}")),
                        }
                    }
                    // Anything else on the control stream is ignored:
                    // unknown kinds are skipped, never fatal.
                }
                _ = tokio::time::sleep(exp_in) => {
                    self.close(CLOSE_EXPIRED, "credential expired");
                    return End::Expired;
                }
                _ = probe_tick.tick(), if cfg.probe_secs > 0 => {
                    if outstanding >= cfg.probe_misses {
                        self.close(CLOSE_PROBE_TIMEOUT, "probe timeout");
                        return End::ProbeTimeout;
                    }
                    seq += 1;
                    let p = Probe { kind: T_PROBE, seq, t_sent: started.elapsed().as_micros() as u64 };
                    let _ = self.chan.send(p.encode().into());
                    outstanding += 1;
                }
            }
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// What an acceptor needs to know once it sees which network a
/// credential belongs to. A relay serving several networks answers
/// differently per network; a single-network acceptor ignores the id.
pub struct AcceptParams {
    pub verifier: Arc<dyn Verifier>,
    pub mode: Mode,
    pub lanes: u8,
    /// Sent in `HelloAck`; informational.
    pub ack_gen: u64,
}

pub trait Acceptor: Send + Sync {
    fn params_for(&self, network_id: &str) -> Option<AcceptParams>;
}

/// A single-network acceptor.
pub struct SingleNetwork {
    pub network_id: String,
    pub verifier: Arc<dyn Verifier>,
    pub mode: Mode,
    pub lanes: u8,
}

impl Acceptor for SingleNetwork {
    fn params_for(&self, network_id: &str) -> Option<AcceptParams> {
        (network_id == self.network_id).then(|| AcceptParams {
            verifier: self.verifier.clone(),
            mode: self.mode,
            lanes: self.lanes,
            ack_gen: 0,
        })
    }
}

/// Acceptor side: read `Hello`, verify against the network the
/// credential names, answer `HelloAck`.
pub async fn accept(conn: quinn::Connection, acceptor: &dyn Acceptor) -> Result<Arc<Session>> {
    let fp = peer_fingerprint(&conn).ok_or_else(|| anyhow!("peer presented no certificate"))?;
    let (mut tx, mut rx) = tokio::time::timeout(Duration::from_secs(10), conn.accept_bi())
        .await
        .context("waiting for the control stream")??;
    let env = tokio::time::timeout(Duration::from_secs(10), read_envelope(&mut rx))
        .await
        .context("waiting for Hello")??;
    if let Err(e) = nqvpn_proto::envelope::check_version(env.major, env.minor) {
        conn.close(3u32.into(), e.to_string().as_bytes());
        anyhow::bail!("{e}");
    }
    anyhow::ensure!(env.kind == Kind::Hello as u16, "expected Hello, got {}", env.kind);
    let hello: Hello = parse(&env)?;
    let network = nqvpn_proto::credential::peek_network(&hello.credential).ok_or_else(|| anyhow!("malformed credential"))?;
    let params = acceptor.params_for(&network).ok_or_else(|| anyhow!("not serving network {network:?}"))?;
    let claims = match params.verifier.verify(&hello.credential, &fp) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.downcast_ref::<StaleLogin>().is_some() { CLOSE_STALE_LOGIN } else { CLOSE_EVICTED };
            conn.close(code.into(), e.to_string().as_bytes());
            return Err(e);
        }
    };
    write_msg(&mut tx, Kind::HelloAck, &HelloAck { gen: params.ack_gen }).await?;
    let chan = PacketChannel::start_lanes(conn.clone(), params.mode, params.lanes);
    let (peer, role) = (claims.node_id, claims.role);
    Ok(Session::new(conn, chan, peer, role, claims, fp, tx, rx))
}

/// Dialer side: connect, `Hello`, wait for `HelloAck`. Tries every
/// address the name resolves to. `expected_fp` is the far end's
/// certificate as the coordinator published it (relays are dialed by
/// it); `None` accepts any. `peer` is who we are dialing; `claims` are
/// our own, decoded from `credential`.
#[allow(clippy::too_many_arguments)]
pub async fn dial(
    addr: &str,
    identity: &TlsIdentity,
    expected_fp: Option<String>,
    credential: &str,
    keepalive_secs: u64,
    mode: Mode,
    lanes: u8,
    peer: nqvpn_proto::types::NodeId,
    peer_role: nqvpn_proto::types::Role,
    claims: Claims,
) -> Result<Arc<Session>> {
    let host = addr.rsplit_once(':').map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']')).unwrap_or("peer").to_string();
    let addrs: Vec<SocketAddr> = tokio::task::spawn_blocking({
        let addr = addr.to_string();
        move || addr.to_socket_addrs().map(|it| it.collect::<Vec<_>>())
    })
    .await?
    .with_context(|| format!("resolving {addr}"))?;
    anyhow::ensure!(!addrs.is_empty(), "no address for {addr}");
    let mut last_err = anyhow!("no addresses");
    for sock in addrs {
        let bind: SocketAddr = if sock.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let mut ep = quinn::Endpoint::client(bind)?;
        ep.set_default_client_config(client_config(identity, expected_fp.clone(), keepalive_secs).map_err(|e| anyhow!("tls: {e}"))?);
        let connecting = match ep.connect(sock, &host) {
            Ok(c) => c,
            Err(e) => {
                last_err = e.into();
                continue;
            }
        };
        let conn = match tokio::time::timeout(Duration::from_secs(10), connecting).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                last_err = anyhow!("{sock}: {e}");
                continue;
            }
            Err(_) => {
                last_err = anyhow!("{sock}: connect timed out");
                continue;
            }
        };
        let fp = peer_fingerprint(&conn).ok_or_else(|| anyhow!("peer presented no certificate"))?;
        let (mut tx, mut rx) = conn.open_bi().await?;
        write_msg(&mut tx, Kind::Hello, &Hello { credential: credential.to_string(), have_gen: 0 }).await?;
        let ack = match tokio::time::timeout(Duration::from_secs(10), read_envelope(&mut rx)).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => {
                // A deliberate refusal carries a code; surface it so the
                // caller can act on it (a stale login means: exit).
                if let Some((code, reason)) = app_close(&conn) {
                    return Err(Refused { code, reason }.into());
                }
                return Err(anyhow!("waiting for HelloAck: {e}"));
            }
            Err(_) => return Err(anyhow!("waiting for HelloAck: timed out")),
        };
        anyhow::ensure!(ack.kind == Kind::HelloAck as u16, "peer refused our credential");
        let chan = PacketChannel::start_lanes(conn.clone(), mode, lanes);
        // The endpoint must outlive the connection: park it on a task.
        let holder = conn.clone();
        tokio::spawn(async move {
            holder.closed().await;
            drop(ep);
        });
        return Ok(Session::new(conn, chan, peer, peer_role, claims, fp, tx, rx));
    }
    Err(last_err)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use nqvpn_proto::credential::{sign, AUD};
    use nqvpn_proto::quic::server_config;
    use nqvpn_proto::types::Role;

    struct Ca(SigningKey);
    impl Ca {
        fn cred(&self, node: u32, fp: &str, exp_in: u64) -> String {
            let now = now_unix();
            sign(
                &Claims {
                    iss: "nqvpn-coord".into(),
                    aud: AUD.into(),
                    network_id: "n".into(),
                    network_uuid: "u".into(),
                    node_id: node,
                    sub: format!("n{node}"),
                    role: Role::Client,
                    pubkey: B64.encode([node as u8; 32]),
                    cert_fp: fp.into(),
                    prefixes: vec![],
                    login_gen: 0,
                    iat: now,
                    exp: now + exp_in,
                },
                "k1",
                &self.0,
            )
        }
    }
    impl Verifier for Ca {
        fn verify(&self, credential: &str, presented_fp: &str) -> Result<Claims> {
            let keys = vec![("k1".to_string(), self.0.verifying_key())];
            let c = nqvpn_proto::credential::verify(
                credential,
                &keys,
                &nqvpn_proto::credential::Expected { iss: "nqvpn-coord", network_id: "n", network_uuid: "u" },
                now_unix(),
            )?;
            anyhow::ensure!(c.cert_fp == presented_fp, "cert_fp mismatch");
            Ok(c)
        }
    }

    fn server() -> (quinn::Endpoint, TlsIdentity) {
        let id = TlsIdentity::generate("srv").unwrap();
        let ep = quinn::Endpoint::server(server_config(&id, 1).unwrap(), "127.0.0.1:0".parse().unwrap()).unwrap();
        (ep, id)
    }

    fn claims_for(cred: &str) -> Claims {
        // The dialer knows its own claims; decode them unverified here.
        let p = cred.split('.').nth(1).unwrap();
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(p).unwrap();
        serde_json::from_slice(&json).unwrap()
    }

    #[tokio::test]
    async fn dial_accept_and_probe_liveness() {
        let ca = Arc::new(Ca(SigningKey::generate(&mut rand::rngs::OsRng)));
        let (srv, srv_id) = server();
        let addr = srv.local_addr().unwrap();
        let ca2 = ca.clone();
        let acceptor = tokio::spawn(async move {
            let conn = srv.accept().await.unwrap().await.unwrap();
            let s = accept(conn, &SingleNetwork { network_id: "n".into(), verifier: ca2.clone(), mode: Mode::Datagram, lanes: 1 }).await.unwrap();
            let got = Arc::new(std::sync::Mutex::new(Vec::new()));
            let g = got.clone();
            let end = s.run(&SessionConfig { probe_secs: 0, probe_misses: 3 }, Some(ca2.as_ref()), move |d, _| g.lock().unwrap().push(d.to_vec())).await;
            let frames = got.lock().unwrap().clone();
            (end, frames)
        });
        let me = TlsIdentity::generate("me").unwrap();
        let cred = ca.cred(10, &me.fingerprint(), 3600);
        let s = dial(&addr.to_string(), &me, Some(srv_id.fingerprint()), &cred, 1, Mode::Datagram, 1, 1, Role::Relay, claims_for(&cred)).await.unwrap();
        assert!(s.chan.send(Bytes::from_static(b"\x01hello")));
        // Probes are answered by the acceptor, so the dialer's liveness holds.
        let s2 = s.clone();
        let runner = tokio::spawn(async move { s2.run(&SessionConfig { probe_secs: 1, probe_misses: 2 }, None, |_, _| {}).await });
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(s.rtt_us.load(Ordering::Relaxed) < 1_000_000, "a probe was answered");
        s.close(CLOSE_SHUTDOWN, "done");
        assert_eq!(runner.await.unwrap(), End::Closed);
        let (end, got) = acceptor.await.unwrap();
        assert_eq!(end, End::Closed);
        assert_eq!(got, vec![b"\x01hello".to_vec()], "data frames reach the handler; probes do not");
    }

    #[tokio::test]
    async fn a_session_ends_at_credential_expiry_unless_refreshed() {
        let ca = Arc::new(Ca(SigningKey::generate(&mut rand::rngs::OsRng)));
        let (srv, srv_id) = server();
        let addr = srv.local_addr().unwrap();
        let ca2 = ca.clone();
        let acceptor = tokio::spawn(async move {
            let conn = srv.accept().await.unwrap().await.unwrap();
            let s = accept(conn, &SingleNetwork { network_id: "n".into(), verifier: ca2.clone(), mode: Mode::Datagram, lanes: 1 }).await.unwrap();
            let exp0 = s.exp();
            let end = s.run(&SessionConfig { probe_secs: 0, probe_misses: 3 }, Some(ca2.as_ref()), |_, _| {}).await;
            (end, exp0, s.exp())
        });
        let me = TlsIdentity::generate("me").unwrap();
        // Expires in 2 s (leeway is applied by verify, not by the session clock).
        let cred = ca.cred(10, &me.fingerprint(), 2);
        let s = dial(&addr.to_string(), &me, Some(srv_id.fingerprint()), &cred, 1, Mode::Datagram, 1, 1, Role::Relay, claims_for(&cred)).await.unwrap();
        // Refresh with a longer credential before it lapses...
        let longer = ca.cred(10, &me.fingerprint(), 3600);
        s.refresh(&longer).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        assert!(!s.conn.close_reason().is_some(), "refreshed session must survive the original expiry");
        // ...and a Refresh for a different node is fatal.
        let other = ca.cred(11, &me.fingerprint(), 3600);
        s.refresh(&other).await.unwrap();
        let (end, exp0, exp1) = acceptor.await.unwrap();
        assert!(matches!(end, End::Protocol(_)), "{end:?}");
        assert!(exp1 > exp0 + 1000, "the refresh extended the acceptor's expiry");
    }

    #[tokio::test]
    async fn the_dialer_gives_up_when_probes_go_unanswered() {
        let ca = Arc::new(Ca(SigningKey::generate(&mut rand::rngs::OsRng)));
        let (srv, srv_id) = server();
        let addr = srv.local_addr().unwrap();
        let ca2 = ca.clone();
        // An acceptor that authenticates but never runs its session: a
        // half-dead peer that keeps QUIC alive and answers nothing.
        tokio::spawn(async move {
            let conn = srv.accept().await.unwrap().await.unwrap();
            let s = accept(conn, &SingleNetwork { network_id: "n".into(), verifier: ca2.clone(), mode: Mode::Datagram, lanes: 1 }).await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(s);
        });
        let me = TlsIdentity::generate("me").unwrap();
        let cred = ca.cred(10, &me.fingerprint(), 3600);
        let s = dial(&addr.to_string(), &me, Some(srv_id.fingerprint()), &cred, 1, Mode::Datagram, 1, 1, Role::Relay, claims_for(&cred)).await.unwrap();
        let end = s.run(&SessionConfig { probe_secs: 1, probe_misses: 2 }, None, |_, _| {}).await;
        assert_eq!(end, End::ProbeTimeout);
    }
}
