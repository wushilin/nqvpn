//! The control session: one QUIC connection to the coordinator carrying
//! `Hello`, then `Snapshot`/`Delta` down and `Heartbeat`/`Resync`/
//! `Refresh` up. The caller reconnects when it ends.

use anyhow::{anyhow, Context, Result};
use nqvpn_proto::api::JoinResponse;
use nqvpn_proto::control::{Delta, GenerationGap, Heartbeat, Hello, HelloAck, Refresh, Resync, Snapshot};
use nqvpn_proto::envelope::{decode_payload, Kind};
use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::client_config;
use nqvpn_proto::seal::StaticKeys;
use nqvpn_proto::stream::{read_envelope, write_msg};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, Notify};

use crate::join::{join_with_backoff_async, renew_after, MemberConfig};

/// The member's copy of the network view. Pure data: replaced by a
/// snapshot, mutated by a delta, read by everyone else.
pub struct View {
    snap: Mutex<Snapshot>,
    /// Bumped on every change; reconcilers wait on it.
    changed: watch::Sender<u64>,
}

impl Default for View {
    fn default() -> Self {
        Self::new()
    }
}

impl View {
    pub fn new() -> Self {
        let (tx, _) = watch::channel(0);
        View { snap: Mutex::new(Snapshot::default()), changed: tx }
    }

    pub fn get(&self) -> Snapshot {
        self.snap.lock().unwrap().clone()
    }

    pub fn gen(&self) -> u64 {
        self.snap.lock().unwrap().gen
    }

    pub fn digest(&self) -> u64 {
        self.snap.lock().unwrap().digest()
    }

    /// Read without cloning.
    pub fn with<R>(&self, f: impl FnOnce(&Snapshot) -> R) -> R {
        f(&self.snap.lock().unwrap())
    }

    pub fn replace(&self, s: Snapshot) {
        *self.snap.lock().unwrap() = s;
        self.changed.send_modify(|v| *v += 1);
    }

    pub fn apply(&self, d: &Delta) -> Result<(), GenerationGap> {
        let mut s = self.snap.lock().unwrap();
        let before = s.gen;
        s.apply(d)?;
        if s.gen != before {
            drop(s);
            self.changed.send_modify(|v| *v += 1);
        }
        Ok(())
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.changed.subscribe()
    }

    /// Wake reconcilers without a view change (a timer, a local event).
    pub fn poke(&self) {
        self.changed.send_modify(|v| *v += 1);
    }
}

/// What the member tells the coordinator about itself.
pub trait LocalFacts: Send + Sync {
    /// Filled in whole on every heartbeat; `gen`/`digest` are added by
    /// the link.
    fn heartbeat(&self) -> Heartbeat;
}

/// A task that must not outlive the future that spawned it. Dropping
/// the guard — including when the owning future is cancelled — aborts
/// the task, so a torn-down session never leaves a writer behind still
/// heartbeating on its behalf.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The link's inbox: a local change to report now, or a renewed
/// credential to present.
#[derive(Default)]
pub struct LinkHandle {
    kick: Notify,
    refresh: Mutex<Option<String>>,
    stop: Mutex<Option<MemberExit>>,
    stop_notify: Notify,
}

/// The coordinator closed the session because this member's
/// configuration changed: re-join now and apply the new facts.
#[derive(Debug)]
pub struct Reconfigured(pub String);

impl std::fmt::Display for Reconfigured {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reconfigured: {}", self.0)
    }
}

impl std::error::Error for Reconfigured {}

/// The control session must end because this member is done: carried
/// as the error of `run_session`.
#[derive(Debug)]
pub struct Stop(pub MemberExit);

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let MemberExit::Replaced(r) = &self.0;
        write!(f, "replaced: {r}")
    }
}

impl std::error::Error for Stop {}

/// Why `run_member` returned. It returns for exactly one reason;
/// everything else — a lost coordinator, a disabled member, a
/// regenerated token — is retried forever with backoff, so that the
/// operator's next decision at the coordinator takes effect without
/// anyone touching the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberExit {
    /// Another instance holds this member's identity now. Re-joining
    /// would only take it back and the two would replace each other
    /// forever, so the process exits with `EXIT_REPLACED`. If the other
    /// join was not the operator's doing, the secret has leaked and
    /// must be rotated.
    Replaced(String),
}

impl MemberExit {
    pub fn exit_code(&self) -> i32 {
        EXIT_REPLACED
    }

    pub fn reason(&self) -> &str {
        let MemberExit::Replaced(r) = self;
        r
    }
}

/// Process exit code for `MemberExit::Replaced`. A supervisor should
/// keep a replaced instance down (`RestartPreventExitStatus=3`).
pub const EXIT_REPLACED: i32 = 3;

impl LinkHandle {
    /// Another instance holds this member's identity: the coordinator
    /// or a relay said so. Recorded once; the control loop ends with
    /// `MemberExit::Replaced` and nothing re-joins.
    pub fn replaced(&self, reason: String) {
        self.stop(MemberExit::Replaced(reason));
    }

    pub fn stop(&self, exit: MemberExit) {
        let mut r = self.stop.lock().unwrap();
        if r.is_none() {
            let MemberExit::Replaced(reason) = &exit;
            tracing::error!(%reason, "this node was replaced by another instance");
            *r = Some(exit);
        }
        self.stop_notify.notify_one();
    }

    /// Set once this member has been kicked out; never cleared.
    pub fn stop_reason(&self) -> Option<MemberExit> {
        self.stop.lock().unwrap().clone()
    }

    /// A local fact changed: heartbeat now instead of at the next tick.
    pub fn kick(&self) {
        self.kick.notify_one();
    }

    /// Present a renewed credential on the next write.
    pub fn refresh(&self, credential: String) {
        *self.refresh.lock().unwrap() = Some(credential);
        self.kick.notify_one();
    }
}

#[derive(Debug, Clone)]
pub struct SessionParams {
    /// `host:port` of the QUIC control plane.
    pub control_addr: String,
    pub credential: String,
    pub keepalive_secs: u64,
    pub heartbeat_secs: u64,
}

fn app_close(conn: &quinn::Connection) -> Option<(u32, String)> {
    match conn.close_reason()? {
        quinn::ConnectionError::ApplicationClosed(a) => {
            Some((a.error_code.into_inner() as u32, String::from_utf8_lossy(&a.reason).into_owned()))
        }
        _ => None,
    }
}

fn resolve(addr: &str) -> Result<Vec<SocketAddr>> {
    let v: Vec<SocketAddr> = addr.to_socket_addrs().with_context(|| format!("resolving {addr}"))?.collect();
    anyhow::ensure!(!v.is_empty(), "no address for {addr}");
    Ok(v)
}

/// Run one control session to completion. Returns when it ends; the
/// caller decides how to reconnect.
pub async fn run_session(
    identity: &TlsIdentity,
    params: SessionParams,
    view: Arc<View>,
    facts: Arc<dyn LocalFacts>,
    handle: Arc<LinkHandle>,
) -> Result<()> {
    let host = params
        .control_addr
        .rsplit_once(':')
        .map(|(h, _)| h.trim_matches(|c| c == '[' || c == ']'))
        .unwrap_or("coord")
        .to_string();
    let addrs = tokio::task::spawn_blocking({
        let a = params.control_addr.clone();
        move || resolve(&a)
    })
    .await??;

    let mut last_err = anyhow!("no addresses");
    let mut connected = None;
    for sock in addrs {
        let bind: SocketAddr = if sock.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
        let mut ep = quinn::Endpoint::client(bind)?;
        // The credential exchange authenticates both directions; the
        // coordinator's certificate is not pinned.
        ep.set_default_client_config(client_config(identity, None, params.keepalive_secs).map_err(|e| anyhow!("tls: {e}"))?);
        match tokio::time::timeout(Duration::from_secs(10), ep.connect(sock, &host)?).await {
            Ok(Ok(c)) => {
                connected = Some((ep, c));
                break;
            }
            Ok(Err(e)) => last_err = anyhow!("{sock}: {e}"),
            Err(_) => last_err = anyhow!("{sock}: connect timed out"),
        }
    }
    let Some((_ep, conn)) = connected else { return Err(last_err) };

    let (mut tx, mut rx) = conn.open_bi().await?;
    write_msg(&mut tx, Kind::Hello, &Hello { credential: params.credential.clone(), have_gen: view.gen() }).await?;
    tracing::info!(addr = %params.control_addr, have_gen = view.gen(), "coordinator control connected");

    // Writer: heartbeats on a timer and on kick; Refresh when handed one.
    let (resync_tx, mut resync_rx) = tokio::sync::mpsc::channel::<u64>(4);
    let writer = AbortOnDrop({
        let (view, facts, handle) = (view.clone(), facts.clone(), handle.clone());
        let period = Duration::from_secs(params.heartbeat_secs.max(1));
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {}
                    _ = handle.kick.notified() => {}
                    Some(have) = resync_rx.recv() => {
                        write_msg(&mut tx, Kind::Resync, &Resync { have_gen: have }).await?;
                        continue;
                    }
                }
                let refresh = handle.refresh.lock().unwrap().take();
                if let Some(c) = refresh {
                    write_msg(&mut tx, Kind::Refresh, &Refresh { credential: c }).await?;
                }
                let mut hb = facts.heartbeat();
                let (gen, digest) = view.with(|s| (s.gen, s.digest()));
                hb.gen = gen;
                hb.digest = digest;
                write_msg(&mut tx, Kind::Heartbeat, &hb).await?;
            }
            #[allow(unreachable_code)]
            Ok::<_, nqvpn_proto::stream::StreamError>(())
        })
    });

    let result = loop {
        let env = tokio::select! {
            env = read_envelope(&mut rx) => match env {
                Ok(e) => e,
                Err(e) => {
                    if let Some((code, reason)) = app_close(&conn) {
                        if code == nqvpn_proto::control::CLOSE_REPLACED {
                            break Err(Stop(MemberExit::Replaced(reason)).into());
                        }
                        if code == nqvpn_proto::control::CLOSE_RECONFIGURED {
                            break Err(Reconfigured(reason).into());
                        }
                        break Err(anyhow!("coordinator closed the session (code {code}): {reason}"));
                    }
                    break Err(anyhow!("control stream ended: {e}"));
                }
            },
            _ = handle.stop_notify.notified() => {
                let exit = handle.stop_reason().unwrap_or(MemberExit::Replaced("stopped".into()));
                break Err(Stop(exit).into());
            }
        };
        match env.kind {
            k if k == Kind::HelloAck as u16 => {
                let a: HelloAck = decode_payload(&env.payload)?;
                tracing::info!(gen = a.gen, "coordinator accepted control session");
            }
            k if k == Kind::Snapshot as u16 => {
                let s: Snapshot = decode_payload(&env.payload)?;
                tracing::info!(gen = s.gen, members = s.members.len(), "snapshot installed");
                view.replace(s);
            }
            k if k == Kind::Delta as u16 => {
                let d: Delta = decode_payload(&env.payload)?;
                if let Err(gap) = view.apply(&d) {
                    tracing::warn!("{gap}; asking for a snapshot");
                    let _ = resync_tx.try_send(gap.have);
                }
            }
            other => tracing::debug!(kind = other, "ignoring control message"),
        }
    };
    drop(writer);
    conn.close(0u32.into(), b"session ended");
    result
}

/// Hooks for the owner of a member (client or relay).
pub trait MemberHooks: Send + Sync {
    /// Called after every successful join, with the response. The owner
    /// installs addresses, updates relay lists it dials, and passes the
    /// renewed credential to its data sessions.
    fn joined(&self, r: &JoinResponse);
}

/// The whole member control loop: join, hold a session, reconnect with
/// backoff, renew at two thirds of the credential lifetime. Returns
/// only when this instance has been replaced by another join under
/// the same name (see `MemberExit`). The first join is done before
/// this is called so the owner can set itself up with the response.
#[allow(clippy::too_many_arguments)]
pub async fn run_member(
    cfg: Arc<MemberConfig>,
    identity: TlsIdentity,
    keys: StaticKeys,
    first: JoinResponse,
    view: Arc<View>,
    facts: Arc<dyn LocalFacts>,
    handle: Arc<LinkHandle>,
    hooks: Arc<dyn MemberHooks>,
) -> MemberExit {
    let credential = Arc::new(Mutex::new(first.credential.clone()));
    #[allow(unused_assignments)]
    let mut renewal_guard: Option<AbortOnDrop<()>> = None;
    let control_addr = Arc::new(Mutex::new(
        nqvpn_proto::joinapi::control_addr(&cfg.coordinator, first.control_port).unwrap_or_default(),
    ));
    let heartbeat_secs = first.heartbeat_secs.max(1) as u64;
    let keepalive_secs = first.keepalive_secs.max(1) as u64;

    // Renewal: a join before expiry; the new credential goes to the
    // control session (Refresh) and to the owner (its data sessions).
    {
        let (cfg, identity, keys, credential, handle, hooks, control_addr) =
            (cfg.clone(), identity.clone(), keys.clone(), credential.clone(), handle.clone(), hooks.clone(), control_addr.clone());
        let mut wait = renew_after(&first.credential);
        let _renewal = AbortOnDrop(tokio::spawn(async move {
            loop {
                tokio::time::sleep(wait).await;
                if handle.stop_reason().is_some() {
                    return;
                }
                let r = join_with_backoff_async(cfg.clone(), identity.clone(), keys.clone()).await;
                wait = renew_after(&r.credential);
                *credential.lock().unwrap() = r.credential.clone();
                if let Ok(a) = nqvpn_proto::joinapi::control_addr(&cfg.coordinator, r.control_port) {
                    *control_addr.lock().unwrap() = a;
                }
                handle.refresh(r.credential.clone());
                hooks.joined(&r);
                tracing::info!(next_in_secs = wait.as_secs(), "credential renewed");
            }
        }));
        // Held until this function returns: a replaced instance must
        // not renew (a renewal is a join, and a join takes the identity
        // back).
        renewal_guard = Some(_renewal);
    }

    let _renewal_guard = renewal_guard;
    let mut delay = Duration::from_secs(1);
    loop {
        if let Some(exit) = handle.stop_reason() {
            return exit;
        }
        let started = std::time::Instant::now();
        let mut reconfigured = false;
        let params = SessionParams {
            control_addr: control_addr.lock().unwrap().clone(),
            credential: credential.lock().unwrap().clone(),
            keepalive_secs,
            heartbeat_secs,
        };
        match run_session(&identity, params, view.clone(), facts.clone(), handle.clone()).await {
            Ok(()) => tracing::warn!("coordinator session ended; reconnecting"),
            Err(e) => {
                if let Some(Stop(exit)) = e.downcast_ref::<Stop>() {
                    handle.stop(exit.clone());
                    return exit.clone();
                }
                if let Some(Reconfigured(why)) = e.downcast_ref::<Reconfigured>() {
                    tracing::info!(%why, "coordinator asked for a re-join: applying new configuration");
                    reconfigured = true;
                } else {
                    tracing::warn!("coordinator session lost: {e:#}")
                }
            }
        }
        // Reset the backoff only after a session that actually lasted.
        // A requested re-join is not a failure: no wait at all.
        let was_healthy = started.elapsed() >= Duration::from_secs(30);
        if !reconfigured {
            tokio::time::sleep(delay).await;
        }
        // Tight: back within seconds of the coordinator being back.
        delay = if was_healthy || reconfigured { Duration::from_secs(1) } else { (delay * 2).min(Duration::from_secs(5)) };
        // Re-join: a fresh credential and a fresh declaration. The view
        // is kept; Hello says what we hold and the coordinator sends
        // only what changed. Never after a replacement: that join
        // would win, and the two instances would take turns.
        if let Some(exit) = handle.stop_reason() {
            return exit;
        }
        let r = join_with_backoff_async(cfg.clone(), identity.clone(), keys.clone()).await;
        *credential.lock().unwrap() = r.credential.clone();
        if let Ok(a) = nqvpn_proto::joinapi::control_addr(&cfg.coordinator, r.control_port) {
            *control_addr.lock().unwrap() = a;
        }
        hooks.joined(&r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nqvpn_proto::control::PeerInfo;
    use nqvpn_proto::types::Role;

    fn peer(id: u32) -> PeerInfo {
        PeerInfo { node_id: id, name: format!("n{id}"), role: Role::Client, prefixes: vec![], pubkey: String::new(), online: true, login_gen: 0 }
    }

    #[test]
    fn view_applies_deltas_and_reports_gaps() {
        let v = View::new();
        let mut rx = v.subscribe();
        let mut s = Snapshot { gen: 10, members: vec![peer(1)], ..Snapshot::default() };
        s.normalize();
        v.replace(s.clone());
        assert!(rx.has_changed().unwrap());
        rx.mark_unchanged();
        let mut s2 = s.clone();
        s2.gen = 11;
        s2.members.push(peer(2));
        s2.normalize();
        let d = s.diff(&s2);
        v.apply(&d).unwrap();
        assert_eq!(v.gen(), 11);
        assert!(rx.has_changed().unwrap());
        let gap = Delta { base_gen: 5, gen: 12, ..Default::default() };
        assert_eq!(v.apply(&gap), Err(GenerationGap { base: 5, have: 11 }));
        assert_eq!(v.digest(), s2.digest());
    }
}
