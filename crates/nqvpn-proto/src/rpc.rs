//! Correlated request/response over the control stream (DESIGN-RPC.md).
//!
//! The control stream had no reply channel: every upstream message was
//! fire-and-forget, and the only way to report a failure was to tear down
//! the session — so a member whose `Refresh` was rejected learned nothing
//! except that the connection dropped. That is survivable for
//! notifications and not survivable for identity rotation, where "did my
//! new key get pinned?" cannot be answered by guessing.
//!
//! Three properties this layer is built around:
//!
//!   * **typed at the call site.** The wire carries an opaque payload,
//!     because that is what lets a peer skip a body it cannot parse — but
//!     no caller ever sees bytes. `call::<RotateIdentity>()` returns
//!     `RotateIdentity::Response`, paired by the compiler.
//!   * **per-verb versions.** Each verb advertises a supported range and
//!     each request names the version it speaks. This is what makes
//!     backward compatibility real, and it is why the payload encoding
//!     does not need to be self-describing: adding a field means adding a
//!     verb version with its own fixed schema, exactly as Kafka does over
//!     a rigid binary encoding.
//!   * **errors are answers.** An unknown verb or version comes back as a
//!     response correlated to the request id, never as a dropped session.
//!     An `UnsupportedVersion` carries the range the peer *does* support,
//!     so the caller can retry lower instead of guessing.
//!
//! The peer here is transport-agnostic: it consumes decoded envelopes and
//! emits encoded ones. That keeps the correlation logic testable without
//! standing up QUIC, which is where the interesting failure modes are.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::envelope::{decode_payload, encode_msg, Envelope, Kind};
use crate::errors::ErrorCode;

/// How long a caller waits before giving up on a reply. Generous: these
/// are administrative operations on a healthy control session, not a hot
/// path, and a spurious timeout is worse than a slow answer.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Verb numbers. Deliberately a separate namespace from `Kind`.
pub mod verb {
    /// Ask a peer what it supports. Version 1 forever, by construction:
    /// it is the one call that cannot rely on negotiation to be
    /// understood, so its shape can never change.
    pub const API_VERSIONS: u16 = 1;
    /// Member -> coordinator: register a new identity, keeping the old
    /// one valid for an overlap.
    pub const ROTATE_IDENTITY: u16 = 2;
}

/// Register a fresh identity for the member holding this session.
///
/// No signature accompanies this: the control session is mutual-TLS with
/// the currently pinned certificate, verified at `Hello`, so being able
/// to send it *is* the proof of possession. A signature scheme over the
/// plaintext HTTP API would be reimplementing, less safely, what the
/// channel already provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateIdentity {
    /// New X25519 public key, base64. Empty leaves the Noise key alone.
    pub new_pubkey: String,
    /// New TLS certificate fingerprint ("sha256:..."). Empty leaves it.
    pub new_cert_fp: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotateIdentityOk {
    /// Unix time the previous identity stops being accepted. Until then
    /// either identity authenticates, so a member that restarts before
    /// switching is not locked out.
    pub old_retires_unix: u64,
}

impl Rpc for RotateIdentity {
    const VERB: u16 = verb::ROTATE_IDENTITY;
    const MIN_VERSION: u16 = 1;
    const MAX_VERSION: u16 = 1;
    type Response = RotateIdentityOk;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub req_id: u64,
    pub verb: u16,
    pub version: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub req_id: u64,
    /// `None` is success. Carried as a string rather than the enum so an
    /// unrecognised code from a newer peer degrades to
    /// `ErrorCode::Unknown` instead of failing to decode — the same
    /// reason the HTTP API carries codes as strings.
    pub code: Option<String>,
    pub payload: Vec<u8>,
}

/// One verb's supported version range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerbSupport {
    pub verb: u16,
    pub min: u16,
    pub max: u16,
}

impl VerbSupport {
    pub fn accepts(&self, version: u16) -> bool {
        version >= self.min && version <= self.max
    }
}

/// Reply to `API_VERSIONS`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiVersions {
    pub verbs: Vec<VerbSupport>,
}

/// A typed call. Implementors pair a request with its response and pin
/// the verb and version range, so no call site handles bytes or has to
/// remember which reply belongs to which request.
pub trait Rpc: Serialize + DeserializeOwned {
    const VERB: u16;
    const MIN_VERSION: u16;
    const MAX_VERSION: u16;
    type Response: Serialize + DeserializeOwned;
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// The peer answered with a failure. This is the normal way calls
    /// fail — the session stays up.
    #[error("{0}")]
    Remote(ErrorCode),
    /// The peer implements the verb at a different version. Carries what
    /// it does support so the caller can adapt rather than guess.
    #[error("peer supports verb {} only at versions {}..={}", .0.verb, .0.min, .0.max)]
    Version(VerbSupport),
    #[error("no response within {0:?}")]
    Timeout(Duration),
    /// The session ended with the call still outstanding. Distinct from a
    /// timeout: the caller knows the request may or may not have been
    /// applied, which matters for anything that mutates state.
    #[error("control session closed before the reply arrived")]
    SessionClosed,
    #[error("codec: {0}")]
    Codec(String),
}

/// What a peer does with an inbound request.
///
/// Synchronous on purpose: every verb we have is a short state mutation
/// under a lock. The peer still spawns the call, so a slow handler cannot
/// stall the single ordered stream behind it.
pub trait VerbHandler: Send + Sync + 'static {
    /// Every verb this side implements, with its version range.
    fn supported(&self) -> Vec<VerbSupport>;
    /// Handle a request whose verb and version have already been checked
    /// against `supported()`.
    fn handle(&self, verb: u16, version: u16, payload: &[u8]) -> Result<Vec<u8>, ErrorCode>;
}

/// A handler that implements nothing. Useful for a side that only makes
/// calls, and as the starting point before verbs are registered.
pub struct NoVerbs;

impl VerbHandler for NoVerbs {
    fn supported(&self) -> Vec<VerbSupport> {
        Vec::new()
    }
    fn handle(&self, _verb: u16, _version: u16, _payload: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        Err(ErrorCode::UnsupportedVerb)
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Response>>>>;

/// Both halves of the protocol for one session: issues calls, answers
/// them, and correlates replies.
///
/// Bidirectional by construction — a coordinator calling a member is the
/// same code as the reverse, which costs nothing now and would be
/// awkward to retrofit.
pub struct RpcPeer {
    out: mpsc::Sender<Vec<u8>>,
    handler: Arc<dyn VerbHandler>,
    pending: Pending,
    next_id: AtomicU64,
    timeout: Duration,
}

impl RpcPeer {
    /// `out` receives fully encoded envelopes, to be written to the
    /// stream by whatever already owns it — responses go through the same
    /// writer as everything else rather than racing it for the stream.
    pub fn new(out: mpsc::Sender<Vec<u8>>, handler: Arc<dyn VerbHandler>) -> Arc<RpcPeer> {
        Arc::new(RpcPeer {
            out,
            handler,
            pending: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            timeout: DEFAULT_TIMEOUT,
        })
    }

    pub fn with_timeout(mut self: Arc<Self>, t: Duration) -> Arc<RpcPeer> {
        // Only ever called during setup, before any clone escapes.
        Arc::get_mut(&mut self).expect("set the timeout before sharing").timeout = t;
        self
    }

    /// Issue a call at the highest version we speak.
    pub async fn call<R: Rpc>(&self, req: R) -> Result<R::Response, RpcError> {
        self.call_versioned(req, R::MAX_VERSION).await
    }

    /// Issue a call at a specific version — used to retry lower after an
    /// `UnsupportedVersion`.
    pub async fn call_versioned<R: Rpc>(
        &self,
        req: R,
        version: u16,
    ) -> Result<R::Response, RpcError> {
        let payload = crate::envelope::encode_payload(&req)
            .map_err(|e| RpcError::Codec(e.to_string()))?;
        let req_id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(req_id, tx);

        let bytes = encode_msg(
            Kind::Request,
            &Request { req_id, verb: R::VERB, version, payload },
        )
        .map_err(|e| RpcError::Codec(e.to_string()))?;

        if self.out.send(bytes).await.is_err() {
            self.pending.lock().unwrap().remove(&req_id);
            return Err(RpcError::SessionClosed);
        }

        // Every outcome resolves: reply, timeout, or the session ending.
        // A caller left awaiting forever is the failure mode this layer
        // exists to remove.
        let resp = match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => return Err(RpcError::SessionClosed),
            Err(_) => {
                self.pending.lock().unwrap().remove(&req_id);
                return Err(RpcError::Timeout(self.timeout));
            }
        };

        if let Some(code) = resp.code {
            let code = ErrorCode::parse(&code);
            // A version refusal carries the peer's range, which is more
            // useful to the caller than the bare code.
            if code == ErrorCode::UnsupportedVersion {
                if let Ok(sup) = decode_payload::<VerbSupport>(&resp.payload) {
                    return Err(RpcError::Version(sup));
                }
            }
            return Err(RpcError::Remote(code));
        }
        decode_payload::<R::Response>(&resp.payload).map_err(|e| RpcError::Codec(e.to_string()))
    }

    /// Ask the peer what it implements.
    pub async fn api_versions(&self) -> Result<ApiVersions, RpcError> {
        self.call(ApiVersionsRequest).await
    }

    /// Feed one decoded envelope in. Returns true if it belonged to this
    /// layer, so the caller can fall through to its other message kinds.
    pub fn on_envelope(self: &Arc<Self>, env: &Envelope) -> bool {
        if env.kind == Kind::Response as u16 {
            if let Ok(resp) = decode_payload::<Response>(&env.payload) {
                // A reply to a request we already gave up on is dropped,
                // not an error: the timeout path removed the waiter.
                if let Some(tx) = self.pending.lock().unwrap().remove(&resp.req_id) {
                    let _ = tx.send(resp);
                }
            }
            return true;
        }
        if env.kind != Kind::Request as u16 {
            return false;
        }
        let Ok(req) = decode_payload::<Request>(&env.payload) else {
            // Undecodable request: nothing to correlate a reply to, so
            // there is nothing useful to say.
            return true;
        };
        let me = self.clone();
        tokio::spawn(async move {
            let resp = me.dispatch(&req);
            let _ = me.respond(resp).await;
        });
        true
    }

    fn dispatch(&self, req: &Request) -> Response {
        let fail = |code: ErrorCode, payload: Vec<u8>| Response {
            req_id: req.req_id,
            code: Some(code.as_str().to_string()),
            payload,
        };

        // API_VERSIONS is answered here rather than by the handler: it
        // must work even on a peer that implements no verbs at all, since
        // it is how you find that out.
        if req.verb == verb::API_VERSIONS {
            let mut verbs = self.handler.supported();
            verbs.push(VerbSupport { verb: verb::API_VERSIONS, min: 1, max: 1 });
            verbs.sort_by_key(|v| v.verb);
            return match crate::envelope::encode_payload(&ApiVersions { verbs }) {
                Ok(payload) => Response { req_id: req.req_id, code: None, payload },
                Err(_) => fail(ErrorCode::Internal, Vec::new()),
            };
        }

        let supported = self.handler.supported();
        let Some(sup) = supported.iter().find(|v| v.verb == req.verb) else {
            return fail(ErrorCode::UnsupportedVerb, Vec::new());
        };
        if !sup.accepts(req.version) {
            // Return the range, so the caller can retry at a version we
            // do speak rather than probing blindly.
            let payload = crate::envelope::encode_payload(sup).unwrap_or_default();
            return fail(ErrorCode::UnsupportedVersion, payload);
        }
        match self.handler.handle(req.verb, req.version, &req.payload) {
            Ok(payload) => Response { req_id: req.req_id, code: None, payload },
            Err(code) => fail(code, Vec::new()),
        }
    }

    async fn respond(&self, resp: Response) -> Result<(), RpcError> {
        let bytes =
            encode_msg(Kind::Response, &resp).map_err(|e| RpcError::Codec(e.to_string()))?;
        self.out.send(bytes).await.map_err(|_| RpcError::SessionClosed)
    }

    /// Fail every outstanding call. Called when the session ends, so no
    /// caller is left waiting on a reply that can never arrive.
    pub fn close(&self) {
        self.pending.lock().unwrap().clear();
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

/// The `API_VERSIONS` request has no fields; it exists so the call is
/// typed like every other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiVersionsRequest;

impl Rpc for ApiVersionsRequest {
    const VERB: u16 = verb::API_VERSIONS;
    const MIN_VERSION: u16 = 1;
    const MAX_VERSION: u16 = 1;
    type Response = ApiVersions;
}

#[cfg(test)]
mod tests {
    use super::*;

    const V_ECHO: u16 = 100;
    const V_FAILING: u16 = 101;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Echo {
        msg: String,
    }
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct EchoOk {
        msg: String,
    }
    impl Rpc for Echo {
        const VERB: u16 = V_ECHO;
        const MIN_VERSION: u16 = 1;
        const MAX_VERSION: u16 = 2;
        type Response = EchoOk;
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Failing;
    impl Rpc for Failing {
        const VERB: u16 = V_FAILING;
        const MIN_VERSION: u16 = 1;
        const MAX_VERSION: u16 = 1;
        type Response = ();
    }

    struct TestHandler;
    impl VerbHandler for TestHandler {
        fn supported(&self) -> Vec<VerbSupport> {
            vec![
                VerbSupport { verb: V_ECHO, min: 1, max: 2 },
                VerbSupport { verb: V_FAILING, min: 1, max: 1 },
            ]
        }
        fn handle(&self, verb: u16, version: u16, payload: &[u8]) -> Result<Vec<u8>, ErrorCode> {
            match verb {
                V_ECHO => {
                    let e: Echo = decode_payload(payload).map_err(|_| ErrorCode::BadRequest)?;
                    // Version is visible to the handler, so a v2 can
                    // behave differently from a v1 without a new verb.
                    let msg = if version >= 2 { format!("v2:{}", e.msg) } else { e.msg };
                    Ok(crate::envelope::encode_payload(&EchoOk { msg }).unwrap())
                }
                V_FAILING => Err(ErrorCode::PinMismatch),
                _ => Err(ErrorCode::UnsupportedVerb),
            }
        }
    }

    /// Wire two peers together so each one's output feeds the other's
    /// input — the smallest thing that exercises real correlation.
    fn pair(
        a_handler: Arc<dyn VerbHandler>,
        b_handler: Arc<dyn VerbHandler>,
    ) -> (Arc<RpcPeer>, Arc<RpcPeer>) {
        let (a_tx, mut a_rx) = mpsc::channel::<Vec<u8>>(64);
        let (b_tx, mut b_rx) = mpsc::channel::<Vec<u8>>(64);
        let a = RpcPeer::new(a_tx, a_handler);
        let b = RpcPeer::new(b_tx, b_handler);

        let b2 = b.clone();
        tokio::spawn(async move {
            while let Some(bytes) = a_rx.recv().await {
                let (env, _) = Envelope::decode(&bytes).expect("valid envelope");
                b2.on_envelope(&env);
            }
        });
        let a2 = a.clone();
        tokio::spawn(async move {
            while let Some(bytes) = b_rx.recv().await {
                let (env, _) = Envelope::decode(&bytes).expect("valid envelope");
                a2.on_envelope(&env);
            }
        });
        (a, b)
    }

    #[tokio::test]
    async fn a_call_returns_its_own_reply() {
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        let r = a.call(Echo { msg: "hi".into() }).await.expect("call");
        assert_eq!(r.msg, "v2:hi", "should negotiate to MAX_VERSION");
        assert_eq!(a.pending_count(), 0, "the waiter must be cleaned up");
    }

    #[tokio::test]
    async fn concurrent_calls_are_correlated_not_interleaved() {
        // The property the req_id exists for: many in flight at once, each
        // caller gets its own answer.
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        // Separate tasks rather than a joined future set: this is closer
        // to how callers actually use it, and genuinely concurrent.
        let handles: Vec<_> = (0..25)
            .map(|i| {
                let a = a.clone();
                tokio::spawn(async move { a.call(Echo { msg: format!("m{i}") }).await })
            })
            .collect();
        for (i, h) in handles.into_iter().enumerate() {
            let r = h.await.expect("join").expect("call");
            assert_eq!(r.msg, format!("v2:m{i}"), "reply {i} went astray");
        }
        assert_eq!(a.pending_count(), 0);
    }

    #[tokio::test]
    async fn an_unknown_verb_is_answered_not_a_dropped_session() {
        // The whole point: a peer that does not implement something says
        // so, and the session survives to be used again.
        #[derive(Serialize, Deserialize)]
        struct Absent;
        impl Rpc for Absent {
            const VERB: u16 = 9999;
            const MIN_VERSION: u16 = 1;
            const MAX_VERSION: u16 = 1;
            type Response = ();
        }
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        match a.call(Absent).await {
            Err(RpcError::Remote(ErrorCode::UnsupportedVerb)) => {}
            other => panic!("expected UnsupportedVerb, got {other:?}"),
        }
        // Session still usable.
        assert_eq!(a.call(Echo { msg: "still here".into() }).await.unwrap().msg, "v2:still here");
    }

    #[tokio::test]
    async fn an_unsupported_version_returns_the_supported_range() {
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        // Ask for v9 of a verb the peer caps at v2.
        match a.call_versioned(Echo { msg: "x".into() }, 9).await {
            Err(RpcError::Version(sup)) => {
                assert_eq!(sup.verb, V_ECHO);
                assert_eq!((sup.min, sup.max), (1, 2));
            }
            other => panic!("expected a version refusal with a range, got {other:?}"),
        }
        // ...and the caller can act on it: retry inside the range.
        let r = a.call_versioned(Echo { msg: "x".into() }, 1).await.expect("retry at v1");
        assert_eq!(r.msg, "x", "v1 must not get the v2 behaviour");
    }

    #[tokio::test]
    async fn a_handler_error_comes_back_as_its_code() {
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        match a.call(Failing).await {
            Err(RpcError::Remote(ErrorCode::PinMismatch)) => {}
            other => panic!("expected the handler's code, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn api_versions_works_even_against_a_peer_with_no_verbs() {
        // It is how you discover a peer implements nothing, so it cannot
        // itself depend on the peer implementing anything.
        let (a, _b) = pair(Arc::new(NoVerbs), Arc::new(NoVerbs));
        let v = a.api_versions().await.expect("api_versions");
        assert_eq!(v.verbs, vec![VerbSupport { verb: verb::API_VERSIONS, min: 1, max: 1 }]);

        let (c, _d) = pair(Arc::new(NoVerbs), Arc::new(TestHandler));
        let v = c.api_versions().await.expect("api_versions");
        let verbs: Vec<u16> = v.verbs.iter().map(|s| s.verb).collect();
        assert_eq!(verbs, vec![verb::API_VERSIONS, V_ECHO, V_FAILING]);
    }

    #[tokio::test]
    async fn a_call_times_out_rather_than_hanging_forever() {
        // Peer that never answers: the output goes nowhere.
        let (tx, _never_read) = mpsc::channel::<Vec<u8>>(64);
        let a = RpcPeer::new(tx, Arc::new(NoVerbs)).with_timeout(Duration::from_millis(80));
        match a.call(Echo { msg: "?".into() }).await {
            Err(RpcError::Timeout(_)) => {}
            other => panic!("expected a timeout, got {other:?}"),
        }
        assert_eq!(a.pending_count(), 0, "a timed-out waiter must not leak");
    }

    #[tokio::test]
    async fn a_closed_session_fails_outstanding_calls() {
        // Distinct from a timeout on purpose: the caller learns the
        // request may or may not have been applied, which matters for
        // anything that mutates state.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
        let a = RpcPeer::new(tx, Arc::new(NoVerbs)).with_timeout(Duration::from_secs(30));
        let a2 = a.clone();
        let call = tokio::spawn(async move { a2.call(Echo { msg: "?".into() }).await });
        // Let it register, then end the session.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(a.pending_count(), 1);
        a.close();
        drop(rx);
        match call.await.expect("join") {
            Err(RpcError::SessionClosed) => {}
            other => panic!("expected SessionClosed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_reply_to_an_abandoned_request_is_ignored() {
        // The timeout path removes the waiter; a late reply must not
        // panic or be mistaken for another call's answer.
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(64);
        let a = RpcPeer::new(tx, Arc::new(NoVerbs));
        let stray = encode_msg(
            Kind::Response,
            &Response { req_id: 4242, code: None, payload: Vec::new() },
        )
        .unwrap();
        let (env, _) = Envelope::decode(&stray).unwrap();
        assert!(a.on_envelope(&env), "still ours to consume");
    }

    #[tokio::test]
    async fn non_rpc_kinds_are_left_for_the_caller() {
        // Pushes must keep flowing through their own path; this layer
        // coexists with them rather than replacing them.
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(64);
        let a = RpcPeer::new(tx, Arc::new(NoVerbs));
        let bytes = encode_msg(Kind::Ping, &()).unwrap();
        let (env, _) = Envelope::decode(&bytes).unwrap();
        assert!(!a.on_envelope(&env), "Ping is not an RPC message");
    }
}
