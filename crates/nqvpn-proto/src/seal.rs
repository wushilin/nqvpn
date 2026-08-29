//! End-to-end encryption between endpoints (DESIGN.md §4).
//!
//! **Noise IK** (`Noise_IK_25519_ChaChaPoly_BLAKE2s`), the
//! WireGuard-proven pattern: the initiator already knows the responder's
//! static key from coordinator-pushed membership, so a session costs one
//! round trip and no directory lookup. Relays forward the handshake
//! frames like any other datagram and can never read what follows.
//!
//! Three properties the design leans on:
//!
//! * **Prologue binding** — every handshake is bound to
//!   `(network_uuid, initiator_id, responder_id)`. A handshake recorded
//!   in one network cannot be replayed into another, and a frame cannot
//!   be re-attributed to a different node pair, because both sides mix
//!   those bytes into the transcript before any key is derived.
//! * **Explicit counters** — the sender writes its nonce in the frame
//!   and the receiver checks a sliding window before decrypting and
//!   commits it only after the tag verified. A frame that fails
//!   authentication leaves the window untouched, so neither an untrusted
//!   relay nor a straggler from a previous session can move it.
//! * **Timestamped initiation** — the first handshake message carries
//!   the initiator's clock, encrypted under the responder's static key.
//!   The engine keeps the newest value per peer and refuses older ones,
//!   so a captured msg1 cannot be replayed to reset a working session.

use crate::types::NodeId;

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Sliding replay window, in packets. Sized for multi-lane stream
/// transport, where lanes are *meant* to deliver out of order relative to
/// each other: one lane stalled on a retransmit while others deliver a
/// thousand frames must not turn the recovered lane into "replays".
pub const REPLAY_WINDOW: u64 = 2048;
/// Rekey after this many seconds (decision #7 — WireGuard's constant).
pub const REKEY_AFTER_SECS: u64 = 120;
/// Give up on a handshake that never completed and start over. Without
/// this a session stuck half-open blocks every later attempt, because
/// the peer already "has" a session and never initiates another.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
/// Hard cap on messages per session before a rekey is mandatory.
pub const REKEY_AFTER_MESSAGES: u64 = 1 << 40;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("noise: {0}")]
    Noise(String),
    #[error("no session for peer {0}")]
    NoSession(NodeId),
    #[error("replayed or too-old counter {0}")]
    Replay(u64),
    #[error("frame too short")]
    Short,
    #[error("handshake message is not a reply")]
    NotAReply,
}

fn ne(e: snow::Error) -> SealError {
    SealError::Noise(e.to_string())
}

/// A static X25519 identity used for every pair session.
#[derive(Clone)]
pub struct StaticKeys {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl StaticKeys {
    pub fn generate() -> Result<StaticKeys, SealError> {
        let kp = snow::Builder::new(PATTERN.parse().expect("valid pattern"))
            .generate_keypair()
            .map_err(ne)?;
        Ok(StaticKeys { private: kp.private, public: kp.public })
    }

    pub fn from_private(private: Vec<u8>) -> Result<StaticKeys, SealError> {
        let pubkey = x25519_public(&private)?;
        Ok(StaticKeys { private, public: pubkey })
    }

    /// Load the node's X25519 key, creating it on first use. Losing this
    /// file simply changes the node's public key; the next join publishes
    /// the new one and peers re-handshake.
    pub fn load_or_create(dir: &std::path::Path) -> Result<StaticKeys, SealError> {
        std::fs::create_dir_all(dir).map_err(|e| SealError::Noise(e.to_string()))?;
        let path = dir.join("static.key");
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| SealError::Noise(e.to_string()))?;
            if let Ok(k) = StaticKeys::from_private(bytes) {
                return Ok(k);
            }
            // A truncated or corrupt file is not worth failing over: a key
            // is cheap and the network learns the new one at the next join.
        }
        let keys = StaticKeys::generate()?;
        write_private_atomic(&path, &keys.private).map_err(|e| SealError::Noise(e.to_string()))?;
        Ok(keys)
    }

    pub fn public_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.public)
    }
}

fn write_private_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("key.tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

pub fn decode_pubkey(b64: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let v = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    (v.len() == 32).then_some(v)
}

fn x25519_public(private: &[u8]) -> Result<Vec<u8>, SealError> {
    if private.len() != 32 {
        return Err(SealError::Noise("private key has wrong length".into()));
    }
    let mut clamped = [0u8; 32];
    clamped.copy_from_slice(private);
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(clamped));
    Ok(public.as_bytes().to_vec())
}

/// The bytes both sides mix into the handshake transcript.
pub fn prologue(network_uuid: &str, initiator: NodeId, responder: NodeId) -> Vec<u8> {
    let mut p = Vec::with_capacity(16 + 8 + network_uuid.len());
    p.extend_from_slice(b"nqvpn-v1");
    p.extend_from_slice(network_uuid.as_bytes());
    p.extend_from_slice(&initiator.to_be_bytes());
    p.extend_from_slice(&responder.to_be_bytes());
    p
}

const WINDOW_WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// Receiver-side sliding window over explicit counters (RFC 6479 shape).
///
/// Two-phase on purpose: `check` is pure and runs before decryption,
/// `commit` runs only after the AEAD tag verified. Advancing on an
/// unauthenticated counter would let anyone who can inject a frame push
/// the window past every genuine one.
#[derive(Debug)]
pub struct ReplayWindow {
    highest: u64,
    bits: [u64; WINDOW_WORDS],
    seen_any: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow { highest: 0, bits: [0; WINDOW_WORDS], seen_any: false }
    }
}

impl ReplayWindow {
    fn bit(&self, ctr: u64) -> bool {
        let idx = (ctr % REPLAY_WINDOW) as usize;
        self.bits[idx / 64] & (1u64 << (idx % 64)) != 0
    }

    fn set(&mut self, ctr: u64) {
        let idx = (ctr % REPLAY_WINDOW) as usize;
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    /// Would `ctr` be accepted right now? Pure.
    pub fn check(&self, ctr: u64) -> bool {
        if !self.seen_any || ctr > self.highest {
            return true;
        }
        if self.highest - ctr >= REPLAY_WINDOW {
            return false; // too old to judge: refuse
        }
        !self.bit(ctr)
    }

    /// Record `ctr` as seen. Call only after `check` said yes and the
    /// frame authenticated.
    pub fn commit(&mut self, ctr: u64) {
        if !self.seen_any {
            self.seen_any = true;
            self.highest = ctr;
            self.bits = [0; WINDOW_WORDS];
            self.set(ctr);
            return;
        }
        if ctr > self.highest {
            let advance = ctr - self.highest;
            if advance >= REPLAY_WINDOW {
                self.bits = [0; WINDOW_WORDS];
            } else {
                // Clear the slots the window slides over.
                for c in (self.highest + 1)..=ctr {
                    let idx = (c % REPLAY_WINDOW) as usize;
                    self.bits[idx / 64] &= !(1u64 << (idx % 64));
                }
            }
            self.highest = ctr;
        }
        self.set(ctr);
    }

    /// `check` then `commit` in one step, for callers that have already
    /// authenticated the frame by other means.
    pub fn accept(&mut self, ctr: u64) -> bool {
        if !self.check(ctr) {
            return false;
        }
        self.commit(ctr);
        true
    }
}

enum Stage {
    Handshake(Box<snow::HandshakeState>),
    Transport(Box<snow::TransportState>),
}

/// One end-to-end session with a single peer.
pub struct PairSession {
    stage: Option<Stage>,
    pub peer: NodeId,
    pub initiator: bool,
    replay: ReplayWindow,
    established_at: u64,
    messages: u64,
}

impl PairSession {
    /// Start a session toward a peer whose static key we know from
    /// membership. Returns the session plus the first handshake message,
    /// which carries `now` so the responder can refuse replays of it.
    pub fn initiate(
        keys: &StaticKeys,
        peer: NodeId,
        peer_pubkey: &[u8],
        network_uuid: &str,
        me: NodeId,
        now: u64,
    ) -> Result<(PairSession, Vec<u8>), SealError> {
        let pro = prologue(network_uuid, me, peer);
        let mut hs = snow::Builder::new(PATTERN.parse().expect("valid pattern"))
            .local_private_key(&keys.private)
            .map_err(ne)?
            .remote_public_key(peer_pubkey)
            .map_err(ne)?
            .prologue(&pro)
            .map_err(ne)?
            .build_initiator()
            .map_err(ne)?;
        let mut msg = vec![0u8; 1024];
        let n = hs.write_message(&now.to_be_bytes(), &mut msg).map_err(ne)?;
        msg.truncate(n);
        Ok((
            PairSession {
                stage: Some(Stage::Handshake(Box::new(hs))),
                peer,
                initiator: true,
                replay: ReplayWindow::default(),
                established_at: now,
                messages: 0,
            },
            msg,
        ))
    }

    /// Answer an incoming handshake. Returns the session, the reply, and
    /// the initiator's timestamp for the caller's replay check.
    pub fn respond(
        keys: &StaticKeys,
        peer: NodeId,
        network_uuid: &str,
        me: NodeId,
        first_message: &[u8],
        now: u64,
    ) -> Result<(PairSession, Vec<u8>, u64), SealError> {
        // The initiator is the peer, so the prologue orders them first.
        let pro = prologue(network_uuid, peer, me);
        let mut hs = snow::Builder::new(PATTERN.parse().expect("valid pattern"))
            .local_private_key(&keys.private)
            .map_err(ne)?
            .prologue(&pro)
            .map_err(ne)?
            .build_responder()
            .map_err(ne)?;
        let mut scratch = vec![0u8; 1024];
        let n = hs.read_message(first_message, &mut scratch).map_err(ne)?;
        let ts = if n >= 8 {
            u64::from_be_bytes(scratch[..8].try_into().expect("8 bytes"))
        } else {
            0
        };
        let mut reply = vec![0u8; 1024];
        let n = hs.write_message(&[], &mut reply).map_err(ne)?;
        reply.truncate(n);
        let transport = hs.into_transport_mode().map_err(ne)?;
        Ok((
            PairSession {
                stage: Some(Stage::Transport(Box::new(transport))),
                peer,
                initiator: false,
                replay: ReplayWindow::default(),
                established_at: now,
                messages: 0,
            },
            reply,
            ts,
        ))
    }

    /// Initiator side: consume the responder's reply and go transport.
    ///
    /// A failed read leaves the session exactly as it was — still an
    /// in-flight initiator — so a crossed handshake (the peer's own msg1
    /// arriving here) is a recoverable event, not a poisoned session.
    pub fn finish(&mut self, reply: &[u8]) -> Result<(), SealError> {
        let Some(Stage::Handshake(hs)) = self.stage.as_mut() else {
            // Already established: a duplicate reply is harmless.
            return Ok(());
        };
        let mut scratch = vec![0u8; 1024];
        if let Err(e) = hs.read_message(reply, &mut scratch) {
            // snow may have consumed internal state; there is nothing to
            // restore beyond leaving the stage in place, which is what a
            // caller needs to decide to yield or retry.
            return Err(ne(e));
        }
        let Some(Stage::Handshake(hs)) = self.stage.take() else { unreachable!() };
        let t = hs.into_transport_mode().map_err(ne)?;
        self.stage = Some(Stage::Transport(Box::new(t)));
        Ok(())
    }

    pub fn is_ready(&self) -> bool {
        matches!(self.stage, Some(Stage::Transport(_)))
    }

    /// Peer's static public key, learned during the handshake — this is
    /// what the caller compares against coordinator-pushed membership.
    pub fn peer_static(&self) -> Option<Vec<u8>> {
        match &self.stage {
            Some(Stage::Transport(t)) => t.get_remote_static().map(|k| k.to_vec()),
            Some(Stage::Handshake(h)) => h.get_remote_static().map(|k| k.to_vec()),
            None => None,
        }
    }

    /// Encrypt one inner packet. Returns `(counter, ciphertext)`; the
    /// caller writes the counter into the frame header.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<(u64, Vec<u8>), SealError> {
        let Some(Stage::Transport(t)) = self.stage.as_mut() else {
            return Err(SealError::NoSession(self.peer));
        };
        let ctr = t.sending_nonce();
        let mut out = vec![0u8; plaintext.len() + 32];
        let n = t.write_message(plaintext, &mut out).map_err(ne)?;
        out.truncate(n);
        self.messages += 1;
        Ok((ctr, out))
    }

    /// Decrypt one frame: window check, authenticate, then commit.
    pub fn unseal(&mut self, ctr: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
        let Some(Stage::Transport(t)) = self.stage.as_mut() else {
            return Err(SealError::NoSession(self.peer));
        };
        if !self.replay.check(ctr) {
            return Err(SealError::Replay(ctr));
        }
        t.set_receiving_nonce(ctr);
        let mut out = vec![0u8; ciphertext.len()];
        let n = t.read_message(ciphertext, &mut out).map_err(ne)?;
        self.replay.commit(ctr);
        out.truncate(n);
        Ok(out)
    }

    /// A handshake that never completed: the transport was down, the
    /// reply was lost, or the peer was not listening yet.
    pub fn is_stale_handshake(&self, now: u64) -> bool {
        !self.is_ready() && now.saturating_sub(self.established_at) >= HANDSHAKE_TIMEOUT_SECS
    }

    /// Sessions are replaced, never repaired: rekeying is a fresh
    /// handshake, which also gives forward secrecy (§4).
    pub fn needs_rekey(&self, now: u64) -> bool {
        now.saturating_sub(self.established_at) >= REKEY_AFTER_SECS
            || self.messages >= REKEY_AFTER_MESSAGES
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    fn pair() -> (StaticKeys, StaticKeys) {
        (StaticKeys::generate().unwrap(), StaticKeys::generate().unwrap())
    }

    /// Drive a full IK handshake between nodes 10 and 20.
    fn established() -> (PairSession, PairSession) {
        let (a_keys, b_keys) = pair();
        let (mut a, msg1) =
            PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        let (b, msg2, _) = PairSession::respond(&b_keys, 10, UUID, 20, &msg1, 0).unwrap();
        a.finish(&msg2).unwrap();
        assert!(a.is_ready() && b.is_ready());
        (a, b)
    }

    #[test]
    fn handshake_then_bidirectional_traffic() {
        let (mut a, mut b) = established();
        let (c1, ct) = a.seal(b"inner ip packet").unwrap();
        assert_eq!(b.unseal(c1, &ct).unwrap(), b"inner ip packet");
        let (c2, ct2) = b.seal(b"reply packet").unwrap();
        assert_eq!(a.unseal(c2, &ct2).unwrap(), b"reply packet");
    }

    #[test]
    fn responder_learns_the_initiators_static_key_and_timestamp() {
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 4242).unwrap();
        let (b, _, ts) = PairSession::respond(&b_keys, 10, UUID, 20, &msg1, 0).unwrap();
        assert_eq!(b.peer_static().unwrap(), a_keys.public);
        assert_eq!(ts, 4242, "the initiator's clock rides inside msg1");
    }

    #[test]
    fn replay_is_rejected_but_reordering_is_not() {
        let (mut a, mut b) = established();
        let mut frames = Vec::new();
        for i in 0..5u8 {
            frames.push(a.seal(&[i]).unwrap());
        }
        for idx in [3usize, 1, 0, 4, 2] {
            let (ctr, ct) = &frames[idx];
            assert_eq!(b.unseal(*ctr, ct).unwrap(), vec![idx as u8]);
        }
        for (ctr, ct) in &frames {
            assert!(matches!(b.unseal(*ctr, ct), Err(SealError::Replay(_))));
        }
    }

    #[test]
    fn a_frame_that_fails_authentication_does_not_move_the_window() {
        // The bug this guards: an untrusted relay (or a straggler from a
        // previous session) injects a frame with an enormous counter. If
        // the window advanced before the tag check, every genuine frame
        // after it would be "too old".
        let (mut a, mut b) = established();
        let forged = vec![0u8; 40];
        assert!(b.unseal(1_000_000, &forged).is_err());
        let (ctr, ct) = a.seal(b"genuine").unwrap();
        assert_eq!(ctr, 0);
        assert_eq!(b.unseal(ctr, &ct).unwrap(), b"genuine", "window must be untouched");
    }

    #[test]
    fn the_window_is_wide_enough_for_lane_reordering() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(0));
        assert!(w.accept(REPLAY_WINDOW - 1));
        // 1 is REPLAY_WINDOW-2 behind: still inside.
        assert!(w.accept(1));
        assert!(!w.accept(1), "but only once");
        assert!(w.accept(REPLAY_WINDOW + 500));
        assert!(!w.accept(100), "now ancient");
        assert!(w.accept(REPLAY_WINDOW + 499));
    }

    #[test]
    fn sliding_clears_reused_slots() {
        // Counters 0 and 2048 share a bitmap slot; sliding past 0 must
        // clear it so 2048 is accepted exactly once.
        let mut w = ReplayWindow::default();
        assert!(w.accept(0));
        assert!(w.accept(REPLAY_WINDOW));
        assert!(!w.accept(REPLAY_WINDOW));
        assert!(!w.accept(0), "0 fell out of the window");
        // A jump larger than the window resets everything.
        assert!(w.accept(10 * REPLAY_WINDOW));
        assert!(w.accept(10 * REPLAY_WINDOW - 1));
    }

    #[test]
    fn ancient_counters_are_refused() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(10_000));
        assert!(!w.accept(1), "far below the window");
        assert!(w.accept(9_999), "just inside the window");
    }

    #[test]
    fn a_frame_from_another_network_cannot_be_decrypted() {
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        let other = "99999999-8888-7777-6666-555555555555";
        assert!(PairSession::respond(&b_keys, 10, other, 20, &msg1, 0).is_err());
    }

    #[test]
    fn a_handshake_cannot_be_re_attributed_to_other_nodes() {
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        assert!(PairSession::respond(&b_keys, 11, UUID, 20, &msg1, 0).is_err());
        assert!(PairSession::respond(&b_keys, 10, UUID, 21, &msg1, 0).is_err());
    }

    #[test]
    fn an_impostor_without_the_static_key_fails() {
        let (a_keys, b_keys) = pair();
        let impostor = StaticKeys::generate().unwrap();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        assert!(PairSession::respond(&impostor, 10, UUID, 20, &msg1, 0).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = established();
        let (ctr, mut ct) = a.seal(b"payload").unwrap();
        ct[0] ^= 0xff;
        assert!(b.unseal(ctr, &ct).is_err());
    }

    #[test]
    fn a_crossed_handshake_leaves_the_initiator_intact() {
        // Both sides initiate at once; each receives the other's msg1
        // where it expected a msg2. That must fail cleanly and leave the
        // session still waiting, so the engine can yield to one side.
        let (a_keys, b_keys) = pair();
        let (mut a, _msg1_a) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        let (_b, msg1_b) = PairSession::initiate(&b_keys, 10, &a_keys.public, UUID, 20, 0).unwrap();
        assert!(a.finish(&msg1_b).is_err());
        assert!(!a.is_ready());
        assert!(a.initiator, "still an in-flight initiator, not a poisoned husk");
    }

    #[test]
    fn a_handshake_that_never_completes_goes_stale() {
        let (a_keys, b_keys) = pair();
        let (a, _msg) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 100).unwrap();
        assert!(!a.is_ready());
        assert!(!a.is_stale_handshake(100 + HANDSHAKE_TIMEOUT_SECS - 1));
        assert!(a.is_stale_handshake(100 + HANDSHAKE_TIMEOUT_SECS));
        let (established, _) = established();
        assert!(!established.is_stale_handshake(1_000_000));
    }

    #[test]
    fn rekey_is_due_after_the_interval() {
        let (a, _) = established();
        assert!(!a.needs_rekey(REKEY_AFTER_SECS - 1));
        assert!(a.needs_rekey(REKEY_AFTER_SECS));
    }

    #[test]
    fn keys_persist_across_restarts_and_survive_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let a = StaticKeys::load_or_create(dir.path()).unwrap();
        let b = StaticKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(a.public, b.public);
        assert_eq!(decode_pubkey(&a.public_b64()).unwrap(), a.public);
        // A truncated key file is replaced, not fatal.
        std::fs::write(dir.path().join("static.key"), b"short").unwrap();
        let c = StaticKeys::load_or_create(dir.path()).unwrap();
        assert_ne!(c.public, a.public);
        assert_eq!(StaticKeys::load_or_create(dir.path()).unwrap().public, c.public);
    }

    #[test]
    fn keys_roundtrip_through_private_bytes() {
        let k = StaticKeys::generate().unwrap();
        let back = StaticKeys::from_private(k.private.clone()).unwrap();
        assert_eq!(k.public, back.public);
    }

    #[test]
    fn a_pubkey_must_be_32_bytes() {
        assert!(decode_pubkey("AAAA").is_none());
        assert!(decode_pubkey("not base64!").is_none());
    }
}
