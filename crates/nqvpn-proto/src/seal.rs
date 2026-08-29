//! End-to-end encryption between endpoints (DESIGN.md §4).
//!
//! **Noise IK** (`Noise_IK_25519_ChaChaPoly_BLAKE2s`), the
//! WireGuard-proven pattern: the initiator already knows the responder's
//! static key from coordinator-pushed membership, so a session costs one
//! round trip and no directory lookup. Relays forward the handshake
//! frames like any other datagram and can never read what follows.
//!
//! Two properties the design leans on:
//!
//! * **Prologue binding** — every handshake is bound to
//!   `(network_uuid, initiator_id, responder_id)`. A handshake recorded
//!   in one network cannot be replayed into another, and a frame cannot
//!   be re-attributed to a different node pair, because both sides mix
//!   those bytes into the transcript before any key is derived.
//! * **Explicit counters** — the sender writes its nonce in the frame
//!   and the receiver checks a sliding window before decrypting, so
//!   out-of-order delivery (normal on a datagram path) is fine while
//!   replays are not.

use crate::types::NodeId;

pub const PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
/// Sliding replay window, in packets (WireGuard uses 2000).
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
        // Derive the public half by running a throwaway builder.
        let pubkey = x25519_public(&private)?;
        Ok(StaticKeys { private, public: pubkey })
    }
}

impl StaticKeys {
    /// Load the node's long-lived X25519 identity, creating it on first
    /// use. Losing this file changes the node's public key, so the
    /// coordinator's TOFU pin will reject it until an admin reset (§3.3).
    pub fn load_or_create(dir: &std::path::Path) -> Result<StaticKeys, SealError> {
        std::fs::create_dir_all(dir).map_err(|e| SealError::Noise(e.to_string()))?;
        let path = dir.join("static.key");
        if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| SealError::Noise(e.to_string()))?;
            return StaticKeys::from_private(bytes);
        }
        let keys = StaticKeys::generate()?;
        std::fs::write(&path, &keys.private).map_err(|e| SealError::Noise(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(keys)
    }

    pub fn public_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.public)
    }
}

pub fn decode_pubkey(b64: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

fn x25519_public(private: &[u8]) -> Result<Vec<u8>, SealError> {
    // snow has no public-from-private helper; do the scalar mult via a
    // builder that accepts our key and reports the resulting public one.
    let builder = snow::Builder::new(PATTERN.parse().expect("valid pattern"));
    let kp = builder.generate_keypair().map_err(ne)?;
    if private.len() != kp.private.len() {
        return Err(SealError::Noise("private key has wrong length".into()));
    }
    // curve25519 base-point multiplication.
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

/// Receiver-side sliding window over explicit counters.
#[derive(Debug, Default)]
pub struct ReplayWindow {
    highest: u64,
    bitmap: u128,
    seen_any: bool,
}

impl ReplayWindow {
    /// Accept `ctr` exactly once, rejecting replays and stale counters.
    pub fn accept(&mut self, ctr: u64) -> bool {
        const BITS: u64 = 128;
        if !self.seen_any {
            self.seen_any = true;
            self.highest = ctr;
            self.bitmap = 1;
            return true;
        }
        if ctr > self.highest {
            let shift = ctr - self.highest;
            self.bitmap = if shift >= BITS { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = ctr;
            return true;
        }
        let back = self.highest - ctr;
        if back >= BITS.min(REPLAY_WINDOW) {
            return false; // too old to judge: refuse
        }
        let mask = 1u128 << back;
        if self.bitmap & mask != 0 {
            return false; // already seen
        }
        self.bitmap |= mask;
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
    /// membership. Returns the session plus the first handshake message.
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
        let n = hs.write_message(&[], &mut msg).map_err(ne)?;
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

    /// Answer an incoming handshake. Returns the session and the reply.
    pub fn respond(
        keys: &StaticKeys,
        peer: NodeId,
        network_uuid: &str,
        me: NodeId,
        first_message: &[u8],
        now: u64,
    ) -> Result<(PairSession, Vec<u8>), SealError> {
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
        hs.read_message(first_message, &mut scratch).map_err(ne)?;
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
        ))
    }

    /// Initiator side: consume the responder's reply and go transport.
    pub fn finish(&mut self, reply: &[u8]) -> Result<(), SealError> {
        let stage = self.stage.take().ok_or(SealError::Short)?;
        match stage {
            Stage::Handshake(mut hs) => {
                let mut scratch = vec![0u8; 1024];
                hs.read_message(reply, &mut scratch).map_err(ne)?;
                let t = hs.into_transport_mode().map_err(ne)?;
                self.stage = Some(Stage::Transport(Box::new(t)));
                Ok(())
            }
            other => {
                self.stage = Some(other);
                Ok(()) // already established: a duplicate reply is harmless
            }
        }
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

    /// Decrypt one frame, enforcing the replay window first.
    pub fn unseal(&mut self, ctr: u64, ciphertext: &[u8]) -> Result<Vec<u8>, SealError> {
        let Some(Stage::Transport(t)) = self.stage.as_mut() else {
            return Err(SealError::NoSession(self.peer));
        };
        if !self.replay.accept(ctr) {
            return Err(SealError::Replay(ctr));
        }
        t.set_receiving_nonce(ctr);
        let mut out = vec![0u8; ciphertext.len()];
        let n = t.read_message(ciphertext, &mut out).map_err(ne)?;
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
        let (b, msg2) = PairSession::respond(&b_keys, 10, UUID, 20, &msg1, 0).unwrap();
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
    fn responder_learns_the_initiators_static_key() {
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        let (b, _) = PairSession::respond(&b_keys, 10, UUID, 20, &msg1, 0).unwrap();
        // This is what lets the receiver check the sender against the
        // coordinator-pinned key in membership.
        assert_eq!(b.peer_static().unwrap(), a_keys.public);
    }

    #[test]
    fn replay_is_rejected_but_reordering_is_not() {
        let (mut a, mut b) = established();
        let mut frames = Vec::new();
        for i in 0..5u8 {
            frames.push(a.seal(&[i]).unwrap());
        }
        // Deliver out of order: 3, 1, 0, 4, 2 — all must succeed.
        for idx in [3usize, 1, 0, 4, 2] {
            let (ctr, ct) = &frames[idx];
            assert_eq!(b.unseal(*ctr, ct).unwrap(), vec![idx as u8]);
        }
        // Every replay of an already-seen counter is refused.
        for (ctr, ct) in &frames {
            assert!(matches!(b.unseal(*ctr, ct), Err(SealError::Replay(_))));
        }
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
        // Same node ids, same keys, different network uuid: the prologue
        // binding must make the handshake fail outright.
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        let other = "99999999-8888-7777-6666-555555555555";
        assert!(PairSession::respond(&b_keys, 10, other, 20, &msg1, 0).is_err());
    }

    #[test]
    fn a_handshake_cannot_be_re_attributed_to_other_nodes() {
        let (a_keys, b_keys) = pair();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        // Responder believes the initiator is node 11, not 10.
        assert!(PairSession::respond(&b_keys, 11, UUID, 20, &msg1, 0).is_err());
        // ...or that it is itself node 21.
        assert!(PairSession::respond(&b_keys, 10, UUID, 21, &msg1, 0).is_err());
    }

    #[test]
    fn an_impostor_without_the_static_key_fails() {
        let (a_keys, b_keys) = pair();
        let impostor = StaticKeys::generate().unwrap();
        let (_, msg1) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 0).unwrap();
        // IK encrypts to the responder's static key: nobody else can read it.
        assert!(PairSession::respond(&impostor, 10, UUID, 20, &msg1, 0).is_err());
        let _ = b_keys;
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut a, mut b) = established();
        let (ctr, mut ct) = a.seal(b"payload").unwrap();
        ct[0] ^= 0xff;
        assert!(b.unseal(ctr, &ct).is_err());
    }

    #[test]
    fn a_handshake_that_never_completes_goes_stale() {
        let (a_keys, b_keys) = pair();
        let (a, _msg) = PairSession::initiate(&a_keys, 20, &b_keys.public, UUID, 10, 100).unwrap();
        assert!(!a.is_ready());
        assert!(!a.is_stale_handshake(100 + HANDSHAKE_TIMEOUT_SECS - 1));
        assert!(a.is_stale_handshake(100 + HANDSHAKE_TIMEOUT_SECS));
        // An established session is never "stale" in this sense.
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
    fn keys_persist_across_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let a = StaticKeys::load_or_create(dir.path()).unwrap();
        let b = StaticKeys::load_or_create(dir.path()).unwrap();
        assert_eq!(a.public, b.public);
        assert_eq!(decode_pubkey(&a.public_b64()).unwrap(), a.public);
    }

    #[test]
    fn keys_roundtrip_through_private_bytes() {
        let k = StaticKeys::generate().unwrap();
        let back = StaticKeys::from_private(k.private.clone()).unwrap();
        assert_eq!(k.public, back.public, "public key derives from the private one");
    }
}
