//! The coordinator's RPC verbs (DESIGN-RPC.md).
//!
//! A handler is bound to one authenticated session, so it never has to
//! decide *who* is calling — the session already established that with
//! mutual TLS and a verified `cert_fp`. That is what lets identity
//! rotation carry no signature of its own.

use nqvpn_proto::envelope::{decode_payload, encode_payload};
use nqvpn_proto::errors::ErrorCode;
use nqvpn_proto::rpc::{verb, RotateIdentity, RotateIdentityOk, VerbHandler, VerbSupport};
use std::sync::Arc;

use crate::state::{now_unix, AppState};

/// How long the previous identity keeps working after a rotation.
///
/// Long enough that a member which rotates and then sits idle — or
/// crashes and takes a while to come back — still authenticates with the
/// key it currently holds on disk. The window closes on its own, and
/// closes early the moment the member is seen using the new key.
pub const ROTATION_OVERLAP_SECS: u64 = 3 * 24 * 60 * 60;

/// Verbs answered on one member's control session.
pub struct SessionVerbs {
    pub state: Arc<AppState>,
    pub network_id: String,
    pub member: String,
}

impl VerbHandler for SessionVerbs {
    fn supported(&self) -> Vec<VerbSupport> {
        vec![VerbSupport { verb: verb::ROTATE_IDENTITY, min: 1, max: 1 }]
    }

    fn handle(&self, verb_id: u16, _version: u16, payload: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        match verb_id {
            verb::ROTATE_IDENTITY => {
                let req: RotateIdentity =
                    decode_payload(payload).map_err(|_| ErrorCode::BadRequest)?;
                let out = self.rotate(req)?;
                encode_payload(&out).map_err(|_| ErrorCode::Internal)
            }
            _ => Err(ErrorCode::UnsupportedVerb),
        }
    }
}

impl SessionVerbs {
    fn rotate(&self, req: RotateIdentity) -> Result<RotateIdentityOk, ErrorCode> {
        if req.new_pubkey.is_empty() && req.new_cert_fp.is_empty() {
            return Err(ErrorCode::BadRequest);
        }
        let net = self.state.networks.get(&self.network_id).ok_or(ErrorCode::NotFound)?;
        let mut ns = net.lock().unwrap();
        let now = now_unix();
        let retire_at = now + ROTATION_OVERLAP_SECS;

        {
            let rec = ns
                .registry
                .members
                .get_mut(&self.member)
                .ok_or(ErrorCode::NotFound)?;
            // A disabled member must not be able to re-establish itself
            // under a new identity.
            if rec.disabled {
                return Err(ErrorCode::ClientDisabled);
            }
            if !req.new_pubkey.is_empty() {
                rec.pubkeys.rotate_to(req.new_pubkey.clone(), retire_at);
            }
            if !req.new_cert_fp.is_empty() {
                rec.cert_fps.rotate_to(req.new_cert_fp.clone(), retire_at);
            }
            rec.mirror_legacy_pins();
        }

        // Durability precedes visibility: a rotation the member believes
        // succeeded must survive a coordinator restart, or the member
        // switches to a key nobody accepts.
        let path = ns.registry_path.clone();
        ns.registry.commit(&path).map_err(|e| {
            tracing::error!(member = %self.member, "rotation commit failed: {e:#}");
            ErrorCode::Internal
        })?;

        // A relay's advertised pin is what dialers verify against, so the
        // fleet has to learn the new fingerprint.
        crate::control::publish_relays_if_changed(&mut ns);

        tracing::info!(
            network = %self.network_id, member = %self.member, retire_at,
            "identity rotated; previous identity valid until the overlap ends"
        );
        Ok(RotateIdentityOk { old_retires_unix: retire_at })
    }
}
