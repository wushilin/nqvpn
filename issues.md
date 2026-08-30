# Code and Design Review Issues

Overall assessment: the architecture is thoughtful and the implementation quality is high, but the project is not production-safe yet. The unauthenticated control plane undermines several of the documented security guarantees and should be fixed before deployment outside a trusted network.

## Critical: the coordinator control connection is not authenticated

The QUIC control client explicitly accepts any coordinator certificate in `crates/nqvpn-sync/src/link.rs:262-269`. It then installs snapshots and deltas without verifying a signature in `crates/nqvpn-sync/src/link.rs:339-355`.

The comment that the credential exchange "authenticates both directions" is incorrect. The member credential authenticates the member to the server; it does not authenticate the server to the member.

A network-path attacker can impersonate the coordinator and send a forged snapshot. Against a relay, that snapshot replaces its trusted credential-signing keys in `crates/nqvpn-relay/src/net.rs:540-546`. The attacker can then sign arbitrary member credentials, alter attachments and relay endpoints, and gain control of forwarding and admission.

This remains exploitable even when `trust_any_cert = false` protects the HTTPS join.

Recommended fix: establish a coordinator trust anchor in the member token, such as a certificate fingerprint or signing public key, and use it to authenticate both HTTPS join and QUIC control. Alternatively, cryptographically sign snapshots and deltas using a key anchored in the token. A signing key delivered inside an unauthenticated snapshot cannot authenticate that snapshot.

## High: an untrusted relay can permanently poison handshake replay state

Incoming handshake timestamps are recorded before the peer's Noise static key is compared with the coordinator-published key:

- Timestamp accepted: `crates/nqvpn-endpoint/src/engine.rs:322-329`
- Static key checked afterward: `crates/nqvpn-endpoint/src/engine.rs:331-346`
- Watermark accepts any larger `u64`: `crates/nqvpn-endpoint/src/peers.rs:272-282`

A malicious relay carrying traffic for a member can inject a valid Noise initiation made with the wrong static key but timestamp `u64::MAX`. The key comparison rejects the session, but the timestamp watermark remains poisoned. Every legitimate future handshake from that member is then considered stale until the endpoint restarts.

Recommended fix: move `accept_handshake_ts` after successful static-key verification. Also bound timestamps to an acceptable clock window so replay protection survives process restarts and cannot accept arbitrary future timestamps.

## High: join rate limiting is bypassable and its map grows without bound

The rate-limit key is the first eight characters of the unauthenticated secret in `crates/nqvpn-coord/src/state.rs:273-278`. An attacker can choose a new prefix for every request, so every request gets a fresh allowance.

Pruning in `crates/nqvpn-coord/src/state.rs:137-147` only removes entries from previous time windows. Thousands of distinct prefixes submitted during the same minute are retained. This permits unauthenticated memory growth while every request also triggers a full scan of all configured members.

Recommended fix: use a bounded global/per-IP limiter before secret resolution, followed by a per-member/IP limiter after resolution. Put a hard capacity on limiter state.

## High: permanent member secrets are exposed to active MITM by default

Both client and relay default to accepting any HTTPS certificate:

- `crates/nqvpn-client/src/config.rs:19-22`
- `crates/nqvpn-relay/src/config.rs:16-19`
- `crates/nqvpn-proto/src/joinapi.rs:109-122`

Because join sends a permanent member secret, an active attacker can impersonate the coordinator, capture the secret, join the real coordinator with new keys, and replace the genuine member. The design documents this as an intentional usability tradeoff, but it is unsafe as the default for a VPN.

Recommended fix: make certificate verification the default. For self-signed deployments, placing a coordinator fingerprint in the out-of-band member token preserves the one-token setup experience.

## Medium: failed persistence leaves mutated live state behind

Several paths change in-memory state before saving it:

- Join registry mutation: `crates/nqvpn-coord/src/state.rs:344-373`
- Network update: `crates/nqvpn-coord/src/admin.rs:136-165`
- Member creation and update: `crates/nqvpn-coord/src/admin.rs:184-229`
- Token rotation, deletion and disable: `crates/nqvpn-coord/src/admin.rs:232-299`

If SQLite returns an error because of a full disk, I/O failure, or corruption, the API reports failure but the running coordinator retains the new state. A later heartbeat or successful operation may publish or persist that supposedly failed change. This contradicts the documented durability-before-visibility principle.

Recommended fix: build changes in cloned state, persist them, and only then swap them into `NetState`. Multi-record operations such as deletion and token rotation should use one SQLite transaction.

## Medium: generated private keys are committed

The repository tracks `tls.key` and `static.key`. They were added in commit `76a5092`, and Git records them as ordinary `100644` files. `.gitignore` only ignores build and state directories.

If these identities have ever joined a real network, treat them as compromised.

Recommended fix: remove the private keys from Git history, rotate the associated identity and token, and ignore generated identity files or their containing state directory.

## Positive observations

- Crate boundaries and dependency direction are clear.
- Pure routing, snapshot/delta, lease, and route decisions are isolated and heavily tested.
- The generation/digest reconciliation model is safer than event-based attachment state.
- Forwarding authorization includes hop-origin and inner-packet source checks.
- Replay-window advancement happens only after successful AEAD verification.
- Bounded queues, named drop decisions, and chaos tests show good operational thinking.
- Clippy passes with warnings denied.

## Verification

- `cargo test --workspace`: all 289 tests passed.
- `cargo clippy --workspace --all-targets -- -D warnings`: passed.

## Priority

Fix the unauthenticated control connection first. The handshake watermark poisoning and join rate-limiter issues should follow before additional feature work. The persistence and repository-secret problems should also be resolved before a production release.
