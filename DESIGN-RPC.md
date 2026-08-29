# Control-plane RPC — design spec

Status: **layer implemented; verbs pending.**

Done: `Kind::Request`/`Kind::Response`, the `Rpc` trait, per-verb version
ranges with range-carrying refusals, `API_VERSIONS`, `UnsupportedVerb` /
`UnsupportedVersion` codes, and the `RpcPeer` — wired into both the
coordinator's control session and the relay's link to it, with responses
routed through each side's existing stream writer. Covered by unit tests
for correlation, timeout, session-close and version refusal, plus an
end-to-end test over a real QUIC session.

Also done: **identity rotation** as the first real verb. Pins are now a
set (`PinSet`) with an overlap rather than a single `Option<String>`,
migrated transparently from legacy registries. The member side stages a
new identity, registers it over the authenticated session, and promotes
it only on success — so any interruption leaves the working identity in
place. Off by default (`rotate_identity_after_days = 0`).

Pending: migrating `Refresh` onto RPC, deleting `Pong`, and secrets
management (`secrets.toml`, admin login + sessions).

**Known limitation — relay rotation.** A relay's pinned fingerprint is
what *dialers* verify against, so the fleet must learn the new
fingerprint before the relay starts presenting it. The coordinator
republishes the relay list on rotation, but that propagation has not been
verified under load, and `RelayEndpoint.cert_fp` carries a single
fingerprint rather than the whole valid set. Until that is addressed,
leave rotation off for relays; clients have no such constraint because
nothing dials them.

## Why

The coordinator's control stream (QUIC, port 14433) carries no tunneled
data — it is a control channel. But it has no request/response layer:

* every upstream message is fire-and-forget. The coordinator accepts
  `Attach`, `MtuReport`, `Ping`, `Refresh`, `TrafficReport` and answers
  none of them;
* `Kind::Pong` has been declared since the beginning and is neither sent
  nor handled — a verb that exists only to look like a protocol;
* failure has one channel: `anyhow::bail!` out of `reader_loop`, which
  tears down the whole session. A member whose `Refresh` was rejected
  learns only that the connection dropped, indistinguishable from a
  network blip.

That is survivable for notifications. It is not survivable for the next
operation we want — **identity rotation** — where "did my new key get
pinned?" cannot be answered by guessing.

## Shape

Two new envelope kinds. The envelope itself is unchanged and stays
frozen; this is additive, and old peers skip unknown kinds by length.

```
Kind::Request  = 16   Request  { req_id: u64, verb: u16, version: u16, payload: Vec<u8> }
Kind::Response = 17   Response { req_id: u64, code: ErrorCode, payload: Vec<u8> }
```

Verbs live in **their own registry**, separate from envelope kinds, so
the two namespaces stop being conflated.

### Typed at every call site

`Vec<u8>` on the wire is deliberate — it is what lets an old peer skip a
payload it cannot parse. But no call site should ever see bytes. That is
the difference between a protocol and ad-hoc wiring:

```rust
trait Rpc: Serialize + DeserializeOwned {
    const VERB: u16;
    const VERSIONS: RangeInclusive<u16>;
    type Response: Serialize + DeserializeOwned;
}

// call site — no bytes, pairing enforced by the compiler
let ok: RotateIdentityOk = session.call(RotateIdentity { .. }).await?;
```

Encoding lives in exactly one place, so swapping it later is a one-file
change rather than a protocol migration.

### Per-verb versioning (Kafka model)

Each side advertises, per verb, the version range it supports. The caller
picks the highest mutually supported version. This is what makes
backward compatibility real, and it is why the payload encoding does
**not** need to be self-describing:

> Measured, not assumed: adding one optional field to a bincode payload
> fails in *both* directions — `V2 -> V1` errors with "slice had bytes
> remaining", `V1 -> V2` with `UnexpectedEof`. JSON tolerates both. But
> per-verb versioning removes the need for that tolerance, because each
> version has its own fixed schema. Kafka does exactly this over a rigid
> binary encoding. **Keep bincode.**

Versioned payloads are separate types (`RotateIdentityV1`,
`RotateIdentityV2`) with `From` conversions, chosen at encode time from
the negotiated version.

### Errors are answers, not disconnections

Every request gets a response, correlated by `req_id`. Reusing the
existing shared `ErrorCode` (which already carries `Unknown(String)` for
version skew, so an old peer meeting a new code degrades instead of
failing):

* **unknown verb** — `UnsupportedVerb`. The receiver has the verb id and
  the payload length, so it skips the payload and answers cleanly. This
  works in both directions.
* **unknown version** — `UnsupportedVersion`, carrying the range the
  receiver *does* support, so the caller can adapt rather than guess.

Neither closes the session.

## Requirements

1. **Bidirectional.** Coordinator→member requests are as useful as the
   reverse ("resync your attachments now") and cost nothing if allowed
   from the start.
2. **No head-of-line blocking.** It is one ordered QUIC stream, so a slow
   handler stalls everything behind it. Handlers are spawned; responses
   serialize through the existing writer task.
3. **Pushes stay pushes.** Membership snapshots are chunked and
   streaming. Forcing them into request/response would be a downgrade.
   RPC coexists with the push channel.
4. **Every pending request resolves** — on response, on timeout, or with
   a defined error when the session drops. No caller waits forever.

## Version scopes

Three, with distinct jobs. Conflating them is the mistake to avoid:

| scope | covers | policy |
| --- | --- | --- |
| envelope **major** | envelope layout itself | strict; already enforced in `decode` |
| envelope **minor** | wire changes outside RPC payloads — data-plane framing, push schemas | strict, checked once at `Hello` |
| **per-verb version** | RPC payload schemas | negotiated; where backward compatibility lives |

`PROTO_MINOR` is the *protocol's* version, deliberately not the crate's:
a patch release that changes nothing on the wire must not force a
fleet-wide restart, and a wire change in a patch release must. Tying it
to the build version gets both backwards.

`check_version()` and its tests already exist in `envelope.rs` and are
**not yet wired into any handler**. Both session types — the
coordinator's control stream and a relay's data session — open with an
enveloped `Hello`, so one check at that point covers both. It would have
caught the lane-framing incompatibility, which currently desyncs
silently.

## First user: identity rotation

Rotation is why this exists, and it should be the first verb — it proves
the layer end to end.

Today `pubkey` and `cert_fp` are `Option<String>`: exactly one pin each.
Rotation makes them a small set with states, mirroring the active/
retiring model the coordinator already uses for its **own** signing keys
in `KeySet`:

```
Pin { key, state: active | retiring, retires_unix }
```

* The member sends `RotateIdentity { new_pubkey, new_cert_fp }` **on the
  authenticated control session**. No signature is needed: mutual TLS
  plus the `cert_fp` verified at `Hello` already proves possession of the
  current identity. Re-deriving that proof over plaintext HTTP would be
  reimplementing, less safely, what the channel gives for free.
* The coordinator adds the new pin as `active`, marks the old
  `retiring` with a deadline, and answers. Both are accepted during the
  overlap, so a restart mid-rotation is safe either way.
* When a session authenticates with the new pin, the old may retire
  immediately rather than waiting out the window.

**Failure mode to design for deliberately:** if a member rotates and then
dies before ever using the new key, the old pin must stay valid until the
deadline. Switching eagerly would lock the member out and force
`reset-pin` — the one operation that reopens the trust window, and the
thing rotation exists to avoid.

### Call sites that must consult the pin set

All four are security-critical. Today each compares a single pin:

1. `state.rs` — join's TOFU branch (`rec.pubkey` / `rec.cert_fp`)
2. `control.rs` — `verify_credential`
3. `control.rs` — the `Refresh` continuity check, `claims.cert_fp != fp`
4. `coordlink.rs` (relay) — `verify_peer`

(3) is the landmine. It exists to stop a `Refresh` from changing who a
session belongs to, but rotation deliberately changes `cert_fp`, so a
credential minted for the new cert arriving on a session established with
the old one is rejected as an identity mismatch. The fix is "matches any
currently-valid pin for this member", **not** a relaxed equality —
loosening it carelessly reintroduces the session hijack the check was
written to prevent.

## Suggested order

1. RPC layer — the foundation.
2. Identity rotation as its first verb — proves the layer, and removes
   the need for `reset-pin` on planned key changes.
3. Migrate `Refresh` onto RPC; delete `Pong`.
4. Secrets management (`secrets.toml`, admin login + sessions) —
   independent of the above and the largest single piece.

## Out of scope here

Secrets management is specified separately. Decisions already taken:
admin auth is **username + password with server-side sessions** (not
bearer tokens), and `secrets.toml` **wins with the network config's
`secret_hash` as fallback**, so existing members keep working and migrate
one at a time.
