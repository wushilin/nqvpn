# DESIGN.md Review Issues

`DESIGN.md` has improved again. Pair-key derivation now separates networks,
node IDs are explicitly never reused, peer key changes invalidate cached
keys and sessions, and the path selector defines the no-candidate state.

The remaining issues below are based on the current draft and are ordered by
severity.

## 1. Critical — random epochs still do not provide durable replay protection

The design assigns a fresh random `u64` epoch at process start and retains
replay windows for the current and most recent prior epoch
(`DESIGN.md:310-323`). It still does not define an authenticated epoch
announcement, an ordering between random epochs, or durable receiver state.

A receiver cannot safely classify an unseen epoch:

- accepting it as new lets an attacker replay a captured frame from a
  forgotten epoch and promote that epoch to current;
- rejecting it prevents a legitimately restarted sender from communicating;
  and
- after the receiver restarts and loses its replay windows, previously
  captured traffic can be accepted again.

Deriving a different traffic key prevents nonce reuse, but it does not make
old ciphertext non-replayable under its old key.

Bind a collision-resistant boot/session identifier (preferably 128 bits) to
the sender's signed credential or coordinator membership entry. Receivers
should accept only the currently advertised identifier and, if required, one
explicit grace identifier. Define the authenticated transition, how delayed
membership is handled, and what happens when the coordinator is unavailable.
Tests must cover sender restart, receiver restart, delayed transition,
rollback to an old identifier, and replay after the old window was evicted.

## 2. High — KDF network separation is not bound to the trust authority

The new KDF salt includes `network_id` (`DESIGN.md:299-306`), which fixes
collisions between differently named networks on one coordinator. However,
`network_id` is a human-selected string whose uniqueness is only defined
within a coordinator. The same node keys, node IDs, and network name can
exist under two coordinators.

In that case the pair and traffic keys are identical. A node authorized in
both trust domains can replay a frame from one through its valid session in
the other, especially when both networks reuse the same private prefixes.
Credential issuer checks do not protect the frame after it has been copied
onto an authenticated target-network session.

Use a durable, random network UUID, or include an immutable coordinator/trust-
domain identifier plus the network ID in the KDF. Define canonical byte
encoding and include the same context in the sealing API so callers cannot
accidentally select a key from another network. Cross-authority tests should
use identical network names, node IDs, node keys, epochs, and inner prefixes.

## 3. High — direct reachability still lacks reverse connection establishment

The overview says a direct connection can be used when either node is
reachable (`DESIGN.md:39, 52-57`). The transport model only lets a node dial
a peer that advertises an endpoint (`DESIGN.md:402-406`). The new prober rule
requests such a dial when a direct candidate has no session
(`DESIGN.md:616-623`), but it does not make a private destination dialable.

If public A has traffic for private B, A cannot dial B and B receives no
signal asking it to reverse-dial A. A direct path appears only if B happens
to establish the connection for another reason.

Choose and specify one mechanism:

- coordinator-assisted reverse-connect requests;
- proactive private-to-public connections, including scaling and idle
  reaping; or
- a narrower v1 guarantee in which direct paths require the destination to
  advertise an endpoint.

Tests should cover public-to-private, private-to-public, both-public, and
both-private traffic initiated in each direction.

## 4. High — relayed Probe and Reply dispatch remains inconsistent

Relay behavior says frames addressed to another node are forwarded verbatim
(`DESIGN.md:416-425`). The inbound-dispatch pseudocode performs destination
routing only for Data. Probe and Reply are authenticated and consumed locally
without first checking `dst_id` (`DESIGN.md:591-603`).

For an A-to-B probe arriving at relay R, R does not possess the A-B probe key.
Following the pseudocode drops the probe and makes every relayed path appear
dead.

Define one common dispatch prefix for all frame types:

1. parse and structurally validate the common header;
2. enforce the arriving session's source rule;
3. if `dst_id != self` and the node may relay, forward verbatim in that
   session's network; and
4. only when `dst_id == self`, perform type-specific replay and AEAD checks.

Add end-to-end Probe and Reply tests through a relay, including forged source,
wrong network, unknown type, and malformed-header cases.

## 5. High — Refresh does not require continuity with the authenticated session

Nodes send `Refresh { credential }` over existing connections to extend their
lifetime (`DESIGN.md:140-143, 223-225, 567-570`). General credential
verification checks signature, network, membership, expiry, and TLS
certificate binding, but the design never says the refreshed credential's
identity must equal the identity already bound to that session.

Certificate fingerprints are not declared unique per member. Reusing one
certificate is particularly plausible for a relay process serving several
members or networks. Without an explicit continuity check, a credential for
another member using the same certificate could refresh or rebind an existing
session. This can undermine disablement and corrupt a relay's node-to-session
table.

A Refresh must preserve at least `(issuer, network, node_id, client_id,
pubkey, cert_fp)` from the original `PeerHello`. Define which authorization
claims may change, whether reductions such as `relay = false` take effect
immediately, and whether any identity change always requires a new QUIC
connection. Test cross-node, cross-network, disabled-node, changed-prefix,
changed-relay-permission, and same-certificate cases.

## 6. High — bincode does not provide the claimed rolling compatibility

The design says unknown control-message variants are ignored so minor
additions can roll out gradually (`DESIGN.md:376-384`). Ordinary serde/bincode
enum decoding normally fails on an unknown variant; adding fields is also not
automatically backward compatible. A `proto` value inside `Hello` cannot
protect parsing that must happen before `Hello` is decoded.

Put a stable envelope outside the version-specific payload, for example:

`major | minor | message_kind | payload_length | payload_bytes`

Unknown kinds can then be skipped by length. Specify capability negotiation,
the permitted changes within a major version, deterministic encoding limits,
and whether malformed or unsupported input closes a stream or the connection.
Run old and new codecs against each other in both directions.

## 7. High — signing-key rotation is still incomplete

Rotation requires old and new verification keys to coexist and be published
during an overlap (`DESIGN.md:209-220`). The concrete protocol and storage
model still show:

- one `coordinator_signing_key` in `JoinResponse`
  (`DESIGN.md:115-126`);
- no verification-key set in the shown Membership/PeerInfo shape
  (`DESIGN.md:132-139`); and
- one durable signing keypair rather than a persisted keyring
  (`DESIGN.md:216-220`).

An existing node can therefore reject a peer's newly signed credential, and
a coordinator restart during rotation can lose a retiring key.

Specify a durable keyring with active, pending, and retiring states; an
authenticated keyset message; how trust in a newly introduced key is
established; which key signs during each stage; and the exact retirement
condition. Include restart tests at every rotation stage.

## 8. Medium — membership snapshots and deltas lack revisions

Membership is initially full, later incremental, and may be chunked
(`DESIGN.md:132-143, 376-384`). There is no snapshot ID, directory revision,
chunk sequence, atomic completion marker, or delta-gap recovery rule.

A change interleaved with a chunked snapshot, or a reconnect near a delta
boundary, can produce a mixed peer/LPM table that retains revoked routes or
omits valid ones.

Give each network directory a monotonically increasing revision. Snapshot
chunks should carry the snapshot revision and chunk index/count; nodes should
assemble and validate them off-path, then install the completed snapshot
atomically. Deltas should state their base and resulting revisions, with any
gap forcing a new snapshot.

## 9. Medium — disable state is not included in durable coordinator state

The admin API can disable and enable a client (`DESIGN.md:244-254`), but the
durable registry contains only IDs, pins, certificate fingerprints, and
dynamic addresses (`DESIGN.md:209-217`). It is unclear whether the endpoint
rewrites the operator-owned TOML or records a durable operational override.

An in-memory disable can disappear on restart. Directly editing TOML creates
different problems around concurrent manual edits, atomic replacement, file
ownership, and reload failures.

Persist administrative disablement explicitly, or define a safe config-
mutation model. Test disable, coordinator restart, failed renewal, enable,
manual config edit, and reload interactions.

## 10. Medium — coordinator mutations have no serialization or commit model

Concurrent joins can allocate node IDs and VPN addresses, establish TOFU
pins, reserve prefixes, update the directory, issue credentials, and rewrite
the registry. An `ArcSwap` directory and atomically replaced file do not by
themselves prevent duplicate allocation or lost updates
(`DESIGN.md:209-220, 692-697`).

Define one transactional authority per network, such as a serialized actor or
a mutex-protected state machine with one durable writer. Do not return a
successful credential until the identity and allocation it depends on are
durably committed. Specify temporary-file handling, file and directory
`fsync`, rollback on write failure, and startup recovery.

## 11. Medium — endpoint advertisements can conflict with installed VPN routes

Nodes install host routes for coordinator, relay, and peer transport IPs via
the physical gateway before installing member prefixes through the TUN
(`DESIGN.md:492-502`). Endpoint advertisements are only gated by the broad
`may_advertise` permission (`DESIGN.md:148-164`).

A mistaken or malicious endpoint can equal a VPN address, fall inside an
advertised LAN prefix, or use an unsafe address class. The resulting host
route can override the intended VPN route and make another member unreachable;
loopback, unspecified, multicast, or otherwise local endpoints can also cause
surprising dials and route changes.

Define endpoint validation and route-conflict policy. At minimum, reject
invalid address classes and detect overlap with tunnel/member prefixes before
programming routes. If private or overlapping underlay endpoints are a
supported use case, require an explicit policy and specify precedence and
scope. Route installation must be transactional so a rejected membership
update cannot leave partial host routes behind.

## 12. Medium — config reload reconciliation is undefined

Reload validates the new TOML and keeps the old configuration on validation
failure (`DESIGN.md:146-165, 244-254`), but it does not define what happens
to already-issued credentials, active advertisements, sessions, pins, or
dynamic address allocations when a valid new configuration removes or
changes a client's permissions.

For example, a reload can remove A's permission for prefix P and assign P to
B while A still holds an unexpired credential containing P. The existing
first-registered rule may reject B, but the document does not say whether A
is immediately removed, retained until expiry, or grandfathered until its
next renewal.

Define reload as an atomic reconciliation transaction with explicit rules for
removed clients, reduced CIDR/relay/endpoint permissions, reassigned static
addresses, changed secrets, and registry entries no longer present in config.
State which changes are immediate and which follow the normal credential-TTL
revocation window. Test reload during active joins and sessions as well as
rollback after reconciliation or persistence failure.

## Verdict

The revised architecture is coherent, and the latest changes close the prior
same-coordinator key-separation issue. The epoch/replay lifecycle remains
release-blocking. Direct connection establishment, relay probe forwarding,
Refresh identity continuity, wire compatibility, and signing-key rotation
should be resolved before their protocol state machines are implemented. The
remaining consistency and persistence issues should be settled before the
registry and control formats become difficult to change.
