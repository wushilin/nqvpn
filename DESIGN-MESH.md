# nqvpn — Draft Design Plan

A symmetric-mesh, L3 (TUN-based), dual-stack (IPv4 + IPv6) VPN in Rust.

There is **no VPN server**. There are only:
- a **coordinator** — a small axum control-plane service that touches no
  traffic and has **no data-plane identity at all** (no node id, no
  prefixes, appears in no forwarding table): membership, authentication,
  prefix planning/conflict rejection, key & endpoint directory,
  credential signing, status. One coordinator hosts **many isolated
  networks**
  (virtual switches) keyed by `network_id` — hundreds are fine, since it
  only ever serves control traffic;
- **nodes** — all running the same binary with equal roles. A node that is
  publicly reachable may **relay** for others; a private node picks its
  best relays by measurement. All paths are continuously (and lightly)
  probed and re-selected — BGP-like in spirit (prefix advertisement +
  measured path selection), deliberately one-hop, not a path-vector
  protocol.

The routed **prefix is the primitive**, not the address: a VPN address is
just an auto-advertised /32 (v4) or /128 (v6) prefix, and is **optional**
per node — a headless gateway node advertises only the LAN CIDRs behind it.

Status: **draft for review** — nothing here is final.

---

## 1. Architecture overview

```
                      coordinator (control only, no traffic)
                     HTTPS /join + QUIC control stream (push)
                      ▲                ▲                ▲
                      │                │                │
                  node A ◄════════ node R ════════► node B
                 (private)      (public, relays)     (private)
                      ║                                 ║
                      ╚═══════ direct QUIC (if A or B reachable) ═══╝

  data frames are END-TO-END encrypted (X25519 + AEAD) and addressed by
  NODE ID — relays forward opaque frames by prefix→node lookup and can
  never read traffic.
```

- Every node: QUIC endpoint + TUN + forwarding + prober. Identical code;
  behavior differs only by config:
  - `advertise_endpoints` set ⇒ **public**: accepts direct connections and
    (unless `relay = false`) relays frames for others.
  - `--relay-only` ⇒ public node with no TUN — a pure relay; the
    deployment replacement for the old "VPN server", typically co-located
    with the coordinator. A relay is required **only when some nodes
    cannot all reach each other directly** — an all-public mesh runs
    relay-free — but in practice nearly every deployment wants one.
- Path choice is per-sender, per-peer-node: direct if possible and
  measured best, else the best of the peer's published home relays. A→B
  and B→A may use different paths (fine at L3).

## 2. Addressing model

- The coordinator assigns each member a stable **node id** (`u32`). All
  frame addressing, probing, pair-key derivation, and relay forwarding use
  node ids — never inner IPs.
- Each node **owns a set of prefixes** (both families), the union of:
  - its optional VPN address(es), auto-advertised as /32 and /128, and
  - its human-planned `routed_cidrs` (LANs behind it).
- Forwarding anywhere in the system is one operation: LPM over
  (prefix → node id), then "how do I reach that node id" (path selection).
- **Headless mode**: a node with no VPN address participates fully as a
  gateway — inner packets carry real LAN addresses end to end. It cannot
  itself be addressed (no prefix terminates at it), which is acceptable
  for a pure gateway; probes still work because they target node ids, not
  addresses.

## 3. Coordinator

### 3.0 Networks (virtual switches)

The coordinator hosts N fully isolated networks, each identified by a
`network_id` string — the ZeroTier controller model. Per network:
its own tunnel subnets, IPAM, prefix plan, membership directory, node-id
space, and registry. There is no routing between networks, ever.

- Every scoping rule below applies **per network**; `client_id` is unique
  within a network, node ids are per-network.
- A session (control or data) is bound to exactly one network at
  authentication time, so the wire format needs no network field — a relay
  simply forwards within the network its session authenticated into.
- **Shared relay fleet**: because data frames are e2e-encrypted and
  sessions are network-bound, a relay-only node may be authorized in many
  networks simultaneously — one public relay fleet can serve all networks
  with isolation intact. TUN-bearing nodes join one network per process in
  v1 (run two processes for two networks).
- Config: one TOML per network under `networks.d/<network_id>.toml`
  (subnets + client list), loaded and overlap-validated independently —
  500 networks is just 500 small files and a directory scan.

### 3.1 Member API: POST /api/v1/join (HTTPS, PORT1)

Request:
```json
{
  "network_id": "acme-prod",
  "client_id": "laptop-1",
  "client_secret": "…",
  "pubkey": "base64(x25519 public key)",
  "want_vpn_ip": true,
  "routed_cidrs": ["192.168.50.0/24", "fd50:1::/64"],
  "advertise_endpoints": ["203.0.113.7:4444"],
  "relay": true,
  "cert_fingerprint": "sha256:…",
  "epoch": "0x9f3a5c21d4e8b07f"        // random u64, this boot (§4)
}
```

Response:
```json
{
  "credential": "eyJ… (JWT, see §3.3)",
  "network_uuid": "b7e2…-…(random 128-bit, minted at network creation, permanent)",
  "coordinator_signing_keys": [ { "kid": "2026-08", "key": "base64(ed25519)", "state": "active" } ],
  "node_id": 7,
  "ip4": "10.99.0.5",  "subnet4": "10.99.0.0/16",   // absent if headless
  "ip6": "fd99::5",    "subnet6": "fd99::/64",
  "coordinator_quic": "coord.example.com:4433",
  "mtu": 1350,
  "keepalive_secs": 15
}
```

The node then opens a **QUIC control connection** to the coordinator
(PORT2, mutual TLS with the node's self-signed cert, control streams
only — the coordinator never carries data):
- `N→C Hello { credential }` / `C→N HelloAck` — accepted iff the
  credential verifies and its `cert_fp` matches the TLS client cert.
- `C→N Membership` — **revisioned**: each network directory carries a
  monotonically increasing `revision`. A full snapshot is sent as chunks
  `{ snapshot_rev, chunk_i, chunk_n, peers: [PeerInfo] }`, assembled
  off-path and installed **atomically** only when complete; deltas are
  `{ base_rev, new_rev, changed: [PeerInfo], removed: [node_id] }` and a
  node whose current revision ≠ `base_rev` discards the delta and
  requests a fresh snapshot — a reconnect or interleaved change can
  never yield a mixed peer/LPM table.
  ```
  PeerInfo { node_id, client_id, prefixes: [cidr],   // vpn /32s + routed LANs, unified
             pubkey, endpoints, cert_fingerprint, epoch,  // sender's current boot epoch (§4)
             relay: bool, online: bool, home_relays: [node_id] }
  ```
- `N→C HomeRelays { relays: [node_id] }` — re-published on change.
- `N→C→N ConnectRequest { to: node_id }` — coordinator-forwarded (only
  between online members of one network, rate-limited): "dial my
  advertised endpoint". This is how a **public** node obtains a direct
  path from a **private** peer that cannot be dialed — the private side
  reverse-dials (§6). Both-private pairs have no direct path in v1 (no
  hole punching), by design.
- `C→N KeySet { keys: [{kid, key, state}] }` — pushed when the signing
  keyring changes (§3.3), so long-lived sessions learn a new
  verification key before credentials signed by it arrive.
- `N→C Refresh { credential }` — after renewal (§3.3), also forwarded by
  nodes to their relays/peers to keep long-lived sessions alive across
  credential expiry.
- Keepalives both ways: the node treats a missed coordinator as
  "reconnect, then rejoin" (idempotent for static assignment); the
  coordinator marks a member **offline after 3 missed keepalives**
  (≈ 3 × `keepalive_secs` = 45 s) and pushes a membership delta with
  `online: false`; a successful `Hello` flips it back. Liveness
  semantics and what peers do with the flag: §6 "Dead peers & relays".

### 3.2 Prefix planning & conflict policy (human-planned)

- The coordinator's TOML config is the **plan of record**: per client —
  secret hash, optional static VPN IPs, `allowed_cidrs`, `may_advertise`,
  `relay` permission, optional pinned pubkey.
- **Startup validation**: overlapping `allowed_cidrs` across clients, or
  overlap with the tunnel subnets, fail coordinator startup with a clear
  error. Conflicts are a planning bug caught before anything runs.
- **Join validation**: requested `routed_cidrs` ⊆ that client's
  `allowed_cidrs`, else reject. A late joiner whose request overlaps any
  *currently advertised* prefix is rejected (first-registered wins) —
  this can only happen across config reloads, since validated configs are
  overlap-free by construction.
- No automatic conflict resolution, no longest-prefix tie-breaking between
  members in v1 — by design, per human planning.
- Dual stack: IPv4 tunnel subnet always defined; IPv6 when `subnet6` set
  (recommended: ULA, e.g. `fd99::/64`). Prefix lists mix families.
- `advertise_endpoints` gated by `may_advertise`; explicit only — no hole
  punching, no reflexive-address discovery in v1.
- **Endpoint validation** (join-time, before an endpoint ever reaches
  membership): reject loopback, unspecified, multicast, and link-local
  addresses outright; reject any endpoint that overlaps a tunnel subnet
  or any member prefix — nodes install *host routes* to peer endpoints
  via the physical gateway (§7), and an endpoint inside VPN-routed space
  would let that host route shadow a member route (mistake or attack,
  same result). Private/RFC1918 endpoints are allowed (same-LAN peers
  are legitimate) as long as they clear the overlap check. On the node
  side, route programming is transactional per membership update: a
  diff that fails to apply is rolled back — no partial host routes.
- Secrets: argon2 hashes in config; used **only** at the HTTPS API.
- **Reload reconciliation** (`POST /api/v1/reload`, §3.4) is an atomic
  transaction: validate the new config in full (any error ⇒ old config
  keeps running untouched), then diff against live state and apply with
  the same trust rules as revocation — nothing is yanked out from under
  an unexpired credential except visibility. Concretely: a removed or
  permission-reduced client is dropped from membership **immediately**
  (honest nodes drop its routes/sessions now) and its next renewal fails
  or grants the reduced set — the hard guarantee stays revocation-by-
  expiry (≤ TTL, §3.3). A prefix moving from A to B follows
  first-registered wins: B's advertisement is accepted only once A's is
  gone from the directory. Changed secrets take effect on the next API
  call. Registry entries (pins, node ids) of clients no longer in config
  are retained inert — ids are never reused (§3.3) — until an explicit
  admin purge.

### 3.3 Security model: API auth once, signed credentials everywhere else

The coordinator is a **signing authority**; everything downstream verifies
offline. `client_id`/`client_secret` are presented only to the HTTPS API;
no other component ever sees or checks secrets.

- **Credential**: a JWT (EdDSA/Ed25519, signed by a per-coordinator
  keypair) with claims:
  `{ iss, network_id, node_id, sub: client_id, pubkey (x25519),
     cert_fp, prefixes, relay, may_advertise, iat, exp }`.
  TTL default **15 min**. It rides only in control streams, never in data
  frames, so size is irrelevant.
- **Verification is offline**: signature against the coordinator signing
  key + `exp` check + **possession proof** — every node↔node / node↔relay
  / node↔coordinator QUIC connection uses mutual TLS with the nodes'
  self-signed certs, and the acceptor requires the presented TLS cert's
  fingerprint to equal the credential's `cert_fp`. A bare bearer token
  could be replayed by an observer; the cert binding makes the QUIC
  handshake itself the proof of ownership. Verifiers additionally check
  `iss` and `network_id` against the network the session is
  authenticating into, `aud = "nqvpn-v1"` (protocol binding), and — where
  the acceptor holds a membership entry for that node id — that the
  credential's claims agree with it. Answering "is this a valid
  member" never requires a coordinator round-trip.
- **Client-side trust is exactly two things**: the coordinator's HTTPS
  cert (webpki or pinned), and the coordinator signing keyset learned
  over that channel (also pinnable in config). Peers trust each other only via
  coordinator-signed credentials — no PKI, no peer-managed trust.
- **Per-node key pinning (TOFU)**: the coordinator *keeps* each node's
  `(pubkey, cert_fp)` — recorded durably on first successful join, and
  every subsequent join must present the same key or is rejected
  (pre-provisioned pins in config for stricter setups; an admin command
  resets a pin when a machine is rebuilt). This makes identity
  two-factor — a stolen `client_secret` alone can no longer impersonate a
  node, since the impersonator lacks the pinned private key — and it
  anchors the distributed offline checks: what peers and relays verify in
  credentials/membership is the coordinator-certified pinned key, not
  whatever key was presented last. Pins live in the durable per-network
  registry (below).
  Future (v2): once pinned, joins can authenticate by the key itself
  (mutual TLS on the API), demoting `client_secret` to a one-time
  enrollment secret; v1 requires secret + key, strictly stronger.
- **Durable coordinator state** — everything a restart must not lose,
  because credentials, pair-key salts, and every peer's routing table
  embed it. Per network, one small atomically-rewritten **registry**
  file: `{network_uuid (minted once at network creation, immutable),
  client_id → node_id, pinned pubkey, cert_fp, assigned VPN addresses
  (when IPAM is dynamic), disabled: bool}`. `disabled` is the durable
  form of the admin disable/enable action (§3.4) — an operational
  override that survives restart, is never written into the
  operator-owned TOML, and composes as: effective-enabled = present in
  config ∧ ¬registry.disabled. Node ids are **never reused**: a
  deleted client's id is retired forever (u32 space is not scarce), so a
  stale membership view can never route an old id's prefixes to a new
  owner. Per coordinator: the Ed25519 **signing keyring** on disk (mode
  0600, backed up like any secret) — a set of keypairs each with `kid`
  and state `active | retiring`, not a single key. Exactly one key is
  `active` and signs everything; rotation = add new key as `active`,
  demote old to `retiring`, publish the full verify set via
  `JoinResponse.coordinator_signing_keys` and a pushed `KeySet` message
  (trusted because both arrive over already-authenticated channels),
  and delete the `retiring` key only after every credential it could
  have signed has expired (> TTL after demotion) — restart at any stage
  reloads the keyring exactly as persisted.
- **Mutation model** — all coordinator writes for one network go through
  **one serialized owner** (a per-network actor task): join allocations
  (node id, addresses), TOFU pin establishment, prefix registration,
  disable flags, registry rewrite. Concurrent joins cannot double-
  allocate because there is exactly one allocator. Durability precedes
  visibility: a `/join` response (and the credential in it) is returned
  only after the registry write is committed — temp file, fsync, rename,
  fsync directory — so a crash can lose an allocation a client never
  saw, but never one it holds. `ArcSwap` snapshots serve reads only.
  Static config (clients, subnets, planned prefixes) is not state — it
  lives in `networks.d/` and is re-read at startup.
- **Renewal**: before `exp` (or after, it's stateless) the node re-calls
  `/join` — idempotent for static assignment — gets a fresh credential,
  and sends `Refresh` on existing sessions so they survive expiry.
  **Refresh is identity-continuous**: the acceptor requires the new
  credential's `(iss, network_id, node_id, sub, pubkey, cert_fp)` to
  equal the identity bound to the session at `Hello`/`PeerHello` time —
  a valid credential for a *different* member (entirely plausible where
  one TLS cert serves several credentials, e.g. a multi-network relay
  process) can never rebind an existing session or bypass disablement.
  Authorization claims (`relay`, `may_advertise`, `prefixes`) may
  change, and reductions take effect immediately on that session (e.g.
  `relay = false` ⇒ stop forwarding for it now). Any identity change
  requires a new connection.
- **Revocation is eventual by design**: remove/disable the client in
  coordinator config ⇒ renewal fails ⇒ the node loses all sessions at
  next credential expiry (≤ TTL). Accelerants, best-effort on top of that
  guarantee: the coordinator pushes membership removal (honest nodes drop
  sessions and routes immediately), and relays/peers enforce `exp` on
  live sessions — a session with an expired, un-refreshed credential is
  closed.
- This replaces the earlier single-use join tokens and pairwise tickets
  entirely: **one credential per node per network** authenticates the
  coordinator control connection, relay sessions, and direct peer dials.

### 3.4 Admin API & control-plane web UI

Same axum process, same PORT1. The full HTTP surface, two auth realms —
**member** (client_id + client_secret, argon2-checked) and **admin**
(admin users in coordinator config, argon2 hashes; session cookie or a
static bearer token for automation):

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/v1/join` | member | join **and** renewal (§3.1, idempotent) |
| `GET /api/v1/status` | admin | global summary: networks, members/online, relay fleet (§9) |
| `GET /api/v1/networks` | admin | list networks + per-network counters |
| `GET /api/v1/networks/{id}/status` | admin | full per-network view (§9 payload) |
| `GET /api/v1/networks/{id}/peers/{node_id}` | admin | one peer: pins, prefixes, endpoints, home relays, last_seen, recent credential issues |
| `POST /api/v1/networks/{id}/clients/{client_id}/reset-pin` | admin | TOFU pin reset for a rebuilt machine (§3.3) |
| `POST /api/v1/networks/{id}/clients/{client_id}/disable` (`/enable`) | admin | sets the durable `disabled` registry flag (§3.3 — survives restart, never edits the operator's TOML): blocks the next renewal ⇒ revocation-by-expiry, plus best-effort membership-removal push |
| `POST /api/v1/reload` | admin | re-read `networks.d/` with full overlap validation; on failure returns the errors and the old config keeps running |
| `POST /api/v1/admin/session`, `DELETE …` | — / admin | UI login/logout |

Error model, uniform: JSON `{ "error": { "code", "message" } }` with
meaningful codes the node acts on — `401 bad_credentials`, `403
pin_mismatch` (node stops retrying, tells the operator: admin reset
needed), `403 client_disabled`, `409 prefix_conflict` (late-joiner
rejection, §3.2), `429` on the per-`client_id`+IP rate limit for `/join`
(argon2 already makes brute force slow; the limiter makes it pointless).
`POST /api/v1/admin/session` is rate-limited the same way — the admin
login is the most valuable brute-force target on the port. Admin
sessions and the "recent credential issues" history are **in-memory
only** (lost on coordinator restart; log in again) — deliberately not
part of the durable state in §3.3.

**Web UI**: a static, dependency-free HTML/JS app **embedded in the
coordinator binary** (rust-embed) served at `/ui` — no separate
deployment, no build toolchain, no external assets (works air-gapped).
It is strictly a client of the admin API above: everything the UI can
show or do is equally scriptable with curl. Views (v1):

- **Networks overview** — table: network, members online/total,
  public/relay counts, prefix count.
- **Network dashboard** — peer table (online, VPN IPs, advertised
  prefixes, home relays, last seen), the prefix→owner table, relay fleet
  health.
- **Peer detail** — pinned pubkey/cert_fp + first-seen, endpoints,
  credential issue history; buttons: reset pin, disable/enable.
- **Operations** — config reload button with validation-error display.

Live-ness is 5-second polling, no websockets in v1. Session cookies are
`HttpOnly` + `SameSite=Strict`; mutating routes additionally require a
CSRF token. Scope note: the UI shows **control-plane truth only** — path
choices and per-path RTT/loss are sender-local facts that never reach
the coordinator; they live in `nqvpn status` on each node (§9). Network
create/delete stays config-file + reload in v1 (open question #10 covers
promoting lifecycle to the API/UI).

## 4. Identity & end-to-end encryption

Because relays are **other members' machines**, hop encryption (QUIC TLS)
is not enough — relayed traffic must be unreadable by the relay.

- Each node has a static **X25519 keypair**; pubkey registered at join,
  distributed in `PeerInfo`. The coordinator is the trust anchor binding
  client_id ↔ node_id ↔ pubkey ↔ prefixes.
- Pair secret for nodes (A, B):
  `S = HKDF-Extract(X25519(a_priv, B_pub), salt = network_uuid(16) ‖
  be32(min(node_id)) ‖ be32(max(node_id)))` — canonical byte encoding,
  no strings. The salt binds keys to the **network UUID** (random
  128-bit, minted once at network creation, §3.3), not the human-chosen
  `network_id` name: node ids are only unique per network, names are
  only unique per coordinator, and the same node keys/ids/name can
  recur under two coordinators — the UUID is unique across trust
  domains, so a frame sealed in one network verifies nowhere else, ever.
  The sealing API takes the UUID as required context, so a caller
  cannot even express "seal with another network's key". Traffic keys
  derive from `S` per direction, per **epoch**, and per domain:
  `key = HKDF-Expand(S, info = sender_id ‖ epoch ‖ label)` with
  `label ∈ {"data", "probe"}` — data and probe keys occupy disjoint
  domains, so their counters are independent. No pairwise handshake —
  both sides derive keys from membership alone.
- **Epoch = fresh random u64 per process start, registered at join and
  advertised through membership** — not inferred from the wire. The
  node reports its epoch in `/join` (a restart re-joins, so a new epoch
  is published automatically); `PeerInfo.epoch` carries every member's
  current epoch. A receiver accepts a frame **only under the sender's
  advertised epoch** — plus, for one `decision_interval`, the
  previously advertised one (grace for frames in flight across the
  transition). The frame-header epoch field selects which of those two
  keys to try; any other value drops + counts. This closes epoch
  classification completely: an attacker replaying a captured
  old-epoch stream fails because that epoch is no longer advertised in
  coordinator-authenticated membership, and a restarted sender is
  accepted exactly when its membership update lands. Delayed membership
  just drops a few frames (retransmitted); a node that restarts while
  the coordinator is down stays offline anyway — it cannot rejoin
  (consistent with §8's outage story).
- Why epochs exist: a rebooted node's counters restart at zero, but
  under a new epoch its traffic keys are new too, so (key, nonce) pairs
  never repeat across boots — no counter persistence, no crash-recovery
  protocol. Random 64-bit epochs make cross-boot collision negligible
  (birthday bound ~ n²/2⁶⁵); a sender that somehow nears counter
  exhaustion (2⁶³) rolls a new epoch by re-joining.
- Frames sealed with ChaCha20-Poly1305; nonce = 32 zero bits ‖ 64-bit
  per-direction counter (uniqueness holds per key; keys are per epoch);
  the full header rides as AEAD associated data. Receiver keeps, per
  (pair, direction), derived keys + a sliding replay window per accepted
  epoch (at most two live at once, per the advertisement rule above).
- **Accepted v1 replay residual**: a receiver that restarts loses its
  replay windows; until genuine traffic re-baselines each window, a
  frame captured earlier *within the sender's still-current epoch* could
  be delivered once more. Bounded (once per receiver restart, current
  epochs only, window re-arms on first real frame) and accepted for v1;
  the Noise re-key upgrade below eliminates it.
- Tradeoff (accepted for v1): static-static ECDH has no per-pair forward
  secrecy. Upgrade path: background Noise IK re-key over the data path (a
  frame type is reserved); node keys rotate by re-registering.
- **All** data frames are e2e-sealed, even on direct connections (QUIC TLS
  adds a second layer there). One code path, no cleartext-inner anywhere.
- **Per-packet origin authenticity, no signatures, no hot spot**: the AEAD
  tag *is* the origin proof — only the holder of the claimed sender's
  pinned private key can produce ciphertext that verifies under the pair
  key, so every decrypted frame authenticates its `src_id` to the
  receiver, offline (trust chain: coordinator-signed credential → pinned
  pubkey → pair key → AEAD tag). Per-packet asymmetric signatures would
  prove the same thing ~20–50× slower. Additionally, every hop binds
  `src_id` to the session: a relay drops frames whose `src_id` ≠ the
  arriving session's credential-authenticated node id, so spoofed frames
  can't even transit an honest relay. A *receiver* accepts a frame only if
  `src_id` == the session peer, **or** the session peer's credential has
  `relay = true` (relayed frames legitimately arrive carrying the origin's
  `src_id` on the relay's session); in both cases the AEAD check then
  proves the true origin. A malicious relay can drop or delay (probing
  routes around it) but can never forge origin — forged frames fail the
  destination's AEAD check.
- **Inner-packet ingress filter** — the frame layer authenticates
  `src_id`, but the *inner* packet must be checked too, or an
  authenticated member could source-spoof another member's addresses or
  bounce traffic off a gateway (confused-router abuse). After unseal,
  before the TUN write: inner source address must fall within a prefix
  owned by `src_id`, and inner destination within a prefix owned by the
  receiving node (two LPM lookups against current membership); the IP
  version nibble must match the parsed family; truncated or malformed
  headers drop + count. Fragments carry full IP headers, so the same
  address checks apply; membership changes take effect on the next
  lookup.

## 5. Wire format (QUIC datagrams)

IP packets ride **QUIC datagrams** (RFC 9221), never streams — a
reliable ordered stream retransmits and re-orders under loss,
head-of-line-blocking every tunneled packet behind it and stacking a
second loss-recovery loop beneath the inner TCP flows (the classic
tunnel-over-reliable-transport meltdown). Streams carry only control
messages, framed by the envelope below.

```
0x01 Data:   [type 1][src_id 4][dst_id 4][epoch 8][ctr 8][AEAD ct (inner IP pkt)]
0xF1 Probe:  [type 1][src_id 4][dst_id 4][epoch 8][seq 8][t_sent 8][AEAD tag 16]
0xF2 Reply:  probe echoed, src/dst swapped, re-tagged by the replier
```

Probes carry an AEAD tag under the pair's **probe-domain** key (§4;
header as associated data), so path measurements can't be forged or answered
by a third party — a spoofed reply fails the tag check and counts as loss.

**Versioning & parser hygiene**: every control message rides a
fixed-layout **envelope** whose header layout is frozen forever:

```
[major u8][minor u8][kind u16][len u32][payload: len bytes]
```

Version bytes sit *outside* the payload, at fixed offsets readable
before any deserializer runs — a `proto` field buried inside a bincode
`Hello` cannot version the parsing of `Hello` itself. Rules: `major`
mismatch ⇒ explicit `IncompatibleVersion` close of the connection.
Within a major, unknown `kind` ⇒ **skip `len` bytes** and continue —
that, not bincode enum tolerance (bincode fails on unknown variants),
is what makes rolling upgrades work. The compatibility contract is
therefore: within a major version, existing payload schemas are
**frozen** — evolution is always a new `kind`, never a field added to
an old one; `minor` only advertises which kinds a peer understands.
`len` is hard-capped (1 MiB; `Membership` chunks stay well below it)
and payloads decode with strict bincode limits on collection/string
sizes — an authenticated but malicious member must not be able to
exhaust a peer's memory. Malformed *payload* ⇒ close the stream;
malformed *envelope* ⇒ close the connection; never the process. Unknown
*datagram* type bytes drop + count. Old-vs-new codec matrices are fuzz
and compatibility targets in Phase 8.

- Relays forward on `dst_id` alone; ciphertext is opaque to them. Probes
  are answered by the destination node on the transport they arrived on;
  `t_sent` is the sender's monotonic clock — RTT needs no clock sync.
- MTU: inner tunnel MTU **1350** (outer 1500 − IP/UDP/QUIC ≈ 60 − header
  25 − AEAD tag 16 leaves comfortable margin, v6 outer included).
  Oversized ⇒ drop + count.

## 6. Transports, relays, path selection

**Connections a node maintains:**
1. Coordinator control connection (always).
2. **Home relays**: every private node QUIC-connects to its best `K`
   (default 2) relays — chosen by probing the relay set — authenticates
   with `PeerHello { credential }` over mutual TLS (§3.3: offline verify +
   cert_fp binding), keeps the connection alive (that inbound-less link is
   how relays deliver to it), and publishes the list via `HomeRelays`.
3. **Direct peer connections**, on demand: if peer B advertises endpoints,
   dial with B's pinned `cert_fingerprint` from membership (MITM-proof
   self-signed certs via rcgen), mutual TLS, `PeerHello { credential }`
   verified the same way on both sides. When both advertise, the lower
   node_id dials. When **only I** advertise (I'm public, B is private),
   I can't dial B and B doesn't know I want a path — so I send
   `ConnectRequest { to: B }` through the coordinator (§3.1) and B
   reverse-dials my advertised endpoint; the resulting connection is a
   direct path candidate exactly as if I had dialed. Direct-path
   coverage in v1 is therefore: at-least-one-side-public ⇒ possible;
   both-private ⇒ relay only (no hole punching).
4. **On-demand relay sessions**: to reach peer B via one of *B's* home
   relays, the sender dials that relay (same credential auth) if it
   doesn't already hold a session there — B's home relays need not be the
   sender's own. With a shared relay fleet they usually coincide and no
   extra dial happens. While a dial is in flight, frames for that peer
   wait in a small bounded per-peer queue (default 64 packets,
   drop-oldest on overflow) — never unbounded buffering. Idle on-demand
   sessions are closed after 10 min.

**Relay behavior** (public node, `relay = true`): inbound frame → drop
unless `src_id` equals the arriving session's authenticated node id
(anti-spoofing, §4); then look up `dst_id` in the session table **of the
network the arriving session authenticated into** — a multi-network relay
keys every table by (network_id, node_id), and a session's network is
fixed at `PeerHello` time by its credential's `network_id`, so a frame
can never cross networks regardless of ids. If a live
credential-authenticated session exists there, forward verbatim; else
drop + count (the sender's probes on that path fail and it re-selects). One hop only — never relay→relay. Sessions are closed at
credential `exp` unless refreshed (§3.3).

**Path selection, per peer node** — candidates = { direct (if dialable) }
∪ { B's home_relays reachable by me }:
- **Light continuous probing**: one probe per (peer, path) per
  `probe_interval` (default 2 s ± 25 % jitter) — per peer *node*, not per
  prefix, so a gateway advertising ten networks costs one probe stream.
  At defaults that is < 40 bytes/s/path. RTT EWMA (α = 0.2) + loss
  counter (no reply in 3 s = lost).
- Probing **pauses for idle peers** (no traffic 5 min); first packet to an
  idle peer uses last-known-good and wakes the prober.
- Re-decide every `decision_interval` (15 s) with hysteresis: switch only
  if the challenger has ≥ 5 samples, acceptable loss, and
  `ewma < current × 0.9 − 2 ms`; prefer direct on ties. **Immediate**
  failover on 3 consecutive losses or transport death.
- The chosen path is an atomic per-peer value read by the TUN→net pump —
  switching is a flag flip, transparent to applications (transient
  reordering acceptable at L3).
- Home-relay selection for myself uses the same machinery on a slow timer
  (60 s) + on relay death; changes re-published via `HomeRelays`.

### Deployment profile: pure-relay (hub) mode

The classic three-role architecture — clients, relay backbone, control —
is a **configuration** of this design, not a different design: set
per-network `direct = false` (or simply advertise no client endpoints)
and no direct paths exist. Every flow is client → receiver's home relay
→ client; the machinery that remains is exactly the Phase-4 subset
(§12) — no direct dials, no `ConnectRequest`, no direct-path probing;
path selection degenerates to "which of the receiver's K relays", and
even that can be pinned. Two properties make this profile strictly
simpler than a routed relay backbone: senders reach the *receiver's*
relay directly using membership, so relays never route to each other
and carry **no shared routing state** (the one-hop invariant holds even
here); and turning short-circuiting back on later is a config change,
not a migration — the frame format, credentials, and sessions are
identical in both profiles. Operators who distrust the dynamic path
layer can run this profile indefinitely; it costs relay bandwidth
(every byte transits the fleet) and same-LAN locality, which is the
standing argument for eventually enabling direct.

### Dead peers & relays (automatic handling)

Two liveness detectors run independently, and they deliberately answer
different questions:

- **Data-plane truth (authoritative for forwarding)**: per-path probes
  (3 consecutive losses ⇒ immediate failover) and QUIC keepalive/idle
  timeouts (transport death ⇒ same). This layer already removes dead
  paths automatically, in seconds, with no coordinator involvement.
- **Control-plane liveness (advisory)**: the coordinator marks a member
  `online: false` after 3 missed keepalives (§3.1) and pushes the delta.
  Advisory *by design* — the data plane survives coordinator outages
  (§8), so "lost its coordinator link" must not be read as "dead": a
  peer with live sessions and answering probes keeps carrying traffic
  regardless of its flag.

What a node does on `online: false` for peer P — suppress, don't sever:
- **keep** live sessions to P and keep probing them (probes are the
  truth; if P is really dead they fail within seconds anyway);
- **stop initiating**: no new dials, no `ConnectRequest`, no on-demand
  relay sessions toward P; the prober's undialable-retry timer pauses;
- **keep P's routes installed** — blackhole, don't leak: if the routes
  were removed, traffic for P's prefixes would fall through to the
  physical default route and exit the underlay in cleartext. Traffic to
  a dead peer must die at the LPM as `no_path` drops, never escape.
  `online: true` reverses all of it.

Dead **relays** need no extra machinery — both roles are already
covered: if *my* home relay dies, the home-relay manager re-selects and
republishes `HomeRelays` (60 s timer + immediately on transport death);
if a *peer's* home relay dies, my probes on that path fail and I fail
over to its surviving candidates; the peer meanwhile republishes, and
the membership delta refreshes my candidate set. A relay that is
`online: false` at the coordinator is additionally excluded from new
home-relay selection (existing sessions ride on probe truth as above).

What stays **manual, on purpose**: directory removal. A long-dead
member keeps its node id, pins, and — critically — its prefix claims
(first-registered wins, §3.2): auto-releasing a prefix on liveness
would let a flapping gateway's LAN get re-advertised by someone else
mid-flap, which is a routing incident, not a convenience. Freeing a
dead gateway's prefix is a human decision: admin disable/remove (§3.4),
with the UI sorting peers by `last_seen` to make the candidates
obvious. Whether v2 adds an opt-in auto-release after a long
configurable offline period is open question #12.

### End-to-end packet walk (the mesh + short-circuit invariant)

A = private laptop (`10.99.0.5`, node 7). B = headless gateway for
`192.168.7.0/24` (node 9), home relay R. App on A pings `192.168.7.20`:

1. **A out**: OS routes into TUN (route from membership) → LPM →
   owner node 9 → candidates {B's home relays} ∪ {direct if B advertises}
   → seal with pair key K_AB → datagram on the current path's session.
   **Cold start needs no pairwise handshake**: keys toward B derive from
   membership alone — there is no per-peer key exchange, ever. If A
   already holds a session to one of B's home relays (the common case
   with a shared fleet), the first packet ever sent to B flows
   immediately; otherwise it waits in the bounded per-peer dial queue
   (§6) while one on-demand QUIC connect + `PeerHello` completes. (QUIC
   0-RTT early data is deliberately not used.) The direct path forms in
   the background and traffic migrates only when probes justify it.
2. **R**: `src_id == session(A)` ✓ → node 9 has a live session → forward
   verbatim (ciphertext opaque). One hop, never relay→relay.
3. **B in**: frame arrives on R's session with `src_id 7` — accepted
   because R's credential says `relay = true`; AEAD under K_AB proves the
   true origin; counter window checked; ingress filter passes (inner src
   `10.99.0.5` ∈ A's /32, inner dst `192.168.7.20` ∈ B's advertised /24);
   inner packet → TUN → OS forwards to `192.168.7.20` (IP forwarding on).
4. **Return**: the LAN host's reply reaches B (gateway return path,
   §7) → B's TUN → LPM → node 7 → **B's own** path choice to A
   (asymmetric paths are fine; the replay window is per pair-direction,
   not per transport, so mid-flow path switches never break it).
5. **Short circuit**: if a direct A↔B path exists, both keep probing it
   alongside the relay path; hysteresis flips the atomic per-peer path to
   direct when it measures better; 3 lost probes or transport death flips
   back instantly. No packet ever touches the coordinator.

Accepted limits: unicast only (no broadcast/multicast through the TUN);
fixed MTU 1350 with drop+count (ICMP too-big generation is a hardening
item); direct paths carry double encryption (e2e AEAD inside QUIC TLS) by
deliberate one-code-path choice.

**BGP analogy, scoped**: members advertise prefixes, routes are (prefix →
node, path) selected on live measurement, the mesh adapts as members come
and go — but no transitive routing, no path vector, no policy language.
The coordinator is the route reflector/directory; forwarding decisions are
sender-local. Multi-hop relay would change only relay forwarding rules,
not the frame format, so it stays a possible future phase.

## 7. TUN & OS routing

On membership receipt (non-relay-only nodes):
1. Create TUN; assign VPN IPs if granted; set MTU. **Headless nodes**:
   Linux supports address-less device routes natively; macOS `utun` and
   Windows `wintun` require an interface address, so headless nodes there
   get a dummy link-local-style point-to-point address (never advertised,
   never routed to).
2. **Pin host routes to the coordinator/relay/peer real IPs via the
   physical default gateway** — mandatory loop prevention.
3. Install routes for all *other* members' prefixes (both families) via
   TUN; diff-and-apply on incremental membership; routes die with the TUN
   device on crash.

Outbound: TUN read → LPM → owner node id → seal with pair key → send on
current path. Inbound: counter-window check, unseal, inner ingress
filter (§4), write to TUN.

Backends (all three in v1): Linux (`/dev/net/tun` + rtnetlink), macOS
(`utun` + `route`), Windows (`wintun` + IP Helper/`netsh`; ships
wintun.dll, needs elevation). Gateway nodes must enable OS IP forwarding
(documented, warned at startup).

**Gateway return path**: hosts on an advertised LAN must route VPN
prefixes back via the gateway node (gateway = LAN default gw, or static
routes on the LAN router). Where that's not possible, a per-gateway
`masquerade = true` option SNATs VPN-sourced traffic to the gateway's LAN
address (nftables/pf/netsh rules) — zero LAN-side config, at the cost of
LAN hosts not seeing real VPN source IPs.

Not automatic in v1: DNS; full-tunnel `0.0.0.0/0` / `::/0` (needs
exit-node NAT + DNS — out of scope).

## 8. Node runtime: the loops every node runs

Startup is a straight line; after that the node is a fixed set of
long-lived tasks connected by **bounded** channels — backpressure and
drop+count everywhere, no unbounded queue anywhere in the process.

**Startup sequence**

1. Load config; load-or-generate the X25519 keypair and self-signed TLS
   cert (persisted next to the config — losing them means a pin reset).
2. `POST /join` — retry with exponential backoff + jitter (cap 60 s),
   abort permanently on `pin_mismatch`/`client_disabled` (§3.4) with an
   operator-readable error.
3. Open the coordinator QUIC control connection; `Hello`/`HelloAck`;
   receive full `Membership`.
4. Build the peer table + LPM; create the TUN (unless `--relay-only`),
   assign addresses, pin host routes to real peer/relay/coordinator IPs,
   install member-prefix routes (§7).
5. Spawn the task inventory below. Ready.

**Task inventory** (all on one current-thread tokio runtime except the
two TUN OS threads, §10):

| # | Task | Woken by |
|---|---|---|
| 1 | coordinator link | control messages, renewal timer, disconnect |
| 2 | outbound pump (TUN→net) | TUN reader channel |
| 3 | inbound dispatch (net→TUN) | datagrams on any live session |
| 4 | dialer | dial requests from 2/6/7 |
| 5 | prober | per-(peer, path) tickers |
| 6 | path selector | 15 s timer + immediate-failover signals |
| 7 | home-relay manager | 60 s timer + relay death (private nodes) |
| 8 | relay forwarder | inline in 3 (relay-capable nodes only) |
| 9 | session reaper | 30 s timer |
| 10 | statusd | local status-socket queries |

**(1) Coordinator link** (`coordlink`):
```
loop select:
  Membership (snapshot chunks or delta, revisioned §3.1) → snapshot:
      assemble off-path, install atomically when complete; delta: apply
      iff base_rev matches, else request fresh snapshot. Then diff-apply:
      peers table, LPM, OS routes;
      removed peer → drop its sessions, keys, routes immediately;
      changed pubkey or cert_fp (pin reset, §3.3) → discard every derived
      pair secret/key for that peer and close its sessions — they
      re-derive/re-dial on demand under the new key;
      changed epoch (peer restarted) → previous epoch enters its grace
      window, new epoch becomes the accepted one (§4);
      online flag change → suppress/resume initiation toward that peer
      per §6 "Dead peers & relays" (sessions, probes, routes untouched)
  ConnectRequest{from a public peer} → hand to dialer: reverse-dial its
      advertised endpoint (§6)
  KeySet → update trusted verification keys (§3.3)
  renewal timer (fires at 2/3 × credential TTL, ±10 % jitter)
      → POST /join → new credential
      → send Refresh on coordinator link + every live peer/relay session
  keepalive miss / disconnect → reconnect with backoff.
      Coordinator outage degrades gracefully: the data plane keeps
      running on last-known membership; what stops is renewals —
      sessions then die at credential exp (≤ TTL), which is the designed
      fail-safe, not a crash.
```

**(2) Outbound pump** — the hot path, per packet:
```
recv from TUN-reader channel (bounded 512)
→ IP version from first nibble; LPM(dst addr) → owner node id
      miss → drop + count(no_route)
→ peers[owner].chosen_path (atomic load — written only by task 6)
→ live session for that path?
      no  → push to per-peer dial queue (≤ 64 pkts, drop-oldest),
            signal dialer, continue
→ seal: AEAD(key[dir, epoch, "data"], nonce = ctr++), header as AD (§4)
→ quinn send_datagram (non-blocking; would-block → drop + count —
      QUIC's congestion controller owns pacing, we never buffer behind it)
```

**(3) Inbound dispatch** — per live session, per datagram. One common
prefix for **every** frame type — probes relay exactly like data (a
relay can't verify an A→B probe tag; it holds no A–B key and never
needs one):
```
parse common header [type][src_id][dst_id] (malformed → drop + count)
→ source rule: src_id == session's node id, or session credential has
      relay = true (§4); else drop + count
→ dst_id != me → I'm relay-capable → task 8 (forward verbatim, any
      type, within the session's network); else drop + count
→ dst_id == me → per type:
   0x01 Data  → advertised-epoch + replay-window check → unseal (fail →
                drop + count(bad_seal)) → inner ingress filter (§4) →
                TUN-writer channel (bounded 512; full → drop + count)
   0xF1 Probe → verify tag (probe-domain key) → echo 0xF2 Reply
                (src/dst swapped, re-tagged) on the same transport
   0xF2 Reply → verify tag → hand (path, seq, rtt = mono_now − t_sent)
                to prober
   unknown    → drop + count
```

**(4) Dialer** — serializes connection setup so the pump never blocks:
```
on dial request (direct peer / on-demand relay session), dedup in-flight:
  connect QUIC with expected cert_fp from membership (MITM-proof)
  → PeerHello{credential} both ways, verify per §3.3 (sig, exp, network,
    cert_fp binding)
  → register session; flush that peer's pending queue through the pump
  failure → exponential backoff per endpoint; mark candidate down
    (prober re-tests it later; selector routes around it now)
```

**(5) Prober** — per (peer, path) ticker at 2 s ± 25 % jitter:
```
peer idle > 5 min → skip (first outbound packet wakes probing again)
candidate path has no live session (e.g. the direct path of an active
    peer) → establish it instead of probing — this is the mechanism by
    which "the direct path forms in the background": peer advertises →
    request dial (task 4); peer is private but I advertise → send
    ConnectRequest via coordinator, peer reverse-dials me (§6); dial
    keeps failing → candidate marked undialable, retried on membership
    change or slow timer (5 min)
send 0xF1 {seq++, mono_now}, record in outstanding table
on Reply: EWMA(α = 0.2) ← rtt; clear outstanding
outstanding > 3 s → loss++; 3 consecutive → immediate signal to selector
```

**(6) Path selector** — every 15 s, plus immediately on failover signal:
```
per peer: candidates = {direct if dialable} ∪ {peer's home_relays}
  challenger wins iff ≥ 5 samples ∧ acceptable loss
                    ∧ ewma < current × 0.9 − 2 ms   (hysteresis)
  tie → prefer direct
  failover signal → drop dead path now, take best surviving candidate
  zero live candidates → peer is unreachable: pump drops + counts
      (no_path); prober/dialer keep retrying — recovery is automatic
write peers[peer].chosen_path (atomic store) — a flag flip; the pump
sees it on the next packet, no locks, no pause
```

**(7) Home-relay manager** (private nodes) — every 60 s + on relay death:
rank the relay set by probe stats, hold sessions to the best K = 2,
publish `HomeRelays` to the coordinator on change (§6).

**(8) Relay forwarder** (relay-capable nodes, inline in dispatch):
`src_id == session's authenticated node id` (else drop + count) →
look up `dst_id` in the session table of the arriving session's network
→ forward the datagram verbatim (§6). No unseal, no queueing beyond
quinn's own — a relay adds one map lookup of latency.

**(9) Session reaper** — every 30 s: close on-demand sessions idle
> 10 min; close any session whose credential `exp` passed without a
`Refresh`; drive QUIC keepalives per config.

**(10) statusd** — answers the local status socket (`nqvpn status`, §9)
from `ArcSwap` snapshots the other tasks publish; it never takes a lock
the hot path can feel.

Every drop site above has a named counter; `nqvpn status` shows them all
(§9) — a silent drop is a bug by definition.

## 9. Observability (what we track)

Coordinator `GET /api/v1/status` (admin-authenticated) gives the global
summary — networks hosted, members/online per network, shared-relay fleet
health. `GET /api/v1/networks/{network_id}/status` answers the per-network
questions directly:

```json
{
  "network_id": "acme-prod",
  "peers_total": 12, "peers_online": 9, "peers_public": 3, "relays": 2,
  "peers": [{
    "node_id": 7, "client_id": "laptop-1", "online": true,
    "public": false, "relay": false,
    "vpn_ips": ["10.99.0.5", "fd99::5"],
    "advertised": ["192.168.50.0/24"],
    "home_relays": [1, 3],
    "endpoints": [], "last_seen": "…", "joined_at": "…"
  }],
  "prefix_table": [{ "cidr": "192.168.50.0/24", "owner": 7 }]
}
```

Node-local `nqvpn status` (CLI, via a local unix/named-pipe socket) shows
the path picture: per peer — candidates, per-path RTT EWMA / loss / sample
count, currently selected path, last switch time, and per-path traffic
counters. Both are Phase-level deliverables, not afterthoughts, since path
behavior is otherwise invisible.

## 10. Concurrency model

**Coordinator** — tokio multi-threaded runtime (tokio's reactor *is*
epoll/kqueue/IOCP; quinn requires an async runtime — hand-rolled epoll
would fight the QUIC stack). One task per member control session;
directory state behind `ArcSwap`.

**Node** — one binary, few threads:
- Current-thread tokio runtime driving all QUIC connections (coordinator,
  home relays, direct peers), control streams, prober, selector, and the
  relay path on relay-capable nodes. A busy public relay can opt into the
  multi-threaded runtime (`--workers N`); same code either way.
- One dedicated OS thread for blocking TUN reads → bounded channel; one
  for TUN writes ← channel. This isolates platform quirks (macOS `utun`
  non-blocking flakiness; Windows `wintun` is a ring-buffer API with no
  fd) behind one abstraction. Sealing happens on the async side
  (ChaCha20-Poly1305 at packet sizes is ~1 µs).
- ~4 OS threads for a typical private node.

## 11. Crates & repo layout

| Purpose | Crate |
|---|---|
| async runtime | tokio |
| HTTP API | axum + rustls |
| QUIC | quinn (datagram support) |
| TUN | `tun-rs` (Linux/macOS/Windows-wintun) — evaluate vs `tun` in Phase 3 |
| routes | rtnetlink (Linux), `route` cmd (macOS), IP Helper / `netsh` (Windows) |
| e2e crypto | x25519-dalek, chacha20poly1305, hkdf, rand |
| credentials | jsonwebtoken (EdDSA) + ed25519-dalek |
| certs/secrets | rcgen, argon2 |
| config/serde | serde, toml, bincode |
| IP handling | ipnet (shared LPM: prefix → node_id) |
| CLI/logging | clap, tracing |
| web UI assets | rust-embed (frontend is plain HTML/JS — no JS build toolchain) |

```
nqvpn/
  crates/
    nqvpn-proto/    # API types, control messages, frame codec, sealing, LPM
    nqvpn-coord/    # coordinator: axum API + QUIC control + directory + status
    nqvpn-node/     # the node binary: TUN, transports, relay, prober, status CLI
```

### Module map

**`nqvpn-proto`** (shared library — everything both sides must agree on):
| Module | Responsibility |
|---|---|
| `api` | REST request/response types (`JoinRequest`, `JoinResponse`, status DTOs) |
| `control` | control-stream messages (`Hello`, `Membership`, `HomeRelays`, `Refresh`, `PeerHello`, keepalives) + length-prefixed bincode framing |
| `frame` | datagram codec: `Data`/`Probe`/`Reply` encode/decode, node-id header |
| `credential` | JWT claims struct, sign (coord) / verify (everyone), cert_fp binding check |
| `seal` | pair-key derivation (X25519+HKDF), ChaCha20-Poly1305 seal/unseal, per-direction counters + replay window |
| `lpm` | dual-family longest-prefix-match table (prefix → node_id), diff/apply |
| `types` | NodeId, NetworkId, prefix/endpoint types, config-shared enums |

**`nqvpn-coord`** (binary):
| Module | Responsibility |
|---|---|
| `config` | `networks.d/` loading, argon2 secret verification, startup overlap validation, reload |
| `registry` | per-network directory: members, node-id allocation, IPAM, online state, home relays |
| `pins` | per-network TOFU key-pin store (pubkey/cert_fp persistence, admin reset) |
| `api` | axum router: `/join` (auth → credential signing), status + admin endpoints (§3.4), rate limiting |
| `webui` | embedded static assets (rust-embed) at `/ui`, admin session auth, CSRF |
| `signer` | Ed25519 coordinator keypair, credential issue/renew |
| `control` | quinn listener: mutual-TLS accept, `Hello` verification, membership push (full + incremental), keepalive tracking |
| `status` | global + per-network status assembly |

**`nqvpn-node`** (binary):
| Module | Responsibility |
|---|---|
| `config` | node TOML (coordinator addr, credentials, advertise/relay flags, tunables), self-signed cert + X25519 key persistence |
| `coordlink` | join/renew via HTTPS, coordinator QUIC control connection, membership intake, `Refresh` scheduling before `exp` |
| `peers` | per-peer state: PeerInfo, derived pair keys, path candidates, chosen path (atomic), traffic counters |
| `transport` | quinn endpoint; dial/accept with credential+cert_fp auth; session registry (peer + relay sessions), reconnect/backoff |
| `relay` | forwarding path for relay-capable nodes: session table per network, dst_id lookup, forward, exp enforcement |
| `pather` | prober (probe tx/rx, EWMA, loss), hysteresis selector, home-relay selection + `HomeRelays` publish, idle pause |
| `tun` | platform trait + backends (`tun_linux`, `tun_macos`, `tun_win`): device create, reader/writer threads, channels |
| `routes` | OS route programming trait + backends (rtnetlink / `route` / IP Helper), pinning, diff/apply, cleanup |
| `engine` | the pump: TUN↔seal↔transport glue, inbound dispatch (Data/Probe), counters |
| `statusd` | local unix/named-pipe status socket + `nqvpn status` CLI rendering |

Dependency rule: `engine`/`relay`/`pather` depend on `peers` + `transport`;
`tun`/`routes` are leaf platform modules behind traits (mockable — Phases
1–2 and CI run with a fake TUN and in-memory routes). `nqvpn-proto` depends
on nothing internal.

## 12. Phases

1. **Proto + coordinator** — workspace, per-network config
   (`networks.d/`) with startup overlap validation, `/join` with
   network_id, node ids, optional dual-stack IPAM, TOFU key pinning,
   credential signing + renewal, QUIC control with membership push, the
   full admin REST surface (§3.4) including reload/disable/reset-pin.
   Testable with a stub node.
2. **Node skeleton + e2e crypto** — QUIC endpoints, mutual-TLS credential
   auth (offline verify + cert_fp binding), pair keys, sealed Data frames
   direct-only, keepalives. CI-testable, no TUN.
3. **TUN + OS routing (Linux + macOS)** — reader/writer threads, v4+v6 +
   headless mode, route install/cleanup + pinning. Milestone: ping between
   two directly-connected nodes.
4. **Relay path** — credential-authenticated relay sessions, forwarding
   by dst_id,
   home-relay connect + publish. Milestone: ping between two private nodes
   via a relay-only node.
5. **Probing + path selection** — probe frames, EWMA, hysteresis,
   immediate failover, home-relay re-selection, `nqvpn status`. Milestone:
   kill a relay mid-ping → re-routes; bring up a direct path → migrates.
6. **Windows node** — wintun backend behind the TUN-thread abstraction,
   IP Helper routes, packaging + elevation.
7. **Control-plane web UI** — embedded static app over the (already
   built) admin API: networks overview, network dashboard, peer detail,
   pin-reset/disable/reload actions, session auth + CSRF. Milestone:
   operate a network end-to-end without curl.
8. **Hardening** — reconnect/backoff, replay & credential tests (expiry,
   refresh, revocation-by-expiry, stolen-credential/cert-mismatch,
   cross-network and cross-coordinator rejection: credentials and frames
   from network A must fail against network B even with identical names,
   node ids, and keys), epoch tests (restart mid-flow, old-epoch replay
   after advertisement change, delayed membership, receiver-restart
   window re-arm), Refresh continuity (cross-node, cross-network,
   same-cert, disabled-node, reduced-permission cases), relayed
   Probe/Reply through a relay (incl. forged source, wrong network,
   unknown type, malformed header), envelope compatibility (old vs new
   codec both directions, unknown-kind skip), signing-key rotation with
   coordinator restart at every stage, membership revision gaps (delta
   on wrong base, reconnect mid-snapshot), reload reconciliation
   (removed client, moved prefix, changed secret, during active joins),
   ingress-filter tests (spoofed inner src/dst, family mismatch), parser
   fuzzing (frames + control messages), MTU edges, graceful shutdown,
   metrics.

## 13. Open questions for review

1. Static VPN IPs in coordinator config (proposed) vs dynamic pool — and
   is headless the *default* (`want_vpn_ip` opt-in) or the exception?
2. IPv6 inner: ULA ok? Any global-v6-through-tunnel need in v1?
3. K = 2 home relays; probe 2 s / decide 15 s / 10 %+2 ms hysteresis /
   idle-pause 5 min — tune?
4. Access control: flat mesh in v1, or per-pair allow rules as a claim in
   the credential (e.g. `allowed_peers`) that relays/peers enforce
   offline?
5. Credential TTL 15 min (= worst-case revocation window) — acceptable,
   or shorter at the cost of more renewal traffic?
6. Relay abuse limits: per-session bandwidth caps in v1 or hardening
   phase?
7. **Crypto layer — adopt Noise IK in v1?** (Recommended.) The
    handshake-free static-static scheme exists to make the first relayed
    packet zero-round-trip, and it costs: the epoch field + advertised-
    epoch lifecycle (§4), the receiver-restart replay residual, and no
    forward secrecy. Noise IK per pair (the WireGuard/Nebula-proven
    choice; 1 RTT once per peer session, handshake frames relay like any
    frame) deletes all three. Three external review rounds found their
    top issue in this layer — the known design is better here. Decide
    before Phase 2 freezes the frame format.
8. NAT traversal (hole punching, reflexive endpoints) stays out of v1 —
   confirm.
9. Multi-network membership for TUN-bearing nodes (one process, several
   networks, one TUN each) — v1 says run one process per network; enough?
10. Network lifecycle API (create/delete networks via REST instead of
    config files) — v1 is config-file + reload button; if promoted, the
    web UI (§3.4) grows matching create/edit screens. Needed sooner?
11. Gateway `masquerade` mode: should the node program OS NAT rules
    itself (nftables/pf/netsh) in v1, or only document manual setup?
12. Dead-member directory cleanup stays manual in v1 (§6) — is an
    opt-in auto-release of a member's prefixes after a long
    configurable offline period (say, 30 days) wanted in v2, or is
    admin-only removal the permanent policy?

## 14. Prior art & positioning

This architecture independently lands on the shape the production
systems in this class share — treat that as validation, and treat the
differences as the actual product:

| | nqvpn | Tailscale | ZeroTier | Nebula |
|---|---|---|---|---|
| control plane | coordinator = offline-verifiable signer (15-min JWTs) | coordination server (online key distribution) | controller | CA + lighthouse (long-lived certs, CRL revocation) |
| relays | any member with `relay = true`, same binary | DERP — separate server fleet | root/moon servers | special relay hosts |
| e2e through relays | yes (AEAD, relay-opaque) | yes (DERP model) | yes | yes |
| addressing | **prefix-first, node-id frames, VPN IP optional (headless)** | address-first + subnet routers | address-first + bridging | address-first + unsafe_routes |
| path selection | client-measured, hysteresis, per peer | magicsock (measured) | measured | lighthouse-directed + direct |
| pair crypto | v1: static-static + epochs; Noise IK recommended (Q7) | WireGuard Noise | custom (Salsa20/Poly1305) | Noise IX |
| NAT traversal | none in v1 (Q8) — one-side-public or relay | disco/STUN hole punching (best in class) | yes | yes |
| multi-network | 500 per coordinator, shared relay fleet | tailnets (1 per node) | yes (controller) | one CA domain |

Positioning in one line: ZeroTier's multi-network controller +
Tailscale's relay/path model + Nebula's offline credential idea, with a
prefix-first data plane none of them have — minus NAT traversal (v1)
and minus their battle-tested handshake unless Q7 is resolved toward
Noise. The deliberate bets worth defending in review: headless
prefix-first addressing, relay-as-flag symmetry, QUIC as the single
transport, and human-planned (never auto-resolved) prefix ownership.
