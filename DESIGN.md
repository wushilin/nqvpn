# nqvpn — Design Plan (relay-mesh architecture)

An L3 (TUN-based), dual-stack (IPv4 + IPv6) VPN in Rust, built as a
**distributed, interconnected relay service**. Three small binaries,
each with one job and a short main loop. No peer-to-peer data
connections between clients — simplicity is the product.

Platforms: the **client** runs on Linux, macOS, and Windows. The
**coordinator and relay** are Linux-first (the tested production
target) and also run on macOS — nothing in them is Linux-specific,
because the async runtime abstracts the OS event queue (epoll on
Linux, kqueue on macOS); a Mac at home is a fine home-site relay.
Windows server roles are unsupported in v1 (untested, unpackaged —
not impossible).

Guiding rule: every component's forwarding logic must fit on one page.

(The earlier full-mesh design with P2P short-circuiting is archived in
`DESIGN-MESH.md`; this document supersedes it and is self-contained.)

Status: **draft for review**.

---

## 1. Architecture

```
                nqvpn-coord  (control only: join, registry, admin+UI)
                 ▲        ▲                    ▲
                 │        │  attachment +      │
        HTTPS + control   │  relay-list push   │
                 │        │                    │
   client A ──► relay R1 ═══════ relay R2 ◄── client B
   (TUN)          full mesh, N×N, QUIC          (TUN)
                 (pure forwarders, no TUN)
```

- **nqvpn-client**: a pure **leaf**. TUN + exactly **one** upstream
  QUIC connection to its chosen relay + a control connection to the
  coordinator. Gets its VPN IP from the control plane; **cannot
  register routes** — it only consumes them. On upstream death it
  reconnects (possibly to a different relay). That is the whole client.
- **nqvpn-relay**: a QUIC forwarding service — sessions to its attached
  clients and to every other relay (full mesh, list pushed by the
  coordinator); forwarding is two table lookups (§6). Optionally, a
  relay is also its site's **gateway**: it may register a local CIDR it
  routes (then it gets a TUN + a data-plane identity like any member).
  This is the site-to-site shape: home has a relay, AWS has a relay,
  Alibaba has a relay — the relay mesh *is* the backbone, and each
  relay fronts its own site's LAN.
- **nqvpn-coord**: control plane only — join API, credential signing,
  membership + attachment + route registry, admin API + web UI. Touches
  no traffic, appears in no forwarding table.

The data path is always `client → relay [→ relay] → endpoint`: clients
attached to the **same relay** reach each other by local delivery at
that relay (no mesh hop); cross-relay pairs cross exactly one mesh
link; traffic to a relay's own CIDR terminates at that relay's TUN.
Never more hops, never fewer, chosen by table lookup, not measurement.
There is **no path selection** in the data plane, no rerouting around a
down mesh link (§7), and loops are impossible by construction (§6).

**Accepted costs** (explicit, so review can challenge them): no P2P
short-circuit — same-LAN clients hairpin through a relay; every byte
transits 1–2 relays, so the fleet is bandwidth- and
availability-critical infrastructure; cross-relay pairs pay one mesh
hop of latency. In exchange: three trivially auditable binaries, one
upstream connection per client, and members **never learn each other's
IP addresses** (endpoints exist only between relays and the
coordinator).

## 2. Addressing & routes

- The coordinator assigns each member (clients *and* relays) a stable
  **node id** (`u32`), never reused. All frame addressing and
  forwarding use node ids — never inner IPs.
- **Clients** own exactly their VPN address(es) — assigned by the
  control plane, auto-advertised as /32 and /128. Nothing else: a
  client cannot register a local route.
- **Relays** may register **local CIDRs** they route (their site's
  LANs, a VPC CIDR, …) — permission-gated in the relay's config entry
  at the coordinator. A gateway relay may be headless (no VPN address;
  inner packets carry real LAN addresses end to end).
- **Route lifecycle — liveness-bound, age-resolved**: several nodes may
  register overlapping CIDRs; for any prefix, the **oldest living
  registration wins** and is the only owner pushed in membership. A
  node's death (§7) withdraws all its registrations automatically —
  the next-oldest living registrant, if any, becomes the owner on the
  next push (free site-gateway failover: run two gateway relays for
  one LAN, the older registration carries traffic, the younger takes
  over when it dies). No registrations left ⇒ the route disappears
  from members' tables (with a blackhole guard, §8). **Flap damping**:
  a registrant returning from death waits `hold_down` (default 60 s,
  0 = off) before reclaiming ownership from a live standby — one flap
  costs one failover, not two.
- Forwarding at a leaf is one operation: LPM over (prefix → node id);
  everything after that is the relay's two lookups.

## 3. Coordinator

### 3.1 Networks (virtual switches)

The coordinator hosts N fully isolated networks (`network_id` string,
ZeroTier-controller style; hundreds are fine — control traffic only).
Per network: tunnel subnets, IPAM, prefix plan, membership, node-id
space, registry. Config: one TOML per network in
`networks.d/<network_id>.toml`, overlap-validated at startup (overlaps
fail startup — conflicts are a planning bug).

**IPAM — network CIDRs and named pools:**

```toml
cidrs = ["10.99.0.0/16", "10.100.0.0/16", "fd99::/64"]   # tunnel space
[pools.default]  cidr = "10.99.1.0/24"                   # ⊆ a network CIDR
[pools.servers]  cidr = "10.99.2.0/24"
[pools.v6]       cidr = "fd99::1:0/112"
```

- Pools are named sub-ranges of the network CIDRs, per family,
  pairwise disjoint (validated at startup/reload like every overlap).
- A joiner may name a `pool` — allocation comes from that pool
  (`409 pool_exhausted` if full, `400 unknown_pool` if absent, and the
  config entry may pin a member to a pool, which the request must then
  match). No pool named ⇒ any pool of the right family with space.
- A joiner may request a `preferred_ip4`/`preferred_ip6`: granted and
  **reserved** (sticky in the registry, survives death — identity
  outlives liveness, §7) if it lies inside the network CIDRs and is
  unassigned; else `409 address_in_use`. Preferred addresses may sit
  outside every pool — that is how infrastructure gets memorable
  addresses (relay at `10.99.0.1`) without a pool carve-out.
  Config-static IPs remain the operator-forced variant of the same
  mechanism; all assignments are durable and re-issued verbatim on
  rejoin.
- Addresses in no pool and not statically assigned are simply never
  auto-allocated.
- **Relays use the identical mechanism** (`want_vpn_ip` +
  `pool`/`preferred_*` in their join): an addressed relay is reachable
  *inside* the VPN — SSH, metrics, admin — as an ordinary endpoint
  with its /32 advertised like any member's, frames to it unsealing at
  its own node id. Address, gateway CIDRs, both, or neither: each is
  optional and independent.
- Members install covering routes for every network CIDR on the TUN
  (blackhole-backed, §7) plus the specific /32s//128s from membership —
  tunnel-space traffic can never leak to the underlay even for
  unassigned addresses. A session is bound to
exactly one network at authentication time, so the wire format needs no
network field; relays serve many networks at once with tables keyed by
(network_id, node_id). Clients join one network per process.

### 3.2 Member API: POST /api/v1/join (HTTPS)

One API for both roles; the config entry at the coordinator declares
what each identity may be and do.

Request: `{ network_id, client_id, client_secret, pubkey (x25519),
role: "client" | "relay", want_vpn_ip (default **true** for both
roles — headless is an explicit opt-out), pool (optional),
preferred_ip4 / preferred_ip6 (optional, §3.1 IPAM), local_cidrs
(relays only), relay_addr (relays only: the public address the fleet
and clients dial), cert_fingerprint }`.
Response: `{ credential (JWT), network_uuid, coordinator_signing_keys:
[{kid, key, state}], node_id, ip4/subnet4, ip6/subnet6 (absent if
headless), relays: [{relay_id, addr, cert_fp}], mtu: 1350,
keepalive_secs: 15 }`.

Join validation: role must match the config entry; `local_cidrs ⊆` that
relay's config `allowed_cidrs` (clients may not register routes at
all — requests with them are rejected); `relay_addr` passes endpoint
validation (no loopback/multicast/link-local, no overlap with
VPN-routed space). **Overlapping `local_cidrs` across relays are
allowed** — that is the failover mechanism; ownership resolves by
registration age (§2). Registration age is durable (registry-recorded
at first grant) so a coordinator restart cannot reshuffle owners.
Secrets are argon2 hashes in config, checked only at this API. Join
doubles as **renewal** (idempotent; renewal never resets age).

The client then opens a **QUIC control connection** (mutual TLS with
its self-signed cert): `Hello{credential}` / `HelloAck`, then receives
**membership** — for clients this is only
`PeerInfo { node_id, prefixes, pubkey }` plus the relay list: no
endpoints, no attachment info. Control messages: `Membership`
(revisioned: snapshot chunks `{snapshot_rev, i, n, …}` assembled and
installed atomically; deltas `{base_rev, new_rev, …}`, gap ⇒ request
snapshot), `Refresh{credential}`, `KeySet`, keepalives.

Relays additionally receive the **attachment registry**
(`node_id → relay_id`, same revisioned push) and the relay list.

### 3.3 Security model: API auth once, signed credentials everywhere

- **Credential**: JWT (EdDSA/Ed25519) with claims `{ iss, aud:
  "nqvpn-v1", network_id, network_uuid, node_id, sub: client_id,
  pubkey, cert_fp, prefixes, iat, exp }`, TTL **15 min**, verified
  offline everywhere: signature (against the pushed keyset, by `kid`) +
  expiry + `iss`/`network_id`/`aud` + **possession proof** — every QUIC
  connection is mutual TLS with self-signed certs and the acceptor
  requires TLS-cert fingerprint == credential `cert_fp`. No component
  but the join API ever sees a secret.
- **TOFU key pinning**: the coordinator durably records each member's
  `(pubkey, cert_fp)` on first join; later joins must match (admin
  reset for rebuilt machines; pre-provisioned pins for strict setups).
  Identity is two-factor: secret + pinned key.
- **Renewal/revocation**: re-join before `exp`, send
  `Refresh{credential}` on live sessions. Refresh is
  **identity-continuous**: the new credential must match the session's
  bound `(iss, network_id, node_id, sub, pubkey, cert_fp)`. Disable a
  client ⇒ renewal fails ⇒ every session dies at `exp` (≤ TTL) —
  hard guarantee; membership-removal push and relay-side `exp`
  enforcement accelerate it best-effort.
- **Durable coordinator state**, per network, one atomically-rewritten
  registry file: `{network_uuid (minted once, immutable), client_id →
  node_id, pins, assigned addresses, route registrations with their
  first-grant timestamps (age is durable — restarts must not reshuffle
  route owners), disabled flag}` — plus the signing
  **keyring** (active/retiring keys, `kid`-tagged; rotation publishes
  the keyset via join + `KeySet`, retires after every credential the
  old key could have signed has expired). All writes for a network go
  through **one serialized owner**; durability precedes visibility
  (fsync-then-reply). Config is not state: `networks.d/` is re-read at
  startup and on reload.
- **Reload** (`POST /api/v1/reload`) is an atomic reconciliation:
  validation failure keeps the old config running; removed/reduced
  clients leave membership immediately but keep the revocation-by-
  expiry guarantee; moved prefixes follow first-registered-wins;
  registry entries of removed clients stay inert (ids never reused)
  until admin purge.

### 3.4 Admin API & web UI

Same axum process. Member realm: `/join`. Admin realm (argon2 admin
users; session cookie `HttpOnly`+`SameSite=Strict`+CSRF, or bearer
token; login rate-limited like `/join`):

| Route | Purpose |
|---|---|
| `GET /api/v1/status` | global: networks, members online, relay fleet + mesh-link health |
| `GET /api/v1/networks` / `…/{id}/status` | per-network: peers (online, addresses, prefixes, **attached relay**, last_seen), prefix→owner table |
| `GET …/{id}/peers/{node_id}` | pins, prefixes, attachment, credential history (in-memory) |
| `POST …/clients/{client_id}/reset-pin` | TOFU reset |
| `POST …/clients/{client_id}/disable` (`/enable`) | durable registry flag; never edits the operator's TOML |
| `POST /api/v1/reload` | §3.3 reconciliation |

Uniform errors `{error: {code, message}}` — `401 bad_credentials`,
`403 pin_mismatch` (client stops retrying), `403 client_disabled`,
`409 prefix_conflict`, `409 address_in_use`, `409 pool_exhausted`,
`400 unknown_pool`, `429 rate_limited`. **Web UI**: dependency-free
static HTML/JS embedded via rust-embed at `/ui`, strictly a client of
this API (everything curl-able), 5 s polling. It shows control-plane
truth incl. per-client attachment, pool utilization, and mesh-link
status.

## 4. Identity & end-to-end encryption

Frames are sealed **endpoint↔endpoint**, where an endpoint is any node
that terminates traffic: every client, and every gateway relay for its
own CIDRs. A relay *forwarding* a frame is an untrusted middleman and
can never read it; the same machine unseals only what is addressed to
its own node id. Trust in transit never depends on relay hosts.

- Each endpoint has a static X25519 keypair (registered at join,
  pinned, distributed in `PeerInfo`).
- **Noise IK** per client pair (the WireGuard-proven pattern, via the
  `snow` crate): the initiator knows the responder's static key from
  membership; handshake messages are ordinary frames relayed like data
  (1 RTT through the relay path). Sessions yield per-direction
  ChaCha20-Poly1305 keys; **explicit 8-byte counter** in each frame +
  sliding replay window (WireGuard-style, reorder-tolerant).
  Rekey on a timer (default **2 min** — WireGuard's proven constant)
  and after counter thresholds; a
  restarted peer simply fails auth until the initiator's retry logic
  re-handshakes (WireGuard timer model — no epoch machinery, no
  counter persistence, forward secrecy included). First packets to a
  peer wait in a small bounded queue (64 pkts, drop-oldest) during the
  handshake.
- Handshake payloads bind `(network_uuid, src_id, dst_id)`; a session
  seals only frames for exactly that pair in that network.
- **Origin authenticity per packet, no hot spot**: the AEAD tag under
  the pair session key proves `src_id` offline (trust chain:
  coordinator-signed credential → pinned pubkey → Noise session → tag).
  Additionally every hop binds `src_id` to the arriving session (§6),
  so spoofed frames don't even transit an honest relay.
- **Inner-packet ingress filter** (after unseal, before TUN write):
  inner source ∈ prefixes(src_id), inner destination ∈ my prefixes,
  version nibble matches family; else drop + count. Stops
  source-spoofing and confused-router abuse by authenticated members.

> **Proposed:** the control stream has no request/response layer — every
> upstream message is fire-and-forget and failures surface only as a
> dropped session. `DESIGN-RPC.md` specifies an additive RPC layer with
> per-verb versioning, and identity rotation as its first verb. Not
> implemented.

## 5. Wire format (QUIC datagrams or lanes)

Data rides **QUIC datagrams** (RFC 9221) or **stream lanes**, chosen per
network by the `transport` setting. The original argument for datagrams
was that a reliable ordered stream would head-of-line-block the tunnel
and stack a second loss-recovery loop under inner TCP.

Measurement complicated that. On a clean backbone with many parallel
flows, datagrams win (69 vs 45 Mbit/s, San Jose ↔ Singapore). On a lossy
consumer uplink, streams win decisively (87 vs 54 Mbit/s upload),
because QUIC repairs loss beneath the inner TCP instead of making it
recover across a full RTT. Neither is right everywhere, so both ship and
the network picks. **The default is `stream`**, the safer of the two on
the paths most deployments actually have.

**Lanes.** Stream mode spreads packets across `lanes` parallel
unidirectional streams, which recovers most of what datagrams were for:
a stalled segment blocks only the flows sharing its lane, while each
flow still gets an ordered pipe. Two properties make this work:

  * **endpoints choose, relays echo.** An endpoint hashes the inner
    5-tuple to pick a lane; the payload is sealed end to end, so a relay
    can see no ports and cannot re-derive it. A relay forwards each frame
    on the lane it arrived on, making the lane an opaque label. Flow
    stickiness therefore holds end to end, and no relay learns anything
    new about the traffic it carries.
  * **no negotiation.** A receiver accepts however many streams arrive,
    so only senders need a number and the coordinator publishes one per
    network. A peer on one lane interoperates with a peer on eight in
    both directions, so the lane *count* can be changed one node at a
    time. A frame relayed onto a connection with fewer lanes wraps rather
    than being dropped.

Lane framing is **not** backward compatible, and this is the one upgrade
edge worth stating plainly. Each stream opens with a one-byte lane id
before the usual `[len u16][packet]` records, so a peer built before
lanes reads that byte as half of the first length prefix and desyncs
immediately. Introducing lanes into a network already running
`transport = "stream"` is therefore a coordinated restart of every
member, not a rolling one. Networks on `datagram` are unaffected —
datagram framing did not change — so the safe path is to upgrade every
binary first and flip `transport` afterwards.

`lanes` defaults to 1. Lanes are not free — each costs a stream, a task,
and a share of the per-connection send queue, and a relay pays that for
every session it holds — so the default is a small number rather than a
large one, and the default is the option that changes nothing. The send
queue is *divided* across lanes rather than replicated per lane, keeping
a connection's worst-case buffering independent of the lane count.

Where lanes should pay is where a single flow cannot fill the path and
loss is the limiter — long-haul or multipath links. On a link one flow
already saturates there is no head-of-line blocking left to recover, and
the extra streams only add contention; measurements on two such links
(HK-SG backbone, and a consumer uplink at ~100 Mbit/s) showed no gain.
Raise `lanes` per network where the path fits the former description,
and measure rather than assume.

Control messages always ride their own bidirectional stream.

```
0x01 Data       [type 1][src_id 4][dst_id 4][ctr 8][AEAD ciphertext]
0x02 Handshake  [type 1][src_id 4][dst_id 4][noise handshake message]
0xF1 Probe      [type 1][seq 8][t_sent 8]        client→its relay only
0xF2 Reply      probe echoed by the relay
```

MTU: inner 1350 (outer 1500 − QUIC/UDP/IP ≈ 60 − header 17 − tag 16,
comfortable margin). Oversized ⇒ drop + count. Probes are unsealed but
ride inside the client↔relay QUIC session (TLS-protected, no third
party can inject); they never cross the mesh.

**Control envelope** (frozen layout):
`[major u8][minor u8][kind u16][len u32][payload]` — version readable
before any deserializer runs; major mismatch ⇒ close; unknown `kind` ⇒
skip `len` bytes (rolling upgrades); within a major, payload schemas
are frozen — evolution is a new `kind`, never a field added. `len`
capped (1 MiB; membership chunks well below), strict bincode
collection limits, malformed payload closes the stream, malformed
envelope the connection, never the process.

## 6. Attachment & forwarding

**Attachment**: if the client's config names a `preferred_relay_id`,
it attaches there (falling back to RTT ranking only if that relay is
unreachable); otherwise it ranks the relay list by a one-shot RTT
probe. It connects to the winner,
authenticates (`Hello{credential}`, mutual TLS + cert_fp). The relay
reports `Attach{node_id}` to the coordinator, which pushes the
attachment delta to all relays. Upstream death ⇒ client reconnects
with backoff to next-best; the new `Attach` supersedes. Stale entries
during a move: the old relay no longer holds the session ⇒ drop +
count, corrected on the next push (sub-second); inner protocols absorb
the loss (it's L3).

**Relay mesh**: every relay connects to every relay (list pushed by
coordinator; lower relay_id dials; mutual TLS between relay certs
pinned via the coordinator). N ≤ ~30 ⇒ N−1 sessions per relay —
trivial. Keepalives + reconnect with backoff.

**Forwarding — the entire relay data plane** (a gateway relay is
"attached to itself" in the registry; `deliver` then means unseal →
ingress filter → own TUN):
```
frame from a CLIENT session (drop unless src_id == session's node id):
    dst == me                → unseal → ingress filter → my TUN
    dst attached to me       → deliver on that client session
    dst attached to relay R  → forward on the R mesh session
    dst unknown / offline    → drop + count
frame from a RELAY session:
    dst == me                → unseal → ingress filter → my TUN
    dst attached to me       → deliver
    else                     → drop + count     # never forward again
```
The last rule makes loops impossible by construction — a frame crosses
at most one mesh link; no TTL, no spanning tree, no routing protocol.

**Per-session bandwidth caps** (v1): relay config `max_session_mbps`
(0 = unlimited; per-member override in the coordinator config entry),
enforced per client session with a token bucket — over-limit datagrams
drop + count, and the inner flows' own congestion control adapts.
Mesh sessions are never capped.
Relays never unseal; both tables are keyed by (network_id, node_id) and
a session's network is fixed at authentication, so frames cannot cross
networks. Handshake frames (0x02) forward exactly like data.

## 7. Liveness & failure handling

- **Client upstream**: QUIC keepalives; a 2 s probe to the relay gives
  RTT/loss for `nqvpn status`; transport death ⇒ reconnect + re-attach
  (next-best relay). Traffic during the gap: bounded queue then drop +
  count.
- **Relay mesh link**: keepalives + reconnect; while down, exactly the
  client pairs straddling it lose connectivity (drop + count, visible
  in relay status and the UI) — deliberately **no rerouting**; run few,
  reliable, well-placed relays.
- **Coordinator liveness**: marks clients/relays offline after
  `offline_after` missed control keepalives (default 3, ≈ 45 s;
  config-tunable per network for tighter site failover), pushes the
  flag. A dead relay's clients
  re-attach elsewhere on their own QUIC timeout; its attachment entries
  are superseded as they do.
- **Death withdraws routes** (§2): the offline transition removes all
  of the dead node's registrations from the active route table,
  recomputes owners (next-oldest living registrant per prefix), and
  pushes the membership delta — members' routing tables converge within
  the detection window (≈ 45 s) plus one push. Rejoining re-activates
  its registrations at their original (durable) age. Registrations are
  liveness-bound; **identity is not** — node id, pins, and address
  assignment survive death and stay until admin removal (UI sorts by
  last_seen).
- **Coordinator outage degrades gracefully**: relays keep forwarding on
  the last-pushed tables, clients keep their upstreams; what stops is
  joins, renewals, and attachment updates — sessions then die at
  credential `exp` (≤ TTL), the designed fail-safe.
- **Blackhole, don't leak**: while my own upstream is down, routes stay
  installed and traffic dies at the LPM as counted drops. When a
  *withdrawn* route has no successor owner, members replace its TUN
  route with an OS blackhole route (configurable, default on) rather
  than deleting it outright — traffic to a dead site must terminate,
  not fall through to the physical default route in cleartext. The
  blackhole clears when a registrant returns.

## 8. TUN & OS routing

Applies to every node with a TUN: all clients, and relays that
registered `local_cidrs` (a pure forwarding relay has none of this).

1. Create TUN; assign VPN IPs if granted; MTU 1350. Headless nodes on
   macOS/Windows get a dummy point-to-point address (utun/wintun
   require one; never advertised); Linux does address-less routes
   natively.
2. **Pin host routes** to the coordinator and all relay addresses via
   the physical default gateway — mandatory loop prevention (relay
   endpoint validation at the coordinator rejects addresses overlapping
   VPN-routed space, loopback, multicast, link-local).
3. Install routes for all other members' prefixes via TUN;
   diff-and-apply on membership deltas, transactional (failed diff ⇒
   rollback); routes die with the TUN on crash.

Backends: clients ship all three in v1 — Linux `/dev/net/tun` +
rtnetlink; macOS `utun` + `route`; Windows `wintun` + IP Helper (ships
wintun.dll, needs elevation). Gateway relays reuse the same trait's
Linux and macOS backends (no Windows relay in v1). Gateways enable OS IP forwarding (warned at startup).
**Gateway return path**: LAN hosts must route VPN prefixes back via the
gateway (gateway = LAN default gw, or a static route on the LAN
router). Where that's impossible, the operator applies SNAT manually on
the gateway host — v1 **documents exact recipes** (nftables / pf /
netsh) and the node warns when return-path checks fail, but programs
no NAT itself; the `masquerade` config flag is reserved for a future
auto-programming version. Not in v1: DNS, full-tunnel `0.0.0.0/0`
(needs exit-node NAT + DNS).

## 9. Runtime loops

Bounded channels everywhere; every drop site has a named counter
surfaced in `nqvpn status` — a silent drop is a bug by definition.

**Hot-path invariant — memory access only.** Per packet: header parse
+ two hash-map lookups on the relay (attachment, session), one LPM
trie lookup + one ChaCha20-Poly1305 op (~1 µs) on endpoints; the only
syscalls are UDP recv/send (TUN read/write on endpoints). All tables
are in-memory snapshots read lock-free (`ArcSwap`) and swapped whole
by the control task — forwarding never waits on a lock, allocates, or
touches disk. Everything expensive is off-path by construction:
credential/JWT verification only at session setup and `Refresh`,
registry fsyncs only on the coordinator, membership diffs applied
beside the pumps, not in them. Counters are atomic increments.

**Client** — plain native OS threads, ~4 total: two dedicated blocking
TUN threads (reader/writer — this is also where platform quirks live:
macOS utun flakiness, wintun's fd-less ring buffer), one network
thread whose event loop (epoll/kqueue/IOCP via current-thread tokio,
confined entirely to this thread) drives the single upstream QUIC
connection and the control connection, plus main/statusd. Startup: config/keys → join (backoff; abort on
`pin_mismatch`/`client_disabled`) → control connection + membership →
attach → TUN + routes → run:

| # | Task | Job |
|---|---|---|
| 1 | coordlink | membership intake (revisioned, incl. route-owner changes → transactional route diff + blackhole guards), renewal at ⅔ TTL (±10 % jitter) + `Refresh`; peer pubkey change ⇒ drop its Noise sessions |
| 2 | outbound pump | TUN read → LPM → Noise seal (handshake if none, queue 64) → send upstream; would-block ⇒ drop + count |
| 3 | inbound pump | upstream datagram → 0x01: window check → unseal → ingress filter → TUN; 0x02: drive Noise handshake; 0xF2 → uplink stats |
| 4 | uplink manager | keepalive + 2 s probe; death ⇒ reconnect, re-attach, re-pin host routes |
| 5 | statusd | local unix/named-pipe socket for `nqvpn status` |

**Relay** (multi-threaded tokio; the reactor is the native OS event
queue — one epoll/kqueue loop feeding worker threads. Hand-rolled
event loops are deliberately rejected because quinn must be driven by
the async runtime; io_uring remains a future Linux optimization):
coordlink (relay list + attachment
registry intake, credential renewal), client acceptor, mesh manager
(dial lower-id rule, reconnect), the §6 forwarding loop, session
reaper (close at credential `exp` without `Refresh`), statusd. A pure
relay has no TUN, no crypto beyond TLS, and no timers that decide
anything; a **gateway relay** additionally runs the client's TUN
pumps (§8, tasks 2/3 equivalents) for frames addressed to its own
node id.

**Coordinator** (multi-threaded tokio): axum API + UI, per-network
serialized state owner, QUIC control listener, membership/attachment/
keyset push, keepalive tracking.

## 10. Crates, layout, modules

tokio, axum + rustls, quinn, snow (Noise IK), x25519-dalek,
chacha20poly1305, jsonwebtoken + ed25519-dalek, rcgen, argon2, serde /
toml / bincode, ipnet, clap, tracing, rust-embed (UI). TUN: `tun-rs`
(evaluate vs `tun` in Phase 4); routes: rtnetlink / `route` / IP
Helper.

```
nqvpn/crates/
  nqvpn-proto/    api, control (envelope), frame, credential, seal (noise), lpm, types
  nqvpn-coord/    config, registry (+attachments), pins, api, webui, signer, control, status
  nqvpn-relay/    config, coordlink, clients, mesh, forward, statusd
  nqvpn-client/   config, coordlink, uplink, tun (linux/macos/win), routes, engine, statusd
```

`tun`/`routes` are leaf modules behind traits — Phases 1–3 and CI run
with a fake TUN and in-memory routes. `nqvpn-proto` depends on nothing
internal.

## 11. Phases

1. **Proto + coordinator** — envelope, credential machinery, keyring,
   `networks.d/` + overlap validation, TOFU pins, registry +
   serialized writes, membership/attachment push, admin API. Stub-node
   testable.
2. **Relay** — client sessions, mesh sessions, §6 forwarding,
   per-session bandwidth caps, `exp` enforcement. Milestone: two stub
   clients exchange sealed frames across two relays.
3. **Client core** — Noise IK sessions, ingress filter, uplink
   manager, fake-TUN pumps. Milestone: CI ping over fake TUN,
   same-relay and cross-relay.
4. **TUN + routing (Linux + macOS)** — real device, headless mode,
   gateway-relay TUN, route pinning/diff/cleanup + blackhole guards.
   Milestones: real ping A↔B across the mesh; kill a relay ⇒ both
   clients re-attach and traffic resumes; two relays register one LAN ⇒
   kill the older ⇒ ownership fails over to the younger.
5. **Windows client** + packaging/elevation.
6. **Web UI** — over the Phase-1 admin API. Milestone: operate a
   network end-to-end without curl.
7. **Hardening** — attach-move races, mesh-partition behavior,
   route-lifecycle tests (age resolution across coordinator restart,
   dead-owner takeover, flap = withdraw/re-activate, blackhole guard),
   relay/client/coordinator restarts, rekey + replay tests,
   cross-network rejection, Refresh continuity, envelope
   compatibility matrix, signing-key rotation with restarts,
   membership revision gaps, reload reconciliation, ingress-filter
   and parser fuzzing, MTU edges, metrics.

## 12. Decisions (locked 2026-08-07)

Formerly the open-questions list; all resolved with the product owner
and reflected in the sections above.

1. `want_vpn_ip` defaults **on** for clients and relays; headless is
   an explicit opt-out (§3.2).
2. IPv6 inner uses **ULA**; no global-v6 tunneling in v1.
3. Relay attachment: **RTT-based auto-detection**; client config may
   set `preferred_relay_id`, which wins when reachable (§6).
4. **Flat mesh** in v1; per-pair ACLs (credential claims) deferred.
5. Credential TTL **15 min** (= worst-case revocation window).
6. Per-session relay **bandwidth caps in v1** (`max_session_mbps`,
   token bucket, per-member override; §6, Phase 2).
7. Noise rekey every **2 min** (WireGuard's constant; §4).
8. Mesh-link outage: **drop, no reroute** — inner TCP retries; worst
   case the client reconnects (§7). Relay-triangle failover rejected
   to keep forwarding one page.
9. **One process per network** for clients in v1.
10. Network lifecycle: **config-file + reload** only in v1.
11. Gateway masquerade/SNAT: **manual, documented recipes** in v1; the
    node warns on broken return paths but programs no NAT (§8).
12. Death detection default **3 missed keepalives (≈ 45 s)**,
    `offline_after` config-tunable per network (§7).
13. Route-ownership **flap damping on** by default (`hold_down` 60 s,
    0 = off; §2).

## 13. Appendix: config examples

Reviewed and locked with the product owner; Phase 1 parses exactly
these shapes. Secrets are plaintext only on the member's own machine
(`_file` variants preferred); the coordinator stores argon2 hashes.
Everything runtime-negotiated (MTU, keepalive, relay list, addresses,
`network_uuid`) arrives via the join response and is deliberately
absent from member configs.

### coordinator.toml
```toml
[listen]
api  = "0.0.0.0:8443"          # HTTPS: /api/v1/* and /ui
quic = "0.0.0.0:4433"          # QUIC control (mutual TLS, push channel)

[tls]
cert = "/etc/nqvpn/tls/fullchain.pem"
key  = "/etc/nqvpn/tls/privkey.pem"

[state]
dir = "/var/lib/nqvpn-coord"   # registries, signing keyring (0600), pins

[admin]
users = { alice = "$argon2id$v=19$..." }      # nqvpn-coord hash
bearer_token_file = "/etc/nqvpn/admin-token"  # optional, automation
session_ttl_mins = 720

[limits]
join_rate_per_min = 10         # per client_id + IP; login endpoint same
```

### networks.d/acme-prod.toml
```toml
network_id = "acme-prod"

cidrs = ["10.99.0.0/16", "fd99::/64"]

[pools.default]
cidr = "10.99.1.0/24"
[pools.servers]
cidr = "10.99.2.0/24"
[pools.v6]
cidr = "fd99::1:0/112"

[settings]                     # defaults shown; all optional
credential_ttl_mins = 15
keepalive_secs = 15
offline_after = 3              # missed keepalives => offline (~45 s)
hold_down_secs = 60            # route-flap damping (0 = off)
mtu = 1350

[relays.home]
secret_hash   = "$argon2id$v=19$..."
relay_addr    = "home.example.com:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.1"
max_session_mbps = 200

[relays.aws]
secret_hash   = "$argon2id$v=19$..."
relay_addr    = "3.1.2.3:4444"
allowed_cidrs = ["172.31.0.0/16"]
preferred_ip4 = "10.99.0.2"

[relays.home-backup]           # overlapping CIDR = age-based failover
secret_hash   = "$argon2id$v=19$..."
relay_addr    = "home2.example.com:4444"
allowed_cidrs = ["192.168.1.0/24"]
preferred_ip4 = "10.99.0.4"

[clients.laptop-1]
secret_hash = "$argon2id$v=19$..."
pool = "default"

[clients.build-server]
secret_hash = "$argon2id$v=19$..."
pool = "servers"
preferred_ip4 = "10.99.2.10"
max_session_mbps = 50

[clients.phone]
secret_hash = "$argon2id$v=19$..."
```

### relay.toml
```toml
coordinator = "https://coord.example.com:8443"
network_id  = "acme-prod"
client_id   = "home"
client_secret_file = "/etc/nqvpn/secret"
# coordinator_ca = "/etc/nqvpn/coord-ca.pem"   # pin if self-signed

listen     = "0.0.0.0:4444"    # one QUIC socket: clients + mesh
relay_addr = "home.example.com:4444"

[identity]
dir = "/var/lib/nqvpn-relay"   # x25519 key + TLS cert (loss => pin reset)

[gateway]                      # OPTIONAL — omit for a pure forwarder
local_cidrs = ["192.168.1.0/24"]

[limits]
max_session_mbps = 200         # coordinator per-member override wins
workers = 0                    # 0 = num_cpus
```

### client.toml
```toml
coordinator = "https://coord.example.com:8443"
network_id  = "acme-prod"
client_id   = "laptop-1"
client_secret_file = "/etc/nqvpn/secret"

[identity]
dir = "/var/lib/nqvpn-client"

[relay]
# preferred_relay_id = "home"  # member name; omit => RTT auto-detect

[address]                      # entire section optional
# pool = "default"
# preferred_ip4 = "10.99.1.50"
```
