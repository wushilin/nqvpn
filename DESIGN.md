# nqvpn — Design

An L3 (TUN-based), dual-stack VPN in Rust, built as a **distributed,
interconnected relay service**. Three binaries with one job each. No
peer-to-peer data connections between clients — simplicity is the
product.

Platforms: the **client** runs on Linux and macOS (Windows: not yet). The
**coordinator and relay** are Linux-first and also run on macOS.

Guiding rules: every component's forwarding logic fits on one page, and
**every piece of shared state is a pure function of what the coordinator
published plus what the node itself holds** — nothing is set by one
message and cleared by another.

(Earlier designs — full-mesh P2P, TOFU pinning, identity rotation, an
event-driven attachment registry — are superseded; their documents are
in git history.)

---

## 1. Architecture

```
                nqvpn-coord  (control only: join, view, admin + UI)
                 ▲        ▲                    ▲
                 │        │  generation-numbered│
        HTTPS join +      │  view, heartbeats   │
        QUIC control      │                     │
   client A ──► relay R1 ═══════ relay R2 ◄── client B
   (TUN)          full mesh, N×N, QUIC          (TUN)
                 (pure forwarders, no TUN)
```

- **nqvpn-client**: a leaf. One TUN, one upstream QUIC session to a
  relay, one control session to the coordinator. Gets its VPN address
  from the control plane; cannot register routes.
- **nqvpn-relay**: a forwarding service — sessions to attached clients
  and to every other relay (full mesh); forwarding is two table lookups
  (§6). One process serves **any number of networks**. Optionally a
  relay is also its site's **gateway**: it registers a local CIDR, gets
  a TUN and an endpoint identity like any member.
- **nqvpn-coord**: control plane only — join API, credential signing,
  the per-network view, admin API + web UI. Touches no traffic.

The data path is always `client → relay [→ relay] → endpoint`, never
more hops, chosen by table lookup. No path selection, no rerouting
around a down mesh link; loops are impossible by construction (§6) and
additionally by a hop counter in every frame (§5).

Members **never learn each other's IP addresses**; only relays and the
coordinator have underlay addresses.

### 1.1 Crates and dependency direction

Crates are the only boundary Rust enforces, so the important seams are
crates. Dependencies point strictly downward; no crate depends on a
binary.

```
nqvpn-proto      wire + crypto, no policy
  envelope, frame, control (Snapshot/Delta/Heartbeat + diff/apply/digest),
  api (join DTOs), credential (JWT), seal (Noise IK, replay window),
  identity (TLS cert), quic (TLS config), transport (lanes), rpc, lpm, flow,
  joinapi (HTTPS join client)

nqvpn-session    "one task owns one connection" — used on every hop from both ends
  Hello/HelloAck, control stream (Refresh, probes), expiry, probe liveness

nqvpn-sync       member side of the control plane — shared by client and relay
  join + renewal, the generation protocol (View, run_session, run_member),
  the reconciler driver

nqvpn-endpoint   everything that terminates traffic — client, and gateway relay
  engine (seal/unseal pumps), peers (LPM + ingress filter), tun (+ backends),
  routes (wanted set, local exclusion, diff reconcile), ifaces, endpoint_guard

nqvpn-relay      forwarding only
  net (RelayNet: per-network tables, sessions, dialers, reconcile, data plane),
  tables (route decision — pure), endpoint (gateway role), config

nqvpn-client     thin: config + client (uplink chooser, reconciler hooks) + main

nqvpn-coord      one module per concern, all mutation through one lock per network
  config, registry (durable identity), secrets, ipam, leases (heartbeat intake),
  directory (registry + leases → Snapshot; generations; delta ring),
  control (QUIC sessions, push, catch-up, sweep), state (join transaction), api
```

Five rules keep it reviewable:

1. **Decisions are pure functions; I/O is executors.** `route()`,
   `Snapshot::diff/apply/digest`, `wanted_routes`, `exclusion_reason`,
   `Leases::attachments`, `Directory::recompute` take values and return
   values. Their tests need no sockets.
2. **One struct owns one table, one task writes it.** A relay's
   `clients`/`mesh` are written only by session lifecycle; its
   attachment table and dialer set only by `reconcile`. No
   `Arc<Everything>` mutated from five tasks.
3. **Cross-module contracts are traits with a fake in the defining
   crate**: `TunDevice`, `RouteProgrammer`, `Uplink`, `Verifier`,
   `Acceptor`, `LocalFacts`, `Reconcile`, `MemberHooks`.
4. **A module imports only from the layer below**: proto ← session ←
   sync/endpoint ← relay/client; coord ← proto.
5. **Each crate has its own test level**: codec/crypto vectors in
   proto; one connection lifecycle in session; gap/resync in sync; fake
   TUN in endpoint; forwarding with a stubbed coordinator in relay;
   join/control with a real coordinator in coord; end-to-end on top.

## 2. Addressing & routes

- The coordinator assigns each member a stable **node id** (`u32`) at
  its first join — the wire identity in every frame header, never
  configured by anyone. All forwarding uses node ids, never inner IPs;
  people only ever deal in member **names**.
- **Clients** own exactly their VPN address(es), advertised as /32 and
  /128. **Relays** register the **local CIDRs** the operator configured
  for them at the coordinator; a gateway relay may be headless. Addresses
  need not lie inside the tunnel CIDRs — a configured one is routed as a
  host prefix — they only have to be unique and routable.
- **Route lifecycle — liveness-bound, age-resolved.** Several relays may
  register overlapping CIDRs; for any prefix the **oldest living
  registration wins** and is the only owner pushed. A node going offline
  withdraws its registrations; the next-oldest living registrant takes
  over on the next recompute (site-gateway failover for free). **Flap
  damping**: a returning older registrant waits `hold_down_secs`
  (default 60, 0 = off) before reclaiming from a live standby.
- Registration **age** belongs to the (node, cidr) pair while the CIDR
  stays continuously declared across joins (renewal is a join). Drop it
  and re-add it and it is young again.
- Forwarding at an endpoint is one LPM lookup (prefix → node id).

## 3. Coordinator

### 3.1 Networks: configuration is the coordinator's

The coordinator hosts N isolated networks (`network_id`). Every network —
tunnel CIDRs, named pools (each entirely inside a tunnel CIDR, pairwise
disjoint), settings, and its members with everything about them — is
created and edited in the web UI (or the admin API) and kept in one
SQLite database (`state.dir/nqvpn.db`), together with the registries.
`coordinator.toml` holds only the process: listen addresses, TLS, the
database directory, the admin login. Every change is validated as a whole
network before it is committed; an invalid change leaves the running one
untouched. Tunnel CIDRs may overlap *across* networks — tenants never see
each other.

A member's configuration is its *declaration*: address (or pool),
routed prefixes and advertised address for relays, preferred relay for
clients, bandwidth cap. Every join applies it in full. When the operator
changes it, the coordinator closes the member's control session with
`CLOSE_RECONFIGURED`; the member re-joins at once (no backoff) and
applies the new facts in place — re-addresses its device, re-announces —
without a restart. Conflicts (overlapping prefixes, duplicate addresses)
are refused at edit time, where the operator is.

IPAM: a configured `pool` (`409 pool_exhausted` / `400 unknown_pool`)
or a `preferred_ip4/6` (`409 address_in_use` if taken). Assignments are
sticky and durable; the allocator cycles forward DHCP-style so a freed
address is not reissued immediately. Relays use the identical mechanism.
A relay's advertised address may be `auto:<port>`: the address it joined
from, on that port.

### 3.2 Security model: the token

**A member is a name and a secret. Nothing else authenticates.** The
secret is what a machine holds, inside its **token** —
`nqv1.<base64url(endpoint=https://coord:8443;secret=…)>` — an opaque
lookup key, not a bearer of configuration: the coordinator maps the
secret to the member (network, name, role) and to everything the
operator configured for it. Tokens do not expire; they are regenerated.
The 32-bit node id is the wire identity, assigned by the coordinator at
the member's first join, durable for the life of the record, never
reused, and never written anywhere by a person.

- Join is `POST /api/v1/join` over HTTPS with `{secret, pubkey,
  cert_fingerprint}` — nothing else about the member, because the
  machine knows nothing else. The coordinator checks the secret and
  nothing about the machine: there is no pinning, no device lock.
  Anyone with the token *is* that member; regenerate the token to evict
  them (immediately: the old holder's next join is refused and every
  acceptor drops its sessions).
- Secrets are **generated, never chosen** (32 random bytes) and kept
  **in the clear** in the database so an operator can show a token again
  or regenerate it at any time. `Export`/`Import` carry them.
- Each member auto-generates a TLS certificate and an X25519 key on
  first run. They are internals: recorded at each join, published to the
  network, replaced silently by the next join if the files were lost.
  The UI never shows them.
- The **credential** is a JWT (Ed25519, `kid`-tagged keyring, TTL
  `credential_ttl_mins`, default 15) with claims `{iss, aud:"nqvpn-v1",
  network_id, network_uuid, node_id, sub (name), role, pubkey, cert_fp,
  prefixes, login_gen, iat, exp}`, verified offline everywhere with
  ±120 s clock leeway. Every QUIC session is mutual TLS and the acceptor
  requires the peer's live certificate to equal the credential's
  `cert_fp`: a stolen credential is useless without the private key. This
  binds a session to a join; it can never refuse a join.
- A relay admits a session only for a node its current view lists (or
  any node while it has no view yet); a node the view does not list —
  deleted, disabled, or simply not pushed yet — is refused and retries a
  second later. Once admitted, a session is evicted only by `reconcile`
  when the view drops the node or shows a newer `login_gen`.
- **HTTPS by default, `trust_any_cert = true` by default.** The
  coordinator serves a self-signed certificate it generates on first
  start (the same identity as its QUIC control port) unless `[tls]` names
  a real one. The default protects the secret against passive listeners
  but not against someone on the path who answers as the coordinator;
  set `trust_any_cert = false` (and `ca` for a self-signed coordinator)
  to verify.
- **Join is a full re-declaration.** Whatever the latest join says
  replaces what was recorded: keys, gateway CIDRs (not re-declared ⇒
  withdrawn now), address requests, relay address. Kept across joins:
  the node id; the assigned address unless the join asks for another
  (granted if free, old one released; `want_vpn_ip = false` releases);
  route age while continuously declared.
- **Replacement.** When a join presents a different `(pubkey, cert_fp)`
  than recorded, the member's `login_gen` is incremented, recorded with
  `replaced_from`/`replaced_unix`, put in the new credential and in the
  published view. Every acceptor closes sessions carrying an older
  `login_gen` (the coordinator at once; relays on the next reconcile,
  ≤ one heartbeat) and refuses the old credential at `Hello`. Two
  machines sharing one id + secret therefore replace each other at every
  renewal; status shows it, and the fix is a second id.
- Revocation: `disable` evicts now (session closed, lease dropped,
  member removed from the view so peers and relays drop it); the
  credential stops renewing. Sessions also end at credential `exp`
  unless refreshed.

### 3.3 The join transaction

One `Mutex<NetState>` per network is the serialization point: every
mutation runs under it, and the registry is fsync-committed *before* the
credential is returned. Rate limit: `join_rate_per_min` (default 30) per
(node, network, IP). The relay reachability probe runs *after*
authentication, against the *configured* `relay_addr`, never the
request's. Response: `{credential, network_uuid,
coordinator_signing_keys, node_id, name, login_gen, ip4/subnet4,
ip6/subnet6, granted_cidrs, relays:[{relay_id,name,addr,cert_fp}], mtu,
keepalive_secs, transport, lanes, control_port, heartbeat_secs}` — the
member dials the API host on `control_port` (default 14433) for the
control plane, so one URL in its config is enough.

### 3.4 Admin API & web UI

Admin access is a UI login (`[admin] user` + argon2 `password_hash`,
session cookie, throttled per address) or a static `bearer_token` for
scripts. All under `/api/v1/`:

| Route | Purpose |
|---|---|
| `POST login` / `POST logout` / `GET me` | UI session |
| `GET ws` | live feed: every network's status, pushed on each publish and every 2 s |
| `GET status` | per network: members, relays, online, current `gen` |
| `POST networks` / `PUT`/`DELETE networks/{id}` / `GET networks/{id}/config` | create, edit (address space, pools, settings), delete, read a network |
| `GET networks/{id}/status` | members (online, address, routes, attached relay, heartbeat age, `reported_gen` + `digest_ok`, last join from, `login_gen`, replaced from), prefix→owner table, traffic matrix |
| `POST networks/{id}/members` / `GET`/`PUT`/`DELETE …/members/{name}` | declare a member (returns its token), read, edit (the member re-joins), forget |
| `GET`/`POST …/members/{name}/token` | show / regenerate (the previous stops working now) |
| `POST …/members/{name}/disable` \| `enable` \| `reconnect` | durable flag (disable evicts); make it re-join now |
| `GET export` / `POST import` | all configuration as JSON |

Errors are `{error:{code,message}}` with codes `bad_credentials`
(unknown id, wrong secret, or unknown network — indistinguishable),
`client_disabled`, `prefix_conflict`, `address_in_use`, `pool_exhausted`,
`unknown_pool`, `relay_unreachable`, `bad_request`, `rate_limited`. The
**web UI** (`/ui`, dependency-free, embedded, responsive, WebSocket-fed)
is a client of this API: a wizard for networks and members, the token
for each member with its ready-to-paste config, live topology and traffic
matrix per network. It speaks in names and tokens; ids appear only as
information.

## 4. Control plane: a generation-numbered view

The coordinator publishes one value per network — a **Snapshot** — the
whole view at one **generation**. Members hold a copy and keep it
current by three rules and nothing else:

```
Hello     { credential, have_gen }              member → coordinator, first message
HelloAck  { gen }
Snapshot  { gen, members: [PeerInfo], attachments: [{node_id, relay_id}],
            relays: [{relay_id, name, addr, cert_fp}], mtu: {mtu, limited_by},
            keys: [{kid, key, state}], reserved_prefixes: [cidr] }
Delta     { base_gen, gen, members_changed, members_removed,
            attachments_changed, attachments_removed,
            relays?, mtu?, keys?, reserved_prefixes? }      (None = unchanged)
Heartbeat { gen, digest, attached: [{node_id, session_id}], mesh_up: [relay_id],
            attached_to?, usable_mtu, traffic? }            member → coordinator
Resync    { have_gen }                                       member → coordinator
Refresh   { credential }                                     member → any acceptor
PeerInfo  { node_id, name, role, prefixes, pubkey, online, login_gen }
```

1. **A `Delta` applies iff `base_gen` equals the held generation.** A
   delta up to a generation already held is a harmless duplicate (a
   catch-up can race a push already queued). Anything else is a gap: the
   member sends `Resync` and touches nothing until a snapshot arrives.
2. **Every heartbeat carries the held `gen` and a content digest.** A
   member behind is caught up from the delta ring (last 512 deltas) or
   by a snapshot. A member at the same generation with a *different*
   digest is a bug: logged with both digests, and resynced.
3. **Heartbeats carry the member's whole local truth**, never events: a
   relay lists every client it holds, every mesh link that is up, its
   traffic counters; a client its relay and usable MTU. There is no
   detach message — a relay that no longer holds a client stops listing
   it.

Push for speed, generation for continuity, heartbeat for safety: every
change is pushed the moment it happens; a lost push costs at most one
heartbeat period; a session whose push queue (256) overflows is closed
and catches up from its generation on reconnect.

`Snapshot::diff/apply/digest` live in `nqvpn-proto` so the coordinator
and every member run the same code over the same type. The digest is
FNV-1a over the canonical (sorted, gen-zeroed) bincode encoding.

**Generations are unique across restarts.** On start `gen =
max(now_ms, hwm + 1000)`; every change is `+1`; the registry persists
`hwm = gen + 1000` whenever `gen` passes it. A crash loses at most 1000
increments, which the start-up rule skips over, so no generation is ever
handed out twice however busy the previous instance was.

**Collect before publishing.** For `2 × heartbeat_secs` after start the
coordinator answers `Hello` but sends no snapshot: members keep their
last view until the fleet has re-declared what it holds.

The member side (`nqvpn-sync`): `run_member` = join → `run_session` →
reconnect with backoff (reset only after a session that lasted 30 s) →
re-join; a renewal task re-joins at ⅔ of the credential lifetime and
hands the new credential to the control session (`Refresh`) and to the
owner's data sessions. `Hello.have_gen` says what the member holds, so a
reconnect costs deltas, not a snapshot.

## 5. Wire format (QUIC datagrams or lanes)

Data rides **QUIC datagrams** (RFC 9221) or **stream lanes**, chosen per
network by `transport` (default `stream`: on lossy consumer uplinks QUIC
repairing loss beneath the inner TCP measured 87 vs 54 Mbit/s; on a
clean backbone with many flows datagrams win). Stream mode spreads
packets across `lanes` (default 1) unidirectional streams: endpoints
hash the inner 5-tuple to pick a lane, relays echo the lane a frame
arrived on. Lane count needs no negotiation — a receiver accepts however
many streams arrive.

Control messages ride a bidirectional stream in a frozen envelope
`[major u8][minor u8][kind u16][len u32][payload]`; version checked once
at `Hello` (equality — peers are deployed together); unknown kinds are
skipped by length; `len` capped at 1 MiB with strict bincode limits.

```
0x01 Data       [type 1][src_id 4][dst_id 4][flags 1][hop 1][trace 4][ctr 8][AEAD ciphertext]
0x02 Handshake  [type 1][src_id 4][dst_id 4][flags 1][hop 1][trace 4][noise handshake message]
0xF1 Probe      [type 1][seq 8][t_sent 8]      hop-local, never forwarded
0xF2 Reply      probe echoed by the far end of the hop
0xF3 TraceNote  [type 1][origin 4][trace 4][hop 1][relay_id 4][decision 1][detail 4]
```

- **`hop`** is incremented by every relay; a frame arriving with
  `hop ≥ 2` is dropped (`drop_too_many_hops`). A loop guard that does
  not depend on any table being right.
- **`trace`** is chosen by the origin per flow (folded flow hash). With
  `FLAG_TRACE` set (`nqvpn-client --trace <ip>`) every relay answers a
  `TraceNote` with what it did — `deliver_local`, `forward_mesh`,
  `terminate_here`, or a `drop_*` reason — on the session the frame
  arrived on; a relay receiving a note from the mesh passes it to the
  attached `origin`. The **Decision** vocabulary is the key of every relay
  counter, so a number in status and a line in a trace cannot disagree.

MTU: inner 1350 = 1500 − ~60 QUIC/UDP/IP − 39 frame overhead (15 header
+ 8 counter + 16 tag) with margin; `INITIAL_MTU` 1440 so full-size
frames fit before path discovery. The coordinator publishes the
network-wide minimum of what members report (`limited_by` names the
member), never below 1280.

## 6. Sessions, attachment & forwarding

**Sessions (`nqvpn-session`).** One task owns one QUIC connection on
every hop — client↔relay and relay↔relay — from both ends. `Hello
{credential}` / `HelloAck`; the control stream carries `Refresh` and
hop-local probes; the task ends at credential expiry unless refreshed,
when the far end stops answering probes (dialer side probes every 2 s,
5 misses = dead; the acceptor answers), when the peer closes, or when
its owner closes it. The acceptor verifies that a `Refresh` is for the
same node and role. **The only way a session leaves any table is its
task ending** — in the relay, registration is an RAII guard, so even an
aborted task deregisters. A newer session for the same node replaces and
closes the older one; the newest wins, everywhere.

**Attachment.** A client picks a relay (`[relay] preferred` when
reachable, else lowest RTT — probed in parallel), dials it, and the
relay's next heartbeat lists it. Convergence is sub-second (a local
change kicks an immediate heartbeat), ≤ one period if a push is lost.

**Relay mesh.** Every relay connects to every relay; the **lower id
dials**, pinned to the fingerprint the coordinator published for the
peer. The dialer set is a diff of the view against running dialer
tasks: new or changed address/fingerprint ⇒ (re)spawn, gone ⇒ abort and
close.

**Forwarding — the entire relay data plane** (`tables.rs::route`):
```
frame from a CLIENT session (drop unless src_id == session's node id):
    dst == me                → unseal → ingress filter → my TUN
    dst attached to me       → deliver on that client session
    dst is a relay           → forward on its mesh session
    dst attached to relay R  → forward on the R mesh session
    dst unknown / link down  → drop + count
frame from a RELAY session (drop unless src_id is that relay or attached to it):
    dst == me                → unseal → ingress filter → my TUN
    dst attached to me       → deliver
    else                     → drop + count     # never forward again
```
Per-client bandwidth cap: `max_session_mbps` token bucket per session;
mesh sessions are never capped. Relays never unseal; a session's network
is fixed at `Hello` (a relay serving several networks dispatches on the
credential's `network_id`), so frames cannot cross networks.

**Reconcile (relay).** On every view change and every 20 s: signing
keys; the attachment table (swap); **evictions** — a session whose node
is no longer in the view, whose `login_gen` is older than the view's, or
whose relay left the fleet is closed on the wire; the dialer set diff;
the gateway endpoint's peers and routes.

## 7. Liveness & failure handling

**Leases.** Members heartbeat every `heartbeat_secs` (default 5) and go
offline after `offline_after` (default 3) misses. Offline withdraws the
member's routes; identity (id, address, ages) survives.

**Attachments are derived, never set.** Each relay's heartbeat is its
whole declared set; the coordinator keeps a claim per (relay, client,
session id) with a sequence number, and for each client **the most
recent declaration wins** — a sequence, not a clock, so a move that
completes within a millisecond still has exactly one winner; a relay's
own session id makes a re-attach a new declaration. An attachment goes
away only when no relay declares it, or when the member is
deleted/disabled. **Neither side's control lease matters**: a relay that
cannot reach the coordinator still forwards for its clients, and a
client that cannot reach the coordinator is still attached to its relay
— the relay holds the session, and reports it for as long as it lasts
(a dead client's session ends at the relay's QUIC idle timeout, and the
declaration with it).

| Scenario | What happens |
|---|---|
| Client loses its coordinator path, relay fine | Lease expires → offline, routes withdrawn. Its relay session and its attachment are untouched (nothing evicts a live session from outside; the relay keeps declaring it); back on the next heartbeat. Zero data-plane effect, in both directions. |
| Relay loses its coordinator path | Its lease expires; its clients' attachments outlive it; mesh peers keep forwarding to it. It reconnects with `have_gen` and catches up by deltas. |
| Coordinator restart | Members keep their views; the coordinator collects heartbeats for 2×`heartbeat_secs`, then publishes; generations continue above the old ones. |
| Relay dies | Its clients' probes fail within ~10 s → re-attach elsewhere → new declarations win. Mesh peers' probes fail → dialers reconnect with backoff. Its routes withdraw at lease expiry; a standby gateway takes over. |
| Client moves relay | The new relay's declaration is newer and wins; the old relay's stale session is replaced/closed and simply stops being listed. No detach can arrive late. |
| Lost push / queue overflow | Next heartbeat is behind → deltas from the ring or a snapshot, ≤ one period. Overflow closes the session; it reconnects with `have_gen`. |
| Digest mismatch at equal gen | Logged as a bug with both digests; snapshot sent. Visible in status as `digest_ok = false`. |
| Different machine joins as a node | `login_gen` bumps; the old control session is closed at once, its relay sessions on the next reconcile, its credential refused at `Hello`. |
| Disable / delete | Session closed, lease dropped, member removed from the view; peers drop its Noise session and relays evict it; renewal refused. |
| Mesh link down | Exactly the pairs straddling it lose connectivity (`drop_mesh_link_down`, visible in status and traces). No reroute by design; run few, well-placed relays. |
| Gateway prefix equals a member's own LAN | Not installed (`inside local interface prefix`), counted and logged; the tunnel never captures the underlay. |

**Blackhole, don't leak.** Members route every `reserved_prefix` —
tunnel CIDRs and every registered gateway CIDR, owned or not — into the
TUN. Traffic to a site that is down enters the tunnel, matches no owner,
and is dropped as `drop_no_route`, rather than leaving in cleartext for
a 192.168.x range that very likely exists somewhere real.

## 8. Endpoint: TUN, crypto & OS routing (`nqvpn-endpoint`)

Applies to clients and gateway relays.

- **Noise IK** per pair (`snow`), prologue-bound to `(network_uuid,
  initiator, responder)`; ChaCha20-Poly1305; explicit 8-byte counter;
  rekey every 2 min. First packets to a peer wait in a bounded queue
  (64, drop-oldest) during the handshake.
- **Replay window: 2048 bits, two-phase** — `check` before decryption,
  `commit` only after the tag verified, so a straggler from a previous
  session or a frame injected by an (untrusted) relay can never move the
  window. Sized for multi-lane reordering.
- **Crossed handshakes**: both sides initiate at once; the lower node id
  yields, answers the other's message, and carries its queued packets
  over. `msg1` carries the initiator's clock; a responder refuses one not
  newer than the last it accepted from that peer (replay).
- **Ingress filter** after unseal: inner source ∈ prefixes(src_id), inner
  destination ∈ mine (host addresses, or a LAN I front), else drop.
  Traffic to my own *host* address loops back to the TUN (macOS routes a
  utun's own address into it); a gateway's LAN never does.
- **Routes are a function of the view.** `wanted = reserved_prefixes ∪
  every other member's prefixes − anything inside my own space`. Then
  **excluded**: a prefix equal to or inside a local interface prefix (it
  would steal the LAN), or one containing an underlay address (the
  coordinator, a relay) with no more-specific local route protecting it.
  A prefix *wider* than a local LAN is fine — the kernel's longest match
  keeps the LAN local. `RouteSet::reconcile` diffs wanted against
  installed and issues only the difference; a 20 s re-assert heals
  routes another writer removed. One endpoint per network per host,
  enforced with an `flock`.
- Backends: Linux `/dev/net/tun` + `ip route`; macOS `utun` + `route`
  (IPv6 with explicit `-prefixlen`). Gateway return path: LAN hosts must
  route VPN prefixes back via the gateway; no NAT is programmed.

## 9. Runtime shape

Bounded channels everywhere; every drop has a named counter (relay
counters are keyed by `Decision`; the engine's by cause). Hot path:
header parse + two hash lookups on the relay; one LPM + one AEAD on an
endpoint; no lock held across I/O.

- **Client** — current-thread tokio plus two blocking TUN threads:
  outbound pump, uplink task (`nqvpn-session`), control link
  (`nqvpn-sync`), reconciler, rekey sweep, status.
- **Relay** — multi-threaded tokio: one accept loop for the fleet; per
  network a `RelayNet` with session tasks, dialer tasks, control link,
  reconciler, and optionally the endpoint pumps.
- **Coordinator** — multi-threaded tokio: HTTPS API (axum), QUIC control
  sessions (reader + writer per member), one liveness sweep per second.

## 10. Status

Implemented: everything above. Not yet: Windows client, DNS, full-tunnel
`0.0.0.0/0`, a runtime IPC for `nqvpn trace` (today the trace target is a
start-up flag and notes are logged), per-member `max_session_mbps`
override from the coordinator.

## 11. Appendix: config

### coordinator.toml
```toml
[listen]
api  = "0.0.0.0:8443"          # HTTPS: /ui and /api/v1/*
quic = "0.0.0.0:14433"         # QUIC control plane; published to members at join
# public_url = "https://coord.example.com:8443"   # in every token; default: the browser's URL

# [tls]                        # optional real certificate; unset = self-signed, generated
# cert = "/etc/nqvpn/tls/fullchain.pem"
# key  = "/etc/nqvpn/tls/privkey.pem"

[state]
dir = "/var/lib/nqvpn-coord"   # nqvpn.db (networks, members, secrets, registries), signing keyring

[admin]
user = "admin"
password_hash = "$argon2id$…"  # nqvpn-coord hash-password
# session_hours = 12
# bearer_token = "..."         # for scripts

[limits]
join_rate_per_min = 30
```

Networks and members are not in any file: they are created in the UI
and live in the database. `GET /api/v1/export` is their JSON form.

### relay.toml
```toml
listen    = "0.0.0.0:4444"     # one QUIC socket: clients + mesh, every network
state_dir = "/var/lib/nqvpn-relay"
# trust_any_cert = true        # default; false + ca = verify

[limits]
max_session_mbps = 0           # per attached client; 0 = what the coordinator says
workers = 0                    # 0 = one per core

[[networks]]                   # one per network this relay serves
token_file = "/etc/nqvpn/relay.token"
```

### client.toml
```toml
token_file = "/etc/nqvpn/client.token"   # or: nqvpn-client --token "nqv1.…"
state_dir  = "/var/lib/nqvpn-client"
# tun_name = "nqvpn0"
```
