# NetQ VPN (`nqvpn`)

**A relay-mesh overlay network that stays correct when the network does not.**

NetQ is an L3 (TUN), dual-stack VPN built as a small fleet of interconnected
relays and one control-plane coordinator. Clients hold exactly one QUIC
session to a relay of their choice; relays hold a full mesh between each
other; every packet is sealed end to end with Noise IK so relays forward what
they cannot read. The coordinator never touches traffic — and the data plane
keeps running when the coordinator, or the path to it, is gone.

```
                    ┌─────────────────────────┐
                    │      nqvpn-coord        │   control only:
                    │  join · view · admin UI │   HTTPS + QUIC
                    └───────┬─────────┬───────┘
          generation-numbered│         │heartbeats
                    ┌────────▼──┐   ┌──▼────────┐
   laptop ─────────►│  relay    │═══│  relay    │◄───────── phone
   (TUN)            │  home     │   │  cloud    │           (TUN)
   office-pc ──────►│  gateway  │═══│           │◄───────── build-server
                    └───┬───────┘   └───────────┘
                  192.168.1.0/24            full mesh, N×N
                  (site LAN)                (pure forwarders, no TUN)
```

## Why a relay mesh

| | Hub and spoke | Full P2P mesh | **NetQ relay mesh** |
|---|---|---|---|
| Sessions per client | 1 | N−1, NAT traversal, holes | **1** |
| Hops between two clients | 2 (always via the hub) | 1 | 1 or 2, by table lookup |
| Who learns your IP | the hub | every peer | **only your relay** |
| Site-to-site (LAN behind a node) | hub is the gateway | every node routes | **any relay is a gateway; two of them fail over by age** |
| Full-tunnel internet exit | the hub, if any | every node | **any relay, flagged and health-checked; clients prefer one and fall back** |
| What breaks when the control plane is down | nothing… until keys expire | discovery, NAT punching | **nothing for 15 min; sessions live until credentials expire** |
| Forwarding logic | trivial | complex | **one page** (§6 of DESIGN.md) |

```mermaid
flowchart LR
    subgraph site_home["home site · LAN 192.168.1.0/24"]
        H[relay home<br/>gateway]
        L1[laptop]
        NAS[(NAS on the LAN)]
    end
    subgraph cloud["cloud"]
        C[relay cloud]
        B[build-server]
    end
    subgraph away["on the road"]
        P[phone]
    end
    L1 -- "1 QUIC session" --> H
    P -- "1 QUIC session" --> C
    B -- "1 QUIC session" --> C
    H <== "mesh link (N×N)" ==> C
    H --- NAS
    P -. "phone → cloud → home → NAS<br/>exactly one mesh hop, sealed end to end" .-> NAS
```

## Design principles

The whole design fits in one sentence: **every piece of shared state is a
pure function of what the coordinator published plus what the node itself
holds** — nothing is set by one message and cleared by another. Concretely:

1. **Push for speed, generation for continuity, heartbeat for safety.** The
   coordinator publishes one *view* per network under a 64-bit generation.
   Changes are pushed as deltas the moment they happen; a delta applies only
   onto exactly the generation a member holds, otherwise it asks for a
   snapshot; every heartbeat carries the held generation and a digest of it,
   so a member that missed a push is caught up within one heartbeat and one
   that *disagrees* at the same generation is logged as the bug it is.
2. **Nodes send facts, not events.** A relay's heartbeat is the whole set of
   clients it holds. There is no attach/detach message to lose or reorder;
   the attachment table is derived — most recent declaration wins — and an
   entry disappears only when no relay declares it.
3. **One task owns one connection.** On every hop, from both ends, a session
   is a single task that authenticates, answers probes, refreshes its
   credential, and ends at expiry or probe timeout. The only way a session
   leaves a table is that task ending. The coordinator never touches one.
4. **Reconcile by diff against observed state.** Desired state arrives
   whole; a node diffs it against what it actually has (open sessions, dialer
   handles, kernel routes) and acts only on the difference, idempotently, on
   every change and on a timer.
5. **Control-plane trouble never becomes data-plane trouble.** A client or
   relay that cannot reach the coordinator keeps forwarding; a coordinator
   restart interrupts nothing; a lost push costs one heartbeat.
6. **Loops are impossible twice.** By construction (a frame crosses at most
   one mesh link) and by a hop counter in every frame that no table can
   override.
7. **A member is a name and a secret.** Nothing else authenticates: no
   certificate pinning, no device lock, no key rotation ceremony. Joining
   from a new machine replaces the old one immediately. Node ids are 32-bit
   wire identities assigned by the coordinator and never configured.
8. **Every drop has a name, every path can be traced.** Six bytes in the
   frame header (`hop`, `trace`) let a relay report exactly what it did
   with a packet back to the sender — `traceroute` for the overlay.

```mermaid
sequenceDiagram
    participant C as client
    participant R as relay
    participant K as coordinator
    Note over C,K: the failure that used to be permanent one-way traffic
    C--xK: control link lost
    K->>K: lease expires → client offline in the view
    Note over R: nothing evicts a live session from outside
    R->>K: heartbeat: I still hold {client}
    K->>R: view: client offline, attachment kept
    C->>R: data frames (sealed)
    R->>C: data frames (sealed)
    C->>K: control link back: Hello{have_gen}
    K->>C: deltas since have_gen
```

## What a member does when things go wrong

Four rules, each with a chaos test behind it:

1. **A valid member connects eventually.** As long as the coordinator is
   reachable, a member with a valid name and secret gets in: join and
   control-link retries are tight (1, 2, 4, 5, 5 … seconds, never longer),
   and a lost session is simply re-established — the view is kept, and the
   coordinator sends only what changed.
2. **Disable is a lever; only replacement ends a member.** A member the
   coordinator refuses — **disabled**, deleted, or holding a regenerated
   token — is thrown off at once and keeps asking to come back with
   exponential backoff (1, 2, 4, 8, 16, then every 30 s), one clear log
   line per attempt.
   Enable it again and it is back within the next retry, without anyone
   touching the machine. The one thing a member never retries is being
   **replaced** by a newer join under its own name: a re-join would win
   (last join wins, by design) and the two instances would take turns
   forever, so the process learns the reason, stops and exits with code
   `3`. A replacement that was not your doing means the token leaked — the
   coordinator records where the replacing join came from — so regenerate
   it. Relays tell stale instances the same on the data plane, so a client
   whose coordinator link is down still finds out from its relay.
   Supervisors should not restart exit code `3` blindly
   (`RestartPreventExitStatus=3`; see `configs/systemd/`).
3. **A preferred relay is a preference.** A client may name a relay; it
   attaches there whenever the relay is reachable, falls back to the
   lowest-RTT relay when it is not (or does not exist), and moves back on
   its own once the preferred relay answers again. Nothing ever waits for
   a relay that is not there.
4. **So is a preferred exit.** With `--route-all-via <name>`, internet
   traffic is sealed to that exit while it qualifies, to any other ready
   exit when it does not — keeping the machine's internet rather than the
   operator's preference — and back to the preferred one the moment it
   returns. The choice is recomputed from the view on every reconcile, so
   nothing is sticky and nothing needs a restart.

And one guarantee for the clients of a relay that was replaced from another
machine: the coordinator publishes the relay's new address and session
certificate; every client attached to the old process sees its fleet entry
change under it, drops the zombie even though it still answers, and
re-attaches to the fleet as published.

## Full-tunnel exit

A relay can also be the fleet's way out to the internet. That is a
**capability, not a prefix**: the operator sets `internet_gateway` on the
member and the coordinator grants that relay `0.0.0.0/0` and `::/0`
internally — typing a default route as a routed LAN is refused, with an
error pointing at the flag. Several exits coexist; ownership of a default
is never exclusive, so it is not an active/standby site prefix and is not
shown as one.

The grant alone does not make an exit. A designated relay self-checks its
egress — IP forwarding on, and a masquerade rule covering its uplink — and
reports the result to the coordinator on its own control message, so the
default is published **only while that exit reports ready**. A relay whose
host was never set up to NAT appears in the admin as an internet exit that
is *not* ready, with the missing half named, and no client is ever routed
through it. nqvpn never edits firewall rules or sysctls itself: it reports
and refuses, because that state has no owner to clean it up.

A client opts in with `--route-all` — or `--route-all-via <name>`, which
is the same thing plus a preferred exit, so the two are alternatives
rather than flags to combine. With no preference the exit is the relay the
client is **already attached to**, when that relay is one: internet
traffic then terminates on the node holding its only session and crosses
no mesh link, where any other exit costs a hop. Deliberately not by ping —
a probe measures the underlay path to an exit, not the path the traffic
takes, and RTT jitter would reshuffle a choice whose every change costs a
fresh end-to-end handshake.

Either way it takes OpenVPN's `def1`
approach — `0.0.0.0/1` + `128.0.0.0/1` (and `::/1` + `8000::/1`) laid
*over* the real default route rather than replacing it — and pins the
coordinator, every relay, and the system resolvers to the real gateway so
the tunnel's own path is never swallowed by the tunnel. A family's halves
are withheld unless it has both a pinned transport **and** a ready exit, so
route-all cannot blackhole a machine, and the pins follow the default
gateway if it moves.

Teardown is symmetric. A clean exit restores the routing table exactly as
it was; and because every tunnel route is bound to the TUN, a process
killed outright loses them all the moment the kernel destroys the device.
What survives is only host routes that duplicate the default route anyway.

```sh
nqvpn-client --token "nqv1.…" --route-all                  # nearest ready exit
nqvpn-client --token "nqv1.…" --route-all-via cloud-exit   # prefer this one
```

## What's in the box

| Crate | Owns |
|---|---|
| `nqvpn-proto` | wire format, Noise IK sealing (two-phase replay window), credentials, the shared `Snapshot`/`Delta`/digest logic, the HTTPS join client |
| `nqvpn-session` | "one task owns one connection": Hello, Refresh, probes, expiry |
| `nqvpn-sync` | member side of the generation protocol + the reconciler driver |
| `nqvpn-endpoint` | Noise engine, ingress filter, TUN, routes as a function of the view with local-LAN/underlay exclusion, route-all's catch-all and underlay pins |
| `nqvpn-relay` | one `RelayNet` per network (multi-tenant), the one-page forwarding rule, mesh dialers, hop guard, trace notes |
| `nqvpn-client` | ~500 lines of wiring |
| `nqvpn-coord` | networks and members in SQLite, join by token, leases, directory with generations and a delta ring, HTTPS API, embedded live admin UI |

Dependencies point strictly downward (`proto ← session ← sync/endpoint ←
relay/client`; `coord ← proto`), so each crate is reviewable on its own.
[`DESIGN.md`](DESIGN.md) is the full specification.

## Quick start

Nothing is configured on members. The coordinator holds every network and
member in its database; a machine gets one **token** and discovers
everything else — network, name, role, address, routed prefixes, relay
fleet, MTU — when it joins.

**1. Coordinator** — `configs/coordinator.toml` is the only file:

```toml
[listen]
api  = "0.0.0.0:8443"        # HTTPS: the UI at /ui, the API at /api/v1/*
quic = "0.0.0.0:14433"       # control plane; published to members at join
# public_url = "https://coord.example.com:8443"   # written into every token
[state]
dir = "/var/lib/nqvpn-coord" # nqvpn.db, signing key, self-signed certificate
[admin]
user = "admin"
password = "change-me"       # or password_hash = "$argon2id$…" from nqvpn-coord hash-password
```

```sh
nqvpn-coord run --config configs/coordinator.toml
```

**2. Open the UI** at `https://coord:8443/ui`, sign in, and follow the
wizard: *New network* (id, address space, defaults are fine) → *Add
member*. A relay gets an address to advertise (`auto:4444` means "wherever
it joins from"), optionally an overlay address and the LANs it routes; a
client optionally a preferred relay and a fixed address. Every member gets
a token and a ready-to-paste config.

**3. Members** hold the token and local facts only:

```toml
# /etc/nqvpn/relay.toml
listen = "0.0.0.0:4444"      # the port in the relay's address at the coordinator
[[networks]]
token = "nqv1.…"             # one entry per network this relay serves
```

```sh
nqvpn-client --token "nqv1.…"          # or token_file = "…" in /etc/nqvpn/client.toml
```

Change anything about a member in the UI — its address, the LAN it routes,
its preferred relay — and it is told to re-join; it applies the change in
place, without a restart. Regenerate a token and the old one stops
working immediately; whoever holds it is thrown off and stops.

The UI is a single embedded page (no external assets), responsive, and
pushed over a WebSocket: topology, traffic matrix, member state and prefix
ownership update as they happen. `Export` / `Import` move all
configuration as JSON for backup or version control.

## Testing philosophy

Correctness here means *convergence under failure*, so the test suite is
built around breaking things:

- **Unit**: every decision is a pure function with its own tests — the
  forwarding rule, `Snapshot::diff/apply/digest`, lease resolution, route
  exclusion, the replay window, crossed handshakes.
- **Crate level**: one connection's lifecycle (expiry, probe timeout,
  Refresh continuity); the generation protocol against a real coordinator
  (catch-up by deltas, snapshot on a gap, digest mismatch, restart grace);
  forwarding across real QUIC with a stubbed coordinator (spoofing, loops,
  eviction on the wire, trace notes).
- **Chaos** (`crates/nqvpn-client/tests/chaos.rs`): a real coordinator,
  real relays and many fake-TUN clients in one process — relay crashes,
  relay flapping, mesh links cut, clients and relays losing their
  coordinator link, coordinator restarts (and a coordinator that comes up
  late), a client or relay replaced from another machine (told by the
  coordinator, or by a relay when the coordinator link is down), disable,
  token regeneration, preferred-relay fallback and return, a byzantine
  relay that duplicates, corrupts and drops frames, a member reconfigured
  live from the coordinator (new address, a LAN added and withdrawn), a
  relay with an `auto:` address, an internet exit whose host stops
  masquerading (the catch-all is withheld until it reports ready, and a
  preferred exit lost mid-run is fallen back from and returned to), and a
  coordinator reloading everything from its database — each asserting that
  traffic converges without anyone restarting anything by hand, and that a
  kicked-out instance stops instead of fighting back.

```sh
cargo test                      # everything, ~2 minutes
cargo test -p nqvpn-client --test chaos -- --nocapture   # watch the chaos
```

## Building static Linux binaries

`build_all.sh` produces fully static `amd64` and `arm64` Linux binaries
(musl, no libc dependency — one artifact runs on any distro) from macOS
or Linux:

```sh
./build_all.sh --setup      # first time: installs zig + cargo-zigbuild into .build-tools/
./build_all.sh              # dist/linux-amd64/, dist/linux-arm64/, tarballs + sha256
./build_all.sh arm64        # one target
```

It uses `cargo zigbuild` when available, `cross` if that is on PATH, and
otherwise native musl toolchains on a Linux host (fetching a musl.cc
cross toolchain for the other architecture).

## Status

Linux and macOS clients and relays, including full-tunnel exit nodes
(`--route-all`). Windows is not implemented, and DNS is never touched: a
full-tunnel client keeps its own resolvers, which are pinned to the real
gateway rather than pushed or captured. Apache-2.0.
