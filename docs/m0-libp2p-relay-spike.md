# M0 spike: libp2p peers through a relay

This is the second M0 spike from [design.md §14](design.md#14-milestones). Two peers behind NATs talk over
`/openaim/msg/1` through a circuit relay v2. The spike measures what §6.1 assumes:

- how often relayed connections reset, and how fast they recover, under go-libp2p's default limits and under our raised limits
- how often DCUtR hole punching succeeds on real home networks

## What's here

| Path | What it is |
|------|-----------|
| `internal/transport/ip/frames.go` | `/openaim/msg/1` framing: 16-bit big-endian length + frame bytes, max 65 535 B. Fuzzed. |
| `internal/transport/ip/host.go` | Host construction (fresh Ed25519 key per run, TCP + QUIC on IPv4/IPv6, optional DCUtR and UPnP), circuit addresses, path description, a relay-only connection gater. |
| `internal/transport/ip/relay.go` | Relay service with limit profiles (`libp2p` 2 min / 128 KiB, `openaim` 1 h / 16 MiB, or none) and a reservation keeper that refreshes and recovers from relay disconnects. |
| `cmd/p2pspike` | The measurement tool: `relay`, `listen`, `dial`. go-libp2p **v0.52.0**. |

```bash
go build -o bin/ ./cmd/...
```

**Try it on one machine:**

```bash
./bin/p2pspike relay --port 14001 --limits libp2p --limit-duration 6s &
./bin/p2pspike listen --relay /ip4/127.0.0.1/tcp/14001/p2p/<relay ID>    # prints the dial command
./bin/p2pspike dial --to <circuit addr> --interval 1s --duration 20s --relay-only
```

## How the tools work

- **`relay`:**
  - Runs a circuit relay v2 with a persistent key (`--key relay.key`), so its address survives restarts.
  - It doesn't wait for AutoNAT before relaying.
  - Logs every reservation, opened or closed circuit (with how long it lasted), and refused request.
  - Prints a status line every minute.
  - Picks a limit profile with `--limits`; override it with `--limit-duration` / `--limit-data`.
- **`listen`:**
  - Reserves a slot on the relay and keeps it: refreshes at ¾ of the TTL, and re-reserves at once if the relay connection drops.
  - Prints the circuit address to dial.
  - Echoes every `/openaim/msg/1` frame byte for byte.
  - Logs its reachability and NAT type as libp2p works them out. A symmetric NAT explains a failed hole punch.
- **`dial`:**
  - Connects through the relay, then pings every `--interval` with `--size`-byte frames (200 B is the canonical mesh frame).
  - Logs each RTT and the path it took: `relay (limited)`, `relay`, `direct/tcp` or `direct/quic-v1`.
  - When a stream dies, records how old it was and how much it carried, then reconnects with backoff and records the downtime. It notices the connection-closed event at once, the way the daemon should, rather than waiting for the next ping to fail.
  - When DCUtR produces a direct connection, opens a new stream on it and closes the relayed one.
  - `--bulk 256KiB` pushes data through every new stream first, to hit the relay's data limit.
  - `--relay-only` refuses direct connections to the listener.

All three take `--jsonl FILE` for raw records. `dial` prints a summary at the end.

## What the local runs already show

These come from the in-process tests and loopback runs. They are libp2p behaviours, not network measurements.

1. **Limits apply per relayed connection, in each direction, whatever protocol is inside.**
   - The relay can't see protocols inside the encrypted circuit, so it can't give OpenAIM traffic special limits.
   - A raised limit applies to everyone the relay serves. To keep a relay for OpenAIM only, gate its *reservations* instead (an ACL, or delivery tokens later).
   - Design §6.1 has been corrected to match.
2. **A relay with no limits produces connections that are not marked limited.**
   - With any limit, connections are marked *limited*. `NewStream` on a limited connection then needs `network.WithAllowLimitedConn`.
   - Without it, `NewStream` waits for a direct connection and fails if none appears. That wait is how a stream picks up a DCUtR upgrade.
   - The design's "presence and message protocols explicitly allow limited connections" is needed only when the relay sets limits.
3. **A duration-limit reset closes the whole relayed connection and every stream on it.**
   - Reconnecting through the relay took 6–11 ms on loopback.
   - The daemon should react to the connection-closed event rather than wait for its next send to fail. `dial` does this.
4. **The data limit counts what the relay forwards.**
   - With 16 × 4 KiB frames in flight, a 64 KiB limit reset the stream after 32–36 KiB had been echoed. The outbound direction reached the limit first.
5. **A reconnect after a reset can come back direct even with hole punching off.**
   - The dialer has learned the listener's own addresses from identify, and the swarm dials all known addresses.
   - On a LAN or with IPv6, many "relayed" sessions will quietly become direct. `--relay-only` exists so the relay can be measured anyway.
6. **DCUtR needs a public address on both sides.**
   - The hole-punch service waits until the host has one. A single observation from the relay's identify is enough, so a lone relay can drive it.
   - Hole punching can't be exercised on loopback or one LAN.
7. **Reservations are capped at 8 per IP and 32 per ASN by default.**
   - Behind carrier-grade NAT, many users share one IP, so a busy community relay will need higher caps. Watch for `reserve RESOURCE_LIMIT_EXCEEDED` in the relay log.

## Setting up the real runs

- **Relay:**
  - Any small VPS with a public IPv4 address (IPv6 too if possible).
  - Open TCP **and** UDP on the relay port (default 4001).
  - Run `p2pspike relay --jsonl relay.jsonl` and give the peers its `public` address.
- **Peers:**
  - Two machines on **different** home networks, ideally different ISPs. Note each router's make and model, and whether the network has IPv6.
  - A phone hotspot makes a good third network, since mobile carriers usually use symmetric carrier-grade NAT.
  - Don't enable `--upnp` unless the experiment calls for it. It hides the NAT behaviour being measured.
- **Fresh keys:** each run starts with fresh keys (the design rotates them), so hole-punch attempts are independent. Copy the new circuit address each time.

## Experiments

L is the listener at home 1, D is the dialer at home 2, and R is the relay on the VPS.

| # | Question (design ref) | Relay | Listener / dialer | Record |
|---|----------------------|-------|-------------------|--------|
| R1 | Reset rate with go-libp2p defaults (§6.1) | `--limits libp2p` | `dial --relay-only --duration 10m` | Resets per 10 min (expect ~5) and the downtime for each. Does each recover well inside the 3-minute "door close" grace? |
| R2 | Data limit with defaults | `--limits libp2p` | `dial --relay-only --bulk 256KiB --duration 2m` | Bytes sent before reset (expect ≤ 128 KiB) |
| R3 | Our raised limits | `--limits openaim` | `dial --relay-only --duration 70m --interval 30s` | Resets before 1 h (expect none), the reset at 1 h, and the reservation refresh in L's log |
| R4 | No limits | `--limits none` | `dial --relay-only --duration 10m` | Path shows `relay`, not `relay (limited)`. No resets. |
| R5 | Hole-punch success on home networks (§6.1, ~70% assumed) | `--limits openaim` | L: `listen`; D: `dial --duration 2m`. Repeat 10× with fresh keys | Success/fail, time to direct, TCP or QUIC, NAT types from L's log, IPv4 or IPv6 |
| R6 | Hole punch with a symmetric NAT | as R5 | Put D on a phone hotspot | Success rate. Expect failures, so traffic stays relayed. |
| R7 | Relay restart | any | L: `listen`; restart R | Time until L logs `reservation (relay disconnected) ok`, and whether D's next reconnect works |
| R8 | Relay RTT cost | `--limits openaim` | R5 runs that succeed | RTT over relay vs. direct, from D's summary |
| R9 | Same LAN, no special mode (§6.1 LAN) | any | L and D on one LAN, no flags | How soon the session goes direct without hole punching (finding 5) |

## Results

Fill these in as you run the experiments. §6.1's reset interval, the 3-minute grace period and the `openaim` limit profile get revised from them.

| # | Date | Networks (ISP / router / IPv6) | Result | Notes |
|---|------|--------------------------------|--------|-------|
| R1 | | | | |
| R2 | | | | |
| R3 | | | | |
| R4 | | | | |
| R5 | | | | |
| R6 | | | | |
| R7 | | | | |
| R8 | | | | |
| R9 | | | | |

## Limitations of this spike

- No DHT or rendezvous yet. The circuit address is copied by hand, and peer IDs change every run unless you pass `--key`.
- No AutoRelay: the listener reserves on one relay you name. The daemon will need several relays and failover.
- Downtime runs from the moment `dial` notices the loss to a working stream. That's usually the close event. A loss that only a ping or bulk transfer reveals is noticed late, by up to one `--interval`.
- The `openaim` limit profile (1 h / 16 MiB) is a first guess. R1–R3 decide it.
- No relay-side ACL. Anyone who finds a spike relay can use it, so don't leave one running unattended.
