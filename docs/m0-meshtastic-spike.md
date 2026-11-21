# M0 spike: Meshtastic from Go

This is the first M0 spike from [design.md §14](design.md#14-milestones). It talks to a Meshtastic radio from Go
over USB serial or TCP on a private PortNum, and measures the numbers the design currently assumes
(§6.2 constraints, §8.8 ack strategy).

## What's here

| Path | What it is |
|------|-----------|
| `internal/transport/mesh/stream.go` | Client-API framing: `0x94 0xC3` + 16-bit length + protobuf. Resyncs on noise and surfaces firmware log text. Fuzzed. |
| `internal/transport/mesh/client.go` | Session with the `want_config` handshake, config snapshot, send with queue-status and routing-ack tracking, and heartbeat. |
| `internal/transport/mesh/conn.go` | Serial (115200 8N1 plus a wake sequence) and TCP (port 4403) connections. |
| `internal/transport/mesh/meshtest` | In-memory fake radio for tests. It does the handshake, sends QueueStatus, and answers with acks, NAKs and TOO_LARGE. |
| `internal/meshpb` | Go code generated from `meshtastic/protobufs` **v2.8.3** (submodule in `third_party/`). Regenerate with `scripts/gen-meshpb.sh`. |
| `cmd/meshspike` | The measurement tool. |
| `cmd/fakeradio` | Serves the fake radio over TCP, so you can try `meshspike` without hardware. |

```bash
go build -o bin/ ./cmd/...
```

**Try it without a radio:**

```bash
./bin/fakeradio &
./bin/meshspike info --tcp 127.0.0.1:14403 --nodes
```

## Before transmitting

- **Use a private test channel.** Test traffic on the default LongFast channel goes over everyone's mesh.
  Make a secondary channel with a random key on both radios, using the Meshtastic app, and pass `--channel N`.
  `meshspike` doesn't change radio config.
- **Check `meshspike info` first.** It warns about:
  - licensed (ham) mode
  - TX disabled or region unset
  - MQTT-uplinked channels
  - relay-blocking rebroadcast modes
- **Keep runs small.** `send` enforces at least 5 s between packets and at most 100 packets. A 200 B LongFast frame is about 2 s of airtime before relays, and EU868 duty-cycle limits can be as low as 1%.

## Experiments

You need two radios, **A** and **B**, on firmware 2.6 or later (2.8.x matches the pinned protobufs). Run
`listen --echo` on B, on its own machine or a second USB port, and the commands below on A. Add `--jsonl
run.jsonl` to any command to keep raw records.

| # | Question (design ref) | Command on A | Record |
|---|----------------------|--------------|--------|
| E1 | Radio facts and blockers (§6.2) | `meshspike info --nodes` | Firmware, preset, rebroadcast mode, whether B's public key is known |
| E2 | Max payload, broadcast path (§6.2, §8.1) | `meshspike probe-size --to broadcast --channel N` | Largest accepted size |
| E3 | Max payload, PKC DM path | `meshspike probe-size --to !<B> --channel N` (B's public key known) | Largest accepted size. Expect about 12 B less than E2. |
| E4 | Max payload with channel AEAD on (2.8.1+) | Repeat E2 with `use_aead` enabled on the test channel | Difference from E2 |
| E5 | DM `want_ack` semantics and timing (§8.8) | `meshspike send --to !<B> --size 200 --count 10 --want-ack --expect-echo --channel N` | `dest-ack` latency distribution, NAKs, echo RTT |
| E6 | Broadcast `want_ack` (§8.8) | `meshspike send --to broadcast --size 200 --count 5 --want-ack --channel N` | Whether acks are `implicit-ack` (a neighbour's rebroadcast was overheard) or nothing when no neighbour is in range |
| E7 | Unreachable DM | Power B off, then repeat E5 with `--count 3` | Time to `MAX_RETRANSMIT` NAK, i.e. how long the firmware keeps retrying |
| E8 | Relaying through restrictive nodes (§6.2) | Put a third radio C between A and B in `CORE_PORTNUMS_ONLY`, then `LOCAL_ONLY`; repeat E5 | Delivered or not, per mode |
| E9 | Distance and hops | Repeat E5 at 1, 2 and 3 hops | Hops, SNR and latency from the `rx` and `tx` lines |

## Results

Fill these in as you run the experiments. The design's canonical frame size (200 B) and ack timeouts get revised from them.

| # | Date | Firmware / preset | Result | Notes |
|---|------|-------------------|--------|-------|
| E1 | | | | |
| E2 | | | | |
| E3 | | | | |
| E4 | | | | |
| E5 | | | | |
| E6 | | | | |
| E7 | | | | |
| E8 | | | | |
| E9 | | | | |

## Limitations of this spike

- No BLE yet. Serial and TCP only.
- It reads config but never writes it, so no admin messages. Set channels with the Meshtastic app.
- `listen --echo` replies only to direct test DMs, at most one every 5 s, never to broadcasts.
- `probe-size` sends without `want_ack`, so each accepted probe goes on air exactly once. It assumes acceptance is monotone in size.
- The fake radio's limits (233 B broadcast, 221 B DM) are this doc's *assumptions*, not measurements. E2–E4 replace them.
