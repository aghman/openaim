# Exploration: OpenAIM on ESP32 boards

**Status:** Exploration only. Not part of the [architecture design](design.md), and nothing here is planned work. · **Date:** 2026-11-21

> Could a version of the OpenAIM "server" run on an ESP32? If the full thing won't fit, could a simpler
> version run on one, working with more capable nodes elsewhere in the network?

**Short answer:** the full daemon won't run on an ESP32, and memory isn't the main reason: libp2p is. An ESP32 can still do useful
**mesh-side** jobs alongside full nodes that handle the IP side.

---

## 1. Framing: there is no single chat server

The design has no central chat server. Every user runs `openaimd` (design §3). The server-like roles are the optional
infrastructure ones:

- relay and bootstrap nodes (`openaimd --public`, §6.1)
- gateways (§7.3)
- mailboxes (§7.4)
- the handle registry (§5.3)

So the real question is which of those roles, or which parts of the client, an ESP32 can take.

---

## 2. Hardware in 2026

| Chip | Internal SRAM | PSRAM | Radio | Notes |
|------|---------------|-------|-------|-------|
| **ESP32-S3** | 512 KB | Commonly 8 MB (e.g. `N16R8` parts) | Wi-Fi 4, BLE | Inside many Meshtastic boards. Not all have PSRAM (Store & Forward names the T-Beam and T3-S3 as PSRAM boards). |
| **ESP32-P4** | 768 KB | 16 or 32 MB in package | **None.** Boards pair it with a separate chip for Wi-Fi. | The most memory, but no radio. |
| **ESP32-S31** | 512 KB | Up to 32 MB (16 MB modules listed) | Wi-Fi 6, BT 5.4 | Announced March 2026. Datasheets still preliminary. |
| *Comparison:* Raspberry Pi Zero 2 W | 512 MB RAM | — | Wi-Fi | Smallest common board that runs the real `openaimd` |

**Crypto speed is fine.** Ed25519 takes about 25 ms on an S3 at 240 MHz. X25519 takes about 16–21 ms on the C3/C6 at 160 MHz. A 200 B
frame takes about 2 s of LongFast airtime (§6.2), so the chip is never the bottleneck on mesh.

---

## 3. Why the full daemon won't fit

1. **libp2p is the blocker.** The whole IP side is go-libp2p:
   - DHT rendezvous
   - circuit relays and hole punching
   - GossipSub rooms
   - `/openaim/msg/1`, `/openaim/sync/1` and `/openaim/gw/1`

   No libp2p implementation runs on an ESP32. The nearest is `libcp2p`, an early-stage C project that is "libp2p-like" and doesn't
   have secure connections yet.
2. **Go doesn't come along.** TinyGo 0.41 (2026) added Wi-Fi on the ESP32-S3 and C3. But TinyGo can't build go-libp2p,
   reflection-based `google.golang.org/protobuf` (including the generated `internal/meshpb`), or `modernc.org/sqlite`. Any ESP32 code
   would be a second implementation, most likely in C++ inside Meshtastic firmware.
3. **Memory is a smaller problem.** The daemon's own data would fit in 8–32 MB of PSRAM:
   - the `conv_tag` table
   - the dedup window, which is "a few MB even for heavy users" (§8.9)
   - the buddy list

   Bigger chips don't get around problem 1.
4. **Handle verification needs DoH and HTTPS (§5.3).** This could be done with mbedTLS over Wi-Fi, but it only matters for an IP-capable
   node, and an IP-capable node runs into problem 1.

---

## 4. Role by role

| Role | ESP32? | Why |
|------|--------|-----|
| Full client daemon | **No** | Needs libp2p, DoH/HTTPS handle checks and SQLite |
| Relay / bootstrap / DHT node | **No** | These are libp2p roles by definition, and they hold many connections |
| Handle registry | **No** | Needs DNS publishing and a transparency log. There's no reason to put it on a microcontroller. |
| Gateway | **Only as the radio** | IP→mesh is small (check a token, then DM). Mesh→IP needs DHT lookups and libp2p dialing (§7.3). |
| Mailbox | **Yes, on the mesh side** | It stores ciphertext and checks HMAC tokens and signatures. It never decrypts. |
| Mesh-only client | **Yes, on a T-Deck-class board** | The mesh path needs no libp2p at all |

---

## 5. Three setups that work

### 5.0 ESP32 as the radio, full node elsewhere

**Works today with no new code.**

- Run stock Meshtastic on an ESP32 radio with Wi-Fi enabled.
- Point `openaimd` on a Pi, VPS or desktop at the radio over TCP port 4403. `internal/transport/mesh/conn.go` already supports this.
- **Gain:** placement. The radio can sit on a solar-powered rooftop or hilltop, and the full node does everything else.
- **Gateways:** this setup already covers them. The gateway runs on the full node and uses the remote radio.
- **Caveat:** Meshtastic's TCP API has no authentication, so anyone who can reach port 4403 can drive the radio. Keep it on the LAN or
  behind WireGuard or Tailscale.

### 5.1 A mesh "post office" (ESP32 with PSRAM)

An OpenAIM module on **one** Meshtastic router node stores frames for users who registered with it, and hands them back over the mesh
when they come online.

**What it does.** It never decrypts anything. It only:
- checks the deposit HMAC (§7.4)
- verifies the Ed25519 signature on a fetch challenge
- removes duplicates on `(conv_tag, msg_id, frag)`
- keeps 14 days of 200 B frames

**What it needs.**
- *Storage:* 8 MB of flash holds about 40,000 frames.
- *Precedent:* Meshtastic's own Store & Forward module requires an ESP32 with PSRAM. With its default setting it uses about two thirds
  of PSRAM, which is roughly 11,000 records.
- *Firmware:* only the post office runs custom firmware. Users' radios stay stock.
- *Registration:* the design already reuses the `FIRST_CONTACT` frame for mailbox registration (§8.5), so registering with the post
  office needs no new frame type.

**The real limit is airtime, not the chip.**
- A deposit plus a later fetch is two transmissions instead of one.
- At the EU 1% duty cycle (about 16 full frames an hour, §6.2), clearing 50 queued frames takes about 3 hours.
- So it fits only as the fallback after a failed DM. That's where §7.2 already puts mailboxes (step 4).

**Variant: passive catch.** For broadcast-path frames, you could give the post office your `conv_tag`s for each day, and it would store
matching frames it overhears. This costs no extra airtime. The trade-off is the one gateways already make (§7.3): the post office
learns which tags are yours.

This doesn't work for the DM path. Meshtastic PKC encrypts DMs to the destination radio, so a third node can't see the OpenAIM frame
inside.

### 5.2 A mesh-only handheld (T-Deck Plus class)

**The hardware.** The LilyGO T-Deck Plus has an ESP32-S3 (`FN16R8`: 16 MB flash, 8 MB PSRAM), an SX1262 LoRa radio, a QWERTY keyboard,
a 320×240 screen and GPS.

**What fits easily:**
- the frame layer
- pairwise keys
- presence beacons
- IMs and acks
- buddy accept
- first contact, including trial decryption, which costs one X25519 operation per frame (about 20 ms)
- mesh rooms (up to 16 members)

**What it gains and lacks.**
- The GPS provides time source #2 from §8.9.
- With no DoH, every contact stays "unverified" until you compare safety numbers. §5.3 already allows this for contacts first met on the
  mesh.
- It fits the retro feel: a pocket AIM device on LoRa.

**What pushes it later:**
1. **One device per identity in v1** (§1 non-goals, §5.6). A handheld would be your only device or a separate screen name. It fits
   better after multi-device (wire v2).
2. **A second implementation of the crypto protocol**, in C++ inside Meshtastic firmware. It would have to pass the same golden vectors
   and fuzzers (§13) and be covered by the external crypto review (§10.4).

---

## 6. The pattern: anchors plus satellites

This is the "simpler version working with more capable nodes":

- **Anchors** are full `openaimd` nodes (Pi, VPS, desktop). They speak libp2p and do handle verification, DHT rendezvous and gateway
  routing.
- **Satellites** are ESP32 nodes. They do mesh-side work (store, catch, carry) and pass frames along.

Two existing design choices make satellites cheap:

- **Frames are byte-identical on every transport** (§8.1).
- **Frames are sealed once** (§8.2). A satellite never re-encrypts, re-fragments or re-encodes.

So a satellite is a byte mover that checks tokens. It usually never holds pairwise keys and never sees plaintext.

---

## 7. Small choices that keep this possible

None of these commit the main design to ESP32 support. They make it cheaper to add later:

1. **Extend the golden vectors (§13).** Cover mailbox deposits, fetch authentication and token derivation, not only frames. A second
   implementation would test against these.
2. **Keep mailbox messages independent of the transport.** Define the deposit and fetch messages (§7.4) separately from libp2p stream
   framing, so they can also be sent as a mesh DM.
3. **Let `REACH` mailbox hints point to a mesh node** (§7.1), not only an IP contact.

---

## 8. Open questions

| # | Question |
|---|----------|
| E1 | Post office as an upstream Meshtastic module or as a fork? Upstreaming would need an official PortNum first (design Q8). |
| E2 | Is the passive-catch variant (§5.1) worth the tag-linkability trade-off, or should the post office accept explicit deposits only? |
| E3 | Should the mesh fetch protocol send queued frames in batches that respect the airtime governor's priority order (§6.2), with IMs before presence? |
| E4 | Should the handheld wait for multi-device (wire v2), or ship earlier as "a separate screen name"? |

**If we prototype one, start with the post office (§5.1).**
- It's the smallest amount of code.
- It never touches plaintext.
- Store & Forward already shows the memory side works.

---

## Sources

- ESP32-P4 vs ESP32-S3 memory: [Elecrow comparison](https://www.elecrow.com/blog/who-is-the-true-performance-king-esp32-p4-vs-esp32-s3.html)
- ESP32-S31: [Espressif release](https://www.espressif.com/news/ESP32_S31_Release), [preliminary datasheet](https://documentation.espressif.com/esp32-s31_datasheet_en.pdf)
- TinyGo Wi-Fi on ESP32-S3/C3: [TinyGo 0.41 release notes](https://tinygo.org/blog/2026/tinygo-0-41-the-big-release/)
- libp2p implementations: [libp2p/libp2p](https://www.github.com/libp2p/libp2p), [libcp2p](https://awesome.ecosyste.ms/projects/github.com%2Frtradeltd%2Flibcp2p)
- Meshtastic Store & Forward: [module settings](https://meshtastic.org/docs/configuration/module/store-and-forward-module/)
- T-Deck: [Meshtastic docs](https://meshtastic.org/docs/hardware/devices/lilygo/tdeck), [CNX Software on the T-Deck Plus](https://cnx-software.com/?p=136193)
- Crypto benchmarks: [ESP32-S3](https://oryx-embedded.com/benchmark/espressif/crypto-esp32-s3.html), [ESP32-C6](https://oryx-embedded.com/benchmark/espressif/crypto-esp32-c6.html)
