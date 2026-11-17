# OpenAIM — Architecture Design (Draft v0.3)

**Status:** Draft v0.3. Revised after the adversarial review; Appendix A maps each finding to its fix. · **Date:** 2026-11-17 · **Author:** Austin Hill

> An instant messenger with the feel of AOL Instant Messenger: a buddy list, presence,
> away messages, one-to-one IMs and chat rooms. It runs without a central service, works
> over ordinary IP networks and over Meshtastic LoRa radios, and has both a terminal (TUI/CLI)
> and a graphical frontend.

**Decisions so far:**
- Go.
- Community-run relay and bootstrap nodes are acceptable.
- Screen names are Bluesky-style DNS handles.
- Ordinary license-free Meshtastic only; no ham operation.

---

## 1. Goals and non-goals

### Goals

| # | Goal | What it means in practice |
|---|------|---------------------------|
| G1 | **AIM-style experience** | Buddy list with groups, online/away/idle presence, away messages, profiles, IM windows, chat rooms, "door open/close" sounds, typing indicators where bandwidth allows. |
| G2 | **Decentralized** | No company-run server is required. Identity is a keypair you own. Any user can run infrastructure (relay, mailbox, gateway, handle registry), and nodes on a LAN or mesh can talk with no internet at all. |
| G3 | **Multi-transport** | The same conversation works over IP (internet or LAN) and Meshtastic. A buddy is addressed by identity, not by transport, and the app chooses the route. |
| G4 | **Mesh-respectful** | LoRa airtime is scarce and shared. Typical IMs fit in one Meshtastic packet. Presence costs one frame per state change, not one per buddy. No layer duplicates another's retries. |
| G5 | **GUI and TUI** | Full-featured terminal client and a desktop GUI, both on top of the same core. Scriptable CLI commands (`openaim send ...`). |
| G6 | **End-to-end encrypted and metadata-minimizing** | Relays, gateways, mailboxes and mesh routers carry ciphertext they can't read. Frames on the wire carry no long-term identifiers. Only accepted buddies can see when you're online. |

### Non-goals (for v1)

- Globally unique screen names with *no* authority at all. DNS is the namespace (§5.3).
- Licensed amateur radio (ham) operation, which forbids encryption (§10.5).
- Multiple devices per identity (room is left for it, §5.6).
- Forward secrecy (planned; §10.3).
- Voice/video, large file transfer over mesh, mobile apps.
- Interop with the real AIM/OSCAR protocol.

---

## 2. Prior art (and why this still makes sense)

| Project | Overlap | Gap vs. our goals |
|---------|---------|-------------------|
| **Reticulum + LXMF** (Sideband, NomadNet, MeshChat) | Very close: crypto networking stack over LoRa, TCP, UDP, I2P; store-and-forward messaging. | Uses its own RNode LoRa stack, not Meshtastic radios/firmware; Python; no AIM-style UX. |
| **Meshtastic apps** | Native mesh text chat. | Mesh-only; no IP federation, buddy-list presence or AIM UX. |
| **Briar, Berty** | P2P, offline-capable messaging. | Mobile-first; no LoRa. |
| **Nostr, Matrix** | Decentralized/federated chat over IP. | JSON-heavy, too big for LoRa packets; relay/homeserver-centric. |
| **Bluesky (AT Protocol)** | Handles as DNS names over permanent identities. | We copy its naming model (§5.3), not its data model. |
| **Noise Protocol Framework** | Handshake patterns. | We use the one-way `X` pattern for first contact (§8.5). |
| **libp2p** | P2P transport, NAT traversal, DHT, pubsub. | A building block; we use it for IP (§6.1). |

**Open question Q5:** we could build on Reticulum instead. This doc assumes a
purpose-built protocol because (a) the target hardware is Meshtastic radios people already
own, (b) the project is in Go, and (c) the AIM-style presence model shapes the protocol.

---

## 3. High-level architecture

```
 ┌────────────────────┐   ┌────────────────────┐   ┌──────────────────────┐
 │  GUI (Wails app)   │   │  TUI (Bubble Tea)  │   │ CLI (openaim send …) │
 └─────────┬──────────┘   └─────────┬──────────┘   └──────────┬───────────┘
           │        local client API (gRPC over Unix socket / named pipe)
           └──────────────────────────┬────────────────────────┘
                                      │
 ┌────────────────────────────────────┴─────────────────────────────────────┐
 │                         openaimd  (core daemon)                          │
 │                                                                          │
 │  ┌───────────┐ ┌────────────┐ ┌──────────────┐ ┌─────────────────────┐   │
 │  │ Identity, │ │ Buddy list │ │ Conversations│ │ Presence & profiles │   │
 │  │ keys,     │ │ & handle   │ │ & rooms      │ │ (away msgs, idle)   │   │
 │  │ backup    │ │ verifier   │ │              │ │                     │   │
 │  └───────────┘ └────────────┘ └──────────────┘ └─────────────────────┘   │
 │  ┌────────────────────────────────────────────────────────────────────┐  │
 │  │ Frame layer: seal once → canonical fragments → persist → resend    │  │
 │  │              verify-before-state, dedup, replay window, acks       │  │
 │  └────────────────────────────────────────────────────────────────────┘  │
 │  ┌────────────────────────────────────────────────────────────────────┐  │
 │  │ Router: per-buddy authenticated reachability → route choice        │  │
 │  │         airtime governor · gateway/mailbox clients                 │  │
 │  └───────┬──────────────────────┬──────────────────────────┬──────────┘  │
 │  ┌───────┴────────┐   ┌─────────┴──────────┐   ┌───────────┴──────────┐  │
 │  │ IP transport   │   │ LAN discovery      │   │ Meshtastic transport │  │
 │  │ (go-libp2p,    │   │ (mDNS, opt-in)     │   │ serial / TCP / BLE   │  │
 │  │ rotating IDs)  │   │                    │   │                      │  │
 │  └───────┬────────┘   └─────────┬──────────┘   └───────────┬──────────┘  │
 │          │   SQLite store · metrics (local only)            │            │
 └──────────┼──────────────────────┼──────────────────────────┼─────────────┘
            │                      │                          │
       Internet / relays      Local network          Meshtastic radio ⇄ LoRa mesh
```

### Why a daemon plus thin clients

- **Presence works like AIM:** you stay "online" (or "away") while the GUI is closed. The daemon keeps delivering, queuing and acking.
- **One owner per radio:** a Meshtastic radio's serial/BLE link supports one client at a time. The daemon owns it, and the GUI, TUI and CLI share it.
- **Same behavior everywhere:** every frontend is a client of the same API, so the TUI and GUI can't drift apart.
- **Headless nodes:** a Raspberry Pi with a radio runs `openaimd` alone as a gateway or mailbox (§7).

For convenience, `openaim tui` starts an in-process daemon if none is running.

---

## 4. Technology choices

| Concern | Choice | Notes / alternatives |
|---------|--------|----------------------|
| Language | **Go** (decided) | One static binary per platform; cross-compiles to Raspberry Pi. |
| IP networking | **go-libp2p** | QUIC + TCP, Noise/TLS, hole punching (DCUtR), circuit relay v2, Kademlia DHT, GossipSub. |
| Meshtastic | **Own thin client** over the official `meshtastic/protobufs` (generated with `buf`) | Serial and TCP (port 4403) framing: `0x94 0xC3` + 16-bit length + `ToRadio`/`FromRadio`. BLE comes later via `tinygo.org/x/bluetooth`. |
| Wire encoding | Fixed binary layout for frames (§8). **Protocol Buffers** inside the ciphertext and for IP control messages. | Other languages can implement clients from the spec and golden vectors. |
| Crypto | Go stdlib `crypto/ed25519`, `crypto/hkdf`, `crypto/hmac`, `crypto/sha256`; `golang.org/x/crypto` (`curve25519`, `chacha20poly1305`, `argon2`); `filippo.io/edwards25519` for the Ed25519→X25519 conversion | No custom primitives. |
| DNS | DNS-over-HTTPS (RFC 8484) client built on `golang.org/x/net/dns/dnsmessage` | Handle checks never use the system resolver (§5.3). |
| Storage | SQLite via `modernc.org/sqlite` | Pure Go, no cgo. |
| Local API | gRPC over Unix socket (Windows: named pipe) | Server-streaming `Events()` for live updates. |
| TUI | **Bubble Tea + Lip Gloss + Bubbles** | |
| GUI | **Wails** | Easiest route to a convincing retro look. Fyne is the pure-Go alternative. |
| Config | TOML at `$XDG_CONFIG_HOME/openaim/config.toml` | |

---

## 5. Identity, keys, handles and buddies

### 5.1 Keys and what each is for

| Key | Lifetime | Used for | Ever on the wire in the clear? |
|-----|----------|----------|-------------------------------|
| **Identity key** (Ed25519) | Long-term | Your account. Signs *public* artifacts only (handle claim, Nearby advert). Its X25519 form (§5.2) does the static Diffie-Hellman exchanges. | Only in your public handle record and opt-in Nearby adverts, never in message frames |
| **Recovery key** (Ed25519) | Long-term, kept offline | Signs a key-rotation statement (§5.5) | No |
| **Network key** (libp2p host key, Ed25519) | **Random, rotated** daily and on every restart | libp2p peer ID, Noise transport handshakes | Yes, but it isn't linked to your identity |
| **Pairwise keys** (derived) | Per buddy pair | Message encryption, conversation tags, rendezvous lookup keys, delivery tokens | No |
| **Presence key** (symmetric) | Rotated when a buddy is removed | Encrypts your mesh presence beacon for *all* buddies at once | No |
| **Room keys** (symmetric, numbered by epoch) | Per room, rotated on membership change | Room messages | No |

**One identity key for both signing and Diffie-Hellman.** The identity key is converted to X25519 (the standard birational map, as in
libsodium), and that form does the static Diffie-Hellman exchanges. Using one key pair for both jobs has been analyzed and is considered sound when every
use is domain-separated (§10.2). We chose this over a separate X25519 key with a signed certificate because the certificate's 64-byte signature
wouldn't fit in a one-frame mesh first-contact message (§8.5). Because two Ed25519 keys can map to the same X25519 key, every key derivation binds the
**Ed25519** public keys, never only the X25519 ones.

**Why the network key is separate:** if your identity key were your libp2p peer ID, anyone who knows your
public handle could look you up in the DHT and learn your IP address and when you're online without being your buddy.
With rotating, unlinkable network keys, only buddies can find you (§6.1).

### 5.2 Identifiers shown to people

- **Safety number** (for out-of-band verification): 128+ bits from `SHA-256(domain ‖ sorted(Ed_A, Ed_B))`, shown as 8 groups of 5 digits and as a QR code. Compare in person, or scan a QR code, to verify.
- **Key ID** (UI only): a short base32 prefix of `SHA-256(identity key)`, such as `~k3f9`. It tells apart buddies with the same name. It isn't a security check and never appears in frames.

### 5.3 Screen names: Bluesky-style DNS handles

The model follows Bluesky:

- **Two layers:** the permanent identity is the identity key. The changeable **handle** is a DNS name.
- **Two-way verification:** the domain points to the key, and the key's signature claims the handle.
- **Default registries:** most people take a free subdomain from a default provider (`skaterdude99.<registry-domain>`), first come, first served. People who own a domain can use it.

**The handle record.** One self-contained DNS TXT record holds both proofs:

```
_openaim.skaterdude99.<registry-domain>.  TXT  "v=oa1; k=<b32 identity key>; t=<issued unix>; i=<inbox hint>; s=<b64 sig>"
```

`s` is an Ed25519 signature over `"openaim/v1/handle-claim" ‖ handle ‖ k ‖ t ‖ i`. Without the inbox hint the record is about 175 characters.
A long inbox hint (a multiaddr) pushes it past the 255-character limit of a single TXT string, so the record spans several strings, which DNS allows.
Clients concatenate the strings before parsing. As an alternative, `https://<handle>/.well-known/openaim` serves the same record. That suits people
whose DNS host makes TXT records awkward.

**Verification rules:**

1. **No system resolver.** DNS lookups go over **DNS-over-HTTPS** to configured resolvers (two independent defaults; they must agree). DNSSEC-validated answers are also accepted. This defeats on-path spoofing on untrusted Wi-Fi.
2. **Safe HTTPS fetches.** HTTPS proofs need a valid WebPKI certificate, follow no redirects, refuse private, loopback and link-local addresses (SSRF guard), and are capped in size and time.
3. **Strict syntax.** Handles are lowercase LDH only (`[a-z0-9-]` labels, standard length limits). `xn--` (punycode) labels are rejected in v1 to prevent look-alike names.
4. **Pin on add.** The buddy *is* the key, and the handle is a label on it.
5. **Re-check monthly** (with jitter) via DoH. Using DoH means the domain owner doesn't learn your IP from re-checks; only the DoH resolver sees the query. If a re-check finds a **different key**, the client **never swaps the pinned key**. It marks the handle "⚠ moved/unverified" and alerts you. A legitimate change of key arrives as a signed rotation (§5.5).
6. **Short display.** Handles on *your configured* default registry show as just the screen name (`SkaterDude99`). The buddy info panel always shows the full handle.

**On the mesh** there's no DNS. Mesh frames carry no names at all (§8). Buddies show under their pinned, already-verified handle.
A contact first met on the mesh, through a Nearby advert or a first-contact message, is labeled **"unverified"** in a distinct style: italic, a ⚠ badge and the key ID always visible.
It stays that way until *you* verify it by checking the handle over IP yourself or by scanning a safety-number QR. We never rely on someone else's word.

**The registry service** is small and anyone can run one:

- **Sign-up:** prove you hold the key by signing a challenge. The registry then publishes your TXT record. Proof-of-work and IP rate limits make bulk squatting expensive, and common names are reserved.
- **Key changes:** the registry repoints a handle **only** on a request signed by the current identity key or the recovery key. There is no "contact support" path that silently moves a handle.
- **Transparency:** every create, rotate and delete goes into a public, append-only, signed **transparency log**, so a takeover is detectable.
- **Expiry and reclaim:** a handle lapses after 12 months without a signed keep-alive (the daemon sends one automatically), plus a 90-day notice. A lapsed name can be reclaimed. Clients' key pinning means a reclaimed name can't impersonate the old owner to existing buddies.
- **Policy:** a written abuse and dispute policy is required before the default registry launches (Q3).

**Inherent limit (same as Bluesky):** if someone lets their own domain expire and a stranger buys it, the stranger owns that handle for *new* adds.
Existing buddies are protected by pinning and see the "moved" warning.

**Rejected alternatives:**
- First-come names in the DHT (squattable and impossible to reclaim).
- Blockchain name systems (heavy, and they cost money).
- Pure petnames (confusing for the "what's your screen name?" moment).

### 5.4 Adding buddies and first contact

- **Invite link / QR:** `openaim:add/<b32 identity key>?h=<handle>&c=<contact hint>`. The contact hint is a relay-circuit address or mailbox address, *never* a direct home IP. Scanning a QR in person also verifies the safety number.
- **By handle:** resolve the handle (§5.3) to the key and inbox hint, then send a first-contact message (§8.5) to the inbox.
- **Nearby:** opt-in Nearby adverts on LAN (mDNS) and mesh (§8.6) list strangers you can add. They're **off by default** because they announce your presence to everyone in range.
- **Approval required:** like AIM's authorization feature, nothing about your presence is shared until you accept. **Accepting** sets up a buddy relationship:
  - It derives the pairwise keys.
  - It sends your presence key and current reachability (§7.1), encrypted.
  - It issues the buddy a **delivery token** for your gateways and mailboxes (§7.3, §7.4).
- **First-contact limits:** unaccepted requests are never auto-answered on mesh. They're rate-limited per transport, and through gateways or mailboxes they need proof-of-work (§7.5).
- **Buddy list:** groups ("Buddies", "Family", "Co-Workers"), local petnames, per-buddy settings. It's stored locally and exportable as an encrypted file.
- **Removing a buddy** rotates your presence key and re-sends it to the remaining buddies. It also revokes the removed buddy's delivery tokens.

### 5.5 Backup, recovery and key rotation (in v1)

- **Backup:** at setup the daemon shows a 24-word **recovery phrase** that encodes the identity seed, and it offers an encrypted backup file (Argon2id + XChaCha20-Poly1305). The file holds the identity seed, the recovery key, the buddy list and pinned keys. Day to day, the private key lives in the OS keychain, or in a passphrase-encrypted file.
- **Recovery key:** generated at setup and stored *only* in the backup (separate from the device). Its public key is in the profile from day one.
- **Rotation statement:** after a compromise or loss, you sign `"openaim/v1/rotate" ‖ old_key ‖ new_key ‖ t` with the recovery key. The statement goes to buddies and to the handle registry or your domain. Buddies accept it only if it's signed by the recovery key they pinned when they added you.
- **Queued messages after rotation:**
  - Unsent plaintext in your queue is sealed again under the new pairwise key, with **new** message IDs. Old frames are discarded, and frames are never re-encrypted under an old message ID (§8.2).
  - Mail at mailboxes and gateways under the old key stays readable, because the client keeps the old key for decryption only, for 30 days.
  - Senders are told to re-send anything still unacked.

### 5.6 Room for multiple devices (not in v1)

Multi-device needs new frame kinds and a device-certificate scheme. It will come as wire version 2
rather than a reserved field nobody budgets for. On mesh, fan-out will target only the device most recently heard there.

---

## 6. Transports

All transports implement one interface:

```go
type Transport interface {
    Name() string                      // "ip", "mesh"
    RouteMTU(r Route) int              // usable frame bytes on this specific route
    Cost() Cost                        // airtime-expensive? metered?
    Send(ctx context.Context, r Route, frames [][]byte, opts SendOpts) (Receipt, error)
    Frames() <-chan InboundFrame       // raw frames + transport metadata (RSSI, hops…)
    Health() <-chan TransportHealth    // e.g. radio channel utilization, queue status
}
```

Reachability is **not** derived from transport metadata. It's only updated from authenticated frame contents (§7.1).

### 6.1 IP (go-libp2p)

- **Network identity:** a random libp2p host key, rotated daily and on restart. Your current peer ID is sent to buddies only inside encrypted presence and reachability messages.
- **Finding buddies (rendezvous):** a private Kademlia DHT (`/openaim/kad/1.0.0`). For each buddy and each day you store a record:
  - The record's **key** is `R = HMAC(K_dir, "rdv" ‖ day)`, which only you and that buddy can compute.
  - Its **value** is your current peer ID and addresses, encrypted under a matching locator key `L = HKDF(K_dir, "loc" ‖ day)`.
  - DHT nodes see an unlinkable key and ciphertext. With 100 buddies that's 100 small record writes a day.
- **Coming online:** the later-arriving side looks up each buddy's rendezvous record and dials them. Both sides exchange presence over `/openaim/msg/1`, and the buddy sees "door open".
- **LAN:** mDNS advertises only in Nearby mode (opt-in). Otherwise, buddies on the same LAN find each other through the same rendezvous records, which list LAN addresses.
- **Relays:**
  - **The problem:** go-libp2p's circuit relay v2 defaults reset a relayed connection after **2 minutes or 128 KiB**, and DCUtR hole punching succeeds only about 70% of the time. The two-buddies-behind-symmetric-NAT case therefore *will* run over relays.
  - **Our own relays:** `openaimd --public` relays run with raised limits for OpenAIM protocols. Relays are told only rotating peer IDs.
  - **Limited connections:** the presence and message protocols explicitly allow limited (relayed) connections.
  - **Flapping:** reconnects are transparent. The "door close" grace period (default 3 minutes) exceeds the relay reset interval, so a reset doesn't show as signing off.
  - Measured in M0.
- **Protocols:**
  - `/openaim/msg/1`: a stream of length-prefixed frames, carried **byte-for-byte identical** to mesh frames (§8).
  - `/openaim/sync/1`: catch-up and mailbox fetch.
  - `/openaim/gw/1`: gateway forwarding.
- **Chat rooms:** GossipSub with the `StrictNoSign` policy, so no host-key signatures are attached. The topic name is derived from the room secret (§8.7), so outsiders can't find or join it. A topic validator drops anything that fails the room-key authentication tag, so garbage isn't propagated.
- **Bootstrap:** a small list of community bootstrap and relay nodes shipped in config, replaceable by the user (decided: acceptable). Internet-wide reachability needs *some* publicly reachable nodes, but no particular one is required.

### 6.2 Meshtastic

**Connecting to the radio:** USB serial, TCP (port 4403) and later BLE. The daemon reads the radio's NodeDB, channels,
`DeviceMetrics` (channel utilization, TX airtime) and `QueueStatus`.

**Carrying our traffic:**

- **PortNum:** a **private-application PortNum** (256–511). We'll request an official one before release (Q8).
- **DM path (preferred):** a DM to the buddy's node number, learned only from authenticated content (§7.1). The firmware uses next-hop routing with flood fallback, and adds Meshtastic PKC encryption.
- **Broadcast path (fallback):** broadcast on a dedicated "OpenAIM" channel when the node number is unknown, or on the Nearby and beacon frames. Receivers recognize their frames by the conversation tag (§8.1).
- **Channel settings:** the daemon creates the OpenAIM channel with **MQTT uplink and downlink disabled**. It warns if any channel carrying OpenAIM traffic is uplinked to MQTT, because that publishes captured frames worldwide and makes replay easy.
- **Node name warning:** the daemon warns if the radio's Meshtastic long or short name contains the user's handle. Meshtastic broadcasts NodeInfo in the clear, which would link the radio to the person.

**Constraints:**

| Constraint | Value | Design consequence |
|------------|-------|--------------------|
| Data payload | **233 B** max. PKC DMs cost **12 B** (8-byte tag + 4-byte extra nonce). A private PortNum takes a 2-byte varint. The newer channel AEAD option may cost more. | All mesh traffic uses a **canonical frame size of 200 B** (headroom for those costs). M0 measures the real limit for each route, and the canonical size may rise if the measurements allow. |
| Throughput (LongFast) | ~1 kbps; a 200 B frame is ~2 s of airtime | No typing indicators, buddy icons or file transfer on mesh. |
| Duty cycle (EU868) | 1–10% depending on sub-band. At 1%, that's ~36 s/hour, or **~16 full frames/hour** | A per-region airtime budget, driven by the radio's own counters. |
| Hop limit | default 3 (max 7) | Delivery isn't guaranteed. Acks are designed per route (§8.8). |
| Rebroadcast modes | Relays in `LOCAL_ONLY`/`KNOWN_ONLY` drop channels they don't know. `CORE_PORTNUMS_ONLY` drops private PortNums. | The broadcast path can silently fail in busy meshes. Prefer the DM path, report "may not be relayed" in the UI, and measure in M0. |

**Mesh-specific behavior:**

- **Presence beacons:** **one** encrypted frame per beacon, readable by all buddies through the presence key (§8.6). Sent on startup, on state change and every ~30 minutes with jitter, within the airtime budget. Away messages and profiles are **fetched on demand**, never broadcast.
- **Fragmentation:** messages split into canonical fragments, up to 4 (~655 bytes, §8.3). Longer messages are IP-only, and on a mesh-only route the UI says so before sending.
- **Airtime governor:**
  - **Inputs:** the radio's reported `channel_utilization`, `air_util_tx` and `QueueStatus`, plus the local duty-cycle budget.
  - **Priority order:** IM > ack > presence > profile > Nearby. Stale presence is dropped first.
  - **When the channel is busy:** above a utilization threshold (default 25%), only IMs and acks are sent.

### 6.3 Optional: stock Meshtastic interop

The daemon can show ordinary Meshtastic users from the radio's NodeDB in a **"Meshtastic"** buddy group,
and exchange standard `TEXT_MESSAGE_APP` messages with them. The UI labels them accurately:

- **🔒 "Meshtastic PKC"** for DMs where the firmware used public-key encryption.
- **🔓 "Meshtastic channel"** for anything sent with a channel key, which may be the well-known default key and is effectively public.

These messages never get OpenAIM's end-to-end encryption or verified identity.

---

## 7. Routing, gateways, mailboxes and abuse control

### 7.1 Authenticated reachability

For each buddy the router keeps reachability hints. They come **only** from fresh, authenticated
frame contents, never from Meshtastic's unauthenticated `from` field or from replayed or deduplicated frames.

| Hint | Source | Fields |
|------|--------|--------|
| IP | live `/openaim/msg/1` stream, or a decrypted rendezvous record | peer ID, addresses, `issued_at`, `expires_at` |
| Mesh | `my_mesh_node` field inside an authenticated presence beacon or `CAPS` message | node number, last heard, hops/SNR (display only) |
| Gateway | `REACH` message from the buddy | gateway's full public key and contact, buddy's node number, delivery token, `seq`, `issued_at`, `expires_at` |
| Mailbox | `REACH` message from the buddy | mailbox key and contact, delivery token, `seq`, `expires_at` |

A record with a lower `seq` than one already held, or past `expires_at`, is ignored. That makes replaying stale records useless.

### 7.2 Send policy

1. **Live IP connection** → send there.
2. **Mesh DM path** (node number known, heard recently on our radio) → send on mesh.
3. **Gateway** → send over IP through a gateway the buddy named. **Never** used when the gateway's mesh is our own mesh, i.e. when the gateway's node is in our radio's NodeDB and was heard within 24 hours. That would just put a second copy on the same air.
4. **Mailbox** → deposit for later pickup.
5. Otherwise **queue locally**, retrying when an authenticated reachability update arrives for that buddy.

Every route carries the **same persisted frames** (§8.2). Fallback only *re-sends* bytes; it never re-encrypts.
Receivers, gateways and mailboxes all deduplicate on `(conv_tag, msg_id, frag)`.

### 7.3 Gateways (IP ⇄ mesh bridges)

A node with both a radio and internet access can opt in as a gateway. v1 allows **exactly one gateway hop**, so forwarding loops can't happen and no hop counter is needed.

- **Discovery:** gateways broadcast a signed `GATEWAY_AD` frame (§8.6) every few hours, with their public key and capabilities. IP-side gateways are listed in a public gateway directory in the DHT. Gateways are infrastructure, so their location being public is fine.
- **Registration (mesh user → gateway):** the mesh user sends the gateway a first-contact-style frame that sets up a service relationship. It carries the user's node number, a **delivery key `T`** and an expiry. The gateway serves **only registered mesh users**.
- **IP → mesh:**
  1. The IP sender learned the gateway, the buddy's node number, a token index `j` and the token `HKDF(T, "token" ‖ j)` from the buddy's encrypted `REACH` message.
  2. It sends `/openaim/gw/1 {node, j, frames, HMAC(token, frames)}`.
  3. The gateway derives the token from `T` and `j`, checks it, and sends the frames as a DM to that node.
  4. **Revocation:** when the mesh user removes a buddy, they send the gateway a revocation for index `j`. A suspected leak rotates `T` instead. Mailbox deposit tokens work the same way.
- **Mesh → IP:**
  1. The mesh user registers routes with the gateway, in batches and only as needed. Each route maps a conversation tag to the buddy's (rendezvous key `R`, locator key `L`) for the current day.
  2. The gateway looks up `R`, decrypts the peer contact with `L` and delivers the frames.
  3. The gateway learns only that day's locator for buddies the user chose to reach through it.
- **What the gateway can see:** frame sizes and timing, the registered user's node number, and the conversation tags it routes. It never sees content or identities.

### 7.4 Mailboxes (offline messages)

- **Delegation:** a mailbox serves identities that delegated to it. The delegation is signed by the identity key and expires (default 30 days, auto-renewed). It goes to buddies **inside encrypted `REACH` messages**, not publicly, so it doesn't reveal who uses which mailbox.
- **Deposits** must carry `HMAC(deposit_token, frames)`. Each buddy gets a token derived from the recipient's delivery key.
- **Strangers' buddy requests** go to a separate small **request inbox**. It's quota-limited and needs proof-of-work. This inbox is also the public "inbox hint" in the handle record, so adding by handle never reveals your home IP.
- **Fetching:** the recipient fetches over `/openaim/sync/1` by signing a challenge, then acks to delete.
- **Retention:** at most 14 days, which is the replay acceptance window (§8.9).

### 7.5 Abuse and DoS controls

New keys cost nothing, so per-sender limits alone are useless (Sybil attacks). Instead:

- **Gateways:**
  - They forward only to registered mesh users, only with a valid delivery token, and only within an airtime budget per recipient and per gateway.
  - First-contact frames forwarded from IP to mesh need **proof-of-work** (~20 bits). They're capped per recipient (default 4/hour) and per gateway (default 20/hour).
- **Mailboxes** work the same way: tokens for buddies, and proof-of-work plus quotas for strangers.
- **Mesh:**
  - The daemon **never acks or answers** frames from non-buddies.
  - Unknown content types from buddies are acked on IP only, never on mesh.
  - Unaccepted first contacts cost the recipient no airtime.
- **Blocking:** a block list drops frames from blocked buddies' tags before any processing.
- **Before any state changes:** fragment reassembly buffers are bounded per conversation tag, and every frame is authenticated before it touches dedup or reachability state (§8.9).

---

## 8. Wire protocol

### 8.1 Frame kinds and layout

Every frame starts with `ver_kind` (3-bit version, 5-bit frame kind). The content type (IM, ACK, presence…) is **inside**
the ciphertext, so observers can't tell an IM from an ack by its type field. **IP carries exactly the same frame bytes** as mesh,
which makes routing and gateway forwarding pure byte copies.

**`DATA` frame** (buddy ⇄ buddy, room messages):

| Field | Bytes | Notes |
|-------|-------|-------|
| `ver_kind` | 1 | `DATA` |
| `conv_tag` | 8 | `HMAC(K_dir, "tag" ‖ day)[:8]` for buddies, `HMAC(K_room_epoch, "tag" ‖ day)[:8]` for rooms. It identifies the conversation, direction and room epoch to the recipient only, and rotates daily. |
| `msg_id` | 8 | synthetic: `HMAC(K_siv, inner_plaintext)[:8]` (§8.2) |
| `frag` | 1 | **always present**: `index:4 ‖ (count−1):4`. A single-frame message is `0x00` = index 0 of 1. |
| ciphertext | ≤ 166 | this fragment's slice of the inner payload |
| tag | 16 | Poly1305 |
| **Overhead** | **34** | within the 200 B canonical frame |

**Associated data (authenticated, not encrypted)** = `ver_kind ‖ conv_tag ‖ msg_id ‖ frag`, the whole header. Gateways and relays never change frame bytes, so
the authenticated data is the same on every transport.

Receivers keep a table of their expected `conv_tag`s for every day within the acceptance window (§8.9): roughly
14 days × buddies × rooms entries. An incoming tag is a single table lookup.

### 8.2 Message keys and nonces: seal once, resend identical bytes

ChaCha20-Poly1305 must never encrypt two different plaintexts under the same key and nonce. This is guaranteed three ways at once:

1. **Synthetic message IDs:** `msg_id = HMAC(K_siv, inner_plaintext)[:8]`. Different plaintext gives a different `msg_id`, which gives a different message key, except for a 64-bit collision. Identical plaintext gives identical ciphertext, which is harmless.
2. **Per-message keys bound to the fragment layout:** `K_msg = HKDF(K_dir, "openaim/v1/msg" ‖ msg_id ‖ frag_count ‖ layout_version)`, with nonce = fragment index (12 bytes, big-endian). Re-fragmenting differently can't reuse a key/nonce pair.
3. **Seal once:** frames are created **once**, at send time, at the canonical size, and **persisted**. Retries, route fallbacks and restarts all re-send the stored bytes. The router never re-encodes, re-compresses, re-timestamps or re-fragments a sealed message. A message that must change (after key rotation, §5.5) is a *new* message with a new `msg_id`.

Pairwise keys:
```
K_pair = HKDF(X25519(my_x, their_x), salt="openaim/v1",
              info="pair" ‖ sorted(Ed_A, Ed_B))          // binds Ed25519 keys
K_dir  = HKDF(K_pair, "dir" ‖ Ed_sender)                  // separate keys per direction
K_siv  = HKDF(K_dir,  "siv")
```

### 8.3 Fragmentation

- Every fragment is authenticated on its own, so a forged or corrupted fragment is detected individually. Acks can then report exactly which fragments arrived (§8.8).
- The inner header is in fragment 0 only.
- **Capacity:** fragment 0 holds ~157 B of body, and later fragments 166 B each. With 4 fragments that's ~655 B before compression.
- **Same frames on IP:** IP sends messages that could go over mesh as the same canonical frames (batched in one stream write). IP-only content (long text, files, buddy icons) uses `layout_version = ip`, with larger fragments, and can never be routed to mesh.

### 8.4 Inner payload (encrypted)

```
content_type (1) | flags (1) | timestamp (4) | seq (varint) | body
```

- **`timestamp`:** seconds since 2025-01-01, unsigned 32-bit, which is good until about 2161.
- **`flags`:** compressed, ack-requested, clock-unsynced.
- **`seq`:** per-direction counter used for ordering and gap detection.
- **`body`:** UTF-8 text for IMs (after optional short-text compression), protobuf for everything else.
- **Content types:** `IM`, `ACK`, `PRESENCE`, `PROFILE_REQ`, `PROFILE`, `AWAY_MSG`, `TYPING` (IP only), `ROOM_MSG`, `ROOM_INVITE`, `ROOM_REKEY`, `BUDDY_ACCEPT`, `REACH`, `CAPS`, `ROTATE`.

A single-frame IM therefore holds about **157 bytes** of text before compression. The UI's character counter uses the
**route's** capacity: 157/655 bytes for routes that may use mesh, much more for IP-only.

### 8.5 First contact (`FIRST_CONTACT` frame): Noise `X`-style, deniable

The first message to someone who isn't yet a buddy uses a one-way handshake modeled on Noise's `X` pattern
(`e, es, s, ss`). It hides the sender's identity from observers and authenticates the sender to the recipient **without a signature**, so the request is deniable.

| Field | Bytes | Notes |
|-------|-------|-------|
| `ver_kind` | 1 | `FIRST_CONTACT` |
| `e` | 32 | ephemeral X25519 public key |
| `msg_id` | 8 | synthetic, as above |
| `frag` | 1 | |
| `enc(s)` | 32 + 16 | sender's Ed25519 identity key, encrypted under `DH(e, R_x)` |
| `enc(payload)` | n + 16 | encrypted under a key from `DH(e, R_x)` and `DH(s_x, R_x)` |
| **Overhead** | **106** | → **94 B** payload in one frame: content type, timestamp, display name, short greeting, contact hint. A longer greeting uses 2 fragments. |

- **Recipient binding:** the recipient is bound by the DH with their static key, and freshness by the timestamp inside. The message can't be redirected to someone else, and replays are limited by the replay window (§8.9).
- **No recipient field:** there's deliberately no recipient hint, because it would be linkable to a public key. Recipients try to decrypt each first-contact frame, which costs one X25519 operation per frame; these frames are rare and rate-limited.
- **Reuse:** gateway and mailbox registration use the same frame type.

### 8.6 Broadcast frames (mesh)

| Frame | Contents | Size | Who can read it |
|-------|----------|------|-----------------|
| `BEACON` | `presence_tag = HMAC(K_presence, "ptag" ‖ day)[:8]`, `msg_id`, encrypted {state, idle, `my_mesh_node`, timestamp} | ~45 B | All buddies, through the shared presence key. It's one frame no matter how many buddies you have, and outsiders can't link it to you. |
| `NEARBY` (opt-in) | identity key, display name, timestamp, signature | ~125 B | Everyone (deliberately public, signed) |
| `GATEWAY_AD` | gateway key, capabilities, timestamp, signature | ~105 B | Everyone (infrastructure, signed) |

**Accepted residual risk:** Meshtastic's own `from` node number and NodeInfo are in the clear and persistent. A radio that's been seen before is linkable
regardless of what OpenAIM does. The UI says so and suggests a nondescript Meshtastic node name.

### 8.7 Rooms

- **Keys:** a room has a long-term **room secret** (used to derive the topic name and a validator key) and a content key numbered by **epoch**. Each epoch's conversation tag differs, so receivers know which key applies without an extra byte. They keep the previous epoch's key for a short overlap so late messages still decrypt.
- **Invites and rekeys:** `ROOM_INVITE` and `ROOM_REKEY` go to each member over their pairwise channel. Removing a member rotates *both* the room secret (so the topic moves) and the content key.
- **IP topic:** `HMAC(room_secret, "topic")`.
- **Mesh:** broadcast on the OpenAIM channel. **Mesh rooms are capped at 16 members** because every rekey costs one frame per member.
- **Sender authenticity:** in v1 any member can forge another member's room messages. On IP, members may optionally sign room messages, since bytes are cheap there. This is stated in the UI's room info.

### 8.8 Delivery and acks: one ack layer per route

| Route | Mechanism | Rationale |
|-------|-----------|-----------|
| **Mesh DM path** | Firmware `want_ack=true`. The firmware asks the *destination node* for an ack and retransmits by itself. **No app-level ack on mesh.** After a firmware failure the app retries at most once, after a long backoff (hop- and preset-scaled). | No layer duplicates another's retries. "Delivered" means delivered to the buddy's radio, which buffers for its daemon. |
| **Mesh broadcast path** | `want_ack=false`. An app-level `ACK` carries a **fragment bitmap**, and only missing fragments are re-sent. At most 3 attempts. Timeouts scale with hop count and modem preset. | Selective repeat avoids re-sending a whole 4-fragment message over one lost fragment. |
| **IP** | App-level `ACK` with a bitmap. | Cheap. |

At most one mesh path is used per message attempt (§7.2 rule 3). Read receipts are optional, off by default and never sent on mesh.

### 8.9 Replay protection and time

- **Verify first:** AEAD verification happens **before** any state is touched (dedup, reassembly, reachability, presence).
- **Acceptance window:** frames with an inner timestamp more than **14 days** old or more than 10 minutes in the future are rejected. Mailbox retention is capped at the same 14 days.
- **Dedup window:** `(conv_tag, msg_id, frag)` entries are kept for **30 days**, which is the acceptance window plus clock-skew margin and more. That's about 24 bytes per entry, or a few MB even for heavy users. A replay older than the dedup window is already outside the acceptance window.
- **Time sources, in priority order:**
  1. An NTP-synced OS clock.
  2. GPS time reported by the radio.
  3. The median of authenticated timestamps from at least 2 buddies' recent frames.
  4. None of these: the node is **clock-unsynced**. It sets the `clock-unsynced` flag, and receivers show its messages in arrival order with an "unverified time" marker. A build-time floor prevents 1970 dates.
- **MQTT:** uplink is disabled on OpenAIM channels (§6.2).

### 8.10 Versioning

A 3-bit wire version, frame kinds and a `CAPS` exchange when buddies connect. Protobuf bodies add fields compatibly.
**The wire format freezes only at the end of M2, after an external cryptography review** (§13).

---

## 9. Observability

The daemon keeps metrics that are local only by default and never phoned home. Gateway and mailbox operators can optionally expose a Prometheus endpoint.

| Metric | Why |
|--------|-----|
| AEAD failures (by frame kind and transport) | Forgery and corruption attempts |
| Replay rejects and dedup hits | Replay attacks; duplicate-path efficiency |
| Airtime used vs. budget; radio channel utilization | Whether we're meeting G4 |
| Ack success, latency and retry counts by route | Route quality; tuning timeouts |
| Gateway forwards per recipient and per token; proof-of-work rejects | Abuse detection (§7.5) |
| Mailbox deposits and quota rejects | Abuse detection |
| Relay resets, hole-punch success rate | Whether NAT traversal assumptions hold (§6.1) |
| Handle re-check failures and key-change warnings | Takeover detection (§5.3) |

`openaim status --verbose` and a TUI/GUI diagnostics panel show these.

---

## 10. Security and privacy

### 10.1 Threat model

**Adversaries we defend against:**
- Passive radio and network observers, including anyone receiving MQTT-uplinked mesh traffic.
- On-path network attackers (café Wi-Fi).
- Malicious or compromised relays, gateways, mailboxes and DHT nodes.
- Strangers who know your handle.
- Spammers with unlimited free keys.
- A malicious or coerced handle registry (partially; see below).

**Out of scope:**
- A compromised endpoint device.
- Global traffic analysis (timing correlation across the internet).
- Radio direction-finding.
- A user who keeps no backup and loses both the device and the recovery phrase.

| Asset | Protection |
|-------|-----------|
| Message content | E2E AEAD; seal once (§8.2) |
| Who talks to whom | Rotating conversation tags, no identities in frames (§8.1), rotating network keys (§6.1). *Residual:* Meshtastic node numbers, IP-level timing at relays. |
| Whether you're online | Visible only to buddies (rendezvous records, presence key). *Residual:* your public request inbox (mailbox) is always up, and your radio's NodeInfo is public. |
| Your location | No public reachability records; gateway use is known only to buddies. *Residual:* a radio's RF presence. |
| Handle → identity binding | DoH/DNSSEC, two proofs, pinning, transparency log (§5.3). *Residual:* expired self-hosted domains, for new adds only. |
| Availability (airtime, quotas) | Tokens, proof-of-work, budgets, no answers to strangers on mesh (§7.5) |

### 10.2 Cryptography summary and domain separation

Every signature and key derivation uses a unique, versioned label. No two uses share a label.

| Use | Primitive | Label |
|-----|-----------|-------|
| Handle claim | Ed25519 sign (identity key) | `openaim/v1/handle-claim` |
| Nearby advert | Ed25519 sign | `openaim/v1/nearby` |
| Gateway advert | Ed25519 sign (gateway key) | `openaim/v1/gateway-ad` |
| Key rotation | Ed25519 sign (recovery key) | `openaim/v1/rotate` |
| Mailbox delegation | Ed25519 sign | `openaim/v1/mailbox-delegation` |
| Mailbox fetch auth | Ed25519 sign over a challenge | `openaim/v1/mailbox-fetch` |
| Registry sign-up | Ed25519 sign over a challenge | `openaim/v1/registry-auth` |
| Pairwise keys | X25519 + HKDF-SHA256 | `openaim/v1` + `pair`/`dir`/`siv`/`msg`/`tag`/`rdv`/`loc`/`token` |
| First contact | Noise `X`-style, X25519 + HKDF + ChaCha20-Poly1305 | `openaim/v1/first-contact` |
| Safety number | SHA-256 | `openaim/v1/safety-number` |

IM content and buddy requests are **deniable**: they're authenticated with shared keys, not signatures. Only deliberately
public artifacts (handle claims, adverts, delegations, rotations) are signed.

### 10.3 Known limitations (v1, stated honestly)

- **No forward secrecy.** Pairwise keys are static-static. If an identity key leaks, captured past traffic can be decrypted. *Planned:* periodic rekeying with ephemeral keys exchanged when both sides are on IP, then a ratchet that tolerates lossy, out-of-order links. Treat this as a research item.
- **Key-compromise impersonation.** If *your* identity key leaks, an attacker can impersonate *any of your buddies to you*, not just read your messages. This is a property of static-static Diffie-Hellman. The fix is rotation (§5.5) plus forward secrecy work.
- **Room members can forge each other** (§8.7).
- **Meshtastic metadata residuals** (§8.6) and the **registry trust residuals** (§5.3).

### 10.4 Review gate

This is a custom protocol that parses bytes from the open air. Before the wire format freezes (end of M2):
- A written threat model (§10.1, kept up to date).
- Published golden test vectors.
- Fuzzing of every decoder.
- **An external cryptography review** of §5 and §8.

### 10.5 Amateur radio (out of scope)

OpenAIM targets ordinary license-free Meshtastic use (e.g., US 915 MHz ISM), where encryption is allowed. If the attached radio
reports `is_licensed`, the daemon **refuses to transmit** OpenAIM traffic on it and explains why.

---

## 11. Client experience

### 11.1 Shared concepts (served by the daemon API)

- Buddy list: groups, online/away/idle/offline, and the route icon for each buddy (🌐 IP, 📡 mesh, 🔁 gateway, 📬 mailbox). Unverified contacts are styled distinctly (§5.3).
- IM conversations: delivery status, the route used, mesh signal info on hover, and a route-aware character counter.
- Away messages with `%n` (buddy name), `%d` (date) and `%t` (time) substitution. Auto-away when idle, with an idle timer.
- Profiles (fetched on demand), chat rooms, the Nearby group (opt-in), sounds and notifications.
- Safety-number verification screen (QR and digits). "Moved/unverified handle" warnings.

### 11.2 TUI (`openaim tui`)

```
┌ Buddy List ───────────┐┌ SkaterDude99 · 📡 mesh DM (2 hops, SNR −7) ─────────────────┐
│ ▾ Buddies (3/5)       ││ [13:02] SkaterDude99: you going to the lan party friday?    │
│   🌐 SkaterDude99     ││ [13:03] me: yeah if my radio reaches lol           ✓ radio  │
│   📡 TrailRunner      ││                                                             │
│   🌐 Mom (away)       ││                                                             │
│ ▾ Nearby (1)          ││                                                             │
│   ⚠ ~q7m2 hikerjen    ││                                                             │
│ ▾ Meshtastic (2)      ││                                                             │
│   🔓 !a1b2 KD-Base    ││                                                             │
│ ▸ Offline (2)         │├─────────────────────────────────────────────────────────────┤
│                       ││ > _                                    157 bytes left (1/4) │
└───────────────────────┘└─────────────────────────────────────────────────────────────┘
 [Tab] switch  [Ctrl+N] new IM  [Ctrl+A] away  [Ctrl+R] rooms  [?] help
```

### 11.3 CLI (scriptable)

```
openaim status [--verbose]           # identity, transports, radio, metrics
openaim buddies                      # list with presence
openaim send SkaterDude99 "brb"      # send an IM
openaim away "at class. %n, IM me later"
openaim invite --qr                  # print your invite code / QR
openaim add skaterdude99.<registry>  # add by handle (or paste an invite link)
openaim verify SkaterDude99          # show safety number / QR
openaim backup export ~/oa-backup    # encrypted backup; shows the recovery phrase
openaim radio connect /dev/ttyUSB0   # or tcp://meshtastic.local
```

### 11.4 GUI (Wails)

- Separate windows for the buddy list and each IM, true to the original layout.
- Retro styling and a skin system. **Use original artwork and sounds.** AOL's icons, logo and door sounds are copyrighted or trademarked, so design homages, not copies.
- System tray, notifications, auto-start of the daemon, diagnostics panel.

---

## 12. Repository layout (proposed)

```
openaim/
  cmd/
    openaimd/          # daemon
    openaim/           # CLI + TUI (subcommands)
    openaim-registry/  # handle registry service
  gui/                 # Wails app (Go bindings + frontend/)
  proto/               # .proto: inner payloads, IP control messages, local API
  spec/                # wire spec + golden vectors (frames, keys, handles)
  internal/
    identity/          # keys, conversion, safety numbers, keystore, backup/recovery
    handle/            # DoH client, HTTPS proof fetcher (SSRF-guarded), pinning
    frame/             # seal-once, canonical fragmentation, AEAD, first-contact, replay/dedup
    router/            # reachability table, send policy, retry queue, airtime governor
    presence/          # presence state machine, idle/away, beacons, presence key
    rooms/             # room secrets, epochs, membership
    gateway/           # gateway server + client
    mailbox/           # mailbox server + client
    store/             # SQLite schema + migrations (persisted sealed frames)
    metrics/
    transport/
      ip/              # libp2p host (rotating keys), DHT rendezvous, relay, protocols
      mesh/            # meshtastic serial/TCP/BLE, framing, DM vs broadcast paths
      sim/             # in-memory lossy network for tests
    api/               # gRPC local API server
  third_party/meshtastic-protobufs/   # pinned
  docs/
```

---

## 13. Testing strategy

- **Simulated transports** (`transport/sim`): an in-memory network with configurable loss, latency, MTU, airtime budget and rebroadcast filtering. Routing, retry, dedup, selective repeat and fallback get deterministic tests in CI.
- **Property tests for the seal-once invariant:** no `(K_msg, nonce)` pair is ever used with two different plaintexts across retries, fallbacks, restarts and rotation.
- **Golden vectors** in `spec/` for every frame kind, key derivation, the handle record and the safety number.
- **Fuzzing** (`go test -fuzz`) on every frame decoder, the protobuf bodies, the DoH response parser and the handle record parser.
- **Adversarial tests:** replayed frames, forged fragments, spoofed Meshtastic `from` fields, stale `REACH` records, Sybil first-contact floods, an attacker-chosen handle that resolves to private addresses.
- **Hardware-in-the-loop:** 2–3 real radios (e.g., Heltec V3, RAK4631) on a bench, including a relay set to `CORE_PORTNUMS_ONLY`.

---

## 14. Milestones

| Milestone | Scope | Exit criteria |
|-----------|-------|---------------|
| **M0 – Spikes & measurements** | Go ⇄ Meshtastic over serial/TCP on a private PortNum. Libp2p peers through a relay. | Measured: real usable payload per route (broadcast vs. PKC DM, channel AEAD on/off), `want_ack` behavior and timing, delivery through each rebroadcast mode, relay v2 resets with our raised limits, hole-punch success on home networks. §6.2's canonical frame size is confirmed or revised. |
| **M1 – Core + IP + TUI** | Identity, keys, backup/recovery phrase, safety numbers, SQLite, frame layer (seal once, AEAD, replay window), rotating network keys, DHT rendezvous, first contact, buddy accept, presence, 1:1 IMs, handle verification (DoH/HTTPS), TUI, CLI, metrics. Draft wire spec + golden vectors. | Two machines on different networks IM each other with presence. Seal-once property tests and fuzzers in CI. |
| **M2 – Mesh transport** | DM and broadcast paths, presence beacons, canonical fragmentation, selective repeat, airtime governor driven by radio telemetry, router fallback. | A conversation continues when one side drops off IP and is only reachable by radio. **Gate: external crypto review → wire format v1 frozen.** |
| **M3 – Gateways + mailboxes** | Gateway registration, tokens, route registration, `GATEWAY_AD`; mailbox delegation, deposits, request inbox, proof-of-work. | IP-only user ⇄ mesh-only user through a gateway. Offline messages delivered on login. Sybil-flood tests pass. |
| **M4 – GUI** | Wails app with multiple windows, skins, tray, sounds, diagnostics panel. | Daily-drivable desktop client. |
| **M5 – Rooms, registry & polish** | Rooms (IP + mesh, epochs, 16-member mesh cap), away-message templates, profiles, Meshtastic interop group, handle registry service + transparency log + policy, key rotation flow end to end. | Feature parity with the AIM experience in G1. |
| **Later** | Multi-device (wire v2), forward secrecy/rekeying, mobile, IP-only file transfer and buddy icons. | — |

---

## 15. Open questions

| # | Question | Status |
|---|----------|--------|
| Q1 | Language | **Resolved: Go** |
| Q2 | Community-run infrastructure acceptable? | **Resolved: yes**, replaceable and anyone can run one |
| Q3 | Screen names | **Resolved in principle:** Bluesky-style DNS handles (§5.3). *Still open:* the default registry's domain, who operates it, and its abuse/dispute/reclaim policy. |
| Q4 | Stock Meshtastic interop in v1 or later? | Assumed M5 |
| Q5 | Build on Reticulum/LXMF instead? | Assumed custom |
| Q6 | Multi-device early? | Assumed no (wire v2) |
| Q7 | Ham operation | **Resolved: no.** ISM only, with a guard rail (§10.5) |
| Q8 | Public project name ("AIM" is an AOL trademark) and an official Meshtastic PortNum | Open; "openaim" stays the codename |
| Q9 | Mobile clients someday? | Later |
| Q10 | One identity key for signing and DH (chosen, §5.1) vs. a separate signed X25519 key | Chosen for mesh byte budget; revisit at crypto review |
| Q11 | Who performs the external crypto review, and what budget? | Open, needed before end of M2 |

---

## Appendix A. Review findings → resolution

| # | Finding (severity) | Resolution |
|---|--------------------|------------|
| 1 | Nonce reuse from re-encrypting on retry (Critical) | Seal once and persist frames, synthetic `msg_id`, per-message keys bound to fragment layout, explicit `frag` byte (§8.2, §8.1); property tests (§13) |
| 2 | Mutable `hops` byte in the AEAD's authenticated data breaks gateways (Critical) | Hop counter removed; exactly one gateway hop in v1; identical frame bytes on all transports; header fully authenticated and never changed (§7.3, §8.1) |
| 3 | No replay protection; bad clocks; MQTT exposure (High) | 14-day acceptance window, 30-day dedup, verify before state, time sources and unsynced mode, MQTT uplink disabled (§8.9, §6.2) |
| 4 | Presence/location exposed via handle → key → DHT (High) | Separate rotating network keys, pairwise DHT rendezvous, encrypted `REACH`, one-frame presence beacons under a shared presence key, Nearby opt-in, residuals documented (§5.1, §6.1, §8.6, §10.1) |
| 5 | Unauthenticated mesh node binding; blackholing (High) | Reachability only from authenticated content, `seq`/`expires_at` on records, gateway adverts defined (§7.1, §8.6) |
| 6 | Gateway amplification and Sybil DoS (High) | Registered recipients only, delivery tokens, budgets, proof-of-work for first contact, no mesh replies to strangers (§7.3, §7.5) |
| 7 | DNS handle scheme gaps (High) | DoH/DNSSEC, safe HTTPS fetching, LDH-only syntax, pinning with move warnings, transparency log, signed-only rotation, keep-alive/reclaim policy, self-contained signed TXT record (§5.3) |
| 8 | First-contact frame unspecified, too big, not deniable (High) | Noise `X`-style `FIRST_CONTACT`: 106 B overhead, no signature, recipient-bound, time-bound; deniability claim restated (§8.5, §10.2) |
| 9 | Byte budgets overstated; `sender_device` contradiction; type leak (Medium) | Canonical 200 B frame pending M0, route-aware counter, `sender_device` removed (wire v2), content type moved inside ciphertext (§6.2, §8.1, §8.4, §5.6) |
| 10 | `want_ack` mischaracterized; duplicated retries; no selective repeat (Medium) | One ack layer per route, fragment bitmaps, no mesh-to-same-mesh gateway fallback, governor driven by radio telemetry (§8.8, §7.2, §6.2) |
| 11 | Relay v2 limits break presence (Medium) | Raised limits on our relays, limited connections allowed, door-close grace > reset interval, measured in M0 (§6.1, §14) |
| 12 | Rooms: no epochs, open topic, GossipSub signing (Medium) | Epoch via tag, topic from room secret, `StrictNoSign`, authentication-checking validator, 16-member mesh cap (§8.7, §6.1) |
| 13 | Rebroadcast modes drop our traffic; interop mislabeled (Medium) | Prefer the DM path, UI warning, M0 measurement, accurate 🔒/🔓 labels (§6.2, §6.3) |
| 14 | Key-compromise impersonation, key reuse, HKDF binding (Medium) | Key-compromise impersonation documented; single-key decision justified with domain-separation table; HKDF binds Ed25519 keys (§10.3, §10.2, §5.1, §8.2) |
| 15 | Mailbox authorization and abuse (Medium) | Signed expiring delegation sent only to buddies, deposit tokens, request inbox with proof-of-work, retention ≤ acceptance window (§7.4) |
| 16 | No backup; rotation path; queued messages (Low–Medium) | Recovery phrase + encrypted backup in v1, recovery key from day one, registry repoints only on signed request, re-seal queued messages with new IDs (§5.5, §5.3) |
| 17 | 64-bit fingerprint too short (Low) | 128+-bit safety number. The key ID is a UI label only (§5.2) |
| 18 | No threat model, review gate or observability (Process) | Threat model (§10.1), review gate before wire freeze (§10.4, §14), metrics (§9) |
