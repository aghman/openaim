# IP transport: rotating network keys, private DHT, bootstrap config

This note records how `internal/transport/ip` implements three parts of
[design.md §5.1 and §6.1](design.md#61-ip-go-libp2p): the rotating network key, the private DHT, and the bootstrap
config. It also lists which linkability residuals remain. The DHT record format is in
[spec/dht-records.md](../spec/dht-records.md).

## Rotation (`ip.Node`)

`ip.Node` owns the current libp2p host. Every host it builds (a *generation*) gets a fresh random Ed25519 key, so
a restart always means a new peer ID. While running, the node rotates on a schedule: every 24 h ± 1 h by default
(uniform jitter, so rotations don't land at a predictable time of day). `Rotate` rotates at once and restarts the
schedule. Relays and bootstrap nodes use `FixedKey` instead: their address must stay stable and is public anyway.

A rotation is a handover, not a restart:

1. **Bring the new host up.** It listens, gets every stream handler registered with `Node.SetStreamHandler`,
   reserves a slot on each configured relay (waiting for each relay's first attempt, at most 30 s), and starts
   every service registered with `Node.Attach` (the DHT, later rendezvous publishing). If an attached service
   fails to start, the rotation fails, the new host is torn down and the old one stays current. Scheduled
   rotations retry after a minute.
2. **Switch.** `Node.Host()` now returns the new host, so new dials and new outbound streams leave from it.
3. **Notify.** Subscribers get a `HostChange` with the new peer ID and addresses (own addresses plus a circuit
   address per relay reservation). This is where later code republishes rendezvous records and tells buddies the new
   peer ID over encrypted presence on the streams they already have.
4. **Drain.** The old host keeps running, with its handlers, for the grace period (default 5 minutes). Streams
   on it keep working in both directions, and a buddy that hasn't heard about the new peer ID can still reach the old
   one. The grace exceeds the 3-minute "door close" grace, so buddies have moved before the old host disappears.
5. **Retire.** Attached services on the old host stop (in reverse start order), its relay reservations are
   dropped, and the host closes. Buddies still connected to it see the connection-closed event at once (spike
   finding 3) and should already know where to go.

`Close` closes every generation at once, without a grace period.

## Sessions (`ip.Sessions`, `/openaim/msg/1`)

`ip.NewSessions(node, opts)` runs `/openaim/msg/1` (design §6.1) on a `Node`: long-lived streams of
length-prefixed frames (`frames.go`: 16-bit big-endian length, 1–65 535 bytes), carrying OpenAIM frames
byte-for-byte. There is one logical session per remote **peer ID**. Frames are opaque at this layer: which buddy a
peer ID belongs to is decided by the router from authenticated frame contents (design §7.1), never here.

**API.**

- `Send(ctx, peer.AddrInfo, frames)` writes the whole batch in **one stream write** (design §8.3).
- `Inbound()` delivers `InboundFrame{Peer, Frame, Path, Relayed, Local, At}`. `Path` is `PathOf` the connection,
  e.g. `direct/tcp` or `relay (limited)`. `Local` is which of our peer IDs received the frame: the current host, or
  one still draining after a rotation.
- `Events()` delivers `SessionEvent{Peer, Up, Path, Relayed, Local, Reason, At}`. A session is **up** while at
  least one stream with the peer is open in either direction. An `Up` event with a new path means the session moved,
  for example relay → direct.
- `Keep(peer.AddrInfo)` / `Drop(peer.ID)`, `Peer(id)` / `Peers()` (snapshots with per-peer counters), `Stats()`
  (global counters for metrics), and `Close`.

**Streams.**

- Each side writes only on streams it opened and reads every stream. Two streams per buddy pair cost nothing on
  yamux or QUIC, and there's no simultaneous-open ambiguity about which one to write.
- A stream on the peer's existing connection can always be opened, whoever dialed. So `Send` with only a peer ID
  works whenever the peer is connected to us.
- Every open allows limited (relayed) connections (spike finding 2).

**Delivery.**

- Delivery is **best effort**. A successful `Send` means its frames were written to one stream, in order and
  contiguously.
- Acks and retries are the router's job (§8.8). Frames from different `Send`s can be reordered when a session
  switches streams.
- If a write fails, the stream is reset (it may hold a partial frame), and `Send` reconnects with backoff
  (250 ms, doubling to 30 s) and writes the whole batch again. It stops when the caller's context ends or after
  `SendTimeout` (30 s), and then returns a `*SendError`.
- A failed or retried batch may have delivered a prefix, or everything. Receivers deduplicate on
  `(conv_tag, msg_id, frag)` (§7.2).

**Reconnects.**

- A closed connection is handled from the `network.Notifiee` event, not at the next write (spike finding 3). Its
  streams end at once and the session goes down.
- A **kept** session reopens at once, then backs off, until `Drop` or `Close`. A session that isn't kept reconnects
  only when there is something to send.
- A reconnect may come back direct (finding 5).
- `Drop` stops keeping and closes our outbound streams. Inbound streams from the peer stay open: the peer decides
  about those.

**Migration.** When a direct connection to a peer appears on a host whose active outbound stream to that peer is
relayed (DCUtR, an identify-driven dial or a reconnect), a new stream is opened on it. Sends switch to the new
stream, and the relayed one is closed gracefully once any write in progress finishes. Each side migrates its own
outbound stream.

**Rotation.** Inbound streams are accepted on every live host (`Node.SetStreamHandler`), and streams on a draining
host keep working until it retires. After a rotation:

- New outbound streams leave from the new host. A kept session moves at once; others move at their next `Send`.
- The old stream is then closed, so the peer sees the old peer ID go down and the new one come up.
- If the new host can't reach the peer (no usable addresses), sends fall back to the draining host's stream, and the
  upgrade is retried at most every 30 s.

**Inbound safety** (defaults; all in `SessionOptions`):

| Limit | Default | Over the limit |
|-------|---------|----------------|
| Frame size | 65 535 B (`MaxFrameLen`, configurable lower) | The stream is reset; zero-length frames too. Counted in `BadFrames`. |
| Inbound streams per peer | 4 | The peer's oldest inbound stream is reset, so a peer reconnecting over a half-dead stream isn't locked out. Counted in `StreamsEvicted`. |
| Per-peer rate | 200 frames/s (burst 1000) and 1 MiB/s (burst 4 MiB) | That peer's streams are read more slowly. Flow control pushes back on the sender; nothing is dropped or disconnected. Counted in `RateLimited`. |
| Idle stream | 10 min with no frame either way | The stream is closed gracefully. Kept peers' outbound streams are exempt. Counted in `IdleCloses`. |
| Inbound queue | 1024 frames, shared | The frame is dropped. Counted in `QueueDrops`, globally and per peer. The libp2p handler never waits for the consumer. |
| Event queue | 256 events | The event is dropped and counted in `EventDrops`. Use `Peers()` to resync. |

A remote that idles out our kept stream is reopened automatically. Presence heartbeats more frequent than the idle
timeout avoid that churn. Per-peer counters live as long as the session (one with no streams, no `Keep` and no
`Send` in progress is forgotten). The global counters in `Stats()` don't reset.

Use one `Sessions` per `Node`: it owns the node's `/openaim/msg/1` handler.

## Unlinkability choices

The acceptance criterion is that peer IDs are unlinkable across rotations. A generation shares nothing with the
previous one that a network observer could use to link them:

| Linking vector | What the node does |
|----------------|--------------------|
| Key / peer ID | Fresh Ed25519 key per generation from `crypto/rand`; never derived from, or signed by, the identity key. |
| Peerstore, connections | Each host has its own in-memory peerstore and swarm. Nothing is copied: the new host starts knowing no peers and holding no connections, so it doesn't reconnect to the old host's exact peer set (which would fingerprint it). Callers re-introduce buddies from their own (encrypted) state. |
| Listen ports | Port 0 by default: every generation listens on new random ports. go-libp2p's TCP transport dials with `SO_REUSEPORT` from its listen port, so a reused port would also show up as the *source* port of outgoing connections. |
| Fixed ports | Allowed through `NodeOptions.Listen(generation)`, e.g. to alternate between two forwarded ports. Consecutive generations overlap during the grace period, so they must not share a port: with `SO_REUSEPORT` both would bind and the kernel would split inbound connections between them, breaking handshakes. The node checks the bound ports and fails the rotation with `ErrPortReuse`. A fixed port links generations for anyone who sees both; that is the user's trade-off for port forwarding. |
| DHT | A new DHT instance with a fresh routing table and datastore per generation (see below). |
| Relay reservations | Made from the new host with its own key; the old reservation lapses when the old host closes. |
| Timing | Jittered schedule. |

Residuals (documented, not solved here):

- **IP address.** Both generations use the same public IP. Anyone who sees both peer IDs from one IP can guess they
  belong together; behind CGNAT this is weaker. Hiding the IP needs Tor or a VPN and is out of scope (design §10.3).
- **Handover timing.** During a rotation the new host contacts the same relays and bootstrap nodes a few seconds
  before the old one goes quiet. A relay or bootstrap operator watching one IP can pair the two IDs by timing. Delaying
  the old host's teardown (the grace period) doesn't hide the new host's arrival. Staggering (bringing up the new host
  minutes before switching to it) would weaken this but not remove it.
- **Buddies** learn every new peer ID; that is the point. Only they can link them.

## Private DHT (`ip.DHT`)

`ip.NewDHT(ctx, node, opts)` runs go-libp2p-kad-dht v0.43.1 with protocol `/openaim/kad/1.0.0` on a `Node` and
follows its rotations through `Node.Attach`:

- **One instance per host generation.** Each instance starts with an empty routing table and an empty in-memory
  datastore, and routing-table persistence is off. Before the new host becomes current, its instance connects to the
  configured bootstrap peers and runs one routing-table refresh, bounded by `BootstrapTimeout` (10 s). Running out of
  time isn't an error, because the first node of a network has nobody to find.
- **No reuse across generations.** The new routing table is seeded only from config, never from the old one, whose
  keyspace-specific peer set would fingerprint the node. The datastore isn't shared either. Otherwise an attacker
  could store a unique record on the old peer ID by direct RPC and ask the new one for it. Our own generations are
  filtered out of each other's routing tables and queries, because records stored on a draining host die with it.
- **Retirement.** The old instance keeps serving during the grace period and closes before its host does. Records it
  stored for others are lost. Kademlia stores each value on ~20 peers, and publishers republish (rendezvous ticket).
- **Modes.** `DHTServer` for bootstrap and other public nodes, `DHTAuto` (server only once AutoNAT says the host is
  public) for ordinary peers, `DHTClient` to never serve.
- **Records.** Only the self-certifying `/oa-rdv/` namespace is accepted (see the spec). Provider records are disabled.

## Bootstrap and relay config (`ip.NetworkConfig`)

The format is JSON, parsed with the standard library:

```json
{
  "comment": "optional, ignored",
  "bootstrap": ["/dns4/boot.example.org/tcp/4001/p2p/12D3Koo…"],
  "relays":    ["/ip4/192.0.2.7/udp/4001/quic-v1/p2p/12D3Koo…"]
}
```

- **Built-in default.** `default_network.json` is embedded in the binary, and `DefaultNetworkConfigJSON` returns it as
  a template. **No community nodes are operated yet**, so both lists are empty, and the file says so.
- **User override.** `LoadNetworkConfig(path)` returns the defaults when the file is missing. A list present in the
  user file, even `[]`, replaces the built-in list, and a list left out (or `null`) keeps it. That way a user can
  replace the relays and keep the shipped bootstrap nodes.
- **Strict parsing.**
  - Unknown fields and trailing data are errors, to catch typos.
  - Every entry must be a multiaddr with a dialable address and a final `/p2p/<peer ID>`. Circuit addresses are
    refused.
  - Addresses of the same peer are merged, in first-seen order.
  - Limits: 64 KiB per file and 64 entries per list.
- **Wiring.** `NetworkConfig.Bootstrap` goes to `DHTOptions.Bootstrap`, and `NetworkConfig.Relays` goes to
  `NodeOptions.Relays`.

Where the file lives (the daemon's config directory) is for `openaimd` to decide.
