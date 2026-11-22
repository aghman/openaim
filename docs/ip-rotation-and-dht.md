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
