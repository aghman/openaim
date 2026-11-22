# IP transport: rotating network keys

This note records how `internal/transport/ip` implements the rotating network key of
[design.md §5.1 and §6.1](design.md#61-ip-go-libp2p), and which linkability residuals remain.

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
