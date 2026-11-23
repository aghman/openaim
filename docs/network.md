# The daemon on the network (`internal/daemon`, M1)

How `openaimd` connects the IP pieces — `internal/transport/ip` ([ip-rotation-and-dht.md](ip-rotation-and-dht.md)),
`internal/rendezvous` ([spec/dht-records.md](../spec/dht-records.md)), `internal/router` and `internal/presence`
([presence.md](presence.md)) — so two daemons on different networks can IM with presence (design §14, M1).

## Running it

```bash
openaimd network init          # writes network.json (bootstrap + relay nodes) into the data dir, to edit
openaimd run                   # joins the network; --listen ADDR (repeatable), --upnp, --offline
openaimd run --public          # a relay + DHT bootstrap node, for publicly reachable machines
openaim status --verbose       # peer ID, relay reservations, DHT, sessions, contact hint
```

- **`network.json`** in the data dir lists bootstrap and relay nodes (format in
  [ip-rotation-and-dht.md](ip-rotation-and-dht.md#bootstrap-and-relay-config-ipnetworkconfig)). A missing file means
  the built-in lists, which are **empty: no community nodes are operated yet**. Two daemons can only find each other
  once both list at least one common bootstrap node and, behind NAT, a relay. A broken file stops `run` with an error.
- **`--public`** gives the node a fixed peer ID (`network.key` in the data dir, created on first use), runs the DHT in
  server mode and a circuit relay service (`ip.OpenAIMLimit`: 1 h or 16 MiB per circuit) on TCP and QUIC port 4001
  unless `--listen` says otherwise, and takes no reservations
  itself. Its address, `/ip4/<public IP>/tcp/<port>/p2p/<peer ID>` (or `/dns4/<name>/…`), goes into everyone's
  `network.json`. Invite links refuse relays on private IP addresses, so a relay needs a public IP or a DNS name.
- **`--offline`** is the old queue-only daemon: no transports, messages stay queued.

## Lifecycle

`daemon.Open` with `Config.Network` set starts, in order: store → keystore / identity → `ip.Node` (first host,
relay reservations) + `ip.DHT` + `ip.Sessions` → rendezvous `Publisher` → `router.Router` (`Start` resumes the
outbox) → `presence.Tracker` (seeded from the stored presence) → then `internal/api` serves. `Close` reverses it:
the tracker signs off (OFFLINE to every buddy with a session, bounded by `SignOffTimeout`, 3 s), then the router, the
publisher and the sessions stop, the daemon's goroutines end, and the DHT, relay service and node close, before the
event bus and the store.

Background goroutines: the inbound loop, the session-event loop, router events → `message_updated`, presence
events, rendezvous lookups, and maintenance (`RedeliverRequests` every 10 min, `Receiver.Sweep`,
`FirstContactReceiver.Sweep` and `store.ExpireDedup` every 10 min). Best-effort sends and lookups share a bound of 32
in flight.

## One inbound path

Every frame from `sessions.Inbound()` goes through `handleFrame`, the code behind `HandleFrameFrom`:

1. FIRST_CONTACT frames: rate limit (per transport, `"ip"`), trial decryption, a BUDDY_REQUEST is recorded. Never
   answered automatically.
2. DATA frames: `Receiver.Accept`. A fresh (not duplicate) frame → `ReachTable.Heard(buddy, peer)` and the peer is
   attributed to the buddy.
3. A delivered message is handled by type: IM (history, `message_received`), BUDDY_ACCEPT (requests.go; its REACH
   feeds the reach table), PRESENCE / AWAY_MSG (tracker), PROFILE_REQ{away_msg} (reply with AWAY_MSG), REACH (reach
   table and `buddy_peer`), ACK (applied by the router).
4. Then `Router.Received` for partial, delivered and duplicate frames: it acks what we kept and applies ACK bodies.
   A message that failed to store is not acked, so the sender's retry gets another chance.

## Who is where (design §7.1)

A peer ID is attributed to a buddy only from authenticated content: a fresh frame from them over a session with the
peer, or their REACH or rendezvous record naming it. For each accepted buddy the daemon **keeps**
(`Sessions.Keep`) a session with the peer it last heard them on, so a relay reset or a dropped connection reconnects
at once; the old peer is dropped when they move (a rotation) and the kept session when they go offline. Session
Up/Down events for attributed peers go to the tracker.

Our own **REACH** (in requests, accepts and announcements) is the current peer ID and up to 8 addresses, relay
circuits first, valid 36 h, seq from a clock-based counter that never repeats across restarts. **Announcing** means
sending it to a buddy as a one-off DATA message: at start to every buddy with a known route, after every key rotation,
and to the peer a rendezvous lookup found. Their daemon takes it because it is authenticated, the session comes up,
and presence follows.

## Router, rendezvous, presence

- **Router**: `SessionsTransport`, the ACK sealer (IP layout, seq 0, not persisted), `ReachTable.OnChange →
  RouteChanged`. `SendIM` and BUDDY_ACCEPT go through the outbox; the router sends, retries and marks them acked.
  Router events for IMs become `message_updated` (queued → sent → acked, or failed). Blocking a buddy fails their
  queued messages.
- **Rendezvous**: a record for every accepted buddy and every buddy we asked (so they find us once they accept),
  republished on rotation and address changes. Accepted buddies without a live session are looked up with backoff
  (30 s doubling to 30 min), and at once when an IM is queued for them; `LookupBuddy` does it on demand.
- **Presence**: the tracker's Sender seals PRESENCE (no ACK, not persisted, seq from the same counter so two in one
  second don't tie) and sends it on the buddy's route. Transitions become `buddy_presence` events (with door open /
  door close); `FetchAway` sends PROFILE_REQ; `SetPresence` and the `Activity` RPC feed it; own changes it makes by
  itself (auto-away) are persisted. `ListBuddies` shows the tracker's view.

## Tests

`internal/daemon/nettest` runs a loopback relay + bootstrap node named `relay.test` (a resolver maps the name to
127.0.0.1: invite links refuse private relay IPs) and a gater that forces every other connection onto relay
circuits. `TestNetworkTwoDaemons` (daemon) and `TestNetworkOverAPI` (api, over gRPC) run the M1 scenario with short
timings; `TestNetworkRestart` restarts both daemons with stale addresses and recovers through rendezvous.

## Not yet

- Community bootstrap and relay nodes (the default lists are empty), so the two-machine M1 test needs an operator
  node (`openaimd run --public`) listed in both `network.json` files.
- An invite's contact hint names our current peer ID, which changes at the daily rotation (and every restart): an
  invite is good until then. Mailboxes (M3) fix this.
- Mesh reachability in the router (M2), delivery tokens, gateways and mailboxes (M3).
