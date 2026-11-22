# Presence state machine (`internal/presence`)

Implements design.md §6.1 and §11.1 for IP. Mesh beacons (§6.2) are M2.

## Inputs and outputs

The daemon owns the transports and the crypto. The `Tracker` only sees:

| Input | Meaning |
|-------|---------|
| `SetBuddies` / `AddBuddy` / `RemoveBuddy` | the accepted set. Every other input naming a buddy outside it returns `ErrNotAccepted` and nothing is sent to them (§5.4). |
| `SessionUp(buddy, peer)` / `SessionDown(buddy, peer)` | `ip.Sessions` Up/Down events, after the daemon has attributed the peer to a buddy |
| `Received(buddy, stamp, *Presence)` | an authenticated PRESENCE (after AEAD, window and dedup checks) |
| `ReceivedAwayMsg(buddy, *AwayMsg)` | the reply to a fetch |
| `Set` / `SetState` / `SetAwayMessage` / `SetMeshNode` / `Activity` | our own state |

Outputs: PRESENCE bodies through `Sender.SendPresence(ctx, Recipient, *Presence)`, where only the
Tracker can make a `Recipient`, and only for an accepted buddy. `Events()` gives buddy `Transition`s,
`FetchAway` requests, `AwayMessage` arrivals and `OwnChange`s. `AwayReply` answers `ProfileReq{away_msg}`.

## Own presence

- **When we send:** when a buddy's first session comes up ("door open"), when what buddies see changes
  (state, becoming idle or active, away rev, mesh node), when a buddy we had as offline sends an online
  PRESENCE (they may have just accepted us), on a heartbeat every 4 min ± 30 s to each buddy with a
  session up, and OFFLINE on `SignOff`.
- **Coalescing:** sends are coalesced per buddy, built when sent, and never run concurrently for one buddy.
  A failed send is retried after 20 s as an early heartbeat.
- **Heartbeat interval:** 4 min + 30 s is under the 10-minute session idle timeout, so heartbeats also keep
  live sessions open. No separate keepalive is needed.
- **Idle:** idle starts after 10 min without `Activity`. Detection begins with the first `Activity` report,
  so a daemon without a UI never looks idle. `idle_minutes` is at least 1 while idle and grows with each heartbeat.
- **Auto-away:** off by default (`AutoAwayAfter`). It switches Online to Away and switches back on activity.
  An explicit `SetState` turns it off until the next activity.
- **`away_rev`:** a 32-bit FNV-1a hash of the away text, 0 for none. It changes with the text without being
  persisted. Going back to an old text brings back a rev that buddies still have cached.
  The text itself is never in PRESENCE.

## Buddy presence

A buddy's state is set only by their authenticated PRESENCE (§7.1). A session coming up never shows a
buddy online by itself.

| Event | Effect |
|-------|--------|
| PRESENCE ONLINE/AWAY (newer stamp) | state, idle, away rev and mesh node are updated; any grace is cancelled; the heartbeat deadline moves to now + 10 min |
| PRESENCE OFFLINE | OFFLINE, `signed-off` |
| last session Down while shown online | the grace starts (3 min) |
| a session Up or a PRESENCE within the grace | the grace is cancelled. No transition, so a relay reset doesn't flap. |
| grace expires | OFFLINE, `door-close` |
| no PRESENCE for 2.5 × 4 min = 10 min | OFFLINE, `heartbeat-timeout` |
| removed from the accepted set | OFFLINE, `removed`, then forgotten |

- **Stale bodies:** a PRESENCE whose `(timestamp, seq)` is not after the last applied one returns `ErrStale`.
  One exception: once a buddy has been OFFLINE for longer than the grace, any stamp is accepted again, so a
  buddy whose clock stepped back recovers. Replays are already stopped by the frame layer's dedup.
- **Transitions:** a `Transition` is emitted whenever the state, idleness, away rev or mesh node shown for a
  buddy changes. `DoorOpen()` and `DoorClose()` tell the UI when to play the sounds.
- **Away messages:** they're fetched on demand. `FetchAway` fires when the buddy is AWAY with an uncached
  nonzero rev, and again after 2 min if the reply hasn't come. The last 4 revs are cached per buddy.

## Concurrency

One scheduling goroutine runs, plus `SendWorkers` (4) senders. The Sender is never called with the lock held.
`Events()` is buffered (256). When it's full, events are dropped and counted, and `Buddies()` and `Own()` let
the consumer resync. `Close` cancels in-flight sends and closes `Events()`. Time comes from an injectable `Clock`.
