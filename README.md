# openaim
Instant messenger in the style of AOL Instant Messenger, uses both TCP/IP and Meshtastic to communicate.

See [docs/design.md](docs/design.md) for the architecture design (draft), and [spec/wire.md](spec/wire.md) for the
wire format draft with its golden vectors. The M0 spikes:

- [docs/m0-meshtastic-spike.md](docs/m0-meshtastic-spike.md): Go ⇄ Meshtastic radio (`cmd/meshspike`)
- [docs/m0-libp2p-relay-spike.md](docs/m0-libp2p-relay-spike.md): libp2p peers through a circuit relay (`cmd/p2pspike`)

```bash
git submodule update --init   # Meshtastic protobufs (only needed to regenerate internal/meshpb)
go build -o bin/ ./cmd/...
go test ./...
```
