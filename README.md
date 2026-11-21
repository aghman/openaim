# openaim
Instant messenger in the style of AOL Instant Messenger, uses both TCP/IP and Meshtastic to communicate.

See [docs/design.md](docs/design.md) for the architecture design (draft), and
[docs/m0-meshtastic-spike.md](docs/m0-meshtastic-spike.md) for the first spike (Go ⇄ Meshtastic radio).

```bash
git submodule update --init   # Meshtastic protobufs (only needed to regenerate internal/meshpb)
go build -o bin/ ./cmd/...
go test ./...
```
