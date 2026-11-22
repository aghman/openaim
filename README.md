# openaim
Instant messenger in the style of AOL Instant Messenger, uses both TCP/IP and Meshtastic to communicate.

See [docs/design.md](docs/design.md) for the architecture design (draft), [spec/wire.md](spec/wire.md) for the
wire format draft with its golden vectors, and [spec/backup.md](spec/backup.md) for the backup and keystore files. The M0 spikes:

- [docs/m0-meshtastic-spike.md](docs/m0-meshtastic-spike.md): Go ⇄ Meshtastic radio (`cmd/meshspike`)
- [docs/m0-libp2p-relay-spike.md](docs/m0-libp2p-relay-spike.md): libp2p peers through a circuit relay (`cmd/p2pspike`)

```bash
git submodule update --init   # Meshtastic protobufs (only needed to regenerate internal/meshpb)
go build -o bin/ ./cmd/...
go test ./...
```

## The daemon

`openaimd` owns the identity, buddy list and message store and serves the local gRPC API
([proto/openaim/api/v1/api.proto](proto/openaim/api/v1/api.proto)) on `openaimd.sock` in its data directory
(macOS `~/Library/Application Support/openaim`, Linux `$XDG_DATA_HOME/openaim` or `~/.local/share/openaim`,
Windows `%AppData%\openaim`; override with `--data-dir` or `$OPENAIM_DATA_DIR`).

```bash
bin/openaimd init              # create an identity; prints the 24-word recovery phrase once
bin/openaimd init --restore    # or restore one (phrase read from the terminal or stdin)
bin/openaimd                   # unlock and serve (same as: openaimd run)
```

The keystore passphrase comes from `--passphrase-file`, `$OPENAIM_PASSPHRASE`, or a terminal prompt.
Regenerate the API stubs with `scripts/gen-apipb.sh` (needs `protoc-gen-go` and `protoc-gen-go-grpc`).
