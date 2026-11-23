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
bin/openaimd                   # unlock, join the network and serve (same as: openaimd run)
bin/openaimd network init      # write network.json (bootstrap and relay nodes) to edit
bin/openaimd run --public      # a relay + DHT bootstrap node with a fixed peer ID, for public machines
```

The keystore passphrase comes from `--passphrase-file`, `$OPENAIM_PASSPHRASE`, or a terminal prompt.
No community bootstrap or relay nodes are operated yet: list one you run (`--public`) in both daemons'
`network.json`. How the daemon wires the network is in [docs/network.md](docs/network.md).
Regenerate the API stubs with `scripts/gen-apipb.sh` (needs `protoc-gen-go` and `protoc-gen-go-grpc`).

## The CLI

`openaim` is a scriptable client of a running daemon (same `--data-dir` / `$OPENAIM_DATA_DIR`).
Buddies are named by identity key, key ID (`~k3f9`), petname or handle.

```bash
bin/openaim status [--verbose]                       # identity, presence, counts
bin/openaim add <identity-key> --petname Bob         # add a buddy (pending until they accept)
bin/openaim buddies                                  # the list, by group, with verified marks
bin/openaim verify Bob [--confirm]                   # safety number; --confirm marks it checked
bin/openaim send Bob "you going friday?"             # prints the msg_id
echo "from a script" | bin/openaim send Bob -        # text from stdin
bin/openaim history Bob --limit 20
bin/openaim away "at class. %n, IM me later"; bin/openaim back
bin/openaim watch --json                             # one event per line until the daemon stops
bin/openaim backup export --out ~/oa-backup          # encrypted, mode 0600; --show-phrase, --force
bin/openaim remove Bob; bin/openaim shutdown; bin/openaim version
```

`--json` prints one JSON object per result (the API's messages in proto3 JSON with `.proto` field names);
errors then go to stderr as `{"error":…,"code":…,"exit_code":…}`. Exit codes: 0 ok, 1 error, 2 usage,
3 daemon not running, 4 no such buddy, 5 buddy already added. The backup passphrase comes from
`--passphrase-file`, `$OPENAIM_BACKUP_PASSPHRASE`, or a terminal prompt. `openaim help <command>` has the details.

## The TUI

```bash
bin/openaim tui               # buddy list + IM window, against a running openaimd
bin/openaim tui --embedded    # no daemon running? run one inside the TUI while it is open
```

The buddy list (left) shows your groups with who is on, then an Offline group; groups collapse with
Space or ←/→. The IM window (right) shows the history with `[queued]`/`[sent]`/`[delivered]`/`[failed]` marks and
a byte counter for the mesh route ("159 bytes left (1/4)": 159 B in the first fragment, 166 B in each
later one, up to 4 = 657 B). Contacts whose safety number you haven't checked are italic, with a ⚠ badge
and their key ID. Keys: Tab switch, Enter open/send, Ctrl+N new IM, Ctrl+A away/back, Ctrl+B add
buddy, `v` verify, `x` remove, F1 or `?` help, Ctrl+C quit. If the daemon stops, the TUI says so and
reconnects by itself. Without `--embedded` it asks before starting a daemon; the passphrase then comes from
`--passphrase-file`, `$OPENAIM_PASSPHRASE` or a prompt, before the screen opens. `NO_COLOR` turns colors off
(bold, italic and reverse stay).
