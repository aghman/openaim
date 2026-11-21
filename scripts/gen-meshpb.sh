#!/usr/bin/env bash
# Regenerates internal/meshpb from the pinned Meshtastic protobufs submodule.
# Requires protoc and protoc-gen-go (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest).
set -euo pipefail
cd "$(dirname "$0")/.."

PROTO_DIR=third_party/meshtastic-protobufs
OUT_PKG=github.com/aghman/openaim/internal/meshpb
FILES=(mesh channel config module_config telemetry portnums xmodem device_ui atak field_metadata)

mopts=()
for f in "${FILES[@]}"; do
  mopts+=("--go_opt=Mmeshtastic/$f.proto=$OUT_PKG;meshpb")
done

rm -f internal/meshpb/*.pb.go
protoc -I "$PROTO_DIR" \
  --go_out=internal/meshpb --go_opt=paths=source_relative "${mopts[@]}" \
  $(printf "$PROTO_DIR/meshtastic/%s.proto " "${FILES[@]}")

# paths=source_relative writes into internal/meshpb/meshtastic/; flatten into the package dir.
mv internal/meshpb/meshtastic/*.pb.go internal/meshpb/
rmdir internal/meshpb/meshtastic
