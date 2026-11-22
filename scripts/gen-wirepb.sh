#!/usr/bin/env bash
# Regenerates internal/wirepb from proto/openaim/v1/*.proto.
# Requires protoc and protoc-gen-go (go install google.golang.org/protobuf/cmd/protoc-gen-go@latest).
set -euo pipefail
cd "$(dirname "$0")/.."

rm -f internal/wirepb/*.pb.go
protoc -I proto --go_out=internal/wirepb --go_opt=paths=source_relative proto/openaim/v1/*.proto
# paths=source_relative writes into internal/wirepb/openaim/v1/; flatten.
mv internal/wirepb/openaim/v1/*.pb.go internal/wirepb/
rm -r internal/wirepb/openaim
