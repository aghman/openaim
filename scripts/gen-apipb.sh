#!/usr/bin/env bash
# Regenerates internal/apipb (the openaimd local API) from proto/openaim/api/v1/*.proto.
# Requires protoc, protoc-gen-go and protoc-gen-go-grpc:
#   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
#   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
#
# The API protos live outside proto/openaim/v1 so scripts/gen-wirepb.sh, which
# compiles every file there, never picks them up.
set -euo pipefail
cd "$(dirname "$0")/.."

rm -f internal/apipb/*.pb.go
protoc -I proto \
  --go_out=internal/apipb --go_opt=paths=source_relative \
  --go-grpc_out=internal/apipb --go-grpc_opt=paths=source_relative \
  proto/openaim/api/v1/*.proto
# paths=source_relative writes into internal/apipb/openaim/api/v1/; flatten.
mv internal/apipb/openaim/api/v1/*.pb.go internal/apipb/
rm -r internal/apipb/openaim
