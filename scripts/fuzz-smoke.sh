#!/usr/bin/env bash
# Runs every Go fuzz target in the module for a short time each.
# Usage: scripts/fuzz-smoke.sh [duration]   (default 20s per target)
#
# go test -fuzz takes one package and one target at a time, so this lists
# the targets per package and runs them one by one. A crash leaves its input
# under the package's testdata/fuzz/ and fails the script.
set -euo pipefail
cd "$(dirname "$0")/.."
time=${1:-20s}

found=0
for pkg in $(go list ./...); do
	targets=$(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)
	for target in $targets; do
		found=$((found + 1))
		echo "== $pkg $target ($time)"
		go test -run '^$' -fuzz "^${target}\$" -fuzztime "$time" "$pkg"
	done
done
if [ "$found" -eq 0 ]; then
	echo "no fuzz targets found" >&2
	exit 1
fi
echo "ran $found fuzz targets"
