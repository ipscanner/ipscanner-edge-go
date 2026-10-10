#!/bin/sh
# Runs test/yaegi/main.go under Yaegi with a GOPATH layout, the way Traefik
# loads plugins. Stub API by default; real API with
#   IPSCANNER_API_URL=http://localhost:3050 IPSCANNER_KEY_FILE=/path/to/key sh test/yaegi/run.sh
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
version=${YAEGI_VERSION:-v0.16.1}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
GOBIN="$work/bin" go install "github.com/traefik/yaegi/cmd/yaegi@$version"
mkdir -p "$work/gopath/src/github.com/ipscanner"
ln -s "$root" "$work/gopath/src/github.com/ipscanner/ipscanner-edge-go"
if [ -n "${IPSCANNER_KEY_FILE:-}" ]; then
	IPSCANNER_API_KEY=$(tr -d '[:space:]' < "$IPSCANNER_KEY_FILE")
	export IPSCANNER_API_KEY
fi
GOPATH="$work/gopath" "$work/bin/yaegi" run "$work/gopath/src/github.com/ipscanner/ipscanner-edge-go/test/yaegi/main.go"
