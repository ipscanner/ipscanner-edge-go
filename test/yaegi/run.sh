#!/bin/sh
# Yaegi needs a GOPATH layout, like Traefik; set IPSCANNER_API_URL and IPSCANNER_KEY_FILE for the real API.
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
