#!/bin/sh
# The helper upserts a site (`node site.cjs <site> <source_type> <mode> '<policy>'`) and prints rows (`rows <source> [n]`).
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
: "${IPSCANNER_KEY_FILE:?set IPSCANNER_KEY_FILE}"
: "${IPSCANNER_E2E_SITE_HELPER:?set IPSCANNER_E2E_SITE_HELPER}"
IPSCANNER_API_URL=${IPSCANNER_API_URL:-http://localhost:3050}
IPSCANNER_E2E_SITE=${IPSCANNER_E2E_SITE:-site_edgegoe2e00000000001}
export IPSCANNER_KEY_FILE IPSCANNER_E2E_SITE_HELPER IPSCANNER_API_URL IPSCANNER_E2E_SITE

cd "$root"
go test -tags e2e -race -count=1 -run E2E -v .

node "$IPSCANNER_E2E_SITE_HELPER" "$IPSCANNER_E2E_SITE" forward_auth enforce '{"tor":"block"}' >/dev/null
IPSCANNER_SITE_ID=$IPSCANNER_E2E_SITE sh test/yaegi/run.sh
