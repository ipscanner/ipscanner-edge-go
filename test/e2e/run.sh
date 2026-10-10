#!/bin/sh
# End to end run against a local IPScanner API: the Go e2e tests, then the
# Yaegi program with a real API call.
#
#   IPSCANNER_KEY_FILE=/path/to/key \
#   IPSCANNER_E2E_SITE_HELPER=/path/to/site.cjs \
#   sh test/e2e/run.sh
#
# IPSCANNER_API_URL defaults to http://localhost:3050. The helper is a node
# script: `node site.cjs <site> <source_type> <mode> '<policy>'` upserts a
# test site, `node site.cjs rows <source> [n]` prints request_log rows.
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
