#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run every client program the reference pages quote against a real sipnab.
#
#   scripts/smoke-clients.sh [path/to/sipnab]
#
# docs/rest-api.md, docs/prometheus-metrics.md and docs/mcp-deploy.md show
# regions of the programs under clients/ (tests/client_snippets_test.rs holds
# each fence to its region). Compiling a program proves it is a program. This
# proves it does what the page says: each one runs against a sipnab replaying
# committed captures, must exit 0, and must print the lines those captures
# produce. Each REST program then runs again with a wrong token and must exit
# non-zero naming the 401, because a client that swallows an error prints a
# zero value and looks like a quiet network.
#
# The captures: tests/pcap-samples/sip-problem-call.pcap holds four failed
# dialogs and one completed one, and tests/fixtures/turn_relay.pcap two RTP
# streams whose MOS is below 3.0. No single committed capture has both, and
# every documented query needs one or the other.
#
# Needs: a sipnab built with the `api` and `mcp` features (default
# target/debug/sipnab), go, node (22.18 or later, which runs .ts files), curl,
# the npm packages installed in clients/typescript (`npm ci`), and a Python
# with the MCP SDK from clients/python/requirements-mcp.txt ($PYTHON, default
# python3). CI provides all of these; a missing one fails, never skips.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Resolved before the cd below, so a relative path means relative to the caller.
BIN="$(realpath -- "${1:-$ROOT/target/debug/sipnab}")"
PYTHON="${PYTHON:-python3}"
cd "$ROOT"

for tool in go node curl "$PYTHON"; do
	command -v "$tool" >/dev/null || { echo "smoke-clients: $tool not found" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "smoke-clients: no sipnab binary at $BIN" >&2; exit 1; }
[ -d clients/typescript/node_modules ] || {
	echo "smoke-clients: run 'npm ci' in clients/typescript first" >&2
	exit 1
}

WORK="$(mktemp -d)"
SIPNAB_PID=""
cleanup() {
	if [ -n "$SIPNAB_PID" ]; then
		kill "$SIPNAB_PID" 2>/dev/null || true
		wait "$SIPNAB_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

FAILED=0
fail() {
	echo "FAIL: $*" >&2
	FAILED=$((FAILED + 1))
}

# A free loopback port, so a second run on the same machine does not collide.
PORT="$("$PYTHON" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
export SIPNAB_URL="http://127.0.0.1:$PORT"
export SIPNAB_API_KEY="smoke-$$-token"

"$BIN" -N --quiet --no-cli-print \
	-I tests/pcap-samples/sip-problem-call.pcap \
	-I tests/fixtures/turn_relay.pcap \
	--api "127.0.0.1:$PORT" >/dev/null 2>"$WORK/sipnab.log" &
SIPNAB_PID=$!

# Ready means the API answers AND the replay is finished: `source_exhausted`
# turns true once the last packet is read, so the counts asserted below are
# final rather than whatever had been parsed when the socket opened.
ready=0
for _ in $(seq 600); do
	if ! kill -0 "$SIPNAB_PID" 2>/dev/null; then
		echo "smoke-clients: sipnab exited before it was ready:" >&2
		cat "$WORK/sipnab.log" >&2
		exit 1
	fi
	if curl -sf -H "Authorization: Bearer $SIPNAB_API_KEY" "$SIPNAB_URL/v1/stats" 2>/dev/null |
		grep -q '"source_exhausted":true'; then
		ready=1
		break
	fi
	sleep 0.1
done
[ "$ready" = 1 ] || { echo "smoke-clients: sipnab not ready after 60s" >&2; cat "$WORK/sipnab.log" >&2; exit 1; }

# Build the Go programs once, into the scratch directory.
(cd clients/go && go build -o "$WORK/go/" ./...)

# expect LABEL LINE... -- COMMAND...
# COMMAND must exit 0 and print every LINE as a whole line of its stdout.
expect() {
	local label="$1"
	shift
	local want=()
	while [ "$1" != "--" ]; do
		want+=("$1")
		shift
	done
	shift
	if ! "$@" >"$WORK/out" 2>"$WORK/err"; then
		fail "$label exited non-zero: $(head -c 400 "$WORK/err")"
		return
	fi
	for line in "${want[@]}"; do
		grep -qxF -- "$line" "$WORK/out" || fail "$label did not print '$line'; it printed: $(head -c 400 "$WORK/out")"
	done
	echo "ok   $label"
}

# refuse LABEL -- COMMAND...
# COMMAND must exit non-zero, print nothing on stdout, and name the 401.
refuse() {
	local label="$1"
	shift 2
	if SIPNAB_API_KEY=wrong-token "$@" >"$WORK/out" 2>"$WORK/err"; then
		fail "$label exited 0 with a wrong token"
		return
	fi
	[ ! -s "$WORK/out" ] || fail "$label printed a result with a wrong token: $(head -c 200 "$WORK/out")"
	grep -q 401 "$WORK/err" || fail "$label did not name the 401: $(head -c 400 "$WORK/err")"
	echo "ok   $label refuses a wrong token"
}

# each NAME ARG LINE... : run the program NAME in all three languages.
each() {
	local name="$1" arg="$2"
	shift 2
	local py="clients/python/${name//-/_}.py"
	local args=()
	[ -z "$arg" ] || args=("$arg")
	expect "python $name" "$@" -- "$PYTHON" "$py" "${args[@]}"
	expect "go $name" "$@" -- "$WORK/go/$name" "${args[@]}"
	expect "javascript $name" "$@" -- node "clients/javascript/$name.mjs" "${args[@]}"
}

CALL_ID="busy-3a2b1c@192.0.2.30"
SSRC="0x11223344"

each health "" "ok"
expect "python list-dialogs" "busy-3a2b1c@192.0.2.30: Failed (4 msgs)" -- "$PYTHON" clients/python/list_dialogs.py
expect "go list-dialogs" "busy-3a2b1c@192.0.2.30: Failed (4 msgs)" "4 dialogs (4 total)" -- "$WORK/go/list-dialogs"
expect "javascript list-dialogs" "busy-3a2b1c@192.0.2.30: Failed" "4 dialogs (4 total)" -- node clients/javascript/list-dialogs.mjs
each get-dialog "$CALL_ID" "State: Failed, Messages: 4"
expect "python dialog-report" "Diagnosis: no issues detected" -- "$PYTHON" clients/python/dialog_report.py "$CALL_ID"
expect "go dialog-report" "Diagnosis: no issues detected" -- "$WORK/go/dialog-report" "$CALL_ID"
expect "javascript dialog-report" "  \"call_id\": \"$CALL_ID\"," -- node clients/javascript/dialog-report.mjs "$CALL_ID"
each list-streams "" "SSRC 0x11223344: MOS=1.0, loss=0.0%" "SSRC 0x55667788: MOS=1.0, loss=0.0%"
each get-stream "$SSRC" "Codec: PCMU, Packets: 75"
expect "python stats" "Dialogs: 5 total, 0 active, 4 failed" "PDD: p50=850ms, p95=850ms" -- "$PYTHON" clients/python/stats.py
expect "go stats" "Dialogs: 5 total, 0 active, 4 failed" -- "$WORK/go/stats"
expect "javascript stats" "Dialogs: 5 total, 0 active" "PDD p50: 850ms, p95: 850ms" -- node clients/javascript/stats.mjs
each metrics "" 'sipnab_dialogs_total{state="failed"} 4'

for name in list-dialogs get-dialog dialog-report list-streams get-stream stats metrics; do
	refuse "python $name" -- "$PYTHON" "clients/python/${name//-/_}.py"
	refuse "go $name" -- "$WORK/go/$name"
	refuse "javascript $name" -- node "clients/javascript/$name.mjs"
done

# health needs no token, so its failure case is an address nothing listens on.
# The port sipnab was given is free again only after it exits, so ask for a
# fresh one.
DEAD_PORT="$("$PYTHON" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
unreachable() {
	local label="$1"
	shift
	if SIPNAB_URL="http://127.0.0.1:$DEAD_PORT" "$@" >"$WORK/out" 2>"$WORK/err"; then
		fail "$label exited 0 with nothing listening"
	elif [ ! -s "$WORK/err" ]; then
		fail "$label failed silently with nothing listening"
	else
		echo "ok   $label reports an unreachable API"
	fi
}
unreachable "python health" "$PYTHON" clients/python/health.py
unreachable "go health" "$WORK/go/health"
unreachable "javascript health" node clients/javascript/health.mjs

# The MCP clients start their own sipnab over stdio, found on PATH.
PATH="$(dirname "$BIN"):$PATH"
export PATH
expect "python sipnab_mcp (stdio)" -- "$PYTHON" clients/python/sipnab_mcp.py tests/fixtures/turn_relay.pcap
grep -q '^find_problems ' "$WORK/out" || fail "sipnab_mcp.py listed no find_problems tool"
grep -q '"total_matched"' "$WORK/out" || fail "sipnab_mcp.py printed no find_problems result"
expect "typescript sipnab-mcp (stdio)" -- node clients/typescript/sipnab-mcp.ts tests/fixtures/turn_relay.pcap
grep -qE '^[0-9]+ tools available$' "$WORK/out" || fail "sipnab-mcp.ts printed no tool count"
grep -q '"total_matched"' "$WORK/out" || fail "sipnab-mcp.ts printed no find_problems result"

if [ "$FAILED" -ne 0 ]; then
	echo "smoke-clients: $FAILED check(s) failed" >&2
	exit 1
fi
echo "smoke-clients: every client program ran and printed what its page says"
