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
# Then the capability examples docs/client-examples.md describes: leg
# correlation across two sipnabs, vCon exports checked against the working
# group's schema file, a HEP collector fed by two sipnab agents, and the BPF
# record decode behind TLS without keys. Every sipnab runs on loopback.
#
# Needs: a sipnab built with `--all-features --bins --examples` (default
# target/debug/sipnab; the TLS example is read from beside it), go, node
# (22.18 or later, which runs .ts files), curl, the npm packages installed in
# clients/typescript (`npm ci`), and a Python with the MCP SDK from
# clients/python/requirements-mcp.txt, which brings jsonschema ($PYTHON,
# default python3). CI provides all of these; a missing one fails, never
# skips.

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
[ -x "$(dirname "$BIN")/examples/tls_plaintext_records" ] || {
	echo "smoke-clients: build the examples too: cargo build --all-features --bins --examples" >&2
	exit 1
}
[ -d clients/typescript/node_modules ] || {
	echo "smoke-clients: run 'npm ci' in clients/typescript first" >&2
	exit 1
}

WORK="$(mktemp -d)"
# Every sipnab this script starts, so an early exit stops all of them.
PIDS=()
cleanup() {
	local pid
	for pid in "${PIDS[@]}"; do
		kill "$pid" 2>/dev/null || true
		wait "$pid" 2>/dev/null || true
	done
	rm -rf "$WORK"
}
trap cleanup EXIT

FAILED=0
fail() {
	echo "FAIL: $*" >&2
	FAILED=$((FAILED + 1))
}

# A free loopback port, so a second run on the same machine does not collide.
free_port() {
	"$PYTHON" -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
PORT="$(free_port)"
export SIPNAB_URL="http://127.0.0.1:$PORT"
export SIPNAB_API_KEY="smoke-$$-token"

# serve NAME PORT ARG... : start a sipnab with ARGs serving REST on PORT. Its
# log is $WORK/NAME.log; its pid joins PIDS and is left in SERVED_PID.
serve() {
	local name="$1" port="$2"
	shift 2
	"$BIN" -N --quiet --no-cli-print "$@" \
		--api "127.0.0.1:$port" >/dev/null 2>"$WORK/$name.log" &
	SERVED_PID=$!
	PIDS+=("$SERVED_PID")
}

# wait_for NAME PID URL PATTERN : poll URL until its body matches PATTERN.
# Evidence, never a fixed sleep: sipnab drops whatever it has not processed
# when it stops, so the checks below must start only once it has.
wait_for() {
	local name="$1" pid="$2" url="$3" pattern="$4"
	for _ in $(seq 600); do
		if ! kill -0 "$pid" 2>/dev/null; then
			echo "smoke-clients: the $name sipnab exited before it was ready:" >&2
			cat "$WORK/$name.log" >&2
			exit 1
		fi
		if curl -sf -H "Authorization: Bearer $SIPNAB_API_KEY" "$url" 2>/dev/null |
			grep -qE -- "$pattern"; then
			return 0
		fi
		sleep 0.1
	done
	echo "smoke-clients: the $name sipnab never matched '$pattern' at $url in 60s" >&2
	cat "$WORK/$name.log" >&2
	exit 1
}

serve sipnab "$PORT" \
	-I tests/pcap-samples/sip-problem-call.pcap \
	-I tests/fixtures/turn_relay.pcap

# Ready means the API answers AND the replay is finished: `source_exhausted`
# turns true once the last packet is read, so the counts asserted below are
# final rather than whatever had been parsed when the socket opened.
wait_for sipnab "$SERVED_PID" "$SIPNAB_URL/v1/stats" '"source_exhausted":true'

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

# expect_exit LABEL STATUS LINE... -- COMMAND...
# COMMAND must exit with STATUS and print every LINE as a whole line of its
# stdout: for a program whose refusal is its answer.
expect_exit() {
	local label="$1" status="$2"
	shift 2
	local want=()
	while [ "$1" != "--" ]; do
		want+=("$1")
		shift
	done
	shift
	local got=0
	"$@" >"$WORK/out" 2>"$WORK/err" || got=$?
	if [ "$got" != "$status" ]; then
		fail "$label exited $got, not $status: $(head -c 400 "$WORK/err") $(head -c 400 "$WORK/out")"
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

# ── Capability examples: what only sipnab does ───────────────────────────

# Leg correlation. One call, two capture points: tests/fixtures/opensips-
# proxy-signaling.pcap is the proxy's view (SIP, no media) and
# tests/fixtures/rtpengine-opensips-ng.pcap the relay's (media and the relay's
# ng control plane over HEP, no SIP). Two sipnabs replay them on loopback and
# leg_correlate.py joins the proxy's dialog to the relay's streams.
PROXY_PORT="$(free_port)"
serve proxy "$PROXY_PORT" --node-name proxy -I tests/fixtures/opensips-proxy-signaling.pcap
PROXY_PID="$SERVED_PID"
RELAY_PORT="$(free_port)"
serve relay "$RELAY_PORT" --node-name relay -I tests/fixtures/rtpengine-opensips-ng.pcap
wait_for proxy "$PROXY_PID" "http://127.0.0.1:$PROXY_PORT/v1/stats" '"source_exhausted":true'
wait_for relay "$SERVED_PID" "http://127.0.0.1:$RELAY_PORT/v1/stats" '"source_exhausted":true'
printf '%s\n' "$SIPNAB_API_KEY" >"$WORK/api.key"
expect "python leg_correlate (proxy + relay)" \
	"1-4062@198.51.100.21     Completed   200   2     40      G722,PCMU  4.22  yes" \
	"  1 call(s) correlated across both nodes" \
	-- "$PYTHON" clients/python/leg_correlate.py --key-file "$WORK/api.key" \
	--proxy "http://127.0.0.1:$PROXY_PORT" --relay "http://127.0.0.1:$RELAY_PORT"
# Both URLs at one sipnab is one witness, not two, and must be refused.
if "$PYTHON" clients/python/leg_correlate.py --key-file "$WORK/api.key" \
	--proxy "http://127.0.0.1:$PROXY_PORT" --relay "http://127.0.0.1:$PROXY_PORT" \
	>"$WORK/out" 2>"$WORK/err"; then
	fail "leg_correlate.py correlated one sipnab with itself"
elif ! grep -q "same capture instance" "$WORK/err"; then
	fail "leg_correlate.py refused one sipnab twice without saying why: $(head -c 400 "$WORK/err")"
else
	echo "ok   python leg_correlate refuses one node counted twice"
fi

# vCon export, validated against the working group's schema file as its
# publisher committed it (tests/schemas/publisher/vcon_json_schema.json) by
# an engine sipnab did not write. A failed call exports a typed Dialog Object
# and must pass. A completed call with no media exports one with no `type`,
# sipnab's one documented deviation: the publisher's file must refuse it
# naming `type`, and sipnab's own copy must accept it. A container whose
# created_at is not a date-time must be refused, which jsonschema alone
# would not do.
"$BIN" -N --quiet --no-cli-print -I tests/pcap-samples/sip-problem-call.pcap \
	--export-vcon "$CALL_ID" --vcon-out "$WORK/failed.vcon" >/dev/null 2>"$WORK/vcon.log" ||
	fail "sipnab did not export $CALL_ID: $(head -c 400 "$WORK/vcon.log")"
"$BIN" -N --quiet --no-cli-print -I tests/fixtures/opensips-proxy-signaling.pcap \
	--export-vcon 1-4062@198.51.100.21 --vcon-out "$WORK/completed.vcon" >/dev/null 2>"$WORK/vcon.log" ||
	fail "sipnab did not export 1-4062@198.51.100.21: $(head -c 400 "$WORK/vcon.log")"
"$PYTHON" -c 'import json, sys; c = json.load(open(sys.argv[1])); c["created_at"] = "yesterday"; json.dump(c, open(sys.argv[2], "w"))' \
	"$WORK/failed.vcon" "$WORK/undated.vcon"
PUBLISHED_ID="checked against https://ietf.org/vcon/schemas/unsigned-vcon.json (tests/schemas/publisher/vcon_json_schema.json)"
expect "python vcon_validate (a failed call)" "$PUBLISHED_ID" "valid    $WORK/failed.vcon" \
	-- "$PYTHON" clients/python/vcon_validate.py --schema tests/schemas/publisher/vcon_json_schema.json "$WORK/failed.vcon"
expect_exit "python vcon_validate (no type, publisher's file)" 1 \
	"invalid  $WORK/completed.vcon" "  /dialog/0: 'type' is a required property" \
	-- "$PYTHON" clients/python/vcon_validate.py --schema tests/schemas/publisher/vcon_json_schema.json "$WORK/completed.vcon"
expect "python vcon_validate (no type, sipnab's copy)" "valid    $WORK/completed.vcon" \
	-- "$PYTHON" clients/python/vcon_validate.py --schema tests/schemas/vcon.schema.json "$WORK/completed.vcon"
expect_exit "python vcon_validate (created_at not a date-time)" 1 \
	"invalid  $WORK/undated.vcon" "  /created_at: 'yesterday' is not a 'date-time'" \
	-- "$PYTHON" clients/python/vcon_validate.py "$WORK/undated.vcon"

# HEP fan-in. One sipnab is the collector (--hep-listen on loopback); two
# more are the peers, each replaying a committed capture to it with
# --hep-send under its own capture id. hep_senders.py must name both senders
# with what each sent, and the collector must report the dialogs of both
# captures. Checked only once the collector's own counters show every packet
# admitted and every dialog built: it drops unprocessed input when it stops.
HEP_PORT="$("$PYTHON" -c 'import socket; s = socket.socket(type=socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
COLLECTOR_PORT="$(free_port)"
COLLECTOR="http://127.0.0.1:$COLLECTOR_PORT"
serve collector "$COLLECTOR_PORT" --node-name collector --hep-listen "127.0.0.1:$HEP_PORT"
COLLECTOR_PID="$SERVED_PID"
wait_for collector "$COLLECTOR_PID" "$COLLECTOR/v1/hep/senders" '"listening":true'
# hep_agent ID CAPTURE : replay CAPTURE to the collector as capture id ID.
hep_agent() {
	"$BIN" -N --quiet --no-cli-print -I "$2" --hep-send "127.0.0.1:$HEP_PORT" --hep-id "$1" \
		>/dev/null 2>"$WORK/agent-$1.log" ||
		fail "HEP agent $1 did not replay $2: $(head -c 400 "$WORK/agent-$1.log")"
}
hep_agent 101 tests/pcap-samples/sip-problem-call.pcap
hep_agent 102 tests/fixtures/sip_call.pcap
wait_for collector "$COLLECTOR_PID" "$COLLECTOR/v1/hep/senders" '"packets_admitted":30,'
wait_for collector "$COLLECTOR_PID" "$COLLECTOR/v1/stats" '"completed":2,"failed":4,"in_call":0,"total":6'
expect "python hep_senders (two agents, one collector)" \
	"hep:101@127.0.0.1  capture id 101  23 packets" \
	"hep:102@127.0.0.1  capture id 102  7 packets" \
	"2 sender(s), 30 packet(s) admitted, 0 refused" \
	-- env SIPNAB_URL="$COLLECTOR" "$PYTHON" clients/python/hep_senders.py
expect "python stats (the collector)" "Dialogs: 6 total, 0 active, 4 failed" \
	-- env SIPNAB_URL="$COLLECTOR" "$PYTHON" clients/python/stats.py
expect "python get-dialog (a call agent 102 sent)" "State: Completed, Messages: 7" \
	-- env SIPNAB_URL="$COLLECTOR" "$PYTHON" clients/python/get_dialog.py test-call-1@192.0.2.1
# A sipnab with no HEP listener has no roster, and saying so is the answer.
expect_exit "python hep_senders (no listener)" 1 \
	-- "$PYTHON" clients/python/hep_senders.py
grep -q "no HEP listener" "$WORK/err" || fail "hep_senders.py did not say the sipnab has no HEP listener: $(head -c 400 "$WORK/err")"

# TLS read without keys, through the BPF backend: the analysis half. The
# live half installs uprobes and needs root and a kernel with BTF, which no
# CI runner offers. What sipnab does with what the kernel hands it does not:
# examples/tls_plaintext_records.rs feeds records laid out exactly as the BPF
# program publishes them through the same decode the backend runs, and must
# report each peer the program paired, no peer where it paired none, and
# nothing for a write that is not SIP. Cargo builds it beside the binary.
TLS_EXAMPLE="$(dirname "$BIN")/examples/tls_plaintext_records"
expect "rust tls_plaintext_records (BPF records, no kernel)" \
	"REGISTER   127.0.0.1:36160 -> 127.0.0.1:15061  TCP  uprobe:python3/349147#0" \
	"200 OK     127.0.0.1:15061 -> 127.0.0.1:36160  TCP  uprobe:python3/349147#1" \
	"OPTIONS    0.0.0.0:0 -> 0.0.0.0:0  TCP  uprobe:python3/349147#2" \
	"record 3 dropped: not a SIP message" \
	"4 records, 3 SIP messages, 2 dialogs" \
	"REGISTER  Registered  alice -> alice  (2 messages)  tls-reg-1@127.0.0.1" \
	"OPTIONS   Trying  alice -> ?  (1 messages)  tls-opt-1@127.0.0.1" \
	-- "$TLS_EXAMPLE"

if [ "$FAILED" -ne 0 ]; then
	echo "smoke-clients: $FAILED check(s) failed" >&2
	exit 1
fi
echo "smoke-clients: every client program ran and printed what its page says"
