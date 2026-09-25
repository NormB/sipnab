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
# Next, the operator tasks: one program per multi-step cookbook recipe,
# triage to a verdict, failed calls by response code, one-way audio and whose
# loss it is, a scanner banned through TFPS, and one customer's calls
# exported from rotated captures and opened by tshark.
#
# Last, the AI tasks, over MCP: an agent triage over stdio and again over
# HTTP with a token minted from a signing key generated at run time, an
# evidence package and repro scripts written twice and compared byte for
# byte, and an aggregate cut to a model's byte budget.
#
# Needs: a sipnab built with `--all-features --bins --examples` (default
# target/debug/sipnab; the TLS example is read from beside it), go, node
# (22.18 or later, which runs .ts files), curl, tshark and capinfos (Ubuntu's
# tshark package), the npm packages installed in clients/typescript
# (`npm ci`), and a Python with the MCP SDK from
# clients/python/requirements-mcp.txt, which brings jsonschema ($PYTHON,
# default python3). CI provides all of these; a missing one fails, never
# skips.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Resolved before the cd below, so a relative path means relative to the caller.
BIN="$(realpath -- "${1:-$ROOT/target/debug/sipnab}")"
PYTHON="${PYTHON:-python3}"
cd "$ROOT"

for tool in go node curl tshark capinfos "$PYTHON"; do
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

# ── Operator tasks: one program per multi-step cookbook recipe ──────────
#
# The CLI programs run sipnab themselves and find it through SIPNAB_BIN; the
# REST ones ask one sipnab, "ops", serving three captures at once.
export SIPNAB_BIN="$BIN"

# Triage to one verdict (recipes 1 and 16). The exit status IS the verdict:
# 1 for findings, 0 for clean, 2 for a capture with nothing to judge, which
# --json-analyze alone reports as an empty, clean-looking list. 3 is sipnab
# failing to read the input at all.
expect_exit "python triage (four failed calls)" 1 \
	"problems: 23 frame(s), 5 dialog(s), 0 stream(s)" \
	"  major  server_failure  2 call(s)" \
	"    decline-7c6d5e@198.51.100.30  Decline" \
	"    unavail-4e5f60@192.0.2.50  Service Unavailable" \
	"  minor  request_failure  2 call(s)" \
	"    busy-3a2b1c@192.0.2.30  Busy Here" \
	"    notfound-1b2c3d@203.0.113.30  Not Found" \
	-- "$PYTHON" clients/python/triage.py tests/pcap-samples/sip-problem-call.pcap
expect "python triage (one clean call)" "clean: 7 frame(s), 1 dialog(s), 0 stream(s)" \
	-- "$PYTHON" clients/python/triage.py tests/fixtures/sip_call.pcap
expect_exit "python triage (no dialog to judge)" 2 \
	"inconclusive: 10 frame(s) and no SIP dialog or RTP stream to judge, so an empty finding list proves nothing" \
	-- "$PYTHON" clients/python/triage.py tests/fixtures/udp_5060.pcap
expect_exit "python triage (no such capture)" 3 \
	-- "$PYTHON" clients/python/triage.py "$WORK/no-such.pcap"
grep -q "does not exist" "$WORK/err" || fail "triage.py did not pass on why sipnab failed: $(head -c 400 "$WORK/err")"

# The ops sipnab. sip-problem-call.pcap holds four failed calls, sip-answered-
# never-acked.pcap a call answered and never acknowledged, which sipnab
# reports only after --ack-timeout (recipe 30: the answer waited 31.5 s, under
# the 32 s Timer H default), and stun_sdp_mismatch.pcap a one-way call behind
# NAT. --tfps-ctl names the fake tfps_ctl beside the Python tests: TFPS bans
# by writing a BPF map as root, which no runner allows. The fake answers in
# the documents the real one prints (clients/python/tests/
# test_fake_tfps_ctl.py holds it to the pinned fixtures) and keeps its block
# list in FAKE_TFPS_STATE, which sipnab passes on to it.
export FAKE_TFPS_STATE="$WORK/tfps-block-list.json"
OPS_PORT="$(free_port)"
OPS="http://127.0.0.1:$OPS_PORT"
serve ops "$OPS_PORT" --node-name ops --ack-timeout 5 \
	--tfps-ctl clients/python/tests/fake_tfps_ctl.py \
	-I tests/pcap-samples/sip-problem-call.pcap \
	-I tests/fixtures/sip-answered-never-acked.pcap \
	-I tests/fixtures/stun_sdp_mismatch.pcap
wait_for ops "$SERVED_PID" "$OPS/v1/stats" '"source_exhausted":true'

# Failed calls by final response code, and the call nobody acknowledged
# (recipes 3 and 30).
expect "python failed_calls (four failures, one missing ACK)" \
	"4 failed call(s), by final response code:" \
	"  404  1 call(s)" "    notfound-1b2c3d@203.0.113.30" \
	"  486  1 call(s)" "    busy-3a2b1c@192.0.2.30" \
	"  503  1 call(s)" "    unavail-4e5f60@192.0.2.50" \
	"  603  1 call(s)" "    decline-7c6d5e@198.51.100.30" \
	"1 call(s) answered and never acknowledged:" \
	"  noack-5d4c3b@192.0.2.70  31.5s elapsed with no ACK, answer sent 11 time(s)" \
	-- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/failed_calls.py
# The first sipnab holds the same failures and no unacknowledged call.
expect "python failed_calls (no missing ACK)" \
	"4 failed call(s), by final response code:" \
	"0 call(s) answered and never acknowledged (a call counts once its answer has waited sipnab's --ack-timeout)" \
	-- "$PYTHON" clients/python/failed_calls.py
refuse "python failed_calls" -- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/failed_calls.py

# One-way audio and whose loss it is (recipes 4, 11 and 22). The replay
# dropped nothing, so the loss is the network's; none of the five asymmetry
# filters matches this call.
NAT_CALL="stun-sdp-mismatch-1@192.168.10.50"
expect "python one_way_audio (a phone behind NAT)" \
	"$NAT_CALL  Completed  200" \
	"one-way audio: yes" \
	"NAT mismatch: yes" \
	"  0x11223344  192.168.10.50:40000 -> 198.51.100.30:41000  PCMU  30 packets  loss 0.0%" \
	"  0x55667788  203.0.113.7:41000 -> 192.168.10.50:40000  PCMU  30 packets  loss 0.0%" \
	"hint: RTP flowed 192.168.10.50:40000 -> 198.51.100.30:41000 only (SSRC 0x11223344). No reverse media flow detected." \
	"asymmetry: none" \
	"capture: no packet dropped by the kernel buffer or the interface, so the loss above is the network's" \
	-- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/one_way_audio.py "$NAT_CALL"
expect_exit "python one_way_audio (no such call)" 1 \
	-- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/one_way_audio.py no-such-call@192.0.2.1
grep -q "HTTP 404" "$WORK/err" || fail "one_way_audio.py did not name the 404: $(head -c 400 "$WORK/err")"
refuse "python one_way_audio" -- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/one_way_audio.py "$NAT_CALL"

# A scanner and a flooding device banned through POST /v1/tfps/ban, and the
# banned list read back (recipes 10 and 23). sipnab accuses three sources;
# the PBX completed a registration before its credentials went wrong, so it
# is withheld. --ttl 0 makes the expiry "none" and the lines exact.
SCAN_CAPTURE=tests/fixtures/sip-scanner-and-register-flood.pcap
expect "python scanner_ban (two banned, the PBX withheld)" \
	"banned 198.51.100.77 (reg_flood) with no expiry" \
	"banned 203.0.113.42 (scanner) with no expiry" \
	"withheld 192.0.2.10 (reg_flood): it also completed a registration or a call in this capture" \
	"verified 2 of 2 ban(s) in TFPS's banned list" \
	-- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/scanner_ban.py "$SCAN_CAPTURE" \
	--ttl 0 --reg-flood-threshold 10
# The peer's own record, not the program's report of it: what reached it.
BLOCKED="$("$PYTHON" -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1])))))' "$FAKE_TFPS_STATE")"
[ "$BLOCKED" = "198.51.100.77 203.0.113.42" ] ||
	fail "the TFPS stand-in holds '$BLOCKED', not the two banned sources"
refuse "python scanner_ban" -- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/scanner_ban.py "$SCAN_CAPTURE"
# The first sipnab has no TFPS beside it, and saying so is the answer.
expect_exit "python scanner_ban (no TFPS)" 1 \
	-- "$PYTHON" clients/python/scanner_ban.py "$SCAN_CAPTURE" --reg-flood-threshold 10
grep -q "no TFPS beside" "$WORK/err" || fail "scanner_ban.py did not say TFPS is missing: $(head -c 400 "$WORK/err")"
expect "python scanner_ban (nobody accused)" "no source accused in tests/fixtures/sip_call.pcap" \
	-- env SIPNAB_URL="$OPS" "$PYTHON" clients/python/scanner_ban.py tests/fixtures/sip_call.pcap

# One customer's calls from rotated captures, exported and opened by tshark
# (recipes 39, 32 and 40). sip-problem-call.pcap is cut into three files the
# way a wrapped `tcpdump -C -W` ring leaves them: the oldest packets in
# tg.pcap2, the newest in tg.pcap1. alice's call crosses all three.
mkdir -p "$WORK/rotated" "$WORK/export"
"$PYTHON" - tests/pcap-samples/sip-problem-call.pcap "$WORK/rotated" <<'SPLIT'
import pathlib, struct, sys
data = pathlib.Path(sys.argv[1]).read_bytes()
order = ">" if data[:4] == b"\xa1\xb2\xc3\xd4" else "<"
records, at = [], 24
while at < len(data):
    size = 16 + struct.unpack_from(order + "I", data, at + 8)[0]
    records.append(data[at:at + size])
    at += size
assert len(records) == 23, len(records)
for name, part in (("tg.pcap2", records[:3]), ("tg.pcap0", records[3:21]), ("tg.pcap1", records[21:])):
    pathlib.Path(sys.argv[2], name).write_bytes(data[:24] + b"".join(part))
SPLIT
ALICE="$WORK/export/alice.pcap"
expect "python customer_export (alice, from three rotated files)" \
	"alice: 1 call(s)" \
	"  completed-9f8e7d@192.0.2.10  7 message(s)" \
	"BPF: host 192.0.2.10 or host 192.0.2.20" \
	"wrote $ALICE: 7 SIP message(s), every call whole, no other call" \
	"tshark -r '$ALICE' -Y 'sip.Call-ID == \"completed-9f8e7d@192.0.2.10\"' -V" \
	-- "$PYTHON" clients/python/customer_export.py "$WORK/rotated" --user alice --out "$ALICE"
# Recipe 40, checked by Wireshark's own engine rather than by sipnab: the
# export opens, holds the call's seven packets and nothing else, and the
# command sipnab printed runs and shows the INVITE.
# Each tool writes to a file before grep reads it: `grep -q` exits at its
# first match, and under pipefail the writer's SIGPIPE would fail the check.
capinfos -c "$ALICE" >"$WORK/capinfos.out" 2>&1 || true
grep -qE '^Number of packets: +7$' "$WORK/capinfos.out" ||
	fail "capinfos does not count 7 packets in $ALICE: $(head -c 400 "$WORK/capinfos.out")"
CALLS="$(tshark -r "$ALICE" -Y sip -T fields -e sip.Call-ID | sort | uniq -c | tr -s ' ')"
[ "$CALLS" = " 7 completed-9f8e7d@192.0.2.10" ] ||
	fail "tshark reads '$CALLS' in $ALICE, not alice's 7 messages alone"
TSHARK_CMD="$(grep '^tshark ' "$WORK/out" || true)"
if [ -z "$TSHARK_CMD" ]; then
	fail "customer_export.py printed no tshark command"
elif ! { bash -c "$TSHARK_CMD" >"$WORK/tshark.out" 2>&1 &&
	grep -q 'Request-Line: INVITE sip:bob@192.0.2.20 SIP/2.0' "$WORK/tshark.out"; }; then
	fail "the printed tshark command did not show alice's INVITE: $TSHARK_CMD"
else
	echo "ok   tshark opens the export with the command sipnab printed"
fi
# The same customer beside another capture whose calls share the registrar's
# address: BPF cannot separate them, so the export is refused and removed.
SHARED="$WORK/export/shared.pcap"
expect_exit "python customer_export (another customer shares an address)" 1 \
	"reg-pbx@192.0.2.10: another customer's call shares an address with this one, and BPF cannot separate them" \
	"refused: removed $SHARED rather than hand over a partial or wider capture" \
	-- "$PYTHON" clients/python/customer_export.py "$WORK/rotated" "$SCAN_CAPTURE" \
	--user alice --out "$SHARED"
[ ! -e "$SHARED" ] || fail "customer_export.py left the refused export at $SHARED"
expect_exit "python customer_export (no such customer)" 1 \
	-- "$PYTHON" clients/python/customer_export.py "$WORK/rotated" --user nobody --out "$WORK/export/nobody.pcap"
grep -q "no call for nobody" "$WORK/err" || fail "customer_export.py did not say nobody has no call: $(head -c 400 "$WORK/err")"

# ── AI tasks: what an agent does with sipnab over MCP ────────────────────
#
# Each program is an MCP client; with a capture it starts sipnab as a stdio
# child through SIPNAB_BIN, and waits for capture_status to say the file is
# read to its end before asking anything else.

# Agent triage over stdio: capture_status, list_dialogs, get_capture_report,
# one verdict. The exit status is triage.py's.
PROBLEM_TRIAGE=(
	"problems: 23 frame(s), 5 dialog(s), 0 stream(s)"
	"  major  server_failure  2 call(s)"
	"    decline-7c6d5e@198.51.100.30  Decline"
	"    unavail-4e5f60@192.0.2.50  Service Unavailable"
	"  minor  request_failure  2 call(s)"
	"    busy-3a2b1c@192.0.2.30  Busy Here"
	"    notfound-1b2c3d@203.0.113.30  Not Found"
	"summary: 5 dialog(s) listed: 4 Failed, 1 Completed"
	"next: triage_call decline-7c6d5e@198.51.100.30"
	"next: triage_call unavail-4e5f60@192.0.2.50"
	"next: triage_call busy-3a2b1c@192.0.2.30"
	"next: triage_call notfound-1b2c3d@203.0.113.30"
)
expect_exit "python agent_triage (stdio, four failed calls)" 1 "${PROBLEM_TRIAGE[@]}" \
	-- "$PYTHON" clients/python/agent_triage.py tests/pcap-samples/sip-problem-call.pcap
cp "$WORK/out" "$WORK/agent-stdio.out"
expect "python agent_triage (stdio, one clean call)" \
	"clean: 7 frame(s), 1 dialog(s), 0 stream(s)" \
	"summary: 1 dialog(s) listed: 1 Completed" \
	-- "$PYTHON" clients/python/agent_triage.py tests/fixtures/sip_call.pcap
expect_exit "python agent_triage (stdio, no dialog to judge)" 2 \
	"inconclusive: 10 frame(s) and no SIP dialog or RTP stream to judge, so an empty finding list proves nothing" \
	"summary: no dialog listed" \
	-- "$PYTHON" clients/python/agent_triage.py tests/fixtures/udp_5060.pcap
expect_exit "python agent_triage (stdio, no such capture)" 3 \
	-- "$PYTHON" clients/python/agent_triage.py "$WORK/no-such.pcap"
grep -q "does not exist" "$WORK/err" || fail "agent_triage.py did not pass on why sipnab failed: $(head -c 400 "$WORK/err")"

# The same triage over HTTP, the shape recipe 55 deploys: a signing key file
# (generated here, never committed), and a short-lived read-scoped token
# minted from it. sipnab binds port 0 and the check reads the port it logs,
# so no port is reserved and released first. Loopback only.
MCP_KEY="$WORK/mcp.key"
"$PYTHON" -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())' >"$MCP_KEY"
chmod 600 "$MCP_KEY"
NO_COLOR=1 "$BIN" --mcp -N --mcp-transport http --mcp-bind 127.0.0.1:0 \
	--mcp-signing-key-file "$MCP_KEY" --node-name agent-box \
	-I tests/pcap-samples/sip-problem-call.pcap >/dev/null 2>"$WORK/mcp-http.log" &
MCP_PID=$!
PIDS+=("$MCP_PID")
MCP_URL=""
for _ in $(seq 600); do
	kill -0 "$MCP_PID" 2>/dev/null || { cat "$WORK/mcp-http.log" >&2; echo "smoke-clients: the HTTP MCP sipnab exited" >&2; exit 1; }
	MCP_URL="$(sed -n 's/.*MCP HTTP server listening on \(127\.0\.0\.1:[0-9]*\).*/http:\/\/\1/p' "$WORK/mcp-http.log")"
	[ -z "$MCP_URL" ] || break
	sleep 0.1
done
[ -n "$MCP_URL" ] || { cat "$WORK/mcp-http.log" >&2; echo "smoke-clients: the HTTP MCP sipnab never said where it listens" >&2; exit 1; }
# mint TOKEN_FILE ARG... : a token from sipnab --mint-token.
mint() {
	local out="$1"
	shift
	"$BIN" --mint-token "$@" >"$out" 2>"$WORK/mint.log" || fail "sipnab --mint-token $*: $(head -c 400 "$WORK/mint.log")"
}
mint "$WORK/agent.token" --token-scope read --token-id agent-ci --mcp-signing-key-file "$MCP_KEY" --mcp-token-ttl 900
"$PYTHON" -c 'import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())' >"$WORK/other.key"
mint "$WORK/wrong-key.token" --token-scope read --mcp-signing-key-file "$WORK/other.key"
# The same key, minted for the REST API: a token names the surface it is for.
mint "$WORK/api-audience.token" --api-signing-key-file "$MCP_KEY"
expect_exit "python agent_triage (HTTP, signed read token)" 1 "${PROBLEM_TRIAGE[@]}" \
	-- "$PYTHON" clients/python/agent_triage.py --url "$MCP_URL" --token-file "$WORK/agent.token"
cmp -s "$WORK/out" "$WORK/agent-stdio.out" ||
	fail "agent_triage.py printed one verdict over stdio and another over HTTP: $(diff "$WORK/agent-stdio.out" "$WORK/out" | head -c 400)"
for token in wrong-key api-audience; do
	expect_exit "python agent_triage (HTTP, $token token)" 3 \
		-- "$PYTHON" clients/python/agent_triage.py --url "$MCP_URL" --token-file "$WORK/$token.token"
	[ ! -s "$WORK/out" ] || fail "agent_triage.py printed a verdict with a $token token"
	grep -q "HTTP 401" "$WORK/err" || fail "agent_triage.py did not name the 401 for a $token token: $(head -c 400 "$WORK/err")"
done
# No Authorization header at all: refused before any MCP session exists.
UNSIGNED="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
	-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
	-d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}' \
	"$MCP_URL/mcp" || true)"
if [ "$UNSIGNED" = 401 ]; then
	echo "ok   the HTTP MCP sipnab refuses a request with no token"
else
	fail "the HTTP MCP sipnab answered $UNSIGNED, not 401, to a request with no token"
fi

# An evidence package and a repro script per call, written under
# --mcp-file-root, read back and checked, twice: two runs over one capture
# must print the same lines and write byte-identical files. The one thing
# that differs between the runs is the absolute path under each root, which
# sipnab's answer carries and the program prints relative to the root.
HANDOFF_LINES=(
	"package failed-calls: 4 call(s), 16 message(s)"
	"repro failed-calls.call-01.xml  decline-7c6d5e@198.51.100.30  asserts 603  pinned request_uri"
	"repro failed-calls.call-02.xml  unavail-4e5f60@192.0.2.50  asserts 503  pinned request_uri"
	"repro failed-calls.call-03.xml  busy-3a2b1c@192.0.2.30  asserts 486  pinned request_uri"
	"repro failed-calls.call-04.xml  notfound-1b2c3d@203.0.113.30  asserts 404  pinned request_uri"
)
for run in 1 2; do
	mkdir -p "$WORK/handoff-$run"
	expect "python evidence_handoff (run $run)" "${HANDOFF_LINES[@]}" \
		-- "$PYTHON" clients/python/evidence_handoff.py tests/pcap-samples/sip-problem-call.pcap \
		--file-root "$WORK/handoff-$run" --name failed-calls
	grep -q '^PROBLEM' "$WORK/out" && fail "evidence_handoff.py found a problem: $(grep '^PROBLEM' "$WORK/out" | head -c 400)"
	cp "$WORK/out" "$WORK/handoff-$run.out"
done
if cmp -s "$WORK/handoff-1.out" "$WORK/handoff-2.out" &&
	diff -r "$WORK/handoff-1" "$WORK/handoff-2" >"$WORK/handoff.diff" 2>&1; then
	echo "ok   two runs wrote a byte-identical package and repro scripts"
else
	fail "two evidence_handoff.py runs over one capture differ: $(head -c 400 "$WORK/handoff.diff") $(diff "$WORK/handoff-1.out" "$WORK/handoff-2.out" | head -c 400)"
fi
[ "$(grep -c '^sha256 ' "$WORK/handoff-1.out")" = 15 ] ||
	fail "evidence_handoff.py did not digest the 11 package files and 4 scenarios"
capinfos -c "$WORK/handoff-1/failed-calls/signaling.pcapng" >"$WORK/capinfos.out" 2>&1 || true
grep -qE '^Number of packets: +16$' "$WORK/capinfos.out" ||
	fail "capinfos does not count the package's 16 messages: $(head -c 400 "$WORK/capinfos.out")"
# sipnab never writes over a name that is taken.
expect_exit "python evidence_handoff (the name is taken)" 1 \
	-- "$PYTHON" clients/python/evidence_handoff.py tests/pcap-samples/sip-problem-call.pcap \
	--file-root "$WORK/handoff-1" --name failed-calls
grep -q "already exists" "$WORK/err" || fail "evidence_handoff.py did not pass on sipnab's refusal: $(head -c 400 "$WORK/err")"
expect_exit "python evidence_handoff (no finding names a call)" 2 \
	"nothing to package: no finding names a call" \
	-- "$PYTHON" clients/python/evidence_handoff.py tests/fixtures/sip_call.pcap --file-root "$WORK/handoff-1"

# Filter DSL into aggregate_dialogs into JSON under a model's byte budget.
# Whole buckets fold into other_count; the counts still add up.
expect "python aggregate_for_model (failed calls by code)" \
	'{"group_by":"response_code","filter":"state == '"'"'Failed'"'"'","total_matched":4,"distinct_values":4,"buckets":[{"value":"404","count":1},{"value":"486","count":1},{"value":"503","count":1},{"value":"603","count":1}],"other_count":0,"omitted_buckets":0}' \
	-- "$PYTHON" clients/python/aggregate_for_model.py tests/pcap-samples/sip-problem-call.pcap \
	--group-by response_code --filter "state == 'Failed'"
expect "python aggregate_for_model (the same, in 200 bytes)" \
	'{"group_by":"response_code","filter":"state == '"'"'Failed'"'"'","total_matched":4,"distinct_values":4,"buckets":[{"value":"404","count":1},{"value":"486","count":1}],"other_count":2,"omitted_buckets":2}' \
	-- "$PYTHON" clients/python/aggregate_for_model.py tests/pcap-samples/sip-problem-call.pcap \
	--group-by response_code --filter "state == 'Failed'" --max-bytes 200
expect "python aggregate_for_model (User-Agents from packets, in 300 bytes)" \
	'{"group_by":"ua","filter":null,"total_matched":8,"distinct_values":3,"buckets":[{"value":"⟦untrusted-capture-data⟧friendly-scanner⟦/untrusted-capture-data⟧","count":6}],"other_count":2,"omitted_buckets":2}' \
	-- "$PYTHON" clients/python/aggregate_for_model.py tests/fixtures/sip-scanner-and-register-flood.pcap \
	--group-by ua --max-bytes 300
# The line and its newline, within the budget in bytes, not characters.
[ "$(head -n 1 "$WORK/out" | tr -d '\n' | wc -c)" -le 300 ] ||
	fail "aggregate_for_model.py printed more than its 300-byte budget"
expect_exit "python aggregate_for_model (a filter field sipnab does not know)" 1 \
	-- "$PYTHON" clients/python/aggregate_for_model.py tests/pcap-samples/sip-problem-call.pcap \
	--group-by response_code --filter "bogus == 1"
grep -q "unknown field 'bogus'" "$WORK/err" || fail "aggregate_for_model.py did not pass on sipnab's refusal: $(head -c 400 "$WORK/err")"
expect_exit "python aggregate_for_model (a budget nothing fits)" 1 \
	-- "$PYTHON" clients/python/aggregate_for_model.py tests/pcap-samples/sip-problem-call.pcap \
	--group-by response_code --max-bytes 50
grep -q "over the 50-byte budget" "$WORK/err" || fail "aggregate_for_model.py did not say the budget is too small: $(head -c 400 "$WORK/err")"

if [ "$FAILED" -ne 0 ]; then
	echo "smoke-clients: $FAILED check(s) failed" >&2
	exit 1
fi
echo "smoke-clients: every client program ran and printed what its page says"
