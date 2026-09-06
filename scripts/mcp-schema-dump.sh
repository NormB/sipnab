#!/usr/bin/env bash
# Dump every MCP tool a sipnab build registers -- name, description and input
# JSON Schema -- as one JSON object, without opening a browser.
#
# WHY THIS EXISTS
#
# The REST surface publishes `website/static/openapi.json`, and
# `tests/openapi_contract_test.rs` regenerates and diffs it, so the document
# cannot drift from the handlers. The MCP surface has no such artifact: the
# schemas live in `#[tool]` attributes and reach a client only over the wire.
# `docs/mcp-tools.md` is the prose reference and `docs_drift_test` holds it to
# the registrations, but neither of those shows a reader the actual JSON
# Schema a client will receive.
#
# The MCP Inspector's `--cli` client speaks the protocol and exits, so one
# `tools/list` call answers exactly that question against a REAL binary. This
# script is that call, with the argument order that works.
#
# WHAT IT IS NOT
#
# Not a gate, and deliberately not a committed artifact. What it prints
# describes ONE build: a binary compiled without `vcon` or `tls` registers
# fewer tools than the tree defines, and an older release registers fewer
# still. Freezing that output would pin a number to whichever machine last ran
# it. Read it as a spot check on a binary in hand.
#
# THE ARGUMENT ORDER, WHICH IS NOT OBVIOUS
#
# The Inspector's CLI client splits its argv at a bare `--`: everything BEFORE
# the separator is the server command, everything AFTER is the Inspector's own
# flags. Its browser client splits the other way round. Neither is a typo
# below.
#
# For an HTTP target there is no separator at all -- the CLI's fallback rule
# treats leading non-dash tokens as the command, and `--server-url` is a dash
# token, so every flag parses as the Inspector's.
#
# USAGE
#
#   scripts/mcp-schema-dump.sh capture.pcap
#   scripts/mcp-schema-dump.sh http://127.0.0.1:8731/mcp
#   SIPNAB_MCP_TOKEN=$(cat ~/.config/sipnab/prod01.token) \
#       scripts/mcp-schema-dump.sh https://capture.example.com/mcp
#
# ENVIRONMENT
#
#   SIPNAB           the sipnab binary to spawn for a stdio target (default:
#                    `sipnab` from PATH). It must carry the `mcp` feature.
#   SIPNAB_MCP_TOKEN bearer token for an HTTP target. Loopback binds need
#                    none; anything else does.
#   INSPECTOR_BIN    an already-installed `mcp-inspector`, instead of npx.
#
# Requires Node 22.19 or newer, which is the Inspector's own floor.

set -euo pipefail

usage() {
	cat >&2 <<'EOF'
usage: scripts/mcp-schema-dump.sh <capture.pcap | http[s]://host:port/mcp>

Prints the MCP tools/list response as JSON on stdout. Pipe it to jq:

  scripts/mcp-schema-dump.sh capture.pcap | jq -r '.result.tools[].name'
  scripts/mcp-schema-dump.sh capture.pcap | jq '.result.tools[] | select(.name=="triage_call") | .inputSchema'
EOF
}

target=${1:-}
case "$target" in
"")
	usage
	exit 2
	;;
-h | --help)
	usage
	exit 0
	;;
esac

if [ -n "${INSPECTOR_BIN:-}" ]; then
	inspector=("$INSPECTOR_BIN")
else
	command -v npx >/dev/null 2>&1 || {
		echo "mcp-schema-dump: npx not found. Install Node 22.19+ or set INSPECTOR_BIN." >&2
		exit 1
	}
	inspector=(npx -y @modelcontextprotocol/inspector)
fi

case "$target" in
http://* | https://*)
	args=(--cli --server-url "$target" --transport http)
	if [ -n "${SIPNAB_MCP_TOKEN:-}" ]; then
		args+=(--header "Authorization: Bearer $SIPNAB_MCP_TOKEN")
	fi
	args+=(--method tools/list --format json)
	;;
*)
	[ -r "$target" ] || {
		echo "mcp-schema-dump: cannot read capture file '$target'." >&2
		exit 1
	}
	# Server command first, separator, then the Inspector's own flags.
	args=(--cli "${SIPNAB:-sipnab}" --mcp -N -I "$target"
		-- --method tools/list --format json)
	;;
esac

exec "${inspector[@]}" "${args[@]}"
