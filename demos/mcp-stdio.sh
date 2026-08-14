#!/usr/bin/env bash
# One readable MCP tool call over stdio, against a capture in this repo.
#
# Usage: demos/mcp-stdio.sh <capture> <tool> [json-arguments]
#
# Why this exists alongside mcp-call.sh:
#
#   mcp-call.sh drives the HTTP transport against the docker harness, which
#   needs `make -C harness up` and a bearer token. That is the right shape for
#   testing the network-exposed server, and the wrong shape for a published
#   demo: a viewer who clones the repo cannot reproduce it without standing up
#   opensips-1 first.
#
#   `--mcp` defaults to stdio, needs no token, no port and no daemon, and reads
#   a capture that ships in the tree. Everything a demo recorded through this
#   script shows, a reader can re-run with one command.
#
# MCP over stdio is newline-delimited JSON-RPC on stdout, so the answer arrives
# nested inside result.content[0].text as a JSON STRING. Raw, that is a wall of
# escapes. This unwraps it once, so a viewer sees the answer rather than the
# envelope.
#
# The sipnab this runs is whatever PATH resolves; demos/Makefile prepends the
# binary built FROM THIS TREE for every render, and refuses to render when that
# binary disagrees with Cargo.toml. Run through the Makefile, not by hand, when
# the output is going to be published.
set -uo pipefail

CAPTURE="${1:?usage: mcp-stdio.sh <capture> <tool> [json-arguments]}"
TOOL="${2:?usage: mcp-stdio.sh <capture> <tool> [json-arguments]}"
ARGS="${3:-{\}}"

# MCP_FILE_ROOT=<dir> enables the file-reading tools, which are OFF by default:
# show_evidence answers "file tools are disabled" until a root is named. That
# default is deliberate — an agent cannot read a byte sipnab was not pointed at
# — so the flag stays explicit here rather than being folded into the server
# invocation for every call.
ROOTFLAG=()
[ -n "${MCP_FILE_ROOT:-}" ] && ROOTFLAG=(--mcp-file-root "$MCP_FILE_ROOT")

# MCP_NODE_NAME=<name> sets what the box calls itself in `capture_identity.node`.
#
# The default is the system hostname, which is right in a deployment — an agent
# querying an SBC and two PBXes needs to know which one answered — and wrong in
# a published recording, where it puts the name of whatever machine rendered
# the demo onto the homepage. `--node-name` says as much in its own help text.
NODEFLAG=()
[ -n "${MCP_NODE_NAME:-}" ] && NODEFLAG=(--node-name "$MCP_NODE_NAME")

[ -r "$CAPTURE" ] || { echo "no capture at $CAPTURE" >&2; exit 1; }

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

# The three messages an MCP session needs before a tool call: initialize, the
# initialized notification, then the call itself. Ids 1 and 2 distinguish the
# initialize reply from the answer we want.
init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sipnab-demo","version":"0"}}}'
ready='{"jsonrpc":"2.0","method":"notifications/initialized"}'
call=$(printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$TOOL" "$ARGS")

# Hold stdin open past the last request: the server reads to EOF, and closing
# immediately after the write races the reply out of the pipe. The sleep is the
# whole reason this is a block rather than three printfs.
{
    printf '%s\n%s\n%s\n' "$init" "$ready" "$call"
    sleep "${MCP_SETTLE:-3}"
} | sipnab --mcp -N -I "$CAPTURE" "${ROOTFLAG[@]}" "${NODEFLAG[@]}" --quiet 2>/dev/null \
  | jq -r 'select(.id == 2)
           | .result.content[0].text // (.error.message | "error: " + .) // "no content"' \
  > "$OUT"

# Pretty-print when the answer is JSON, pass it through when it is not.
#
# Not every tool answers in JSON — a refusal ("failed to deserialize
# parameters: missing field `refs`") is plain prose, and piping that straight
# into `jq .` replaced sipnab's actual message with "jq: parse error: Invalid
# literal at line 1, column 7". The diagnostic a viewer needs was the one the
# formatter destroyed.
if jq -e . >/dev/null 2>&1 < "$OUT"; then jq . < "$OUT"; else cat "$OUT"; fi
