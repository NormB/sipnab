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

# A coprocess rather than a pipe, because this has to READ before it writes.
#
# The capture loads in the BACKGROUND while the server is already answering
# tool calls, so a call issued straight after `initialize` is answered from
# whatever has been parsed so far. Measured on Asterisk_ZFONE_XLITE.pcap
# (256 KiB): three runs out of three of the previous write-only pipe — which
# sent all three messages at once and slept afterwards to hold stdin open —
# rendered the INVITE as `Result: In Progress`, with the 200 and the BYE
# missing from a call that had both. Sleeping LONGER is not the fix; it is the
# same race with a bigger constant, and a bigger capture puts it back.
#
# `capture_status.source_exhausted` flips false to true exactly when the source
# has been read to its end, so this polls it and refuses to make the real call
# until it is true. `MCP_MAX_POLLS` bounds the wait so a genuine hang fails
# instead of running forever.
coproc SRV { sipnab --mcp -N -I "$CAPTURE" "${ROOTFLAG[@]}" "${NODEFLAG[@]}" --quiet 2>/dev/null; }
SRV_PID=$!
trap '[ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null' EXIT

send() { printf '%s\n' "$1" >&"${SRV[1]}"; }

# Replies to earlier polls, and any notification the server sends, share the
# one stream, so reading "the next line" is never reading "the answer". Each
# request carries its own id and this keeps the line that quotes it back.
#
# The reply lands in a VARIABLE rather than on stdout because bash closes the
# coprocess file descriptors inside a subshell, and `await 2 | jq ...` puts
# `await` in one: the read then fails with EBADF on a descriptor the parent
# still holds open. That failure was silent in every earlier stage of this
# script and only bit the final call.
REPLY_LINE=""
await() {
    local want="$1" line got
    REPLY_LINE=""
    while IFS= read -r -t "${MCP_TIMEOUT:-20}" -u "${SRV[0]}" line; do
        got="$(jq -r '.id // empty' 2>/dev/null <<< "$line")"
        if [ "$got" = "$want" ]; then REPLY_LINE="$line"; return 0; fi
    done
    return 1
}

status_call() { printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"capture_status","arguments":{}}}' "$1"; }

# The two messages an MCP session needs before any tool call.
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sipnab-demo","version":"0"}}}'
await 1 || { echo "mcp-stdio: no initialize reply from sipnab" >&2; exit 1; }
send '{"jsonrpc":"2.0","method":"notifications/initialized"}'

id=2
loaded=0
limit=$(( 2 + ${MCP_MAX_POLLS:-400} ))
while [ "$id" -le "$limit" ]; do
    send "$(status_call "$id")"
    await "$id" || break
    exhausted="$(jq -r '.result.content[0].text // empty' <<< "$REPLY_LINE" \
        | jq -r '.source_exhausted // empty' 2>/dev/null)"
    if [ "$exhausted" = "true" ]; then loaded=1; break; fi
    sleep 0.05
    id=$((id + 1))
done
[ "$loaded" = 1 ] || { echo "mcp-stdio: $CAPTURE never finished loading" >&2; exit 1; }

OUT="$(mktemp)"
trap 'rm -f "$OUT"; [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null' EXIT

id=$((id + 1))
send "$(printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"%s","arguments":%s}}' "$id" "$TOOL" "$ARGS")"
await "$id" || { echo "mcp-stdio: no reply to $TOOL" >&2; exit 1; }
jq -r '.result.content[0].text // (.error.message | "error: " + .) // "no content"' \
  <<< "$REPLY_LINE" > "$OUT"

# Pretty-print when the answer is JSON, pass it through when it is not.
#
# Not every tool answers in JSON — a refusal ("failed to deserialize
# parameters: missing field `refs`") is plain prose, and piping that straight
# into `jq .` replaced sipnab's actual message with "jq: parse error: Invalid
# literal at line 1, column 7". The diagnostic a viewer needs was the one the
# formatter destroyed.
if jq -e . >/dev/null 2>&1 < "$OUT"; then jq . < "$OUT"; else cat "$OUT"; fi
