#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

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
# SIPNAB_BIN=<path> names the binary this drives. It defaults to `sipnab`,
# which is PATH RESOLUTION, and PATH resolution is how a measurement ends up
# describing a program nobody is working on.
#
# That is not hypothetical. Run by hand on a box with a packaged sipnab in
# /usr/local/sbin, this script answered from 0.5.78 while the tree said 0.5.134
# -- fifty-five releases apart. The MCP untrusted-capture-data fencing the run
# was checking for did not exist in 0.5.78, so the absence looked like a
# defect in the tree and was reported as one. The retraction cost more than the
# check did.
#
# So: name the binary, or accept that the answer describes whatever PATH found.
#
#     SIPNAB_BIN=target/debug/sipnab demos/mcp-stdio.sh <capture> <tool>
#
# Needs: bash 3.2 or later (the bash macOS ships), jq, mkfifo and mktemp.
# Nothing here uses a coprocess, an associative array or any other construct
# bash gained after 3.2, and tests/demo_mcp_stdio_test.rs keeps it so; the
# macOS leg of CI runs the script on 3.2 itself.
#
# demos/Makefile passes SIPNAB_BIN for every render and refuses to render when
# that binary disagrees with Cargo.toml. Run through the Makefile, not by hand,
# when the output is going to be published.
set -uo pipefail

SIPNAB_BIN="${SIPNAB_BIN:-sipnab}"

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

# Say what is missing before anything is started. Every reply is read with
# jq, so without it each read fails and the run ends as "no initialize reply";
# a binary that is not there ends the same way, 20 seconds later.
command -v jq >/dev/null 2>&1 || {
    echo "mcp-stdio: jq is not installed; this script reads every reply with it" >&2
    exit 1
}
command -v "$SIPNAB_BIN" >/dev/null 2>&1 || {
    echo "mcp-stdio: no sipnab at '$SIPNAB_BIN'; set SIPNAB_BIN to the binary to drive" >&2
    exit 1
}

# Two named pipes rather than one pipeline, because this has to READ before
# it writes.
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
#
# Named pipes and not `coproc`: a coprocess is bash 4.0, and macOS ships bash
# 3.2, where the script ended at that line. The server reads its requests from
# one pipe and writes its replies to the other; descriptors 3 and 4 are this
# script's ends of them.
WORK="$(mktemp -d)" || { echo "mcp-stdio: cannot make a temporary directory" >&2; exit 1; }
SRV_PID=""
cleanup() {
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null
        # Reap it here, with stderr closed to the shell's own notice: bash 3.2
        # otherwise prints "Terminated" and the server's whole command line
        # as this script exits.
        wait "$SRV_PID" 2>/dev/null
    fi
    rm -rf "$WORK"
}
trap cleanup EXIT
mkfifo "$WORK/requests" "$WORK/replies" || { echo "mcp-stdio: cannot make a named pipe in $WORK" >&2; exit 1; }

# `${ARRAY[@]+"${ARRAY[@]}"}` and not `"${ARRAY[@]}"`: under `set -u`, bash
# before 4.4 refuses the plain form of an EMPTY array as an unbound variable.
# The guarded form expands to nothing when the array is empty.
#
# `exec`, so the background job IS the server: the pid recorded below is the
# one to stop, with no shell left between this script and it.
( exec "$SIPNAB_BIN" --mcp -N -I "$CAPTURE" ${ROOTFLAG[@]+"${ROOTFLAG[@]}"} ${NODEFLAG[@]+"${NODEFLAG[@]}"} --quiet \
    <"$WORK/requests" >"$WORK/replies" 2>/dev/null ) &
SRV_PID=$!

# Opening a named pipe waits for the other end. The server's side opens
# `requests` for reading and then `replies` for writing, so this opens them in
# the same order. A server that could not start never opens its ends; the
# opens are done read-write so that this script does not wait on it forever,
# and the first read below times out instead.
exec 3<>"$WORK/requests" 4<>"$WORK/replies"

send() { printf '%s\n' "$1" >&3; }

# Replies to earlier polls, and any notification the server sends, share the
# one stream, so reading "the next line" is never reading "the answer". Each
# request carries its own id and this keeps the line that quotes it back.
#
# The reply lands in a VARIABLE rather than on stdout so that the caller reads
# it without a subshell between the read and its use.
#
# A server that has exited cannot answer. Because this script holds both ends
# of `replies` open, the read would not see end-of-file; it would wait out the
# whole timeout on every call. So each wait is one second long at most, and a
# server that is gone ends the wait at once.
REPLY_LINE=""
await() {
    local want="$1" line got waited=0
    REPLY_LINE=""
    while [ "$waited" -lt "${MCP_TIMEOUT:-20}" ]; do
        if IFS= read -r -t 1 -u 4 line; then
            got="$(jq -r '.id // empty' 2>/dev/null <<< "$line")"
            if [ "$got" = "$want" ]; then REPLY_LINE="$line"; return 0; fi
        else
            kill -0 "$SRV_PID" 2>/dev/null || return 1
            waited=$((waited + 1))
        fi
    done
    return 1
}

status_call() { printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"capture_status","arguments":{}}}' "$1"; }

# The two messages an MCP session needs before any tool call.
send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"sipnab-demo","version":"0"}}}'
await 1 || { echo "mcp-stdio: no initialize reply from $SIPNAB_BIN" >&2; exit 1; }
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

OUT="$WORK/answer"

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
