#!/usr/bin/env sh
# Mint a fresh short-lived MCP bearer token from the long-lived HMAC signing key
# and publish it atomically to the shared token file. The harness rotator loop
# (sipnab/entrypoint.sh) calls this on an interval, and it can be run by hand to
# force a rotation. Every consumer (server, `make laptop`, `make mcp-test`) reads
# the published file, so the swap MUST be atomic — readers see either the old or
# the new token, never a half-written one.
#
# Usage: rotate-token.sh <signing-key-file> <token-file> <ttl-seconds> [sipnab-bin]
set -eu

KEY_FILE="${1:?usage: rotate-token.sh <signing-key-file> <token-file> <ttl> [sipnab-bin]}"
TOKEN_FILE="${2:?usage: rotate-token.sh <signing-key-file> <token-file> <ttl> [sipnab-bin]}"
TTL="${3:?usage: rotate-token.sh <signing-key-file> <token-file> <ttl> [sipnab-bin]}"
SIPNAB="${4:-sipnab}"

if [ ! -s "$KEY_FILE" ]; then
    echo "rotate-token: signing key '$KEY_FILE' is empty or missing" >&2
    exit 1
fi

# Mint into a temp file in the SAME directory as the target so the rename below
# is a same-filesystem (atomic) operation. The token id (jti) is auto-derived
# from a microsecond timestamp by --mint-token, so each rotation is distinct and
# individually revocable via --mcp-revoked-file.
tmp="${TOKEN_FILE}.tmp.$$"
# Best-effort cleanup if minting fails partway (set -e will exit non-zero).
trap 'rm -f "$tmp"' EXIT

if ! "$SIPNAB" --mint-token \
        --mcp-signing-key-file "$KEY_FILE" \
        --mcp-token-ttl "$TTL" > "$tmp"; then
    echo "rotate-token: minting failed" >&2
    exit 1
fi

if [ ! -s "$tmp" ]; then
    echo "rotate-token: minted token is empty" >&2
    exit 1
fi

# World-readable: sipnab drops to 'nobody' before reading it inside the
# container, and `make laptop`/`make mcp-test` read it from the host bind mount.
chmod 644 "$tmp"
mv -f "$tmp" "$TOKEN_FILE"
trap - EXIT
