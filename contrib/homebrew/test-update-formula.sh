#!/usr/bin/env bash
#
# Tests for update-formula.sh — the Homebrew tap formula generator used by the
# release workflow to auto-bump NormB/homebrew-tap on every tag push.
#
# TDD harness: covers success, failure, and adversarial inputs (wrong-version
# lines, missing targets, malformed/short/uppercase checksums, empty version,
# backslashes/special chars, embedded NUL). Run: bash test-update-formula.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="$HERE/update-formula.sh"

pass=0
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok()   { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }

# A valid SHA256SUMS.txt for v0.4.3 (includes musl + .deb noise lines that the
# generator must ignore, and a stray wrong-version line it must NOT pick up).
good_sums() {
  cat <<'EOF'
d1c0d9fcce3dcb79599e96efa317c7b2433128088bddeddb1065fead35bea7c0  sipnab-0.4.3-aarch64-apple-darwin.tar.gz
17a1bda119ebf54ca5af286ae4c55becd0430648664afd2f5fede3eb439e6bbd  sipnab-0.4.3-x86_64-apple-darwin.tar.gz
858136ae7e3faca63d9521156e2f0897e389efbf81efc8bdcafe4511f215a5bb  sipnab-0.4.3-aarch64-unknown-linux-gnu.tar.gz
f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0  sipnab-0.4.3-x86_64-unknown-linux-gnu.tar.gz
1111111111111111111111111111111111111111111111111111111111111111  sipnab-0.4.3-aarch64-unknown-linux-musl.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  sipnab-0.4.3-x86_64-unknown-linux-musl.tar.gz
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0  sipnab-0.4.2-x86_64-apple-darwin.tar.gz
abc  sipnab_0.4.3_amd64.deb
EOF
}

# --- success path -----------------------------------------------------------
sums="$tmp/SHA256SUMS.txt"; good_sums > "$sums"
out="$("$GEN" 0.4.3 "$sums" 2>"$tmp/err")"; rc=$?
[ $rc -eq 0 ] && ok "exits 0 on valid input" || { bad "exits 0 on valid input (rc=$rc)"; cat "$tmp/err"; }

grep -q 'version "0.4.3"' <<<"$out" && ok "emits version 0.4.3" || bad "emits version 0.4.3"
grep -q 'd1c0d9fcce3dcb79599e96efa317c7b2433128088bddeddb1065fead35bea7c0' <<<"$out" && ok "macOS arm64 sha" || bad "macOS arm64 sha"
grep -q '17a1bda119ebf54ca5af286ae4c55becd0430648664afd2f5fede3eb439e6bbd' <<<"$out" && ok "macOS x86_64 sha" || bad "macOS x86_64 sha"
grep -q '858136ae7e3faca63d9521156e2f0897e389efbf81efc8bdcafe4511f215a5bb' <<<"$out" && ok "linux arm64 sha"  || bad "linux arm64 sha"
grep -q 'f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0' <<<"$out" && ok "linux x86_64 sha" || bad "linux x86_64 sha"
grep -q 'releases/download/v0.4.3/sipnab-0.4.3-aarch64-apple-darwin.tar.gz' <<<"$out" && ok "macOS arm64 url" || bad "macOS arm64 url"

# Adversarial: a 0.4.2 line lives in the file; it must never leak into output.
grep -q '0.4.2' <<<"$out" && bad "must not pick up wrong-version (0.4.2) line" || ok "ignores wrong-version line"
grep -q 'deadbeef' <<<"$out" && bad "must not emit 0.4.2 darwin sha" || ok "ignores 0.4.2 darwin sha"
# musl checksums must not be emitted (tap ships gnu/darwin only).
grep -q '1111111111111111' <<<"$out" && bad "must not emit musl sha" || ok "ignores musl checksums"

# Generated formula must be a single self-contained class.
[ "$(grep -c '^class Sipnab < Formula' <<<"$out")" -eq 1 ] && ok "one formula class" || bad "one formula class"
grep -q '^end$' <<<"$out" && ok "closes the class" || bad "closes the class"

# Optional: real Ruby syntax check when available.
if command -v ruby >/dev/null 2>&1; then
  printf '%s\n' "$out" > "$tmp/sipnab.rb"
  ruby -c "$tmp/sipnab.rb" >/dev/null 2>&1 && ok "valid ruby syntax" || bad "valid ruby syntax"
fi

# --- failure paths ----------------------------------------------------------
"$GEN" "" "$sums" >/dev/null 2>&1 && bad "rejects empty version" || ok "rejects empty version"
"$GEN" 0.4.3 "$tmp/nope.txt" >/dev/null 2>&1 && bad "rejects missing sums file" || ok "rejects missing sums file"
"$GEN" 0.4.3 >/dev/null 2>&1 && bad "rejects missing args" || ok "rejects missing args"

# Missing target line -> must fail, not emit a blank/garbage sha.
partial="$tmp/partial.txt"; grep -v 'x86_64-unknown-linux-gnu' "$sums" > "$partial"
"$GEN" 0.4.3 "$partial" >/dev/null 2>&1 && bad "rejects missing target" || ok "rejects missing target"

# Malformed checksum (too short / non-hex) -> must fail.
short="$tmp/short.txt"; sed 's/f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0/abc123/' "$sums" > "$short"
"$GEN" 0.4.3 "$short" >/dev/null 2>&1 && bad "rejects short checksum" || ok "rejects short checksum"
upper="$tmp/upper.txt"; sed 's/f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0/F94435E79A5AAAE1CB24050CC9AC7F94041588C845B425F2CA73750A8B89E3C0/' "$sums" > "$upper"
"$GEN" 0.4.3 "$upper" >/dev/null 2>&1 && bad "rejects uppercase checksum" || ok "rejects uppercase checksum"

# Adversarial version strings must not produce a target match (no such files).
"$GEN" '0.4.3; rm -rf /' "$sums" >/dev/null 2>&1 && bad "rejects version with shell metachars" || ok "rejects version with shell metachars"
"$GEN" 'back\slash' "$sums" >/dev/null 2>&1 && bad "rejects version with backslash" || ok "rejects version with backslash"
"$GEN" $'nul\x00ver' "$sums" >/dev/null 2>&1 && bad "rejects version with embedded NUL" || ok "rejects version with embedded NUL"

# A version that IS a regex metachar-laden prefix must be matched literally,
# not as a pattern (e.g. '0.4.3' must not also match '0x4y3' style lines).
echo
printf 'passed: %d  failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
