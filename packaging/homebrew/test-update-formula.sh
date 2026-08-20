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

# A SHA256SUMS.txt for v0.4.3 with the SHAPE OF A REAL ONE.
#
# It used to be eight lines: four tap tarballs, two musl, a wrong-version line
# and `abc  sipnab_0.4.3_amd64.deb`. That is not what a release publishes.
# release.yml builds the file with
#   sha256sum *.tar.gz *.deb *.rpm *.cdx.json > SHA256SUMS.txt
# which on 0.5.117 produced sixteen entries: six tarballs (gnu, musl, darwin),
# four .deb and four .rpm (each in plain and `-noaudio` flavours), and two
# CycloneDX SBOMs — in glob order, which is NOT the order the generator reads
# them in. A fixture narrower than that cannot exercise the classes that
# actually break a release: a new artifact name, a platform that did not build,
# a change in asset count or ordering.
#
# The shape is not asserted by eye. `test-real-sums.sh` carries the rules for
# what a real manifest looks like and this fixture is run through them below,
# so the two cannot drift — and that same checker meets the genuine article in
# CI, against the latest published release.
#
# The 0.4.2 line is deliberate: a stray wrong-version entry the generator must
# never pick up.
good_sums() {
  cat <<'EOF'
d1c0d9fcce3dcb79599e96efa317c7b2433128088bddeddb1065fead35bea7c0  sipnab-0.4.3-aarch64-apple-darwin.tar.gz
858136ae7e3faca63d9521156e2f0897e389efbf81efc8bdcafe4511f215a5bb  sipnab-0.4.3-aarch64-unknown-linux-gnu.tar.gz
1111111111111111111111111111111111111111111111111111111111111111  sipnab-0.4.3-aarch64-unknown-linux-musl.tar.gz
17a1bda119ebf54ca5af286ae4c55becd0430648664afd2f5fede3eb439e6bbd  sipnab-0.4.3-x86_64-apple-darwin.tar.gz
f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0  sipnab-0.4.3-x86_64-unknown-linux-gnu.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  sipnab-0.4.3-x86_64-unknown-linux-musl.tar.gz
deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef  sipnab-0.4.2-x86_64-apple-darwin.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  sipnab_0.4.3_amd64-noaudio.deb
4444444444444444444444444444444444444444444444444444444444444444  sipnab_0.4.3_amd64.deb
5555555555555555555555555555555555555555555555555555555555555555  sipnab_0.4.3_arm64-noaudio.deb
6666666666666666666666666666666666666666666666666666666666666666  sipnab_0.4.3_arm64.deb
7777777777777777777777777777777777777777777777777777777777777777  sipnab-0.4.3-1.aarch64-noaudio.rpm
8888888888888888888888888888888888888888888888888888888888888888  sipnab-0.4.3-1.aarch64.rpm
9999999999999999999999999999999999999999999999999999999999999999  sipnab-0.4.3-1.x86_64-noaudio.rpm
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab  sipnab-0.4.3-1.x86_64.rpm
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbc  sipnab-0.4.3.cdx.json
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccd  sipnab-audio-0.4.3.cdx.json
EOF
}

# --- success path -----------------------------------------------------------
sums="$tmp/SHA256SUMS.txt"; good_sums > "$sums"

# The fixture matches the shape of a real release manifest, checked by the same
# script that meets the real one in CI rather than by a comment claiming it.
# Without this the fixture can narrow back to four tarballs and every assertion
# below stays green over a file no release ever produced.
if bash "$HERE/test-real-sums.sh" "$sums" 0.4.3 >/dev/null 2>&1; then
  ok "fixture has the shape of a real release manifest"
else
  bad "fixture has the shape of a real release manifest"
  bash "$HERE/test-real-sums.sh" "$sums" 0.4.3 || true
fi
out="$("$GEN" 0.4.3 "$sums" 2>"$tmp/err")"; rc=$?
[ $rc -eq 0 ] && ok "exits 0 on valid input" || { bad "exits 0 on valid input (rc=$rc)"; cat "$tmp/err"; }

grep -q 'version "0.4.3"' <<<"$out" && ok "emits version 0.4.3" || bad "emits version 0.4.3"
grep -q 'd1c0d9fcce3dcb79599e96efa317c7b2433128088bddeddb1065fead35bea7c0' <<<"$out" && ok "macOS arm64 sha" || bad "macOS arm64 sha"
grep -q '17a1bda119ebf54ca5af286ae4c55becd0430648664afd2f5fede3eb439e6bbd' <<<"$out" && ok "macOS x86_64 sha" || bad "macOS x86_64 sha"
grep -q '858136ae7e3faca63d9521156e2f0897e389efbf81efc8bdcafe4511f215a5bb' <<<"$out" && ok "linux arm64 sha"  || bad "linux arm64 sha"
grep -q 'f94435e79a5aaae1cb24050cc9ac7f94041588c845b425f2ca73750a8b89e3c0' <<<"$out" && ok "linux x86_64 sha" || bad "linux x86_64 sha"
grep -q 'releases/download/v0.4.3/sipnab-0.4.3-aarch64-apple-darwin.tar.gz' <<<"$out" && ok "macOS arm64 url" || bad "macOS arm64 url"

# Each url must carry ITS OWN digest. Every check above greps the whole
# document, so all four url/sha pairs could be swapped across architectures and
# still pass — demonstrated: 21/21 green with each url bound to another arch's
# digest, and every `brew install` then aborting on sha256 mismatch. Presence
# of a digest somewhere is not a binding.
#
# The expected digest is looked up from the SHA256SUMS input by the filename in
# the url, so this derives the pairing rather than restating it.
pairs=$(awk '
  /url "/     { if (match($0, /sipnab-[^"]*\.tar\.gz/)) u = substr($0, RSTART, RLENGTH) }
  /sha256 "/  { if (match($0, /[0-9a-f]{64}/))            { print u, substr($0, RSTART, RLENGTH); u = "" } }
' <<<"$out")
pair_count=$(printf '%s\n' "$pairs" | grep -c . || true)
[ "$pair_count" -eq 4 ] && ok "formula emits 4 url/sha pairs" \
  || bad "formula emits 4 url/sha pairs (got $pair_count)"

mismatched=0
while read -r fname sha; do
  [ -n "$fname" ] || continue
  want=$(awk -v f="$fname" '$2 == f { print $1 }' "$sums")
  if [ "$sha" != "$want" ]; then
    mismatched=$((mismatched + 1))
    printf '  %s carries %s, SHA256SUMS says %s\n' "$fname" "$sha" "$want"
  fi
done <<<"$pairs"
[ "$mismatched" -eq 0 ] && ok "every url carries its own digest" \
  || bad "every url carries its own digest ($mismatched mismatched)"

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
#
# This comment sat directly above `echo` and the summary: there was NO
# assertion. The property is real in the generator -- it compares $2 == n, not
# $2 ~ n -- and was wholly unasserted here, so relaxing the generator to a
# regex match left 21/21 green while a sums file whose only match is
# `sipnab-0x4y3-...` would bind the real v0.4.3 url to that bogus checksum.
literal="$tmp/literal.txt"
cat > "$literal" <<'EOF'
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  sipnab-0x4y3-aarch64-apple-darwin.tar.gz
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  sipnab-0x4y3-x86_64-apple-darwin.tar.gz
cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  sipnab-0x4y3-aarch64-unknown-linux-gnu.tar.gz
dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd  sipnab-0x4y3-x86_64-unknown-linux-gnu.tar.gz
EOF
lit_out="$("$GEN" 0.4.3 "$literal" 2>/dev/null)"; lit_rc=$?
if [ $lit_rc -ne 0 ]; then
  ok "version is matched literally, not as a regex (0.4.3 does not match 0x4y3)"
elif grep -qE 'aaaaaaaa|bbbbbbbb|cccccccc|dddddddd' <<<"$lit_out"; then
  bad "version matched 0x4y3 as a regex and bound a bogus checksum to the real url"
else
  ok "version is matched literally, not as a regex (0.4.3 does not match 0x4y3)"
fi

echo
printf 'passed: %d  failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
