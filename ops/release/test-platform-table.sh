#!/usr/bin/env bash
# Scenario tests for ops/release/platform-table.sh.
#
# Run from anywhere:  bash ops/release/test-platform-table.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TABLE="$HERE/platform-table.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

PASSED=0
FAILED=0
pass() {
  echo "PASS: $1"
  PASSED=$((PASSED + 1))
}
fail() {
  echo "FAIL: $1"
  echo "      $2"
  FAILED=$((FAILED + 1))
}

# The six tarballs a real release publishes, by name only — the script reads
# filenames, never contents.
REAL=(
  sipnab-9.9.9-x86_64-unknown-linux-gnu.tar.gz
  sipnab-9.9.9-aarch64-unknown-linux-gnu.tar.gz
  sipnab-9.9.9-x86_64-unknown-linux-musl.tar.gz
  sipnab-9.9.9-aarch64-unknown-linux-musl.tar.gz
  sipnab-9.9.9-x86_64-apple-darwin.tar.gz
  sipnab-9.9.9-aarch64-apple-darwin.tar.gz
)

setup() {
  rm -rf "$WORK/a"
  mkdir -p "$WORK/a"
  for f in "${REAL[@]}"; do touch "$WORK/a/$f"; done
}

run_table() {
  OUT=$(bash --noprofile --norc -e -o pipefail "$TABLE" "$1" 2>&1)
  RC=$?
}

# 1. A full release directory produces a row per tarball.
setup
run_table "$WORK/a"
rows=$(printf '%s\n' "$OUT" | grep -c '^| .* | `sipnab-')
if [ "$RC" -eq 0 ] && [ "$rows" -eq "${#REAL[@]}" ]; then
  pass "every published tarball gets a row (${rows}/${#REAL[@]})"
else
  fail "every published tarball gets a row" "rc=$RC rows=$rows out=$OUT"
fi

# 2. THE POINT OF THE TABLE. The row must decode the triple into something a
#    human can act on, and must explain the word that prompted all this.
setup
run_table "$WORK/a"
if [[ "$OUT" == *"glibc 2.36+"* ]] && [[ "$OUT" == *"static"* ]] &&
  [[ "$OUT" == *"Apple silicon"* ]] && [[ "$OUT" == *"vendor"* ]]; then
  pass "the table decodes gnu/musl/arch and explains the vendor field"
else
  fail "the table decodes gnu/musl/arch and explains the vendor field" "out=$OUT"
fi

# 3. Rows are DERIVED. Half a release must produce half a table, never the six
#    rows a hand-written table would always print.
rm -rf "$WORK/a"
mkdir -p "$WORK/a"
touch "$WORK/a/sipnab-9.9.9-x86_64-unknown-linux-musl.tar.gz"
run_table "$WORK/a"
rows=$(printf '%s\n' "$OUT" | grep -c '^| .* | `sipnab-')
if [ "$RC" -eq 0 ] && [ "$rows" -eq 1 ] && [[ "$OUT" != *"apple-darwin"* ]]; then
  pass "a partial release yields a partial table, not a fixed one"
else
  fail "a partial release yields a partial table, not a fixed one" "rc=$RC rows=$rows"
fi

# 4. An unrecognised target is a hard error. If the build matrix gains a target
#    and this script does not, the table would otherwise publish silently
#    missing a platform — the exact "looks complete, is not" failure the rest of
#    this repository's gates were audited for.
setup
touch "$WORK/a/sipnab-9.9.9-riscv64gc-unknown-linux-gnu.tar.gz"
run_table "$WORK/a"
if [ "$RC" -ne 0 ] && [[ "$OUT" == *"riscv64gc"* ]]; then
  pass "an unmapped target fails loudly instead of vanishing from the table"
else
  fail "an unmapped target fails loudly instead of vanishing from the table" "rc=$RC out=$OUT"
fi

# 5. An empty directory is an error, not an empty table. No artifacts means the
#    build did not produce them, which a release body must not paper over.
rm -rf "$WORK/a"
mkdir -p "$WORK/a"
run_table "$WORK/a"
if [ "$RC" -ne 0 ] && [[ "$OUT" == *"no .tar.gz artifacts"* ]]; then
  pass "an empty artifacts directory is an error"
else
  fail "an empty artifacts directory is an error" "rc=$RC out=$OUT"
fi

# 6. Non-tarball artifacts (deb/rpm/sums/SBOM) are ignored rather than tripping
#    the unmapped check — they sit in the same directory at release time.
setup
touch "$WORK/a/sipnab_9.9.9_amd64.deb" "$WORK/a/sipnab-9.9.9-1.x86_64.rpm" \
  "$WORK/a/SHA256SUMS.txt" "$WORK/a/sipnab-9.9.9.cdx.json" \
  "$WORK/a/sipnab-9.9.9-x86_64-apple-darwin.tar.gz.sha256"
run_table "$WORK/a"
rows=$(printf '%s\n' "$OUT" | grep -c '^| .* | `sipnab-')
if [ "$RC" -eq 0 ] && [ "$rows" -eq "${#REAL[@]}" ]; then
  pass "deb/rpm/sums/SBOM in the same directory are ignored"
else
  fail "deb/rpm/sums/SBOM in the same directory are ignored" "rc=$RC rows=$rows out=$OUT"
fi

echo
echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
