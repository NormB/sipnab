#!/usr/bin/env bash
#
# test-real-sums.sh [SUMS_FILE VERSION]
#
# Run the REAL Homebrew formula generator against a REAL release manifest.
#
# packaging/homebrew/test-update-formula.sh already covers the generator in
# depth — success, failure, and adversarial input — but every one of those runs
# feeds it a FIXTURE. The generator only ever met the real `SHA256SUMS.txt` on a
# release tag, which is the worst place to learn something is wrong: the tag is
# cut and the workflow is already publishing. That is exactly how 0.5.113
# shipped a broken `.rpm` (#244).
#
# "The harness passes" and "the generator works on real input" are different
# claims. This asserts the second.
#
# With no arguments it fetches the latest published release's SHA256SUMS.txt
# through the GitHub API (`gh`), which is how CI runs it. With two arguments it
# uses a local file, which is how the Rust gate
# `the_homebrew_generator_meets_a_real_sums_file_in_ci` mutation-tests it
# offline: a checker nobody has watched fail is decoration.
#
# It NEVER skips. A download that fails, returns nothing, or returns something
# that is not shaped like a release manifest is a failure, not a reason to exit
# 0 — an absent measurement must not read as a passing one.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEN="$HERE/update-formula.sh"

pass=0
fail=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok()  { printf '  ok   %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL %s\n' "$1"; fail=$((fail+1)); }
die() { printf 'test-real-sums: %s\n' "$1" >&2; exit 1; }

SUMS="${1-}"
VERSION="${2-}"

if [ -z "$SUMS" ]; then
  command -v gh >/dev/null 2>&1 || die "gh is required to fetch a real release manifest"
  repo="${GH_REPO:-NormB/sipnab}"
  tag="$(gh api "repos/${repo}/releases/latest" --jq .tag_name)" \
    || die "could not read the latest release of ${repo}"
  [ -n "$tag" ] || die "the latest release of ${repo} has no tag"
  VERSION="${tag#v}"
  SUMS="$tmp/SHA256SUMS.txt"
  gh release download "$tag" --repo "$repo" --pattern SHA256SUMS.txt --dir "$tmp" \
    || die "could not download SHA256SUMS.txt from ${repo} ${tag}"
  printf 'real release manifest: %s %s\n' "$repo" "$tag"
fi

[ -f "$SUMS" ] || die "SHA256SUMS file not found: $SUMS"
[ -n "$VERSION" ] || die "could not determine the release version"

printf 'checking %s against version %s\n' "$SUMS" "$VERSION"

# --- is this a real release manifest? ---------------------------------------
#
# Checked BEFORE the generator runs. A truncated download, an empty asset or a
# stub would otherwise sail through: the generator only needs four tar.gz lines,
# so it cannot tell a whole release from a fragment of one, and "the fetch
# succeeded" would become indistinguishable from "the fetch returned nothing
# real". release.yml builds the file with
#   sha256sum *.tar.gz *.deb *.rpm *.cdx.json > SHA256SUMS.txt
# so all four kinds are present in every genuine one.
lines=$(grep -c . "$SUMS" || true)
[ "$lines" -ge 12 ] \
  && ok "manifest has $lines entries (>= 12)" \
  || bad "manifest has only $lines entries — not a whole release"

for kind in '\.tar\.gz$' '\.deb$' '\.rpm$' '\.cdx\.json$'; do
  n=$(awk '{print $2}' "$SUMS" | grep -cE "$kind" || true)
  [ "$n" -ge 1 ] \
    && ok "manifest carries $n artifact(s) matching $kind" \
    || bad "manifest carries no artifact matching $kind — release.yml checksums all four kinds"
done

# Every line must be a sha256 plus a filename. A stray log line or an HTML
# error page saved to disk fails here rather than three steps later.
malformed=$(grep -cvE '^[0-9a-f]{64}[[:space:]]+[^[:space:]]+$' "$SUMS" || true)
[ "$malformed" -eq 0 ] \
  && ok "every manifest line is <sha256>  <filename>" \
  || bad "$malformed manifest line(s) are not <sha256>  <filename>"

# The version must actually appear, or the whole run proves nothing about this
# release: the generator would fail for the trivial reason that no line matches.
named=$(awk -v v="-${VERSION}" '$2 ~ v { n++ } END { print n+0 }' "$SUMS")
[ "$named" -ge 4 ] \
  && ok "manifest names version ${VERSION} on $named artifact(s)" \
  || bad "manifest names version ${VERSION} on only $named artifact(s)"

# --- the real generator, on that real input ---------------------------------
out="$("$GEN" "$VERSION" "$SUMS" 2>"$tmp/err")"; rc=$?
if [ $rc -eq 0 ]; then
  ok "update-formula.sh exits 0 on the real manifest"
else
  bad "update-formula.sh exits 0 on the real manifest (rc=$rc)"
  cat "$tmp/err" >&2
fi

grep -q "version \"${VERSION}\"" <<<"$out" \
  && ok "formula declares version ${VERSION}" \
  || bad "formula declares version ${VERSION}"

# Four url/sha pairs, each digest bound to ITS OWN url. Presence of a digest
# somewhere in the document is not a binding: all four could be rotated across
# architectures and every whole-file grep would still pass, with `brew install`
# aborting on a sha256 mismatch for three of the four platforms.
pairs=$(awk '
  /url "/    { if (match($0, /sipnab-[^"]*\.tar\.gz/)) u = substr($0, RSTART, RLENGTH) }
  /sha256 "/ { if (match($0, /[0-9a-f]{64}/))          { print u, substr($0, RSTART, RLENGTH); u = "" } }
' <<<"$out")
pair_count=$(printf '%s\n' "$pairs" | grep -c . || true)
[ "$pair_count" -eq 4 ] \
  && ok "formula emits 4 url/sha pairs" \
  || bad "formula emits 4 url/sha pairs (got $pair_count)"

mismatched=0
while read -r fname sha; do
  [ -n "$fname" ] || continue
  want=$(awk -v f="$fname" '$2 == f { print $1 }' "$SUMS")
  if [ -z "$want" ]; then
    mismatched=$((mismatched + 1))
    printf '  %s is not in the manifest at all\n' "$fname"
  elif [ "$sha" != "$want" ]; then
    mismatched=$((mismatched + 1))
    printf '  %s carries %s, manifest says %s\n' "$fname" "$sha" "$want"
  fi
done <<<"$pairs"
[ "$mismatched" -eq 0 ] \
  && ok "every url carries the digest the real manifest gives it" \
  || bad "every url carries the digest the real manifest gives it ($mismatched wrong)"

# The tap ships gnu + darwin only. A real manifest also carries musl tarballs,
# .deb, .rpm and two SBOMs; none of their digests may reach the formula.
leaked=0
while read -r sha name; do
  case "$name" in
    sipnab-"${VERSION}"-aarch64-apple-darwin.tar.gz|\
    sipnab-"${VERSION}"-x86_64-apple-darwin.tar.gz|\
    sipnab-"${VERSION}"-aarch64-unknown-linux-gnu.tar.gz|\
    sipnab-"${VERSION}"-x86_64-unknown-linux-gnu.tar.gz) continue ;;
  esac
  if grep -qF "$sha" <<<"$out"; then
    leaked=$((leaked + 1))
    printf '  digest of %s reached the formula\n' "$name"
  fi
done < "$SUMS"
[ "$leaked" -eq 0 ] \
  && ok "no non-tap artifact digest reaches the formula" \
  || bad "no non-tap artifact digest reaches the formula ($leaked leaked)"

# Real Ruby syntax check when available. `brew` will not forgive a formula that
# does not parse, and the generator builds it by string interpolation.
if command -v ruby >/dev/null 2>&1; then
  printf '%s\n' "$out" > "$tmp/sipnab.rb"
  ruby -c "$tmp/sipnab.rb" >/dev/null 2>&1 \
    && ok "generated formula is valid ruby" \
    || bad "generated formula is valid ruby"
else
  printf '  note ruby absent; syntax check skipped\n'
fi

echo
printf 'passed: %d  failed: %d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
