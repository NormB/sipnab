#!/usr/bin/env bash
# Emit the "which download do I want" table for a release body.
#
# Usage: ops/release/platform-table.sh <artifacts-dir>
#
# Rows are derived from the artifacts that ACTUALLY EXIST in the directory, not
# from a hand-kept list, so the table cannot advertise a build that failed or
# omit one that was added. An artifact whose platform this script does not
# recognise is a hard error rather than a blank row: a silently unmapped target
# would publish a table that looks complete while missing a platform.
#
# It exists because `x86_64-unknown-linux-gnu` is not self-explanatory. The
# `unknown` in it is the VENDOR field of the Rust target triple -- the canonical
# value meaning "no specific vendor", which is why the macOS artifacts say
# `apple` in the same position. It is not a failed detection, and the filenames
# are deliberately left as the canonical triple: they match `rustc -vV`, they are
# what SHA256SUMS.txt and the provenance attestation cover, and install.sh
# constructs them. What was missing was the explanation, not a rename.

set -uo pipefail

DIR=${1:?usage: platform-table.sh <artifacts-dir>}

if [ ! -d "$DIR" ]; then
  echo "platform-table: $DIR is not a directory" >&2
  exit 1
fi

# Describe a tarball from its filename components. Keyed on the same target
# triples the release matrix builds, so adding a target to the matrix without
# adding it here fails loudly below.
describe() {
  case "$1" in
  *-x86_64-unknown-linux-gnu.tar.gz) echo "Linux · Intel/AMD 64-bit|glibc 2.36+ (Debian 12+, Ubuntu 23.04+), libpcap required" ;;
  *-aarch64-unknown-linux-gnu.tar.gz) echo "Linux · ARM 64-bit|glibc 2.36+, libpcap required" ;;
  *-x86_64-unknown-linux-musl.tar.gz) echo "Linux · Intel/AMD 64-bit|static — any distro, any glibc; no TUI audio" ;;
  *-aarch64-unknown-linux-musl.tar.gz) echo "Linux · ARM 64-bit|static — any distro, any glibc; no TUI audio" ;;
  *-x86_64-apple-darwin.tar.gz) echo "macOS · Intel|" ;;
  *-aarch64-apple-darwin.tar.gz) echo "macOS · Apple silicon|" ;;
  *) return 1 ;;
  esac
}

rows=""
unmapped=""
for path in "$DIR"/*.tar.gz; do
  [ -e "$path" ] || continue
  file=$(basename "$path")
  if desc=$(describe "$file"); then
    rows="${rows}| ${desc%%|*} | \`${file}\` | ${desc#*|} |"$'\n'
  else
    unmapped="${unmapped}  ${file}"$'\n'
  fi
done

if [ -n "$unmapped" ]; then
  echo "platform-table: no description for these artifacts:" >&2
  printf '%s' "$unmapped" >&2
  echo "add them to describe() — a release table that silently omits a platform is worse than none" >&2
  exit 1
fi

if [ -z "$rows" ]; then
  echo "platform-table: no .tar.gz artifacts found in $DIR — nothing to describe" >&2
  exit 1
fi

cat <<'HEADER'
### Which download do I want?

| Platform | File | Notes |
|----------|------|-------|
HEADER
printf '%s' "$rows"
cat <<'FOOTER'

`.deb` and `.rpm` packages are attached as well, and
`curl -fsSL https://www.sipnab.com/install.sh | sh` picks the right one for you.

<sub>The `unknown` in `x86_64-unknown-linux-gnu` is the <em>vendor</em> field of
the Rust target triple — the canonical value for "no specific vendor", which is
why the macOS files say `apple` in the same position. It is part of the platform
name, not a failed detection.</sub>

Verify a download against `SHA256SUMS.txt`, or with
`gh attestation verify <file> --repo NormB/sipnab`.
FOOTER
