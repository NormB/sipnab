#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Promote one harness capture into the committed fixture set, with the record
# that makes it usable by somebody who was not there.
#
# # The rule this enforces
#
# LIVE4 in docs/design/backlog.md: every capture gets one of three homes,
# decided at the time it is taken -- a committed fixture, the private corpus
# reached through SIPNAB_CORPUS, or deletion -- and **the default is
# deletion**. This script is the first of those three, and it refuses anything
# `capture.sh` did not record provenance for, because that record is the whole
# difference between a fixture and a file.
#
# The other two homes need no script. The private corpus is a directory outside
# this tree, and deletion is `rm`.
#
# Usage:
#   harness/scripts/promote.sh --name <slug>

set -uo pipefail

NAME=""
die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --name)    NAME="${2:-}"; shift 2 ;;
        -h|--help) sed -n '3,21p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done
[ -n "$NAME" ] || die "--name is required"

cd "$(git rev-parse --show-toplevel)" || die "not in a git worktree"
SRC="harness/captures/$NAME.pcap"
META="harness/captures/$NAME.provenance.json"
DEST="tests/pcap-samples/$NAME.pcap"
MANIFEST="tests/pcap-samples/PROVENANCE.md"

[ -r "$SRC" ] || die "no $SRC"
# The refusal that matters. A capture with no sidecar was taken by hand rather
# than by capture.sh, so nobody recorded the anchor or the scenario, and the
# honest answer for it is deletion rather than promotion.
[ -r "$META" ] || die "no $META -- this capture has no provenance record, so it cannot be promoted. Re-take it with harness/scripts/capture.sh"
[ -e "$DEST" ] && die "$DEST already exists"
[ -r "$MANIFEST" ] || die "no $MANIFEST"

# One field per LINE. The first version of this read a single whitespace-split
# line, and `pins` -- which is prose, and the only field that matters -- was
# scattered across seven variables and reported as the capture's "home". A
# record whose most important field cannot survive being read is not a record.
mapfile -t FIELDS < <(python3 harness/scripts/read-provenance.py "$META")
[ "${#FIELDS[@]}" -eq 8 ] || die "could not read the provenance record from $META"
PINS="${FIELDS[0]}"; ANCHOR="${FIELDS[1]}"; TAKEN="${FIELDS[2]}"; FILTER="${FIELDS[3]}"
PACKETS="${FIELDS[4]}"; SHA="${FIELDS[5]}"; SECONDS_TAKEN="${FIELDS[6]}"; CAPTURE_HOME="${FIELDS[7]}"
[ "$CAPTURE_HOME" = "undecided" ] || die "this capture's home is already '$CAPTURE_HOME'"

# Verify the bytes are the ones the record describes. A sidecar that has come
# apart from its capture is a record of a different file.
NOW=$(sha256sum "$SRC" | cut -d' ' -f1)
[ "$NOW" = "$SHA" ] \
    || die "$SRC no longer matches its recorded sha256 -- the record describes a different file"

cp "$SRC" "$DEST"
{
    printf '\n### %s\n\n' "$NAME.pcap"
    printf -- '- **Taken:** %s from the docker-compose harness, %ss\n' "$TAKEN" "$SECONDS_TAKEN"
    printf -- '- **Media anchor:** %s\n' "$ANCHOR"
    printf -- '- **Filter:** `%s`\n' "$FILTER"
    printf -- '- **Packets:** %s\n' "$PACKETS"
    printf -- '- **SHA-256:** `%s`\n' "$NOW"
    printf -- '- **Pins:** %s\n' "$PINS"
} >> "$MANIFEST"

python3 harness/scripts/read-provenance.py --set-home fixture "$META"

echo "promoted $DEST"
echo "recorded in $MANIFEST"
echo "if it was on the pre-manifest list in tests/repo_hygiene_test.rs, take it off: one record per fixture"
