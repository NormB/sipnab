#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Take a capture off the harness AND record where it came from, in the same
# command.
#
# # Why the two are one command
#
# The harness has always produced captures and always thrown them away:
# `captures/*.pcap` is ignored and only `.gitkeep` is tracked, so every run
# reproduced traffic no test would ever see again while the project went short
# of fixtures (LIVE2 in docs/design/backlog.md).
#
# The reason it could not simply keep them is LIVE4: a capture with no recorded
# provenance cannot be safely promoted afterwards, because nobody can later
# establish which scenario produced it, which media anchor was in force, or
# whether it carries anything that must not be committed. Five undocumented
# captures sat in `captures/` for two weeks and had to be deleted rather than
# promoted, for exactly that reason.
#
# So this script refuses to run without `--pins`. Deciding what a capture is
# FOR is cheap while the stack is still up and impossible a fortnight later.
#
# # What it does not do
#
# It does not decide the capture's home. `home` is written as `undecided`, and
# `promote.sh` is what moves a capture into `tests/pcap-samples/`. Deletion is
# the default: a capture nobody promotes is one `make clean` away from gone,
# which is the correct end for most of them.
#
# Usage:
#   harness/scripts/capture.sh --name <slug> --pins "<what this pins>" \
#       [--seconds N] [--filter <bpf>] [--container <name>]

set -uo pipefail

NAME=""
PINS=""
SECONDS_TO_RUN=20
FILTER="udp or tcp"
CONTAINER="sipnab-proxy"

die() { echo "error: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --name)      NAME="${2:-}"; shift 2 ;;
        --pins)      PINS="${2:-}"; shift 2 ;;
        --seconds)   SECONDS_TO_RUN="${2:-}"; shift 2 ;;
        --filter)    FILTER="${2:-}"; shift 2 ;;
        --container) CONTAINER="${2:-}"; shift 2 ;;
        -h|--help)   sed -n '3,36p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$NAME" ] || die "--name is required"
case "$NAME" in
    *[!a-z0-9-]*) die "--name must be lower-case letters, digits and hyphens: $NAME" ;;
esac
# THE refusal this script exists for. A capture whose purpose nobody wrote down
# at the time it was taken is one that cannot be promoted later, so taking it
# without saying is worse than not taking it.
[ -n "$PINS" ] || die "--pins is required: say what this capture is meant to pin, now, while the stack is up"

cd "$(git rev-parse --show-toplevel)" || die "not in a git worktree"
OUT_DIR="harness/captures"
PCAP="$OUT_DIR/$NAME.pcap"
META="$OUT_DIR/$NAME.provenance.json"
[ -d "$OUT_DIR" ] || die "no $OUT_DIR — run this from a checkout with the harness"
[ -e "$PCAP" ] && die "$PCAP exists; pick another --name or delete it"

docker inspect -f '{{.Id}}' "$CONTAINER" >/dev/null 2>&1 \
    || die "container $CONTAINER is not running — bring the harness up first (make -C harness up)"

# The anchor ACTUALLY in force, read from the container rather than from .env.
# The two drift the moment anyone runs `make up ANCHOR=x`, and a fixture
# labeled with the wrong anchor is worse than one labeled with none.
ANCHOR=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' opensips-1 2>/dev/null \
    | sed -n 's/^MEDIA_ANCHOR=//p')
ANCHOR="${ANCHOR:-unknown}"
OPENSIPS_IMAGE=$(docker inspect -f '{{.Image}}' opensips-1 2>/dev/null || echo unknown)

echo "capturing ${SECONDS_TO_RUN}s from $CONTAINER (anchor: $ANCHOR, filter: $FILTER)"
# tcpdump, not sipnab -O: a fixture written by the program under test cannot
# contradict it. The capture has to come from somewhere else to be evidence.
docker exec "$CONTAINER" timeout "$SECONDS_TO_RUN" \
    tcpdump -i any -nn -s 0 -U -w "/captures/$NAME.pcap" "$FILTER" >/dev/null 2>&1
rc=$?
# 124 is the timeout firing, which is the normal end of a timed capture.
if [ "$rc" -ne 0 ] && [ "$rc" -ne 124 ]; then
    die "tcpdump exited $rc; no capture written"
fi
PACKETS=$(docker exec "$CONTAINER" tcpdump -r "/captures/$NAME.pcap" -nn 2>/dev/null | wc -l)
# A pcap with a header and no packets is 24 bytes, so `-s` calls it non-empty.
# That is exactly the shape a capture takes when the harness is up and idle,
# and it was the first thing this script produced: a provenance record
# describing zero packets. Refuse it and take the empty file with it, rather
# than leaving something that looks like a capture.
if [ "${PACKETS:-0}" -eq 0 ]; then
    rm -f "$PCAP"
    die "captured 0 packets in ${SECONDS_TO_RUN}s with filter '$FILTER'. The harness \
is up but idle unless something places calls -- drive it (docker exec sipp-uac \
sipp ...) while this runs, or widen the filter. Nothing written."
fi
SHA=$(sha256sum "$PCAP" | cut -d' ' -f1)
TAKEN=$(date -u +%Y-%m-%dT%H:%M:%SZ)

python3 - "$META" "$NAME" "$TAKEN" "$SECONDS_TO_RUN" "$ANCHOR" "$FILTER" \
         "$OPENSIPS_IMAGE" "$PACKETS" "$SHA" "$PINS" <<'PY'
import json, sys
(meta, name, taken, secs, anchor, filt, image, packets, sha, pins) = sys.argv[1:11]
json.dump({
    "name": name,
    "taken_at": taken,
    "seconds": int(secs),
    "media_anchor": anchor,
    "bpf_filter": filt,
    "opensips_image": image,
    "packets": int(packets),
    "sha256": sha,
    "pins": pins,
    # Not "fixture". promote.sh is what decides that, and the default for
    # everything else is deletion -- see LIVE4.
    "home": "undecided",
}, open(meta, "w"), indent=1, sort_keys=True)
open(meta, "a").write("\n")
PY

echo "wrote $PCAP ($PACKETS packets)"
echo "wrote $META"
echo "home=undecided — promote it with harness/scripts/promote.sh --name $NAME, or let it be deleted"
