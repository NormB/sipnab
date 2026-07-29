#!/usr/bin/env bash
# Decide whether a ThreadSanitizer run found anything, and name what it found.
#
# Usage: ops/tsan/verdict.sh <binary> <cargo-log> <per-process-log-dir>
#
# Exits 0 when the run is clean, 1 when it found something in the fatal set, and
# 1 when the binary is not instrumented — a clean report out of an uninstrumented
# build is not a clean run, it is no run at all.
#
# This lives in a script, with `test-verdict.sh` next to it, because the version
# that lived inline in `sanitizers.yml` was wrong in the one direction nobody
# checks. Its warning loop was a bare `grep ... | sort -u | while read`, and
# GitHub runs `run:` blocks under `bash -e -o pipefail`: with no findings, grep
# exits 1, pipefail promotes it, and -e killed the step before it could print
# its verdict. The job therefore FAILED, silently, exactly when the tree was
# clean -- and PASSED while a thread leak was present, because a match made grep
# succeed. It went green on one commit for that reason. Inline YAML cannot be
# run against a fixture; a script can, which is the whole point of this file.

set -uo pipefail

BIN=${1:?usage: verdict.sh <binary> <cargo-log> <log-dir>}
CARGO_LOG=${2:?usage: verdict.sh <binary> <cargo-log> <log-dir>}
LOG_DIR=${3:?usage: verdict.sh <binary> <cargo-log> <log-dir>}

# Findings that mean the job has done its job. `thread leak` is here and not in
# the tolerated set: sipnab's fatal startup paths spawn the capture thread
# before they can fail, so a leak means one was abandoned holding an open
# capture source -- `sipnab -I /nonexistent.pcap` was once enough to cause it.
FATAL='data race|thread leak|heap-use-after-free|lock-order-inversion|signal-unsafe call|unlock of an unlocked mutex|destroy of a locked mutex'

# A build that quietly lost -Zsanitizer=thread reports no races forever, and
# "no races" is the most reassuring possible way to say nothing was checked.
#
# `grep -c`, not `grep -q`, and the count captured rather than tested through a
# pipeline. `grep -q` exits the instant it matches, which closes the pipe under
# a still-writing `nm`; nm dies of SIGPIPE with status 141, `pipefail` promotes
# that to the pipeline's status, and the check reports "not instrumented" for a
# binary that plainly is. It only shows up on a big binary — sipnab's debug
# build is ~280 MB of symbols, far past the 64 KB pipe buffer — which is exactly
# why the fixture in test-verdict.sh has thousands of symbols rather than two.
symbols=$(nm -C "$BIN" 2>/dev/null | grep -c __tsan_init || true)
if [ "${symbols:-0}" -eq 0 ]; then
  echo "::error::$BIN is not ThreadSanitizer-instrumented — a clean run would be vacuous"
  exit 1
fi

# Every process gets its own log via TSAN_OPTIONS=log_path, because the suites
# spawn the sipnab binary and consume its stderr: a report from a child reaches
# the cargo log only if some test happens to print that stderr into an assertion
# message.
logs=()
[ -f "$CARGO_LOG" ] && logs+=("$CARGO_LOG")
while IFS= read -r f; do
  logs+=("$f")
done < <(find "$LOG_DIR" -maxdepth 1 -type f -name 'tsan.*' 2>/dev/null | sort)

if [ ${#logs[@]} -eq 0 ]; then
  echo "::error::no logs to read at all ($CARGO_LOG, $LOG_DIR/tsan.*) — nothing was examined"
  exit 1
fi

# `|| true` on every grep, deliberately: "found nothing" is the expected result
# here and must not be an error. That is the bug this script exists to not have.
findings=$(grep -hoE 'WARNING: ThreadSanitizer: [a-z -]+' "${logs[@]}" 2>/dev/null |
  sed 's/[[:space:]]*$//' | sort -u || true)

if [ -n "$findings" ]; then
  fatal=$(printf '%s\n' "$findings" | grep -E ": ($FATAL)\$" || true)
  if [ -n "$fatal" ]; then
    printf '%s\n' "$fatal"
    echo "::error::ThreadSanitizer reported the findings above — see the uploaded logs"
    exit 1
  fi
  # Anything outside the fatal set is surfaced without failing, and without
  # claiming a finding type that was never matched.
  while IFS= read -r w; do
    [ -n "$w" ] && echo "::warning::$w (not in the fatal set; not failing the job)"
  done <<<"$findings"
fi

echo "no races and no leaked threads reported"
