#!/usr/bin/env bash
# Scenario tests for ops/tsan/verdict.sh.
#
# The verdict is run the way GitHub runs it -- `bash -e -o pipefail` -- because
# that is what broke the inline version: a clean tree made its `grep` exit 1,
# pipefail promoted it, and -e killed the step before it printed anything. The
# job failed silently when there was nothing wrong and passed while a thread
# leak was present. Scenario 1 below is that exact case, and it is the reason
# this file exists.
#
# Run from anywhere:  bash ops/tsan/test-verdict.sh

set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
VERDICT="$HERE/verdict.sh"
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

# `nm` is stubbed on PATH rather than run against a compiled fixture, the same
# way scripts/test-pre-commit.sh stubs cargo.
#
# The reason is not convenience. The guard's contract is about what it does with
# nm's OUTPUT, and the output shape that breaks it is a large symbol table whose
# match lands near the START: `grep -q` exits on that match while nm is still
# writing, nm dies of SIGPIPE (141), pipefail promotes 141 to the pipeline's
# status, and an instrumented binary gets reported as uninstrumented. sipnab's
# real debug binary has ~284,000 symbols and hits this every time.
#
# A cc-built fixture cannot reproduce it: the linker placed __tsan_init last in
# every ordering tried, so grep read to EOF and the pipe never broke. A fixture
# that cannot fail the way production fails is a test of nothing — which is the
# entire subject of this file — so the stub produces the real shape directly.
mkdir -p "$WORK/bin"
PATH="$WORK/bin:$PATH"
export PATH

# $1: "with" to include __tsan_init as the FIRST line, "without" to omit it.
make_nm() {
  {
    echo '#!/usr/bin/env bash'
    echo '[ "$1" = "-C" ] && shift'
    if [ "$1" = "with" ]; then
      echo 'echo "00000000001acb00 T __tsan_init"'
    fi
    # ~100k symbols, several MB — far past the 64 KB pipe buffer, so a reader
    # that stops early leaves this writing.
    echo 'seq 1 100000 | awk "{printf \"%016x T sipnab_symbol_%d\\n\", \$1, \$1}"'
  } >"$WORK/bin/nm"
  chmod +x "$WORK/bin/nm"
}

BIN_OK="$WORK/anybinary"
BIN_BAD="$WORK/anybinary"
touch "$BIN_OK"

# Guard the guard: if the stub ever stops producing more than a pipe buffer of
# output, every scenario below silently stops testing the thing it exists for.
make_nm with
stub_bytes=$(nm -C "$BIN_OK" | wc -c)
if [ "$stub_bytes" -lt 65536 ]; then
  echo "FAIL: nm stub emits only ${stub_bytes}B — under the 64 KB pipe buffer, so it cannot reproduce the SIGPIPE case"
  exit 1
fi

# Fresh log tree per scenario, so no scenario inherits another's findings.
setup() {
  rm -rf "$WORK/run"
  mkdir -p "$WORK/run/tsan-logs"
  : >"$WORK/run/cargo.log"
}

# Run the verdict exactly as the workflow does.
run_verdict() {
  OUT=$(bash --noprofile --norc -e -o pipefail "$VERDICT" \
    "$1" "$WORK/run/cargo.log" "$WORK/run/tsan-logs" 2>&1)
  RC=$?
}

# 1. THE REGRESSION. A clean run must pass. The inline version exited 1 here,
#    with no output, purely because grep found nothing.
setup
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 0 ] && [[ "$OUT" == *"no races and no leaked threads"* ]]; then
  pass "a clean run passes and says so"
else
  fail "a clean run passes and says so" "rc=$RC out=$OUT"
fi

# 2. A data race fails, and the message names what was matched.
setup
echo "WARNING: ThreadSanitizer: data race (pid=1)" >"$WORK/run/tsan-logs/tsan.1"
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 1 ] && [[ "$OUT" == *"data race"* ]] && [[ "$OUT" == *"::error::"* ]]; then
  pass "a data race fails the job"
else
  fail "a data race fails the job" "rc=$RC out=$OUT"
fi

# 3. A thread leak fails too. It was briefly treated as expected; sipnab's fatal
#    startup paths spawn the capture thread before they can fail, so a leak
#    means one was abandoned with its capture source open.
setup
echo "WARNING: ThreadSanitizer: thread leak (pid=1)" >"$WORK/run/tsan-logs/tsan.1"
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 1 ] && [[ "$OUT" == *"thread leak"* ]]; then
  pass "a thread leak fails the job"
else
  fail "a thread leak fails the job" "rc=$RC out=$OUT"
fi

# 4. A finding in a CHILD's log fails. Before log_path, a child's report reached
#    the cargo log only if a test printed the child's stderr into an assertion.
setup
echo "WARNING: ThreadSanitizer: data race (pid=99)" >"$WORK/run/tsan-logs/tsan.99"
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 1 ]; then
  pass "a race in a child process log fails the job"
else
  fail "a race in a child process log fails the job" "rc=$RC out=$OUT"
fi

# 5. A finding outside the fatal set is surfaced but does not fail, and is not
#    announced as a race.
setup
echo "WARNING: ThreadSanitizer: signal handler spoils errno (pid=1)" \
  >"$WORK/run/tsan-logs/tsan.1"
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 0 ] && [[ "$OUT" == *"::warning::"* ]] && [[ "$OUT" != *"::error::"* ]]; then
  pass "a non-fatal finding warns without failing"
else
  fail "a non-fatal finding warns without failing" "rc=$RC out=$OUT"
fi

# 6. An uninstrumented binary fails. Silence from a build that lost
#    -Zsanitizer=thread is not evidence of anything.
setup
make_nm without
run_verdict "$BIN_BAD"
if [ "$RC" -eq 1 ] && [[ "$OUT" == *"not ThreadSanitizer-instrumented"* ]]; then
  pass "an uninstrumented binary fails instead of reporting a clean run"
else
  fail "an uninstrumented binary fails instead of reporting a clean run" "rc=$RC out=$OUT"
fi

# 7. Findings in the cargo log itself are read, not just the per-process files.
setup
echo "WARNING: ThreadSanitizer: data race (pid=1)" >"$WORK/run/cargo.log"
make_nm with
run_verdict "$BIN_OK"
if [ "$RC" -eq 1 ]; then
  pass "a race in the cargo log fails the job"
else
  fail "a race in the cargo log fails the job" "rc=$RC out=$OUT"
fi

# 8. Nothing to read at all is an error, not a pass. An empty log tree means the
#    run never happened or wrote somewhere else.
rm -rf "$WORK/run"
mkdir -p "$WORK/run/tsan-logs"
make_nm with
OUT=$(bash --noprofile --norc -e -o pipefail "$VERDICT" \
  "$BIN_OK" "$WORK/run/missing.log" "$WORK/run/tsan-logs" 2>&1)
RC=$?
if [ "$RC" -eq 1 ] && [[ "$OUT" == *"nothing was examined"* ]]; then
  pass "no logs at all is an error, not a clean run"
else
  fail "no logs at all is an error, not a clean run" "rc=$RC out=$OUT"
fi

echo
echo "$PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
