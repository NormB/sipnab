#!/bin/sh
# BDD test for .githooks/pre-commit's homepage-test-count logic.
#
# Regression under test: the hook used to run `cargo test --features full`
# a SECOND time (in the count step) after step 2 already ran it. That second
# run could race a concurrent cargo on the target dir, abort a binary's
# compile, drop its `test result:` line, and silently undercount the homepage
# assertion — producing a false FAIL that self-heals on retry.
#
# SCENARIOS:
#   1. The hook runs the full suite exactly ONCE (count is derived from the
#      step-2 output, not a fresh run).
#   2. A complete captured run sums every `test result:` passed column.
#   3. A non-zero test exit is rejected at step 2 (fails "retry"), so a
#      truncated run can never reach the count comparison.
#
# This test never runs cargo; it exercises the hook's shell logic directly.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HOOK="$REPO_ROOT/.githooks/pre-commit"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }

# ── Scenario 1: exactly one full-suite invocation ──────────────────────────
# Count real invocations only — the command-substitution form
# `$(cargo test --features full` — not error-message text that names the
# command for the human to re-run.
RUNS=$(grep -c '\$(cargo test --features full' "$HOOK" || true)
if [ "$RUNS" -eq 1 ]; then
	ok "hook invokes 'cargo test --features full' exactly once (got $RUNS)"
else
	bad "hook must invoke 'cargo test --features full' exactly once, got $RUNS (a second run is the flaky-count regression)"
fi

# The count step must reuse the captured output, not shell out again.
if grep -q 'echo "\$TEST_OUTPUT" | grep "test result:"' "$HOOK"; then
	ok "count is derived from the captured \$TEST_OUTPUT"
else
	bad "count step must reuse \$TEST_OUTPUT from step 2"
fi

# ── Scenario 2: a complete run sums correctly ──────────────────────────────
COMPLETE=$(printf '%s\n' \
	'test result: ok. 264 passed; 0 failed; 0 ignored' \
	'test result: ok. 1600 passed; 0 failed' \
	'test result: ok. 974 passed; 0 failed')
SUM=$(printf '%s\n' "$COMPLETE" | grep 'test result:' | awk '{sum += $4} END {print sum}')
if [ "$SUM" = "2838" ]; then
	ok "complete run sums the passed column (2838)"
else
	bad "complete run should sum to 2838, got $SUM"
fi

# ── Scenario 3: the step-2 gate rejects a non-zero (partial) run ────────────
# Mirrors the hook's guard: [ "$TEST_RC" -ne 0 ] || grep -q "FAILED\|error["
gate() { # args: rc, output
	if [ "$1" -ne 0 ] || printf '%s' "$2" | grep -q "FAILED\|error\["; then
		echo "reject"
	else
		echo "proceed"
	fi
}
[ "$(gate 0 "$COMPLETE")" = "proceed" ] \
	&& ok "clean run (rc=0) proceeds to the count" \
	|| bad "clean run should proceed"
[ "$(gate 101 "$COMPLETE")" = "reject" ] \
	&& ok "compile-aborted run (rc=101) is rejected before counting" \
	|| bad "non-zero exit must be rejected at step 2"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
