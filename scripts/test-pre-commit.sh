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

# ── Scenario 4: gate 8 (developer-docs coupling) is advisory ───────────────
# The gate flags staged files that docs/internals/ cites, so a contributor is
# reminded to check the prose. It must NEVER block a commit: hard-failing on
# every edit to a cited file would fire on routine typo fixes and train people
# to bypass the hook. The blocking check is dev_docs_drift_test.
if grep -q 'Developer-docs coupling' "$HOOK"; then
	ok "hook carries the developer-docs coupling gate"
else
	bad "hook is missing the developer-docs coupling gate"
fi

# Extract the gate-8 block and prove it contains no exit — advisory by
# construction, not merely by intent.
GATE8=$(awk '/8\. Developer docs cite code/,/All pre-commit checks passed/' "$HOOK" \
	| grep -v 'All pre-commit checks passed' || true)
if printf '%s' "$GATE8" | grep -q 'exit'; then
	bad "gate 8 must never exit — it is advisory (found an exit in the block)"
else
	ok "gate 8 contains no exit (cannot block a commit)"
fi

# The cited-file set the gate matches against, built from the real pages so a
# broken regex or sed pipeline shows up here.
CITED=$(grep -rhoE '\]\((\.\./)+[a-zA-Z0-9_./-]+\)' "$REPO_ROOT"/docs/internals/*.md 2>/dev/null \
	| sed -E 's/^\]\(//; s/\)$//; s#(\.\./)+##' | sort -u)
if printf '%s\n' "$CITED" | grep -qx 'src/pipeline.rs'; then
	ok "cited-file extraction resolves ../../src/pipeline.rs to src/pipeline.rs"
else
	bad "cited-file extraction failed — gate 8 would match nothing"
fi

# Mirrors the hook's decision: skip entirely when docs/internals/ is staged,
# else REVIEW when a staged path is cited.
CITED_FILE=$(mktemp)
trap 'rm -f "$CITED_FILE" "$STAGED_FILE"' EXIT
printf '%s\n' "$CITED" > "$CITED_FILE"
STAGED_FILE=$(mktemp)

coupling() { # arg: newline-separated staged paths
	if printf '%s\n' "$1" | grep -q '^docs/internals/'; then
		echo "OK"
		return
	fi
	printf '%s\n' "$1" | sort -u > "$STAGED_FILE"
	if [ -n "$(comm -12 "$STAGED_FILE" "$CITED_FILE")" ]; then
		echo "REVIEW"
	else
		echo "OK"
	fi
}

[ "$(coupling 'src/pipeline.rs')" = "REVIEW" ] \
	&& ok "a staged cited file yields REVIEW" \
	|| bad "staged src/pipeline.rs should yield REVIEW"
[ "$(coupling 'docs/internals/README.md
src/pipeline.rs')" = "OK" ] \
	&& ok "staging docs/internals/ alongside a cited file is quiet" \
	|| bad "a staged docs/internals/ change must skip the notice"
[ "$(coupling 'Cargo.lock')" = "OK" ] \
	&& ok "an uncited staged file is quiet" \
	|| bad "Cargo.lock is not cited and should be quiet"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
