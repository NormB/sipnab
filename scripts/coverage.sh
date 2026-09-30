#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Reproduce CI's coverage job locally, before pushing.
#
# Deliberately NOT wired into .githooks/pre-push. An instrumented build plus the
# full suite takes 30-60 minutes on a developer machine; the pre-push hook is
# already around fifteen, and a gate nobody will wait for is a gate that gets
# bypassed. Run this when you have changed something you expect to move the
# number, or before a release.
#
# The floor and the scope are READ FROM .github/workflows/quality.yml rather
# than repeated here. Two copies of a threshold is how a gate and its local
# rehearsal come to disagree, and the rehearsal is the one that gets trusted.
#
# Usage:
#   scripts/coverage.sh            # collect, report, enforce the floor
#   scripts/coverage.sh --report   # report from the last collection, no re-run
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
WORKFLOW=".github/workflows/quality.yml"

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
    echo "cargo-llvm-cov is not installed. Install it with:" >&2
    echo "    rustup component add llvm-tools-preview" >&2
    echo "    cargo install cargo-llvm-cov --locked" >&2
    exit 127
fi

FLOOR=$(grep -oE -- '--fail-under-lines [0-9]+' "$WORKFLOW" | grep -oE '[0-9]+' | head -1)
if [ -z "$FLOOR" ]; then
    echo "::error:: no --fail-under-lines found in $WORKFLOW — refusing to" >&2
    echo "  enforce a floor this script invented rather than read." >&2
    exit 1
fi

# The scope -- which tests are skipped and which files are ignored -- is the
# workflow-level COVERAGE_TEST_SKIPS / COVERAGE_IGNORE_REGEX in the workflow,
# which also says why each entry exists. Read, not repeated: the line job, the
# weekly branch job and this rehearsal must measure one population.
scope_var() {
    local value
    value=$(sed -nE "s/^  $1: (.*)$/\1/p" "$WORKFLOW" | head -1)
    if [ -z "$value" ]; then
        echo "::error:: no workflow-level $1 in $WORKFLOW -- refusing to" >&2
        echo "  measure a scope this script invented rather than read." >&2
        exit 1
    fi
    printf '%s\n' "$value"
}
read -r -a SKIPS <<<"$(scope_var COVERAGE_TEST_SKIPS)"
IGNORE=$(scope_var COVERAGE_IGNORE_REGEX)

if [ "${1:-}" != "--report" ]; then
    echo "==> collecting coverage (this takes a while; see the note above)"
    cargo llvm-cov --all-features --workspace --no-report -- "${SKIPS[@]}"
fi

echo "==> summary"
cargo llvm-cov report --summary-only --ignore-filename-regex "$IGNORE"

echo "==> enforcing the floor CI enforces (${FLOOR}% lines)"
cargo llvm-cov report --fail-under-lines "$FLOOR" \
    --ignore-filename-regex "$IGNORE"

echo "coverage floor of ${FLOOR}% met"
