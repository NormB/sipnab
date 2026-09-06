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
# The floor and the skips are READ FROM .github/workflows/quality.yml rather
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

# The two skips are not preferences. `cli_goldens` spawns the instrumented
# binary as 13 parallel subprocesses that collide on the llvm-cov merge-pool
# .profraw; `wasm_plugin_` shells out to a wasm32 build, and wasm32 ships no
# profiler_builtins, so the nested build fails E0463. Both run in full under
# the CI workflow's plain `cargo test`; only their coverage contribution is
# dropped, which is why this total is short of the whole suite by design.
SKIPS=(--skip cli_goldens --skip wasm_plugin_)

if [ "${1:-}" != "--report" ]; then
    echo "==> collecting coverage (this takes a while; see the note above)"
    cargo llvm-cov --all-features --workspace --no-report -- "${SKIPS[@]}"
fi

echo "==> summary"
cargo llvm-cov report --summary-only --ignore-filename-regex 'gen_fixture\.rs'

echo "==> enforcing the floor CI enforces (${FLOOR}% lines)"
cargo llvm-cov report --fail-under-lines "$FLOOR" \
    --ignore-filename-regex 'gen_fixture\.rs'

echo "coverage floor of ${FLOOR}% met"
