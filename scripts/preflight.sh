#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Run the gates that actually bounce a commit, in about a minute, BEFORE the
# pre-commit hook spends twenty-five minutes discovering the same thing.
#
# # Why this exists
#
# The pre-commit hook runs the full suite. That is correct and it is not the
# problem. The problem is that the failures which actually happen are almost
# never test failures -- they are documentation ratchets, prose linting, and
# the homepage test count, all of which are decidable in seconds. Over one
# release day, four separate commits bounced on exactly these, at ~25 minutes
# each: Vale twice (on a dictionary the local binary did not share with CI), a
# table ratchet twice, and the homepage count once. None needed the suite to
# find. That is roughly an hour and a half of wall clock spent re-running tests
# that were already passing.
#
# So this checks the cheap things first and says what to do about each. It is
# NOT a replacement for the hook: it does not run the test suite, clippy, the
# corpus gate, or the feature matrix. A green preflight means "the hook will
# probably not bounce you on paperwork", not "this is correct".
#
# # Usage
#
#   scripts/preflight.sh          # check the working tree
#   scripts/preflight.sh --fix    # regenerate site mirrors, then check
#
# Exit 0 when every check passed, 1 when any failed.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
FAILED=0
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

step()  { printf '  %-38s' "$1"; }
ok()    { printf '%bOK%b\n' "$GREEN" "$NC"; }
bad()   { printf '%bFAIL%b\n' "$RED" "$NC"; FAILED=1; }
warn()  { printf '%bWARN%b\n' "$YELLOW" "$NC"; }
note()  { printf '    %s\n' "$1"; }

printf '%bPreflight -- the cheap gates, before the expensive ones%b\n' "$YELLOW" "$NC"

# ---------------------------------------------------------------------------
# 1. Vale, and specifically the version CI pins.
#
# The local binary being SOME version of Vale is not the check. Vale's spelling
# rule consults a dictionary that changes between releases, so 3.9.1 returning
# zero errors says nothing about the 3.16.0 CI runs -- that exact gap let
# `UUIDs` and `handshook` through a green local gate and into a red CI job.
# Compare the versions and refuse to report a pass from the wrong one.
# ---------------------------------------------------------------------------
step "vale (CI-pinned version)"
WANT_VALE=$(grep -oE "VALE_VERSION: '[0-9.]+'" .github/workflows/quality.yml 2>/dev/null | grep -oE "[0-9.]+" | head -1)
if ! command -v vale >/dev/null 2>&1; then
    warn
    note "vale is not installed. CI runs it and it BLOCKS."
    note "Install ${WANT_VALE:-the pinned version}: https://vale.sh"
elif [ -n "$WANT_VALE" ] && ! vale --version 2>/dev/null | grep -qF "$WANT_VALE"; then
    warn
    note "local $(vale --version 2>/dev/null | head -1) but CI pins $WANT_VALE."
    note "Different dictionaries: a green run here is NOT evidence about CI."
    note "Fetch the pinned build for this arch and use that instead."
else
    # CI's exact path list. Adding anything to it -- CHANGELOG.md especially --
    # invents errors CI will never report.
    if vale docs/ website/content/ README.md SUPPORT.md MAINTAINERS.md >/tmp/.sipnab-preflight-vale.$$ 2>&1; then
        ok
    else
        bad
        tail -25 /tmp/.sipnab-preflight-vale.$$
    fi
    rm -f /tmp/.sipnab-preflight-vale.$$
fi

# ---------------------------------------------------------------------------
# 2. codespell, over CI's own path list (both `bench` AND `benches`).
# ---------------------------------------------------------------------------
step "codespell"
if ! command -v codespell >/dev/null 2>&1; then
    warn
    note "not installed; CI runs it and it blocks. pipx install codespell"
else
    if codespell src tests docs website bench benches harness scripts README.md \
        CONTRIBUTING.md SECURITY.md CHANGELOG.md SUPPORT.md MAINTAINERS.md \
        >/tmp/.sipnab-preflight-cs.$$ 2>&1; then
        ok
    else
        bad
        head -15 /tmp/.sipnab-preflight-cs.$$
    fi
    rm -f /tmp/.sipnab-preflight-cs.$$
fi

# ---------------------------------------------------------------------------
# 3. Site mirrors. Two generators, and they own different pages -- running only
#    one leaves the other's pages stale, which fails as a table mismatch rather
#    than as anything mentioning mirrors.
#
#    `benchmarks.md` is deliberately NOT generated: both copies are
#    hand-maintained because they frame the same tables differently. Editing one
#    without the other fails `benchmark_tables_match_between_docs_and_website`.
# ---------------------------------------------------------------------------
step "site mirrors current"
if [ "$FIX" = "1" ]; then
    python3 scripts/build-site-pages.py >/dev/null 2>&1
    python3 scripts/build-site-internals.py >/dev/null 2>&1
fi
BEFORE=$(git status --porcelain website/content | sort)
python3 scripts/build-site-pages.py >/dev/null 2>&1
python3 scripts/build-site-internals.py >/dev/null 2>&1
AFTER=$(git status --porcelain website/content | sort)
if [ "$BEFORE" = "$AFTER" ]; then
    ok
else
    bad
    note "a generator rewrote a site page, so the mirror was stale."
    note "The regeneration already ran; review and stage the result."
fi
if git diff --name-only HEAD -- docs/benchmarks.md website/content/docs/benchmarks.md 2>/dev/null \
    | grep -q . ; then
    CHANGED=$(git diff --name-only HEAD -- docs/benchmarks.md website/content/docs/benchmarks.md | wc -l)
    if [ "$CHANGED" = "1" ]; then
        step "benchmarks pages in step"
        bad
        note "only ONE benchmarks copy changed. They are hand-maintained in"
        note "pairs and their TABLES must match exactly; edit both."
    fi
fi

# ---------------------------------------------------------------------------
# 4. Test-count change -> the homepage tile moves too.
#
#    Deliberately a heuristic on the diff rather than a count. The hook derives
#    the real number by summing the `passed` column of a full run, which cannot
#    be reproduced cheaply: `--list` over-counts by including `#[ignore]`d tests
#    and under-counts doctests, and on this tree the two disagree by 18. Rather
#    than encode a fragile formula, detect the CONDITION that breaks the gate --
#    the diff changing how many tests exist -- and say so.
# ---------------------------------------------------------------------------
step "homepage test count"
ADDED=$(git diff HEAD -- '*.rs' | grep -cE '^\+\s*#\[(tokio::)?test\]' || true)
REMOVED=$(git diff HEAD -- '*.rs' | grep -cE '^-\s*#\[(tokio::)?test\]' || true)
if [ "$ADDED" = "$REMOVED" ]; then
    ok
else
    NET=$((ADDED - REMOVED))
    if git diff HEAD -- website/templates/index.html | grep -q 'automated tests'; then
        ok
        note "net ${NET} test(s) and the homepage moved with them."
    else
        bad
        note "net ${NET} test(s) added/removed, and website/templates/index.html"
        note "was not touched. The count lives in THREE places: the prose, the"
        note "stat card's data-count, and the card's no-JS fallback text."
    fi
fi

# ---------------------------------------------------------------------------
# 5. The documentation gates themselves. These need a build, so they are last:
#    on a warm tree they are seconds, and on a cold one you wanted the compile
#    anyway. They are where the table and wiki-link ratchets live -- the
#    failure mode being that a table added ANYWHERE, including in CHANGELOG.md
#    or a backlog entry, moves a number nobody expected to be moving.
# ---------------------------------------------------------------------------
step "docs + site gates"
# dev_docs_drift_test is here because it caught something preflight missed on
# the day preflight was written: adding a twelfth workflow moves a spelled-out
# count in a heading ("The eleven workflows") AND requires a row in the table
# under it. Both are decidable in seconds and both bounced a commit.
if cargo test --features full --test docs_drift_test --test link_integrity_test \
    --test site_journey_test --test dev_docs_drift_test \
    >/tmp/.sipnab-preflight-gates.$$ 2>&1; then
    ok
else
    bad
    grep -E "^test .* FAILED|panicked at|expected [0-9]+|left:|right:" \
        /tmp/.sipnab-preflight-gates.$$ | head -12
    note "Ratchet numbers come from THIS run, not from arithmetic."
fi
rm -f /tmp/.sipnab-preflight-gates.$$

# ---------------------------------------------------------------------------
# 6. Formatting, which is a pre-PUSH gate rather than pre-commit -- so it bites
#    after the suite has already passed, which is the worst possible moment.
# ---------------------------------------------------------------------------
step "cargo fmt"
if cargo fmt --all -- --check >/dev/null 2>&1; then ok; else
    bad
    note "run: cargo fmt --all"
fi

printf '\n'
if [ "$FAILED" = "0" ]; then
    printf '%bPreflight clean.%b The hook still runs the suite, clippy, the corpus\n' "$GREEN" "$NC"
    printf 'gate and the feature matrix -- this only means the paperwork is right.\n'
else
    printf '%bPreflight found something.%b Fixing it now costs seconds; finding it\n' "$RED" "$NC"
    printf 'from the hook costs a full suite run.\n'
fi
exit "$FAILED"
