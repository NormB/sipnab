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
#   PREFLIGHT_STRICT=1 scripts/preflight.sh   # a tool it cannot find FAILS
#   PREFLIGHT_STRICT=0 scripts/preflight.sh   # ... warns, whatever the context
#
# Exit 0 when every check passed, 1 when any failed.

set -uo pipefail

# >>> BEGIN repo-root
# `cd "$(git rev-parse --show-toplevel)" || exit 1` was NOT the guard it looks
# like. With git absent, or outside a repository, the substitution is empty and
# `cd ""` SUCCEEDS in bash without moving -- so the whole run measured whatever
# directory it was started from, and said nothing about it. Same class as the
# missing tools below: an empty answer reading as a good one.
ROOT=$(git rev-parse --show-toplevel 2>/dev/null)
if [ -z "$ROOT" ]; then
    printf 'preflight: not inside a git repository, or git is not installed.\n' >&2
    printf 'Every check below reads the repository, so none of them can run.\n' >&2
    exit 1
fi
cd "$ROOT" || exit 1
# <<< END repo-root

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
FIX=0
[ "${1:-}" = "--fix" ] && FIX=1

# >>> BEGIN status-and-strictness
FAILED=0

step()  { printf '  %-38s' "$1"; }
ok()    { printf '%bOK%b\n' "$GREEN" "$NC"; }
bad()   { printf '%bFAIL%b\n' "$RED" "$NC"; FAILED=1; }
warn()  { printf '%bWARN%b\n' "$YELLOW" "$NC"; }
note()  { printf '    %s\n' "$1"; }

# ---------------------------------------------------------------------------
# What a check this script CANNOT PERFORM means.
#
# A missing tool used to be a WARN, and the run still ended "Preflight clean".
# For a contributor without Vale on their laptop that is right: the tool is a
# convenience they can install later, and blocking them helps nobody. For
# anything automated it is the worst answer available, because the output says
# a gate passed when in truth it never ran.
#
# That is not a hypothetical either. A background script with a hardened PATH
# that omitted ~/.local/bin -- where both vale and codespell live here -- ran
# this and got "Preflight clean" with two BLOCKING gates silently downgraded to
# warnings. Nothing in the output said "command not found". Two Vale errors
# reached CI and turned main red (c3befb9, 2026-08-10).
#
# So the answer depends on who is asking, and the script decides rather than
# guessing:
#
#   PREFLIGHT_STRICT=1   fail. Anything else non-empty is also strict.
#   PREFLIGHT_STRICT=0   warn, even under CI. The explicit opt-out.
#   CI is set            fail. CI installs every tool; missing means broken.
#   stdout is not a tty  fail. Nobody is reading the warning, so it is not a
#                        warning -- it is a gate quietly reporting nothing.
#   otherwise            warn. A human at a terminal, who can act on it.
#
# The tty test is the half that catches the incident above: that script did not
# set CI, it just redirected output to a log.
#
# `strict_mode` takes the terminal answer as an ARGUMENT rather than testing
# `-t 1` itself, so tests/preflight_strict_test.rs can drive both sides of the
# decision without allocating a pty. It prints `<0|1> <reason>`; the reason is
# printed in the banner, because a run that changed its own severity should say
# why.
# ---------------------------------------------------------------------------
strict_mode() {
    case "${PREFLIGHT_STRICT:-}" in
        '') ;;  # unset or empty: fall through to the defaults below
        0|no|NO|off|OFF|false|FALSE)
            printf '0 PREFLIGHT_STRICT=%s' "${PREFLIGHT_STRICT}"; return ;;
        *)  printf '1 PREFLIGHT_STRICT=%s' "${PREFLIGHT_STRICT}"; return ;;
    esac
    if [ -n "${CI:-}" ]; then printf '1 CI is set'; return; fi
    if [ "${1:-}" != tty ]; then printf '1 output is not a terminal'; return; fi
    printf '0 interactive terminal'
}

if [ -t 1 ]; then STRICT_DECISION=$(strict_mode tty)
else STRICT_DECISION=$(strict_mode notty); fi
STRICT=${STRICT_DECISION%% *}
STRICT_WHY=${STRICT_DECISION#* }

# A check that could not run: a tool that is not installed, a pin that cannot
# be read, a comparison with nothing to compare. Never silently OK, and counted
# so the closing summary cannot call the run clean when part of it never ran.
DEGRADED=0
degraded() {
    DEGRADED=$((DEGRADED + 1))
    if [ "$STRICT" = "1" ]; then bad; else warn; fi
}
# <<< END status-and-strictness

printf '%bPreflight -- the cheap gates, before the expensive ones%b\n' "$YELLOW" "$NC"
if [ "$STRICT" = "1" ]; then
    printf 'Strict (%s): a check that cannot RUN fails, rather than warning.\n' "$STRICT_WHY"
fi

# ---------------------------------------------------------------------------
# 1. Vale, and specifically the version CI pins.
#
# The local binary being SOME version of Vale is not the check. Vale's spelling
# rule consults a dictionary that changes between releases, so 3.9.1 returning
# zero errors says nothing about the 3.16.0 CI runs -- that exact gap let
# `UUIDs` and `handshook` through a green local gate and into a red CI job.
# Compare the versions and refuse to report a pass from the wrong one.
# ---------------------------------------------------------------------------
# >>> BEGIN vale-gate
# Sourced INSIDE the marker, not once at the top of the file.
# tests/preflight_strict_test.rs runs the text between these markers verbatim
# and standalone, so anything this block needs has to be inside it -- a source
# line further up is simply absent when the block is extracted. Sourcing twice
# in a full run costs nothing: it redefines the same shell functions.
#
# Located without requiring git: this script cds to ROOT before any gate runs
# and the extracted blocks run with cwd at the tree root, so the relative path
# is right in both. `git rev-parse` is tried first only so a run started from a
# subdirectory still finds it. A bare `$(git ...)` here resolved to
# /scripts/prose-gates.sh in a temp tree that was not a repository.
PROSE_LIB="scripts/prose-gates.sh"
_root=$(git rev-parse --show-toplevel 2>/dev/null) &&
	[ -r "$_root/$PROSE_LIB" ] && PROSE_LIB="$_root/$PROSE_LIB"
# shellcheck source=scripts/prose-gates.sh
. "$PROSE_LIB"
step "vale (CI-pinned version)"
# Resolution, the version pin and the path list all live in
# scripts/prose-gates.sh, sourced at the top. This block owns only how the
# result is rendered, which is the one part that differs between the three
# runners. `degraded` and not `ok` for return 2: under PREFLIGHT_STRICT=1 --
# the DEFAULT whenever stdout is not a tty, so a log file, a CI job or an agent
# -- that sets FAILED=1, because a gate that could not run must not read green.
prose_vale_run
case $? in
0)
    ok
    ;;
1)
    bad
    # E100 is "style does not exist", not a prose error: `.vale/styles/` holds
    # gitignored packages, so a fresh clone lints against nothing until
    # `vale sync` fetches them. Say so, because the raw message reads like the
    # documentation is broken.
    if grep -q 'E100' "$PROSE_OUTPUT" 2>/dev/null; then
        note "Vale could not LOAD a style, so it linted nothing. The style"
        note "packages under .vale/styles/ are gitignored and a fresh"
        note "clone has none. Run: vale sync"
    fi
    tail -25 "$PROSE_OUTPUT"
    ;;
*)
    # PROSE_REASON distinguishes the three ways a run does not happen -- no
    # binary, no pin in the workflow, or a binary whose version is not the
    # pinned one. Collapsing them into one message lost the distinction AND
    # the install pointer, and preflight_strict_test asserts on both.
    degraded
    note "$PROSE_REASON."
    note "CI runs vale and it blocks. Install v${PROSE_PIN:-pinned} from"
    note "https://vale.sh, or point VALE_BIN at one, to check here."
    note "A green run on another version is NOT evidence about CI."
    ;;
esac
rm -f "$PROSE_OUTPUT"
# <<< END vale-gate

# ---------------------------------------------------------------------------
# 2. codespell, over the shared list in .config/codespell-paths.txt.
# ---------------------------------------------------------------------------
# >>> BEGIN codespell-gate
# Sourced inside the marker, and located, for the reasons the vale gate gives.
PROSE_LIB="scripts/prose-gates.sh"
_root=$(git rev-parse --show-toplevel 2>/dev/null) &&
	[ -r "$_root/$PROSE_LIB" ] && PROSE_LIB="$_root/$PROSE_LIB"
# shellcheck source=scripts/prose-gates.sh
. "$PROSE_LIB"
step "codespell"
# Paths and resolution from scripts/prose-gates.sh, as above.
prose_codespell_run
case $? in
0)
    ok
    ;;
1)
    bad
    head -15 "$PROSE_OUTPUT"
    ;;
*)
    degraded
    note "$PROSE_REASON; CI runs it and it blocks. pipx install codespell"
    note "(or point CODESPELL_BIN at one in a venv, as the hook accepts)"
    ;;
esac
rm -f "$PROSE_OUTPUT"
# <<< END codespell-gate

# ---------------------------------------------------------------------------
# 3. Site mirrors. Two generators, and they own different pages -- running only
#    one leaves the other's pages stale, which fails as a table mismatch rather
#    than as anything mentioning mirrors.
#
#    `benchmarks.md` is deliberately NOT generated: both copies are
#    hand-maintained because they frame the same tables differently. Editing one
#    without the other fails `benchmark_tables_match_between_docs_and_website`.
# ---------------------------------------------------------------------------
# >>> BEGIN site-mirror-gate
step "site mirrors current"
GEN_OUT="/tmp/.sipnab-preflight-gen.$$"
# The generators used to run with `>/dev/null 2>&1` and their exit status
# dropped, so a crashed generator wrote nothing, changed nothing, and read as
# "the mirror is current" -- a missing tool by another name. python3 absent
# does the same thing twice over.
run_generators() {
    python3 scripts/build-site-pages.py >"$GEN_OUT" 2>&1 || return 1
    python3 scripts/build-site-internals.py >>"$GEN_OUT" 2>&1 || return 1
    return 0
}
if ! command -v python3 >/dev/null 2>&1; then
    degraded
    note "python3 is not installed, so neither site generator ran. A stale"
    note "mirror then bounces the hook as a table mismatch, which names the"
    note "wrong thing entirely."
else
    [ "$FIX" = "1" ] && run_generators
    BEFORE=$(git status --porcelain website/content | sort)
    if ! run_generators; then
        bad
        note "a site generator exited non-zero, so it rewrote nothing and"
        note "'unchanged' proves nothing about the mirror."
        tail -10 "$GEN_OUT"
    else
        AFTER=$(git status --porcelain website/content | sort)
        if [ "$BEFORE" = "$AFTER" ]; then
            ok
        else
            bad
            note "a generator rewrote a site page, so the mirror was stale."
            note "The regeneration already ran; review and stage the result."
        fi
    fi
    rm -f "$GEN_OUT"
fi
# <<< END site-mirror-gate
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
# 4b. Untracked files that the ratchets count.
#
#     Several gates count TRACKED files -- `git ls-files`, not the working
#     tree -- so a brand-new page is invisible to them until it is staged. That
#     is how this script reported clean on a commit that then bounced on three
#     ratchets at once: the two new pages did not exist as far as
#     `docs_drift_test` was concerned. Stage first, or check here.
#
#     `*.rs` is here for the check directly above: `git diff HEAD` does not see
#     an untracked file either, so a whole new test FILE moves the homepage
#     count by however many tests it holds while the diff heuristic counts
#     zero. Same class as a missing tool -- nothing to look at read as nothing
#     wrong -- so it degrades the same way.
# ---------------------------------------------------------------------------
step "new files staged for the ratchets"
UNTRACKED=$(git ls-files --others --exclude-standard -- '*.md' '*.rs' | grep -v '^SESSION_STATE.md$' || true)
if [ -z "$UNTRACKED" ]; then
    ok
else
    degraded
    note "untracked files the tracked-file gates cannot see yet:"
    printf '      %s\n' $UNTRACKED
    note "git add them, then re-run: the file, table, wiki-link, docs-page and"
    note "homepage-count ratchets all read tracked files and will move."
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
#
# doc_link_hygiene_test joined them on 2026-08-23 for the same reason and after
# the same evidence: it bounced two commits that day, both on a tracked path
# written as a bare code span where the page wants a link. The whole binary
# runs in under a second, it names the file and line, and it names the fixer
# -- scripts/link-repo-paths.py --apply -- which produces exactly what it
# demands. Learning that from the hook costs a full suite run instead.
if cargo test --features full --test docs_drift_test --test link_integrity_test \
    --test site_journey_test --test dev_docs_drift_test \
    --test doc_link_hygiene_test \
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

# >>> BEGIN summary
printf '\n'
if [ "$FAILED" = "0" ] && [ "$DEGRADED" != "0" ]; then
    # "Preflight clean" under a WARN is the sentence this script printed on
    # 2026-08-10 while two blocking gates had not run at all. It does not get
    # to print it again.
    printf '%bPreflight clean MINUS %d check(s) that could not run%b -- the WARN\n' \
        "$YELLOW" "$DEGRADED" "$NC"
    printf 'lines above. Those gates block in CI, so this is an UNMEASURED tree\n'
    printf 'rather than a green one. PREFLIGHT_STRICT=1 fails on them instead.\n'
elif [ "$FAILED" = "0" ]; then
    printf '%bPreflight clean.%b The hook still runs the suite, clippy, the corpus\n' "$GREEN" "$NC"
    printf 'gate and the feature matrix -- this only means the paperwork is right.\n'
else
    printf '%bPreflight found something.%b Fixing it now costs seconds; finding it\n' "$RED" "$NC"
    printf 'from the hook costs a full suite run.\n'
fi
exit "$FAILED"
# <<< END summary
