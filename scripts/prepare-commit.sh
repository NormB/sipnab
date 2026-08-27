#!/usr/bin/env bash
# Run every fixer, then report what changed.
#
# The repository has a fixer for most of what its gates enforce -- citations,
# repo-path links, site mirrors, the backlog status table. Each one is a
# separate command nobody remembers in the right order, so the usual way to
# discover a stale mirror is a failed commit five minutes into the test suite.
#
# This runs them all and prints a summary. It changes files and stages nothing:
# deciding what belongs in a commit is not a script's job.
set -uo pipefail

cd "$(dirname "$0")/.."

GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; NC=$'\033[0m'
changed=0
failed=0

# before/after on the working tree, so "no change" is a measured fact rather
# than a fixer's own claim about itself.
snapshot() { git status --porcelain | sha256sum | cut -d' ' -f1; }

run() {  # run <label> <command...>
    local label="$1"; shift
    local before after out
    before="$(snapshot)"
    printf '  %-26s' "$label"
    if ! out="$("$@" 2>&1)"; then
        printf '%sFAIL%s\n' "$RED" "$NC"
        printf '%s\n' "$out" | tail -6 | sed 's/^/      /'
        failed=1
        return
    fi
    after="$(snapshot)"
    if [ "$before" = "$after" ]; then
        printf '%sok%s\n' "$GREEN" "$NC"
    else
        printf '%schanged%s  %s\n' "$YELLOW" "$NC" "$(printf '%s' "$out" | tail -1)"
        changed=1
    fi
}

echo "Running fixers..."
run "formatting"        cargo fmt --all
run "line citations"    python3 scripts/check-line-drift.py --apply
run "repo path links"   python3 scripts/link-repo-paths.py --apply
run "site pages"        python3 scripts/build-site-pages.py
run "site internals"    python3 scripts/build-site-internals.py
run "backlog status"    python3 scripts/backlog-status.py --apply

echo
if [ "$failed" -ne 0 ]; then
    echo "${RED}A fixer failed.${NC} Read its output above before committing."
    exit 1
fi
if [ "$changed" -ne 0 ]; then
    echo "${YELLOW}Files changed.${NC} Review with 'git diff', stage what belongs,"
    echo "then run the gate: bash .githooks/pre-commit"
    exit 0
fi
echo "${GREEN}Nothing to fix.${NC}"
