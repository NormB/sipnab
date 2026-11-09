#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

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
#   2. A complete captured run is counted by the published rule
#      (scripts/published-test-count.py), and a literal count in the
#      homepage template, or a template that stopped loading the generated
#      count, is rejected.
#   3. A non-zero test exit is rejected at step 2 (fails "retry"), so a
#      truncated run can never reach the count comparison.
#   4. Gate 8 advises and never blocks.
#   5. The unwrap scanner scopes #[cfg(test)] to the item, and covers every
#      workspace member rather than the literal path src/.
#   6. That scoping survives braces written inside strings, char literals and
#      comments -- which is where it used to fail open.
#   6b. The abort macros are reported, and a `gate:` marker excuses a site
#      only when it gives a reason.
#
# The hook is EXECUTED, in a throwaway git repo with `cargo` stubbed onto PATH.
# It used to be grepped instead, and the greps are what let two of the exact
# regressions this file names slip back in -- see the sandbox comment below.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HOOK="$REPO_ROOT/.githooks/pre-commit"

# Every git command below must act on a throwaway repository, never on the one
# whose hook (or whose GIT_DIR-carrying shell) runs this script: see
# scripts/lib-git-sandbox.sh. Cleared once, here, for the whole script and the
# hooks it runs.
. "$REPO_ROOT/scripts/lib-git-sandbox.sh"
clear_git_env

PASS=0
FAIL=0
# A scenario whose ASSERTION is only true on one platform. Counted separately
# and printed in the summary, because the alternative -- quietly not running it
# -- is the "green means nothing" shape this whole file exists to prevent. SKIP
# is never a pass and never a failure; it is the harness saying which coverage
# this host did not provide, so `0 skipped` on Linux is the real total.
SKIP=0
ok()   { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }
skip() { SKIP=$((SKIP + 1)); printf 'SKIP: %s\n' "$1"; }

# ---- Scratch file for the Rust fixtures, and why they need one --------------
#
# Three scenarios below feed a multi-line Rust fixture to `scan_v`. They were
# written as `BODY=$(cat <<-'RS' ... RS)`, and that construct is UNPARSEABLE by
# bash 3.2 -- which is `/bin/sh` on macOS, and this file's shebang is
# `#!/bin/sh`. bash 3.2 does not honor the heredoc's `'RS'` quoting while it is
# inside a command substitution: it keeps scanning the body for shell quotes, so
# the first apostrophe or backtick in the FIXTURE opens a quote that never
# closes.
#
# All three fixtures trip it, because Rust is full of both:
#
#   `&'static str`  (lifetime tick)      `'{'` and `b'{'`  (char literals)
#   `` `.unwrap()` `` (doc-comment backticks)
#
# Measured 2026-08-19 on macOS 26.5.2/aarch64 with the fixtures unchanged:
# dash OK, bash 5 OK, zsh OK, /bin/sh (bash 3.2.57) FAILS. Apple has not shipped
# a newer bash since 2007 (GPLv3), so this is not a machine that can be fixed by
# updating something -- and Debian/Ubuntu `/bin/sh` is dash, which is why CI and
# every Linux developer saw nothing.
#
# The failure is the worst available shape. It is a PARSE error, and bash reads
# a script in chunks, so it does not fire where it is written: twenty scenarios
# print PASS first and the script then dies at EOF with `unexpected EOF while
# looking for matching`, before its own summary line and before `[ "$FAIL" -eq
# 0 ]`. The harness that exists to prove the hook is honest was, on every Mac,
# reporting a partial run as if it were a whole one.
#
# Hoisting the heredoc out of the substitution removes the construct bash 3.2
# disagrees about, and the fixtures keep every character they are testing.
HD=$(mktemp)
trap 'rm -f "$HD"' EXIT INT TERM

# ── The sandbox: run the REAL hook against a stubbed cargo ─────────────────
# Built by scripts/lib-hook-sandbox.sh, which says why the hook is executed
# rather than grepped. scripts/tests/test_gate_cache_hooks.py builds the same
# sandbox, so the two harnesses run the hook against one fixture.
. "$REPO_ROOT/scripts/lib-hook-sandbox.sh"

# Sets HOOK_OUT and HOOK_RC. Deliberately does NOT echo: a caller writing
# `OUT=$(run_hook "$D")` would run it in a subshell, where the assignment to
# HOOK_RC is discarded and the parent reads a STALE exit code from an earlier
# run. The first draft of this file did exactly that and reported gate 8 as
# blocking when the hook had returned 0 -- the same "success you did not
# observe" shape these scenarios exist to catch, in the test itself.
HOOK_OUT=""
HOOK_RC=0
run_hook() { # run_hook <sandbox-dir>
	set +e
	# SIPNAB_HOOK_ANY_TREE=1: the repository's hook, run against a sandbox,
	# is the "hook from another checkout" shape its first check refuses;
	# Scenario 0 proves that it does.
	HOOK_OUT=$(cd "$1" && PATH="$1/bin:$PATH" SIPNAB_HOOK_ANY_TREE=1 bash "$HOOK" 2>&1)
	HOOK_RC=$?
	set -e
}

# ── Scenario 0: a hook from another checkout refuses to gate this one ──────
# `core.hooksPath` was an absolute path into one checkout, so every worktree
# ran that checkout's branch's hooks: on 2026-09-29 that was a branch whose
# pre-commit lacked the sipnab-bpf-types step, and commits on main went
# through without it, silently. The hook now checks it is the tree's own.
D=$(sandbox 1)
set +e
FOREIGN_OUT=$(cd "$D" && PATH="$D/bin:$PATH" env -u SIPNAB_HOOK_ANY_TREE bash "$HOOK" 2>&1)
FOREIGN_RC=$?
set -e
if [ "$FOREIGN_RC" -ne 0 ] && printf '%s' "$FOREIGN_OUT" | grep -qF 'core.hooksPath .githooks'; then
	ok "a hook from another checkout blocks and says how to point git at this tree's"
else
	bad "a hook from another checkout gated this tree (rc=$FOREIGN_RC): $FOREIGN_OUT"
fi
# ...and the same file installed as the tree's OWN hook gets past that check.
mkdir -p "$D/.githooks"
cp "$HOOK" "$D/.githooks/pre-commit"
set +e
OWN_OUT=$(cd "$D" && PATH="$D/bin:$PATH" env -u SIPNAB_HOOK_ANY_TREE bash .githooks/pre-commit 2>&1)
set -e
if printf '%s' "$OWN_OUT" | grep -qF 'Formatting' \
	&& ! printf '%s' "$OWN_OUT" | grep -qF 'core.hooksPath .githooks'; then
	ok "the tree's own hook passes the same-checkout check"
else
	bad "the tree's own hook was refused as foreign: $OWN_OUT"
fi
rm -rf "$D"

# ── Scenario 1: exactly one full-suite invocation, measured by running it ──
D=$(sandbox 264 1600 974)
run_hook "$D"
# The FULL suite: `cargo test -p sipnab-bpf-types` is a separate, deliberate
# run of another package and is not the regression this counts.
RUNS=$(grep -c '^nextest run --profile suite --features full' "$D/cargo-invocations" || true)
if [ "$RUNS" -eq 1 ]; then
	ok "hook ran the suite exactly once (counted $RUNS actual invocations)"
else
	bad "hook must run the suite exactly once, it ran it $RUNS times (a second run is the flaky-count regression)"
fi
DOCS=$(grep -c '^test --features full.* --doc$' "$D/cargo-invocations" || true)
if [ "$DOCS" -eq 1 ]; then
	ok "hook ran the doctests exactly once, beside the nextest run"
else
	bad "hook must run the doctests once (nextest does not run them), it ran them $DOCS times: $(cat "$D/cargo-invocations")"
fi

# ── Scenario 1b: the suite runs under nextest, with a deadline per test ────
# `cargo test` bounds no single test, so one hung test held the hook until
# its 30-minute watchdog (TEST-DEADLINE-NEXTEST-SIPNAB). The hook must run the
# suite through scripts/parallel-tests.py, whose `suite` nextest profile
# stops a test past its slow-timeout.
if grep -q '^nextest run --profile suite ' "$D/cargo-invocations"; then
	ok "hook runs the suite under nextest's suite profile"
else
	bad "hook ran the suite without nextest's suite profile: $(cat "$D/cargo-invocations")"
fi

# ── Scenario 1c: the suite runs without the private capture corpus ────────
# The pool used to inherit the shell's SIPNAB_CORPUS, so every corpus binary
# replayed the real captures in a DEBUG build on every commit: in the
# 2026-10-23 log the 15 slowest corpus binaries took 1,158.7 s of the
# suite's 1,882.7 s. pre-push runs the same binaries against the corpus under
# the optimized `corpus` profile, so the pool is started without
# SIPNAB_CORPUS and SIPNAB_VCON_DATASETS. Read from what the suite's cargo
# was handed, not from the hook's text.
#
# pool_env <sandbox> <SIPNAB_CORPUS value> <SIPNAB_VCON_DATASETS value>
# Runs the hook with both variables set (to the given values, empty allowed)
# plus a probe variable the hook has no reason to touch.
pool_env() {
	rm -f "$1/pool-env"
	set +e
	HOOK_OUT=$(cd "$1" && PATH="$1/bin:$PATH" SIPNAB_HOOK_ANY_TREE=1 \
		SIPNAB_CORPUS="$2" SIPNAB_VCON_DATASETS="$3" SIPNAB_HOOK_ENV_PROBE=kept \
		bash "$HOOK" 2>&1)
	HOOK_RC=$?
	set -e
}
# Its own sandbox: Scenario 2 below reuses Scenario 1's $D.
E=$(sandbox 1)
mkdir -p "$E/corpus" "$E/vcon"
pool_env "$E" "$E/corpus" "$E/vcon"
if [ ! -f "$E/pool-env" ]; then
	bad "the suite never ran, so its environment could not be read (rc=$HOOK_RC): $HOOK_OUT"
elif ! grep -qx 'SIPNAB_HOOK_ENV_PROBE=kept' "$E/pool-env"; then
	# Negative control: without it, an empty pool-env (a stub that recorded
	# nothing) would pass the two checks below.
	bad "the suite did not see a variable the hook leaves alone, so pool-env proves nothing: $(cat "$E/pool-env")"
else
	ok "the suite inherits the hook's environment (probe variable seen)"
fi
if [ -f "$E/pool-env" ] && ! grep -q '^SIPNAB_CORPUS=' "$E/pool-env"; then
	ok "the suite runs without SIPNAB_CORPUS"
else
	bad "the suite was handed SIPNAB_CORPUS, so every corpus binary replays it in a debug build: $(cat "$E/pool-env" 2>/dev/null)"
fi
if [ -f "$E/pool-env" ] && ! grep -q '^SIPNAB_VCON_DATASETS=' "$E/pool-env"; then
	ok "the suite runs without SIPNAB_VCON_DATASETS"
else
	bad "the suite was handed SIPNAB_VCON_DATASETS: $(cat "$E/pool-env" 2>/dev/null)"
fi
# Edge: set but EMPTY. tests/support/corpus.rs reads an empty SIPNAB_CORPUS as
# a corpus at "" (Some), not as unset, so blanking the variable is not
# removing it; only unsetting it is.
pool_env "$E" "" ""
if [ -f "$E/pool-env" ] && grep -qx 'SIPNAB_HOOK_ENV_PROBE=kept' "$E/pool-env" \
	&& ! grep -qE '^SIPNAB_(CORPUS|VCON_DATASETS)=' "$E/pool-env"; then
	ok "an empty SIPNAB_CORPUS or SIPNAB_VCON_DATASETS is removed, not passed on blank"
else
	bad "an empty corpus variable reached the suite (rc=$HOOK_RC): $(cat "$E/pool-env" 2>/dev/null)"
fi
rm -rf "$E"

# ── Scenario 2: the hook's count gate, exercised end to end ────────────────
# 264 + 1600 + 974 = 2838. The gate runs scripts/published-test-count.py, the
# rule pages.yml publishes with, on the step-2 output; a wrong column or a
# second rule would not print 2838.
run_hook "$D"
if printf '%s' "$HOOK_OUT" | grep -q 'Homepage test count generated.*OK (2838)'; then
	ok "hook counted the step-2 run with the published rule (2838)"
else
	bad "hook did not compute 2838 from 264+1600+974; output was: $HOOK_OUT"
fi

# And it must FAIL when a literal count comes back into the template --
# otherwise the above proves only that the gate is quiet, not that it checks.
# The hand-set number is what made every pair of test-adding pull requests
# conflict. Every platform blocks: nothing here depends on the host's suite.
#
# Write-to-temp-and-move rather than `sed -i`. `sed -i EXPR FILE` is the GNU
# spelling; BSD sed takes the backup SUFFIX as -i's argument, so on macOS it
# read the expression as the suffix and the filename as the script, and
# answered `sed: 1: "/var/folders/...": invalid command code f` (measured
# 2026-08-19, macOS 26.5.2/aarch64). Under `set -eu` that aborted the whole
# harness mid-run. The portable form has no `-i` to disagree about.
sed 's/{{ suite.automated_tests }} automated tests/9999 automated tests/' \
	"$D/website/templates/index.html" >"$D/index.html.new"
mv "$D/index.html.new" "$D/website/templates/index.html"
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ] && printf '%s' "$HOOK_OUT" | grep -q 'literal test count: 9999 automated tests'; then
	ok "hook rejects a literal test count in the homepage template"
else
	bad "hook accepted a literal '9999 automated tests' (rc=$HOOK_RC): $HOOK_OUT"
fi
rm -rf "$D"

# ...and a template that stopped loading the generated file.
D=$(sandbox 5)
sed 's/load_data(path="data\/test-count.toml", required=false)/false/' \
	"$D/website/templates/index.html" >"$D/index.html.new"
mv "$D/index.html.new" "$D/website/templates/index.html"
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ] && printf '%s' "$HOOK_OUT" | grep -q 'no longer loads data/test-count.toml'; then
	ok "hook rejects a template that no longer loads the generated count"
else
	bad "hook accepted a template that does not load data/test-count.toml (rc=$HOOK_RC): $HOOK_OUT"
fi
rm -rf "$D"

# ── Scenario 2b: gate 4 derives the export list from src/wasm.rs ───────────
# The list used to be twelve hand-kept names in the hook and twelve more in
# tests/wasm_exports_test.rs, while src/wasm.rs exported sixteen. Adding an
# export to the Rust source and not to the glue is precisely the "stale WASM
# build" the gate claims to catch, and a hand-kept list cannot: a NEW function
# is by definition not on it.
D=$(sandbox 10)
echo '    pub fn brand_new_export(&self) -> u8 { 1 }' >> "$D/src/wasm.rs"
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ] && printf '%s' "$HOOK_OUT" | grep -q 'brand_new_export'; then
	ok "gate 4 catches a new src/wasm.rs export missing from the glue"
else
	bad "gate 4 missed a new export absent from the glue; output: $HOOK_OUT"
fi
rm -rf "$D"

# ── Scenario 2c: RETIRED with gate 7 ───────────────────────────────────────
# Gate 7 demanded a rebuilt sipnab_bg.wasm beside any src/wasm.rs change, and
# this scenario proved it could not be satisfied by touching the glue alone.
# Both are gone: the binary is no longer committed (it is built at deploy time
# and tripped OpenSSF Scorecard's Binary-Artifacts check), so a gate demanding
# it be restaged would block every src/wasm.rs commit forever. The export
# guard that DOES still work is exercised by tests/wasm_exports_test.rs and
# scripts/check-wasm-exports.py, both of which read the committed glue.

# ── Scenario 3: the step-2 gate rejects a non-zero (partial) run ────────────
COMPLETE=$(printf '%s\n' \
	'test result: ok. 264 passed; 0 failed; 0 ignored' \
	'test result: ok. 1600 passed; 0 failed' \
	'test result: ok. 974 passed; 0 failed')
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

# Advisory means "a commit with a cited file staged still succeeds" — so stage
# one and see whether the hook lets it through.
#
# This replaced two stacked proxies. The block was located with
# `awk '/8\. Developer docs cite code/,/All pre-commit checks passed/'`, so
# rewording a COMMENT made GATE8 the empty string and the check vacuous; and
# absence of the literal word "exit" stood in for "cannot block a commit",
# though the hook runs under `set -e`, where a bare `false` blocks with no
# "exit" anywhere. Rewording the header and adding `exit 1` left this reporting
# "gate 8 contains no exit" while a real commit of a cited file was REFUSED.
D=$(sandbox 10)
printf 'See [pipeline](../../src/lib.rs).\n' > "$D/docs/internals/x.md"
( cd "$D" && git add -A && git commit -qm docs )
printf 'pub fn prod() -> u8 { 2 }\n' > "$D/src/lib.rs"
( cd "$D" && git add src/lib.rs )
run_hook "$D"
if [ "$HOOK_RC" -eq 0 ]; then
	ok "a commit staging a cited file is allowed through (gate 8 is advisory)"
else
	bad "gate 8 BLOCKED a commit staging a cited file — it must only advise; output: $HOOK_OUT"
fi
if printf '%s' "$HOOK_OUT" | grep -q 'REVIEW'; then
	ok "gate 8 still prints REVIEW for a staged cited file"
else
	bad "gate 8 did not notice a staged cited file at all; output: $HOOK_OUT"
fi
rm -rf "$D"

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

# ── Scenario 5: the unwrap scanner scopes #[cfg(test)] to the item ─────────
# Gate 3 banned unwrap()/expect() on production paths, and its scanner set
# in_test=True on the FIRST #[cfg(test)] and never cleared it — so every line
# below one was exempt. Eleven files under src/ put a per-item #[cfg(test)]
# above production code; src/tui/controllers/mod.rs latched at line 23 of 1659,
# leaving ~10,800 production lines unscanned. An unwrap injected at line 149
# was reported as 0 violations.
#
# The scanner runs against ./src, so each case is a temp tree with cwd set to it.
#
# Sets SCAN_OUT and SCAN_RC rather than echoing, for the reason run_hook does:
# `OUT=$(scan_v ...)` would run it in a subshell and the parent would read a
# STALE SCAN_RC from an earlier case. Both are needed, because "non-zero" alone
# conflates two different answers — 1 means "found a violation" and 2 means
# "the scanner refuses to answer", and a scenario that accepts either can pass
# on a scanner that never looked at the code.
SCAN_OUT=""
SCAN_RC=0
scan_v() { # scan_v <src-file-body> [<audio-file-body>]
	_d=$(mktemp -d)
	mkdir -p "$_d/src" "$_d/crates/sipnab-audio/src"
	cat > "$_d/Cargo.toml" <<-EOF
		[workspace]
		members = [".", "crates/sipnab-audio"]
	EOF
	printf '%s\n' "$1" > "$_d/src/lib.rs"
	printf '%s\n' "${2:-pub fn audio() -> u8 { 1 }}" > "$_d/crates/sipnab-audio/src/lib.rs"
	set +e
	SCAN_OUT=$(cd "$_d" && python3 "$REPO_ROOT/scripts/check-unwrap.py" 2>&1)
	SCAN_RC=$?
	set -e
	rm -rf "$_d"
}

scan() { # scan <src-file-body> [<audio-file-body>] -> exit status of the scanner
	if [ "$#" -ge 2 ]; then scan_v "$1" "$2"; else scan_v "$1"; fi
	return $SCAN_RC
}

# `reports <line-number> <label>` — the scanner must have found exactly ONE
# violation, on that line of src/lib.rs.
#
# Both halves are load-bearing. Asserting the line separates "the gate is still
# scanning the production code after a test item" from "the gate blew up for
# some unrelated reason". Asserting the COUNT is what makes the `}`-in-a-string
# case discriminate at all: the old scanner reported that fixture's production
# line too, alongside a false positive inside the test module, so a check for
# "line 13 appears" passed on the very scanner the case exists to reject.
reports() {
	_hits=$(printf '%s\n' "$SCAN_OUT" | grep -c '^  ' || true)
	if [ "$SCAN_RC" -eq 1 ] && [ "$_hits" -eq 1 ] \
		&& printf '%s' "$SCAN_OUT" | grep -q "src/lib.rs:$1:"; then
		ok "$2"
	else
		bad "$2 -- expected exactly one violation, at src/lib.rs:$1; got rc=$SCAN_RC, $_hits violation(s): $SCAN_OUT"
	fi
}

# `quiet <label>` — a clean tree, reported as clean.
quiet() {
	if [ "$SCAN_RC" -eq 0 ] && [ "$SCAN_OUT" = "0" ]; then
		ok "$1"
	else
		bad "$1 -- expected rc=0 and a count of 0, got rc=$SCAN_RC and: $SCAN_OUT"
	fi
}

# A real test module: its unwrap is exempt, and the exemption ENDS with it.
scan 'fn prod() -> u8 { 1 }
#[cfg(test)]
mod tests {
    #[test]
    fn t() { let _ = "7".parse::<u8>().unwrap(); }
}' \
	&& ok "unwrap inside #[cfg(test)] mod tests is exempt" \
	|| bad "unwrap inside a test module must not be reported"

# A per-item #[cfg(test)] must NOT exempt the production code after it.
scan '#[cfg(test)]
use std::io::Write;

fn prod() -> u8 { "7".parse::<u8>().unwrap() }' \
	&& bad "a per-item #[cfg(test)] must not exempt the rest of the file (this is the latch bug)" \
	|| ok "production unwrap after a per-item #[cfg(test)] is reported"

# And after a test module closes, production code is scanned again.
scan '#[cfg(test)]
mod tests {
    #[test]
    fn t() { let _ = 1; }
}

fn prod() -> u8 { "7".parse::<u8>().unwrap() }' \
	&& bad "code after a closing test module must be scanned" \
	|| ok "production unwrap after a test module closes is reported"

# Clean production code is quiet.
scan 'fn prod() -> Result<u8, std::num::ParseIntError> { "7".parse::<u8>() }' \
	&& ok "clean production code reports nothing" \
	|| bad "clean production code must not be reported"

# A second workspace member is production code too. The scanner walked the
# literal path `src`, so crates/sipnab-audio/src/lib.rs -- which compiles to
# libsipnab_audio.so and is installed by build-deb.sh -- was outside the ban
# entirely, and an unwrap() appended there committed cleanly.
scan 'pub fn prod() -> u8 { 1 }' 'pub fn a() -> u8 { Some(1u8).unwrap() }' \
	&& bad "an unwrap in crates/sipnab-audio/src must be reported (the walk is not covering workspace members)" \
	|| ok "an unwrap in a second workspace member is reported"

# A `#[cfg(test)]` item NESTED in a `#[cfg(test)] mod` must not end the
# module's exemption when it closes. The exemption depth was a single scalar,
# so the inner item OVERWROTE the module's and its closing brace cleared both
# -- every test line after the helper was then scanned as production. Found by
# adding a `dict_of` helper to `rtpengine::bencode`'s tests, which reported two
# `.expect()` calls that were plainly test code.
scan_v 'fn prod() -> Result<u8, std::num::ParseIntError> { "7".parse::<u8>() }
#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn helper() -> u8 {
        1
    }

    #[test]
    fn t() { let _ = "7".parse::<u8>().unwrap(); }
}'
quiet "a nested #[cfg(test)] item does not end the module's exemption"

# ...and the exemptions still POP. A stack that never unwinds would exempt the
# rest of the file, which is the same silent hole from the other direction.
scan_v '#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn helper() -> u8 {
        1
    }
}

fn prod() -> u8 { "7".parse::<u8>().unwrap() }'
reports 9 "production code after a nested test item is scanned again"

# Several sibling `#[cfg(test)]` items: the module's exemption survives all of
# them, not just the last.
scan_v 'fn prod() -> Result<u8, std::num::ParseIntError> { "7".parse::<u8>() }
#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn a() -> u8 {
        1
    }

    #[cfg(test)]
    fn b() -> u8 {
        2
    }

    #[test]
    fn t() { let _ = "7".parse::<u8>().unwrap(); }
}'
quiet "sibling #[cfg(test)] items each restore the module's exemption"

# The SILENT direction, and the reason this is worth fixing rather than working
# around. A one-line `#[cfg(test)]` item that closes more braces than it opens
# took a `continue` that skipped the end-of-exemption check entirely, so the
# exemption stayed live over the production code that followed and its
# `unwrap()` was never reported -- the gate answering OK while checking
# nothing, which is the failure mode this scanner's own header warns about.
scan_v '#[cfg(test)]
mod tests {
    #[cfg(test)]
    fn helper() { } }
fn prod() -> u8 { "7".parse::<u8>().unwrap() }'
reports 5 "an exemption does not leak past a one-line test item that closes its block"

# ── Scenario 6: braces written inside strings, chars and comments ──────────
# The exemption above is scoped by counting `{` and `}`. Counting the raw
# characters made every brace in a string literal move the depth, and the two
# directions are not equally visible:
#
#   * an unmatched `}` ends the exemption EARLY, so test code is scanned as
#     production and someone sees a false failure and investigates;
#   * an unmatched `{` never ends it, so the exemption runs over the production
#     code that FOLLOWS the test item, every unwrap()/expect() there is exempt,
#     and the gate prints OK. Nobody investigates a gate that passes.
#
# Each case below therefore asserts the LINE reported, not merely a non-zero
# exit — see `reports`.

# THE ONE THAT FAILED OPEN. Before the fix this scan reported 0 violations and
# exited 0 with a live `.unwrap()` on line 10.
scan_v '#[cfg(test)]
mod tests {
    #[test]
    fn an_opening_brace_in_a_string() {
        let s = "a bare { inside a string literal";
        assert!(!s.is_empty());
    }
}

pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }'
reports 10 "an unmatched { in a string does not extend a test exemption over the production code after it"

# The other direction, and the reason tests/mcp_untrusted_fencing_test.rs was
# written to build its `"\n}"` needle out of a format! call: an unmatched `}`
# used to collapse the depth and expose the rest of the test module.
# Heredoc written to $HD rather than into `$( )` -- see the HD comment at the
# top. The `&'static` tick in this fixture is one of the three characters that
# make bash 3.2 lose the thread.
cat >"$HD" <<-'RS'
	#[cfg(test)]
	mod tests {
	    fn end_of_struct() -> &'static str {
	        "\n}"
	    }

	    #[test]
	    fn t() {
	        assert_eq!(end_of_struct().len(), "2".parse::<usize>().unwrap());
	    }
	}

	pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }
	RS
BODY=$(cat "$HD")
scan_v "$BODY"
reports 13 "an unmatched } in a string does not end a test exemption early (line 9 stays exempt, line 13 does not)"

# Raw strings, with hashes, are strings too — and a JSON or SIP fixture is
# exactly where a lone `{` gets written. The body deliberately carries an ODD
# number of `"`, because that is what makes the case discriminate: a scanner
# that ignores the `r#` prefix and reads the first `"` as a plain string ends
# the string at the wrong quote, leaves the `{` in the code, and then opens a
# second string that never closes.
scan_v '#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let fragment = r#"a "quoted { brace" inside"#;
        assert!(!fragment.is_empty());
    }
}

pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }'
reports 10 "braces inside a raw string do not move the brace depth"

# Char and byte-char literals. `'{'` is two opening braces to a raw count and
# none to Rust. The lifetimes elsewhere in these fixtures are load-bearing
# too: reading `'a` as the start of a char literal would swallow whatever
# follows, which the end-of-file balance check turns into a hard failure
# rather than a wrong answer.
# Heredoc written to $HD rather than into `$( )` -- see the HD comment at the
# top. The `'{'` and `b'{'` char literals here are the second of the three
# characters that make bash 3.2 lose the thread.
cat >"$HD" <<-'RS'
	#[cfg(test)]
	mod tests {
	    #[test]
	    fn t() {
	        assert_eq!('{', char::from(b'{'));
	    }
	}

	pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }
	RS
BODY=$(cat "$HD")
scan_v "$BODY"
reports 9 "braces inside char and byte-char literals do not move the brace depth"

# Line comments, block comments (which nest in Rust), and doc comments.
scan_v '#[cfg(test)]
mod tests {
    // A line comment with an opening brace: {
    /* a block comment with another {
       and /* a nested one */ closing here } */
    #[test]
    fn t() {
        assert_eq!(1, 1);
    }
}

pub fn prod() -> u8 { "7".parse::<u8>().unwrap() }'
reports 12 "braces inside line, block and nested block comments do not move the brace depth"

# A comment BETWEEN the attribute and the item it annotates. The raw-line
# scanner treated that comment as the annotated item, decided it was a one-line
# item, and dropped the exemption before the module even opened.
scan_v '#[cfg(test)]
// The item this annotates is on the next line.
mod tests {
    #[test]
    fn t() {
        let _ = "7".parse::<u8>().unwrap();
    }
}'
quiet "a comment between #[cfg(test)] and its item does not break the exemption"

# `.unwrap()` written inside a string or a doc comment is prose about the ban,
# not a violation of it. The scanner reads the stripped code for this too.
#
# Heredoc written to $HD rather than into `$( )` -- see the HD comment at the
# top. This fixture carries all three of the characters bash 3.2 trips on: the
# doc comment's backticks, the `&'static` tick, and a double quote.
cat >"$HD" <<-'RS'
	/// Never call `.unwrap()` on a request path.
	pub fn explain() -> &'static str {
	    "sipnab does not call .unwrap() while parsing a packet"
	}
	RS
BODY=$(cat "$HD")
scan_v "$BODY"
quiet "a mention of .unwrap() inside a string or doc comment is not a violation"

# FAIL CLOSED. A .rs file the compiler accepts ends outside every literal with
# its braces balanced; anything else means the stripping lost the thread, and a
# scanner that lost the thread reports the rest of the file as exempt. Refusing
# to answer is the same intent as the empty-walk guard: a count nobody can
# trust must not be printed as a clean result.
scan_v 'pub fn prod() -> u8 {
    let s = "unterminated;
    1
}'
if [ "$SCAN_RC" -eq 2 ] && printf '%s' "$SCAN_OUT" | grep -q 'ended in lexer state'; then
	ok "a file the lexer cannot balance is refused (exit 2), not reported as clean"
else
	bad "an unterminated string must make the scanner refuse to answer; got rc=$SCAN_RC and: $SCAN_OUT"
fi

# ── Scenario 6b: the abort macros, and the marker that excuses one site ────
# `panic!`, `unreachable!`, `todo!` and `unimplemented!` end the process the
# way an unwrap does, and the scanner never looked at them. A site that
# cannot be reached keeps the macro only under `// gate: <macro> because
# <reason>`, and the reason is the part that matters: a marker without one
# is reported, not honored. scripts/tests/test_check_unwrap.py holds the
# full rule set; these three are its shape, kept beside the unwrap cases so
# both halves of one scanner are exercised by one harness.
scan_v 'pub fn prod(x: u8) -> u8 {
    match x {
        0 => 1,
        _ => unreachable!(),
    }
}'
reports 4 "a bare unreachable!() on a production path is reported"

scan_v 'pub fn prod(x: u8) -> u8 {
    match x {
        0 => 1,
        // gate: unreachable because the caller masks every other value
        _ => unreachable!(),
    }
}'
quiet "an unreachable!() under a gate: marker that gives a reason is accepted"

scan_v 'pub fn prod(x: u8) -> u8 {
    match x {
        0 => 1,
        // gate: unreachable because
        _ => unreachable!(),
    }
}'
reports 5 "a gate: marker with no reason does not exempt the site"

# The hook must read the scanner's EXIT STATUS, not parse merged output: stderr
# is unbuffered and stdout is not, so a violation line can arrive after the
# count in a 2>&1 stream.
grep -q 'if ! UNWRAP_OUT=\$(python3 scripts/check-unwrap.py' "$HOOK" \
	&& ok "hook reads the scanner's exit status" \
	|| bad "hook must branch on the scanner's exit status, not parse its output"

# ── Scenario 7: a prose gate that FINDS something says what it found ───────
# The regression: `set -e` is on, `prose_vale_run` is a simple command, and the
# CONTRACT in scripts/prose-gates.sh has it return 1 for "the tool ran and found
# something". `set -e` therefore killed the hook on that return -- BEFORE the
# `case $?` written to render it -- and before the `rm -f "$PROSE_OUTPUT"` that
# would at least have left the findings on disk. What an operator saw was the
# literal string `  Vale... ` and exit 1: no findings, no file names, no
# "Commit blocked" line, and nothing to distinguish a prose failure from a hook
# that crashed. Measured 2026-08-24 against the real hook.
#
# Both gates are exercised, because they are two copies of one shape and the
# first fix touched only one of them.
prose_sandbox() { # prose_sandbox <vale-exit> <codespell-exit>; echoes the dir
	_p=$(sandbox 100)
	mkdir -p "$_p/.github/workflows" "$_p/.config"
	cp "$REPO_ROOT/scripts/prose-gates.sh" "$_p/scripts/"
	# The pin the stub below must match. prose_vale_pin() reads it from here,
	# and a mismatch is return 2 (NOT CHECKED), which is neither arm under test.
	printf "env:\n  VALE_VERSION: '9.9.9'\n" > "$_p/.github/workflows/quality.yml"
	# The same for codespell: prose_codespell_pin() reads the version from the
	# requirements file, and the stub below reports it.
	echo 'codespell==9.9.9 --hash=sha256:0' > "$_p/scripts/requirements-codespell.txt"
	echo 'docs' > "$_p/.config/vale-paths.txt"
	echo 'docs' > "$_p/.config/codespell-paths.txt"
	mkdir -p "$_p/docs"
	echo 'Some prose.' > "$_p/docs/page.md"

	cat > "$_p/bin/vale" <<-EOF
		#!/bin/sh
		case "\$1" in --version) echo "vale version 9.9.9"; exit 0 ;; esac
		echo "docs/page.md:1:1  error  A findable prose problem  Some.Rule"
		exit $1
	EOF
	cat > "$_p/bin/codespell" <<-EOF
		#!/bin/sh
		case "\$1" in --version) echo "9.9.9"; exit 0 ;; esac
		echo "docs/page.md:1: a findable spelling problem"
		exit $2
	EOF
	chmod +x "$_p/bin/vale" "$_p/bin/codespell"
	( cd "$_p" && git add -A && git commit -qm prose )
	echo "$_p"
}

D=$(prose_sandbox 1 0)
run_hook "$D"
if printf '%s' "$HOOK_OUT" | grep -q 'A findable prose problem'; then
	ok "a vale finding reaches the operator instead of dying with set -e"
else
	bad "vale found something and the hook printed nothing about it: $HOOK_OUT"
fi
if [ "$HOOK_RC" -ne 0 ] && printf '%s' "$HOOK_OUT" | grep -q 'Commit blocked'; then
	ok "a vale finding blocks the commit, and says so"
else
	bad "a vale finding must block and name itself; rc=$HOOK_RC out: $HOOK_OUT"
fi
rm -rf "$D"

D=$(prose_sandbox 0 1)
run_hook "$D"
if printf '%s' "$HOOK_OUT" | grep -q 'a findable spelling problem'; then
	ok "a codespell finding reaches the operator too"
else
	bad "codespell found something and the hook printed nothing about it: $HOOK_OUT"
fi
rm -rf "$D"

# The clean arm, so the two above are not passing because the hook prints
# everything unconditionally: with both tools silent the gate must say OK and
# carry on to the gates after it.
D=$(prose_sandbox 0 0)
run_hook "$D"
if printf '%s' "$HOOK_OUT" | grep -q 'Vale... .*OK'; then
	ok "a clean tree passes the prose gates rather than reporting a finding"
else
	bad "a clean prose run must render OK: $HOOK_OUT"
fi
rm -rf "$D"

# ── Scenario P: the gitignored inputs are checked before anything runs ────
# A fresh worktree has none of them. The G.729 test vectors
# (crates/g729/test-vectors) are filled only by
# `python3 scripts/fetch-g729-vectors.py`, and the hook used to discover them
# missing 25 minutes into the suite, on 52 failing tests. Vale's style
# package is written only by `vale sync`. The hook now refuses at once,
# naming the command for each missing input, before any gate runs: the stub
# cargo logs every call, and it must not have been called.
prereq_sandbox() { # echoes a sandbox holding every prerequisite
	_p=$(sandbox 1)
	mkdir -p "$_p/crates/g729" "$_p/.vale/styles/Google"
	printf '[package]\nname = "sipnab-g729"\n' > "$_p/crates/g729/Cargo.toml"
	cp "$REPO_ROOT/.vale.ini" "$_p/.vale.ini"
	printf '#!/bin/sh\nexit 0\n' > "$_p/bin/vale"
	chmod +x "$_p/bin/vale"
	# A placeholder at every path the fetcher writes, read from its own pins.
	python3 -I -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("fetch", sys.argv[1])
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)
for entry in {**fetch.ALL_PINS, **fetch.G7291_PINS}:
    path = fetch.destination(sys.argv[2], entry)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x")
' "$REPO_ROOT/scripts/fetch-g729-vectors.py" "$_p/crates/g729/test-vectors"
	echo "$_p"
}

# refused_at_once <case> <command...>: after run_hook, the hook must have
# refused, printed each command, run no gate and called no cargo, in seconds.
refused_at_once() {
	_case=$1
	shift
	_why=""
	[ "$HOOK_RC" -ne 0 ] || _why="$_why exit 0;"
	for _cmd in "$@"; do
		printf '%s' "$HOOK_OUT" | grep -qF "run: $_cmd" || _why="$_why no 'run: $_cmd';"
	done
	! printf '%s' "$HOOK_OUT" | grep -qF 'Formatting' || _why="$_why a gate ran;"
	[ ! -s "$D/cargo-invocations" ] || _why="$_why cargo ran;"
	[ "$PREREQ_SECONDS" -le 10 ] || _why="$_why took ${PREREQ_SECONDS}s;"
	if [ -z "$_why" ]; then
		ok "$_case: refused at once with the command that fixes it"
	else
		bad "$_case:$_why out: $HOOK_OUT"
	fi
}

timed_hook() {
	: > "$D/cargo-invocations"
	_t0=$(date +%s)
	run_hook "$D"
	PREREQ_SECONDS=$(( $(date +%s) - _t0 ))
}

D=$(prereq_sandbox)
timed_hook
if [ "$HOOK_RC" -eq 0 ] && printf '%s' "$HOOK_OUT" | grep -qF 'Prerequisites... OK' \
	&& [ -s "$D/cargo-invocations" ]; then
	ok "with every prerequisite in place the hook checks them and goes on to the gates"
else
	bad "a provisioned tree must pass the prerequisite check and run the gates (rc=$HOOK_RC): $HOOK_OUT"
fi
rm -rf "$D"

D=$(prereq_sandbox)
rm -rf "$D/crates/g729/test-vectors"
timed_hook
refused_at_once "the G.729 vectors never fetched" "python3 scripts/fetch-g729-vectors.py"
rm -rf "$D"

D=$(prereq_sandbox)
rm -f "$D/crates/g729/test-vectors/annex-b/"*
timed_hook
refused_at_once "one directory of G.729 vectors gone" "python3 scripts/fetch-g729-vectors.py"
rm -rf "$D"

D=$(prereq_sandbox)
rm -rf "$D/.vale/styles/Google"
timed_hook
refused_at_once "the Vale style package never synced" "vale sync"
rm -rf "$D"

D=$(prereq_sandbox)
rm -rf "$D/crates/g729/test-vectors" "$D/.vale/styles/Google"
timed_hook
refused_at_once "both missing, both named" "python3 scripts/fetch-g729-vectors.py" "vale sync"
rm -rf "$D"

# cargo-nextest runs the suite, at the version .config/nextest.toml pins.
NEXTEST_PIN=$(sed -n 's/^nextest-version = { required = "\(.*\)" }$/\1/p' "$REPO_ROOT/.config/nextest.toml")
D=$(prereq_sandbox)
rm -f "$D/nextest-version"
timed_hook
refused_at_once "cargo-nextest not installed" "cargo install cargo-nextest --locked --version $NEXTEST_PIN"
rm -rf "$D"

D=$(prereq_sandbox)
echo 0.0.1 > "$D/nextest-version"
timed_hook
refused_at_once "another cargo-nextest version installed" "cargo install cargo-nextest --locked --version $NEXTEST_PIN"
rm -rf "$D"

# A tree from before the check (no scripts/check-hook-prerequisites.py) is
# not refused for lacking it: the hook says it did not check, the way the
# prose gate does for a missing scripts/prose-gates.sh, and runs its gates.
D=$(sandbox 1)
rm -f "$D/scripts/check-hook-prerequisites.py"
timed_hook
if printf '%s' "$HOOK_OUT" | grep -qF 'Prerequisites... NOT CHECKED' \
	&& [ -s "$D/cargo-invocations" ]; then
	ok "a tree without the checker is told it was not checked, and its gates run"
else
	bad "a tree without the checker must be NOT CHECKED, not refused (rc=$HOOK_RC): $HOOK_OUT"
fi
rm -rf "$D"

# ── Scenario 9: a release-only commit runs the release gates, not the suite ─
# The 0.5.238 release commit spent 14 minutes in this hook running the whole
# suite on a version bump. scripts/release-only.py decides; these drive the
# REAL hook on a sandbox with a CHANGELOG and watch which cargo runs it makes.
#
# release_sandbox: a sandbox whose base commit has a CHANGELOG under
# [Unreleased], then the version 9.9.9 -> 9.9.10 and the heading staged.
release_sandbox() {
	_rd=$(sandbox 1)
	printf '# Changelog\n\n## [Unreleased]\n\n- a change\n' >"$_rd/CHANGELOG.md"
	( cd "$_rd" && git add CHANGELOG.md && git commit -qm changelog )
	sed -i.bak 's/^version = "9.9.9"$/version = "9.9.10"/' "$_rd/Cargo.toml" && rm -f "$_rd/Cargo.toml.bak"
	sed -i.bak 's/^## \[Unreleased\]$/## [9.9.10] - 2026-11-08/' "$_rd/CHANGELOG.md" && rm -f "$_rd/CHANGELOG.md.bak"
	( cd "$_rd" && git add Cargo.toml CHANGELOG.md )
	: >"$_rd/cargo-invocations"
	echo "$_rd"
}
D=$(release_sandbox)
run_hook "$D"
if [ "$HOOK_RC" -eq 0 ] && printf '%s' "$HOOK_OUT" | grep -qF 'release-only: 9.9.9 -> 9.9.10'; then
	ok "a staged release bump passes and the hook names the release-only proof"
else
	bad "a staged release bump was not handled as release-only (rc=$HOOK_RC): $HOOK_OUT"
fi
if ! grep -q '^nextest run' "$D/cargo-invocations" && ! grep -q '^clippy' "$D/cargo-invocations"; then
	ok "a release-only commit runs neither the suite nor clippy"
else
	bad "a release-only commit still ran the suite or clippy: $(cat "$D/cargo-invocations")"
fi
if grep -q '^test --features full --color never --test cli_flag_since_test .*--test docs_drift_test .*--test release_delivery_test' "$D/cargo-invocations"; then
	ok "a release-only commit runs the release test targets"
else
	bad "a release-only commit did not run the release test targets: $(cat "$D/cargo-invocations")"
fi
if printf '%s' "$HOOK_OUT" | grep -qF 'Homepage test count generated... ' \
	&& printf '%s' "$HOOK_OUT" | grep -qF 'not counted: a release-only commit'; then
	ok "a release-only commit still checks the homepage count mechanism and says it counted nothing"
else
	bad "the homepage count step did not say the release-only commit counted nothing: $HOOK_OUT"
fi
rm -rf "$D"

# A failing release test target blocks the commit.
D=$(release_sandbox)
: >"$D/fail-test"
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ] && printf '%s' "$HOOK_OUT" | grep -qF '(the release test targets)' \
	&& printf '%s' "$HOOK_OUT" | grep -qF 'test stub_fails ... FAILED'; then
	ok "a failing release test target blocks a release-only commit"
else
	bad "a failing release test target did not block the release-only commit (rc=$HOOK_RC): $HOOK_OUT"
fi
rm -rf "$D"

# The same bump with a source change beside it is an ordinary commit.
D=$(release_sandbox)
echo 'pub fn prod() -> u8 { 2 }' >"$D/src/lib.rs"
( cd "$D" && git add src/lib.rs )
run_hook "$D"
if grep -q '^nextest run --profile suite' "$D/cargo-invocations" \
	&& ! printf '%s' "$HOOK_OUT" | grep -qF 'release-only:'; then
	ok "a release bump with a source change runs the full suite"
else
	bad "a release bump with a source change skipped the suite: $(cat "$D/cargo-invocations")"
fi
rm -rf "$D"

# SIPNAB_GATE_NO_CACHE=1 runs every step, even on a release bump.
D=$(release_sandbox)
set +e
HOOK_OUT=$(cd "$D" && PATH="$D/bin:$PATH" SIPNAB_HOOK_ANY_TREE=1 SIPNAB_GATE_NO_CACHE=1 bash "$HOOK" 2>&1)
HOOK_RC=$?
set -e
if grep -q '^nextest run --profile suite' "$D/cargo-invocations"; then
	ok "SIPNAB_GATE_NO_CACHE=1 runs the full suite on a release bump"
else
	bad "SIPNAB_GATE_NO_CACHE=1 did not run the suite on a release bump: $(cat "$D/cargo-invocations")"
fi
rm -rf "$D"

# A tree without scripts/release-only.py (an older branch) runs every step.
D=$(release_sandbox)
rm -f "$D/scripts/release-only.py"
run_hook "$D"
if grep -q '^nextest run --profile suite' "$D/cargo-invocations"; then
	ok "a tree without the classifier runs the full suite"
else
	bad "a tree without the classifier skipped the suite: $(cat "$D/cargo-invocations")"
fi
rm -rf "$D"

printf '\n%d passed, %d failed, %d skipped (host: %s)\n' \
	"$PASS" "$FAIL" "$SKIP" "$(uname -s)"
if [ "$SKIP" -ne 0 ]; then
	printf 'A SKIP is coverage this host could not provide, not coverage that\n'
	printf 'passed. Run on Linux for the full set.\n'
fi
[ "$FAIL" -eq 0 ]
