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
#   4. Gate 8 advises and never blocks.
#   5. The unwrap scanner scopes #[cfg(test)] to the item, and covers every
#      workspace member rather than the literal path src/.
#
# The hook is EXECUTED, in a throwaway git repo with `cargo` stubbed onto PATH.
# It used to be grepped instead, and the greps are what let two of the exact
# regressions this file names slip back in -- see the sandbox comment below.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HOOK="$REPO_ROOT/.githooks/pre-commit"

PASS=0
FAIL=0
ok()  { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$1"; }

# ── The sandbox: run the REAL hook against a stubbed cargo ─────────────────
# Everything below used to be grepped for out of the hook's source, which made
# the hook's exact SPELLING the proxy for its behaviour, twice over:
#
#   * `grep -c '\$(cargo test --features full'` counted the literal `$(`. The
#     regression this script is the designated pin for -- a second full-suite
#     run -- was reintroduced spelled with backticks (identical POSIX command
#     substitution) and this reported "exactly once (got 1)", 11/11 green. The
#     script never executed the hook at all.
#   * Scenario 2 summed a `test result:` fixture with its OWN copy of
#     `awk '{sum += $4}'`. Changing the hook's copy to `$6` left 11/11 green,
#     because the assertion never read the hook's expression.
#
# The fix is to run the hook and observe what it did. `cargo` is stubbed onto
# PATH so it is instant and its output is known exactly; the stub appends one
# line per invocation, which is what "exactly once" is now measured against.
sandbox() { # sandbox <passed-per-binary...> ; echoes the sandbox dir
	_d=$(mktemp -d)
	mkdir -p "$_d/src" "$_d/crates/sipnab-audio/src" "$_d/scripts" \
		"$_d/website/templates" "$_d/docs/internals" "$_d/bin"

	cat > "$_d/Cargo.toml" <<-EOF
		[workspace]
		members = [".", "crates/sipnab-audio"]
		[package]
		name = "sipnab"
		version = "9.9.9"
	EOF
	echo 'pub fn prod() -> u8 { 1 }' > "$_d/src/lib.rs"
	echo 'pub fn audio() -> u8 { 1 }' > "$_d/crates/sipnab-audio/src/lib.rs"
	cp "$REPO_ROOT/scripts/check-unwrap.py" "$REPO_ROOT/scripts/check-wasm-exports.py" \
		"$_d/scripts/"

	# A WASM surface, so gates 4 and 7 are reachable rather than skipped. Ten
	# exports is the floor check-wasm-exports.py refuses to go below.
	mkdir -p "$_d/website/static/wasm"
	{
		echo '#[wasm_bindgen]'
		echo 'impl Analyzer {'
		for _i in 1 2 3 4 5 6 7 8 9 10 11; do
			echo "    pub fn export_$_i(&self) -> u8 { 1 }"
		done
		echo '}'
	} > "$_d/src/wasm.rs"
	{
		echo 'class Analyzer {'
		for _i in 1 2 3 4 5 6 7 8 9 10 11; do
			echo "    export_$_i() { return 1; }"
		done
		echo '}'
	} > "$_d/website/static/wasm/sipnab.js"
	printf '\0asm' > "$_d/website/static/wasm/sipnab_bg.wasm"

	# The cargo stub. Every invocation is logged; `test` emits the canned
	# per-binary results the caller asked for.
	cat > "$_d/bin/cargo" <<-EOF
		#!/bin/sh
		echo "\$*" >> "$_d/cargo-invocations"
		case "\$1" in
		  test) shift; cat "$_d/canned-test-output" ;;
		  *) : ;;
		esac
		exit 0
	EOF
	chmod +x "$_d/bin/cargo"
	: > "$_d/cargo-invocations"
	: > "$_d/canned-test-output"
	_total=0
	for _n in "$@"; do
		echo "test result: ok. $_n passed; 0 failed; 0 ignored" >> "$_d/canned-test-output"
		_total=$((_total + _n))
	done
	# The homepage the hook will check, carrying the true total.
	cat > "$_d/website/templates/index.html" <<-EOF
		<span class="arch-stat" data-count="$_total" data-suffix="">$_total</span>
		<p>Automated tests</p>
		<tr><td>$_total automated tests.</td></tr>
	EOF

	( cd "$_d" && git init -q . && git config user.email t@t && git config user.name t \
		&& git add -A && git commit -qm base )
	echo "$_d"
}

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
	HOOK_OUT=$(cd "$1" && PATH="$1/bin:$PATH" bash "$HOOK" 2>&1)
	HOOK_RC=$?
	set -e
}

# ── Scenario 1: exactly one full-suite invocation, measured by running it ──
D=$(sandbox 264 1600 974)
run_hook "$D"
RUNS=$(grep -c '^test ' "$D/cargo-invocations" || true)
if [ "$RUNS" -eq 1 ]; then
	ok "hook invoked 'cargo test' exactly once (counted $RUNS actual invocations)"
else
	bad "hook must invoke 'cargo test' exactly once, it invoked it $RUNS times (a second run is the flaky-count regression)"
fi

# ── Scenario 2: the hook's own summing, exercised end to end ───────────────
# 264 + 1600 + 974 = 2838, and the sandbox homepage says 2838. If the hook's
# awk column were wrong the sum would not match and the gate would fail.
run_hook "$D"
if printf '%s' "$HOOK_OUT" | grep -q 'Homepage test count.*OK (2838)'; then
	ok "hook summed the passed column across three binaries (2838)"
else
	bad "hook did not compute 2838 from 264+1600+974; output was: $HOOK_OUT"
fi

# And it must FAIL when the homepage disagrees — otherwise the above proves
# only that the gate is quiet, not that it compares.
sed -i 's/2838/9999/g' "$D/website/templates/index.html"
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ]; then
	ok "hook rejects a homepage count that disagrees with the run"
else
	bad "hook accepted a homepage count of 9999 against a real 2838"
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

# ── Scenario 2c: gate 7 requires the compiled artifact, not any path ───────
# `grep -q "website/static/wasm/sipnab"` matched sipnab.js, so a single
# appended newline to the glue satisfied it while sipnab_bg.wasm stayed
# byte-identical — a behaviour change to src/wasm.rs shipping with a stale
# bundle.
D=$(sandbox 10)
echo '// behaviour change' >> "$D/src/wasm.rs"
echo '' >> "$D/website/static/wasm/sipnab.js"
( cd "$D" && git add src/wasm.rs website/static/wasm/sipnab.js )
run_hook "$D"
if [ "$HOOK_RC" -ne 0 ]; then
	ok "gate 7 rejects a src/wasm.rs change with only the glue restaged"
else
	bad "gate 7 accepted a src/wasm.rs change whose .wasm was never rebuilt"
fi
# Restaging the compiled artifact clears it.
printf '\0asmREBUILT' > "$D/website/static/wasm/sipnab_bg.wasm"
( cd "$D" && git add website/static/wasm/sipnab_bg.wasm )
run_hook "$D"
if [ "$HOOK_RC" -eq 0 ]; then
	ok "gate 7 passes once sipnab_bg.wasm is rebuilt and staged"
else
	bad "gate 7 still blocked after the .wasm was rebuilt; output: $HOOK_OUT"
fi
rm -rf "$D"

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
scan() { # scan <src-file-body> -> exit status of the scanner
	_d=$(mktemp -d)
	mkdir -p "$_d/src" "$_d/crates/sipnab-audio/src"
	cat > "$_d/Cargo.toml" <<-EOF
		[workspace]
		members = [".", "crates/sipnab-audio"]
	EOF
	printf '%s\n' "$1" > "$_d/src/lib.rs"
	printf '%s\n' "${2:-pub fn audio() -> u8 { 1 }}" > "$_d/crates/sipnab-audio/src/lib.rs"
	( cd "$_d" && python3 "$REPO_ROOT/scripts/check-unwrap.py" >/dev/null 2>&1 )
	_rc=$?
	rm -rf "$_d"
	return $_rc
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

# The hook must read the scanner's EXIT STATUS, not parse merged output: stderr
# is unbuffered and stdout is not, so a violation line can arrive after the
# count in a 2>&1 stream.
grep -q 'if ! UNWRAP_OUT=\$(python3 scripts/check-unwrap.py' "$HOOK" \
	&& ok "hook reads the scanner's exit status" \
	|| bad "hook must branch on the scanner's exit status, not parse its output"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
