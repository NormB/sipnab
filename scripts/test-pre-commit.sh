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
#   6. That scoping survives braces written inside strings, char literals and
#      comments -- which is where it used to fail open.
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
# Everything below used to be grepped for out of the hook's source, which made
# the hook's exact SPELLING the proxy for its behavior, twice over:
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
	# EVERY python gate the hook runs, and a source surface for each. The list
	# was `check-unwrap.py` and `check-wasm-exports.py` only, and it went stale
	# the moment gate 3b (privilege drop) landed: the hook ran
	# `python3 scripts/check-privilege-drop.py`, python3 could not open a file
	# that had never been copied, the hook exited 1 at step 3b -- and every
	# scenario from 2 onward was then asserting against a hook that died before
	# reaching the gate under test. Scenario 1 still passed (cargo runs at step
	# 2, before the break), which is why the harness reported a partial green
	# rather than an obvious red. Found 2026-08-19 on macOS/aarch64 by running
	# it; it fails identically on Linux, so this half is not a platform defect,
	# it is a stale list -- the same class the hook's own WASM-export comment
	# already records.
	cp "$REPO_ROOT/scripts/check-unwrap.py" "$REPO_ROOT/scripts/check-wasm-exports.py" \
		"$REPO_ROOT/scripts/check-privilege-drop.py" "$_d/scripts/"

	# A privilege-drop surface, so gate 3b is reachable rather than exploding.
	# check-privilege-drop.py wants all five controls, drop_supplementary_groups
	# BEFORE set_gid, a main.rs that calls block_privilege_escalation(), and at
	# least 500 bytes of production code (its own guard against a scan that read
	# nothing). This is the minimum that satisfies all four.
	cat > "$_d/src/privilege.rs" <<-'EOF'
		//! Minimal stand-in for the real privilege-drop path.
		pub fn block_privilege_escalation() -> Result<(), ()> {
		    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
		    set_no_new_privs()?;
		    Ok(())
		}
		pub fn set_no_new_privs() -> Result<(), ()> {
		    unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
		    Ok(())
		}
		pub fn drop_supplementary_groups() -> Result<(), ()> {
		    Ok(())
		}
		pub fn set_gid(gid: u32) -> Result<(), ()> {
		    let _ = gid;
		    Ok(())
		}
		pub fn harden() -> Result<(), ()> {
		    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
		    unsafe { libc::chroot(c"/var/empty".as_ptr()) };
		    unsafe { libc::chdir(c"/".as_ptr()) };
		    drop_supplementary_groups()?;
		    set_gid(65534)?;
		    set_no_new_privs()?;
		    Ok(())
		}
	EOF
	cat > "$_d/src/main.rs" <<-'EOF'
		mod privilege;
		fn main() {
		    let _ = privilege::block_privilege_escalation();
		}
	EOF

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
#
# Write-to-temp-and-move rather than `sed -i`. `sed -i EXPR FILE` is the GNU
# spelling; BSD sed takes the backup SUFFIX as -i's argument, so on macOS it
# read `s/2838/9999/g` as the suffix and the filename as the script, and
# answered `sed: 1: "/var/folders/...": invalid command code f` (measured
# 2026-08-19, macOS 26.5.2/aarch64). Under `set -eu` that aborted the whole
# harness mid-run: scenarios 2b through 6 never executed and the script printed
# no summary at all. The portable form has no `-i` to disagree about.
sed 's/2838/9999/g' "$D/website/templates/index.html" >"$D/index.html.new"
mv "$D/index.html.new" "$D/website/templates/index.html"
run_hook "$D"
# ---- Why this scenario cannot assert a BLOCK off Linux ----------------------
# The gate under test now warns instead of failing when `uname -s` is not
# Linux, and that is deliberate: the published number must be the LINUX count
# because ci.yml compares against it, and the ~114 `#[cfg(target_os = "linux")]`
# uprobe/bpf tests cannot compile on a Mac, so a local run can never reach it.
# See the comment at .githooks/pre-commit's step 5.
#
# That makes "the hook rejects a disagreeing count" true on Linux and false
# here, by design. Asserting it anyway would turn a correct hook into a red
# harness on every Mac; deleting the assertion would drop the only coverage of
# the comparison. So each host asserts the branch it can actually reach --
# BLOCK on Linux, WARN-and-name-both-numbers everywhere else -- and neither
# host is allowed to pass by observing nothing.
if [ "$(uname -s)" != "Linux" ]; then
	# The warn arm must still have COMPARED: it prints both figures, and a
	# gate that skipped the comparison outright would print neither.
	if printf '%s' "$HOOK_OUT" | grep -q 'Homepage shows 9999.*counted 2838'; then
		ok "hook warns (not blocks) on a disagreeing homepage count off Linux, naming 9999 vs 2838"
	else
		bad "off Linux the hook must WARN and name both numbers; output was: $HOOK_OUT"
	fi
	skip "hook rejects a disagreeing homepage count -- blocking is Linux-only by design (ci.yml owns the number)"
elif [ "$HOOK_RC" -ne 0 ]; then
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

# The hook must read the scanner's EXIT STATUS, not parse merged output: stderr
# is unbuffered and stdout is not, so a violation line can arrive after the
# count in a 2>&1 stream.
grep -q 'if ! UNWRAP_OUT=\$(python3 scripts/check-unwrap.py' "$HOOK" \
	&& ok "hook reads the scanner's exit status" \
	|| bad "hook must branch on the scanner's exit status, not parse its output"

printf '\n%d passed, %d failed, %d skipped (host: %s)\n' \
	"$PASS" "$FAIL" "$SKIP" "$(uname -s)"
if [ "$SKIP" -ne 0 ]; then
	printf 'A SKIP is coverage this host could not provide, not coverage that\n'
	printf 'passed. Run on Linux for the full set.\n'
fi
[ "$FAIL" -eq 0 ]
