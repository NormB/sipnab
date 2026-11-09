# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# shellcheck shell=sh
# Sourced (POSIX sh) by scripts/test-pre-commit.sh, and by
# scripts/tests/test_gate_cache_hooks.py, which drive the REAL
# .githooks/pre-commit in the throwaway tree `sandbox` builds. The caller sets
# REPO_ROOT (this checkout) and HOOK (the hook whose named Python scripts are
# copied in), and sources scripts/lib-git-sandbox.sh first for
# require_own_git_dir.
#
# The stub cargo also reads three per-sandbox switches, all absent by default:
#   fail-<subcommand>   exit 1 for that cargo subcommand (clippy, test, ...);
#   sleep-<subcommand>  sleep that many seconds before it runs;
#   canned-replay-junit.xml  the report of a `nextest run` given `-E` (the
#                       replay of the last failures); canned-junit.xml otherwise.

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
		"$_d/website/templates" "$_d/docs/internals"
	# The harness's own files -- the stubs, their logs and canned reports --
	# live in the sandbox unless SANDBOX_HARNESS_DIR names a directory for
	# them. scripts/tests/test_gate_cache_hooks.py names one: a pass stamp
	# covers every file in the tree, so stubs that rewrite their logs inside it
	# would change the tree under every run.
	_h=${SANDBOX_HARNESS_DIR:-$_d}
	mkdir -p "$_h/bin"

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
	#
	# It went stale AGAIN with check-generated-inputs-staged.py: the hook died
	# at "Generated files staged with their inputs" and four scenarios failed,
	# unnoticed, because nothing ran this file (found 2026-09-29; CI runs it
	# now). So the list is no longer kept by hand: it is every Python script
	# the hook names, read from the hook itself, and the scripts/lib_*.py
	# helpers they import (rfc-links.py needs lib_markdown.py).
	for _py in $(grep -o 'scripts/[A-Za-z0-9_-]*\.py' "$HOOK" | sort -u); do
		cp "$REPO_ROOT/$_py" "$_d/scripts/"
	done
	for _lib in $(cat "$_d"/scripts/*.py | sed -n 's/^from \(lib_[a-z_]*\) import.*/\1/p' | sort -u); do
		cp "$REPO_ROOT/scripts/$_lib.py" "$_d/scripts/"
	done

	# A feature-gate surface, so "Features declare their modules' imports" is
	# reachable. check-feature-deps.py refuses fewer than 10 feature-gated
	# modules or 5 optional crates -- a walk that sees nothing must not pass --
	# so the fixture has exactly that many, importing nothing.
	{
		echo '[dependencies]'
		for _n in 1 2 3 4 5; do
			echo "optcrate$_n = { version = \"1\", optional = true }"
		done
		echo '[features]'
		for _n in 1 2 3 4 5; do
			echo "feat$_n = [\"dep:optcrate$_n\"]"
		done
	} >> "$_d/Cargo.toml"
	mkdir -p "$_d/src/gated"
	for _n in 1 2 3 4 5 6 7 8 9 10; do
		printf '#[cfg(feature = "feat%s")]\nmod m%s;\n' $(( (_n - 1) % 5 + 1 )) "$_n" >> "$_d/src/gated/mod.rs"
		echo 'pub fn f() {}' > "$_d/src/gated/m$_n.rs"
	done

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

	# The cargo stub. Every invocation is logged except `nextest --version`,
	# which scripts/check-hook-prerequisites.py and scripts/parallel-tests.py
	# ask before anything runs: it prints the version in $_h/nextest-version,
	# or fails as an absent cargo-nextest does when that file is missing.
	# The suite runs as `cargo nextest run --profile suite ...` (via
	# scripts/parallel-tests.py, which also asks `cargo metadata` for the
	# target directory): the stub writes the canned JUnit report where nextest
	# writes it, one test binary per number the caller asked for, and
	# parallel-tests.py renders it as libtest text. The doctests run as
	# `cargo test ... --doc` and report none.
	#
	# The suite's own invocation also writes the SIPNAB_* variables it can see
	# to pool-env: nextest and every test process inherit exactly that
	# environment, so Scenario 1c reads from it what the suite was given.
	#
	# The workspace root the stub reports, and the target directory and JUnit
	# report under it, are one per tree, under the harness and keyed on the
	# tree's top level, as two worktrees have one each. One shared root let
	# two hooks run at once in two worktrees race on one JUnit report:
	# parallel-tests.py deletes the report (at <workspace root>/target/nextest)
	# before each run, so one hook could delete the report the other hook's
	# stub had just written (FLAKY-GATE-CACHE-CONCURRENT).
	cat > "$_h/bin/cargo" <<-EOF
		#!/bin/sh
		_w="$_h/ws/\$(git rev-parse --show-toplevel 2>/dev/null | cksum | cut -d' ' -f1)"
		if [ "\$1 \$2" = "nextest --version" ]; then
		  [ -f "$_h/nextest-version" ] || exit 101
		  echo "cargo-nextest \$(cat "$_h/nextest-version") (stub)"; exit 0
		fi
		echo "\$*" >> "$_h/cargo-invocations"
		[ -f "$_h/sleep-\$1" ] && sleep "\$(cat "$_h/sleep-\$1")"
		case "\$1" in
		  nextest)
		    env | grep '^SIPNAB_' | sort > "$_h/pool-env"
		    mkdir -p "\$_w/target/nextest/suite"
		    _junit="$_h/canned-junit.xml"
		    case " \$* " in *" -E "*) [ -f "$_h/canned-replay-junit.xml" ] && _junit="$_h/canned-replay-junit.xml" ;; esac
		    cp "\$_junit" "\$_w/target/nextest/suite/junit.xml"
		    exit 0 ;;
		  test)
		    if [ -f "$_h/fail-test" ]; then
		      echo 'test stub_fails ... FAILED'
		      echo 'test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
		      exit 101
		    fi
		    echo 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'; exit 0 ;;
		esac
		[ -f "$_h/fail-\$1" ] && exit 1
		for _a in "\$@"; do
		  case "\$_a" in
		    metadata) echo "{\"target_directory\": \"\$_w/target\", \"workspace_root\": \"\$_w\"}"; exit 0 ;;
		  esac
		done
		exit 0
	EOF
	# The pinned nextest, and the config that pins it, which
	# parallel-tests.py reads from the tree it runs in.
	mkdir -p "$_d/.config"
	cp "$REPO_ROOT/.config/nextest.toml" "$_d/.config/nextest.toml"
	sed -n 's/^nextest-version = { required = "\(.*\)" }$/\1/p' "$REPO_ROOT/.config/nextest.toml" > "$_h/nextest-version"
	chmod +x "$_h/bin/cargo"
	# The rustfmt stub, for the same reason: the format gate
	# (scripts/check-rustfmt.sh) calls rustfmt directly, not through cargo,
	# and these scenarios are about the gates after it. The format gate's own
	# verdicts are tested by tests/format_coverage_test.rs and
	# scripts/test-pre-push.sh, which run the real rustfmt.
	printf '#!/bin/sh\necho "rustfmt $*" >> "%s/cargo-invocations"\nexit 0\n' "$_h" > "$_h/bin/rustfmt"
	chmod +x "$_h/bin/rustfmt"
	: > "$_h/cargo-invocations"
	_total=0
	_bin=0
	{
		echo '<?xml version="1.0" encoding="UTF-8"?>'
		echo '<testsuites name="nextest-run">'
		for _n in "$@"; do
			_bin=$((_bin + 1))
			echo "<testsuite name=\"sipnab::bin$_bin\" tests=\"$_n\">"
			_i=0
			while [ "$_i" -lt "$_n" ]; do
				_i=$((_i + 1))
				echo "<testcase name=\"t$_i\" classname=\"sipnab::bin$_bin\" time=\"0.001\"/>"
			done
			echo '</testsuite>'
			_total=$((_total + _n))
		done
		echo '</testsuites>'
	} > "$_h/canned-junit.xml"
	# The homepage the hook will check. It carries no number: the count is
	# generated at deploy time from the file this loads.
	cat > "$_d/website/templates/index.html" <<-'EOF'
		{% set suite = load_data(path="data/test-count.toml", required=false) %}
		<span class="arch-stat" data-count="{{ suite.automated_tests }}" data-suffix="">{{ suite.automated_tests }}</span>
		<p>Automated tests</p>
		<tr><td>{{ suite.automated_tests }} automated tests.</td></tr>
	EOF

	( cd "$_d" && git init -q . ) >&2
	require_own_git_dir "$_d"
	( cd "$_d" && git config user.email t@t && git config user.name t \
		&& git add -A && git commit -qm base )
	echo "$_d"
}
