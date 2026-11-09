#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# BDD test for .githooks/pre-push.
#
# SCENARIO: format gate
#   Given a throwaway crate containing UNFORMATTED Rust,
#     when the pre-push hook runs, then it BLOCKS the push (exit != 0).
#   Given the same crate after `scripts/check-rustfmt.sh --fix` (FORMATTED Rust),
#     when the pre-push hook runs, then it ALLOWS the push (exit == 0).
#   Given UNFORMATTED Rust but SKIP_FMT_HOOK=1,
#     when the pre-push hook runs, then it ALLOWS the push (bypass).
#
# SCENARIO: the other three hard gates
#   Given FORMATTED Rust that violates clippy's -D warnings, or carries a
#     broken intra-doc link, or a fuzz/ workspace that fails cargo check,
#     when the pre-push hook runs, then it BLOCKS the push.
#
#   These exist because only the rustfmt gate used to be reachable: the
#   throwaway crate was clippy-clean, doc-clean, and had no fuzz/, so deleting
#   the other three gates from the hook left 4/4 green and printed "GREEN: all
#   pre-push BDD scenarios passed." CONTRIBUTING.md points contributors here,
#   directly beneath the table listing all four gates.
#
# This test never performs a real `git push`. It builds an isolated temp crate,
# invokes the hook from inside it, asserts exit codes, and cleans up on exit.

set -eu

# Resolve repo root and the hook under test (absolute paths).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)
HOOK="$REPO_ROOT/.githooks/pre-push"

# Every git command below must act on a throwaway repository, never on the one
# whose hook (or whose GIT_DIR-carrying shell) runs this script: see
# scripts/lib-git-sandbox.sh. Cleared once, here, for the whole script and the
# hook it runs. Inherited, the fixture's own `git commit` fired the calling
# repository's pre-commit hook, which ran this script again: 285 levels deep
# on 2026-10-28 before it was stopped.
. "$REPO_ROOT/scripts/lib-git-sandbox.sh"
clear_git_env

# The hook's message gate (scripts/commit-message-check.sh) builds
# private_identity_test to read each pushed message. Its rule uses nothing
# from the crate, and CI's "Git hook scenarios" runner has no system
# libraries to link the `full` feature set, so a scenario's push failed
# closed at that gate instead of reaching the gate it was about. The
# scenarios build it with no features, as .github/workflows/pr-text.yml does.
export SIPNAB_MESSAGE_FEATURES=none

PASS=0
FAIL=0

ok() {
	PASS=$((PASS + 1))
	printf 'PASS: %s\n' "$1"
}

bad() {
	FAIL=$((FAIL + 1))
	printf 'FAIL: %s\n' "$1"
}

# A scenario this host cannot decide. Counted and printed, never folded into
# PASS: the whole argument of this file is that a verdict nobody observed must
# not read as a verdict, and that applies to the harness before it applies to
# the hook.
SKIP=0
skip() {
	SKIP=$((SKIP + 1))
	printf 'SKIP: %s\n' "$1"
}

# Did the non-Linux cfg gate reach a VERDICT on the last `run_hook`?
#
# scripts/check-non-linux.sh exits 2 with "NOT CHECKED -- host is Darwin, not
# Linux" off Linux, and the hook prints that line verbatim and carries on. The
# three scenarios below then asserted the hook's EXIT CODE and got the answer
# they wanted anyway -- from a different gate:
#
#   fixture 1 (ungated `#[cfg(test)]` reaching a Linux-only const) -- on macOS
#     `super::FLAG` genuinely does not exist, so the CLIPPY gate 130 lines
#     earlier fails with E0425 and the push is blocked. Correct outcome, wrong
#     gate, and the scenario printed "non-Linux cfg gate blocks ...".
#   fixture 2 (test module gated too) -- on macOS the module drops out and
#     everything compiles, so the hook exits 0 and the scenario printed a pass
#     for a gate that never ran.
#   fixture 3 (parameter whose only reader is Linux-gated) -- on macOS the
#     parameter is genuinely unused, so `-D warnings` blocks at CLIPPY.
#
# All three therefore reported PASS on macOS: measured 2026-08-19, the whole
# file printed "31 passed, 0 failed" and "GREEN: all pre-push BDD scenarios
# passed" while the gate those three name had contributed nothing. The
# harness's own comment two dozen lines below already names this exact hazard
# for the clippy gate -- "this scenario would report a pass it never earned" --
# and then it happened, on the axis the file is named after.
#
# So: observe the gate's line in the hook's output and refuse to grade the
# scenario unless the gate actually reached a verdict.
#
# THREE outcomes, not two, and the third is the one that made the first draft of
# this helper wrong. The hook prints `  non-Linux cfg (...) ... ` before running
# the check, so:
#
#   line absent           the hook exited at an EARLIER gate and never reached
#                         this one. That is what fixtures 1 and 3 do on macOS:
#                         clippy fails first, the hook exits, and out.log has no
#                         non-Linux line at all. Grading on exit code here is
#                         precisely the false pass being removed.
#   line says NOT CHECKED reached, declined (wrong host, no cargo, no cfgs).
#   anything else         reached and decided; grade it.
nonlinux_gate_verdict() {
	if ! grep -q 'non-Linux cfg' "$TMP/out.log" 2>/dev/null; then
		printf 'not-reached'
	elif grep -q 'non-Linux cfg.*NOT CHECKED' "$TMP/out.log" 2>/dev/null; then
		printf 'not-checked'
	else
		printf 'decided'
	fi
}

# Throwaway workspace; removed on any exit.
TMP=$(mktemp -d 2>/dev/null || mktemp -d -t prepush)
cleanup() {
	rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

# -- Preconditions ------------------------------------------------------------
if [ ! -x "$HOOK" ]; then
	bad "hook missing or not executable: $HOOK"
	printf '\nRED: cannot test a hook that does not exist / is not executable.\n'
	exit 1
fi
if ! command -v cargo >/dev/null 2>&1; then
	printf 'SKIP: cargo not on PATH; cannot exercise rustfmt gate.\n'
	exit 0
fi
# The format gate runs the dated nightly rustfmt named in .rustfmt-toolchain.
# Without it the gate exits 2 in every scenario, and each later gate would
# read as "blocked, but not by that gate". Stop once, with the fix.
PIN=$(tr -d '[:space:]' < "$REPO_ROOT/.rustfmt-toolchain")
if ! rustfmt "+$PIN" --version >/dev/null 2>&1; then
	bad "the format gate's rustfmt ($PIN) is not installed, so no scenario can run"
	printf '    rustup toolchain install %s --profile minimal --component rustfmt\n' "$PIN"
	exit 1
fi

# Format the fixture with the gate's own fixer. Exit 1 (a file rustfmt could
# not rewrite) is the fixture's business; exit 2 means the fixer could not
# run at all, and every verdict after it would be about the wrong gate.
fmt_fixture() {
	_rc=0
	( cd "$CRATE" && "$REPO_ROOT/scripts/check-rustfmt.sh" --fix ) >"$TMP/fmt.log" 2>&1 || _rc=$?
	if [ "$_rc" -eq 2 ]; then
		bad "scripts/check-rustfmt.sh --fix could not run on the fixture"
		sed 's/^/    /' "$TMP/fmt.log"
		exit 1
	fi
}

# -- Build an isolated minimal crate -----------------------------------------
CRATE="$TMP/throwaway"
mkdir -p "$CRATE/src"
# A git work tree from the start: the format gate, scripts/check-rustfmt.sh,
# takes its file list from git and refuses to run outside a work tree.
( cd "$CRATE" && git init -q . )
require_own_git_dir "$CRATE"

cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "throwaway"
path = "src/main.rs"
EOF

# The two packages the workspace excludes. Since 0561a524 (2026-09-10) the
# hook formats `fuzz/` and `bpf/` by name, so a fixture without them failed
# every scenario at `cargo fmt --manifest-path fuzz/Cargo.toml` -- and every
# "gate blocks X" scenario then passed without its gate ever running, because
# a non-zero exit was all it checked. Minimal, formatted, and compiling, so
# each scenario reaches the gate it is about; the fuzz scenario below swaps in
# a broken one and restores this.
write_companions() {
	for pkg in fuzz bpf; do
		rm -rf "${CRATE:?}/$pkg"
		mkdir -p "$CRATE/$pkg/src"
		printf '[package]\nname = "throwaway-%s"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n' \
			"$pkg" >"$CRATE/$pkg/Cargo.toml"
		printf 'fn main() {}\n' >"$CRATE/$pkg/src/main.rs"
	done
}
write_companions

# Deliberately UNFORMATTED: bad indentation + spacing rustfmt will rewrite.
write_unformatted() {
	cat >"$CRATE/src/main.rs" <<'EOF'
fn   main( ) {
let x=1   ;
        let    y =2;
println!("{}",x+y) ;
}
EOF
}

# Corpus-gate environment, as globals rather than two more positional
# parameters: every call site below already passes SKIP_FMT_HOOK and a stdin
# line, and only the corpus scenarios care about these.
HOOK_CORPUS_DIR=
HOOK_CORPUS_SKIP=

# Run the hook with cwd = throwaway crate. We deliberately do NOT pass through
# the caller's SKIP_FMT_HOOK; each case sets it explicitly.
# The rest of sipnab's shape the hook reaches for by name: the release-delivery
# gate (`cargo test --features full --test release_delivery_test`, 76d27bf8,
# strict by design, it must not skip at push time) and the PTY suite
# (`cargo test --features tui --test tui_e2e_test -- --ignored`). The fixture
# carries those features and passing targets of those names rather than the
# hook growing a way to skip them. Ensured before every run, because several scenarios
# rewrite Cargo.toml from scratch.
ensure_repo_shape() {
	for feature in full tui; do
		grep -q "^$feature = " "$CRATE/Cargo.toml" && continue
		if grep -q '^\[features\]' "$CRATE/Cargo.toml"; then
			awk -v f="$feature" '{ print } /^\[features\]/ { print f " = []" }' \
				"$CRATE/Cargo.toml" >"$TMP/Cargo.toml.new"
			mv "$TMP/Cargo.toml.new" "$CRATE/Cargo.toml"
		else
			printf '\n[features]\n%s = []\n' "$feature" >>"$CRATE/Cargo.toml"
		fi
	done
	# The tag gate's second check (code scanning) runs this script; its own
	# verdicts are tested in tests/code_scanning_gate_test.rs.
	mkdir -p "$CRATE/scripts"
	[ -f "$CRATE/scripts/code-scanning-clean.py" ] \
		|| printf 'raise SystemExit(0)\n' >"$CRATE/scripts/code-scanning-clean.py"
	# The tag gate's first check is the signature rule itself, copied rather
	# than stubbed so these scenarios exercise the script the hook ships with.
	cp "$REPO_ROOT/scripts/tag-signature-check.sh" "$CRATE/scripts/"
	# The first thing the hook runs: its gitignored prerequisites. The crate
	# has neither the g729 crate nor a .vale.ini, so it needs none of them
	# unless a scenario below adds one.
	cp "$REPO_ROOT/scripts/check-hook-prerequisites.py" \
		"$REPO_ROOT/scripts/fetch-g729-vectors.py" "$CRATE/scripts/" 2>/dev/null || true
	mkdir -p "$CRATE/tests"
	for target in release_delivery_test tui_e2e_test; do
		[ -f "$CRATE/tests/$target.rs" ] && continue
		printf '#[test]\nfn stands_in_for_the_gate_that_runs_this_target() {}\n' \
			>"$CRATE/tests/$target.rs"
	done
}

run_hook() {
	ensure_repo_shape
	# $1 = value for SKIP_FMT_HOOK ("" means unset)
	# $2 = optional pre-push stdin line ("<local_ref> <local_sha> <remote_ref>
	#      <remote_sha>"); empty means a push with nothing on stdin.
	#
	# stdin is redirected ALWAYS. The hook reads it to learn which refs are
	# being pushed, and real git always supplies it -- a harness that leaves it
	# attached to the terminal would hang here instead of testing anything.
	if [ -n "${2:-}" ]; then
		printf '%s\n' "$2" >"$TMP/refs.in"
	else
		: >"$TMP/refs.in"
	fi
	# SIPNAB_CORPUS and SKIP_CORPUS_HOOK are unset unless a scenario asks for
	# them. Inheriting the caller's SIPNAB_CORPUS would make every scenario
	# above behave differently on a machine that holds the corpus, which is
	# every machine where this script gets run in anger.
	#
	# SIPNAB_HOOK_ANY_TREE=1 because this runs the repository's hook against a
	# throwaway crate: exactly the "hook from another checkout" shape the
	# hook's first check refuses. The scenario after the rest proves it does.
	( cd "$CRATE" && env -u SKIP_FMT_HOOK -u SIPNAB_CORPUS -u SKIP_CORPUS_HOOK \
		SIPNAB_HOOK_ANY_TREE=1 \
		${1:+SKIP_FMT_HOOK="$1"} \
		${HOOK_CORPUS_DIR:+SIPNAB_CORPUS="$HOOK_CORPUS_DIR"} \
		${HOOK_CORPUS_SKIP:+SKIP_CORPUS_HOOK="$HOOK_CORPUS_SKIP"} \
		"$HOOK" <"$TMP/refs.in" ) >"$TMP/out.log" 2>&1
}

# A blocking scenario passes only if the hook blocked AND named the gate the
# scenario is about. A bare non-zero exit is not enough: from 2026-09-10 every
# scenario died at the fmt step before its own gate ran, and each "blocks X"
# still passed.
blocked_for() { # $1 = text the gate prints when it blocks; call after run_hook
	grep -qF "$1" "$TMP/out.log"
}

# -- GIVEN unformatted Rust, THEN hook blocks --------------------------------
write_unformatted
if run_hook ""; then
	bad "unformatted Rust was ALLOWED (expected block)"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "unformatted Rust is BLOCKED (non-zero exit)"
fi

# Confirm the message is actionable (names the fixer).
if grep -q "scripts/check-rustfmt.sh --fix" "$TMP/out.log"; then
	ok "failure message points to 'scripts/check-rustfmt.sh --fix'"
else
	bad "failure message does not mention 'scripts/check-rustfmt.sh --fix'"
fi

# -- GIVEN unformatted Rust + SKIP_FMT_HOOK=1, THEN bypass -------------------
write_unformatted
if run_hook "1"; then
	ok "SKIP_FMT_HOOK=1 bypasses the gate (allowed)"
else
	bad "SKIP_FMT_HOOK=1 did not bypass (expected allow)"
	sed 's/^/    /' "$TMP/out.log"
fi

# -- GIVEN formatted Rust, THEN hook allows ----------------------------------
write_unformatted
fmt_fixture
if run_hook ""; then
	ok "formatted Rust is ALLOWED (zero exit)"
else
	bad "formatted Rust was BLOCKED (expected allow)"
	sed 's/^/    /' "$TMP/out.log"
fi

# -- The other three hard gates ----------------------------------------------
# Only the rustfmt gate was ever reachable here. The throwaway crate is
# clippy-clean, doc-clean, and has no fuzz/ directory, so deleting the clippy,
# rustdoc and fuzz gates from the hook outright left 4/4 green and printed
# "GREEN: all pre-push BDD scenarios passed." CONTRIBUTING.md tells contributors
# to verify the hooks with this script, directly beneath the table listing all
# four gates.
#
# Each case below writes FORMATTED source that violates exactly one gate, so a
# block proves that gate ran rather than the fmt gate firing again.

# clippy: `-D warnings` promotes the default-warn `unused_variables`.
cat >"$CRATE/src/main.rs" <<'EOF'
fn main() {
    let unused_binding = 1;
    println!("hi");
}
EOF
fmt_fixture
if run_hook ""; then
	bad "clippy gate did NOT block a -D warnings violation (the gate is unreachable from this fixture)"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: clippy reported warnings."; then
	bad "clippy gate blocks a -D warnings violation: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "clippy gate blocks a -D warnings violation"
fi

# rustdoc: a broken intra-doc link, which RUSTDOCFLAGS=-D warnings rejects and
# neither clippy nor the test suite ever builds.
cat >"$CRATE/src/main.rs" <<'EOF'
/// See [`does::not::Exist`] for details.
pub fn documented() {}

fn main() {
    documented();
}
EOF
fmt_fixture
if run_hook ""; then
	bad "rustdoc gate did NOT block a broken intra-doc link"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: rustdoc reported warnings"; then
	bad "rustdoc gate blocks a broken intra-doc link: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "rustdoc gate blocks a broken intra-doc link"
fi

# fuzz: the hook runs `cd fuzz && cargo clippy --all-targets -- -D warnings`.
# With no fuzz/ directory that step cannot fail, which is why it was never
# exercised. Give the fixture one that does not compile.
mkdir -p "$CRATE/fuzz/src"
cat >"$CRATE/fuzz/Cargo.toml" <<'EOF'
[package]
name = "throwaway-fuzz"
version = "0.0.0"
edition = "2021"

[dependencies]
EOF
cat >"$CRATE/fuzz/src/main.rs" <<'EOF'
fn main() {
    this_function_does_not_exist();
}
EOF
cat >"$CRATE/src/main.rs" <<'EOF'
fn main() {
    println!("hi");
}
EOF
fmt_fixture
if run_hook ""; then
	bad "fuzz gate did NOT block a fuzz/ workspace that fails cargo check"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: fuzz targets do not compile or are not lint-clean."; then
	bad "fuzz gate blocks a fuzz/ workspace that fails cargo check: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "fuzz gate blocks a fuzz/ workspace that fails cargo check"
fi
write_companions

# reduced feature combinations: the gate added after a new test reflected over a
# `native`-gated module and broke `Features (tls)` on a release commit. The
# fixture reproduces that exact shape -- an item that compiles under the default
# features and not without them -- because a gate whose test cannot fail the way
# production failed is a gate nobody has checked.
cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[features]
default = ["native"]
native = []
tls = []
api = []
wasm = []
EOF
mkdir -p "$CRATE/tests"
cat >"$CRATE/src/lib.rs" <<'EOF'
#[cfg(feature = "native")]
pub mod gated {
    pub fn thing() {}
}
EOF
cat >"$CRATE/src/main.rs" <<'EOF'
fn main() {}
EOF
cat >"$CRATE/tests/reduced.rs" <<'EOF'
// Calls a `native`-gated path unconditionally: fine with default features,
// broken under --no-default-features --features tls.
#[test]
fn uses_a_gated_module() {
    throwaway::gated::thing();
}
EOF
fmt_fixture
if run_hook ""; then
	bad "reduced-combo gate did NOT block a test that needs a feature-gated module"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "reduced-combo gate blocks a test that needs a feature-gated module"
fi
rm -f "$CRATE/tests/reduced.rs"

# ...and passes once the item is gated, which is the fix the message recommends.
cat >"$CRATE/tests/reduced.rs" <<'EOF'
#[cfg(feature = "native")]
#[test]
fn uses_a_gated_module() {
    throwaway::gated::thing();
}
EOF
fmt_fixture
if run_hook ""; then
	ok "reduced-combo gate passes once the item itself is gated"
else
	bad "reduced-combo gate blocked a correctly gated test"
	sed 's/^/    /' "$TMP/out.log"
fi
rm -f "$CRATE/tests/reduced.rs"

# non-Linux cfg gate: the same shape as the reduced-combo gate, one axis over.
#
# The fixture is the FIRST of the two real breaks in miniature (34defd5): a
# cross-platform function whose Linux arm owns a `#[cfg(target_os = "linux")]`
# constant, and an UNGATED `#[cfg(test)]` module that reaches for it. That
# compiles here and fails on macOS with E0425, which is exactly why nothing
# local caught it.
#
# `pub` on the constant is not decoration. Private and read only from tests, it
# is dead code in the lib target, so `cargo clippy --all-targets -- -D warnings`
# would block at the CLIPPY gate and this scenario would report a pass it never
# earned -- the gate under test never reached.
write_platform_lib() { # $1 = attribute on the test module
	cat >"$CRATE/src/lib.rs" <<EOF
#[cfg(feature = "native")]
pub mod gated {
    pub fn thing() {}
}

/// Linux-only, like PACKET_FANOUT's mode flags.
#[cfg(target_os = "linux")]
pub const FLAG: u32 = 0x1000;

/// Real on Linux, a stub everywhere else -- the platform split, written once.
#[cfg(target_os = "linux")]
pub fn arg(group: u16) -> u32 {
    (FLAG << 16) | u32::from(group)
}

/// Non-Linux arm of the same function.
#[cfg(not(target_os = "linux"))]
pub fn arg(_group: u16) -> u32 {
    0
}

$1
mod platform_tests {
    #[test]
    fn flag_is_in_the_high_half() {
        assert_eq!(super::arg(1) >> 16, super::FLAG);
    }
}
EOF
	fmt_fixture
}

# The blocking scenarios assert the gate's OWN message, not merely a non-zero
# exit: "the hook blocked" is true here for three different gates, and only one
# of them is under test.
NL_BLOCKED='Push blocked: the code does not build or document for a non-Linux target'

write_platform_lib '#[cfg(test)]'
NL_RC=0
run_hook "" || NL_RC=$?
NL_V=$(nonlinux_gate_verdict)
if [ "$NL_V" != decided ]; then
	skip "non-Linux cfg gate blocks Linux-only tests for a cross-platform module -- gate $NL_V on $(uname -s); the block seen here came from the clippy gate instead"
elif [ "$NL_RC" -ne 0 ] && grep -qF "$NL_BLOCKED" "$TMP/out.log"; then
	ok "non-Linux cfg gate blocks Linux-only tests for a cross-platform module"
else
	bad "non-Linux cfg gate did NOT block Linux-only tests for a cross-platform module"
	sed 's/^/    /' "$TMP/out.log"
fi

# ...and passes once the test module carries the platform decision too, which is
# the fix 34defd5 actually shipped.
write_platform_lib '#[cfg(all(test, target_os = "linux"))]'
NL_RC=0
run_hook "" || NL_RC=$?
NL_V=$(nonlinux_gate_verdict)
if [ "$NL_V" != decided ]; then
	skip "non-Linux cfg gate passes once the test module is gated as well -- gate $NL_V on $(uname -s), so a green hook proves nothing about it"
elif [ "$NL_RC" -eq 0 ]; then
	ok "non-Linux cfg gate passes once the test module is gated as well"
else
	bad "non-Linux cfg gate blocked a correctly gated test module"
	sed 's/^/    /' "$TMP/out.log"
fi

# The SECOND real break (82eb8ff), which fails by a different mechanism: name
# resolution succeeds everywhere, and it is `-D warnings` that rejects a
# parameter whose only reader is behind a cfg. A gate that caught the first and
# not this one would have let the day's second red CI through.
cat >"$CRATE/src/main.rs" <<'EOF'
fn join(group: Option<u16>) -> u32 {
    #[cfg(target_os = "linux")]
    if let Some(g) = group {
        return throwaway::arg(g);
    }
    0
}

fn main() {
    let _ = join(None);
}
EOF
fmt_fixture
NL_RC=0
run_hook "" || NL_RC=$?
NL_V=$(nonlinux_gate_verdict)
if [ "$NL_V" != decided ]; then
	skip "non-Linux cfg gate blocks a parameter whose only use is Linux-gated -- gate $NL_V on $(uname -s); the block seen here came from the clippy gate instead"
elif [ "$NL_RC" -ne 0 ] && grep -qF "$NL_BLOCKED" "$TMP/out.log"; then
	ok "non-Linux cfg gate blocks a parameter whose only use is Linux-gated"
else
	bad "non-Linux cfg gate did NOT block a parameter whose only use is Linux-gated"
	sed 's/^/    /' "$TMP/out.log"
fi
cat >"$CRATE/src/main.rs" <<'EOF'
fn main() {}
EOF
cat >"$CRATE/src/lib.rs" <<'EOF'
#[cfg(feature = "native")]
pub mod gated {
    pub fn thing() {}
}
EOF
fmt_fixture

# non-Linux cfg gate and a checkout nested inside the tree.
#
# A linked worktree under .claude/worktrees/ is a separate checkout, with its
# own sources and its own target/. The gate once copied every one of them into
# its shim tree and counted their `target_os` gates as this tree's: on
# 2026-10-18 the copy held 474 GB of other checkouts, and a file that vanished
# from a worktree's target/ during a concurrent build made the copy fail and
# the self-check refuse the v0.5.226 tag ("1327 sentinel, expected 1859"; the
# tree itself had 266). That failure was a race; the gated source file below
# makes one certain. Its path is just short of PATH_MAX (4096) here and longer
# than it under target/nonlinux-shim/tree/, so any step that handles the copy
# by its full path fails on it.
NESTED="$CRATE/.claude/worktrees/other"
mkdir -p "$NESTED/src" "$CRATE/.cargo"
printf 'gitdir: /nonexistent/.git/worktrees/other\n' >"$NESTED/.git"
LONG="$NESTED/src"
SEG=$(printf '%0200d' 0)
while [ $((${#LONG} + 201 + 6)) -le 4088 ]; do LONG="$LONG/$SEG"; done
LONG="$LONG/$(printf "%0$((4088 - ${#LONG} - 7))d" 0)"
mkdir -p "$LONG"
printf '#[cfg(target_os = "linux")]\npub fn other() {}\n' >"$LONG/x.rs"
printf '[build]\nincremental = true\n' >"$CRATE/.cargo/config.toml"
write_platform_lib '#[cfg(all(test, target_os = "linux"))]'
SHIM_TREE="$CRATE/target/nonlinux-shim/tree"
NL_RC=0
( cd "$CRATE" && sh "$REPO_ROOT/scripts/check-non-linux.sh" ) >"$TMP/out.log" 2>&1 || NL_RC=$?
if [ "$NL_RC" -eq 2 ]; then
	skip "non-Linux cfg gate is not broken by a nested checkout it cannot copy -- $(head -1 "$TMP/out.log")"
elif [ "$NL_RC" -eq 0 ]; then
	ok "non-Linux cfg gate is not broken by a nested checkout it cannot copy"
else
	bad "non-Linux cfg gate failed on a correct tree because of a nested checkout"
	sed 's/^/    /' "$TMP/out.log"
fi
if [ "$NL_RC" -eq 2 ]; then
	skip "non-Linux cfg gate copies none of a nested checkout -- the gate did not run"
elif [ ! -e "$SHIM_TREE/.claude/worktrees/other" ]; then
	ok "non-Linux cfg gate copies none of a nested checkout"
else
	bad "non-Linux cfg gate copied a nested checkout into its shim tree"
fi
if [ "$NL_RC" -eq 2 ]; then
	skip "non-Linux cfg gate still copies a directory of the tree's own -- the gate did not run"
elif [ -f "$SHIM_TREE/.cargo/config.toml" ] && [ -f "$SHIM_TREE/src/lib.rs" ]; then
	ok "non-Linux cfg gate still copies a directory of the tree's own"
else
	bad "non-Linux cfg gate left the tree's own .cargo/ or src/ out of its shim tree"
fi
rm -rf "$CRATE/.claude" "$CRATE/.cargo" "$CRATE/target/nonlinux-shim"
cat >"$CRATE/src/lib.rs" <<'EOF'
#[cfg(feature = "native")]
pub mod gated {
    pub fn thing() {}
}
EOF
fmt_fixture

# v* tag gate: a tag must point at a commit whose CI is green.
#
# `gh` is stubbed on PATH, the way ops/tsan/test-verdict.sh stubs nm. The gate's
# contract is what it does with gh's OUTPUT, and a stub gives every case
# deterministically and offline -- including the red one, which cannot be
# produced on demand against a real repository.
STUB_BIN="$TMP/stubbin"
mkdir -p "$STUB_BIN"
make_gh() { # $1 = json array the stub prints for `gh run list`
	cat >"$STUB_BIN/gh" <<EOF
#!/bin/sh
case "\$1" in
run) printf '%s' '$1' ;;
*)   exit 1 ;;
esac
EOF
	chmod +x "$STUB_BIN/gh"
}

# The fixture needs to be a real git repo with a real commit: the hook resolves
# the pushed sha with `git rev-list -n1`, which is how an ANNOTATED tag's object
# becomes the commit it marks. A synthetic sha would make that resolution fail
# and the gate skip the ref -- the scenarios below would then pass by not
# running, which is the failure mode this suite exists to avoid.
#
# The fixture commit is signed with the throwaway trusted key: the hook's first
# gate refuses a push carrying an unsigned commit, and every scenario below
# pushes this one. Signing it explicitly also keeps a machine's global
# commit.gpgsign from signing it with that machine's own key.
ssh-keygen -q -t ed25519 -N "" -C trusted -f "$TMP/trusted" </dev/null
ssh-keygen -q -t ed25519 -N "" -C untrusted -f "$TMP/untrusted" </dev/null
( cd "$CRATE" && git init -q . ) >/dev/null 2>&1
require_own_git_dir "$CRATE"
( cd "$CRATE" \
	&& git config user.email t@example.com \
	&& git config user.name test \
	&& git add -A \
	&& git -c gpg.format=ssh -c "user.signingkey=$TMP/trusted.pub" commit -S -qm fixture ) >/dev/null 2>&1
TAGGED=$( cd "$CRATE" && git rev-parse HEAD )

# A v* tag must also be signed by a key in .github/allowed_signers, and that
# gate runs first. The fixture trusts one throwaway key, so the CI scenarios
# push a tag that passes it, and the signature scenarios below push the tags it
# must refuse. tag.gpgSign is forced off for the unsigned ones: a machine whose
# global config signs every tag would otherwise sign them with its own key.
mkdir -p "$CRATE/.github"
printf 't@example.com namespaces="git" %s\n' "$(cat "$TMP/trusted.pub")" >"$CRATE/.github/allowed_signers"
sign_tag() { # $1 = tag name, $2 = key
	( cd "$CRATE" && git -c gpg.format=ssh -c "user.signingkey=$2.pub" tag -s -m release "$1" ) >/dev/null 2>&1
}
sign_tag v9.9.9 "$TMP/trusted"
sign_tag v9.9.6 "$TMP/untrusted"
( cd "$CRATE" \
	&& git -c tag.gpgSign=false tag -a -m release v9.9.7 \
	&& git -c tag.gpgSign=false tag v9.9.8 ) >/dev/null 2>&1
tag_ref() { # $1 = tag name -> the pre-push stdin line pushing it
	printf 'refs/tags/%s %s refs/tags/%s 0000000000000000000000000000000000000000' \
		"$1" "$( cd "$CRATE" && git rev-parse "$1" )" "$1"
}
for t in v9.9.9 v9.9.6 v9.9.7; do
	if [ "$( cd "$CRATE" && git cat-file -t "$t" 2>/dev/null )" != tag ]; then
		bad "fixture: $t is not an annotated tag, so the tag scenarios cannot run"
	fi
done
REFLINE=$(tag_ref v9.9.9)

# SIGNATURE: each unsigned or untrusted shape is blocked by the signature gate,
# named, before CI is consulted. gh reports green so only the signature can
# block.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"completed\",\"conclusion\":\"success\",\"name\":\"CI\"}]"
for case in "v9.9.8|is a lightweight tag|a lightweight tag" \
	"v9.9.7|is not signed|an unsigned annotated tag" \
	"v9.9.6|is not a trusted signer|a tag signed by an untrusted key"; do
	t=${case%%|*}; rest=${case#*|}; why=${rest%%|*}; what=${rest#*|}
	if PATH="$STUB_BIN:$PATH" run_hook "" "$(tag_ref "$t")"; then
		bad "signature gate ALLOWED $what"
		sed 's/^/    /' "$TMP/out.log"
	elif ! blocked_for "Push blocked: tag" || ! blocked_for "$why"; then
		bad "signature gate blocks $what: blocked, but not by that gate"
		sed 's/^/    /' "$TMP/out.log"
	elif blocked_for "checking CI"; then
		bad "signature gate blocks $what, but only after asking CI"
	else
		ok "signature gate blocks $what"
	fi
done

# A tag signed by the trusted key passes the signature gate and says whose key.
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE" && blocked_for 'Good "git" signature for t@example.com'; then
	ok "signature gate passes a tag signed by a trusted key and names the signer"
else
	bad "signature gate did not pass a tag signed by a trusted key"
	sed 's/^/    /' "$TMP/out.log"
fi

# GREEN: every run for the commit completed successfully -> allowed.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"completed\",\"conclusion\":\"success\",\"name\":\"CI\"}]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	ok "tag gate allows a tag on a commit whose CI is green"
else
	bad "tag gate BLOCKED a tag on a green commit"
	sed 's/^/    /' "$TMP/out.log"
fi

# RED: a failed run for the commit -> blocked. This is the 0.5.61 case.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"completed\",\"conclusion\":\"failure\",\"name\":\"CI\"}]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag on a commit whose CI failed"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a tag on a commit whose CI failed: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a tag on a commit whose CI failed"
fi

# STILL RUNNING: not green YET is not green. Tagging here races the result.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"in_progress\",\"conclusion\":null,\"name\":\"CI\"}]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag while CI was still running"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a tag while CI is still running: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a tag while CI is still running"
fi

# GATE-DUP1: the same workflow can run more than once on one commit (a
# duplicated push event on 2026-09-23 did it to every workflow on 3d91991a).
# The newer Quality run canceled the older one through its concurrency group
# and passed, and the gate still refused v0.5.187 over the canceled one. Only
# the LATEST run of each workflow speaks for the commit; `databaseId` and
# `createdAt` say which that is.
run_json() { # $1 = id, $2 = name, $3 = status, $4 = conclusion (json literal), $5 = event (default push)
	printf '{"databaseId":%s,"createdAt":"2026-09-23T10:%02d:00Z","headSha":"%s","status":"%s","conclusion":%s,"name":"%s","event":"%s"}' \
		"$1" "$1" "$TAGGED" "$3" "$4" "$2" "${5:-push}"
}

# SUPERSEDED: the older Quality run canceled, the newer one passed -> allowed.
make_gh "[$(run_json 1 Quality completed '"cancelled"'),$(run_json 2 Quality completed '"success"'),$(run_json 3 CI completed '"success"')]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	ok "tag gate allows a commit whose canceled run a newer passing run superseded"
else
	bad "tag gate BLOCKED a commit whose only canceled run was superseded by a passing one"
	sed 's/^/    /' "$TMP/out.log"
fi

# LATEST FAILED: an older pass does not excuse a newer failure -> blocked.
make_gh "[$(run_json 1 Quality completed '"success"'),$(run_json 2 Quality completed '"failure"')]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose latest Quality run failed"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a commit whose latest run of a workflow failed: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a commit whose latest run of a workflow failed"
fi

# LONE CANCELED: nothing newer stands in for it, so it verified nothing.
make_gh "[$(run_json 1 Quality completed '"cancelled"'),$(run_json 2 CI completed '"success"')]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose only Quality run was canceled"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a commit whose only run of a workflow was canceled: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a commit whose only run of a workflow was canceled"
fi

# RERUN IN FLIGHT: an older pass, a newer run still going -> not green yet.
make_gh "[$(run_json 1 Quality completed '"success"'),$(run_json 2 Quality in_progress null)]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose latest Quality run is still running"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a commit whose latest run of a workflow is still running: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a commit whose latest run of a workflow is still running"
fi

# TAG-GATE-COUNTS-SCHEDULED-RUNS: a scheduled run is not a verdict on the
# commit. A cron workflow (the ClusterFuzzLite batch run, the throughput
# bench) runs against whatever main points at when the clock fires, so its
# result says nothing about the change and its timing is the clock's. On
# 2026-11-05 a scheduled ClusterFuzzLite batch run on the release commit held
# the v0.5.234 tag for about an hour. Only runs a push or a pull request
# started speak for the commit; `event` is what gh says started a run.

# SCHEDULED IN FLIGHT: every push run green, a scheduled run still going -> allowed.
make_gh "[$(run_json 1 CI completed '"success"'),$(run_json 2 ClusterFuzzLite in_progress null schedule)]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	ok "tag gate does not wait on a scheduled run still in flight"
else
	bad "tag gate BLOCKED a green commit on a scheduled run still in flight"
	sed 's/^/    /' "$TMP/out.log"
fi

# SCHEDULED FAILED: a scheduled run's failure is not the commit's -> allowed.
make_gh "[$(run_json 1 CI completed '"success"'),$(run_json 2 Throughput completed '"failure"' schedule)]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	ok "tag gate does not judge the commit by a scheduled run's failure"
else
	bad "tag gate BLOCKED a green commit on a scheduled run's failure"
	sed 's/^/    /' "$TMP/out.log"
fi

# A NEWER SCHEDULED PASS does not excuse an older PUSH failure of the same
# workflow: the scheduled run is set aside BEFORE the newest-per-workflow rule
# picks, so the push run is still the one that speaks -> blocked.
make_gh "[$(run_json 1 ClusterFuzzLite completed '"failure"'),$(run_json 2 ClusterFuzzLite completed '"success"' schedule),$(run_json 3 CI completed '"success"')]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose push run failed because a newer scheduled run of that workflow passed"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a failed push run that a newer scheduled run passed over: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a failed push run whatever a newer scheduled run of that workflow says"
fi

# A PULL REQUEST run is still a gate: a pull_request run in flight blocks.
make_gh "[$(run_json 1 CI completed '"success"'),$(run_json 2 Quality in_progress null pull_request)]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose pull_request run is still running"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on"; then
	bad "tag gate blocks a pull_request run in flight: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate still blocks on a pull_request run in flight"
fi

# ONLY SCHEDULED RUNS: nothing a push started has verified the commit -> blocked.
make_gh "[$(run_json 1 ClusterFuzzLite completed '"success"' schedule)]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a commit whose only runs were scheduled"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: no CI runs found"; then
	bad "tag gate blocks a commit with only scheduled runs: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a commit whose only runs were scheduled"
fi

# NO RUNS: the commit was never pushed, so nothing has verified it.
make_gh "[]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag on a commit with no CI runs"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: no CI runs found"; then
	bad "tag gate blocks a tag on a commit with no CI runs at all: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a tag on a commit with no CI runs at all"
fi

# NON-TAG PUSH: an ordinary branch push must not consult CI at all.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"completed\",\"conclusion\":\"failure\",\"name\":\"CI\"}]"
if PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/main $TAGGED refs/heads/main 0000000000000000000000000000000000000000"; then
	ok "tag gate ignores an ordinary branch push"
else
	bad "tag gate blocked an ordinary branch push"
	sed 's/^/    /' "$TMP/out.log"
fi

# UNSIGNED COMMIT: a branch push carrying a commit with no signature is
# blocked by the commit-signature gate, which names the commit. commit-tree
# makes the commit without moving HEAD, so the scenarios after this one still
# push the signed fixture.
UNSIGNED=$( cd "$CRATE" && git commit-tree --no-gpg-sign -p HEAD -m unsigned "HEAD^{tree}" )
UNSIGNED_SHORT=$(printf '%s' "$UNSIGNED" | cut -c1-7)
if PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/topic $UNSIGNED refs/heads/topic 0000000000000000000000000000000000000000"; then
	bad "commit-signature gate ALLOWED an unsigned commit"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "$UNSIGNED_SHORT not signed"; then
	bad "commit-signature gate blocks an unsigned commit: blocked, but not by that gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "commit-signature gate blocks an unsigned commit and names it"
fi

# TAG DELETION: an all-zero local sha has no commit to verify.
make_gh "[]"
if PATH="$STUB_BIN:$PATH" run_hook "" "(delete) 0000000000000000000000000000000000000000 refs/tags/v9.9.9 $TAGGED"; then
	ok "tag gate ignores a tag deletion"
else
	bad "tag gate blocked a tag deletion"
	sed 's/^/    /' "$TMP/out.log"
fi

# -- The tag gate accepts the merged PR head on the same tree ----------------
# SCENARIO: TAG-GATE-WAITS-FOR-MERGE-CI
#   Given a tagged merge commit whose own CI is still running, and a merged
#     pull request head with the same tree whose required checks and workflow
#     runs all succeeded, then the push is ALLOWED and the output names the
#     pull request; the runs on the merge commit are not awaited.
#   Given a red run on the merge commit, a head on another tree, a red run on
#     the head, or an origin that is not GitHub, then the commit's own runs
#     decide and the push is BLOCKED while they run.
#   Code scanning: under a head proof "no analysis of the merge commit yet"
#     (exit 2) passes and says why; open alerts (exit 1) still block; without
#     a head proof exit 2 still blocks.
#
# A fuller gh stub than make_gh: it answers the API paths tag-push-proof.py
# asks, per commit. The head is a sha nothing resolves locally; the gate asks
# GitHub about it, never git.
PRHEAD=8888888888888888888888888888888888888888
make_gh_world() { # $1 own runs json, $2 head runs json, $3 head tree
	printf '%s' "$1" >"$TMP/gh-own.json"
	printf '%s' "$2" >"$TMP/gh-head.json"
	printf '%s\n' "$3" >"$TMP/gh-head-tree"
	cat >"$STUB_BIN/gh" <<EOF_GH_WORLD
#!/bin/sh
if [ "\$1" = run ]; then
	c=""; prev=""
	for a in "\$@"; do [ "\$prev" = --commit ] && c=\$a; prev=\$a; done
	if [ "\$c" = "$TAGGED" ]; then cat "$TMP/gh-own.json"; else cat "$TMP/gh-head.json"; fi
	exit 0
fi
[ "\$1" = api ] || exit 1
case "\$2" in
repos/*/rules/branches/main) printf 'CI success\nlicense/cla\n' ;;
repos/*/branches/main/protection) echo 'gh: Branch not protected (HTTP 404)' >&2; exit 1 ;;
repos/*/compare/*) echo behind ;;
repos/*/commits/$TAGGED/pulls) printf '701\t%s\n' "$PRHEAD" ;;
repos/*/git/commits/$TAGGED) echo 6644a32b9 ;;
repos/*/git/commits/$PRHEAD) cat "$TMP/gh-head-tree" ;;
repos/*/commits/$PRHEAD/check-runs*) printf 'CI success\t2026-11-08T13:50:00Z\tsuccess\n' ;;
repos/*/commits/$PRHEAD/status) printf 'license/cla\tsuccess\n' ;;
repos/*/commits/$TAGGED/check-runs*) printf 'CI success\t~\tin_progress\n' ;;
repos/*/commits/$TAGGED/status) : ;;
*) exit 1 ;;
esac
EOF_GH_WORLD
	chmod +x "$STUB_BIN/gh"
}
head_run() { # $1 = id, $2 = name, $3 = status, $4 = conclusion (json literal)
	printf '{"databaseId":%s,"headSha":"%s","status":"%s","conclusion":%s,"name":"%s","event":"pull_request"}' \
		"$1" "$PRHEAD" "$3" "$4" "$2"
}
code_scanning_says() { # $1 = the exit status the crate's code-scanning-clean.py gives
	printf 'import sys\nprint("code scanning: stub")\nsys.exit(%s)\n' "$1" >"$CRATE/scripts/code-scanning-clean.py"
}
OWN_PENDING="[$(run_json 1 CI in_progress null),$(run_json 2 Quality queued null)]"
HEAD_GREEN="[$(head_run 11 CI completed '"success"'),$(head_run 12 Quality completed '"success"')]"
( cd "$CRATE" && git remote add origin https://github.com/example/sipnab.git )

# PROVEN BY THE HEAD: merge commit CI still running -> allowed, names PR #701.
make_gh_world "$OWN_PENDING" "$HEAD_GREEN" 6644a32b9
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	if blocked_for "merge of PR #701, whose head 888888888" && blocked_for "not awaited"; then
		ok "tag gate accepts the merged PR head on the same tree while the merge commit's CI runs"
	else
		bad "tag gate allowed the tag but did not name the PR head proof"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "tag gate BLOCKED a merge commit its same-tree PR head had proved"
	sed 's/^/    /' "$TMP/out.log"
fi

# NO ANALYSIS OF THE MERGE COMMIT YET, under a head proof -> allowed, says why.
code_scanning_says 2
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE" && blocked_for "OK (proven on the PR head)"; then
	ok "code scanning's no-analysis-yet passes under a head proof and says the head judged the tree"
else
	bad "code scanning's no-analysis-yet did not pass under a head proof"
	sed 's/^/    /' "$TMP/out.log"
fi

# OPEN ALERTS, under a head proof -> still blocked.
code_scanning_says 1
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED open code-scanning alerts because a PR head was green"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Fix the code, wait for CodeQL"; then
	bad "open alerts under a head proof: blocked, but not by the code-scanning gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "open code-scanning alerts still block under a head proof"
fi

# NO ANALYSIS YET, and no head proof (the commit's own runs are green) -> blocked.
code_scanning_says 2
make_gh_world "[$(run_json 1 CI completed '"success"')]" "$HEAD_GREEN" 6644a32b9
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag with no code-scanning analysis and no head proof"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Fix the code, wait for CodeQL"; then
	bad "no analysis and no head proof: blocked, but not by the code-scanning gate"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "code scanning's no-analysis-yet still blocks without a head proof"
fi
code_scanning_says 0

# RED ON THE MERGE COMMIT ITSELF -> the head does not override it.
make_gh_world "[$(run_json 1 CI completed '"failure"')]" "$HEAD_GREEN" 6644a32b9
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a merge commit with a failed run because its PR head was green"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on" || ! blocked_for "red on"; then
	bad "red merge commit with a green head: blocked, but not by the CI gate's red verdict"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "a failed run on the merge commit refuses the PR head proof"
fi

# THE HEAD IS ON ANOTHER TREE -> the merge commit's pending runs decide.
make_gh_world "$OWN_PENDING" "$HEAD_GREEN" 0000aaaa1
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a pending merge commit on a head with another tree"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on" || ! blocked_for "no merged pull request head has the tree"; then
	bad "head on another tree: blocked, but not saying why the head was not used"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "a PR head on another tree proves nothing and the pending merge commit blocks"
fi

# THE HEAD'S CI RUN FAILED (the macOS leg, which CI success leaves out).
make_gh_world "$OWN_PENDING" "[$(head_run 11 CI completed '"failure"'),$(head_run 12 Quality completed '"success"')]" 6644a32b9
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a head whose CI run failed although its required checks passed"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "Push blocked: CI on" || ! blocked_for "workflow runs not_green"; then
	bad "head with a failed CI run: blocked, but not naming the head's runs"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "a failed workflow run on the PR head refuses its proof"
fi

# ORIGIN IS NOT GITHUB -> no head is looked for; the pending runs decide.
( cd "$CRATE" && git remote set-url origin https://gitlab.example.com/example/sipnab.git )
make_gh_world "$OWN_PENDING" "$HEAD_GREEN" 6644a32b9
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a pending commit whose origin is not GitHub"
	sed 's/^/    /' "$TMP/out.log"
elif ! blocked_for "PR head proof not used: origin is not a GitHub repository"; then
	bad "origin not GitHub: blocked, but not saying why the head was not used"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "an origin that is not GitHub gets no head proof"
fi
( cd "$CRATE" && git remote remove origin )

# -- A push of release-only commits skips the tree gates ----------------------
# SCENARIO: RELEASE-FAST B
#   Given a pushed branch whose only new commit moves the version and the
#     CHANGELOG heading, then the push is ALLOWED without clippy, rustdoc or
#     the other tree gates, the output names the release-only proof, the
#     release-delivery test still runs, and the corpus gate says NOT RUN.
#   Given the same range plus a code commit, a new branch with no origin/main
#     to measure from, or SIPNAB_GATE_NO_CACHE=1, then every gate runs.
sign_commit() { # $1 = message
	( cd "$CRATE" && git -c gpg.format=ssh -c "user.signingkey=$TMP/trusted.pub" commit -S -qm "$1" ) >/dev/null 2>&1
}
( cd "$CRATE" && printf '# Changelog\n\n## [Unreleased]\n\n- a change\n' >CHANGELOG.md && git add CHANGELOG.md )
sign_commit changelog
RO_BASE=$( cd "$CRATE" && git rev-parse HEAD )
sed 's/^version = "0.0.0"$/version = "0.0.1"/' "$CRATE/Cargo.toml" >"$TMP/Cargo.toml.ro" && mv "$TMP/Cargo.toml.ro" "$CRATE/Cargo.toml"
sed 's/^## \[Unreleased\]$/## [0.0.1] - 2026-11-08/' "$CRATE/CHANGELOG.md" >"$TMP/CHANGELOG.ro" && mv "$TMP/CHANGELOG.ro" "$CRATE/CHANGELOG.md"
( cd "$CRATE" && git add Cargo.toml CHANGELOG.md )
sign_commit "Release 0.0.1"
RO_HEAD=$( cd "$CRATE" && git rev-parse HEAD )
if [ "$RO_HEAD" = "$RO_BASE" ]; then
	bad "fixture: the release commit was not made, so the release-only scenarios cannot run"
fi
make_gh "[]"

# RELEASE-ONLY: allowed, tree gates skipped, release-delivery still runs.
if PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/release/0.0.1 $RO_HEAD refs/heads/release/0.0.1 $RO_BASE"; then
	if blocked_for "release-only push: release/0.0.1 carry only release bumps" \
		&& ! blocked_for "cargo clippy --workspace --all-features" \
		&& blocked_for "cargo test --features full --test release_delivery_test ... " \
		&& blocked_for "corpus: NOT RUN -- a release-only push"; then
		ok "a release-only push skips the tree gates, keeps release-delivery and says the corpus did not run"
	else
		bad "a release-only push was allowed, but not by the release-only path"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "a release-only push was BLOCKED"
	sed 's/^/    /' "$TMP/out.log"
fi

# SIPNAB_GATE_NO_CACHE=1 runs every gate on the same range.
export SIPNAB_GATE_NO_CACHE=1
PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/release/0.0.1 $RO_HEAD refs/heads/release/0.0.1 $RO_BASE" || true
unset SIPNAB_GATE_NO_CACHE
if blocked_for "cargo clippy --workspace --all-features" && ! blocked_for "release-only push:"; then
	ok "SIPNAB_GATE_NO_CACHE=1 runs the tree gates on a release-only push"
else
	bad "SIPNAB_GATE_NO_CACHE=1 still skipped the tree gates on a release-only push"
	sed 's/^/    /' "$TMP/out.log"
fi

# A NEW BRANCH with no origin/main to measure from: every gate runs.
PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/release/0.0.1 $RO_HEAD refs/heads/release/0.0.1 0000000000000000000000000000000000000000" || true
if blocked_for "cargo clippy --workspace --all-features" && ! blocked_for "release-only push:"; then
	ok "a new branch with no merge base to measure from runs the tree gates"
else
	bad "a new branch with no merge base skipped the tree gates"
	sed 's/^/    /' "$TMP/out.log"
fi

# A CODE COMMIT after the bump: every gate runs.
printf '// a code change\n' >>"$CRATE/src/main.rs"
( cd "$CRATE" && git add src/main.rs )
sign_commit code
RO_CODE=$( cd "$CRATE" && git rev-parse HEAD )
PATH="$STUB_BIN:$PATH" run_hook "" "refs/heads/release/0.0.1 $RO_CODE refs/heads/release/0.0.1 $RO_BASE" || true
if blocked_for "cargo clippy --workspace --all-features" && ! blocked_for "release-only push:"; then
	ok "a push with a code commit after the release bump runs the tree gates"
else
	bad "a push with a code commit after the release bump skipped the tree gates"
	sed 's/^/    /' "$TMP/out.log"
fi
( cd "$CRATE" && git reset -q --hard "$TAGGED" )

# -- Corpus gate --------------------------------------------------------------
# SCENARIO: the conditional corpus gate
#   Given a crate with corpus test targets and a readable SIPNAB_CORPUS,
#     when the suite passes, then the push is ALLOWED and the output says
#     VALIDATED;
#     when a corpus test fails, then the push is BLOCKED and the output NAMES
#     the failing binary and test.
#   Given SIPNAB_CORPUS unset, or set to something that is not a readable
#     directory, then the push is ALLOWED and the output says NOT VALIDATED --
#     never nothing, because silence in a column of OK lines reads as a pass.
#   Given SKIP_CORPUS_HOOK=1, then the push is ALLOWED and the output says
#     BYPASSED.
#
# The gate cannot be exercised against the real corpus from here: those
# captures carry PII, never leave the machine that recorded them, and are not
# present on any machine that merely checked out this repository. What IS
# testable, and what these cases cover, is the hook's own contract -- which
# binaries it selects, which of the five states it lands in, whether it blocks,
# and whether a failure arrives with a name attached.
CORPUS_DIR="$TMP/fixture-corpus"
mkdir -p "$CORPUS_DIR"

# The fixture needs [profile.corpus]: the gate runs `--profile corpus`,
# because the release profile's panic = "abort" kills a failing test process
# before libtest prints the `failures:` list the gate reads back.
cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[features]
default = ["native"]
native = []
tls = []
api = []
wasm = []

[profile.corpus]
inherits = "release"
lto = false
panic = "unwind"
EOF

# Two stand-ins for real corpus binaries. The gate finds its targets by
# grepping tests/*.rs for SIPNAB_CORPUS, so naming the variable is what puts a
# file in the suite -- and asserting on it proves the gate passed it through to
# cargo rather than merely deciding to run.
write_corpus_tests() { # $1 = "pass" | "fail"
	cat >"$CRATE/tests/corpus_alpha_test.rs" <<'EOF'
#[test]
fn alpha_reads_the_corpus() {
    assert!(
        std::env::var("SIPNAB_CORPUS").is_ok(),
        "the gate must pass SIPNAB_CORPUS through to cargo"
    );
}
EOF
	if [ "$1" = "fail" ]; then
		cat >"$CRATE/tests/corpus_beta_test.rs" <<'EOF'
#[test]
fn beta_finds_a_regression_on_every_capture() {
    let _ = std::env::var("SIPNAB_CORPUS");
    panic!("induced corpus regression");
}
EOF
	else
		cat >"$CRATE/tests/corpus_beta_test.rs" <<'EOF'
#[test]
fn beta_finds_a_regression_on_every_capture() {
    assert!(std::env::var("SIPNAB_CORPUS").is_ok());
}
EOF
	fi
	fmt_fixture
}

# GIVEN no corpus targets at all, THEN the gate skips rather than fails closed.
rm -f "$CRATE"/tests/corpus_*_test.rs
HOOK_CORPUS_DIR="$CORPUS_DIR"
HOOK_CORPUS_SKIP=
if run_hook ""; then
	if grep -q "corpus: NOT VALIDATED -- no corpus test targets" "$TMP/out.log"; then
		ok "corpus gate skips a crate with no corpus targets, and says so"
	else
		bad "corpus gate allowed a crate with no corpus targets but did not say so"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "corpus gate BLOCKED a crate that has no corpus targets"
	sed 's/^/    /' "$TMP/out.log"
fi

# GIVEN a readable corpus and a passing suite, THEN allowed and VALIDATED.
write_corpus_tests pass
HOOK_CORPUS_DIR="$CORPUS_DIR"
HOOK_CORPUS_SKIP=
if run_hook ""; then
	if grep -q "corpus: 2 test binaries against $CORPUS_DIR ... VALIDATED" "$TMP/out.log"; then
		ok "corpus gate runs every derived binary and reports VALIDATED"
	else
		bad "corpus gate allowed the push without reporting VALIDATED"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "corpus gate BLOCKED a passing corpus suite"
	sed 's/^/    /' "$TMP/out.log"
fi

# GIVEN a corpus test that fails, THEN blocked AND the failure is named.
# A gate that only prints FAIL costs whoever hit it a second full run of a
# multi-minute suite just to learn which test broke.
write_corpus_tests fail
HOOK_CORPUS_DIR="$CORPUS_DIR"
HOOK_CORPUS_SKIP=
if run_hook ""; then
	bad "corpus gate ALLOWED a push with a failing corpus test"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "corpus gate blocks a push with a failing corpus test"
	if grep -q "beta_finds_a_regression_on_every_capture" "$TMP/out.log"; then
		ok "corpus failure output NAMES the failing test"
	else
		bad "corpus failure output does not name the failing test"
		sed 's/^/    /' "$TMP/out.log"
	fi
	if grep -q "tests/corpus_beta_test.rs ::" "$TMP/out.log"; then
		ok "corpus failure output names the failing BINARY too"
	else
		bad "corpus failure output does not name the failing binary"
		sed 's/^/    /' "$TMP/out.log"
	fi
	if grep -q "induced corpus regression" "$TMP/out.log"; then
		ok "corpus failure output carries the panic message"
	else
		bad "corpus failure output withheld the panic message"
		sed 's/^/    /' "$TMP/out.log"
	fi
	if grep -q "Reproduce: SIPNAB_CORPUS=.* --test corpus_beta_test " "$TMP/out.log"; then
		ok "corpus failure output offers a single-test reproduce command"
	else
		bad "corpus failure output has no reproduce command"
		sed 's/^/    /' "$TMP/out.log"
	fi
	if grep -q "Full output: .*sipnab-pre-push-corpus.log" "$TMP/out.log"; then
		ok "corpus failure output points at the full capture on disk"
	else
		bad "corpus failure output does not point at the full capture"
		sed 's/^/    /' "$TMP/out.log"
	fi
fi

# GIVEN SIPNAB_CORPUS unset, THEN allowed -- and the output must SAY it did not
# validate. This is the case that must never look like a pass.
write_corpus_tests fail
HOOK_CORPUS_DIR=
HOOK_CORPUS_SKIP=
if run_hook ""; then
	if grep -q "corpus: NOT VALIDATED -- SIPNAB_CORPUS is unset" "$TMP/out.log"; then
		ok "unset SIPNAB_CORPUS allows the push and says NOT VALIDATED"
	else
		bad "unset SIPNAB_CORPUS allowed the push SILENTLY"
		sed 's/^/    /' "$TMP/out.log"
	fi
	if grep -q "VALIDATED" "$TMP/out.log" && ! grep -q "NOT VALIDATED" "$TMP/out.log"; then
		bad "unset SIPNAB_CORPUS reported a bare VALIDATED"
		sed 's/^/    /' "$TMP/out.log"
	else
		ok "unset SIPNAB_CORPUS never claims the corpus was validated"
	fi
else
	bad "unset SIPNAB_CORPUS BLOCKED the push (must stay conditional)"
	sed 's/^/    /' "$TMP/out.log"
fi

# GIVEN SIPNAB_CORPUS pointing at something that is not a readable directory,
# THEN allowed and reported. An unreadable directory walks to zero files, and a
# corpus test over zero files passes while proving nothing.
HOOK_CORPUS_DIR="$TMP/definitely-not-a-directory"
HOOK_CORPUS_SKIP=
if run_hook ""; then
	if grep -q "corpus: NOT VALIDATED -- SIPNAB_CORPUS is not a readable directory" "$TMP/out.log"; then
		ok "unreadable SIPNAB_CORPUS allows the push and says NOT VALIDATED"
	else
		bad "unreadable SIPNAB_CORPUS allowed the push without saying so"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "unreadable SIPNAB_CORPUS BLOCKED the push (must stay conditional)"
	sed 's/^/    /' "$TMP/out.log"
fi

# GIVEN a failing suite but SKIP_CORPUS_HOOK=1, THEN allowed and BYPASSED.
HOOK_CORPUS_DIR="$CORPUS_DIR"
HOOK_CORPUS_SKIP=1
if run_hook ""; then
	if grep -q "corpus: BYPASSED (SKIP_CORPUS_HOOK=1)" "$TMP/out.log"; then
		ok "SKIP_CORPUS_HOOK=1 bypasses the corpus gate and says BYPASSED"
	else
		bad "SKIP_CORPUS_HOOK=1 bypassed the gate SILENTLY"
		sed 's/^/    /' "$TMP/out.log"
	fi
else
	bad "SKIP_CORPUS_HOOK=1 did not bypass a failing corpus suite"
	sed 's/^/    /' "$TMP/out.log"
fi

# ...and the bypass must be NARROW. SKIP_FMT_HOOK=1 already switches off every
# gate; a corpus escape hatch that did the same would make "the corpus is
# unavailable today" a reason to push unformatted, lint-dirty code.
cat >"$CRATE/src/main.rs" <<'EOF'
fn   main( ) {
let x=1   ;
println!("{}",x) ;
}
EOF
HOOK_CORPUS_DIR="$CORPUS_DIR"
HOOK_CORPUS_SKIP=1
if run_hook ""; then
	bad "SKIP_CORPUS_HOOK=1 also switched off the format gate (too broad)"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "SKIP_CORPUS_HOOK=1 leaves the other gates standing"
fi
fmt_fixture
HOOK_CORPUS_DIR=
HOOK_CORPUS_SKIP=

# -- SCENARIO: the feature matrix, run by hand and in CI, not by this hook ----
#
# The break this covers only appears with a feature OFF: `--features full`
# (pre-commit) and `--all-features` (the clippy gate) both turn features ON.
# CI's Features job builds every combo, and since 2026-09-29 it runs on the
# aarch64 self-hosted runners (moved there by Norm), so this hook no longer
# repeats it on every push.
# `scripts/check-feature-matrix.py` still runs the same combos with CI's flags
# by hand, and this scenario holds it to both cases: an ungated item that the
# combo without the feature reports as dead code, and the same item gated.
#
# The fixture gets its own minimal workflow and combination list.
# check-feature-matrix.py reads the combos from .github/feature-combos.txt
# and RUSTFLAGS from the workflow of the crate it runs in, so without them it
# exits 2 and reports NOT CHECKED -- correct, and the reason this scenario
# has to write them rather than rely on the real repo's.
write_matrix_workflow() {
	mkdir -p "$CRATE/.github/workflows"
	cat >"$CRATE/.github/workflows/ci.yml" <<'EOF'
name: CI
env:
  RUSTFLAGS: -Dwarnings
jobs: {}
EOF
	printf 'plain\nextra\n' >"$CRATE/.github/feature-combos.txt"
	# Keeps every feature the EARLIER gates build (the reduced-combo gate
	# checks tls/api/wasm) and adds two of its own. A scenario that narrowed
	# this list would make the reduced-combo gate fail on a missing feature
	# and the hook would exit before ever reaching the matrix gate.
	cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[features]
default = ["native"]
native = []
tls = []
api = []
wasm = []
plain = []
extra = []

[[bin]]
name = "throwaway"
path = "src/main.rs"
EOF
}

# $1 = "" for an ungated helper, or the cfg attribute that gates it.
write_matrix_lib() {
	# `uses_helper` is CALLED from main, not merely defined: an uncalled
	# function is dead under `--all-features` too, so the clippy gate would
	# block first and the hook would never reach the matrix gate -- the
	# scenario would then report "not-reached" and prove nothing.
	# The break is reachable ONLY under `--no-default-features --features
	# plain`, a combo the matrix lists and no earlier gate builds.
	# `any(not(plain), extra)` is false for exactly that one case:
	#   --all-features        plain AND extra on -> the `extra` arm is true
	#   --features tls|api|.. plain off          -> `not(plain)` is true
	#   --features plain      plain on, extra off -> FALSE, `helper` is dead
	# So clippy (`--all-features`) and the reduced-combo gate (tls/api/wasm)
	# both see `helper` used and pass, and a scenario that blocks therefore
	# credits THIS gate rather than an earlier one catching the same thing.
	# A first attempt used `not(feature = "plain")`, which `--all-features`
	# also makes false -- clippy blocked first and the scenario proved
	# nothing.
	cat >"$CRATE/src/main.rs" <<EOF
fn main() {
    #[cfg(any(not(feature = "plain"), feature = "extra"))]
    println!("{}", uses_helper());
    println!("ok");
}

$1
fn helper() -> u32 {
    1
}

#[cfg(any(not(feature = "plain"), feature = "extra"))]
fn uses_helper() -> u32 {
    helper()
}
EOF
	fmt_fixture
}

# run_matrix_script: run the script by hand in the fixture, as a developer
# would before pushing, and leave its exit status in MX_RC.
run_matrix_script() {
	MX_RC=0
	( cd "$CRATE" && python3 "$REPO_ROOT/scripts/check-feature-matrix.py" ) \
		>"$TMP/out.log" 2>&1 || MX_RC=$?
}

write_matrix_workflow
write_matrix_lib ''

# The hook leaves the matrix to CI: it neither runs nor mentions it, so an
# item dead only without its feature does not block here.
run_hook "" || true
if grep -q 'feature matrix' "$TMP/out.log"; then
	bad "the pre-push hook still runs the feature matrix CI runs on the local runners"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "the pre-push hook leaves the feature matrix to CI on the local runners"
fi

# By hand, the script blocks the ungated item...
run_matrix_script
if [ "$MX_RC" -eq 2 ]; then
	skip "check-feature-matrix.py blocks an item that is dead without its feature -- NOT CHECKED on $(uname -s)"
elif [ "$MX_RC" -ne 0 ]; then
	ok "check-feature-matrix.py blocks an item that is dead without its feature"
else
	bad "check-feature-matrix.py did NOT block an item that is dead without its feature"
	sed 's/^/    /' "$TMP/out.log"
fi

# ...and passes once the item carries the same gate its only caller has.
write_matrix_lib '#[cfg(any(not(feature = "plain"), feature = "extra"))]'
run_matrix_script
if [ "$MX_RC" -eq 2 ]; then
	skip "check-feature-matrix.py passes once the item is gated -- NOT CHECKED on $(uname -s)"
elif [ "$MX_RC" -eq 0 ]; then
	ok "check-feature-matrix.py passes once the item is gated"
else
	bad "check-feature-matrix.py blocked a correctly gated item"
	sed 's/^/    /' "$TMP/out.log"
fi

# ...and blocks a LINT that fires only in one combo, which compiles cleanly.
# CI's Features job runs clippy on every leg, so the script must too: under
# `--features plain` alone the gated block below vanishes, the `return`
# becomes the function's tail, and clippy denies `needless_return` while
# `cargo check` sees nothing wrong. The same shape failed `cargo clippy` with
# sipnab's default features on main (`run_pending_install` without `g729`).
cat >"$CRATE/src/main.rs" <<'EOF'
fn main() {
    let mut n = u32::from(std::env::args().count() > 1);
    bump(&mut n);
    println!("{n}");
}

fn bump(n: &mut u32) {
    if *n == 0 {
        return;
    }
    #[cfg(any(not(feature = "plain"), feature = "extra"))]
    {
        *n += 1;
    }
}
EOF
fmt_fixture
# Colored, as CI's workflows set it: the lint's name must survive cargo's ANSI
# codes, or the report shows only a location.
CARGO_TERM_COLOR=always
export CARGO_TERM_COLOR
run_matrix_script
unset CARGO_TERM_COLOR
if [ "$MX_RC" -eq 2 ]; then
	skip "check-feature-matrix.py blocks a lint that fires only in one combo -- NOT CHECKED on $(uname -s)"
elif [ "$MX_RC" -ne 0 ] && grep -q 'needless_return\|unneeded `return`' "$TMP/out.log"; then
	ok "check-feature-matrix.py blocks a lint that fires only in one combo"
else
	bad "check-feature-matrix.py did NOT block a lint that fires only in one combo (exit $MX_RC)"
	sed 's/^/    /' "$TMP/out.log"
fi

# Put the fixture back exactly as it was found: the workflow, the feature list
# and the source. A scenario that leaves its own Cargo.toml behind changes what
# every later scenario compiles.
rm -rf "$CRATE/.github"
cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "throwaway"
path = "src/main.rs"
EOF
rm -f "$CRATE/src/lib.rs"
write_unformatted
fmt_fixture

# -- Summary ------------------------------------------------------------------
# -- GIVEN a hook from ANOTHER checkout, THEN it refuses to gate this one ---
# `core.hooksPath` was an absolute path into one checkout, so every worktree
# ran that checkout's branch's hooks: on 2026-09-29 that was a branch whose
# pre-commit lacked the sipnab-bpf-types step, and commits on main went
# through without it, silently. The hook now checks it is the tree's own.
ensure_repo_shape
: >"$TMP/refs.in"
# The exit status is captured, not tested bare: the harness runs under
# `set -e`, and this run is EXPECTED to fail.
foreign_rc=0
( cd "$CRATE" && env -u SIPNAB_HOOK_ANY_TREE SKIP_FMT_HOOK=1 "$HOOK" <"$TMP/refs.in" ) >"$TMP/out.log" 2>&1 \
	|| foreign_rc=$?
if [ "$foreign_rc" -ne 0 ] && grep -qF 'core.hooksPath .githooks' "$TMP/out.log"; then
	ok "a hook from another checkout blocks and says how to point git at this tree's"
else
	bad "a hook from another checkout gated this tree: $(cat "$TMP/out.log")"
fi
# ...and the same file installed as the tree's OWN hook gets past that check.
mkdir -p "$CRATE/.githooks"
cp "$HOOK" "$CRATE/.githooks/pre-push"
( cd "$CRATE" && env -u SIPNAB_HOOK_ANY_TREE SKIP_FMT_HOOK=1 sh .githooks/pre-push <"$TMP/refs.in" ) >"$TMP/out.log" 2>&1 \
	|| true
if grep -qF 'Running pre-push checks' "$TMP/out.log" && ! grep -qF 'core.hooksPath .githooks' "$TMP/out.log"; then
	ok "the tree's own hook passes the same-checkout check"
else
	bad "the tree's own hook was refused as foreign: $(cat "$TMP/out.log")"
fi
rm -rf "$CRATE/.githooks"

# -- Prerequisites: checked before any gate --------------------------------
# A fresh worktree has no .vale/styles/Google: only `vale sync` writes it,
# and the hook used to die on it at the prose gate, after the build gates.
# It now refuses before its first gate, naming the command. The G.729 test
# vectors are a pre-commit prerequisite only: no test pre-push runs reads
# them, so their absence must not block a push.
printf '#!/bin/sh\nexit 0\n' >"$TMP/vale-stub"
chmod +x "$TMP/vale-stub"
cp "$REPO_ROOT/.vale.ini" "$CRATE/.vale.ini"
rm -rf "$CRATE/.vale"
t0=$(date +%s)
VALE_BIN="$TMP/vale-stub"
export VALE_BIN
run_hook "" || true
secs=$(( $(date +%s) - t0 ))
why=""
grep -qF 'run: vale sync' "$TMP/out.log" || why="$why no 'run: vale sync';"
grep -qF 'every pushed commit is signed' "$TMP/out.log" && why="$why a gate ran;"
grep -qF 'cargo fmt --all -- --check' "$TMP/out.log" && why="$why the fmt gate ran;"
[ "$secs" -le 10 ] || why="$why took ${secs}s;"
if [ -z "$why" ]; then
	ok "a tree without Vale's style package is refused before any gate, with 'vale sync'"
else
	bad "missing Vale styles:$why out: $(cat "$TMP/out.log")"
fi

mkdir -p "$CRATE/.vale/styles/Google" "$CRATE/crates/g729"
printf '[package]\nname = "sipnab-g729"\n' >"$CRATE/crates/g729/Cargo.toml"
run_hook 1 || true
unset VALE_BIN
if grep -qF 'Prerequisites... OK' "$TMP/out.log" \
	&& ! grep -qF 'fetch-g729-vectors' "$TMP/out.log"; then
	ok "with the styles synced, a push goes on to the gates, and needs no G.729 vectors"
else
	bad "a synced tree must pass the prerequisite check without the G.729 vectors: $(cat "$TMP/out.log")"
fi
rm -rf "$CRATE/.vale" "$CRATE/.vale.ini" "$CRATE/crates"

printf '\n--- test-pre-push summary: %d passed, %d failed, %d skipped (host: %s) ---\n' \
	"$PASS" "$FAIL" "$SKIP" "$(uname -s)"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
if [ "$SKIP" -ne 0 ]; then
	printf 'AMBER: %d scenario(s) could not be decided on this host. A SKIP is\n' "$SKIP"
	printf 'coverage that did not happen, not coverage that passed -- run this on\n'
	printf 'Linux for the full set. The rest passed.\n'
	exit 0
fi
printf 'GREEN: all pre-push BDD scenarios passed.\n'
exit 0
