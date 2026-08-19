#!/bin/sh
# BDD test for .githooks/pre-push.
#
# SCENARIO: format gate
#   Given a throwaway crate containing UNFORMATTED Rust,
#     when the pre-push hook runs, then it BLOCKS the push (exit != 0).
#   Given the same crate after `cargo fmt --all` (FORMATTED Rust),
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

# -- Build an isolated minimal crate -----------------------------------------
CRATE="$TMP/throwaway"
mkdir -p "$CRATE/src"

cat >"$CRATE/Cargo.toml" <<'EOF'
[package]
name = "throwaway"
version = "0.0.0"
edition = "2021"

[[bin]]
name = "throwaway"
path = "src/main.rs"
EOF

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
run_hook() {
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
	( cd "$CRATE" && env -u SKIP_FMT_HOOK -u SIPNAB_CORPUS -u SKIP_CORPUS_HOOK \
		${1:+SKIP_FMT_HOOK="$1"} \
		${HOOK_CORPUS_DIR:+SIPNAB_CORPUS="$HOOK_CORPUS_DIR"} \
		${HOOK_CORPUS_SKIP:+SKIP_CORPUS_HOOK="$HOOK_CORPUS_SKIP"} \
		"$HOOK" <"$TMP/refs.in" ) >"$TMP/out.log" 2>&1
}

# -- GIVEN unformatted Rust, THEN hook blocks --------------------------------
write_unformatted
if run_hook ""; then
	bad "unformatted Rust was ALLOWED (expected block)"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "unformatted Rust is BLOCKED (non-zero exit)"
fi

# Confirm the message is actionable (mentions cargo fmt).
if grep -q "cargo fmt" "$TMP/out.log"; then
	ok "failure message points to 'cargo fmt'"
else
	bad "failure message does not mention 'cargo fmt'"
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
if run_hook ""; then
	bad "clippy gate did NOT block a -D warnings violation (the gate is unreachable from this fixture)"
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
if run_hook ""; then
	bad "rustdoc gate did NOT block a broken intra-doc link"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "rustdoc gate blocks a broken intra-doc link"
fi

# fuzz: the hook runs `cd fuzz && cargo check`. With no fuzz/ directory that
# step cannot fail, which is why it was never exercised. Give the fixture one
# that does not compile.
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
if run_hook ""; then
	bad "fuzz gate did NOT block a fuzz/ workspace that fails cargo check"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "fuzz gate blocks a fuzz/ workspace that fails cargo check"
fi
rm -rf "$CRATE/fuzz"

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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
	( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true

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
( cd "$CRATE" \
	&& git init -q . \
	&& git config user.email t@example.com \
	&& git config user.name test \
	&& git add -A \
	&& git commit -qm fixture ) >/dev/null 2>&1
TAGGED=$( cd "$CRATE" && git rev-parse HEAD )
REFLINE="refs/tags/v9.9.9 $TAGGED refs/tags/v9.9.9 0000000000000000000000000000000000000000"

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
else
	ok "tag gate blocks a tag on a commit whose CI failed"
fi

# STILL RUNNING: not green YET is not green. Tagging here races the result.
make_gh "[{\"headSha\":\"$TAGGED\",\"status\":\"in_progress\",\"conclusion\":null,\"name\":\"CI\"}]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag while CI was still running"
	sed 's/^/    /' "$TMP/out.log"
else
	ok "tag gate blocks a tag while CI is still running"
fi

# NO RUNS: the commit was never pushed, so nothing has verified it.
make_gh "[]"
if PATH="$STUB_BIN:$PATH" run_hook "" "$REFLINE"; then
	bad "tag gate ALLOWED a tag on a commit with no CI runs"
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

# TAG DELETION: an all-zero local sha has no commit to verify.
make_gh "[]"
if PATH="$STUB_BIN:$PATH" run_hook "" "(delete) 0000000000000000000000000000000000000000 refs/tags/v9.9.9 $TAGGED"; then
	ok "tag gate ignores a tag deletion"
else
	bad "tag gate blocked a tag deletion"
	sed 's/^/    /' "$TMP/out.log"
fi

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

# The fixture needs [profile.profiling]: the gate runs `--profile profiling`,
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

[profile.profiling]
inherits = "release"
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
	( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
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
( cd "$CRATE" && cargo fmt --all ) >/dev/null 2>&1 || true
HOOK_CORPUS_DIR=
HOOK_CORPUS_SKIP=

# -- Summary ------------------------------------------------------------------
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
