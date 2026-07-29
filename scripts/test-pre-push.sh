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

# Run the hook with cwd = throwaway crate. We deliberately do NOT pass through
# the caller's SKIP_FMT_HOOK; each case sets it explicitly.
run_hook() {
	# $1 = value for SKIP_FMT_HOOK ("" means unset)
	( cd "$CRATE" && env -u SKIP_FMT_HOOK ${1:+SKIP_FMT_HOOK="$1"} "$HOOK" ) >"$TMP/out.log" 2>&1
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

# -- Summary ------------------------------------------------------------------
printf '\n--- test-pre-push summary: %d passed, %d failed ---\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
printf 'GREEN: all pre-push BDD scenarios passed.\n'
exit 0
