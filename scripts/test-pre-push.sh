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

# -- Summary ------------------------------------------------------------------
printf '\n--- test-pre-push summary: %d passed, %d failed ---\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
	exit 1
fi
printf 'GREEN: all pre-push BDD scenarios passed.\n'
exit 0
