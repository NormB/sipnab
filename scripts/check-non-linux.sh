#!/bin/sh
# Compile the NON-LINUX arm of every `#[cfg(target_os = ...)]` split, on Linux.
#
# WHY THIS EXISTS
#
# CI is the only non-Linux build in this project, so a `#[cfg]` mistake that is
# invisible on Linux costs a red macOS job and a round-trip. It has happened
# twice in one day, from the same module:
#
#   34defd5  error[E0425]: cannot find value `FANOUT_HASH_WITH_ROLLOVER`
#            -- a cross-platform module with a `#[cfg(test)]` test module whose
#            tests reached for a `#[cfg(target_os = "linux")]` constant.
#   82eb8ff  error: unused variable: `fanout_group`, under -D warnings
#            -- `#[cfg(all(unix, target_os = "linux"))]` on the call site gated
#            the USE of a parameter but not its BINDING.
#
# Neither is reachable from any Linux build, at any feature combination. The
# gates in `.githooks/pre-push` all compile the SAME arm of the split, so all of
# them said OK. This script compiles the OTHER arm.
#
# HOW: THE SAME CODE, WITH THE PLATFORM CFG SWAPPED
#
# The tree is copied to `target/nonlinux-shim/tree`, and in the copy every
# `target_os` predicate is rewritten:
#
#   target_os = "linux"  ->  target_os = "sipnab_not_linux"   (never true)
#   target_os = "macos"  ->  target_os = "linux"              (true, on Linux)
#
# On a Linux host that inverts both halves of every split at once: the Linux
# arms drop out, the `not(target_os = "linux")` arms compile, and the genuinely
# macOS-only arms compile too instead of being skipped the way they would be
# under any real cross-check from here. `cfg(unix)` and `target_family` are
# untouched, so what gets built is a unix that is not Linux -- which is exactly
# the shape of both breaks above.
#
# The rewrite runs ONLY on the copy. The real working tree is never modified, so
# a Ctrl-C in the middle leaves nothing to clean up but a stale directory under
# `target/`, which the next run deletes. That is the whole reason for the copy;
# rewriting in place and reverting afterwards is faster and one interrupt away
# from handing someone a source tree full of `sipnab_not_linux`.
#
# WHAT WAS REJECTED, AND WHAT KILLED IT
#
# * `cargo check --target x86_64-unknown-freebsd` -- dies in libmimalloc-sys's
#   build script (`cc: error: unrecognized command-line option '-m64'`), and no
#   feature set avoids it: mimalloc is declared under
#   `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` with no
#   `optional = true`, so it is unconditional for every non-wasm target
#   regardless of `--no-default-features`. Fixing it means a FreeBSD C
#   cross-toolchain and sysroot on every contributor's machine.
# * `cargo check --target wasm32-unknown-unknown` -- already runs in this hook
#   and in CI, and cannot see this class at all. `capture::fanout` and
#   `capture::live` are `#[cfg(feature = "native")]`, and `wasm` excludes
#   `native`. Measured, not assumed: an unconditional `compile_error!` at the
#   top of `src/capture/fanout.rs` leaves BOTH `cargo check --no-default-features
#   --features wasm --lib` and CI's `--target wasm32-unknown-unknown` variant
#   exiting 0. Adding `native` to the wasm feature set does not rescue it --
#   libc has no `sys` module for wasm32-unknown-unknown.
# * `wasm32-wasip1` -- the one std-bearing non-Linux target that escapes
#   mimalloc (it is wasm32, so the target dependency does not apply). Fails
#   earlier still: `errno` needs `#![feature]` on stable there. And `cfg(unix)`
#   is false on wasi, so the `fanout_group` call site would not have been
#   compiled even if the dependency graph had built.
# * A grep for identifiers used only inside `#[cfg(target_os = ...)]` blocks --
#   runs anywhere, but it is a lexical guess at a name-resolution question. It
#   cannot see that `fanout_group` is a BINDING whose only reader is gated,
#   which is the second bug in full.
#
# COST, measured on this machine (14 cores, cold `target/nonlinux-shim/`):
#
#   first run (whole dependency graph checked) ...........  50 s, 1.3 GB
#   subsequent run, no source change ....................   10 s
#   subsequent run, one source file changed .............   10-17 s
#
# The disk figure is the one that moves, and it moves FAR harder than this
# header used to say. 1.3 GB is what the first run leaves. Cargo keeps the
# artifacts of every source version it has already seen, so the directory
# scales with the number of DISTINCT SOURCE STATES checked -- not with the
# number of runs, which is what the earlier "1.7 GB after a dozen runs" figure
# actually measured, over a handful of trees.
#
# Measured 2026-08-08: 78 GB, on a machine that had run the gate across a day
# of commits. That is 46x the documented figure, and it is not academic -- it
# exhausted a 3.6 TB disk and failed a release build mid-`cargo test`, which is
# how it was found. A busy day of commits is a busy day of source states.
#
# There is still no cap and no prune here, but the reason the last review gave
# for not adding one ("a gigabyte on a machine with terabytes") does not
# survive the real number, and docs/design/ has no entry for it yet. Until it
# does, treat `rm -rf target/nonlinux-shim` as routine maintenance rather than
# a thing you do when space is "genuinely wanted": it is disposable, the next
# run rebuilds it in 50 seconds, and nothing else reads it.
#
# It is a second set of check artifacts, deliberately NOT shared with
# `target/`: `cargo clippy` in a directory that also serves ordinary builds is
# how a stale artifact gets picked up later.
#
# EXIT CODES (the hook depends on these)
#   0  checked, and the non-Linux arm builds clean
#   1  checked, and it does NOT build -- the message names what broke
#   2  NOT CHECKED, with the reason on stdout. Never silence: a gate that goes
#      quiet when it cannot run is worse than no gate, because green then means
#      nothing. Same rule the corpus and Vale gates follow.

set -eu

# The sentinel is a made-up `target_os` value on purpose. A real one ("freebsd",
# "netbsd") would need no `-A unexpected_cfgs` below, but it would silently
# MERGE with any genuine `#[cfg(target_os = "freebsd")]` this tree ever grows --
# two distinct arms collapsing into one, with no error. A value no target can
# ever have makes that unrepresentable.
SENTINEL=sipnab_not_linux

# Whitespace-tolerant so no spelling can slip past. `target_os="linux"` is not
# what rustfmt emits, but the gate must not depend on that: a pattern that
# quietly matches nothing would leave this script copying, compiling and
# reporting OK on an UNMODIFIED tree, forever.
LINUX_RE='target_os[[:space:]]*=[[:space:]]*"linux"'
MACOS_RE='target_os[[:space:]]*=[[:space:]]*"macos"'

skip() {
	printf 'NOT CHECKED -- %s\n' "$1"
	exit 2
}

# Count matches of an ERE across every .rs file under a directory.
#
# `find -exec grep +` rather than a list of paths in a variable: an unquoted
# `$(cat filelist)` word-splits, and the first contributor with a space in a
# path would get a miscount -- which here means the self-check below comparing
# two wrong numbers and passing. `grep -o` puts each match on its own line, so
# two gates on one line both count.
count_cfg() { # count_cfg <dir> <ere>
	find "$1" -name target -prune -o -name .git -prune -o -name '*.rs' -type f \
		-exec grep -ohE "$2" {} + | wc -l | tr -d ' '
}

# -- Preconditions ------------------------------------------------------------

# Linux hosts only, and this is not a limitation worth working around: on macOS
# or a BSD the developer's ORDINARY `cargo clippy` already is the non-Linux
# build. Inverting the swap there (to check the Linux arm) would compile
# Linux-only `libc` items against a libc that does not define them, and report
# failures nobody can act on.
[ "$(uname -s)" = "Linux" ] || skip "host is $(uname -s), not Linux; the ordinary build here already compiles the non-Linux arm"

command -v cargo >/dev/null 2>&1 || skip "cargo is not on PATH"
cargo clippy --version >/dev/null 2>&1 || skip "cargo clippy is unavailable (rustup component add clippy)"

# Run from the package root, which is where git invokes hooks from and where
# every other gate in .githooks/pre-push already assumes it is.
ROOT=$(pwd)
[ -f "$ROOT/Cargo.toml" ] || skip "no Cargo.toml in $ROOT"

SHIM="$ROOT/target/nonlinux-shim"
TREE="$SHIM/tree"
SENTINEL_RE="target_os[[:space:]]*=[[:space:]]*\"$SENTINEL\""

# Count what the rewrite is supposed to change, BEFORE changing anything. These
# two numbers are the gate's own self-check: they are re-counted in the copy
# afterwards and must match exactly.
n_linux=$(count_cfg "$ROOT" "$LINUX_RE")
n_macos=$(count_cfg "$ROOT" "$MACOS_RE")

# A crate with no platform splits has nothing for this gate to invert. Skip the
# way the fuzz gate skips a missing fuzz/ and the feature gate skips an
# undefined combination -- otherwise every throwaway fixture crate in
# scripts/test-pre-push.sh pays a full dependency check to inspect nothing.
[ "$n_linux" -gt 0 ] || skip "no \`target_os = \"linux\"\` gates in this crate"

# The sentinel must not already be in the tree, or the post-rewrite counts below
# would be measuring somebody else's text.
if [ "$(count_cfg "$ROOT" "$SENTINEL_RE")" -ne 0 ]; then
	printf 'FAILED -- '%s' already appears as a target_os value in the tree.\n' "$SENTINEL"
	printf 'Pick a different SENTINEL in scripts/check-non-linux.sh; this one can no\n'
	printf 'longer be told apart from real code.\n'
	exit 1
fi

# -- Build the shim tree ------------------------------------------------------

rm -rf "$TREE"
mkdir -p "$TREE"

# `cp -a` preserves mtimes, and that is load-bearing rather than tidiness:
# cargo fingerprints on mtime, so a fresh copy of unchanged sources rebuilds
# nothing and the second run costs 10 s instead of 50. Copying with mtimes
# reset would make every run a cold run.
#
# Everything except target/ (recursion) and .git/ (nothing here reads it --
# build.rs falls back gracefully when .git is absent, which it documents).
find "$ROOT" -maxdepth 1 -mindepth 1 ! -name target ! -name .git -exec cp -a {} "$TREE/" \;

# ORDER MATTERS, and it is the whole reason a sentinel exists. `sed` applies
# `-e` scripts in sequence per line, so the linux->sentinel pass runs first and
# consumes every "linux" before the macos->linux pass can create new ones.
# Reversed, the second expression would rewrite the first's output and every
# Linux gate would come out as a macOS gate -- a tree that compiles, passes, and
# checked the arm it was supposed to be replacing.
find "$TREE" -name '*.rs' -type f -exec sed -i \
	-e "s/$LINUX_RE/target_os = \"$SENTINEL\"/g" \
	-e "s/$MACOS_RE/target_os = \"linux\"/g" \
	{} +

# -- The self-check: prove the rewrite actually happened ----------------------
#
# Without this the failure mode is silent and permanent. If the patterns ever
# stop matching -- a rustfmt spacing change, a raw string, a macro that builds
# the cfg -- the gate would copy the tree, compile it unchanged, print OK, and
# go on catching nothing. It would look exactly like a gate that works.
got_sentinel=$(count_cfg "$TREE" "$SENTINEL_RE")
got_linux=$(count_cfg "$TREE" "$LINUX_RE")
got_macos=$(count_cfg "$TREE" "$MACOS_RE")

if [ "$got_sentinel" -ne "$n_linux" ] || [ "$got_linux" -ne "$n_macos" ] || [ "$got_macos" -ne 0 ]; then
	printf 'FAILED -- the cfg rewrite did not land as intended.\n'
	printf '  original tree: %s linux, %s macos\n' "$n_linux" "$n_macos"
	printf '  shim tree:     %s sentinel, %s linux, %s macos (expected %s, %s, 0)\n' \
		"$got_sentinel" "$got_linux" "$got_macos" "$n_linux" "$n_macos"
	printf 'Every target_os predicate must be one of the two forms this script\n'
	printf 'rewrites. Check scripts/check-non-linux.sh against the new spelling --\n'
	printf 'do NOT relax this check: an un-rewritten tree compiles clean and the\n'
	printf 'gate then reports OK while inspecting nothing.\n'
	exit 1
fi

# -- Compile the inverted tree ------------------------------------------------
#
# The same invocation CI runs on macos-latest, so a lint that fails there fails
# here first: `cargo clippy --all-features --all-targets -- -D warnings`.
# `--all-targets` is not optional -- the first of the two breaks lived in a
# `#[cfg(test)]` module, which no `--lib` check ever builds.
#
# `-A unexpected_cfgs` is required and is the one honest cost of the sentinel:
# `target_os = "sipnab_not_linux"` is not a value rustc knows, so every gated
# item raises `unexpected cfg condition value` and -D warnings turns each into
# an error (verified -- 101 errors without the allow, none with it). The lint
# still runs for real on the real tree, in the clippy gate above this one in
# .githooks/pre-push; nothing is lost by suppressing it in the copy.
cd "$TREE"
CARGO_TARGET_DIR="$SHIM/target" \
	cargo clippy --all-features --all-targets -- -D warnings -A unexpected_cfgs
