#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# Check (or, with --fix, apply) rustfmt on every tracked Rust file, with the
# dated nightly rustfmt named in .rustfmt-toolchain.
#
# usage: scripts/check-rustfmt.sh [--fix]
#
# Why a nightly rustfmt. sipnab follows the Google Rust Style Guide, which sets
# rustfmt options that are still unstable (imports_granularity,
# format_macro_matchers). A stable rustfmt warns about them and ignores them,
# so only a nightly applies the whole rustfmt.toml. The nightly is pinned by
# date, because a bare `nightly` is a different formatter every day and would
# reformat the tree with no change to it. Only rustfmt runs on it: sipnab
# builds, tests and lints on stable, with no unstable language features.
#
# Why every tracked file. `cargo fmt --all` reaches only the module trees of
# this workspace's targets, and fuzz/ and bpf/ are not members. Listing the
# files from git reaches those two, build_script/ and ops/ as well, from one
# command, so no package can be left out by a missing line.
# `skip_children` stops rustfmt from formatting a file a second time when it
# reaches it through its parent's `mod` declaration.
#
# Exit status: 0 when every file is formatted, 1 when rustfmt would change one
# (it prints the diff), 2 when the pinned rustfmt is not installed.
set -euo pipefail

# The pin belongs to the checkout this script ships in. The files are the tree
# the caller stands in, which is the same tree except in the hook harnesses,
# where it is a throwaway crate.
here=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
pin=$(tr -d '[:space:]' < "$here/.rustfmt-toolchain")
case "$pin" in
nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;;
*)
	echo ".rustfmt-toolchain must name one dated nightly (nightly-YYYY-MM-DD), not '$pin'" >&2
	exit 2
	;;
esac
if ! rustfmt "+$pin" --version > /dev/null 2>&1; then
	echo "rustfmt for $pin is not installed. Install it with:" >&2
	echo "    rustup toolchain install $pin --profile minimal --component rustfmt" >&2
	exit 2
fi

check=--check
if [ "${1:-}" = --fix ]; then
	check=
elif [ $# -gt 0 ]; then
	echo "usage: scripts/check-rustfmt.sh [--fix]" >&2
	exit 2
fi

if ! top=$(git rev-parse --show-toplevel 2> /dev/null); then
	echo "check-rustfmt.sh: not inside a git work tree, so there is no file list" >&2
	exit 2
fi
cd "$top"

# Tracked files and new ones git does not ignore, as `cargo fmt` would see a
# new module; a tracked file deleted from the work tree is skipped.
list=$(mktemp)
trap 'rm -f "$list"' EXIT
git ls-files -z --cached --others --exclude-standard -- '*.rs' \
	| while IFS= read -r -d '' f; do
		[ -f "$f" ] && [ ! -L "$f" ] && printf '%s\0' "$f"
	done > "$list"
if [ ! -s "$list" ]; then
	echo "check-rustfmt.sh: no Rust files in $top" >&2
	exit 2
fi

jobs=$(getconf _NPROCESSORS_ONLN 2> /dev/null || echo 4)
# xargs exits 123 when any rustfmt run fails; report that as 1.
# shellcheck disable=SC2086 # $check is one word or none.
if xargs -0 -n 64 -P "$jobs" rustfmt "+$pin" $check --config skip_children=true < "$list"; then
	exit 0
fi
exit 1
