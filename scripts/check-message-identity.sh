#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Check one commit message or pull request description for the lab's private
# identities: the development host, the lab's machines, its DNS domain, its LAN
# and account paths.
#
#   scripts/check-message-identity.sh <file>
#
# Exit 0: nothing found, and nothing is printed.
# Exit 1: something was found; each line is printed with its class and what to
#         write instead.
# Exit 2: the check could not run (no file, or the test did not build or run).
#
# The commit-msg hook runs this on every commit. .github/workflows/pr-text.yml
# runs it on every pull request: over the title and each commit message in the
# pull request (what a merge puts on main), and over the description, which is
# public from the moment the pull request is opened. Run it by hand on a
# description before posting it.
#
# # One rule in one place
#
# The rules are the predicates in `tests/private_identity_test.rs`, the same
# ones that scan the tracked files. This script holds no pattern of its own: it
# runs one `#[ignore]`d test from that file over the message. The features are
# the pre-commit hook's, `--features full`, so the test binary that hook just
# built is reused and nothing is rebuilt.
#
# SIPNAB_MESSAGE_FEATURES, when set and not empty, replaces `--features full`
# for a caller that has no such binary to reuse. `none` builds with no features
# (`--no-default-features`); a comma-separated list builds with exactly that
# list, the defaults off. The pull-request-text workflow sets `none`: the test
# uses nothing from the crate, and a cold runner then builds neither `full` nor
# the system libraries it links. The commit-msg hook leaves it unset.
#
# SIPNAB_MESSAGE_WHOLE=1 reads the whole message, past a scissors line. The
# hook leaves it unset: git removes a scissors line and what follows it from a
# message written in an editor. CI sets it: a message read back from git, or a
# pull request's text, is published as it stands. The variable reaches the
# test through the environment; the test refuses any value other than 1.
#
# SIPNAB_MESSAGE_TEST_BIN, when set, names an already-built
# `private_identity_test` binary to run instead of cargo. The test suite uses
# it to drive this script without starting cargo from inside cargo.

set -euo pipefail

TEST_NAME=message_in_sipnab_scan_message_names_no_private_identity

if [ "$#" -ne 1 ]; then
	echo "usage: $0 <message-file>" >&2
	exit 2
fi
if [ ! -r "$1" ] || [ -d "$1" ]; then
	echo "$0: cannot read the message file '$1'" >&2
	exit 2
fi

FEATURE_ARGS=(--features full)
case "${SIPNAB_MESSAGE_FEATURES:-}" in
'') ;;
none) FEATURE_ARGS=(--no-default-features) ;;
*[!a-z0-9,_-]* | ,* | *, | *,,*)
	echo "$0: SIPNAB_MESSAGE_FEATURES='$SIPNAB_MESSAGE_FEATURES' is not 'none' or a comma-separated feature list, so the message is NOT CHECKED" >&2
	exit 2
	;;
*) FEATURE_ARGS=(--no-default-features --features "$SIPNAB_MESSAGE_FEATURES") ;;
esac

# Absolute, because cargo runs the test from the repository root.
MESSAGE="$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd -P)/$(basename -- "$1")"
ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"

if [ -n "${SIPNAB_MESSAGE_TEST_BIN:-}" ]; then
	OUT=$(SIPNAB_SCAN_MESSAGE="$MESSAGE" "$SIPNAB_MESSAGE_TEST_BIN" \
		--ignored --exact "$TEST_NAME" 2>&1) && rc=0 || rc=$?
else
	OUT=$(SIPNAB_SCAN_MESSAGE="$MESSAGE" cargo test "${FEATURE_ARGS[@]}" --color never \
		--test private_identity_test -- --ignored --exact "$TEST_NAME" 2>&1) && rc=0 || rc=$?
fi

# A run that exits 0 without running the test checked nothing: a renamed test
# matches no `--exact` filter, and libtest reports "0 passed" and success.
if [ "$rc" -eq 0 ]; then
	if printf '%s\n' "$OUT" | grep -q 'test result: ok\. 1 passed'; then
		exit 0
	fi
	echo "$0: the check did not run $TEST_NAME, so the message is NOT CHECKED:" >&2
	printf '%s\n' "$OUT" | tail -n 20 >&2
	exit 2
fi

# The test ran and failed: print its own message, which names every line.
FINDINGS=$(printf '%s\n' "$OUT" | awk -v name="---- $TEST_NAME stdout ----" '
	$0 == name { on = 1; next }
	on && /^note: run with `RUST_BACKTRACE=1`/ { exit }
	on && /^failures:$/ { exit }
	on && /^thread / { next }
	on && !started && /^$/ { next }
	on { started = 1; print }
')
if printf '%s\n' "$FINDINGS" | grep -q 'names a private identity'; then
	printf '%s\n' "$FINDINGS"
	exit 1
fi
echo "$0: the check failed before it read the message:" >&2
printf '%s\n' "$OUT" | tail -n 30 >&2
exit 2
