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
# The commit-msg hook runs this on every commit. Run it by hand on a pull
# request description before posting it: a squash merge makes the title and
# body the commit message on main.
#
# # One rule in one place
#
# The rules are the predicates in `tests/private_identity_test.rs`, the same
# ones that scan the tracked files. This script holds no pattern of its own: it
# runs one `#[ignore]`d test from that file over the message. The features are
# the pre-commit hook's, `--features full`, so the test binary that hook just
# built is reused and nothing is rebuilt.
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

# Absolute, because cargo runs the test from the repository root.
MESSAGE="$(CDPATH='' cd -- "$(dirname -- "$1")" && pwd -P)/$(basename -- "$1")"
ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"

if [ -n "${SIPNAB_MESSAGE_TEST_BIN:-}" ]; then
	OUT=$(SIPNAB_SCAN_MESSAGE="$MESSAGE" "$SIPNAB_MESSAGE_TEST_BIN" \
		--ignored --exact "$TEST_NAME" 2>&1) && rc=0 || rc=$?
else
	OUT=$(SIPNAB_SCAN_MESSAGE="$MESSAGE" cargo test --features full --color never \
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
