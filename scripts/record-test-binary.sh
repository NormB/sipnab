#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# cargo's runner hook for scripts/parallel-tests.py: record a test binary
# instead of running it.
#
#   record-test-binary.sh SPOOL TARGET_DIR BINARY [ARGS...]
#
# cargo invokes the configured runner as `RUNNER BINARY ARGS...`, from the
# directory and with the environment it would run the binary with. This
# writes all three into a fresh directory under SPOOL and exits 0 at once,
# so cargo moves straight on to the next binary; parallel-tests.py then runs
# the recordings side by side. It prints nothing: cargo would show any
# output as the test binary's own.
#
# Only binaries inside cargo's TARGET_DIR are recorded. Doctests go through
# the runner too (since Rust 1.89), but rustdoc builds each one in a temporary
# directory that it deletes as soon as the runner returns, so a recorded
# doctest would be gone before it could run. Anything outside TARGET_DIR is
# run here and now, its output and exit status going straight back to cargo.
#
# NUL-separated, because an argument or an environment value may contain a
# newline. `env -0` is GNU; the fallback covers a BSD env without it.
set -eu
spool=$1
target=$2
shift 2
case $1 in
"$target"/*) ;;
*) exec "$@" ;;
esac
dir=$(mktemp -d "$spool/binary.XXXXXXXX")
pwd >"$dir/cwd"
printf '%s\0' "$@" >"$dir/argv"
env -0 >"$dir/env" 2>/dev/null ||
	python3 -c 'import os, sys; sys.stdout.write("".join(k + "=" + v + "\0" for k, v in os.environ.items()))' >"$dir/env"
# Last: parallel-tests.py treats a directory without `ready` as a recording
# that never finished.
: >"$dir/ready"
