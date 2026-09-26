# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The check helpers scripts/smoke-clients.sh uses, in a file of their own so
# scripts/tests/test_smoke_expect.py can run them without starting sipnab.
# Sourced; expects FAILED (a counter) and WORK (a scratch directory) set.

fail() {
	echo "FAIL: $*" >&2
	FAILED=$((FAILED + 1))
}

# expect LABEL LINE... -- COMMAND...
# COMMAND must exit 0 and print every LINE as a whole line of its stdout.
expect() {
	local label="$1"
	shift
	local want=()
	while [ "$1" != "--" ]; do
		want+=("$1")
		shift
	done
	shift
	if ! "$@" >"$WORK/out" 2>"$WORK/err"; then
		fail "$label exited non-zero: $(head -c 400 "$WORK/err")"
		return
	fi
	local missing=0
	for line in "${want[@]}"; do
		if ! grep -qxF -- "$line" "$WORK/out"; then
			fail "$label did not print '$line'; it printed: $(head -c 400 "$WORK/out")"
			missing=1
		fi
	done
	# A check with a missing line has failed; saying ok for it as well is
	# what made a FAIL line and an ok line appear for one check.
	[ "$missing" = 0 ] && echo "ok   $label"
	return 0
}

# expect_exit LABEL STATUS LINE... -- COMMAND...
# COMMAND must exit with STATUS and print every LINE as a whole line of its
# stdout: for a program whose refusal is its answer.
expect_exit() {
	local label="$1" status="$2"
	shift 2
	local want=()
	while [ "$1" != "--" ]; do
		want+=("$1")
		shift
	done
	shift
	local got=0
	"$@" >"$WORK/out" 2>"$WORK/err" || got=$?
	if [ "$got" != "$status" ]; then
		fail "$label exited $got, not $status: $(head -c 400 "$WORK/err") $(head -c 400 "$WORK/out")"
		return
	fi
	local missing=0
	for line in "${want[@]}"; do
		if ! grep -qxF -- "$line" "$WORK/out"; then
			fail "$label did not print '$line'; it printed: $(head -c 400 "$WORK/out")"
			missing=1
		fi
	done
	# A check with a missing line has failed; saying ok for it as well is
	# what made a FAIL line and an ok line appear for one check.
	[ "$missing" = 0 ] && echo "ok   $label"
	return 0
}
