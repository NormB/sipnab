#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Does a commit message's test count match the tests the commit actually adds?
#
#   check-test-claim.sh --classify <actual>   read the message on stdin
#
# ── Why this exists ─────────────────────────────────────────────────────────
#
# Commit messages here end with a sentence of the form "Seventeen tests,
# mutation-proven: ...". On 2026-09-11 one of them said "Sixteen tests" about a
# commit that added seventeen. Nothing caught it, because a number spelled as a
# word does not look like data — it reads as prose, and prose is not checked.
#
# A count in a commit message is the one claim about a change that a reader
# cannot verify without the diff in front of them, which is exactly the kind of
# claim that should not be typed from memory. So it is derived here instead.
#
# ── What counts as a claim ──────────────────────────────────────────────────
#
# The convention here is one summary sentence: "Eighteen tests, mutation-proven:
# ...", on its own line. THAT is the claim — the count of what the commit adds.
#
# Nothing else is. A message may legitimately count subsets along the way ("the
# ten tests the outage bought", "removing the rule fails one test"), and reading
# the first number next to the word "tests" picks one of those up instead. It
# did, on the commit that introduced this script: the message claimed eighteen
# and the gate read ten out of a sentence three lines above it.
#
# So a claim is `<number> test(s), mutation-proven` and nothing else. Accepting
# any count that begins a line was the next thing tried and it is no better:
# "Two tests were removed and nothing replaced them yet" begins a line and is
# not a claim either. The marker that actually distinguishes the summary
# sentence is the one the convention always writes.
#
# A count phrased any other way therefore goes unchecked. That is the honest
# trade: a gate that fired on "automated tests", "these tests" or a line that
# happens to open with a number would be wrong far more often than right, and a
# gate that cries wolf gets switched off.
#
# ── Exit codes ──────────────────────────────────────────────────────────────
#
#   0  AGREES     the message names a count and the diff matches it
#   1  DISAGREES  the message names a count the diff does not support
#   2  NO CLAIM   the message names no count, which is normal and fine

set -eu

# Number words, one word at a time. Tens and units are combined by the caller.
word_value() {
	case $(printf '%s' "$1" | tr 'A-Z' 'a-z') in
	zero) printf '0' ;;
	one) printf '1' ;;
	two) printf '2' ;;
	three) printf '3' ;;
	four) printf '4' ;;
	five) printf '5' ;;
	six) printf '6' ;;
	seven) printf '7' ;;
	eight) printf '8' ;;
	nine) printf '9' ;;
	ten) printf '10' ;;
	eleven) printf '11' ;;
	twelve) printf '12' ;;
	thirteen) printf '13' ;;
	fourteen) printf '14' ;;
	fifteen) printf '15' ;;
	sixteen) printf '16' ;;
	seventeen) printf '17' ;;
	eighteen) printf '18' ;;
	nineteen) printf '19' ;;
	twenty) printf '20' ;;
	thirty) printf '30' ;;
	forty) printf '40' ;;
	fifty) printf '50' ;;
	sixty) printf '60' ;;
	seventy) printf '70' ;;
	eighty) printf '80' ;;
	ninety) printf '90' ;;
	*) return 1 ;;
	esac
}

# A token before the word "tests": digits, a number word, or `forty-two`.
token_value() {
	case $1 in
	'' | *[!0-9]*) ;;
	*)
		printf '%s' "$1"
		return 0
		;;
	esac
	case $1 in
	*-*)
		tens=$(word_value "${1%%-*}") || return 1
		units=$(word_value "${1#*-}") || return 1
		# `twenty-one`, not `one-twenty` and not `twenty-thirty`.
		[ "$tens" -ge 20 ] || return 1
		[ "$units" -ge 1 ] && [ "$units" -le 9 ] || return 1
		printf '%s' $((tens + units))
		return 0
		;;
	esac
	word_value "$1"
}

classify() {
	actual=$1
	message=$(cat)

	claim=""
	# The summary sentence, by the marker the convention always writes. The
	# last match wins, because the summary comes after whatever the body
	# counted on the way.
	for token in $(printf '%s\n' "$message" \
		| grep -oiE '[A-Za-z0-9-]+ tests?, mutation-proven' \
		| sed -e 's/, mutation-proven$//' -e 's/ tests\{0,1\}$//'); do
		if value=$(token_value "$token" 2>/dev/null); then
			claim=$value
		fi
	done

	if [ -z "$claim" ]; then
		printf 'NO CLAIM: the message names no test count.\n'
		return 2
	fi

	if [ "$claim" -eq "$actual" ]; then
		printf 'AGREES: the message says %s and the diff adds %s.\n' "$claim" "$actual"
		return 0
	fi

	printf 'DISAGREES: the message says %s tests and the diff adds %s.\n' \
		"$claim" "$actual"
	printf '  A count in a commit message is a claim nobody can check without\n'
	printf '  the diff, so it is the one number worth deriving rather than\n'
	printf '  typing. Fix the message, or the tests.\n'
	return 1
}

if [ "${1:-}" = "--classify" ]; then
	[ $# -ge 2 ] || {
		printf 'usage: %s --classify <actual count>   (message on stdin)\n' "$0" >&2
		exit 64
	}
	classify "$2"
	exit $?
fi

printf 'usage: %s --classify <actual count>   (message on stdin)\n' "$0" >&2
exit 64
