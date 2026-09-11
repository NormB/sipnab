#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# How long until the published site's certificate expires, and is that enough.
#
#   check-cert-expiry.sh [host] [warn-days]   fetch the certificate and judge
#   check-cert-expiry.sh --classify <days>    judge a day count, and nothing else
#
# ── The outage this exists for ──────────────────────────────────────────────
#
# On 2026-09-11 the origin certificate for sipnab.com expired at 14:10 UTC. The
# CDN was set to a strict SSL mode, refused an origin it could not validate, and
# returned 526 to every visitor. Nothing warned. Nothing was watching the date.
#
# The renewal had been failing for some time and could not announce it either:
# the published CNAME named `www.sipnab.com` while GitHub Pages was configured
# for the apex, so every deploy flipped the custom domain and each flip dropped
# the certificate. A certificate that is never renewed still looks perfectly
# healthy right up to the minute it does not.
#
# So the thing to watch is not "is the site up" — by then it is too late — but
# "how many days are left", checked on a schedule, with a margin wide enough to
# fix a renewal that has silently stopped working.
#
# ── Why the margin is what it is ────────────────────────────────────────────
#
# Let's Encrypt issues for 90 days and renews at 30 remaining. A warning at 21
# days therefore fires only when renewal has ALREADY failed at least once,
# which is the signal worth having: it is not "renewal is due", it is "renewal
# is not happening". Three weeks is also enough to notice on a Monday, find
# somebody with CDN access, and still have a fortnight spare.
#
# ── Exit codes ──────────────────────────────────────────────────────────────
#
#   0  OK       more days remain than the margin
#   1  EXPIRING within the margin, and renewal has therefore already failed
#   2  EXPIRED  no days remain; the site is down or about to be
#   3  UNKNOWN  the certificate could not be read at all

set -eu

DEFAULT_WARN_DAYS=21

# Is this a whole number, sign and all, and nothing else?
#
# The guard this replaces was the character class `*[!0-9-]*`, which admits a
# `-` ANYWHERE rather than only at the front -- so `1-2`, `12-` and a bare `-`
# walked past it. `[` then refused them with "Illegal number", and because a
# failing command in an `if` condition is exempt from `set -e`, both
# comparisons fell through to the last line of the function: OK, exit 0. The
# one input this script exists to refuse came out as its healthiest verdict,
# with the diagnosis on stderr where no exit code carries it.
#
# Stripping ONE leading `-` and requiring digits after it is the whole rule.
is_whole_number() {
	case ${1#-} in
	'' | *[!0-9]*) return 1 ;;
	esac
	return 0
}

classify() {
	days=$1
	# `${2-...}`, not `${2:-...}`: an ABSENT margin takes the default, an
	# explicitly empty one is a typo and is refused below. Collapsing the two
	# is how a mistyped threshold becomes an invisible working one.
	warn=${2-$DEFAULT_WARN_DAYS}

	if ! is_whole_number "$days"; then
		printf 'UNKNOWN: %s is not a number of days.\n' "${days:-<empty>}"
		printf '  The certificate could not be read. That is not the same as a\n'
		printf '  healthy one and must never be scored as a pass.\n'
		return 3
	fi

	# A margin decides every verdict this script gives, so one that cannot be
	# read is a watcher that is not watching. Refused rather than defaulted,
	# because a silently-defaulted margin looks exactly like a working one.
	case $warn in
	'' | *[!0-9]*)
		printf 'UNKNOWN: a margin of %s is not a number of days.\n' "${warn:-<empty>}"
		printf '  The threshold was unreadable, so nothing here was compared\n'
		printf '  against anything. That is not a pass.\n'
		return 3
		;;
	esac

	if [ "$days" -le 0 ]; then
		printf 'EXPIRED: the certificate expired %s day(s) ago.\n' "$((0 - days))"
		printf '  Under a strict CDN SSL mode this is an outage, and a\n'
		printf '  self-sustaining one: the renewal challenge has to reach the\n'
		printf '  origin, and it cannot while the edge refuses to talk to it.\n'
		printf '  Relax the mode until the origin holds a certificate again.\n'
		return 2
	fi

	if [ "$days" -le "$warn" ]; then
		printf 'EXPIRING: %s day(s) left, under a %s day margin.\n' "$days" "$warn"
		printf '  Automatic renewal happens at 30 days remaining, so being inside\n'
		printf '  this margin means renewal has ALREADY failed at least once. Go\n'
		printf '  and find out why rather than waiting for the next attempt.\n'
		return 1
	fi

	printf 'OK: %s day(s) left.\n' "$days"
	return 0
}

if [ "${1:-}" = "--classify" ]; then
	[ $# -ge 2 ] || {
		printf 'usage: %s --classify <days> [warn-days]\n' "$0" >&2
		exit 64
	}
	classify "$2" "${3-$DEFAULT_WARN_DAYS}"
	exit $?
fi

HOST=${1:-sipnab.com}
WARN=${2-$DEFAULT_WARN_DAYS}

# WHICH certificate, and this is the whole trap. Connecting to the hostname
# reaches the CDN and reads the EDGE certificate, which was perfectly healthy
# throughout the 2026-09-11 outage — issued by a different CA, expiring three
# months later, and completely unrelated to the one that had expired. A check
# pointed at the public name would have been green while every visitor got a
# 526.
#
# The certificate that matters is the ORIGIN's, so this connects to the origin
# address with SNI for the hostname. `SIPNAB_ORIGIN` names it; without one this
# reads the edge and says so rather than pretending it checked.
ORIGIN=${SIPNAB_ORIGIN:-}
if [ -n "$ORIGIN" ]; then
	target=$ORIGIN
	which_cert="origin $ORIGIN"
else
	target=$HOST
	which_cert="edge (set SIPNAB_ORIGIN to check the origin, which is the one that expires unwatched)"
fi

not_after=$(echo \
	| openssl s_client -connect "$target:443" -servername "$HOST" 2>/dev/null \
	| openssl x509 -noout -enddate 2>/dev/null \
	| sed 's/^notAfter=//')

if [ -z "$not_after" ]; then
	classify "" "$WARN"
	exit $?
fi

end=$(date -u -d "$not_after" +%s 2>/dev/null || printf '')
if [ -z "$end" ]; then
	classify "" "$WARN"
	exit $?
fi
now=$(date -u +%s)
days=$(( (end - now) / 86400 ))

printf 'certificate for %s via %s expires %s\n' "$HOST" "$which_cert" "$not_after"
classify "$days" "$WARN"
