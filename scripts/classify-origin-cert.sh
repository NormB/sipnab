#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Is the origin's certificate load-bearing, and therefore worth failing on?
#
#   classify-origin-cert.sh --classify <cert exit code> <site status>
#
# ── Why a dead certificate is not always a failure ──────────────────────────
#
# On 2026-09-11 the origin certificate expired, the CDN was validating it, and
# every visitor got a 526. The fix that brought the site back moved the CDN to a
# mode that terminates TLS at the edge with its own certificate and reaches the
# origin over plain HTTP. The origin certificate is still dead, and now decides
# nothing a visitor can see.
#
# A daily job that fails on it is then red every single morning for a fault
# nobody can observe, and a permanently red check is one nobody reads — which is
# how the next real one gets missed. But silence is not right either: the leg
# between the CDN and the origin now carries no TLS at all, and that is worth
# saying out loud once a day.
#
# ── How the mode is inferred ────────────────────────────────────────────────
#
# The CDN's encryption mode cannot be read from here without a credential. It
# does not need to be: the only question is whether anybody can load the page.
# If the site serves, the CDN is plainly not refusing the origin, so the
# certificate is not load-bearing today. Put the CDN back into a validating mode
# with a dead origin and the site answers 526 — which arrives here as an outage
# on the very next run, with no setting to keep in step.
#
# ── Exit codes ──────────────────────────────────────────────────────────────
#
#   0  OK         the origin certificate has time left
#   1  OUTAGE     the certificate is unusable AND the site is not serving
#   2  TOLERATED  unusable, but the site serves — the CDN is not validating it

set -eu

classify() {
	cert=$1
	status=$2

	case "$cert" in
	'' | *[!0-9]*)
		printf 'OUTAGE: %s is not a verdict from the certificate check.\n' \
			"${cert:-<empty>}"
		printf '  A checker whose own output cannot be read is not a pass.\n'
		return 1
		;;
	esac

	if [ "$cert" -eq 0 ]; then
		printf 'OK: the origin certificate has time left.\n'
		return 0
	fi

	case "$status" in
	2??)
		printf 'TOLERATED: the origin certificate is unusable and the site serves anyway (%s).\n' \
			"$status"
		printf '  The CDN is terminating TLS at the edge and is not validating\n'
		printf '  the origin, so no visitor can be hurt by this today.\n'
		printf '  What it does mean: the leg between the CDN and the origin is\n'
		printf '  UNENCRYPTED. To close it, take the CDN proxy off the records\n'
		printf '  long enough for the origin to be issued a certificate, put the\n'
		printf '  proxy back, and choose the mode that encrypts without\n'
		printf '  validating.\n'
		return 2
		;;
	esac

	printf 'OUTAGE: the origin certificate is unusable and the site answers %s.\n' \
		"$status"
	printf '  The CDN is refusing an origin it cannot validate. This is the\n'
	printf '  2026-09-11 failure exactly, and it is self-sustaining: the renewal\n'
	printf '  challenge has to reach the origin and cannot while the edge\n'
	printf '  refuses to talk to it.\n'
	return 1
}

if [ "${1:-}" = "--classify" ]; then
	[ $# -ge 3 ] || {
		printf 'usage: %s --classify <cert exit code> <site status>\n' "$0" >&2
		exit 64
	}
	classify "$2" "$3"
	exit $?
fi

printf 'usage: %s --classify <cert exit code> <site status>\n' "$0" >&2
exit 64
