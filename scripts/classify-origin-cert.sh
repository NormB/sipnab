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
#   3  BLOCKED    the edge refused the checker, so nothing about the origin
#                 follows from it in either direction

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

	# The edge answered, and said no to US. Bot protection, a rate limit, a
	# WAF rule -- the site may be perfectly healthy for everyone else. Found
	# on this check's first real run, where a GitHub runner got 403 and the
	# verdict came back as the outage: one answer standing for several
	# situations, which is the exact mistake this file was built to stop.
	#
	# It is not a pass either. Folding it into OK would make the watcher go
	# quiet the moment it stopped being able to see anything.
	case "$status" in
	403 | 429)
		printf 'BLOCKED: the edge refused the check itself (%s).\n' "$status"
		printf '  Bot protection, a rate limit or a firewall rule. The edge is\n'
		printf '  healthy and declined to talk to this client, so nothing about\n'
		printf '  the origin certificate follows from it in either direction.\n'
		printf '  Let the checker identify itself, or allow it at the edge.\n'
		return 3
		;;
	esac

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

# ── Asking whether the site serves ──────────────────────────────────────────
#
# One sample cannot tell a network hiccup from a site that is down. On
# 2026-09-22 a runner's single curl got no answer inside 20 s, the status came
# back 000, and with the origin certificate already dead that read as the
# outage above; the re-run passed. So ask up to three times, stop at the first
# answer -- any HTTP status, a 403 included, because the edge answered -- and
# print exactly one code: 000 only when no attempt got a response.
#
# The inline probe this replaces printed 000000 on a failure: curl's -w writes
# 000 when nothing answers, and its `|| printf '000'` fallback added another.
#
# Named, not anonymous: the first real run of the watcher got a 403 from the
# edge's bot protection, and a checker that says who it is gets through.
probe() {
	url=$1
	attempts=3
	pause=${SIPNAB_PROBE_PAUSE:-10}
	case "$pause" in
	'' | *[!0-9]*)
		printf 'SIPNAB_PROBE_PAUSE must be whole seconds, not %s\n' "$pause" >&2
		return 64
		;;
	esac
	i=1
	while :; do
		code=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' \
			--user-agent 'sipnab-cert-watcher/1.0 (+https://github.com/NormB/sipnab)' \
			"$url" 2>/dev/null) || true
		case "$code" in
		'' | 000) ;;
		*)
			printf '%s\n' "$code"
			return 0
			;;
		esac
		[ "$i" -ge "$attempts" ] && break
		i=$((i + 1))
		sleep "$pause"
	done
	printf '000\n'
	return 0
}

if [ "${1:-}" = "--probe" ]; then
	[ $# -ge 2 ] || {
		printf 'usage: %s --probe <url>\n' "$0" >&2
		exit 64
	}
	probe "$2"
	exit $?
fi

if [ "${1:-}" = "--classify" ]; then
	[ $# -ge 3 ] || {
		printf 'usage: %s --classify <cert exit code> <site status>\n' "$0" >&2
		exit 64
	}
	classify "$2" "$3"
	exit $?
fi

printf 'usage: %s --classify <cert exit code> <site status>\n       %s --probe <url>\n' "$0" "$0" >&2
exit 64
