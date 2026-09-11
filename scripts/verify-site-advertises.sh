#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Does the published site actually offer a release, and if not, WHY not.
#
#   verify-site-advertises.sh <version> [url]   fetch and judge
#   verify-site-advertises.sh --classify <version>   judge stdin, and nothing else
#
# ── The check this replaces, and the outage it missed ───────────────────────
#
# The release flow said "verify from the live page, not from a green deploy",
# and the command it gave was:
#
#     curl -s https://sipnab.com/download/ | grep -c <version>
#
# That prints `0` when the site advertises the wrong version. It also prints
# `0` when the site is DOWN, when DNS fails, when the certificate has expired,
# and when the body is empty — five different situations, one indistinguishable
# answer, and only one of them is about the release.
#
# On 2026-09-11 the origin certificate expired at 14:10 UTC. Cloudflare was set
# to Full (strict), refused an origin it could not validate, and returned 526 to
# every visitor. The check returned nothing, which is exactly what it returns on
# a healthy site advertising the wrong version, and the outage went unremarked
# for half an hour by the person running the check.
#
# So this script's job is not to answer yes or no. It is to say WHICH of those
# situations is happening, because the operator response differs completely: a
# stale version means land the advertisement commit, and an expired origin
# certificate means go and change a CDN setting.
#
# ── Exit codes, one per situation ───────────────────────────────────────────
#
#   0  OK          the page is healthy and names the version
#   1  STALE       the page is healthy and names a different version
#   2  UNREACHABLE DNS or connection failure
#   3  TLS         the certificate could not be validated
#   4  HTTP        the server answered, with an error status
#   5  EMPTY       a success status carrying no body
#
# `--classify` reads `<status code>` on the first line and the body after it, so
# `site_liveness_test` drives every one of these without a network.

set -eu

# Cloudflare's status codes for an origin it cannot reach or validate. These are
# NOT ordinary server errors: they say the edge is healthy and the thing behind
# it is not, which is a different job to go and do.
CF_ORIGIN_CERT_INVALID=526
CF_ORIGIN_UNREACHABLE=523
CF_ORIGIN_DOWN=521
CF_ORIGIN_TIMEOUT=522

classify() {
	want=$1
	status=""
	body=""
	first=1
	while IFS= read -r line || [ -n "$line" ]; do
		if [ "$first" = 1 ]; then
			status=$line
			first=0
			continue
		fi
		body="$body$line
"
	done

	case "$status" in
	000)
		printf 'UNREACHABLE: the host did not answer.\n'
		printf '  DNS, routing or a refused connection. Nothing about the release\n'
		printf '  can be concluded from this, in either direction.\n'
		return 2
		;;
	"$CF_ORIGIN_CERT_INVALID")
		printf 'TLS: the CDN could not validate the origin certificate (%s).\n' "$status"
		printf '  The edge is healthy and the site behind it is unreachable to it.\n'
		printf '  Usually an EXPIRED origin certificate under a strict SSL mode, and\n'
		printf '  that state is self-sustaining: the renewal challenge has to reach\n'
		printf '  the origin, and it cannot while the edge refuses to talk to it.\n'
		printf '  Relax the mode until the origin has a certificate again.\n'
		return 3
		;;
	"$CF_ORIGIN_UNREACHABLE" | "$CF_ORIGIN_DOWN" | "$CF_ORIGIN_TIMEOUT")
		printf 'HTTP: the CDN answered %s — it cannot reach the origin.\n' "$status"
		printf '  The release may be perfectly published; nobody can see it.\n'
		return 4
		;;
	2??) ;;
	*)
		printf 'HTTP: the server answered %s.\n' "$status"
		printf '  A page that errors advertises nothing, whatever it contains.\n'
		return 4
		;;
	esac

	# A success status with nothing in it is the shape that reads as "the
	# version is absent" to a bare grep, and it is not.
	if [ -z "$(printf '%s' "$body" | tr -d '[:space:]')" ]; then
		printf 'EMPTY: %s with no body.\n' "$status"
		printf '  A bare `grep -c` scores this the same as a healthy page naming\n'
		printf '  the wrong version. It is not the same and needs a different fix.\n'
		return 5
	fi

	# An error page can easily mention a version string — Cloudflare's own
	# interstitials carry the hostname, and a cached 404 can carry anything.
	# Requiring the download page's own furniture keeps a match on an error
	# page from reading as success.
	if ! printf '%s' "$body" | grep -qi 'sha256\|checksum\|download'; then
		printf 'EMPTY: %s carrying no download page.\n' "$status"
		printf '  The body does not look like the page being checked, so a version\n'
		printf '  found in it would be a match on somebody else document.\n'
		return 5
	fi

	if printf '%s' "$body" | grep -qF "$want"; then
		printf 'OK: the page names %s.\n' "$want"
		return 0
	fi

	printf 'STALE: the page is healthy and does not name %s.\n' "$want"
	printf '  This is the one verdict that is actually about the release: the\n'
	printf '  advertisement commit has not landed, or has not deployed.\n'
	return 1
}

if [ "${1:-}" = "--classify" ]; then
	[ $# -ge 2 ] || {
		printf 'usage: %s --classify <version>\n' "$0" >&2
		exit 64
	}
	classify "$2"
	exit $?
fi

VERSION=${1:-}
URL=${2:-https://sipnab.com/download/}
if [ -z "$VERSION" ]; then
	printf 'usage: %s <version> [url]\n' "$0" >&2
	printf '   or: %s --classify <version>   (judge stdin)\n' "$0" >&2
	exit 64
fi

# The status on the first line, the body after it, which is the shape
# `--classify` reads. `--write-out` still prints on a transport failure, where
# it reports 000 — which is how UNREACHABLE is told from a server that answered.
body=$(curl -sS --max-time 20 "$URL" 2>/dev/null || true)
status=$(curl -sS --max-time 20 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null || printf '000')
printf '%s\n%s' "$status" "$body" | classify "$VERSION"
