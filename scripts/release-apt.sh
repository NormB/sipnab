#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# release-apt.sh: the release builds' package installs in the bookworm
# containers. Sourced by .github/workflows/release.yml's "Install build deps
# (bookworm container)"; run as `bash scripts/release-apt.sh <function>
# <args...>` by scripts/tests/test_release_apt.py.
#
# Two defects of 2026-11-16 (release run 43881101798, v0.5.260):
#
# - RELEASE-AARCH64-DEPS-UNPINNED. libpcap-dev:arm64 pulls libc6-dev:arm64,
#   which needs linux-libc-dev:arm64. bookworm-security carried arm64
#   6.1.192-2 before amd64 had more than 6.1.192-1, and the package is
#   `Multi-Arch: same`: both architectures must hold one version, so apt
#   could not resolve the install. `multiarch_pins` names, for each such
#   package, the newest version BOTH architectures' indexes carry, and the
#   step installs both at it.
# - RELEASE-APT-BOUNDED-MESSAGE-SAYS-TIMEOUT-FOR-ANY-FAILURE. The step said
#   "did not complete within 600s ... re-run the job" for an apt run that
#   ended in about 7 s on dependency resolution, which a re-run cannot fix.
#   `apt_failure_kind` reads the exit status and apt's own lines, and
#   `apt_failure_message` says what each kind means.

# apt_failure_kind <exit status> <log file>: prints none, timeout, fetch,
# resolve or other. A timeout is `timeout`'s 124, or 137 when it had to
# kill. A download failure comes before a resolution failure: a failed
# index download leaves "Unable to locate package" behind it, and that one
# a re-run can fix.
apt_failure_kind() {
	local rc="$1" log="$2"
	case "$rc" in
	0) echo none; return 0 ;;
	124 | 137) echo timeout; return 0 ;;
	esac
	if [ -f "$log" ] && grep -q -F -e 'Failed to fetch ' -e 'Temporary failure resolving' \
		-e 'Could not connect to' -e 'Hash Sum mismatch' -e 'failed to download' "$log"; then
		echo fetch
	elif [ -f "$log" ] && grep -q -F -e 'Unable to correct problems' -e 'is not going to be installed' \
		-e 'Unable to locate package' -e 'was not found' -e 'unmet dependencies' \
		-e 'Broken packages' "$log"; then
		echo resolve
	else
		echo other
	fi
}

# apt_failure_message <kind> <what> <seconds> <exit status>: the one
# `::error::` line for that kind of failure.
apt_failure_message() {
	local kind="$1" what="$2" secs="$3" rc="$4"
	case "$kind" in
	timeout)
		echo "::error::FETCH failure, not a build failure: apt-get $what did not complete within ${secs}s against the Debian archives. No sipnab source was compiled and nothing in this repository is broken — re-run the job."
		;;
	fetch)
		echo "::error::FETCH failure, not a build failure: apt-get $what could not download from the Debian archives (exit $rc; the lines above name the host). No sipnab source was compiled and nothing in this repository is broken — re-run the job."
		;;
	resolve)
		echo "::error::DEPENDENCY failure, not a fetch failure: apt-get $what could not resolve the packages it was asked for (exit $rc; the lines above name them). A re-run fails the same way until the archives agree; no sipnab source was compiled."
		;;
	other)
		echo "::error::apt-get $what failed with exit $rc (the lines above say why). No sipnab source was compiled."
		;;
	*)
		echo "apt_failure_message: unknown kind: $kind" >&2
		return 2
		;;
	esac
}

# madison_versions: reads `apt-cache madison` lines on stdin and prints the
# version column, once each, in the order apt-cache gave.
madison_versions() {
	awk -F'|' 'NF >= 3 { v = $2; gsub(/^[ \t]+|[ \t\r]+$/, "", v); if (v != "" && !seen[v]++) print v }'
}

# common_version <file A> <file B>: the newest version, by dpkg's ordering,
# that both files list (one a line); nothing and exit 1 when none is.
common_version() {
	local best="" v
	while IFS= read -r v; do
		v="${v%"${v##*[![:space:]]}"}"
		[ -n "$v" ] || continue
		if ! awk -v want="$v" '{ sub(/[ \t\r]+$/, "") } $0 == want { found = 1 } END { exit !found }' "$2"; then
			continue
		fi
		if [ -z "$best" ] || dpkg --compare-versions "$v" gt "$best"; then
			best="$v"
		fi
	done < "$1"
	[ -n "$best" ] || return 1
	echo "$best"
}

# multiarch_pins <package>...: for each `Multi-Arch: same` package, the
# newest version the amd64 and arm64 indexes both carry, printed as
# `pkg:amd64=V pkg:arm64=V`, one word a line, after `apt-get update` has read
# both indexes. Refuses (exit 1, `::error::` on stderr, nothing on stdout)
# when any package has no such version.
multiarch_pins() {
	if [ "$#" -eq 0 ]; then
		echo "::error::multiarch_pins: no package named" >&2
		return 1
	fi
	local dir pkg arch v out=""
	dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/multiarch-pins.XXXXXX")" || return 1
	for pkg in "$@"; do
		for arch in amd64 arm64; do
			if ! apt-cache madison "$pkg:$arch" > "$dir/$arch.madison"; then
				echo "::error::apt-cache madison $pkg:$arch failed, so its versions are unknown" >&2
				rm -rf "$dir"
				return 1
			fi
			madison_versions < "$dir/$arch.madison" > "$dir/$arch"
		done
		if ! v="$(common_version "$dir/amd64" "$dir/arm64")"; then
			echo "::error::DEPENDENCY failure, not a fetch failure: no version of $pkg is in both the amd64 index ($(tr '\n' ' ' < "$dir/amd64")) and the arm64 index ($(tr '\n' ' ' < "$dir/arm64")). It is Multi-Arch: same, so both must hold one version; a re-run fails the same way until the archives agree." >&2
			rm -rf "$dir"
			return 1
		fi
		out="$out$pkg:amd64=$v"$'\n'"$pkg:arm64=$v"$'\n'
	done
	rm -rf "$dir"
	printf '%s' "$out"
}

# pins_line <pin>...: prints the pins multiarch_pins computed as one
# `::notice title=multiarch pins::` line, a line of the job log and an
# annotation of the job, so a release can quote the versions it installed
# (RELEASE-APT-PINS-NOT-PRINTED: 0.5.262 applied the pins and no line named
# them). Refuses (exit 1, one `::error::` line on stderr, nothing on stdout)
# a word that is not `package:amd64=version` or `package:arm64=version`, and
# a package that is not pinned exactly once for each architecture at one
# version. The character classes are spelled out so that no locale widens
# them.
pins_line() {
	if [ "$#" -eq 0 ]; then
		echo "::error::pins_line: no pin named" >&2
		return 1
	fi
	local word pkg arch ver i found
	local -a names=() amd=() arm=()
	local lower='abcdefghijklmnopqrstuvwxyz0123456789'
	local re="^([${lower}][${lower}.+-]+):(amd64|arm64)=([0123456789][${lower}ABCDEFGHIJKLMNOPQRSTUVWXYZ.+~:-]*)\$"
	for word in "$@"; do
		if ! [[ "$word" =~ $re ]]; then
			echo "::error::pins_line: '$word' is not a pin of the form package:amd64=version or package:arm64=version" >&2
			return 1
		fi
		pkg="${BASH_REMATCH[1]}"
		arch="${BASH_REMATCH[2]}"
		ver="${BASH_REMATCH[3]}"
		found=""
		for i in "${!names[@]}"; do
			if [ "${names[$i]}" = "$pkg" ]; then
				found="$i"
				break
			fi
		done
		if [ -z "$found" ]; then
			found="${#names[@]}"
			names+=("$pkg")
			amd+=("")
			arm+=("")
		fi
		if [ "$arch" = amd64 ]; then
			if [ -n "${amd[$found]}" ]; then
				echo "::error::pins_line: $pkg is pinned more than once for amd64" >&2
				return 1
			fi
			amd[found]="$ver"
		else
			if [ -n "${arm[$found]}" ]; then
				echo "::error::pins_line: $pkg is pinned more than once for arm64" >&2
				return 1
			fi
			arm[found]="$ver"
		fi
	done
	# Each entry holds at least one version, so a missing one differs too.
	for i in "${!names[@]}"; do
		if [ "${amd[$i]}" != "${arm[$i]}" ]; then
			echo "::error::pins_line: ${names[$i]} is not pinned at one version for both architectures (amd64: ${amd[$i]:-none}, arm64: ${arm[$i]:-none}); Multi-Arch: same needs one" >&2
			return 1
		fi
	done
	printf '::notice title=multiarch pins::%s\n' "$*"
}

# apt_bounded <seconds> <apt args...>: apt-get, bounded and retried, with
# apt's own lines in the job log and, on failure, the one line that says
# which kind of failure it was; exits the shell with 1 on failure.
apt_bounded() {
	local secs="$1"
	shift
	local what="$1" log rc=0
	log="$(mktemp "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/apt-bounded.XXXXXX")" || exit 1
	# apt neither retries nor gives up on its own. Acquire::Retries covers a
	# dropped connection; the Timeouts cover a stalled read; `timeout` covers
	# the case neither does, a host that keeps the socket alive and sends
	# nothing.
	timeout "$secs" apt-get -o Acquire::Retries=5 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 "$@" > "$log" 2>&1 || rc=$?
	cat "$log"
	if [ "$rc" -ne 0 ]; then
		apt_failure_message "$(apt_failure_kind "$rc" "$log")" "$what" "$secs" "$rc"
		rm -f "$log"
		exit 1
	fi
	rm -f "$log"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
	fn="$1"
	shift
	"$fn" "$@"
fi
