#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# Refuse a published binary larger than the size ceiling the homepage and the
# build docs quote: binary_size_ceiling_mb in website/config.toml.
#
#   scripts/check-binary-size.sh <binary> [<config.toml>]
#
# Exit 0: at or under the ceiling; prints the size and a ::notice:: with the
#         bytes left.
# Exit 1: over the ceiling; prints a ::error:: naming the bytes and what to
#         change.
# Exit 2: nothing to judge: no such file, an empty file, no readable ceiling,
#         or a wrong argument count.
#
# One rule in one place. release.yml runs this on every musl artifact it
# builds, after the symbol split. .github/workflows/binary-size.yml runs it on
# a pull-request build of x86_64-unknown-linux-musl, made the way release.yml
# makes it, so a change that grows the binary fails on its pull request and
# not at the tag (backlog GATE-SIZE1: the first v0.5.228 Release run failed
# this step at 22,685,568 bytes against 20 MB, after GHCR had the image).
#
# Integer arithmetic only: `bc` is not guaranteed on a runner. The musl
# artifacts are measured on Linux runners; the test suite also runs the
# release step on macOS, so both GNU and BSD stat are read.

set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
	echo "usage: $0 <binary> [<config.toml>]" >&2
	exit 2
fi
bin=$1
config=${2:-"$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)/website/config.toml"}

if [ ! -f "$bin" ]; then
	echo "$0: cannot measure '$bin': no such file" >&2
	exit 2
fi

ceiling=""
if [ -r "$config" ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
		'binary_size_ceiling_mb = '*)
			if [[ "$line" =~ ^binary_size_ceiling_mb\ =\ \"([0-9]+)\" ]]; then
				ceiling=$((10#${BASH_REMATCH[1]}))
			fi
			break
			;;
		esac
	done <"$config"
fi
if [ -z "$ceiling" ] || [ "$ceiling" -lt 1 ]; then
	echo "$0: no binary_size_ceiling_mb = \"<whole number of MB, at least 1>\" line in $config" >&2
	exit 2
fi

# GNU stat first; BSD stat (macOS, where the suite also runs this) refuses
# -c and takes -f %z.
bytes=$(stat -L -c %s -- "$bin" 2>/dev/null || stat -L -f %z -- "$bin")
if [ "$bytes" -eq 0 ]; then
	echo "$0: cannot measure '$bin': the file is empty" >&2
	exit 2
fi
limit=$((ceiling * 1024 * 1024))

printf '%s is %s bytes (%s.%02d MB), ceiling %s MB\n' \
	"$bin" "$bytes" "$((bytes / 1048576))" "$((bytes % 1048576 * 100 / 1048576))" "$ceiling"
if [ "$bytes" -gt "$limit" ]; then
	echo "::error::$bin is $bytes bytes, over the ${ceiling} MB published on the homepage and in the build docs: shrink it, or raise binary_size_ceiling_mb in website/config.toml (and the claims it feeds)"
	exit 1
fi
echo "::notice::$bin is $((limit - bytes)) bytes under the ${ceiling} MB ceiling"
