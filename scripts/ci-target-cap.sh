#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Remove a persistent cargo target directory when it has grown past a cap.
#
#   scripts/ci-target-cap.sh <dir> <max>
#
# <dir>  absolute path of the target directory. A directory that does not
#        exist yet (a runner's first job) is not an error.
# <max>  the cap: a positive integer followed by G (GiB) or M (MiB), for
#        example 64G. The unit is required so that a bare number cannot be
#        read as the wrong one.
#
# Exit 0: the directory is under the cap and kept, was over it and removed,
#         or does not exist. One line says which, with the measured size.
# Exit 2: bad arguments; nothing is removed.
#
# The self-hosted runners keep one target directory each between jobs (see
# .github/actions/runner-target/action.yml, which calls this before every
# build). Cargo never deletes old artifacts, so without a bound the directory
# grows with every feature set and every Cargo.lock change. Removing it
# entirely when it passes the cap costs one cold build and needs no knowledge
# of cargo's layout.
#
# The size is disk usage (du), not apparent size: it is the disk this bounds.
# The test suite drives this with caps in MiB on small temporary directories.

set -euo pipefail

usage() {
	echo "usage: $0 <absolute-dir> <max: N followed by G or M, e.g. 64G>" >&2
	exit 2
}

[ $# -eq 2 ] || usage
dir=$1
max=$2

case $dir in
/*) ;;
*) usage ;;
esac
# Never "/": a mistyped variable that expands to the root must not reach rm.
[ "${dir%/}" != "" ] || usage

case $max in
*[!0-9GM]* | [GM]* | *[GM]*[GM]* | *[0-9]) usage ;;
*G) unit_kib=$((1024 * 1024)) ;;
*M) unit_kib=1024 ;;
*) usage ;;
esac
count=${max%[GM]}
case $count in
'' | *[!0-9]*) usage ;;
esac
# Base 10 explicitly, so a leading zero is not read as octal.
count=$((10#$count))
[ "$count" -gt 0 ] || usage
cap_kib=$((count * unit_kib))

if [ ! -e "$dir" ]; then
	echo "ci-target-cap: $dir does not exist yet; nothing to bound"
	exit 0
fi

used_kib=$(du -sk -- "$dir" | cut -f1)

if [ "$used_kib" -gt "$cap_kib" ]; then
	rm -rf -- "$dir"
	echo "ci-target-cap: $dir used ${used_kib} KiB, over the ${max} cap (${cap_kib} KiB); removed, this build starts cold"
else
	echo "ci-target-cap: $dir uses ${used_kib} KiB, within the ${max} cap (${cap_kib} KiB); kept"
fi
