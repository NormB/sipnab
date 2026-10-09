#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Remove the workspace's own build outputs from a cargo target directory
# before it is saved to the GitHub Actions cache.
#
#   scripts/ci-cache-prune.sh <dir>
#
# <dir>  absolute path of the target directory. A directory that does not
#        exist (a job that built nothing) is not an error.
#
# Exit 0: pruned, or nothing to prune. One line gives the size before and
#         after, in KiB.
# Exit 2: bad arguments; nothing is removed.
#
# What a later build reuses stays: dependency libraries (.rlib, .rmeta),
# proc-macro libraries (.so, .dylib, .dll), dep-info (.d), build-script
# outputs (build/) and fingerprints. What goes is what every change to the
# sources rebuilds anyway: the executables cargo links into <profile>/deps
# (test, bench and binary targets) and their copies at <profile>/, the
# examples/ directory, and incremental/ state. Profiles are found both at
# <dir>/<profile>/deps and, for a --target build, at
# <dir>/<triple>/<profile>/deps.
#
# The repository's cache holds at most 10 GB for every workflow together, and
# an entry nothing reads still counts against it. tests/ci_cache_policy_test.rs
# holds every cargo cache save in the workflows to running this first, and
# drives this script on temporary directories.

set -euo pipefail

usage() {
	echo "usage: $0 <absolute target dir>" >&2
	exit 2
}

[ $# -eq 1 ] || usage
dir=$1
case $dir in
/) usage ;;
/*) ;;
*) usage ;;
esac

if [ ! -d "$dir" ]; then
	echo "ci-cache-prune: $dir does not exist; nothing to prune"
	exit 0
fi

before=$(du -sk "$dir" | cut -f1)

# A profile directory is the parent of a `deps` directory one or two levels
# below the target directory. build/<pkg>/... is deeper and never matches.
find "$dir" -mindepth 2 -maxdepth 3 -type d -name deps | while IFS= read -r deps; do
	profile=$(dirname "$deps")
	# Executables a later build relinks. The library suffixes are excluded by
	# name because a proc-macro shared library carries the execute bit too.
	find "$deps" "$profile" -maxdepth 1 -type f -perm -u+x \
		! -name '*.so' ! -name '*.dylib' ! -name '*.dll' \
		! -name '*.rlib' ! -name '*.rmeta' ! -name '*.d' -exec rm -f {} +
	find "$deps" "$profile" -maxdepth 1 -type d -name '*.dSYM' -exec rm -rf {} +
	rm -rf "$profile/examples" "$profile/incremental"
done

after=$(du -sk "$dir" | cut -f1)
echo "ci-cache-prune: $dir ${before} KiB -> ${after} KiB"
