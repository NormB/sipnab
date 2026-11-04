#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# Refuse to start a CI job on a machine short of disk.
#
#   scripts/ci-disk-floor.sh <GB> [path]
#
# <GB>   the free space, in GiB, the job needs on the filesystem of [path].
# [path] defaults to the current directory, the job's workspace.
#
# Exit 0: at least <GB> GiB free. Exit 1: less, with a workflow error that
# says how much is free and how much the job needs. Exit 2: bad arguments.
#
# The x86_64 self-hosted runner is a virtual machine on a host that runs other
# virtual machines; a build that filled its disk would stop them as well.
# tests/ci_runner_target_test.rs requires this as the step after checkout of
# every job on that runner, and drives this script.

set -euo pipefail

[ $# -ge 1 ] && [ $# -le 2 ] || { echo "usage: $0 <GB> [path]" >&2; exit 2; }
need=$1
path=${2:-.}
case $need in
'' | *[!0-9]*) echo "ci-disk-floor: <GB> must be a whole number, got '$need'" >&2; exit 2 ;;
esac

# POSIX df: the fourth column of the second line is the available 1024-byte
# blocks.
avail_kib=$(df -Pk "$path" | awk 'NR == 2 { print $4 }')
avail_gib=$((avail_kib / 1024 / 1024))
if [ "$avail_gib" -lt "$need" ]; then
	echo "::error::only ${avail_gib} GiB free on $(df -P "$path" | awk 'NR == 2 { print $6 }'); this job needs ${need} GiB. Free space on the runner, or route the job elsewhere."
	exit 1
fi
echo "ci-disk-floor: ${avail_gib} GiB free, ${need} GiB needed"
