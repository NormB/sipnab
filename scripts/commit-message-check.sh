#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# commit-message-check.sh  < pre-push lines
#
# Refuses a push that sends a commit whose message names a private identity or
# credits an AI assistant, naming each such commit and the line. It reads git's
# pre-push input, one `<local ref> <local sha> <remote ref> <remote sha>` line
# per ref, and judges exactly the commits scripts/lib-pushed-range.sh says the
# push sends: a commit already on a remote is not this push's.
#
# Each message is read whole (SIPNAB_MESSAGE_WHOLE=1): it is what git stored,
# and nothing will cut it now. The rule is scripts/check-message-identity.sh,
# the one the commit-msg hook and CI's pull-request check run, so a message the
# commit-msg hook never saw (`--no-verify`, or a commit made before the hook
# knew the form) is caught before it leaves the machine.
#
# Exit 0: every message clean. 1: a message named something, or a message
# could not be checked, which refuses rather than passes.
set -euo pipefail

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
# shellcheck source=scripts/lib-pushed-range.sh
. "$here/lib-pushed-range.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

bad=0
while read -r local_ref local_sha _remote_ref remote_sha; do
	range=()
	while IFS= read -r word; do
		range+=("$word")
	done < <(pushed_range "${local_sha:-}" "${remote_sha:-}")
	[ "${#range[@]}" -gt 0 ] || continue
	if ! shas=$(git log --format=%H "${range[@]}"); then
		echo "Cannot list the commits pushed for $local_ref, so none is checked."
		exit 1
	fi
	for sha in $shas; do
		git log -1 --format=%B "$sha" >"$work/message"
		out=$(SIPNAB_MESSAGE_WHOLE=1 bash "$here/check-message-identity.sh" "$work/message" 2>&1) \
			&& rc=0 || rc=$?
		case $rc in
		0) ;;
		1)
			bad=1
			echo "  ${sha:0:7} $(git log -1 --format=%s "$sha")"
			printf '%s\n' "$out" | sed 's/^/  /'
			;;
		*)
			echo "  ${sha:0:7}: the message check did not run, so the push is refused:"
			printf '%s\n' "$out" | sed 's/^/  /'
			exit 1
			;;
		esac
	done
done

if [ "$bad" -ne 0 ]; then
	echo "Reword each commit named above (git rebase -i, then reword) and push again."
	exit 1
fi
