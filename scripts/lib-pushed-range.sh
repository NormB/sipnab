# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# shellcheck shell=bash
# Sourced by scripts/commit-signature-check.sh and scripts/commit-message-check.sh:
# which commits one pre-push line sends, decided in one place.

# pushed_range <local sha> <remote sha>
# Print, one per line, the `git log` arguments that select the commits the
# push sends for one ref: those reachable from <local sha> that no
# remote-tracking ref reaches, and, for an update, that <remote sha> does not
# reach either. <remote sha>..<local sha> alone is wrong for a branch rebased
# onto a newer main: it spans every commit main gained since the old base.
# Prints nothing for a deleted ref, or for a ref that names no commit.
pushed_range() {
	local tip
	[ -n "${1:-}" ] || return 0
	[ "$1" = 0000000000000000000000000000000000000000 ] && return 0
	tip=$(git rev-parse -q --verify "$1^{commit}" 2>/dev/null) || return 0
	printf '%s\n' "$tip" --not --remotes
	if [ "${2:-}" != 0000000000000000000000000000000000000000 ] \
		&& [ -n "${2:-}" ] && git cat-file -e "$2^{commit}" 2>/dev/null; then
		printf '%s\n' "$2"
	fi
}
