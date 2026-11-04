# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# shellcheck shell=sh
# Sourced by .githooks/commit-msg to decide how much of the message git will
# store, which is how much the identity check must read.
#
# git strips a message it opens in an editor (it drops `#` lines and cuts at a
# scissors line, below which `git commit -v` puts the diff). A message given
# with -m, -F or -C, or kept with --no-edit, is not edited: git stores every
# line, a scissors line and what follows it included. The hook used to stop at
# a scissors line always, so `git commit -m` with a credit below one passed it.

# commit_edits_message <words of the git command line>
# Exit 0 when that command is `git commit` and git will open the message in an
# editor; 1 otherwise, including any command that is not `git commit`, which the
# hook then reads whole because it cannot tell. Only the words after `commit`
# count: `git -C <dir> commit` carries a -C that is not commit's.
commit_edits_message() {
	_cem_seen=0
	_cem_edit=1
	_cem_force=0
	for _cem_word in "$@"; do
		if [ "$_cem_seen" = 0 ]; then
			[ "$_cem_word" = commit ] && _cem_seen=1
			continue
		fi
		case "$_cem_word" in
		-e | --edit) _cem_force=1 ;;
		--no-edit | --message | --message=* | --file | --file=* | --reuse-message | --reuse-message=*)
			_cem_edit=0
			;;
		--*) ;;
		-*[mFC]*) _cem_edit=0 ;;
		esac
	done
	_cem_result=1
	if [ "$_cem_seen" = 1 ] && { [ "$_cem_force" = 1 ] || [ "$_cem_edit" = 1 ]; }; then
		_cem_result=0
	fi
	unset _cem_seen _cem_edit _cem_force _cem_word
	return "$_cem_result"
}
