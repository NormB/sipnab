# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# shellcheck shell=sh
# Sourced (POSIX sh) by scripts/test-pre-commit.sh and scripts/test-pre-push.sh,
# which build throwaway git repositories and run the hooks inside them.
#
# Git hands a hook the repository it runs for. In a linked worktree it exports
# an absolute GIT_DIR (<repo>/.git/worktrees/<name>) and GIT_INDEX_FILE, and
# `git --git-dir=... commit` exports them anywhere. Inherited by these scripts,
# `cd <tmp> && git init -q .` re-initializes THAT repository instead of making
# <tmp>/.git, `git config user.name ...` writes its shared .git/config, and
# `git commit` commits the fixture into it. vcon-server's copy of the pattern
# rewrote its own .git/config that way on 2026-10-28.
# tests/hook_test_scripts_git_env_test.rs runs both scripts from inside a hook
# and requires the hook's repository to come out byte-identical.

# Unset every exported GIT_* variable in this shell, so every git command after
# it -- the scripts' own and the hooks' they run -- finds its repository from
# its working directory, the way an ordinary invocation does.
clear_git_env() {
	for _git_var in $(env | sed -n 's/^\(GIT_[A-Za-z0-9_]*\)=.*/\1/p'); do
		unset "$_git_var"
	done
	unset _git_var
}

# require_own_git_dir <dir>: exit 1 unless git, run in <dir>, uses a git
# directory inside <dir>. Called right after a throwaway repository's
# `git init`, before anything writes to it, so a repository found anywhere
# else is refused rather than written to.
require_own_git_dir() {
	_want=$(CDPATH='' cd -- "$1" && pwd -P) || {
		printf 'REFUSED: the sandbox %s does not exist\n' "$1" >&2
		exit 1
	}
	_got=$(cd -- "$1" && git rev-parse --absolute-git-dir 2>/dev/null) || _got=''
	if [ -n "$_got" ]; then
		_got=$(CDPATH='' cd -- "$_got" && pwd -P) || _got=''
	fi
	case "$_got" in
	"$_want"/*) ;;
	*)
		printf 'REFUSED: git in the sandbox %s uses the git directory %s, which is not inside it.\n' \
			"$_want" "${_got:-<none>}" >&2
		printf 'A GIT_* variable from the calling environment (a hook exports GIT_DIR) would\n' >&2
		printf 'send this script'"'"'s git commands to that repository. Nothing was written.\n' >&2
		exit 1
		;;
	esac
	unset _want _got
}
