#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# commit-signature-check.sh  < pre-push lines
#
# Refuses a push that carries a commit without a good signature, and names
# each such commit with the command that re-signs it. It reads git's pre-push
# input, one line per ref:
#
#   <local ref> <local sha> <remote ref> <remote sha>
#
# * A deleted ref (local sha all zeros) pushes no commit: nothing to check.
# * Otherwise the push carries the commits reachable from <local sha> that no
#   remote-tracking ref reaches, and, for an update, that <remote sha> does
#   not reach either. Only those need a good signature: a commit already on
#   the remote is not this push's. <remote sha>..<local sha> alone is wrong
#   for a branch rebased onto a newer main: it spans every commit main gained
#   since the old base, and main's squash merges carry GitHub's own signature,
#   which reads as E here.
#
# Why: branch protection on main requires signed commits. GitHub enforces that
# only at merge time, so PR #333 sat BLOCKED with every check green and no
# reason shown, because four of its commits were unsigned. .githooks/pre-push
# runs this script before any other gate; tests/commit_signature_gate_test.rs
# holds both to that.
#
# Signatures are verified as scripts/tag-signature-check.sh verifies a tag: SSH
# format, against the repository's .github/allowed_signers (or
# $SIPNAB_ALLOWED_SIGNERS, which the tests use).
set -euo pipefail

root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
signers=${SIPNAB_ALLOWED_SIGNERS:-$root/.github/allowed_signers}
zero=0000000000000000000000000000000000000000

# git log's %G? letter, per commit. Which letters pass is the whole rule:
#
#   G  good signature from a key in the allowed-signers file: passes.
#   U  good signature from a key the file does not list: passes, with a note.
#      The file lists the maintainer's release keys. GitHub decides whether a
#      commit is verified by the keys registered to the committer's own
#      account, which no local file can know, so refusing U would refuse every
#      correctly signed commit from any other contributor. The note names the
#      key, so a commit signed with the wrong key of one's own is visible here.
#   N  no signature: refused. This is the defect the gate exists for.
#   B  bad signature (the commit changed after signing): refused.
#   E  the signature cannot be checked here, e.g. a GPG key missing from the
#      keyring: refused, because a signature this machine cannot check is not
#      known to be good.
#   X, Y, R  expired signature, expired key, revoked key: refused, since GitHub
#      does not show such a commit as verified.
describe() {
	case "$1" in
	N) echo "not signed" ;;
	B) echo "bad signature" ;;
	E) echo "signature cannot be checked on this machine" ;;
	X) echo "signature has expired" ;;
	Y) echo "signed by an expired key" ;;
	R) echo "signed by a revoked key" ;;
	*) echo "signature status '$1'" ;;
	esac
}

bad=0
notes=""
while read -r local_ref local_sha _remote_ref remote_sha; do
	[ -n "${local_sha:-}" ] || continue
	[ "$local_sha" = "$zero" ] && continue
	# A ref naming no commit (a tag on a tree or blob) pushes no commit.
	tip=$(git rev-parse -q --verify "$local_sha^{commit}" 2>/dev/null) || continue
	range=("$tip" --not --remotes)
	if [ "$remote_sha" != "$zero" ] && git cat-file -e "$remote_sha^{commit}" 2>/dev/null; then
		range+=("$remote_sha")
	fi
	# Fail closed: a range git cannot list is a range nobody checked.
	if ! commits=$(git -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$signers" \
		log --format='%H%x1f%G?%x1f%GK%x1f%s' "${range[@]}"); then
		echo "Cannot list the commits pushed for $local_ref, so none is checked."
		exit 1
	fi
	# Fields are split on the unit separator (0x1f), not whitespace: %GK is
	# empty for an unsigned commit, and whitespace splitting would collapse it.
	while IFS=$'\x1f' read -r sha letter key subject; do
		[ -n "$sha" ] || continue
		case "$letter" in
		G) ;;
		U)
			notes="$notes  ${sha:0:7} is signed by key $key, which is not in $signers. GitHub verifies it only if that key is on the committer's account: $subject
"
			;;
		*)
			if [ "$bad" -eq 0 ]; then
				echo "Commits without a good signature (branch protection on main requires one on every commit):"
			fi
			bad=$((bad + 1))
			echo "  ${sha:0:7} $(describe "$letter"): $subject"
			;;
		esac
	done <<<"$commits"
done

if [ -n "$notes" ]; then
	printf '%s' "$notes"
fi
if [ "$bad" -gt 0 ]; then
	echo "Re-sign them with SSH signing configured (gpg.format ssh, user.signingkey):"
	echo "  the last commit only:        git commit --amend -S --no-edit"
	echo "  every commit since <base>:   git rebase --exec 'git commit --amend --no-edit -S' <base>"
	exit 1
fi
