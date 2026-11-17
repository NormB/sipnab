#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# usage: pick-tag-proof.sh <checkout copy> <copy path in the git dir> < <pre-push stdin>
#
# Which copy of scripts/tag-push-proof.py judges a push that holds a tag
# (TAG-PUSH-GATE-RUNS-FROM-TAG-COMMIT). The release train checks out the merge
# commit before it pushes the tag, and the pre-push hook ran the proof script
# of that checkout, so a gate fix merged after the release merge never reached
# that release's tag push (0.5.259, 2026-11-16).
#
# origin/main's copy is written to <copy path> and named when all of these
# hold: the push creates or moves a tag; origin/main resolves to a commit
# here; every tagged commit is an ancestor of it; and the file there is a
# regular, non-empty blob that git can write out. Otherwise the checkout's
# copy is named, with one line that says why. The copy named decides the
# verdict; this script never decides one.
#
# Output: line 1 is the path the hook runs; a second line, when present, is
# printed by the hook as it stands. A push without a tag ref prints the
# checkout's path alone. Exit 0; 2 on a usage error.
#
# Only for a tag whose tagged commit holds this hook change: an older tagged
# commit runs its own hook, which never calls this script.

set -u
set -f

if [ "$#" -ne 2 ]; then
	echo "usage: pick-tag-proof.sh <checkout copy> <copy path in the git dir> < <pre-push stdin>" >&2
	exit 2
fi
CHECKOUT=$1
COPY=$2
SRC=scripts/tag-push-proof.py
ZERO=0000000000000000000000000000000000000000

fallback() {
	rm -f "$COPY" 2>/dev/null
	printf '%s\n' "$CHECKOUT"
	printf "  tag proof: this checkout's %s judges this push: %s\n" "$SRC" "$1"
	exit 0
}

short() {
	printf '%.12s' "$1"
}

TAGS=0
MALFORMED=0
COMMITS=""
UNRESOLVED=""
while IFS= read -r line || [ -n "$line" ]; do
	[ -n "$line" ] || continue
	# Word splitting is intended: git writes four space-separated fields.
	# shellcheck disable=SC2086
	set -- $line
	if [ "$#" -ne 4 ]; then
		MALFORMED=1
		continue
	fi
	case "$3" in
	refs/tags/*) ;;
	*) continue ;;
	esac
	TAGS=1
	[ "$2" = "$ZERO" ] && continue
	if commit=$(git rev-parse --verify --quiet "$2^{commit}" 2>/dev/null) && [ -n "$commit" ]; then
		COMMITS="$COMMITS $commit"
	elif [ -z "$UNRESOLVED" ]; then
		UNRESOLVED=$2
	fi
done

[ "$MALFORMED" = 0 ] || fallback "a pushed ref line could not be read"
if [ "$TAGS" = 0 ]; then
	printf '%s\n' "$CHECKOUT"
	exit 0
fi
[ -z "$UNRESOLVED" ] || fallback "the pushed tag $(short "$UNRESOLVED") does not resolve to a commit"
[ -n "$COMMITS" ] || fallback "the push creates or moves no tag"

MAIN=$(git rev-parse --verify --quiet "refs/remotes/origin/main^{commit}" 2>/dev/null) || MAIN=""
[ -n "$MAIN" ] || fallback "origin/main does not resolve to a commit here (run: git fetch origin main)"

for commit in $COMMITS; do
	git merge-base --is-ancestor "$commit" "$MAIN" 2>/dev/null \
		|| fallback "the tagged commit $(short "$commit") is not on origin/main $(short "$MAIN") (a stale origin/main? run: git fetch origin main)"
done

ENTRY=$(git ls-tree "$MAIN" -- "$SRC" 2>/dev/null) || ENTRY=""
[ -n "$ENTRY" ] || fallback "origin/main has no $SRC"
# One entry: "<mode> <type> <sha>\t<path>".
set -- $ENTRY
case "$1 $2" in
"100644 blob" | "100755 blob") ;;
*) fallback "origin/main's $SRC is not a regular file" ;;
esac
BLOB=$3
git cat-file blob "$BLOB" >"$COPY" 2>/dev/null || fallback "the copy could not be written to $COPY"
[ -s "$COPY" ] || fallback "origin/main's $SRC is empty"

printf '%s\n' "$COPY"
printf "  tag proof: origin/main's %s (%s) judges this push\n" "$SRC" "$(short "$MAIN")"
