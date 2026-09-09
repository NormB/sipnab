#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The cheap gates, on the files you just wrote, in about a second.
#
# # Why this exists
#
# `.githooks/pre-commit` is the entry check on a commit and it takes minutes,
# because it compiles and runs the suite. Nothing in that list is expensive
# EXCEPT the compile, and the prose gates in particular answer in well under a
# second on one file. Learning about a British spelling from a multi-minute
# hook, fixing it, and running the hook again is a cycle that costs more than
# the whole class of defect is worth -- and it happened eight times in one
# session, which is what this script is for.
#
# This is NOT a replacement for the hook. It runs the subset that is per-FILE
# and fast. The hook still owns clippy, the suite, the ratchets and everything
# that needs the whole tree.
#
# # One rule in one place
#
# Every decision here is borrowed rather than restated:
#
#  * vale and codespell come from scripts/prose-gates.sh, the same runners the
#    hooks call, including the version pin that decides whether a vale run is
#    evidence about CI at all;
#  * the British-spelling list is PARSED OUT of `const BRITISH` in
#    tests/docs_drift_test.rs, the way tests/us_spelling_test.rs already reads
#    it, so a word added to the gate is caught here without a second edit;
#  * rustfmt is the toolchain's, on the edition Cargo.toml declares.
#
# A second copy of any of those would drift, and a local check that disagrees
# with the gate is worse than no local check: it teaches you to ignore it.
#
# Usage:
#   scripts/check-file.sh <path>...
#   scripts/check-file.sh $(git diff --name-only)

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || { echo "not in a git worktree" >&2; exit 2; }
# shellcheck source=scripts/prose-gates.sh
. scripts/prose-gates.sh

[ $# -gt 0 ] || { sed -n '3,36p' "$0"; exit 2; }

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
rc=0
skipped=0

# Is this path inside one of the trees a shared list names?
#
# The trailing slash matters and cost the first run of this script. The lists
# write directories as `docs/`, so a naive `"$_tree"/*` builds the pattern
# `docs//*`, which matches nothing -- and the script reported "not a
# vale-gated path" for a file vale gates. That is the failure mode of every
# scanner: it answered without checking, and the answer looked like a pass.
on_list() {
	_path="$1"; _list="$2"
	for _tree in $(prose_paths "$_list"); do
		_tree="${_tree%/}"
		case "$_path" in
			"$_tree"|"$_tree"/*) return 0 ;;
		esac
	done
	return 1
}

# The spelling gate's own word list, read from the gate rather than copied.
british_words() {
	sed -n '/const BRITISH: &\[&str\] = &\[/,/^    \];/p' tests/docs_drift_test.rs |
		grep -oE '^\s+"[a-z-]+"' | tr -d ' "'
}

# The gate's EXEMPT_CONTEXTS, borrowed for the same reason as the word list.
#
# These are published wire keys, a released flag alias and another
# specification's attribute name, and the gate removes them from the text
# BEFORE tokenizing. Without them this script reported a British spelling in a
# backlog paragraph the gate passes -- a local check that disagrees with the
# gate, which is worse than no local check because it teaches you to ignore it.
#
# Extracted with a parser rather than a regex, because one entry is a Rust
# literal whose VALUE contains quotes -- an MCP wire key, quoted inside the
# string. A `"[^"]+"` match stops at the first escaped quote and yields two
# characters of noise, so that exemption never applied and this script kept
# reporting a word the gate passes. That is the whole failure mode a borrowed
# rule exists to avoid, and the words are not written out here because this
# script would then fail on its own explanation.
exempt_contexts() {
	python3 - tests/docs_drift_test.rs <<-'PYEXEMPT'
		import re, sys
		src = open(sys.argv[1], encoding="utf-8").read()
		block = src.split("const EXEMPT_CONTEXTS: &[&str] = &[", 1)[1].split("];", 1)[0]
		for lit in re.findall(r'"((?:[^"\\]|\\.)*)"', block):
		    print(lit.replace('\\"', '"').replace("\\\\", "\\"))
	PYEXEMPT
}

# Files the gate does not scan at all, for reasons it states in place: the file
# that DECLARES the forbidden words, the changelog's frozen history, vendored
# third-party text, generated site assets and lockfiles.
spelling_exempt_file() {
	case "$1" in
		target/*|LICENSES/*|website/static/*) return 0 ;;
		THIRD-PARTY-NOTICES.md|CHANGELOG.md) return 0 ;;
		tests/docs_drift_test.rs) return 0 ;;
		tests/schemas/vcon-store-openapi.json) return 0 ;;
		*.lock) return 0 ;;
	esac
	return 1
}

BRITISH_LIST=$(british_words)
EXEMPT_CONTEXTS=$(exempt_contexts)
if [ -z "$BRITISH_LIST" ]; then
	echo "${RED}cannot read const BRITISH from tests/docs_drift_test.rs${NC}" >&2
	echo "The spelling check below would pass by matching nothing, which is not a pass." >&2
	exit 2
fi

for f in "$@"; do
	[ -f "$f" ] || { echo "  ${YELLOW}skip${NC} $f (not a file)"; continue; }
	echo "== $f"

	# 1. Vale, only where the tree is gated. A file outside .config/vale-paths.txt
	#    is not checked by CI either, and reporting it here would demand prose
	#    nothing enforces.
	if on_list "$f" .config/vale-paths.txt; then
		prose_vale_run "$f" && vrc=0 || vrc=$?
		case "$vrc" in
			0) echo "  vale        ${GREEN}OK${NC}" ;;
			1) echo "  vale        ${RED}FAIL${NC}"; sed -n '1,40p' "$PROSE_OUTPUT"; rc=1 ;;
			*) echo "  vale        ${YELLOW}NOT CHECKED${NC} -- $PROSE_REASON"; skipped=1 ;;
		esac
		[ -n "$PROSE_OUTPUT" ] && rm -f "$PROSE_OUTPUT"
	else
		echo "  vale        -- not a vale-gated path"
	fi

	# 2. Codespell, same shape.
	if on_list "$f" .config/codespell-paths.txt; then
		prose_codespell_run "$f" && crc=0 || crc=$?
		case "$crc" in
			0) echo "  codespell   ${GREEN}OK${NC}" ;;
			1) echo "  codespell   ${RED}FAIL${NC}"; sed -n '1,20p' "$PROSE_OUTPUT"; rc=1 ;;
			*) echo "  codespell   ${YELLOW}NOT CHECKED${NC} -- $PROSE_REASON"; skipped=1 ;;
		esac
		[ -n "$PROSE_OUTPUT" ] && rm -f "$PROSE_OUTPUT"
	else
		echo "  codespell   -- not a codespell-gated path"
	fi

	# 3. US spellings, everywhere. The gate scans the whole tree rather than a
	#    path list, so this does too: in one session it caught British past
	#    participles in a shell script and in a Rust comment, neither of which
	#    vale reads. The words themselves are not written here, because this
	#    check would then fail on its own explanation -- which it did, on the
	#    first run, and that is the check working.
	if spelling_exempt_file "$f"; then
		echo "  spelling    -- the gate does not scan this file"
	else
		_stripped=$(cat "$f")
		for _ctx in $EXEMPT_CONTEXTS; do
			_stripped=$(printf '%s' "$_stripped" | sed "s|$(printf '%s' "$_ctx" | sed 's/[][\\.*^$/]/\\&/g')||g")
		done
		hits=$(printf '%s\n' "$_stripped" |
			grep -noiE "\b($(echo "$BRITISH_LIST" | tr '\n' '|' | sed 's/|$//'))\b" || true)
		if [ -n "$hits" ]; then
			echo "  spelling    ${RED}FAIL${NC}"
			echo "$hits" | sed 's/^/    /'
			rc=1
		else
			echo "  spelling    ${GREEN}OK${NC}"
		fi
	fi

	# 4. rustfmt for Rust sources. `--check` prints the diff the hook would.
	case "$f" in
		*.rs)
			if rustfmt --check --edition 2024 "$f" >/tmp/.sipnab-check-fmt.$$ 2>&1; then
				echo "  rustfmt     ${GREEN}OK${NC}"
			else
				echo "  rustfmt     ${RED}FAIL${NC}"
				sed -n '1,30p' /tmp/.sipnab-check-fmt.$$
				rc=1
			fi
			rm -f /tmp/.sipnab-check-fmt.$$
			;;
	esac

	# 5. Shell and Python parse, which is free and catches a heredoc that ate
	#    its own delimiter.
	case "$f" in
		*.sh) bash -n "$f" && echo "  parse       ${GREEN}OK${NC}" || { echo "  parse       ${RED}FAIL${NC}"; rc=1; } ;;
		*.py) python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$f" &&
			echo "  parse       ${GREEN}OK${NC}" || { echo "  parse       ${RED}FAIL${NC}"; rc=1; } ;;
	esac
done

if [ "$skipped" = "1" ]; then
	echo
	echo "${YELLOW}Something did not run.${NC} A gate that could not run is not a pass -- the"
	echo "hook will still check it, and this script only saved you a cycle on the rest."
fi
exit "$rc"
