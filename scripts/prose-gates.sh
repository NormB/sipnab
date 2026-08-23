# shellcheck shell=sh
# The prose gates -- vale and codespell -- resolved and run in ONE place.
#
# Sourced by .githooks/pre-commit, .githooks/pre-push and scripts/preflight.sh.
# It deliberately does NOT print: the three callers render differently (color
# printf, the preflight step/ok/bad helpers) and each has a different amount of
# room. What is shared is every DECISION -- which binary, whether its version is
# the one CI pins, which paths, and whether a run happened at all -- because
# those are what drift when they are written more than once.
#
# The path lists this reads are themselves single-sourced, in
# .config/vale-paths.txt and .config/codespell-paths.txt. Those were three
# copies each, and the codespell copies had already diverged: .githooks/pre-push
# omitted `bench`, so a misspelling in the operator harness passed the gate that
# exists to catch it and failed in CI instead. This file is the same fix one
# level up, for the resolution rather than the paths.
#
# CONTRACT. Each runner returns:
#
#   0  the tool ran and the tree is clean
#   1  the tool ran and found something -- output is in $PROSE_OUTPUT
#   2  the tool did NOT run -- why is in $PROSE_REASON
#
# Return 2 is not a pass and callers must not render it as one. A gate that
# cannot run has to say so: this repository has been bitten twice by the
# opposite, once by a hardened PATH that hid vale and codespell and reported
# "Preflight clean" with two blocking gates silently downgraded, and once by a
# corpus gate that reported NOT VALIDATED when its environment variable was
# unset. Both looked like success.
#
# Callers own $PROSE_OUTPUT's lifetime: read it, then delete it.

#: Where the last run's output went. Set on return 0 and 1.
PROSE_OUTPUT=''
#: Why the tool did not run. Set on return 2.
PROSE_REASON=''
#: The version CI pins, and what the local binary reports. Set for vale.
PROSE_PIN=''
PROSE_HAVE=''

# Read a shared path list into a space-separated word list.
#
# One grammar, matching .config/code-trees.txt: one path per line, `#` comments
# and blank lines ignored.
prose_paths() {
	sed 's/#.*//' "$1" | tr '\n' ' '
}

# The vale version quality.yml pins, or empty when the workflow does not say.
#
# Derived rather than restated. scripts/preflight.sh already read it from the
# workflow while .githooks/pre-push carried its own literal, so a bump in CI
# would have left the hook comparing a correct binary against a stale number and
# reporting NOT CHECKED -- a gate switching itself off quietly.
prose_vale_pin() {
	grep -oE "VALE_VERSION: '[0-9.]+'" .github/workflows/quality.yml 2>/dev/null |
		grep -oE '[0-9.]+' | head -1
}

# Run vale over .config/vale-paths.txt. See CONTRACT above.
#
# VALE_BIN is checked BEFORE the PATH, and that order is the point: it exists to
# override a PATH binary of the wrong version, so a PATH-first lookup would
# defeat it. Measured 2026-08-19 on macOS/aarch64, Homebrew ships a version
# other than the pin, and without this there is no second binary to reach for.
prose_vale_run() {
	PROSE_OUTPUT=''
	PROSE_REASON=''
	PROSE_PIN=$(prose_vale_pin)
	PROSE_HAVE=''

	_vale=''
	if [ -n "${VALE_BIN:-}" ] && [ -x "${VALE_BIN}" ]; then
		_vale="$VALE_BIN"
	elif command -v vale >/dev/null 2>&1; then
		_vale=vale
	fi

	if [ -z "$_vale" ]; then
		PROSE_REASON='vale is not installed'
		return 2
	fi
	if [ -z "$PROSE_PIN" ]; then
		# Nothing to compare against, so whatever this binary reports is not
		# evidence about CI. Refusing is the honest answer.
		PROSE_REASON='no VALE_VERSION in .github/workflows/quality.yml'
		return 2
	fi
	PROSE_HAVE=$("$_vale" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
	if [ "$PROSE_HAVE" != "$PROSE_PIN" ]; then
		# The version is part of the check, not a detail. Vale.Spelling consults
		# an internal dictionary that changes between releases, and the Google
		# package resolves differently across binaries, so a run on the wrong
		# version is not evidence about CI in EITHER direction. Measured
		# 2026-08-18 on identical committed bytes: vale 3.16.0 (what CI pins)
		# reported 0 errors, Homebrew's 3.17.1 reported 475. That is not a
		# stricter check finding more; it is a different check answering a
		# different question, and it made this gate unpassable locally while CI
		# was green. `.vale.ini` says the same thing at its top.
		PROSE_REASON="vale ${PROSE_HAVE:-unknown}, CI pins $PROSE_PIN"
		return 2
	fi

	PROSE_OUTPUT="/tmp/.sipnab-prose-vale.$$"
	# shellcheck disable=SC2086
	if "$_vale" $(prose_paths .config/vale-paths.txt) >"$PROSE_OUTPUT" 2>&1; then
		return 0
	fi
	return 1
}

# Run codespell over .config/codespell-paths.txt. See CONTRACT above.
#
# PATH first here, unlike vale, and deliberately: codespell has no version pin,
# so any install is as good as another and CODESPELL_BIN is only a fallback for
# a venv rather than an override.
prose_codespell_run() {
	PROSE_OUTPUT=''
	PROSE_REASON=''

	_cs=''
	if command -v codespell >/dev/null 2>&1; then
		_cs=codespell
	elif [ -n "${CODESPELL_BIN:-}" ] && [ -x "${CODESPELL_BIN}" ]; then
		_cs="$CODESPELL_BIN"
	fi

	if [ -z "$_cs" ]; then
		PROSE_REASON='codespell is not installed'
		return 2
	fi

	PROSE_OUTPUT="/tmp/.sipnab-prose-cs.$$"
	# shellcheck disable=SC2086
	if $_cs $(prose_paths .config/codespell-paths.txt) --skip ./.git >"$PROSE_OUTPUT" 2>&1; then
		return 0
	fi
	return 1
}
