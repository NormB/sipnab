#!/usr/bin/env bash
# Test harness for packaging/deb/build-deb.sh.
#
# Runs the deb builder in a throwaway sandbox with a dummy binary and plugin
# (no cargo build, no root) and asserts the control metadata and payload for
# every packaging mode:
#   1. full deb        -> ships plugin, Recommends libasound
#   2. noaudio variant -> "-noaudio" filename, no plugin, no Recommends
#   3. plugin missing  -> falls back to a no-plugin package (no Recommends)
#   4. bad inputs      -> unknown variant and non-digit version are rejected
#
# Usage: bash packaging/deb/test-build-deb.sh   (from anywhere)
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILED=0
PASSED=0

fail() { echo "FAIL: $*" >&2; FAILED=$((FAILED + 1)); }
pass() { echo "ok:   $*"; PASSED=$((PASSED + 1)); }

assert_contains() { # haystack-desc, haystack, needle
    case "$2" in
        *"$3"*) pass "$1 contains '$3'" ;;
        *) fail "$1 does not contain '$3'" ;;
    esac
}

assert_not_contains() { # haystack-desc, haystack, needle
    case "$2" in
        *"$3"*) fail "$1 unexpectedly contains '$3'" ;;
        *) pass "$1 does not contain '$3'" ;;
    esac
}

# --- Sandbox: the builder resolves man/ and packaging/ relative to cwd -----
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/man" "$SANDBOX/packaging/deb" "$SANDBOX/bin"
cp "$REPO_ROOT/packaging/deb/build-deb.sh" "$SANDBOX/packaging/deb/"
cp "$REPO_ROOT/packaging/sipnab.service"   "$SANDBOX/packaging/"
cp "$REPO_ROOT/man/sipnab.1"               "$SANDBOX/man/"
# Licence and attribution files the package installs into
# /usr/share/doc/sipnab. The sandbox is a declared minimal file set, so a new
# input to build-deb.sh has to be added here too — which is how this test
# caught them being introduced without it.
cp "$REPO_ROOT/LICENSE-MIT" "$REPO_ROOT/LICENSE-APACHE" \
   "$REPO_ROOT/THIRD-PARTY-NOTICES.md" "$SANDBOX/"

printf '#!/bin/sh\nexit 0\n' > "$SANDBOX/bin/sipnab"
chmod 755 "$SANDBOX/bin/sipnab"
printf 'not a real shared object\n' > "$SANDBOX/bin/libsipnab_audio.so"

# Guarded because this script runs with `set -u` and not `set -e`: an
# unguarded failure here would leave the rest running in the repo root, where
# build-deb.sh does `rm -rf "$PKG_DIR"` and creates directories.
cd "$SANDBOX" || { echo "FAIL: cannot enter sandbox $SANDBOX"; exit 1; }

build() { # version, arch, [variant] -- with plugin unless NOPLUGIN=1
    local plugin="bin/libsipnab_audio.so"
    [ "${NOPLUGIN:-0}" = "1" ] && plugin=""
    SIPNAB_BIN="bin/sipnab" SIPNAB_AUDIO_PLUGIN="$plugin" \
        bash packaging/deb/build-deb.sh "$@"
}

# --- 1. Full package: plugin shipped, libasound Recommends ------------------
echo "=== full package ==="
if build 1.2.3 amd64 >/dev/null 2>&1 && [ -f sipnab_1.2.3_amd64.deb ]; then
    pass "full build produced sipnab_1.2.3_amd64.deb"
    control="$(dpkg-deb -f sipnab_1.2.3_amd64.deb)"
    contents="$(dpkg-deb -c sipnab_1.2.3_amd64.deb)"
    assert_contains     "full control" "$control" "Package: sipnab"
    assert_contains     "full control" "$control" "Version: 1.2.3"
    assert_contains     "full control" "$control" "Depends: libpcap0.8 | libpcap0.8t64"
    assert_contains     "full control" "$control" "Recommends: libasound2 | libasound2t64"
    assert_contains     "full contents" "$contents" "usr/lib/sipnab/libsipnab_audio.so"
    assert_contains     "full contents" "$contents" "usr/bin/sipnab"
    # Attribution is a licence obligation: MIT and Apache-2.0 both require the
    # notice to travel with the binary, and the audio plugin reaches libasound
    # (LGPL-2.1-or-later). The .deb shipped none of these until 0.5.47 — a
    # build that succeeds proves nothing about whether they are inside it.
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/LICENSE-MIT"
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/LICENSE-APACHE"
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/THIRD-PARTY-NOTICES.md"
else
    fail "full build failed or did not produce sipnab_1.2.3_amd64.deb"
fi

# --- 2. noaudio variant: suffixed name, no plugin, no Recommends ------------
echo "=== noaudio variant ==="
if build 1.2.3 amd64 noaudio >/dev/null 2>&1 && [ -f sipnab_1.2.3_amd64-noaudio.deb ]; then
    pass "noaudio build produced sipnab_1.2.3_amd64-noaudio.deb"
    control="$(dpkg-deb -f sipnab_1.2.3_amd64-noaudio.deb)"
    contents="$(dpkg-deb -c sipnab_1.2.3_amd64-noaudio.deb)"
    assert_contains     "noaudio control" "$control" "Package: sipnab"
    assert_contains     "noaudio control" "$control" "Version: 1.2.3"
    assert_contains     "noaudio control" "$control" "Depends: libpcap0.8 | libpcap0.8t64"
    assert_not_contains "noaudio control" "$control" "Recommends"
    assert_not_contains "noaudio control" "$control" "libasound"
    assert_not_contains "noaudio contents" "$contents" "libsipnab_audio.so"
    assert_contains     "noaudio contents" "$contents" "usr/bin/sipnab"
else
    fail "noaudio build failed or did not produce sipnab_1.2.3_amd64-noaudio.deb"
fi

# --- 3. Plugin missing: silently ships a no-plugin, no-Recommends package ---
echo "=== plugin missing fallback ==="
rm -f sipnab_9.9.9_arm64.deb
if NOPLUGIN=1 build 9.9.9 arm64 >/dev/null 2>&1 && [ -f sipnab_9.9.9_arm64.deb ]; then
    pass "no-plugin build produced sipnab_9.9.9_arm64.deb"
    control="$(dpkg-deb -f sipnab_9.9.9_arm64.deb)"
    contents="$(dpkg-deb -c sipnab_9.9.9_arm64.deb)"
    assert_contains     "no-plugin control" "$control" "Architecture: arm64"
    assert_not_contains "no-plugin control" "$control" "Recommends"
    assert_not_contains "no-plugin contents" "$contents" "libsipnab_audio.so"
else
    fail "no-plugin build failed or did not produce sipnab_9.9.9_arm64.deb"
fi

# --- 4. Adversarial inputs ---------------------------------------------------
echo "=== adversarial inputs ==="
if build 1.2.3 amd64 "bogus-variant" >/dev/null 2>&1; then
    fail "unknown variant 'bogus-variant' was accepted"
else
    pass "unknown variant 'bogus-variant' rejected"
fi

if build 1.2.3 amd64 'noaudio; touch pwned' >/dev/null 2>&1 || [ -e pwned ]; then
    fail "shell-metacharacter variant was accepted (or executed)"
else
    pass "shell-metacharacter variant rejected"
fi

# dpkg requires versions to start with a digit; the builder must not mask that.
if build "v1.2.3" amd64 >/dev/null 2>&1; then
    fail "non-digit version 'v1.2.3' was accepted"
else
    pass "non-digit version 'v1.2.3' rejected by dpkg-deb"
fi

echo
echo "${PASSED} passed, ${FAILED} failed"
[ "$FAILED" -eq 0 ]
