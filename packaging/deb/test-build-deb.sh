#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

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
# License and attribution files the package installs into
# /usr/share/doc/sipnab. The sandbox is a declared minimal file set, so a new
# input to build-deb.sh has to be added here too — which is how this test
# caught them being introduced without it.
cp "$REPO_ROOT/LICENSE-MIT" "$REPO_ROOT/LICENSE-APACHE" "$REPO_ROOT/DUAL-LICENSE" \
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
    # Attribution is a license obligation: MIT and Apache-2.0 both require the
    # notice to travel with the binary, and the audio plugin reaches libasound
    # (LGPL-2.1-or-later). The .deb shipped none of these until 0.5.47 — a
    # build that succeeds proves nothing about whether they are inside it.
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/LICENSE-MIT"
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/LICENSE-APACHE"
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/DUAL-LICENSE"
    assert_contains     "full contents" "$contents" "usr/share/doc/sipnab/THIRD-PARTY-NOTICES.md"
    # build-deb.sh installs seven things; this asserted three of them, so
    # deleting the man page, the systemd unit and the postinst chmod outright
    # left 25 passed / 0 failed while `dpkg-deb -c` showed man1/ and
    # lib/systemd/system/ present but EMPTY, and the maintainer script that
    # creates the privilege-drop `sipnab` user simply gone. The test copies
    # those files into the sandbox and never checked they arrived.
    assert_contains     "full contents" "$contents" "usr/share/man/man1/sipnab.1.gz"
    assert_contains     "full contents" "$contents" "lib/systemd/system/sipnab.service"
    # The maintainer script is not in `dpkg-deb -c` (that lists the data
    # archive); it lives in the control archive.
    scripts="$(dpkg-deb --ctrl-tarfile sipnab_1.2.3_amd64.deb 2>/dev/null | tar -t 2>/dev/null || true)"
    assert_contains     "full control archive" "$scripts" "postinst"
    # And it has to be executable, or dpkg refuses to run it and the
    # privilege-drop user is never created.
    perms="$(dpkg-deb --ctrl-tarfile sipnab_1.2.3_amd64.deb 2>/dev/null | tar -tv 2>/dev/null | grep postinst || true)"
    case "$perms" in
      *rwxr-xr-x*) pass "postinst is executable" ;;
      *) fail "postinst is not executable (dpkg will skip it): $perms" ;;
    esac
else
    fail "full build failed or did not produce sipnab_1.2.3_amd64.deb"
fi

# --- 1b. Maintainer scripts: what each dpkg action does to the service -----
#
# Up to this fix the package had a postinst and nothing else, so `apt remove`
# left the daemon running on a deleted /usr/bin/sipnab and left
# multi-user.target.wants/sipnab.service pointing at a unit file that was
# gone, and an upgrade left the old process running on the replaced binary.
# Each script is taken out of the built package and run in a sandbox whose
# PATH holds only stubs that record their arguments. The one absolute path the
# scripts test, /run/systemd/system (present only while systemd is the running
# init), is rewritten to a sandbox directory so both answers can be driven.
echo "=== maintainer scripts ==="
CTRL="$SANDBOX/ctrl"
rm -rf "$CTRL"
if [ -f sipnab_1.2.3_amd64.deb ] && dpkg-deb -e sipnab_1.2.3_amd64.deb "$CTRL" 2>/dev/null; then
    pass "extracted the control archive"
else
    fail "cannot extract the control archive of sipnab_1.2.3_amd64.deb"
fi
for script in postinst prerm postrm; do
    if [ -x "$CTRL/$script" ]; then
        pass "$script is in the package and executable"
    else
        fail "$script is missing from the package or not executable"
    fi
done

# run_script <script> <systemd running: 1|0> <deb-systemd-invoke present: 1|0> <args...>
# Prints "rc=<exit status>" and then one line per systemd stub call. STUB_RC
# sets the exit status of the systemd stubs, to show a failing systemctl does
# not fail dpkg. getent always succeeds: the sipnab user exists, so postinst's
# useradd (whose failure should fail the install) is not reached.
run_script() {
    local script="$CTRL/$1" running="$2" invoke="$3" d tool rc
    shift 3
    d="$(mktemp -d "$SANDBOX/run.XXXXXX")"
    mkdir -p "$d/bin"
    for tool in systemctl deb-systemd-invoke deb-systemd-helper useradd; do
        printf '#!/bin/sh\nprintf "%%s\\n" "%s $*" >> "%s/calls"\nexit %s\n' \
            "$tool" "$d" "${STUB_RC:-0}" > "$d/bin/$tool"
        chmod 755 "$d/bin/$tool"
    done
    printf '#!/bin/sh\nexit 0\n' > "$d/bin/getent"
    chmod 755 "$d/bin/getent"
    [ "$invoke" = "1" ] || rm -f "$d/bin/deb-systemd-invoke"
    [ "$running" = "1" ] && mkdir -p "$d/run/systemd/system"
    : > "$d/calls"
    if [ -f "$script" ]; then
        sed "s#/run/systemd/system#$d/run/systemd/system#g" "$script" > "$d/script"
        PATH="$d/bin" /bin/sh "$d/script" "$@" > /dev/null 2>&1
        rc=$?
    else
        rc=127
    fi
    echo "rc=$rc"
    cat "$d/calls"
}

# The rewrite above is what makes "systemd is not running" reachable. A script
# that stopped naming the path would make every not-running case pass vacuously.
for script in postinst prerm postrm; do
    if grep -q '/run/systemd/system' "$CTRL/$script" 2>/dev/null; then
        pass "$script tests /run/systemd/system"
    else
        fail "$script does not test /run/systemd/system, so the sandbox cannot drive it"
    fi
done

expect_calls() { # description, expected (newline-separated), actual
    if [ "$2" = "$3" ]; then
        pass "$1"
    else
        fail "$1"
        printf '  expected:\n%s\n  actual:\n%s\n' "$2" "$3" >&2
    fi
}

NL='
'
expect_calls "prerm remove stops (via deb-systemd-invoke) and disables" \
    "rc=0${NL}deb-systemd-invoke stop sipnab.service${NL}systemctl --no-reload disable sipnab.service" \
    "$(run_script prerm 1 1 remove)"
expect_calls "prerm remove without deb-systemd-invoke stops with systemctl" \
    "rc=0${NL}systemctl stop sipnab.service${NL}systemctl --no-reload disable sipnab.service" \
    "$(run_script prerm 1 0 remove)"
expect_calls "prerm remove with systemd not running disables only" \
    "rc=0${NL}systemctl --no-reload disable sipnab.service" \
    "$(run_script prerm 0 1 remove)"
expect_calls "prerm upgrade neither stops nor disables" \
    "rc=0" "$(run_script prerm 1 1 upgrade 1.2.4)"
expect_calls "prerm failed-upgrade does nothing" \
    "rc=0" "$(run_script prerm 1 1 failed-upgrade 1.2.2)"
expect_calls "prerm deconfigure does nothing" \
    "rc=0" "$(run_script prerm 1 1 deconfigure)"
expect_calls "prerm remove under DPKG_ROOT disables in that root and stops nothing" \
    "rc=0${NL}systemctl --root=/target --no-reload disable sipnab.service" \
    "$(DPKG_ROOT=/target run_script prerm 1 1 remove)"
expect_calls "prerm remove still exits 0 when systemctl fails" \
    "rc=0${NL}deb-systemd-invoke stop sipnab.service${NL}systemctl --no-reload disable sipnab.service" \
    "$(STUB_RC=1 run_script prerm 1 1 remove)"
expect_calls "postrm remove reloads systemd" \
    "rc=0${NL}systemctl daemon-reload" "$(run_script postrm 1 1 remove)"
expect_calls "postrm remove with systemd not running does nothing" \
    "rc=0" "$(run_script postrm 0 1 remove)"
expect_calls "postrm upgrade does nothing" \
    "rc=0" "$(run_script postrm 1 1 upgrade 1.2.4)"
expect_calls "postrm purge exits 0" \
    "rc=0" "$(run_script postrm 0 1 purge)"
expect_calls "postinst upgrade restarts a running service on the new binary" \
    "rc=0${NL}systemctl daemon-reload${NL}deb-systemd-invoke try-restart sipnab.service" \
    "$(run_script postinst 1 1 configure 1.2.2)"
expect_calls "postinst upgrade without deb-systemd-invoke uses systemctl" \
    "rc=0${NL}systemctl daemon-reload${NL}systemctl try-restart sipnab.service" \
    "$(run_script postinst 1 0 configure 1.2.2)"
expect_calls "postinst fresh install neither starts nor enables" \
    "rc=0" "$(run_script postinst 1 1 configure)"
expect_calls "postinst upgrade with systemd not running does nothing" \
    "rc=0" "$(run_script postinst 0 1 configure 1.2.2)"
expect_calls "postinst upgrade still exits 0 when systemctl fails" \
    "rc=0${NL}systemctl daemon-reload${NL}deb-systemd-invoke try-restart sipnab.service" \
    "$(STUB_RC=1 run_script postinst 1 1 configure 1.2.2)"

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
