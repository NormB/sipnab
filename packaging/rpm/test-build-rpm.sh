#!/usr/bin/env bash
# Test harness for packaging/rpm/build-rpm.sh, the sibling of
# packaging/deb/test-build-deb.sh.
#
# Runs the rpm builder in a throwaway sandbox with synthetic ELFs (no cargo
# build, no root) and asserts the metadata and payload for every packaging
# mode:
#   1. full rpm        -> ships plugin, weak alsa-lib dependency only
#   2. noaudio variant -> "-noaudio" filename, no plugin, no alsa-lib
#   3. cross-arch      -> arch plumbing and filename
#   4. already correct -> a binary that arrives with the RPM-world SONAME is
#                         packaged unchanged
#   5. libpcap SONAME  -> the package names libpcap.so.1, never Debian's
#                         libpcap.so.0.8, in BOTH the generated Requires and
#                         the packaged ELF's DT_NEEDED
#   6. bad inputs      -> unknown variant, unknown arch, and a binary the
#                         builder cannot rename are rejected
#
# Point 5 is the reason this harness exists. The release workflow builds the
# gnu binaries, and therefore the .rpm, inside a Debian container. Debian
# patches libpcap's SONAME to libpcap.so.0.8 and every RPM distro ships
# libpcap.so.1, so rpmbuild's automatic dependency generator read the Debian
# name off the binary and wrote `Requires: libpcap.so.0.8()(64bit)` into the
# package -- which no Fedora or RHEL host can satisfy, so dnf refused the
# install outright. The .deb harness next door has always checked its own
# Depends line; the .rpm had nothing watching.
#
# PORTABILITY IS PART OF THE CONTRACT. This runs on ubuntu-latest in CI and on
# whatever a contributor has locally, and an assertion that quietly depends on
# the local rpm or gcc is not a gate. Two things are therefore built by hand
# rather than inherited from the toolchain:
#   * the fixtures' DT_NEEDED is written with patchelf, not produced by
#     linking against stub libraries -- link behavior (--as-needed, default
#     dtags, -l: support) varies by distro and would decide the result;
#   * the package is unpacked with `rpm2archive -`, the one spelling that
#     behaves the same on rpm 4 and rpm 6 (see extract_needed below).
# Verified identical on ubuntu:24.04 (rpm 4.18.2, gcc 13.3, ld 2.42) and
# fedora:44 (rpm 6.0.x, gcc 16.1, ld 2.46) -- the rpm 4 / rpm 6 split is where
# rpm2archive's behavior changes, not any particular patch release.
#
# Usage: bash packaging/rpm/test-build-rpm.sh   (from anywhere)
set -u

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAILED=0
PASSED=0

fail() { echo "FAIL: $*" >&2; FAILED=$((FAILED + 1)); }
pass() { echo "ok:   $*"; PASSED=$((PASSED + 1)); }

# A broken measurement is not a test result. Anything that leaves these
# helpers without something to read stops the run instead of scoring it: an
# empty haystack makes every assert_not_contains pass, which is precisely how
# the assertion guarding this bug could go green while seeing nothing.
die() { echo "HARNESS BROKEN: $*" >&2; exit 1; }

assert_contains() { # haystack-desc, haystack, needle
    [ -n "$2" ] || die "$1 is empty, so nothing can be asserted about it"
    case "$2" in
        *"$3"*) pass "$1 contains '$3'" ;;
        *) fail "$1 does not contain '$3'" ;;
    esac
}

assert_not_contains() { # haystack-desc, haystack, needle
    [ -n "$2" ] || die "$1 is empty, so nothing can be asserted about it"
    case "$2" in
        *"$3"*) fail "$1 unexpectedly contains '$3'" ;;
        *) pass "$1 does not contain '$3'" ;;
    esac
}

# --- Preflight: name every missing tool at once, not one per run ------------
MISSING=""
for tool in rpmbuild rpm rpm2archive patchelf readelf gcc tar gzip; do
    command -v "$tool" > /dev/null 2>&1 || MISSING="${MISSING} ${tool}"
done
if [ -n "$MISSING" ]; then
    echo "FAIL: missing required tools:${MISSING}" >&2
    echo "Debian/Ubuntu: apt-get install -y rpm patchelf binutils gcc" >&2
    echo "Fedora/RHEL:   dnf install -y rpm-build rpm patchelf binutils gcc" >&2
    exit 1
fi

# The ELF fixtures are whatever gcc produces here, so the package must be
# labeled with the arch this host actually builds. Labeling it otherwise
# would put a foreign-arch ELF in the package and leave the arch-dependent
# assertions passing for a reason unrelated to what they claim to test.
case "$(uname -m)" in
    x86_64)        HOST_ARCH=x86_64;  OTHER_ARCH=aarch64 ;;
    aarch64|arm64) HOST_ARCH=aarch64; OTHER_ARCH=x86_64 ;;
    *) die "unsupported test host architecture $(uname -m); expected x86_64 or aarch64" ;;
esac
echo "host arch ${HOST_ARCH}; cross-arch case builds ${OTHER_ARCH}"

# --- Sandbox: the builder resolves man/ and packaging/ relative to cwd -----
SANDBOX="$(mktemp -d)"
trap 'rm -rf "$SANDBOX"' EXIT
mkdir -p "$SANDBOX/man" "$SANDBOX/packaging/rpm" "$SANDBOX/bin" "$SANDBOX/src"
cp "$REPO_ROOT/packaging/rpm/build-rpm.sh" "$SANDBOX/packaging/rpm/"
cp "$REPO_ROOT/packaging/sipnab.service"   "$SANDBOX/packaging/"
cp "$REPO_ROOT/man/sipnab.1"               "$SANDBOX/man/"

# Guarded because this script runs with `set -u` and not `set -e`: an
# unguarded failure here would leave the rest running in the repo root, where
# build-rpm.sh does `rm -rf "$TOPDIR"` under target/.
cd "$SANDBOX" || die "cannot enter sandbox $SANDBOX"

# --- Fixtures: real ELFs, because DT_NEEDED is what is under test ----------
#
# A shell script standing in for the binary (what the .deb harness uses) has
# no DT_NEEDED at all and cannot express this bug. The dependency is added
# with patchelf rather than by linking against a stub .so: the linker's
# willingness to record a NEEDED entry depends on --as-needed and on the
# reference actually surviving, which differs between distributions, and a
# fixture that builds differently under two toolchains tests the toolchain.
printf 'int main(void) { return 0; }\n' > src/main.c
printf 'int play(void) { return 0; }\n' > src/plugin.c

make_bin() { # dest, soname-to-need
    gcc -o "$1" src/main.c || die "gcc cannot build $1"
    patchelf --add-needed "$2" "$1" || die "patchelf cannot add $2 to $1"
    dt_of "$1" | grep -qx "$2" || die "fixture $1 does not carry DT_NEEDED $2"
}

# readelf's stderr is deliberately NOT discarded: a reader that cannot read
# must say so on the terminal, not hand back an empty list for an assertion to
# misinterpret.
dt_of() { readelf -d "$1" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'; }

# What a bookworm-built sipnab hands the builder.
make_bin bin/sipnab libpcap.so.0.8
# What a native Fedora build would hand it: already the RPM-world SONAME.
make_bin bin/sipnab-native libpcap.so.1
# The dlopen-only audio plugin, which is why alsa-lib is a weak dependency.
gcc -shared -fPIC -o bin/libsipnab_audio.so src/plugin.c || die "gcc cannot build the plugin"
patchelf --add-needed libasound.so.2 bin/libsipnab_audio.so || die "patchelf cannot add libasound"

# Guarded in three places on purpose. `die` inside this function runs in the
# command substitution that calls it, so it ends that subshell rather than the
# run; the scored check and the empty-haystack guard in the assert helpers are
# what turn a broken extractor into a red run instead of a quiet one. Removing
# any one of them because the other two look redundant reopens the hole.
needed() { # rpm-path -> DT_NEEDED of the /usr/bin/sipnab inside it
    local rpm_file="$1" dir out err
    dir="$(mktemp -d)"
    # `rpm2archive - < file` reads the package on stdin and writes the archive
    # on stdout. The obvious spelling is NOT portable: `rpm2archive <file>`
    # writes <file>.tgz beside the input on rpm 4.x but streams to stdout on
    # rpm 6.x, creating no file at all -- so the tar that followed it failed,
    # this helper returned an empty string, and every DT_NEEDED assertion
    # scored against nothing. Measured on rpm 4.18.2 and rpm 6.0.2; `-` works
    # on both. cpio is the other portable route but ships on neither runner.
    err="$dir/.unpack-stderr"
    rpm2archive - < "$rpm_file" 2> "$err" | ( cd "$dir" && tar xz ) 2>> "$err"
    if [ ! -f "$dir/usr/bin/sipnab" ]; then
        echo "--- rpm2archive/tar stderr ---" >&2
        cat "$err" >&2
        echo "--- rpm2archive --help ---" >&2
        rpm2archive --help >&2 2>&1 || true
        rm -rf "$dir"
        die "cannot unpack /usr/bin/sipnab from $(basename "$rpm_file")"
    fi
    out="$(dt_of "$dir/usr/bin/sipnab")"
    rm -rf "$dir"
    [ -n "$out" ] || die "read no DT_NEEDED from the binary inside $(basename "$rpm_file")"
    printf '%s\n' "$out"
}

build() { # version, arch, [variant] -- with plugin unless NOPLUGIN=1
    local plugin="bin/libsipnab_audio.so"
    [ "${NOPLUGIN:-0}" = "1" ] && plugin=""
    SIPNAB_BIN="${BIN:-bin/sipnab}" SIPNAB_AUDIO_PLUGIN="$plugin" \
        bash packaging/rpm/build-rpm.sh "$@"
}

# --- 1. Full package: plugin shipped, alsa-lib weak only -------------------
echo "=== full package ==="
PKG="sipnab-1.2.3-1.${HOST_ARCH}.rpm"
if build 1.2.3 "$HOST_ARCH" > /dev/null 2>&1 && [ -f "$PKG" ]; then
    pass "full build produced $PKG"
    requires="$(rpm -qp --requires "$PKG" 2> /dev/null)"
    recommends="$(rpm -qp --recommends "$PKG" 2> /dev/null)"
    contents="$(rpm -qpl "$PKG" 2> /dev/null)"
    info="$(rpm -qpi "$PKG" 2> /dev/null)"
    assert_contains     "full info" "$info" "sipnab"
    assert_contains     "full info" "$info" "1.2.3"
    # The install-blocking pair. Both directions matter: dropping the Debian
    # name without gaining the RPM one would mean the package no longer
    # declares the library it loads at runtime.
    assert_contains     "full requires" "$requires" "libpcap.so.1()(64bit)"
    assert_not_contains "full requires" "$requires" "libpcap.so.0.8"
    assert_contains     "full requires" "$requires" "libpcap"
    # A package that installs and then cannot load libpcap is worse than one
    # that refuses to install, so the ELF has to agree with the metadata.
    # Prove the measurement happened before trusting what it says. An
    # extractor that quietly returns nothing would otherwise make the
    # not-contains below the cleanest pass in the file while seeing no ELF at
    # all -- the exact shape of a gate that reports a safety it never checked.
    dt="$(needed "$PKG")"
    entries="$(printf '%s\n' "$dt" | grep -c .)"
    if [ "$entries" -ge 2 ]; then
        pass "unpacked the packaged binary and read ${entries} DT_NEEDED entries"
    else
        fail "expected at least libc and libpcap in DT_NEEDED, read ${entries} entries"
    fi
    assert_contains     "packaged binary DT_NEEDED" "$dt" "libpcap.so.1"
    assert_not_contains "packaged binary DT_NEEDED" "$dt" "libpcap.so.0.8"
    # ALSA is a weak dependency by design: the plugin is dlopen'd lazily and a
    # headless server should not have the ALSA stack dragged in behind it.
    # The automatic generator read the plugin's DT_NEEDED and turned that into
    # a hard Requires, which is the opposite of what Recommends means.
    assert_contains     "full recommends" "$recommends" "alsa-lib"
    assert_not_contains "full requires" "$requires" "libasound.so.2"
    assert_contains     "full contents" "$contents" "/usr/bin/sipnab"
    assert_contains     "full contents" "$contents" "/usr/share/man/man1/sipnab.1.gz"
    assert_contains     "full contents" "$contents" "/usr/lib/systemd/system/sipnab.service"
    assert_contains     "full contents" "$contents" "/usr/lib/sipnab/libsipnab_audio.so"
    # The privilege-drop user is created by a %pre scriptlet; a package that
    # builds proves nothing about whether the scriptlet survived.
    scriptlets="$(rpm -qp --scripts "$PKG" 2> /dev/null)"
    assert_contains     "full scriptlets" "$scriptlets" "useradd"
else
    fail "full build failed or did not produce $PKG"
fi

# --- 2. noaudio variant: suffixed name, no plugin, no alsa-lib -------------
echo "=== noaudio variant ==="
PKG="sipnab-1.2.3-1.${HOST_ARCH}-noaudio.rpm"
if build 1.2.3 "$HOST_ARCH" noaudio > /dev/null 2>&1 && [ -f "$PKG" ]; then
    pass "noaudio build produced $PKG"
    requires="$(rpm -qp --requires "$PKG" 2> /dev/null)"
    recommends="$(rpm -qp --recommends "$PKG" 2> /dev/null)"
    contents="$(rpm -qpl "$PKG" 2> /dev/null)"
    assert_contains     "noaudio requires" "$requires" "libpcap.so.1()(64bit)"
    assert_not_contains "noaudio requires" "$requires" "libpcap.so.0.8"
    assert_not_contains "noaudio requires" "$requires" "libasound"
    assert_not_contains "noaudio contents" "$contents" "libsipnab_audio.so"
    assert_contains     "noaudio contents" "$contents" "/usr/bin/sipnab"
    dt="$(needed "$PKG")"
    assert_contains     "noaudio binary DT_NEEDED" "$dt" "libpcap.so.1"
    # rpm prints nothing for an absent weak dependency, so this one cannot use
    # assert_not_contains: an empty string is the expected answer here, and
    # the helpers refuse to score against emptiness.
    if [ -z "$recommends" ]; then
        pass "noaudio recommends nothing"
    else
        fail "noaudio recommends '$recommends', expected none"
    fi
else
    fail "noaudio build failed or did not produce $PKG"
fi

# --- 3. Cross-arch: plugin missing, and a package labeled for the other arch
# The ELF inside is this host's -- rpm labels the package from --target and
# never inspects the payload's machine type, so this case exercises the arch
# plumbing and the filename, and deliberately makes no claim about the binary.
echo "=== cross-arch, plugin missing ==="
PKG="sipnab-9.9.9-1.${OTHER_ARCH}.rpm"
rm -f "$PKG"
if NOPLUGIN=1 build 9.9.9 "$OTHER_ARCH" > /dev/null 2>&1 && [ -f "$PKG" ]; then
    pass "no-plugin build produced $PKG"
    requires="$(rpm -qp --requires "$PKG" 2> /dev/null)"
    recommends="$(rpm -qp --recommends "$PKG" 2> /dev/null)"
    contents="$(rpm -qpl "$PKG" 2> /dev/null)"
    info="$(rpm -qpi "$PKG" 2> /dev/null)"
    assert_contains     "no-plugin info" "$info" "$OTHER_ARCH"
    assert_not_contains "no-plugin contents" "$contents" "libsipnab_audio.so"
    assert_not_contains "no-plugin requires" "$requires" "libpcap.so.0.8"
    if [ -z "$recommends" ]; then
        pass "no-plugin recommends nothing"
    else
        fail "no-plugin recommends '$recommends', expected none"
    fi
else
    fail "no-plugin build failed or did not produce $PKG"
fi

# --- 4. A binary already using the RPM SONAME is packaged unchanged --------
echo "=== native RPM-world binary ==="
PKG="sipnab-2.0.0-1.${HOST_ARCH}.rpm"
rm -f "$PKG"
if BIN=bin/sipnab-native NOPLUGIN=1 build 2.0.0 "$HOST_ARCH" > /dev/null 2>&1 \
   && [ -f "$PKG" ]; then
    pass "native-SONAME build produced $PKG"
    requires="$(rpm -qp --requires "$PKG" 2> /dev/null)"
    assert_contains     "native requires" "$requires" "libpcap.so.1()(64bit)"
    dt="$(needed "$PKG")"
    assert_contains     "native binary DT_NEEDED" "$dt" "libpcap.so.1"
    assert_not_contains "native binary DT_NEEDED" "$dt" "libpcap.so.0.8"
else
    fail "native-SONAME build failed or did not produce $PKG"
fi

# --- 5. Adversarial inputs -------------------------------------------------
echo "=== adversarial inputs ==="
if build 1.2.3 "$HOST_ARCH" "bogus-variant" > /dev/null 2>&1; then
    fail "unknown variant 'bogus-variant' was accepted"
else
    pass "unknown variant 'bogus-variant' rejected"
fi

if build 1.2.3 "$HOST_ARCH" 'noaudio; touch pwned' > /dev/null 2>&1 || [ -e pwned ]; then
    fail "shell-metacharacter variant was accepted (or executed)"
else
    pass "shell-metacharacter variant rejected"
fi

if build 1.2.3 i386 > /dev/null 2>&1; then
    fail "unknown arch 'i386' was accepted"
else
    pass "unknown arch 'i386' rejected"
fi

# A rename the builder cannot perform must stop the build. Shipping the
# Debian SONAME quietly is the whole bug; a build that succeeds anyway would
# put it straight back.
PKG="sipnab-3.0.0-1.${HOST_ARCH}.rpm"
rm -f "$PKG"
if PATCHELF="$SANDBOX/no-such-patchelf" NOPLUGIN=1 build 3.0.0 "$HOST_ARCH" > /dev/null 2>&1 \
   || [ -f "$PKG" ]; then
    fail "build succeeded with no patchelf, so the Debian SONAME could ship"
else
    pass "missing patchelf fails the build instead of shipping libpcap.so.0.8"
fi

echo
echo "${PASSED} passed, ${FAILED} failed"
[ "$FAILED" -eq 0 ]
