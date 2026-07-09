#!/bin/sh
# Test harness for website/static/install.sh.
# The installer must be sourceable with SIPNAB_INSTALL_TEST=1 so its functions
# can be unit-tested without touching the network or the filesystem.
set -u

SCRIPT="$(dirname "$0")/../../website/static/install.sh"
PASS=0
FAIL=0

t() { # t <name> <expected> <actual>
  if [ "$2" = "$3" ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL %s\n  expected: %s\n  actual:   %s\n' "$1" "$2" "$3"
  fi
}

t_err() { # t_err <name> <exit-code-of-last-cmd> — expect nonzero
  if [ "$2" -ne 0 ]; then
    PASS=$((PASS + 1))
  else
    FAIL=$((FAIL + 1))
    printf 'FAIL %s\n  expected: nonzero exit\n  actual:   0\n' "$1"
  fi
}

[ -f "$SCRIPT" ] || { echo "FAIL install.sh does not exist at $SCRIPT"; exit 1; }

SIPNAB_INSTALL_TEST=1
export SIPNAB_INSTALL_TEST
# shellcheck disable=SC1090
. "$SCRIPT" || { echo "FAIL install.sh is not sourceable"; exit 1; }

# ── detect_os ────────────────────────────────────────────────────────
t "detect_os Linux"  "linux"  "$(detect_os Linux)"
t "detect_os Darwin" "darwin" "$(detect_os Darwin)"
detect_os FreeBSD >/dev/null 2>&1; t_err "detect_os FreeBSD rejected" $?
detect_os "" >/dev/null 2>&1; t_err "detect_os empty rejected" $?
detect_os 'Linux; rm -rf /' >/dev/null 2>&1; t_err "detect_os garbage rejected" $?

# ── detect_arch ──────────────────────────────────────────────────────
t "detect_arch x86_64"  "x86_64"  "$(detect_arch x86_64)"
t "detect_arch amd64"   "x86_64"  "$(detect_arch amd64)"
t "detect_arch aarch64" "aarch64" "$(detect_arch aarch64)"
t "detect_arch arm64"   "aarch64" "$(detect_arch arm64)"
detect_arch i686 >/dev/null 2>&1; t_err "detect_arch i686 rejected" $?
detect_arch armv7l >/dev/null 2>&1; t_err "detect_arch armv7l rejected" $?
detect_arch "" >/dev/null 2>&1; t_err "detect_arch empty rejected" $?
detect_arch 'x86_64\evil' >/dev/null 2>&1; t_err "detect_arch backslash rejected" $?

# ── glibc version parse + compare ────────────────────────────────────
t "parse_glibc debian ldd"  "2.36" "$(parse_glibc_version 'ldd (Debian GLIBC 2.36-9+deb12u10) 2.36')"
t "parse_glibc ubuntu ldd"  "2.39" "$(parse_glibc_version 'ldd (Ubuntu GLIBC 2.39-0ubuntu8.4) 2.39')"
t "parse_glibc trixie ldd"  "2.41" "$(parse_glibc_version 'ldd (Debian GLIBC 2.41-12) 2.41')"
parse_glibc_version 'musl libc (x86_64)' >/dev/null 2>&1; t_err "parse_glibc musl rejected" $?
parse_glibc_version '' >/dev/null 2>&1; t_err "parse_glibc empty rejected" $?

t "glibc_at_least 2.41 >= 2.39" "yes" "$(glibc_at_least 2.41 2.39)"
t "glibc_at_least 2.39 >= 2.39" "yes" "$(glibc_at_least 2.39 2.39)"
t "glibc_at_least 2.36 >= 2.39" "no"  "$(glibc_at_least 2.36 2.39)"
t "glibc_at_least 2.4 vs 2.36 (numeric not lexical)" "no" "$(glibc_at_least 2.4 2.36)"
t "glibc_at_least 3.0 >= 2.39" "yes" "$(glibc_at_least 3.0 2.39)"

# ── artifact choice ──────────────────────────────────────────────────
# linux + new glibc → gnu tarball; old/none/musl glibc → musl tarball; darwin → apple
t "choose linux x86_64 glibc2.41" "sipnab-0.5.2-x86_64-unknown-linux-gnu.tar.gz"   "$(choose_artifact linux x86_64 2.41 0.5.2)"
t "choose linux x86_64 glibc2.36" "sipnab-0.5.2-x86_64-unknown-linux-musl.tar.gz"  "$(choose_artifact linux x86_64 2.36 0.5.2)"
t "choose linux x86_64 no-glibc"  "sipnab-0.5.2-x86_64-unknown-linux-musl.tar.gz"  "$(choose_artifact linux x86_64 "" 0.5.2)"
t "choose linux aarch64 glibc2.39" "sipnab-0.5.2-aarch64-unknown-linux-gnu.tar.gz" "$(choose_artifact linux aarch64 2.39 0.5.2)"
t "choose darwin aarch64"         "sipnab-0.5.2-aarch64-apple-darwin.tar.gz"       "$(choose_artifact darwin aarch64 "" 0.5.2)"
t "choose darwin x86_64"          "sipnab-0.5.2-x86_64-apple-darwin.tar.gz"        "$(choose_artifact darwin x86_64 "" 0.5.2)"
choose_artifact plan9 x86_64 "" 0.5.2 >/dev/null 2>&1; t_err "choose bad os rejected" $?

# ── checksum verification ────────────────────────────────────────────
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
printf 'hello sipnab\n' > "$tmp/artifact.tar.gz"
good=$(sha256sum "$tmp/artifact.tar.gz" | cut -d' ' -f1)
printf '%s  artifact.tar.gz\n' "$good" > "$tmp/artifact.tar.gz.sha256"
verify_checksum "$tmp/artifact.tar.gz" "$tmp/artifact.tar.gz.sha256" >/dev/null 2>&1; t "verify ok" "0" "$?"
printf '%s  artifact.tar.gz\n' "0000000000000000000000000000000000000000000000000000000000000000" > "$tmp/artifact.tar.gz.sha256"
verify_checksum "$tmp/artifact.tar.gz" "$tmp/artifact.tar.gz.sha256" >/dev/null 2>&1; t_err "verify tampered rejected" $?
verify_checksum "$tmp/missing.tar.gz" "$tmp/artifact.tar.gz.sha256" >/dev/null 2>&1; t_err "verify missing file rejected" $?

echo "----------------------------------------"
echo "pass=$PASS fail=$FAIL"
[ "$FAIL" -eq 0 ]
