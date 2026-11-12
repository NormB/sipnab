#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# sipnab installer — https://sipnab.com/install.sh
#
#   curl -fsSL https://sipnab.com/install.sh | sh
#
# Detects OS (Linux/macOS), CPU (x86_64/aarch64), and glibc version, downloads
# the matching release tarball from GitHub, verifies its sha256, and installs
# the binary to /usr/local/bin (override with SIPNAB_INSTALL_DIR).
#
# The glibc floor of the -gnu builds; hosts below this get the static musl
# build instead. Must equal the floor enforced by the "Enforce glibc floor"
# step in release.yml and glibc_floor in website/config.toml — the Rust test
# published_glibc_floor_matches_release_gate fails if the three disagree.
# "Keep in sync" was the only thing holding this together before, and it did
# not: this said 2.39 while release.yml built to 2.36, so every Debian 12 host
# was pushed to the musl build it did not need.
SIPNAB_GLIBC_FLOOR="2.36"
SIPNAB_REPO="NormB/sipnab"
# The libpcap SONAME the -gnu builds link. They are built on Debian, which
# names libpcap libpcap.so.0.8; upstream and every RPM distribution name it
# libpcap.so.1. Must equal DEBIAN_PCAP_SONAME in packaging/rpm/build-rpm.sh,
# which tests/install-sh/run-tests.sh checks.
SIPNAB_GNU_PCAP_SONAME="libpcap.so.0.8"

set -u

err() { printf 'sipnab-install: error: %s\n' "$1" >&2; exit 1; }
info() { printf 'sipnab-install: %s\n' "$1"; }

detect_os() {
  case "${1:-}" in
    Linux)  echo linux ;;
    Darwin) echo darwin ;;
    *) printf 'sipnab-install: error: unsupported OS "%s" (Linux and macOS only; on Windows use WSL or build from source)\n' "${1:-}" >&2; return 1 ;;
  esac
}

detect_arch() {
  case "${1:-}" in
    x86_64|amd64)   echo x86_64 ;;
    aarch64|arm64)  echo aarch64 ;;
    *) printf 'sipnab-install: error: unsupported CPU "%s" (x86_64/amd64 and aarch64/arm64 only)\n' "${1:-}" >&2; return 1 ;;
  esac
}

# Read the glibc version out of ldd's first line. Empty exit 1 on musl, which
# is how an Alpine host reaches the static build it wants.
#
# Keyed on POSITION, not on a vendor string. This used to match the literal
# "GLIBC", which only Debian and Ubuntu print:
#
#   ldd (Debian GLIBC 2.36-9) 2.36     matched
#   ldd (Ubuntu GLIBC 2.39-...) 2.39   matched
#   ldd (GNU libc) 2.34                DID NOT -- RHEL, CentOS, Rocky, Alma
#   ldd (GNU libc) 2.39                DID NOT -- Fedora, RHEL 10
#
# so every RHEL-family host reported "no glibc detected" and took the musl
# build, including hosts far above the gnu floor, which silently cost them the
# audio feature. Matching "GNU libc" too would have fixed those distros and
# waited for the next vendor to rename its banner. The version is the last
# token of line 1 in every glibc family, and musl prints no version there.
parse_glibc_version() {
  _v=$(printf '%s\n' "${1:-}" | awk 'NR==1{print $NF}' \
       | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
  [ -n "$_v" ] || { printf 'sipnab-install: not a glibc host\n' >&2; return 1; }
  echo "$_v"
}

# glibc_at_least <have> <want> → "yes"/"no", numeric per-component compare
glibc_at_least() {
  _maj1=${1%%.*}; _min1=${1#*.}
  _maj2=${2%%.*}; _min2=${2#*.}
  if [ "$_maj1" -gt "$_maj2" ] 2>/dev/null; then echo yes
  elif [ "$_maj1" -eq "$_maj2" ] 2>/dev/null && [ "$_min1" -ge "$_min2" ] 2>/dev/null; then echo yes
  else echo no
  fi
}

# choose_artifact <os> <arch> <glibc-version-or-empty> <version> <libpcap yes|no>
# → tarball name. Linux gets the gnu build only when glibc is at the floor and
# the libpcap it links is installed; otherwise the static musl build, which
# needs neither.
choose_artifact() {
  _os=$1; _arch=$2; _glibc=$3; _ver=$4; _pcap=${5:-no}
  case "$_os" in
    darwin) echo "sipnab-${_ver}-${_arch}-apple-darwin.tar.gz" ;;
    linux)
      if [ -n "$_glibc" ] && [ "$(glibc_at_least "$_glibc" "$SIPNAB_GLIBC_FLOOR")" = "yes" ] \
         && [ "$_pcap" = "yes" ]; then
        echo "sipnab-${_ver}-${_arch}-unknown-linux-gnu.tar.gz"
      else
        echo "sipnab-${_ver}-${_arch}-unknown-linux-musl.tar.gz"
      fi
      ;;
    *) printf 'sipnab-install: error: unsupported OS "%s"\n' "$_os" >&2; return 1 ;;
  esac
}

# The architecture tag `ldconfig -p` prints for a library of this CPU, as in
# "libpcap.so.0.8 (libc6,x86-64) => ...". A 32-bit x86 library prints
# "(libc6)" alone and must not count for a 64-bit binary.
ldconfig_arch_tag() {
  case "${1:-}" in
    x86_64)  echo "x86-64" ;;
    aarch64) echo "AArch64" ;;
    *) return 1 ;;
  esac
}

# libpcap_present <arch> <ldconfig -p output> [<lib dir>...] → "yes"/"no"
#
# Whether the library the -gnu build loads, $SIPNAB_GNU_PCAP_SONAME, is
# installed for this CPU. The ldconfig cache answers when there is one. With
# no ldconfig output (ldconfig is in /sbin, which a non-root Debian PATH
# leaves out, and some hosts have no cache), each directory is checked for the
# file instead. Only the exact SONAME counts: libpcap.so (the -dev symlink)
# and libpcap.so.1 (Fedora's libpcap) do not satisfy the binary's DT_NEEDED.
libpcap_present() {
  _arch=$1; _cache=$2; shift 2
  if [ -n "$_cache" ]; then
    _tag=$(ldconfig_arch_tag "$_arch") || { echo no; return 0; }
    if printf '%s\n' "$_cache" | awk -v so="$SIPNAB_GNU_PCAP_SONAME" -v tag="$_tag" '
        $1 == so && index($2, "," tag ")") { found = 1 }
        END { exit found ? 0 : 1 }'; then
      echo yes
    else
      echo no
    fi
    return 0
  fi
  for _d in "$@"; do
    if [ -e "$_d/$SIPNAB_GNU_PCAP_SONAME" ]; then echo yes; return 0; fi
  done
  echo no
}

# The ldconfig cache listing, or nothing. Tries PATH, then the two places
# ldconfig lives, because /sbin is not on a non-root PATH on Debian.
ldconfig_listing() {
  for _l in ldconfig /sbin/ldconfig /usr/sbin/ldconfig; do
    if command -v "$_l" >/dev/null 2>&1; then
      "$_l" -p 2>/dev/null && return 0
    fi
  done
  return 0
}

# choice_reason <artifact> <glibc-version-or-empty> <libpcap yes|no> → the
# line the installer prints about which build it chose and why.
choice_reason() {
  _art=$1; _glibc=$2; _pcap=$3
  case "$_art" in
    *musl*)
      if [ -z "$_glibc" ]; then
        echo "no glibc detected — using the static musl build"
      elif [ "$(glibc_at_least "$_glibc" "$SIPNAB_GLIBC_FLOOR")" != "yes" ]; then
        echo "glibc $_glibc < $SIPNAB_GLIBC_FLOOR — using the static musl build (no TUI audio, WASM plugins, vCon export or eBPF uprobe backend)"
      else
        echo "$SIPNAB_GNU_PCAP_SONAME not found — using the static musl build (no TUI audio, WASM plugins, vCon export or eBPF uprobe backend). For the gnu build, install libpcap0.8t64 (Debian 13, Ubuntu 24.04) or libpcap0.8 (Debian 12) and run the installer again; on Fedora or RHEL install the .rpm package instead"
      fi
      ;;
    *gnu*) echo "glibc $_glibc and $SIPNAB_GNU_PCAP_SONAME found — using the gnu build, which needs libpcap" ;;
    *) : ;;
  esac
}

# install_payload <extracted dir> <dest dir> [<command prefix, e.g. sudo>]
#
# Installs the sipnab binary from the unpacked tarball into <dest>, and the
# audio plugin beside it when the tarball holds one. sipnab looks for the
# plugin next to its own executable first (src/rtp/playback.rs), so a binary
# installed alone has no TUI audio playback. The musl tarballs hold no plugin.
install_payload() {
  _src=$1; _dest=$2; _pre=${3:-}
  _bin=$(find "$_src" -type f -name sipnab | head -1)
  [ -n "$_bin" ] || { printf 'sipnab-install: error: sipnab binary not found in archive\n' >&2; return 1; }
  $_pre install -m 755 "$_bin" "$_dest/sipnab" || return 1
  for _name in libsipnab_audio.so libsipnab_audio.dylib; do
    _plugin=$(find "$_src" -type f -name "$_name" | head -1)
    [ -n "$_plugin" ] || continue
    $_pre install -m 644 "$_plugin" "$_dest/$_name" || return 1
    printf 'sipnab-install: installed the audio plugin %s/%s\n' "$_dest" "$_name"
  done
  return 0
}

# verify_checksum <file> <file.sha256> — .sha256 format: "<hex>  <basename>"
verify_checksum() {
  _file=$1; _sums=$2
  [ -f "$_file" ] || { printf 'sipnab-install: error: missing file %s\n' "$_file" >&2; return 1; }
  [ -f "$_sums" ] || { printf 'sipnab-install: error: missing checksum file %s\n' "$_sums" >&2; return 1; }
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$(dirname "$_file")" && sha256sum -c "$(basename "$_sums")" >/dev/null 2>&1) || {
      printf 'sipnab-install: error: sha256 mismatch for %s — download corrupted or tampered, aborting\n' "$_file" >&2; return 1; }
  elif command -v shasum >/dev/null 2>&1; then
    (cd "$(dirname "$_file")" && shasum -a 256 -c "$(basename "$_sums")" >/dev/null 2>&1) || {
      printf 'sipnab-install: error: sha256 mismatch for %s — download corrupted or tampered, aborting\n' "$_file" >&2; return 1; }
  else
    printf 'sipnab-install: error: neither sha256sum nor shasum found; refusing to install unverified binary\n' >&2; return 1
  fi
  return 0
}

main() {
  command -v curl >/dev/null 2>&1 || err "curl is required"
  command -v tar  >/dev/null 2>&1 || err "tar is required"

  os=$(detect_os "$(uname -s)") || exit 1
  arch=$(detect_arch "$(uname -m)") || exit 1

  glibc=""
  if [ "$os" = "linux" ] && command -v ldd >/dev/null 2>&1; then
    glibc=$(parse_glibc_version "$(ldd --version 2>&1 | head -1)" 2>/dev/null) || glibc=""
  fi

  version=${SIPNAB_VERSION:-}
  if [ -z "$version" ]; then
    version=$(curl -fsSL "https://api.github.com/repos/${SIPNAB_REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[^"]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
    [ -n "$version" ] || err "could not determine the latest version (set SIPNAB_VERSION to pin one)"
  fi

  pcap=no
  if [ "$os" = "linux" ]; then
    pcap=$(libpcap_present "$arch" "$(ldconfig_listing)" \
      "/lib/${arch}-linux-gnu" "/usr/lib/${arch}-linux-gnu" /lib64 /usr/lib64 /lib /usr/lib)
  fi

  artifact=$(choose_artifact "$os" "$arch" "$glibc" "$version" "$pcap") || exit 1
  if [ "$os" = "linux" ]; then
    info "$(choice_reason "$artifact" "$glibc" "$pcap")"
  fi

  base="https://github.com/${SIPNAB_REPO}/releases/download/v${version}"
  tmp=$(mktemp -d) || err "mktemp failed"
  trap 'rm -rf "$tmp"' EXIT

  info "downloading ${artifact} (v${version})"
  curl -fsSL -o "$tmp/$artifact" "$base/$artifact" || err "download failed: $base/$artifact"
  curl -fsSL -o "$tmp/$artifact.sha256" "$base/$artifact.sha256" || err "checksum download failed"
  verify_checksum "$tmp/$artifact" "$tmp/$artifact.sha256" || exit 1
  info "sha256 verified"

  mkdir "$tmp/x" || err "mktemp failed"
  tar -xzf "$tmp/$artifact" -C "$tmp/x" || err "extraction failed"

  dest="${SIPNAB_INSTALL_DIR:-/usr/local/bin}"
  if [ -w "$dest" ]; then
    install_payload "$tmp/x" "$dest" || err "install to $dest failed"
  else
    info "$dest is not writable — using sudo"
    install_payload "$tmp/x" "$dest" sudo || err "install to $dest failed"
  fi
  info "installed $dest/sipnab — run 'sipnab --version' to confirm"
  post_install_hint "$dest"
}

# Return 0 when $1 is a directory sudo would search, per sudo's secure_path.
#
# RHEL, CentOS, Rocky, Alma and Fedora ship
# secure_path=/sbin:/bin:/usr/sbin:/usr/bin, which does NOT include
# /usr/local/bin -- the default install prefix. So the interactive shell finds
# sipnab and `sudo sipnab` answers "command not found", which reads like the
# install failed. Debian and Ubuntu include /usr/local/bin and never see it.
#
# Best effort by design: `sudo -l` may prompt or be denied, so an inconclusive
# answer means "say nothing" rather than "warn wrongly".
sudo_can_find() {
  _dir=$1
  command -v sudo >/dev/null 2>&1 || return 0
  _sp=$(sudo -n -l 2>/dev/null | sed -n 's/.*secure_path=\([^ ]*\).*/\1/p' | head -1)
  [ -n "$_sp" ] || return 0
  case ":$_sp:" in
    *":$_dir:"*) return 0 ;;
    *) return 1 ;;
  esac
}

# What to actually run next, said once, only when it is not obvious.
#
# sipnab needs CAP_NET_RAW to open a live capture, so the step after install is
# almost always an attempt to get privileges. Pointing at setcap first is
# deliberate: it is the narrower grant, and it means the tool never runs as
# root at all.
post_install_hint() {
  _dest=$1
  printf 'sipnab-install: live capture needs CAP_NET_RAW. Grant it once:\n' >&2
  printf 'sipnab-install:   sudo setcap cap_net_raw,cap_net_admin+ep %s/sipnab\n' "$_dest" >&2
  printf 'sipnab-install: (re-apply after each upgrade — replacing the binary drops it)\n' >&2
  printf 'sipnab-install: reading a pcap needs no privileges at all: sipnab -I capture.pcap\n' >&2
  if ! sudo_can_find "$_dest"; then
    printf 'sipnab-install: NOTE %s is not in sudo secure_path on this host, so\n' "$_dest" >&2
    printf 'sipnab-install: "sudo sipnab" reports "command not found". Use the setcap\n' >&2
    printf 'sipnab-install: line above, or the full path: sudo %s/sipnab\n' "$_dest" >&2
  fi
}

# Under test, expose functions without executing.
if [ "${SIPNAB_INSTALL_TEST:-}" != "1" ]; then
  main "$@"
fi
