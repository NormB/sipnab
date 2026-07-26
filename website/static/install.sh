#!/bin/sh
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

# Parse "ldd (Debian GLIBC 2.36-9) 2.36" → "2.36". Fails on musl/unknown.
parse_glibc_version() {
  _v=$(printf '%s' "${1:-}" | sed -n 's/.*GLIBC[^0-9]*\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p')
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

# choose_artifact <os> <arch> <glibc-version-or-empty> <version> → tarball name
choose_artifact() {
  _os=$1; _arch=$2; _glibc=$3; _ver=$4
  case "$_os" in
    darwin) echo "sipnab-${_ver}-${_arch}-apple-darwin.tar.gz" ;;
    linux)
      if [ -n "$_glibc" ] && [ "$(glibc_at_least "$_glibc" "$SIPNAB_GLIBC_FLOOR")" = "yes" ]; then
        echo "sipnab-${_ver}-${_arch}-unknown-linux-gnu.tar.gz"
      else
        echo "sipnab-${_ver}-${_arch}-unknown-linux-musl.tar.gz"
      fi
      ;;
    *) printf 'sipnab-install: error: unsupported OS "%s"\n' "$_os" >&2; return 1 ;;
  esac
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

  artifact=$(choose_artifact "$os" "$arch" "$glibc" "$version") || exit 1
  if [ "$os" = "linux" ]; then
    case "$artifact" in
      *musl*)
        if [ -n "$glibc" ]; then
          info "glibc $glibc < $SIPNAB_GLIBC_FLOOR — using the static musl build (no TUI audio; otherwise identical)"
        else
          info "no glibc detected — using the static musl build"
        fi
        ;;
      *) info "glibc $glibc — using the gnu build (needs libpcap: apt/dnf install libpcap)" ;;
    esac
  fi

  base="https://github.com/${SIPNAB_REPO}/releases/download/v${version}"
  tmp=$(mktemp -d) || err "mktemp failed"
  trap 'rm -rf "$tmp"' EXIT

  info "downloading ${artifact} (v${version})"
  curl -fsSL -o "$tmp/$artifact" "$base/$artifact" || err "download failed: $base/$artifact"
  curl -fsSL -o "$tmp/$artifact.sha256" "$base/$artifact.sha256" || err "checksum download failed"
  verify_checksum "$tmp/$artifact" "$tmp/$artifact.sha256" || exit 1
  info "sha256 verified"

  tar -xzf "$tmp/$artifact" -C "$tmp" || err "extraction failed"
  bin=$(find "$tmp" -type f -name sipnab | head -1)
  [ -n "$bin" ] || err "sipnab binary not found in archive"

  dest="${SIPNAB_INSTALL_DIR:-/usr/local/bin}"
  if [ -w "$dest" ]; then
    install -m 755 "$bin" "$dest/sipnab" || err "install to $dest failed"
  else
    info "$dest is not writable — using sudo"
    sudo install -m 755 "$bin" "$dest/sipnab" || err "install to $dest failed"
  fi
  info "installed $dest/sipnab — run 'sipnab --version' to confirm"
}

# Under test, expose functions without executing.
if [ "${SIPNAB_INSTALL_TEST:-}" != "1" ]; then
  main "$@"
fi
