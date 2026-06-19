#!/usr/bin/env bash
#
# update-formula.sh <version> <SHA256SUMS.txt>
#
# Render the NormB/homebrew-tap Homebrew formula for a given sipnab release,
# pulling the four prebuilt-target checksums out of the release's
# SHA256SUMS.txt. Prints the complete formula to stdout.
#
# Used by .github/workflows/release.yml to auto-bump the tap on every tag push,
# so a release can never again ship while the tap still points at the previous
# version. Fails loudly (non-zero, message on stderr) if the version is empty,
# the sums file is missing, any required target checksum is absent, or a
# checksum is not a well-formed lowercase 64-hex-char sha256 — better to break
# the release than to publish a formula with a wrong or blank checksum.
set -euo pipefail

die() { printf 'update-formula: %s\n' "$1" >&2; exit 1; }

VERSION="${1-}"
SUMS="${2-}"

[ -n "$VERSION" ] || die "version argument is required and must be non-empty"
[ -n "$SUMS" ]    || die "SHA256SUMS file argument is required"
[ -f "$SUMS" ]    || die "SHA256SUMS file not found: $SUMS"
# Reject control characters (NUL, etc.) in the version — they cannot appear in a
# real tag and would corrupt the generated formula / filename matching.
case "$VERSION" in
  *[![:print:]]*) die "version contains non-printable characters" ;;
esac

# Pull the checksum for exactly "sipnab-<version>-<target>.tar.gz". Match the
# filename as a literal string ($2 == name) so regex/shell metacharacters in the
# version are never interpreted, and a different version's line can never match.
sha_for() {
  local target="$1" name sha
  name="sipnab-${VERSION}-${target}.tar.gz"
  sha="$(awk -v n="$name" '$2 == n { print $1; exit }' "$SUMS")"
  [ -n "$sha" ] || die "no checksum for $name in $SUMS"
  [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || die "malformed sha256 for $name: '$sha' (need 64 lowercase hex chars)"
  printf '%s' "$sha"
}

mac_arm="$(sha_for aarch64-apple-darwin)"
mac_x86="$(sha_for x86_64-apple-darwin)"
lin_arm="$(sha_for aarch64-unknown-linux-gnu)"
lin_x86="$(sha_for x86_64-unknown-linux-gnu)"

base="https://github.com/NormB/sipnab/releases/download/v${VERSION}"

cat <<EOF
class Sipnab < Formula
  desc "SIP & RTP capture, analysis, and security tool"
  homepage "https://www.sipnab.com"
  license any_of: ["MIT", "Apache-2.0"]
  version "${VERSION}"

  on_macos do
    on_arm do
      url "${base}/sipnab-${VERSION}-aarch64-apple-darwin.tar.gz"
      sha256 "${mac_arm}"
    end
    on_intel do
      url "${base}/sipnab-${VERSION}-x86_64-apple-darwin.tar.gz"
      sha256 "${mac_x86}"
    end
  end

  on_linux do
    # The gnu binaries dynamically link libpcap (and need it at runtime).
    depends_on "libpcap"
    on_arm do
      url "${base}/sipnab-${VERSION}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "${lin_arm}"
    end
    on_intel do
      url "${base}/sipnab-${VERSION}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "${lin_x86}"
    end
  end

  def install
    bin.install "sipnab"
    man1.install "sipnab.1"
  end

  test do
    assert_match "sipnab", shell_output("#{bin}/sipnab --version")
  end
end
EOF
