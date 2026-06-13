#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[0].version")}"
ARCH="${2:-amd64}"
PKG_DIR="sipnab_${VERSION}_${ARCH}"

echo "Building sipnab ${VERSION} for ${ARCH}..."

# Resolve the binary to package.
#
# When SIPNAB_BIN is set (CI cross-build mode), use that pre-built binary
# directly and do NOT rebuild or host-strip it -- it may be a foreign-arch
# binary the local strip cannot handle (the CI already strips native targets).
# When SIPNAB_BIN is unset (local mode), build natively as before.
if [ -n "${SIPNAB_BIN:-}" ]; then
    echo "Using pre-built binary: ${SIPNAB_BIN}"
    BIN_SRC="${SIPNAB_BIN}"
else
    cargo build --release --features full
    BIN_SRC="target/release/sipnab"
fi

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/man/man1"
mkdir -p "$PKG_DIR/etc/sipnab"
mkdir -p "$PKG_DIR/lib/systemd/system"

# Copy files
cp "$BIN_SRC" "$PKG_DIR/usr/bin/sipnab"
if [ -z "${SIPNAB_BIN:-}" ]; then
    strip "$PKG_DIR/usr/bin/sipnab"
fi
cp man/sipnab.1 "$PKG_DIR/usr/share/man/man1/"
gzip -9 "$PKG_DIR/usr/share/man/man1/sipnab.1"
cp contrib/sipnab.service "$PKG_DIR/lib/systemd/system/"

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << CTRL
Package: sipnab
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libpcap0.8 | libpcap0.8t64
Maintainer: Norm Brandinger <n.brandinger@gmail.com>
Description: SIP & RTP capture, analysis, and security
 sipnab unifies sngrep and sipgrep into a single Rust binary with
 first-class RTP support, VoIP diagnosis, security analysis, and
 a declarative filter DSL.
Homepage: https://sipnab.com
CTRL

# Create postinst
cat > "$PKG_DIR/DEBIAN/postinst" << "POST"
#!/bin/sh
set -e
# Create sipnab user for privilege drop
if ! getent passwd sipnab > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent sipnab
fi
POST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Build .deb
dpkg-deb --build "$PKG_DIR"
echo "Built: ${PKG_DIR}.deb"
