#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[0].version')}"
ARCH="${2:-amd64}"
PKG_DIR="sipnab_${VERSION}_${ARCH}"

echo "Building sipnab ${VERSION} for ${ARCH}..."

# Build release binary
cargo build --release --features full

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/man/man1"
mkdir -p "$PKG_DIR/etc/sipnab"
mkdir -p "$PKG_DIR/lib/systemd/system"

# Copy files
cp target/release/sipnab "$PKG_DIR/usr/bin/"
strip "$PKG_DIR/usr/bin/sipnab"
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
Depends: libpcap0.8
Maintainer: Norm Brandinger <n.brandinger@gmail.com>
Description: SIP & RTP capture, analysis, and security
 sipnab unifies sngrep and sipgrep into a single Rust binary with
 first-class RTP support, VoIP diagnosis, security analysis, and
 a declarative filter DSL.
Homepage: https://sipnab.com
CTRL

# Create postinst
cat > "$PKG_DIR/DEBIAN/postinst" << 'POST'
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
