#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

set -euo pipefail

VERSION="${1:-$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[0].version")}"
ARCH="${2:-amd64}"
VARIANT="${3:-}"

# Variant selects the packaging flavor. "noaudio" ships no audio plugin and
# no libasound Recommends (for headless servers, where apt would otherwise
# pull in the ALSA stack) and suffixes the artifact name; empty means the
# default full package.
case "$VARIANT" in
    "")      SUFFIX="" ;;
    noaudio) SUFFIX="-noaudio" ;;
    *)
        echo "Unknown variant '${VARIANT}' (expected empty or 'noaudio')" >&2
        exit 1
        ;;
esac

PKG_DIR="sipnab_${VERSION}_${ARCH}${SUFFIX}"

echo "Building sipnab ${VERSION} for ${ARCH}${VARIANT:+ (${VARIANT})}..."

# Resolve the binary to package.
#
# When SIPNAB_BIN is set (CI cross-build mode), use that pre-built binary
# directly and do NOT rebuild or host-strip it -- it may be a foreign-arch
# binary the local strip cannot handle (the CI already strips native targets).
# When SIPNAB_BIN is unset (local mode), build natively as before.
# Resolve the audio plugin (libsipnab_audio.so), if available:
#   - CI cross mode: $SIPNAB_AUDIO_PLUGIN points at the prebuilt cdylib.
#   - Local mode: `cargo build --release --features full` builds the whole
#     workspace, so target/release/libsipnab_audio.so exists.
# If neither is present (e.g. a no-audio / musl build), ship no plugin and
# drop the libasound Recommends.
if [ -n "${SIPNAB_BIN:-}" ]; then
    echo "Using pre-built binary: ${SIPNAB_BIN}"
    BIN_SRC="${SIPNAB_BIN}"
    PLUGIN_SRC="${SIPNAB_AUDIO_PLUGIN:-}"
else
    cargo build --release --features full
    BIN_SRC="target/release/sipnab"
    PLUGIN_SRC="${SIPNAB_AUDIO_PLUGIN:-target/release/libsipnab_audio.so}"
fi

# The noaudio variant never ships the plugin, even when one was built.
if [ "$VARIANT" = "noaudio" ]; then
    PLUGIN_SRC=""
fi

# Normalize: only ship the plugin if the file actually exists.
if [ -n "${PLUGIN_SRC}" ] && [ -f "${PLUGIN_SRC}" ]; then
    SHIP_PLUGIN=1
else
    SHIP_PLUGIN=0
    PLUGIN_SRC=""
fi

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/share/man/man1"
mkdir -p "$PKG_DIR/etc/sipnab"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/share/doc/sipnab"

# Copy files
cp "$BIN_SRC" "$PKG_DIR/usr/bin/sipnab"
if [ -z "${SIPNAB_BIN:-}" ]; then
    strip "$PKG_DIR/usr/bin/sipnab"
fi
cp man/sipnab.1 "$PKG_DIR/usr/share/man/man1/"
gzip -9 "$PKG_DIR/usr/share/man/man1/sipnab.1"
# License and attribution. MIT and Apache-2.0 both require the notice to travel
# with the binary, and libasound (reached via the audio plugin) is
# LGPL-2.1-or-later, so the third-party notices are an obligation rather than a
# nicety. The package shipped none of this before.
cp LICENSE-MIT LICENSE-APACHE DUAL-LICENSE THIRD-PARTY-NOTICES.md "$PKG_DIR/usr/share/doc/sipnab/"
cp packaging/sipnab.service "$PKG_DIR/lib/systemd/system/"

# Audio plugin (optional): install the cdylib and add libasound Recommends.
RECOMMENDS_LINE=""
if [ "$SHIP_PLUGIN" = "1" ]; then
    echo "Shipping audio plugin: ${PLUGIN_SRC}"
    mkdir -p "$PKG_DIR/usr/lib/sipnab"
    cp "$PLUGIN_SRC" "$PKG_DIR/usr/lib/sipnab/libsipnab_audio.so"
    if [ -z "${SIPNAB_BIN:-}" ]; then
        strip "$PKG_DIR/usr/lib/sipnab/libsipnab_audio.so" || true
    fi
    RECOMMENDS_LINE="Recommends: libasound2 | libasound2t64"
else
    echo "No audio plugin available; building a no-audio package."
fi

# Create control file
cat > "$PKG_DIR/DEBIAN/control" << CTRL
Package: sipnab
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: libpcap0.8 | libpcap0.8t64${RECOMMENDS_LINE:+
$RECOMMENDS_LINE}
Maintainer: Norm Brandinger <n.brandinger@gmail.com>
Description: SIP & RTP capture, analysis, and security
 One static binary that reads a whole estate: Kamailio, OpenSIPS and
 Asterisk mirror their signaling to a sipnab HEP listener, so one
 process covers every node with no collector, no database and no web UI.
 Adds first-class RTP support, VoIP diagnosis, security analysis, and
 a declarative filter DSL.
Homepage: https://sipnab.com
CTRL

# Maintainer scripts. They follow what dh_installsystemd generates, by hand
# because this builder does not use debhelper: the service is stopped and
# disabled only when the package is removed, never when it is upgraded, and an
# upgrade restarts a running service so it does not keep running the replaced
# binary. A fresh install neither enables nor starts the service; that stays
# the administrator's decision. systemctl is reached through deb-systemd-invoke
# when it is installed, so that policy-rc.d is honored in chroots and image
# builds. A failing systemctl never fails the dpkg operation. Under DPKG_ROOT
# (dpkg operating on another root) nothing is stopped or restarted.
#
# packaging/deb/test-build-deb.sh runs each script per dpkg action against
# stub commands.

# postinst: "configure <old-version>" on an upgrade, "configure" alone on a
# fresh install.
cat > "$PKG_DIR/DEBIAN/postinst" << "POST"
#!/bin/sh
set -e
# Create sipnab user for privilege drop
if ! getent passwd sipnab > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent sipnab
fi
if [ "$1" = configure ] && [ -n "${2:-}" ] && [ -z "${DPKG_ROOT:-}" ] \
    && [ -d /run/systemd/system ]; then
    # Upgrade: load the new unit file, and restart the service only if it is
    # running (try-restart), so it runs the new /usr/bin/sipnab.
    systemctl daemon-reload > /dev/null 2>&1 || true
    if command -v deb-systemd-invoke > /dev/null 2>&1; then
        deb-systemd-invoke try-restart sipnab.service > /dev/null 2>&1 || true
    else
        systemctl try-restart sipnab.service > /dev/null 2>&1 || true
    fi
fi
POST
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# prerm: "remove", "upgrade <new-version>", "deconfigure ..." or
# "failed-upgrade <old-version>". Only "remove" acts. The disable happens here
# and not in postrm because systemctl reads the [Install] section of the unit
# file to find the links to delete, and the file is gone by postrm.
cat > "$PKG_DIR/DEBIAN/prerm" << "PRERM"
#!/bin/sh
set -e
if [ "$1" = remove ]; then
    if [ -z "${DPKG_ROOT:-}" ] && [ -d /run/systemd/system ]; then
        if command -v deb-systemd-invoke > /dev/null 2>&1; then
            deb-systemd-invoke stop sipnab.service > /dev/null 2>&1 || true
        else
            systemctl stop sipnab.service > /dev/null 2>&1 || true
        fi
    fi
    if command -v systemctl > /dev/null 2>&1; then
        if [ -n "${DPKG_ROOT:-}" ]; then
            systemctl --root="$DPKG_ROOT" --no-reload disable sipnab.service > /dev/null 2>&1 || true
        else
            systemctl --no-reload disable sipnab.service > /dev/null 2>&1 || true
        fi
    fi
fi
PRERM
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# postrm: after "remove" the unit file is gone, so systemd is told to forget
# it. "purge" follows a "remove" whose prerm already disabled the service.
cat > "$PKG_DIR/DEBIAN/postrm" << "POSTRM"
#!/bin/sh
set -e
if [ "$1" = remove ] && [ -z "${DPKG_ROOT:-}" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi
POSTRM
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# Build .deb
dpkg-deb --build "$PKG_DIR"
echo "Built: ${PKG_DIR}.deb"
