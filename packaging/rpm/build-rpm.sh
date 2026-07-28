#!/usr/bin/env bash
# Build a binary .rpm for sipnab, mirroring packaging/deb/build-deb.sh:
# same inputs (VERSION ARCH VARIANT), same env contract (SIPNAB_BIN /
# SIPNAB_AUDIO_PLUGIN for CI cross-build mode), same package payload
# (binary, gzipped man page, systemd unit, optional audio plugin with a
# weak ALSA dependency) and the same "-noaudio" artifact suffix.
set -euo pipefail

VERSION="${1:-$(cargo metadata --no-deps --format-version 1 | jq -r ".packages[0].version")}"
ARCH="${2:-x86_64}"
VARIANT="${3:-}"

case "$ARCH" in
    x86_64|aarch64) ;;
    *)
        echo "Unknown arch '${ARCH}' (expected x86_64 or aarch64)" >&2
        exit 1
        ;;
esac

# Variant selects the packaging flavor. "noaudio" ships no audio plugin and
# no alsa-lib weak dependency (for headless servers) and suffixes the
# artifact name; empty means the default full package.
case "$VARIANT" in
    "")      SUFFIX="" ;;
    noaudio) SUFFIX="-noaudio" ;;
    *)
        echo "Unknown variant '${VARIANT}' (expected empty or 'noaudio')" >&2
        exit 1
        ;;
esac

echo "Building sipnab ${VERSION} for ${ARCH}${VARIANT:+ (${VARIANT})}..."

# Resolve the binary to package (see build-deb.sh for the CI/local split).
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
if [ -n "${PLUGIN_SRC}" ] && [ -f "${PLUGIN_SRC}" ]; then
    WITH_PLUGIN=1
else
    WITH_PLUGIN=0
    PLUGIN_SRC=""
    echo "No audio plugin available; building a no-audio package."
fi

TOPDIR="$(pwd)/target/rpmbuild-${ARCH}${SUFFIX}"
rm -rf "$TOPDIR"
mkdir -p "$TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Stage the gzipped man page as a source the spec installs.
gzip -9 -c man/sipnab.1 > "$TOPDIR/SOURCES/sipnab.1.gz"

SPEC="$TOPDIR/SPECS/sipnab.spec"
cat > "$SPEC" << 'SPEC_EOF'
%global debug_package %{nil}
%global _build_id_links none
# The binary may be foreign-arch (CI cross mode); never host-strip it.
%global __strip /bin/true
%global __brp_strip /bin/true
%global __brp_strip_static_archive /bin/true
%global __brp_check_rpaths %{nil}

Name:           sipnab
Version:        %{pkg_version}
Release:        1
Summary:        SIP & RTP capture, analysis, and security
License:        MIT OR Apache-2.0
URL:            https://sipnab.com
Requires:       libpcap
%if 0%{?with_plugin}
Recommends:     alsa-lib
%endif

%description
sipnab unifies sngrep and sipgrep into a single Rust binary with
first-class RTP support, VoIP diagnosis, security analysis, and
a declarative filter DSL.

%install
install -D -m 0755 %{bin_src} %{buildroot}/usr/bin/sipnab
install -D -m 0644 %{_sourcedir}/sipnab.1.gz %{buildroot}/usr/share/man/man1/sipnab.1.gz
install -D -m 0644 %{service_src} %{buildroot}/usr/lib/systemd/system/sipnab.service
%if 0%{?with_plugin}
install -D -m 0644 %{plugin_src} %{buildroot}/usr/lib/sipnab/libsipnab_audio.so
%endif

%pre
# Create sipnab user for privilege drop (mirrors the .deb postinst).
if ! getent passwd sipnab > /dev/null 2>&1; then
    useradd -r -s /usr/sbin/nologin -d /nonexistent sipnab
fi

%files
/usr/bin/sipnab
/usr/share/man/man1/sipnab.1.gz
/usr/lib/systemd/system/sipnab.service
%if 0%{?with_plugin}
/usr/lib/sipnab/libsipnab_audio.so
%endif
SPEC_EOF

rpmbuild -bb \
    --define "_topdir ${TOPDIR}" \
    --define "pkg_version ${VERSION}" \
    --define "bin_src $(readlink -f "${BIN_SRC}")" \
    --define "service_src $(readlink -f packaging/sipnab.service)" \
    ${WITH_PLUGIN:+--define "with_plugin ${WITH_PLUGIN}"} \
    ${PLUGIN_SRC:+--define "plugin_src $(readlink -f "${PLUGIN_SRC}")"} \
    --target "${ARCH}" \
    "$SPEC"

OUT="sipnab-${VERSION}-1.${ARCH}${SUFFIX}.rpm"
mv "$TOPDIR/RPMS/${ARCH}/sipnab-${VERSION}-1.${ARCH}.rpm" "$OUT"
echo "Built: ${OUT}"
