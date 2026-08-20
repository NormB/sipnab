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

# --- libpcap carries two different SONAMEs, and this package needs the other one
#
# Debian patched libpcap's SONAME to libpcap.so.0.8 in the 0.x days and has
# never bumped it. Upstream, and therefore every RPM distribution, ships
# libpcap.so.1. Same library, same 1.10.x sources, same symbols, no symbol
# versioning on either side -- only the recorded name differs.
#
# The release workflow builds the gnu binaries, and packages both the .deb and
# this .rpm, inside a Debian container, so the binary's DT_NEEDED says
# libpcap.so.0.8. rpmbuild's automatic dependency generator reads DT_NEEDED and
# writes what it finds, so the published .rpm demanded
# `libpcap.so.0.8()(64bit)`. No Fedora or RHEL host provides that name, so dnf
# refused the install on a machine with libpcap already present.
#
# Filtering the generated Requires would be worse than the bug: the package
# would install and then fail to load libpcap, because the loader reads the
# same DT_NEEDED the generator does. So the ELF is what changes here. The
# generator then emits libpcap.so.1 on its own, because that is genuinely the
# library the packaged binary loads.
#
# The .deb keeps Debian's name, which is why this lives here and not in a
# shared step: the two package formats disagree about the SONAME because the
# two distribution families do.
DEBIAN_PCAP_SONAME="libpcap.so.0.8"
RPM_PCAP_SONAME="libpcap.so.1"
# Overridable the way the repo's other tool pins are (VALE_BIN, CODESPELL_BIN),
# so a test can prove the builder refuses to ship without it.
PATCHELF="${PATCHELF:-patchelf}"

# Resolve the ELF reader once. Doing it inside dt_needed would put the `exit`
# in a pipeline subshell, where it aborts the pipe and not the build.
if command -v readelf > /dev/null 2>&1; then
    dt_needed() { readelf -d "$1" 2> /dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'; }
elif command -v objdump > /dev/null 2>&1; then
    dt_needed() { objdump -p "$1" 2> /dev/null | awk '$1 == "NEEDED" { print $2 }'; }
else
    echo "Need readelf or objdump to read the packaged binary's libpcap SONAME." >&2
    echo "Debian/Ubuntu: apt-get install -y binutils" >&2
    exit 1
fi

# Read into a variable rather than piping into `grep -q`: this script runs
# under `set -o pipefail`, and a -q grep exits the moment it matches, which can
# leave the reader with SIGPIPE and turn a found SONAME into a failed pipeline
# — the one outcome that would silently skip the rewrite.
links_debian_pcap() { # elf-path
    local needed
    needed="$(dt_needed "$1")"
    case "${needed}" in
        "$DEBIAN_PCAP_SONAME") return 0 ;;
        "$DEBIAN_PCAP_SONAME"$'\n'* | *$'\n'"$DEBIAN_PCAP_SONAME"$'\n'* | *$'\n'"$DEBIAN_PCAP_SONAME") return 0 ;;
        *) return 1 ;;
    esac
}

# Copy first, rewrite second: release.yml hands over the very binary the
# tarball and the .deb are built from, and both of those must keep Debian's
# SONAME. The package gets its own copy.
stage_elf() { # src, dest
    cp "$1" "$2"
    chmod 0755 "$2"
    if ! links_debian_pcap "$2"; then
        return 0
    fi
    if ! command -v "$PATCHELF" > /dev/null 2>&1; then
        echo "$(basename "$2") links ${DEBIAN_PCAP_SONAME}, which no RPM distribution" >&2
        echo "provides, and patchelf is not installed to rename it. Building anyway" >&2
        echo "would publish an .rpm that dnf refuses to install." >&2
        echo "Debian/Ubuntu: apt-get install -y patchelf   (or set PATCHELF=/path/to/patchelf)" >&2
        exit 1
    fi
    "$PATCHELF" --replace-needed "$DEBIAN_PCAP_SONAME" "$RPM_PCAP_SONAME" "$2"
    if links_debian_pcap "$2"; then
        echo "patchelf left ${DEBIAN_PCAP_SONAME} in $(basename "$2")." >&2
        exit 1
    fi
    echo "Rewrote ${DEBIAN_PCAP_SONAME} -> ${RPM_PCAP_SONAME} in $(basename "$2")"
}

STAGED_BIN="$TOPDIR/SOURCES/sipnab"
stage_elf "$(readlink -f "${BIN_SRC}")" "$STAGED_BIN"
# Empty for a build with no libpcap linked at all; the post-build check below
# only demands the dependency when the binary actually took one.
PCAP_NEEDED="$(dt_needed "$STAGED_BIN" | grep '^libpcap\.so\.' || true)"

STAGED_PLUGIN=""
if [ "$WITH_PLUGIN" = "1" ]; then
    STAGED_PLUGIN="$TOPDIR/SOURCES/libsipnab_audio.so"
    stage_elf "$(readlink -f "${PLUGIN_SRC}")" "$STAGED_PLUGIN"
fi

SPEC="$TOPDIR/SPECS/sipnab.spec"
cat > "$SPEC" << 'SPEC_EOF'
%global debug_package %{nil}
%global _build_id_links none
# The binary may be foreign-arch (CI cross mode); never host-strip it.
%global __strip /bin/true
%global __brp_strip /bin/true
%global __brp_strip_static_archive /bin/true
%global __brp_check_rpaths %{nil}
# The audio plugin is dlopen'd lazily, and alsa-lib is declared below as a WEAK
# dependency on purpose: a headless server should not have the ALSA stack
# dragged in behind a feature it never uses, which is the whole point of the
# -noaudio variant existing beside this one. Left alone, the automatic
# generator reads libasound.so.2 out of the plugin's DT_NEEDED and writes a
# hard Requires for it -- the opposite of Recommends, and an install blocker on
# any host whose repositories carry no alsa-lib. Only the plugin directory is
# excluded; the binary's own dependencies are still generated from its ELF,
# which is what makes the libpcap Requires correct.
%global __requires_exclude_from ^/usr/lib/sipnab/

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
One static binary that reads a whole estate: Kamailio, OpenSIPS and
Asterisk mirror their signaling to a sipnab HEP listener, so one
process covers every node with no collector, no database and no web UI.
Adds first-class RTP support, VoIP diagnosis, security analysis, and
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
    --define "bin_src ${STAGED_BIN}" \
    --define "service_src $(readlink -f packaging/sipnab.service)" \
    ${WITH_PLUGIN:+--define "with_plugin ${WITH_PLUGIN}"} \
    ${STAGED_PLUGIN:+--define "plugin_src ${STAGED_PLUGIN}"} \
    --target "${ARCH}" \
    "$SPEC"

OUT="sipnab-${VERSION}-1.${ARCH}${SUFFIX}.rpm"
mv "$TOPDIR/RPMS/${ARCH}/sipnab-${VERSION}-1.${ARCH}.rpm" "$OUT"

# Check the artifact, not the inputs. The package is what a user points dnf at,
# and every step between the staged binary and the .rpm -- the spec, the
# generator, the exclude above -- can change what it asks for.
REQUIRES="$(rpm -qp --requires "$OUT" 2> /dev/null)"
case "$REQUIRES" in
    *"${DEBIAN_PCAP_SONAME}"*)
        echo "${OUT} requires ${DEBIAN_PCAP_SONAME}, which no RPM distribution" >&2
        echo "provides. dnf will refuse to install it. This is issue #244." >&2
        rm -f "$OUT"
        exit 1
        ;;
esac
if [ -n "$PCAP_NEEDED" ]; then
    case "$REQUIRES" in
        *"${RPM_PCAP_SONAME}"*) ;;
        *)
            echo "${OUT} packages a binary that loads ${PCAP_NEEDED} but does not" >&2
            echo "require it, so dnf would install it onto a host without libpcap." >&2
            rm -f "$OUT"
            exit 1
            ;;
    esac
fi

echo "Built: ${OUT}"
