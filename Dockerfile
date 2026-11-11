# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

# Multi-stage build for minimal image
#
# Both stages are pinned by digest, with the tag kept alongside it. A tag is a
# moving pointer: `debian:trixie-slim` can be republished under you, and this
# image ships to users through GHCR, so what they run would change without any
# commit here. The tag stays because it is what a reader and Dependabot read —
# and because rust_toolchain_pins_agree parses `FROM rust:X.Y` to check the
# builder compiles with the same toolchain CI pins.
#
# Updating: the runtime `debian` digest is Dependabot's (docker ecosystem,
# weekly). The `rust` builder is on Dependabot's ignore list, deliberately — a
# tag bump there would contradict the toolchain gate — so bump its digest by
# hand when you move the pinned toolchain. A stale builder digest is the
# tolerable half of that trade: the builder is not shipped, only its output is.
FROM rust:1.99-slim-trixie@sha256:24e632c09342c20abf8312cf4f61430a911c01ed3a5e4c02b87292b1c39c5273 AS builder
# cmake and make build libopus (the `opus` feature in `full`) from vendored
# source; the slim image carries neither. libcap2-bin provides `setcap`, used
# below.
RUN apt-get update && apt-get install -y libpcap-dev libasound2-dev pkg-config cmake make libcap2-bin && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --features full
# File capabilities, so the image's non-root user can capture (OPS-4). Docker's
# `--cap-add` puts a capability in the bounding set, but a process that is not
# root loses its permitted and effective sets at execve unless the file it
# runs carries file capabilities. Without these, `--cap-add NET_RAW --cap-add
# NET_ADMIN` reached the user `sipnab` as nothing at all.
#
# Permitted only (`+p`), not `+ep`. With the effective bit, execve fails with
# EPERM whenever the bounding set lacks one of the named capabilities, and
# Docker's default set lacks CAP_NET_ADMIN: `docker run <image> --version`
# would fail. With `+p` the kernel grants what the bounding set allows and
# sipnab raises it into the effective set at startup
# (`privilege::raise_capture_capabilities`). The names are
# `privilege::CAPTURE_CAP_NAMES`; tests/container_image_test.rs holds this line
# to them.
#
# After `strip`, which writes a new file and so drops extended attributes.
# `COPY --from` keeps the `security.capability` attribute.
RUN strip target/release/sipnab \
 && setcap cap_net_raw,cap_net_admin+p /build/target/release/sipnab

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime
# trixie renamed these runtime libs in the 64-bit time_t transition
# (libpcap0.8 -> libpcap0.8t64, libasound2 -> libasound2t64).
# `upgrade` before `install`, in the same layer: the base image is pinned by
# digest for reproducibility, which also means it never picks up Debian security
# updates published after that digest was built. util-linux 2.41-5 in this
# digest carries CVE-2026-53613 and CVE-2026-53614, both fixed in
# 2.41.5-0+deb13u1 — verified: the pinned base ships 2.41-5 and this line
# produces 2.41.5-0+deb13u1. Trivy runs with `ignore-unfixed: true`, so it fails
# the build only for vulnerabilities Debian has ALREADY fixed, which is exactly
# the set an upgrade resolves. Bumping the base digest would not have helped
# here: it was already the newest published one.
#
# This stage is NAMED so the build can refuse to cache it. A cached upgrade
# layer is the same packages forever, which turns the vulnerability scan into a
# test of whatever Debian shipped the day the cache was filled -- it passed for
# weeks and then failed on 0.5.168 with the image two point releases behind.
# See `no-cache-filters` in `.github/workflows/docker.yml`.
#
# ca-certificates puts the CA bundle at /etc/ssl/certs/ca-certificates.crt, the
# first path in src/tls_files.rs SYSTEM_CA_BUNDLES. Without it a TLS HEP sender
# in the image needed --hep-tls-ca even for a collector with a public
# certificate (OPS-15). It is pinned the way the other runtime packages are:
# by the digest-pinned trixie base, and upgraded in this uncached layer. A
# version pin would fail the build at every Debian update of the package (the
# archive keeps only the current version: the base's 20250419 is already
# superseded by 20250419+deb13u1 from trixie-security), and a CA bundle held
# back is one that still trusts a CA Debian has removed.
RUN apt-get update && apt-get upgrade -y \
 && apt-get install -y libpcap0.8t64 libasound2t64 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin sipnab
COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab
USER sipnab
ENTRYPOINT ["sipnab"]
CMD ["--help"]
