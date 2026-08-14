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
FROM rust:1.97-slim-trixie@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS builder
RUN apt-get update && apt-get install -y libpcap-dev libasound2-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --features full
RUN strip target/release/sipnab

FROM debian:trixie-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258
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
RUN apt-get update && apt-get upgrade -y \
 && apt-get install -y libpcap0.8t64 libasound2t64 \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin sipnab
COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab
USER sipnab
ENTRYPOINT ["sipnab"]
CMD ["--help"]
