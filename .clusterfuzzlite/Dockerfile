# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The image ClusterFuzzLite builds sipnab's fuzz targets in.
#
# COPY, not `git clone`. ClusterFuzzLite fuzzes the tree it was handed --- a
# branch, a pull request, a commit that is not pushed yet. Cloning would fuzz
# whatever is on main and report the result as though it were about this
# commit. `ops/oss-fuzz/Dockerfile` clones, because OSS-Fuzz rebuilds from the
# public repository daily; that is the one place it is right.
#
# Pinned by digest, which OSS-Fuzz's own convention does not do: its projects
# write a bare `FROM gcr.io/oss-fuzz-base/base-builder-rust` and take whatever
# was rebuilt overnight. This repository pins every base image, and a fuzzing
# image is not an exception worth carving.
#
# What the pin does NOT cover, stated plainly: the two ClusterFuzzLite actions
# are Docker actions whose own runtime images are the floating tags
# `gcr.io/oss-fuzz-base/clusterfuzzlite-{build,run}-fuzzers:v1`. Nothing in
# this repository can pin those. The trust boundary for fuzzing is OSS-Fuzz's
# infrastructure either way; the pin here buys a reproducible build of the
# targets, not an unbroken chain.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:433319ea1a6bbea6c1db1915a5d385021908cc62026d9f0efda2270ef6060de3

# The builder image's Rust is a year behind sipnab's. It ships
# `nightly-2025-09-05` --- rustc 1.91.0-nightly --- and this crate's
# `rust-version` is 1.98, so without a newer toolchain the build stops at
# resolution with "rustc 1.91.0-nightly is not supported by the following
# packages" before a single target compiles. That failure is why this line
# exists rather than a guess that the image would be current.
#
# Pinned to a date, not `nightly`: a toolchain resolved at image-build time is
# a different compiler every day, and a fuzzing build that changes underneath
# you cannot be reproduced from a crash report.
ARG RUST_NIGHTLY=nightly-2026-09-01
# `rust-src` is not optional here even though nothing in this repository
# builds std: OSS-Fuzz's own `compile` script copies the standard library
# source out of the active toolchain so a sanitizer report can name a line
# inside std. Without it the build dies at `cp: cannot stat
# '.../lib/rustlib/src/rust/library/'`, after the image is built and every
# flag is right.
RUN rustup toolchain install "$RUST_NIGHTLY" --profile minimal --component rust-src

# ENV, not `rustup default`. The base image exports
# `RUSTUP_TOOLCHAIN=nightly-2025-09-05`, and an environment override beats
# the default in `settings.toml` --- so `rustup default` reports success,
# writes the setting, and changes nothing about which compiler runs. rustup
# says so in its own output ("currently in use (overridden by environment
# variable RUSTUP_TOOLCHAIN)") and the build still came back with 1.91.
ENV RUSTUP_TOOLCHAIN="$RUST_NIGHTLY"

# What the image does not ship at all is
# libpcap: `fuzz/Cargo.toml` depends on sipnab with the `native` feature, which
# links the capture backend, and without the headers `cargo fuzz build` fails
# at link time inside a container nobody is watching.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

COPY . $SRC/sipnab
COPY .clusterfuzzlite/build.sh $SRC/build.sh

WORKDIR $SRC/sipnab
