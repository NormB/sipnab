# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The image OSS-Fuzz builds sipnab's fuzz targets in. Submitted to
# google/oss-fuzz as projects/sipnab/Dockerfile; kept here so it is versioned
# beside the code it builds.
# Pinned by digest, matching `.clusterfuzzlite/Dockerfile`. OSS-Fuzz's
# convention is a bare image name; if submission ever requires that, this
# is the line to change and the reason to record.
FROM gcr.io/oss-fuzz-base/base-builder-rust:v1@sha256:433319ea1a6bbea6c1db1915a5d385021908cc62026d9f0efda2270ef6060de3

# The builder image ships nightly Rust and cargo-fuzz. It does not ship
# libpcap, which sipnab's `native` feature links; see the note in
# `.clusterfuzzlite/Dockerfile`.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# Shallow: OSS-Fuzz rebuilds from scratch daily and never reads history.
RUN git clone --depth 1 https://github.com/NormB/sipnab.git sipnab

# The shim OSS-Fuzz invokes. It execs `.clusterfuzzlite/build.sh` from the
# checkout, so the real build logic has ONE home and cannot drift between
# repositories.
COPY build.sh $SRC/build.sh

WORKDIR $SRC/sipnab
