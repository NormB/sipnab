# SPDX-License-Identifier: MIT OR Apache-2.0
#
# voipmonitor, built from source, purely so the benchmark comparison can
# include it. Containerized deliberately: voipmonitor is not packaged for most
# distributions and a host install pulls in a database service, which is a lot
# to ask of someone who only wants to re-run a table.
#
# Build:
#   docker build -f bench/voipmonitor.Dockerfile -t voipmonitor:bench bench/
#
# Then bench/compare.sh picks it up via VM_IMAGE=voipmonitor:bench.
#
# Dependency list is voipmonitor's own README_debian.md, which is why it is not
# trimmed: guessing at it produces a configure that succeeds and a binary
# missing codecs.
FROM debian:bookworm@sha256:6ebd97fa83deb272194a2cf015b3d26a4d538e9ad3a7a79d544c8af5b0a01443

# `time` is GNU time, for peak-RSS measurement inside the container; the shell
# builtin reports CPU time only.
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential git ca-certificates time \
      default-libmysqlclient-dev libvorbis-dev libpcap-dev unixodbc-dev \
      libsnappy-dev libcurl4-openssl-dev libssh-dev libjson-c-dev librrd-dev \
      liblzo2-dev liblzma-dev libglib2.0-dev libxml2-dev libzstd-dev liblz4-dev \
      libssl-dev autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src
RUN git clone --depth 1 https://github.com/voipmonitor/sniffer.git
WORKDIR /usr/src/sniffer
RUN ./configure && make -j"$(nproc)" && make install && voipmonitor --version

ENTRYPOINT ["voipmonitor"]
