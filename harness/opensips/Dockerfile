# OpenSIPS built from upstream, pinned to a release tag.
# Override OPENSIPS_GIT_URL / OPENSIPS_GIT_REF to build a fork or a branch.
# The default `make all` excludes all heavy-dep modules (DB, presence, pua,
# xml, tls_mgm, httpd, rest_client), so the build needs only a minimal dep set
# while still producing the modules this harness uses: proto_udp, tm, sl, rr,
# maxfwd, usrloc, registrar, rtpengine, sipmsgops, textops, nathelper, mi_fifo.
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd

ARG OPENSIPS_GIT_URL=https://github.com/OpenSIPS/opensips.git
ARG OPENSIPS_GIT_REF=3.6.7

RUN apt-get update && apt-get install -y --no-install-recommends \
        git ca-certificates \
        build-essential bison flex m4 pkg-config \
        libssl-dev libpcre2-dev libncurses-dev zlib1g-dev uuid-dev libmnl-dev \
        iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --filter=blob:none "$OPENSIPS_GIT_URL" /usr/src/opensips \
    && cd /usr/src/opensips && git checkout "$OPENSIPS_GIT_REF"

WORKDIR /usr/src/opensips
RUN make all -j"$(nproc)" && make install

COPY opensips.cfg.tmpl /etc/opensips/opensips.cfg.tmpl
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
