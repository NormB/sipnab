# sipnab built as an MCP HTTP server + live capture probe.
# Build context is the sipnab repo root (see docker-compose.yml: context ../..).
# Feature set: capture (native) + MCP HTTP (pulls mcp + api) + TLS/SRTP.
# Deliberately excludes tui and audio so the runtime needs no libasound.
FROM rust:1.97-slim-trixie@sha256:5c6f46a6e4472ab1ca7ba7d494e6677f2f219ebc02f32025d3986f057635ec9c AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap-dev pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --locked \
        --no-default-features --features "native,mcp-http,tls" \
    && strip target/release/sipnab

FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
# trixie renamed libpcap0.8 -> libpcap0.8t64 (64-bit time_t transition).
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpcap0.8t64 tcpdump iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab
COPY harness/sipnab/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY harness/scripts/rotate-token.sh /usr/local/bin/rotate-token.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/rotate-token.sh
RUN useradd -U -u 1000 appuser && chown -R 1000:1000 /usr/local/bin/sipnab /usr/local/bin/entrypoint.sh /usr/local/bin/rotate-token.sh
USER 1000
# Runs as root: live capture needs CAP_NET_RAW and the MCP bind is >=1024.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
