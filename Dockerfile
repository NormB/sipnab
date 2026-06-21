# Multi-stage build for minimal image
FROM rust:1.94-slim-trixie AS builder
RUN apt-get update && apt-get install -y libpcap-dev libasound2-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --features full
RUN strip target/release/sipnab

FROM debian:trixie-slim
# trixie renamed these runtime libs in the 64-bit time_t transition
# (libpcap0.8 -> libpcap0.8t64, libasound2 -> libasound2t64).
RUN apt-get update && apt-get install -y libpcap0.8t64 libasound2t64 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin sipnab
COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab
USER sipnab
ENTRYPOINT ["sipnab"]
CMD ["--help"]
