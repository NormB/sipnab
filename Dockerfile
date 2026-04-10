# Multi-stage build for minimal image
FROM rust:1.92-slim-bookworm AS builder
RUN apt-get update && apt-get install -y libpcap-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --features full
RUN strip target/release/sipnab

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin sipnab
COPY --from=builder /build/target/release/sipnab /usr/local/bin/sipnab
USER sipnab
ENTRYPOINT ["sipnab"]
CMD ["--help"]
