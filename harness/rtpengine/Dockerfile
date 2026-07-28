# rtpengine media relay -- exact trixie/main package (matches the host version).
# Runs in userspace forwarding mode (table=-1, no kernel module), sharing
# opensips-1's network namespace so OpenSIPS reaches it on 127.0.0.1:22222.
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
RUN apt-get update && apt-get install -y --no-install-recommends \
        rtpengine-daemon iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
