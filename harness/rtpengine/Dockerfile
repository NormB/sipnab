# rtpengine media relay -- exact trixie/main package (matches the host version).
# Runs in userspace forwarding mode (table=-1, no kernel module), sharing
# opensips-1's network namespace so OpenSIPS reaches it on 127.0.0.1:22222.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        rtpengine-daemon iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
