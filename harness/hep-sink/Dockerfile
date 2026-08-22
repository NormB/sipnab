# A stand-in Homer collector: it absorbs HEP and does nothing else.
#
# It exists because rtpengine will not mirror into the void. It CONNECTS its
# Homer socket, so an unreachable destination returns ICMP port-unreachable,
# rtpengine logs "Connection error from Homer ... Connection refused" and drops
# the trace. Aiming --homer at an address nobody answers therefore produces no
# control plane at all, which looks identical to the feature being broken.
#
# Standing in for Homer rather than replacing it is the point. sipnab reads
# these datagrams PASSIVELY off the wire; it is not the recipient. That is the
# deployment sipnab is built for -- rtpengine takes exactly ONE --homer
# destination, so pointing it at a diagnostic tool would take it away from the
# collector it already feeds.
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
RUN apt-get update && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*
# fork so one sender erroring out does not end the listener.
CMD ["socat", "-u", "UDP-RECVFROM:9060,fork,reuseaddr", "/dev/null"]
