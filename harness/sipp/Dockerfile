# SIPp traffic generator (trixie sip-tester, built with pcap playback support).
FROM debian:trixie-slim@sha256:020c0d20b9880058cbe785a9db107156c3c75c2ac944a6aa7ab59f2add76a7bd
RUN apt-get update && apt-get install -y --no-install-recommends \
        sip-tester iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY scenarios/ /harness/scenarios/
COPY run-uas.sh run-uac-loop.sh /harness/
RUN chmod +x /harness/run-uas.sh /harness/run-uac-loop.sh
RUN useradd -U -u 1000 appuser && chown -R 1000:1000 /harness
USER 1000
WORKDIR /harness/scenarios
