# SIPp traffic generator (trixie sip-tester, built with pcap playback support).
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        sip-tester iproute2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY scenarios/ /harness/scenarios/
COPY run-uas.sh run-uac-loop.sh /harness/
RUN chmod +x /harness/run-uas.sh /harness/run-uac-loop.sh
WORKDIR /harness/scenarios
