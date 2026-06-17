#!/bin/sh
# SIPp UAC: continuously cycles a curated set of public SIPp scenarios through
# opensips-1 so there is always live SIP+RTP traffic for sipnab to diagnose.
#
# "happy path" scenarios complete cleanly; "fault injection" scenarios send
# malformed/edge-case SIP and are EXPECTED to error or time out -- they exist
# to give the diagnosing agent real problems to find (bad SDP, bogus codecs,
# malformed messages). A non-zero exit from those is normal.
set -u

IFACE="${IFACE:-eth0}"
IP="$(ip -4 -o addr show "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)"
PROXY="${PROXY:-172.28.0.10:5060}"
PAUSE="${LOOP_PAUSE:-5}"
cd /harness/scenarios

# run <scenario> [extra sipp args...]
run() {
    scen="$1"; shift
    [ -f "$scen" ] || { echo "  skip $scen (not present)"; return; }
    echo "=== UAC ${scen} -> ${PROXY} ==="
    sipp -sf "$scen" "$PROXY" \
         -i "$IP" -mi "$IP" \
         -nostdin -m 1 -r 1 -l 1 \
         -timeout 25s -recv_timeout 6000 \
         -trace_err "$@" \
      || echo "  (${scen} exited non-zero -- ok for fault-injection scenarios)"
}

echo "sipp-uac: local ${IP}, proxy ${PROXY}, pause ${PAUSE}s"
cycle=0
while true; do
    cycle=$((cycle + 1))
    echo "########## cycle ${cycle} ##########"

    # ---- happy path ----
    run uac_basic.xml       -s service
    run uac_options.xml     -s service
    run uac_register.xml    -s regtest -inf register_data.csv
    run uac_hold.xml        -s service
    run uac_pcap_g711a.xml  -s service
    run uac_pcap_g722.xml   -s service

    # ---- fault injection (expected to error / time out) ----
    run uac_broken_sdp.xml  -s service
    run uac_bad_message.xml -s service
    run uac_bogus_codec.xml -s service

    echo "########## cycle ${cycle} done; sleeping ${PAUSE}s ##########"
    sleep "$PAUSE"
done
