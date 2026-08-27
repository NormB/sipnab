#!/usr/bin/env bash
# One end-to-end run: place calls through opensips-1, let rtpengine anchor the
# media, and ask BOTH sipnab nodes what they saw.
#
# The two nodes are the point. The proxy sees signaling and no media; the
# relay sees media and no signaling. A result that came from one of them is
# half a call, so this script fails if either door is silent.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
CALLS="${CALLS:-3}"
SCENARIO="${SCENARIO:-uac_pcap_g711a.xml}"
PROXY_API="${PROXY_API:-http://127.0.0.1:8080}"
RELAY_API="${RELAY_API:-http://127.0.0.1:8081}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$HERE/results/e2e-$STAMP.md}"

echo "== placing $CALLS call(s) with $SCENARIO"
# sipp exits non-zero when ANY call fails, and under `set -o pipefail` that
# aborted this script before it reported anything -- the one run that most
# needs a report is the one with a failure in it. The status is captured and
# printed instead.
SIPP_RC=0
docker exec sipp-uac sh -c \
  "cd /harness/scenarios && sipp -sf '$SCENARIO' -s service 172.28.0.10:5060 \
   -m $CALLS -l 1 -timeout 60 -nostdin 2>&1" \
  > "$HERE/results/.sippraw.$$" 2>&1 || SIPP_RC=$?
grep -E "Successful call|Failed call" "$HERE/results/.sippraw.$$" | tail -2 \
  > "$HERE/results/.sipp.$$" || true
echo "  sipp exit=$SIPP_RC" >> "$HERE/results/.sipp.$$"
cat "$HERE/results/.sipp.$$"

# The exporters run at end of capture, and the relay learns a Call-ID from the
# mirrored ng control plane a beat after the media starts. Reading immediately
# reports a call the relay has seen the packets for but cannot yet name.
sleep 6

echo
echo "== REST: joining the two nodes"
python3 "$HERE/clients/leg_correlate.py" --proxy "$PROXY_API" --relay "$RELAY_API" \
  | tee "$HERE/results/.rest.$$"

echo
echo "== MCP: the same question at both doors"
python3 "$HERE/clients/mcp_probe.py" | tee "$HERE/results/.mcp.$$"

{
  echo "# sipnab two-node end-to-end run"
  echo
  echo "- UTC: \`$STAMP\`"
  echo "- Calls placed: \`$CALLS\` with \`$SCENARIO\`"
  echo "- sipnab: \`$(docker exec sipnab-proxy sipnab --version 2>/dev/null | head -1)\`"
  echo
  echo "## Topology"
  echo
  echo '```mermaid'
  echo 'flowchart LR'
  echo '    UAC["sipp-uac"] -->|INVITE| OS'
  echo '    subgraph P["proxy namespace"]'
  echo '      OS["opensips-1"]'
  echo '      SNP["sipnab-proxy<br/>signaling"]'
  echo '    end'
  echo '    subgraph R["relay namespace"]'
  echo '      RTP["rtpengine"]'
  echo '      SNR["sipnab-relay<br/>media"]'
  echo '    end'
  echo '    OS -->|relayed INVITE| UAS["sipp-uas"]'
  echo '    OS -->|ng control| RTP'
  echo '    UAC <-->|RTP| RTP'
  echo '    RTP <-->|RTP| UAS'
  echo '    RTP -.->|ng mirrored to HEP| SNR'
  echo '```'
  echo
  echo "## SIPp"
  echo; echo '```'; cat "$HERE/results/.sipp.$$"; echo '```'
  echo
  echo "## Correlated across both nodes (REST)"
  echo; echo '```'; cat "$HERE/results/.rest.$$"; echo '```'
  echo
  echo "## Both nodes over MCP"
  echo; echo '```'; cat "$HERE/results/.mcp.$$"; echo '```'
} > "$OUT"

rm -f "$HERE/results/.sippraw.$$" "$HERE/results/.sipp.$$" "$HERE/results/.rest.$$" "$HERE/results/.mcp.$$"
echo
echo "== wrote $OUT"
