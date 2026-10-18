# Recipes for common tasks

Recipe-style walkthroughs for the things people actually want to do. Each recipe:

- states the problem,
- gives exact commands,
- tells you what to look for in the output,
- flags common pitfalls.

Each recipe stands alone. Nothing here depends on anything above it.
If you are new, [1. Triage a pcap fast](#triage-a-pcap-fast) is the broadest starting point.

## What do you want to do?

**Find out what went wrong**

| I want to… | Recipe |
|---|---|
| Work out whether anything is wrong with a capture | [1. Triage a pcap fast](#triage-a-pcap-fast) |
| See which calls failed, and why | [3. Find every failed call, grouped by response code](#find-every-failed-call-grouped-by-response-code) |
| Write a filter for common triage | [5. Filter for the five things you look for most](#filter-for-the-five-things-you-look-for-most) |
| Read a busy capture call by call | [18. Collect messages by call, host or method](#collect-messages-by-call-host-or-method) |
| Find every call that mentions a string | [38. Search a capture for a header or a body string](#search-a-capture-for-a-header-or-a-body-string) |
| Get one machine-readable verdict per capture | [16. Analyze a capture into one machine-readable verdict](#analyze-a-capture-into-one-machine-readable-verdict) |
| Read the timers behind a slow call | [41. Measure the gap between consecutive messages](#measure-the-gap-between-consecutive-messages) |
| Chase calls that answer and then drop | [30. Find calls that answered and were never acknowledged](#find-calls-that-answered-and-were-never-acknowledged) |
| Work out why a capture shows almost no SIP | [29. Read a capture whose SIP is not on port 5060](#read-a-capture-whose-sip-is-not-on-port-5060) |
| Read a load test that reuses one Call-ID | [47. Follow a load generator's traffic by transaction, not by call](#follow-a-load-generators-traffic-by-transaction-not-by-call) |
| Settle "we sent it" / "we never got it" | [27. Compare the same call at two nodes](#compare-the-same-call-at-two-nodes) |
| Look only at the hour the problem happened | [67. Narrow a capture to when the problem happened](#narrow-a-capture-to-when-the-problem-happened) |

**Chase audio and quality complaints**

| I want to… | Recipe |
|---|---|
| Chase a "no audio" or "one-way audio" complaint | [4. Diagnose a one-way audio complaint](#diagnose-a-one-way-audio-complaint) |
| Work out why a call sounds bad in one direction | [11. Find why a call sounds bad in one direction only](#find-why-a-call-sounds-bad-in-one-direction-only) |
| Know whether the loss is mine or the network's | [22. Measure whether the loss is yours or the network's](#measure-whether-the-loss-is-yours-or-the-networks) |
| Explain one-way findings on a VoLTE trunk | [45. Check whether comfort noise explains a one-way finding](#check-whether-comfort-noise-explains-a-one-way-finding) |
| Diagnose a codec mismatch to a vendor | [24. Diagnose a codec mismatch](#diagnose-a-codec-mismatch) |
| Work out why DTMF never lands | [25. Find out why DTMF does not reach the IVR](#find-out-why-dtmf-does-not-reach-the-ivr) |
| See what NAT/STUN/TURN did | [17. Inspect what NAT did to a call](#inspect-what-nat-did-to-a-call) |
| Know what a media-address claim is worth | [54. Find out where a stream's endpoint came from](#find-out-where-a-streams-endpoint-came-from) |
| Decide what counts as bad audio on my network | [31. Set the quality thresholds to your own network](#set-the-quality-thresholds-to-your-own-network) |
| Listen to the audio | [13. Export RTP audio as WAV](#export-rtp-audio-as-wav) |

**Capture live, at scale, or through tunnels**

| I want to… | Recipe |
|---|---|
| Watch one user's traffic live | [2. Live capture, narrow to a single user](#live-capture-narrow-to-a-single-user) |
| Capture without running as root | [48. Run a live capture without giving sipnab root](#run-a-live-capture-without-giving-sipnab-root) |
| Keep a capture running across reboots | [28. Run sipnab as a service](#run-sipnab-as-a-service) |
| Capture overnight without filling the disk | [44. Run a capture that stops on its own](#run-a-capture-that-stops-on-its-own) |
| Stop a week-long capture from eating the box | [43. Keep a long-running capture inside a memory budget](#keep-a-long-running-capture-inside-a-memory-budget) |
| Read a very large capture faster | [19. Read a very large capture faster](#read-a-very-large-capture-faster) |
| Read a call that spans several capture files | [39. Collect a directory of rotated captures into one analysis](#collect-a-directory-of-rotated-captures-into-one-analysis) |
| Read SIP split across TCP segments | [35. Read SIP that arrives in TCP segments or IP fragments](#read-sip-that-arrives-in-tcp-segments-or-ip-fragments) |
| See the WebRTC leg of a call | [36. Read SIP over WebSocket from a WebRTC gateway](#read-sip-over-websocket-from-a-webrtc-gateway) |
| Capture SIP inside a mobile or fabric tunnel | [37. Read SIP carried inside a GTP-U or VXLAN tunnel](#read-sip-carried-inside-a-gtp-u-or-vxlan-tunnel) |
| Move eleven flags into a config file | [49. Configure sipnab from a file instead of a long command line](#configure-sipnab-from-a-file-instead-of-a-long-command-line) |
| Stop typing flags from memory | [50. Install shell completions](#install-shell-completions) |

**Read encrypted traffic**

| I want to… | Recipe |
|---|---|
| Read encrypted SIP or SRTP | [7. Decrypt SIP over TLS with a key log file](#decrypt-sip-over-tls-when-you-can-restart-the-phone-or-server--key-log-file-sslkeylogfile) |
| Read TLS with **no keys at all** (eBPF) | [7g. Read TLS with no keys](#read-tls-with-no-keys-at-all) and [7h. …and who the peer was](#read-tls-and-who-the-peer-was) |
| Understand what reading TLS without keys costs and requires | [TLS-without-keys walkthrough](uprobe-walkthrough.md) — security implications, and whether your kernel supports it |
| Decrypt TLS from a server private key | [59. Decrypt TLS with the server's private key](#decrypt-tls-with-the-servers-private-key) |

**Collect from proxies, relays and recorders**

| I want to… | Recipe |
|---|---|
| Collect traffic from proxies I cannot install on | [6. Wire HEP from your SIP stack to a central sipnab](#wire-hep-from-your-sip-stack-to-a-central-sipnab) |
| Collect HEP *and* forward it upstream | [26. Run sipnab as a HEP relay](#run-sipnab-as-a-hep-relay) |
| Graph traffic over time | [9. Graph call rate, response codes and PDD over time](#graph-call-rate-response-codes-and-pdd-over-time) |
| See who is on a recorded call | [60. See who is on a recorded call](#see-who-is-on-a-recorded-call) |
| Ask a media relay whether it is dropping packets | [61. Ask a relay whether it is dropping packets](#ask-a-relay-whether-it-is-dropping-packets) |
| See if a relay is holding sessions nobody released | [62. Ask a relay what it is still holding](#ask-a-relay-what-it-is-still-holding) |
| Compare a relay's view of a call with mine | [63. Compare a relay's per-call count with your capture](#compare-a-relays-per-call-count-with-your-capture) |
| Tell a relay's reported loss from the loss I measured | [64. Read a relay's loss beside the loss you measured](#read-a-relays-loss-beside-the-loss-you-measured) |

**Detect abuse and fraud**

| I want to… | Recipe |
|---|---|
| Detect and block scanners or fraud | [10. Detect SIP scanners and auto-block via fail2ban](#detect-sip-scanners-and-auto-block-via-fail2ban) |
| Chase a device flooding REGISTER | [23. Find the device flooding REGISTER](#find-the-device-flooding-register) |
| Catch calls placed at three in the morning | [46. Detect fraud placed outside business hours](#detect-fraud-placed-outside-business-hours) |
| See what a STIR/SHAKEN token actually claims | [33. Check what a STIR/SHAKEN Identity header actually claims](#check-what-a-stirshaken-identity-header-actually-claims) |
| Audit how the phones authenticate | [34. Detect weak digest authentication on a registrar](#detect-weak-digest-authentication-on-a-registrar) |
| Add my own detection | [21. Detect your own fault patterns with a plugin](#detect-your-own-fault-patterns-with-a-plugin) |

**Share the evidence**

| I want to… | Recipe |
|---|---|
| Hand someone a written summary of a call | [12. Generate a call report (text / Markdown / JSON)](#generate-a-call-report-text--markdown--json) |
| Check signaling against the RFCs | [15. Check a capture against the RFCs](#check-a-capture-against-the-rfcs) |
| Prove a finding with the exact bytes | [20. Verify the exact bytes behind a finding](#verify-the-exact-bytes-behind-a-finding) |
| Hand the same packets to Wireshark | [40. Open the same evidence in Wireshark](#open-the-same-evidence-in-wireshark) |
| Send a carrier the capture with my notes on the frames | [65. Send a carrier the capture with your notes on the frames](#send-a-carrier-the-capture-with-your-notes-on-the-frames) |
| Send a vendor only the calls that concern them | [32. Export one customer's calls as a smaller capture](#export-one-customers-calls-as-a-smaller-capture) |
| Prove which command produced a report | [42. Record which invocation produced a report](#record-which-invocation-produced-a-report) |
| Look at a pcap with nothing installed | [14. Analyze a pcap without installing anything](#analyze-a-pcap-without-installing-anything) |
| Export one call to a conversation archive | [13b. Export one call to a conversation archive as a vCon](#export-one-call-to-a-conversation-archive-as-a-vcon) |
| Ship failed calls to an archive without the numbers | [51. Export every failed call as a redacted vCon in one pass](#export-every-failed-call-as-a-redacted-vcon-in-one-pass) |
| Validate a vCon before a store refuses it | [52. Check a vCon against the schema before a store rejects it](#check-a-vcon-against-the-schema-before-a-store-rejects-it) |
| Analyze calls somebody stored as vCons | [66. Analyze a call from a stored vCon](#analyze-a-call-from-a-stored-vcon) |

**Let an AI agent do it**

| I want to… | Recipe |
|---|---|
| Drive sipnab from an AI agent | [8. Let an AI agent ask sipnab about your calls](#let-an-ai-agent-ask-sipnab-about-your-calls) |
| Expose MCP to an agent I do not host | [55. Set up the MCP server for a hosted agent](#set-up-the-mcp-server-for-a-hosted-agent) |
| Let an agent read TLS with no keys | [56. Read TLS from an agent, with no keys and no restart](#read-tls-from-an-agent-with-no-keys-and-no-restart) |
| Get a count an agent cannot miscount | [57. Ask the capture how many calls failed](#ask-the-capture-how-many-calls-failed) |
| Get the facts behind a MOS score | [58. Ask why the MOS is what it is](#ask-why-the-mos-is-what-it-is) |
| Export a whole set of calls in one agent call | [53. Export a vCon per failed call in one round trip](#export-a-vcon-per-failed-call-in-one-round-trip) |

Just want a command to copy? [Look up a one-liner by task](#look-up-a-one-liner-by-task).

### Where a recipe fits

Most recipes are one of three shapes. Knowing which you are in tells you what
the commands are doing:

```mermaid
flowchart LR
    P[pcap file] --> A[sipnab]
    L[live interface] --> A
    H[HEP from proxies] --> A
    A --> T[TUI: look at it]
    A --> J[JSON / report: pipe it]
    A --> M[metrics / alerts: watch it]
```

- **Look at it** — the TUI, for a human working a ticket.
- **Pipe it** — JSON, reports, WAV, Wireshark filters, for tooling.
- **Watch it** — metrics, scanner detection, alerts, for something long-running.

## Triage a pcap fast

**Problem:** Someone handed you a `capture.pcap` and asked "is anything wrong?"

**Commands:**

Open the call list and scan it visually — the interactive TUI:

```bash
sipnab -I capture.pcap
```

The same capture without the TUI. `-N` prints one line per SIP message, and then a totals line.
A message line shows time, source, destination, method or status, and transport:

```bash
sipnab -N -I capture.pcap
```

One line per call instead. Each line shows state, final response code, duration and PDD
(post-dial delay). `--no-cli-print` drops the per-message lines:

```bash
sipnab -N -I capture.pcap --report --no-cli-print
```

A one-flag diagnostic sweep. `--problems` keeps only these calls:

- the calls that failed,
- the calls that show any of these:
  - one-way audio,
  - high loss or jitter,
  - a NAT mismatch,
  - retransmits,
  - slow setup,
  - a media asymmetry.

What to look for, below, gives the exact expression:

```bash
sipnab -N -I capture.pcap --problems
```

The same selection as a per-call table, which is usually the quickest read:

```bash
sipnab -N -I capture.pcap --problems --report --no-cli-print
```

The same sweep in JSON, for piping into another tool:

```bash
sipnab -N -I capture.pcap --problems --json
```

The same sweep spelled the long way. `--problems` expands to the `problems` DSL alias. So this selects exactly the same calls.

```bash
sipnab -N -I capture.pcap --filter problems
```

Without `--report`, the `--problems` sweep prints a flagged call's messages.
It starts at the message that made the call a problem.

- For a failed call, that is the final error response and the ACK after it.
- The end-of-capture totals line follows on stderr.

[`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap)
is a sample in the repository. It holds four failed calls. Against it, the first lines read:

```text
22:13:24.800 192.0.2.40:5060 -> 192.0.2.30:5060 486 Busy Here UDP
22:13:24.810 192.0.2.30:5060 -> 192.0.2.40:5060 ACK UDP
22:13:27.800 198.51.100.40:5060 -> 198.51.100.30:5060 603 Decline UDP
22:13:27.810 198.51.100.30:5060 -> 198.51.100.40:5060 ACK UDP
```

**What to look for:**

- The `--problems` **flag** and the **DSL alias** reached with `--filter problems` expand to one and the same expression: `state == 'Failed' OR one_way == true OR rtp.loss > 5.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 11.0 OR codec_asymmetry == true OR ptime_asymmetry == true OR payload_asymmetry == true OR duration_asymmetry == true OR late_media == true`.
  - Either spelling flags the same calls.
  - So an empty answer means the capture is probably clean.
- The end-of-capture summary distinguishes RTP packets from RTP streams: `852 packets captured, 10 SIP messages, 839 RTP packets across 2 streams`.
  - A capture with media but no SIP usually means the SIP signaling happened off-pcap.
  - For example: a different VLAN, a different host, or a different port.

**Pitfalls:**

- The TUI requires a tty. If you're SSH'd in without `-t`, force `-N` mode.
- For large pcaps (>1 GB), prefer `-N` first. The TUI loads everything into memory.

**Runnable example:** [Triage a capture to one verdict](client-examples.md#triage-a-capture-to-one-verdict) turns this triage into one verdict and an exit status.
It also tells a capture with nothing to judge apart from a clean one.

---

## Live capture, narrow to a single user

**Problem:** A user reports their calls are flaky. Capture only their traffic in real time.

**Commands:**

Capture on eth0, and keep only this user's calls. The filter matches From or To:

```bash
sudo sipnab -d eth0 --filter "from.user == '1001' OR to.user == '1001'"
```

The same capture with a CLI summary line per dialog instead of the TUI:

```bash
sudo sipnab -N -d eth0 --filter "from.user == '1001' OR to.user == '1001'" --json
```

**What to look for:**

- The TUI's call list updates as new dialogs appear. Press `Tab` to switch to the RTP stream view. Press `Enter` on a stream to see jitter/loss/MOS history.
- In CLI mode, each completed dialog is one line of JSON. Pipe to `jq` or `tee` to a log.

**Pitfalls:**

- Live capture needs `CAP_NET_RAW` (Linux) or root. `setcap cap_net_raw,cap_net_admin=eip $(which sipnab)` lets you skip `sudo` after the first run.
- The filter DSL evaluates against complete dialog records.
  - It evaluates once the dialog state machine has enough information.
  - That is typically after the first response.
  - It is earlier for fields that only depend on the request.
- For per-header regex filtering on individual messages, use the older `--from`, `--to`, `--contact`, `--ua` flags.
  - `sipnab --help` lists them.

---

## Find every failed call, grouped by response code

**Problem:** "We had a spike in failures around 14:00. What was it?"

**Commands:**

`sipnab -N --json` emits per-message records, not per-dialog summaries.

- It writes one JSON line per SIP message.
- The `status_code` field is on response messages.
- `--filter` evaluates against the dialog. So all messages from matched dialogs flow through.
- Combine the two, and you get a histogram of every response code seen during failed dialogs:

Every failed call's response messages — Call-ID, status_code and reason:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq 'select(.is_request == false) | {call_id, status_code, reason}'
```

A histogram of the response codes seen in failed dialogs:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r 'select(.is_request == false) | .status_code' \
  | sort | uniq -c | sort -rn
```

A detailed report for one failure, in Markdown, ready to paste into a ticket:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --markdown > failure-report.md
```

The histogram output looks like (`uniq -c` count, then status code):

```text
     23 100
     14 486
      6 503
      3 488
```

**What to look for:**

- A 401/407 spike usually means a credential-rotation push hit the wrong realm.
- A 408 spike on outbound is upstream timeout. Check rtpengine / SBC.
- A 488 spike (Not Acceptable Here) usually means a codec mismatch.
  - Combine with [11. Find why a call sounds bad in one direction only](#find-why-a-call-sounds-bad-in-one-direction-only).

**Pitfalls:**

- The histogram counts *all* response codes seen in messages of failed dialogs.
  - So a single failed call with `100 Trying → 488` contributes both 100 and 488.
  - For just the final response per call, use `--call-report <id>` per dialog.
- The dialog summary returned by the REST API (`/v1/dialogs`) has no `status_code` field.
  - That's a per-message field.
  - It is only available in CLI `--json` output, or via `/v1/dialogs/{id}`.
  - That endpoint includes the full message list.

**Runnable example:** [Group failed calls by response code](client-examples.md#group-failed-calls-by-response-code) works over REST. It:

- groups each failed call once under its final code,
- names the calls,
- adds the ones answered and never acknowledged (recipe "Find calls that answered and were never acknowledged").

---

## Diagnose a one-way audio complaint

**Problem:** A user said "I can hear them but they can't hear me." There's a Call-ID in the ticket.

**Commands:**

First, confirm the diagnosis engine flagged it.
The diagnosis block lives on the dialog-level JSON that `--call-report` emits. It is not on per-message records.

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --json --no-cli-print \
  | jq '{call_id, state, diagnosis}'
```

Then get the human-readable call report. It shows NAT mismatch, SDP offer/answer, and media path:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --markdown --no-cli-print
```

Finally, inspect the actual RTP streams for that call in the TUI:

```bash
sipnab -I capture.pcap
#   → press '/' to search, type 'abc123', Enter
#   → Tab to switch to RTP streams view
#   → Enter on each stream to see packet count, jitter, loss
```

The first command should print a diagnosis object like:

```json
{
  "call_id": "abc123@host",
  "state": "Completed",
  "diagnosis": {
    "one_way_audio": true,
    "nat_mismatch": true,
    "no_media": false,
    "hints": [
      "RTP flowed 203.0.113.7:41002 -> 192.0.2.5:16386 only (SSRC 0x1a2b3c4d). No reverse media flow detected.",
      "RTP arrived from 203.0.113.7:41002 at 192.0.2.5:16386, and no SDP in this dialog advertised 203.0.113.7 (it offered 198.51.100.20:16384) — the media source was rewritten, typically by NAT, so replies sent to 198.51.100.20:16384 never reach it.",
      "One-way audio combined with NAT mismatch — media likely being sent to the wrong address."
    ]
  }
}
```

**What to look for:**

- `diagnosis.one_way_audio: true` confirms the engine saw RTP in only one direction for ≥6s after call establishment.
- The ports in the hint are where the fix goes.
  - Each side advertises a receive port in its SDP.
  - Under symmetric RTP ([RFC 4961](https://www.rfc-editor.org/rfc/rfc4961.html)), each side should send from that same port.
  - A hint reading `advertised 16384 but sends from 41002` means the far end is replying to a port nothing is sending from.
  - So no NAT pinhole was ever opened there.
  - Go and check that firewall rule, port-forward or RTP port range.
  - When the ports agree, the hint stays quiet about them.
- `diagnosis.nat_mismatch: true` is the usual root cause.
  - The Contact header / Via address differs from the SDP `c=` line.
  - This is common when the upstream SBC isn't rewriting Contact.
- In the TUI's RTP stream view, look for one stream with packets and one with `0 packets received`.
  - The second one is the silenced direction.

**Pitfalls:**

- Both streams may show packets while the user still reports silence.
  - Then the issue is downstream of sipnab (codec mismatch, jitter buffer underflow, bad headset).
  - Use [11. Find why a call sounds bad in one direction only](#find-why-a-call-sounds-bad-in-one-direction-only) for codec asymmetry checks.

**Runnable example:** [Diagnose one-way audio, and whose loss it is](client-examples.md#diagnose-one-way-audio-and-whose-loss-it-is) runs these for one Call-ID:

- this diagnosis,
- the asymmetry checks of recipe "Find why a call sounds bad in one direction only",
- the capture-loss check of recipe "Measure whether the loss is yours or the network's".

---

## Filter for the five things you look for most

The filter DSL has 42 fields and 8 operators. These five cover most operational triage:

Slow setup. This is every dialog whose post-dial delay (PDD) exceeded 3 seconds.
PDD is the time from the INVITE to the first `180 Ringing` or `183 Session Progress`:

```bash
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json
```

REGISTER dialogs that failed:

```bash
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND state == 'Failed'" --json
```

Short calls. These completed, but in under 10 seconds. That usually points at a UX or cancellation problem:

```bash
sipnab -N -I capture.pcap --filter "duration < 10.0 AND state == 'Completed'" --json
```

Heavy retransmits. These are the signature of packet loss on the SIP path:

```bash
sipnab -N -I capture.pcap --filter "retransmits > 5" --json
```

A specific User-Agent, matched as a regex:

```bash
sipnab -N -I capture.pcap --filter "ua =~ '(?i)friendly.*scanner|sipvicious'" --json
```

For per-call asymmetry checks, see [11. Find why a call sounds bad in one direction only](#find-why-a-call-sounds-bad-in-one-direction-only).
Those checks cover a different codec on each leg, late media, and so on.

**Pitfalls:**

- String comparisons are case-sensitive. State names must match exactly (`'Completed'`, not `'completed'`). Use `=~ '(?i)...'` if you want case-insensitive.
- Boolean fields only support `==` and `!=`. `one_way > true` is a parse error.

---

## Wire HEP from your SIP stack to a central sipnab

**Problem:** You want one sipnab box collecting traffic mirrors from multiple SIP servers.

### Set up the listener

Build sipnab with HEP support. Skip this if you installed a package that already has it:

```bash
cargo build --release --no-default-features \
    --features native,hep,api,mcp,mcp-http
```

Run it as a daemon.

- UDP :9060 receives HEP.
- TCP :9100 serves REST + Prometheus.
- sipnab refuses a routable bind that nothing guards.
  - So the command carries a HEP source allowlist and an API signing key:

```bash
sipnab -N --hep-listen 0.0.0.0:9060 --hep-allow 192.0.2.0/24 --api 0.0.0.0:9100 --api-signing-key-file /etc/sipnab/signing.key --no-priv-drop --syslog
```

A ready-to-deploy systemd unit lives at [`contrib/observability/sipnab-hep.service`](https://github.com/NormB/sipnab/blob/main/contrib/observability/sipnab-hep.service).
Put sipnab on the collector host first. [The install guide](install.md) covers every channel.

### Configure the SIP server to mirror

**OpenSIPS:**

```cfg
loadmodule "proto_hep.so"
modparam("proto_hep", "hep_id", "[hep_central]udp:capture.example.com:9060;version=3")

loadmodule "siptrace.so"
modparam("siptrace", "trace_id", "[hep_central]uri=hep:hep_central")

route {
    sip_trace("hep_central", "d", "sip");
    ...
}
```

Reload with `opensipsctl restart` (or `systemctl reload opensips` for graceful reload).

**rtpengine:**

```ini
# /etc/rtpengine/rtpengine.conf
homer = capture.example.com:9060
homer-protocol = udp
homer-id = 1
# Without this, rtpengine mirrors RTCP statistics only -- which carry no
# Call-ID and no SDP, so nothing sipnab reads can name a call or find a media
# endpoint. It is the first thing to check when a relay looks silent.
homer-enable-ng = true
```

Restart with `systemctl restart rtpengine`. See [the rtpengine page](rtpengine.md) for:

- what sipnab does with the result,
- the two ways to read it that do not cost you your collector.

**Kamailio:**

```cfg
loadmodule "siptrace.so"
modparam("siptrace", "duplicate_uri", "sip:capture.example.com:9060")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "hep_version", 3)

route {
    sip_trace();
    ...
}
```

**FreeSWITCH (mod_sofia):**

```xml
<!-- conf/sip_profiles/external.xml -->
<param name="capture-server" value="udp:capture.example.com:9060;hep=3"/>
<param name="sip-capture" value="yes"/>
```

### Verify packets are arriving

On the sipnab host, tcpdump the HEP socket to see whether anything is arriving at all:

```bash
sudo tcpdump -i eth0 -n udp port 9060
```

Confirm the HEP feed is producing dialogs:

```bash
curl -s http://localhost:9100/v1/stats | jq
```

Watch dialogs accumulate live:

```bash
watch -n 1 'curl -s http://localhost:9100/v1/dialogs?limit=5 | jq ".dialogs[] | {call_id, state}"'
```

### Take signaling from HEP and media off the wire, in one process

**Problem:** the HEP mirror is the robust way to get decrypted SIP.

- It is already plaintext at the source. So there is no TLS key extraction to go wrong.
- But a HEP feed carries no RTP. So a `--hep-listen` run measures no media at all.
- Capturing the interface instead gets you media.
  - But it puts you back on key extraction for the signaling.

Run both in one sipnab.

- HEP supplies the signaling.
- The NIC supplies the RTP for the same calls.
- Streams bind to dialogs by SDP media endpoint:

```bash
sipnab -N -d eth0 --hep-listen 127.0.0.1:9060 "udp portrange 10000-20000"
```

Raised by Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) from
OpenSIPS deployment experience.

The BPF expression narrows the capture to your media ports.

- Without one, the interface gets sipnab's auto-generated filter.
  - On a run like this, that filter admits media only: RTP on any port.
  - The mirror supplies the signaling.
- `--no-rtp` still gives the interface the signaling filter. sipnab warns about that.

**What you get that a single source cannot give you.**
The two accounts are complementary rather than redundant. Their DISAGREEMENT is the finding.

- HEP reports what the proxy *believes* it did.
- The wire reports what actually left the box.
- Sometimes the question is "is the proxy misbehaving, or did I configure it to".
  - A mirror produced by the suspect cannot answer it.
  - It is the same witness twice.

A composite run therefore reports, per call:

| Finding | What it means |
|---|---|
| Seen by both | The proxy did what it says it did |
| Mirror-only | The proxy believes it sent something the wire never carried |
| Wire-only | Traffic left the box that the tracing never reported |
| Differing SDP | Both saw the message and disagree about the media endpoint, so the report carries both accounts side by side |

Neither account carries the label expected or actual.

- sipnab pairs copies by transaction identity ([RFC 3261 section 17.1.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.3) and [RFC 3261 section 17.2.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3)).
- It never pairs them by arrival order, because the mirror usually arrives FIRST.
  - The proxy mirrors as it processes.
  - The wire copy takes a network hop.
  - So any "first one wins" rule would quietly make the suspect authoritative.

A single-source run reports none of this and allocates nothing for it.

**Trace both directions, or this measures nothing.** In OpenSIPS, use transaction scope.
Then the tracer mirrors the message it *sent* as well as the one it received:

```cfg
route {
    $var(tid) = "hep_central";
    trace($var(tid), "t", "sip");   # "t", not "m"
}
```

At `"m"` (message) scope the tracer mirrors only the received copy.

- That matters the moment rtpengine or any other relay rewrites the SDP.
  - The address OpenSIPS received is not the address the media flows to.
  - So streams come out orphaned: bound to no dialog.
- At `"t"`, each advertised media endpoint is the socket the RTP actually uses.

Note also that `proto_hep` refuses to start without a HEP *listener* socket.
It refuses even when the config only sends.
Add `socket=hep_udp:127.0.0.1:9061` alongside your `hep_id`.
Otherwise OpenSIPS exits with `No HEP listener defined!`.

**Where this helps, and where it cannot.**

- It helps where media transits the machine running the mirror.
  - A proxy anchoring media through rtpengine on the same box is the case this composition targets.
- Media may flow end-to-end and never cross that machine.
  - Then no capture there can see it.
  - No amount of correlation changes that.
  - Put sipnab's `-d` where the media actually is.

**Pitfalls:**

- HEP is UDP. It silently drops if the listener can't keep up.
  - The `--hep-rate-limit 50000` default lets you tune.
- A routable HEP listener needs a guard.
  - sipnab refuses a non-loopback `--hep-listen` bind unless you pass one of these:
    - `--hep-allow 192.0.2.0/24` (repeatable),
    - `--hep-auth`/`--hep-auth-file`.
  - A loopback bind needs neither.
- `--hep-allow` guards the **listener** and nothing else.
  - HEP that sipnab merely sniffs off the wire reaches no socket. That includes rtpengine's mirrored control plane.
  - So no allowlist applies to it.
  - See [rtpengine.md](rtpengine.md#how-much-a-media-relay-assertion-is-worth) for what a sniffed assertion is worth.
- Your central host may be reachable by hostname only.
  - Then set `--mcp-allowed-host` for the MCP transport too.
  - See [8. Let an AI agent ask sipnab about your calls](#let-an-ai-agent-ask-sipnab-about-your-calls).
- `-d` with `--hep-listen` takes exactly one interface and one listener.
  - sipnab refuses `-I` with `--hep-listen`.
    - A file's addresses are historical and belong to third parties.
    - sipnab keeps them off its active-response path. It refuses to transmit for a file run at all.
  - It also refuses `--multi-device` with `--hep-listen`.
  - It also refuses `-O` with the pair.
    - The two sources disagree about the link layer. So there is no honest pcap to write.
  - Use `--hep-send` to forward the signaling instead.
- One sipnab, one mirroring node.
  - The SDP endpoint index keys on address and port, with no node dimension.
  - So two nodes advertising the same [RFC 1918](https://www.rfc-editor.org/rfc/rfc1918.html) socket would overwrite each other.
  - A stream would then bind to whichever offer arrived last.

### Find who feeds the collector and who it refuses

A collector fed by twenty proxies needs to answer three questions:

- Which of them are sending?
- Which one stopped?
- Which one sends while the listener refuses it?

The listener keeps a roster that answers all three.

At the end of a bounded headless run:

```bash
sipnab -N -L 0.0.0.0:9060 --hep-parse --hep-auth-file /etc/sipnab/hep.key --duration 600 --hep-senders
```

While a server runs, from the REST API or the MCP `hep_senders` tool:

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" http://localhost:9100/v1/hep/senders \
  | jq '.senders[] | {source, packets, idle_seconds, silent}'
```

In the TUI, press `h` for capture health and then `s`.

Each row is one sender. Two things key a row:

- the capture id the sender claims:
  - `--hep-id` on a sipnab agent,
  - the capture-agent id on OpenSIPS or Kamailio;
- the address it sends from.

Give every sender its own id.

- Two proxies left at the default id 1 are still two rows, because their addresses differ.
- But a sipnab agent and its host's proxy share an address. Only the id tells them apart.

Read `refused_sources` when a sender you configured never shows up. The reason names the fix:

- `auth_mismatch` is the wrong shared secret.
- `auth_missing` is a sender with no key.
- `allowlist` is an address `--hep-allow` does not cover.
- `hmac_timestamp_out_of_window` is a sender whose clock drifted.
- `hmac_unsupported_version` is a sender running an older sipnab. Upgrade it.

The listener also logs lines about silent senders.

- It logs `sender 7@192.0.2.7 silent for 30s` when one sender goes quiet while others keep sending.
- It logs a `resumed` line when that sender comes back.
- `--hep-silence-warn` sets the threshold.
- The roster covers this run only. sipnab persists none of it.

---

## Decrypt SIP over TLS when you can restart the phone or server — key log file (SSLKEYLOGFILE)

**Problem:** TLS-encrypted SIP captures are unreadable without keys.

### Live decryption (UA produces keys, sipnab follows)

Build sipnab with the `tls` feature, or use `--features full`:

```bash
cargo build --release --features tls,hep,api
```

On the SIP user agent, set `SSLKEYLOGFILE` in its environment. The user agent is a different machine from the capture host:

```bash
SSLKEYLOGFILE=/tmp/sipua.keylog /opt/myua/bin/start
```

Then, on the capture host, start sipnab watching that keylog file for live updates:

```bash
sudo sipnab -N -d eth0 \
            --keylog /tmp/sipua.keylog --keylog-watch
```

### Decrypt a capture you already recorded

Capture the encrypted pcap normally:

```bash
sudo sipnab -N -d eth0 -O encrypted.pcap
```

Later, decrypt it using the keylog the UA wrote during the call. Later can be minutes or months:

```bash
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog
```

### Export encrypted packets for Wireshark

The default `raw` mode writes original packets without embedding TLS keys:

```bash
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog \
       -O original.pcap --pcap-export-mode raw
```

To let Wireshark decrypt the original bytes, explicitly embed a Decryption
Secrets Block in PCAP-NG. This file contains TLS keys:

```bash
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog \
       --pcapng -O wireshark-friendly.pcapng --pcap-export-mode encrypted+dsb
```

To write what sipnab decrypted as plaintext, with no keys in the file, use `decrypted`.

- SIP over TLS and WSS comes out as plain SIP.
- SRTP comes out as plain RTP:

```bash
sipnab -I encrypted.pcap --keylog /tmp/sipua.keylog \
       --pcapng -O plaintext.pcapng --pcap-export-mode decrypted
```

This file holds readable signaling. When sipnab has SRTP keys, it also holds listenable audio.
So treat it like the call itself.

- Its PCAP-NG section comment says sipnab decrypted it.
- Each rebuilt frame names its source (TLS, WSS or SRTP).
- The run ends with one line of counts.
  - The counts include what it copied as captured, because it could not decrypt it.

### Decrypt SRTP from a DTLS keylog

```bash
sipnab -I capture.pcap --dtls-keylog /tmp/dtls.keylog
```

### Decrypt traffic from a daemon you cannot restart

Everything above needs the SIP daemon to cooperate.

- `SSLKEYLOGFILE` has to be in its environment when it starts.
- On a running production Kamailio, OpenSIPS or Asterisk, that means a restart.
- A restart is usually the reason you are looking at the capture in the first place.

[eCapture](https://github.com/gojue/ecapture) reads the TLS master secrets straight out of the process.
It uses eBPF uprobes on the TLS library.

- It needs nothing from the daemon: no environment variable, no configuration, no restart.
- It writes the same NSS keylog format sipnab already consumes.

On the SIP host, as root:

```bash
ecapture tls -m keylog --keylogfile=/tmp/sip.keylog
```

Then point sipnab at that file, exactly as in [7a. Live decryption (UA produces keys, sipnab follows)](#live-decryption-ua-produces-keys-sipnab-follows):

```bash
sudo sipnab -N -d eth0 --keylog /tmp/sip.keylog --keylog-watch
```

`-m keylog` is the mode for a LIVE capture.
It hands sipnab keys while sipnab reads the wire itself.
eCapture's `-m text` emits plaintext. That is a different artifact: bytes that never existed on the wire in that form.

**`-m pcap` is neither.**

- It writes the real encrypted frames.
- It embeds the secrets in the file as a pcapng Decryption Secrets Block.
- So it produces exactly the artifact this section argues for -- with no live sipnab at all.
- That is [7i. One file, taken off the host, that decrypts itself](#one-file-taken-off-the-host-that-decrypts-itself).
  - It is the easier recipe of the two when you can work from a file.

**Pitfalls:**

- `tls` is a **build-time** feature, not a runtime flag.
  - There is no `sipnab --features tls` invocation. Pass `--features` to `cargo build` and use the resulting binary.
  - To check what a binary carries, run `sipnab --version`.
    - It prints the version, the commit, and the compiled feature list.
    - `tls` in that list means the build decrypts.
  - `sipnab --help | grep -E '\-\-keylog|\-\-tls-key'` answers the same question from the flag surface.
    - If the flags appear, the build has `tls`.
- The keylog format is the standard NSS `SSLKEYLOGFILE` (one line per session).
  - It is the same format Firefox/Chrome/curl produce.
- TLS 1.3 + ECDH ephemeral handshakes are fully supported via the `ring` backend.
- eCapture is a separate program under Apache-2.0.
  - sipnab neither bundles nor links it.
  - It needs `CAP_BPF`/`CAP_PERFMON` or root.
  - It needs Linux 4.18+ on x86_64, or 5.5+ on aarch64.
  - It does not need kernel BTF. Without it, eCapture loads its non-CO-RE bytecode instead.
- A keylog is key material.
  - It decrypts every session it covers. So treat the file as a secret.
  - sipnab disables core dumps once decryption is active, for the same reason.
- Keys only appear for handshakes eCapture was running for.
  - Start it before the calls you care about.
  - It cannot recover a session whose handshake it missed.

### Decrypt without writing the keys to disk

[7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart) leaves master secrets in a file.

- That file decrypts every session it covers.
- That is why the pitfall above says to treat it as a secret.
- sipnab can take the same keylog lines over a pipe instead. Then they never reach a disk at all.

Hand sipnab the read end of a pipe with `--keylog-fd`:

```bash
sudo sh -c 'ecapture tls -m keylog --keylogfile=/dev/stdout | sipnab -N -d eth0 --keylog-fd 0'
```

Or use a named pipe, when a supervisor starts the two halves separately:

Create the pipe once:

```bash
sudo mkfifo -m 600 /run/sip.keys
```

then read it as a live stream:

```bash
sudo sipnab -N -d eth0 --keylog /run/sip.keys --keylog-watch
```

`--keylog` accepts a FIFO and reads it as a live stream.

- `--keylog-fd` implies `--keylog-watch`.
  - A descriptor from a running producer has nothing to read at startup, and everything to read later.
- Pass one or the other, never both.

**Start the extractor yourself. sipnab cannot start it for you.**

- It sets `PR_SET_NO_NEW_PRIVS` at startup, and every child inherits it.
- So a process sipnab spawns can never acquire the `CAP_BPF` eCapture needs.
- Start the extractor from a supervisor, and hand sipnab the read end.

**Pitfalls:**

- sipnab opens whatever `--keylog` names, a FIFO or a file, **before** it drops privileges.
  - It opens capture devices there for the same reason.
  - A path under `/run` is unreachable once sipnab has dropped to an unprivileged user or entered a `--chroot`.
- An inherited descriptor needs no privilege at all.
  - So `--keylog-fd` works whatever sipnab drops to afterwards.
- Core dumps are still disabled, exactly as for a keylog file.
  - The secrets arrive over a pipe, but land in the same process memory.

### Read TLS with no keys at all

[7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart) and [7f. Decrypt without writing the keys to disk](#decrypt-without-writing-the-keys-to-disk) still need session secrets from somewhere. This recipe needs none.

- sipnab puts a kernel uprobe on the TLS library's write function.
- It reads the plaintext **before encryption**.
- No certificate, no private key, no keylog, and nothing restarted.

**Look before you probe.** This installs nothing. It answers whether the capture is worth starting:

```bash
sudo sipnab --uprobe-list
```

```text
FLAVOR        INODE  PIDS  LIBRARY
OpenSSL     14166752     1  /proc/982690/root/usr/lib/aarch64-linux-gnu/libssl.so.3
wolfSSL     17433084     1  /proc/982702/root/usr/lib/aarch64-linux-gnu/libwolfssl.so.42.2.0
OpenSSL        21143    12  /usr/lib/aarch64-linux-gnu/libssl.so.3
```

Then capture. sipnab probes every library listed, not one.

- A host commonly runs both OpenSSL and wolfSSL.
- Probing only the one you had in mind misses the rest without saying so:

```bash
sudo sipnab -N --uprobe-tls
```

Narrow it if only one stack is yours to read:

```bash
sudo sipnab -N --uprobe-tls --uprobe-flavor openssl
```

Or name a library yourself. That is the only way to attach to a daemon that has **not started yet**.
Discovery can only see what is already mapped:

```bash
sudo sipnab -N --uprobe-tls --uprobe-library /usr/lib/x86_64-linux-gnu/libssl.so.3
```

**What this gives up.**

- A uprobe sees the bytes an application handed its TLS library.
- It sees nothing about the socket beneath.
- So dialogs from this source carry **no addresses and port 0**.
- sipnab labels them `uprobe:<comm>/<pid>` instead. That names the process, not a peer.
- It never invents an address it did not observe.

**Pitfalls:**

- Needs root (or `CAP_SYS_ADMIN` + `CAP_PERFMON`) and a mounted `tracefs`.
  - Unprivileged, `/proc/<pid>/maps` is readable only for your own processes.
  - So `--uprobe-list` quietly shows a fraction of the host.
  - Run it as root before concluding a daemon is not using TLS.
- **Containers.** The path a containerized process sees names a *different file* from sipnab's namespace.
  - sipnab handles this by matching inodes and probing through `/proc/<pid>/root`.
  - That is why the listing above shows such paths.
  - If you pass `--uprobe-library` by hand for a container, pass the `/proc/<pid>/root/...` form.
  - Otherwise the probe attaches to the host's copy and captures nothing.
- GnuTLS is not probed.
  - Its write function has a different signature.
  - Attaching the OpenSSL probe shape to it would read the wrong register.
- This input can never transmit.
  - `--hep-allow-kill` has an equivalent for HEP input.
  - There is no such flag here, because sipnab has no observed peer to answer to.
- A write larger than 2048 bytes arrives truncated.
  - sipnab marks it as such, rather than presenting a fragment as a whole message.

### Read TLS *and* who the peer was

[7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all) gives you the plaintext but no addresses.

- A uprobe sees the bytes an application handed its TLS library.
- It sees nothing about the socket beneath.
- So those dialogs name a process rather than a peer.

The `bpf` backend closes that gap.

- It pairs each write with the `tcp_sendmsg` that carried it: same thread, back to back.
- It reports the addresses the plaintext actually went out on:

```bash
sudo sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535
```

```text
200 OK     127.0.0.1:15061 -> 127.0.0.1:36160  TCP  uprobe:python3/349147#0
REGISTER   127.0.0.1:36160 -> 127.0.0.1:15061  TCP  uprobe:python3/349147#1
200 OK     127.0.0.1:15061 -> 127.0.0.1:36172  TCP  uprobe:python3/349147#2
```

Each request and its response share an ephemeral port. A second connection gets a different one.
The pairing binds each write to **its own** socket.

**What it needs, and what it refuses:**

- a sipnab built with `--features bpf`.
  - That needs a nightly toolchain and `cargo install bpf-linker`.
  - Without them, sipnab still builds and every other backend still works.
  - This one refuses at runtime and names the missing tool.
- a kernel with `CONFIG_DEBUG_INFO_BTF`.
  - BTF is the **BPF Type Format**. It is the kernel's description of its own structs and where each member sits.
  - Check with `ls /sys/kernel/btf/vmlinux`.
  - sipnab reads the socket layout out of that BTF at load time.
  - So the program keeps working across kernels, instead of matching only the one that compiled it.
- root, as [7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all) does.

You may ask for it on a build or a kernel that cannot run it. Then sipnab **refuses** rather than falling back to `tracefs`.

- The addresses are the only reason to choose this backend.
- A silent downgrade would hand you a capture with none.

**Pitfalls:**

- **Widen `--portrange`.**
  - A TLS trunk on 5061 is the exception.
  - The port a uprobe reports is whatever the socket actually used. That is often ephemeral.
  - The default range drops them.
- A write the TLS library buffered rather than sent arrives with **no addresses**.
  - That is exactly like a capture from [7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all).
  - sipnab does not guess a peer for it. A guessed one would be indistinguishable from an observed one.
- The kernel and the daemon may disagree about which symbol carries the plaintext.
  - OpenSSL 3 applications increasingly call `SSL_write_ex`.
  - Check with `nm -D --undefined-only /path/to/app | grep SSL_write`.
  - Pass `--uprobe-symbol` if it differs.

**Runnable example:** [Read TLS without keys: the half that needs no kernel](client-examples.md#read-tls-without-keys-the-half-that-needs-no-kernel) needs no root and no BTF.
It shows what sipnab makes of the records the BPF program of this backend publishes.

---

### One file, taken off the host, that decrypts itself

[7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart) and [7f. Decrypt without writing the keys to disk](#decrypt-without-writing-the-keys-to-disk) keep sipnab running beside the daemon.
This recipe does not run sipnab on the SIP host at all.

- eCapture writes one file there.
- You copy it somewhere else.
- sipnab reads it with no keylog, no flags and no configuration -- because the secrets are inside the file.

On the SIP host, as root:

```bash
ecapture tls -m pcap -i eth0 -w /tmp/sip-tls.pcapng tcp port 5061
```

Stop it with Ctrl-C when you have the calls you need. Copy the file off, and read it anywhere:

```bash
sipnab -N -I sip-tls.pcapng --portrange 1-65535 --report
```

That is the whole recipe. There is no `--keylog`.

- `-m pcap` puts the master secrets in the file as a **pcapng Decryption Secrets Block**.
- sipnab reads a DSB automatically.
- Wireshark reads the same file for the same reason.

The first line of the output names the embedded secrets. The call table follows:

```text
TLS decryption active: 6 secret(s) from embedded DSB in sip-tls.pcapng
Call-ID                       From   To     State       Code  Msgs
tls-split-invite-1@127.0.0.1  uac    echo   Completed   200   7
```

**Which recipe to reach for:**

| You want | Use |
|---|---|
| A live view, decrypted as calls happen | 7e or 7f -- sipnab runs beside the daemon |
| One artifact to take away, open later, or hand to somebody | **7i** -- nothing runs on the host afterwards |
| The real wire bytes, verifiable independently | Either. Both keep the encrypted frames; neither writes plaintext |

**Pitfalls:**

- **`-m pcap` needs more from the kernel than `-m keylog` does.**
  - It attaches a TC (traffic control) classifier to the interface as well as the uprobes.
  - So the kernel needs `CONFIG_NET_CLS_BPF`.
  - On a kernel without it, eCapture starts and loads its bytecode. Then it fails with
    `couldn't add a ingress filter to interface 1: netlink receive: no such file
    or directory`.
  - Check the kernel configuration before you plan around this recipe. `# CONFIG_NET_CLS_BPF is not set` means `-m pcap` cannot run there:

    ```bash
    zcat /proc/config.gz | grep NET_CLS_BPF
    ```

  - `-m keylog` ([7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart)) needs only the uprobes. It runs on such a kernel.
- **`-i` takes a real interface, and it is not optional.**
  - `-m pcap` captures through the interface, not through the process.
  - So use `-i lo` for loopback traffic, and the SIP-facing NIC otherwise.
- **Widen the port range when the SIP is not on 5060-5061.**
  - The default `--portrange` is 5060-5061. A decrypted file whose SIP runs on another port reports no calls.
  - sipnab logs `SIP outside --portrange 5060-5061 is being skipped` and names the busiest port it saw.
  - The command above passes `--portrange 1-65535` for that reason.
- **eCapture needs no BTF.**
  - On a kernel with none, it falls back to its own non-CO-RE bytecode.
  - It logs the file it loaded (`bytecode/openssl_3_0_0_kern_noncore.o`).
  - A missing `/sys/kernel/btf/vmlinux` is not a reason to skip this.
- **The file is key material.**
  - A DSB decrypts every session in it.
  - So the pcapng is as sensitive as the keylog in [7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart), and more portable.
  - Treat it that way when you copy it off the host.
- Same as [7e. Decrypt traffic from a daemon you cannot restart](#decrypt-traffic-from-a-daemon-you-cannot-restart):
  - eCapture is a separate Apache-2.0 program that sipnab neither bundles nor links.
  - It captures only handshakes it was running for.

---

## Let an AI agent ask sipnab about your calls

**Problem:** You want an AI agent to query a capture without you typing CLI flags.
The agent can be Claude Code, Claude Desktop, or anything that speaks MCP, the Model Context Protocol.

<!-- The sub-section markers below ("8a.", "10d.") are labels, not sentences, so
the word after them opens the heading and takes a capital. Vale reads "10a." as
the first word and wants everything after it lowercased. Purely numeric markers
("13.") it skips correctly; only the alphanumeric ones misfire. -->
<!-- vale sipnab.Headings = NO -->

### Drive sipnab from an agent on the same machine

One-shot: the agent reads a pcap you already have.

```bash
sipnab -N --mcp -I capture.pcap --quiet
```

The same, against a live capture instead of a file:

```bash
sudo sipnab -N --mcp -d eth0 --quiet
```

**Claude Desktop config** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-N", "-I", "/path/to/capture.pcap", "--quiet"]
    }
  }
}
```

**Claude Code** (in your project directory):

```bash
claude mcp add sipnab -- sipnab -N --mcp -I "$PWD/capture.pcap" --quiet
```

### Drive sipnab from an agent on another machine

Generate the bearer token once, when you first set the host up.

- `openssl rand` overwrites `/etc/sipnab/mcp-token`.
- If you run it against a live server, the server starts serving a secret none of the configured agents hold.
- There is no way to recover the old one.

Steps:

- Create the directory:

  ```bash
  mkdir -p /etc/sipnab && chmod 0755 /etc/sipnab
  ```

- Generate the token:

  ```bash
  openssl rand -hex 32 > /etc/sipnab/mcp-token
  ```

- Make the token readable by its owner only:

  ```bash
  chmod 0600 /etc/sipnab/mcp-token
  ```

Then run sipnab listening on a private network interface.
This is the every-boot command. It reads the token file. It does not create one.

```bash
sipnab -N --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp-token \
       --mcp-allowed-host capture.example.com \
       --hep-listen 0.0.0.0:9060 --hep-allow 192.0.2.0/24 --quiet
```

The agent connects to `http://capture.example.com:8731/mcp` with `Authorization: Bearer <token>`.

### Test the JSON-RPC handshake from a shell

Each probe below sends the bearer token. So read it into the shell first.
The three requests are independent. None of them carries a session on to the next. So run whichever one you need.

```bash
TOKEN=$(cat /etc/sipnab/mcp-token)
```

Initialize, pretending to be an MCP client. Keep the session id the server returns.

- Every later request must carry it in `Mcp-Session-Id`.
- The transport rejects a request that does not.
- It answers HTTP 422 `Unexpected message, expect
initialize request`:

```bash
SID=$(curl -sS -D - -o /dev/null http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize",
          "params":{"protocolVersion":"2025-06-18",
                    "capabilities":{},
                    "clientInfo":{"name":"curl","version":"0"}}}' \
     | awk 'tolower($1) == "mcp-session-id:" { print $2 }' | tr -d '\r')
```

Send the `initialized` notification the protocol requires before any tool call.
It answers `202 Accepted` with no body:

```bash
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Mcp-Session-Id: $SID" \
     -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'
```

List every registered tool:

```bash
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Mcp-Session-Id: $SID" \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Call `find_problems` and get JSON of the problematic dialogs:

```bash
curl -sS http://capture.example.com:8731/mcp \
     -H "Content-Type: application/json" \
     -H "Accept: application/json, text/event-stream" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Mcp-Session-Id: $SID" \
     -d '{"jsonrpc":"2.0","id":3,"method":"tools/call",
          "params":{"name":"find_problems",
                    "arguments":{"kinds":["one-way","nat-issues"]}}}'
```

The `tools/list` response is a standard JSON-RPC envelope with a `result.tools` array.
This copy truncates the descriptions and input schemas:

```json
{"jsonrpc":"2.0","id":2,"result":{"tools":[
  {"name":"list_dialogs","description":"...","inputSchema":{"type":"object","properties":{"...":{}}}},
  {"name":"get_dialog_report","description":"...","inputSchema":{"...":"..."}},
  {"name":"find_problems","description":"...","inputSchema":{"...":"..."}}
]}}
```

The response lists every registered tool. [The MCP tool reference](mcp-tools.md) has the complete table.
The tools most triage starts with, grouped by what they do:

- **Browse and quote the capture** — `list_dialogs`, `get_dialog`, `get_dialog_report`, `get_message`, `search_messages`, `search_by_time`, `tail_dialogs`, `render_ladder`, `compare_dialogs`, `find_correlated`, `show_evidence`
- **Diagnose** — `find_problems`, `triage_call`, `diagnose_registration`, `check_codec_negotiation`, `explain_response_code`, `get_sdp_timeline`, `rtp_stats`, `security_findings`, `capture_health`
- **Check a message or dialog against the RFCs** — `lint_dialog`, `validate_message`, `explain_rule`
- **Ask about the session itself** — `capture_status`, `server_capabilities`, `list_captures`
- **Write a file or a note, swap the capture, or end the run** — `export_capture`, `export_audio`, `save_findings`, `open_capture`, `shutdown_server`

A tool that writes, changes the run or transmits acts only under a flag you pass at startup. The last group above works this way:

- The two exports write only under `--mcp-file-root`.
- `save_findings` records only under `--mcp-allow-save-findings`.
- `open_capture` acts only under `--mcp-allow-open-capture`.
- `shutdown_server` acts only under `--mcp-allow-shutdown`.

These tools still appear in `tools/list` when you omit those flags.

- sipnab registers the tools unconditionally, and refuses the call instead.
- Seeing `shutdown_server` listed does not mean an agent can stop your capture.

**Pitfalls:**

- Stdout is the JSON-RPC wire in stdio mode.
  - Use `--quiet`.
  - Don't combine with `--json`/`--report`/etc. sipnab refuses to start.
- sipnab refuses a non-loopback bind without a token at startup. A loopback bind needs no token.
- Pass `--mcp-allowed-host` when the client connects via the actual hostname.
  - The default Host allowlist is `localhost`, `127.0.0.1`, `::1` and the bound address.

---

## Graph call rate, response codes and PDD over time

**Problem:** You want a dashboard tracking call rate, response codes, and PDD over time.

### Use the bundled stack

Clone the repository and take a copy of the sample environment. Do this once per host.

- `cp .env.example .env` overwrites `.env`.
- So on a host where you have already edited it, skip straight to starting the stack.

Steps:

- Clone the repository:

  ```bash
  git clone https://github.com/NormB/sipnab.git
  ```

- Change into the observability directory:

  ```bash
  cd sipnab/contrib/observability
  ```

- Copy the sample environment:

  ```bash
  cp .env.example .env
  ```

sipnab may run on a different host. Then point the stack at it before starting:

- `echo 'SIPNAB_HOST=192.0.2.10' >> .env`,
- or the hostname (`capture.example.com`), if that is how it resolves.

Start the stack from [`contrib/observability`](https://github.com/NormB/sipnab/tree/main/contrib/observability).
`docker compose` reads its compose file out of the working directory. So a fresh shell needs the `cd` above first:

```bash
docker compose up -d
```

This boots:

- Prometheus (`:9090`),
- Grafana (`:3000`, admin/admin),
- an OTel Collector (`:4317`/`:4318`),
- Tempo.

The included Grafana dashboard provisions automatically. Log in and look for the `sipnab` folder.

### Run sipnab so Prometheus can scrape it

Both listeners below bind a routable address. sipnab refuses either one without a credential.

- So each command supplies one.
- The scrape job has to send the matching half.

A standalone metrics endpoint, which takes HTTP Basic:

```bash
sipnab -N -d eth0 --metrics 0.0.0.0:9100 --metrics-auth-file /etc/sipnab/metrics.cred --json
```

Or serve the metrics from the REST API, so one port carries both.
That side takes the same Bearer token as every other REST route:

```bash
sipnab -N -d eth0 --api 0.0.0.0:9100 --api-signing-key-file /etc/sipnab/signing.key
```

### Verify the scrape

From the Prometheus host, confirm the target is up:

```bash
curl -s http://localhost:9090/api/v1/query?query=up{job=\"sipnab\"} | jq
```

Then spot-check a metric value:

```bash
curl -s 'http://localhost:9090/api/v1/query?query=rate(sipnab_messages_total[1m])' | jq
```

### Query the metrics with PromQL

```promql
# Call rate (per method)
rate(sipnab_messages_total[5m])

# Active dialogs (in-progress)
sum(sipnab_dialogs_total{state=~"trying|ringing|incall"})

# Setup time p95
histogram_quantile(0.95, rate(sipnab_pdd_seconds_bucket[5m]))

# RTP MOS p10 (worst 10%)
histogram_quantile(0.1, rate(sipnab_mos_bucket[5m]))
```

**Pitfalls:**

- The dashboard ships with the metric names sipnab actually emits.
  - If you wrote a custom panel using older docs, double-check against [the Prometheus metrics reference](prometheus-metrics.md).
- `sipnab_security_alerts_total{type}` carries only the alert types that have fired.
  - It is absent from the scrape until the first one does.
  - An absent series means no alert of that type fired since the process started.
  - It does not mean that the metric is unavailable.
- `sipnab_responses_total{code}` reports every response class on every scrape.
  - It reports `0` where the capture saw none.
- [The Prometheus metrics reference](prometheus-metrics.md) describes both.

---

## Detect SIP scanners and auto-block via fail2ban

**Problem:** Your honeypot or edge box is getting probed by `friendly-scanner`, `sipvicious`, etc.

### Detect + log

```bash
sudo sipnab -N -d eth0 \
            --kill-scanner \
            --alert syslog \
            --json
```

`--kill-scanner` actively responds to known scanner User-Agents.

- The responses come from a scanner-kill worker that runs as a process of its own.
- The process parsing your traffic holds none of the sockets it sends through.
- The response code defaults to **200**.
- Pass `--kill-response 403` (or any 100–699 code) to change it.

`--alert syslog` writes alerts to `LOCAL0`. So you can pick them up from `/var/log/syslog`.
(`--syslog` is the equivalent boolean form.)

### Detect scanners without answering them

Use `--kill-scanner-detect-only` when you want to know which sources scan you, and you do not want sipnab to send them anything.

- It detects scanners exactly as `--kill-scanner` does: the same User-Agent signatures and the same behavior thresholds.
- It never answers them. sipnab starts no scanner-kill worker and sends no packet, on a live interface too.
- You do not need `--kill-scanner` with it. If you give both, detect-only wins.
- To make it the default, set `kill_scanner_detect_only = true` in the `[security]` section of the configuration file. `--no-kill-scanner-detect-only` turns it off for one run.

On a live interface:

```bash
sudo sipnab -N -d eth0 --kill-scanner-detect-only --alert syslog
```

To see what it reports, run it over a capture first:

```bash
sipnab -N -I capture.pcap --kill-scanner-detect-only --no-cli-print
```

The lines below came from this command with
[`tests/fixtures/sip-scanner-and-register-flood.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/sip-scanner-and-register-flood.pcap)
from the sipnab repository as `capture.pcap`. It holds a probe from a `friendly-scanner` User-Agent.

sipnab says at startup that detection is detect-only:

```text
2026-10-18T16:12:53.806330Z  INFO sipnab::app::bootstrap: Scanner detection is detect-only (--kill-scanner-detect-only or [security] kill_scanner_detect_only): sipnab detects, alerts on and reports SIP scanners and never answers them. The scanner-kill worker is not started and nothing is transmitted.
```

It reports each scanner it detects:

```text
2026-10-18T16:12:53.945702Z  WARN sipnab::alert: [ALERT] scanner src=203.0.113.42 method="OPTIONS" ua="friendly-scanner" detection=ua_pattern alert_type="scanner" src_ip=203.0.113.42 sanitized_detail=method="OPTIONS" ua="friendly-scanner" detection=ua_pattern
```

The end-of-run summary says it again:

```text
2026-10-18T16:12:53.956077Z  INFO sipnab::app::batch: sipnab: scanner detection was detect-only: no scanner was answered and nothing was transmitted
```

With `--api`, `GET /v1/security/findings` reports `"scanner_response": "detect_only"`, and so does the MCP `security_findings` tool. A program reading `armed_kinds: ["scanner"]` can use it to tell that sipnab detected the scanners and did not answer them. Start the run with the REST API (it keeps serving until you stop it), then ask it from a second terminal:

```bash
sipnab -N -I capture.pcap --kill-scanner-detect-only --no-cli-print --api 127.0.0.1:8080
```

```bash
curl -s -H "Authorization: Bearer $SIPNAB_API_KEY" http://127.0.0.1:8080/v1/security/findings | jq '{armed_kinds, scanner_response}'
```

```json
{
  "armed_kinds": [
    "scanner"
  ],
  "scanner_response": "detect_only"
}
```

sipnab refuses `-K`/`--kill-target` together with detect-only, with exit status 2. `-K` asks sipnab to answer every request from a source you name, and detect-only asks it to answer nothing.

### Wire to fail2ban

`--fail2ban` is a boolean flag. It switches sipnab's stdout to fail2ban-friendly log lines.
Pipe to a file (or run under systemd and capture the unit's stdout).

`--fail2ban` writes **detections**. So it needs a detector switched on beside it:

- `--kill-scanner` for `scanner_detected`,
- `--reg-flood` for `reg_flood`.

On its own, it selects the format, and nothing produces lines for it.
A jail reading an always-empty file never says so.

Detections carried by HEP input never reach the log without `--hep-allow-kill`.
The kill path refuses them for the same reason:

- The inner addresses are the sender's claim.
- A jail line would ban whatever address the sender chose.

sipnab warns once at startup when `--fail2ban` meets HEP input without the opt-in.
So the empty file is not mistaken for an all-clear.

```bash
# Run sipnab with fail2ban-format output, write to a logfile
sudo sipnab -N -d eth0 --kill-scanner --fail2ban \
     >> /var/log/sipnab/fail2ban.log 2>&1
```

**Measure it against your own traffic before any of it reaches fail2ban.**
Point sipnab at a capture of a normal hour, and count who it would have banned:

```bash
sipnab -N -I trunk.pcap --kill-scanner --fail2ban | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn
```

Every address in that list is one the jail below would ban.
Use `ignoreip` in the jail for the peers you already trust.

`--reg-flood` does two things:

- It counts refused credentialed REGISTERs per source, inside a one-second window of capture time.
- It treats a `401` that arrives more than 32 seconds after its REGISTER (RFC 3261 Timer F) as a stray.

Some sites see slow guessing runs, or have phones that run a longer T1. Such a site tunes both:

```bash
sipnab -N -I registrar.pcap --reg-flood --reg-flood-threshold 20 \
       --reg-flood-window 60 --reg-flood-transaction-timeout 64000
```

[Registration-flood timers](troubleshooting.md#registration-flood-timers) explains which transaction timeout matches your proxy's `fr_timer`/`fr_timeout` and T1.

### Block a scanner with a rule sipnab wrote, after reading the evidence

Counting `src=` fields tells you who. It does not tell you whether banning them costs you a customer.

`--recommend-block` groups the detections by source. It prints one block per accused address. Each block carries:

- the evidence,
- the counter-evidence,
- a rule in the dialect you name (`fail2ban`, `nftables`, `iptables` or `all`):

```bash
sipnab -N -I trunk.pcap --kill-scanner --reg-flood --recommend-block all --quiet
```

**sipnab recommends and does not apply.**

- sipnab ran none of that output.
- It contacted no firewall.
- It holds no credential anywhere in sipnab.
- It prints text and stops.

The line to read in every block is `COUNTER-EVIDENCE:`. It says one of three things:

- **`also completed a registration or a call`**
  - The source is a working peer, and a block disconnects it.
  - So the `nftables` and `iptables` commands arrive commented out.
  - The fail2ban jail arrives with `ignoreip` already filled in.
- **`none`**
  - Nothing in this capture says the source has a relationship.
  - The commands are live.
- **`UNKNOWN`**
  - No scanner detector ran, so sipnab asked nothing.
  - The commands are live.
  - The block tells you to re-run with `--kill-scanner` before acting on them.

The third case is the one worth pausing on.

- "Asked and it had not" and "never asked" produce the same silence.
- Only the first is a reason to feel safe.

#### What the behavioral rules actually test

Neither behavioral rule fires on volume. Volume does not separate reconnaissance from operation.

- A trunk sends OPTIONS keepalives continuously by design. That is how each end learns the other is alive.
- An SBC fronting a hunt group reaches dozens of distinct extensions a second.

Both rules therefore need an OUTCOME as well as a rate:

| Signal | What it counts | What arms it |
|---|---|---|
| `behavioral` | More than 10 probe transactions from one source in 5s | Probing evidence |
| `enumeration` | More than 5 distinct target extensions in 5s | Probing evidence |

Probing evidence means one of two things inside that window:

- **5 refusals.** These are final responses past `4xx` that are neither of these:
  - an auth challenge (`401`, `407`),
  - an ordinary call outcome (`408`, `480`, `486`, `487`, `488`, `491`, `600`, `603`).
  - A `5xx` blames the server. So it counts for nothing.
  - Only a refusal on a probe transaction counts. The `Via` branch matches it.
  - So a `481` answering a stray `NOTIFY` says nothing about the OPTIONS beside it.
- **5 probes with no answer.**
  - They are still unanswered half a second later.
  - They outnumber the ones that drew a reply.
  - Any response settles a probe, including a `100 Trying`.
    - The question is whether anything is there.
    - Waiting for the final response would count every ringing call as a probe into a hole.
  - Retransmissions of one request count once. So a peer resending an INVITE is one probe rather than four.

Some sources have completed a registration or a call: a `2xx` to its REGISTER or its INVITE.
Such a source needs four times either number.
Answering its OPTIONS earns it nothing, because sipnab answers anyone's.

Two consequences follow for anyone reading a file rather than watching an interface:

- A capture of one direction holds no responses.
  - So sipnab stands the unanswered test down entirely.
  - Only the signature and refusal rules remain.
- You may take a capture upstream of whatever generates your `404`s (between two proxies, say).
  - It never shows the refusals either.

Sample log line shape (from [`src/output/fail2ban.rs`](https://github.com/NormB/sipnab/blob/main/src/output/fail2ban.rs)):

```text
2026-05-05 12:34:56 sipnab[12345]: scanner_detected src=203.0.113.42 ua="friendly-scanner" method="OPTIONS"
2026-05-05 12:34:57 sipnab[12345]: scanner_detected src=203.0.113.43 ua=- method="REGISTER"
2026-05-05 12:34:57 sipnab[12345]: reg_flood src=203.0.113.42 count=37
```

sipnab **quotes** the `ua=` and `method=` values.

- A bare `-` means the request carried none.
- An absent `User-Agent` is itself a scanner signal.
- So it is worth keeping distinct from a client that sends the string `-`. That renders as `"-"`.

Both fields carry attacker-influenced text (`method` can be a non-standard token).

- So quoting is also what stops a crafted value forging a second `src=` field inside the line.
- sipnab escapes embedded `"` and `\`.
- `src=` carries no quotes. It holds a parsed IP address, not text from the wire.

`/etc/fail2ban/filter.d/sipnab.conf`:

```ini
[Definition]
failregex = ^.*sipnab\[\d+\]: scanner_detected src=<HOST>.*$
            ^.*sipnab\[\d+\]: reg_flood src=<HOST>.*$
ignoreregex =
```

`/etc/fail2ban/jail.d/sipnab.local`:

```ini
[sipnab]
enabled = true
filter = sipnab
logpath = /var/log/sipnab/fail2ban.log
# Never ban the boxes the phone system needs. List every carrier SBC, every
# trunk peer and the PBX itself, before enabling the jail — these are the
# addresses that talk to you most, so they are the ones a detector tuned for a
# honeypot flags first.
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24 198.51.100.10
findtime = 600
# Several detections inside findtime, not one. A single enumeration alert is
# how a busy trunk looks, and `maxretry = 1` turns any one of them into a ban.
maxretry = 5
# An hour, not a day. Long enough to shed a scan, short enough that a wrong
# ban of your own carrier heals without an engineer.
bantime = 3600
# Read logpath whatever the distribution's default backend is: Ubuntu 24.04's
# is systemd, which reads the journal and never this file.
backend = auto
# Ban on every port, UDP and TCP, with nftables, as Debian 13's fail2ban does.
action = nftables[type=allports, name=sipnab, protocol="udp,tcp"]
# On a host that bans with legacy iptables instead, use:
# action = iptables-allports[name=sipnab, protocol=all]
```

Verify the filter against a real log file before enabling the jail. Check the ban list afterwards.
`fail2ban-regex` reports what it would have matched, without banning anything:

```bash
fail2ban-regex /var/log/sipnab/fail2ban.log /etc/fail2ban/filter.d/sipnab.conf
```

### Detect toll fraud and wangiri call-back bait

**Symptom:** any of these:

- an unexpected spike of international or premium-rate calls,
- bursts of short calls to one number prefix (wangiri call-back bait),
- sequential dialing through a number range.

```bash
# Live fraud heuristics on the edge box (batch mode required)
sudo sipnab -N -d eth0 --fraud-detect --alert syslog
```

Where a call is going is a signal the shape-based heuristics cannot see.
Name the destinations you never expect to dial.
Then sipnab reports an INVITE to one the moment it sees it. It needs no pattern:

```bash
sipnab -d eth0 -N --fraud-detect --fraud-destination DO,VG,MA
```

sipnab reads numbers through the common international prefixes.

- It resolves them by the longest calling code.
  - So `+1 809 555 0100` is the Dominican Republic and not the United States.
- A number dialed with no prefix is domestic and never matches.
- Every other fraud finding names the resolved destination beside its detail.

`--fraud-detect` runs three heuristics over INVITE traffic per source IP:

- **VolumeSpike**: call rate far above the rolling baseline.
- **Wangiri**: repeated short calls to the same number prefix.
- **SequentialScanning**: consecutive destination numbers.

Alerts fire through the same alert engine as the scanner detectors.
So `--alert syslog` and `--alert-exec` both work.

You should see alert lines like:

```text
[ALERT] fraud src=203.0.113.42 Wangiri: 4 short calls to prefix '+44900' in 60s
[ALERT] fraud src=203.0.113.42 SequentialScanning: sequential dialing detected: 3 consecutive numbers ending at 15550104
[ALERT] fraud src=203.0.113.42 VolumeSpike: 40 calls in 60s (baseline: 1.5/min)
```

**What to look for:**

- A `Wangiri` alert on a premium-rate prefix (`+44 9xx`, `+2xx` IRSF ranges) is the classic revenue-fraud signature.
  - Block the destination prefix at the trunk, not just the source IP.
- `SequentialScanning` from an external source usually precedes a toll-fraud attempt.
  - Feed the source IP to fail2ban ([10b. Wire to fail2ban](#wire-to-fail2ban)).
  - Review outbound dial permissions.

### Run your own script when an alert fires

For exec hooks instead of syslog/fail2ban:

```bash
sudo sipnab -N -d eth0 --kill-scanner \
            --alert-exec '/usr/local/bin/notify-slack.sh "$SIPNAB_RULE" "$SIPNAB_SRC" "$SIPNAB_DETAIL"'
```

Alert data reaches the hook as the `SIPNAB_RULE`, `SIPNAB_SRC`, and `SIPNAB_DETAIL` environment variables.
It is never interpolated into the command string.

- sipnab rewrites only the three legacy placeholders `%rule`, `%src`, and `%detail`.
  - It rewrites them into quoted references to those variables, such as `"${SIPNAB_DETAIL}"`.
  - So each value reaches the hook as one argument.
- Anything else (`%type%`, `%source_ip%`, …) reaches the shell verbatim.

The hook is rate-limited (`--exec-rate-limit 10` default) and runs in a sandboxed process.

**Pitfalls:**

- Forging the source of a kill response needs a raw socket. A raw socket needs `CAP_NET_RAW`.
  - Run sipnab as root or with capabilities.
  - It opens the raw socket and starts the scanner-kill worker process before it drops privileges.
  - The worker keeps that socket and gives up everything else.
  - Without the capability, responses still go out, from sipnab's own port.
- `--kill-ua "<regex>"` adds a custom User-Agent pattern beyond the built-in scanner list.

**Runnable example:** [Ban a scanner through TFPS, and verify it](client-examples.md#ban-a-scanner-through-tfps-and-verify-it) does two things:

- It bans through `POST /v1/tfps/ban` only the sources `--recommend-block` finds no counter-evidence for.
- It then checks TFPS's banned list.

---

<!-- vale sipnab.Headings = YES -->

## Find why a call sounds bad in one direction only

**Problem:** A call sounds bad in one direction. The codec/ptime might differ between legs.

Five asymmetry signals compare the two directions of a call: codec, packetization interval (ptime), payload type, duration and late media.

- You select calls by them with `--filter`.
- The `diagnosis` block of the dialog JSON does not carry them.
- `--filter` accepts the alias name directly (`codec-asym`).
- It falls back to the raw DSL expression if it isn't an alias.
- Both forms are equivalent.

All five asymmetry checks at once, via the `problems` DSL alias.
The `--problems` flag expands to the same expression. So either spelling works:

```bash
sipnab -N -I capture.pcap --filter problems --json
```

Targeted, one signal at a time:

- `sipnab -N -I capture.pcap --filter codec-asym    --json` — different codec on each leg
- `sipnab -N -I capture.pcap --filter ptime-asym    --json` — different packetization interval on each leg
- `sipnab -N -I capture.pcap --filter payload-asym  --json` — same codec, different dynamic payload type
- `sipnab -N -I capture.pcap --filter duration-asym --json` — the two streams ran for noticeably different lengths
- `sipnab -N -I capture.pcap --filter late-media    --json` — media started well after the answering 200 OK

The equivalent raw-DSL forms, for the two most common of those:

- `sipnab -N -I capture.pcap --filter "codec_asymmetry == true"  --json`
- `sipnab -N -I capture.pcap --filter "ptime_asymmetry == true"  --json`

Multiple signals OR'd together require raw DSL. An alias name covers only one signal each:

```bash
sipnab -N -I capture.pcap \
       --filter "codec_asymmetry == true OR ptime_asymmetry == true OR late_media == true" \
       --json
```

From an MCP client, multiple alias names go through `find_problems` instead:
`tools/call find_problems {"kinds": ["codec-asym", "ptime-asym", "late-media"]}`.
See the MCP docs for the full client-side syntax.

**What to look for:**

- `codec_asymmetry: true` on a call from PSTN to internal:
  - This is usually a transcoding policy that fired in one direction only.
- `ptime_asymmetry: true` between two SIP UAs:
  - One is using `ptime=20`, the other `ptime=30`.
  - Some downstream jitter buffers can't handle the mismatch.
- `payload_asymmetry: true`:
  - Same codec, but each side picked a different dynamic payload type number.
  - This causes audio cut-out on RFC-strict implementations.
- `late_media: true`:
  - Media starts noticeably after the answering 200 OK.
  - This usually means an SBC is doing late-attach NAT.
  - The first real RTP arrives only after media-binding.

**Pitfalls:**

- `sipnab -N --filter '<expr>' --json` emits **per-message** records for every message of every matching dialog.
  - Pipe through `jq -s 'unique_by(.call_id)'` if you want one record per affected call.
- The `diagnosis` block in CLI `--json` output and in the REST API exposes only these:
  - `one_way_audio`,
  - `nat_mismatch`,
  - `no_media`,
  - `private_media_address`,
  - free-form `hints`.
- The five asymmetry booleans are filterable via the DSL, but aren't in the JSON shape.
  - If you need them in your output, use the MCP `find_problems` tool.
  - JSON `--call-report` uses the same dialog projection and does not add them.

**Runnable example:** [Diagnose one-way audio, and whose loss it is](client-examples.md#diagnose-one-way-audio-and-whose-loss-it-is) asks all five asymmetry filters about one call.
It asks them beside the call's one-way diagnosis.

---

## Generate a call report (text / Markdown / JSON)

**Problem:** A support ticket needs full call details attached.

In `-N` (non-interactive) mode, sipnab normally prints each captured SIP message to stdout. Then it emits the report.

- Pass `--no-cli-print` to suppress the per-message dump. Then only the report reaches stdout.
- (`-N` is not optional. Without it, sipnab tries to start the TUI, and the report output never reaches stdout.)

Markdown, to paste into a ticket or a markdown editor:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --markdown --no-cli-print > ticket.md
```

Plain text, the default report format:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print > ticket.txt
```

JSON, for a tool on the other end:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --json --no-cli-print > ticket.json
```

The report covers:

- SIP message timeline,
- SDP offers/answers,
- RTP stream stats per direction,
- computed timing (PDD, setup time, retransmits),
- the diagnosis engine's findings.

**Tip:** combine with the filter from [3. Find every failed call, grouped by response code](#find-every-failed-call-grouped-by-response-code).
That bulk-generates reports for every failed call.
The CLI `--filter` outputs per-message records. So deduplicate to call_ids first:

- Create the reports directory:

  ```bash
  mkdir -p /tmp/reports
  ```

- Generate one report per failed call:

  ```bash
  # Run all of these, in order.
  # First pass: enumerate matching calls (no --no-cli-print here — we want the
  # per-message JSON so jq can extract call_id).
  sipnab -N -I capture.pcap --filter "state == 'Failed'" --json 2>/dev/null \
    | jq -r '.call_id' | sort -u \
    | while read cid; do
        # Second pass per call: --no-cli-print so only the report is written.
        sipnab -N -I capture.pcap --call-report "$cid" --markdown --no-cli-print \
          > "/tmp/reports/$(echo "$cid" | tr '/' '_').md"
      done
  ```

---

## Export RTP audio as WAV

**Problem:** A call sounds bad. You want the actual audio to listen to or share.

### Export a WAV from the TUI

```bash
sipnab -I capture.pcap
#   → select the call in the call list (Up/Down)
#   → press Tab to switch to the RTP stream view
#   → highlight a stream
#   → F2 to open the Save dialog
#   → cycle the format (Tab or Up/Down) until you reach the WAV row
#   → Enter to save
```

A timestamped `.wav` lands at the path you choose.
The Save dialog also exposes PCAP, PCAP-NG, TXT, JSON, NDJSON, CSV, HTML, Markdown, RTP JSON, SIPp XML and NOTES formats.
WAV is the format you want for audio.

### Live audio playback (TUI)

You may have built with the `audio` feature (in default). Then:

- Press `Enter` on a stream to open Stream Detail.
- Then `P` plays that stream through your local audio device.
- Only Stream Detail binds that key. The stream list ignores it.

### Check whether the file holds the whole call

Every exported WAV carries a comment recording its origin. The comment holds:

- the sipnab version,
- the mechanism (`sipnab-capture`),
- whether anything is missing.

Read it with any tool that shows RIFF metadata:

```bash
ffprobe -v error -show_entries format_tags -of default=noprint_wrappers=1 call.wav
```

A complete file says `No omissions recorded`.
A partial one says `INCOMPLETE` and names the reason, because these are different problems:

| The note says | What happened | What to do |
|---|---|---|
| `the payload ring wrapped and dropped N earlier frame(s)` | The call was longer than the `[limits] max_audio_frames` cap. The file holds the END of it. | Raise or remove `[limits] max_audio_frames` |
| `the [limits] max_audio_bytes retention budget was reached and released N earlier frame(s)` | The audio retained across every call reached the budget, and the oldest stream gave up its earliest frames. The file holds the END of it. | Raise `[limits] max_audio_bytes` |
| `N earlier frame(s) were released after this call's vCon container was written` | A live capture wrote this call's vCon, which carries the audio, and then released it | Read the audio from the vCon container |
| `N of M stream(s) on this call are NOT in this file` | A WAV carries two channels; a three-legged call does not fit | Export the legs separately |
| `(G729)` beside that | A stream's codec is not one sipnab decodes | Nothing — the audio is not recoverable from this capture |
| `N frame(s) failed to decode` | The decoder rejected individual Opus frames | Check for truncation (`--snaplen`) |
| `media in only ONE direction reached this capture` | sipnab saw no stream going the other way. Either the call really was one-way, or the capture point only sees one leg | Check where the tap sits before treating it as a fault |

sipnab writes the note after the audio.
So the first 44 bytes stay a standard WAV header, and every player reads the file normally.

**Pitfalls:**

- Codecs sipnab decodes to WAV:
  - G.711 µ-law (`PCMU`, payload type 0),
  - G.711 A-law (`PCMA`, payload type 8),
  - G.722 (payload type 9),
  - Opus (dynamic payload type; the `rtpmap` name matches in any case),
  - G.729 (payload type 18), when the binary carries the `g729` feature and you have installed the codebook tables.
    [G.729 audio](g729.md) covers `sipnab g729 install`.
  - Other codecs (AMR, GSM, video) are not decoded. The export names the codec it skipped.
- **An export refusing with "No audio payload retained" is telling you about the run, not the call.**
  - It means this run kept no payload to decode.
  - Most often, that is because retention was off.
  - It is not a finding that the call was silent.
- On a host with no audio device, such as a headless server, the TUI disables playback.
  - It shows a message suggesting F2 → WAV instead.
- No command-line flag writes WAV files. For a scripted export, use one of these:
  - the MCP `export_audio` tool, which writes under `--mcp-file-root`,
  - a vCon export with `--retain-audio`, which carries each call's audio inside the container as a `recording` ([Export one call to a conversation archive as a vCon](#export-one-call-to-a-conversation-archive-as-a-vcon)).

---

## Export one call to a conversation archive as a vCon

`--export-vcon` writes one observed dialog as a vCon container.

- vCon is the IETF interchange format.
- A conversation archive, a compliance store or an agent-facing pipeline already reads it.
- Handing one of those a pcap makes the decoding their problem. Handing them a vCon does not.

```sh
sipnab -N -I capture.pcap --export-vcon '1-1966@10.0.2.20' --vcon-out call.vcon
```

Straight into a conserver, without a file in between:

```sh
sipnab -N -I capture.pcap --export-vcon '1-1966@10.0.2.20'   | curl -fsS -X POST "$CONSERVER/vcon"       -H 'Content-Type: application/json'       -H "Authorization: Bearer $CONSERVER_TOKEN" --data-binary @-
```

Read the caveat before you trust the contents.
The analysis `body` is the JSON object itself. So `jq` indexes into it directly:

```sh
sipnab -N -I capture.pcap --export-vcon '1-1966@10.0.2.20'   | jq -r '.analysis[0].body.capture_completeness.note'
```

This needs a build carrying the non-default `vcon` feature.

- `sipnab --version` lists what yours has.
- As a library, [`examples/export_vcon.rs`](../examples/export_vcon.rs) is the same thing as a program you can run.
- The [vCon page](vcon.md) covers what a consumer may and may not conclude from a container sipnab wrote.

## Analyze a pcap without installing anything

**Problem:** You don't want to install anything. The pcap is on your laptop. You want to look at it.

Open <https://sipnab.com/analyze/> in any modern browser. Drag-and-drop a pcap or `.pcapng` file.
Everything runs locally via WebAssembly. The pcap never leaves your machine.

The analyze page supports these files:

- `.pcap`, `.pcapng`, `.cap` (pcap format),
- their gzip-compressed variants (`.pcap.gz`, `.pcapng.gz`).
  - The page decompresses these transparently, with a notice.

It gives you the same tools as the native TUI:

- call list,
- ladder diagram,
- RTP stream view,
- search,
- filter DSL.

Keyboard shortcuts match the TUI (`?` opens the help popup).

**Pitfalls:**

- WASM has no network access. Live capture is native-only.
- Very large pcaps (>200 MB) may strain browser memory. Use the native `sipnab -N` for those.

---

## Check a capture against the RFCs

**Problem:** A call works "most of the time". Nothing in the ladder looks wrong, and both vendors say their side is fine.

`--lint` reads the signaling against RFC 3261. It reports what violates it, citing the section:

```bash
sipnab -N -I capture.pcap --lint
```

Each finding names what sipnab saw and what the RFC requires:

```text
error: SIP-3261-12.1.1-CONTACT-MISSING-IN-2XX [call-id@host] §12.1.1 makes the
UAS add a Contact to the response. It is the remote target for the dialog the
2xx creates, so without it the caller has nowhere to send the ACK and nowhere
to send the BYE. The call answers and then cannot be hung up cleanly.
(RFC 3261 §12.1.1) observed=2xx to INVITE with no Contact header field
expected=Contact: <sip:user@host>
Lint: 4 finding(s) across 3 dialog(s)
```

That is the whole value:

- `observed=` and `expected=` are what you paste into a vendor ticket.
- The `§` reference is what ends the argument.

Use it as a gate in CI, where a violation should fail the build:

```bash
sipnab -N -I regression.pcap --lint --lint-fail-on error
```

**Pitfalls:**

- `--lint-fail-on error` **exits non-zero when it finds something.**
  - That is the point. But it means a shell with `set -e` stops there.
  - Exit 3 is "lint findings at or above the threshold", not a crash.
- `--lint-fail-on warning` is stricter than most real traffic survives. Start at `error`.
- Findings are per dialog.
  - A capture with one broken proxy repeats the same rule many times.
  - `--lint-max-per-rule` caps the noise.

---

## Analyze a capture into one machine-readable verdict

**Problem:** You have a pipeline, not a person. It needs one answer per capture, not a stream of messages.

```bash
sipnab -N -I capture.pcap --analyze
```

```bash
sipnab -N -I capture.pcap --json-analyze
```

`--json-analyze` emits **one object**, not one line per finding.

- The frames read and the dialogs examined are properties of the run, not of any finding.
- So a clean capture still serializes to something that states them.
- A per-finding stream would make "no findings" and "never ran" identical.
- That is the distinction a pipeline most needs.

**Pitfalls:**

- This is a summary, not a substitute for `--report`.
  - It tells you the capture's verdict, not each stream's jitter.
- A capture whose SIP sits outside `--portrange` analyzes cleanly, because it saw no SIP.
  - Check the packet counts in the same object before trusting a green result.

**Runnable example:** [Triage a capture to one verdict](client-examples.md#triage-a-capture-to-one-verdict) reads this object. It exits:

- `0` for clean,
- `1` for problems,
- `2` for inconclusive. That is for a capture with no SIP to judge.

---

## Inspect what NAT did to a call

**Problem:** One-way audio, and the SDP addresses look like private space. You suspect NAT traversal failed but cannot prove where.

```bash
sipnab -N -I capture.pcap --stun
```

```bash
sipnab -N -I capture.pcap --json-stun
```

You get one record per STUN/TURN transaction and per TURN allocation.
Each carries a `record` field naming which it is. That tells you:

- whether the endpoint ever learned its public address,
- whether the relay allocation succeeded,
- whether the candidate it then advertised in SDP matches either.

**Pitfalls:**

- STUN rides on the media ports. So a capture filtered to port 5060 contains none of it.
  - Capture the media range too, or use `--portrange`.
- A missing STUN transaction is not proof of a broken client.
  - An endpoint with a public address does not need one.

---

## Collect messages by call, host or method

**Problem:** A busy capture interleaves twenty calls. Reading it message by message means reconstructing each call in your head.

```bash
sipnab -N -I capture.pcap --group-by call-id
```

```bash
sipnab -N -I capture.pcap --group-by src --json
```

sipnab emits messages sharing the field together, **reordered but not reformatted**.
So `--json` output stays one valid object per line, and anything downstream keeps working.

Accepts `call-id`, `from`, `to`, `method`, `src`, `dst`.

**Pitfalls:**

- Requires `-N`/`--no-tui`.
- It buffers until the capture ends. So it is an offline tool.
  - On a live device you get nothing until you stop it.
- `--max-groups` (default 100000) bounds that buffer.
  - A capture with more distinct keys drops the excess, rather than growing without limit.

---

## Read a very large capture faster

**Problem:** A multi-gigabyte capture takes long enough that you stop using the tool.

```bash
sipnab -N -I huge.pcap --cores 8 --report
```

Offline, `--cores N` runs N reconstruction workers.

- It shards packets by host pair.
- Each worker has private dialog and RTP-stream stores.

**Pitfalls:**

- It prints the whole-capture views: `--report`, `--json-dialogs`, `--analyze`
  and `--call-report`. It prints no per-message lines.
- It refuses, with exit 2, a flag it does not carry out: per-message output and
  matching, the security detectors, decryption keys, DTMF, exec hooks, servers,
  HEP forwarding, `--replay` and confinement. Drop `--cores` for those:

  ```text
  --cores 8 does not do what --hexdump asks for: the parallel reader rebuilds dialogs per shard and prints only whole-capture views, so it would skip them and still exit 0. Drop --cores for these, or keep --cores and ask for a whole-capture view instead (--json-dialogs, --report, --analyze, --call-report).
  ```
- On a **live** device, `--cores` means something different: N capture sockets.
  - That widens capture, not analysis.
  - Processing stays on one thread either way.
  - See [tuning](tuning-capture.md#offline---cores).
- `--cores` and `--metrics` do not combine usefully offline.
  - The run exits before a scrape lands, and sipnab says so.

---

## Verify the exact bytes behind a finding

**Problem:** You are disputing a finding with a vendor. Paraphrasing the packet is not evidence.

Every `--json`, `--report`, REST and MCP result carries a `frame` pointer:

```text
"frame": "capture.pcap#3@86eadc8a324bb487"
```

Hand it straight back to sipnab:

```bash
sipnab --show-frame 'capture.pcap#3@86eadc8a324bb487'
```

```text
VERIFIED  capture.pcap#3@86eadc8a324bb487
348 bytes, frame 3 of capture.pcap
00000030  30 20 34 30 33 20 46 6f  72 62 69 64 64 65 6e 0d  |0 403 Forbidden.|
```

**`VERIFIED` is the word that matters.**

- With the digest, sipnab checks the frame's bytes against it.
  - It **refuses** a capture that has since rotated, truncated or recompressed.
  - It does not answer with whatever now sits at that position.
- Without a digest (the form a human types), sipnab prints the frame and marks it `UNVERIFIED`.
  - It has nothing to check against.

**Pitfalls:**

- Quote the pointer. `#` starts a comment in most shells, and everything after it disappears.
- `UNVERIFIED` is not a warning about that packet.
  - It means you did not give sipnab a way to prove it is the same file.

---

## Detect your own fault patterns with a plugin

**Problem:** You have a site-specific fault pattern. A filter can select the calls.
But you want sipnab to *diagnose* it: as a finding, with evidence, everywhere findings appear.

```bash
sipnab -N -I capture.pcap --plugin ./my-detector.wasm --report
```

Findings appear beside the built-in ones, in the same shape.
So `--call-report`, the TUI and the JSON all render yours with no extra work.

Before loading one someone sent you, know what you are trusting:

**A plugin has no imports at all.** Not a restricted set: none.

- No WASI, no filesystem, no network, no clock, not even logging.
- A module that imports anything fails to instantiate.
- Fuel metering bounds CPU.
- A 16 MiB ceiling bounds memory.
- 4 MiB bounds each reply.
- A trap or exhausted budget fails *that dialog's* plugin findings and nothing else.

What is **not** bounded is what it reads.

- A plugin sees every dialog sipnab reconstructs, including `Authorization` headers and `MESSAGE` bodies.
- It cannot send them anywhere. But it chooses what to report.
- Load one the way you would run a script: from someone you trust, or after reading it.

**Pitfalls:**

- Needs a build with `--features plugins`. That is **not** in the default feature set.
  - `sipnab --version` tells you whether the binary in front of you can load one.
- A filter or a `jq` pipeline may already answer your question.
  - Then use those: no build step, no trust decision.
  - See [plugins](plugins.md).

---

## Measure whether the loss is yours or the network's

**Problem:** RTP loss figures look terrible.
Before you escalate to the carrier, you need to know the capture itself was not the thing dropping packets.

A lossy capture does not produce a smaller answer. It produces a **wrong** one.

- sipnab counts a dropped RTP packet as network loss that never happened.
- So MOS reads worse than the call actually was.

sipnab polls libpcap's kernel counters once a second. It reports two numbers that mean different things:

```text
PACKETS ARE BEING DROPPED on 'eth0' (kernel buffer: 18432, interface/driver: 0).
```

| Counter | libpcap field | What it means | What fixes it |
|---|---|---|---|
| kernel buffer | `ps_drop` | The ring was full when the packet arrived. sipnab was not draining fast enough. | a bigger `-B`, a narrower BPF filter, a lower `--snaplen` |
| interface/driver | `ps_ifdrop` | The NIC or its driver discarded it before libpcap ever saw it. | **a bigger buffer cannot fix this** — it is the NIC |

The same two numbers appear in four places.
So whichever surface you are on can answer the question:

```bash
sipnab -N -I capture.pcap --report          # named separately, each with its own fix
```

```bash
sipnab -N -d eth0 --metrics 127.0.0.1:9100  # sipnab_capture_kernel_dropped_packets_total
                                            # sipnab_capture_interface_dropped_packets_total
```

A clean run says so explicitly, so silence is never ambiguous:

```text
Live capture on 'eth0' finished: 4821003 packets, no drops
```

**Pitfalls:**

- Operators routinely respond to *any* drop by raising `-B`.
  - That does nothing at all for interface drops.
  - It wastes memory while the real problem goes unaddressed.
- Both counters at zero does not mean the capture is complete.
  - A frame can arrive intact and still be unreadable.
  - Or `--snaplen` can cut it short.
  - `--report` counts those separately. See [tuning](tuning-capture.md#are-you-dropping-packets).

**Runnable example:** [Diagnose one-way audio, and whose loss it is](client-examples.md#diagnose-one-way-audio-and-whose-loss-it-is) ends a one-way-audio diagnosis with this answer. Either:

- the loss is the network's, or
- the capture host dropped packets, and the loss figures include them.

---

## Find the device flooding REGISTER

**Problem:** A device is hammering `REGISTER`, and the proxy's CPU shows it. You need to name the device and the reason.

```bash
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND state == 'Failed'" --json
```

```bash
sipnab -N -I capture.pcap --group-by src --filter "method == 'REGISTER'"
```

The pattern to look for is a `401`/`403` answered by an immediate retry with the same credentials.

- That is a client that treats an auth challenge as a transient error.
- It does not stop on its own:

```text
{"status_code":403,"reason":"Forbidden","cseq":{"number":2,"method":"REGISTER"},
 "ua":"SynthSwitch/1.0","from":"Alice <sip:alice@example.com>"}
```

`ua` and `from` are what you take to the desk that owns the endpoint.
The `frame` field in the same object is what proves it ([20. Verify the exact bytes behind a finding](#verify-the-exact-bytes-behind-a-finding)).

**Pitfalls:**

- A storm from many sources with one `From` is credential reuse, not one broken phone.
  - Group by `src` before concluding.
- Registration traffic is often on a different port from calls.
  - If the counts look impossibly low, widen `--portrange`.

**Runnable example:** [Ban a scanner through TFPS, and verify it](client-examples.md#ban-a-scanner-through-tfps-and-verify-it) does two things:

- It withholds a flooding device that completed a registration earlier in the capture.
- It bans the ones that never did.

---

## Diagnose a codec mismatch

**Problem:** Calls to one destination fail immediately. The far end says "your equipment is wrong".

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json
```

Then set `CALL_ID` to the `call_id` of one failed call from that output. Ask for its report:

```bash
CALL_ID='a84b4c76e66710@pc33.atlanta.example.com'
```

```bash
sipnab -N -I capture.pcap --call-report "$CALL_ID" --markdown
```

A `488 Not Acceptable Here` after an INVITE is the signature.

- The call report puts the offered and answered codec lists next to each other.
- That is the part that settles it.
- Say the offer contains only `PCMU`, and the far end supports only `G729`.
  - Then no configuration on your side of the trunk was ever going to work.

**Pitfalls:**

- `488` is not always codec.
  - It also covers unsupported transport or an unacceptable `ptime`.
  - Read the SDP, not just the status code.
- A re-INVITE can renegotiate mid-call.
  - So a call that answered can still fail this way later.
  - Filter on the dialog, not the first transaction.

---

## Find out why DTMF does not reach the IVR

**Problem:** Callers press keys and the IVR does not respond. Everyone blames the IVR.

DTMF travels three different ways. The failure is nearly always that the two ends chose differently:

- as `telephone-event` packets inside the RTP stream ([RFC 4733](https://www.rfc-editor.org/rfc/rfc4733.html), formerly [RFC 2833](https://www.rfc-editor.org/rfc/rfc2833.html)),
- as SIP `INFO` requests,
- as audio tones inside the voice stream (in-band).

Check each in turn.

Decode `telephone-event` packets with `-t`. Each completed key press logs one line, with the digit masked as `x`:

```bash
sipnab -N -t -I capture.pcap --no-cli-print
```

Against [`tests/pcap-samples/SIP_DTMF2.cap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/SIP_DTMF2.cap):

```text
… INFO sipnab::app::batch: DTMF digit='x' duration=120ms ssrc=0x5711bf84
```

No `DTMF digit` line means no `telephone-event` packet reached the capture point.

List the SIP `INFO` requests:

```bash
sipnab -N -I capture.pcap --json | jq -c 'select(.method == "INFO") | {call_id, timestamp, src}'
```

Against [`tests/pcap-samples/DTMFsipinfo.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/DTMFsipinfo.pcap):

```text
{"call_id":"2091060b-146f-e011-809a-0019cb53db77@admind-desktop","timestamp":"2011-04-27T08:14:36.869586+00:00","src":"178.45.73.241"}
{"call_id":"2091060b-146f-e011-809a-0019cb53db77@admind-desktop","timestamp":"2011-04-27T08:14:40.600416+00:00","src":"178.45.73.241"}
```

Then check that both ends negotiated `telephone-event`. Show every message whose SDP names it:

```bash
sipnab -N -I capture.pcap -e 'telephone-event'
```

Look for an `a=rtpmap:<pt> telephone-event/8000` line in the offer **and** in the answer.

- One side may offer it while the other does not.
- Then that side sends in-band audio tones instead.
- Those tones survive G.711. G.729 destroys them.

To see which key the caller pressed, add `--dtmf-cleartext` beside `-t` and raise the log level to `debug`.
sipnab then logs a second line, at `debug`, carrying the digit:

```bash
SIPNAB_LOG=debug sipnab -N -t --dtmf-cleartext -I capture.pcap --no-cli-print
```

```text
… INFO sipnab::app::batch: DTMF digit='x' duration=120ms ssrc=0x5711bf84
… DEBUG sipnab::app::batch: DTMF cleartext digit='6' duration=120ms ssrc=0x5711bf84
```

Digits are often PINs and card numbers. Everyone who can read the log can read them.
Without `-t`, `--dtmf-cleartext` has no effect.

**Pitfalls:**

- In-band DTMF through a low-bitrate codec is not a bug you can fix in signaling.
  - The codec destroys the tones before they reach the IVR.
- A `telephone-event` payload type that differs between offer and answer (101 vs 96) is legal and still works.
  - A mismatch in whether it exists at all is not.

---

## Run sipnab as a HEP relay

**Problem:** Several edge nodes send HEP.
You want them analyzed locally *and* forwarded to a central Homer, without installing an agent twice.

sipnab both receives and sends HEP, and the two are not the same job:

```bash
sipnab -N \
  --hep-listen 0.0.0.0:9060 --hep-allow 192.0.2.0/24 \
  --hep-send homer.example.com:9060 --hep-id 42
```

Receiving makes sipnab a **collector**.

- Your SBC or proxy already speaks HEP.
- So nothing touches the capture path: no port mirror, no root.

Sending makes it a **capture agent**.

- SIP goes as HEP protocol type 1, and RTCP as type 5.
- RTCP goes as JSON carrying the call's Call-ID, the form HOMER stores.
- So the collector can report media quality, and not only call setup.
- RTP is never forwarded.

Doing both makes it a tap in the middle. You analyze at the edge, and keep the central Homer authoritative.

**Pitfalls:**

- sipnab **refuses** a non-loopback `--hep-listen` unless you pass `--hep-allow` or `--hep-auth`.
  - An open HEP port accepts forged call records from anyone who can reach it.
- `--hep-auth` travels in cleartext inside the datagram.
  - It defeats blind spoofing. But it does not survive an on-path sniffer.
  - Tunnel HEP over WireGuard or IPsec on an untrusted path.
- `--hep-auth-mode hmac` signs the **whole datagram**: every chunk.
  - So the signature covers the source and destination the sender asserts, not only the payload.
  - That is what makes `--hep-allow-kill` safe to pair with it.
  - The kill response targets exactly those fields. An unsigned assertion could aim it at a third party.
  - The listener **refuses** a version-1 HMAC token, the payload-only signature older sipnab senders produce.
    - It logs a warning containing `REFUSING version-1 tokens`, and the sender roster lists the source under `hmac_unsupported_version`.
    - There is no compatibility switch. Upgrade the sender to the same release as the listener.
- Give each agent its own `--hep-id`. Otherwise the collector cannot tell your nodes apart.

### Carry the feed over TCP and TLS

Both halves of HEP default to UDP.

- Homer's collectors also accept TCP and TLS.
- Each side of sipnab names its own transport.
- So a relay can take one in and send another out:

```bash
sipnab -N \
  --hep-listen 0.0.0.0:9061 --hep-listen-transport tcp --hep-allow 192.0.2.0/24 \
  --hep-send homer.example.com:9060 --hep-id 42
```

No single flag sets both transports. Set `--hep-listen-transport` for the receiving side and `--hep-send-transport` for the sending side.

Across a path you do not control, wrap the outgoing feed in TLS.
Name the issuer that signs the collector's certificate:

```bash
sipnab -N -d eth0 \
  --hep-send collector.example.com:9063 --hep-send-transport tls \
  --hep-tls-ca /etc/sipnab/collector-ca.pem
```

The receiving side needs a certificate of its own.
It refuses a private key that any other user on the host can read:

- Restrict the private key to its owner:

  ```bash
  chmod 600 /etc/sipnab/collector.key
  ```

- Start the listener:

  ```bash
  sipnab -N \
    --hep-listen 0.0.0.0:9063 --hep-listen-transport tls \
    --hep-tls-cert /etc/sipnab/collector.pem --hep-tls-key /etc/sipnab/collector.key \
    --hep-parse --hep-auth-file /etc/sipnab/hep.key
  ```

**Pitfalls:**

- **HEP v1 and v2 cannot travel on a stream.**
  - They declare no total length.
  - So nothing can say where one packet ends and the next begins.
  - A `tcp` or `tls` listener reads HEP v3 only.
  - Senders that emit v1 or v2 must stay on `udp`.
- **TLS says the path is private, not who is on it.**
  - sipnab asks connecting agents for no certificate of their own.
  - So the identity of a peer still comes from `--hep-auth-file`.
  - `--hep-allow` still applies too. It means the same thing it means on UDP and TCP: the source address of the connection.
  - Keep both. TLS does not lift the bind refusal for a routable `--hep-listen`, for exactly this reason.
- **A named `--hep-tls-ca` replaces the trust store rather than joining it.**
  - That is what you want for a private collector.
  - It means a public certificate stops verifying the moment you name a private issuer.
  - Omit the flag to use the host's CA bundle instead.
- **`--hep-tls-extra-ca` joins the trust store instead.**
  - It trusts the named CA in addition to the host's CA bundle.
  - That is for a sender that should accept both a private collector's issuer and the public roots.
  - sipnab refuses the two flags together.
  - `[hep] tls_ca` and `[hep] tls_extra_ca` in [`sipnab.toml`](config-reference.md#hep) set the same choice.
  - A flag for either replaces both keys.
- A `tcp` or `tls` sender connects at startup.
  - If the collector refuses that first connection, the run stops with exit 2 and `Failed to create HEP sender`. Start the collector first.
- A `tcp` or `tls` sender rebuilds its connection when the collector restarts.
  - It makes one attempt per packet.
  - sipnab can lose the packet that discovers the break. It sends the packets after it on the new connection.

**Runnable example:** [See who feeds a HEP collector](client-examples.md#see-who-feeds-a-hep-collector) lists each agent feeding a collector, and what the listener refused.

---

## Compare the same call at two nodes

**Problem:** The SBC says it sent the call. The PBX says it never arrived. Both are looking at their own logs.

Capture at both ends, and read the same `Call-ID` from each.
Set `CALL_ID` to the call you are chasing first:

- Set the Call-ID:

  ```bash
  CALL_ID='a84b4c76e66710@pc33.atlanta.example.com'
  ```

- Write the report from the SBC capture:

  ```bash
  sipnab -N -I sbc.pcap --call-report "$CALL_ID" --markdown > sbc.md
  ```

- Write the report from the PBX capture:

  ```bash
  sipnab -N -I pbx.pcap --call-report "$CALL_ID" --markdown > pbx.md
  ```

- Compare the two:

  ```bash
  diff sbc.md pbx.md
  ```

What the difference tells you:

- **Present at the SBC, absent at the PBX**: it never crossed.
  - Look at routing, firewall, or the network in between.
- **Present at both, different bodies**: something rewrote it.
  - An SBC that changes SDP addresses is doing its job.
  - One that drops a header is not.
- **Present at both, different timing**: the message crossed, but late.
  - Compare against the retransmission timers in each report.

**Pitfalls:**

- Clocks.
  - Two captures from two machines are only comparable if their clocks are.
  - A few hundred milliseconds of skew makes a normal exchange look like a retransmission.
  - Check NTP before reading timing differences as evidence.
- A B2BUA **changes the `Call-ID`** between its legs by design.
  - So this recipe compares a proxy's two sides, not a B2BUA's.
  - Correlate those by `From`/`To` and time instead.

**Runnable example:** one node may see the signaling and another the media, as a proxy and an rtpengine relay do.
Then neither report holds the whole call.
[Join one call seen at two nodes](client-examples.md#join-one-call-seen-at-two-nodes) joins them over REST.

---

## Run sipnab as a service

**Problem:** The capture should survive a reboot and an SSH disconnect, and write somewhere you can find it.

```ini
# /etc/systemd/system/sipnab.service
[Unit]
Description=sipnab SIP capture
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/sipnab -N -d eth0 --syslog \
  --metrics 127.0.0.1:9100 \
  --alert-json
Restart=on-failure
RestartSec=5
# sipnab drops privileges itself after opening the capture socket.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

- Reload systemd so it reads the new unit:

  ```bash
  sudo systemctl daemon-reload
  ```

- Enable the service, and start it.
  - `restart` starts a stopped sipnab.
  - It also restarts a running one on the new unit. `enable --now` would leave that one as it is:

  ```bash
  # Run all of these, in order.
  sudo systemctl enable sipnab
  sudo systemctl restart sipnab
  ```

- Follow its log:

  ```bash
  journalctl -u sipnab -f
  ```

**Pitfalls:**

- `--syslog` is what makes `journalctl` useful.
  - Without it, the interesting output goes to stdout. journald merges it there without structure.
- Granting `CAP_NET_RAW` via `AmbientCapabilities` is what lets the unit run without being root at all.
  - Do not add `User=root` back "to be safe". That undoes it.
- A live run with no `-O` writes no capture file.
  - If you want the packets kept, say where.

---

## Read a capture whose SIP is not on port 5060

**Problem:** A trunk capture shows almost no SIP. The calls are in the file. The signaling is on 5070, or 5080, or whatever port the SBC uses.

`--portrange` gates signaling only.

- sipnab skips SIP whose source and destination both sit outside the range.
- That traffic then appears in no message count, no dialog and no output format.

Widen the gate to everything the file holds:

```bash
sipnab -N -I capture.pcap --portrange 1-65535 --report --no-cli-print
```

Or name the range you actually run. That keeps a busy file fast:

```bash
sipnab -N -I capture.pcap --portrange 5060-5090 --report --no-cli-print
```

**What to look for:**

- sipnab counts the SIP the gate discarded, and names the busiest ports it was on.
  - So a default run tells you what to widen to, instead of reporting a quiet capture.
- Media is never gated by `--portrange`, because RTP uses SDP-negotiated dynamic ports.
  - A too-narrow signaling range does not hide the streams.
  - It hides the calls they belong to.
  - The streams then arrive as orphans.

**Pitfalls:**

- On a **live** device, the range becomes the BPF filter when you supply no filter of your own.
  - There the kernel drops the traffic.
  - So nothing downstream (this counter included) can see it was ever there.
- SIP over WebSocket has a gate of its own, `--ws-portrange`.
  - Widening this one does not widen that one ([36. Read SIP over WebSocket from a WebRTC gateway](#read-sip-over-websocket-from-a-webrtc-gateway)).

---

## Find calls that answered and were never acknowledged

**Problem:** Calls answer and drop a second later, or the switch logs "no ACK".
A `200 OK` with no `ACK` behind it is a call that both sides' CDRs record as connected. Nobody could speak on it.

Two timers decide when sipnab treats silence as a fault, rather than as a capture that stopped early:

```bash
sipnab -N -I capture.pcap --ack-timeout 5 --analyze
```

`--no-final-response-timeout` does the same for an `INVITE` that never drew a final response at all:

```bash
sipnab -N -I capture.pcap --no-final-response-timeout 30 --analyze
```

**What to look for:**

- The defaults are the RFC 3261 timers:
  - Timer H (32 s) for the missing ACK,
  - Timer C (180 s) for the missing final response.
  - A capture shorter than the timer cannot distinguish a fault from a truncation.
  - That is exactly why sipnab does not call it one.
- Lower them when the capture is short and the calls are local.
  - A five-second `--ack-timeout` on a LAN is a real finding.
  - The same number on an international trunk is a stopwatch running against the network.

**Pitfalls:**

- Lowering `--no-final-response-timeout` reports **every call still ringing when the capture stopped**.
  - On a live tap, that is a normal state and not a fault.
  - Read it against how the capture ended.
- These change what sipnab reports, not what the capture holds.
  - A missing ACK that arrived after the last packet in the file is missing from the file, not from the network.

**Runnable example:** [Group failed calls by response code](client-examples.md#group-failed-calls-by-response-code) lists the calls answered and never acknowledged, beside the failed ones.

---

## Set the quality thresholds to your own network

**Problem:** Every stream shows yellow, or nothing ever does.
The shipped thresholds describe a general network, and yours is not one.

The eight quality knobs carry no built-in command-line default.
So a value you do not pass leaves the config file's value in charge:

```bash
sipnab -N -I capture.pcap --mos-warn 4.0 --mos-bad 3.2 --jitter-warn-ms 20 --jitter-bad-ms 50 --loss-warn-pct 1.0 --loss-bad-pct 3.0 --report --no-cli-print
```

Round-trip time has its own pair, read from RTCP when the capture carries it:

```bash
sipnab -N -I capture.pcap --rtt-warn-ms 150 --rtt-bad-ms 300 --report --no-cli-print
```

The one MOS input a passive tap cannot measure is the one-way delay.
Declare it, rather than letting the default stand:

```bash
sipnab -N -I capture.pcap --one-way-delay 40 --report --no-cli-print
```

**What to look for:**

- A MOS built on an assumed delay is only as good as the assumption.
  - `media_diagnostics` ([58. Ask why the MOS is what it is](#ask-why-the-mos-is-what-it-is)) reports `delay.assumed: true` when nothing supplied one.
  - That is the flag to read before quoting a score to a carrier.
- `--pdd-threshold` defaults to ITU-T E.721's target for an **international** connection.
  - A capture does not say what kind of call it holds.
  - A network that knows its traffic is local or toll wants a tighter number.

**Pitfalls:**

- Thresholds change which figures the output colors, and which ones it reports.
  - They do not change the measurement.
  - So widening one to quiet a report hides the finding rather than fixing it.
- `--one-way-delay` is a declaration about the observed path.
  - Declaring one you have not measured trades an honest default for a confident wrong number.

---

## Export one customer's calls as a smaller capture

**Problem:** A vendor wants the packets, and the file is 4 GB of everyone's traffic.
Sending all of it is both slow and a disclosure.

**Only the BPF expression narrows `-O`.**

- It writes each packet as it arrives, inside the capture loop.
- That is before any dialog is complete enough to judge.
- Nothing can tell whether a call matches `from.user == '1001'` until sipnab has seen and correlated its INVITE.
- So `--filter` does not reach it.
- A run with `-O` and a `--filter` that matches no dialog writes the same bytes as a run with no filter.

That matters here more than anywhere else on this page.
The thing you are about to do is mail the result to somebody else.
Narrow with the positional BPF expression. It runs in the kernel before sipnab sees a packet:

```bash
sipnab -N -I capture.pcap -O one-customer.pcap --no-cli-print "host 192.0.2.10"
```

The same as pcapng. That is the format that can also carry decryption secrets:

```bash
sipnab -N -I capture.pcap -O one-customer.pcapng --pcapng --no-cli-print "host 192.0.2.10"
```

BPF is a network-level language. It selects by address, port and protocol, not by SIP user.
The subset you need may be a SIP-level one. Then you have two honest options, and neither is `-O`.

Export the dialogs as vCon containers. That export IS dialog-filtered:

```bash
sipnab -N -I capture.pcap --export-vcon-when "from.user == '1001'" --export-vcon-dir ./out
```

Or export those dialogs with the identifiers replaced by pseudonyms.
`--redact` rewrites exported containers only. There is no redacted pcap, and `-O` with `--redact` and no vCon export stops with exit 2:

```bash
sipnab -N -I capture.pcap --export-vcon-when "from.user == '1001'" --export-vcon-dir ./out --redact
```

**What to look for:**

- Read the output back before you send it.
  - A file that reconstructs the same dialogs is one the far end can work with.
  - One that does not means the filter cut a leg off the call.
- `--pcapng` is worth the extra bytes when the capture carried decryption secrets.
  - pcapng is the format that can carry them ([7c. Export encrypted packets for Wireshark](#export-encrypted-packets-for-wireshark)).

**Pitfalls:**

- A filter selects **dialogs**.
  - So a call whose INVITE was outside the capture has no dialog to match.
  - Its packets are not written.
- sipnab refuses to write its output over its input.
  - Name a different path. Use a different directory if you are working in place.

**Runnable example:** [Export the calls of one customer from rotated captures](client-examples.md#export-the-calls-of-one-customer-from-rotated-captures):

- builds the BPF expression from the customer's calls,
- reads the export back,
- removes it when another customer's call shares an address.

---

## Check what a STIR/SHAKEN Identity header actually claims

**Problem:** Somebody is spoofing a number, or a carrier says your calls arrive with a bad attestation.
The argument is about what the header actually held.

`--stir-shaken` decodes the [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224.html) `Identity` header's PASSporT. It reports what the PASSporT claims:

```bash
sipnab -N -I capture.pcap --stir-shaken --no-cli-print
```

Each decoded token prints one line:

```text
STIR/SHAKEN: attest=A orig=+15551234567 dest=["+15559876543"] verified=NotChecked
```

**What to look for:**

- `attest=A` means the originator **claimed** full attestation.
  - Nothing here confirms the claim.
  - A forged Identity header decodes exactly like a genuine one.
  - So this is evidence about what the originator claimed. It is never grounds for trusting a calling number.
- `verified=Expired` is the one check sipnab applies locally.
  - The check is [RFC 8224 section 6.2](https://www.rfc-editor.org/rfc/rfc8224.html#section-6.2), Step 4, `iat` freshness.
  - sipnab checks it against the capture timestamp of the packet carrying the header.
  - An old pcap therefore reports the tokens that were still fresh at the moment they crossed the tap.
- No `STIR/SHAKEN:` line at all means no `Identity` header reached the capture point.
  - On an inbound trunk, that is itself the finding.

**Pitfalls:**

- sipnab makes no outbound request to analyze a capture.
  - So it never fetches the certificate the token references.
  - It never checks the signature over it.
  - `verified=NotChecked` is the honest answer, not a failure.
- sipnab logs the line at `info`.
  - `--quiet` floors the log at `warn` and hides it. So does the TUI.

---

## Detect weak digest authentication on a registrar

**Problem:** An audit asks whether the phones authenticate properly.
Nobody can answer from the switch's configuration alone, because the challenge is what the wire actually carried.

`--digest-leak` reads the 401/407 challenges and the `Authorization` headers answering them. It reports four weaknesses:

- an MD5 algorithm,
- a nonce reused across challenges,
- a challenge with no `qop`,
- a response with no `cnonce` where the challenge offered `qop`.

```bash
sipnab -N -I capture.pcap --digest-leak --alert-json --no-cli-print
```

Findings arrive as one JSON object per detection:

```text
{"alert":"digest","detail":"WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)","src":"203.0.113.101","ts":"2026-05-05T12:34:56Z"}
```

Group the accused sources and get a firewall rule with the evidence beside it:

```bash
sipnab -N -I capture.pcap --digest-leak --recommend-block fail2ban --quiet
```

**What to look for:**

- `WeakAlgorithm` with **no** `algorithm` parameter in the challenge is the same finding as `algorithm=MD5`.
  - [RFC 2617](https://www.rfc-editor.org/rfc/rfc2617.html) makes MD5 the default when the parameter is absent.
  - So silence is a choice.
- `NonceReuse` across challenges is the one to act on first.
  - A nonce that repeats is a replay window.
  - It usually means a registrar cluster whose nodes do not share nonce state.
  - A 401 the registrar retransmitted (the same Call-ID, CSeq and Via branch) is the same challenge arriving twice. It does not count.

**Pitfalls:**

- **The detector needs an alert channel, or it prints nothing.**
  - `--digest-leak` on its own arms the detection, and has nowhere to put it.
  - Pass `--alert-json`, or `--alert syslog`, or read it through `--recommend-block`.
  - A run with neither looks exactly like a clean capture.
- This is a configuration audit, not a credential dump.
  - sipnab reports the weakness in the exchange.
  - It never prints the `response` hash. That hash is an offline attack against the subscriber's password.

---

## Read SIP that arrives in TCP segments or IP fragments

**Problem:** A capture full of SIP over TCP shows half the messages.
Or a large INVITE with many codecs and ICE candidates never parses.

sipnab reassembles IP fragments and TCP segments by default. Two limits bound what that costs:

```bash
sipnab -N -I capture.pcap --max-reassembly 500 --reassembly-ttl 15 --report --no-cli-print
```

sipnab drops a message larger than the TCP buffer, rather than growing one into memory.
Raise it for a switch that sends very large bodies:

```bash
sipnab -N -I capture.pcap --max-tcp-buffer 262144 --report --no-cli-print
```

Turn reassembly off when the capture is pure single-packet UDP. Then reassembly is only overhead:

```bash
sipnab -N -I capture.pcap --no-reassembly --report --no-cli-print
```

**What to look for:**

- `--report` counts frames no decoder could read separately from frames that were never captured.
  - A capture that lost the second half of every large INVITE reports differently from one that never saw them.
- sipnab holds an incomplete datagram or half-read stream for `--reassembly-ttl` seconds. Then it sweeps it.
  - On a lossy path, that sweep is where a truncated message goes.
  - Its count is what tells you the path is lossy.

**Pitfalls:**

- `--no-reassembly` is the inverse of segment reassembly.
  - On a TCP or TLS capture, it does not make the run faster in any useful sense.
  - It makes every multi-segment message unparseable.
- A `--snaplen` that cut the frame short is a different problem with the same symptom.
  - Reassembly cannot restore bytes the capture never took ([22. Measure whether the loss is yours or the network's](#measure-whether-the-loss-is-yours-or-the-networks)).

---

## Read SIP over WebSocket from a WebRTC gateway

**Problem:** A WebRTC leg is invisible.
The browser talks SIP over WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118.html)) to Kamailio, OpenSIPS or Janus.
The capture shows TCP and no calls.

The shipped WebSocket port set is 80, 443, 8080, 8443.

- That is the browser's view of the web, not a deployment's.
- Behind a reverse proxy, sipnab sees whichever port the proxy forwards to:

```bash
sipnab -N -I capture.pcap --ws-portrange 1-65535 --report --no-cli-print
```

Or name the port the gateway actually listens on:

```bash
sipnab -N -I capture.pcap --ws-portrange 5066-5066 --report --no-cli-print
```

sipnab refuses a WebSocket frame whose payload exceeds 64 KiB (65,536 bytes).
It does not reassemble it.

- No SIP message comes close.
- So a frame that large is either not SIP or not well-formed.

**What to look for:**

- sipnab tallies the SIP-over-WebSocket it declined to unwrap, and names the ports it was on.
  - So a run with the default set still tells you where the traffic is.
- A range **replaces** the shipped set, exactly as `--portrange` replaces the default signaling ports.
  - Naming 5066 alone stops unwrapping 443.

**Pitfalls:**

- WSS is TLS. Unwrapping the WebSocket framing needs the TLS decrypted first. Use one of:
  - a keylog ([7. Decrypt SIP over TLS when you can restart the phone or server — key log file (SSLKEYLOGFILE)](#decrypt-sip-over-tls-when-you-can-restart-the-phone-or-server--key-log-file-sslkeylogfile)),
  - a uprobe ([7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all)).
  - `--ws-portrange` alone does nothing for it.
- When the media goes peer to peer, a browser leg carries no RTP that a server-side tap can see.
  - Put the capture where the media is.
  - Or read the relay's account of it ([54. Find out where a stream's endpoint came from](#find-out-where-a-streams-endpoint-came-from)).

---

## Read SIP carried inside a GTP-U or VXLAN tunnel

**Problem:** On a mobile core or a data-center fabric, the SIP is real and the capture is empty.
Every packet is an outer UDP header with the call inside it.

`--capture-tunnels` takes all traffic on the tunnel ports, so the inner SIP reaches sipnab.
With no value, it covers GTP-U (2152), VXLAN (4789) and GENEVE (6081):

```bash
sudo sipnab -N -d eth0 --capture-tunnels
```

Name the ports yourself for a non-standard deployment. Linux's pre-IANA VXLAN port is one example:

```bash
sudo sipnab -N -d eth0 --capture-tunnels=8472
```

It applies to a file too, where the tunnel is already in the bytes:

```bash
sipnab -N -I capture.pcap --capture-tunnels --report --no-cli-print
```

**What to look for:**

- Without the flag, the auto-generated filter still sees VLAN, QinQ, PPPoE and MPLS-encapsulated SIP.
  - Those cost nothing to add, and are already on.
  - Tunnels are the case that is off.
- The dialogs come out with the **inner** addresses.
  - Those are the ones the SIP layer used, and the ones a routing argument is about.

**Pitfalls:**

- This is not a narrowing filter.
  - BPF cannot walk a GTP-U extension-header chain to reach the inner port.
  - So the only way to cover these is to take everything on the port.
  - On a mobile core, that is the entire user plane.
  - Size `-B` for it ([43. Keep a long-running capture inside a memory budget](#keep-a-long-running-capture-inside-a-memory-budget)).
- sipnab ignores the flag when you supply your own BPF expression.
  - Your filter is then the whole filter, tunnel ports included or not.

---

## Search a capture for a header or a body string

**Problem:** You know a string that identifies the traffic. You do not know which calls carry it. The string can be:

- a `P-Asserted-Identity`,
- an `X-` header your SBC adds,
- a trunk group name.

`-e` is the positional match expression: a regex against the whole raw message.
Once any message in a dialog matches, sipnab shows every later message of that dialog too:

```bash
sipnab -N -I capture.pcap -e 'X-Trunk-Group' -i
```

Whole words only, with two messages of context after each hit:

```bash
sipnab -N -I capture.pcap -e 'INVITE' -w -A 2
```

Multi-line headers folded into one line before matching. A regex spanning a wrapped `Contact` needs this:

```bash
sipnab -N -I capture.pcap -e 'User-Agent' -i --single-line
```

Everything that does **not** match, for finding the odd one out:

```bash
sipnab -N -I capture.pcap -v -e 'OPTIONS'
```

`-v` still follows dialogs. Once one message of a dialog prints, every later message of that dialog prints too, including messages that match.
For example, `-v -e 'BYE'` against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap) prints the INVITE first. The BYE and its `200 OK` then print as part of that dialog:

```text
14:52:59.666 10.0.2.20:5060 -> 10.0.2.15:5060 INVITE UDP
…
14:52:59.670 10.0.2.20:5060 -> 10.0.2.15:5060 ACK UDP
14:53:08.170 10.0.2.15:5060 -> 10.0.2.20:5060 BYE UDP
14:53:08.170 10.0.2.20:5060 -> 10.0.2.15:5060 200 OK UDP
…
```

**What to look for:**

- `-e` matches the message text. `--filter` matches the reconstructed dialog.
  - Use `-e` for "which calls mention this string".
  - Use `--filter` for "which calls behaved this way".
  - `payload =~ '<regex>'` in the filter DSL is the bridge. It selects a dialog when any of its messages matches the regex.
- Add `--hexdump` when the argument is about bytes rather than text. For example:
  - a header with trailing whitespace,
  - a body whose line endings are wrong.

**Pitfalls:**

- `-e` is a regex.
  - So `.` and `+` in a phone number or a header name match more than you meant.
  - Escape them, or add `-w`.
- The trailing positional argument is a **BPF** filter, not a match expression.
  - `sipnab -I capture.pcap INVITE` asks libpcap to compile `INVITE`, and fails.
  - The match expression needs `-e`.

---

## Collect a directory of rotated captures into one analysis

**Problem:** `tcpdump -C -W` left you 27 files, and the call you want crosses three of them.

`-I` takes a file, a **directory** or a **glob**. It is repeatable.

- sipnab reads the files in the order their packets arrived, never by filename.
- A ring buffer wraps. So `tg.pcap7` can hold older traffic than `tg.pcap0`:

```bash
sipnab -N -I '/var/captures/*.pcap' --report --no-cli-print
```

Descend into subdirectories, which is off by default:

```bash
sipnab -N -I '/var/captures/*.pcap' --recursive --report --no-cli-print
```

**What to look for:**

- One store serves the whole set.
  - So a dialog whose INVITE is in one file and whose BYE is in another comes out as one call.
- `sipnab -N -I /var/captures --input-name 'tg.pcap[0-4]'` narrows a **directory** to the files worth reading.
  - sipnab matches the pattern against the filename alone.
  - So it behaves the same at every depth under `--recursive`.
  - When `-I` names one file directly, the pattern must match that file's name.
    - If it does not, sipnab exits 1 and says `--input-name filters only files found in a directory or by a glob`.
    - Compressed files follow the same rule: `'*.pcap'` does not match `call.pcap.gz`.

**Pitfalls:**

- `-l`/`--limit` bounds dialogs for the whole **run**, not per file.
  - A 27-file directory reaches the cap 27 times sooner than one file does.
  - Eviction drops the oldest dialogs. Those are the worst ones to lose for a post-mortem.
  - Raise it ([43. Keep a long-running capture inside a memory budget](#keep-a-long-running-capture-inside-a-memory-budget)).
- `--recursive` is off by default.
  - Descending silently can analyze several times the traffic you pointed at.
  - Nothing in the output would say so.

**Runnable example:** [Export the calls of one customer from rotated captures](client-examples.md#export-the-calls-of-one-customer-from-rotated-captures):

- reads a directory of rotated captures,
- exports one customer's calls,
- checks the export holds them whole.

---

## Open the same evidence in Wireshark

**Problem:** The argument has moved to a layer sipnab does not decode.
Or the person you are arguing with only trusts Wireshark.

`--tshark-filter` prints a ready-to-run tshark command for this capture and this display filter:

```bash
sipnab -N -I capture.pcap --tshark-filter 'sip.Method == "INVITE"' --no-cli-print
```

```text
tshark -r capture.pcap -Y 'sip.Method == "INVITE"' -V
```

Narrow it to one call, using a Call-ID you already have:

```bash
sipnab -N -I capture.pcap --tshark-filter 'sip.Call-ID == "abc123@host"' --no-cli-print
```

**What to look for:**

- Pair it with [20. Verify the exact bytes behind a finding](#verify-the-exact-bytes-behind-a-finding).
  - A frame pointer names one frame.
  - A digest proves it is the same file.
  - The tshark command puts that frame in front of somebody who wants to see the whole stack under it.
- The printed command is text.
  - Read it, edit the filter, and run it yourself.
  - sipnab does not run it for you.
- `sipnab -N -I capture.pcap --wireshark` is the same idea for the GUI.
  - It builds a display filter naming every Call-ID in the capture.
  - It prints the filter for you to paste into Wireshark.

**Pitfalls:**

- `--wireshark` only prints text.
  - So it needs neither Wireshark nor a display on the capture host.
  - Open the capture in Wireshark separately, and paste the printed filter.
- A tshark display filter is not sipnab's filter DSL, and not a BPF expression.
  - All three languages appear in this cookbook.
  - None of them accepts the syntax of the other two.

**Runnable example:** [Export the calls of one customer from rotated captures](client-examples.md#export-the-calls-of-one-customer-from-rotated-captures) ends with the `tshark` command for the export.

---

## Measure the gap between consecutive messages

**Problem:** The ladder looks correct, and the call still feels slow.
Or a retransmission argument needs the actual timers, rather than "it looked immediate".

`--delta-time` replaces the wall clock in front of each message with the gap since the previous one:

```bash
sipnab -N -I capture.pcap --delta-time
```

```text
+0.000s 192.0.2.20:5060 -> 192.0.2.15:5060 INVITE UDP
+0.512s 192.0.2.15:5060 -> 192.0.2.20:5060 100 Trying UDP
```

Add the full header block of the bodyless messages. Otherwise they print as a one-line summary:

```bash
sipnab -N -I capture.pcap --delta-time --show-empty
```

Group the messages by call first. Then the gaps you are reading belong to one ladder:

```bash
sipnab -N -I capture.pcap --group-by call-id --delta-time
```

**What to look for:**

- 500 ms, then 1 s, then 2 s, then 4 s between copies of one request is RFC 3261's Timer A backing off.
  - That is a retransmission.
  - It says the first copy never reached anything that would answer it.
  - It does not say that the sender is chatty.
- A long gap before `180 Ringing` is post-dial delay. It belongs to the far end.
- A long gap before `100 Trying` belongs to the next hop. The next hop should answer immediately.

**Pitfalls:**

- Without `--group-by`, a busy capture interleaves twenty calls.
  - Then the "gap" is the time to the next message of **any** of them.
- sipnab computes each delta from capture timestamps.
  - Two captures from two machines are only comparable if their clocks are ([27. Compare the same call at two nodes](#compare-the-same-call-at-two-nodes)).

---

## Record which invocation produced a report

**Problem:** A report from three weeks ago says the capture was clean.
Nobody can say which file, which filter or which port range produced it.

`--run-provenance-file` appends one JSON line per run, at startup.

- It writes before the config takes effect.
- It writes before sipnab opens any capture device.
- sipnab reads the config file first. So `capture.node` is the node `--node-name` or `[capture] node_name` sets:

```bash
sipnab -N -I capture.pcap --node-name capture-01 --run-provenance-file runs.jsonl --report --no-cli-print
```

Under systemd, point it somewhere durable: `--run-provenance-file /var/log/sipnab/runs.jsonl`.
Then every restart appends rather than replaces.

```text
{"argv":["sipnab","-N","-I","capture.pcap","--node-name","capture-01","--run-provenance-file","runs.jsonl","--report","--no-cli-print"],
 "capture":{"dialog_generation":0,"instance":"12d0b918df0076acd28253-1","node":"capture-01","stream_generation":0},
 …
 "pid":1233081,"record":"run","seq":1,
 "started":"2026-10-16T11:54:46.422350839+00:00","ts":"2026-10-16T11:54:46.422377376+00:00",
 "uid":1000,"user":"operator",
 "version":"0.5.222 (16f7b0ea) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,wasm,plugins,bpf,vcon,opus,archive,g729"}
```

`uid` and `user` name the account that ran sipnab. This sample shows a placeholder account name.

sipnab records a secret given on the command line as `[redacted]`. That covers:

- the value of `--api-key`, `--api-signing-key`, `--archive-password`, `--hep-auth`, `--mcp-signing-key`, `--mcp-token`, `--metrics-auth` and `--vcon-forward-auth`,
  - whether the value follows the flag after a space or after `=`;
- the user name and password in a URL such as `--vcon-forward-url https://user:pass@store.example.com/`.

**What to look for:**

- `capture.instance` is the identifier every MCP and REST answer about the loaded capture carries, in `capture_identity.instance`.
  - [MCP across an estate](mcp-estate.md#check-what-federation-cannot-prove) and [the REST reference](rest-api.md#which-capture-these-counts-came-from) list the few answers that do not carry it.
  - So it joins an artifact back to the command that made it.
- `features` is the build, not the flags.
  - A report can miss a section because the binary lacked the Cargo feature.
  - That report reads identically to a clean one.
  - This line is where that difference shows up.

**Pitfalls:**

- **A record sipnab cannot write stops the run.**
  - A best-effort line's absence would mean either "not enabled" or "the disk was full".
  - Nobody could tell which.
  - Stopping costs nothing, because sipnab has read no packet yet.
- sipnab opens the file for append, and never truncates it.
  - It creates it mode 0600.
  - argv holds capture paths, and a path holds a customer's name.

---

## Keep a long-running capture inside a memory budget

**Problem:** A capture that should run for a week dies on day three under the out-of-memory killer.

Five caps bound what a run retains, and each bounds a different thing:

```bash
sipnab -N -I capture.pcap --limit 20000 --max-streams 4000 --max-lost-sequences 4000 --findings-history 500 --report --no-cli-print
```

The in-flight queue between capture and processing has a budget of its own.
It is separate from the kernel ring `-B` sizes:

```bash
sudo sipnab -N -d eth0 --buffer-budget 128 -B 128
```

**What to look for:**

- `-l`/`--limit` is **not** a concurrency limit.
  - Nothing removes a completed dialog.
  - So the bound scales with uptime rather than with load.
  - A box carrying five concurrent calls still evicts once 100,000 calls have completed.
- The eviction count appears wherever a dialog count appears.
  - So a run that hit a cap says so, rather than quietly answering from a truncated store.

**Pitfalls:**

- Eviction drops the **oldest** dialogs. Those are the ones a post-mortem wants.
  - On a long run, prefer rotating output files ([44. Run a capture that stops on its own](#run-a-capture-that-stops-on-its-own)).
  - Do not rely on the store to hold a week.
- `--max-groups` bounds `--group-by` keys. It is a separate map from `--limit`.
  - A run that groups a week of traffic by source address needs both raised.

---

## Run a capture that stops on its own

**Problem:** A capture running over a weekend either fills the disk, or waits for somebody to stop it at the wrong moment.

Stop after a packet count, a wall-clock duration, or a size:

```bash
sudo sipnab -N -d eth0 -n 500000 --duration 8h --autostop filesize:2048 -O /var/capture/sip.pcapng --pcapng
```

Or keep capturing forever inside a fixed budget. Rotate, and delete the oldest chunks:

```bash
sudo sipnab -N -d eth0 -O /var/capture/sip.pcapng --pcapng --split filesize:50 --split-keep 8
```

**What to look for:**

- `filesize` counts **MiB**, the same unit `--split filesize` and `-B` use.
  - So `filesize:2048` stops at what a file browser calls 2 GiB.
- `-n`/`--count` counts every packet received from the capture source.
  - On a HEP listener, that includes packets later dropped by the allowlist, the rate limiter or authentication.

**Pitfalls:**

- `--split-keep` **deletes** capture files.
  - It touches only the files that running process created and named.
  - So anything else in the directory stays.
  - But leave it off whenever the capture is evidence you cannot retake.
- A run killed mid-capture leaves behind whatever it had not yet deleted.
  - The next run does not adopt it.

---

## Check whether comfort noise explains a one-way finding

**Problem:** A mobile or VoLTE trunk reports one-way audio on calls that were fine.
Or a trunk that really is one-way reports nothing.

`--cn-suppression-ratio` is a share of a call's packets.

- That share must be comfort noise before sipnab accepts comfort noise as the explanation for media in one direction.
- It is the one threshold that **suppresses** a finding.
- So getting it wrong fails silently:

```bash
sipnab -N -I capture.pcap --cn-suppression-ratio 0.6 --report --no-cli-print
```

Lower it where a call carrying any comfort noise at all is still expected to be bidirectional:

```bash
sipnab -N -I capture.pcap --cn-suppression-ratio 0.1 --one-way --json-dialogs
```

**What to look for:**

- A trunk with aggressive voice activity detection routinely passes 30 % comfort noise.
  - Above the ratio, one-way audio is never reported on it.
  - If a trunk has stopped producing one-way findings entirely, this is the first knob to check.
- `media_diagnostics` ([58. Ask why the MOS is what it is](#ask-why-the-mos-is-what-it-is)) counts the comfort-noise frames and the silence periods per stream.
  - That is the measurement this ratio governs.

**Pitfalls:**

- sipnab refuses values of 0 and above 1 by name, in the flag and in the config file.
  - So a config file is not the lenient way in.
- Raising it is a statement about the trunk, not about the call.
  - Set it per capture source rather than globally.

---

## Detect fraud placed outside business hours

**Problem:** The international bill jumped, and the calls all happened at 03:00.

`--fraud-detect` runs the volume, wangiri and sequential-dialing heuristics.
`--business-hours` adds the off-hours detector.

- That detector is otherwise unreachable.
- With no window declared, there is no "outside" for a call to fall in:

```bash
sipnab -N -I capture.pcap --fraud-detect --business-hours 8-18 --alert-json --no-cli-print
```

A wrapping range is the overnight window:

```bash
sipnab -N -I capture.pcap --fraud-detect --business-hours 22-6 --alert-json --no-cli-print
```

**What to look for:**

- The window is whole **UTC** hours.
  - A site that works 08:00–18:00 local is a different pair of numbers.
  - Getting it wrong moves the alert rather than silencing it.
- Off-hours volume from a single extension is the classic compromised-handset signature.
  - Feed the source to the block recommendation in [10. Detect SIP scanners and auto-block via fail2ban](#detect-sip-scanners-and-auto-block-via-fail2ban) before banning it.
  - Then a night-shift desk is not the thing you disconnect.

**Pitfalls:**

- `--business-hours` without `--fraud-detect` arms nothing.
  - The second flag is what runs the detector.
- As with every detector on this page, an alert channel is what makes the findings visible.
  - Use `--alert-json`, `--alert syslog` or `--recommend-block`.
  - With none of them, the run is silent.

---

## Follow a load generator's traffic by transaction, not by call

**Problem:** A SIPp run or a proxy under test reuses one `Call-ID` across hundreds of transactions.
The whole capture then reconstructs as a single enormous dialog.

`--dialog-track branch` groups by SIP transaction (the `Via` branch), instead of by `Call-ID`:

```bash
sipnab -N -I capture.pcap --dialog-track branch --report --no-cli-print
```

**What to look for:**

- A single ordinary call yields **several** units under `branch`.
  - RFC 3261 gives the ACK to a 2xx a new branch, and the BYE another.
  - That is the transaction view, not a miscount.
- Compare the two counts.
  - A capture whose `call-id` count is 1 and whose `branch` count is 400 is a load generator.
  - One where they are close is ordinary traffic.

**Pitfalls:**

- sipnab computes every dialog-level diagnosis per tracked unit. That includes one-way audio, codec asymmetry and PDD.
  - Under `branch`, those units are transactions.
  - So a per-call figure is not what you get.
- Switch back to `call-id` (the default) before quoting durations or MOS at anyone.

---

## Run a live capture without giving sipnab root

**Problem:** Security refuses to sign off on a packet capture running as root.
And `sudo sipnab` on every invocation is what the procedure currently says.

Grant the binary the two capabilities live capture needs, once:

```bash
sipnab --setup-caps
```

Then run it as an ordinary user.
sipnab opens its capture devices first, and drops privileges afterwards.
So name the user, and a directory to confine it to:

```bash
sudo sipnab -N -d eth0 --user sipnab --chroot /var/empty
```

**What to look for:**

- `--setup-caps` sets `cap_net_raw,cap_net_admin+ep` via `setcap`, and exits.
  - It re-invokes itself through `sudo` when it is not already root.
  - After it, `sudo` is no longer part of the daily command.
- Under systemd, `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` does the same job for the unit ([28. Run sipnab as a service](#run-sipnab-as-a-service)).
  - Do not add `User=root` back "to be safe". That undoes it.

**Pitfalls:**

- **`setcap` does not survive a new binary.**
  - Every upgrade, every rebuild, every package update drops it.
  - The failure looks like a permissions problem that appeared from nowhere.
  - Re-run `--setup-caps` after an upgrade.
- sipnab opens anything it must reach by path **before** the drop and the chroot.
  - That includes a keylog file or FIFO, an output file, a config.
  - A path under `/run` is unreachable afterwards ([7f. Decrypt without writing the keys to disk](#decrypt-without-writing-the-keys-to-disk)).
- `--no-priv-drop` keeps the privileges for the rest of the run.
  - It is not the way to fix a permissions error.
  - Forging kill responses does not need it.
  - sipnab opens the raw socket before the drop, and hands it to the scanner-kill worker process.
  - That process never keeps root either way.

---

## Configure sipnab from a file instead of a long command line

**Problem:** The capture command has grown to eleven flags, three of them thresholds.
It now lives in four places that disagree.

Print the configuration this invocation would actually use, and exit:

```bash
sipnab -D
```

Point at a file explicitly. A systemd unit should do this, rather than rely on search order:

```bash
sipnab --dump-config --config /etc/sipnab/sipnab.toml
```

Ignore every config file. That is how you prove a behavior comes from the flags, and not from a file you forgot:

```bash
sipnab -D --no-config
```

**What to look for:**

- A flag beats the file.
  - Several knobs carry no built-in flag default.
  - That keeps "not typed" and "typed the default" distinguishable.
  - It also gives the config key something to override.
  - The eight quality thresholds ([31. Set the quality thresholds to your own network](#set-the-quality-thresholds-to-your-own-network)) and `--mcp-max-rows` are among them.
- `-D` is the fastest way to settle "is this host reading the config I think it is".
  - It answers before any capture starts.

**Pitfalls:**

- `-D` dumps the **effective** configuration.
  - That includes values that came from a file you did not name.
  - Add `--no-config` to see the flags alone.
- A config file is per host. The tool set an MCP server registers is usually per client.
  - Set the host default in `[mcp] tools`.
  - Give each client its own list with `--mcp-tools`.
  - That flag replaces the config list rather than adding to it.

---

## Install shell completions

**Problem:** sipnab has a long flag for nearly everything on this page, and you are typing them from memory.

```bash
sipnab --completions bash
```

Write it where your shell looks for it:

```bash
sipnab --completions zsh
```

**What to look for:**

- Accepted shells are `bash`, `elvish`, `fish`, `powershell` and `zsh`.
  - The script goes to stdout. So redirect it: `sipnab --completions bash > /etc/bash_completion.d/sipnab`.
- sipnab generates the completions from the same flag definitions `--help` prints.
  - So they cannot drift from the binary that produced them.

**Pitfalls:**

- Regenerate after an upgrade.
  - A completion file from an older build offers flags the new binary may have renamed.
  - That is the one failure mode a completion has.
- Completions know the flags, not your captures. They do not complete a Call-ID or a filter expression.

---

## Export every failed call as a redacted vCon in one pass

**Problem:** A conversation archive, a compliance store or an agent pipeline wants the calls that failed.

- It wants them as containers, not as a pcap.
- The subscriber numbers may not leave the building in the clear.

`--export-vcon-when` takes a filter. It writes one container per matching dialog into a directory.
`--redact` turns every identity into a keyed pseudonym:

```bash
sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./vcons --redact --vcon-digest
```

This run does three more things:

- writes the reversal table,
- keeps three leading digits of each number,
- caps what a container may inline:

```bash
sipnab -N -I capture.pcap --export-vcon-when "response_code >= 400" --export-vcon-dir ./vcons --redact --redact-map ./redact-map.json --redact-keep-prefix 3 --vcon-max-inline-media 2
```

`--vcon-digest` prints one `sha256sum`-format line per container written to `--export-vcon-dir`.
Against [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap), the first command above prints:

```text
e25aea942fe9554a9a8cbf66c1a9025ed32fee43cde8edb478f22788a21d806e  c1a0efc0ee0127a1_151.86.209.85-e9e13aaaf4fb470d.vcon.json
b9c04e01de9a2655ea960e7203d694f83d44c757c67eec594d4b546edf70dfab  92aa11e99171d82d_147.248.178.148-455cc7c020c3162d.vcon.json
…
```

The digests and file names change on every run, because each run draws a fresh redaction key.

To check the containers later, save the lines and verify them from inside the export directory. The file names in the lines are relative to it:

- Save the digests:

  ```bash
  sipnab -N -I capture.pcap --export-vcon-when "state == 'Failed'" --export-vcon-dir ./vcons --redact --vcon-digest > SHA256SUMS
  ```

- Verify them:

  ```bash
  cd vcons && sha256sum -c ../SHA256SUMS
  ```

`--vcon-digest` prints nothing for a single container written with `--export-vcon --vcon-out`. Run `sha256sum` on that file instead.

**What to look for:**

- Redaction is **not** masking.
  - Every identity becomes a token that is equal exactly when the original was equal.
  - Addresses go through a prefix-preserving map.
  - So both of these are still answerable on the output:
    - "these forty failures came from one subscriber",
    - "the media went to a subnet no SDP advertised".
- Two things go entirely, rather than becoming tokens: digest credentials and inline audio.
  - No pseudonym of them carries diagnostic value.
- Redaction affects the **serialized container only**.
  - The TUI, the reports and every in-process analysis keep the real values.
  - So a redacted export and a live triage session read the same capture.
- Every run draws a fresh redaction key, unless you pass `--redact-key-file`.
  - That default is the safe one.
  - The tokens join against no other export, and nothing anywhere can reverse them.
  - Supply a file when tokens must stay stable across captures or across hosts.
  - The whole file is the secret, trailing newline included.
  - Understand what that buys whoever holds it.

**Pitfalls:**

- `--export-vcon-when` takes the same expressions as `--filter`, aliases included.
  - `--export-vcon-when problems` exports every call `--problems` would select.
- `--redact-map` is the reversal of every pseudonym the run produced.
  - So it is exactly as sensitive as the capture.
  - sipnab creates it mode 0600.
  - It **refuses to overwrite** an existing one. That file may be the map for containers already sent somewhere.
  - The refusal comes after sipnab writes the containers: the run exits 1, and the new containers have no map. Delete them, name a new map path, and run again.
- `--redact-keep-prefix` publishes that many leading digits of a real subscriber number in the clear.
  - Zero is the default for that reason.
  - Three buys you NANP area-code analysis, and costs three digits.
- `--vcon-max-inline-media` bounds inline audio.
  - The default is 5 MiB. A vCon store can answer HTTP 204 for a larger container and still drop its audio.
  - Over the budget, sipnab refuses the media **out loud**.
  - `capture_completeness.media` says so. It does not let an absent recording read as a silent call.

---

## Check a vCon against the schema before a store rejects it

**Problem:** A conserver refuses a container. It reports the refusal to whoever POSTed it, never to whoever built it.

Run sipnab as an MCP server over the capture. Ask `validate_vcon` before you hand anything to a store:

```bash
sipnab -N --mcp -I capture.pcap --quiet
```

```jsonc
// validate_vcon { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 2,
  "verdict": "valid",
  "schema_path": "tests/schemas/vcon.schema.json",
  "errors": []
}
```

Pass a container somebody else produced as an object, rather than a Call-ID.
For example, one a store already rejected:

```jsonc
// validate_vcon { "container": { "uuid": "018f3a2b-4c5d-8e6f-9012-3456789abcde", "created_at": "2026-09-01T12:00:00Z", "dialog": [ { "type": "transfer", "parties": [0, 1] } ] } }
{
  "schema_version": 2,
  "verdict": "invalid",
  "errors": [
    { "instance_path": "/dialog/0", "keyword": "not",
      "detail": "carries `parties`, which the schema forbids here" }
  ]
}
```

**What to look for:**

- **There are two verdicts, `valid` and `invalid`.**
  - The schema is the working group's [draft-ietf-vcon-vcon-core-04 schema](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B), unchanged.
  - The `transfer` object above breaks a rule core-04 added.
  - The rule: `parties` MUST NOT be present on a transfer ([section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4)).
- An empty Dialog Object `{}` is an error under core-04.
  - For an attended transfer's unseen consultation leg, sipnab writes the placeholder core-04 defines, `{"type": "recording"}` ([section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3)).
- A container that disagrees with the schema is an **answer**, not a tool error.
  - The call fails only when the request is wrong:
    - neither argument,
    - both,
    - an unknown Call-ID,
    - a `container` that is not a JSON object.

**Pitfalls:**

- Needs a build carrying the non-default `vcon` Cargo feature.
  - Without it, the tool refuses by name.
  - `server_capabilities` lists what a given binary has.

**Runnable example:** `validate_vcon` is sipnab checking its own work.
[Check a vCon against the publisher's schema](client-examples.md#check-a-vcon-against-the-publishers-schema) checks an export with `jsonschema` against the working group's file itself.
sipnab's copy matches that file byte for byte.

---

## Export a vCon per failed call in one round trip

**Problem:** An agent asked for "every failed call as a container" lists the dialogs. Then it issues one export per row.
On a real capture, that is hundreds of round trips to do what one invocation does.

`export_vcon` takes a **filter** as well as a `call_id`. It returns the whole matching set inline:

```bash
sipnab -N --mcp -I capture.pcap --retain-audio --mcp-max-rows 200 --quiet
```

Against [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap), which holds four failed calls and no RTP, with the containers and most fields trimmed:

```jsonc
// export_vcon { "filter": "state == 'Failed'", "limit": 2 }
{
  "returned": 2,
  "total_matched": 4,
  "truncated": true,
  "containers": [
    { "call_id": "busy-3a2b1c@192.0.2.30",
      "digest": "027bb627c8680804a02da0342a5b2998f019dfa8e504a2488fb0648ebef87d5a",
      "completeness": { "media": "none-decodable", "complete": true, "omissions": [] },
      "container": {} },
    { "call_id": "decline-7c6d5e@198.51.100.30", … }
  ]
}
```

**What to look for:**

- `total_matched` counts the whole store. So it is the number to page against.
  - `returned` is only what this call fitted under `limit`.
- Give `call_id` **or** `filter`, never both.
  - A request naming a dialog and a rule for choosing dialogs has two answers, and names neither.
  - The CLI refuses the same pair.
- A filter matching nothing answers with an empty set.
  - "No call failed" is a finding.
  - A refusal there would make a clean capture look like a broken request.
- Every container comes back with its SHA-256.
  - sipnab computes it exactly as `--vcon-digest` computes it: one function.
  - So a store's ledger entry compares against this value directly.
  - The digest identifies the **document**.
  - Re-exporting one call produces a second document with a new digest and the same `uuid`.
  - So deduplicate on the `uuid`.

**Pitfalls:**

- `--retain-audio` is what puts audio inside the containers. It **requires `--mcp`**.
  - The MCP server is the only batch-mode consumer that can read the buffers back.
  - Without it, `capture_completeness.media` reads `none-decodable`.
  - That reports the run, and never claims the call was silent.
- Unlike its file-writing neighbors, this tool writes nothing and needs no `--mcp-file-root`.
  - It returns the container inline. The agent decides what to do with it.
- There is no `format` parameter.
  - A vCon is a JSON container defined by the draft.
  - A Markdown arm would render a document whose whole purpose is to travel between machines.

---

## Find out where a stream's endpoint came from

**Problem:** A report gives the address a call's media went through. The address can come from three places:

- SDP the two parties exchanged,
- a relay sipnab asked,
- a mirrored datagram anybody on the segment could have sent.

Which one it came from decides what the claim is worth. Every other surface renders the three identically.

Start the server with the relay's control address. Opt in to the one tool that transmits:

```bash
sudo sipnab -N --mcp -d eth0 --rtpengine-control 127.0.0.1:22222 --mcp-allow-relay-query --quiet
```

`explain_attribution` answers for one call, endpoint by endpoint. Against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// explain_attribution { "call_id": "1-1966@10.0.2.20" }
{
  "endpoints": [
    { "address": "10.0.2.15", "port": 27942,
      "asserted_by": "signaled",
      "delivery_trust": "not-relay-asserted",
      "delivery_note": "the parties' own claim in SDP, not a relay's statement about its allocation" },
    …
  ],
  "unauthenticated_endpoints": 0
}
```

`reconcile_orphans` says **why** a stream has no dialog. It does not just count the ones that do not.
Against [`tests/fixtures/rtpengine-media-only.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/rtpengine-media-only.pcap), which holds media and no signaling:

```jsonc
// reconcile_orphans { "limit": 2 }
{ "orphans": [ { "ssrc": 168430090, "reason": "never-named" }, … ],
  "total_orphans": 4, "relay_was_consulted": false }
```

`query_relay` asks the relay itself about a call that was already up when the capture started.
`decode_ng` decodes one captured relay control message, and says which path carried it.

**What to look for:**

- `delivery_trust` values, strongest first:
  - `asked`: sipnab asked the relay over its control socket, so no third party could answer.
  - `hmac-verified`
  - `plain-secret`
  - `port-gated-only`: **the source is not authenticated**.
  - `not-relay-asserted`: the parties' own SDP claim.
  - With no posture configured, sipnab reports the weakest reading.
    - A tool whose job is telling you what a claim is worth must not round up in the absence of information.
  - The posture is the HEP listener's.
    - A relay datagram read off a capture interface (`input_origin: wire`) is `port-gated-only`, whatever the listener checks.
    - So is a HEP datagram `--hep-parse` unwraps off an interface or a file, although it reports `input_origin: hep`.
    - `decode_ng` reads frames from a capture file, so it reports `port-gated-only` for every frame.
- `reconcile_orphans` has three verdicts. The difference is the point:
  - `relay-asserted-but-no-dialog` means the **signaling** is missing, not the media.
  - `signaled-but-no-dialog` means the capture missed the dialog, or its SDP predates the capture.
  - `never-named` means nothing in the capture named the endpoint at all.
- `relay_was_consulted: false` beside a `never-named` verdict means **nobody asked**.
  - That is an absence of evidence, not evidence of absence.

**Pitfalls:**

- `query_relay` needs three things, and says which one is missing:
  - `--mcp-allow-relay-query`,
  - the relay control flag,
  - a **live** source.
  - A run reading a file can obtain no transmit permit.
- **There is no address parameter.**
  - The destination comes from `--rtpengine-control` and from nowhere else.
  - An address sipnab could otherwise infer is one it learned from packets.
  - That is a host that was a relay during the capture, and may be somebody's laptop now.
- `--rtpengine-control` transmits `list` and `query` and nothing else. This is structural.
  - `offer`, `answer`, `delete` and `start recording` each change a production relay.
  - None is representable on that path.

---

## Set up the MCP server for a hosted agent

**Problem:** The agent driving sipnab is not on your laptop, and not run by you.
So "loopback with no token" stops being the deployment.

Every knob below is a separate decision. The defaults are the conservative half of each:

```bash
sipnab -N --mcp --mcp-transport http --mcp-bind 0.0.0.0:8731 --mcp-signing-key-file /etc/sipnab/mcp.key --mcp-token-ttl 900 --mcp-rate-limit-per-peer 20 --mcp-max-rows 200 --mcp-max-body-bytes 8192 --mcp-audit-file /var/log/sipnab/mcp-audit.jsonl --mcp-tools core --mcp-file-root /var/lib/sipnab/captures --quiet
```

Mint a short-lived token from the same signing key, rather than share a static secret:

```bash
sipnab --mint-token --token-scope read --token-id agent-a --mcp-signing-key-file /etc/sipnab/mcp.key --mcp-token-ttl 900
```

**What to look for:**

- `--mcp-tools core` registers a small set that still answers a whole call.
  - sipnab sends every registered tool's name, description and JSON schema on `tools/list`.
  - The model then carries them in context for the whole session, before the agent has asked anything.
  - On a client with a small context window, that fixed cost is worth cutting.
- `--mcp-rate-limit-per-peer` and `--mcp-max-concurrent` answer different questions.
  - That one bounds calls **in flight**.
  - This one bounds their **arrival rate**.
  - Some agents never exceed the concurrency cap, and simply loop as fast as sipnab answers.
  - Such an agent holds one slot at a time, and asks again the moment it frees up.
  - The concurrency cap alone does not bound that.
- `--mcp-audit-file` is the durable copy of what an agent looked at.
  - The same record already rides the ordinary log. But that is a console view.
  - `SIPNAB_LOG` filters it, and `--quiet` suppresses it.
  - The question comes later, from somebody who did not choose the log level.

**Pitfalls:**

- **sipnab refuses a tool call it cannot write to the audit file.**
  - An audit trail that silently skipped what it could not record would be worse than none.
  - So a full disk stops the answers, rather than the recording.
- `--mcp-file-root` is the whole security model for the file tools. It is not negotiable.
  - They take a **filename**, never a path.
  - sipnab rejects anything containing a separator, a `..` or an absolute prefix, before touching the filesystem.
  - An agent-supplied path is an arbitrary file write wearing a feature's clothes.
- A peer is:
  - the source IP over HTTP. That is the address, not the socket. So reconnecting does not mint a fresh allowance.
  - the pipe itself over stdio.
- The write verbs still appear in `tools/list` when you omit their flags.
  - sipnab registers tools unconditionally, and refuses the **call** instead.
  - Seeing `shutdown_server` listed does not mean an agent can stop your capture.

---

## Read TLS from an agent, with no keys and no restart

**Problem:** Somebody wants an agent to look at SIP over TLS on a host you cannot restart.
Whether that is even possible is a property of the host. Asking it is a smaller act than doing it.

`list_tls_libraries` stays available whatever else is off.
So an agent can always report what a capture **would** see:

```bash
sudo sipnab -N --mcp -d eth0 --quiet
```

```jsonc
// list_tls_libraries { }
{
  "supported": true,
  "privileged": true,
  "libraries": [
    { "flavor": "OpenSSL", "path": "/usr/lib/libssl.so.3", "inode": 21143,
      "process_count": 12, "symbol": "SSL_write",
      "probe_path": "/proc/954/root/usr/lib/libssl.so.3" },
    { "flavor": "wolfSSL", "path": "/usr/lib/libwolfssl.so.42.2.0", "inode": 17433084,
      "process_count": 1, "symbol": "wolfSSL_write", "probe_path": null }
  ],
  "unreachable_count": 1
}
```

Actually installing the probes is a separate opt-in. It is the most consequential one on this surface:

```bash
sudo sipnab -N --mcp -d eth0 --mcp-allow-tls-capture --quiet
```

```jsonc
// start_tls_capture { "flavors": ["openssl"] }
// stop_tls_capture  { }
{ "running": false, "messages": 412, "lost": 0, "uptime_sec": 96 }
```

**What to look for:**

- **Read `privileged` before believing an empty list.**
  - Unprivileged, `/proc/<pid>/maps` is readable only for the server's own processes.
  - So a short list is evidence about privilege, rather than about the host.
  - The `summary` field says which of the two produced the answer. So a relayed conclusion does not lose it.
- **`probe_path: null` is a finding, not a blank.**
  - That library is carrying traffic sipnab cannot capture.
  - Usually it is a containerized process whose `/proc/<pid>/root` this server cannot read.
  - Reporting it is what keeps a capture from looking complete when it is not.
- `inode` is there because `path` is not unique.
  - The same string names different files in different mount namespaces.
  - On an ordinary host with containers, several distinct `libssl.so.3` files coexist.
- `lost` on the stop is the number the kernel dropped because the reader fell behind.
  - Those are messages that existed and are missing.
  - That is a different fact from a quiet trunk.
  - It is the only one you cannot discover any other way.

**Pitfalls:**

- **Keep calling `stop_tls_capture` until `running` is false.**
  - The stop is a request.
  - The worker owns the probes, and removes them on its way out: a kernel round trip per probe.
  - Probes left installed cost every process that maps the library. They outlive sipnab.
- Three refusals arrive before any kernel state exists. Each names itself:
  - not root. A server started with `--user` has already dropped privileges, and cannot attach probes later.
  - a live source already running. sipnab's stores have one writer.
  - a capture still loading. Poll `capture_status` until `load.done`.
- An attach failure arrives **later**, not from the start call.
  - A background thread installs the probes. The call returns as soon as it starts.
  - Poll to see whether messages actually arrive.
- The uprobe path costs you the addresses.
  - See [7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all) for what a dialog from this source can and cannot say.
  - See [7h. Read TLS *and* who the peer was](#read-tls-and-who-the-peer-was) for the backend that pairs the write with its socket.

---

## Ask the capture how many calls failed

**Problem:** An agent asked "how many calls failed?" fetches rows and tallies them in its head.

- Counting is the operation a language model gets wrong most reliably.
- A truncated page makes a confident wrong total.

`aggregate_dialogs` counts inside the store, and returns the buckets:

```bash
sipnab -N --mcp -I capture.pcap --mcp-max-rows 200 --quiet
```

Against [`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap):

```jsonc
// aggregate_dialogs { "group_by": "response_code", "filter": "state == 'Failed'" }
{
  "group_by": "response_code",
  "buckets": [ { "value": "404", "count": 1 }, { "value": "486", "count": 1 },
               { "value": "503", "count": 1 }, { "value": "603", "count": 1 } ],
  "other_count": 0,
  "distinct_values": 4,
  "total_matched": 4
}
```

`get_capture_report` is the whole-capture analysis: the one `--report` prints.
It is for the questions that are about the capture, rather than about one call. Against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_capture_report { "format": "json" }
{ "findings": [ { "kind": "one_way_audio", "severity": "critical", "occurrences": 2, … } ],
  "dialogs_examined": 2, "streams_examined": 2,
  "frames_read": 852, "complete": true }
```

**What to look for:**

- **The buckets plus `other_count` always equal `total_matched`.**
  - A truncated aggregate that does not say what it left out is a wrong total, rather than a partial one.
  - So nothing is silently dropped. That includes nulls.
  - Nulls become the literal `(none)`, because "how many dialogs carry no User-Agent" is a real question.
- **Read `complete` before the findings.**
  - It is `false` when the capture:
    - lost packets,
    - hit a retention cap,
    - or held frames no decoder could read.
  - A findings list from such a capture is a **floor, not a total**.
  - It also reads `false` in two more cases:
    - while a load is still running,
    - for a source whose read stopped before its end.
- Legal `group_by` values are `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip` and `rtp.codec`.
  - Anything else fails, naming the legal set.

**Pitfalls:**

- One dimension, and no time bucketing.
  - Two dimensions is a pivot table, and a pivot table wants a UI.
  - Narrow the window with `filter` instead.
- Grouping by `from.user`, `to.user` or `ua` returns **fenced** values.
  - Those are text the packet's sender wrote.
  - A state name, a status code, an address or a codec is sipnab's own derivation. It comes back verbatim.
- `markdown` and `text` renderings of the report have no envelope to carry the completeness flags.
  - So they state it in the document: an `INCOMPLETE RUN` block, the same one `--report` appends.
  - Ask for `json` when you want the booleans as fields.

---

## Ask why the MOS is what it is

**Problem:** "The MOS is 3.6." A score is a conclusion.
The argument with a carrier is about the facts underneath it.

`rtp_stats` gives the score. `media_diagnostics` gives the inputs.
Each input carries a label saying what kind of number it is:

```bash
sipnab -N --mcp -I capture.pcap --quiet
```

```jsonc
// media_diagnostics { "call_id": "1-1966@10.0.2.20" }
{
  "applicable": true,
  "streams": [
    { "ssrc": "0x343da99b", "codec": "PCMU", "packets": 425,
      "qos": { "marking_observed": true, "dscp": 0, "name": "CS0 / default (best effort)" },
      "jitter": { "grounded": true, "clock_basis": "rfc3551", "clock_rate_hz": 8000,
                  "measured_ms": 0.0054046519599899685 },
      "delay": { "source": "assumed", "assumed": true, "one_way_ms": 100.0 },
      "silence": { "cn_frames": 0, "periods": 0, "total_ms": 0 } }
  ]
}
```

**What to look for:**

- **Read `applicable` first.**
  - It is `false` when no RTP stream belongs to the dialog. The response then carries almost nothing.
  - An empty `streams` array would read as "sipnab checked the media and it was fine".
  - That is a different claim from "no media reached the capture point".
- Three things in the answer above read together:
  - The media is in the **default queue**. So it competes with bulk traffic.
    - That is the most common cause of jitter that adding bandwidth does not fix.
  - The jitter figure **is** a measurement.
    - Payload type 0 has a clock rate [RFC 3551](https://www.rfc-editor.org/rfc/rfc3551.html) fixes.
  - The delay behind the MOS is a **default**, not anything this capture showed.
    - So the score is only as good as that assumption ([31. Set the quality thresholds to your own network](#set-the-quality-thresholds-to-your-own-network)).
- `jitter.grounded: false` means the stream supplied no clock rate, and sipnab fell back to a default.
  - Jitter is an RTP-timestamp difference divided by that rate.
  - So a wrong divisor gives a **different quantity**, not a rough one.
  - An ungrounded stream reports no `measured_ms` at all.
- `qos.remarked_to` appears only when the stream's last packet carries a different code point from its first.
  - That is an SBC or a policy boundary rewriting the marking in flight.
  - Its presence is the finding.
  - A steady stream omits it, rather than repeating the same number.

**Pitfalls:**

- `endpoint_reported` is what the far end said over RTCP.
  - It sits apart from everything beside it, and feeds nothing.
  - Nobody authenticates RTCP. Anyone can forge it.
  - A report describes the path from the sender to **the reporter**.
  - On a mid-path capture, that is a different segment from the one sipnab watches.
  - The two disagreeing is normal and informative.
- `marking_observed: false` on a HEP-fed stream is not a missing marking.
  - sipnab saw no IP header, because a mirror carries the message and not the frame.

---

## Decrypt TLS with the server's private key

**Problem:** You hold the SIP server's TLS private key, and no keylog.
Nobody was running one when the calls happened.

`-k`/`--tls-key` takes the PEM private key. It uses it to recover the pre-master secret:

```bash
sudo sipnab -N -d eth0 -k /etc/sipnab/server-key.pem
```

The same key reads a capture you already recorded: `sipnab -N -I capture.pcap -k /etc/sipnab/server-key.pem --report`.
sipnab refuses to start when it cannot read the key. It does not capture everything and decrypt nothing.

**What to look for:**

- This works for **TLS 1.2 RSA key exchange only**.
  - Those are the handshakes with no forward secrecy.
  - The client encrypts the pre-master secret to the server's key. So that key recovers it afterwards.
- If the decryption produces nothing, look at the cipher suite in the handshake before suspecting the key.
  - An ECDHE or DHE suite is doing exactly the job it exists to do.

**Pitfalls:**

- **Forward secrecy is the normal case now, and it defeats this.**
  - ECDHE and DHE handshakes need one of these:
    - `--keylog` ([7. Decrypt SIP over TLS when you can restart the phone or server — key log file (SSLKEYLOGFILE)](#decrypt-sip-over-tls-when-you-can-restart-the-phone-or-server--key-log-file-sslkeylogfile)),
    - a uprobe ([7g. Read TLS with no keys at all](#read-tls-with-no-keys-at-all)).
  - A server key cannot recover them, and no flag changes that.
- TLS 1.3 removed RSA key exchange entirely.
  - On a TLS 1.3 capture, this flag has nothing to do.
- A server private key is a larger secret than a keylog.
  - A keylog decrypts the sessions it covers.
  - This decrypts every session that key ever protected.
  - sipnab disables core dumps once decryption is active, for the same reason it does with a keylog.

---

## See who is on a recorded call

**Problem:** Something is recording a call. You need to know what the recorder learned about it:

- which parties,
- which media stream belongs to which one.

A session recording client (an SBC, or OpenSIPS's `siprec` module) sends the recording server an INVITE.
The INVITE's body carries an `application/rs-metadata+xml` part.
sipnab reads that part off the wire like any other body:

```bash
sipnab -N -I recorded.pcap --call-report "4f1c0a2e-siprec@192.0.2.31"
```

```text
SIPREC recording (4f1c0a2e-siprec@192.0.2.31): session 4f1c0a2e, complete
  participant sip:alice@example.com (Alice)
  participant sip:bob@example.com
  stream label 0 -> sip:alice@example.com
  stream label 1 -> sip:alice@example.com
  stream label 2 -> sip:bob@example.com
```

The same facts reach an agent through MCP as `siprec_metadata { "call_id": "..." }`.
The REST API serves them on `GET /v1/dialogs/{call_id}` as a `siprec` block:

```jsonc
"siprec": {
  "session_id": "4f1c0a2e",
  "mode": "complete",
  "participants": [
    { "participant_id": "9b2d1f00", "aor": "sip:alice@example.com", "name": "Alice" },
    { "participant_id": "c7e40a13", "aor": "sip:bob@example.com" }
  ],
  "streams": [
    { "stream_id": "1a2b3c4d", "label": "0", "participant_id": "9b2d1f00" },
    { "stream_id": "2b3c4d5e", "label": "1", "participant_id": "9b2d1f00" },
    { "stream_id": "3c4d5e6f", "label": "2", "participant_id": "c7e40a13" }
  ]
}
```

In the TUI, the ladder annotates the recording INVITE in place. So you see it without leaving the call flow.

`--export-vcon` on the same Call-ID writes Alice and Bob as parties, and maps each stream to its sender.
[A SIPREC recording session](vcon.md#a-siprec-recording-session) describes the container.

**What to look for:**

- **`label` is the `m=` line.**
  - Alice has two streams here, labels 0 and 1: the audio and the video of one call.
  - The label ties a recorded stream back to the media description it came from.
  - On a multi-stream call, nothing else does.
- **`participant_id` is who SENDS the stream.**
  - Bob receives Alice's audio and video, and neither is his.
  - Ownership comes from `<participantstreamassoc>`.
  - Its `<send>` children mean origination. Its `<recv>` children do not.
- **A missing `name` is missing, not empty.**
  - An SRC that has no display name for a party sends the AOR alone.

**Pitfalls:**

- **`recorded: false` does not mean the call went unrecorded.**
  - It means no SIPREC metadata reached the capture point.
  - A recorder signaling on a path sipnab cannot see looks exactly the same from here.
  - The tool says so, rather than implying the stronger claim.
- **sipnab reads SIPREC and does not speak it.**
  - It is not a session recording client, and not a recording server.
  - Putting it in the recording path is not what it is for.
- Recording metadata rides in the INVITE that opens the recording dialog.
  - A capture that starts mid-call has missed it.
  - No later message repeats it, unless the SRC re-sends.

---

## Ask a relay whether it is dropping packets

**Problem:** Audio is bad, and the media relay (rtpengine) is the prime suspect.
You want the relay's OWN drop and throughput counters. You do not want a guess from the packets your capture happened to see.

A relay statistic is a claim from the relay, not something sipnab measured.

- Ask over the relay's read-only control port. sipnab prints what the relay says.
- The output carries a tag naming it the relay's own count. So you never mistake it for sipnab's:

```bash
sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats
```

Every figure names the relay as its source (wire tier `relay_reported`).
Reading it as "sipnab saw this" is the one mistake this whole view exists to stop.

**Pitfalls:**

- **A relay that restarted a second ago reads as a quiet one.**
  - rtpengine's counters are cumulative, and reset to zero on restart.
  - Where the relay publishes `uptime`, sipnab shows it beside them. rtpproxy publishes none.
  - So a small number can mean "handled little" or "just restarted". Only the uptime tells them apart.
  - A polled series (`--relay-stats-interval`) can step backwards. sipnab flags that as a probable restart, rather than a drop in traffic.
- Asking transmits to the relay.
  - So this needs a live source (`-d`), never a capture file.
  - On `-I file.pcap`, sipnab does not ask. It logs `--relay-stats will not ask a relay on a run that reads a file`, analyzes the file, and exits 0.
  - `--rtpengine-control` on a file run logs a warning and transmits nothing.
- A statistic missing from the reply was not asked for. A zero means the relay counted zero.
  - They are different answers, and never render the same.

---

## Ask a relay what it is still holding

**Problem:** You suspect leaked sessions. These are calls that ended, but whose media ports the relay never tore down.

```bash
sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats
```

Read the active-session count beside the created and destroyed totals.

- A created count far above destroyed, with a high active count, is the shape of sessions nobody released.

**Pitfalls:**

- **"Active" is this instant, not a window.**
  - A session torn down a second ago is already gone from the count.
  - Poll on a timer with `--relay-stats-interval 5` to watch it move, rather than reading one snapshot.
- The counters are the relay's own (`relay_reported`). They are cumulative, and reset on restart.
  - See the uptime caveat in [61. Ask a relay whether it is dropping packets](#ask-a-relay-whether-it-is-dropping-packets).

---

## Compare a relay's per-call count with your capture

**Problem:** You have a Call-ID. You want to know whether the relay's view of it matches what your capture saw.
This is "we sent it" / "we never got it", one hop up.

```bash
sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-compare 'abc123@host'
```

This shows two figures side by side, each showing which it is:

- the relay's own RTP packet count for the call,
- the count sipnab measured from the media it captured.

It also shows a one-word verdict (match or differ), with a plain-language note.

**Pitfalls:**

- **A difference is not automatically a fault.**
  - The two count different sockets, over different windows, with different start times.
  - Three ordinary causes:
    - A capture off a mirror port under load misses packets.
    - A capture that sees BOTH sides of the relay's hairpin counts each packet twice.
    - A relay that restarted mid-call zeroed its counters.
  - The note names these. Read it before you escalate.
- A side can be absent. Absent is not zero.
  - The relay side is absent when the relay does not hold the call.
  - sipnab's side is absent when your capture saw no RTP for it.
  - An absent side never renders as `0`.
  - sipnab flags a per-call total too large to compare as suspect. It does not read it as a call the relay does not hold.

---

## Read a relay's loss beside the loss you measured

**Problem:** The relay reports packet loss, and so does sipnab. The two numbers disagree.
You need to know which to believe.

**Neither — because they are not the same measurement.**

- This is the recipe most easily got wrong.
- Getting it wrong is how a real fault gets blamed on the wrong hop.
- There are three different "loss" numbers for one call. Each is a different claim:

| The number | Wire tier | What it actually is |
|---|---|---|
| The relay's own loss counter | the relay's own count (`relay_reported`) | what the relay's box counted, on its sockets, since its last restart |
| sipnab's sequence-gap loss | what sipnab saw on the wire (`sipnab_measured`) | gaps in the RTP sequence numbers that reached the capture point — bounded by what your capture saw |
| the far end's RTCP `fraction lost` | what the far end claims (`endpoint_reported`) | the remote endpoint's own assertion, never checkable |

```bash
sipnab -N -d eth0 --rtpengine-control 127.0.0.1:22222 --relay-stats
```

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host'
```

- The first asks the relay for its own loss counter, live.
- The second reads two things from the capture:
  - what sipnab measured on the wire,
  - the far end's RTCP claim.

None is authoritative over the others.

- The relay's count and sipnab's differ whenever the capture is off the relay's path.
- The far end's claim is about a third socket again.

Cite the tier when you quote the number: "the relay reports 40 lost, our capture measured 3 gaps".
Then the disagreement stops being a contradiction. It becomes three facts about three points on the path.

**Pitfalls:**

- Do not subtract one tier from another.
  - The relay's count minus sipnab's is not "packets sipnab missed".
  - The two count different sockets over different windows. So the difference describes nothing.
- For sipnab's own capture loss versus the network's, see [recipe "Measure whether the loss is yours or the network's"](#measure-whether-the-loss-is-yours-or-the-networks).
  - That is a different axis: whether YOUR capture dropped packets.

---

## Send a carrier the capture with your notes on the frames

**Problem:** You found the message that went wrong.

- The carrier's engineer opens the capture in Wireshark, not in sipnab.
- A remark in an email comes apart from the file it is about.

Take each frame's pointer from `--json`. Write the notes file, one JSON object per line:

```bash
sipnab -N -I capture.pcap --json | jq -c 'select(.status_code == 183) | {frame, note: "the SDP changed here, after the 180"}' > capture.notes.jsonl
```

Then write the annotated copy:

```bash
sipnab -N -I capture.pcap --notes capture.notes.jsonl --write-annotated capture-for-carrier.pcapng
```

- Wireshark shows each note as the packet comment on its frame.
- `tshark -r capture-for-carrier.pcapng -Y frame.comment` lists the annotated frames.
- The copy carries the original frames byte for byte.
- sipnab checks every note against its frame's digest.
  - It refuses, writing nothing, when the capture changed after you took the pointers.

In the TUI, `C` on a message types the note there. A PCAP-NG save writes it.
[Operator notes](keybindings.md#operator-notes) has the keys.

**Pitfalls:**

- The copy carries none of these:
  - decryption secrets,
  - name resolution blocks,
  - the input's own comments.
  - If the carrier needs to decrypt TLS, send the key log on purpose, separately.
- A note is text you typed. sipnab never reads it back.
  - `--json`, the REST API and MCP never show it.
  - Notes are output only. Keep the notes file as the record of what you wrote.
- sipnab refuses a note holding an SDES key, a TLS key-log line or a digest `response=` value.
  - Describe the message that carried the key, and leave the key out.

---

## Analyze a call from a stored vCon

**Problem:** The call is no longer in any capture you hold. What you have is a vCon:

- the one a store kept,
- one sipnab exported,
- or one another producer wrote.

`-I` reads it the way it reads a pcap:

```bash
sipnab -N -I call.vcon.json --analyze --no-cli-print --quiet
```

[`tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json`](https://github.com/NormB/sipnab/blob/main/tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json) is the container `--export-vcon 1-1966@10.0.2.20 --node-name tap-a` writes from the sample capture.
Against it:

```text
Capture analysis: 1 finding(s) across 1 dialog(s), 0 stream(s), 6 frame(s) read.

THIS ANALYSIS IS INCOMPLETE — sipnab did not read all of this capture. The findings below describe what it UNDERSTOOD, so their counts are floors and the ABSENCE of a finding is not evidence that the problem is absent. The blind finding(s) are listed first.

1. [BLIND] Rebuilt from a stored vCon — 1 container(s)
   These dialogs were rebuilt from stored vCon containers, not read from packets. A vCon holds no RTP, so no media statistic here was computed, and whatever its producer did not store is absent. The evidence names each container, what it lacks, and the producer's own caveat.
   Evidence:
     - tests/fixtures/vcon/sip-rtp-g711-1966.vcon.json, vcon 0158a120-0392-8751-9a04-9decf1485b22 | messages=6 | 6 SIP message(s) rebuilt from this container. Not recomputed or not stored: media: a vCon carries no RTP, so no stream, MOS, jitter or loss was computed from it; the producer's analysis holds 1 media_quality row(s), its own numbers, not recomputed; request-URI: not stored for 3 request(s), which carry sip:request-uri-not-stored.invalid; header order: the trace keys headers by name, so their order across names is the container's, not the wire's, and headers the producer did not store (credential headers, when sipnab produced it) are absent. The producer's caveat: Produced by sipnab 0.5.208 on node tap-a. sipnab OBSERVED this dialog and took no part in it: the parties below are what the From and To headers said, not identities anyone established, and nothing here is signed. No media is in this container because this run decoded none for the dialog; the capture_completeness media_note says what was measured. That is a statement about what this run kept, not a finding that the call was silent. sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.
```

The other report flags read it the same way: `--json-dialogs`, `--report`, `--call-report` and the TUI.

- `-I` also takes a directory of containers.
  - It skips one it cannot read, with the reason.
- The MCP tool `analyze_vcon` and `POST /v1/vcon/analyze` analyze a container handed over inline.

**Pitfalls:**

- A vCon stores no RTP. So no media statistic comes back.
  - The first finding says so, and quotes the producer's own caveat.
- A container that fails the vCon schema still reads.
  - One example is a container vcon.store handed back with `extensions` as an object.
  - sipnab logs the schema finding, and carries it in the analysis.
- sipnab refuses `--cores` and a BPF filter for a container.
  - Both work on captured frames.
  - Select dialogs with `--filter`.

[Analyze a stored vCon](vcon.md#analyze-a-stored-vcon) walks through it in full.

## Narrow a capture to when the problem happened

**Problem:** The complaint says the calls failed "between ten and eleven this morning".
The capture covers the whole day. Every report you run lists the calls from before and after the window too.

Give the window with `--since` and `--until`, in [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html):

```bash
sipnab -N -I capture.pcap --json-dialogs --no-cli-print --quiet --since 2026-10-09T10:00:00Z --until 2026-10-09T11:00:00Z
```

Each line is one call whose first message falls in the window.
The window joins `--filter`. So the failed calls in that hour are:

```bash
sipnab -N -I capture.pcap --report --filter "state == 'Failed'" --since 2026-10-09T10:00:00Z --until 2026-10-09T11:00:00Z
```

**What to look for:**

- **The window is half-open.**
  - A call that started at exactly 10:00:00 is in.
  - One at exactly 11:00:00 belongs to the next hour.
  - Back-to-back windows count every call once.
- **The same window on every surface.**
  - REST's `GET /v1/dialogs?after=...&before=...` and the MCP `search_by_time` tool return the same calls for the same capture.
- **An empty answer says why.** Sometimes no call in the capture started inside the window. Then:
  - the run exits 0 with an empty listing,
  - it prints the span the capture's calls do cover on stderr.
  - So a window typed in local time instead of UTC is visible at once.

**Pitfalls:**

- Write the instant in UTC (`Z`) or with its offset (`+02:00`).
  - sipnab refuses a time with no offset, exit 2, because it names no instant.
- The window bounds when a call **started**.
  - A call that started at 09:59 and failed at 10:05 is outside it.

---

## Look up a one-liner by task

The recipes above walk through a problem end to end. This section is the other shape.

- It holds dense one-line commands to copy.
- Use it when you already know what you want, and just need the invocation.
- Every flag used here appears in [cli-reference.md](cli-reference.md).

### Triage a capture fast

- `sudo sipnab -d eth0` — watch SIP interactively on an interface (TUI)
- `sipnab -N -I capture.pcap --problems` — show only problem calls from a pcap.
  - The flag expands to the `problems` DSL alias.
  - So it covers the whole diagnostic set: Failed state, one-way audio, loss/jitter, NAT mismatch, retransmits, PDD, asymmetry, late media.
  - `sipnab -N -I capture.pcap --filter problems` returns the same calls.
- `sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1'` — deep-dive one call: ladder, timing, SDP, RTP quality, diagnosis
- `sipnab -N -I capture.pcap --call-report 'abc123@192.0.2.1' --markdown > call.md` — the same as a Markdown report for a ticket
- `sipnab -N -I capture.pcap --report --no-cli-print` — post-capture aggregate summary only, no per-message noise

### Narrow a capture to the calls you care about

- `sudo sipnab -N -d eth0 --from '^1001@' --to '^18005551212'` — calls from/to specific users, matched as regexes
- `sipnab -N -I capture.pcap --filter "method == 'INVITE' and rtp.mos < 3.5"` — filter DSL: INVITE dialogs that ended with bad audio quality
- `sipnab -N -I capture.pcap --filter codec-asym` — diagnostic aliases go through the same flag (see docs/filter-dsl.md).
  - `sipnab -N -I capture.pcap --filter late-media` is the same flag with the late-media alias.
- `sipnab -N -I capture.pcap --slow-setup` — slow call setup, meaning long post-dial delay

### Feed NDJSON into jq and other tools

NDJSON to jq, counting failures by status code:

```bash
sipnab -N -I capture.pcap --json | jq -s 'map(select(.status_code >= 400)) | group_by(.status_code) | map({code: .[0].status_code, n: length})'
```

Every Call-ID seen on the wire, ready to feed back into `--call-report`:

```bash
sipnab -N -I capture.pcap --json | jq -r '.call_id // empty' | sort -u
```

More in [output-formats.md](./output-formats.md).

### Record traffic to disk, encrypted or not

Capture SIP+RTP to rotating pcapng files, 50 MiB chunks:

```bash
sudo sipnab -N -d eth0 -O /var/capture/sip.pcapng --pcapng --split filesize:50
```

Run that capture forever inside 400 MiB, keeping the newest eight chunks:

```bash
sudo sipnab -N -d eth0 -O /var/capture/sip.pcapng --pcapng \
     --split filesize:50 --split-keep 8
```

`--split-keep` **deletes** capture files: the older chunks, as rotation creates new ones.

- sipnab deletes nothing without the flag.
- It deletes only the files that running process created and named.
- So anything else in `/var/capture` stays.
- Leave it off whenever the capture is evidence you cannot retake.

Decrypt SIPS signaling with a TLS key log, and export decryptable pcapng.
`--keylog` is the SIP/TLS NSS keylog. It covers signaling only, and it does not decrypt media.

```bash
sudo sipnab -N -d eth0 --keylog /tmp/sslkeys.log --keylog-watch \
     -O decrypted.pcapng --pcapng
```

SRTP needs media keys instead:

- `sipnab -N -I capture.pcap --dtls-keylog /tmp/dtls.keylog` — keys recovered from DTLS-SRTP handshakes
- `sipnab -N -I capture.pcap --srtp-keys /tmp/srtp-keys.txt` — AES-CM master keys.
  - SDES `a=crypto` keys are also learned from SDP.

### Detect scanners and block abuse

- `sudo sipnab -N -d eth0 --kill-scanner --alert syslog` — detect SIP scanners and answer them, rate-limited
- `sudo sipnab -N -d eth0 --fail2ban` — emit fail2ban-compatible lines for scanner/flood sources

### Run a command when a call or its quality changes

- `sudo sipnab -N -d eth0 --on-dialog-exec '/usr/local/bin/call-logger'` — run a command on every dialog state change.
  - Details arrive as `SIPNAB_*` env vars plus a `SIPNAB_JSON` payload.
  - They are never shell-interpolated.
- `sudo sipnab -N -d eth0 --on-quality-exec '/usr/local/bin/page-noc'` — alert when RTP quality drops

### Exchange HEP with Kamailio, OpenSIPS or Homer

- `sipnab -N -L 0.0.0.0:9060 --hep-allow 192.0.2.0/24` — receive HEP from Kamailio/OpenSIPS/Asterisk and analyze live.
  - A routable bind needs the allowlist (or `--hep-auth`). Otherwise sipnab refuses to start.
  - `-L`/`--hep-listen` decodes HEP on its own.
  - `--hep-parse` is only for unwrapping HEP that arrives inside ordinary UDP capture.
- `sudo sipnab -N -d eth0 -H homer.example.net:9060` — mirror captured traffic to Homer
- `sudo sipnab -N -d eth0 -H collector:9060 --hep-send-transport tcp` — mirror over TCP instead of UDP, for a collector that wants a stream
- `sipnab -N -L 0.0.0.0:9060 --hep-listen-transport tls --hep-tls-cert cert.pem --hep-tls-key key.pem --hep-allow 192.0.2.0/24` — receive HEP inside TLS.
  - Each side names its own transport. So a relay can take TCP in and send UDP out.

---

## Next steps

- [keybindings.md](keybindings.md) — the interactive TUI these captures feed
- [filter-dsl.md](filter-dsl.md) — the full filter language behind `--filter`
- [mcp.md](mcp.md) — drive the same analysis from an AI agent
