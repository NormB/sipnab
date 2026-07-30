# Troubleshooting

> **Under pressure?** Each scenario below is: Problem, Command, What to look for, Next steps. Copy-paste and go.

## Start here: one pass over everything

Don't know which problem you have yet? The `--problems` alias surfaces every
troubled call in a single sweep -- failed calls **plus** one-way audio, high
loss/jitter, NAT mismatches, retransmit storms, slow setup, and media
asymmetries:

```bash
# Every problematic call
sipnab -N -I capture.pcap --problems --json
```

`--problems` is shorthand for the full Filter-DSL expression `state == 'Failed' OR one_way == true OR rtp.loss > 2.0 OR rtp.jitter > 50.0 OR nat_mismatch == true OR retransmits > 3 OR pdd > 32.0 OR ...` -- so it is a superset of "failed calls". Once you know the symptom, jump to the matching section below for the precise filter.

---

## Failed calls

Calls rejected with `403 Forbidden`, `404 Not Found`, `486 Busy Here`, `488 Not Acceptable Here`, or timing out with `408 Request Timeout`? Find every call that never established, then triage by response code.

List every failed call, one line per response message, carrying the Call-ID, the response code, and the reason text:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -c 'select(.is_request == false) | {call_id, status_code, reason}'
```

You should see one line per response message of each failed call (minimal example):

```json
{"call_id":"abc123@host","status_code":100,"reason":"Trying"}
{"call_id":"abc123@host","status_code":486,"reason":"Busy Here"}
{"call_id":"def456@host","status_code":408,"reason":"Request Timeout"}
```

Once one of those Call-IDs is worth escalating, write the detailed Markdown report for that single call and attach it to a ticket. Substitute the Call-ID you picked; the redirect overwrites `report.md` in the current directory:

```bash
sipnab -I capture.pcap --call-report "abc123@host" --markdown > report.md
```

**What to look for:** sipnab includes response code intelligence -- the status field tells you why:

| Code | Meaning | Typical fix |
|------|---------|-------------|
| 401/407 | Authentication required | Check credentials, realm mismatch, nonce expiry |
| 403 | Forbidden | ACL/IP allowlist, registration required, call barring |
| 404 | Not found | Bad dial plan, missing route, number not provisioned |
| 408 | Request timeout | Endpoint unreachable, DNS failure, firewall |
| 486 | Busy here | Endpoint occupied, no call waiting |
| 488 | Not acceptable here | Codec mismatch, SDP incompatibility -- full recipe [below](#488-not-acceptable-here-codec-mismatch) |
| 503 | Service unavailable | Upstream overload, trunk down, proxy crash |

**Next steps:** If the response code is 408 or you see high `retransmits`, the problem is network-level -- check connectivity and firewall rules before touching SIP config.

---

## Dropped Calls (call answers, then disconnects mid-conversation)

The call sets up fine, both sides talk, then it dies partway through -- often after a suspiciously round number of minutes.

Enumerate the calls that established and then ended early -- completed, but far shorter than a real conversation:

```bash
sipnab -N -I capture.pcap --filter "duration < 120.0 AND state == 'Completed'" --json \
  | jq -r '.call_id' | sort -u
```

Then print the timeline for one of those calls -- who sent the BYE, and exactly when. Substitute a Call-ID from the list above for `abc123@host`:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print
```

The call report shows the full SIP message timeline plus per-stream RTP stats (including first/last packet timestamps). Match the signature:

- **BYE at a round interval after answer** (exactly 15 min, 30 min, 1 h -- e.g. 200 OK at `14:00:02`, BYE at `14:30:02`): RFC 4028 **session-timer expiry**. One side never sent (or never received) the session refresh re-INVITE/UPDATE and tore the call down when `Session-Expires` ran out.
- **RTP last packet well before the BYE** (stream `last_seen` minutes earlier than the BYE): a NAT/firewall **idle timeout silently dropped the media path**; the endpoint's RTP-timeout watchdog eventually hung up.
- **BYE from the carrier side, accompanied by SIP retransmits**: trunk-side reset or an upstream element recycling the session.

**Next steps:**

1. Session timer: align `Min-SE` / `Session-Expires` between PBX and trunk, and confirm the negotiated refresher actually sends the refresh before expiry.
2. NAT/firewall: enable RTP keepalives (or comfort noise) on the endpoints, and raise the firewall's UDP session timeout above the keepalive interval.
3. Disable SIP ALG on intermediate NAT devices -- it corrupts dialogs in ways that surface as mid-call drops.

---

<!-- "488 Not Acceptable Here" is the SIP reason phrase verbatim (RFC 3261).
Sentence-casing it would name a response that does not exist. -->
<!-- vale sipnab.Headings = NO -->

## 488 Not Acceptable Here (codec mismatch)

An INVITE comes back `488 Not Acceptable Here`: the callee (or an SBC in the path) found no common codec between the SDP offer and what it supports.

Find every 488 rejection in the capture:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -c 'select(.status_code == 488) | {call_id, status_code, reason}'
```

You should see:

```json
{"call_id":"abc123@host","status_code":488,"reason":"Not Acceptable Here"}
```

Then compare the SDP offer against the answer for one of those calls, substituting its Call-ID for `abc123@host`:

```bash
sipnab -N -I capture.pcap --call-report 'abc123@host' --no-cli-print
```

The call report's **SDP timeline** lists each offer/answer with its codec set. A 488 means there is no overlap: e.g. the offer carries only `G729` while the callee's profile allows only `PCMU, PCMA`. (If the reject comes from an SBC, the offer may never have reached the far end at all.)

**Next steps:** Enable transcoding on the SBC/media server, or add the missing codec to the endpoint/trunk profile so the offer and answer share at least one codec.

---

<!-- vale sipnab.Headings = YES -->

## One-way audio

One direction of RTP has zero packets. The caller can hear the callee (or vice versa) but not both.

The `--one-way` alias finds every call flagged for one-way audio and dumps the matching SIP messages as NDJSON:

```bash
sipnab -N -I capture.pcap --one-way --json
```

You should see one NDJSON record per SIP message of each flagged call (abridged -- real records carry the full field set):

```json
{"is_request":true,"method":"INVITE","call_id":"7f3a9c@192.0.2.5","from":"...","to":"...", "...":"..."}
```

For the same set of calls rendered as the full diagnostic report rather than raw records:

```bash
sipnab -N -I capture.pcap --one-way --report
```

`--one-way` is shorthand for a Filter-DSL condition. Write that condition out when you want to combine it with others:

```bash
sipnab -N -I capture.pcap --filter "one_way == true" --json
```

Get the diagnosis detail (`one_way_audio`, `nat_mismatch`, hints) per call with `--call-report <call-id>`.

**What to look for:**

- `nat_mismatch == true` alongside `one_way` -- the Contact/Via IP doesn't match the packet source. This is the most common cause.
- Codec asymmetry in the SDP offer/answer (one side offers a codec the other doesn't support).
- RTP ports in the SDP that never receive traffic (firewall blocking the return path).

**Next steps:**

1. Check NAT: `sipnab -N -I capture.pcap --filter "one_way == true AND nat_mismatch == true" --json`
2. If NAT is the cause: enable `fix_nated_contact` / `fix_nated_register` on the proxy, or deploy a TURN server.
3. If NAT is clean: verify symmetric RTP, check for SIP ALG on intermediate firewalls (disable it), and confirm both endpoints negotiate a common codec.

---

## Poor call quality

MOS below 3.0 means quality degradation users will notice. Below 2.5, calls are unusable.

Find the calls in a capture whose MOS fell below the noticeable-degradation line:

```bash
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0" --json
```

You should see the SIP messages of every matching call as NDJSON (abridged):

```json
{"is_request":true,"method":"INVITE","call_id":"bad-audio@pbx1", "...":"..."}
```

The per-message records identify *which* calls are bad; pull the per-stream numbers (`jitter_ms`, `loss_pct`, quality intervals) with `--call-report <call-id>`.

To watch a live interface instead, widen the same filter to jitter spikes and let it run -- each matching call prints as it happens. Live capture needs raw-socket access, hence `sudo`:

```bash
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0 OR rtp.jitter > 50" --json
```

**What to look for:**

| Metric | Threshold | Likely cause |
|--------|-----------|--------------|
| `rtp.mos` < 3.0 | Quality degradation | Aggregated impairment -- check jitter and loss |
| `rtp.jitter` > 30ms | Congestion or buffering | Network saturation, Wi-Fi, VPN overhead |
| `rtp.loss` > 2% | Packet drops | Overloaded links, QoS misconfiguration, carrier issue |

**Next steps:** If jitter is high but loss is low, the problem is buffering or path instability (check for Wi-Fi hops, VPN tunnels, or missing QoS marking). If loss is high, run a path MTR/traceroute to find where packets are dropping.

### Deep-dive with stream detail

In the TUI, navigate to a call's flow view and press `Enter` on an RTP bar (or press `r` to jump to the streams list, then `Enter` on a stream) to open the **Stream Detail** view. This shows:

- **MOS and jitter sparklines** -- visual trend graphs across the stream's lifetime, making it easy to spot the exact moment quality degraded.
- **Quality intervals** -- per-interval breakdown of MOS, jitter, and loss so you can correlate degradation with specific time windows.
- **Burst/gap analysis** (RFC 3611) -- distinguishes between bursty loss (congestion events) and gap loss (steady-state impairment). Bursty loss points to queue overflow; gap loss points to a consistently lossy link.
- **Silence detection** -- identifies periods where no RTP was flowing, which can indicate hold events, codec DTX, or network black holes.

This same data is available in the browser analyzer at [sipnab.com/analyze/](https://sipnab.com/analyze/) under the **Streams** tab.

---

## Slow call setup (post-dial delay)

PDD over 3 seconds is perceptible to users. Over 5 seconds and they'll hang up.

Find the calls whose post-dial delay crossed the 3-second perceptibility line:

```bash
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json
```

The `--slow-setup` alias carries that same threshold; pair it with `--report` for a summary instead of per-message records:

```bash
sipnab -N -I capture.pcap --slow-setup --report
```

**What to look for:**

- High `retransmits` alongside high PDD -- the caller keeps retransmitting the INVITE because the first one never landed, or the remote side is slow to respond.
- DNS resolution delays (common when the proxy does NAPTR/SRV lookups for every call).
- Deep proxy chains adding latency at each hop.

**Next steps:** Compare `pdd` with `retransmits`. If retransmits > 0, the delay is network loss or an unresponsive next hop. If retransmits == 0 but PDD is still high, the downstream server is slow to route (check its logs, database lookups, or LCR table performance).

---

## NAT traversal issues

The Contact or Via header advertises a private IP that doesn't match the actual packet source.

Find the calls where the address in the SIP headers disagrees with the address the packet came from:

```bash
sipnab -N -I capture.pcap --filter "nat_mismatch == true" --json
```

The `--nat-issues` alias is the same selection without writing the filter out:

```bash
sipnab -N -I capture.pcap --nat-issues
```

**What to look for:** `nat_mismatch == true` means the SIP headers contain an IP/port that differs from where the packet actually came from. This breaks return routing for SIP responses and RTP media.

**Next steps:**

1. **Proxy-side:** Enable `fix_nated_contact` and `fix_nated_register` (OpenSIPS/Kamailio) to rewrite Contact headers with the observed source address.
2. **Endpoint-side:** Configure STUN/TURN on the phone or softclient so it discovers its public address.
3. **Network-side:** Disable SIP ALG on every NAT device in the path. SIP ALGs almost always make things worse.

---

## SIP scanner detection

Scanners probe for open registrations and try credential stuffing. Detect them early and feed the IPs to fail2ban.

Detect scanners on a live interface and append fail2ban-compatible lines to a log file fail2ban can watch. `--kill-scanner` additionally sends the kill response back to the scanner, so run it only where you mean to:

```bash
sudo sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab/scanners.log
```

After the fact, match the known scanner User-Agents in a capture -- this only reads the file, and sends nothing:

```bash
sipnab -N -I capture.pcap --filter "ua =~ 'friendly-scanner|sipcli|sipvicious'"
```

**What to look for:** Known scanner fingerprints (`friendly-scanner`, `sipvicious`, `sipcli`), high REGISTER rates from a single source, sequential extension enumeration (INVITE to 100, 101, 102...).

**Next steps:**

1. Point fail2ban at the log file sipnab writes with `--fail2ban`.
2. For broader detection, combine flags: `sudo sipnab -N -d eth0 --kill-scanner --fraud-detect --reg-flood --alert syslog`
3. Use `--digest-leak` to check if any endpoints are leaking credentials in cleartext.

---

## Registration failures

REGISTER rejected with `401 Unauthorized`, `403 Forbidden`, or `423 Interval Too Brief`? Phones not registering means no inbound calls and potentially no outbound.

```bash
sipnab -N -I capture.pcap --filter "method == 'REGISTER' AND state == 'Failed'" --json
```

**What to look for:**

| Code | Meaning | Typical fix |
|------|---------|-------------|
| 401/407 | Auth challenge | Normal first response -- check if the phone retries with credentials. If it doesn't, credentials are misconfigured. |
| 403 | Forbidden | IP not in ACL, registration not allowed for this user, or domain mismatch |
| 423 | Interval too brief | The registrar wants a longer expiry. Increase the registration interval on the phone. |

**Next steps:** A REGISTER that gets 401 followed by a second REGISTER with credentials followed by 200 is healthy. If you see repeated 401s with no successful registration, the password or auth username is wrong. If you see `retransmits > 3` on REGISTERs, the registrar may be unreachable.

---

## Generating reports

Export call data for tickets, post-mortems, or automated pipelines.

A Markdown report for one call, to attach to a ticket. The redirect overwrites `report.md` in the current directory:

```bash
sipnab -I capture.pcap --call-report "abc123@host" --markdown > report.md
```

A JSON export of every failed call, to feed a monitoring system. This one overwrites `failed_calls.json`:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json > failed_calls.json
```

A failure count per response code, written to the terminal rather than a file:

```bash
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r '.status_code' | sort | uniq -c | sort -rn
```

---

## Quick browser analysis

No install, no upload, no data leaves your machine.

Drop a pcap file at [sipnab.com/analyze/](https://sipnab.com/analyze/) -- your browser does all the work via WebAssembly. The analyzer provides two tabs: **Dialogs** (SIP call list with flow diagrams) and **Streams** (full RTP quality data including MOS, jitter, loss, and per-stream detail). Useful for quick triage when you can't install the CLI, or for sharing a link with a colleague who doesn't have sipnab.

---

## Export call audio

When metrics aren't enough — export the actual audio to hear what the caller heard.

In the TUI: select a dialog, press **F2**, Tab to **WAV** format, type a filename, press Enter.

sipnab decodes G.711 audio (mu-law/A-law) from captured RTP streams and writes a standard WAV file. If the dialog has two RTP streams (one per direction), the export produces a **stereo WAV** with caller on the left channel and callee on the right.

- **Supported codecs:** PCMU (PT 0), PCMA (PT 8)
- **Buffer:** Last ~30 seconds of audio per stream (configurable: `[limits] max_audio_frames`)
- **Output:** 16-bit PCM WAV at the stream's sample rate (typically 8000 Hz)

Open the WAV in any audio player or Audacity.

---

## Still stuck?

Build custom queries with the [Filter DSL](filter-dsl.md) -- 31 fields, regex support, boolean logic. See the [CLI Reference](cli-reference.md) for every flag and more recipes.
