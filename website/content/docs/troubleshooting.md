+++
title = "Troubleshooting"
weight = 1
description = "Real-world VoIP diagnostic workflows with exact commands."
+++

> **Under pressure?** Each scenario below is: Problem, Command, What to look for, Next steps. Copy-paste and go.

## Failed Calls

Find every call that never established, then triage by response code.

```bash
# All failed calls with Call-ID and response code
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json | jq '.call_id, .status'

# Detailed report for one call (Markdown, ready for a ticket)
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
| 488 | Not acceptable here | Codec mismatch, SDP incompatibility |
| 503 | Service unavailable | Upstream overload, trunk down, proxy crash |

**Next steps:** If the response code is 408 or you see high `retransmits`, the problem is network-level -- check connectivity and firewall rules before touching SIP config.

---

## One-Way Audio

One direction of RTP has zero packets. The caller can hear the callee (or vice versa) but not both.

```bash
# Find calls flagged for one-way audio
sipnab -N -I capture.pcap --filter "one_way == true" --json

# Full diagnostic output
sipnab -N -I capture.pcap --filter "one_way == true" --report
```

**What to look for:**

- `nat_mismatch == true` alongside `one_way` -- the Contact/Via IP doesn't match the packet source. This is the most common cause.
- Codec asymmetry in the SDP offer/answer (one side offers a codec the other doesn't support).
- RTP ports in the SDP that never receive traffic (firewall blocking the return path).

**Next steps:**

1. Check NAT: `sipnab -N -I capture.pcap --filter "one_way == true AND nat_mismatch == true" --json`
2. If NAT is the cause: enable `fix_nated_contact` / `fix_nated_register` on the proxy, or deploy a TURN server.
3. If NAT is clean: verify symmetric RTP, check for SIP ALG on intermediate firewalls (disable it), and confirm both endpoints negotiate a common codec.

---

## Poor Call Quality

MOS below 3.0 means quality degradation users will notice. Below 2.5, calls are unusable.

```bash
# Find completed calls with poor MOS
sipnab -N -I capture.pcap --filter "rtp.mos < 3.0" --json

# Live monitoring -- alert on quality or jitter spikes
sudo sipnab -N -d eth0 --filter "rtp.mos < 3.0 OR rtp.jitter > 50" --json
```

**What to look for:**

| Metric | Threshold | Likely cause |
|--------|-----------|--------------|
| `rtp.mos` < 3.0 | Quality degradation | Aggregated impairment -- check jitter and loss |
| `rtp.jitter` > 30ms | Congestion or buffering | Network saturation, Wi-Fi, VPN overhead |
| `rtp.loss` > 2% | Packet drops | Overloaded links, QoS misconfiguration, carrier issue |

**Next steps:** If jitter is high but loss is low, the problem is buffering or path instability (check for Wi-Fi hops, VPN tunnels, or missing QoS marking). If loss is high, run a path MTR/traceroute to find where packets are dropping.

---

## Slow Call Setup (Post-Dial Delay)

PDD over 3 seconds is perceptible to users. Over 5 seconds and they'll hang up.

```bash
# Find calls with excessive PDD
sipnab -N -I capture.pcap --filter "pdd > 3.0" --json

# Built-in alias with summary report
sipnab -N -I capture.pcap --slow-setup --report
```

**What to look for:**

- High `retransmits` alongside high PDD -- the INVITE is being retransmitted because the first one was lost or the remote side is slow to respond.
- DNS resolution delays (common when the proxy does NAPTR/SRV lookups for every call).
- Deep proxy chains adding latency at each hop.

**Next steps:** Compare `pdd` with `retransmits`. If retransmits > 0, the delay is network loss or an unresponsive next hop. If retransmits == 0 but PDD is still high, the downstream server is slow to route (check its logs, database lookups, or LCR table performance).

---

## NAT Traversal Issues

The Contact or Via header advertises a private IP that doesn't match the actual packet source.

```bash
# Find NAT mismatches
sipnab -N -I capture.pcap --filter "nat_mismatch == true" --json

# Built-in alias
sipnab -N -I capture.pcap --nat-issues
```

**What to look for:** `nat_mismatch == true` means the SIP headers contain an IP/port that differs from where the packet actually came from. This breaks return routing for SIP responses and RTP media.

**Next steps:**

1. **Proxy-side:** Enable `fix_nated_contact` and `fix_nated_register` (OpenSIPS/Kamailio) to rewrite Contact headers with the observed source address.
2. **Endpoint-side:** Configure STUN/TURN on the phone or softclient so it discovers its public address.
3. **Network-side:** Disable SIP ALG on every NAT device in the path. SIP ALGs almost always make things worse.

---

## SIP Scanner Detection

Scanners probe for open registrations and try credential stuffing. Detect them early and feed the IPs to fail2ban.

```bash
# Live detection with fail2ban-compatible output
sudo sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab/scanners.log

# Find scanner User-Agents in a pcap
sipnab -N -I capture.pcap --filter "ua =~ 'friendly-scanner|sipcli|sipvicious'"
```

**What to look for:** Known scanner fingerprints (`friendly-scanner`, `sipvicious`, `sipcli`), high REGISTER rates from a single source, sequential extension enumeration (INVITE to 100, 101, 102...).

**Next steps:**

1. Point fail2ban at the log file sipnab writes with `--fail2ban`.
2. For broader detection, combine flags: `sudo sipnab -N -d eth0 --kill-scanner --fraud-detect --reg-flood --alert syslog`
3. Use `--digest-leak` to check if any endpoints are leaking credentials in cleartext.

---

## Registration Failures

Phones not registering means no inbound calls and potentially no outbound.

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

## Generating Reports

Export call data for tickets, post-mortems, or automated pipelines.

```bash
# Markdown report for a specific call (attach to a ticket)
sipnab -I capture.pcap --call-report "abc123@host" --markdown > report.md

# JSON export of all failed calls (feed to your monitoring system)
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json > failed_calls.json

# Count failures by response code
sipnab -N -I capture.pcap --filter "state == 'Failed'" --json \
  | jq -r '.status' | sort | uniq -c | sort -rn
```

---

## Quick Browser Analysis

No install, no upload, no data leaves your machine.

Drop a pcap file at [sipnab.com/analyze/](https://sipnab.com/analyze/) -- the file is processed entirely in your browser via WebAssembly. Useful for quick triage when you can't install the CLI, or for sharing a link with a colleague who doesn't have sipnab.

---

## Still stuck?

Build custom queries with the [Filter DSL](@/docs/filter-dsl.md) -- 24 fields, regex support, boolean logic. See the [CLI Reference](@/docs/cli.md) for every flag and more recipes.
