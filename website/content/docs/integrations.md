+++
title = "Integrations"
weight = 13
description = "Forward to HEP/Homer, run event-exec hooks, and emit fail2ban and syslog alerts."
+++

Wire sipnab into your wider stack: forward captured traffic to HEP/Homer, run external commands on dialog and quality events, and emit fail2ban and syslog security alerts.

## HEP Protocol

sipnab supports HEP v2/v3 (Homer Encapsulation Protocol) for integration with Homer/SIPCAPTURE.

### Receiving HEP

```bash
sipnab -L 0.0.0.0:9060 -E
```

Restrict sources with `--hep-allow` and rate-limit with `--hep-rate-limit`:

```bash
sipnab -L 0.0.0.0:9060 -E --hep-allow 192.0.2.0/24 --hep-rate-limit 25000
```

### Sending HEP

Mirror captured traffic to a Homer collector:

```bash
sipnab -d eth0 -H 192.0.2.50:9060
```

## Event execution

sipnab can execute external commands on dialog state changes or quality drops. The command receives event data via `SIPNAB_*` environment variables (`SIPNAB_JSON` carries the full dialog JSON) — never on stdin and never interpolated into the command line. Event execution works in **all modes** (TUI, CLI, and API) -- it is not specific to the API feature.

Run a script when any dialog changes state:

```bash
sipnab -d eth0 --on-dialog-exec "/usr/local/bin/sip-event.sh"
```

Run a script when RTP quality drops below a MOS threshold:

```bash
sipnab -d eth0 --on-quality-exec "/usr/local/bin/quality-alert.sh" \
  --quality-threshold 3.0
```

Rate-limit exec invocations. The default is 10 per second:

```bash
sipnab -d eth0 --on-dialog-exec "logger" --exec-rate-limit 5
```

> **Warning:** Always use `--exec-rate-limit` in production to prevent response amplification. Under a SIP flood, an unthrottled exec handler could fork-bomb the system. The default limit of 10/sec is conservative -- adjust based on your use case.

## Fail2ban Integration

`--fail2ban` switches sipnab's per-message output to log lines fail2ban can
read. It selects a **format** and detects nothing on its own: `--kill-scanner`
(or `--kill-ua`) produces `scanner_detected` lines and `--reg-flood` produces
`reg_flood` lines. Without one of those the log stays empty, and an empty jail
log reads as "nothing attacked me".

```bash
sipnab -N -d eth0 --kill-scanner --reg-flood --fail2ban >> /var/log/sipnab-fail2ban.log
```

The two line shapes, from [`src/output/fail2ban.rs`](https://github.com/NormB/sipnab/blob/main/src/output/fail2ban.rs):

```text
2026-05-05 12:34:56 sipnab[12345]: scanner_detected src=203.0.113.42 ua="friendly-scanner" method="OPTIONS"
2026-05-05 12:34:57 sipnab[12345]: scanner_detected src=203.0.113.43 ua=- method="REGISTER"
2026-05-05 12:34:57 sipnab[12345]: reg_flood src=203.0.113.42 count=37
```

sipnab quotes `ua=` and `method=`, and a bare `-` means the request carried no such
header at all — worth keeping distinct, because a missing `User-Agent` is itself
a scanner signal while a client sending the string `-` renders as `"-"`. `src=`
is never quoted: it holds a parsed IP address, not text from the wire.

### Measure it against your own traffic first

The detectors suit a honeypot or an edge box, and a carrier trunk is neither —
[the Cookbook](/docs/cookbook/#10b-wire-to-fail2ban) sets out exactly what the
behavioural rules test. Point sipnab at a capture of an ordinary hour and count
who it would have banned:

```bash
sipnab -N -I trunk.pcap --kill-scanner --fail2ban \
  | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn
```

Every address in that list is one the jail below would ban. On a real trunk the
top entries are routinely your own carrier's SBCs. Put each of them in
`ignoreip` and raise `maxretry` until the list holds only what you meant.

### Filter and jail

```ini
# /etc/fail2ban/filter.d/sipnab.conf
[Definition]
failregex = ^.*sipnab\[\d+\]: scanner_detected src=<HOST>.*$
            ^.*sipnab\[\d+\]: reg_flood src=<HOST>.*$
ignoreregex =
```

```ini
# /etc/fail2ban/jail.d/sipnab.local
[sipnab]
enabled = true
filter = sipnab
logpath = /var/log/sipnab-fail2ban.log
# Never ban the boxes the phone system needs. List every carrier SBC, every
# trunk peer and the PBX itself BEFORE enabling this jail — they are the
# addresses that talk to you most, so a detector tuned for a honeypot flags
# them first.
ignoreip = 127.0.0.1/8 ::1 203.0.113.0/24 198.51.100.10
findtime = 600
# Several detections inside findtime, not one. A single enumeration alert is
# what a busy trunk looks like.
maxretry = 5
# An hour, not a day: long enough to shed a scan, short enough that a wrong
# ban of your own carrier heals without an engineer.
bantime = 3600
action = iptables-allports[name=sipnab, protocol=udp]
```

Check the filter against a real log before you enable the jail.
`fail2ban-regex` reports what it would have matched, and bans nothing:

```bash
fail2ban-regex /var/log/sipnab-fail2ban.log /etc/fail2ban/filter.d/sipnab.conf
```

> **Tip:** Combine `--kill-scanner` with `--kill-ua "friendly-scanner|sipvicious"` to target specific scanner signatures. The `--kill-response` flag (default: 200) picks the SIP response code that goes back to detected scanners. Reading a capture file, `--kill-scanner` detects and reports but never transmits — only a live capture arms the response.

## Syslog alerts

Send security alerts to syslog:

```bash
sipnab -d eth0 --kill-scanner --alert syslog --syslog
```

Alerts go out with facility `LOG_LOCAL0` and a severity keyed to event type (scanner=warning, fraud=alert). Use your syslog server's filtering to route sipnab events to dedicated log files or SIEM systems.
