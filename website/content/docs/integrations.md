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

## Event Execution

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

Rate-limit exec invocations; the default is 10 per second:

```bash
sipnab -d eth0 --on-dialog-exec "logger" --exec-rate-limit 5
```

> **Warning:** Always use `--exec-rate-limit` in production to prevent response amplification. Under a SIP flood, an unthrottled exec handler could fork-bomb the system. The default limit of 10/sec is conservative -- adjust based on your use case.

## Fail2ban Integration

Generate fail2ban-compatible output for SIP security events:

```bash
sipnab -N -d eth0 --kill-scanner --fail2ban >> /var/log/sipnab-fail2ban.log
```

Example fail2ban filter configuration:

```ini
# /etc/fail2ban/filter.d/sipnab.conf
[Definition]
failregex = ^.*SCANNER.*from=<HOST>.*$
            ^.*REG_FLOOD.*from=<HOST>.*$
ignoreregex =
```

```ini
# /etc/fail2ban/jail.d/sipnab.conf
[sipnab]
enabled = true
filter = sipnab
logpath = /var/log/sipnab-fail2ban.log
maxretry = 3
findtime = 300
bantime = 3600
action = iptables-allports[name=sipnab, protocol=udp]
```

> **Tip:** Combine `--kill-scanner` with `--kill-ua "friendly-scanner|sipvicious"` to target specific scanner signatures. The `--kill-response` flag (default: 200) controls what SIP response code is sent back to detected scanners.

## Syslog Alerts

Send security alerts to syslog:

```bash
sipnab -d eth0 --kill-scanner --alert syslog --syslog
```

Alerts are sent with facility `LOG_LOCAL0` and severity based on event type (scanner=warning, fraud=alert). Use your syslog server's filtering to route sipnab events to dedicated log files or SIEM systems.
