# Run commands and send alerts on sipnab's events

sipnab can tell other programs what it sees as it sees it: it runs a command
of yours when a call changes state, when audio quality drops, or when a
security detector fires, and it sends its security alerts to syslog, to a JSON
line on standard error, and to fail2ban. This page sets up each one.

- [Before you start](#before-you-start)
- [Forward to Homer over HEP](#forward-to-homer-over-hep)
- [Run a command on an event](#run-a-command-on-an-event)
- [Send alerts to syslog, JSON or a command](#send-alerts-to-syslog-json-or-a-command)
- [Block scanners with fail2ban](#block-scanners-with-fail2ban)
- [Check that it worked](#check-that-it-worked)
- [When something does not work](#when-something-does-not-work)

Every command and output on this page ran on 2026-11-03 with sipnab 0.5.232
built from source, on Ubuntu 24.04.5 (aarch64, kernel 6.8.12), against the
capture files named in each step. The live runs captured the loopback
interface while `tcpreplay` replayed those files onto it.

## Before you start

- **A sipnab binary.** Hooks, alerts and the fail2ban format are in every
  build.
- **`sh` on the host.** sipnab runs each hook command with `sh -c`.
- **A place for a hook script that the user of the run can reach.** On a live
  capture started as root that user is `nobody`, or the `--user` you name.
- **A syslog daemon or the systemd journal,** for the syslog channel.
- **fail2ban on the same host,** for the jail.
  [Feed fail2ban from sipnab](fail2ban-sipnab.md) installs it.
- **No change on any other system:** nothing on the SIP server, the relay or
  Homer.
  - A hook command is a program of yours.
  - syslog is the host's own.
  - fail2ban reads a file sipnab writes.

## Forward to Homer over HEP

sipnab works with Homer over HEP, the Homer Encapsulation Protocol
([specification](https://github.com/sipcapture/HEP)). It receives HEP
versions 1, 2 and 3, and sends version 3.

OpenSIPS, Kamailio and Asterisk can each send copies of their SIP to sipnab
over HEP.

- [Connect sipnab to Homer](homer-sipnab.md) sets up sipnab as a second
  receiver beside Homer, with OpenSIPS or Kamailio, and as a source that
  forwards to Homer.
- [Receive Asterisk's HEP](asterisk-sipnab.md#receive-asterisks-hep) sets it
  up for Asterisk.
- [Run sipnab as a HEP relay](examples.md#run-sipnab-as-a-hep-relay) carries
  the feed over TCP or TLS.

## Run a command on an event

Two flags run a command of yours, and both work in every mode: the terminal
interface, `-N`, and a run that serves the REST API or MCP.

| Flag | Runs when | Environment variables |
|---|---|---|
| `--on-dialog-exec <CMD>` | a dialog changes state | `SIPNAB_CALL_ID`, `SIPNAB_FROM`, `SIPNAB_TO`, `SIPNAB_STATE`, `SIPNAB_METHOD`, and `SIPNAB_JSON`, the whole dialog |
| `--on-quality-exec <CMD>` | an RTP packet arrives on a stream whose estimated MOS is below `--quality-threshold` (default `3.0`) | `SIPNAB_SSRC`, `SIPNAB_MOS`, `SIPNAB_JITTER`, `SIPNAB_LOSS`, and `SIPNAB_STREAM_JSON`, the whole stream |

- sipnab runs `<CMD>` with `sh -c`. The event data arrives only in the
  environment. It never reaches the command line and never arrives on
  standard input, so a value from the wire cannot inject a shell command.
- At most `--exec-rate-limit` commands start each second (default `10`, `0`
  for no limit), and at most `--exec-queue-depth` run at once (default `100`).
  An event over either limit runs no command, and the end of the run counts
  how many.
- On a live capture started as root, sipnab drops to the `nobody` user, or
  the `--user` you name, before it runs any command. The command runs as that
  user, with `NoNewPrivs` set, so it cannot gain privileges through a setuid
  program. It is not confined beyond that: it can read and write whatever
  that user can.

**Steps.** Save this hook as `/usr/local/bin/sip-event.sh`. It appends one
line per event:

```sh
#!/bin/sh
# Append one line per dialog event: who, what state, and the JSON's size.
printf '%s %s %s %s %s json=%s bytes\n' "$SIPNAB_CALL_ID" "$SIPNAB_METHOD" "$SIPNAB_STATE" "$SIPNAB_FROM" "$SIPNAB_TO" "${#SIPNAB_JSON}" >> /var/tmp/sipnab-dialog-events.log
```

```sh
# Run all of these, in order.
sudo chmod 755 /usr/local/bin/sip-event.sh
sipnab -N --no-cli-print --quiet -I tests/pcap-samples/sip-rtp-g711.pcap --on-dialog-exec /usr/local/bin/sip-event.sh
cat /var/tmp/sipnab-dialog-events.log
```

**Verify.** The log held one line per state change of the capture's two calls:

```text
1-1966@10.0.2.20 INVITE Trying sipp test json=782 bytes
1-1966@10.0.2.20 INVITE InCall sipp test json=1175 bytes
1-1966@10.0.2.20 INVITE Completed sipp test json=1336 bytes
1-1968@10.0.2.20 INVITE Trying sipp test json=784 bytes
1-1968@10.0.2.20 INVITE InCall sipp test json=1177 bytes
```

Hooks run at the same time, so their lines can land out of order. In another
run of the same command, the first call's `InCall` line came before its
`Trying` line. Order by the dialog in `SIPNAB_JSON` if it matters.

**A quality hook runs per packet.** While a stream stays below the
threshold, every one of its RTP packets is an event, and the rate limit
decides how many run. With `--quality-threshold 4.5` on the same capture, a
stream scoring 4.36 produced 839 events: 10 ran, and the run ended with
`829 event(s) ran no command at all (rate limit 829, queue full 0, spawn failed 0)`.
Each line the hook wrote looked like:

```text
ssrc=0x343da99b mos=4.36 jitter=0.0 loss=0.0
```

Write a quality hook to act once per `SIPNAB_SSRC`, for example by keeping a
file per SSRC it has already reported.

**When it does not work.**

- `Event exec command failed (exit status: 126)` in the log: the user the
  command runs as cannot run it. On a live capture that is `nobody`, which
  needs to read and execute the script and to search every directory above
  it. Install it under `/usr/local/bin`, not in a home directory.
- `Event exec command failed (exit status: 127)`: the command was not found.
  Give its full path.
- The end of the run says some events `ran no command at all`: the rate limit
  or the queue depth turned them away. Raise `--exec-rate-limit`, or make the
  hook return faster.

## Send alerts to syslog, JSON or a command

The security detectors (`--kill-scanner`, `--kill-scanner-detect-only`,
`--kill-ua`, `--reg-flood`, `--fraud-detect`, `--digest-leak`) raise alerts.
Without one of them armed, no alert fires. Each alert always prints an
`[ALERT]` line on standard error, and goes to each channel you add:

| Channel | Flags | What it writes |
|---|---|---|
| syslog | `--alert syslog --syslog` | the `[ALERT]` text to syslog, facility `LOCAL0`; a scanner alert at priority `warning` |
| JSON | `--alert-json` | one JSON object per alert on standard error, beside the `[ALERT]` line |
| command | `--alert exec --alert-exec <CMD>` | runs `<CMD>` with `SIPNAB_RULE`, `SIPNAB_SRC` and `SIPNAB_DETAIL` in its environment |

This run reads a capture that holds a scanner, with all three:

```sh
sipnab -N --no-cli-print -I tests/fixtures/sip-scanner-and-register-flood.pcap \
  --kill-scanner --alert syslog --syslog --alert-json \
  --alert exec --alert-exec /usr/local/bin/sip-alert.sh
```

`/usr/local/bin/sip-alert.sh` held:

```sh
#!/bin/sh
printf 'rule=%s src=%s detail=%s\n' "$SIPNAB_RULE" "$SIPNAB_SRC" "$SIPNAB_DETAIL" >> /var/tmp/sipnab-alerts.log
```

**Verify.** Each channel received the one scanner alert:

- standard error, the JSON line:

  ```json
  {"alert":"scanner","detail":"method=\"OPTIONS\" ua=\"friendly-scanner\" detection=ua_pattern","src":"203.0.113.42","ts":"2023-11-14T22:13:21+00:00"}
  ```

- the hook's log:

  ```text
  rule=scanner src=203.0.113.42 detail=method="OPTIONS" ua="friendly-scanner" detection=ua_pattern
  ```

- the journal, with `journalctl -t sipnab`, at facility 16 (`LOCAL0`) and
  priority 4 (`warning`):

  ```text
  sipnab[2020185]: [ALERT] scanner src=203.0.113.42 method="OPTIONS" ua="friendly-scanner" detection=ua_pattern
  ```

`ts` is the capture's time for the packet, not the time the run read it.
Route `LOCAL0` to a file of its own in your syslog daemon's configuration if
you want sipnab's alerts apart from the rest.

**Rules: when an alert fires.** `--alert` also takes a rule,
`<name>:<threshold>/<window>[:<cooldown>]`, for `scanner`, `fraud`, `digest`
or `reg_flood` (`reg-flood` works too). A rule sits on top of its detector: the
detector decides whether a finding exists, and the rule how many findings
from one source inside the window raise an alert, and how long to stay quiet
after. [Registration-flood timers](troubleshooting.md#registration-flood-timers)
sets the detector's own thresholds. On the same capture, with
`--reg-flood --reg-flood-threshold 5 --reg-flood-window 60`, two
`reg_flood` alerts fired with no rule, and none with
`--alert reg-flood:100/60s`.

**When it does not work.**

- No alert at all: you armed no detector, or none fired. A capture file never
  answers a scanner, but `--kill-scanner` still detects and alerts.
- sipnab stops with exit `2` and
  `--alert: Unknown alert channel 'pager': expected one of syslog, json, exec, or a rule written name:threshold/window`:
  the channel name is wrong.
- sipnab stops with exit `2` and
  `--alert: Unknown alert rule 'bogus': expected one of digest, fraud, reg_flood, scanner (reg-flood is accepted for reg_flood)`:
  the rule names no detector.
- Nothing in the journal: `--alert syslog` needs `--syslog` as well.

## Block scanners with fail2ban

`--fail2ban` switches sipnab's per-message output to log lines fail2ban can
read. It selects a **format** and detects nothing on its own:

- `--kill-scanner`, `--kill-scanner-detect-only` or `--kill-ua` produce
  `scanner_detected` lines;
- `--reg-flood` produces `reg_flood` lines;
- without one of those the log stays empty, and an empty jail log reads as
  "nothing attacked me".

On the scanner capture above, with a low flood threshold so the short capture
makes a flood:

```sh
sipnab -N -I tests/fixtures/sip-scanner-and-register-flood.pcap --reg-flood --reg-flood-threshold 5 --reg-flood-window 60 --fail2ban | head -2
```

```text
2026-11-03 10:31:54 sipnab[2073248]: reg_flood src=198.51.100.77 count=6
2026-11-03 10:31:54 sipnab[2073248]: reg_flood src=198.51.100.77 count=7
```

[Feed fail2ban from sipnab](fail2ban-sipnab.md) installs the filter and the
jail, and watches a scanner and a flood become bans.

### Measure it against your own traffic first

The detectors suit a honeypot or an edge box. A carrier trunk is neither.
Point sipnab at a capture of an ordinary hour, and count who it would have
banned:

```bash
sipnab -N -I trunk.pcap --kill-scanner --fail2ban \
  | grep -oE 'src=[^ ]+' | sort | uniq -c | sort -rn
```

Every address in that list is one the jail would ban.

- On a real trunk the top entries are routinely your own carrier's SBCs.
- Put each of them in `ignoreip`.
- Raise `maxretry` until the list holds only what you meant.

To read the evidence for each address before you ban it, and get a rule to
apply yourself, use `--recommend-block fail2ban`:
[Block a scanner with a rule sipnab wrote, after reading the evidence](examples.md#block-a-scanner-with-a-rule-sipnab-wrote-after-reading-the-evidence).
The MCP tool [`generate_fail2ban_rule`](mcp-tools-security.md#generate_fail2ban_rule)
gives an agent the same.

## Check that it worked

This check needs no root and no script file. From a source checkout, run a
hook that appends one line for each dialog event of a sample capture, then
print the distinct lines:

```sh
sipnab -N --no-cli-print --quiet -I tests/pcap-samples/sip-rtp-g711.pcap --on-dialog-exec 'echo "$SIPNAB_CALL_ID $SIPNAB_STATE" >> sipnab-hook-check.log' && sort -u sipnab-hook-check.log
```

Expect five lines, one for each state the two calls of the capture reached:

```text
1-1966@10.0.2.20 Completed
1-1966@10.0.2.20 InCall
1-1966@10.0.2.20 Trying
1-1968@10.0.2.20 InCall
1-1968@10.0.2.20 Trying
```

Each event carried its Call-ID and its state in the environment of the
command, so the hook mechanism works. `sort -u` puts the lines in order,
because hooks run at the same time. Delete `sipnab-hook-check.log` after.

The test suite runs this check on each build, in a directory of its own, and
compares the five lines. On Ubuntu 24.04 (Linux 6.8, aarch64) the hook wrote
them.

## When something does not work

| Symptom | Likely cause |
|---|---|
| `Event exec command failed (exit status: 127)` in the log | The shell did not find the command. Give its full path |
| `Event exec command failed (exit status: 126)` in the log | The user of the run cannot run the command. On a live capture that user is `nobody`: install the script under `/usr/local/bin`, not in a home directory |
| The end of the run says some events `ran no command at all` | The rate limit or the queue depth turned them away. Raise `--exec-rate-limit`, or make the hook return sooner |
| `--alert: Unknown alert channel 'pager': expected one of syslog, json, exec, or a rule written name:threshold/window`, exit 2 | The channel name is wrong |
| `--alert: Unknown alert rule 'bogus': expected one of digest, fraud, reg_flood, scanner (reg-flood is accepted for reg_flood)`, exit 2 | The rule names no detector |
| No alert on any channel | You armed no detector, or none fired. `--alert` selects where alerts go, and a detector flag such as `--kill-scanner` or `--reg-flood` raises them |
| Nothing in the journal | `--alert syslog` needs `--syslog` as well |
| The fail2ban log stays empty | `--fail2ban` selects a format and detects nothing. Add a detector flag |
