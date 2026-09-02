+++
title = "A total that cannot say what it missed is a floor"
date = 2026-09-01
description = "Kernel drops, interface drops, unusable timestamps, frames no decoder read, and SIP the port gate set aside — five separate channels, kept separate because their remedies disagree. Plus the run record that ties an artifact back to the command that made it."

[extra]
kind = "feature"
+++

`dialogs.total` reads as "how much was there". A capture missing a third of its
calls renders identically to one that only ever had two-thirds, and nothing in
the number itself tells the two apart.

So every sipnab surface that reports a count also reports what stood between
that count and the wire. This is not a warning banner bolted on the side — the
incompleteness findings rank *above* every call fault in the ranked problem
list, at `Severity::Blind`, so a capture that failed to decode or hit a
retention cap can never render as clean.

## Five channels, kept apart on purpose

Three of them describe the host, and summing them would name one problem where
there are three.

- **`kernel_dropped_packets`** — the capture ring was full when the packet
  arrived. Raise `-B`/`--buffer`, narrow the BPF filter, or cut `--snaplen`.
- **`interface_dropped_packets`** — the NIC or its driver discarded the packet
  before libpcap saw it. Look at the NIC, the driver or the mirror: **a bigger
  buffer recovers none of these.**
- **`invalid_timestamps`** — the pcap timestamp was unusable, so the packet
  carries the wall clock instead. Nothing went missing, and post-dial delay,
  jitter, MOS and duration for that run are unreliable.

`degraded` reads `true` when any of the three is non-zero. **`false` means no
counter noticed anything, not that the capture provably saw every packet.** Loss upstream of the capture point — an oversubscribed SPAN port, a
tap mirroring one direction, a filter that excluded the traffic — is invisible
to all three.

The fourth channel is about sipnab rather than the host. `undecodable_frames`
counts frames that arrived intact and that no decoder here could read, so the
analysis saw none of their contents. It is what separates *this capture holds
no SIP* from *sipnab could not read this capture*, both of which otherwise
report zero dialogs. It stays deliberately outside `degraded`: ARP is an
undecodable frame by definition and turns up on nearly every Ethernet capture,
so a flag including it would be true always and useful never.

## The fifth channel is the largest, and no drop counter can see it

`--portrange` defaults to `5060-5061`, and SIP on other ports is ordinary —
carriers and SBCs use 5070, 5080 and 8090 routinely. No packet goes missing and
no decoder gives up. sipnab reads the bytes, recognizes them as SIP, and sets
them aside because both ports fell outside the range.

Measured over a corpus of real captures the default skips 46,421 of the 148,944
SIP messages sipnab can otherwise analyze, and `tshark` independently puts
49,576 of 152,865 SIP frames outside the range. On one file it cost 1,401 of
3,712 dialogs — **37.7% gone**, and the run printed its reduced totals as if
they were complete.

Three fixes were available and only one is honest about what it costs.
Widening the default to `5060-5090` recovers 26,033 of the lost messages and
still loses 23,543, trading a silent 32% loss for a silent 15% one, which is
worse because it looks fixed. Sniffing SIP by content on any port recovers all
of it and makes `--portrange` a no-op for signaling, which is a different
promise from the one the flag documents. Both decide on the operator's behalf
what their capture contains.

Counting the loss instead turns it into a prompt, under four keys:

| Key | Meaning |
|-----|---------|
| `unanalysed_sip_messages` | plain SIP with both ports outside `--portrange` |
| `unanalysed_busiest_ports` | the five busiest ports carrying it |
| `unanalysed_websocket_messages` | SIP-over-WebSocket outside the WebSocket port set |
| `unanalysed_websocket_ports` | the five busiest ports carrying that |

The ports travel with the counts because the answer has to name its own remedy
— they are what you write into `--portrange`. A bare number says something is
wrong without saying where to look. The two pairs stay apart because widening
`--portrange` recovers none of the WebSocket half: that needs `--ws-portrange`,
and the shipped 80/443/8080/8443 set is the browser's view of the web rather
than a deployment's. Kamailio, OpenSIPS and Janus each default outside it.

## How a run says it was partial

Exit code `1` says something went wrong and cannot say what, and a consumer
reading NDJSON on a pipe never sees it. So the output says it too.

- **`--report`** ends with an `INCOMPLETE RUN` block naming each reason, one
  sentence per reason. The MCP server appends the same block to the rendered
  documents its report tools answer with, from one formatter, so a reader who
  has learned to scan for that heading finds it wherever sipnab has to say it.
- **`--json-dialogs`** emits one extra NDJSON line after the dialogs, under a
  top-level `sipnab_run` key that no dialog object has. `input_complete` there
  is the same predicate as the exit status, so a script reading stdout and a
  script reading `$?` cannot reach different verdicts. A clean run emits
  nothing extra.
- **MCP** carries `source_exhausted` and `source_stopped_early` on every answer,
  and `capture_health` reads the counters twice across a window you name, which
  turns a pile of monotonic counters into a rate — the difference between "this
  process has dropped 4 million packets since Tuesday" and "this process is
  dropping packets **now**".

## And which command produced the artifact

A report says what sipnab concluded. Nothing in it says which invocation
produced it — which capture, which filter, which port range.
`--run-provenance-file` writes that record: the argv, the working directory,
the effective user, the wall-clock start, the version and feature set, and the
capture instance that stamps every MCP and REST answer.

It writes once at startup, before the config loads and before any capture
device opens. The file opens for append and never truncates, so successive runs
accumulate, and it takes mode 0600 when absent, because argv holds capture
paths and a path holds a customer name.

**A record sipnab cannot write stops the run.** A best-effort line would be
worse than none: its absence would mean either "not enabled" or "the disk was
full", and nobody could tell which. Stopping there costs nothing — no packet
has reached the pipeline yet.

```bash
sipnab -N -I capture.pcap --report --run-provenance-file /var/log/sipnab/runs.jsonl
```

## Telling it works

Read `capture_quality` before you read the counts, not after. With `degraded`
true, every number above it is a floor rather than a total. Then read
`unanalysed_sip_messages`, which no drop counter covers and which has been the
largest loss this project has measured. A total that cannot say what it missed
is not a total.
