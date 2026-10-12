+++
title = "How sipnab reports what a capture missed"
date = 2026-09-01
updated = 2026-10-11
description = "The counters that say which packets a capture lost or could not use, the markers a partial run adds to its output, and the record that ties an output back to the command that produced it."

[extra]
kind = "feature"
+++

## In short

A count of calls only means something if you know whether sipnab saw all of the
traffic. The network or the operating system can drop packets before sipnab
reads them, sipnab can fail to decode some of them, and sipnab sets aside SIP
on unexpected ports. sipnab counts each of these separately, adds a marker to its output when a run read only part of its
input, and can write a record of the exact command that produced a result.

## Who this is for

Anyone who reads sipnab's call counts, reports or JSON output and needs to know
whether they describe all of the traffic, including scripts and AI agents that
consume that output.

## What it does

### Five separate loss counters

Each counter has a different cause and a different remedy, so sipnab keeps them
apart instead of adding them together. Over MCP (the Model Context Protocol,
the interface an AI agent uses to call sipnab's tools) the first four are in
the `capture_quality` block of `capture_status`.

| Counter | What it counts | What to do |
|---|---|---|
| `kernel_dropped_packets` | Packets the operating system discarded because the capture buffer was full. | Raise `-B`/`--buffer`, narrow the BPF filter, or lower `--snaplen`. |
| `interface_dropped_packets` | Packets the network card or its driver discarded before the capture library saw them. | Look at the network card, its driver or the mirror port. A bigger buffer does not recover these. |
| `invalid_timestamps` | Packets whose recorded time was unusable, so sipnab stamped them with the current clock. | Nothing is missing, but every timing figure from the run (setup delay, jitter, call quality score, duration) rests on a substituted clock. |
| `undecodable_frames` | Frames that arrived intact but that no sipnab decoder could read. | Separates "this capture holds no SIP" from "sipnab could not read this capture", which both show zero dialogs. |
| `unanalysed_sip_messages` | SIP whose source and destination ports are both outside `--portrange`. | Widen `--portrange` to the ports named in `unanalysed_busiest_ports`. |

`capture_quality.degraded` is `true` when any of the first three counters is
above zero. `degraded` leaves out `undecodable_frames` because ARP (the
protocol that maps addresses on a local network) is undecodable to sipnab and
appears on almost every capture, so the flag would always be true.

`--portrange` defaults to `5060-5061`. sipnab recognizes SIP on other ports as
SIP and then leaves it out of every dialog and count. Four keys report it:
`unanalysed_sip_messages` and `unanalysed_busiest_ports` (the five busiest
ports carrying that SIP) for plain SIP, and `unanalysed_websocket_messages` and
`unanalysed_websocket_ports` for SIP carried over WebSocket.

The WebSocket pair is separate because widening `--portrange` recovers none of
it: SIP over WebSocket needs `--ws-portrange`, whose default set is 80, 443,
8080 and 8443. On the command line, `--analyze` lists the port-range loss first,
as a `BLIND` finding. `BLIND` is the severity sipnab gives to anything that
limits what the analysis could see. Step 2 of
[Check five things before you act on a sipnab finding](@/notes/a-finding-is-a-floor-not-a-verdict.md)
shows that finding and the MCP fields on a capture whose SIP is on port 5080.

### Markers on a partial run

When sipnab could not read all of its input, the run exits with status 1 and
also says so in its output, because a program reading the output through a pipe
does not see the exit status:

- `--report` ends with an `INCOMPLETE RUN` block that names each reason.
- `--json-dialogs` writes one extra line after the dialogs, under a top-level
  `sipnab_run` key that no dialog object has. Its `input_complete` field comes
  from the same test as the exit status. A complete run writes no extra line.
- Over MCP, answers drawn from the capture carry `source_exhausted` (sipnab has
  read the source to its end) and `source_stopped_early` (the read ended before the
  source did). Tools that answer from something other than the loaded
  capture, such as `explain_response_code`, `query_relay`, `relay_stats` and the
  TFPS tools, do not carry them. `capture_health` reads the loss counters twice, at the call and
  again after a sampling window you choose, so it can show whether the capture is
  losing packets now rather than at some time since the run started.

### A record of the command

`--run-provenance-file FILE` appends one JSON line to `FILE` at startup, before
sipnab loads its configuration or opens a capture device. The record holds the
command-line arguments, the working directory, the user, the start time, the
version and build features, and the capture instance token that MCP and REST
answers also carry. sipnab opens the file for append and never truncates it, and
creates it with mode `0600` (readable only by its owner) when it does not
exist. If sipnab cannot write the record, it does not run.

## How to turn it on

The loss counters, the `BLIND` finding and the partial-run markers are always
on. The command record is off until you pass `--run-provenance-file`.

## Example: read a capture file that ends early

These commands run from the root of a sipnab checkout. The first copies the
first 30,000 bytes of a repository capture, which ends the copy part-way through
a packet.

```bash
head -c 30000 tests/pcap-samples/sip-rtp-g711.pcap > cut.pcap
```

```bash
sipnab -N -q -I cut.pcap --json-dialogs --no-cli-print 2>/dev/null
```

```json
{"call_id":"1-1966@10.0.2.20","diagnosis":{"hints":["RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."],"nat_mismatch":false,"no_media":false,"one_way_audio":true,"private_media_address":false},"duration_sec":0.004,"final_status_code":200,"final_status_reason":"OK","frame":"cut.pcap#0@db88659b94678546","from":"sipp","from_display":"PCMU/8000","input_origin":"wire","method":"INVITE","msg_count":4,"schema_version":1,"sdp_timeline":[{"codecs":["PCMU"],"direction":"offer","media_addr":"10.0.2.20","media_port":6000,"mode":"recvonly","timestamp":"2016-11-26T14:52:59.666393+00:00"},{"codecs":["PCMU","telephone-event"],"direction":"answer","event":"MediaAnchorChange","media_addr":"10.0.2.15","media_port":27942,"mode":"sendonly","timestamp":"2016-11-26T14:52:59.670743+00:00"}],"state":"InCall","streams":[{"associated_dialog":"1-1966@10.0.2.20","codec":"PCMU","dialog_assertion":"signaled","dscp":0,"dst":"10.0.2.20:6000","first_seen":"2016-11-26T14:52:59.689083+00:00","frame":"cut.pcap#5@ae02f78d2d48b4f0","input_origin":"wire","jitter_ms":0.0065016585598163595,"last_seen":"2016-11-26T14:53:02.049070+00:00","loss_pct":0.0,"mos":4.3580999873438255,"mos_grounded":true,"mos_grounding":"published","octets":19040,"orphaned":false,"packets":119,"payload_type":0,"quality_intervals":[],"r_factor":90.79984396019456,"schema_version":1,"src":"10.0.2.15:27942","ssrc":"0x343da99b"}],"timing":{"retransmits":0,"setup_ms":4,"trying_delay_ms":0},"to":"test","to_display":"test"}
{"sipnab_run":{"archives":{"cut_short":false},"files":{"given":1,"not_reached":0,"read_in_full":0,"skipped":0,"stopped_early":1},"input_complete":false,"plugins":{"failed":0,"loaded":0,"requested":0},"reasons":["1 of 1 capture file(s) was not read to the end; every report from this run rests on a partial read"],"retention":{"messages_dropped":0}}}
```

The first line is the one dialog sipnab read before the file ended. The second
is the `sipnab_run` line. The exit status of the run is 1.

The same file with `--report`:

```bash
sipnab -N -q -I cut.pcap --report --no-cli-print
```

```text
2026-10-12T00:44:15.224169Z ERROR sipnab::capture::file: Error reading pcap file 'cut.pcap': truncated dump file; tried to read 214 captured bytes, only got 178
2026-10-12T00:44:15.224209Z ERROR sipnab::capture::file: Stopped reading 'cut.pcap' early: Error reading pcap file: truncated dump file; tried to read 214 captured bytes, only got 178. Continuing with the rest of the set.
2026-10-12T00:44:15.224220Z  WARN sipnab::capture::file: Read 124 packets: 0 of 1 file(s) read in full, 1 stopped early
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags            
-------------------------------------------------------------------------------------------------------------------------
1-1966@10.0.2.20                 sipp           test           InCall       200    0s         4      -        -               

RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps   
--------------------------------------------------------------------------------------------------------------------------
0x343da99b   0    PCMU     8000   10.0.2.15:27942       10.0.2.20:6000        119     0      0.0%    0ms      2s     65     

INCOMPLETE RUN — this report does not describe the whole capture:
  - 1 of 1 capture file(s) was not read to the end; every report from this run rests on a partial read
```

The first three lines go to standard error.

## Example: record which command produced a result

```bash
sipnab -N -q --node-name lab -I tests/pcap-samples/sip-register.pcap --analyze --no-cli-print --run-provenance-file runs.jsonl
```

```bash
jq -c '{seq, record, argv, version, instance: .capture.instance}' runs.jsonl
```

```json
{"seq":1,"record":"run","argv":["sipnab","-N","-q","--node-name","lab","-I","tests/pcap-samples/sip-register.pcap","--analyze","--no-cli-print","--run-provenance-file","runs.jsonl"],"version":"0.5.211 (15e5e7bd) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,archive","instance":"8ae0418dda191727a687d-1"}
```

The record also carries `ts`, `started`, `cwd`, `uid`, `user`, `pid` and
`features`. The `jq` filter above leaves them out. A path sipnab cannot write
to stops the run with exit status 2:

```bash
sipnab -N -q -I tests/pcap-samples/sip-register.pcap --analyze --no-cli-print --run-provenance-file missing-dir/runs.jsonl
```

```text
2026-10-12T00:44:28.947736Z ERROR sipnab: --run-provenance-file missing-dir/runs.jsonl: No such file or directory (os error 2). sipnab refuses to run without the provenance record it was asked for -- a missing record would otherwise be indistinguishable from a run nobody asked to record
```

## Limits

- `degraded: false` means no counter recorded a loss. It does not prove the
  capture saw every packet: loss before the capture point, such as an
  overloaded mirror port, a tap that copies one direction only, or a filter
  that excluded the traffic, is invisible to all three counters.
- SIP set aside by `--portrange` does not change the exit status and does not
  add a `sipnab_run` line or an `INCOMPLETE RUN` block. sipnab reports it in
  the `BLIND` finding of `--analyze`, in messages on standard error, and in the
  `unanalysed_*` keys over MCP.
- With `-q`, sipnab does not print the summary line that names port-range
  losses at the end of a run. It still prints the warnings on standard error.

## Terms used here

- **Capture**: a file of recorded network packets, or a live recording from a
  network interface.
- **SIP**: Session Initiation Protocol, the messages that set up, change and end
  calls.
- **Dialog**: one call or registration, from its first SIP message to its last.
- **Port**: the number that identifies which service on a machine a packet is
  for.
- **Frame**: one packet as stored in a capture.
- **Capture buffer**: the memory the operating system fills with packets until
  sipnab reads them.
- **BPF filter**: a rule that tells the operating system which packets to hand
  to sipnab.
- **Snaplen**: the number of bytes kept from each packet.
- **Mirror port** (also SPAN port) and **tap**: switch features or devices that
  copy traffic to the machine running the capture.
- **Jitter**: variation in the arrival time of audio packets.
- **WebSocket**: a protocol that browsers use, which can carry SIP.
- **MCP**: Model Context Protocol, the interface an AI agent uses to call
  sipnab's tools.
- **REST**: sipnab's HTTP interface.
- **TFPS**: a toll-fraud prevention service that sipnab can query.
- **Exit status**: the number a program returns when it ends. 0 means success.
- **jq**: a command-line program that selects fields from JSON.

## Related guides

- [The two counters mean different things](@/docs/tuning-capture.md#the-two-counters-mean-different-things)
- [Interface and driver drops](@/docs/tuning-capture.md#7-interface-and-driver-drops)
- [When the answer is partial](@/docs/cli.md#when-the-answer-is-partial)
- [`--run-provenance-file` in the Security flags](@/docs/cli.md#security)
- [SIP the port gate never analyzed](@/docs/api.md#sip-the-port-gate-never-analyzed)
- [Rules every tool follows](@/docs/mcp-tools.md#rules-every-tool-follows)
- [`capture_status`](@/docs/mcp-tools.md#capture-status) and
  [`capture_health`](@/docs/mcp-tools.md#capture-health)
