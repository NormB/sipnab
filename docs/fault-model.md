# sipnab — fault model

How sipnab behaves when its input is hostile or its environment fails, and
how to tell from a run whether something went wrong. This page covers:

- the fault classes a SIP/RTP capture tool faces,
- what sipnab guarantees for each,
- what you see when one happens, and what to do.

A capture tool reads bytes from an untrusted network. The governing rule is:
**no sequence of bytes an attacker can put on the wire (or in a capture file)
may crash sipnab, hang it, or grow its memory without bound.** A crash in a
parser would be a remote denial of service against the capture process.

[Testing: Failure-path coverage](internals/testing.md#failure-path-coverage)
lists the tests that pin each guarantee.

## Fault classes

| # | Class | Surface | Guarantee |
|---|-------|---------|-----------|
| 1 | **Hostile packet bytes** | every parser reachable from raw frames | A malformed frame produces a parse error, never a crash. Each frame gets a bounded amount of work and memory. |
| 2 | **Hostile capture file** | pcap/pcapng reader | A malformed or truncated file produces a clean error, never a crash. |
| 3 | **Resource exhaustion** | dialog table, RTP stream table, reassembly, audio buffers | Every table keyed by attacker-chosen values has a ceiling and evicts. Memory stays bounded under a flood of unique keys. |
| 4 | **Capture-source faults** | live capture loop | An interface going down, a permission failure or a receive error ends the capture with a clean error, never a hang. |
| 5 | **Output-sink faults** | JSON, Prometheus, fail2ban, `--on-dialog-exec` and `--on-quality-exec` hooks, REST API | sipnab reports a write failure. Packet data reaches hook commands only as environment variables, and sipnab strips line breaks from alert log values. |
| 6 | **Concurrency and shutdown** | channels, signals, locks | Ctrl-C stops the run cleanly. sipnab checks every send to a thread that has already exited, so it causes no crash. |

## Malformed packets and capture files (classes 1 and 2)

A malformed SIP message, SDP body or RTP header does not stop the run. sipnab
marks the message as a parse error and continues with the next packet.

The project fuzzes every parser reachable from packet or file bytes, with 20 targets: sip, sdp, rtp, rtcp, hep, websocket,
filter-dsl, stir-shaken, tls-records, srtp-keys, keylog-line,
pcap-reader, dtls, tcp-reassembly, siprec, rtpengine-ng, stun, llmnr,
archive-password, g729-decode.

Each parser has fixed upper bounds on what it reads:

| Input | Bound |
|---|---|
| SIP header fields per message | 200 |
| One folded SIP header | 8 KB |
| WebSocket payload | 64 KB |
| TLS record length | 18432 octets |
| Nested IP or GRE encapsulation | 5 layers |

### Check that a run read the whole capture

sipnab reads a capture file that ends in the middle of a packet up to the
break. It then reports the partial read in three places, so a script and a
person both see it.

Read it with nothing else asked for:

```sh
sipnab -N -I truncated.pcap --no-cli-print
```

The log, on standard error:

```text
2026-10-18T15:23:04.490014Z  INFO sipnab::capture::file: Reading from 'truncated.pcap'
2026-10-18T15:23:04.520968Z ERROR sipnab::capture::file: Error reading pcap file 'truncated.pcap': truncated dump file; tried to read 296 captured bytes, only got 182
2026-10-18T15:23:04.545776Z ERROR sipnab::capture::file: Stopped reading 'truncated.pcap' early: Error reading pcap file: truncated dump file; tried to read 296 captured bytes, only got 182. Continuing with the rest of the set.
2026-10-18T15:23:04.602032Z  WARN sipnab::capture::file: Read 4 packets: 0 of 1 file(s) read in full, 1 stopped early
2026-10-18T15:23:04.622948Z  INFO sipnab::app::batch: sipnab: 4 packets captured, 4 SIP messages, 0 RTP packets across 0 streams
```

The exit status is `1` instead of `0`.

`--report` ends with the same finding:

```sh
sipnab -N -I truncated.pcap --report --no-cli-print
```

Its output on standard output:

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
test-call-1@192.0.2.1            1001           1002           InCall       200    2s         4      0.5s     -

INCOMPLETE RUN — this report does not describe the whole capture:
  - 1 of 1 capture file(s) was not read to the end; every report from this run rests on a partial read
```

`--json-dialogs` ends with a `sipnab_run` record, which a script can test with
`input_complete`:

```sh
sipnab -N -q -I truncated.pcap --json-dialogs --no-cli-print
```

Its output on standard output:

```text
{"call_id":"test-call-1@192.0.2.1","diagnosis":{"hints":[],"nat_mismatch":false,"no_media":false,"one_way_audio":false,"private_media_address":false},"duration_sec":2.0,"final_status_code":200,"final_status_reason":"OK","frame":"truncated.pcap#0@4ed7f4560fa79e74","from":"1001","input_origin":"wire","method":"INVITE","msg_count":4,"schema_version":1,"sdp_timeline":[],"state":"InCall","streams":[],"timing":{"pdd_ms":500,"retransmits":0,"ring_ms":1500,"setup_ms":2000,"trying_delay_ms":100},"to":"1002"}
{"sipnab_run":{"archives":{"cut_short":false},"files":{"given":1,"not_reached":0,"read_in_full":0,"skipped":0,"stopped_early":1},"input_complete":false,"plugins":{"failed":0,"loaded":0,"requested":0},"port_gate":{"sip_outside_portrange":0,"sip_outside_ws_ports":0},"reasons":["1 of 1 capture file(s) was not read to the end; every report from this run rests on a partial read"],"retention":{"messages_dropped":0}}}
```

These outputs came from the first 1,500 bytes of
[`tests/fixtures/sip_call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/sip_call.pcap). To fix the input, copy the capture again from
its source.

A `--plugin` that fails to load produces the same exit status `1` and sets
`plugins.failed` in the same record.

### A parser that panics

A panic in a parser is a sipnab defect. When one happens while sipnab reads
a captured frame, a record of a capture file, an archive member, a vCon
container or a packet a HEP listener received, sipnab stops reading that one
input and goes on with the run. It
logs a warning, `contained a panic at <location>: <message>`, and you see:

| Input | What you see |
|---|---|
| A captured frame | The frame counts as `decode_error` in `sipnab_capture_undecodable_frames_total`, and the run goes on with the next frame. |
| A record of a capture file | `Error reading pcap file '<file>': the record reader panicked: <message>`. sipnab keeps the packets read before it. |
| An archive member | `'<archive>/<member>' could not be read past this point: the decoder panicked: <message>`. |
| A vCon container given to `-I` | sipnab skips the container and reports `cannot read the vCon container: the parser panicked: <message>`. |
| A packet a HEP listener received | The listener refuses the packet as `malformed` in `sipnab_hep_datagrams_refused_total`, as it refuses one that does not parse, and goes on with the next packet. |

To report it, [open an issue](https://github.com/NormB/sipnab/issues/new/choose) with the warning and, if you can share it, the input.

## Memory bounds (class 3)

An attacker can invent unlimited unique Call-IDs or SSRCs. Each table keyed by
them has a ceiling:

| Table | Setting | Default | At the ceiling |
|-------|---------|---------|----------------|
| Dialogs | `--limit` | 100000 | Evicts the oldest dialog. With `--no-rotate`, drops new dialogs instead. |
| RTP streams | `--max-streams` | 50000 | Evicts the oldest stream. |
| Messages per dialog | none | 500 | Drops messages past the cap. |
| Audio frames per stream | none | 1500 | Keeps the most recent frames. |
| IP fragment and TCP reassembly | none | 10,000 entries, 30 s | Evicts entries past the cap or older than 30 seconds. |

Both dialog policies keep memory bounded.

- The default evicts the oldest dialog, so new calls keep arriving.
- `--no-rotate` never evicts a tracked dialog. Under a flood, sipnab drops new
  calls instead.

## Capture, output and shutdown (classes 4 to 6)

- **Live capture.** A device that fails to open, or a capture filter that fails
  to compile, stops sipnab at startup with an error. A receive error during
  the capture ends the capture: sipnab logs it at error level and exits
  non-zero, because every report from the run rests on a partial read.
- **Hook commands.** `--on-dialog-exec` and `--on-quality-exec` pass packet
  data as `$SIPNAB_*` environment variables, never interpolated into a shell
  command line. At most 100 hook commands wait to run at once.
- **Logs and JSON.** JSON output escapes every value. Alert log values have
  carriage returns and line feeds removed, so packet data cannot forge a log
  line.
- **HTTP servers.** The REST API and the Prometheus endpoint set read and
  write timeouts and cap concurrent connections. A request over the cap gets
  `503`.
- **Shutdown.** Ctrl-C stops the run cleanly.

## Known gaps

- A transient receive error on a live capture ends the capture. sipnab does
  not retry.
- An interface going down during a live capture ends the capture the same way.
- Opus decoding, for WAV export, uses `opus-decoder`, a pure-Rust crate.
  Opus encoding, used only for vCon recordings in builds with the `opus`
  feature, uses libopus through the `opus` crate. The build compiles libopus
  from source rather than taking it from the system. sipnab checks the length
  of what it passes to either, and does not fuzz the codec itself.
- A full disk while writing a pcap or WAV file produces an error. No test
  covers that path.

## Memory-safety boundary

sipnab is a Rust program. Rust marks code that the compiler cannot check for
memory safety as `unsafe`. The tree holds 113 blocks outside `#[cfg(test)]`, across 30 files, the
largest groups in [`src/privilege.rs`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs) (17), [`src/rtp/playback.rs`](https://github.com/NormB/sipnab/blob/main/src/rtp/playback.rs) (10) and
[`src/capture/uprobe/perf.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/uprobe/perf.rs) (9).

- Every block is a call into the operating system or another foreign library.
- Every block carries a `// SAFETY:` comment stating why it is sound, and the
  build fails on a block without one.
