# Operator guide engineering notes

The operator guides in `docs/` say what to run and what to expect.
This page keeps the engineering record those guides used to carry:
why a rule exists, the release that changed it, and the measurements behind a limit.
Each section names the guide it came from.

## CLI flags

Removed from [the CLI reference](../cli-reference.md).

### Where the Since column of the CLI reference comes from

[`scripts/flag-since.py`](../../scripts/flag-since.py) writes the **Since**
column of `docs/cli-reference.md` from the release tags.

- It reads [`src/cli.rs`](../../src/cli.rs) and the clap groups directly in
  `src/cli/` at each release tag, `v0.3.0` onward. A flag
  counts under its current name or any alias, and a flag moved from one of
  those files to another keeps the release it first appeared in. A file there
  that derives `clap::Parser` is a command line of its own (`sipnab g729`),
  and its flags are not counted.
- The pre-release tags `v0.1.0-alpha` and `v0.2.0-beta` do not count as
  releases.
- A flag that a release removed and a later release restored keeps the release
  it first appeared in.
- The changelog lists four versions that were never tagged or released: 0.3.1,
  0.4.1, 0.5.76 and 0.5.111. A flag first added in one of them shows the next
  release.

### The generated live-capture filter and HEP

Up to 0.5.192 the BPF filter sipnab generates from `--portrange` admitted
signaling only, so a default live capture measured no media. Later releases
admit UDP whose first payload byte marks RTP version 2 as well.

Up to 0.5.192, `-d <iface>` beside `--hep-listen` also got the signaling filter:
the interface captured no media and every mirrored message arrived a second
time, once over HEP and once off the wire. The interface now gets a media-only
default when the command line names no BPF expression.
[`src/app/bootstrap.rs`](../../src/app/bootstrap.rs) builds the filter.

### Multi-file input order: the measurement behind it

[`src/capture/input_set.rs`](../../src/capture/input_set.rs) orders a set of
capture files by each file's first packet timestamp, never by name.

- `tcpdump -C 100 -W 10` writes `tg.pcap0` to `tg.pcap9` and then overwrites
  the oldest file in place. The set measured for this feature ran
  `tg.pcap7`, `tg.pcap8`, `tg.pcap9`, then `tg.pcap0` to `tg.pcap6` in time order, so
  neither lexicographic nor natural-numeric name order reconstructs it.
- Out-of-order replay corrupts every timing derivation that assumes time moves
  forward: post-dial delay, setup time, retransmission detection, and the
  [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) Timer B, C and H bounds.
- On that 10-file, 921 MB set, 2271 of 20512 calls (11%) spanned a file
  boundary. [`tests/multi_input_test.rs`](../../tests/multi_input_test.rs)
  records the same figure.

### WebSocket and DTLS size bounds

- [`src/capture/websocket.rs`](../../src/capture/websocket.rs):
  `MAX_WS_MESSAGE_SIZE` (65536) bounds one reassembled WebSocket message, and
  `MAX_WS_HANDSHAKE_SIZE` (8192) bounds the HTTP upgrade and its `101` answer.
  OpenSIPS writes a WebSocket frame's header and payload as two TLS records,
  and its `101` answer as three, which is why sipnab joins both across records.
- [`src/capture/dtls.rs`](../../src/capture/dtls.rs): `MAX_RECORD_LEN`,
  2^14 + 2048 bytes, the ciphertext limit TLS sets and DTLS inherits. A record
  declaring more is not treated as DTLS.

### vCon export flags: design reasons

The reference rows for these flags state behavior only. The reasons:

- `--export-vcon-when` reuses the `--filter` language rather than adding a flag
  per policy (failures, calls with media, a duration threshold). A flag per
  policy covers only the cases someone anticipated.
- `--export-vcon-dir` sanitizes the Call-ID into a file name because a Call-ID
  is text whoever placed the call chose, and the directory export is the first
  path sipnab builds from one.
- `--vcon-max-inline-media` defaults to 5 MiB because a probed store answered
  HTTP 204 for a container of roughly 12 MB and then dropped its payload. The
  measurement is in [docs/design/vcon.md](../design/vcon.md).
- `--content-deny-header` has no default header, because a built-in guess would
  miss a deployment's header or match one it did not mean. The header's presence
  suppresses and its value plays no part, because the only safe reading of a
  deny marker sipnab does not understand is to deny. There is no permit
  counterpart: acting on a header to retain content would let anyone who can set
  a header decide retention. Every vCon party already carries
  `validation: "none"` for the same reason.
- `--content-deny-tombstone` is off by default because a tombstone reveals
  that the call existed.
- `--redact-keep-prefix` defaults to 0 because every retained digit is a digit
  of a real subscriber number, and sipnab has no basis for choosing how many: a
  country code is one to three digits, an NANP area code three, a national
  destination code any length.
- `--redact` deletes digest credentials and inline audio rather than tokenizing
  them, because no pseudonym of either has diagnostic value. Masking would lose
  the equality relations the keyed tokens keep.
- `--redact-map` refuses to overwrite a file because that file may be the map
  for containers already sent elsewhere.
- `--vcon-digest` is a digest and not a signature, and it sits outside the
  container: a conserver adds fields on ingest, so a signature over the bytes
  sipnab wrote would fail to verify against what the store holds. The digest
  binds an emission to a store's ledger entry out of band. It covers the
  containers `--export-vcon-when` writes; `--export-vcon`, with or without
  `--vcon-out`, prints no digest.
- `--vcon-forward-content-type` defaults to `application/json` because a
  conserver answered `422` to `application/vcon` and `204` to
  `application/json` and `application/vcon+json`. The forwarder is
  [`src/app/vcon_forward.rs`](../../src/app/vcon_forward.rs).

### rtpengine control on a file run

`--rtpengine-control` on `-I <file>` sends nothing and does not refuse the run:
sipnab logs a warning and analyzes the file, still decoding any relay control
traffic in the capture. `--relay-stats`, `--relay-stats-call`,
`--relay-stats-list`, `--relay-compare` and `--relay-stats-interval` each log an
ERROR line naming why they do not ask, and the run still exits `0`. The
control client in [`src/rtpengine/`](../../src/rtpengine/) has no command value
for `offer`, `answer`, `delete` or `start recording`, so sipnab can send only
`list` and `query`.

### HEP sender: the 3-second connect timeout

`HEP_SEND_CONNECT_TIMEOUT` in [`src/capture/hep.rs`](../../src/capture/hep.rs)
is 3 seconds. A TCP sender's first retransmission timeout is one second and
doubles on each expiry ([RFC 6298](https://www.rfc-editor.org/rfc/rfc6298.html), sections 2.1 and 5.5), so 3 seconds lets the
SYN and one retransmission go unanswered. Without it, a collector whose host or
firewall drops the SYN held forwarding, and the shutdown waiting on it, for the
operating system's limit, about 127 seconds on Linux. sipnab makes the first
connection at startup. When it fails, `--hep-send-transport tcp` stops the run
with exit `2` (verified on 0.5.222 with a refused connection to 127.0.0.1).

### The HEP HMAC window trade-off

`--hep-hmac-window` is how long a packet captured on the path stays acceptable
to a replay, and how far back the receiver's nonce cache must remember. On an
agent and collector with poor clock synchronization the receiver refuses every
packet as out of window, so the collector admits nothing.

### MCP tool-list size with and without output schemas

`--mcp-output-schemas` is off by default because the schemas are most of the
`tools/list` answer.

| Release | Without schemas | With schemas | How measured |
|---|---|---|---|
| 0.5.196 | 78,920 bytes | 181,691 bytes | every tool |
| 0.5.222 (16f7b0ea) | 89,789 bytes | 270,932 bytes | the `tools/list` response line over stdio, `--mcp -N -I tests/fixtures/sip_call.pcap`, every tool |

### Flag history recorded out of the reference

- `--retain-audio` used to require `--mcp`, when the MCP server was its only
  reader. The amplitude measurement in the media diagnosis now reads it too.
  Under `--cores` the parallel workers used to discard payload whatever the
  flag said. They now honor it.
- `--lint-suppress-file`: before 0.5.130 the MCP lint tools honored a
  `.sipnablint` beside a capture while the binary ignored it. The binary now
  discovers the same file the MCP tools read
  ([`src/sip/lint/mod.rs`](../../src/sip/lint/mod.rs)).
- `--reassembly-ttl` defaults to 30 seconds because that value suits IP fragments
  in flight, and the TCP reassembler
  ([`src/capture/reassembly.rs`](../../src/capture/reassembly.rs)) inherited
  it.
- `--uprobe-flavor` shipped as `--uprobe-flavour` through 0.5.104. The old
  spelling stays accepted as an alias, because a released flag is a contract.
- A live run of the `bpf` uprobe backend showed a REGISTER and its `200 OK`
  as `127.0.0.1:36160 -> 127.0.0.1:15061` and the reverse, each
  connection with its own ephemeral port.
- Exec hooks: sipnab sets `PR_SET_NO_NEW_PRIVS` on every Linux run. Root runs
  always did; unprivileged runs (`--setup-caps`) gained it later. sipnab does not
  clear the environment before spawning a hook, because a hook that calls back
  into the API needs the credential and a hook already runs as the invoking user.

### HEP transport numbers: the upstream sources

The table in the CLI reference's "How `--hep-listen` reads the transport" comes
from these sources:

- OpenSIPS
  [`modules/tracer/tracer.c`](https://github.com/OpenSIPS/opensips/blob/5fa4e627187f23544e702db0a47dbe877a407117/modules/tracer/tracer.c#L3584-L3591)
  and its own receiver
  [`modules/proto_hep/proto_hep.c`](https://github.com/OpenSIPS/opensips/blob/5fa4e627187f23544e702db0a47dbe877a407117/modules/proto_hep/proto_hep.c#L1132-L1138),
- Kamailio
  [`src/modules/siptrace/siptrace_hep.c`](https://github.com/kamailio/kamailio/blob/24cbec17f6030f7a9a3c632f0a0842a37b46bdf5/src/modules/siptrace/siptrace_hep.c#L480-L495),
  [`siptrace.c`](https://github.com/kamailio/kamailio/blob/24cbec17f6030f7a9a3c632f0a0842a37b46bdf5/src/modules/siptrace/siptrace.c#L1393) and
  [`siptrace_send.c`](https://github.com/kamailio/kamailio/blob/24cbec17f6030f7a9a3c632f0a0842a37b46bdf5/src/modules/siptrace/siptrace_send.c#L387-L403).

## Configuration keys

Removed from [the configuration reference](../config-reference.md).

### Configuration limits: where the numbers come from

Relocated from `docs/config-reference.md`. The operator page states each limit
and its error. This section records the source constants and the reasoning.

#### HEP to a loopback port with no listener

A proxy that mirrors HEP to a loopback port sipnab sniffs (`[capture]
device = "lo"`, `hep_parse = true`) loses copies when no process binds the
port. The kernel answers each datagram to a closed port with an ICMP
port-unreachable message, and a sender using a connected UDP socket fails its
next send with `ECONNREFUSED`.

- Measured on 2026-10-07 with sipnab's own sender before it changed: a
  7-message call sent with `sipnab -H 127.0.0.1:19063` to a port with no
  listener had 3 of 7 sends fail, and a reader on `lo` saw 4 messages.
- sipnab's `-H` now sends UDP from an unconnected socket, to which the kernel
  does not report the ICMP error. On 2026-10-08 the same run reported 7 sent
  and none failed.
- Rechecked on 2026-10-16 (0.5.222): `-H` to a closed loopback port reports
  `7 packet(s) sent, none failed`; a Python connected UDP socket sending 7
  datagrams to a closed loopback port had 4 succeed and 3 fail with
  `[Errno 111] Connection refused`.

#### HEP HMAC token version 2

[`src/capture/hep.rs`](../../src/capture/hep.rs) sets `HMAC_TOKEN_VERSION`
to 2 (since 0.5.131) and refuses `HMAC_TOKEN_VERSION_UNBOUND` (1) with
`HmacAuthError::UnsupportedVersion`, logged once by
`warn_hmac_version_one_sender`.

- Version 1's MAC covered only the payload. The addressing chunks
  (`0x0003`, `0x0004`, `0x0008`) were outside it, so anyone holding a captured
  v1 packet could append forged address chunks without the key. The
  last-wins chunk walk then recorded the forged addresses, which are the
  fields `--hep-allow-kill` aims a kill response at.
- Version 2 signs the whole datagram (`hmac_over_datagram`), so no in-place upgrade
  turns a v1 token into a v2 one.
- There is deliberately no flag to accept v1: accepting it would report HMAC
  authentication as active over addresses nothing signed.
- A 0.5.130 collector also refuses v2 tokens: its check was
  `token[0] != HMAC_TOKEN_VERSION` with the constant at 1. A mixed pair loses
  every packet in either direction.
- The symptom in both directions is a collector receiving nothing, which
  operators attribute to routing, a firewall or a dead agent before a token
  version. For that reason sipnab logs the refusal rather than only counting it.

`hep_hmac_window_secs` (range 1-300) bounds two things at once: how long a
packet captured by an on-path attacker stays acceptable, and how far back the
receiver's nonce cache must remember. A sender more than 300 s adrift has no
working time daemon, which is what to repair.

#### Registration-flood bounds

The `[security]` keys and the `--reg-flood-window` /
`--reg-flood-transaction-timeout` flags read the same constants in
[`src/security/reg_flood.rs`](../../src/security/reg_flood.rs):
`MAX_WINDOW_SECS` (3,600), `MIN_TRANSACTION_TIMEOUT_MS` (1,000) and
`MAX_TRANSACTION_TIMEOUT_MS` (600,000). Past an hour the window count is a
daily tally rather than a rate. Below one second every challenge arrives after
its transaction ends and the detector counts nothing.

#### Scanner thresholds

- `scanner_behavioral_probes` (10): behind an SBC every source collapses to
  one address, so ordinary aggregated traffic clears ten probes in five
  seconds.
- `scanner_rejected_probes` / `scanner_unanswered_probes` are the evidence
  gate in `is_probing` ([`src/security/scanner_detect.rs`](../../src/security/scanner_detect.rs)):
  they separate an enumeration sweep from a trunk sending keepalives at the
  same rate.
- `scanner_established_factor` multiplies only those two counts, via
  `evidence_factor`. A registered endpoint that starts probing is worth
  reporting, but it is also the peer whose ordinary traffic looks most like
  probing and the one a false positive costs most.
- `kill_rate_limit` has no unlimited setting because it bounds the one
  feature that transmits to an address taken from the capture, and a forged
  source address chooses where each response goes.

#### Limits whose defaults carry a reason

- `max_tcp_buffer` (65536) is the only limit that destroys data rather than
  truncating a report. Neither TCP nor RFC 3261 sets a ceiling; a carrier
  message with ISUP encapsulation, a long `Record-Route` set or a large SDP
  offer passes 64 KiB legitimately.
- The 30-second `reassembly_ttl_secs` default suits IP fragments in flight, and the TCP
  reassembler inherited it. A persistent SIP/TCP or SIP/TLS trunk goes quiet for
  longer on an ordinary night.
- `metrics_max_conn` (16) stops a burst of slow clients exhausting threads.
  An HA pair, a federating parent, a `remote_write` shard, an Alertmanager
  sidecar and an engineer's `curl` reach it together. A refused scrape leaves a
  gap that reads as a capture that died.
- `mcp_max_response_bytes` (1 MiB) is under twice the largest response
  measured on the sample captures in `tests/pcap-samples` (561,420 bytes,
  `list_dialogs` with `limit: 1000`), so the default changes no answer on
  those.
- `mcp_max_findings` is the one write budget on the MCP surface;
  `mcp_max_rows` and `mcp_max_body_bytes` bound reads.
- `[sip] active_idle_window_secs` (3600) is twice [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028.html)'s default
  `Session-Expires`. That grounds it for trunks with session timers, not for a
  contact center where a caller on hold past an hour is a channel in use.
- `[diagnosis] cn_suppression_ratio` (0.3) is the one diagnosis threshold that
  withholds a finding rather than raising one, so a wrong value fails silently:
  above it sipnab never reports one-way audio, the most-reported VoIP fault.
- `[capture] ws_ports` default (80, 443, 8080, 8443) is the browser's view of
  the web, not a deployment's.

#### Audio retention budget

[`src/rtp/stream_store.rs`](../../src/rtp/stream_store.rs) defines
`DEFAULT_MAX_AUDIO_BYTES` (1073741824) and `MIN_MAX_AUDIO_BYTES` (1048576).
The per-frame charge (payload + payload/4 + 32 bytes, plus 32 bytes per
buffer slot) is an upper bound. Measured on aarch64 Linux with mimalloc, the
allocator the binary ships with, a 20 ms G.711 frame used 192.6 bytes, so at
the budget the heap the audio really holds is about 0.73 GiB. With `--cores N`
each worker takes 1/N of the budget through `AudioLimits::per_worker` in the same file, applied in
[`src/parallel.rs`](../../src/parallel.rs).

#### vCon enrichment timeout

[`src/app/vcon_enrich.rs`](../../src/app/vcon_enrich.rs) defines
`DEFAULT_TIMEOUT_SECS` (120) and `MAX_TIMEOUT_SECS` (3600) for
`[[vcon.enrich]] timeout_secs`.

## Troubleshooting

Removed from [the troubleshooting guide](../troubleshooting.md).

<!-- Relocated from docs/troubleshooting.md by the docs/rewrite-cli pass.
     Suggested home: a new docs/internals/troubleshooting-notes.md, or the
     sections split across the pages named in each heading's note. -->

### ICMP errors: why sipnab reports the classes separately

sipnab reports `administratively prohibited` (ICMPv4 codes 9, 10 and 13, and
ICMPv6 type 1 code 1) apart from `host unreachable` and `network unreachable` because the
remedies sit on different devices: a filtering device for the first, a routing
problem or a dead host for the others.

The evidence for keeping them apart came from a real corpus: a single capture
held 433 host-unreachable and 262 administratively prohibited errors. Merging
the classes would have directed an engineer to the wrong device for 262 of
them.

### Media ICMP errors: the match order

A media ICMP error carries no `Call-ID`, so sipnab attributes it by trying, in
order:

1. the quoted datagram's own 5-tuple against the tracked streams;
2. the SSRC inside the quote;
3. either socket against a tracked stream endpoint;
4. an SDP-advertised media address, or the RTCP port one above it ([RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html)
   Section 11).

The rules are not equally strong, which is why each printed line names the one
that matched. A quote that matches nothing is still counted and printed: the
endpoint it names is real whether or not the capture holds the stream, so
hiding it would discard evidence.

### Amplitude measurements: thresholds and their reasons

Source: [`src/rtp/amplitude.rs`](../../src/rtp/amplitude.rs).

- `WINDOW_MS` (100): short enough to place a dead-air span within a tenth of a
  second, long enough that one glottal stop between words is not a window of
  its own (800 samples at 8 kHz).
- `MIN_DEAD_AIR_MS` (1,000): shorter gaps are speech. Normal conversation is
  roughly half silence, so a shorter minimum would report every healthy call.
- `DEAD_AIR_FLOOR_DBFS` (-60.0): the floor, relative to the codec's own full
  scale.
- `CLIP_FRACTION` (0.99): not 1.0. A signal driven into the ceiling lands on
  the two or three codes below the decoder's largest output as often as on the
  top one, so an exact-equality test misses most clipping.
- `MIN_CLIP_RUN` (3), asserted at compile time to be at least 2.

The clipping threshold is the codec's ceiling, not the 16-bit container's.
G.711 never fills its container: mu-law tops out at 32,124 and A-law at 32,256.
A test against 32,767 would never fire on the two codecs most telephony uses.

sipnab converts neither measurement into a quality score. Mapping amplitude onto
a MOS would need a corpus of listener scores. None exists here, and a reader
could not reproduce such a mapping from the pcap.

### The generated BPF filter and IPv4 options

Source: `auto_bpf_filter` and `ip_and_ports_at` in
[`src/app/bootstrap.rs`](../../src/app/bootstrap.rs).

The encapsulated arms pin IPv4 to `0x45` (version 4, header length 5 words).
A BPF byte offset has to be a constant and BPF cannot multiply the IHL nibble
into an index, so the encapsulated arms miss an IPv4 header with options.
The other arms do not. The untagged arm is a real libpcap `portrange`, which handles
options. The gap therefore needs IPv4 options and an encapsulation together.

Measured against the repository's PPPoE-over-Ethernet sample
([`tests/pcap-samples/DTMFsipinfo.pcap`](../../tests/pcap-samples/DTMFsipinfo.pcap)): a plain `portrange 5060-5061` matched
0 of 32 frames and the generated filter matched all 32. With the same SIP
wrapped in Linux cooked headers, the filter matched 11 of 11 encapsulations on
Ethernet, cooked v1 and cooked v2 alike.

### ICE role conflicts: why sipnab reports the resolution

Each role-conflict report states whether the agents nominated a pair anyway.
A conflict ICE resolves costs one round trip. Reporting those at the same
weight as an unresolved one trains a reader to skip the warning that matters.
sipnab reports the nominated pair because without it a capture of an exchange
that converged and one that never did read the same.

### STUN error responses count as answered

A STUN or TURN error response proves the server was reachable, so sipnab
counts the transaction as answered. Counting it as unanswered would send the
reader after a blocked path that does not exist.

### TURN ChannelData and the stream list

sipnab unwraps ChannelData, so the RTP inside reaches the stream list as
ordinary media. That media carries phone-to-relay addresses, so before the
join existed nothing in the stream list said a relay had carried it. Every
surface now names the channel-to-SSRC join: the `--stun` allocations section,
the lapsed-allocation `media on it:` line, the `relayed_streams` count in the
`--analyze` finding, the `channels` array in `--json-stun`, and `media_relay`
on a relayed call's diagnosis.

### Private media addresses: STUN evidence and CGNAT

The STUN-backed cases raise `private_media_address` without an observed
stream because the stream-based test needs a peer to examine, and a call whose
media never arrived has none: the test could not fire exactly when the finding
was most needed.

Carrier-grade NAT space ([RFC 6598](https://www.rfc-editor.org/rfc/rfc6598.html), `100.64.0.0/10`) is not flagged: it is
routable inside the carrier that assigned it, and flagging it would fire on a
large share of working mobile calls.

### Keylog named pipes: the two failure modes the reader closed

Source: [`src/capture/keylog_source.rs`](../../src/capture/keylog_source.rs).

Two silent failure modes existed before the current reader:

- **Capture stalled outright.** Opening a FIFO read-only blocks until a writer
  appears. That open sat in the sweep loop that drives dialog expiry and output
  flushing, so the whole capture stopped rather than the keylog degrading.
  `mkfifo kl.fifo && timeout 2 cat kl.fifo` reproduces the underlying
  behavior: it exits 124.
- **Zero keys, no complaint.** The freshness check compared file sizes. A FIFO
  stats as zero length however much data waits in it (`stat -c %s kl.fifo`
  returns `0`), so every pipe-based producer loaded nothing and reported nothing
  wrong, indistinguishable from a capture with no encrypted traffic.

The fix: a FIFO opens `O_RDONLY | O_NONBLOCK`, and stream mode never consults
the file's length. The run logs `<path> is a FIFO, reading it as a live
stream`.

### Keylog rotation

A reader that resumes from a remembered byte offset either gives up for good
once the file shrinks, or seeks into the middle of a line of new content. The
current reader resumes by file identity (device and inode, with the old inode
pinned by an open descriptor so a recreated file cannot reuse it) and offset,
resets on a shrink or an identity change, and logs one warning naming the
cause (`was truncated` or `was replaced`) from
[`src/capture/decrypt.rs`](../../src/capture/decrypt.rs).

### eCapture `-m pcap` and `CONFIG_NET_CLS_BPF`

The `couldn't add a ingress filter to interface 1` failure appeared on
Linux 6.8.12-rt-tegra, whose config reports `# CONFIG_NET_CLS_BPF is not set`.
`-m keylog` runs on the same kernel.

### HEP tracer transports before 0.5.188

Up to 0.5.187, OpenSIPS and Kamailio tracer messages for TLS and WebSocket legs
landed under NOT DECODED as `no transport (IP protocol 22)` and `ESP not
NULL-encrypted (IP protocol 50)`. Both numbers are the proxies' convention for
naming those transports in the HEP IP-protocol chunk. 0.5.188 decodes them
(see the CHANGELOG entry for that release).

## Recipe cookbook

Removed from [the recipe cookbook](../examples.md).

### Measurements behind the recipe cookbook

These records come from the operator recipe page
([`docs/examples.md`](../examples.md)). Each one backs an instruction the recipe
still gives. The recipe states the instruction, and this section keeps the
measurement it came from.

#### eCapture in keylog mode feeding a live sipnab (2026-08-14)

Backs the recipe "Decrypt traffic from a daemon you cannot restart".

- Traffic: a TLS 1.3 `REGISTER` over `TLS_AES_256_GCM_SHA384`.
- Keys: taken from a running process with no `SSLKEYLOGFILE` anywhere, by
  `ecapture tls -m keylog`.
- Result: sipnab decoded it as `127.0.0.1:53810 -> 127.0.0.1:15300 REGISTER TLS`.
- Hosts:
  - aarch64, kernel 6.8, no BTF. eCapture fell back to its non-CO-RE bytecode
    automatically.
  - x86_64, Debian 13, OpenSSL 3.5.6, BTF present.

An earlier revision of the recipe described eCapture's `-m pcap` mode as
writing plaintext. It writes the encrypted frames with the secrets embedded as
a pcapng Decryption Secrets Block (DSB), which is the recipe "One file, taken off
the host, that decrypts itself".

#### eCapture in pcap mode, read by sipnab with no keylog (2026-09-09)

Backs the recipe "One file, taken off the host, that decrypts itself".

- eCapture v2.5.2 took the keys by uprobe from a Python 3.13 process running
  OpenSSL 3.5.6. The process had no `SSLKEYLOGFILE` and set no keylog of its
  own.
- The session was TLS 1.3 `TLS_AES_256_GCM_SHA384` and carried one complete SIP
  dialog: an `INVITE` split across two TLS records, `100`, `180`, `200` with SDP,
  `ACK`, `BYE`, `200`.
- sipnab read the 50-packet file with no flags beyond `--portrange` and
  reported:

  ```text
  TLS decryption active: 6 secret(s) from embedded DSB in sip-tls.pcapng
  Call-ID                       From   To     State       Code  Msgs
  tls-split-invite-1@127.0.0.1  uac    echo   Completed   200   7
  ```

- The lab used port 15061. The first run, with the default `--portrange`
  5060-5061, decrypted the file and reported no calls; the skipped-SIP notice
  (`SIP outside --portrange 5060-5061 is being skipped`) named the port.
- On Linux 6.8.12-rt-tegra, `-m pcap` loaded its bytecode and then failed with
  `couldn't add a ingress filter to interface 1: netlink receive: no such file
  or directory`. That kernel's `/proc/config.gz` holds
  `# CONFIG_NET_CLS_BPF is not set`; `-m pcap` attaches a TC classifier as well
  as the uprobes. `-m keylog` ran on the same kernel.
- On a kernel with no BTF, eCapture logged the non-CO-RE object it loaded
  (`bytecode/openssl_3_0_0_kern_noncore.o`).

#### `-O` is not narrowed by `--filter`

Backs the recipe "Export one customer's calls as a smaller capture".

The pcap writer runs inside the capture loop, before any dialog exists to
evaluate. Re-measured 2026-10-16 against 0.5.222 (16f7b0ea):
`-O` under `--filter "from.user == 'nobody'"` (matching no dialog) and `-O` with
no filter wrote byte-identical files from
[`tests/pcap-samples/sip-problem-call.pcap`](../../tests/pcap-samples/sip-problem-call.pcap)
(`cmp` reports no difference, 8665 bytes each).

#### The MCP tool list in the cookbook

The recipe "Let an AI agent ask sipnab about your calls" groups the registered
tools for reading. The authoritative list is the table in
[`docs/mcp-tools.md`](../mcp-tools.md), which
[`tests/docs_drift_test.rs`](../../tests/docs_drift_test.rs)
(`mcp_tool_table_lists_every_registered_tool`) checks against the registry.

Until 2026-08-05 the recipe said "all 25 tools" and enumerated 25 while the
registry held 31. The six missing were `capture_health`, `explain_rule`,
`find_correlated`, `lint_dialog`, `save_findings` and `validate_message`. The
recipe no longer states a count.

#### Asymmetry signals and the dialog JSON

The five asymmetry booleans (`codec_asymmetry`, `ptime_asymmetry`,
`payload_asymmetry`, `duration_asymmetry`, `late_media`) live on the internal
`MediaDiagnosis` struct. They reach the filter DSL and the MCP
`find_problems` tool. The `diagnosis` block of `--json`, `--call-report --json`
and `--json-dialogs` does not carry them. On 0.5.222 its keys are `hints`,
`nat_mismatch`, `no_media`, `one_way_audio` and `private_media_address`.

#### vCon recipes

- The `--vcon-max-inline-media` default of 5 MiB comes from a probed vCon
  store that answered HTTP 204 for a larger container and dropped the payload.
  See [the vCon design notes](../design/vcon.md).
- The recipe "Check a vCon against the schema before a store rejects it" was
  motivated by a validation pass over 4,216 real containers that found 2 the
  schema rejects, with nothing on any surface reporting it.

#### Maximum WebSocket frame size

The recipe "Read SIP over WebSocket from a WebRTC gateway" states the 64 KiB
frame limit. It is `MAX_FRAME_SIZE` (65,536 bytes) in
[`src/capture/websocket.rs`](../../src/capture/websocket.rs).

#### Scripted WAV export

There is no CLI flag that writes WAV files. The library functions
`export_stream_to_wav` and `export_dialog_to_wav` in
[`src/rtp/audio_export.rs`](../../src/rtp/audio_export.rs) are what the TUI's
Save dialog calls.

#### `--no-cli-print` on old binaries

`--no-cli-print` arrived in 0.3.2. On older binaries, `sed -n '/^# Call Report:/,$p'`
(Markdown) or `awk '/^{$/{found=1} found'` (JSON) removed the per-message text
ahead of a `--call-report`.

## Installation and release artifacts

Removed from [the installation guide](../install.md) and the site's build page.

### The netmap capture backend: release history

The install page lists the three `netmap:` failures fixed since 0.5.183 as a
symptom table. This section records the mechanism behind each.

**netmap API 13 in the musl libpcap (fixed in 0.5.184).**

- On 0.5.183 and earlier, the release compiled the musl tarballs' libpcap
  against netmap's `v13.0` headers, which speak netmap API 13.
- A netmap kernel module built from current netmap sources accepts API 14 and
  later. On Debian 13 (kernel 6.12) the open fails with
  `nm_open [948] NIOCREGIF failed: Invalid argument netmap:<iface>`, and the
  kernel log says `Minimum supported API is 14 (requested 13)`.
- netmap `v13.0` itself no longer compiles against that kernel, so there is no
  older module to pair those builds with.
- 0.5.184 builds the same libpcap 1.10.6 against current netmap headers. Its
  published x86_64-musl binary captured 5 of 5 SIP messages through `netmap:`
  on that host.

**Crash on the first filtered frame (fixed in 0.5.189).**

- libpcap's netmap module reports a frame its BPF filter rejects as a
  successful read that delivers no data.
- 0.5.188 and earlier then copied the previous packet's length from address 0,
  and the capture thread died. The kernel log recorded a segfault at
  address 0 in the `capture-netmap` thread.
- It presented as a crash at shutdown. The dropped frame is usually link
  chatter, such as an IPv6 router solicitation, arriving while the capture is
  idle. An idle capture that had captured nothing survived, because no packet
  had yet set a length to copy.
- Later builds check that a read delivered a packet before they copy it.

**No stop on a silent link (fixed in 0.5.190).**

- libpcap's netmap module waits for a frame inside its own read and never
  returns control while the link is silent, so SIGTERM and `--duration` could
  not end the capture.
- Later builds break that read with `pcap_breakloop` from the
  `capture-stop:<device>` thread (see [Threading](threading.md)), implemented
  in [`src/capture/breaker.rs`](../../src/capture/breaker.rs).
- Measured on a veth pair with IPv6 turned off: the older build was still
  running 15 seconds after SIGTERM in 10 runs of 10. The fixed build exited in
  30 to 71 ms, and at 3.0 seconds under `--duration 3s`.

**netmap takes the interface from the host.** Measured 2026-09-21 on a veth
pair under Debian 13: a UDP socket bound on the host received 0 of 5 datagrams
while sipnab captured on `netmap:<iface>`, and 5 of 5 during an ordinary
capture on the same interface. The install page's warning states the
consequence, and [`tests/capture_backend_claim_test.rs`](../../tests/capture_backend_claim_test.rs) pins it.

### Release artifact naming

The release file names use canonical Rust target triples
(`x86_64-unknown-linux-gnu`, not a shortened or distribution-specific name).

- They match `rustc -vV`.
- They are the names `SHA256SUMS.txt` and the build-provenance attestation
  cover.
- [`website/static/install.sh`](../../website/static/install.sh) constructs
  them from `uname` output, so a renamed artifact breaks the installer.

### Two SBOMs per release

The release publishes `sipnab-<version>.cdx.json` and
`sipnab-audio-<version>.cdx.json`.

- `cargo cyclonedx` runs once, with `--features full,bpf`, and writes one SBOM
  per workspace crate. `release.yml` publishes the two that ship.
- The audio plugin is the separate `sipnab-audio` crate, loaded with `dlopen`.
  Its dependencies (`rodio`, and through it `cpal` and `alsa`) appear nowhere
  in the binary's own dependency graph, so a scan of the binary SBOM alone
  would miss them.
- `full,bpf` is the largest feature set any published binary carries, so the
  binary SBOM is a superset of every published binary's dependencies.

### The installer's glibc cutover

The installer serves the static musl build only to hosts below the floor the
release gate enforces on every gnu binary, or with no glibc at all. The
installer and the release gate use one number, glibc 2.36. A host that the gnu
build runs on therefore never takes the musl build, which would cost it TUI
audio playback. [`tests/site_journey_test.rs`](../../tests/site_journey_test.rs) holds the installer's
`SIPNAB_GLIBC_FLOOR` to the floor `release.yml` enforces.

### The published binary size ceiling

The "Enforce published binary size (musl targets)" step in `release.yml` reads
`binary_size_ceiling_mb` from
[`website/config.toml`](../../website/config.toml) and fails the release when a
musl binary exceeds it. The install page, the build page and the homepage all
quote the same value, and [`tests/site_journey_test.rs`](../../tests/site_journey_test.rs) holds each quote to the
config key.

## Capture tuning and the filter language

Removed from [capture tuning](../tuning-capture.md) and [the filter language reference](../filter-dsl.md).

### Filter DSL parser limits

Relocated from `docs/filter-dsl.md` ("Parser constraints"). The operator page
now lists each limit with the error text the binary prints. The reasons and
the code locations live here.

`FilterExpr::parse` enforces all limits, in
[`src/sip/dsl.rs`](../../src/sip/dsl.rs), so every surface that parses a
filter (CLI flags, `[filter] expression`, `[filters]` entries, REST, MCP, the
TUI filter dialog) inherits them.

- `MAX_EXPRESSION_NODES = 1024`. The bound a caller is most likely to reach.
  Without it, a long flat chain such as `a OR b OR c OR d` built one node per term and
  overflowed the stack during evaluation, which aborts the process instead of
  returning an error. `MAX_NESTING_DEPTH` could not catch it, because a flat
  chain has no parentheses. `count_nodes` runs after the syntax checks, so a
  malformed expression is still reported as malformed rather than as
  oversized. A comparison, `AND`, `OR` and `NOT` each count as one node; 600
  comparisons joined with `OR` count 1199. `@name` references expand before
  parsing, so they do not reduce the count.
- `MAX_NESTING_DEPTH = 50`. Bounds recursion in the parser itself. How large
  the resulting tree may grow is the separate node bound.
- `MAX_HEADER_NAME_LEN = 256` bytes for `header.<name>`. The sender of the
  message chooses the header name, so sipnab bounds the field that names one
  like every other input.
- `REGEX_SIZE_LIMIT = 1_000_000` bytes, passed to the regex builder's
  `size_limit`. The same error text covers a pattern that does not compile
  and one over the limit.
- The error position is the 0-based character column the caret marks, not a
  byte offset.
- [`tests/filter_depth_bounds_test.rs`](../../tests/filter_depth_bounds_test.rs) harvests every double-quoted
  `--filter` argument and `expression =` value from `docs/` and requires it to parse, so a page
  that shows a refused expression must quote it with single quotes.

### Filter DSL: unknown numeric values

Relocated from `docs/filter-dsl.md` ("Poor audio quality" and the numeric
fields note).

- Before the fix that made unmeasured `pdd`, `setup_time`, `rtp.mos`,
  `rtp.jitter` and `rtp.loss` unknown, a signaling-only dialog reported
  `rtp.mos` as `0.0` and satisfied `rtp.mos < 3.0`. The page then said the
  `rtp.packets > 0` clause was mandatory.
- Measured on one real trunk capture: reading unknown as `0` selected 2292 of
  2311 dialogs for `rtp.mos < 3.0`, against 2 genuine low-MOS calls.
- Unknown now matches no comparison, `!=` included, which is the SQL `NULL`
  rule. Saved filters that still carry `AND rtp.packets > 0` keep working.

### Capture ring arithmetic and the `any` device

Relocated from `docs/tuning-capture.md` ("Snapshot length" and "Which
interfaces"). Verification debt for these figures is item V3 in
[`docs/design/capture-tuning-tasks.md`](../design/capture-tuning-tasks.md).

libpcap's `create_ring()` (in `pcap-linux.c`) sizes each TPACKET_V2 slot from
the snapshot length:

- `frame_size` starts as `handle->snapshot`.
- The slot size `req.tp_frame_size` is `TPACKET_ALIGN(macoff + frame_size)`.
- The slot count `req.tp_frame_nr` is the buffer size divided by the slot size,
  rounded up: `(handle->opt.buffer_size + req.tp_frame_size - 1) / req.tp_frame_size`.

The link type guards the only clamp on `frame_size`. It runs only when
`handle->linktype == DLT_EN10MB`:

- With offloads on, the limit is `MAX(mtu, 65535) + 18`.
- With offloads off, the limit is `mtu + 18`.
- libpcap cuts a `frame_size` above the limit to the limit.

- `find_default_device()` in
  [`src/capture/device.rs`](../../src/capture/device.rs) returns `"any"` on
  Linux, with the comment "SIP servers often listen on loopback, so capturing
  only eth0 misses traffic". It is a coverage choice, not a performance one.
- `any` reports `DLT_LINUX_SLL2`, so the clamp never runs on the default
  device and no `ethtool` setting changes that.
- At the 64 MiB default a V2 ring on `any` holds about 1,000 slots, against
  about 41,000 for a named Ethernet interface with offloads off. At the
  former 2 MiB default the same arithmetic gave `any` 31 slots.
- [`src/capture/live.rs`](../../src/capture/live.rs) computes
  `let use_promisc = config.promisc && device != "any"`: the pseudo-device
  does not support promiscuous mode, so sipnab does not request it.
- `start_multi_capture()` in
  [`src/capture/native.rs`](../../src/capture/native.rs) starts one
  coordinator thread and one capture thread per named device.

### Ring format selection: immediate mode

Relocated from `docs/tuning-capture.md` ("Which ring you get"). The shipped
work item is CT7 in
[`docs/design/capture-tuning-tasks.md`](../design/capture-tuning-tasks.md).

libpcap's `prepare_tpacket_socket()` makes immediate mode a ring-format
choice:

```c
/*
 * The only mode in which buffering is done on PF_PACKET
 * sockets, so that packets might not be delivered
 * immediately, is TPACKET_V3 mode.
 *
 * The buffering cannot be disabled in that mode, so
 * if the user has requested immediate mode, we don't
 * use TPACKET_V3.
 */
if (!handle->opt.immediate) {
        ret = init_tpacket(handle, TPACKET_V3, "TPACKET_V3");
```

- `immediate_mode_for()` in [`src/app/bootstrap.rs`](../../src/app/bootstrap.rs)
  returns true for `RunMode::Tui` only. The TUI keeps per-message latency;
  every headless mode takes the V3 ring, whose blocks do not shrink with the
  snaplen.
- libpcap copies the read timeout into `req.tp_retire_blk_tov` and then polls
  with `-1`, so on V3 the timeout adds delivery latency rather than a poll
  bound. The interactive 100 ms would have delayed a partly filled block by up
  to 100 ms. The batched path uses `BATCHED_READ_TIMEOUT_MS = 5` in
  [`src/capture/live.rs`](../../src/capture/live.rs).
- Shutdown (`--duration`, Ctrl-C) does not depend on either timeout: the
  handle is non-blocking, an empty ring returns `TimeoutExpired`, and the wait
  is sipnab's own bounded `wait_readable()`.
- Not measured on hardware. Whether the kernel selects V3, and what it is
  worth, comes from reading libpcap's source. Two checks would settle it:
  `strace -e trace=setsockopt` for `PACKET_VERSION`, and kernel drops under
  load against a V2 baseline.

### Kernel buffer ceiling

Relocated from `docs/tuning-capture.md` ("And it caps at 2047 MiB").

- `pcap_set_buffer_size` takes a C `int`, so 2047 MiB is the last whole MiB
  whose byte count fits. `MAX_BUFFER_MB = 2047` in
  [`src/capture/live.rs`](../../src/capture/live.rs) clamps larger requests
  and warns.
- Before the clamp, the arithmetic wrapped: `--buffer 2148` handed libpcap a
  negative byte count.

### Capture documentation: measurements and rationale

Relocated from `docs/tuning-capture.md`.

- sipnab exports drops as two Prometheus counters,
  `sipnab_capture_kernel_dropped_packets_total` and
  `sipnab_capture_interface_dropped_packets_total`, rather than one counter
  with a label, so that a dashboard or alert cannot sum two figures whose
  remedies differ (a larger `-B` fixes only the first).
- `--capture-profile signaling` is a named profile rather than a smaller
  default because truncation breaks audio reconstruction and `-O` re-emit. It
  stops at 1500 bytes rather than 200 to 400, because an INVITE with a full
  `Record-Route` set, a long `Contact`, ISUP encapsulation or a large SDP offer
  passes 400 bytes routinely.
- netmap, measured on a veth pair: a UDP socket on the host received 0 of 5
  datagrams during a `netmap:` capture, and 5 of 5 during an ordinary capture
  on the same interface. No other measurement on the tuning page went through
  netmap.
- The tuning page previously stated that RTP is about 93% of carrier traffic
  by packet count. The page now cites the test fixture
  [`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap) (839 of 852 packets are RTP).
- Offline `--cores` scaling on the reference corpus, as the tuning page
  stated it: 1.13M packets/s at one core, 2.17M at two, 3.23M at four, 3.24M
  at eight. The curve flattens after four; the gap between four and eight is
  inside the noise of a single sweep. The workers, not the sequential reader,
  compute the frame-provenance digest, so that cost scales with the worker
  count (see
  [`docs/design/process-isolation-and-hot-path-cost.md`](../design/process-isolation-and-hot-path-cost.md)).
