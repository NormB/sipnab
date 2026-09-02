# MCP tool reference

Every tool the MCP server exposes, what it answers, and what it returns.

This is lookup material, not reading material.

- [MCP server](mcp.md) — what MCP is, and a first working example.
- [MCP deployment](mcp-deploy.md) — the deployment shapes.
- [MCP protocol](mcp-protocol.md) — the wire contract, security model and error semantics.


The v0.5 sipnab MCP tool surface. No tool edits the analysis in place, and
every response carries a ceiling. That ceiling defaults to 1000 rows and is an
operator setting, not a build-time fact: `--mcp-max-rows N`, or `[limits]
mcp_max_rows` in the config file, with the flag winning. The right value
belongs to the consumer — a model with a small context window wants far fewer,
a batch client piping to a file wants far more. Note this is a DIFFERENT limit
from `dialog_limit`, which bounds dialogs tracked over the whole run and
defaults 100x higher. One tool replaces
the analysis outright — `open_capture`, off unless you enable it — and it mints
a new capture identity so the replacement cannot reach a consumer as an
ordinary update.


**[Survey — what is in this capture](#survey-what-is-in-this-capture)**


| Tool | Parameters | Returns |
|---|---|---|
| [`capture_status`](#capture_status) | -- | What this server captures: live or file, uptime, and whether stopping loses unsaved packets |
| [`capture_health`](#capture_health) | `sample_seconds` | Capture-path counters read twice: run totals, deltas across the window, `undecoded_fraction`, and undecodable frames by reason |
| [`reconcile_orphans`](#reconcile_orphans) | `limit?` | Why each RTP stream with no dialog lacks one: a relay named the endpoint but no signaling arrived, SDP named it but no dialog claims it, or nothing named it at all |
| [`get_capture_report`](#get_capture_report) | `format?` | Whole-capture analysis: findings, orphaned media, STUN/ICMP evidence, what the caps shed |
| [`list_captures`](#list_captures) | -- | Capture files in `--mcp-file-root`, with sizes |
| [`list_dialogs`](#list_dialogs) | `filter?`, `limit?`, `cursor?` | A page of dialog summaries, with the total behind it |
| [`timeline`](#timeline) | `bucket_seconds?` | Call volume per fixed-width interval, so a gap or a spike is visible without reading every dialog |
| [`top_talkers`](#top_talkers) | `by`, `limit?`, `filter?`, `prefix_digits?` | The busiest IPs, user agents or dialled prefixes, ranked, each share stated against the population behind it |
| [`aggregate_dialogs`](#aggregate_dialogs) | `group_by`, `filter?`, `top_n?` | Counts dialogs grouped by ONE field, in the store rather than in the model |
| [`group_dialogs`](#group_dialogs) | `by`, `metrics?`, `filter?`, `top_n?` | Carrier metrics per group — ASR, NER, ACD, post-dial delay, MOS, retransmissions — each beside the population it rests on |
| [`server_capabilities`](#server_capabilities) | -- | sipnab version and the optional features this binary carries |

**[Find — narrow to the calls that matter](#find-narrow-to-the-calls-that-matter)**


| Tool | Parameters | Returns |
|---|---|---|
| [`find_problems`](#find_problems) | `kinds?`, `filter?`, `limit?`, `cursor?` | A page of dialogs matching one or more diagnostic alias names |
| [`search_messages`](#search_messages) | `query`, `limit?`, `cursor?` | A page of substring matches across method/From/To/UA/body, with the total behind it |
| [`search_by_time`](#search_by_time) | `start`, `end?`, `filter?`, `limit?`, `cursor?` | Dialogs whose first message falls in an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339) window |
| [`validate_filter`](#validate_filter) | `expr` | Whether a filter DSL expression parses, the parser's message when it does not, and how many dialogs it selects — with no rows |
| [`describe_endpoint`](#describe_endpoint) | `ip?`, `user?`, `limit?` | Everything one participant did: dialogs by method and state, INVITE outcomes, REGISTER state, banners, streams, findings |
| [`tail_dialogs`](#tail_dialogs) | `cursor?`, `limit?` | Cursor-based incremental dialog fetch |
| [`await_condition`](#await_condition) | `filter`, `timeout_seconds?`, `poll_interval_ms?` | Waits until a filter matches or a deadline passes, whichever is first, so a live capture costs one call instead of a polling loop |
| [`find_correlated`](#find_correlated) | `call_id`, `limit?` | The other legs of the same call across a B2BUA, each with a score AND the strategy that matched it |
| [`get_call_tree`](#get_call_tree) | `call_id`, `limit?` | Every leg of one call as a tree, each edge carrying its parent, depth, score, strategy and whether the walk went through it |
| [`compare_dialogs`](#compare_dialogs) | `call_id_a`, `call_id_b` | Two calls side by side, with the differences named |
| [`compare_captures`](#compare_captures) | `a`, `b`, `dimensions?`, `top_n?` | Diffs two capture files in `--mcp-file-root` by aggregate, ranked by how far each bucket MOVED. Neither becomes the loaded capture |

**[Diagnose one call](#diagnose-one-call)**


| Tool | Parameters | Returns |
|---|---|---|
| [`triage_call`](#triage_call) | `call_id` | First-pass verdict: signaling problem, media problem, both, or none, with evidence |
| [`get_dialog`](#get_dialog) | `call_id`, `max_messages?`, `cursor?` | Paginated dialog with full SIP messages |
| [`get_dialog_report`](#get_dialog_report) | `call_id`, `format?` | Structured per-call report (JSON / Markdown / text) |
| [`get_message`](#get_message) | `call_id`, `index` | Single SIP message at a given index |
| [`render_ladder`](#render_ladder) | `call_id`, `format?` | Call-flow ladder (Markdown / text) |
| [`get_sdp_timeline`](#get_sdp_timeline) | `call_id` | SDP offer/answer exchanges in order: codecs, ptime, direction |
| [`check_codec_negotiation`](#check_codec_negotiation) | `call_id` | Codecs offered vs answered and whether they intersect — for 488s |
| [`diagnose_registration`](#diagnose_registration) | `call_id` | Whether an endpoint registered, hit a rejection, is looping on auth, or got a short expiry |
| [`media_diagnostics`](#media_diagnostics) | `call_id` | The facts under the MOS: QoS marking, jitter grounding, delay provenance, silence, and what the far end reported |
| [`rtp_stats`](#rtp_stats) | `call_id?`, `min_mos?`, `max_mos?`, `limit?`, `cursor?` | One call's RTP quality and diagnosis, or a capture-wide stream sweep |

**[Conformance and rules](#conformance-and-rules)**


| Tool | Parameters | Returns |
|---|---|---|
| [`lint_dialog`](#lint_dialog) | `call_id`, `rulesets?`, `severity_min?`, `suppression_file?` | Conformance findings for one call, declaration against observation included, each with its RFC and section |
| [`validate_message`](#validate_message) | `call_id`, `index`, `suppression_file?` | Conformance findings for one message, read alone |
| [`explain_rule`](#explain_rule) | `rule_id` | The catalog entry behind one rule identifier: citation, basis, scope, selectors |
| [`explain_response_code`](#explain_response_code) | `code` | IANA registry meaning and class for a SIP status code |
| [`evaluate_expectations`](#evaluate_expectations) | `rules?`, `rules_toml?`, `suppression_file?` | A pass/fail verdict per rule plus an exit code for a build. A rule whose population is empty fails rather than passing quietly |

**[Security](#security)**


| Tool | Parameters | Returns |
|---|---|---|
| [`security_findings`](#security_findings) | `kinds?`, `since?`, `limit?` | Recent `scanner` / `fraud` / `digest` / `reg_flood` findings, plus the detectors this server runs |
| [`generate_fail2ban_rule`](#generate_fail2ban_rule) | `finding_id` | A fail2ban filter and jail derived from ONE recorded finding, with that finding attached as the evidence |

**[Evidence and provenance](#evidence-and-provenance)**


| Tool | Parameters | Returns |
|---|---|---|
| [`explain_attribution`](#explain_attribution) | `call_id` | Where each of a call's media endpoints came from and how much that path is worth — asked directly, HMAC-verified, plain secret, port-gated only, or the parties' own SDP |
| [`show_evidence`](#show_evidence) | `refs`, `max_bytes?` | Follows frame pointers back to the captured bytes: verified, unverified, or unresolvable with a reason |
| [`decode_evidence`](#decode_evidence) | `frame_ref`, `field?` | Decodes the frame one pointer names: link type, addressing, and each SIP header's byte range inside the message and the frame |
| [`decode_ng`](#decode_ng) | `frame_ref` | Decodes the relay control message one pointer names: the command, the call, whether it carries SDP, and which delivery path carried it |
| [`build_evidence_package`](#build_evidence_package) | `call_ids`, `filename` | **Write.** One directory of escalation artifacts in `--mcp-file-root`: pcapng, ladder and RTP stats per call, manifest, and the rebuilt-frames README |
| [`save_findings`](#save_findings) | `summary`, `call_id?`, `detail?` | **Write.** Records the agent's conclusion to sipnab's log. Needs `--mcp-allow-save-findings`; no tool reads it back |

**[Export and handoff](#export-and-handoff)**


| Tool | Parameters | Returns |
|---|---|---|
| [`export_capture`](#export_capture) | `filename` | Writes held SIP signaling to a pcap in `--mcp-file-root` (re-synthesized frames, no RTP) |
| [`export_audio`](#export_audio) | `call_id`, `filename` | Writes a call's RTP audio to a WAV in `--mcp-file-root`; needs the server started with `--retain-audio` |
| [`export_vcon`](#export_vcon) | `call_id?`, `filter?`, `limit?` | Dialogs as vCon conversation containers, structured JSON, each with its SHA-256. One `call_id` or a whole filtered set. Unsigned, retained audio inline, and every omission stated in the response |
| [`validate_vcon`](#validate_vcon) | `call_id?`, `container?` | Checks a container against the schema sipnab vendors and names the one documented deviation instead of passing it |
| [`generate_repro`](#generate_repro) | `call_id`, `format?`, `pin?`, `vary?`, `filename?` | A SIPp scenario replaying one call, with the hypothesis as an input: `pin` holds the suspected cause fixed, `vary` regenerates identity |
| [`generate_wireshark_filter`](#generate_wireshark_filter) | `call_id`, `include_media?` | A Wireshark display filter selecting one call's signaling and its RTP by SSRC, plus the tshark line that applies it |

**[Capture control (opt-in, off by default)](#capture-control-opt-in-off-by-default)**


| Tool | Parameters | Returns |
|---|---|---|
| [`query_relay`](#query_relay) | `call_id?`, `max_calls?` | **Transmits.** Asks the configured relay what it holds right now. Needs `--mcp-allow-relay-query` and a live source; the destination comes from operator configuration only |
| [`open_capture`](#open_capture) | `filename` | **Destructive.** Replaces every dialog and stream with another capture from `--mcp-file-root`. Needs `--mcp-allow-open-capture`; loads in the background |
| [`shutdown_server`](#shutdown_server) | `dry_run?`, `save_to?`, `discard_unsaved?` | **Destructive.** Stops the process. Needs `--mcp-allow-shutdown`; dry-run by default |
| [`start_tls_capture`](#start_tls_capture) | `flavors`, `libraries` | installs kernel uprobes and reads SIP plaintext with no key; needs `--mcp-allow-tls-capture` |
| [`stop_tls_capture`](#stop_tls_capture) | -- | stops that capture and removes its kernel probes |
| [`list_tls_libraries`](#list_tls_libraries) | -- | which TLS libraries this host runs, and whether sipnab could read their plaintext without keys |


### Rules every tool follows

Six rules hold across the whole surface. Each tool section below states only
what it does differently, so read these once and skip them afterwards.

**A required parameter has no default.** Leave one out, or send the wrong JSON
type, and the call fails with `invalid_params` (-32602) before the tool runs.
Optional parameters carry a `?` in every table on this page, and each row says
what the tool does when you omit that one.

**A `limit` of `0` means the default, not "no rows".** `limit` defaults to 50
everywhere it appears. The server clamps anything larger to `--mcp-max-rows`
(1000 unless the operator lowered it) and returns the clamped page without an
error. Both edges bite the same caller: a client that computes `limit` from
"rows I still want" asks for 50 when it meant to ask for none, and a client
that asks for 5000 to "get everything" receives 1000 and no complaint. Read
`returned` rather than the length you asked for.

**Pass a cursor back exactly as it arrived.** `next_cursor` pairs a timestamp
with an identity — `<RFC 3339>|<Call-ID>` for dialogs, and
`<RFC 3339>|0xSSRC@src>dst` for the `rtp_stats` sweep. A hand-rebuilt bare
timestamp still parses, so rebuilding one costs rows instead of raising an
error. `next_cursor: null` marks the final page.

**Every list-style tool answers with a page object, never a bare array.** The
rows sit under a named key — `dialogs`, `hits`, `streams`, `findings` — beside
`returned` and `total_matched`, so counting the rows is never necessary and
never right. `search_messages` and `security_findings` carry the
page fields too. `tail_dialogs` is the one page object with no
total, because a tail cannot have one. [Response
bounding](#response-bounding) tabulates it.

**Every answer says how much of the capture is behind it.** Two booleans ride
on every response object: `source_exhausted`, true once sipnab has read the
source to its end, and `source_stopped_early`, true when a read ended before the
source did — a truncated dump file, a file that would not open, a read error
part-way through. The answer is the WHOLE answer only when `source_exhausted` is
true and `source_stopped_early` is false, and one response tells you that much,
so nothing has to call `capture_status` to interpret it.

Until then the response omits `truncated: false` entirely. That value claims
outright that the page holds every match, and a caller reading only that field
deserves no claim rather than a wrong one — JSON absence and `false` are
different values. The response still says `truncated: true` whenever the row cap
really did keep matches out, because that fact holds whatever the load state.
`complete`, where a tool has one, likewise never reads `true` over a partial
read.

A file source loads on a background thread, so an agent's first call lands
inside a window a human client never sees: on a 921 MB capture, `list_dialogs`
answered with 6 of 18,241 dialogs. `tail_dialogs` and `capture_status` have
always carried `source_exhausted`. Now every tool that answers from the capture
does. The exceptions are the tools whose answer cannot move with the load —
`explain_response_code`, `explain_rule`, `decode_evidence`, `show_evidence`,
`list_captures`, `list_tls_libraries`, `server_capabilities` and
`compare_captures`, which reads two files and never the loaded capture. The
tools that answer with a rendered document — `render_ladder`, and
`get_capture_report` / `get_dialog_report` in `markdown` and `text` — have no
object to put a field in, so they say it in prose instead: a document drawn
over a capture that is still loading, or over one whose read stopped before its
end, ends with the same `INCOMPLETE RUN` block `--report` appends, naming each
reason. A document drawn over a capture read in full says nothing extra,
because a caveat on every answer is a caveat nobody reads.
`timeline`, whose payload is a top-level array with no key to carry a field,
carries the two booleans in a second content block instead.

**Capture text arrives fenced, and identifiers do not.** Free text an endpoint
wrote — display names, `User-Agent`, SDP, whole messages — comes wrapped in
`⟦untrusted-capture-data⟧` … `⟦/untrusted-capture-data⟧`, and the tools that
emit it append a provenance note as the LAST content block. Call-IDs, cursors,
addresses and timestamps stay verbatim so they pass straight into the next
call. [Untrusted capture text](mcp-protocol.md#untrusted-capture-text) gives the per-tool
breakdown. Every JSON sample below shows the markers where the server really
emits them.

### Reproduce every example on this page

Each tool section names the capture its example ran against. Start a server on
that capture, then call the tool. These two cover most of the page:

```bash
# The paging examples: 1334 dialogs, no RTP.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sipp-branch-scenario.pcapng
```

```bash
# The media examples: one completed call, two RTP streams.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sip-rtp-g711.pcap
```

Drive either one with the [raw HTTP test](mcp-deploy.md#test-the-http-wire-by-hand) on the deployment page, or point
a client at `http://127.0.0.1:8731/mcp`. A loopback bind needs no token.

Numbers in the samples are what those captures produce. Jitter and MOS come out
byte-identical run to run, because a file replay reads packet timestamps rather
than arrival times, so a value that fails to match points at a real change
rather than at timing noise.


## Survey — what is in this capture

Start here when you have a capture and no particular suspect. These answer "what is in it", "how much", and "is the server even seeing traffic".

### `capture_status`

**Ask this first.** It answers what the server is actually attached to — a live
interface or a replayed file — which nothing else on this surface reveals.

No parameters. Returns:

```jsonc
{
  "schema_version": 2,           // 2 absorbed the counters the old stats tool returned
  "source": "live",              // "live" | "file" | "unknown"
  "name": "eth0",                // interface, or file path
  "uptime_sec": 3612,
  "dialog_count": 128,
  "stream_count": 64,
  "orphaned_stream_count": 3,    // streams no dialog claims
  "active_dialog_count": 12,     // any non-terminal state
  "active_call_count": 9,        // InCall only — narrower, hence the version bump
  "capture_quality": {
    "kernel_dropped_packets": 0,
    "interface_dropped_packets": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 0,
    "degraded": false
  },
  "caveats": {
    "media_creating_commands": 0  // relay commands seen and NOT attributed
  },
  "source_exhausted": false,     // true once a file is read to the end
  "source_stopped_early": false, // true when a read ended before the file did
  "writing_to": null,            // path packets are being saved to, if any
  "unsaved": true,               // stopping now would lose packets
  "capture_identity": {
    "node": "capture01",
    "instance": "1f4a17c8e2b91d40-1",
    "dialog_generation": 412,
    "stream_generation": 96
  },
  "unanalysed_sip_messages": 0,  // SIP that --portrange excluded
  "unanalysed_busiest_ports": [],
  "unanalysed_websocket_messages": 0,  // SIP-over-WebSocket the WS port set excluded
  "unanalysed_websocket_ports": [],    // pass these to --ws-portrange
  "load": null                   // an open_capture load in flight, if any
}
```

`unsaved` is the field that matters. It is `true` only for a **live** capture
with no output file — packets held in memory and nowhere else. A file replay is
already on disk, so it is never unsaved.

`source: "unknown"` means nobody gave the server capture context. It
reports that rather than guessing, because a wrong `"live"` would be worse than
an admission of ignorance.

`capture_identity` says which capture this is and how many times its stores have
changed. Compare it across calls: a higher generation on the same instance means
the capture grew, and a different instance means `open_capture` loaded a
different file and every cursor you hold is void. The same object appears on
`capture_status`, `list_dialogs`, `find_problems`, `tail_dialogs`, `find_correlated`,
`save_findings`, `open_capture` and the capture-wide `rtp_stats` sweep. `node` names
the box that answered, which decides whose capture a fact came from once an agent
holds several servers at once.

`load` is null except while an `open_capture` read runs. During one:

```jsonc
"load": {
  "filename": "outage-0722.pcap",
  "instance": "1f4a17c8e2b91d40-2",
  "packets": 184320,             // climbing
  "elapsed_sec": 4,
  "done": false,
  "error": null                  // set when a load stopped early
}
```

The stores fill as the read goes, so dialogs appear before `done`. Wait for
`done` before concluding anything about how many calls the capture holds — a
partial answer looks exactly like a complete one.

Read the two `unanalysed_` pairs before reading anything into `dialog_count`.
They report SIP that sipnab recognized and did not analyze, and they are the
only way to tell a capture that holds no calls from one whose calls fell
outside a port setting. They count different losses with different
remedies, so a non-zero figure names its own flag:

- `unanalysed_sip_messages` / `unanalysed_busiest_ports` — plain SIP signaling
  with both ports outside `--portrange`. Re-run with a range that covers the
  ports listed.
- `unanalysed_websocket_messages` / `unanalysed_websocket_ports` —
  SIP-over-WebSocket ([RFC 7118](https://www.rfc-editor.org/rfc/rfc7118)) on a
  port outside the WebSocket set. Re-run with `--ws-portrange` covering the
  ports listed; widening `--portrange` recovers none of it. This is the common
  case on a WSS listener behind a reverse proxy, and on Kamailio, OpenSIPS and
  Janus, which all default outside sipnab's shipped 80/443/8080/8443.

Both are zero on a live capture, where BPF filtered before the pipeline saw
anything and there is nothing to under-report.

#### What the capture DECLINED — `caveats`

`capture_quality` above counts what the capture **lost**. `caveats` counts what
sipnab **chose not to do**, which is a different thing and is not a defect.

| Key | What it counts |
|-----|----------------|
| `media_creating_commands` | rtpengine `subscribe`, `publish` and `start recording` commands seen and deliberately not attributed |
| `tls` | TLS decryption state — **absent** unless a decryptor ran |

Those commands create media belonging to a call without being one of its two
legs. Decoding one as an ordinary leg would make a two-party call report three
streams, after which the analysis that judges one-way audio and asymmetry
answers a question nobody asked — so sipnab counts them instead.

**Read this before reasoning about a stream count.** A call with a recording
fork has media on the wire that no `rtp_stats` row explains, and this number is
how you know that is a decision rather than a gap. Zero is a real
answer and the key is always present.

##### `caveats.tls` — is decryption working?

Absent when nobody supplied keys, which is not a decryption failure. When a
decryptor ran, the block carries `keylog_entries`, `sessions_with_keys`,
`app_data_records`, `decrypted_records`, `undecrypted_records`,
`late_recovered`, `late_evicted` and `read_nothing`.

**Act on `read_nothing`, never on the arithmetic.** A TLS handshake carries
records sipnab never loads keys for, so `app_data_records > decrypted_records`
is not by itself a failure — an agent deriving a verdict from the two counts
reports a working capture as broken and sends an operator after keys that
already work. `read_nothing` is `true` only when application data arrived and
none of it opened.

That case is why the block exists. A capture holding ciphertext nobody can open
produces a dialog listing identical to one from a quiet network. If you are
about to answer "there was no SIP on this capture", check this field first:
`server_capabilities.can_decrypt` says whether the BUILD can decrypt, and this
says whether this RUN did.

`GET /v1/stats` carries the same block under the same name.

### `capture_health`

Reads the capture counters, waits, and reads them again. The response carries
the run totals **and** the change across that window, which turns a pile of
monotonic counters into a rate.

`sample_seconds` is **required** — this tool has no default window, because a
rate without a stated interval is not a rate. The call blocks for that long:

```jsonc
capture_health { "sample_seconds": 1 }
```

`capture_status` tells you what the counters say right now. `capture_health` tells you
what they did over a window you chose, which is the difference between "this
process has dropped 4 million packets since Tuesday" and "this process is
dropping packets **now**".

Three questions it answers on a busy production server:

1. **Does the capture path drop packets under load?** Read
   `in_window.kernel_dropped` and `in_window.interface_dropped`. They stay
   apart because their fixes disagree — a bigger ring buffer cures the first
   and does nothing for the second.
2. **What is on this wire that sipnab cannot decode?** Read
   `undecodable_by_reason`. Each entry names the reason as a code and carries
   the number that identifies it: the link type, the EtherType, or the IP
   protocol.
3. **What does the encapsulation-aware capture filter cost?** Run the same
   window twice, once with `--capture-tunnels` and once without, and compare
   `in_window.packets` against the two drop counters.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `sample_seconds` | u32 | 1 to 30. A larger value clamps to 30, and `window.requested_seconds` beside `window.applied_seconds` reports both. Zero fails with `sample_seconds must be at least 1`. | Required — the call fails. This tool is the one place with no default, because a rate without a stated interval is not a rate. |

**The call blocks for the whole window**, so a client with a short request
timeout should ask for a few seconds rather than 30.

Returns:

```jsonc
{
  "schema_version": 1,
  "attachment": 2,
  "window": {
    "requested_seconds": 10,
    "applied_seconds": 10,
    "observed_ms": 10003
  },
  "totals": {
    "packets": 8412990,
    "kernel_dropped": 1204,
    "interface_dropped": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 2103247
  },
  "in_window": {
    "packets": 94318,
    "kernel_dropped": 17,
    "interface_dropped": 0,
    "invalid_timestamps": 0,
    "undecodable_frames": 23610
  },
  "undecoded_fraction": 0.24999999,
  "undecoded_fraction_in_window": 0.2503,
  "undecodable_by_reason": [
    { "reason": 2, "number": 34887, "frames": 2061109, "frames_in_window": 23140 },
    { "reason": 3, "number": 47,    "frames": 41022,   "frames_in_window": 465 },
    { "reason": 4, "number": null,  "frames": 1116,    "frames_in_window": 5 }
  ],
  "undecodable_reasons_dropped": 0,
  "dialogs_tracked": 2411,
  "streams_tracked": 4802,
  "clock": {
    "synchronized": true,
    "max_error_us": 238000,
    "est_error_us": 0,
    "available": true
  },
  "source_exhausted": true,
  "source_stopped_early": false
}
```

`source_stopped_early` answers the question this tool usually gets: **did the
whole capture arrive?** It reads `true` when a file's read ended before the file
did — `libpcap error: truncated dump file`, a file that would not open, a read
that hit an error part-way through — which is the normal state of a ring
buffer's newest member and otherwise stays invisible here. Until this field
landed, that condition reached stderr as `0 of 1 file(s) read in full, 1 stopped
early` and reached this response not at all, so an agent asking whether a
capture was sound got no answer either way. Both fields are booleans, so the response type stays
free of strings.

> **This tool starts no capture.** With `--mcp` attached to a live interface,
> the counters already accumulate, so a rate costs two reads and a wait. That
> is not only the cheap design, it is the safe one: the handler opens no
> device, names no interface, and writes no file, so no path leads from an MCP
> call to a capture that transmits or records anything.

> **No value in this response is a string.** The response type holds integers,
> codes, two proportions and the clock's booleans, and it has no string field
> anywhere in it or in anything nested inside it. A type that cannot represent packet
> content cannot leak packet content, which is why the reasons below travel as
> codes and their labels live on this page instead of on the wire. The test
> `a_populated_capture_health_response_carries_no_string_value_anywhere`
> serializes a full response and fails on any string value at any depth.

#### `attachment` — what this server has packets from

| Code | Meaning |
|---|---|
| `1` | Nothing attached. No capture context reached this server. |
| `2` | A live interface. |
| `3` | A capture file replaying. |

Code `1` exists so that a server with nothing to read says so. A row of zeros
from a tool that never had a capture looks exactly like a healthy quiet wire,
and no code is `0`, so a defaulted or truncated response can never pass for a
real answer.

#### `undecodable_by_reason` — the reason codes

| `reason` | Meaning | What `number` carries | Where to start |
|---|---|---|---|
| `1` | The pcap link type has no decoder here | The DLT number | `editcap -T ether` converts a `DLT_NULL` (0) or `DLT_LINUX_SLL` (113) file |
| `2` | The link layer named a payload that is not IP | The EtherType, or `null` when the link layer records none | `34887` is `0x8847`, so the mirror carries MPLS. `2054` is ARP, which every Ethernet capture carries and nothing needs to decode |
| `3` | An IP header decoded, and its payload is no transport sipnab handles | The outermost IP protocol, or `null` when the decoder recorded none | `47` is GRE and `4`/`41` are IP-in-IP. `--capture-tunnels` widens the filter to reach inside them |
| `4` | The frame is shorter than a header it claims | `null` | Raise `--snaplen`. A cut frame is a capture setting, not a parser gap |
| `5` | A decoder rejected the bytes | `null` | Save a sample and open an issue |

The number is the whole point of the entry. "Unsupported link type" names no
action, and "unsupported link type 0" names three. `frames` counts the whole
run, `frames_in_window` counts the sample, and an entry whose `frames_in_window`
is `0` describes a problem that has already stopped.

`undecodable_reasons_dropped` counts frames whose specific number did not fit
the fixed-slot tables behind these counters. A non-zero value means the
breakdown adds up to less than `totals.undecodable_frames`, and the field
exists so that nobody has to discover the shortfall by subtracting.

#### Why 30 seconds is the ceiling

An MCP tool call blocks the agent that made it. The handler holds a request
slot for the whole window, and clients cancel a call that has not answered —
60 seconds is the common default. A window that can run for minutes turns a
diagnostic into a denial of service against the agent that asked for it.

Thirty seconds keeps the whole call inside half of that budget and still buys
a window worth having. A trunk at 10,000 packets per second puts 300,000
packets through it, which is enough for a drop rate to mean something. For a
longer view, call the tool repeatedly and read `totals`.

Divide by `window.observed_ms`, never by `sample_seconds`. A loaded runtime
wakes the handler late, and the response reports the wall clock precisely so
that a rate does not inherit that error.

**Clock discipline.** The response carries a `clock` object — `synchronized`,
`max_error_us`, `est_error_us`, `available` — read from `adjtimex(2)` at report
time rather than cached at startup, since a host can lose its time source while
sipnab runs.

It is irrelevant to a single capture, where one clock stamped every packet and a
constant offset cancels out of every interval. It matters the moment you
correlate across NODES: `find_correlated`'s `timing_heuristic` matches dialogs
that started within the leg-correlation window of each other — two seconds
unless `--leg-correlation-window` says otherwise — and that is smaller than the
skew an undisciplined host accumulates in a day. A clock three seconds fast
fails to correlate legs that belong together, and a slow one pulls unrelated
legs inside the window. Widening the window to reach a B2BUA that dips a
database before placing the outbound leg widens this exposure with it. Read `clock` from both servers before trusting a time-based
match, and prefer any of the six identifier strategies — `session_id`,
`x_call_id`, `charging_vector_related_icid`, `sdp_origin`,
`charging_vector_icid` or `via_branch` — none of which care what time anyone
thinks it is.

`available: false` means the platform gave no answer — NOT that the clock is
bad. The two are different facts and only one of them is a problem.


### `get_capture_report`

The whole-capture analysis, the one `--report` prints. Backed by
[`analysis::analyze`](https://github.com/NormB/sipnab/blob/main/src/analysis.rs)
and rendered by `output::analysis_report`.

[`get_dialog_report`](#get_dialog_report) and [`render_ladder`](#render_ladder)
both answer for ONE Call-ID, so everything the report says about the capture as
a whole had no MCP path: orphaned media, STUN, ICMP errors quoting SIP or RTP,
and what the retention caps shed. [`capture_status`](#capture_status) could hand an agent a count, and no tool
could expand it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `format` | string? | `"json"`, `"markdown"` or `"text"`. Anything else fails with `unknown format 'x', expected json\|markdown\|text`. | `"json"`. |

Frames read comes from the same process-global counter the Prometheus scrape
reports (`sipnab_capture_packets_total`), so the denominator here is the one
every other number in the run measures against.

A capture with no findings still answers with the clean line rather than an
empty body, because silence is indistinguishable from the tool not having run:

```jsonc
// get_capture_report { "format": "text" }
// A capture with findings names each one; a clean capture says so outright.
"Capture analysis: 2 finding(s) across 1 dialog(s), 2 stream(s), 535000 frame(s) read."
```

**`json` is the default and returns an OBJECT**, serialized from the analysis
itself — `findings`, `dialogs_examined`, `streams_examined`, `frames_read` and
`complete`. Read `complete` before the findings: it is `false` when the capture
lost packets, hit a retention cap, or held frames no decoder could read, and a
findings list from such a capture is a **floor, not a total**.

`complete` also reads `false` while the load runs, and for a source whose read
stopped before its end. It answers "did sipnab read all of its input", so a file
still arriving cannot satisfy it. Until this gate landed it ignored the load
entirely and read backwards during one: on a 100 MB capture the same tool in the same
session answered `complete: true` at `frames_read: 312` and `complete: false` at
`frames_read: 365747` — `true` over 0.09% of the file, `false` once the whole
file had arrived. The field keeps its name and its meaning. What changed is that
the two facts under it, `source_exhausted` and `source_stopped_early`, now gate
it and travel beside it.

`markdown` and `text` answer with a rendered document, which has no envelope to
carry either flag, so the document states the fact itself. A report drawn while
the capture is still loading, or over one whose read stopped before its end,
ends with an `INCOMPLETE RUN` block naming each reason — the same block
`--report` appends, and for the same reason: the reader of a rendered report has
no `$?` and no JSON in front of them, and a partial report looks exactly like a
whole one. A capture read in full adds nothing and the report ends where it
always did. Ask for `json` when you want the two booleans as fields.

> Before 0.5.125 this default returned the TEXT rendering. `format` chooses
> between markdown headings and plain text inside the renderer and never had a
> JSON arm, so the tool asked for JSON, got prose, and fell back to a text
> block. An agent that called it with no argument received prose and nothing to
> say the structure it asked for was never there.

`GET /v1/report` answers the same question over REST.

### `list_captures`

Capture files in the configured root, with sizes.

**Parameters:** none.

**It lists `.pcap` and `.pcapng` only**, matched case-insensitively, and skips
directories. That is narrower than what [`open_capture`](#open_capture) accepts,
which is any readable capture the name resolves to — a `.cap` file sitting in
the root opens fine and never appears here, so an agent that treats this listing
as the whole set it may open misses it. Ask the operator, or try the name.

```jsonc
list_captures {}
```

Without `--mcp-file-root` the whole file-tool group is off, and this answers
with a refusal rather than an empty list — "no directory configured" and "the
directory is empty" are different facts:

```jsonc
{ "code": -32602,
  "message": "file tools are disabled: start sipnab with --mcp-file-root <DIR>" }
```

Otherwise it answers with `captures` sorted by filename, plus
`schema_version`. Running it against `tests/pcap-samples` returns 29 of the
directory's 35 entries. The six it leaves out are five `.cap` captures and one
directory:

```jsonc
// list_captures {}
{
  "schema_version": 1,
  "captures": [
    { "filename": "Asterisk_ZFONE_XLITE.pcap", "bytes": 255581 },
    { "filename": "DTMFsipinfo.pcap", "bytes": 25429 },
    { "filename": "b2bua-asterisk.pcapng", "bytes": 114952 }
    // ... 26 more
  ]
}
```

### `list_dialogs`

Returns one page of dialog summaries from the live capture store.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `filter` | string? | A diagnostic alias name — `problems`, `slow-setup`, `short-calls`, `one-way`, `nat-issues`, `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media` — **or** a raw [filter DSL](filter-dsl.md) expression. Anything else fails with `invalid_params` naming the position it stopped parsing at. | Every dialog in the store matches. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 unless the operator changed it). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest dialog. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `dialogs` | `DialogSummary[]` | This page, oldest first (ties broken by Call-ID). |
| `returned` | usize | Rows in `dialogs`, so counting the array is never necessary. |
| `total_matched` | usize | Dialogs matching the filter across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `truncated` | bool | `true` when matches remain after this page. Absent while the answer is not whole — see the sixth rule above. |
| `source_exhausted` | bool | `true` once sipnab has read the capture source to its end. |
| `source_stopped_early` | bool | `true` when a source's read ended before the source did. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered — see [`capture_status`](#capture_status). A changed `instance` voids every cursor you hold. |

Each `DialogSummary` row carries `call_id`, `state`, `method`, `from_user`,
`to_user`, `msg_count`, `duration_sec`, `created_at`, `updated_at`, a `timing`
object (`pdd_ms`, `setup_ms`, `retransmits`, `duration_ms`, each `null` when the
capture never showed it) and a `frame` pointer for
[`show_evidence`](#show_evidence). `from_user` and `to_user` arrive fenced,
because an endpoint chose them.

The example below runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng),
which holds 1334 dialogs. `limit: 2` therefore reports 2 of 1334 — and says so:

```jsonc
// list_dialogs { "limit": 2 }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-1-synth@192.0.2.10",
      "state": "Registered",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 7,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.303349+00:00",
      "updated_at": "2016-11-17T21:52:35.339349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#0@0f039ad14545671e"
    },
    {
      "call_id": "call-2-synth@192.0.2.10",
      "state": "Registered",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 7,
      "duration_sec": 0.036,
      "created_at": "2016-11-17T21:52:35.403349+00:00",
      "updated_at": "2016-11-17T21:52:35.439349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#7@f7951dd197e419b9"
    }
  ],
  "returned": 2,
  "total_matched": 1334,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:35.403349+00:00|call-2-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1ae7318cb5c11b1a306dd-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

Two fields in there catch people writing a client from this page. `from_user`
reads `⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧`, not `ua-a`, so a
comparison against the bare name never matches — strip the markers, or match
inside them. And `capture_identity.node` names the box that answered, which
decides whose capture a fact came from once an agent holds several servers.

#### Why the page object, and why the cursor is compound

A bare array hides its own size. This tool returned 50 of 2311 dialogs on a
production capture with nothing in the reply to mark the cut, and `limit` alone
could not close the gap: requests above 1000 clamp to the hard cap, leaving 1311
dialogs no call could reach. An agent asked "how many calls failed?" counts the
rows it holds and answers with that number, so a short list does not read as an
incomplete answer — it reads as a confident wrong one. `total_matched` and
`truncated` name the shortfall. `cursor` closes it.

`next_cursor` pairs a timestamp with a Call-ID for the same reason
[`tail_dialogs`](#tail_dialogs) does. Dialogs share a `created_at` routinely — a
burst of registrations lands on one millisecond — and a bare timestamp forces a
choice between dropping the rest of that group and serving it twice. Resuming
after the `(created_at, Call-ID)` pair splits the group exactly where the page
ended. **Pass the value back unmodified.** A bare RFC 3339 timestamp still
parses, so rebuilding one by hand fails silently rather than erroring.

The two tools page on different clocks, deliberately. `tail_dialogs` follows
`updated_at`, because reporting change is its job. `list_dialogs` pages on
`created_at`, which never moves: a dialog that gains one more message mid-sweep
would jump forward in an `updated_at` ordering, past a cursor that had already
gone by, and vanish from the listing.

### Narrowing a row with `fields`

`list_dialogs`, `find_problems`, `tail_dialogs` and `search_by_time` take an
optional `fields` array. This surface already bounds rows three ways -- `limit`, `--mcp-max-rows`, and
cursors -- and it bounded columns not at all, so asking for a page to read two
values off it still paid for every other value on every row.

```jsonc
// list_dialogs { "limit": 200, "fields": ["state", "final_status_code"] }
{ "call_id": "1-1966@10.0.2.20", "state": "Completed", "final_status_code": 200 }
```

Three rules, each there for a reason:

- **`call_id` always survives**, listed or not. Every follow-up tool here takes
  a Call-ID, so a row an agent cannot address is a row it can do nothing with.
- **An unknown name fails**, naming both the typo and the fields the row
  actually carries. Silently returning rows without the field asked for reads
  as "no such data", which is a wrong answer rather than an error.
- **The envelope is never projected.** `total_matched`, `truncated`,
  `next_cursor` and `capture_identity` are how a caller knows what it did NOT
  get, and dropping them to save bytes would trade away the very thing the
  bounds exist to report.

A field already absent from a row stays absent rather than reappearing as
null: the projection runs on the serialized page, so `skip_serializing_if`
still decides what exists.

### `timeline`

Call volume over time, in fixed-width buckets.

`aggregate_dialogs` answers "how many, grouped by what" and is blind to WHEN.
A trunk that failed for ninety seconds and a trunk that fails one call in
forty produce the same bucket counts, and only the shape over time separates
them. This returns one row per interval so the shape is readable without
fetching every dialog and bucketing them in the model's head -- the counting
task language models get wrong most reliably.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `bucket_seconds` | integer? | Greater than zero. A zero-width bucket describes no interval and every dialog would fall into all of them at once, so it fails with `invalid_params` rather than dividing by zero. | 60. |

```jsonc
// timeline { "bucket_seconds": 60 }
[
  { "start": "2026-08-28T04:00:00Z", "bucket_seconds": 60, "dialogs": 412 },
  { "start": "2026-08-28T04:01:00Z", "bucket_seconds": 60, "dialogs": 0 },
  { "start": "2026-08-28T04:02:00Z", "bucket_seconds": 60, "dialogs": 377 }
]
```

Two properties are deliberate. Buckets align to the **epoch**, not to the
first dialog, so two captures of the same window produce identical boundaries
and line up against each other. Aligning to the earliest call would instead
shift every boundary whenever that call changed. The series also **keeps empty
buckets**, as the middle row above shows -- a gap is a finding, and a series
that silently drops it renders as continuous traffic on a shorter axis.

### `top_talkers`

Ranks the busiest participants: IPs, user agents, or dialled prefixes.

`aggregate_dialogs` and `group_dialogs` group DIALOGS, and a dialog has two
ends. Asking "who is busiest" of a dialog-shaped answer forces the caller to
pick one end and ignore the other, which reports a trunk's traffic as belonging
to whichever side the schema happened to name first. This counts PARTICIPANTS
instead.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `by` | string | `ip`, `ua` or `prefix`. Anything else fails with `invalid_params` naming the legal set. | Required. |
| `limit` | integer? | Bounded by `--mcp-max-rows`. | The usual row default. |
| `filter` | string? | Alias or DSL, the same vocabulary every other tool takes. | The whole store. |
| `prefix_digits` | integer? | How many leading digits make a prefix bucket. | 4. |

```jsonc
// top_talkers { "by": "ip", "limit": 3 }
{
  "by": "ip",
  "rows": [
    { "value": "203.0.113.9", "dialogs": 812, "share_pct": 60.9 },
    { "value": "198.51.100.4", "dialogs": 511, "share_pct": 38.3 },
    { "value": "192.0.2.77", "dialogs": 44, "share_pct": 3.3 }
  ],
  "counts": "participants"
}
```

**The shares deliberately sum above 100%.** One dialog counts for every talker
in it, so a two-ended call adds to two rows. The response says `counts:
"participants"` rather than leaving a reader to discover it from arithmetic that
looks broken. `by: "prefix"` is the exception and does partition, because a call
has one dialled number.

`ip` reads senders off the MESSAGES, not off the dialog's opening addresses: a
proxy that re-originates mid-dialog is invisible in the dialog record and would
otherwise never appear. `ua` reads `User-Agent` from requests and `Server` from
responses, both sender-written and therefore fenced. `prefix` strips a leading
`+` before taking digits, so `+15551234` and `15551234` are one destination
rather than two.

### `aggregate_dialogs`

Counts dialogs grouped by one field, inside the store.

Counting is the operation a language model gets wrong most reliably, and this
page documents that failure elsewhere: an agent asked "how many calls failed?"
counts the rows it is holding and answers with that number. The page object
fixed exactly one count — `total_matched`, for one filter. Every other count
still meant fetching pages and tallying them in the model's head, or issuing N
filtered queries with the buckets guessed in advance.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `group_by` | string | One of `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip`, `rtp.codec`. Anything else fails with `invalid_params` naming the legal set. | Required. |
| `filter` | string? | Alias or DSL, applied before grouping. | No filter — the whole store. |
| `top_n` | integer? | Bounded by `--mcp-max-rows`, the same knob that bounds dialog rows — not a second ceiling of sipnab's own. Anything past it lands in `other_count` rather than disappearing. | The same default as any row limit. |

```jsonc
// aggregate_dialogs { "group_by": "response_code", "filter": "state == 'Failed'" }
{
  "group_by": "response_code",
  "buckets": [ { "value": "503", "count": 412 }, { "value": "486", "count": 77 } ],
  "other_count": 11,
  "distinct_values": 6,
  "total_matched": 500
}
```

**The buckets plus `other_count` always equal `total_matched`.** A truncated
aggregate that does not say what it left out is a wrong total rather than a
partial one, so nothing is silently dropped — including nulls, which become the
literal `(none)`: "how many dialogs carry no User-Agent" is a real question.

**One dimension, and no time bucketing.** That is a deliberate cap, not an
unfinished feature. Two dimensions is a pivot table, a pivot table wants a UI,
and [positioning](https://github.com/NormB/sipnab/blob/main/docs/design/positioning.md)
puts that outside what sipnab is. Narrow the window with `filter` instead.

**Grouping by `from.user`, `to.user` or `ua` returns fenced values.** Those are
text the packet's sender wrote, and they reach a model here exactly as they
would in a row. A state name, a status code, an IP or a codec is sipnab's own
derivation and comes back verbatim — fencing those would tell the agent to
distrust the analysis.

### `group_dialogs`

Carrier metrics per group, computed inside the store.

[`aggregate_dialogs`](#aggregate_dialogs) answers "how many" and stops.
Every question beginning with WHICH — which trunk is failing, which User-Agent
has the worst audio, which hour it started — wants a rate, and a rate is the one
thing a language model cannot recover from a page of rows: it would have to hold
every dialog, classify each outcome and divide. Agents stop early and answer
from the rows they happen to hold, which is how a truncated page becomes a
confident verdict about a carrier. So this tool computes the rate where the
dialogs live and reports the population underneath it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `by` | string | ONE of `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip`, `rtp.codec`, `to_domain`, `hour`, `next_hop`. Anything else — including two names in one string, such as `"src.ip,hour"` — fails with `invalid_params` naming all twelve. | Required. |
| `metrics` | string[]? | Any of `count`, `asr`, `ner`, `acd`, `pdd_p50`, `pdd_p95`, `mos_p10`, `retransmit_rate`. The tool sorts and de-duplicates the list, so the key order in the answer never depends on the order you wrote. An unknown name fails naming all eight. | All eight. |
| `filter` | string? | Alias or DSL, applied before grouping — the same vocabulary [`list_dialogs`](#list_dialogs) takes. | No filter — the whole store. |
| `top_n` | integer? | Bounded by `--mcp-max-rows`, the same knob that bounds dialog rows. Everything past it lands in `other_count` rather than disappearing. | 50, the same default as any row limit. |

```jsonc
// group_dialogs { "by": "next_hop", "metrics": ["count", "asr", "ner"], "top_n": 2 }
{
  "schema_version": 1,
  "group_by": "next_hop",
  "metrics": ["asr", "count", "ner"],
  "units": { "asr": "percent", "count": "dialogs", "ner": "percent" },
  "groups": [
    {
      "value": "203.0.113.9:5060",
      "count": 412,
      "metrics": { "asr": 71.6, "count": 412.0, "ner": 98.27 },
      "not_grounded": {},
      "population": {
        "dialogs": 412, "seizures": 405, "answered": 290, "delivered": 398,
        "completed_calls": 288, "pdd_measured": 401,
        "mos_grounded_dialogs": 260, "retransmits": 14
      }
    },
    {
      "value": "203.0.113.10:5060",
      "count": 77,
      "metrics": { "asr": null, "count": 77.0, "ner": null },
      "not_grounded": {
        "asr": "no INVITE in this group reached a final response, so nothing in it was a decided call attempt",
        "ner": "no INVITE in this group reached a final response, so nothing in it was a decided call attempt"
      },
      "population": {
        "dialogs": 77, "seizures": 0, "answered": 0, "delivered": 0,
        "completed_calls": 0, "pdd_measured": 0,
        "mos_grounded_dialogs": 0, "retransmits": 0
      }
    }
  ],
  "other_count": 11,
  "distinct_values": 6,
  "total_matched": 500,
  "capture_identity": { "node": "capture-01", "instance": "1d1a718cb5c33b7c52754-1",
                        "dialog_generation": 4113, "stream_generation": 902 }
}
```

**A `null` metric is an answer, and `not_grounded` says which population went
missing.** The second group above holds 77 REGISTER dialogs. An ASR of `0` there
would name a working registrar a dead trunk, which is a wrong answer rather than
a missing one. That is the discipline `mos_grounded` already applies to a MOS on
an unpublished codec, extended to the other seven metrics.

**Every figure names its unit in the answer.** An ASR of `0.65` and an ASR of
`65` describe the same trunk and differ by a factor of a hundred, so `units`
travels with the numbers rather than living on this page. `asr` and `ner` are
PERCENTS here and in [`evaluate_expectations`](#evaluate_expectations), which
takes its thresholds in the same unit: a rule reads `"value": 99`, matching the
number you read in a report. The two tools disagreed on this before 0.5.130 --
one percent, one a ratio -- and a threshold copied between them was wrong by a
hundredfold in the direction that always passes.

The eight metrics, and what each one measures:

| Metric | Unit | Definition | Population it rests on |
|---|---|---|---|
| `count` | dialogs | Dialogs in the group. | `dialogs` |
| `asr` | percent | Answer-seizure ratio: 2xx answers over seizures. | `seizures` |
| `ner` | percent | Network effectiveness ratio ([ITU-T E.411](https://www.itu.int/rec/T-REC-E.411)): seizures the network delivered over seizures. | `seizures` |
| `acd` | seconds | Average call duration: mean CONVERSATION time, not dialog span. | `completed_calls` |
| `pdd_p50`, `pdd_p95` | milliseconds | Post-dial delay percentiles, nearest rank. | `pdd_measured` |
| `mos_p10` | mos | Tenth-percentile MOS across dialogs holding a stream sipnab can score, worst stream per dialog. | `mos_grounded_dialogs` |
| `retransmit_rate` | retransmissions per dialog | `retransmits` over `dialogs`. Never refused — a group exists because a dialog fell into it. | `dialogs` |

**A seizure is an INVITE dialog that reached a final response.** Both halves
carry weight. A REGISTER is not a call attempt, and an INVITE still ringing when
the capture ended has not failed — counting it as a failed seizure reports a live
capture as an outage that looks worse the earlier you look.

**NER credits the far end where ASR does not.** A trunk full of 486s has an ASR
of zero and works perfectly: the network delivered every call and the callee was
busy, so reading the ASR alone escalates a healthy carrier. The five codes that
count as delivered are `480`, `486`, `487`, `600` and `603` — the callee
unavailable, busy, busy everywhere, declining, or the CALLER hanging up on a
call that had already reached the far end. **`408 Request Timeout` is
deliberately absent.** A proxy emits it both for a silent phone and for an
unreachable next hop, so crediting it would credit the network for calls that
may never have arrived, which is the exact misattribution NER exists to prevent.

**ACD times the conversation, not the dialog.** A call that rang for five
seconds, talked for sixty and took one more on the BYE handshake spans 66
seconds and contributes 60. Averaging the span bills the caller for the
ring-back, which is not what any carrier means by average call duration.

**Percentiles use nearest rank, with no interpolation.** An interpolated p95
returns a number no call experienced, and these figures get quoted back to a
carrier as evidence about real calls. Every metric rounds to two decimal places,
because a ratio over three dialogs is not accurate to fourteen — and the
population sits beside it, so anyone wanting the exact ratio divides the two
integers.

**Groups rank by dialog count, largest first, ties broken by value.** Ranking by
the metric would answer a different question per call and could not page against
`other_count`. That remainder carries a count and nothing else, deliberately: an
ASR averaged over the groups that fell off the end is an average of averages
across the smallest groups, which is the arithmetic that turns one busy trunk
into a capture-wide verdict. The groups plus `other_count` always equal
`total_matched`.

**Three dimensions live here and not in `aggregate_dialogs`**, and the set is a
strict SUPERSET rather than an overlapping one, so an agent never has to
discover per tool which vocabulary it is talking to:

| Dimension | Value | Fenced? |
|---|---|---|
| `to_domain` | The host half of the To URI, port stripped, IPv6 brackets kept. | Yes — the sender wrote it. |
| `hour` | The calendar hour the dialog opened in, aligned to the epoch like [`timeline`](#timeline) buckets, RFC 3339. | No |
| `next_hop` | `host:port` the opening message went to, read off the IP and transport headers. | No |

Fencing follows the same rule as everywhere else. `to_domain`, `to.user`,
`from.user` and `ua` arrive wrapped in `⟦untrusted-capture-data⟧` because a
sender chose them. A state name, a status code, an address, a codec and
`next_hop` come back verbatim, because they are sipnab's own derivation and
telling an agent to distrust them would tell it to distrust the analysis.

Note `next_hop` names the peer only from the vantage point of a capture taken
beside the sender, which is where a proxy's own trunk traffic gets captured.

One dimension, for the reason [`aggregate_dialogs`](#aggregate_dialogs) gives:
two is a pivot table, and a pivot table wants a UI. Narrow with `filter`
instead. Reach for `aggregate_dialogs` when a bare count answers the question —
it does the same walk without computing seven metrics.

### `server_capabilities`

What this binary can do and what this server permits. Ask before requesting
decryption, HEP, a file export or a capture swap: a build without the feature,
or a server without the flag, fails confusingly otherwise.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "version": "0.5.143",
  "features": ["api", "hep", "mcp", "native", "tls", "tui"],
  "can_decrypt": true,           // tls
  "can_hep": true,               // hep
  "can_plugins": false,          // plugins
  "runtime": {
    "mcp_file_root": "/var/spool/sipnab-captures",  // null when unset
    "mcp_allow_shutdown": false,
    "mcp_allow_open_capture": true,
    "mcp_allow_save_findings": false
  }
}
```

`features` comes from `cfg!` at compile time, so it cannot claim a feature the
binary does not have. `runtime` is a different question — what the **operator**
turned on — and no compile-time check can answer it. Without it an agent
discovers the setup by calling a tool and collecting a refusal, and a refusal
mid-investigation reads as a dead end rather than as a server it was never
allowed to use that way.


### `reconcile_orphans`

An orphaned stream is media with no dialog. `rtp_stats` names which streams
have none. This tool says why each one has none, which is the part an incident
needs.

Three verdicts, and the difference between them is the point:

| verdict | what it means |
|---|---|
| `relay-asserted-but-no-dialog` | a relay named this endpoint and no captured dialog claims it — the **signaling** is missing, not the media |
| `signaled-but-no-dialog` | SDP named it and no dialog holds it — either the capture missed the dialog, or its SDP arrived before capture started |
| `never-named` | nothing in this capture named this endpoint at all |

`relay_was_consulted` rides alongside the verdict and matters more than it looks. A
`never-named` verdict with `relay_was_consulted: false` means **nobody asked** —
an absence of evidence, not evidence of absence. It is deliberately not
reported using the `Unattributed` vocabulary, which answers "sipnab asked the
relay and it said X": this server holds no live reconciler, and claiming an answer
nobody received is the failure that vocabulary exists to prevent.

```jsonc
// reconcile_orphans { "limit": 2 }
{
  "orphans": [
    {
      "ssrc": 305419896,
      "src": "127.0.0.1:5094",
      "dst": "127.0.0.1:5084",
      "named_endpoint": null,
      "asserted_by": null,
      "reason": "never-named",
      "note": "nothing in this capture named this endpoint. A relay could answer it and none was asked: that is an absence of evidence, not evidence of absence"
    }
  ],
  "total_orphans": 4,
  "truncated": true,
  "relay_was_consulted": false,
  "schema_version": 1
}
```

## Find — narrow to the calls that matter

You know something is wrong but not which call. These cut a capture down to the dialogs worth reading: by symptom, by text, by time, or by relationship to a call you already have.

### `find_problems`

Convenience wrapper over `list_dialogs` that ORs each named alias, then ANDs
the optional `filter`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds` | string[]? | One or more of the ten diagnostic aliases listed under [`list_dialogs`](#list_dialogs), OR-ed together. An unknown name fails with `invalid_params`. An empty array behaves as omitted. | `["problems"]`. |
| `filter` | string? | An alias name or a raw [DSL](filter-dsl.md) expression, **ANDed** with the alias match. | The alias match alone decides the page. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim. | Starts at the oldest match. |

Returns the same page object as [`list_dialogs`](#list_dialogs) — `dialogs`,
`returned`, `total_matched`, `truncated`, `next_cursor`, `schema_version` and
`capture_identity` — with the same meanings and the same fenced `from_user` and
`to_user`.

`filter` is what makes this the triage entry point rather than a firehose. The
aliases answer "is this call interesting". The filter answers "is it one of
mine", so `{"kinds": ["problems"], "filter": "dst.ip == '203.0.113.9'"}` asks a
question that previously needed a client-side join. The two AND together —
ORing them would widen the sweep instead of narrowing it.

An unknown alias, or a filter that neither names an alias nor parses, returns
invalid_params (-32602) naming the offending value.

```jsonc
// find_problems { "limit": 1, "filter": "msg_count > 5" }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-1197-synth@192.0.2.10",
      "state": "Failed",
      "method": "REGISTER",
      "from_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧ua-a⟦/untrusted-capture-data⟧",
      "msg_count": 6,
      "duration_sec": 0.03,
      "created_at": "2016-11-17T21:54:34.903349+00:00",
      "updated_at": "2016-11-17T21:54:34.933349+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": null,
        "retransmits": 0,
        "duration_ms": null
      },
      "frame": "tests/pcap-samples/sipp-branch-scenario.pcapng#8028@42ba0f02341ca2f7"
    }
  ],
  "returned": 1,
  "total_matched": 6,
  "truncated": true,
  "next_cursor": "2016-11-17T21:54:34.903349+00:00|call-1197-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1ae7318cb5c11b1a306dd-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

The same capture answers `find_problems {}` with `total_matched: 127`. Six of
those 127 carry more than five messages, which is what the filter selects.

### `search_messages`

Case-insensitive substring search over method, status, From, To,
User-Agent, and body across all dialogs.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `query` | string | Any substring. Matching ignores case. | Required — the call fails. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 hits. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>#<zero-padded message index>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest match. |

**Returns** — the same page shape [`list_dialogs`](#list_dialogs) returns, not
a bare array, plus the provenance note as a second content block:

| Field | Type | Description |
|---|---|---|
| `hits` | object[] | This page of `{ call_id, message_index, snippet }`, ordered by the dialog's `created_at`, then Call-ID, then message index. |
| `returned` | usize | Rows in `hits`. |
| `total_matched` | usize | Messages matching the query across the **whole store**, whatever `limit` and `cursor` say. This is the number that answers "how many". |
| `truncated` | bool | `true` when matches remain after this page. Absent while the answer is not whole — see the sixth rule above. |
| `source_exhausted` | bool | `true` once sipnab has read the capture source to its end. |
| `source_stopped_early` | bool | `true` when a source's read ended before the source did. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |
| `schema_version` | u32 | `1` for this shape. |
| `capture_identity` | object | Which capture answered. A changed `instance` voids the cursor. |

`snippet` holds the whole raw message, fenced, and stops at 4 KB. Pass `call_id`
and `message_index` straight to [`get_message`](#get_message) for the parsed
form.

> **Count from the fields, never from the rows.** A capped result and a
> complete one hold the same shape, so the row count cannot tell them apart:
> on the sample capture below, `{ "query": "REGISTER" }` returns 50 rows and
> `limit: 1000` returns 1000, while 1334 messages match. `total_matched` is
> the number that answers "how many are there", `truncated` says whether you
> are seeing all of them, and `next_cursor` reaches the rest.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng):

```jsonc
// search_messages { "query": "REGISTER", "limit": 1 }
{
  "schema_version": 1,
  "hits": [
    {
      "call_id": "call-1-synth@192.0.2.10",
      "message_index": 0,
      "snippet": "⟦untrusted-capture-data⟧REGISTER sip:example.net SIP/2.0\r\n…⟦/untrusted-capture-data⟧"
    }
  ],
  "returned": 1,
  "total_matched": 1334,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:35.303349+00:00|call-1-synth@192.0.2.10#0000000000",
  "capture_identity": {
    "node": "capture-01",
    "instance": "12100b18cb6971cf461cff-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

Passing that `next_cursor` back returns `call-2-synth@192.0.2.10` and reports
the same `total_matched: 1334`: the total describes the store, not the page.
The index half of the cursor carries leading zeros because the server compares
the cursor as text — rebuild one by hand and `#10` sorts before `#2`, which
silently skips eight messages of a dialog. Pass it back exactly as it arrived.

### `search_by_time`

Returns dialogs whose first message falls in the window, oldest first.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `start` | string | An inclusive RFC 3339 instant, such as `"2026-07-31T14:00:00Z"`. A malformed one fails with `start 'x' is not RFC 3339`. | Required — the call fails. |
| `end` | string? | An exclusive RFC 3339 instant after `start`. At or before `start` fails with `invalid_params` (-32602). | Everything from `start` onward. |
| `filter` | string? | An alias name or a raw [DSL](filter-dsl.md) expression, ANDed with the window. | The window alone decides the page. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339 created_at>\|<Call-ID>`). A malformed timestamp half fails with `invalid_params`. | Starts at the oldest dialog in the window. |

**Returns** `{ dialogs, returned, total_matched, truncated, next_cursor,
capture_identity, schema_version }`.
Each row carries `call_id`, `created_at`, `state` and `final_status_code` —
**a narrower row than [`list_dialogs`](#list_dialogs) returns**, with no
`msg_count`, no `from_user`, no `timing` and no `frame`. No markers appear
here either, because none of those four fields is free text. Feed a `call_id` to another
tool when you need the rest.

`total_matched` counts every dialog in the window before `limit` applies, so a
small answer from a quiet window reads differently from a truncated one.

`filter` turns "failed calls between 14:00 and 14:05" into a single call. The
window narrows first and the filter runs over what survives.

The example runs against [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng). The
same window without a filter answers `total_matched: 247`:

```jsonc
// search_by_time { "start": "2016-11-17T21:52:35Z", "end": "2016-11-17T21:53:00Z",
//                  "filter": "problems", "limit": 2 }
{
  "schema_version": 1,
  "dialogs": [
    {
      "call_id": "call-10-synth@192.0.2.10",
      "created_at": "2016-11-17T21:52:36.203349+00:00",
      "final_status_code": 403,
      "state": "Failed"
    },
    {
      "call_id": "call-25-synth@192.0.2.10",
      "created_at": "2016-11-17T21:52:37.703349+00:00",
      "final_status_code": 403,
      "state": "Failed"
    }
  ],
  "returned": 2,
  "total_matched": 16,
  "truncated": true,
  "next_cursor": "2016-11-17T21:52:37.703349+00:00|call-25-synth@192.0.2.10",
  "capture_identity": {
    "node": "capture-01",
    "instance": "12100b18cb6971cf461cff-1",
    "dialog_generation": 9015,
    "stream_generation": 0
  }
}
```

**`truncated: true` is not a dead end.** Pass `next_cursor` back to
continue through the window. `total_matched` keeps counting the whole window
rather than the remainder, so it does not shrink as you page — without a
cursor the only way past a truncated window would be to narrow it, putting
every row past the 1000-row ceiling out of reach. The cursor is
the same compound form [`list_dialogs`](#list_dialogs) issues, and it is opaque:
pass it back exactly as it arrived.

### `validate_filter`

Compiles a Filter DSL expression, counts what it selects, and returns no rows.

The DSL narrows [`list_dialogs`](#list_dialogs), [`find_problems`](#find_problems),
[`search_by_time`](#search_by_time), [`aggregate_dialogs`](#aggregate_dialogs)
and [`group_dialogs`](#group_dialogs), and before this tool every way of trying
an expression cost a page. An agent converging on a working filter — widen it,
narrow it, try the other field name — paid for a page of fenced summaries per
attempt and discarded every row. The two failure modes also look alike from
outside: a malformed expression comes back as `invalid_params`, which lands in
the error channel where a model acts on it least, and an expression that parses
but selects nothing returns the same empty page as an empty capture.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `expr` | string | A raw [filter DSL](filter-dsl.md) expression, **or** one of the diagnostic aliases [`list_dialogs`](#list_dialogs) takes. Nothing you can put here fails the call. | Required — the call fails. |

**A parse failure is a successful call.** Every other tool rejects a bad filter
with `invalid_params`, which is right there and wrong here: learning what is
wrong with an expression is the entire point of this tool, and an error object
carries that message where a model is least likely to act on it. So a bad
expression answers `valid: false` with the parser's own text — position, caret
and hint included — and the only error this tool raises is one it did not
expect.

```jsonc
// validate_filter { "expr": "state = Failed" }
{
  "schema_version": 1,
  "expr": "state = Failed",
  "valid": false,
  "error": "invalid filter 'state = Failed': unexpected input at position 6: '='\n  state = Failed\n        ^\nvalid operators: ==, !=, <, <=, >, >=, =~ (regex)\nsee docs/filter-dsl.md for fields, values, and diagnostic aliases",
  "total_matched": null,
  "total_dialogs": 2
}
```

`total_matched` stays `null` on a parse failure rather than dropping to `0`,
because a zero there reads as "parsed, matched nothing" — the opposite of what
happened. Fix the expression and the count arrives, measured against the whole
store with no cursor and no truncation. The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// validate_filter { "expr": "state == 'Completed' and rtp.mos < 4.5" }
{
  "schema_version": 1,
  "expr": "state == 'Completed' and rtp.mos < 4.5",
  "valid": true,
  "error": null,
  "total_matched": 1,
  "total_dialogs": 2
}
```

**Read `total_dialogs` beside `total_matched`.** It is the denominator, and it
comes back even on a parse failure: 0 matches out of 0 dialogs is an empty
capture, 0 out of 4000 is an expression that selects nothing, and no single
number separates them.

Aliases expand here exactly as they do everywhere else, because this tool calls
the same compiler the other tools call. A second parser would eventually accept
an expression `list_dialogs` then rejects, which is worse than no tool at all.
This response carries your own expression and two integers and nothing read off
the wire, so it appends no provenance note.

### `describe_endpoint`

Everything the capture holds about one participant.

The rest of this surface keys on Call-ID, which is the right shape for "why did
this call fail" and the wrong shape for the question that comes first. An
operator handed a complaint holds a phone, a trunk or a subscriber — an address
or a name — and wants to know what that thing has been doing. Agents reason in
entities too. Answering from a dialog-centric surface meant listing every
dialog, filtering client-side, and re-deriving per-entity facts the stores
already hold.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `ip` | string? | The endpoint's address, v4 or v6. Mutually exclusive with `user`. An unparseable value fails with `ip '...' is not an address`. | Give `user` instead. |
| `user` | string? | The user part of a SIP URI — `alice` from `sip:alice@example.com`. Mutually exclusive with `ip`. | Give `ip` instead. |
| `limit` | u32? | Bounds `recent_dialogs`, `problem_call_ids` and `findings` only. Ceiling is `--mcp-max-rows` (1000 by default), `0` means the default. | 50. |

**Exactly one selector, and the tool refuses both.** A caller passing an address
and a name means either their intersection or their union, the two give
different answers, and picking one silently would answer a question nobody
asked:

```jsonc
{ "code": -32602,
  "message": "give exactly one of ip or user, not both: the two select different sets, and whether you meant their intersection or their union changes the answer" }
```

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// describe_endpoint { "ip": "10.0.2.20", "limit": 1 }
{
  "schema_version": 1,
  "endpoint_kind": "ip",
  "endpoint": "10.0.2.20",
  "dialogs": 2,
  "by_method": { "INVITE": 2 },
  "by_state": { "Completed": 1, "InCall": 1 },
  "messages_sent": 5,
  "messages_received": 5,
  "calls": {
    "invites": 2, "with_final_status": 2, "failed": 0,
    "failure_rate_pct": 0.0, "by_final_status": { "200": 2 }
  },
  "registration": {
    "applicable": false, "dialogs": 0, "succeeded": 0, "failed": 0,
    "auth_loops": 0, "problem_call_ids": []
  },
  "user_agents": [],
  "streams": {
    "count": 2, "orphaned": 0, "packets": 839, "lost_packets": 0,
    "max_jitter_ms": 0.0061987502747274615, "codecs": ["PCMA", "PCMU"]
  },
  "findings": {
    "selectable": true, "findings": [], "total_matched": 0, "armed_kinds": [],
    "note": "No detection rule is armed on this server, so no finding could have been recorded. ..."
  },
  "recent_dialogs": [ /* one fenced dialog summary */ ],
  "truncated": true
}
```

**`limit` bounds the page and never the counts.** `dialogs`, `by_method`,
`by_state`, `calls` and `streams` describe every match, and only
`recent_dialogs` shortens — with `truncated` saying so. `recent_dialogs` runs
newest first, because an operator chasing a complaint wants what just happened,
and [`list_dialogs`](#list_dialogs) already pages the whole history oldest-first
for anyone sweeping it.

**An `ip` matches on MESSAGES, not on the dialog's opening addresses.** A dialog
records the socket pair its first message arrived on, so a proxy re-originating
mid-dialog, a re-INVITE from a second interface, and a BYE from the far side all
belong to the call while carrying different addresses. Matching the dialog
record alone would silently drop them, and the dropped ones are exactly the
transfers and hand-offs an operator is looking for.

**A `user` matches the From or To user part EXACTLY.** [RFC 3261
§19.1.4](https://www.rfc-editor.org/rfc/rfc3261#section-19.1.4) makes the user
part case-sensitive, so `Alice` and `alice` name two URIs, and folding the case
here would file one endpoint's traffic under the name of a second.

Three fields answer differently for a `user`, and each says so rather than
inventing a number:

| Field | For a `user` | Why |
|---|---|---|
| `messages_sent`, `messages_received` | Always `0` | A URI user part names a party, not a socket. Which party sent a given message does not follow from it, and a count derived from something else under this name would be worse than zero. |
| `streams` | The streams linked to that user's dialogs | A user has no media identity of its own, so the Call-IDs are the only bridge. An `ip` matches the media 5-tuple directly and therefore sees orphans too. |
| `findings.selectable` | `false`, with a `note` | The alert engine files every finding against a source IP, so no key selects a user. Re-ask with the address. |

That `selectable` flag matters because an empty list has three readings, not
one. `selectable: false` means nobody could ask. An empty `armed_kinds` means
nothing was watching, and the `note` says so in the same words
[`security_findings`](#security_findings) uses. Only on a server with a detector
armed does an empty list mean the endpoint stayed clean.

`failure_rate_pct` guards its denominator: it comes back `null`, not `0.0`, when
nothing reached a final status. A zero there hands a clean bill of health to an
endpoint nobody has measured. `registration.applicable` does the same job for
REGISTER — `false` means the endpoint sent none, so the four counts under it
read as "no input" rather than "no failures". A registration counts by the
REQUEST rather than by the dialog's method, because a REGISTER can arrive inside
a dialog something else opened once Call-ID reuse is in play, and a registration
nobody examined reports as a healthy one. The Call-IDs in `problem_call_ids` go
straight into [`diagnose_registration`](#diagnose_registration).

`user_agents` attributes a banner to whoever wrote it: `User-Agent` off requests
the address SENT and `Server` off responses it sent, per [RFC 3261
§20.41](https://www.rfc-editor.org/rfc/rfc3261#section-20.41) and
[§20.35](https://www.rfc-editor.org/rfc/rfc3261#section-20.35). Reading them off
received messages would file the far end's software under this endpoint. For a
`user` only `User-Agent` on requests whose From user matches counts, the one
case where the URI identifies the party that wrote the header. Values arrive
fenced, and so do the summaries in `recent_dialogs`.

### `tail_dialogs`

Incremental fetch of the dialogs updated after a cursor position.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `cursor` | string? | The previous response's `next_cursor`, verbatim (`<RFC 3339>\|<Call-ID>`). A bare RFC 3339 timestamp also parses, and filters strictly after it. | Starts from the beginning of the store. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 rows. |

Returns `{ dialogs, next_cursor, source_exhausted, source_stopped_early,
capture_identity }`, where
`dialogs` holds the same summary rows [`list_dialogs`](#list_dialogs) returns,
fencing included. This page object carries no `returned`, `total_matched` or
`truncated` — "how many are there" is not a question a tail can answer, because
the store keeps changing underneath it. Poll until `dialogs` comes back empty
and `source_exhausted` is `true`.

`next_cursor` is compound — `<RFC 3339>|<Call-ID>` — not a bare
timestamp. Dialogs can share an `updated_at`, so resuming from the
`(updated_at, Call-ID)` pair is what keeps a tie group split across a
page boundary from vanishing or arriving twice. Pass it back
unmodified. A client that rebuilds a bare timestamp from a dialog's
`updated_at` instead falls back to the pre-compound strictly after
filter and loses or repeats the tied dialogs — that bare-timestamp
form is still accepted, so the mistake is silent rather than an error.
`|` occurs in neither an RFC 3339 timestamp nor a valid Call-ID
([RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) `word`), so the split is unambiguous.

`source_exhausted` is `false` while more dialog updates can still
arrive and `true` once the capture source is fully drained — the end of
an `-I` pcap replay, or a live capture that has hit its
`--count`/`--duration`/`--autostop` stop condition. sipnab keeps
serving MCP after that, so this is the flag to poll to learn a replay
has finished: stop when it turns `true` instead of polling forever.

```jsonc
// tail_dialogs { "limit": 1 }
{
  "dialogs": [
    {
      "call_id": "1-1966@10.0.2.20",
      "state": "Completed",
      "method": "INVITE",
      "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
      "msg_count": 6,
      "duration_sec": 8.504,
      "created_at": "2016-11-26T14:52:59.666393+00:00",
      "updated_at": "2016-11-26T14:53:08.170676+00:00",
      "timing": {
        "pdd_ms": null,
        "setup_ms": 4,
        "retransmits": 0,
        "duration_ms": 8499
      },
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
    }
  ],
  "next_cursor": "2016-11-26T14:53:08.170676+00:00|1-1966@10.0.2.20",
  "source_exhausted": true,
  "source_stopped_early": false,
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

### `await_condition`

Waits until a filter selects at least one dialog, or until a deadline passes —
whichever happens first. One call replaces a [`tail_dialogs`](#tail_dialogs)
loop in which every turn that finds nothing still costs a model call.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `filter` | string | A named alias or a filter DSL expression, exactly what [`list_dialogs`](#list_dialogs) accepts. [`validate_filter`](#validate_filter) checks one without waiting. | Required — the call fails. |
| `timeout_seconds` | u32? | Ceiling is `--mcp-max-wait-seconds` (60 by default). Higher clamps to it and sets `timeout_clamped`. `0` means "look once and answer". | 30 seconds. |
| `poll_interval_ms` | u32? | Floor is 100 ms. sipnab raises anything smaller and returns the effective value. | 500 ms. |

Returns `{ matched, stopped_because, dialogs, returned, total_matched,
truncated, elapsed_ms, timeout_seconds, timeout_clamped, poll_interval_ms,
polls, scans, source_exhausted, capture_identity }`, where `dialogs` holds the
same summary rows [`list_dialogs`](#list_dialogs) returns, fencing included,
and is empty unless `matched` is `true`.

There is no page-size argument. This tool answers *did it happen*, and the rows
are evidence that it did rather than a page to work through — so it returns
what any list tool returns to a caller that named no `limit`: the default fifty
rows, cut to `--mcp-max-rows` when the operator set that lower.
[`list_dialogs`](#list_dialogs) with the same `filter` is the paging surface,
with the cursors and field projection that belong there. The response carries
reported either way, so a bounded page never reads as a smaller event than it
was.

**A deadline that passes is an answer, not an error.** It comes back as a
successful call carrying `matched: false` — because "the fault has not
reproduced" and "the tool broke" are different findings, and an agent has to
be able to tell them apart.

`stopped_because` names which of three endings this was, and the two negative
ones differ in whether asking again could ever help:

| Value | `matched` | Meaning |
|---|---|---|
| `condition_met` | `true` | The filter selected at least one dialog |
| `deadline` | `false` | The wait ran out. Not yet — asking again may still find it |
| `source_exhausted` | `false` | The capture source drained. Not ever, from this capture: the wait returns early rather than holding a slot to learn nothing |

The numbers this tool applies, and what moves each one:

- **Deadline default: 30 seconds** (`DEFAULT_TIMEOUT_SECONDS`). Used when the
  call names no `timeout_seconds`.
- **Deadline ceiling: 60 seconds** (`DEFAULT_MCP_MAX_WAIT_SECONDS`, which
  `await_condition` reads as `DEFAULT_MAX_WAIT_SECONDS`). The shipped value of
  `--mcp-max-wait-seconds`; the operator moves it, and a request above it is
  clamped rather than refused.
- **Poll default: 500 milliseconds** (`DEFAULT_POLL_INTERVAL_MS`). Used when
  the call names no `poll_interval_ms`.
- **Poll floor: 100 milliseconds** (`MIN_POLL_INTERVAL_MS`). A smaller request
  meets that floor, so no caller can turn this into a spin loop, and the
  response carries the value actually used.

`polls` counts the looks and `scans` counts the looks that ran the filter. They
differ because both stores number their revisions, so a look at a capture that
has not moved resolves by comparing two integers rather than by re-running
the filter — an idle capture costs almost nothing to watch.

Nothing this call allocates outlives it. There is no subscription registry, no
per-client filter and no background task, which is why the deadline is not a
detail: it is what ends the server's obligation. `--mcp-max-wait-seconds`
bounds that obligation for the same reason `--mcp-max-rows` bounds a response,
and for a reason of its own — a waiting call occupies one of
`--mcp-max-concurrent` slots while producing nothing.

```jsonc
// await_condition { "filter": "state == Failed", "timeout_seconds": 20 }
{
  "schema_version": 1,
  "filter": "state == Failed",
  "matched": true,
  "stopped_because": "condition_met",
  "dialogs": [
    {
      "call_id": "1-1966@10.0.2.20",
      "state": "Failed",
      "method": "INVITE",
      "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
      "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
      "msg_count": 4,
      "duration_sec": 1.204,
      "created_at": "2016-11-26T14:52:59.666393+00:00",
      "updated_at": "2016-11-26T14:53:00.870676+00:00",
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
    }
  ],
  "returned": 1,
  "total_matched": 1,
  "truncated": false,
  "elapsed_ms": 4512,
  "timeout_seconds": 20,
  "timeout_clamped": false,
  "poll_interval_ms": 500,
  "polls": 10,
  "scans": 3,
  "source_exhausted": false,
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 41,
    "stream_generation": 7
  }
}
```

### `find_correlated`

Finds the other legs of one call — the far side of a B2BUA, SBC or PBX hop.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds — the leg to correlate **from**. | Required — the call fails. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 legs. |

Returns `source_call_id`, `legs`, `total_matched`, `heuristic_only`,
`capture_identity`, `timing_clock` and `schema_version`. A leg the source has no
relationship with answers with an empty `legs` array and `total_matched: 0`,
never an error. There is no cursor — raise `limit` to reach past a truncated
answer, and a call with more than 1000 correlated legs is a capture problem
rather than a paging one.

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
whose two calls share an SDP origin:

```jsonc
// find_correlated { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "source_call_id": "1-1966@10.0.2.20",
  "legs": [
    { "call_id": "1-1968@10.0.2.20", "score": 90, "strategy": "sdp_origin",
      "identifier_match": true, "observed_gap_ms": null }
  ],
  "total_matched": 1,
  "heuristic_only": false,
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  },
  "timing_clock": null              // non-null only when a timing_heuristic leg is returned
}
```

**Read `strategy`, not just `score`.** Two strategies score 100 and they are not
the same claim:

| `strategy` | What it means | Survives a B2BUA? |
|---|---|---|
| `session_id` | [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) `Session-ID` matched | **Yes, by design** |
| `x_call_id` | A configured header matched (`X-Call-ID` by default) | Only if the SBC inserts it |
| `charging_vector_related_icid` | One leg's [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) `related-icid` names the other's `icid-value` | Yes — but only when the B2BUA chose to emit it (`MAY`) |
| `sdp_origin` | The [RFC 8866](https://www.rfc-editor.org/rfc/rfc8866) SDP origin tuple matched | Only if the SBC forwards SDP untouched |
| `charging_vector_icid` | Both legs carry the same RFC 7315 `icid-value` | Not by design: an ICID identifies one dialog, and a B2BUA is two |
| `via_branch` | Two INVITEs shared a Via branch | No: a new transaction gets a new branch |
| `timing_heuristic` | Same endpoint, close in time | Not an identifier at all |

**The two `P-Charging-Vector` rows are one header and two different claims.**
[RFC 7315 §4.6](https://www.rfc-editor.org/rfc/rfc7315#section-4.6) says the ICID identifies *a dialog*, so a conformant B2BUA emits
a different `icid-value` on each side and `charging_vector_icid` is silent
across it — a match there means some intermediary copied a per-dialog
identifier onto a second dialog, which no RFC grants. The parameter that
addresses the hop is `related-icid` (§4.6.4.1), and it is optional. Two limits
worth knowing before you rely on either: the first proxy generates the icid
(§5.6), so a leg arriving from an endpoint carries none and this is useless at
the access edge. And §4.6.2.2 lets the next hop *"modify the contents"*, which
§6.6 calls normal behavior, so unlike `Session-ID` there is no end-to-end
constancy requirement at all. Full argument:
[`docs/design/icid-correlation.md`](design/icid-correlation.md).

Neither strategy puts the matched value in the response. [RFC 7315 §4.6](https://www.rfc-editor.org/rfc/rfc7315#section-4.6)'s own
suggested construction embeds the generating proxy's hostname or address in the
icid, so it is operator-internal rather than opaque, and `strategy` names the
strategy and nothing else.

`identifier_match` carries that distinction as a boolean, so a caller can filter
on it without knowing which names mean what. `heuristic_only` says whether
*every* returned leg came from a guess — a call tree built only from timing is a
hypothesis, and an agent that cannot tell presents it as a finding.

`observed_gap_ms` appears **only** for `timing_heuristic`, because there it is
the evidence: a 15 ms gap on a quiet box and a 1,900 ms gap on a busy SBC score
identically and mean very different things. On an identifier match it is null,
since the elapsed time is not why they matched.

A caveat worth stating plainly: most deployments emit no correlation header at
all. Where none is present, the only strategy left is the bottom row, and on a
busy SBC unrelated calls routinely share an endpoint inside its window.

### `get_call_tree`

Every leg of one call, as a tree.

The TUI has stitched B2BUA legs together since the `x` key, and nothing on the
MCP surface reached it. [`find_correlated`](#find_correlated) answers one hop
from one Call-ID, so an agent facing a carrier call across an SBC and a PBX —
three or four dialogs deep — had to call it on each result and assemble the
graph itself. Multi-leg is the normal case in carrier work, and
[`get_dialog`](#get_dialog) hands back a quarter of the call without saying so.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | Any leg of the call. The walk is symmetric, so naming the B-leg returns the same set rooted differently. A Call-ID the store does not hold fails with `call_id '...' not found`. | Required — the call fails. |
| `limit` | u32? | Maximum legs including the root. Ceiling is `--mcp-max-rows` (1000 by default), higher clamps to it, `0` means the default. | 50 legs. |

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
whose two calls share an SDP origin, with each leg's `dialog` summary trimmed to
its first three keys:

```jsonc
// get_call_tree { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "root_call_id": "1-1966@10.0.2.20",
  "legs": [
    {
      "call_id": "1-1966@10.0.2.20",
      "depth": 0,
      "parent_call_id": null,
      "score": null,
      "strategy": null,
      "identifier_match": null,
      "followed": true,
      "dialog": { "call_id": "1-1966@10.0.2.20", "state": "Completed", "method": "INVITE" }
    },
    {
      "call_id": "1-1968@10.0.2.20",
      "depth": 1,
      "parent_call_id": "1-1966@10.0.2.20",
      "score": 90,
      "strategy": "sdp_origin",
      "identifier_match": true,
      "followed": true,
      "dialog": { "call_id": "1-1968@10.0.2.20", "state": "InCall", "method": "INVITE" }
    }
  ],
  "total_legs": 2,
  "max_depth": 1,
  "truncated": false,
  "heuristic_edges": 0,
  "total_messages": 10,
  "first_activity": "2016-11-26T14:52:59.666393+00:00",
  "last_activity": "2016-11-26T14:53:08.290927+00:00"
}
```

Every leg past the root names the leg it came from (`parent_call_id`), how far
out it sits (`depth`), and the strategy and score of that one edge — the same
`strategy` vocabulary [`find_correlated`](#find_correlated) tabulates. The root
carries `null` for all four, because the caller named it rather than any
strategy matching it.

**The walk stops at a timing guess, and says so.** Six of the seven correlation
strategies compare a value both legs carry, and the walk expands those
transitively. `timing_heuristic` links two INVITE dialogs that share an endpoint
address and started inside the leg-correlation window, so on a proxy carrying
ten calls a second every dialog sits within a guess of every other. Expanded
transitively that is not a call tree, it is the capture. Such an edge still
appears in `legs` with `followed: false`, so an agent that wants the next hop
calls `get_call_tree` again rooted there and sees what it costs.

**Read `followed` before you read the shape.** A leaf appears for two opposite
reasons — a `timing_heuristic` edge the walk declined to expand, or a leg the
row cap cut the walk short of — and `followed` reflects what the walk actually
visited rather than what it intended to visit. A leg still sitting in the queue
when `limit` ended the walk reports `followed: false`, because claiming it
had searched that subtree would describe work nobody did. `truncated` says
the cap fired at all.

`heuristic_edges` counts the guesses in the whole tree. Zero means every link is
an identifier both legs carried. `total_messages` is the size of the merged
ladder the TUI's extended flow renders, and `first_activity` and
`last_activity` bracket the call rather than the root leg.

An unknown `call_id` fails with `invalid_params` rather than answering with an
empty tree. A call with no other legs and a Call-ID nobody holds are different
facts, and one empty answer for both collapses them — a lone dialog comes back
as a one-leg tree with `total_legs: 1` and `max_depth: 0`.

### `compare_dialogs`

"Why did this one work and that one not?"

**Parameters:** `call_id_a` and `call_id_b` (both string, both required) — two
Call-IDs the store holds. Either one unknown fails with `invalid_params` naming
it. No optional parameters, and passing the same Call-ID twice is legal and
answers with an empty `differences`.

Each side reports `call_id`, `state`, `final_status_code`, `msg_count`,
`methods` (sorted) and `hints`. `differences` names the fields that differ, so
you are not diffing two objects by eye. The example compares the two calls in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// compare_dialogs { "call_id_a": "1-1966@10.0.2.20", "call_id_b": "1-1968@10.0.2.20" }
{
  "schema_version": 1,
  "a": { "call_id": "1-1966@10.0.2.20", "state": "Completed", "final_status_code": 200,
         "msg_count": 6, "methods": ["ACK", "BYE", "INVITE"], "hints": [] },
  "b": { "call_id": "1-1968@10.0.2.20", "state": "InCall", "final_status_code": 200,
         "msg_count": 4, "methods": ["ACK", "INVITE"], "hints": [] },
  "differences": ["state", "msg_count", "methods"]
}
```

`final_status_code` matches on both sides here and so stays out of
`differences` — the second call simply never sent a `BYE`.

### `compare_captures`

Is today worse than yesterday, and where.

Baseline comparison is what turns a capture tool into an operations tool, and
nothing else on this surface reaches past the loaded capture. The answer has to
be a diff of AGGREGATES rather than of dialog lists — two captures never share a
Call-ID, so comparing rows finds every dialog different and says nothing. This
tool reads both files, groups each one the way
[`aggregate_dialogs`](#aggregate_dialogs) groups, and ranks the buckets by how
far they MOVED.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `a` | string | The baseline: a bare filename inside `--mcp-file-root`. | Required — the call fails. |
| `b` | string | The capture to hold against it, in the same root. | Required — the call fails. |
| `dimensions` | string[]? | From the `aggregate_dialogs` vocabulary: `state`, `response_code`, `method`, `from.user`, `to.user`, `ua`, `src.ip`, `dst.ip`, `rtp.codec`. A repeated name de-duplicates rather than failing. Anything else fails naming the nine. | `["state", "response_code"]` — how many calls reached each state, and which codes they ended on. |
| `top_n` | integer? | Rows per dimension. Everything past it sums into `other`. Ceiling is `--mcp-max-rows`. | 50. |

The example diffs two files in `tests/pcap-samples`:

```jsonc
// compare_captures { "a": "sip-rtp-g711.pcap", "b": "sip-auth-failure.pcapng",
//                    "dimensions": ["state"], "top_n": 4 }
{
  "schema_version": 1,
  "a": { "filename": "sip-rtp-g711.pcap", "packets": 852, "dialogs": 2,
         "streams": 2, "dialogs_dropped": 0, "read_error": null },
  "b": { "filename": "sip-auth-failure.pcapng", "packets": 8, "dialogs": 2,
         "streams": 0, "dialogs_dropped": 0, "read_error": null },
  "dimensions": [
    {
      "dimension": "state",
      "buckets": [
        { "value": "Completed",  "a": 1, "b": 0, "delta": -1 },
        { "value": "Failed",     "a": 0, "b": 1, "delta":  1 },
        { "value": "InCall",     "a": 1, "b": 0, "delta": -1 },
        { "value": "Terminated", "a": 0, "b": 1, "delta":  1 }
      ],
      "other": { "value": "(other)", "a": 0, "b": 0, "delta": 0 },
      "distinct_values": 4
    }
  ],
  "summary": "'sip-rtp-g711.pcap' (2 dialogs) is the baseline; 'sip-auth-failure.pcapng' (2 dialogs) is held against it, so delta is b minus a. Neither is the capture this server has loaded."
}
```

**Buckets rank by absolute movement, not by size.** The question is what
changed, and the largest bucket is usually the one that changed least, so "today
is worse than yesterday, and here is where" reads off the first row. `delta` is
`b - a` throughout. A value absent from one side counts as zero there rather
than as missing, because a response code appearing only in `b` IS the finding.

**Neither file becomes the loaded capture.** Both reads land in private stores
that the call drops before it builds the answer, so what an agent asked a minute
ago stays true afterwards. The read runs on a blocking thread, since two whole
captures inside a tool handler would otherwise hold the single runtime thread
the MCP server and the REST API share.

One thing does escape that isolation, which is why this tool carries
`readOnlyHint: false`: reading a file through the shared pipeline bumps the
PROCESS-WIDE undecodable-frame tallies and the ICMP evidence store that
[`get_capture_report`](#get_capture_report) reports. It destroys nothing, and
something observable moves. This reuses
[`open_capture`](#open_capture)'s existing behavior rather than inventing a new
one.

**Read the two `CaptureSide` blocks before the deltas.** `dialogs_dropped` above
zero means that side hit the dialog ceiling and every count under it is a FLOOR
rather than a total, and `read_error` names a read that stopped early. A
truncated pcap is the normal state of a rotating capture's newest member, so a
partial read reports rather than fails — and `summary` restates both conditions
in words, because a comparison against a partial population is a wrong answer
wearing the shape of a right one.

Four refusals, each cheaper than the mistake it prevents:

| Situation | Answer |
|---|---|
| No `--mcp-file-root` | `file tools are disabled: start sipnab with --mcp-file-root <DIR> to enable them` |
| A path rather than a bare name | `'../../etc/passwd' is not a bare filename. These tools take a name, not a path, ...` |
| `a` and `b` resolving to one file | `'x.pcap' and 'x.pcap' are the same file (...); a capture compared with itself differs from itself nowhere` |
| A dimension outside the vocabulary | `cannot compare on 'hour'; one of: state, response_code, ...` |

The vocabulary check runs BEFORE either file opens, because reading two captures
is the most expensive thing this surface does and a mistyped dimension must not
cost it. The same-file check runs after the resolver fully resolves both names,
so it catches two spellings of one file as well as the same name twice. And a
capture that yielded no dialogs AND reported a read error fails with
`internal_error` rather than diffing: every bucket would appear to collapse to
zero, which is a finding that is not there.

Note the dimension list here is the plain
[`aggregate_dialogs`](#aggregate_dialogs) nine.
[`group_dialogs`](#group_dialogs)'s three extras — `to_domain`, `hour`,
`next_hop` — do not apply, and `hour` in particular would compare two captures
of different days bucket by bucket.


## Diagnose one call

You have a call-id. These explain what happened to that one call -- its signaling, its media, and the specific negotiations that tend to break.

### `triage_call`

**Start here.** The first question in VoIP triage is which half of the stack
failed.
Signaling decides whether a call *connects*. RTP decides whether you can
*hear* it. They have different causes and different fixes, and confusing them
is the most common wrong turn — so ask this before anything else.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds, as
returned by [`list_dialogs`](#list_dialogs). An unknown one fails with
`invalid_params` (-32602) naming the value. There are no optional parameters.

```jsonc
// triage_call { "call_id": "1-1966@10.0.2.20" }
{
  "verdict": "media",              // "signaling" | "media" | "both" | "none"
  "state": "InCall",
  "final_status_code": 200,
  "signaling": { "problem": false, "hints": [] },
  "media": {
    "problem": true,
    "one_way_audio": true,
    "nat_mismatch": false,
    "no_media": false,
    "stream_count": 1,
    "hints": ["RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."]
  }
}
```

A clean `200 OK` with one-way audio is a **media** problem. Nothing in the SIP
exchange is wrong, and time spent reading it is time lost.

Where to go next, by verdict:

| Verdict | Next tool |
|---|---|
| `signaling` | [`explain_response_code`](#explain_response_code) on the final code, then [`get_dialog`](#get_dialog) |
| `media` | [`rtp_stats`](#rtp_stats), and [`check_codec_negotiation`](#check_codec_negotiation) if the call failed |
| `both` | Signaling first — media symptoms are often downstream of a failed negotiation |
| `none` | The call is fine. Check you have the right Call-ID |

### `get_dialog`

Paginated dialog with full SIP messages.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `call_id 'x' not found`. | Required — the call fails. |
| `max_messages` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 100 messages. |
| `cursor` | u32? | A message index, counting from 0. Unlike the dialog cursors elsewhere, this one is a plain integer, and past-the-end returns an empty page rather than an error. | Starts at message 0. |

**Returns:**

| Field | Type | Description |
|---|---|---|
| `dialog` | object | The same summary [`list_dialogs`](#list_dialogs) returns, with `from_user` and `to_user` fenced. |
| `messages` | object[] | This page of full messages, in dialog order. |
| `total_messages` | usize | Messages in the whole dialog, so `truncated` is unnecessary here. |
| `next_cursor` | u32? | Index to resume at. `null` on the final page. |
| `complete` | bool | `true` when this page reaches the end of the dialog. |

Every `messages` row carries `call_id`, `is_request`, `cseq` (`method` and
`number`), `from`, `to`, `src`, `src_port`, `dst`, `dst_port`, `transport`,
`timestamp`, `frame` and `schema_version`. The rest depends on the direction,
so branch on `is_request` rather than expecting one shape:

- **A request** adds `method`, and `contact` and `sdp` when it carried them.
- **A response** adds `status_code`, `reason`, `response_context` and `ua`, and
  carries no `method` — read `cseq.method` for the transaction it answers.

> **This tool fences, and it is the one that returns the most capture text.**
> `reason`, `from`, `to`, `contact`, `ua`, `sdp` and `malformed` in `messages[]`
> come back wrapped in `⟦untrusted-capture-data⟧` markers, the same treatment
> [`get_message`](#get_message) gives them. The SDP body keeps its line
> structure, `--mcp-max-body-bytes` bounds it, and the header values arrive
> capped with every control character removed.
>
> This page said the opposite until 0.5.134 — that the fields came back
> verbatim and that a reader should reach for `get_message` instead. Both tools
> fenced the whole time. Treat every string in `messages[]` as attacker-written
> regardless: the markers say where the text came from, they do not make it
> safe.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_dialog { "call_id": "1-1966@10.0.2.20", "max_messages": 1 }
{
  "complete": false,
  "total_messages": 6,
  "next_cursor": 1,
  "dialog": {
    "call_id": "1-1966@10.0.2.20",
    "state": "Completed",
    "method": "INVITE",
    "from_user": "⟦untrusted-capture-data⟧sipp⟦/untrusted-capture-data⟧",
    "to_user": "⟦untrusted-capture-data⟧test⟦/untrusted-capture-data⟧",
    "msg_count": 6,
    "duration_sec": 8.504,
    "created_at": "2016-11-26T14:52:59.666393+00:00",
    "updated_at": "2016-11-26T14:53:08.170676+00:00",
    "timing": { "pdd_ms": null, "setup_ms": 4, "retransmits": 0, "duration_ms": 8499 },
    "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
  },
  "messages": [
    {
      "call_id": "1-1966@10.0.2.20",
      "method": "INVITE",
      "is_request": true,
      "cseq": { "method": "INVITE", "number": 1 },
      "from": "\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1",
      "to": "test <sip:test@10.0.2.15:5060>",
      "contact": "sip:sipp@10.0.2.20:5060",
      "src": "10.0.2.20",
      "src_port": 5060,
      "dst": "10.0.2.15",
      "dst_port": 5060,
      "transport": "UDP",
      "timestamp": "2016-11-26T14:52:59.666393+00:00",
      "sdp": "v=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n",
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
      "schema_version": 1
    }
  ]
}
```

`total_messages` is 6 and `next_cursor` is 1, so five messages remain. Call
again with `cursor: 1` to continue, and stop when `complete` turns `true`.

### `get_dialog_report`

Per-call diagnostic report for one Call-ID. Backed by
`output::generate_call_report` — same content as `--call-report`.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `invalid_params` (-32602) naming the value. | Required — the call fails. |
| `format` | string? | `"json"`, `"markdown"` or `"text"`. Anything else fails with `unknown format 'x', expected json\|markdown\|text`. | `"json"`. |

`"json"` answers with the structured object below. `"markdown"` and `"text"`
answer with one text block holding the rendered report, byte-identical to what
[`render_ladder`](#render_ladder) produces for the same dialog. All three append
the provenance note as a second content block. The two rendered formats also
carry the `INCOMPLETE RUN` block described under
[`get_capture_report`](#get_capture_report) when the capture was not read in
full. `"json"` carries `source_exhausted` and `source_stopped_early` as fields
instead.

The example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// get_dialog_report { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "state": "Completed",
  "method": "INVITE",
  "final_status_code": 200,
  "final_status_reason": "OK",
  "from": "sipp",
  "from_display": "PCMU/8000",
  "to": "test",
  "to_display": "test",
  "msg_count": 6,
  "duration_sec": 8.504,
  "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
  "timing": {
    "retransmits": 0,
    "setup_ms": 4,
    "teardown_ms": 0,
    "trying_delay_ms": 0
  },
  "diagnosis": {
    "hints": [
      "RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."
    ],
    "nat_mismatch": false,
    "no_media": false,
    "one_way_audio": true
  },
  "sdp_timeline": [ /* the same rows get_sdp_timeline returns */ ],
  "streams": [ /* the same rows rtp_stats returns, without mos */ ]
}
```

This report bundles what [`triage_call`](#triage_call),
[`get_sdp_timeline`](#get_sdp_timeline) and [`rtp_stats`](#rtp_stats) answer
separately, so one call replaces three when you already know which call to read.
Its `streams` rows omit `mos` and `mos_grounded` — ask `rtp_stats` when the
question is audio quality rather than what the call did.

Unlike the summary rows elsewhere, `from` and `to` here arrive **unfenced**, and
the trailing provenance note explains why: a rendered report interleaves
sipnab's diagnosis with header values the sender wrote, and fencing the whole
document would tell an agent to distrust the analysis as well.

### `get_message`

Single SIP message at a given zero-based index.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `index` | u32 | `0` to `msg_count - 1` for that dialog. | Required — the call fails. |

**Where an index comes from,** because the number means nothing on its own:
`msg_count` on any [`list_dialogs`](#list_dialogs) row is the count, so the last
valid index is `msg_count - 1`. [`get_dialog`](#get_dialog) pages messages from
its `cursor`, so the Nth row of that page sits at `cursor + N`, and every
[`lint_dialog`](#lint_dialog) finding reports the `message_index` it fired on.

An index at or past the end fails with `index 999 out of range for dialog with
7 messages` — the count is in the message, so a caller that guessed corrects
itself without another round trip.

Returns one message in the same shape [`get_dialog`](#get_dialog) uses for a
`messages` row, plus the provenance note as a second content block. The
difference is the fencing: this tool wraps `from`, `to`, `contact`, `sdp`, `ua`,
`reason` and `malformed`, and leaves `call_id`, addresses, ports, `method`,
`status_code`, `cseq` and timestamps verbatim so they pass into the next call.

```jsonc
// get_message { "call_id": "1-1966@10.0.2.20", "index": 0 }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "method": "INVITE",
  "is_request": true,
  "cseq": { "method": "INVITE", "number": 1 },
  "from": "⟦untrusted-capture-data⟧\"PCMU/8000\" <sip:sipp@10.0.2.20:5060>;tag=1⟦/untrusted-capture-data⟧",
  "to": "⟦untrusted-capture-data⟧test <sip:test@10.0.2.15:5060>⟦/untrusted-capture-data⟧",
  "contact": "⟦untrusted-capture-data⟧sip:sipp@10.0.2.20:5060⟦/untrusted-capture-data⟧",
  "sdp": "⟦untrusted-capture-data⟧v=0\r\no=- 42 42 IN IP4 10.0.2.20\r\ns=-\r\nc=IN IP4 10.0.2.20\r\nt=0 0\r\nm=audio 6000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=recvonly\r\n⟦/untrusted-capture-data⟧",
  "src": "10.0.2.20",
  "src_port": 5060,
  "dst": "10.0.2.15",
  "dst_port": 5060,
  "transport": "UDP",
  "timestamp": "2016-11-26T14:52:59.666393+00:00",
  "frame": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"
}
```

### `render_ladder`

Call-flow ladder for one Call-ID.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `format` | string? | `"markdown"` or `"text"`. Anything else, `"json"` included, fails with `unknown format 'x', expected markdown\|text`. | `"markdown"`. |

Returns one text content block holding the rendered report, and the provenance
note as a second block. There is no JSON shape here — ask
[`get_dialog_report`](#get_dialog_report) with `format: "json"` for fields a
program can read.

```jsonc
render_ladder { "call_id": "1-1966@10.0.2.20" }
```

Output is byte-identical to the report
`sipnab -N --call-report <id> --markdown --no-cli-print` /
`sipnab -N --call-report <id> --no-cli-print` writes for the same dialog.
`--no-cli-print` matters for the comparison: without it the CLI writes the whole
capture's per-message dump ahead of the report, and the tool never does.

Over a capture that was not read in full — still loading, or a read that
stopped before the file's end — the tool appends an `INCOMPLETE RUN` block
after the ladder, which `--call-report` does not. The ladder itself does not
change: the block goes after it, so no line of the drawing moves.

```text
# Call Report: 1-1966@10.0.2.20

## Summary

| Field | Value |
|-------|-------|
| Time | 2016-11-26 14:52:59 -> 14:53:08 (8s) |
| From | sipp |
| To | test |
| State | Completed |

## Timing

| Metric | Value |
|--------|-------|
| PDD | - |
| Setup | 0.00s |
| Ring | - |
| Teardown | 0.00s |
| Retransmits | 0 |

## Media Streams

| SSRC | Codec | Source | Destination | Packets | Jitter | Loss |
|------|-------|--------|-------------|---------|--------|------|
| 0x343da99b | PCMU | 10.0.2.15:27942 | 10.0.2.20:6000 | 425 | 0ms | 0.0% |

## Issues

- RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected.
```

### `get_sdp_timeline`

The offer/answer exchanges in order — codecs, media address, port and mode per
negotiation, including re-INVITEs. Use it when audio changed mid-call, or when
the two ends disagree about the codec.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters.

Every exchange carries `direction` (`offer` or `answer`), `codecs`,
`media_addr`, `media_port`, `mode` (`sendrecv`, `sendonly`, `recvonly` or
`inactive`), `timestamp`, and `event` — `null` unless sipnab classified the
exchange, as with the `MediaAnchorChange` below. A call carrying no SDP answers
with an empty `exchanges` array rather than an error.

```jsonc
// get_sdp_timeline { "call_id": "1-1966@10.0.2.20" }
{
  "call_id": "1-1966@10.0.2.20",
  "exchanges": [
    {
      "codecs": [
        "PCMU"
      ],
      "direction": "offer",
      "event": null,
      "media_addr": "10.0.2.20",
      "media_port": 6000,
      "mode": "recvonly",
      "timestamp": "2016-11-26T14:52:59.666393+00:00"
    },
    {
      "codecs": [
        "PCMU",
        "telephone-event"
      ],
      "direction": "answer",
      "event": "MediaAnchorChange",
      "media_addr": "10.0.2.15",
      "media_port": 27942,
      "mode": "sendonly",
      "timestamp": "2016-11-26T14:52:59.670743+00:00"
    }
  ],
  "schema_version": 1
}
```

The offer promises `recvonly` on `10.0.2.20:6000` and the answer replies
`sendonly` from `10.0.2.15:27942`, which is why
[`triage_call`](#triage_call) calls this capture one-way media rather than a
fault.

### `check_codec_negotiation`

For `488 Not Acceptable Here`, which usually means nobody offered the far end a
codec it accepts.

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters.

Returns `offered`, `answered`, `common`, `result`, `sdp_exchange_count`,
`final_status_code`, `call_id` and `schema_version`. Codec names come from the
SDP unfenced, because they are tokens from a registry rather than free text.

```jsonc
// check_codec_negotiation { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "offered": ["PCMU"],
  "answered": ["PCMU", "telephone-event"],
  "common": ["PCMU"],
  "result": "ok",
  "final_status_code": 200,
  "sdp_exchange_count": 2
}
```

`result` has five values, and the distinction matters:

| Result | Meaning | What to do |
|---|---|---|
| `ok` | The two sides agreed | Codecs are not your problem |
| `no_common_codec` | Both offered codecs, none shared | A codec policy problem — compare the lists |
| `no_answer` | An offer went out, nothing came back | The call did not get far enough to negotiate |
| `sdp_present_but_no_codecs` | Both sides exchanged SDP, but neither listed a codec | Look at the SDP itself — a malformed or media-less `m=` line |
| `no_sdp_in_capture` | No SDP at all | Not a codec problem. Hold with inactive media, or a reject before any offer |

`no_answer` and `no_sdp_in_capture` are deliberately separate: reporting the
first for the second sends you hunting a reply that was never expected.

### `diagnose_registration`

"Is this phone online?" — a different question from "why did this call fail?".

**Parameters:** `call_id` (string, required) — a Call-ID the store holds. No
optional parameters. The call need not carry a `REGISTER`, and the answer says
so when it does not.

**Read `applicable` first.** It is `false` for a dialog carrying no `REGISTER`,
and the response then holds only `call_id`, `reason` and `schema_version` — no
`hints`, no `registration_failure`. Reporting a healthy registration for a call
that never attempted one would be worse than admitting the question does not
apply:

```jsonc
// diagnose_registration { "call_id": "1-1966@10.0.2.20" }   — an INVITE dialog
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "applicable": false,
  "reason": "this dialog carries no REGISTER request"
}
```

When it does apply, `registration_failure` is `null` for a registration that
worked, and otherwise names the `kind` — `rejected`, `shortened_expiry` or an
auth loop reported through `auth_loop`. `evidence` lists the message indexes
behind the verdict, ready for [`get_message`](#get_message). The example runs
against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng):

```jsonc
// diagnose_registration { "call_id": "auth-fail-register-synth@203.0.113.1" }
{
  "schema_version": 1,
  "call_id": "auth-fail-register-synth@203.0.113.1",
  "applicable": true,
  "final_status_code": null,
  "auth_loop": null,
  "registration_failure": {
    "kind": "rejected",
    "code": 403,
    "evidence": [0, 3],
    "requested_expiry_sec": null,
    "granted_expiry_sec": null
  },
  "hints": [
    "Call failed: 403 Forbidden.",
    "Registration rejected: 403 Forbidden. The endpoint answered an authentication challenge and the registrar refused the credentials it offered, so the fault is in the account, its password or its permission to register — none of which is a reachability problem."
  ]
}
```

`final_status_code` is `null` here even though the registrar answered 403,
because the dialog never reached a state that records one. Read
`registration_failure.code` for the status that decided the verdict.

### `media_diagnostics`

"The MOS is 3.6 — why?" `rtp_stats` gives the score. This gives the facts
underneath it, and each one says what kind of number it is.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |

**Read `applicable` first.** It is `false` when no RTP stream belongs to the
dialog, and the response then holds only `call_id`, `reason`,
`capture_identity` and `schema_version`. An empty `streams` array would read as
"sipnab checked the media and it was fine", which is a different claim from "no
media reached the capture point".

Otherwise `streams` carries one entry per stream, each with five blocks:

| Block | Answers | The honesty flag |
|---|---|---|
| `qos` | Which queue the sender asked the network to put this media in | `marking_observed` — `false` for a HEP-fed stream, where sipnab saw no IP header. `dscp: 0` means observed best effort, a real and frequently wrong marking |
| `jitter` | The interarrival jitter, and whether it is a measurement | `grounded` — `false` when the stream supplied no clock rate and sipnab fell back to a default. Jitter is an RTP-timestamp difference divided by that rate, so a wrong divisor gives a different quantity, not a rough one. An ungrounded stream reports no `measured_ms` at all |
| `delay` | The one-way delay behind the published MOS | `assumed` — `true` when neither the operator nor any RTCP supplied one |
| `silence` | Comfort-noise frames and detected silence periods | -- (counts, not estimates) |
| `endpoint_reported` | What the far end said over RTCP | The whole block is the flag. Omitted entirely when no RTCP arrived |

`endpoint_reported` sits apart from everything beside it on purpose. Nobody
authenticates RTCP and anyone can forge it, and a report describes the path
from the sender to *the reporter* — on a mid-path capture, a different segment
from the one sipnab watches. The two disagreeing is normal and informative, and
merging them would destroy exactly that signal. Nothing under this key feeds the
MOS.

`qos.remarked_to` appears only when the stream's last packet carries a different
code point from its first — an SBC or a policy boundary rewriting the marking in
flight. Its presence is the finding, and a steady stream omits it rather than
repeating the same number.

The example runs against
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// media_diagnostics { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "applicable": true,
  "streams": [
    {
      "ssrc": "0x343da99b",
      "src": "10.0.2.15:27942",
      "dst": "10.0.2.20:6000",
      "codec": "PCMU",
      "packets": 425,
      "qos": {
        "marking_observed": true,
        "dscp": 0,
        "name": "CS0 / default (best effort)",
        "expedited": false
      },
      "jitter": {
        "grounded": true,
        "clock_basis": "rfc3551",
        "clock_rate_hz": 8000,
        "measured_ms": 0.0054046519599899685
      },
      "delay": { "source": "assumed", "assumed": true, "one_way_ms": 100.0 },
      "silence": { "cn_frames": 0, "periods": 0, "total_ms": 0 }
    }
  ],
  "capture_identity": {
    "instance": "6dac718cb96d767d0f490-1",
    "node": "sbc-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

Three things in that answer are worth reading together. The media is in the
default queue, so it competes with bulk traffic — the most common cause of
jitter that adding bandwidth does not fix. The jitter figure IS a measurement,
because payload type 0 has a clock rate [RFC 3551](https://www.rfc-editor.org/rfc/rfc3551)
Table 4 fixes. And the delay behind the MOS is a default, not anything this
capture showed, so a MOS built on it is only as good as that assumption.

`clock_basis` has three values: `rfc3551` (a static payload type), `rtpmap` (a
dynamic one an SDP named), and `assumed` (neither, and the reason `grounded` is
`false`).

### `rtp_stats`

Per-stream RTP quality for one call, or across the whole capture.

This tool has **two modes**, and `call_id` is the switch. Pass it for one
dialog's streams. Omit it to sweep the whole capture. The four sweep-only
parameters fail with `invalid_params` when a `call_id` accompanies them, rather
than quietly doing nothing:

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string? | A Call-ID the store holds. | **Switches modes** — the tool sweeps every stream in the capture, orphans included. |
| `min_mos` | f64? | Sweep only. Keeps streams scoring at or above this. Rejected alongside `call_id`. | No lower bound. |
| `max_mos` | f64? | Sweep only. Keeps streams scoring strictly below this. Rejected alongside `call_id`. | No upper bound. |
| `limit` | u32? | Sweep only. Ceiling is `--mcp-max-rows` (1000 by default), higher clamps to it, `0` means the default. | 50 streams. |
| `cursor` | string? | Sweep only. The previous response's `next_cursor`, verbatim (`<RFC 3339>\|0xSSRC@src>dst`). | Starts at the earliest stream. |

**With `call_id`** the answer keeps its existing shape — `{ call_id, streams, diagnosis }`,
where `streams` is an array of stream JSON objects (codec, MOS, jitter, loss%,
packets, SSRC, quality intervals) and `diagnosis` carries the standard one-way /
NAT-mismatch flags plus the asymmetry signals (`codec_asymmetry`,
`ptime_asymmetry`, `payload_type_asymmetry`, `duration_asymmetry`,
`late_media`). A MOS bound alongside a `call_id` returns invalid_params
(-32602) rather than quietly doing nothing.

```jsonc
// rtp_stats { "call_id": "1-1966@10.0.2.20" }
{
  "call_id": "1-1966@10.0.2.20",
  "streams": [
    {
      "associated_dialog": "1-1966@10.0.2.20",
      "codec": "PCMU",
      "src": "10.0.2.15:27942",
      "dst": "10.0.2.20:6000",
      "ssrc": "0x343da99b",
      "payload_type": 0,
      "packets": 425,
      "octets": 68000,
      "loss_pct": 0.0,
      "jitter_ms": 0.0054046519599899685,
      "mos": 4.358100599599484,
      "mos_grounded": true,
      "mos_grounding": "published",
      "orphaned": false,
      "first_seen": "2016-11-26T14:52:59.689083+00:00",
      "last_seen": "2016-11-26T14:53:08.169060+00:00",
      "round_trip_note": "Not measured. No endpoint reported a round trip for this stream, so latency is unknown rather than good — a stream with clean jitter and no loss can still be unusable on delay alone (ITU-T G.114).",
      "quality_intervals": [
        {
          "jitter_ms": 0.0063823922199494915,
          "loss_pct": 0.0,
          "packets": 252,
          "timestamp": "2016-11-26T14:53:04.709076+00:00"
        }
      ],
      "frame": "tests/pcap-samples/sip-rtp-g711.pcap#5@ae02f78d2d48b4f0",
      "schema_version": 1
    }
  ],
  "diagnosis": {
    "actual_media": null,
    "hints": [
      "RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b). No reverse media flow detected."
    ],
    "nat_mismatch": false,
    "no_media": false,
    "one_way_audio": true,
    "sdp_media": "10.0.2.20"
  }
}
```

Per-call mode returns no `total_matched`, `truncated` or `next_cursor` — a call
holds every stream it holds, so there is nothing to page. `quality_intervals`
holds one entry per completed sampling window, so a short call legitimately
returns an empty array while this eight-second one returns a single row.

Each stream carries **`mos_grounded`** and **`mos_grounding`**. `estimate_mos`
returns the same number — 4.216 at 10 ms jitter — for AMR, AMR-WB, EVS, G.722
*and* for a stream whose codec was never identified, because sipnab only has
published ITU-T G.113 impairment values for G.711, G.729 and Opus. When
`mos_grounded` is `false` the MOS means **unknown**, not "about 4.2", and a
`mos_note` says so.

`mos_grounding` names which basis the number rests on, because "grounded" now
covers two of them:

| `mos_grounding` | `mos_grounded` | What the number rests on |
|---|---|---|
| `published` | `true` | An ITU-T G.113 impairment value sipnab implements. |
| `operator_declared` | `true` | An `Ie` this deployment supplied in `[media.codec_ie]`. A `mos_note` says so, so an agent citing the figure cites the operator rather than a standard. |
| `unpublished` | `false` | Nothing published and nothing declared. Placeholder. |

For AMR-WB specifically the placeholder is wrong by roughly a full MOS point in
either direction: its nine modes genuinely span about 4.49 down to 3.51. Do not
report a MOS to a human without checking this field. See
[MOS and codecs](mos-and-codecs.md) for the full picture.

#### Who named the dialog — `dialog_assertion`

Each stream also says who asserted the SDP media endpoint that tied it to its
Call-ID:

| `dialog_assertion` | Who said it | What the address is |
|---|---|---|
| `signaled` | a negotiating party, in its own SDP | that party's endpoint |
| `media-relay` | an rtpengine relay, about a port it allocated | the leg's **midpoint** |

A relay cannot be wrong about which socket it opened, so the address is
authoritative — and it is still not an endpoint. An agent reasoning about where
media went must not report a `media-relay` address as the far party's, because
it names the box in the middle and the two lead to opposite conclusions.

sipnab emits the key whenever it knows the answer, `signaled` included. **Absent
means nobody recorded who asserted it**, never "a party did". Do not default it.

Distinct from `dialog_origin`, which names the capture **source** that delivered
the assertion rather than its author. See
[rtpengine relay attribution](rtpengine.md).

#### Capture-wide sweep — omit `call_id`

"Every stream with a MOS below 3.5" is one call rather than a listing plus one
`rtp_stats` per dialog, which costs thousands of round trips on a real capture.
The sweep also reaches streams the per-call mode cannot: a stream that never
linked to a dialog has no Call-ID to ask about, and an orphan is not an oddity —
it is what a NAT or one-way-audio fault looks like from the media side.

| Field | Type | Description |
|---|---|---|
| `streams` | object[] | This page, oldest `first_seen` first. |
| `returned` | usize | Rows in `streams`. |
| `total_matched` | usize | Streams matching across the whole store. |
| `ungrounded_excluded` | usize | Streams a MOS bound could not judge. |
| `truncated` | bool | `true` when matches remain after this page. |
| `next_cursor` | string? | Pass back to continue. `null` on the final page. |

**A MOS bound only judges codecs sipnab has a real impairment value for** —
one G.113 publishes, or one this deployment declared in `[media.codec_ie]`.
`min_mos` and `max_mos` skip every ungrounded stream and count it in
`ungrounded_excluded`,
because a bound on a placeholder picks calls out of a guess — and it goes
wrong in both directions. A healthy AMR-WB stream never appears in a `max_mos`
sweep, while a degraded one turns up on a figure that never described it.
Reporting the skipped count keeps the difference visible: "2 streams below 3.5"
and "2 streams below 3.5, plus 200 I cannot score" describe different captures,
and on any network carrying AMR-WB, EVS or G.722 the second one is the truth.
Omit both bounds and the sweep lists every stream, including the codecs with no
published value, each still carrying `mos_grounded`.

The example runs against [`tests/pcap-samples/codec-negotiation.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/codec-negotiation.pcap), which
carries four streams — two PCMU, two G722 — and no dialogs at all:

```jsonc
// rtp_stats { "max_mos": 4.5, "limit": 1 }
{
  "schema_version": 1,
  "streams": [
    {
      "codec": "PCMU",
      "dst": "127.0.0.1:5084",
      "first_seen": "2026-07-08T18:35:27.407583+00:00",
      "frame": "tests/pcap-samples/codec-negotiation.pcap#5@5d4c3e3d970a836b",
      "jitter_ms": 0.26954164761616456,
      "last_seen": "2026-07-08T18:35:30.407077+00:00",
      "loss_pct": 0.0,
      "mos": 4.357953149337916,
      "mos_grounded": true,
      "mos_grounding": "published",
      "octets": 24160,
      "orphaned": true,
      "packets": 151,
      "payload_type": 0,
      "quality_intervals": [],
      "round_trip_note": "Not measured. No endpoint reported a round trip for this stream, so latency is unknown rather than good — a stream with clean jitter and no loss can still be unusable on delay alone (ITU-T G.114).",
      "schema_version": 1,
      "src": "127.0.0.1:5094",
      "ssrc": "0x0e330af3"
    }
  ],
  "returned": 1,
  "total_matched": 2,
  "ungrounded_excluded": 2,
  "truncated": true,
  "next_cursor": "2026-07-08T18:35:27.407583+00:00|0x0e330af3@127.0.0.1:5094>127.0.0.1:5084",
  "capture_identity": {
    "node": "capture-01",
    "instance": "22fa418cb5c799c57abef-1",
    "dialog_generation": 1,
    "stream_generation": 4
  }
}
```

The sweep adds `frame`, `capture_identity` and the page fields the per-call mode
omits.

**`orphaned` means "no dialog claims this stream", and nothing else.** It is
`associated_dialog.is_none()`, which sipnab computes while building the
response, so the two fields can never disagree: every stream above reports `orphaned: true`, which
is the truth about a capture holding four streams and no dialogs at all.

sipnab computes `orphaned` per response as `associated_dialog.is_none()`, so a
stream reports it from its FIRST packet. That matters because a short unclaimed
stream is exactly what a NAT or one-way-audio fault looks like from the media
side: an agent filtering for orphans to find one must not have to wait for a
sweep to notice. Reading `associated_dialog` directly means the same thing.

`total_matched: 2` and `ungrounded_excluded: 2` account for all four streams.
The two G722 streams score 4.22 from the placeholder arm, which would have put
them under a 4.5 bound on a number that means nothing.


## Conformance and rules

Whether the traffic obeys the RFCs, and which clause it broke. These turn "the call failed" into "12.1.1 requires a Contact and there is none".

### `lint_dialog`

Conformance, which is not the question `triage_call` answers. That tool asks
why a call failed. This one asks whether the traffic obeys the specification. A
call can complete over messages that break four MUSTs, and a fully conformant
call can hit a busy signal.

The rules that earn this tool its place compare the declaration against the
observation. sipnab holds the signaling and the RTP in one process, so it can
report that the SDP declared PCMU on payload type 0 while the wire carried
payload type 8, that RTP arrived on a port no `m=` line advertised, that
`sendrecv` promised media in both directions and the capture holds it in one,
or that the packet spacing contradicts `a=ptime`. A linter reading message text
reaches none of that, because the defect sits in neither message.

The RFC 3261 syntax rules and the [RFC 3264](https://www.rfc-editor.org/rfc/rfc3264) offer/answer rules run alongside
them. Everything citing [RFC 4566](https://www.rfc-editor.org/rfc/rfc4566), 3551 or 5761 belongs to the observation half.
[SIP conformance rules](sip-lint-rules.md) lists every rule, the section behind
it, and the suppression syntax.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `rulesets` | string[]? | The 15 selectors below, OR-ed together. An unknown one fails with `invalid_params` listing all 15. | The whole catalog, reported back as `rulesets: ["all"]`. |
| `severity_min` | string? | `info`, `notice`, `warning` or `error`. Anything else fails with `unknown severity 'x'. Valid values: info, notice, warning, error`. | `info`, so the floor drops nothing. |
| `suppression_file` | string? | A bare filename inside `--mcp-file-root`. A file sipnab cannot open fails with `invalid_params` rather than linting with every rule on. | sipnab walks for a `.sipnablint` beside the capture and upward to the project root. |

Selectors take two forms — the catalog's own names, and one per RFC the rules
cite:

- **By category:** `all`, `must`, `rfc` (MUST and SHOULD together), `interop`,
  `observation` (`observed` also works) and `syntax`.
- **By RFC:** `rfc3261`, `rfc3262`, `rfc3264`, `rfc3551`, `rfc4028`, `rfc4566`,
  `rfc5761`, `rfc7989`.

An unknown selector fails with `invalid_params` (-32602) naming the whole
vocabulary, so a typo such as `rfc3621` cannot quietly select nothing and hand
back an empty list that reads as a clean call. Passing an empty array behaves
as omitting the parameter.

The example runs against [`tests/pcap-samples/b2bua-asterisk.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/b2bua-asterisk.pcapng). Its SDP
negotiates `sendrecv` in both directions, and the capture carries 355 RTP
packets in one:

```jsonc
// lint_dialog { "call_id": "b2bua-leg-synth@203.0.113.101:5060",
//               "rulesets": ["observed"] }
{
  "schema_version": 1,
  "call_id": "b2bua-leg-synth@203.0.113.101:5060",
  "rulesets": ["observed"],
  "severity_min": "info",
  "message_count": 15,
  "rtp_streams_observed": 1,
  "finding_count": 1,
  "severity_counts": { "error": 0, "warning": 1, "notice": 0, "info": 0 },
  "findings": [
    {
      "rule_id": "OBS-3264-6.1-DIRECTION-UNMET",
      "severity": "warning",
      "basis": "observation",
      "rfc": 3264,
      "section": "6.1",
      "message_index": 0,
      "observed": "355 RTP packets observed, none of them toward one negotiated endpoint",
      "expected": "media in both directions, as a=sendrecv promised",
      "explanation": "§6.1 makes sendrecv a promise to send as well as receive. ..."
    }
  ],
  "rules_not_evaluated": [
    {
      "reason": "needs the endpoint pairs RTCP arrived on. ...",
      "rule_ids": ["OBS-5761-5.1.1-RTCP-MUX-UNANSWERED"]
    }
  ],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

`rfc` and `section` stay separate fields rather than prose inside the
explanation, and that is the whole point of the shape. An agent quotes RFC 3264
§6.1 out of the data instead of inventing a section number that reads
plausibly, and `explain_rule` turns the identifier back into the citation and
the link.

`rules_not_evaluated` names what the run could not settle, grouped by reason. A
rule that found nothing and a rule that never ran leave the same empty finding
list behind, and only this field separates them. Two reasons appear on this
tool:

- No RTP reached the call, so the `OBS-` rules had nothing to compare the
  declaration against.
- `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` needs the endpoint pairs RTCP arrived
  on. The stream store folds an RTCP report into the stream it describes and
  keeps no record of where it landed, so no MCP tool raises this rule.

#### Suppression, and what it must tell you

A project silences rules with a `.sipnablint` — one identifier per line, or a
prefix ending `*`, with `#` starting a comment. [SIP conformance
rules](sip-lint-rules.md) documents the pattern syntax.

sipnab looks for one beside the capture, then climbs toward the project root
and stops there. A capture that sits outside any project — a corpus mount, a
share, `/tmp` — adopts nothing from above itself, because inheriting a
stranger's suppression list would switch off rules nobody here turned off.
`suppression_file` overrides the search outright, and a file it names that
sipnab cannot open returns invalid_params rather than quietly linting with every
rule on.

Two response fields carry the consequences, and every call includes both, even
when every number is zero:

```jsonc
"suppressions": {
  "file": "/srv/captures/.sipnablint",   // null when none applied
  "patterns": ["OBS-*", "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING"],
  "findings_suppressed": 4
},
"findings_withheld": { "suppressed": 4, "below_severity": 2, "capped": 0 }
```

A response carrying no field and a response carrying zero must not be the same
bytes. The first says nothing about whether the run hid findings. The second
says it hid none.

The three counts stay apart because they send you to three different places:
something you wrote down silenced it, your severity floor dropped it, or there
was simply too much of it and the per-rule cap stopped after 25.
`capped` is the only lower bound of the three — a rule may stop evaluating once
it hits the cap, and nothing can count what it then never raises. `suppressed`
and `below_severity` are exact, which is why suppression deliberately does not
short-circuit the rule.

The response names the file rather than merely acknowledging one. "4 findings
suppressed" leaves you nothing to act on when the search walked up three
directories to find the file that did it.

### `validate_message`

The same rules against one message, named by its zero-based index — the shape a
CI job or a header-level argument with a vendor wants. `lint_dialog` reports
`message_index` on every finding, so this tool narrows a hit rather than
finding new ones.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `index` | u32 | `0` to `msg_count - 1`. Out of range fails with `invalid_params` (-32602) naming the message count. | Required — the call fails. |
| `suppression_file` | string? | A bare filename inside `--mcp-file-root`, exactly as [`lint_dialog`](#lint_dialog) takes it. Wins outright over the discovery walk. | sipnab walks for a `.sipnablint` beside the capture and upward. |

There is no `rulesets` or `severity_min` here. Every rule that can run on one
message runs, and the response reports the rest under `rules_not_evaluated`.

```jsonc
// validate_message { "call_id": "options-ping-c-synth@198.51.100.206", "index": 0 }
{
  "schema_version": 1,
  "call_id": "options-ping-c-synth@198.51.100.206",
  "message_index": 0,
  "message_count": 2,
  "finding_count": 2,
  "severity_counts": { "error": 0, "warning": 2, "notice": 0, "info": 0 },
  "findings": [
    {
      "rule_id": "SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING",
      "severity": "warning", "basis": "must", "rfc": 3261, "section": "8.1.1.6",
      "message_index": 0,
      "observed": "no Max-Forwards header field",
      "expected": "Max-Forwards: 70",
      "explanation": "§8.1.1.6 makes a UAC insert one into every request it originates. ..."
    },
    {
      "rule_id": "SIP-3261-8.1.1.7-BRANCH-COOKIE",
      "severity": "warning", "basis": "must", "rfc": 3261, "section": "8.1.1.7",
      "message_index": 0,
      "observed": "top Via branch without the z9hG4bK prefix",
      "expected": "branch=z9hG4bK...",
      "explanation": "§8.1.1.7 makes every compliant branch begin with z9hG4bK. ..."
    }
  ],
  "rules_not_evaluated": [
    { "reason": "reads a dialog's messages against each other, and this tool reads one message alone. Call lint_dialog.",
      "rule_ids": ["SIP-3261-8.1.1.2-TO-TAG-IN-INITIAL-REQUEST", "..."] },
    { "reason": "compares the declaration against the observed media, and this tool reads one message alone. Call lint_dialog.",
      "rule_ids": ["OBS-3264-6.1-PT-UNDECLARED", "..."] },
    { "reason": "needs the endpoint pairs RTCP arrived on. ...",
      "rule_ids": ["OBS-5761-5.1.1-RTCP-MUX-UNANSWERED"] }
  ],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

That example runs against [`tests/pcap-samples/sip-488-codec-reject.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-488-codec-reject.pcapng),
whose first `OPTIONS` ping carries neither a `Max-Forwards` header field nor
the RFC 3261 branch cookie.

Thirteen of the thirty-two rules skip on a one-message run, which is why the
response names them. Reach for `lint_dialog` first and use this to confirm one
message.

### `explain_rule`

Turns a rule identifier back into its catalog entry, so an identifier lifted
out of a finding, a CI log or a suppression file resolves without a round trip
to the source.

**Parameters:** `rule_id` (string, required) — one of the 32 catalog
identifiers, matched exactly, such as `OBS-3264-6.1-PT-UNDECLARED`. No optional
parameters, and the tool reads no capture, so it answers the same on any
server. An unknown identifier fails with `invalid_params` (-32602) **listing all
32**, which doubles as the way to enumerate them.

```jsonc
// explain_rule { "rule_id": "OBS-3264-6.1-DIRECTION-UNMET" }
{
  "schema_version": 1,
  "rule_id": "OBS-3264-6.1-DIRECTION-UNMET",
  "title": "sendrecv negotiated, media observed one way",
  "severity": "warning",
  "basis": "observation",
  "rfc": 3264,
  "section": "6.1",
  "citation": "RFC 3264 §6.1",
  "url": "https://www.rfc-editor.org/rfc/rfc3264#section-6.1",
  "scope": "media",
  "rulesets": ["all", "observation", "observed", "rfc3264"],
  "rule_catalogue": "docs/sip-lint-rules.md"
}
```

`rulesets` lists every selector that reaches this rule, so any entry passes
straight back as a `lint_dialog` `rulesets` value. `scope` says what the rule
has to read before it can run: `message`, `dialog` or `media`.

An unknown identifier returns invalid_params (-32602) listing all thirty-two,
because an empty answer would read as "that rule found nothing".

### `explain_response_code`

The IANA registry, not an agent's recollection.

**Parameters:** `code` (integer, required) — a SIP status code from 100 to 699.
Outside that range fails with `999 is not a SIP response code (100-699)`. No
optional parameters, and this tool reads no capture either, so it answers on a
server holding nothing.

```jsonc
// explain_response_code { "code": 488 }
{
  "schema_version": 1,
  "code": 488,
  "class": "failure",     // provisional|success|redirect|challenge|canceled|declined|failure
  "explanation": "488 Not Acceptable Here — Codec negotiation failed. Compare the SDP offer against the callee's supported codecs and ptime values.",
  "registered": true
}
```

`class` distinguishes a challenge from a failure: `401` is `challenge`, not
`failure`, because a challenged call has not failed — it is mid-handshake.
`registered: false` means the code is outside the registry, usually a vendor
extension. The tool says so rather than inventing a meaning.

### `evaluate_expectations`

A pass/fail verdict on the loaded capture, and an exit code for a build.

Every other tool here makes a bad day shorter. This one prevents it, and it
moves sipnab from something an operator reaches for during an incident to
something that runs on every commit. The rules live in a checked-in
`sipnab.expect.toml` beside the SBC config: that file is the UX, and this tool
is how an agent reasons about it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `rules` | object[]? | The suite inline. Each rule is `{metric, op, value}` plus optional `name`, `scope`, `min_sample` and `grounded_only`. Mutually exclusive with `rules_toml`. | Give `rules_toml` instead. |
| `rules_toml` | string? | The verbatim text of a `sipnab.expect.toml`. Mutually exclusive with `rules`. | Give `rules` instead. |
| `suppression_file` | string? | A lint suppression file in `--mcp-file-root`, applied to the `lint_errors` rules. | Discovers a `.sipnablint` beside the capture, exactly as [`lint_dialog`](#lint_dialog) does. |

Passing the file's own bytes is the point of `rules_toml`: the agent then judges
the capture against exactly what CI judges it against, rather than against its
own transcription. Passing both, or neither, fails — two suites in one call have
no defined order, and a call with no suite would report a verdict on nothing.

One rule is a metric, a comparison, a threshold, and what it applies to:

| Field | Legal values |
|---|---|
| `metric` | `count` (dialogs matching the scope), `asr` (answered over seized, as a PERCENT from 0 to 100, the same unit `group_dialogs` reports), `lint_errors` (conformance findings at or above a severity floor), `mos_p<N>` (a MOS percentile, `mos_p0` worst to `mos_p100` best). |
| `op` | `>=`, `>`, `<=`, `<`, `==`, `!=` |
| `value` | The threshold, in the metric's own unit. |
| `scope` | `filter:<alias-or-DSL>` to narrow by dialog, or `severity:<info\|notice\|warning\|error>` to set the floor a `lint_errors` rule counts from. Omitted means the whole capture. |
| `min_sample` | Observations below which the rule reports `skipped` rather than a verdict. |
| `grounded_only` | MOS metrics only. Defaults to `true`. |

```jsonc
// evaluate_expectations { "rules": [
//   { "name": "no codec rejections", "metric": "count", "op": "==", "value": 0,
//     "scope": "filter:response_code == 488" },
//   { "name": "audio floor", "metric": "mos_p10", "op": ">=", "value": 4.0 },
//   { "name": "answer rate", "metric": "asr", "op": ">=", "value": 99, "min_sample": 50 } ] }
{
  "schema_version": 1,
  "verdict": "pass",
  "exit_code": 0,
  "rules_total": 3, "evaluated": 2, "passed": 2, "failed": 0, "skipped": 1,
  "dialogs_in_capture": 2,
  "streams_in_capture": 2,
  "suppressions_applied": false,
  "results": [
    { "index": 0, "name": "no codec rejections", "metric": "count",
      "unit": "dialogs", "op": "==", "threshold": 0.0,
      "scope": "filter:response_code == 488", "observed": 0.0, "sample": 2,
      "verdict": "pass", "reason": "0 is == 0 over 2 dialog(s)" },
    { "index": 1, "name": "audio floor", "metric": "mos_p10",
      "unit": "mos (1.0-5.0)", "op": ">=", "threshold": 4.0,
      "observed": 4.358100156401542, "sample": 2, "ungrounded_excluded": 0,
      "verdict": "pass", "reason": "4.3581 is >= 4 over 2 scored stream(s)" },
    { "index": 2, "name": "answer rate", "metric": "asr",
      "unit": "ratio (0.0-1.0)", "op": ">=", "threshold": 0.99,
      "observed": 1.0, "sample": 2, "min_sample": 50,
      "verdict": "skipped",
      "reason": "skipped: 2 seizure(s) is below the declared min_sample of 50" }
  ],
  "capture_identity": { "node": "capture-01", "instance": "1d1a718cb5c33b7c52754-1",
                        "dialog_generation": 13, "stream_generation": 2 }
}
```

**`unit` rides on every outcome, and reading it is not optional.** `asr` here is
a RATIO from 0.0 to 1.0, and the same name in
[`group_dialogs`](#group_dialogs) is a PERCENT. A threshold of `0.99` means 99%
under one reading and 1% under the other, so the answer names its unit rather
than leaving it to this page.

**An empty population FAILS, and the message says why.** Three failure modes get
a gate deleted rather than fixed, and each one has an answer here:

| Failure mode | What this tool does |
|---|---|
| Passing on data it never judged | A rule whose population is empty reports `fail` with `reason` beginning `unevaluable:`. A MOS threshold on a capture full of AMR-WB would otherwise score every stream off a placeholder and report green having measured nothing. |
| Failing on a sample too small to mean anything | `min_sample` is a declared floor. Below it a rule reports `skipped`, so a three-call smoke test never trips an ASR threshold on a Friday afternoon. |
| Lying about coverage | A suite where every rule skipped reports `not_evaluated` with exit code `2`, distinct from a pass. A file of rules that never run is exactly the thing that stays in a repository claiming to check something. |

Declaring `min_sample` of 1 or more is the ONLY way to have an empty population
tolerated, and that asymmetry carries weight: a gate goes quiet only where its
author wrote down that it may. `min_sample: 0` declares no floor at all, so it
leaves the empty case failing exactly as an absent one does.

```jsonc
// evaluate_expectations { "rules": [{ "metric": "asr", "op": ">=", "value": 95 }] }
// ... on a capture holding two REGISTER dialogs and no call attempt:
{ "verdict": "fail", "exit_code": 1, "evaluated": 1, "failed": 1,
  "results": [ { "index": 0, "metric": "asr", "observed": null, "sample": 0,
    "verdict": "fail",
    "reason": "unevaluable: no seizure was in scope, so 'asr >= 95' rests on nothing. Declare a min_sample of 1 or more to accept an empty population in writing; a gate does not pass on data it never judged" } ] }
```

The verdict tests the SAMPLE rather than whether a value came back. `count`
always produces a value — zero matches is zero — so checking the value alone let
`count == 0` pass on a capture holding no dialogs at all, which is the exact
"green on data it never judged" this design refuses.

`exit_code` is what a command line reports: `0` every rule that ran passed, `1`
at least one failed, `2` nothing ran. CI has to tell a green run from a run that
judged nothing, and a shell script comparing against `0` cannot.

Three more things the report says out loud. `sample` names how many observations
each figure rests on. `ungrounded_excluded` appears on MOS rules and counts the
streams whose codec has no published impairment value — with `grounded_only`
off, `notes` says instead that placeholder scores entered the percentile.
`suppressions_applied` says whether a lint suppression file was in force, so a
`lint_errors` count of zero cannot pass for one taken with every rule armed.

A defect in the RULES is a hard error rather than a per-rule failure: an unknown
metric, an unparseable filter, a `severity:` scope on a metric that reads no
findings, `grounded_only` on a metric that reads no MOS, or a percentile outside
0 to 100 all fail the whole call with `invalid_params` naming the rule's index.
A misspelled metric evaluating to "fail" would look identical to traffic that
genuinely broke the threshold, and one evaluating to "pass" would be a gate that
checks nothing while looking green. Half a gate reporting green is the outcome
this refuses to produce.

> Nothing on the CLI reaches this evaluator yet. It and `exit_code` both ship
> and both carry tests, and no flag runs them, so a checked-in
> `sipnab.expect.toml` cannot fail a build on its own today.


## Security

Scanner and abuse signals derived from the capture, and the one tool that turns them into something a firewall can act on.

### `security_findings`

Recent findings from active detection rules (scanner, fraud, digest,
reg-flood, etc.). Backed by the AlertEngine's bounded ring buffer
(default 1000 entries, kept in memory only).

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `kinds` | string[]? | Exactly four names: `scanner`, `fraud`, `digest`, `reg_flood`. Anything else fails with `invalid_params` naming all four — including `reg-flood` with a hyphen, which suggests the underscore spelling. | Findings of every kind. |
| `since` | string? | RFC 3339. Keeps findings recorded strictly after it. A malformed value fails with `since must be RFC 3339`. | The whole retained history. |
| `limit` | u32? | Ceiling is `--mcp-max-rows` (1000 by default). Higher clamps to it, `0` means the default. | 50 findings. |

**Returns** — a page object, not a bare array:

| Field | Type | Description |
|---|---|---|
| `findings` | object[] | This page of `{ rule_name, src_ip, detail, timestamp }`, newest first. |
| `returned` | usize | Rows in `findings`. |
| `total_matched` | usize | Findings matching `kinds` and `since` across the whole retained ring buffer. |
| `truncated` | bool | `true` when matches remain after this page. There is no cursor — narrow with `since`, or raise `limit`. |
| `armed_kinds` | string[] | The detectors this server runs. Empty means it runs none, so `findings` could only ever be empty. |
| `detection_armed` | bool | `false` when `armed_kinds` is empty, stated separately so a caller can branch on one field. |
| `note` | string? | Present **only** when no detector runs, saying so in words. |
| `schema_version` | u32 | `1` for this shape. |

> **Read `armed_kinds` before you read `findings`.** An empty findings list
> means "nothing tripped" only on a server that armed something; on any other
> it means nothing was watching, and the two are opposite operational states.
> A `kinds` value outside the vocabulary fails rather than answering with an
> empty list, which would be a third way to read `[]`. Cross-checking
> [`server_capabilities`](#server_capabilities) is not necessary for this
> question: the answer is in the response.

The page fields carry the meanings they do everywhere else on this surface —
[`search_messages`](#search_messages) documents the same four. `armed_kinds` is
per detector, which is what makes it worth reading rather than a bare
"detection is on": a server started with `--kill-scanner` alone answers
"no fraud findings" for a capture full of toll fraud, and `armed_kinds:
["scanner"]` is what tells an agent that the question was never asked.

Arming a rule takes a flag on the server command line, such as `--kill-scanner`
or `--digest-leak`. Findings then land in a bounded in-memory ring buffer
(1000 entries by default, `--findings-history` to change it) and go nowhere
else — stopping the process discards them.

`timestamp` records when the rule **fired during analysis**, not when the packet
arrived. On a replayed pcap those differ by years, so a `since` value copied
from a dialog's `created_at` returns everything.

The example runs against
[`tests/pcap-samples/sip-auth-failure.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-auth-failure.pcapng)
on a server started with `--digest-leak`:

```jsonc
// security_findings {}
{
  "schema_version": 1,
  "findings": [
    {
      "rule_name": "digest",
      "src_ip": "203.0.113.101",
      "detail": "WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)",
      "timestamp": "2026-08-13T16:16:02.880725566+00:00"
    }
  ],
  "returned": 1,
  "total_matched": 1,
  "truncated": false,
  "armed_kinds": ["digest"],
  "detection_armed": true
}
```

The same tool on a server started without a detection flag answers with an
empty `findings` list, `armed_kinds: []`, `detection_armed: false` and a `note`
saying that nothing was watching. `armed_kinds: ["digest"]` above says the
opposite in the same field: this server watched for digest weaknesses and for
nothing else, so it answers nothing about scanners either way.

### `generate_fail2ban_rule`

A fail2ban filter and jail derived from ONE recorded security finding.

Scoped to one finding, with that finding attached as the evidence. A rule
generated from a class of findings would be a policy this tool has no standing
to write. A rule generated from one, with the alert line it matches printed
beside it, is something an operator can read and decide on.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `finding_id` | string | `<rule_name>@<src_ip>@<timestamp>` — the three fields [`security_findings`](#security_findings) already returns for every finding. | Required — the call fails. |

The id derives from the finding rather than coming from a counter, because an
assigned id would have to survive eviction, restart and a second server reading
the same capture, and none of those hold for a position in a bounded ring
buffer. An agent holding "id 7" across a restart would act on a different
finding.

```jsonc
// generate_fail2ban_rule { "finding_id": "digest@203.0.113.101@2026-08-28T11:31:03.859034298+00:00" }
{
  "schema_version": 1,
  "finding_id": "digest@203.0.113.101@2026-08-28T11:31:03.859034298+00:00",
  "evidence": {
    "rule_name": "digest",
    "src_ip": "203.0.113.101",
    "detail": "⟦untrusted-capture-data⟧WeakAlgorithm: challenge uses algorithm=MD5 (should be SHA-256+)⟦/untrusted-capture-data⟧",
    "timestamp": "2026-08-28T11:31:03.859034298+00:00"
  },
  "filter_name": "sipnab-digest",
  "filter_path": "/etc/fail2ban/filter.d/sipnab-digest.conf",
  "filter_conf": "# Generated by sipnab from finding digest@203.0.113.101@...\n[Definition]\nfailregex = ^.*\\[ALERT\\] digest src=<HOST> .*$\nignoreregex =\n",
  "jail_path": "/etc/fail2ban/jail.d/sipnab-digest.conf",
  "jail_conf": "[sipnab-digest]\nenabled  = true\nfilter   = sipnab-digest\nlogpath  = /var/log/syslog\nport     = 5060,5061\nprotocol = udp\nmaxretry = 3\nfindtime = 600\nbantime  = 3600\n",
  "log_line_format": "[ALERT] <rule_name> src=<ip> <detail>",
  "caveats": [ /* three, below */ ]
}
```

**The `failregex` matches sipnab's own alert line**, the `[ALERT] <rule> src=<ip>
<detail>` form sipnab writes. So the jail sees nothing until sipnab runs with
`--alert syslog`, or something captures its stderr to the `logpath`. That is the
first caveat, and it is the one that makes an otherwise-correct jail inert.

The other two caveats say what the numbers are not. `maxretry`, `findtime` and
`bantime` are fail2ban's conventional starting values rather than figures sipnab
measured on this traffic — choose them from your own false-positive tolerance.
And one finding is evidence that this detector fired, not that every future
match is an attacker: the jail bans any source the detector reports, this one
included. A loopback `src_ip` adds a fourth caveat, because a jail acting on it
would ban the host from itself.

Two refusals. A server with no detector armed holds no findings at all, and says
so rather than reporting an unknown id:

```jsonc
{ "code": -32602,
  "message": "this server holds no findings: no detection rule was armed, so nothing could have been recorded. Arm one with --kill-scanner, --fraud-detect, --digest-leak or --reg-flood and re-run the capture." }
```

An id the server does not hold comes back with the ids it does hold, up to the
row cap, so a caller that mistyped a timestamp does not have to go back to
[`security_findings`](#security_findings). The scan walks the whole ring buffer
for that list, because a truncated scan cannot report what it truncated — and
here the truncated part is the vocabulary the caller gets offered.

`detail` arrives fenced: it quotes headers a sender wrote. `rule_name` does not,
because sipnab chose it — and the tool checks that name is a bare identifier
before writing it into a regular expression, since a name carrying a
regular-expression operator would produce a pattern the author never wrote.


## Evidence and provenance

Every claim above points back at bytes. These retrieve those bytes, prove which frame they came from, and package them so someone else can check the work.

### `show_evidence`

Follows a frame pointer back to the bytes it names, turning one from a string
into something a reader can check without reopening the capture.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `refs` | string[] | At least one pointer in `<source>#<ordinal>@<digest>` form. An empty array fails with `refs must name at least one frame pointer`, because an empty result would read as "nothing resolved". | Required — the call fails. |
| `max_bytes` | u32? | 1 to 4096 bytes of hex per frame. Higher clamps to 4096, and to the frame length when the frame is shorter. **`0` means zero bytes here**, not the default — this is the one parameter on the surface that does not read `0` as "unset". | 256 bytes, enough for a SIP start line and its headers. |

A pointer whose `@digest` half is missing still resolves, and comes back
`unverified` rather than `verified`. Batching is the normal use — one bad
pointer never discards the rest, so each entry reports its own `status`.

**Not every tool returns a pointer, and the two that do use different key
names.** A caller planning around "every tool returns `frame_ref`" would look
for a key most responses do not carry:

- **`frame_ref`** — the findings `lint_dialog` and `validate_message` return.
  Named apart because a finding cites a message *index*, and the pointer is
  what makes it checkable without the list that index counts within.
- **`frame`** — `list_dialogs`, `find_problems`, `tail_dialogs`, `get_dialog`
  (its dialog and its messages), `get_message`, the JSON `get_dialog_report`,
  and the streams in `rtp_stats`.
- **No pointer at all** — `search_messages`, `search_by_time`,
  `find_correlated`, `triage_call`, `check_codec_negotiation`,
  `diagnose_registration`, `compare_dialogs`, `get_sdp_timeline`, the RTCP
  remote reports, and the capture-level counters.

A fact with no pointer omits the key entirely — never `""`, never frame 0, both
of which read as a real pointer.

The example follows the `frame` pointer that
[`list_dialogs`](#list_dialogs) returned for the first call in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap),
with `max_bytes` cut to 64 to keep the hex short:

```jsonc
// show_evidence { "refs": ["tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546"],
//                 "max_bytes": 64 }
{
  "schema_version": 1,
  "requested": 1,
  "resolved": 1,
  "verified": 1,
  "summary": "1 of 1 pointer(s) resolved; 1 verified against a recorded digest",
  "frames": [
    {
      "pointer": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
      "status": "verified",
      "source": "sip-rtp-g711.pcap",
      "ordinal": 0,
      "frame_bytes": 500,
      "hex_bytes_shown": 64,
      "truncated": true,
      "hex": "00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00 01 e6 fe 17 40 00 40 11 22 cd 0a 00 02 14 0a 00 02 0f 13 c4 13 c4 01 d2 1a 06 49 4e 56 49 54 45 20 73 69 70 3a 74 65 73 74 40 31 30 2e 30 2e 32"
    }
  ]
}
```

`source` reports the bare filename, not the path the pointer carried — the tool
keeps only the final component and pushes it through the file-root guard. A
pointer that resolves to nothing keeps its entry and gains a `reason` instead of
the byte fields:

```jsonc
// show_evidence { "refs": ["bogus#1@deadbeef"] }
{
  "schema_version": 1,
  "requested": 1,
  "resolved": 0,
  "verified": 0,
  "summary": "0 of 1 pointer(s) resolved; 0 verified against a recorded digest",
  "frames": [
    {
      "pointer": "bogus#1@deadbeef",
      "status": "unresolvable",
      "reason": "cannot open '<file-root>/bogus': Failed to open pcap file ..."
    }
  ]
}
```

`status` has three values and they are deliberately not interchangeable:

| Status | Means |
|---|---|
| `verified` | The frame is there and its bytes hash to what the pointer recorded. The capture has not changed under the claim. |
| `unverified` | The frame is there, the pointer carried no `@digest`, so this checked **nothing**. The bytes could come from a rotated capture. |
| `unresolvable` | No bytes. `reason` says why — a malformed pointer, a source outside the file root, a frame past the end, or a digest mismatch. |

A digest mismatch is `unresolvable`, not a resolved frame with a warning.
Returning bytes from a capture that changed after someone made the pointer
would manufacture exactly the confidence this feature exists to provide.

The file root confines every source. A pointer carries whatever path the
producing run read, which usually sits outside the server's reach. The tool
therefore takes only the final component and pushes it through the same guard
the file tools use.
A pointer naming a live device or a HEP listener is `unresolvable`: sipnab
retains parsed messages, not frames, so there is nothing on disk to seek to.

One bad pointer never discards the rest of a batch — each gets its own entry, so
a caller can tell which one failed. `max_bytes` caps the hex per frame (default
256, maximum 4096) and `truncated` says when a frame was longer.

### `decode_evidence`

Follows one frame pointer down to the byte range of a single header.

[`show_evidence`](#show_evidence) answers half the provenance question — are
these the bytes behind the claim — and hands back a hexdump. That
leaves a reader holding 500 bytes of Ethernet, IP, UDP and SIP when one header
line provoked the finding. This tool follows the same pointer through the same
resolver and reports what the frame CONTAINS: the link type, the innermost
addressing, and one row per SIP header with where that header sits.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `frame_ref` | string | ONE pointer in `<source>#<ordinal>@<digest>` form — the `frame` key on a dialog, message or stream, or the `frame_ref` key on a `lint_dialog` or `validate_message` finding. Both names carry the same text. A blank string fails with `invalid_params`. | Required — the call fails. |
| `field` | string? | Keep only headers with this name, matched case-insensitively against the canonical long form (`Contact`, never `m`). | Every header in the message. |

One pointer rather than a batch, unlike `show_evidence`: a status line per
pointer is small, and a whole packet's structure per pointer fills a context
window with frames nobody asked to read. `field` is the compact form and the one
an agent chasing a finding wants — a REGISTER carries a dozen headers and the
malformed one is a single line.

The example follows the pointer
[`list_dialogs`](#list_dialogs) returns for the first call in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// decode_evidence { "frame_ref": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
//                   "field": "Contact" }
{
  "frame_bytes": 500,
  "link_type": 1,
  "network": { "src_addr": "10.0.2.20", "src_port": 5060,
               "dst_addr": "10.0.2.15", "dst_port": 5060, "transport": "UDP" },
  "ordinal": 0,
  "payload_bytes": 458,
  "payload_offset": 42,
  "pointer": "tests/pcap-samples/sip-rtp-g711.pcap#0@db88659b94678546",
  "schema_version": 1,
  "sip": {
    "header_count": 9,
    "headers_returned": 1,
    "headers": [
      { "name": "Contact", "value": "sip:sipp@10.0.2.20:5060", "index": 5,
        "message_byte_start": 227, "message_byte_end": 259,
        "frame_byte_start": 269, "frame_byte_end": 301 }
    ],
    "is_request": true,
    "method": "INVITE",
    "start_line": "INVITE sip:test@10.0.2.15:5060 SIP/2.0"
  },
  "source": "sip-rtp-g711.pcap",
  "status": "verified"
}
```

`header_count` counts the message and `headers_returned` counts this answer, so
`field` never hides how much it filtered out. `index` is the ordinal a lint
finding cites, so a caller holding one pairs the two without matching on header
names. The message-relative pair locates the header inside the SIP bytes and the
frame-relative pair locates it inside the whole frame, which is what turns
`show_evidence`'s hexdump into a quotation.

**A range this tool cannot vouch for disappears, and `ranges_unavailable` says
why.** The SIP parser keeps no span per header, so this tool walks the raw
message a second time to find where each logical header line sits — and a second
walk of one grammar can part company with the first, over a line with no colon,
a non-UTF-8 line, an over-long one, or the per-message header cap. Every located
range therefore has to reproduce the value the parser already produced, and on
any disagreement the WHOLE set drops:

```jsonc
{ "sip": { "header_count": 7, "headers_returned": 7, "headers": [ /* no byte keys */ ],
           "ranges_unavailable": "the header walk found 6 logical header line(s) where the parser produced 7 header(s), so nothing pairs them reliably. A range pinned to the wrong header still resolves, which makes it worse than no range." } }
```

Citing a neighboring header would be worse than citing none, precisely because
it resolves. The frame-relative pair also drops on its own when the transport
payload does not sit at exactly one place in the frame — a decapsulated or
reassembled payload need not be a contiguous slice at all, and two candidate
offsets make `frame[start..end]` a coin toss. Keys stay absent rather than
empty throughout, the rule `frame_ref` already follows: `0` and `""` both read
as real values.

`status` carries the same three words `show_evidence` uses, with the same
meanings. An unresolvable pointer keeps its own compact shape — no addressing,
no headers, no byte counts — so a thin decode can never pass for a partial one:

```jsonc
// decode_evidence { "frame_ref": "uprobe:opensips/1234#7" }
{
  "schema_version": 1,
  "pointer": "uprobe:opensips/1234#7",
  "status": "unresolvable",
  "reason": "read 7 came from the TLS library inside opensips (pid 1234); it was never a frame on any wire, so there is no capture to seek into and no bytes to verify it against. This is not a missing file"
}
```

Two more refusals sit between "resolved" and "decoded", and each keeps its own
key rather than pretending to a decode. `decode_unavailable` appears when the
frame resolves and the capture does not reopen for its link-layer type —
decoding an SLL or PPPoE capture as Ethernet produces addressing that looks
decoded and is wrong — and when the frame carries no SIP-bearing transport.
`not_sip` appears when the transport payload does not parse as SIP.

**The file root confines every source.** A pointer carries whatever path the
producing run read, usually an absolute path far outside this server's reach.
This tool never opens that path: it keeps the final component and pushes it
through `resolve_in_root`, the same guard the file tools use, which is why
`source` above reads `sip-rtp-g711.pcap` and not the path in the pointer. Without
that step, a tool taking a caller-supplied path and returning the decoded
contents of the file there is an arbitrary-file-read primitive wearing a
`readOnlyHint`. A pointer naming a file outside the root comes back
`unresolvable` with the confined path in its reason.

**No timestamp, deliberately.** The resolver returns the frame's bytes without
the capture record that framed them, so any time here would be an invention —
and a manufactured capture time on an evidence surface is the exact failure this
mechanism exists to prevent. [`get_message`](#get_message) carries the message's
time alongside the same pointer. For the same honesty, a frame carrying two
SIP messages packed into one TCP segment decodes as the FIRST one: the
pointer is frame-granular, so it cannot name the second.

### `build_evidence_package`

One directory holding everything an escalation needs for a set of calls.

Analysis ending in a paragraph creates work: somebody has to translate it into
an attachment, a ticket or a message to a carrier. This tool ends the analysis
in an artifact instead — a pcapng of the signaling, a ladder and an RTP-stats
file per call, a manifest, and a README carrying the rebuilt-frames disclaimer.
The disclaimer lives INSIDE the directory on purpose. The directory is what gets
forwarded, and whoever opens it at the carrier never saw the tool that made it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_ids` | string[] | At least one Call-ID the store holds, in the order they should appear. A repeat packages once. More than `--mcp-max-rows` of them fails, asking for batches. | Required — the call fails. |
| `filename` | string | A bare directory name inside `--mcp-file-root`, and it must not already exist. | Required — the call fails. |

```jsonc
// build_evidence_package { "call_ids": ["1-1966@10.0.2.20", "1-1968@10.0.2.20"],
//                          "filename": "escalation-4417" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/escalation-4417",
  "calls": 2,
  "messages": 10,
  "files": [
    "README.md", "manifest.json",
    "call-01-ladder.md", "call-01-rtp.json",
    "call-02-ladder.md", "call-02-rtp.json",
    "signaling.pcapng"
  ],
  "summary": "2 call(s) packaged in /var/spool/sipnab-exports/escalation-4417. README.md inside it states that the frames in signaling.pcapng were rebuilt from parsed messages rather than copied, which is the claim the recipient has to see."
}
```

`manifest.json` maps each ordinal back to its Call-ID and repeats the
disclaimer as a field:

```jsonc
{
  "schema_version": 1,
  "sipnab_version": "0.5.129",
  "package": "escalation-4417",
  "signaling": "signaling.pcapng",
  "signaling_frames_rebuilt": true,
  "calls": [
    { "index": 1, "call_id": "1-1966@10.0.2.20",
      "ladder": "call-01-ladder.md", "rtp_stats": "call-01-rtp.json" },
    { "index": 2, "call_id": "1-1968@10.0.2.20",
      "ladder": "call-02-ladder.md", "rtp_stats": "call-02-rtp.json" }
  ]
}
```

**Filenames are ordinals, never the Call-ID.** A Call-ID is arbitrary text a
peer chose: it can hold a separator, a leading dash, four hundred characters, or
bytes no filesystem wants. None of that belongs in a name this tool constructs,
so the manifest carries the correlation and `call-01-ladder.md` carries the
content.

**The pcapng holds every named call's messages in one chronological run**, not
grouped by leg. A multi-leg escalation reads as one timeline, and splitting it
by leg hides the interleaving that is usually the finding. Its frames come from
[`export_capture`](#export_capture)'s writer and carry that tool's whole
asterisk: the SIP layer is faithful, everything under it comes rebuilt from
recorded addresses and ports, a SIP-over-TCP message writes as UDP, and RTP,
RTCP, DNS and ICMP are absent. The RTP measurements in `call-NN-rtp.json` come
from the ORIGINAL capture and nobody can reproduce them from the pcapng alone,
which is exactly why the README says so.

The ladder and the stats come from [`render_ladder`](#render_ladder) and
[`rtp_stats`](#rtp_stats) rather than from a second rendering path, so a package
can never disagree with what the same agent saw over the wire.

**Nothing gets created until every Call-ID checks out.** The tool collects the
messages first, so an unknown id in the middle of the list fails with
`invalid_params` and leaves no directory and no claimed name behind. Any write
that fails afterwards removes the part-built directory too: a half-written
package would hold the name against a retry and read as complete evidence.

The [shared file rule](#file-tools--the-shared-rule) applies in full — bare
names only, no symlink out of the root, and the tool declines a name already
taken, including by a directory:

```jsonc
{ "code": -32602,
  "message": "the requested filename '/var/spool/sipnab-exports/escalation-4417' already exists. sipnab will not write over it, because that file may be the only copy of a capture — choose a name that is not taken." }
```

An empty `call_ids` array fails too, with `an empty package is a directory of
disclaimers`.

### `save_findings`

**The only write verb on sipnab's network surface.** Requires
`--mcp-allow-save-findings`, which is off by default.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `summary` | string | A one-line conclusion. sipnab clips it at 500 characters and reports the original length. | Required — the call fails. |
| `call_id` | string? | Any string. **Not checked against the store**, deliberately: a note about a call the store has since dropped is still the note that mattered. | The finding records no call. |
| `detail` | string? | Supporting text, clipped at 4096 characters. | The finding carries a summary alone. |

```jsonc
// save_findings { "summary": "audit probe", "call_id": "1-1966@10.0.2.20", "detail": "x" }
{
  "schema_version": 1,
  "seq": 0,
  "written_at": "2026-08-13T12:12:17.976455577+00:00",
  "summary_chars_submitted": 11,
  "detail_chars_submitted": 1,
  "truncated": false,
  "recorded_total": 1,
  "remaining": 999,
  "readable_over_mcp": false,
  "delivered_to": "sipnab log (tracing/journald/stderr)",
  "capture_identity": {
    "node": "capture-01",
    "instance": "1d1a718cb5c33b7c52754-1",
    "dialog_generation": 13,
    "stream_generation": 2
  }
}
```

`readable_over_mcp: false` is a constant, not a state. It appears on every
response so a client never has to infer the dead end from the absence of a
reader.

It records what the agent concluded, and that is all it does. **The finding goes
to sipnab's log and nowhere else**: no tool reads it back, it appears in no query
result, and no analysis consumes it. There is no `list_findings`, deliberately.

That dead end is the entire safety argument. Every response on this surface
carries attacker-controlled text — `From` display names, `User-Agent` strings,
raw message snippets — so a write verb reachable from that text must not be able
to change what an operator is reading, or to come back later as evidence the
agent then cites. The compiler enforces this rather than convention: the
annotation types stay private to the MCP module, so no analysis code can name
them.

Read your findings where operational facts already live — `journalctl -u sipnab`,
syslog, or stderr. Each line records the agent's claim as the agent's claim,
never as a measurement of sipnab's own.

Two bounds, both reported rather than silent. sipnab clips text at 500
characters of `summary` and 4096 of `detail`, setting `truncated` and
`*_chars_submitted` giving the original length. And one process accepts 1000
findings, after which writes are **refused** with an error naming the limit —
never accepted and discarded, because an agent told "recorded" about something
the server threw away is worse off than one told plainly that it was not.
`remaining` counts down so the bound is visible before it bites.


### `explain_attribution`

An agent that reports "media anchored at `<addr>`" cannot otherwise say whether
that came from SDP the two parties exchanged, from a relay sipnab asked, or
from a mirrored datagram anybody could have sent. Those carry very different
weight in an incident review and every other surface renders them identically.

`delivery_trust`, strongest first:

| value | meaning |
|---|---|
| `asked` | sipnab asked the relay over its control socket; no third party could answer |
| `hmac-verified` | delivered over HEP, authenticated with a token covering the datagram |
| `plain-secret` | delivered over HEP with a shared secret; the token does not cover the datagram, so anyone who captures one can replay it |
| `port-gated-only` | accepted because it arrived on the expected port and for no other reason — **the source is not authenticated** |
| `not-relay-asserted` | the parties' own claim in SDP |

The authentication answer comes from the run's configuration rather than a
per-packet record, and that is correct rather than a shortcut: ingest rejects any datagram
that fails authentication, so everything still in the store arrived under
whatever posture the run configured. With no posture configured it
reports the **weakest** reading — a tool whose job is telling you what a claim
is worth must not round up in the absence of information.

```jsonc
// explain_attribution { "call_id": "call-2c9d47@192.0.2.10" }
{
  "call_id": "call-2c9d47@192.0.2.10",
  "endpoints": [
    {
      "address": "192.0.2.10",
      "port": 10000,
      "asserted_by": "signaled",
      "input_origin": "wire",
      "observed_at": "2023-11-14T22:13:25+00:00",
      "delivery_trust": "not-relay-asserted",
      "delivery_note": "the parties' own claim in SDP, not a relay's statement about its allocation"
    }
  ],
  "unauthenticated_endpoints": 0,
  "schema_version": 1
}
```

### `decode_ng`

`decode_evidence` decodes a SIP frame. This decodes a relay control message,
and adds the question no other surface answers: **which path carried it, and did
that path authenticate whoever sent it.**

That distinction decides what the message is worth. Anything on the segment can put a
control message on the HEP port, and landing there is the whole reason sipnab
credits it -- whereupon it names a call and binds media to an address its sender
chose. One delivered to an
HMAC-authenticated listener is a different claim entirely. Both decode to the
same bytes.

`delivery` is `hep` or `sniffed-udp`. `delivery_trust` uses the same scale as
[`explain_attribution`](#explain_attribution). `on_believed_mirror_port` stands
apart because it is the ONLY reason anything believes a sniffed message at all,
and a reader should see the whole of that reason rather than its conclusion.

Status is `verified`, `unverified` or `unresolvable`, as in
[`decode_evidence`](#decode_evidence), and a pointer leading nowhere returns
a reason rather than failing the call.

```jsonc
// decode_ng { "frame_ref": "relay.pcap#412@9f2c1a" }
{
  "pointer": "relay.pcap#412@9f2c1a",
  "status": "verified",
  "source": "relay.pcap",
  "ordinal": 412,
  "delivery": "hep",
  "delivery_trust": "port-gated-only",
  "delivery_note": "accepted because it arrived on the expected port and for no other reason: the source is not authenticated",
  "on_believed_mirror_port": true,
  "command": "offer",
  "call_id": "call-2c9d47@192.0.2.10",
  "has_sdp": true,
  "sdp_bytes": 231,
  "schema_version": 1
}
```

## Export and handoff

Getting the result out of sipnab and into the next tool, the next team, or a bug report someone else can reproduce.

### File tools — the shared rule

`list_captures`, `export_capture`, `export_audio`,
[`compare_captures`](#compare_captures) and
[`build_evidence_package`](#build_evidence_package) all require
`--mcp-file-root <DIR>` and refuse to run without it. They take a **bare
filename, never a path**. [`generate_repro`](#generate_repro) joins them the
moment you give it a `filename`, and
[`decode_evidence`](#decode_evidence) pushes the source half of a frame pointer
through the same guard.

sipnab refuses `../x`, `/etc/passwd` and `sub/dir.pcap` before any filesystem
call. That is the whole security model and it is deliberately absolute: a tool
accepting an agent-supplied path is an arbitrary file write, not an export.

Name checking alone does not finish the job, so sipnab does one more thing. A
symlink already sitting in the root is a single bare component — it passes every
check above, and the kernel follows it when the file opens. sipnab therefore
compares the resolved path against the root in its fully resolved form and refuses a name by
where it points rather than by how someone spelled it. Each tool returns the
resolved path, so a caller learns where the bytes actually went.

That escape needed prior write access inside the root, so it never amounted to a
remote break. sipnab closes it because this page calls the boundary absolute, and
a boundary described that way ought to be.

> **The boundary stops an escape, and an overwrite.** Inside the root,
> `export_capture`, `export_audio`, `build_evidence_package`, `generate_repro`'s
> `filename` and `shutdown_server`'s `save_to` refuse a
> filename that already exists, name the file, and ask for one that is free.
> sipnab declines to write over a file it did not create, because that file may
> hold the only copy of a capture. Call
> [`list_captures`](#list_captures) to see which names a directory already
> uses.
>
> The guard covers every capture in the root, not only the one the run is
> reading. Narrowed to the current capture it would miss the others staged
> there for [`open_capture`](#open_capture), and every earlier export, which
> then fall to a name collision on a call that reports success.

### `export_capture`

Writes the SIP signaling sipnab is holding to a pcap. Use it to preserve
signaling **before** stopping a live capture — otherwise the messages end with
the process.

> **The file is not a copy of the capture.** sipnab keeps parsed messages, not
> the frames that arrived, so the export rebuilds one Ethernet/IP/UDP frame
> around each message. The SIP layer is faithful. Everything under it is
> reconstructed from the addresses and ports sipnab recorded.
>
> Concretely, the file holds **no RTP, no RTCP and no non-SIP traffic**, and
> writes a SIP-over-TCP message as UDP. On one measured export, 4,875 of the
> 5,000 packets that had been on the wire were absent.
>
> That matters beyond the analysis, because the output is a pcap and people
> forward pcaps. If the file is going to a carrier, a regulator or a court, say
> what it is — nothing inside it announces that the frames were rebuilt.

**Parameters:** `filename` (string, required) — a bare filename inside
`--mcp-file-root`. A path component of any kind fails with `'../escape.pcap' is
not a bare filename`. sipnab does **not** require a `.pcap` extension and does
not add one, so `notes.txt` writes a pcap under that name, which
[`list_captures`](#list_captures) then never lists. No optional parameters.

Returns `path` (the resolved absolute path, so you learn where the bytes went),
`messages`, `bytes` and `schema_version`:

```jsonc
// export_capture { "filename": "sig.pcap" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/sig.pcap",
  "messages": 10,
  "bytes": 5673
}
```

### `export_audio`

Writes one call's RTP audio to a WAV in the configured root. Fails when the
call carries no audio it can decode, rather than writing an empty file.

Requires `--retain-audio` on the server command line: call audio is
content, not signaling, so holding it in memory is an operator decision
rather than a side effect of enabling MCP. Without the flag the tool refuses,
and its refusal reports the media it measured and names the flag — a capture
setting, not a finding that the call was silent.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID whose streams carry audio sipnab can decode. | Required — the call fails. |
| `filename` | string | A bare filename inside `--mcp-file-root`, under the same rule `export_capture` applies. sipnab writes a WAV whatever extension you give it. | Required — the call fails. |

Returns `path`, `summary` and `schema_version`:

```jsonc
// export_audio { "call_id": "1-1966@10.0.2.20", "filename": "call.wav" }
{
  "schema_version": 1,
  "path": "/var/spool/sipnab-exports/call.wav",
  "summary": "Exported 8.5s of mu-law audio (425 frames, PCMU/8000Hz) to /var/spool/sipnab-exports/call.wav"
}
```

Without `--retain-audio` the refusal arrives as `internal_error` (-32603) rather
than `invalid_params`, and it reports what sipnab measured so the answer cannot
read as a silent call:

```text
No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1
decodable stream, but kept none of their payload, so there is nothing to
decode. Audio payload retention was off for this run — that is a capture
setting, not a finding that the call was silent. Start the server with
--retain-audio to hold payload for export.
```

### `export_vcon`

One observed dialog as a **vCon** conversation container
([`draft-ietf-vcon-vcon-core`](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/),
syntax `0.4.0`) — the interchange format a conversation travels in once it
leaves the system that captured it. Backed by
[`output::vcon`](https://github.com/NormB/sipnab/blob/main/src/output/vcon.rs).
`--export-vcon` writes the same container from the CLI.

Unlike its file-writing neighbors this tool writes nothing and needs no
`--mcp-file-root`. It returns the container inline, so `read_only_hint` is
`true` and the agent decides what to do with it.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. An unknown one fails with `invalid_params` (-32602) naming the value. | Give `filter` instead. |
| `filter` | string | A filter alias or a raw DSL expression, the vocabulary [`list_dialogs`](#list_dialogs) takes. The `--export-vcon-when` flag answers the same question but accepts the DSL expression ONLY -- it rejects an alias, which is [FLT1](https://github.com/NormB/sipnab/blob/main/docs/design/backlog.md). Every matching dialog comes back. | Give `call_id` instead. |
| `limit` | integer | 1 to `--mcp-max-rows` (1000 by default). | 50. |

Give `call_id` or `filter`, never both. The CLI refuses the same pair, because
a request naming a dialog AND a rule for choosing dialogs has two answers and
names neither.

**Export a set in one call.** An agent asked for every failed call used to list
dialogs and then issue one `export_vcon` per row — on a real capture, hundreds
of round trips to do what `--export-vcon-when` does in one invocation. Pass the
filter here instead. A container is a large answer, so `limit` bounds the set.
`total_matched` counts the whole store, so it is the number to page against.

A filter matching nothing answers with an empty set. "No call failed" is a
finding, and a refusal there would make a clean capture look like a broken
request.

There is no `format`. A vCon IS a JSON container defined by the draft, so a
markdown arm would render a document whose whole purpose is to travel between
machines — and an agent offered one would eventually hand the prose to
something expecting a container.

**What sipnab claims, and what it refuses to claim.** The container is an
**observer** vCon and says so in its own parties. sipnab read a mirror port: it
did not place the call, record it, or obtain anyone's permission to keep it. So
four things are absent by design, and their absence is the message:

- **No signature and no encryption.** A JWS over this container reads as *the
  domain that constructed this vouches for it*. What sipnab could truthfully
  sign is *these bytes are what sipnab observed*, and no signature algorithm
  carries that distinction. A verifier would check it, get back "authentic",
  and draw the wrong conclusion.
- **No party name sipnab vouches for, and `validation` is always `"none"`.**
  `From` and `To` are a claim the sender made about itself. sipnab EMITS a `name`
  when the wire carried a display name -- beside `sip_display_name`, not
  instead of it -- so a generic vCon reader shows a named party. What sipnab
  refuses is the claim, not the field. Treat the name as personal data: a
  redaction step must cover `name` as well as `sip_display_name`.
- **No consent and no lawful-basis attachment.** An empty consent field reads
  as "nobody recorded consent", a statement about the CALL. The truth is a
  statement about the producer: sipnab was never in a position to record one.
- **No `url`, ever.** Media travels INLINE or not at all, because sipnab hosts
  nothing a URL could reach and a dead link inside a record is
  indistinguishable from evidence somebody removed.

**What happens to the audio.** `dialog.type: "recording"` is a FORMAT term for
a Dialog Object carrying media. A consumer's `recordings` table is a PROVENANCE
term for containers from an in-path recorder. sipnab emits the first and is
never the second: it reconstructed the audio from a mirror port, and every WAV
it writes says "not a recording made by the endpoints".

So audio the run RETAINED travels inline -- base64url, `mediatype:
"audio/x-wav"`, and a `content_hash` of `sha512-` plus the base64url SHA-512 of
the DECODED bytes, which `sha512sum` on the exported `.wav` reproduces. The
`duration` on that object is the FILE's, never the call's. When a payload ring
dropped frames, a `recording-set` wraps it carrying the CALL's media window, so
the two clocks stand side by side -- that is the only way the format can say
"this file is a fragment of that call".

`capture_completeness.media` says which of four things happened, so nobody has
to read a missing `recording` object as an answer:

| `media` | What it means |
|---|---|
| `carried` | The audio is inline in a `recording` Dialog Object |
| `refused-over-budget` | sipnab decoded audio and REFUSED to inline it. One probed store answers 204 and drops a payload over 10485760 bytes without telling the producer, so the emitter enforces a 5 MiB budget itself. The audio exists and was not truncated |
| `none-decodable` | The run decoded no audio. `media_note` reports the measurement -- never that the call was silent |
| `not-considered` | Nobody asked this export for media. A fact about the export, not about the call |

**What the capture MISSED travels with the container, in two places.** vCon has
no field meaning "this record is incomplete" — `dialog.type: "incomplete"` says
the CALL did not complete, which accuses the traffic rather than the tap. So the
caveat rides in the `analysis` object AND in a `sipnab-capture-completeness`
attachment, both built from ONE value so the two cannot contradict each other.
Read `capture_completeness.note` before the contents: every clause in it is a
measurement of what this run READ and dropped.

**Every container comes back with its SHA-256.** sipnab computes it exactly as
`--vcon-digest` does — one function, over the container's own serialized bytes
— so a `SHA256SUMS` line or a store's ledger entry compares against this value
directly. That is what binds one emission to one ledger entry.

The digest identifies the DOCUMENT, not the dialog. `created_at` records the
moment sipnab wrote the container, so re-exporting one call produces a second
document with a new digest and the same `uuid`. Deduplicate on the `uuid`.

**What the container omits reaches you in the response.** A container over the
size budget carries no audio, which looks exactly like a conversation that had
none, and the caveat explaining the difference lives inside an attachment whose
body is JSON text. So the response repeats it where a caller reads it.
`completeness.note` is the container's own caveat, verbatim.
`completeness.max_inline_media_bytes` is the budget this run ENFORCED, never the
compiled-in default. `completeness.omissions` carries one row per loss, each
naming the counter it came from, how many, and in what unit. An empty list and
`complete: true` say the container lost nothing.

The response is an envelope, so one dialog and a filtered set arrive in one
shape:

```jsonc
// export_vcon { "filter": "response_code >= 400", "limit": 2 }
{
  "schema_version": 1,
  "returned": 2,
  "total_matched": 7,
  "truncated": true,
  "capture_identity": { /* which capture, and which revision of its stores */ },
  "containers": [
    {
      "call_id": "1-1966@10.0.2.20",
      "digest": "b6f0a1c9d84e2f7a3b5c6d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c",
      "completeness": {
        "note": "Produced by sipnab 0.5.141 on node capture-01. ... sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
        "media": "none-decodable",
        "media_note": "No audio payload retained: ...",
        "max_inline_media_bytes": 5242880,
        "complete": true,
        "omissions": []
      },
      "container": { /* the vCon itself, shown in full below */ }
    }
  ]
}
```

A run that lost something fills the same block instead:

```jsonc
"completeness": {
  "note": "Produced by sipnab 0.5.141 on node capture-01. ... — INCOMPLETE: 3 header line(s) exceeded the parser's length cap and were dropped, ...",
  "media": "refused-over-budget",
  "media_note": "...",
  "max_inline_media_bytes": 1048576,
  "complete": false,
  "omissions": [
    { "kind": "media_refused_over_budget", "count": 1, "unit": "recording" },
    { "kind": "headers_dropped_oversize", "count": 3, "unit": "header" }
  ]
}
```

One row per `— INCOMPLETE:` clause in the note, always. One set of counters
produces both the rows and the prose, so a reader holding either has the whole
account.

The container example runs against [`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

```jsonc
// the "container" member of one entry above
{
  "vcon": "0.4.0",
  "uuid": "0158a120-0392-86a4-a667-78f1c5213800",
  "created_at": "2026-08-24T22:13:31.238368261+00:00",
  "extensions": ["sip-signaling", "CC"],
  "parties": [
    {
      "sip": "sip:sipp@10.0.2.20:5060",
      "sip_contact": "sip:sipp@10.0.2.20:5060",
      "sip_display_name": "PCMU/8000",
      "validation": "none"
    },
    {
      "sip": "sip:test@10.0.2.15:5060",
      "sip_display_name": "test",
      "sip_user_agent": "FreeSWITCH-mod_sofia/1.6.12-20-b91a0a6~64bit",
      "validation": "none"
    },
    {
      "role": "observer",
      "sip_user_agent": "sipnab/0.5.124 (observer; node capture-01)",
      "validation": "none"
    }
  ],
  "dialog": [ { "sip_call_id": "1-1966@10.0.2.20" } ],
  "attachments": [
    {
      "purpose": "sip-message-trace",
      "party": 2,
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "sip_call_id": "1-1966@10.0.2.20", "messages": [ /* the same objects --json emits, one per message */ ] }
    },
    {
      "purpose": "sipnab-capture-completeness",
      "party": 2,
      "mediatype": "application/json",
      "encoding": "json",
      "body": {
        "note": "Produced by sipnab 0.5.127 on node capture-01. sipnab OBSERVED this dialog and took no part in it: ... sipnab read 852 frame(s) for this capture. No omissions recorded: every message sipnab held for this dialog is in this container. A capture-level analysis ran and ranked no blind spots.",
        "node": "capture-01",
        "sipnab_version": "0.5.124",
        "frames_read": 852,
        "undecodable_frames": 0,
        "sip_discarded_by_port_gate": 0,
        "sip_discarded_by_websocket_gate": 0,
        "messages_evicted": 0,
        "dialogs_refused": 0,
        "dialogs_rotated": 0,
        "blind_spots": [],
        "media": "none-decodable",
        "media_note": "No audio payload retained: sipnab measured 425 RTP packet(s) of PCMU on 1 decodable stream, but kept none of their payload, so there is nothing to decode. This is a statement about what this run kept, not a finding that the call was silent. ..."
      }
    }
  ],
  "analysis": [
    {
      "type": "report",
      "dialog": 0,
      "vendor": "sipnab",
      "product": "sipnab 0.5.143 (passive observer; not a recording system)",
      "schema": "sipnab-dialog-diagnosis/1",
      "mediatype": "application/json",
      "encoding": "json",
      "body": { "schema_version": 1, "sip_call_id": "1-1966@10.0.2.20", "final_status_code": 200, "capture_completeness": { /* the same object the attachment carries */ } }
    }
  ]
}
```

An unknown Call-ID answers with an error, never an empty container:

```jsonc
// export_vcon { "call_id": "no-such@nowhere" }
{ "code": -32602, "message": "call_id 'no-such@nowhere' not found" }
```

A filter that selects nothing answers with an empty set instead, because
"nothing matched" is a finding about the capture and "that call is not here" is
a mistake in the request.

**Three things a reader must not conclude.**

`blind_spots: []` is not the same answer as an absent `blind_spots`. The empty
array means a capture analysis ran and ranked nothing. The absent field means
nobody looked. Both doors here always run the analysis, so an absent field on a
container from this tool would be a defect rather than a clean bill.

The observer party is always the LAST entry, and every attachment's `party`
index points at it. Do not hard-code `2`: the count changes the day a container
carries a party the two observed headers did not name.

`uuid` is a UUIDv8 whose timestamp half is the DIALOG's, not the export's, so
re-exporting one dialog out of one capture keeps one identifier and a consumer
can deduplicate on it. Two dialogs that opened in the same millisecond on the
same node have only 12 bits separating them — that is inherent in the draft's
layout, which spends a v7's entropy on a host-derived `rand_b`.

A binary built without the `vcon` Cargo feature refuses this tool with
`invalid_params` and names the feature, rather than the tool being absent.
[`server_capabilities`](#server_capabilities) lists what a given binary carries.

### `validate_vcon`

Checks a vCon container against the working group's schema as sipnab vendors it
([`tests/schemas/vcon.schema.json`](https://github.com/NormB/sipnab/blob/main/tests/schemas/vcon.schema.json)). Backed by
[`output::vcon_schema`](https://github.com/NormB/sipnab/blob/main/src/output/vcon_schema.rs).

Run it before handing containers to a conserver. A store that refuses one
reports the refusal to whoever POSTed it, never to whoever built it — and a
validation pass over 4,216 real containers found 2 the schema rejects, with
nothing on any surface saying so.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. sipnab exports its container, then checks it. | Give `container` instead. |
| `container` | object | A container you already hold — one sipnab wrote, one another producer wrote, one a store rejected. It must be the object itself, not a string holding it. | Give `call_id` instead. |

Give one, never both.

**Three verdicts, not two.**

| `verdict` | What it means |
|---|---|
| `valid` | Nothing disagrees with the schema |
| `valid-except-documented-deviation` | Every finding is a shape sipnab emits on purpose that the schema rejects. `deviations` names each one and `explanations` says why |
| `invalid` | At least one finding is an ordinary defect. `errors` carries it |

The middle verdict carries the whole point. §4.3 of the draft says "it is
possible to have a Dialog Object with no parameters in it", the working group
agreed that shape in issue #20 after IETF 124, and the draft's own Appendix B
schema forbids it, because every Dialog Object requires a `start`. sipnab emits
one: the consultative call of an attended transfer, which the observed leg
never saw. A validator that folded that into a clean pass would teach a
producer that a missing `start` is fine — and a missing `start` on a `transfer`
object is exactly the defect the corpus pass found.

So the exemption is narrow. ONLY a Dialog Object with no members at all counts
as the documented deviation. A typed object missing `start` is an error, and
the two never merge.

```jsonc
// validate_vcon { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "verdict": "valid",
  "schema_path": "tests/schemas/vcon.schema.json",
  "schema_id": "https://ietf.org/vcon/schemas/unsigned-vcon.json",
  "errors": [],
  "deviations": [],
  "explanations": [],
  "call_id": "1-1966@10.0.2.20"
}
```

A container carrying an attended transfer's consultation object:

```jsonc
{
  "verdict": "valid-except-documented-deviation",
  "errors": [],
  "deviations": [
    {
      "instance_path": "/dialog/2",
      "keyword": "required",
      "detail": "missing required properties: start",
      "deviation": "empty-dialog-object"
    }
  ],
  "explanations": [
    {
      "name": "empty-dialog-object",
      "explanation": "The empty Dialog Object `{}` of section 4.3: ... reported here rather than passed silently ..."
    }
  ]
}
```

And the defect the corpus pass found, which is an error rather than an
exemption:

```jsonc
// validate_vcon { "container": { ..., "dialog": [ { "type": "transfer" } ] } }
{
  "verdict": "invalid",
  "errors": [
    {
      "instance_path": "/dialog/0",
      "keyword": "required",
      "detail": "missing required properties: start"
    }
  ],
  "deviations": []
}
```

A container that disagrees with the schema is an ANSWER, not a tool error. The
call fails with `invalid_params` only when the REQUEST is wrong: neither
argument, both arguments, an unknown `call_id`, or a `container` that is not a
JSON object.

**The validator reads the vendored file rather than a transcription of it.**
`jsonschema` is a dev-dependency, so a validator built on it would ship only in
the test tree — which is where the gap already was. This walks the schema
itself, implementing the draft-07 subset the file uses, and it refuses to guess:
a keyword outside that subset makes every validation report `invalid` naming
the keyword. Re-vendoring a richer schema therefore fails loudly instead of
quietly certifying less than it claims.

A binary built without the `vcon` Cargo feature refuses this tool with
`invalid_params` and names the feature.
[`server_capabilities`](#server_capabilities) lists what a given binary carries.

### `generate_repro`

A SIPp scenario that replays one call, with your hypothesis as an input.

The novel part is the second half of that sentence. `pin` names the aspects of
the captured request you believe caused the outcome and copies them
byte-for-byte. `vary` names the identity fields SIPp regenerates per run, so the
replay is a new call rather than a retransmission of the captured one. The
artifact then encodes the theory, and running it tests THAT rather than
replaying generically. Getting the split wrong emits a scenario that
"reproduces" for unrelated reasons, which is worse than emitting nothing.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds, carrying at least one request. | Required — the call fails. |
| `format` | string? | `"sipp"`, the only one. Anything else fails with `unknown format 'x'; 'sipp' is the only one`. | `"sipp"`. |
| `pin` | string[]? | Any of `branch`, `call_id`, `cseq`, `headers`, `request_uri`, `sdp`, `tags`, `user_agent`. An explicit `[]` means "nothing", not "the default". | Nothing pinned — the scenario tests no theory and the response says so. |
| `vary` | string[]? | `branch`, `call_id`, `tags` — the three SIPp can regenerate. Anything else from the `pin` vocabulary fails, naming the three. | All three. |
| `filename` | string? | A bare name in `--mcp-file-root` to write the scenario to as well. The text comes back either way. | The response carries the scenario and nothing touches the disk. |

```jsonc
// generate_repro { "call_id": "1-1966@10.0.2.20", "pin": ["sdp", "user_agent"] }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "format": "sipp",
  "hypothesis": {
    "pinned": ["sdp", "user_agent"],
    "varied": ["branch", "call_id", "tags"],
    "generated": ["contact", "content_length", "cseq", "max_forwards", "request_uri", "via"],
    "omitted": ["headers"]
  },
  "asserted": { "provisional": [100], "final": 200 },
  "scenario": "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<!DOCTYPE scenario SYSTEM \"sipp.dtd\">\n...",
  "run": "sipp -sf <scenario.xml> -m 1 <proxy-host>:<port>",
  "caveats": [
    "user_agent was pinned and the captured request carries no User-Agent header, so none is sent",
    "the pinned body names the media endpoint the ORIGINAL caller advertised, so any RTP the far end sends goes there and not to the machine running SIPp",
    "SIPp sends from the host you run it on. Source address, routing and any IP access list differ from the capture, and a reproduction depends on those matching."
  ]
}
```

**Read the `hypothesis` block as a four-way split of the original request.**
`pinned` came across byte-for-byte, `varied` is what SIPp regenerates,
`generated` is what the template supplies instead of the capture, and `omitted`
is what the capture held and the scenario leaves out. Nothing falls outside
those four, so no aspect of the original quietly survives or quietly vanishes.

**Only three aspects can vary, because varying needs a generator rather than an
opinion.** SIPp supplies a fresh Call-ID, tag and branch for every call it
places. It has no defined way to invent a plausible SDP body or User-Agent, and
a scenario built on an invented one would reproduce — or fail to — for a reason
nobody chose. Asking for anything else fails:

```jsonc
{ "code": -32602,
  "message": "'sdp' cannot be varied: SIPp has no generator for it. Variable aspects are branch, call_id, tags. Pin it instead if it is part of your hypothesis." }
```

**An aspect in both `pin` and `vary` fails outright.** Held fixed and
regenerated are opposite instructions, and a scenario that silently picked one
would encode a theory nobody stated. All three identity fields vary by default
for a reason worth stating: replaying a captured Call-ID, tag and branch at a
proxy is not a repro at all — to the transaction layer it is a retransmission of
a call that proxy already answered, so the response says more about its
transaction state than about the theory under test.

**Anything unpinned takes a generic value, and `caveats` names the cost.** With
no `sdp` pin the offer is a stock PCMU one, so a codec or attribute the far end
rejected never appears. With an empty `pin` list the response says outright that
the scenario encodes no hypothesis. A pinned body brings the captured
`Content-Type` with it, because the aspect pins BYTES and the label has to
describe them — a multipart body announced as `application/sdp` gets rejected
for a reason that has nothing to do with the theory.

The `recv` sequence asserts what the capture actually held: every provisional
code seen, plus `100` whether or not the capture held one, and the final status.
A call with no final response in the capture asserts nothing about the outcome —
the scenario sends the request and waits. For an INVITE the scenario sends an ACK either
way, with the Via that RFC 3261 calls for in each case: a fresh branch on a 2xx,
because that ACK is a new transaction, and `[last_Via:]` on a non-2xx, because
[§17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.1.3) makes it
part of the INVITE transaction.

Twelve headers the scenario always owns come from the template whatever the
capture held, `pin: ["headers"]` included: `Via`, `Contact`, `Content-Length`,
`Content-Type`, `CSeq`, `From`, `To`, `Call-ID`, `Max-Forwards`, `Record-Route`,
`Route` and `User-Agent`. A replay runs from a different host, so a captured
`Via` or `Contact` would send the responses to a machine that is not the one
running the test.

Two escaping rules protect the artifact, because an operator runs it against
their own proxy. A CR or LF inside a captured header value would end that header
and start another, so this tool strips control characters rather than escaping
them — a SIP header has no escape for one. And `]]>` inside a header value or
SDP attribute would close the scenario's CDATA section early, so it splits
across two sections, which preserves the bytes exactly.

Everything in `scenario` beyond the template — the Request-URI, header values,
SDP — came from the packet's sender, so the response carries the provenance note
rather than fencing the document field by field.

### `generate_wireshark_filter`

A display filter selecting one call, and the tshark line that applies it.

This is a deliberate small thing. Handing off cleanly to the human's preferred
tool signals that sipnab is not trying to own the workflow, and the person who
takes the escalation usually opens Wireshark next.

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `call_id` | string | A Call-ID the store holds. | Required — the call fails. |
| `include_media` | bool? | `true` adds one `rtp.ssrc` term per stream attributed to the call. | `true`. |

```jsonc
// generate_wireshark_filter { "call_id": "1-1966@10.0.2.20" }
{
  "schema_version": 1,
  "call_id": "1-1966@10.0.2.20",
  "display_filter": "sip.Call-ID == \"1-1966@10.0.2.20\" || rtp.ssrc == 0x343da99b",
  "tshark": "tshark -r 'tests/pcap-samples/sip-rtp-g711.pcap' -Y 'sip.Call-ID == \"1-1966@10.0.2.20\" || rtp.ssrc == 0x343da99b'",
  "streams_included": 1,
  "notes": [
    "rtp.ssrc matches only once Wireshark is decoding those packets as RTP. Enable 'Try to decode RTP outside of conversations', or use Decode As on the media ports, if the SSRC terms select nothing."
  ]
}
```

The `tshark` line names this run's capture file when the server reads one, and
falls back to `<capture.pcap>` on a live capture. Both the filename and the
filter go through POSIX shell quoting, so an embedded quote in a Call-ID closes
and reopens the quoted word rather than ending it.

`notes` earns its place twice. With `include_media: true` and no stream
attributed to the call, it says the filter selects signaling only — otherwise a
filter that quietly lost half its intent looks the same as one that never had
it. With SSRC terms present, it warns that `rtp.ssrc` matches nothing until
Wireshark decodes those packets as RTP, which is the first thing that goes wrong
when someone pastes this filter into a fresh window.

**A Call-ID carrying a control character fails.** The display-filter grammar
escapes `\` and `"` and nothing else, so a filter built around a control
character either fails to compile or selects something other than what it names.
A filter that quietly selects the wrong packets is worse than no filter:

```jsonc
{ "code": -32602,
  "message": "this Call-ID carries the control character U+0009, which a Wireshark display-filter string literal cannot represent. A filter written around it would not mean what the Call-ID says." }
```


## Capture control (opt-in, off by default)

The tools that change server state rather than read it. Every one stays off until you turn it on server-side.

### `query_relay`

**This is the only tool that transmits.** Every other one answers from bytes
sipnab already holds. This one puts a packet on the network.

It closes a gap a passive decoder cannot. A call already in progress when
sipnab started has no control exchange left to read, so the relay's own view is
the only way to learn which ports belong to it -- and incident response usually
begins mid-call, which is exactly when that gap is worst.

The tool needs three things, and says which one is missing:

| requirement | why |
|---|---|
| `--mcp-allow-relay-query` | transmitting is a larger act than reading, so an operator opts in |
| the relay control flag | names which relay to ask |
| a live source | a run reading a file can obtain no transmit permit |

**There is no address parameter, deliberately.** The destination comes from
operator configuration and from nowhere else. A tool argument naming the
destination would turn this surface into a way to make sipnab send packets to a
host the caller chose, and an address sipnab could otherwise infer is one it
learned from packets -- a host that served as a relay during the capture, and
may be somebody's laptop now.

Omit `call_id` to enumerate. `truncated` reports that the relay held more than
it returned, because "the relay holds these 32 calls" and "the relay returned
the first 32 of an unknown number" are different statements.

```jsonc
// query_relay { "call_id": "call-2c9d47@192.0.2.10" }
{
  "asked": "query",
  "relay_address": "127.0.0.1:22222",
  "outcome": "call",
  "call_id": "call-2c9d47@192.0.2.10",
  "tags": [
    {
      "tag": "from-tag-9a1c",
      "in_dialogue_with": ["to-tag-4b7e"],
      "codec": "PCMU",
      "streams": [
        {
          "local_address": "192.0.2.10",
          "local_port": 30000,
          "endpoint": "198.51.100.4:16388",
          "is_rtcp": false,
          "ssrcs": [305419896]
        }
      ]
    }
  ],
  "delivery_trust": "asked",
  "delivery_note": "sipnab asked the relay over its control socket; no third party could answer",
  "schema_version": 1
}
```

### `open_capture`

**Destructive.** Requires `--mcp-allow-open-capture`, which is off by default.
It loads another capture from `--mcp-file-root` and throws away every dialog and
stream the server holds.

Use it on a long-lived HTTP server working through a corpus, where a restart
costs an operator their session. In either stdio shape, starting sipnab again
with a different `-I` does the same job and leaves a clean store behind, so
prefer that.

**Parameters:** `filename` (string, required) — a bare filename inside
`--mcp-file-root`, under the rule every file tool applies. Unlike
[`list_captures`](#list_captures), any capture format libpcap reads is fine,
`.cap` included. No optional parameters, and no way to ask for a merge: this
replaces the stores rather than adding to them.

Returns `status` (`"loading"`), `filename`, `path`, the **new**
`capture_identity`, `discarded_dialogs`, `note` and `schema_version`.

```jsonc
// open_capture { "filename": "outage-0722.pcap" }
{
  "schema_version": 1,
  "status": "loading",
  "filename": "outage-0722.pcap",
  "path": "/var/spool/sipnab-captures/outage-0722.pcap",
  "capture_identity": {
    "node": "capture01",
    "instance": "1f4a17c8e2b91d40-2",
    "dialog_generation": 1,
    "stream_generation": 1
  },
  "discarded_dialogs": 128,
  "note": "the previous capture is gone; poll capture_status until load.done is true, and treat every answer carrying a different capture_identity.instance as a different capture"
}
```

The call returns as soon as the background read starts, not when it finishes.
That is deliberate: the REST API and the MCP server share one runtime thread, so
a multi-gigabyte read inside the handler stops every other client for its
duration. Poll `capture_status` and watch `load.packets` climb until
`load.done` turns true.

**Every answer afterwards carries a new `capture_identity.instance`.** Treat any
cursor, message index or Call-ID from before the swap as void — they addressed a
different capture. `discarded_dialogs` says how much analysis the call threw
away, so an agent can report the cost rather than discover it.

Four refusals, each naming what to do instead:

| Refusal | Why |
|---|---|
| `--mcp-allow-open-capture` missing | The operator did not enable it. The tool is still listed, because "not permitted here" and "this build cannot" are different answers |
| The source is a live interface | A live capture's writer never stops, so a second writer would race it for the life of the process. No opt-out |
| The source has not drained | The original reader is still filling the stores. Poll `capture_status` until `source_exhausted` is true |
| A load is already running | Poll `capture_status` until `load.done` is true |

**A fifth, where the client can carry the question.** If your client declared
MCP's `elicitation` capability, a swap that would discard dialogs asks the
person driving it to confirm first, and a decline refuses the call:

```text
refusing to open 'outage-0722.pcap': the confirmation was declined; nothing
was done. The loaded capture is untouched and its 13 dialog(s) are still
addressable.
```

The four refusals above resolve *before* the question, so sipnab asks nobody
to approve a swap sipnab was going to refuse anyway. A swap that would discard
nothing does not ask, and a client that declared no elicitation capability is
not asked and is not treated as having refused — `--mcp-allow-open-capture`
remains the guard it always was. See
[the protocol page](mcp-protocol.md#confirming-the-two-irreversible-ones).

A filename must be a bare name inside the root, under the same rule every file
tool applies. sipnab also refuses a capture that belongs to this run's own `-I`
set, with the output guard's wording about overwriting — that file is already
loaded, and reading it again under a new identity would duplicate what the store
holds.

### `shutdown_server`

**Destructive.** Requires `--mcp-allow-shutdown`, which is off by default.
Without it every call fails, whatever the arguments say:

```text
shutdown is disabled: start sipnab with --mcp-allow-shutdown to permit it.
A stock server cannot be stopped by an agent.
```

| Name | Type | Legal values | If omitted |
|---|---|---|---|
| `dry_run` | bool? | `true` reports what would happen. `false` stops the process. | **`true`** — the safe value is the default, so stopping takes a deliberate second call. |
| `save_to` | string? | A bare filename inside `--mcp-file-root` to write the capture to before stopping. | sipnab writes nothing. On a live capture holding unsaved packets, the call then refuses unless `discard_unsaved` is `true`. |
| `discard_unsaved` | bool? | `true` accepts losing the packets a live capture holds in memory. | `false` — a live capture with unsaved packets refuses to stop. |

Returns `dry_run`, `would_stop`, `live`, `unsaved`, `dialogs`, `streams`,
`saved_to`, `confirmed_by_operator`, `note` and `schema_version`. Read
`would_stop` rather than assuming: it is `false` on a dry run, on a refusal and
on a declined confirmation alike, and `note` says which.

```jsonc
// shutdown_server {}   — no arguments means DRY RUN
{
  "schema_version": 1,
  "dry_run": true,
  "would_stop": false,
  "live": false,
  "unsaved": false,
  "dialogs": 13,
  "streams": 2,
  "saved_to": null,
  "confirmed_by_operator": null,
  "note": "dry run — nothing stopped. Call again with dry_run=false to stop."
}
```

Stopping takes a deliberate second call with `dry_run: false`. On a **live**
capture holding packets written nowhere, it refuses outright unless you pass
`save_to` or `discard_unsaved: true` — losing a capture to a misread sentence
is the failure worth engineering against.

**And, where the client can carry the question, sipnab asks a person.** If your
client declared MCP's `elicitation` capability, a `dry_run: false` call sends a
real `elicitation/create` request and waits for the answer. Only `accept`
carrying `confirm: true` stops the process:

```jsonc
// shutdown_server { "dry_run": false }, confirmation declined
{
  "schema_version": 1,
  "dry_run": false,
  "would_stop": false,
  "confirmed_by_operator": false,
  "note": "the confirmation was declined; nothing was done"
  // ...
}
```

`confirmed_by_operator` is `null` where sipnab asked nobody — a dry run, or a
client that declared no elicitation capability. That case is **not** a refusal:
`dry_run` remains the guard it always was, so the tool behaves exactly as it
did on any client that cannot answer. `save_to` writes only on the path that
actually stops, so a declined confirmation leaves no file behind. See
[the protocol page](mcp-protocol.md#confirming-the-two-irreversible-ones).

### `start_tls_capture`

Installs kernel uprobes on this host's TLS libraries and reads SIP plaintext
from them — no key, no certificate, and no restart of the process observed.

**Needs `--mcp-allow-tls-capture`.** It is off by default and separate from
`--mcp-allow-open-capture`, because it is a different act: that one reads a
file an operator placed in a directory, this one attaches probes to a running
process's TLS library and reads its plaintext.

Call [`list_tls_libraries`](#list_tls_libraries) first.

| Parameter | Type | Default | Meaning |
|---|---|---|---|
| `flavors` | array of string | every one found | `openssl`, `wolfssl` |
| `libraries` | array of string | discover | probe these paths instead of discovering |

```jsonc
// start_tls_capture { }                                  // every library found
// start_tls_capture { "flavors": ["openssl"] }          // one flavor only
// start_tls_capture { "libraries": ["/proc/954/root/usr/lib/libssl.so.3"] }
{
  "schema_version": 1,
  "running": true,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 0,
  "lost": null,
  "uptime_sec": 0,
  "error": null,
  "summary": "Probing 1 TLS library. ..."
}
```

**Three refusals, each before any kernel state exists**, and each says which
one it is rather than a bare failure:

- **not root** — sipnab drops privileges after opening its capture devices, so
  a server started with `--user` cannot attach probes later;
- **a live source is already running** — sipnab's stores have one writer, so a
  uprobe capture cannot run beside one;
- **a capture is still loading** — poll `capture_status` until `load.done`.

**An attach failure arrives later, not here.** A background thread installs
the probes, so the call returns as soon as that thread starts. Poll
[`stop_tls_capture`](#stop_tls_capture) or `capture_status` to see whether
messages actually arrive.

### `stop_tls_capture`

Stops the running capture and removes its kernel probes. Safe to call when
nothing is running — it says so rather than failing.

No parameters. Returns:

```jsonc
// stop_tls_capture { }
{
  "schema_version": 1,
  "running": false,
  "targets": ["/proc/954/root/usr/lib/libssl.so.3:SSL_write"],
  "messages": 412,
  "lost": 0,          // records the kernel DROPPED: messages that existed and are missing
  "uptime_sec": 96,
  "error": null,
  "summary": "The TLS capture has stopped and its probes are removed."
}
```

**Keep calling until `running` is false.** The stop is a request: the worker
owns the probes and removes them on its way out, which is a kernel round trip
per probe. Probes left installed cost every process that maps the library, and
they outlive sipnab.

`lost` is worth reading. It counts records the kernel dropped because the
reader fell behind — messages that existed and are missing, which is a
different fact from a quiet trunk and the only one you cannot discover any
other way. The dialogs already collected stay in the store after the stop.

### `list_tls_libraries`

Which TLS libraries processes on this host are **actually mapping**, and
whether sipnab could attach a uprobe to read their plaintext. Ask before
concluding that reading SIP over TLS needs keys — and read
`privileged` and `probe_path` before concluding it can.

No parameters. Returns:

```jsonc
{
  "schema_version": 1,
  "supported": true,          // false off Linux, or without the `native` feature
  "privileged": true,         // running as root
  "libraries": [
    {
      "flavor": "OpenSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libssl.so.3",
      "inode": 21143,         // the identity; the PATH is not unique
      "process_count": 12,
      "symbol": "SSL_write",
      "probe_path": "/proc/954/root/usr/lib/aarch64-linux-gnu/libssl.so.3"
    },
    {
      "flavor": "wolfSSL",
      "path": "/usr/lib/aarch64-linux-gnu/libwolfssl.so.42.2.0",
      "inode": 17433084,
      "process_count": 1,
      "symbol": "wolfSSL_write",
      "probe_path": null      // in use, but NOT capturable from here
    }
  ],
  "unreachable_count": 1,
  "summary": "1 of 2 TLS libraries could be read with `sipnab --uprobe-tls`, without any key or certificate. 1 cannot be reached from this server's mount namespace and would be missed."
}
```

**Read `privileged` before believing an empty list.** Unprivileged,
`/proc/<pid>/maps` is readable only for the server's own processes, so a short
list is evidence about privilege rather than about the host. `summary` says
which of the two situations produced the answer, so a relayed conclusion does
not lose it.

**`probe_path: null` is a finding, not a blank.** That library is carrying
traffic sipnab cannot capture — usually a containerized process whose
`/proc/<pid>/root` this server cannot read. sipnab reports it rather than
dropping it, because the alternative is a capture that looks complete and is
not.

`inode` is there because `path` is **not** unique: the same string names
different files in different mount namespaces, and on an ordinary host with
containers several distinct `libssl.so.3` files coexist.

### Tool argument enums

**`find_problems.kinds`** — diagnostic alias names, OR-ed together.
Defaults to `["problems"]`. The full vocabulary:

`problems` · `slow-setup` · `short-calls` · `one-way` · `nat-issues` ·
`codec-asym` · `ptime-asym` · `payload-asym` · `duration-asym` ·
`late-media`

An unknown alias returns a JSON-RPC *invalid params* error naming the
bad alias. The same names work as the `list_dialogs` `filter` aliases
(and as `sipnab --filter` aliases on the CLI).

**`security_findings.kinds`** — matches the rule names sipnab records
findings under: `scanner`, `fraud`, `digest`, `reg_flood` (note the
underscore — the `--alert` rule grammar spells it `reg-flood`, but
sipnab records and filters findings as `reg_flood`). Omitted or empty
`kinds` returns findings of every kind.

Both enums **refuse** a name they do not know, and name the vocabulary in the
refusal. `security_findings.kinds` used to accept anything and match nothing,
so a name outside those four answered `[]` — the same bytes a quiet capture
returns. `reg-flood` was the case that bit, and its refusal now suggests the
underscore spelling by name.

### Error model

All tools return MCP errors via the JSON-RPC `error` object. The codes
sipnab uses:

| Code | Meaning |
|---|---|
| -32602 (`invalid_params`) | Unknown Call-ID, out-of-range index, malformed filter, unknown format, unknown alias, a path where a bare filename belongs, and every "this tool is not enabled" refusal. The common case by far. |
| -32603 (`internal_error`) | A read or write that reached the filesystem or the decoder and failed there — `export_audio` with no retained payload, a capture file sipnab cannot open. Not only for bugs. |
| -32000 (server error) | Capacity, not correctness: `--mcp-max-concurrent` or `--mcp-rate-limit-per-peer` turned this call away, and the same call succeeds once the server has room. The only code here worth a retry — treat -32602 as a bug in the request. |

Tools never panic. An unknown Call-ID always produces a structured error
rather than an empty result.

### Response bounding

| Limit | Default | Set by |
|---|---|---|
| Default `limit` for list-style tools | 50 | the per-call `limit` |
| Ceiling on `limit` (clamps higher requests) | 1000 | `--mcp-max-rows` |
| SIP body / snippet bytes | 4096 | `--mcp-max-body-bytes` |
| Messages per `get_dialog` page | 1000 | `--mcp-max-rows` |

**These are defaults, not laws.** The right ceiling belongs to the CONSUMER
rather than to sipnab: an agent with a small context window wants far fewer
than a thousand rows and a batch consumer piping to a file wants far more, so
no single number serves both. Raise or lower them with `--mcp-max-rows` and
`--mcp-max-body-bytes`, or the matching `[limits]` keys in the config file.
The per-call `limit` narrows an answer below the ceiling, and cannot exceed
it.

A bound is not a loss. `list_dialogs`, `find_problems`, `search_by_time`,
`search_messages`, `security_findings` and the capture-wide `rtp_stats` sweep
each report `total_matched` beside their page, so a caller sees how much of the
answer it holds. That number describes the STORE, not the file: while the
source is still loading it counts what had arrived by then, which is why every
one of them also carries `source_exhausted` and why the response omits
`truncated: false` until the answer is whole. All of those except `security_findings` carry a cursor to the
rest, as do `tail_dialogs` and `get_dialog`. Asking for a `limit` above the
ceiling does nothing — the ceiling clamps it — so either raise the ceiling with
`--mcp-max-rows` or page.

**Two tools remain exceptions, and a caller has to know which:**

| Tool | Reports a total | Carries a cursor | How to reach the rest |
|---|---|---|---|
| `security_findings` | Yes | No | Raise `limit`, and narrow with `since` |
| `tail_dialogs` | No | Yes | Follow `next_cursor` until the page comes back empty |

`security_findings` has no cursor because its source is a ring buffer whose
default depth is 1000 — the same as the maximum `limit`, so one call reaches
all of it. Raise `--findings-history` above 1000 and `total_matched` is what
tells you a page is short, and `since` is the way through. `tail_dialogs` reports
no total because a tail cannot have one: the store keeps changing underneath
it, so any number it gave would describe a moment that has passed.

