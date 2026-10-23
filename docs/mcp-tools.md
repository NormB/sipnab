# MCP tool reference

Every tool the MCP server exposes, grouped by bundle. This page does four
things:

- it says what a bundle is,
- it lists the bundles,
- it finds any tool by name,
- it states the rules every tool follows.

Each bundle's page documents what its tools answer and what they return.

This is lookup material, not reading material.

- [MCP server](mcp.md) — what MCP is, and a first working example.
- [MCP deployment](mcp-deploy.md) — the deployment shapes.
- [MCP protocol](mcp-protocol.md) — the wire contract, security model and error semantics.


No tool edits the analysis in place, and every response carries a row
ceiling.

That ceiling defaults to 1000 rows and is an operator setting:

- Set it with `--mcp-max-rows N`, or `[limits]
  mcp_max_rows` in the config file. The flag wins.
- Lower it for a model with a small context window; raise it for a batch
  client that writes answers to a file.
- It is a different limit from `dialog_limit` (`--limit`, default 100000),
  which bounds the dialogs tracked over the whole run.

One tool replaces the analysis outright: `open_capture`, off unless you enable
it. It mints a new capture identity. So the replacement cannot reach a
consumer as an ordinary update.

## Bundles

A bundle is a named set of tools defined in sipnab's code.

- Every tool is in exactly one bundle. So the ten bundles together are every
  tool the server has.
- `--mcp-tools` loads bundles by name, as [Choosing which tools
  load](#choosing-which-tools-load) describes.
- Each bundle has a page that documents its tools.

| Bundle | Tools | What its tools answer |
|---|---|---|
| [`core`](mcp-tools-core.md) | 9 | The smallest set that answers what happened on one call, and whether the fault was in signaling or media, from listing the calls to the bytes that prove it. |
| [`signaling`](mcp-tools-signaling.md) | 20 | Follow-up questions about SIP signaling: single messages, call flows, SDP negotiation, related call legs, RFC conformance, time windows, and reproducing a call. |
| [`captures`](mcp-tools-captures.md) | 11 | Capture files in the file root: listing, searching, comparing, opening and exporting them, and the evidence that ties a finding to captured bytes. |
| [`security`](mcp-tools-security.md) | 6 | Who sent what: scanner and fraud findings, the busiest sources, one endpoint's activity, registration problems, pass/fail expectations, and fail2ban rules. |
| [`media`](mcp-tools-media.md) | 4 | Where a call's media endpoints came from, why a stream has no dialog, the facts under a quality score, and audio export. |
| [`relay`](mcp-tools-relay.md) | 4 | Questions put to the configured media relay, and decoding the relay control messages sipnab captured. |
| [`tfps`](mcp-tools-tfps.md) | 7 | The toll-fraud prevention peer (TFPS): what it blocks and logs, and the operator's ban, unban and revert actions. |
| [`server`](mcp-tools-server.md) | 5 | The sipnab process and its capture path: capture health, HEP senders, resource use, build capabilities, and shutdown. |
| [`vcon`](mcp-tools-vcon.md) | 7 | vCon conversation containers, exported, validated and analyzed, one at a time or a directory at once, read from the operator's store, the vCon export spool's counts, and the SIPREC recording metadata a call carried. |
| [`tls`](mcp-tools-tls.md) | 3 | Reading SIP inside TLS without keys through kernel uprobes, and which TLS libraries this host runs. |

### Choosing which tools load

Every tool the server registers sends its name, description and schemas to the
client on `tools/list`. The client keeps them in the model's context for
the whole session. The client pays that cost before the agent asks anything. So
give a client that needs a few tools only those few:

```sh
sipnab -N -I capture.pcap --mcp --mcp-tools core,relay,get_sdp_timeline
```

`--mcp-tools` (or `[mcp] tools` in the [config file](config-reference.md#mcp))
takes a comma-separated list of:

- **bundles**, from the [bundle table](#bundles). Every tool is in exactly
  one, so the bundles together are `full`.
- **single tool names**, for one tool from a bundle you do not want whole.
- **your own bundles**, defined under `[mcp.bundles]` in the config file.
- **`full`**, every tool. This is the default.

sipnab refuses to start, exit 2, when a name is unknown or empty, and lists
the valid bundles. Names are case-sensitive. With `--mcp-tools core,bogus`:

```text
--mcp-tools: unknown tool or bundle 'bogus'; bundles: core, signaling, captures, security, media, relay, tfps, server, vcon, tls, or full; tool names are listed in the MCP tool reference
```

The handshake's `instructions` string names the tools sipnab loaded and the
bundles it left out, so an agent that misses a tool can tell the operator
which bundle to add. Under `--mcp-tools core` it ends:

```text
Tools loaded: core. Other bundles, which the operator can add with --mcp-tools or [mcp] tools: signaling, captures, security, media, relay, tfps, server, vcon, tls.
```

The same string names every loaded tool that changes another system. Without
`--allow-action` it says:

```text
This server changes no external system: the tools that would (actions_revert, tfps_ban, tfps_unban) refuse unless the operator enables them with --allow-action.
```

With `--allow-action tfps:mcp` it says:

```text
The operator enabled actions that change another system from MCP (--allow-action tfps:mcp): actions_revert, tfps_ban, tfps_unban. Over HTTP they also need an "actions"-scope token.
```

Output schemas are **off by default**.

- MCP makes them optional, and they are more than half the bytes.
- Every response carries the same JSON with or without them, as a text block
  and as `structuredContent`.
- Only a client that validates responses against a declared shape needs them.
- Turn them on with `--mcp-output-schemas` or
  `[mcp] output_schemas = true`.

You can read one tool's response shape without turning output schemas on for
every tool. Read the resource `sipnab://schema/<tool>`. It returns one of
these:

- the tool's output JSON Schema and an example payload generated from that
  schema,
- a statement that the tool declares no output schema.

[Tool response schemas](mcp-protocol.md#tool-response-schemas) describes the
resource.

| Bundle | Tools | Bytes (default) | Bytes with output schemas |
|---|---|---|---|
| core | 9 | 12,316 | 54,624 |
| signaling | 20 | 22,474 | 58,619 |
| captures | 11 | 12,723 | 30,211 |
| security | 6 | 9,954 | 9,954 |
| media | 4 | 3,480 | 16,048 |
| relay | 4 | 4,199 | 19,988 |
| tfps | 7 | 5,563 | 15,947 |
| server | 5 | 5,394 | 27,452 |
| vcon | 7 | 10,714 | 33,024 |
| tls | 3 | 2,850 | 4,943 |
| full | 76 | 89,667 | 270,810 |

Bytes are the compact JSON of each tool's `tools/list` entry, summed over the
bundle.

> **Measured on sipnab 0.5.222** on a build with every feature.
>
> - Sizes, tool counts and bundle membership may change in later releases.
> - A build without a feature does not register that feature's tools, so its
>   bundles are smaller.

## Find a tool by name

Every tool in alphabetical order, with the bundle that holds it. The tool name
links to its section on the bundle's page.

| Tool | Bundle | Returns |
|---|---|---|
| [`actions_revert`](mcp-tools-tfps.md#actions_revert) | [tfps](mcp-tools-tfps.md) | **Write, off by default.** Backs out one ban sipnab placed, or every one it still holds |
| [`aggregate_dialogs`](mcp-tools-core.md#aggregate_dialogs) | [core](mcp-tools-core.md) | Counts dialogs grouped by ONE field, in the store rather than in the model |
| [`analyze_vcon`](mcp-tools-vcon.md#analyze_vcon) | [vcon](mcp-tools-vcon.md) | Rebuilds the SIP messages a stored container holds and analyzes them apart from the loaded capture: per dialog the `--json-dialogs` object, the signaling diagnosis and the ladder, plus the capture analysis and what a container cannot reproduce |
| [`await_condition`](mcp-tools-signaling.md#await_condition) | [signaling](mcp-tools-signaling.md) | Waits until a filter matches or a deadline passes, whichever is first, so a live capture costs one call instead of a polling loop |
| [`build_evidence_package`](mcp-tools-captures.md#build_evidence_package) | [captures](mcp-tools-captures.md) | **Write.** One directory of escalation artifacts in `--mcp-file-root`: pcapng, ladder and RTP stats per call, manifest, and the rebuilt-frames README |
| [`cancel_find_in_captures`](mcp-tools-captures.md#cancel_find_in_captures) | [captures](mcp-tools-captures.md) | Stops a running `find_in_captures` job |
| [`capture_health`](mcp-tools-server.md#capture_health) | [server](mcp-tools-server.md) | Capture-path counters read twice: run totals, deltas across the window, `undecoded_fraction`, and undecodable frames by reason |
| [`capture_status`](mcp-tools-core.md#capture_status) | [core](mcp-tools-core.md) | What this server captures: live or file, uptime, and whether stopping loses unsaved packets |
| [`check_codec_negotiation`](mcp-tools-signaling.md#check_codec_negotiation) | [signaling](mcp-tools-signaling.md) | Codecs offered vs answered and whether they intersect — for 488s |
| [`compare_captures`](mcp-tools-captures.md#compare_captures) | [captures](mcp-tools-captures.md) | Diffs two capture files in `--mcp-file-root` by aggregate, ranked by how far each bucket MOVED. Neither becomes the loaded capture |
| [`compare_dialogs`](mcp-tools-signaling.md#compare_dialogs) | [signaling](mcp-tools-signaling.md) | Two calls side by side, with the differences named |
| [`decode_evidence`](mcp-tools-captures.md#decode_evidence) | [captures](mcp-tools-captures.md) | Decodes the frame one pointer names: link type, addressing, and each SIP header's byte range inside the message and the frame |
| [`decode_ng`](mcp-tools-relay.md#decode_ng) | [relay](mcp-tools-relay.md) | Decodes the relay control message one pointer names: the command, the call, whether it carries SDP, and which delivery path carried it |
| [`describe_endpoint`](mcp-tools-security.md#describe_endpoint) | [security](mcp-tools-security.md) | Everything one participant did: dialogs by method and state, INVITE outcomes, REGISTER state, banners, streams, findings |
| [`diagnose_registration`](mcp-tools-security.md#diagnose_registration) | [security](mcp-tools-security.md) | Whether an endpoint registered, hit a rejection, is looping on auth, or got a short expiry |
| [`evaluate_expectations`](mcp-tools-security.md#evaluate_expectations) | [security](mcp-tools-security.md) | A pass/fail verdict per rule plus an exit code for a build. A rule whose population is empty fails rather than passing quietly |
| [`explain_attribution`](mcp-tools-media.md#explain_attribution) | [media](mcp-tools-media.md) | Where each of a call's media endpoints came from and how much that path is worth — asked directly, HMAC-verified, plain secret, port-gated only, or the parties' own SDP |
| [`explain_response_code`](mcp-tools-signaling.md#explain_response_code) | [signaling](mcp-tools-signaling.md) | IANA registry meaning and class for a SIP status code |
| [`explain_rule`](mcp-tools-signaling.md#explain_rule) | [signaling](mcp-tools-signaling.md) | The catalog entry behind one rule identifier: citation, basis, scope, selectors |
| [`export_audio`](mcp-tools-media.md#export_audio) | [media](mcp-tools-media.md) | Writes a call's RTP audio to a WAV in `--mcp-file-root`; needs the server started with `--retain-audio` |
| [`export_capture`](mcp-tools-captures.md#export_capture) | [captures](mcp-tools-captures.md) | Writes held SIP signaling to a pcap in `--mcp-file-root` (re-synthesized frames, no RTP) |
| [`export_vcon`](mcp-tools-vcon.md#export_vcon) | [vcon](mcp-tools-vcon.md) | Dialogs as vCon conversation containers, structured JSON, each with its SHA-256. One `call_id` or a whole filtered set, paged with `cursor`. Unsigned, retained audio inline unless `media` is `omit`, and every omission stated in the response |
| [`fetch_vcon`](mcp-tools-vcon.md#fetch_vcon) | [vcon](mcp-tools-vcon.md) | **Connects, off by default.** One container from the operator's `[vcon_fetch]` store by uuid, returned inline with the checks it passed. Needs `--mcp-allow-vcon-fetch`; the store and its keys come from operator configuration only |
| [`find_correlated`](mcp-tools-signaling.md#find_correlated) | [signaling](mcp-tools-signaling.md) | The other legs of the same call across a B2BUA, each with a score AND the strategy that matched it |
| [`find_in_captures`](mcp-tools-captures.md#find_in_captures) | [captures](mcp-tools-captures.md) | Which capture files hold dialogs matching a filter, without opening any of them; a sweep that outlasts its wait returns a job |
| [`find_in_captures_status`](mcp-tools-captures.md#find_in_captures_status) | [captures](mcp-tools-captures.md) | A `find_in_captures` job's progress, or its result once it finishes |
| [`find_problems`](mcp-tools-core.md#find_problems) | [core](mcp-tools-core.md) | A page of dialogs matching one or more diagnostic alias names |
| [`generate_fail2ban_rule`](mcp-tools-security.md#generate_fail2ban_rule) | [security](mcp-tools-security.md) | A fail2ban filter and jail derived from ONE recorded finding, with that finding attached as the evidence |
| [`generate_repro`](mcp-tools-signaling.md#generate_repro) | [signaling](mcp-tools-signaling.md) | A SIPp scenario replaying one call, with the hypothesis as an input: `pin` holds the suspected cause fixed, `vary` regenerates identity |
| [`generate_wireshark_filter`](mcp-tools-signaling.md#generate_wireshark_filter) | [signaling](mcp-tools-signaling.md) | A Wireshark display filter selecting one call's signaling and its RTP by SSRC, plus the tshark line that applies it |
| [`get_call_tree`](mcp-tools-signaling.md#get_call_tree) | [signaling](mcp-tools-signaling.md) | Every leg of one call as a tree, each edge carrying its parent, depth, score, strategy and whether the walk went through it |
| [`get_capture_report`](mcp-tools-core.md#get_capture_report) | [core](mcp-tools-core.md) | Whole-capture analysis: findings, orphaned media, STUN/ICMP evidence, what the caps shed |
| [`get_dialog`](mcp-tools-core.md#get_dialog) | [core](mcp-tools-core.md) | Paginated dialog with full SIP messages |
| [`get_dialog_report`](mcp-tools-signaling.md#get_dialog_report) | [signaling](mcp-tools-signaling.md) | Structured per-call report (JSON / Markdown / text) |
| [`get_message`](mcp-tools-signaling.md#get_message) | [signaling](mcp-tools-signaling.md) | Single SIP message at a given index |
| [`get_sdp_timeline`](mcp-tools-signaling.md#get_sdp_timeline) | [signaling](mcp-tools-signaling.md) | SDP offer/answer exchanges in order: codecs, ptime, direction |
| [`group_dialogs`](mcp-tools-signaling.md#group_dialogs) | [signaling](mcp-tools-signaling.md) | Carrier metrics per group — ASR, NER, ACD, post-dial delay, MOS, retransmissions — each beside the population it rests on |
| [`hep_senders`](mcp-tools-server.md#hep_senders) | [server](mcp-tools-server.md) | Who feeds this run's HEP listener: each sender, its count, when it was last heard and whether it went silent, and every address the listener refused, by reason |
| [`lint_dialog`](mcp-tools-signaling.md#lint_dialog) | [signaling](mcp-tools-signaling.md) | Conformance findings for one call, declaration against observation included, each with its RFC and section |
| [`list_captures`](mcp-tools-captures.md#list_captures) | [captures](mcp-tools-captures.md) | Capture files and stored vCon containers in `--mcp-file-root`, with sizes and each one's kind |
| [`list_dialogs`](mcp-tools-core.md#list_dialogs) | [core](mcp-tools-core.md) | A page of dialog summaries, with the total behind it |
| [`list_tls_libraries`](mcp-tools-tls.md#list_tls_libraries) | [tls](mcp-tools-tls.md) | which TLS libraries this host runs, and whether sipnab could read their plaintext without keys |
| [`media_diagnostics`](mcp-tools-media.md#media_diagnostics) | [media](mcp-tools-media.md) | The facts under the MOS: QoS marking, jitter grounding, delay provenance, silence, and what the far end reported |
| [`open_capture`](mcp-tools-captures.md#open_capture) | [captures](mcp-tools-captures.md) | **Destructive.** Replaces every dialog and stream with another capture from `--mcp-file-root`. Needs `--mcp-allow-open-capture`; loads in the background |
| [`query_relay`](mcp-tools-relay.md#query_relay) | [relay](mcp-tools-relay.md) | **Transmits.** Asks the configured relay what it holds right now. Needs `--mcp-allow-relay-query` and a live source; the destination comes from operator configuration only |
| [`reconcile_orphans`](mcp-tools-media.md#reconcile_orphans) | [media](mcp-tools-media.md) | Why each RTP stream with no dialog lacks one: a relay named the endpoint but no signaling arrived, SDP named it but no dialog claims it, or nothing named it at all |
| [`relay_compare`](mcp-tools-relay.md#relay_compare) | [relay](mcp-tools-relay.md) | **Transmits.** Sets the relay's per-call RTP count beside sipnab's measured count, both tiers named and a word verdict, never a sum. Same gate as `query_relay` |
| [`relay_stats`](mcp-tools-relay.md#relay_stats) | [relay](mcp-tools-relay.md) | **Transmits.** Asks the configured relay for its own counters (global, per-call, or the names it knows), tiered `relay_reported`. Same opt-in and live-source gate as `query_relay` |
| [`render_ladder`](mcp-tools-signaling.md#render_ladder) | [signaling](mcp-tools-signaling.md) | Call-flow ladder (Markdown / text), or an annotated Mermaid diagram |
| [`rtp_stats`](mcp-tools-core.md#rtp_stats) | [core](mcp-tools-core.md) | One call's RTP quality and diagnosis, or a capture-wide stream sweep |
| [`runtime_stats`](mcp-tools-server.md#runtime_stats) | [server](mcp-tools-server.md) | What sipnab is doing and what it costs the host: its own memory, threads, descriptors and CPU; the host's totals and the basis they came from; its share of them and whether that share is load-bearing; per-interface counters; store occupancy against the caps |
| [`save_findings`](mcp-tools-captures.md#save_findings) | [captures](mcp-tools-captures.md) | **Write.** Records the agent's conclusion to sipnab's log. Needs `--mcp-allow-save-findings`; no tool reads it back |
| [`search_by_time`](mcp-tools-signaling.md#search_by_time) | [signaling](mcp-tools-signaling.md) | Dialogs whose first message falls in an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html) window |
| [`search_messages`](mcp-tools-core.md#search_messages) | [core](mcp-tools-core.md) | A page of substring matches across method/From/To/UA/body, with the total behind it |
| [`security_findings`](mcp-tools-security.md#security_findings) | [security](mcp-tools-security.md) | Recent `scanner` / `fraud` / `digest` / `reg_flood` findings, plus the detectors this server runs |
| [`server_capabilities`](mcp-tools-server.md#server_capabilities) | [server](mcp-tools-server.md) | sipnab version, the optional features this binary carries, and the libpcap it runs |
| [`show_evidence`](mcp-tools-captures.md#show_evidence) | [captures](mcp-tools-captures.md) | Follows frame pointers back to the captured bytes: verified, unverified, or unresolvable with a reason |
| [`shutdown_server`](mcp-tools-server.md#shutdown_server) | [server](mcp-tools-server.md) | **Destructive.** Stops the process. Needs `--mcp-allow-shutdown`; dry-run by default |
| [`siprec_metadata`](mcp-tools-vcon.md#siprec_metadata) | [vcon](mcp-tools-vcon.md) | The SIPREC ([RFC 7866](https://www.rfc-editor.org/rfc/rfc7866.html)) recording metadata a call carried: session id, mode, participants with AOR and display name, and the recorded streams, each naming its `m=` line label and the participant that sends it |
| [`start_tls_capture`](mcp-tools-tls.md#start_tls_capture) | [tls](mcp-tools-tls.md) | installs kernel uprobes and reads SIP plaintext with no key; needs `--mcp-allow-tls-capture` |
| [`stop_tls_capture`](mcp-tools-tls.md#stop_tls_capture) | [tls](mcp-tools-tls.md) | stops that capture and removes its kernel probes |
| [`tail_dialogs`](mcp-tools-signaling.md#tail_dialogs) | [signaling](mcp-tools-signaling.md) | Cursor-based incremental dialog fetch |
| [`tfps_ban`](mcp-tools-tfps.md#tfps_ban) | [tfps](mcp-tools-tfps.md) | **Write, off by default.** Relays an OPERATOR's decision to condemn a source, recorded in the journal and rate limited, and reports the TFPS answer as given, refusal included |
| [`tfps_banned`](mcp-tools-tfps.md#tfps_banned) | [tfps](mcp-tools-tfps.md) | Every source TFPS holds condemned right now, with the rule, what it saw, and when the ban began and lapses |
| [`tfps_dropped`](mcp-tools-tfps.md#tfps_dropped) | [tfps](mcp-tools-tfps.md) | Per condemned source, what the enforcement dropped and the last request line the source sent |
| [`tfps_labels`](mcp-tools-tfps.md#tfps_labels) | [tfps](mcp-tools-tfps.md) | The TFPS verdict log -- blocked, would-block, exempt -- the export the label corpus harness scores the scanner detector against |
| [`tfps_status`](mcp-tools-tfps.md#tfps_status) | [tfps](mcp-tools-tfps.md) | Whether the toll-fraud prevention peer (TFPS) runs on this host, and what it reports: enforcement, mode, interface, sources blocked now, database, version |
| [`tfps_unban`](mcp-tools-tfps.md#tfps_unban) | [tfps](mcp-tools-tfps.md) | **Write, off by default.** Releases a source sipnab banned |
| [`timeline`](mcp-tools-signaling.md#timeline) | [signaling](mcp-tools-signaling.md) | Call volume per fixed-width interval, so a gap or a spike is visible without reading every dialog |
| [`top_talkers`](mcp-tools-security.md#top_talkers) | [security](mcp-tools-security.md) | The busiest IPs, user agents or dialled prefixes, ranked, each share stated against the population behind it |
| [`triage_call`](mcp-tools-core.md#triage_call) | [core](mcp-tools-core.md) | First-pass verdict: signaling problem, media problem, both, or none, with evidence |
| [`validate_filter`](mcp-tools-signaling.md#validate_filter) | [signaling](mcp-tools-signaling.md) | Whether a filter DSL expression parses, the parser's message when it does not, and how many dialogs it selects — with no rows |
| [`validate_message`](mcp-tools-signaling.md#validate_message) | [signaling](mcp-tools-signaling.md) | Conformance findings for one message, read alone |
| [`validate_vcon`](mcp-tools-vcon.md#validate_vcon) | [vcon](mcp-tools-vcon.md) | Checks a container against the working group's draft-ietf-vcon-vcon-core-04 schema and names every finding |
| [`vcon_directory_report`](mcp-tools-vcon.md#vcon_directory_report) | [vcon](mcp-tools-vcon.md) | Every stored container in a directory of the file root: per container its status, form, schema finding count, calls, dispositions and duration, or why sipnab skipped it, then the totals. The report `-I <dir> --report` prints |
| [`vcon_spool_status`](mcp-tools-vcon.md#vcon_spool_status) | [vcon](mcp-tools-vcon.md) | Counts the `--export-vcon-dir` spool: containers pending, delivered and failed, with the store's answer from each failed container's record. A snapshot of files; sends, moves and deletes nothing |

## Which tool finds calls

Seven tools select calls, and each answers a different question.

A filter is one of these:

- an expression in sipnab's filter language (the DSL), such as
  `state == Failed`. A value may be bare or quoted: `method == INVITE` and
  `method == 'INVITE'` are the same filter,
- the name of a built-in alias such as `problems`.

| The question | The tool | Why this one |
|---|---|---|
| Which calls match this condition? | [`list_dialogs`](mcp-tools-core.md#list_dialogs) with `filter` | Takes an alias or any DSL expression and pages through every match, with `total_matched` and a cursor |
| Which calls show a known kind of problem? | [`find_problems`](mcp-tools-core.md#find_problems) | Takes diagnostic alias names (`problems`, `slow-setup`, `one-way` and the rest) instead of an expression, and can narrow them with a DSL filter |
| Which calls contain this text: a number, a User-Agent, a header value? | [`search_messages`](mcp-tools-core.md#search_messages) | Searches the whole SIP message, every header, the request line and the body, case-insensitively, and returns the message that matched |
| Which calls started in this time window? | [`search_by_time`](mcp-tools-signaling.md#search_by_time) | Selects by the time of the first message, in an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html) window, optionally narrowed by a filter |
| What did this one IP address or user do? | [`describe_endpoint`](mcp-tools-security.md#describe_endpoint) | Selects by `ip` or `user` and returns counts over every match plus a page of that participant's dialogs |
| Which capture file holds these calls? | [`find_in_captures`](mcp-tools-captures.md#find_in_captures) | Sweeps the files in `--mcp-file-root` with a filter and names the files that match, without replacing the loaded capture |
| Does my filter parse, and how many calls does it select? | [`validate_filter`](mcp-tools-signaling.md#validate_filter) | Compiles the expression and returns the count with no rows, so a wrong filter costs one small answer |

## Prompts

A prompt is a named list of steps. It tells a model which tools to call and
in what order. A client lists them with `prompts/list` and fetches one with
`prompts/get`. No prompt takes arguments, and every tool stays callable
without one.

| Prompt | When to use it | Tools it calls, in order | Bundles it needs |
|---|---|---|---|
| `triage-outage` | Something is failing now | `capture_status`, `find_problems`, `triage_call`, `show_evidence` | `core`, `captures` |
| `carrier-escalation` | Building a case to send to a carrier | `capture_status`, `group_dialogs`, `get_call_tree`, `build_evidence_package` | `core`, `signaling`, `captures` |
| `codec-interop-audit` | Two endpoints disagree about media | `capture_status`, `check_codec_negotiation`, `group_dialogs`, `media_diagnostics` | `core`, `signaling`, `media` |
| `post-change-verification` | A change went in and needs checking against a baseline | `capture_status`, `compare_captures`, `evaluate_expectations`, `timeline` | `core`, `signaling`, `captures`, `security` |
| `vcon-handoff` | You are exporting calls to a vCon store | `capture_status`, `validate_filter`, `export_vcon`, `validate_vcon` | `core`, `signaling`, `vcon` |

Each prompt's steps:

- **`triage-outage`**:
  - read `unanalysed_sip_messages` from `capture_status` first;
  - get the shape of the failure from `find_problems`;
  - run `triage_call` on one Call-ID from that result;
  - follow its `frame` pointer with `show_evidence` before stating that a
    message caused the failure.
- **`carrier-escalation`**:
  - `capture_status`;
  - `group_dialogs` by `next_hop` with the `asr` and `ner` metrics, reading
    the `population` block;
  - `get_call_tree` on an affected Call-ID, because carrier faults usually
    span several legs;
  - `build_evidence_package` for the calls the escalation cites.
- **`codec-interop-audit`**:
  - `capture_status`;
  - `check_codec_negotiation` for offers with no common codec;
  - `group_dialogs` by `rtp.codec` with `mos_p10`;
  - `media_diagnostics` on a call that negotiated a codec and still sounded
    wrong.
- **`post-change-verification`**:
  - `capture_status`;
  - `compare_captures` against the baseline from before the change;
  - `evaluate_expectations` when the repository has a rules file;
  - `timeline` to check the failures did not move to a different hour.
- **`vcon-handoff`**:
  - `capture_status`;
  - `validate_filter` on the filter that selects the calls;
  - `export_vcon` with that `filter`;
  - `validate_vcon` on each exported container, passed as `container`;
  - then record each container's `digest` (its SHA-256) and Call-ID.

  Passing `call_id` to `validate_vcon` instead exports a second container with
  a different creation time. So its digest differs from the one sent.

**sipnab serves a prompt only when the server registers every tool it
calls.**

- Under `--mcp-tools core`, `prompts/list` returns no prompt. Each one calls
  at least one tool outside `core`.
- `prompts/get` refuses a prompt it does not serve with error -32602. The
  message names the tools the server does not load and the bundles that
  hold them:

  ```json
  {"code":-32602,"message":"prompt 'triage-outage' is not served: it calls show_evidence, which this server does not load. Add the bundle(s) captures with --mcp-tools or [mcp] tools. Served: ","data":{"param":"name","reason":"not_enabled"}}
  ```

- A tool the build does not carry also hides the prompts that call it.

## Rules every tool follows

Seven rules hold across the whole surface. Each tool section on a bundle page
states only what its tool does differently. So read these once and skip them
afterwards.

**A required parameter has no default.**

- Leave one out, or send the wrong JSON type, and the tool does not run. The
  call fails with `invalid_params` (-32602), `data.reason`
  `"invalid_arguments"`, and a message that names the field, for example
  ``failed to deserialize parameters: missing field `call_id` ``.
- A value of the right type that the tool cannot use (an unknown choice, a
  range it does not accept) fails with `invalid_params` (-32602), and
  `data.reason` says which; see [Error data](#error-data).
- Optional parameters carry a `?` in every parameter table.
- Each row says what the tool does when you omit that one.

**A `limit` of `0` means the default, not "no rows".**

- `limit` defaults to 50 everywhere it appears.
- The server clamps anything larger to `--mcp-max-rows` (1000 unless the
  operator lowered it). It returns the clamped page without an error.
- Both edges bite the same caller:
  - A client that computes `limit` from "rows I still want" asks for 50 when
    it meant to ask for none.
  - A client that asks for 5000 to "get everything" receives 1000 and no
    complaint.
- Read `returned` rather than the length you asked for.

**Pass a cursor back exactly as it arrived.** `next_cursor` pairs a timestamp
with an identity:

- `<RFC 3339>|<Call-ID>` for dialogs,
- `<RFC 3339>|<Call-ID>#<message index>` for `search_messages` hits and
  `get_dialog` messages,
- `<RFC 3339>|0xSSRC@src>dst` for the `rtp_stats` sweep and
  `reconcile_orphans`.

A hand-rebuilt bare timestamp still parses on the dialog tools. So rebuilding
one costs rows instead of raising an error. `next_cursor: null` marks the
final page.

**A page ends at the first bound it reaches, and says which.** Two bounds
apply to every paged tool:

- the row limit (`limit`, clamped to `--mcp-max-rows`),
- the byte budget (`max_response_bytes`, clamped to
  `--mcp-max-response-bytes`, 1048576 bytes unless the operator changed it).

Either one does three things:

- sets `truncated: true`,
- names itself in `truncated_by` (`rows` or `bytes`),
- leaves a `next_cursor` that resumes at the first row the page left out.

`truncated_by` is absent when neither bound cut the page.

The byte budget works like this:

- It drops whole rows from the end of the page and never part of one.
- A page always keeps at least one row. So following the cursor always moves
  forward, even when one row alone is larger than the budget.
- It counts the bytes the `sipnab_mcp_tool_response_bytes_total` metric
  counts: the JSON page, the provenance note and the two completeness
  booleans below.
- The JSON-RPC framing and the `structuredContent` copy of the page are not
  counted.
- Every paged tool takes it: `list_dialogs`, `find_problems`,
  `search_by_time`, `search_messages`, `tail_dialogs`, `get_dialog`,
  `reconcile_orphans` and the `rtp_stats` sweep.

**Every list-style tool answers with a page object, never a bare array.**

- The rows sit under a named key (`dialogs`, `hits`, `streams`, `findings`)
  beside `returned` and `total_matched`.
- So counting the rows is never necessary and never right.
- `search_messages` and `security_findings` carry the page fields too.
- `tail_dialogs` is the one page object with no total, because a tail cannot
  have one. [Response
  bounding](#response-bounding) tabulates it.

**Every answer says how much of the capture is behind it.** Two booleans ride
on every response object:

- `source_exhausted`, true once sipnab has read the source to its end,
- `source_stopped_early`, true when a read ended before the source did. Causes
  are a truncated dump file, a file that would not open, or a read error
  part-way through.

The answer is the WHOLE answer only when `source_exhausted` is true and
`source_stopped_early` is false. One response tells you that much. So nothing
has to call `capture_status` to interpret it.

Until then the response omits `truncated: false` entirely.

- That value claims outright that the page holds every match.
- A caller reading only that field deserves no claim rather than a wrong one.
  JSON absence and `false` are different values.
- The response still says `truncated: true` whenever the row cap really did
  keep matches out. That fact holds whatever the load state.
- `complete`, where a tool has one, likewise never reads `true` over a partial
  read.

A file source loads on a background thread, so a call made right after the
server starts can answer from part of the file. This sends `list_dialogs` with
no pause, against a sample capture that holds 1334 dialogs:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"shell","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_dialogs","arguments":{}}}' \
  | sipnab --mcp -N -I tests/pcap-samples/sipp-branch-scenario.pcapng --quiet \
  | jq -c 'select(.id == 2) | .result.content[0].text | fromjson | {returned, total_matched, truncated_by, source_exhausted}'
```

```json
{"returned":33,"total_matched":33,"truncated_by":null,"source_exhausted":false}
```

`jq` prints `null` for `truncated_by` because the response leaves that field
out. The counts vary from run to run with how far the load had got. The same
call
sent two seconds after `notifications/initialized`:

```json
{"returned":50,"total_matched":1334,"truncated_by":"rows","source_exhausted":true}
```

When `source_exhausted` is `false`, `total_matched` counts only what had
loaded. Repeat the call, or poll `capture_status` until `source_exhausted`
reads `true`, before treating a count as final.

Twenty-one tools are the exception, because their answer cannot move with
the load. How much of the capture sipnab has read says nothing about what
their sources hold:
- Twelve read something other than the capture store:
  - `explain_response_code`, `explain_rule`, `decode_evidence`, `decode_ng`,
    `show_evidence`, `list_captures`, `list_tls_libraries`,
    `server_capabilities`;
  - `vcon_spool_status`, which counts the vCon export spool that the
    forwarder drains;
  - `compare_captures`, which reads two files and never the loaded capture;
  - `analyze_vcon`, which analyzes a container the caller hands over;
  - `vcon_directory_report`, which reads the containers in a directory of the
    file root.
- The other nine ask another process:
  - `query_relay` and `relay_stats` put the question to the media relay;
  - `tfps_status`, `tfps_banned`, `tfps_dropped`, `tfps_labels`, `tfps_ban`
    and `tfps_unban` put it to the toll-fraud prevention peer;
  - `fetch_vcon` puts it to the operator's vCon store.

The tools that answer with a rendered document have no object to put a field
in. These are `render_ladder`, and `get_capture_report` / `get_dialog_report`
in `markdown` and `text`. So they say it in prose instead.

- A document drawn over a capture that is still loading ends with the same
  `INCOMPLETE RUN` block `--report` appends, naming each reason.
- The same holds over a capture whose read stopped before its end.
- A document drawn over a capture read in full says nothing extra. A caveat on
  every answer is a caveat nobody reads.

Every other tool answers with a JSON object, and the two booleans sit in the
object beside the tool's own fields.
[`timeline`](mcp-tools-signaling.md#timeline), for example, returns its
`buckets` inside an object that carries both.

**Capture text arrives fenced, and identifiers do not.**

- Free text an endpoint wrote comes wrapped in
  `⟦untrusted-capture-data⟧` and `⟦/untrusted-capture-data⟧`. That covers
  display names, `User-Agent`, SDP and whole messages.
- The tools that emit it append a provenance note as the LAST content block.
- Call-IDs, cursors, addresses and timestamps stay verbatim. So they pass
  straight into the next call.

[Untrusted capture text](mcp-protocol.md#untrusted-capture-text) gives the
per-tool breakdown. Every JSON sample on the bundle pages shows the markers
where the server really emits them.

### Narrowing a row with `fields`

`list_dialogs`, `find_problems`, `tail_dialogs` and `search_by_time` take an
optional `fields` array. Each row then carries only the fields you name, which
makes a large page smaller. `limit`, `--mcp-max-rows` and cursors bound the
number of rows, and `fields` bounds what each row carries.

Ask for two fields on each dialog in the paging sample capture from
Reproduce the examples below:

```json
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_dialogs","arguments":{"limit":2,"fields":["state","final_status_code"]}}}
```

The `dialogs` array in the answer:

```json
[{"call_id":"call-1-synth@192.0.2.10","final_status_code":403,"state":"Registered"},{"call_id":"call-2-synth@192.0.2.10","final_status_code":403,"state":"Registered"}]
```

The rules:

- **`call_id` is always kept**, listed or not, so you can pass every row to a
  follow-up tool.
- **An unknown name fails** with `invalid_params` (-32602). The message and
  `data.valid_values` list the fields the row carries:

  ```json
  {"code":-32602,"message":"unknown field 'stat'; this row carries: call_id, created_at, duration_sec, final_status_code, frame, from_user, input_origin, method, msg_count, state, timing, to_user, updated_at","data":{"param":"fields","reason":"invalid_choice","valid_values":["call_id","created_at","duration_sec","final_status_code","frame","from_user","input_origin","method","msg_count","state","timing","to_user","updated_at"]}}
  ```

- **The page fields are always kept.** `total_matched`, `truncated`,
  `next_cursor` and `capture_identity` stay on the response whatever `fields`
  names.
- A field a row does not carry stays absent. It does not appear as `null`.

### File tools — the shared rule

These tools all require `--mcp-file-root <DIR>` and refuse to run without it:

- `list_captures`, `export_capture`, `export_audio`,
- [`compare_captures`](mcp-tools-captures.md#compare_captures),
- [`build_evidence_package`](mcp-tools-captures.md#build_evidence_package).

They take a **bare filename, never a path**.

- [`generate_repro`](mcp-tools-signaling.md#generate_repro) joins them the
  moment you give it a `filename`.
- [`decode_evidence`](mcp-tools-captures.md#decode_evidence) pushes the source
  half of a frame pointer through the same guard.

sipnab refuses `../x`, `/etc/passwd` and `sub/dir.pcap` before any filesystem
call, with `invalid_params` and `data.reason` `path_refused`:

```json
{"code":-32602,"message":"'../x' is not a bare filename. These tools take a name, not a path, and write only inside the configured --mcp-file-root.","data":{"reason":"path_refused"}}
```

sipnab also refuses a symbolic link inside the root that resolves outside the
root. It checks where the name points, not how the caller wrote it:

```json
{"code":-32602,"message":"'link' resolves outside the configured --mcp-file-root. The name is a link to '/tmp', and these tools write only inside the root.","data":{"reason":"path_refused"}}
```

sipnab also refuses a name that holds a control character, such as a newline
or a NUL byte, with the same reason. sipnab accepts a space in a name:

```json
{"code":-32602,"message":"\"out\\n.pcap\" contains a control character. These tools take a plain file name inside the configured --mcp-file-root.","data":{"reason":"path_refused"}}
```

Each tool returns the resolved path of the file it wrote. Without
`--mcp-file-root`, every file tool answers `not_enabled`:

```json
{"code":-32602,"message":"file tools are disabled: start sipnab with --mcp-file-root <DIR> to enable them","data":{"reason":"not_enabled"}}
```

> **The boundary stops an escape, and an overwrite.** Inside the root, these
> refuse a filename that already exists:
>
> - `export_capture`, `export_audio`, `build_evidence_package`,
> - `generate_repro`'s `filename`,
> - `shutdown_server`'s `save_to`.
>
> They name the file and ask for one that is free (`data.reason`
> `already_exists`). Choose another name, or call
> [`list_captures`](mcp-tools-captures.md#list_captures) to see which names a
> directory already uses.
>
> The write itself creates the file only if the name is still free and never
> follows a link at that name, so a file or link that appears after the check
> fails the call instead of being overwritten.
>
> The guard covers every file in the root, not only the capture the run is
> reading: the captures staged there for
> [`open_capture`](mcp-tools-captures.md#open_capture) and every earlier
> export keep their contents too.

### Tool argument enums

**`find_problems.kinds`** — diagnostic alias names, OR-ed together.
Defaults to `["problems"]`. The full vocabulary:

`problems` · `slow-setup` · `short-calls` · `one-way` · `nat-issues` ·
`codec-asym` · `ptime-asym` · `payload-asym` · `duration-asym` ·
`late-media`

An unknown alias returns `invalid_params` (-32602) naming the alias, with
the vocabulary in `data.valid_values`:

```json
{"code":-32602,"message":"unknown alias 'bogus'","data":{"param":"kinds","reason":"invalid_choice","valid_values":["problems","slow-setup","short-calls","one-way","nat-issues","codec-asym","ptime-asym","payload-asym","duration-asym","late-media"]}}
```

The same names work as the `list_dialogs` `filter` aliases (and as
`sipnab --filter` aliases on the CLI).

**`security_findings.kinds`** matches the rule names sipnab records findings
under: `scanner`, `fraud`, `digest`, `reg_flood`.

- Write `reg_flood` with an underscore. The `--alert` rule grammar spells it
  `reg-flood`, but sipnab records and filters findings as `reg_flood`.
- Omitted or empty `kinds` returns findings of every kind.
- sipnab refuses an unknown name and lists the four names. For `reg-flood`
  the refusal also suggests the underscore spelling:

  ```json
  {"code":-32602,"message":"unknown kind 'reg-flood', expected one of: digest, fraud, reg_flood, scanner (did you mean 'reg_flood'?)","data":{"param":"kinds","reason":"invalid_choice","valid_values":["digest","fraud","reg_flood","scanner"]}}
  ```

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

#### Error data

Every -32602 and -32000 error also carries a `data` object. So a client can
act on the error without parsing `message`.

- The `message` text stays as it was.
- People read `message`, and its wording may improve between releases.
- The `data` codes below stay stable.

```jsonc
{
  "code": -32602,
  "message": "cannot group by 'bogus'; one of: state, response_code, method, from.user, to.user, ua, src.ip, dst.ip, rtp.codec. One dimension only -- narrow with `filter` rather than adding a second.",
  "data": {
    "param": "group_by",              // the argument that was refused, when one was
    "reason": "invalid_choice",       // always present
    "valid_values": ["state", "response_code", "method", "from.user", "to.user", "ua", "src.ip", "dst.ip", "rtp.codec"]  // the allowed set, when there is one
  }
}
```

| Member | Present | Meaning |
|---|---|---|
| `reason` | always | A stable lowercase code from the table below. |
| `param` | when one argument caused the refusal | The argument's name, as the tool's input schema spells it. For a resource read, the URI template variable (`tool`, `alias`, `rule_id`) or `uri`. |
| `valid_values` | when the refusal is "not one of these" | The values the server accepts for that argument. |
| `retry_after_ms` | on a rate-limit refusal | Milliseconds until the current one-second window ends and the same call can succeed. |

sipnab omits a member that does not apply, rather than sending it as `null`.

| `reason` | Code | Meaning |
|---|---|---|
| `not_found` | -32602 | A named thing (a Call-ID, a rule, a finding, a sweep job, a subscription) is not held by this server. |
| `invalid_choice` | -32602 | The value is not in the allowed set; `valid_values` lists the set. |
| `invalid_value` | -32602 | The value is empty, out of range, or not in the expected format. |
| `invalid_filter` | -32602 | A filter expression did not compile. |
| `missing_param` | -32602 | A required argument, or one of a set of alternatives, was not given. |
| `conflicting_params` | -32602 | The call named two arguments that cannot appear together. |
| `not_enabled` | -32602 | The operator did not enable this on the server: an opt-in flag such as `--mcp-allow-shutdown`, `--mcp-file-root`, or `--allow-action`. |
| `path_refused` | -32602 | sipnab refused a filename: not a bare name, outside `--mcp-file-root`, or one of the capture's own inputs. |
| `already_exists` | -32602 | The filename asked for already exists, and sipnab does not overwrite. |
| `not_ready` | -32602 | The server's current state refuses the request (a capture is still loading, a live capture is running, the source has not finished). The same call can succeed later. |
| `limit_exceeded` | -32602 | The request asks for more than a ceiling this server enforces. |
| `unsupported` | -32602 | This build, platform, or process privilege cannot do this. |
| `scope_refused` | -32602 | The caller's token scope does not cover this tool. |
| `declined` | -32602 | The person asked to confirm the request (MCP elicitation) declined it. |
| `no_data` | -32602 | The named call holds nothing of the kind asked for: no messages, no RTP streams, no request to replay. |
| `unknown_tool` | -32602 | The tool name is not loaded on this server; `valid_values` lists the loaded names. |
| `invalid_arguments` | -32602 | Arguments that do not match the tool's input schema (a wrong JSON type, a missing required key), an argument this server refuses whatever its value (a password-like argument name), or a refusal the MCP SDK built without naming the argument. |
| `at_capacity` | -32000 | `--mcp-max-concurrent` calls are already running. There is no `retry_after_ms`, because a slot frees when some running call ends and the server cannot know when that happens. |
| `rate_limited` | -32000 | This peer used its `--mcp-rate-limit-per-peer` allowance for the current one-second window. `retry_after_ms` says when the window ends. |

Arguments that do not match a tool's input schema at all (a wrong JSON type,
a missing required key) fail the same way, with `invalid_arguments` and the
parse error as the message:

```json
{"jsonrpc": "2.0", "id": 3, "error": {"code": -32602, "message": "failed to deserialize parameters: missing field `call_id`", "data": {"reason": "invalid_arguments"}}}
```

### Response bounding

| Limit | Default | Set by |
|---|---|---|
| Default `limit` for list-style tools | 50 | the per-call `limit` |
| Ceiling on `limit` (clamps higher requests) | 1000 | `--mcp-max-rows` |
| SIP body / snippet bytes | 4096 | `--mcp-max-body-bytes` |
| Messages per `get_dialog` page | 100 | the per-call `max_messages`, up to `--mcp-max-rows` |
| Bytes of one whole paged response | 1048576 | the per-call `max_response_bytes`, up to `--mcp-max-response-bytes` |

Set the ceilings for the client that reads the answers: lower for an agent
with a small context window, higher for a batch client that writes answers to
a file. Raise or lower them with `--mcp-max-rows`, `--mcp-max-body-bytes` and
`--mcp-max-response-bytes`, or the matching `[limits]` keys in the config
file. The per-call `limit` and `max_response_bytes` narrow an answer below the
ceiling, and cannot exceed it.

The row and body ceilings bound a row's count and a body's width. Neither
bounds the response as a whole.

- Fifty `get_dialog` messages that each carry a long SDP body are within both.
  They can still exceed what a small model can read.
- The byte budget covers that case. Its default is 1048576 bytes (1 MiB).
  Lower it per call with `max_response_bytes`, or for every call with
  `--mcp-max-response-bytes`.

A bound is not a loss. These tools each report `total_matched` beside their
page:

- `list_dialogs`, `find_problems`, `search_by_time`, `search_messages`,
  `security_findings`,
- the capture-wide `rtp_stats` sweep.

So a caller sees how much of the answer it holds.

That number describes the STORE, not the file.

- While the source is still loading, it counts what had arrived by then.
- That is why every one of them also carries `source_exhausted`.
- It is also why the response omits `truncated: false` until the answer is
  whole.

All of those except `security_findings` carry a cursor to the rest. So do
`tail_dialogs`, `get_dialog` and `reconcile_orphans`. Every one of the eight
cursor tools takes `max_response_bytes`.

Asking for a `limit` above the ceiling does nothing, because the ceiling
clamps it. So either raise the ceiling with `--mcp-max-rows` or page.

**Some tools take `limit` and carry no cursor, and a caller has to know
which:**

| Tool | Reports a total | Why no cursor | How to reach the rest |
|---|---|---|---|
| `security_findings` | Yes, `total_matched` | Its source is a ring buffer whose default depth is 1000, the same as the maximum `limit`, so one call reaches all of it | Raise `limit`, and narrow with `since` |
| `find_correlated` | Yes, `total_matched` | A ranking by score: a later page would hold weaker matches, not the rest of a list | Raise `limit` |
| `get_call_tree` | No, `truncated` only | A breadth-first walk outward from one call, stopped at `limit` legs | Raise `limit` |
| `top_talkers` | Yes, `distinct_talkers` | A ranking by dialog count | Raise `limit` |
| `describe_endpoint` | Yes, `dialogs` | `recent_dialogs` is newest first by `updated_at`, which moves each time a call gains a message, so a cursor on it would skip rows | [`list_dialogs`](mcp-tools-core.md#list_dialogs) with a filter such as `src.ip == '192.0.2.10'` or `from.user == 'alice'` pages that endpoint's dialogs |
| `hep_senders` | Yes, `senders_tracked` and `refused_sources_tracked` | Two lists in one answer, the refused sources ranked by count, and the same fields and values `GET /v1/hep/senders` returns | Raise `limit`, and raise `--mcp-max-rows` as well when the listener tracks more than 1000 senders |
| `tfps_labels` | No: `total` counts the rows TFPS returned, and `truncated` says it held more | TFPS's `log` command takes a row count and no offset, so there is no position to resume from | Raise `limit`, or run `tfps_ctl log --json --limit N` on the TFPS host |
| `tail_dialogs` | No | It has a cursor. The table names it because it has no total | Follow `next_cursor` until the page comes back empty |

`aggregate_dialogs`, `group_dialogs` and `compare_captures` take `top_n` rather
than `limit`.

- They sum everything past it into `other_count` or `other`.
- So they withhold nothing silently, and have no cursor either.

`tail_dialogs` reports no total, because a tail cannot have one. The store
keeps changing underneath it. So any number it gave would describe a moment
that has passed.

## Reproduce the examples

Each tool section on a bundle page names the capture its example ran against.
Start a server on that capture, then call the tool. These two cover most of
the examples:

```bash
# The paging examples: 1334 dialogs, no RTP.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sipp-branch-scenario.pcapng
```

```bash
# The media examples: two calls (one completed, one still in progress at the end of the file) and two RTP streams.
sipnab -N --mcp --mcp-transport http --mcp-bind 127.0.0.1:8731 \
       --mcp-file-root tests/pcap-samples \
       -I tests/pcap-samples/sip-rtp-g711.pcap
```

Drive either one with the [raw HTTP test](mcp-deploy.md#test-the-http-wire-by-hand) on the deployment page, or point
a client at `http://127.0.0.1:8731/mcp`. A loopback bind needs no token.

Numbers in the samples are what those captures produce. A file replay reads
packet timestamps rather than arrival times, so jitter and MOS come out
identical on every run. A value that does not match points at a change in the
binary or the capture.
