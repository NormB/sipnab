# The surface-capability matrix (PAR2)

The JOIN the four inventories exist to feed. PAR1
([`surface-capability-inventory.md`](surface-capability-inventory.md)) lists
every item on each surface separately. This document is the join across them: one
capability per row, and for each of CLI, TUI, REST and MCP the exact spelling
that reaches it, or a recorded reason it is absent. Parity is measured the way
[`surface-parity-definition.md`](surface-parity-definition.md) defines it, and
the anchor is the MCP tool set, because parity here means "everything an agent
can ask, reachable however each other caller would want to ask it."

[`tests/surface_capability_matrix_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/surface_capability_matrix_test.rs) holds this document to the program:
every `present` spelling must be a real item in the PAR1 inventory, every MCP
tool must be claimed by exactly one capability, every REST route and TUI view
must be claimed or declared operational, and every gap is counted so closing one
is a visible, deliberate edit.

## How to read a row

Each capability has one table. The `Detail` cell is one of three things:

- **A spelling** in backticks — the capability is present on that surface, and
  the spelling is the flag, route, view or tool a caller reaches for. It must be
  a real item in the PAR1 inventory.
- **`decision: <reason>`** — the capability is deliberately absent, because it
  fails that surface's own question (a build gate is not interactive, a prose
  explanation is not something a program polls). The reason is the decision.
- **`gap: <reason>`** — the capability passes that surface's question but is not
  built there yet. This is a real hole, named so PAR3 (REST), PAR4 (TUI) or
  PAR5 (CLI) can close it. MCP is never a gap here, because MCP is the anchor.

## Operational routes and views (not capabilities)

These carry no user capability. They exist so the machinery runs, and they are
declared here so the matrix accounts for every inventory item without pretending
these are features.

### Operational REST routes

- `/health` — liveness for a load balancer, returns `ok`.
- `/metrics` — the Prometheus scrape, counters about sipnab itself.
- `/v1/persistence` — the persistence control plane, an operational toggle
  rather than a capture capability, and it has no agent-facing tool.

### Operational TUI views

- `Help` — the keybinding reference, reachable with `?`.

## Capabilities

### List dialogs

Which dialogs are in the store, filtered and paged?

| Surface | Detail |
|---|---|
| CLI | `--json-dialogs` with `--filter` |
| TUI | `CallList` |
| REST | `/v1/dialogs` |
| MCP | `list_dialogs` |

### Read one dialog

Show me one whole dialog with its SIP messages.

| Surface | Detail |
|---|---|
| CLI | `--json-dialogs` |
| TUI | `CombinedDetail` |
| REST | `/v1/dialogs/{call_id}` |
| MCP | `get_dialog` |

### Read one SIP message

Re-read one SIP message in full, by its index in the dialog.

| Surface | Detail |
|---|---|
| CLI | `--json` |
| TUI | `RawMessage` |
| REST | `/v1/dialogs/{call_id}` |
| MCP | `get_message` |

### Per-call structured report

The structured per-call report — timing, parties, RTP quality, diagnosis.

| Surface | Detail |
|---|---|
| CLI | `--call-report` |
| TUI | `CallFlow` and `CallTimeline` |
| REST | `/v1/dialogs/{call_id}/report` |
| MCP | `get_dialog_report` |

### Call-flow ladder

Draw the SIP call-flow ladder for this Call-ID.

| Surface | Detail |
|---|---|
| CLI | `--call-report` with `--markdown` |
| TUI | `CallFlow` |
| REST | decision: a rendered ladder is a drawing for eyes, and a program integrates the structured flow at `/v1/dialogs/{call_id}` instead |
| MCP | `render_ladder` |

### SDP offer/answer timeline

What were the SDP offer and answer exchanges, in order?

| Surface | Detail |
|---|---|
| CLI | `--json-dialogs` |
| TUI | `SdpTimeline` |
| REST | `/v1/dialogs/{call_id}` |
| MCP | `get_sdp_timeline` |

### B2BUA call tree

Show me every leg of this call as a tree across the B2BUA, SBC and PBX hops.

| Surface | Detail |
|---|---|
| CLI | gap: transitive multi-leg reassembly is a one-shot fact, but no flag exposes correlation (PAR5) |
| TUI | `CallFlow` |
| REST | `/v1/dialogs/{call_id}/tree` |
| MCP | `get_call_tree` |

### Correlate legs

What are the other legs of this call, and by which strategy was each matched?

| Surface | Detail |
|---|---|
| CLI | gap: a one-shot "where did this call go next" is legitimate, but no flag exposes correlation (PAR5) |
| TUI | `CallFlow` |
| REST | `/v1/dialogs/{call_id}/correlated` |
| MCP | `find_correlated` |

### Search message bodies

Find every SIP message whose full text contains this substring.

| Surface | Detail |
|---|---|
| CLI | `--match` |
| TUI | `CallList` |
| REST | `/v1/dialogs` with a `payload =~` DSL `filter` |
| MCP | `search_messages` |

### Search by time window

Which dialogs fall in this wall-clock window?

| Surface | Detail |
|---|---|
| CLI | gap: scoping a batch to when the user says it broke is one-shot, but no time-window flag exists and the filter has no timestamp field (PAR5) |
| TUI | gap: a human reviewing a capture wants a time-range filter, but the filter dialog has no time field (PAR4) |
| REST | `/v1/dialogs` with `after`/`before` |
| MCP | `search_by_time` |

### Call-volume histogram

What is the call volume over time, in fixed-width buckets?

| Surface | Detail |
|---|---|
| CLI | gap: a volume histogram is a one-shot batch fact, but no flag produces per-bucket counts (PAR5) |
| TUI | `CallVolume` |
| REST | `/v1/timeline` |
| MCP | `timeline` |

### Group-by counts

Count dialogs grouped by one field — state, response code, source IP, codec.

| Surface | Detail |
|---|---|
| CLI | gap: arbitrary single-field counts are one-shot, but no group-by flag exists (PAR5) |
| TUI | `Statistics` |
| REST | `/v1/aggregate` |
| MCP | `aggregate_dialogs` |

### Carrier metrics by group

Per group, the carrier metrics — ASR, NER, ACD, PDD percentiles, MOS, retransmit rate.

| Surface | Detail |
|---|---|
| CLI | gap: rates per dimension are one-shot facts, but no flag computes them (PAR5) |
| TUI | `CarrierMetrics` |
| REST | `/v1/dialogs/rates` |
| MCP | `group_dialogs` |

### Compare two dialogs

Put two calls side by side and list what differs.

| Surface | Detail |
|---|---|
| CLI | gap: one-shot comparison belongs here, but there is no compare flag (PAR5) |
| TUI | `CompareDialogs` |
| REST | `/v1/dialogs/compare` |
| MCP | `compare_dialogs` |

### Diagnostic problem filter

Show me the calls matching diagnostic aliases — problems, one-way, late-media.

| Surface | Detail |
|---|---|
| CLI | `--filter` |
| TUI | `QualityDashboard` |
| REST | `/v1/dialogs` with a DSL `filter` (aliases like `problems`) |
| MCP | `find_problems` |

### RFC conformance findings

What SIP RFC-conformance defects does this call or message trip?

| Surface | Detail |
|---|---|
| CLI | `--lint` with `--lint-fail-on` |
| TUI | `Conformance` |
| REST | `/v1/dialogs/{call_id}/lint` |
| MCP | `lint_dialog` and `validate_message` |

### Tail changes since a cursor

Which dialogs changed since I last polled?

| Surface | Detail |
|---|---|
| CLI | decision: cursor-resume polling is a machine pattern, and the CLI streams live with `--json-dialogs` instead of resuming from a cursor |
| TUI | `CallList` |
| REST | `/v1/dialogs/tail` |
| MCP | `tail_dialogs` |

### Orphaned media reconciliation

For each RTP stream with no dialog, why is it unexplained?

| Surface | Detail |
|---|---|
| CLI | `--analyze` |
| TUI | `StreamList` |
| REST | `/v1/streams` |
| MCP | `reconcile_orphans` |

### Per-stream RTP quality

Each RTP stream's quality — codec, MOS, jitter, loss, packets, SSRC.

| Surface | Detail |
|---|---|
| CLI | `--report` |
| TUI | `StreamList`, `StreamDetail`, `QualityDashboard` and `StreamLossMap` |
| REST | `/v1/streams` |
| MCP | `rtp_stats` |

### Media diagnostics

The media facts beyond raw quality — DSCP, jitter grounding, silence, RTCP.

| Surface | Detail |
|---|---|
| CLI | `--report` |
| TUI | `StreamDetail` |
| REST | `/v1/streams/{id}` |
| MCP | `media_diagnostics` |

### Codec negotiation

What codecs were offered against answered, and do they intersect?

| Surface | Detail |
|---|---|
| CLI | `--call-report` |
| TUI | `CallFlow` |
| REST | `/v1/dialogs/{call_id}/report` |
| MCP | `check_codec_negotiation` |

### Registration diagnosis

Is this phone online — did it register, get rejected, loop on auth?

| Surface | Detail |
|---|---|
| CLI | `--call-report` |
| TUI | `CallFlow` |
| REST | `/v1/dialogs/{call_id}/report` |
| MCP | `diagnose_registration` |

### Top talkers

Who are the busiest participants, largest first?

| Surface | Detail |
|---|---|
| CLI | gap: a one-shot ranked talker table needs no human, but no flag produces it (PAR5) |
| TUI | `Talkers` |
| REST | `/v1/talkers` |
| MCP | `top_talkers` |

### Per-endpoint rollup

Everything one endpoint did — counts, INVITE outcomes, REGISTER state, streams.

| Surface | Detail |
|---|---|
| CLI | gap: a one-shot per-endpoint rollup is CLI-shaped, but the match flags filter and dump, they do not aggregate (PAR5) |
| TUI | `EndpointRollup` |
| REST | `/v1/endpoints` |
| MCP | `describe_endpoint` |

### Export decoded audio

Give me this call's decoded RTP audio as a file.

| Surface | Detail |
|---|---|
| CLI | gap: a one-shot `--export-audio` to a WAV is CLI-shaped, but audio leaves the CLI only inside a vCon, never as a standalone WAV (PAR5) |
| TUI | `StreamDetail` |
| REST | `/v1/dialogs/{call_id}/audio` |
| MCP | `export_audio` |

### Relay statistics

What counters does the live relay keep — global, per-call, and the names it knows?

| Surface | Detail |
|---|---|
| CLI | `--relay-stats`, `--relay-stats-call` and `--relay-stats-list` |
| TUI | `RelayStats` |
| REST | `/v1/relay/stats`, `/v1/relay/stats/call/{call_id}` and `/v1/relay/stats/names` |
| MCP | `relay_stats` |

### Relay against capture

How does the relay's per-call RTP count compare to what sipnab measured?

| Surface | Detail |
|---|---|
| CLI | `--relay-compare` |
| TUI | `RelayStats` |
| REST | `/v1/relay/compare/{call_id}` |
| MCP | `relay_compare` |

### Poll relay statistics on an interval

Keep asking the relay for its counters, every N seconds.

| Surface | Detail |
|---|---|
| CLI | `--relay-stats-interval` |
| TUI | `RelayStats` |
| REST | decision: a poll is a standing instruction to transmit, and a REST caller who starts one does not own the host or see that it keeps transmitting after disconnect |
| MCP | decision: as with REST, the caller who starts a timer is not the operator, and every other agent tool answers from bytes already held rather than installing a standing transmit |

### Relay holdings

What Call-IDs is the live relay holding right now?

| Surface | Detail |
|---|---|
| CLI | gap: a one-shot holdings query is CLI-shaped for incident response, but the relay-stats family transmits only for stats, not holdings (PAR5) |
| TUI | `RelayStats` |
| REST | `/v1/relay/holdings` and `/v1/relay/holdings/{call_id}` |
| MCP | `query_relay` |

### Decode a relay control message

Follow a frame pointer to one captured relay control message and its provenance.

| Surface | Detail |
|---|---|
| CLI | decision: the input is a machine-emitted frame pointer, and the CLI already surfaces relay control messages inline, so there is nothing for an operator to type |
| TUI | decision: the TUI shows control messages in its message views, and a frame-pointer step is a machine artifact a person never types |
| REST | decision: no REST response emits frame pointers, so a REST client has nothing to decode |
| MCP | `decode_ng` |

### Capture status

What is this server attached to, how much does it hold, is the source exhausted?

| Surface | Detail |
|---|---|
| CLI | `--report` |
| TUI | `Statistics` |
| REST | `/v1/stats` |
| MCP | `capture_status` |

### Capture health

Is the capture path losing packets — kernel drops, invalid timestamps, undecodable frames?

| Surface | Detail |
|---|---|
| CLI | `--analyze` |
| TUI | `CaptureHealth` |
| REST | `/v1/stats` |
| MCP | `capture_health` |

### Runtime cost

What is sipnab costing the host — its memory, threads, CPU, load-bearing share?

| Surface | Detail |
|---|---|
| CLI | decision: a process's own footprint is a running-server poll, and a batch run exposes none of it while `ps` and `time` answer it |
| TUI | decision: memory and descriptor impact is machine-to-machine monitoring read in a process monitor, not the live capture terminal |
| REST | `/v1/runtime` |
| MCP | `runtime_stats` |

### Whole-capture report

The whole-capture problem report — findings, orphaned media, what retention shed.

| Surface | Detail |
|---|---|
| CLI | `--report` |
| TUI | `Statistics` |
| REST | `/v1/report` |
| MCP | `get_capture_report` |

### Open or replace the capture

Load a different capture file, replacing what I am looking at now.

| Surface | Detail |
|---|---|
| CLI | `--input` |
| TUI | `CallList` |
| REST | decision: swapping the loaded capture is a destructive control that voids every other client's cursors, and REST here is read-only query over one capture |
| MCP | `open_capture` |

### List captures in the sandbox

Which capture files are in the agent sandbox directory?

| Surface | Detail |
|---|---|
| CLI | decision: the sandbox is an agent affordance, and a CLI user has a shell and passes paths directly |
| TUI | `CallList` |
| REST | decision: REST cannot open a different capture, so a file listing is inert to a REST client |
| MCP | `list_captures` |

### Find a Call-ID across files

Which of these rotated files holds Call-ID X, without disturbing what is loaded?

| Surface | Detail |
|---|---|
| CLI | gap: a bounded sweep of several files reporting which match is a textbook one-shot CLI job, but no dedicated flag exists (PAR5) |
| TUI | decision: a cross-file content sweep is a batch affordance, and a human opens one file and searches within it |
| REST | decision: the do-not-touch-the-loaded-capture guarantee is an agent-cursor concern, and REST has no file-root surface |
| MCP | `find_in_captures` |

### Compare two captures

Is today's capture worse than yesterday's, and in which bucket?

| Surface | Detail |
|---|---|
| CLI | gap: diff capture A against B and rank what moved is exactly a cron job, but it is absent (PAR5) |
| TUI | decision: a whole-file cross-capture trend is a batch artifact, not an interactive terminal affordance |
| REST | `/v1/captures/compare` |
| MCP | `compare_captures` |

### Export capture to pcap

Write the SIP I am holding to a pcap before the process exits.

| Surface | Detail |
|---|---|
| CLI | `--output` |
| TUI | `CallList` |
| REST | decision: writing a server-side pcap file is a side-effecting control action, not a queryable fact, and REST here is read-only |
| MCP | `export_capture` |

### Export vCon

Hand me these dialogs as vCon conversation containers.

| Surface | Detail |
|---|---|
| CLI | `--export-vcon` |
| TUI | decision: a structured interchange container is a machine handoff, and the save dialog deliberately offers pcap and text formats, not vCon |
| REST | `/v1/dialogs/{call_id}/vcon` |
| MCP | `export_vcon` |

### Validate vCon

Does this vCon container pass sipnab's vendored schema?

| Surface | Detail |
|---|---|
| CLI | gap: schema conformance of a document is a one-shot CI check, but no flag exists (PAR5) |
| TUI | decision: validating JSON against a schema is a CI concern, and a human at a terminal would not reach for a conformance screen |
| REST | `/v1/vcon/validate` (POST) |
| MCP | `validate_vcon` |

### SIPREC metadata

Who was recorded on this call, in what mode, and which stream carries whom?

| Surface | Detail |
|---|---|
| CLI | `--call-report` |
| TUI | `CallFlow` |
| REST | `/v1/dialogs/{call_id}/report` |
| MCP | `siprec_metadata` |

### Start TLS capture

Attach kernel uprobes to this host's TLS libraries and read SIP plaintext.

| Surface | Detail |
|---|---|
| CLI | `--uprobe-tls` |
| TUI | decision: installing privileged kernel probes on the host is a launch-time operator decision, not an interactive affordance |
| REST | decision: starting a live writer is a control mutation that would race sipnab's single-writer stores, and REST here is read-only |
| MCP | `start_tls_capture` |

### List TLS libraries

Which TLS libraries is this host mapping, and could sipnab probe them?

| Surface | Detail |
|---|---|
| CLI | `--uprobe-list` |
| TUI | decision: a pre-capture host probe is something you run before deciding to capture, not from a TUI bound to a loaded capture |
| REST | decision: a host-inventory pre-flight for a control action REST cannot invoke has no REST home |
| MCP | `list_tls_libraries` |

### Server capabilities

What did this build compile in, and what did the operator turn on?

| Surface | Detail |
|---|---|
| CLI | decision: `--version` carries the human-readable feature list, and the runtime opt-ins are flags the operator set themselves |
| TUI | decision: the `Help` view's version line shows the feature list, and the structured opt-in contract is machine-only |
| REST | `/v1/capabilities` |
| MCP | `server_capabilities` |

### Remote lifecycle stop

Stop this process, or remove the uprobes, from a caller with no OS signal.

| Surface | Detail |
|---|---|
| CLI | decision: a CLI run ends on Ctrl-C or an exhausted source, and process lifecycle is the invocation's own concern |
| TUI | decision: the human quits with `q`, and that is the stop, not a distinct capability |
| REST | decision: remote process control is a privileged operational action, not a queryable fact a polling integrator would want |
| MCP | `stop_tls_capture` and `shutdown_server` |

### Evidence bytes behind a pointer

Do the raw bytes behind this pointer still match the digest recorded when the claim was made?

| Surface | Detail |
|---|---|
| CLI | decision: the raw-print path already shows bytes, and the digest re-check exists to let an agent audit its own text answers |
| TUI | `RawMessage` |
| REST | decision: frames are not retained live, so there is nothing for a REST client to resolve a pointer against |
| MCP | `decode_evidence` and `show_evidence` |

### Evidence package bundle

Give me one shareable bundle to attach to a carrier ticket.

| Surface | Detail |
|---|---|
| CLI | decision: the pieces exist as pcap write and report, but a bundled directory with a manifest is a handoff convenience, not a capture flag |
| TUI | decision: the save dialog exports each piece individually, and a single-key bundle is an agent handoff shape |
| REST | decision: the report and vCon already expose the analyzable data, and writing a package directory is a side-effecting file operation |
| MCP | `build_evidence_package` |

### Save an agent finding

Record my one-line conclusion about this capture to the log.

| Surface | Detail |
|---|---|
| CLI | decision: this is an agent's private conclusion log, gated by its own opt-in, and reaches no store or later answer |
| TUI | decision: the action trail logs a human's keystrokes and exports, not a free-text conclusion a person writes outside the tool |
| REST | decision: the only REST writes are enforcement and persistence, and a findings-write is an agent memory affordance |
| MCP | `save_findings` |

### Detector security findings

What did the armed detectors — scanner, fraud, digest, reg-flood — record recently?

| Surface | Detail |
|---|---|
| CLI | `--alert-json` |
| TUI | `SecurityFindings` |
| REST | `/v1/security/findings` |
| MCP | `security_findings` |

### Explain and triage

Explain a code, a rule or an attribution in words, and triage where the fault lies.

| Surface | Detail |
|---|---|
| CLI | decision: a prose explanation is agent reasoning, and a script uses the structured facts and alias filters instead |
| TUI | decision: a human reads the split from the flow and quality views, and reason phrases already appear there, so no prose-verdict panel is needed |
| REST | decision: a classification narrative is not a poll-or-integrate resource, and integrators consume the underlying facts |
| MCP | `triage_call`, `explain_attribution`, `explain_response_code` and `explain_rule` |

### Generate a SIPp repro

Build a SIPp scenario that replays this call to test a hypothesis.

| Surface | Detail |
|---|---|
| CLI | decision: no SIPp-export flag exists, and the pin-and-vary hypothesis encoding is agent reasoning over the plain replay |
| TUI | `CallFlow` |
| REST | decision: producing a test artifact is not a poll-or-integrate operation |
| MCP | `generate_repro` |

### Generate a fail2ban rule

Turn one recorded finding into a fail2ban filter and jail.

| Surface | Detail |
|---|---|
| CLI | `--fail2ban` |
| TUI | decision: generating a ban stanza is not an interactive capture-review action, and enforcement is the peer's job |
| REST | decision: the automation path is the evidence feed into the enforcement peer, and there is no findings route to key a stanza off |
| MCP | `generate_fail2ban_rule` |

### Generate a Wireshark filter

Give me a Wireshark or tshark display filter selecting this call and its RTP.

| Surface | Detail |
|---|---|
| CLI | `--tshark-filter` |
| TUI | decision: the TUI produces no display filter, and a human uses the CLI or copies the Call-ID |
| REST | decision: a filter string is a templating convenience, and the report already carries the Call-ID and SSRCs a client can template |
| MCP | `generate_wireshark_filter` |

### Validate a filter expression

Does this filter expression parse, and how many dialogs does it select?

| Surface | Detail |
|---|---|
| CLI | decision: `--filter` compiles and rejects the same expression, and the count-only dry run is an agent's cheap-iterate affordance |
| TUI | `CallList` |
| REST | decision: `/v1/dialogs` has no expression filter param, so there is nothing to validate, and a program just issues its query |
| MCP | `validate_filter` |

### Evaluate expectations

Judge this capture against a rule suite and return a build exit code.

| Surface | Detail |
|---|---|
| CLI | gap: the engine returns a CI exit code, but [`src/expect.rs`](https://github.com/NormB/sipnab/blob/main/src/expect.rs) records that no flag reaches it yet, so a checked-in expectations file cannot fail a build and only the agent tool can run it — the strongest close-worthy gap in this matrix (PAR5) |
| TUI | decision: a build gate is not interactive |
| REST | decision: CI gates run through CLI exit codes, and a monitoring poll uses the stats route with its own thresholds |
| MCP | `evaluate_expectations` |

### Await a condition

Block until a filter matches, so I do not poll in a loop.

| Surface | Detail |
|---|---|
| CLI | decision: a script tails the live stream, and the per-poll cost this removes is a model-call cost specific to agents |
| TUI | decision: watching the live-updating `CallList` is the wait, because the TUI is inherently live |
| REST | decision: interval-polling `/v1/dialogs` is idiomatic and cheap for a program, with no model-call cost to eliminate |
| MCP | `await_condition` |

### TFPS observe

Is the enforcement peer condemning sources, and what has it dropped?

| Surface | Detail |
|---|---|
| CLI | decision: the enforcement peer's own control tool is the authoritative status path, and sipnab is a passive observer that proxies it |
| TUI | `TfpsObserve` |
| REST | `/v1/tfps/status`, `/v1/tfps/banned` and `/v1/tfps/dropped` |
| MCP | `tfps_status`, `tfps_banned` and `tfps_dropped` |

### TFPS relay actions

Relay an operator's decision to condemn or release a source, and read the verdict labels.

| Surface | Detail |
|---|---|
| CLI | decision: banning and releasing are done through the peer's own control tool directly, and sipnab is passive |
| TUI | decision: a ban button would put an action verb on a passive observer surface, and enforcement stays in the peer |
| REST | `/v1/tfps/ban`, `/v1/tfps/unban` and `/v1/tfps/labels` |
| MCP | `tfps_ban`, `tfps_unban` and `tfps_labels` |

### Diff two SIP messages

Put two SIP messages side by side and highlight what differs.

| Surface | Detail |
|---|---|
| CLI | decision: a byte diff of two messages is a visual affordance, and a script diffs the two raw payloads itself |
| TUI | `MessageDiff` |
| REST | decision: a client composes two message fetches and diffs them, with no diff resource to poll |
| MCP | decision: an agent composes two message reads and reasons over the difference, with no dedicated diff tool |

### Edit the capture BPF filter

Narrow the live capture with a BPF expression, interactively.

| Surface | Detail |
|---|---|
| CLI | `--bpf-file` |
| TUI | `BpfFilter` |
| REST | decision: changing the capture filter re-scopes what every client sees, a control mutation the read-only REST surface does not expose |
| MCP | decision: re-scoping the live capture is an operator control, not an agent query over what is already captured |
