# MCP server design notes

This page records why the MCP server behaves as it does: the reason behind a
limit, refusal or response shape, the history of a change, and the internal
names that implement it. The operator pages under `docs/mcp*.md` say what to
run and what it returns. This page is for someone changing the code.

## Notes for [MCP server](../mcp.md)

### Input schema type unions and `--strict`

`schemars` renders an optional field as `"type": ["string","null"]`. That is
legal JSON Schema, and several clients cannot read it: they take `type` as a
single string and either drop the constraint or refuse the whole tool. sipnab
collapses those unions on input schemas, where a client validates arguments
before calling and a refusal costs the tool. Output schemas keep them,
because sipnab writes an explicit `null` for an absent optional field.
Collapsing there would advertise a schema its own responses violate.

No CI job runs the Inspector command, `--cli` with `--strict`, that the MCP server page shows.
`no_input_schema_advertises_a_spelling_a_strict_client_may_refuse` checks the
same property offline against the live wire, with no network and no package
manager. Run the Inspector command by hand when Inspector's rules change.

### Tool table completeness gate

`mcp_tool_table_lists_every_registered_tool` in [`tests/docs_drift_test.rs`](../../tests/docs_drift_test.rs)
fails the build when `docs/mcp-tools.md` stops naming every registered tool.

### Why `mcp` is not a default feature

The default build excludes `mcp` so an operator who never exposes the MCP
surface pays no binary size for it.

### Why sipnab refuses stdout-writing flags with `--mcp`

With stdio, stdout is the JSON-RPC wire. Allowing `--json` or `--report`
would corrupt the wire with report text and leave the client to fail later on
malformed JSON-RPC, so sipnab refuses the combination at startup.

## Notes for [MCP tool reference](../mcp-tools.md)

### Bundle size table and its byte-budget test

The "Bytes (default)" and "Bytes with output schemas" table in
`docs/mcp-tools.md#choosing-which-tools-load` is the compact JSON of each
tool's `tools/list` entry, summed per bundle, on a build with every feature.
The unit test `each_bundle_stays_within_its_byte_budget` in
[`src/mcp/server.rs`](../../src/mcp/server.rs) fails when a bundle grows past its recorded ceiling.
Update the table in the same change that moves a ceiling. The 0.5.221
measurement came after the `filter` parameters gained "Values may be bare or
quoted." The 0.5.222 figures are byte-identical.

Output schemas are off by default because MCP makes them optional and they
are more than half the bytes of `tools/list` (89,667 bytes without, 270,810
with, at 0.5.222).

### Why every capture-derived tool carries `source_exhausted`

A file source loads on a background thread, so an agent's first call lands
inside a window a human client never sees. Measured on 0.5.130: on a 921 MB
capture, `list_dialogs` answered with 6 of 18,241 dialogs. Before that change
only `tail_dialogs` and `capture_status` carried `source_exhausted`. Every
tool that answers from the capture now does, and sipnab omits
`truncated: false` until the answer is whole, because `false` claims the page
holds every match. `timeline` was the last tool returning a bare array. Its
answer became an object so it could carry the two booleans.

### Rules behind the `fields` projection

The MCP surface bounded rows three ways (`limit`, `--mcp-max-rows`, cursors)
and columns not at all, so a page fetched to read two values paid for every
other value on every row. `fields` closes that.

- `call_id` always survives because every follow-up tool takes a Call-ID. A
  row an agent cannot address is a row it can do nothing with.
- An unknown name fails rather than returning rows without the field, because
  a silently missing field reads as "no such data", a wrong answer rather than
  an error.
- The envelope (`total_matched`, `truncated`, `next_cursor`,
  `capture_identity`) is never projected: those fields are how a caller knows
  what it did not get.
- The projection runs on the serialized page, so `skip_serializing_if` still
  decides which fields exist. An absent field does not reappear as `null`.

### File-root symlink resolution and the overwrite guard

Bare-name checking alone does not hold the `--mcp-file-root` boundary: a
symlink already in the root is a single bare component, passes every name
check, and the kernel follows it on open. sipnab therefore compares the fully
resolved path against the fully resolved root. That escape needed prior write
access inside the root, so it was never a remote break. The fix shipped
because the reference describes the boundary as absolute.

The name checks and that resolution are one function, `confine_bare_name` in
[`src/capture/output_guard.rs`](../../src/capture/output_guard.rs), which the
REST compare route's `--api-file-root` applies too, so the two surfaces cannot
drift apart. It also refuses a control character: a NUL or a newline is one
bare component as well, and no file name a person picks needs one.

The tools that walk the root instead of taking a name, `list_captures` and
`find_in_captures`, list by `capture::archive::listed_files`, which keeps
regular files only and judges them by the directory entry's own type. That
type does not follow a link, so a link in the root is never opened, wherever
it points. A check that follows the link listed a capture outside the root
and let the sweep read it.

The overwrite refusal covers any name already taken in the root
(`resolve_in_root_for_write` in [`src/mcp/server.rs`](../../src/mcp/server.rs), using
`symlink_metadata` so a dangling link still counts as taken).
`protected_inputs` alone knew only the files the server opened, so a capture
staged in the root for `open_capture`, or an earlier export, could disappear
under a name collision on a call that reported success.

That check answers with a clear refusal, but it is not what holds the line:
a file or link can appear at the name between the check and the open. Every
MCP writer therefore opens with `crate::new_file::open_for_write` and
`CreateMode::NewOnly`, one `O_CREAT | O_EXCL` open that never truncates and
never follows a link at the name. `PcapWriter` carries the mode in its
options and keeps it for rotation. The command line and the TUI pass
`Replace`, because their path is one the operator chose. A unit test in that
module fails when production code under `src/mcp` creates or truncates a
file any other way.

### `security_findings.kinds` refusal

`security_findings.kinds` used to accept any string and match nothing, so a
name outside `scanner`, `fraud`, `digest`, `reg_flood` answered `[]`, the
same bytes a quiet capture returns. `reg-flood` (the `--alert` grammar's
spelling) was the case that caused it. The refusal now lists the vocabulary
and suggests `reg_flood` by name.

### Default of `--mcp-max-response-bytes`

The 1048576-byte default is under twice the largest response measured over
the sample captures in `tests/pcap-samples`: 561,420 bytes, `list_dialogs`
with `limit: 1000` on `sipp-branch-scenario.pcapng`. With the default, no
answer on those captures changes. The largest at the default `limit` was
52,809 bytes, a `get_dialog` page on `DTMFsipinfo.pcap`.

### Prompts hidden when a tool is not loaded

`prompts/list` omits a prompt whose tools are not all registered, rather than
serving it with a note, because a step naming a tool the client cannot call
fails with "tool not found" in the middle of the workflow.

## Notes for [MCP protocol](../mcp-protocol.md)

### Security model: the design reasons

- **No tool edits the analysis in place.** The rule is narrower than
  "read-only" on purpose. Ending a session is visible, and a swap mints a new
  `capture_identity` that every later answer carries. Rewriting the evidence
  underneath someone mid-incident is the failure both of those exist to make
  impossible.
- **Token comparison.** sipnab compares tokens in constant time via the shared
  `crypto::constant_time_eq` helper, through `auth::TokenVerifier`. This is the
  same code path as the REST API.
- **One challenge for every rejected credential.** Telling expired from revoked
  from forged in the `WWW-Authenticate` header would make the header an oracle.
  A request that presented nothing carries no error code, as [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html) section
  3.1 asks, which lets an operator tell a misconfigured client from a wrong
  token.
- **No `authorization_servers` in the [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728.html) document.** sipnab issues and
  validates no OAuth tokens. A client sent to fetch one elsewhere would return
  holding a credential this server rejects. The operator names the URL because
  behind a TLS-terminating proxy sipnab cannot see the scheme a client used,
  and [RFC 9728 section 3.3](https://www.rfc-editor.org/rfc/rfc9728.html#section-3.3) makes a client discard a document whose `resource`
  does not match the URL it requested.
- **Two caps, refused rather than queued.** `--mcp-max-concurrent` and
  `--mcp-rate-limit-per-peer` are different bounds. An agent that never exceeds
  the concurrency cap and loops as fast as sipnab answers holds a single slot
  forever, and only the rate limit stops it. A queue behind either cap is the
  same resource exhaustion, deferred. Over HTTP the peer is the address, not
  the socket, so reconnecting mints no fresh allowance. On a shared egress
  every client behind one address shares one allowance. That is the
  consequence of rate-limiting what the transport can prove rather than what
  the caller claims. The per-peer accounting is the same code that meters HEP
  senders for `--hep-rate-limit-per-peer`.
- **Privilege drop.** The MCP listener binds after
  `privilege::drop_privileges` (called from [`src/app/bootstrap.rs`](../../src/app/bootstrap.rs)). The default
  port 8731 is at or above 1024 to permit this.

### Audit record: the design reasons

- **The record includes refused calls.** An agent probing for tools that do not exist
  is exactly the traffic the record exists to show. The running
  `N refused since start` total on a rate-limit refusal separates one confused
  client from a flood.
- **`token=<id>`.** Two agents on one host present two tokens from one address,
  and the socket alone does not tell them apart. sipnab percent-encodes the id
  so an id carrying a space, a quote or a newline cannot forge a field or a
  line. It cuts an id over 64 characters and marks it `…(truncated)` (`CAP` in
  [`src/mcp/server.rs`](../../src/mcp/server.rs)) so a prefix never reads as a whole id.
- **Why a file as well as a log line.** The log line is a console view:
  `SIPNAB_LOG` filters it, `--quiet` suppresses it, and it interleaves with
  everything else. Those are the right properties for something a person
  watches and the wrong ones for something produced later: whoever asks "what did the agent
  look at" after the fact did not choose the log level.
- **JSON lines.** Same shape as `--alert-json`, for the same reason:
  `serde_json` escapes every value, so a crafted header reaching the record
  through `args` cannot end the line or forge a field. `args` is a bounded
  string byte-identical to the log line, including where the bound fell, so
  the two can never disagree. `error` is always present so a reader never has
  to tell `.error` apart from an absent key. `seq` exists because nothing else
  makes a missing record detectable.
- **Write path ([`src/mcp/audit.rs`](../../src/mcp/audit.rs)).** Opened `O_APPEND`, created `0600` when
  absent (the record carries tool arguments). One `write_all` per record with
  the newline attached, under a mutex, to an unbuffered file, so concurrent
  calls interleave whole records.
- **No `fsync`.** An `fsync` per tool call would buy machine-crash durability
  for a record whose realistic threat is a process that stopped. A record on
  disk survives panic, signal and `shutdown_server`, not a power loss before
  the page cache flushes.
- **Refuse what the file cannot hold.** No result leaves the server that is not
  in the file, so an operator who finds no record can conclude the call did not
  happen, rather than that writing the record failed.
- **Known gap.** Nothing outside `tools/call` reaches the audit point:
  `resources/*`, `completion/complete`, subscribe/unsubscribe and the prompt
  methods. The tracing record has the same gap.

### Resources, live views and completions: design reasons

- **Why file resources exist.** `export_capture` returns a server-local
  absolute path. That works over stdio and does nothing over HTTP, where the
  client has no access to the server's filesystem: the tool reports success
  and the agent still cannot obtain the bytes. The protocol makes a resource
  read-only by construction, and a host can grant resource reads without
  granting tool calls, which no tool annotation can express.
- **One sandbox.** The resource URI goes through the same single-component
  check and symlink resolution as the file tools, so there is one sandbox, not
  two that can drift apart.
- **8 MiB per read** (`MAX_RESOURCE_BYTES` in [`src/mcp/server.rs`](../../src/mcp/server.rs)). JSON-RPC
  carrying base64 is not a bulk transfer channel: a 128 MB capture becomes
  roughly 170 MB of one JSON string. Non-UTF-8 files come back as base64
  because a lossy conversion would hand the model something the file does not
  contain.
- **One renderer.** The live views render through the same code path as
  `list_dialogs`, so an operator never holds two versions of the same capture
  with no way to decide which to believe. The same function builds
  `sipnab://lint/<rule-id>` and `explain_rule`, and `sipnab://filter/<alias>` uses the
  same `expand_alias` that `find_problems` compiles.
- **Unknown Call-ID is an empty page.** A live view's content is what the
  capture holds right now, and "right now, nothing" is an answer. A subscriber
  watching a call that has not started, or that the store evicted, needs the
  URI to have defined content on both sides of the change.
- **Completions are not cached.** A completion that offered an evicted Call-ID
  would cost an agent a call to discover, and the agent would conclude the
  capture was wrong rather than the completion.
- **Hidden file template.** A template promises the URI resolves. Advertising
  one whose every URI would draw a refusal tells an agent captures are
  reachable, and it finds out otherwise one call at a time. The same reasoning
  hides the vCon template in a build without `vcon`.
- **Unknown completion argument.** The empty answer is the specification's rule.
  Answering an unknown argument name with another argument's vocabulary would
  make a client fill that argument with it.
- **Completion ceiling.** 100 values (`MAX_VALUES` in
  [`src/mcp/completion.rs`](../../src/mcp/completion.rs)), lowered by `--mcp-max-rows`. A completion reaches
  the store without the audit line, scope check or rate limit `tools/call`
  applies, and a Call-ID is the most identifying row sipnab holds, so one
  ceiling serves both doors.

### Design reasons for subscriptions

- **Only live views.** A reference page cannot change during the run, and a
  file under `--mcp-file-root` changes only when something outside sipnab
  writes it. sipnab is a packet analyzer, not a filesystem watcher. Accepting
  either would be a subscription that can never fire, which a client cannot
  tell from a quiet network.
- **Change detection.** First the dialog store's revision counter (an unchanged
  counter proves unchanged content and costs one `u64` read), then a digest of
  the rendered content. RTP moves the stream store, so audio never wakes a
  dialog-list subscriber. A revision bump that leaves the rendering identical
  sends nothing.
- **One-second debounce** (`DEBOUNCE` in [`src/mcp/subscribe.rs`](../../src/mcp/subscribe.rs)). The
  notification carries no data. Its whole value is one `resources/read` round
  trip through a model on the client side. A shorter interval would send the
  second notification before the client could act on the first. A capture
  doing hundreds of calls a second mutates the store thousands of times a
  second, so one notification per mutation would be a denial of service.
- **Per-connection state.** `MAX_SUBSCRIPTIONS` = 16. There is no registry that
  outlives a connection. A watcher holds a weak handle, so a client that
  disappears without unsubscribing takes its watchers with it and nothing has
  to notice the disconnect.

### Write verbs and confirmation: design reasons

- **Annotation gate.** A test walks the registered router and fails if any
  tool carries no `readOnlyHint`, or if the set of non-read-only tools stops
  matching the write-verb table in docs/mcp-protocol.md
  ([`tests/docs_drift_test.rs`](../../tests/docs_drift_test.rs) also pins the counts in that page).
- **`compare_captures` is not read-only.** It changes no state a later answer
  depends on, but reading through the shared pipeline bumps the process-wide
  undecodable tallies `get_capture_report` reports, and a tool whose effects
  stay invisible in its own answer should not call itself read-only.
- **`build_evidence_package` refuses an existing name** so a second call fails
  instead of replacing evidence someone may already have sent.
- **Why elicitation.** Before it, a convention guarded `shutdown_server` and
  `open_capture`: `dry_run` defaulted to the safe value, so stopping took a
  deliberate second call. That has a structural hole: the second call comes
  from the same agent on the same reasoning. It rate-limits an accident. It
  does not introduce a second party.
- **A dry run asks nobody.** A confirmation with no consequence behind it
  teaches whoever reads it to click through the next one.
- **No capability is not a refusal.** Elicitation is a client capability.
  Reading "nobody to ask" as "they said no" would make `shutdown_server`
  impossible on every stock client.
- **`open_capture` checks before and after asking.** It settles its three
  refusals (live source, load in flight, source not drained) before it asks,
  and again inside the lock that performs the swap. Asking first and refusing
  afterwards would put the question on a false premise.

### Untrusted capture text: design reasons

- **Identifiers verbatim.** Wrapping a Call-ID, cursor or address turns a
  working round trip into a lookup miss. The provenance note says they are
  attacker-chosen too, so the omission does not look accidental.
- **`get_dialog` history.** It used to fence its `dialog` summary while its
  `messages[]` array, the largest block of sender-written text on the surface,
  carried no markers and no note explained the absence. It now fences both
  halves message by message, with the field/body split `get_message` uses.
- **Reports carry a note, not markers.** Fencing a mixed document would tell
  the agent to distrust sipnab's own analysis too.
- **Fence code points.** U+27E6 and U+27E7 carry no meaning in SIP, which makes
  rewriting them to ASCII `[` `]` before wrapping affordable.
- **Bidi controls** (`BIDI_CONTROLS` in [`src/mcp/shape.rs`](../../src/mcp/shape.rs)) are Unicode category
  `Cf`, not `Cc`, so a control-only strip misses them. They are the "Trojan
  Source" shape aimed at an audit transcript.
- **Bodies keep `\n` and `\t`.** An agent diagnosing one-way audio reads `a=`
  lines. Destroying that to harden a boundary that already holds is the wrong
  trade. A field is single-line by construction after [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261.html) unfolding.
- **256-byte field cap** (`MAX_FIELD_BYTES` in [`src/mcp/shape.rs`](../../src/mcp/shape.rs)). No RFC
  bounds a display name or `User-Agent`, so uncapped, one header is as much room
  to write instructions as the sender cares to spend, in a context window the
  operator pays for. 256 clears every honest value: the longest `User-Agent` in
  sipnab's fixtures is 49 bytes, browser UAs reach about 150. It is about three
  lines of prose.
- **The operator page documents the residue** because a defense described as
  total is one nobody checks. Diagnosis `hints` that interpolate a `Reason` header are not fenced.
- **Note is the last content block.** The markers are inline, so placing the
  note after the data costs nothing; putting it first would have broken every
  client that indexes block 0.

### Result envelope and stdio: design reasons

- **sipnab attaches `structuredContent` centrally**, on the way out of every
  tool call, not per tool: fifty-odd tools build results in fifty-odd places,
  and a per-tool helper is a rule the next author has to remember. sipnab
  parses it from the text block rather than serializing a second time, so
  there is no second serialization to drift.
- **No `structuredContent` for rendered documents.** MCP types the field as an
  object. Wrapping a document in an invented key would put a shape in
  `structuredContent` that the text block does not have.
- **stdio.** All logging goes through `tracing-subscriber` to stderr (Phase
  8.0b). [`tests/parse_path_test.rs`](../../tests/parse_path_test.rs) verifies no log line leaks to stdout.

## Notes for [MCP deployment](../mcp-deploy.md)

### MCP HTTP transport: details a client has to handle

Running a client against the HTTP transport, not reading the specification,
surfaced three details, each of which fails with an error that does not name
its cause:

- The reply is `text/event-stream` even for a single response, with an empty
  `data:` keepalive as its first frame.
- `Accept` must offer both `application/json` and `text/event-stream`. The
  server answers 406 otherwise, before any tool runs.
- The client must echo the `mcp-session-id` from `initialize` on every later
  request. The server answers 422 `Unexpected message, expect initialize
  request` otherwise.

sipnab 0.5.87 answered a `tools/list` sent before
`notifications/initialized`, and 0.5.222 still does. The protocol does not promise this, so the
user documentation tells clients to send the notification first.

### MCP: why every rejected credential gets the same challenge

sipnab rejects a bearer token that has expired, that the operator revoked,
that someone forged, or that the operator minted for the REST API instead of
MCP. The `WWW-Authenticate` challenge is identical for all
four. An attacker receives the challenge without authenticating, so a
challenge that distinguished the four would answer "is this token id known?"
for anyone who asked.

### MCP: why `--mcp-resource-url` is not derived from the request

sipnab does not read `X-Forwarded-Proto` when publishing the RFC 9728
protected-resource metadata, for the same reason it ignores
`X-Forwarded-For` when rate limiting: a header the client sets is not
evidence. Behind a TLS-terminating proxy sipnab sees a cleartext request, so a
URL derived from its own socket would say `http://` for a resource the client
reached over `https://`, and [RFC 9728 section 3.3](https://www.rfc-editor.org/rfc/rfc9728.html#section-3.3) makes a conformant client
discard such a document. The operator names the URL. A malformed value is a
startup error rather than a wrong document.

### MCP: sipnab parses `structuredContent` from the text block

Each tool result carries its payload twice: serialized in
`result.content[0].text` and as JSON in `result.structuredContent`. sipnab
builds `structuredContent` by parsing the text block rather than serializing
the payload a second time, so the two views cannot disagree.

### MCP: why `--mcp-allow-tls-capture` is separate from `--mcp-allow-open-capture`

`start_tls_capture` installs uprobes on a running process's TLS library and
reads plaintext from sessions belonging to processes the agent does not own.
Reading a file an operator placed in a directory (`open_capture`) and
attaching probes to a live daemon are different acts, so each has its own
opt-in.

### MCP: why `shutdown_server` takes two calls and may also elicit

The first `shutdown_server` call is always a dry run, and stopping a live
capture with unsaved packets also needs `save_to` or `discard_unsaved: true`.
An agent can misread "we can stop looking at this now" as an instruction, and
should not be able to end hours of capture on that reading. When the client
declares the `elicitation` capability, the second call also asks a person.
The two guards stack because the same agent that made the first call makes
the deliberate second call.

### MCP: shared TLS handshake limits

The MCP HTTP listener's TLS handshake limits (each handshake on its own task,
10 seconds each, at most 256 at once) come from the same code as the REST
API's TLS listener.

### MCP: feature cost

The `mcp` feature pulls in the `rmcp` dependency. The user documentation
described its binary cost as about 3 MB. Nobody re-measured that figure when
it moved here. `mcp-http` enables `mcp`, `api` and
`rmcp/transport-streamable-http-server`.

## Notes for [Run MCP across an estate](../mcp-estate.md)

### Federated tracing: provenance of the estate transcripts

The tunnel, NAT and `ProxyJump` commands in docs/mcp-estate.md were not run
against three real hosts, because one machine was available. The measured
behavior used three (and, for the proxy-mode case, four) sipnab servers on one
host, each with its own `--node-name` and capture, driven by
[`contrib/mcp/trace-call.py`](../../contrib/mcp/trace-call.py). The transcripts were first taken on 0.5.97 and
re-run on 0.5.222 (7f9ffaa7) on 2026-10-16.

`max_error_us` is a live reading. On the original host it reported 0.295 s,
1.944 s and 2.38 s on different runs, all with `synchronized=True`. The
2026-10-16 re-run reported 0.7245 s. The last of the earlier readings exceeded the 2 s
correlation window, at which point the clock alone could account for a
`timing_heuristic` match.

### Federated tracing: why sipnab omits `timing_clock` on identifier matches

A clock reading beside an identifier match invites weighing one against the
other, and they do not trade off. sipnab omits `timing_clock` rather than send a
healthy-looking default. The loop evaluates strategies in descending score and
stops at the first match per leg. It then sorts the legs by score.

### Federated tracing: why sipnab does not compute a cross-node identifier

A computed "same id on both nodes" would have to come from what each node
sees independently. Across a re-originating B2BUA, Call-ID, From tag, Via
branch, Contact and usually the SDP are all new on the far side, which is what
re-origination means. Any id derived from the remainder is a heuristic that
would arrive looking like proof and correlate two unrelated calls with no field
left to catch it, while `timing_heuristic` announces itself as a guess. The same
judgement records the [RFC 7329](https://www.rfc-editor.org/rfc/rfc7329.html) legacy `Session-ID` form as an interop notice
rather than a violation, because a single message cannot distinguish a legacy
implementation from a broken one.

`Session-ID` correlation ([`src/sip/session_id.rs`](../../src/sip/session_id.rs)) intersects the non-nil halves
rather than comparing strings, because the halves swap direction across a B2BUA
and string equality would find nothing.

## Notes for [core bundle](../mcp-tools-core.md)

### Why `capture_status` reports AMI cleartext logins

`capture_status` reported `unanalysed_sip_messages: 0` on a capture full of
Asterisk Manager Interface traffic, and the zero was correct: AMI is not SIP,
so there was no unparsed SIP message to count. Every detector ran on parsed SIP
messages, and this traffic never became one. `capture_status` gained the
`ami_cleartext` list because that is where the misleading zero appeared.

- The check costs two literal prefix tests on payloads that already failed the
  SIP check, so it is not gated behind a flag.
- The sighting key is `(src, dst, dst_port, observation kind)`. The username
  is outside the key because this path runs before authentication, so the field
  is attacker-chosen and keying on it would let a sender grow the map without
  limit. As a consequence `findings_from` rebuilds each observation with
  `username: None`, so `capture_status` never carries a username although
  `observe` reads one (bounded by `MAX_AMI_VALUE_CHARS`, 64).
- sipnab reports the port rather than requiring it (`AMI_DEFAULT_PORT`), because a
  deployment that moved AMI off 5038 is the one most likely to assume nobody
  can find it.
- The field is always present: sipnab runs this check on every capture, so `[]`
  means "looked, found none", unlike optional blocks that sipnab omits when a
  check never ran.

### `caveats.media_creating_commands`: why sipnab counts relay forks instead of attributing them

rtpengine `subscribe`, `publish` and `start recording` create media belonging to
a call without being one of its two legs. Decoding one as an ordinary leg would
make a two-party call report three streams, after which the one-way-audio and
asymmetry analysis answers the wrong question. sipnab counts them instead.

### `caveats.tls.read_nothing`: why the counts are not the verdict

A TLS handshake carries records sipnab never loads keys for, so
`app_data_records > decrypted_records` is not a failure by itself. An agent that
derived a verdict from the two counts reported working captures as broken and
sent operators after keys that already worked. `read_nothing` exists because a
capture of ciphertext nobody can open produces a dialog listing identical to a
quiet network's.

### `get_capture_report`: history of `complete` and the default format

- `get_dialog_report` and `render_ladder` answer for one Call-ID, so before this
  tool the capture-wide findings (orphaned media, STUN, ICMP quoting SIP or RTP,
  what retention caps shed) had no MCP path. `analysis::analyze` backs the tool
  and `output::analysis_report` renders it.
- `frames_read` reads the same process-global counter the Prometheus scrape
  reports (`sipnab_capture_packets_total`), so it is the denominator every other
  number in the run measures against.
- sipnab counts `evidence_omitted` while accumulating, not by subtraction: one
  evidence row often stands for many occurrences, and the subtraction reported
  omissions that never existed.
- Before the load gate, `complete` ignored an `open_capture` load and read
  backwards during one. On a 100 MB capture the same tool in the same session
  answered `complete: true` at `frames_read: 312` and `complete: false` at
  `frames_read: 365747`. `source_exhausted` and `source_stopped_early` now gate
  it and travel beside it.
- The rendered formats append an `INCOMPLETE RUN` block for the same reason
  `--report` does: the reader of a rendered report has no exit status and no
  JSON, and a partial report looks like a whole one.
- Before 0.5.125 the default returned the text rendering. `format` chose between
  markdown and text inside the renderer, which had no JSON arm, so a call with no
  argument received prose and nothing said the requested structure was absent.

### `list_dialogs`: reasons for the page object and the compound cursor

A bare array hides its size. The tool once returned 50 of 2311 dialogs on a
production capture with nothing marking the cut, and `limit` alone could not
close the gap because requests above 1000 clamped to the cap, leaving 1311
dialogs unreachable. An agent asked "how many calls failed?" counts the rows it
holds, so a short list reads as a confident wrong answer. `total_matched` and
`truncated` name the shortfall, and `cursor` closes it.

The cursor pairs `created_at` with the Call-ID because dialogs routinely share
a timestamp (a burst of registrations lands on one millisecond), and a bare
timestamp forces a choice between dropping the rest of that group and serving
it twice. `list_dialogs` pages on `created_at` because it never moves: in an
`updated_at` ordering, a dialog that gained a message mid-sweep would jump past
a cursor already gone by and vanish. `tail_dialogs` pages on `updated_at`
because reporting change is its job.

`sipp-branch-scenario.pcapng` is the example fixture because its `by_method`
shows all 1334 dialogs are REGISTER, which the two rows on the page cannot.

### `aggregate_dialogs`: why it exists and why it has one dimension

Counting is the operation a language model gets wrong most reliably: an agent
asked "how many calls failed?" counts the rows it holds. The page object fixed
one count (`total_matched`, for one filter). Every other count still meant
fetching pages and tallying them in the model, or issuing N filtered queries
with buckets guessed in advance.

- Buckets plus `other_count` always equal `total_matched`, because a truncated
  aggregate that does not say what it left out is a wrong total. Nulls become
  `(none)`.
- One dimension and no time bucketing is a deliberate cap: two dimensions is a
  pivot table, a pivot table wants a UI, and docs/design/positioning.md puts
  that outside sipnab.
- sipnab fences sender-written dimensions and not its own derivations,
  because fencing those would tell the agent to distrust the analysis. It
  fences the codec name (`rtp.codec`) because it comes from the SDP.

### `find_problems`: the OPTIONS keepalive observation

On one real capture 98 of 110 `find_problems` rows carried OPTIONS, and 89 of
those matched an alias solely on `retransmits > 3`: dead qualify peers, not call
faults. Without `by_method` an agent had to already suspect the keepalive plane
to exclude it. Before `filter` was ANDed with the aliases, restricting problems
to one's own traffic needed a client-side join.

### `search_messages` and `get_dialog`: zero-padded message index in cursors

The server compares cursors as text, so the message index is zero-padded. A
hand-built `#10` sorts before `#2` and silently skips eight messages.

### `get_dialog`: documentation and shape history

- Through 0.5.211 `get_dialog` carried no `schema_version`, took an integer
  `cursor` and returned an integer `next_cursor`, and had no `returned`,
  `first_index`, `truncated` or `truncated_by`. Schema version 2 made the cursor
  the opaque string every other paged tool uses. An integer cursor now fails
  deserialization (`invalid type: integer`, a tool error).
- Until 0.5.134 the reference said `get_dialog` returned message fields verbatim
  and pointed readers to `get_message`. Both tools fenced the whole time.

### `triage_call`: how sipnab selects the termination cause

sipnab reads the last message naming a cause because a call that went through
a challenge, a retry and a clear carries several, and the last says why it
ended. `Reason` on BYE or CANCEL counts, which is the case the block exists for:
a normally cleared call has no failure response to carry a cause. When one
message carries both protocols, the non-SIP cause wins because a SIP cause
restates `final_status_code`. sipnab cuts `cause_text` at `MAX_CAUSE_TEXT_CHARS`
(200), past every value a gateway produces and short enough that a crafted
header cannot spend a context window. The block comes from one assembler shared
with `get_dialog_report` and the REST report route.

### `rtp_stats`: interval scoring, placeholders and orphans

- Per-interval MOS exists because a whole-call mean hides a burst shorter than
  itself: one 90 % loss figure the project had to explain turned out to be three
  bursts of half a second. sipnab scores each interval on its own jitter and
  loss and on the stream's resolved path delay, so the trend and the headline share one
  basis.
- `estimate_mos` returns the same number (4.216 at 10 ms jitter) for AMR,
  AMR-WB, EVS, G.722 and an unidentified codec, because sipnab implements G.113
  impairment values only for G.711, G.729 and Opus. For AMR-WB the placeholder is
  wrong by about a full MOS point in either direction (its nine modes span about
  4.49 to 3.51).
- A MOS bound skips ungrounded streams because a bound on a placeholder goes
  wrong both ways: a healthy AMR-WB stream never appears under `max_mos`, and a
  degraded one appears on a figure that never described it. On
  `codec-negotiation.pcap` the two G722 streams score 4.22 from the placeholder
  arm and would otherwise fall under a 4.5 bound.
- sipnab computes `orphaned` per response as `associated_dialog.is_none()`, so the
  two fields cannot disagree and a stream reports it from its first packet.
- The `orphaned` filter is independent of the MOS bounds because an orphan
  usually has no dialog to ground its clock, so requiring a bound alongside
  would filter out most of what the filter exists to find.
- The sweep replaces a listing plus one `rtp_stats` per dialog, which costs
  thousands of round trips on a real capture.

## Notes for [signaling bundle](../mcp-tools-signaling.md)

### Why `timeline` returns an object and keeps empty buckets

`aggregate_dialogs` is blind to when dialogs occurred, and bucketing a page of
dialogs inside the model is the counting task language models get wrong most
reliably, so `timeline` counts in the store. Its answer is an object rather
than a bare array because a bare array has no key to carry `source_exhausted`:
a series drawn while the capture was still loading looked exactly like one
drawn over the whole file. Buckets align to the epoch rather than to the first
dialog, so two captures of the same window produce identical boundaries.
Aligning to the earliest call would shift every boundary whenever that call
changed. The series keeps empty buckets because a gap is a finding, and a series that
drops it renders as continuous traffic on a shorter axis.

Keeping every empty bucket needs a ceiling, because the instants come from the
capture: two forged timestamps decades apart would be tens of millions of rows.
Every surface refuses a span of more than `MAX_TIMELINE_BUCKETS` (100,000)
intervals and names a width that fits. None truncates it, because a truncated
series ends early and reads as traffic that stopped.

### `group_dialogs` design decisions

A rate is the one thing a language model cannot recover from a page of rows:
it would have to hold every dialog, classify each outcome and divide. Agents
stop early and answer from the rows they hold, which is how a truncated page
becomes a confident verdict about a carrier, so the tool computes the rate in
the store and reports the population beside it.

- A `null` metric with `not_grounded` rather than `0`: an ASR of 0 for a group
  of REGISTER dialogs would name a working registrar a dead trunk. This is the
  discipline `mos_grounded` applies to a MOS on an unpublished codec, extended
  to the other seven metrics.
- `units` travels with the numbers because an ASR of `0.65` and of `65`
  differ by a factor of a hundred. Before 0.5.130 `group_dialogs` and
  `evaluate_expectations` disagreed (one percent, one ratio), so a threshold
  copied between them was wrong by a hundredfold in the direction that always
  passes.
- A seizure excludes an INVITE still ringing at the end of the capture:
  counting it as failed reports a live capture as an outage that looks worse
  the earlier you look.
- `408 Request Timeout` does not count as delivered: a proxy emits it both for
  a silent phone and for an unreachable next hop, so crediting it would credit
  the network for calls that may never have arrived.
- ACD averages conversation time, not dialog span: averaging the span bills
  the caller for ring-back.
- Percentiles use nearest rank because an interpolated p95 is a number no call
  experienced, and these figures get quoted to carriers as evidence. Two
  decimal places because a ratio over three dialogs is not accurate to
  fourteen.
- Groups rank by count, not by metric: ranking by the metric would answer a
  different question per call and could not page against `other_count`.
  `other_count` carries no metrics because an ASR averaged over the groups
  that fell off the end is an average of averages across the smallest groups.
- The `by` vocabulary is a strict superset of `aggregate_dialogs`' so an agent
  never has to discover per tool which vocabulary it is using. One dimension
  only: two is a pivot table, and a pivot table wants a UI
  (docs/design/positioning.md).
- `next_hop`, state, codes, addresses and codecs come back unfenced because
  they are sipnab's own derivation. Telling an agent to distrust them would
  tell it to distrust the analysis.

### `search_by_time`, `validate_filter`, `tail_dialogs` and `await_condition` rationale

- `search_by_time` gained a cursor because without one the only way past a
  truncated window was to narrow it, which put every row past the row ceiling
  out of reach.
- `validate_filter` exists because every other way of trying an expression
  cost a page of fenced summaries per attempt. It returns a parse failure as a
  successful call because `invalid_params` lands in the error channel, where a
  model acts on it least. `total_matched` is `null` on a parse failure because
  a zero reads as "parsed, matched nothing". It calls the same compiler as the
  other tools. A second parser would eventually accept an expression
  `list_dialogs` rejects.
- `tail_dialogs` has no `returned` or `total_matched` because "how many are
  there" is not a question a tail can answer while the store changes. The
  compound cursor exists because dialogs share `updated_at`. A bare timestamp
  falls back to the pre-compound strictly after filter, which the tool still
  accepts, so a client that rebuilds one loses or repeats tied dialogs
  silently.
- `await_condition` returns a passed deadline as a successful call because
  "the fault has not reproduced" and "the tool broke" are different findings.
  Constants: `DEFAULT_TIMEOUT_SECONDS` (30), `DEFAULT_MCP_MAX_WAIT_SECONDS`
  (60, read as `DEFAULT_MAX_WAIT_SECONDS`), `DEFAULT_POLL_INTERVAL_MS` (500),
  `MIN_POLL_INTERVAL_MS` (100, so no caller can make a spin loop). `scans` can
  be lower than `polls` because both stores number their revisions, so a look
  at an unchanged capture compares two integers. Nothing the call allocates
  outlives it: no subscription registry, no per-client filter, no background
  task. The deadline is what ends the server's obligation, and a waiting call
  holds a `--mcp-max-concurrent` slot while producing nothing.

### Correlation tools: `find_correlated` and `get_call_tree`

- No cursor on `find_correlated`: the design treats a call with more than 1000
  correlated legs as a capture problem rather than a paging one.
- `charging_vector_icid` matching across a B2BUA means some intermediary copied
  a per-dialog identifier onto a second dialog, which no RFC grants. The tool
  does not return the matched ICID because [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315.html)'s suggested construction
  embeds the generating proxy's hostname or address, making it
  operator-internal rather than opaque.
- `heuristic_only` exists because a call tree built only from timing is a
  hypothesis, and an agent that cannot tell presents it as a finding.
- `get_call_tree` exists because the TUI stitched B2BUA legs together (the
  `x` key) and nothing on the MCP surface reached it. An agent had to call
  `find_correlated` on each result and assemble the graph. The walk does not
  expand `timing_heuristic` edges transitively: on a proxy carrying ten calls
  a second every dialog sits within a guess of every other, so a transitive
  expansion would return the capture, not a call tree. A queued leg cut off by
  `limit` reports `followed: false` because claiming the walk searched its
  subtree would describe work nobody did. An unknown `call_id` fails rather than
  returning an empty tree because "no other legs" and "no such Call-ID" are
  different facts.

### Per-call report, message and ladder tools

- `output::generate_call_report` backs `get_dialog_report`, the same function
  `--call-report` uses. `from` and `to` arrive unfenced because a
  rendered report interleaves sipnab's diagnosis with sender-written header
  values, and fencing the whole document would tell an agent to distrust the
  analysis as well. The provenance note carries the warning instead.
- `get_message.extension_headers` closed a projection gap, not a parsing one:
  the parser always retained vendor headers, and before the field existed the
  only route to them was `decode_evidence` (file-root opt-in, reachable
  original capture, one call per frame). Fencing the name as well as the value
  widens the prompt-injection surface the threat model already tracks rather
  than adding a new one: the same bytes were reachable through
  `search_messages`. The field has no ceiling of its own because the parser's
  200-header and 8 KiB-line limits already bound it.
- `render_ladder` output is byte-identical to `--call-report` with
  `--no-cli-print`. The `INCOMPLETE RUN` block goes after the ladder so no
  line of the drawing moves.
- `check_codec_negotiation` keeps `no_answer` and `no_sdp_in_capture` apart
  because reporting the first for the second sends the reader hunting a reply
  that nothing ever called for.

### Conformance tools: `lint_dialog`, `validate_message`, `explain_rule`

- The observation rules are the reason `lint_dialog` exists: sipnab holds the
  signaling and the RTP in one process, so it can compare declaration against
  observation, which a linter reading message text cannot.
- `rfc` and `section` are separate fields so an agent quotes the section from
  the data instead of inventing a plausible one.
- `rules_not_evaluated` exists because a rule that found nothing and a rule
  that never ran leave the same empty list. No MCP tool raises
  `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` because the stream store folds an RTCP report into
  the stream it describes and keeps no record of where it landed.
- `.sipnablint` discovery stops at the project root, and a capture outside any
  project adopts nothing from above, because inheriting a stranger's
  suppression list would switch off rules nobody here turned off.
- `suppressions` and `findings_withheld` appear on every call, zeros included,
  because a missing field and a zero must not be the same bytes. The response
  names the file because "4 findings suppressed" gives nothing to act on when
  discovery walked up several directories. Suppression does not
  short-circuit a rule, which is why `suppressed` and `below_severity` are
  exact while `capped` is a lower bound.
- `explain_rule` lists all 41 identifiers on an unknown one because an empty
  answer would read as "that rule found nothing".

### `generate_repro` and `generate_wireshark_filter` rationale

- `generate_repro` takes the hypothesis as input because a scenario that
  "reproduces" for unrelated reasons is worse than no scenario. Only `branch`,
  `call_id` and `tags` can vary because varying needs a generator, and SIPp has
  none for SDP or User-Agent. An aspect in both `pin` and `vary` fails because
  a scenario that silently picked one would encode a theory nobody stated.
  Identity fields vary by default because replaying a captured Call-ID, tag
  and branch at a proxy is, to its transaction layer, a retransmission of a
  call it already answered. A pinned body brings its `Content-Type` because
  the aspect pins bytes and the label must describe them. sipnab strips control
  characters rather than escaping them because a SIP header has no escape for
  them, and a CR or LF would start a new header in an artifact the operator
  runs against their own proxy.
- `generate_wireshark_filter` exists to hand off to the escalation engineer's
  tool. A Call-ID with a control character fails because the display-filter
  grammar escapes only `\` and `"`, and a filter that quietly selects the
  wrong packets is worse than no filter.

## Notes for [media bundle](../mcp-tools-media.md)

### Why `reconcile_orphans` does not use the `Unattributed` vocabulary

sipnab reports a `never-named` verdict with `relay_was_consulted: false` as
"nobody asked", not with the `Unattributed` vocabulary. That vocabulary answers
"sipnab asked the relay and it said X". The MCP server holds no live
reconciler, so reporting an answer nobody received would be the failure that
vocabulary exists to prevent. The `relay_control` retry counts exist because a
control channel that loses answers shows on the SIP side only as a proxy that
is sometimes slow.

### Why `media_diagnostics` returns `applicable: false` instead of an empty `streams` array

An empty `streams` array would read as "sipnab checked the media and it was
fine", a different claim from "no media reached the capture point". The
response therefore carries `applicable: false` and a `reason`.

`endpoint_reported` stays apart from sipnab's own measurements on purpose.
Nothing authenticates RTCP, and a report describes the path from the sender to the
reporter, which on a mid-path capture is a different segment from the one
sipnab watches. The two disagreeing is normal and informative. Merging them
would destroy that signal, so nothing under the key feeds the MOS.

sipnab emits `qos.remarked_to` only on a change so that its presence is the
finding.

### Why `explain_attribution` reads authentication from the run configuration

The authentication answer comes from the run's configuration rather than a
per-packet record. That is sound because ingest rejects any datagram that fails
authentication, so everything still in the store arrived under the configured
posture. With no posture configured the tool reports the weakest reading: a
tool whose job is to say what a claim is worth must not round up in the
absence of information.

### Why `export_audio` requires `--retain-audio`

Call audio is content, not signaling, so holding it in memory is an operator
decision rather than a side effect of enabling MCP.

## Notes for [captures bundle](../mcp-tools-captures.md)

### Capture-file MCP tools: design notes

- `list_captures` reports neither a dialog count nor a last-packet time,
  because both need the whole file parsed, and a listing that costs a full
  read of every capture in the root is a listing nobody runs.
  sipnab reads `first_packet` from the first record only, so it is cheap.
- `find_in_captures` exists because the only other way inside another file
  was `open_capture`, which is destructive: it replaces every dialog and
  stream and mints a new `capture_identity` that voids every cursor an agent
  holds. A sweep reads each file into a scratch store instead.
- Sweep job bounds. Each running sweep is one OS thread with its own scratch
  dialog and stream stores, so `--mcp-sweep-max-running` (default
  `DEFAULT_MCP_SWEEP_MAX_RUNNING` = 4, maximum `MAX_MCP_SWEEP_MAX_RUNNING` =
  64, sixteen times the default) caps threads and stores. A held result keeps
  one entry per matched file and one per unreadable file, so held memory is
  `--mcp-sweep-max-held-results` times the largest result; its maximum
  (`MAX_MCP_SWEEP_MAX_HELD_RESULTS` = 256, default 16) is four held results
  per running sweep at the running maximum, the ratio the defaults carry.
  `--mcp-sweep-result-retention-secs` (default 600, maximum
  `MAX_MCP_SWEEP_RESULT_RETENTION_SECS` = 43200) matches the
  `--mcp-sweep-deadline-ms` maximum: a finished result waits at most as long
  as the longest sweep may run.
- Sweep ceilings. `DEFAULT_MCP_SWEEP_MAX_FILES` (20) and
  `DEFAULT_MCP_SWEEP_DEADLINE_MS` (30000), which `find_in_captures` reads as
  `DEFAULT_MAX_FILES` and `DEFAULT_DEADLINE_MS`. `MAX_MCP_SWEEP_MAX_FILES`
  (4294967295) is the largest value of the per-call `max_files`, a u32.
  `MAX_MCP_SWEEP_DEADLINE_MS` (43200000, twelve hours) bounds how long one
  sweep may keep a thread and a disk busy, since a sweep is a background job
  holding no MCP slot. sipnab cuts an unreadable file's reason to
  `MAX_REASON_CHARS` (200). `unreadable` never skips a file silently, because
  the file nobody could look in is the one that might hold the call.
- Two bounds, not one: `max_files` makes cost predictable, but a file's cost
  is its size, which the caller cannot see, so `deadline_ms` is the bound that
  matters.
- `compare_captures` diffs aggregates rather than dialog lists because two
  captures never share a Call-ID. Buckets rank by absolute movement because
  the largest bucket is usually the one that changed least. A value absent
  from one side counts as zero because a code appearing only in `b` is the
  finding. The read runs on a blocking thread because two whole captures
  inside a tool handler would otherwise hold the single runtime thread the MCP
  server and the REST API share. It is `readOnlyHint: false` because reading
  through the shared pipeline bumps the process-wide undecodable-frame tallies
  and the ICMP evidence store (the same behavior `open_capture` has). The
  vocabulary check runs before either file opens because reading two captures
  is the most expensive thing the surface does. A side with no dialogs and a
  read error fails with `internal_error`, because every bucket would appear to
  collapse to zero. sipnab counts `dialogs_dropped` against
  `Cli::DEFAULT_DIALOG_LIMIT` (100000), not the operator's `--limit`.
- `show_evidence` returns a digest mismatch as `unresolvable` rather than a
  resolved frame with a warning: returning bytes from a capture that changed
  after sipnab made the pointer would manufacture the confidence the feature
  exists to provide. `frame_ref` on lint findings has a name apart from `frame`
  because a finding cites a message index. The pointer makes it checkable
  without the list that index counts within. A missing pointer omits the key
  rather than sending `""` or frame 0, both of which read as a real pointer.
- `decode_evidence` takes one pointer, not a batch, because a whole packet's
  structure per pointer fills a context window. Byte ranges come from the
  parse itself: `SipHeader` carries the byte range of its own logical line,
  recorded by the parser as it walks. This replaced a second walk of the
  header grammar paired with the parse positionally. Two walks of one grammar
  part company over a line with no colon, a non-UTF-8 line, an over-long line
  or the per-message header cap, and a range pinned one header early still
  resolves, so it reads as evidence. The old design dropped the whole set on
  any disagreement. A header that came from no bytes carries no range because
  a plausible invented range would point at bytes that never said it. sipnab
  drops the frame-relative pair when the payload does not sit at exactly one
  place in the frame (two candidate offsets make `frame[start..end]` a coin
  toss). Sources go through `resolve_in_root` so a caller-supplied path never
  becomes an arbitrary-file-read primitive behind a `readOnlyHint`. The answer
  carries no timestamp because the resolver returns frame bytes without the
  capture record, and a manufactured capture time on an evidence surface is
  the failure the mechanism exists to prevent.
- `build_evidence_package` ends the analysis in an artifact. The rebuilt-frames
  disclaimer lives inside the directory because the directory is what gets
  forwarded. Each file takes its ordinal as its name because a Call-ID is arbitrary peer
  text (separators, leading dash, hundreds of characters, bytes no filesystem
  wants). The pcapng is one chronological run because splitting by leg hides
  the interleaving that is usually the finding. sipnab removes a half-written
  package because it would hold the name against a retry and read as complete
  evidence.
- `save_findings` is a dead end on purpose: every response on the surface
  carries attacker-controlled text, so a write verb reachable from that text
  must not change what an operator reads or come back later as evidence the
  agent cites. The annotation types stay private to the MCP module so no
  analysis code can name them, and there is no `list_findings`.
  `readable_over_mcp: false` is a constant so a client never infers the dead
  end from the absence of a reader. The 1000-finding budget refuses rather
  than accepts-and-discards, because an agent told "recorded" about something
  thrown away is worse off than one told it was not. sipnab does not check
  `call_id` against the store because a note about a dropped call is still the note
  that mattered.
- `export_capture`: on one measured export, 4,875 of the 5,000 packets that
  had been on the wire were absent (RTP, RTCP, non-SIP).
- `open_capture` returns as soon as the background read starts because the
  REST API and the MCP server share one runtime thread, so a multi-gigabyte
  read inside the handler would stop every other client. sipnab refuses a live
  source because a live capture's writer never stops, so a second writer
  would race it for the life of the process. The tool stays listed without its
  flag because "not permitted here" and "this build cannot" are different
  answers. sipnab refuses password arguments because an argument passes through
  the model's context, the client's transcript and the provider's logs
  (OWASP LLM02:2025, and the MCP specification's rule that credentials never
  pass through the client).
- Discrepancy found 2026-10-16: the user page used to say `open_capture`
  refuses a capture belonging to this run's own `-I` set, and a comment in
  `open_capture` (src/mcp/server.rs) says `resolve_in_root` refuses it.
  `resolve_in_root` does not consult `protected_inputs` (only
  `resolve_in_root_for_write` does), and a run of 0.5.222 opened the `-I` file
  by name and returned `status: "loading"`.

## Notes for [security bundle](../mcp-tools-security.md)

### Why `top_talkers` counts participants rather than dialogs

`aggregate_dialogs` and `group_dialogs` group dialogs, and a dialog has two
ends. Asking "who is busiest" of a dialog-shaped answer forces the caller to
pick one end and ignore the other, which reports a trunk's traffic as belonging
to whichever side the schema happened to name first. `top_talkers` counts
participants instead, so shares sum above 100%. Rows sort by `dialogs`,
`messages`, `key` so two runs over one capture cannot disagree. `share_pct` is
`null` rather than `0` when nothing matched, because a zero would read as a
talker measured to be idle.

### Why `describe_endpoint` exists and refuses two selectors

The rest of the MCP surface keys on Call-ID, which suits "why did this call
fail" but not the question that comes first: an operator handed a complaint
holds a phone, a trunk or a subscriber. Answering from a dialog-centric surface
meant listing every dialog, filtering client-side and re-deriving per-entity
facts the stores already hold. sipnab refuses `ip` and `user` together because
the caller could mean their intersection or their union, and picking one
silently would answer a question nobody asked.

Matching an `ip` on messages rather than on the dialog's opening socket pair
keeps re-originated legs, re-INVITEs from a second interface and BYEs from the
far side. Matching the dialog record alone would drop exactly the transfers and
hand-offs an operator looks for. `failure_rate_pct` and
`registration.applicable` guard their denominators so that an unmeasured
endpoint never reads as a clean one. sipnab counts registrations by request
rather than by dialog method because a REGISTER can arrive inside a dialog
another method opened once Call-ID reuse is in play.

### Why a private `Contact` is an observation, not a finding

Measured against the private corpus on 2026-09-08, 1,660 of 2,226 REGISTER
contacts carried a private host (74.6%), and that estate works. A rule firing
on the observation alone would report three quarters of a healthy fleet. The
finding therefore needs later requests: any request to the private host is a
finding, because a proxy that sends some requests to the source and some to the
header still sends some nobody receives. `no-later-requests` stays distinct
from `rewritten` so that a capture that stopped too early does not read as a
clean bill of health. The registered AoR ties later requests to the
endpoint, because a request sent to the private `Contact` carries no address
belonging to the endpoint.

### Why `stack` fingerprinting exists and how conservative it is

On one capture, `top_talkers by=ua` reported `Asterisk PBX 20.15.2` as one row
at `share_pct: 100.0` across 507 dialogs, while `tshark` found 18 distinct
source addresses behind that label running two different SIP stacks. The banner
cannot tell them apart, and request syntax can. The fingerprint names a library,
never a product, because pjproject ships inside Asterisk `res_pjsip`,
Grandstream UCM and FreePBX alike. Two agreeing observations are the floor for
an inference because the magic cookie is mandatory for every sender and
`callid_has_host` alone splits senders roughly in half. `MAX_FINGERPRINT_CHARS`
(32) bounds echoed values. The fingerprint reads only requests, because a
response echoes the request's branch, `From` tag and `Call-ID`.

### Design of `evaluate_expectations`

The tool's purpose is to move sipnab from an incident tool to a check that runs on
every commit, with the rules in a checked-in `sipnab.expect.toml`. Passing the
file's bytes in `rules_toml` means the agent judges against what CI judges,
not against its own transcription. The tool refuses both suites or neither,
because two suites have no defined order and none would report a verdict on nothing.

Three failure modes get a gate deleted rather than fixed, and each has an
answer: passing on data never judged (an empty population fails as
`unevaluable:`, where a MOS threshold on an AMR-WB capture would otherwise
score placeholders and report green), failing on a sample too small to mean anything
(`min_sample` skips), and lying about coverage (an all-skipped suite reports
`not_evaluated`, exit code 2). Declaring `min_sample >= 1` is the only way to
tolerate an empty population, so a gate goes quiet only where its author wrote
that it may. The verdict tests the sample, because `count` always produces a
value and checking the value alone let `count == 0` pass on an empty capture.
Rule defects are hard errors because a misspelled metric evaluating to "fail"
would look like a real breach, and evaluating to "pass" would be a gate that
checks nothing.

### Why `generate_fail2ban_rule` takes one finding and a derived id

A rule generated from a class of findings would be a policy the tool has no
standing to write. A rule from one finding, with the alert line beside it, is
something an operator can read and decide on. The id derives from the finding
(`<rule_name>@<src_ip>@<timestamp>`) rather than a counter, because an assigned
id would have to survive eviction, restart and a second server reading the same
capture, and a position in a bounded ring buffer survives none of them. The
not-found message lists the held ids from a scan of the whole ring buffer,
because a truncated scan cannot report what it truncated. The tool checks that
`rule_name` is a bare identifier before writing it into a regular expression.

The tool returns the `NotEnabled` refusal in
[`src/mcp/tools/expectations.rs`](../../src/mcp/tools/expectations.rs)
(`this server holds no findings: no detection rule was armed`) when the server
has no alert engine or no armed detector. The armed detectors decide it, not
the engine, because a normal server run attaches an engine whether or not it
arms a detector (see the `armed_detections` field in
[`src/mcp/server.rs`](../../src/mcp/server.rs)).

## Notes for [server bundle](../mcp-tools-server.md)

### Design notes for `runtime_stats` and `capture_health`

`runtime_stats` exists because the Prometheus listener is off by default, so
the metrics exist inside the process and nothing can read them. An agent asked
"is this server healthy" could not enable a listener to find out. Absent fields
mean "not readable here" because a `0` on a platform where the value was never
read is worse than an admission. `impact.significant` exists because a capture
that is itself the reason a proxy started dropping calls was previously
invisible. The response omits the capture-queue fields without a capture meter
because a zero would read as "the queue is clear". The 30-second sample cap
exists because an MCP call blocks its caller and holds a request slot, and
clients commonly cancel at 60 seconds.

`capture_health` has no default window because a rate without a stated
interval is not a rate. `source_stopped_early` exists because a truncated
file previously reached only stderr (`0 of 1 file(s) read in full, 1 stopped
early`). The response type carries no string field at any depth, so it cannot
carry packet content. The test
`a_populated_capture_health_response_carries_no_string_value_anywhere`
enforces it. The handler opens no device and writes no file, so no path leads
from an MCP call to a capture that transmits or records. `attachment` code `1`
exists so that a server with nothing to read says so, and no code is `0`, so a
defaulted response cannot pass for a real one. `undecodable_reasons_dropped`
counts frames whose number did not fit the fixed-slot tables behind the
counters.

### Why `server_capabilities` reports `runtime` separately from `features`

`features` comes from `cfg!` at compile time, so it cannot claim a feature the
binary lacks. What the operator enabled is a different question no compile-time
check answers. Without `runtime` an agent discovers the setup by collecting
refusals mid-investigation. `named_backends` comes from the same function as
the second line of `sipnab --version` and REST `GET /v1/capabilities`.

## Notes for [TFPS bundle](../mcp-tools-tfps.md)

### TFPS JSON-mode provenance

`tfps_ctl --json` arrived in sippulse/tfps#6, merged into `master` on
2026-09-18 (commit `984577dc`). v0.2.1, the newest tag at that date, rejects
`--json`. [`tests/peer_release_honesty_test.rs`](../../tests/peer_release_honesty_test.rs) and
[`tests/tfps_contract_test.rs`](../../tests/tfps_contract_test.rs) record the same facts.

## Notes for [tls bundle](../mcp-tools-tls.md)

### `start_tls_capture`: refusal order and attach timing

All refusals happen in `plan_tls_targets` and `start_tls_capture` before any
kernel state exists, each with a reason, because an agent told only that a
capture failed cannot tell "this host runs no TLS" from "this server dropped
privileges", which lead to opposite next steps. The root check runs before the
attach because the attach happens on a background thread and its failure would
otherwise reach the agent minutes later as an empty capture. The one-writer
check runs under the same lock that records the new capture.

The `flavors` parameter keeps the serde alias `flavors` (the spelling through
0.5.104). The `--uprobe-flavor` flag dropped its alias in 0.5.157. The
parameter keeps it because clap refuses an unknown flag while serde ignores an
unknown key. Dropping it would silently widen the probe to every library.

## Notes for [vCon bundle](../mcp-tools-vcon.md)

### vCon MCP tools: design notes

- Backing code for each tool:
  - `export_vcon`: `output::vcon`.
  - `validate_vcon`: `output::vcon_schema`.
  - `analyze_vcon`: `output::vcon_analysis`, shared with
    `POST /v1/vcon/analyze`.
  - `fetch_vcon`: `app::vcon_fetch`, the same function as
    `sipnab --vcon-fetch`.
  - `vcon_directory_report`: `output::dialog_report::vcon_containers_report`,
    shared with `-I <dir> --report`.
  - `vcon_spool_status`: `app::vcon_spool::snapshot`, with
    `app::vcon_forward`'s file rules.
- `export_vcon` takes a `filter` because agents asked for every failed call
  used to list dialogs and issue one `export_vcon` per row, hundreds of round
  trips for what `--export-vcon-when` does in one invocation. The tool refuses
  `call_id` and `filter` together because a request naming a dialog and a rule
  for choosing dialogs has two answers and names neither. A filter matching
  nothing answers with an empty set because "no call failed" is a finding.
  There is no `format`: a markdown rendering of a document meant to travel
  between machines would eventually reach something expecting a container.
- docs/design/vcon.md records the observer posture (no signature, no consent
  attachment, `validation: "none"`, no `url`) in sections 2.1-2.5. It records
  the `recording` format-versus-provenance distinction in section 4b, the
  "incomplete record" gap in section 3, and the 204 store probe in section
  4a.1.
- sipnab builds the completeness caveat from one value into both the
  `analysis` object and the attachment so the two cannot contradict each other, and the
  response repeats it because a container over the size budget carries no
  audio, which looks exactly like a conversation that had none.
- An absent `blind_spots` on a container from the MCP tools would be a defect:
  both doors always run the capture analysis.
- `validate_vcon` response `schema_version` 1 also had `deviations`,
  `explanations` and a third verdict, `valid-except-documented-deviation`, for
  the empty Dialog Object `{}` that core-03 allowed in prose and rejected in
  its schema. core-04 section 4.3 replaced it with a typed placeholder, so
  version 2 dropped them. A validation pass over 4,216 real containers found 2
  the schema rejects, with nothing on any surface saying so. The validator
  walks the vendored schema itself (the draft-07 subset the file uses) because
  `jsonschema` is a dev-dependency and a validator built on it would ship only
  in the test tree. A keyword outside the subset reports `invalid` so
  re-vendoring a richer schema fails loudly.
