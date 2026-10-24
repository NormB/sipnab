# Code map

A codemap for contributors. It covers:

- what lives where,
- how data flows,
- the design decisions that explain the shape of the code.

For the historical roadmap and the full design-decision catalog (D1–D21), see
[`design/implementation-plan-v6.md`](../design/implementation-plan-v6.md).
This file tracks the code as it exists. The operator explanation of the same
pipeline is [Architecture](../architecture.md).

## One binary, two run modes, four answer surfaces

`sipnab` is a single binary (plus the `sipnab-audio` dlopen'd plugin crate).
It runs in one of two modes:

- as a **TUI** (interactive, ratatui),
- or in **batch/CLI mode** (parse → print/JSON/report → exit).

Both modes share one library
([`src/lib.rs`](../../src/lib.rs)). The binary ([`src/main.rs`](../../src/main.rs)) wires CLI flags to library calls.

The run mode decides who drives. It does not decide who can ask.

- The same analysis is readable over four surfaces.
- All of them are readers of the same two stores.
- None of them is a second copy of the state.

| Surface | Flag | Who asks |
|---|---|---|
| Terminal | default | A person at a TUI, or a script reading text/JSON/NDJSON |
| REST API | `--api` | Another program, over HTTP |
| MCP | `--mcp`, plus `--mcp-transport http` to serve it over HTTP | An AI agent, calling Model Context Protocol tools |
| Prometheus | `--metrics` | A scraper |

MCP is not a wrapper bolted over the CLI.

- It is a first-class reader
  ([`src/mcp/server.rs`](../../src/mcp/server.rs)).
- It takes the same read locks the TUI takes.
  That is why an agent can query a live capture while it is still running.
- No tool mutates the analysis.
- For the write-back question and why it stays closed, see
  [`design/mcp-write-back.md`](../design/mcp-write-back.md).

Two surfaces answering one question derive the answer once.

- `GET /v1/dialogs` and the MCP `list_dialogs` page each report which methods their match set
  holds.
- Both call `method_breakdown` in [`src/sip/dialog.rs`](../../src/sip/dialog.rs) rather than
  tallying separately.
  So the ordering rule and its tie-break cannot drift apart between them.
- Each tallies the whole match set rather than the page it returns.
  The composition of one page answers a different question.
- A fact two surfaces state is a fact one function derives.

The core is synchronous.

- Async (tokio) exists only at the edges, for the optional API and MCP servers.
- Those run on one shared runtime ([`src/app/servers.rs`](../../src/app/servers.rs)).

## Data flow

```text
capture sources                 per-packet path                    consumers
───────────────                ─────────────────                  ──────────
live device  ─┐
pcap file    ─┤   Packet    PacketProcessor::process      ParsedPacket
HEP listener ─┼──► (Bytes) ──► link/IP decap, IP-frag ──► (payload = Bytes ──► pipeline::process_packet
stdin        ─┘    channel     + TCP reassembly,           slice, zero-copy)   │  ws unwrap → SIP parse
                               TCP SIP framing                                 │  → RTCP → RTP/heuristic
                                                                               ▼
                                                     DialogStore ◄──── SDP links ────► StreamStore
                                                    (Arc<RwLock>)                     (Arc<RwLock>)
                                                          ▲                                ▲
                                          TUI (try_read) ─┴─ outputs / API / MCP (read) ───┘
```

- Parsing always happens **outside** the store locks.
- Each store is write-locked once per packet, briefly.
- Payloads are `bytes::Bytes` slices of
  the captured frame end to end (see [Zero-copy payloads](zero-copy-payloads.md)).

> All four packet paths classify through the one `pipeline::classify_packet` router:
>
> - live,
> - batch,
> - TUI file-open,
> - the `--cores` sharded path (`parallel.rs`).
>
> Only the per-path appliers differ.

[The subsystem guide](subsystem-guide.md) narrates the same journey packet by packet:

- every decision point,
- both store writes,
- where each of the four paths diverges.

## Module map

Annotations cover only the load-bearing files. Siblings follow the same pattern.

```text
src/
├── lib.rs                # curated public API; #[doc(hidden)] on bin-internal modules
├── main.rs               # binary: thin dispatcher into app/
├── app/                  # binary orchestration as library code
│   ├── bootstrap.rs      # CLI+config → RunPlan (mode/source/policy) + launch
│   ├── batch.rs          # BatchRunner: batch/offline receive loop, reports
│   ├── servers.rs        # API + MCP servers on one shared tokio runtime
│   ├── tui_mode.rs       # TUI mode entry
│   └── vcon_forward.rs   # --vcon-forward: a separate process that delivers a vCon spool to a store (vcon feature)
├── cli.rs                # clap definitions (the terminal SIP tools flag superset)
├── config.rs             # sipnabrc parsing/merging (toml_edit for surgical writes)
├── pipeline.rs           # THE shared per-packet protocol router (all four paths)
├── parallel.rs           # --cores N: shard-by-host-pair offline reconstruction
├── auth.rs / crypto.rs   # HMAC bearer tokens for api/mcp
├── analysis.rs           # capture-level verdict behind --analyze / find_problems
├── expect.rs             # capture thresholds as a pass/fail gate (MCP only)
├── provenance.rs         # capture identity + store generation (frame pointers)
├── stun.rs               # STUN/TURN parse and the request that never came back
├── error.rs              # typed error enums: Error (config/CLI), ParseError (parse_sip/_bytes/_rtp_header/_sdp), CaptureError (parse_packet/PcapReader) — all re-exported at the crate root
├── names.rs              # name resolution + [names.manual] persistence
├── privilege.rs          # setuid drop, chroot (drop early, drop hard); the one secret-file permission rule
├── process_isolation.rs  # isolated child for active responses (scanner kill)
├── signals.rs            # signal handling
├── capture/              # sources + L2-L4
│   ├── mod.rs            # PacketProcessor: decap, IP-frag/TCP reassembly, TCP SIP framing
│   ├── live.rs / file.rs / pcap_reader.rs   # libpcap live, libpcap file, pure-Rust reader
│   ├── libpcap.rs        # which libpcap runs + the backends its banner names (--version, capabilities)
│   ├── channel.rs        # capped packet channel (capture → processing)
│   ├── parse.rs          # link/IP/transport decap → ParsedPacket
│   ├── reassembly.rs     # IPv4/IPv6 fragments + TCP segments (RFC-annotated)
│   ├── hep.rs            # HEP v1/v2/v3 in, v3 out (Homer)
│   ├── tls.rs / decrypt.rs / dtls.rs / rsa_key.rs   # TLS record decryption (tls feature)
│   ├── websocket.rs      # WS frame unwrap (SIP over WebSocket)
│   ├── tunnel/           # MPLS/PPPoE/GTP-U/VXLAN/NSH decap → one offset each
│   ├── uprobe/           # eBPF uprobe TLS plaintext source (bpf feature)
│   ├── merged.rs / mapped.rs / native.rs   # merged-pcapng probe, mmap reader, AF_PACKET
│   └── writer.rs / atomic.rs / pcapng_meta.rs       # pcap/pcapng export
├── sip/
│   ├── parser.rs         # zero-copy-spine SIP parser (DoS caps on headers/line length)
│   ├── message.rs        # SipMessage (raw/body are Bytes slices; lazy accessors)
│   ├── dialog.rs         # SipDialog state machine
│   ├── dialog_store.rs   # capped store; Call-ID map + endpoint index; batched eviction
│   ├── sdp.rs / sdp_timeline.rs   # SDP parse; offer/answer timeline (hold/resume/T.38)
│   ├── dsl.rs            # --filter expression language (nom); regexes compiled at parse
│   ├── matcher.rs        # header/payload regex matching
│   ├── lint/             # RFC conformance rules (message/dialog/media)
│   └── method.rs / response_codes.rs / timing.rs / stir_shaken.rs / siprec.rs
├── rtp/                  # first-class peer of sip/ (streams exist without dialogs)
│   ├── stream.rs / stream_store.rs   # RtpStream; SSRC-indexed capped store
│   ├── parser.rs / rtcp.rs           # RTP header, RTCP SR/RR/XR
│   ├── quality.rs        # jitter/loss/MOS, burst-gap
│   ├── heuristic.rs      # RTP discovery without SDP
│   ├── diagnosis.rs      # one-way audio, NAT mismatch
│   ├── srtp.rs           # SRTP auth+decrypt (tls feature)
│   ├── dtmf.rs           # RFC 4733 events
│   ├── loss_map.rs       # per-interval loss/jitter map behind the TUI's `L` view
│   └── g711.rs / opus_decode.rs / wav.rs / audio_export.rs / playback.rs
├── security/             # passive-first detection
│   ├── scanner_detect.rs / fraud_detect.rs / digest_leak.rs / reg_flood.rs
│   ├── scanner_kill.rs   # active response (via process_isolation)
│   ├── tfps.rs           # optional TFPS peer: find tfps_ctl, ask it, read the answer
│   └── alerting.rs       # rule engine + event-exec hooks
├── output/
│   ├── model.rs            # canonical DialogSummary/StreamSummary (one JSON+MCP wire shape)
│   ├── cli_print.rs / json.rs / hexdump.rs / fail2ban.rs / wireshark.rs
│   ├── dialog_report.rs / call_report.rs / synthetic.rs
│   ├── api.rs            # axum REST (api feature)
│   ├── query/            # query answers REST serializes and the CLI query flags print
│   ├── prometheus.rs / prometheus_server.rs
│   ├── vcon.rs / vcon_schema.rs   # vCon container export (vcon feature)
│   ├── redact.rs         # --redact rewriting, with the reversible map
│   └── event_exec.rs     # external command hooks
├── mcp/                  # MCP server (mcp feature): server.rs, transport.rs, shape.rs
│   └── tools/            # tool bodies split out of server.rs, one module per group
├── rtpengine/            # rtpengine ng control-plane decode (bencode, ng, control)
├── relay/                # the media-relay seam: what sipnab needs from ANY relay
├── plugin/               # WASM plugin host (plugins feature; no interpreter without it)
├── llmnr/                # LLMNR (RFC 4795) decode + name store
├── tui/
│   ├── mod.rs            # App state + event loop
│   ├── state.rs          # per-view state structs + derived-data caches (LadderCache/DisplayedCache), refreshed by App::sync_caches()
│   ├── controllers/      # key/mouse handling, one module per view/popup (KeyAction mapping layer)
│   ├── render/           # frame composition: mod.rs + popups.rs + status.rs (render pass is read-only)
│   ├── call_list.rs / stream_list.rs / stream_detail.rs / msg_raw.rs
│   ├── call_flow/        # ladder diagram: prepare.rs (layout) + render.rs + arrows/export
│   ├── save.rs / help.rs / theme.rs
├── wasm.rs               # wasm-bindgen browser surface (wasm feature)
└── test_utils.rs         # shared SIP message builder for tests
crates/sipnab-audio/      # rodio/ALSA playback plugin, dlopen'd (no libasound NEEDED)
fuzz/                     # cargo-fuzz targets (20), out-of-workspace; weekly run via .github/workflows/fuzz.yml
tests/property_test.rs    # proptest properties (SIP/SDP round-trip, filter-DSL total-function)
harness/                  # docker-compose e2e (opensips + rtpengine + sipp)
```

## Threading model

See [Threading](threading.md) for the full topology and lock discipline.
Short version:

- Capture threads → bounded channel → one processing thread that owns all store writes.
- TUI, API and MCP are readers.
- Batch `--cores N` shards packets by host pair to worker threads with thread-local stores.
  sipnab merges those stores at EOF.

## Key design decisions (abridged)

- **D2 — Synchronous core, async only at the edges.**
  - The packet path is plain threads + channels.
  - tokio appears only inside the optional API/MCP/Prometheus servers.
- **D3 — Zero-copy payload spine.**
  - `Packet.data`, `ParsedPacket.payload`,
    `SipMessage.raw`/`body` are refcounted `Bytes` slices of one buffer.
  - Header parsing allocates lazily (canonical-name table + `Cow` unfold,
    WS4.1) — 3→1 allocations per header on the hot path.
- **D10 — Feature gates keep the binary small.**
  - `native`, `tui`, `tls`, `hep`, `api`, `mcp`, `mcp-http`, `audio`, `wasm`.
  - Check `Cargo.toml`
    before assuming a build includes a module.
- **D11 — Key material is toxic waste.**
  - `zeroize` on key types.
  - Redacting `Debug` impls.
  - `--tls-key`/keylog material never logged.
- **D13 — RTP is first-class.**
  - sipnab discovers streams heuristically even without SIP/SDP.
  - `rtp/` never depends on a dialog existing.
- **D15 — Privilege drop.**
  - sipnab sets `PR_SET_NO_NEW_PRIVS` at startup on every run mode, root or not.
    - That flag has no precondition.
    - The recommended `--setup-caps` install has no root to drop.
  - It then drops root right after socket open.
  - It disables core dumps whenever decryption keys are
    resident ([`src/privilege.rs`](../../src/privilege.rs)).
  - `--chroot` is available for daemon deployments.
- **D16 — Process isolation: scanner-kill yes, the REST API no.**
  - D16
    ([`docs/design/implementation-plan-v6.md`](../design/implementation-plan-v6.md) line 624) called for scanner-kill and the
    REST API to run in forked children.
  - **Scanner-kill does.**
    - Its worker is a process of its own ([`src/process_isolation.rs`](../../src/process_isolation.rs)).
      It is this binary, re-executed before the chroot and the privilege drop.
    - The parent creates the only sockets the kill path sends through.
      It hands them to the worker and closes its own copies.
    - So the process parsing captured traffic holds none of them.
    - The worker never creates a socket. Holding none, it refuses every request.
  - The REST/MCP servers
    still run as tasks on a shared runtime thread ([`src/app/servers.rs`](../../src/app/servers.rs)).
    - They share one address space with the parsers, the stores, TLS key material and bearer tokens.
    - Treat the API bind address and key accordingly.
    - Outside a `crash::contain` scope, the panic hook ends the whole process
      on a panic on any thread ([`src/crash.rs`](../../src/crash.rs)).
      So threads buy no fault containment either.
  - [`docs/design/process-isolation-and-hot-path-cost.md`](../design/process-isolation-and-hot-path-cost.md)
    analyzes whether to close the rest of this gap, and why most of it should stay open.
- **D17 — Warn and continue.**
  - Malformed input must never crash the process.
  - Parsers set `parse_error` and keep going ([the fault model](../fault-model.md)).

## Where to add things

| Task | Touch |
|---|---|
| Support a new SIP header accessor | `sip/message.rs` (+ parser test) |
| Add a per-packet protocol behavior | `pipeline.rs` (one classifier — all paths route through it) |
| Add an output format | `output/` + dispatch in `app/batch.rs` |
| Add a TUI view/keybinding | `tui/mod.rs` (App/Popup) + `tui/state.rs` + `tui/controllers/` + `render/` + keybinding drift test |
| Add a detection | `security/` + wiring in `app/batch.rs` |
| Add an MCP tool | `mcp/tools/` for a new group, else `mcp/server.rs` (`#[tool]`) + `mcp/shape.rs` |
| Add a CLI flag | `cli.rs` + `flag_coverage_test.rs` forces a test |

This table names the files. It does not name:

- the order,
- the tests each change owes,
- the gates that reject it.

[Walkthroughs](walkthroughs.md) has an ordered
checklist for each row.
