# Architecture

A codemap for contributors: what lives where, how data flows, and the design
decisions that explain the shape of the code. For the historical roadmap and
the full design-decision catalog (D1–D21), see `design/implementation-plan-v6.md`.
This file tracks the code as it exists.

## One binary, two modes

`sipnab` is a single binary (plus the `sipnab-audio` dlopen'd plugin crate).
It runs either as a **TUI** (interactive, ratatui) or in **batch/CLI mode**
(parse → print/JSON/report → exit). Both modes share one library
([`src/lib.rs`](https://github.com/NormB/sipnab/blob/main/src/lib.rs)). The binary ([`src/main.rs`](https://github.com/NormB/sipnab/blob/main/src/main.rs)) wires CLI flags to library calls.
The core is synchronous, and async (tokio) exists only at the edges, for the
optional API/MCP servers.

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

Parsing always happens **outside** the store locks. Each store is
write-locked once per packet, briefly. Payloads are `bytes::Bytes` slices of
the captured frame end to end (see [`docs/internals/zero-copy-payloads.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/zero-copy-payloads.md)).

> All four packet paths — live, batch, TUI file-open and the `--cores`
> sharded path (`parallel.rs`) — classify through the one
> `pipeline::classify_packet` router; only the per-path appliers differ.

For the same journey narrated packet by packet — every decision point, both
store writes, and where each of the four paths diverges — see
[docs/internals/subsystem-guide.md](internals/subsystem-guide.md).

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
│   └── tui_mode.rs       # TUI mode entry
├── cli.rs                # clap definitions (sngrep + sipgrep flag superset)
├── config.rs             # sipnabrc parsing/merging (toml_edit for surgical writes)
├── pipeline.rs           # THE shared per-packet protocol router (all four paths)
├── parallel.rs           # --cores N: shard-by-host-pair offline reconstruction
├── auth.rs / crypto.rs   # HMAC bearer tokens for api/mcp
├── error.rs              # typed error enums: Error (config/CLI), ParseError (parse_sip/_bytes/_rtp_header/_sdp), CaptureError (parse_packet/PcapReader) — all re-exported at the crate root
├── names.rs              # name resolution + [names.manual] persistence
├── privilege.rs          # setuid drop, chroot (drop early, drop hard)
├── process_isolation.rs  # isolated child for active responses (scanner kill)
├── signals.rs            # signal handling
├── capture/              # sources + L2-L4
│   ├── mod.rs            # PacketProcessor: decap, IP-frag/TCP reassembly, TCP SIP framing
│   ├── live.rs / file.rs / pcap_reader.rs   # libpcap live, libpcap file, pure-Rust reader
│   ├── channel.rs        # capped packet channel (capture → processing)
│   ├── parse.rs          # link/IP/transport decap → ParsedPacket
│   ├── reassembly.rs     # IPv4/IPv6 fragments + TCP segments (RFC-annotated)
│   ├── hep.rs            # HEP v2/v3 in/out (Homer)
│   ├── tls.rs / decrypt.rs / dtls.rs / rsa_key.rs   # TLS record decryption (tls feature)
│   ├── websocket.rs      # WS frame unwrap (SIP over WebSocket)
│   └── writer.rs / atomic.rs / pcapng_meta.rs       # pcap/pcapng export
├── sip/
│   ├── parser.rs         # zero-copy-spine SIP parser (DoS caps on headers/line length)
│   ├── message.rs        # SipMessage (raw/body are Bytes slices; lazy accessors)
│   ├── dialog.rs         # SipDialog state machine
│   ├── dialog_store.rs   # capped store; Call-ID map + endpoint index; batched eviction
│   ├── sdp.rs / sdp_timeline.rs   # SDP parse; offer/answer timeline (hold/resume/T.38)
│   ├── dsl.rs            # --filter expression language (nom); regexes compiled at parse
│   ├── matcher.rs        # header/payload regex matching
│   └── method.rs / response_codes.rs / timing.rs / stir_shaken.rs / siprec.rs
├── rtp/                  # first-class peer of sip/ (streams exist without dialogs)
│   ├── stream.rs / stream_store.rs   # RtpStream; SSRC-indexed capped store
│   ├── parser.rs / rtcp.rs           # RTP header, RTCP SR/RR/XR
│   ├── quality.rs        # jitter/loss/MOS, burst-gap
│   ├── heuristic.rs      # RTP discovery without SDP
│   ├── diagnosis.rs      # one-way audio, NAT mismatch
│   ├── srtp.rs           # SRTP auth+decrypt (tls feature)
│   ├── dtmf.rs           # RFC 4733 events
│   └── g711.rs / opus_decode.rs / wav.rs / audio_export.rs / playback.rs
├── security/             # passive-first detection
│   ├── scanner_detect.rs / fraud_detect.rs / digest_leak.rs / reg_flood.rs
│   ├── scanner_kill.rs   # active response (via process_isolation)
│   └── alerting.rs       # rule engine + event-exec hooks
├── output/
│   ├── model.rs            # canonical DialogSummary/StreamSummary (one JSON+MCP wire shape)
│   ├── cli_print.rs / json.rs / hexdump.rs / fail2ban.rs / wireshark.rs
│   ├── dialog_report.rs / call_report.rs / synthetic.rs
│   ├── api.rs            # axum REST (api feature)
│   ├── prometheus.rs / prometheus_server.rs
│   └── event_exec.rs     # external command hooks
├── mcp/                  # MCP server (mcp feature): server.rs, transport.rs, shape.rs
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
fuzz/                     # cargo-fuzz targets (15), out-of-workspace; weekly run via .github/workflows/fuzz.yml
tests/property_test.rs    # proptest properties (SIP/SDP round-trip, filter-DSL total-function)
harness/                  # docker-compose e2e (opensips + rtpengine + sipp)
```

## Threading model

See [`docs/internals/threading.md`](https://github.com/NormB/sipnab/blob/main/docs/internals/threading.md) for the full topology and lock discipline.
Short version: capture threads → bounded channel → one processing thread
that owns all store writes. TUI, API and MCP are readers. Batch `--cores N` shards
packets by host pair to worker threads with thread-local stores, merged at
EOF.

## Key design decisions (abridged; full text in design/implementation-plan-v6.md)

- **D2 — Synchronous core, async only at the edges.** The packet path is
  plain threads + channels; tokio appears only inside the optional
  API/MCP/Prometheus servers.
- **D3 — Zero-copy payload spine.** `Packet.data`, `ParsedPacket.payload`,
  `SipMessage.raw`/`body` are refcounted `Bytes` slices of one buffer.
  Header parsing allocates lazily (canonical-name table + `Cow` unfold,
  WS4.1) — 3→1 allocations per header on the hot path.
- **D10 — Feature gates keep the binary small.** `native`, `tui`, `tls`,
  `hep`, `api`, `mcp`, `mcp-http`, `audio`, `wasm`. Check [`Cargo.toml`](https://github.com/NormB/sipnab/blob/main/Cargo.toml)
  before assuming a build includes a module.
- **D11 — Key material is toxic waste.** `zeroize` on key types, redacting
  `Debug` impls, `--tls-key`/keylog material never logged.
- **D13 — RTP is first-class.** sipnab discovers streams heuristically even
  without SIP/SDP; `rtp/` never depends on a dialog existing.
- **D15 — Privilege drop.** sipnab sets `PR_SET_NO_NEW_PRIVS` at startup on
  every run mode — root or not, because that flag has no precondition and the
  recommended `--setup-caps` install has no root to drop — then drops root
  right after socket open and disables core dumps whenever decryption keys are
  resident ([`src/privilege.rs`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs)); `--chroot` is available for daemon
  deployments.
- **D16 — Process isolation: specified, not shipped.** D16
  ([`docs/design/implementation-plan-v6.md:624`](https://github.com/NormB/sipnab/blob/main/docs/design/implementation-plan-v6.md#L624)) called for scanner-kill and the
  REST API to run in forked children behind a Unix socket pair. **Neither
  does.** Scanner-kill runs in the `scanner-kill` *thread*
  ([`src/process_isolation.rs`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs)) and the REST/MCP servers run as tasks on a shared
  runtime thread ([`src/app/servers.rs`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs)), all in one address space alongside the
  parsers, the stores, TLS key material and bearer tokens. Treat the API bind
  address and key accordingly — and note that `panic = "abort"`
  ([`Cargo.toml:262`](https://github.com/NormB/sipnab/blob/main/Cargo.toml#L262)) means a panic on any thread ends the whole process, so
  threads buy no fault containment either. The analysis of whether to close this
  gap, and why most of it should stay open, is in
  [`docs/design/process-isolation-and-hot-path-cost.md`](https://github.com/NormB/sipnab/blob/main/docs/design/process-isolation-and-hot-path-cost.md).
- **D17 — Warn and continue.** Malformed input must never crash the
  process; parsers set `parse_error` and keep going ([`docs/fault-model.md`](https://github.com/NormB/sipnab/blob/main/docs/fault-model.md)).

## Where to add things

| You want to… | Touch |
|---|---|
| Support a new SIP header accessor | `sip/message.rs` (+ parser test) |
| Add a per-packet protocol behavior | `pipeline.rs` (one classifier — all paths route through it) |
| Add an output format | `output/` + dispatch in `app/batch.rs` |
| Add a TUI view/keybinding | `tui/mod.rs` (App/Popup) + `tui/state.rs` + `tui/controllers/` + `render/` + keybinding drift test |
| Add a detection | `security/` + wiring in `app/batch.rs` |
| Add an MCP tool | `mcp/server.rs` (`#[tool]`) + `mcp/shape.rs` |
| Add a CLI flag | `cli.rs` + `flag_coverage_test.rs` forces a test |

This table names the files. It does not name the order, the tests each change
owes, or the gates that reject it.
[docs/internals/walkthroughs.md](internals/walkthroughs.md) has an ordered
checklist for each row.
