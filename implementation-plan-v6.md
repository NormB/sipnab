# sipnab — Implementation Plan v6

**Project:** sipnab — The definitive SIP analysis tool, built in Rust
**Repository:** github.com/NormB/sipnab
**Domain:** sipnab.com
**License:** MIT OR Apache-2.0
**Author:** Norm Brandinger

> **⚠ Living document — superseded in places by `implementation-plan-phases-8-10.md`.**
> The Phase 8–10 plan's "Resolved Decisions" section formally drops several
> v6 designs that this document still describes as active. As of 2026-05-05:
>
> - **gRPC API (D11 RPC slot, `grpc` feature flag) was dropped.** Replaced by
>   REST + OpenAPI (Phase 9) + MCP (Phase 8). The `grpc` flag has never
>   existed in `Cargo.toml`.
> - **Pluggable crypto backend (D14) was dropped.** Only the pure-Rust `tls`
>   feature (`ring` + `rustls`) ever shipped; `tls-wolfssl` and `tls-openssl`
>   were never implemented and remain phantom flags in this document's
>   feature/dependency tables. There is no FIPS 140-3 path today.
> - **Lab-internal SIP server fleet** assumptions in some risk-register
>   entries are not reflective of current public release scope.
>
> Use `Cargo.toml`'s `[features]` block as the authoritative feature list.
> Use `implementation-plan-phases-8-10.md` for current phase status.

**Changes from v5:** Added threat model, risk register, security hardening throughout all phases, privilege separation model, process isolation for daemon mode, MVP release milestones, tightened exit criteria, dependency audit strategy, testing pyramid. Replaced Lua scripting with Filter DSL + NDJSON pipeline + event exec hooks. Added VoIP engineering workflow features: SIP response code intelligence, transaction timing/PDD analysis, one-way audio diagnosis, multi-leg call correlation, structured call diagnosis reports, SDP negotiation timeline tracking, per-endpoint concurrent call tracking, and built-in diagnostic filter aliases. Adjusted timeline estimates for single-developer reality.

---

## Scope

sipnab unifies the capabilities of **sngrep** (interactive TUI flow viewer) and **sipgrep** (CLI regex matcher with dialog reports) into a single binary, treats SIP signaling and RTP media as **equal peers**, then adds features neither tool provides. One tool replaces two, with zero memory leaks and zero CPU waste by construction.

**Tagline:** sipnab — SIP & RTP capture, analysis, and security

### Feature Origin Map

| Feature Area | sngrep | sipgrep | sipnab NEW |
|---|---|---|---|
| Interactive TUI (call list, ladder, raw view) | ✅ | — | Enhanced |
| Live pcap capture | ✅ | ✅ | ✅ |
| BPF filters | ✅ | ✅ | ✅ |
| Pcap read/write | ✅ | ✅ | + PCAP-NG |
| Regex match on payload | ✅ | ✅ | ✅ |
| Dialog tracking | ✅ | ✅ (-g) | ✅ |
| HEP/Homer integration | ✅ | ✅ | ✅ |
| TLS decryption | ✅ | — | Enhanced (keylog, PCAP-NG DSB) |
| SRTP decryption (SDES) | — | — | ✅ |
| DTLS-SRTP decryption | — | — | ✅ |
| Decryption security guardrails | — | — | ✅ |
| From/To/Contact/UA filters | — | ✅ (-f/-t/-c/-j) | ✅ |
| Dialog report output | — | ✅ (-G) | ✅ |
| Friendly-scanner kill | — | ✅ (-J/-K) | ✅ |
| Pcap replay with timestamps | — | ✅ (-D) | ✅ |
| Trailing context packets | — | ✅ (-A) | ✅ |
| Autostop (duration/filesize) | — | ✅ (-q) | ✅ |
| Pcap rotation/splitting | — | ✅ (-Q) | ✅ |
| Delta timestamps | — | ✅ (-T) | ✅ |
| Word-regex matching | — | ✅ (-w) | ✅ |
| Port range filter | — | ✅ (-P) | ✅ |
| Filter DSL expressions | — | — | ✅ |
| NDJSON pipeline extensibility | — | — | ✅ |
| Event exec hooks | — | — | ✅ |
| STIR/SHAKEN analysis | — | — | ✅ |
| Toll fraud / IRSF detection | — | — | ✅ |
| RTP quality (jitter/loss/MOS) | — | — | ✅ First-class |
| RTP stream as top-level entity | — | — | ✅ |
| RTP heuristic discovery (no SDP) | — | — | ✅ |
| RTCP SR/RR/XR parsing | — | — | ✅ |
| Per-interval quality metrics | — | — | ✅ |
| Orphaned stream detection | — | — | ✅ |
| RTP on by default (not opt-in) | — | — | ✅ |
| JSON/NDJSON streaming output | — | — | ✅ |
| Prometheus metrics endpoint | — | — | ✅ |
| Alerting rules engine | — | — | ✅ |
| Fail2ban format output | — | — | ✅ |
| SIP digest leak detection | — | — | ✅ |
| Registration flood detection | — | — | ✅ |
| Multi-device capture | — | — | ✅ |
| gRPC/REST API daemon mode | — | — | ✅ |
| SIPREC metadata parsing | — | — | ✅ |
| Wireshark display filter export | — | — | ✅ |
| tshark command generation | — | — | ✅ |
| Raw hex+ASCII dump (tcpdump replacement) | — | — | ✅ |
| SIP response code intelligence | — | — | ✅ |
| SIP transaction timing / PDD | — | — | ✅ |
| One-way audio detection & diagnosis | — | — | ✅ |
| NAT mismatch detection & visualization | — | — | ✅ |
| Media path analysis (SDP vs actual) | — | — | ✅ |
| Multi-leg B2BUA/SBC call correlation | — | — | ✅ |
| SDP offer/answer negotiation timeline | — | — | ✅ |
| Hold/resume/transfer detection | — | — | ✅ |
| Structured call diagnosis reports | — | — | ✅ |
| Per-endpoint concurrent call tracking | — | — | ✅ |
| Built-in diagnostic filter aliases | — | — | ✅ |

---

## Non-Goals

These are explicitly out of scope. Documenting them prevents scope creep.

- **General packet analysis.** sipnab decodes SIP, SDP, RTP, and HEP. It does not decode HTTP, DNS, SMTP, or the other ~3,000 protocols tshark handles. For non-SIP deep-dive, sipnab generates tshark commands to bridge you there.
- **Full PBX management.** sipnab observes traffic. It does not provision extensions, manage registrations, or modify call routing. That's what Saturn, VitalPBX, or OpenSIPS do.
- **Replacing Wireshark's GUI.** The TUI is for real-time terminal work. For pixel-perfect ladder diagrams, pcap annotation, or protocol dissection beyond SIP, export to Wireshark.
- **Stateful SIP proxy behavior.** sipnab tracks dialogs passively by observing packets. It does not maintain transaction timers, retransmit, or act as a B2BUA (scanner-kill is the sole exception, and it's opt-in).
- **Decoding SRTP media content.** sipnab can decrypt SRTP headers and verify stream integrity when keys are provided, but it does not decode audio codecs (G.711, G.729, Opus, etc.) or play back voice. For audio playback, export the decrypted RTP stream to Wireshark or a dedicated tool. sipnab's SRTP support is limited to: header decryption for quality metrics, key extraction from SDES in decrypted SDP, and verification that encryption is correctly negotiated.
- **Embedded scripting runtime.** sipnab does not embed Lua, Python, or any general-purpose scripting language. Embedded runtimes introduce unsafe FFI boundaries, sandbox escape risk, and supply chain dependencies disproportionate to their value. Instead, sipnab provides a declarative filter DSL, NDJSON pipeline output for external processing, and event exec hooks for custom automation. If plugin extensibility is needed in the future, WASM (with wasmtime) is the secure path — sandbox by construction, no unsafe FFI.

---

## Threat Model

sipnab captures network traffic, decrypts TLS/SRTP, injects packets (scanner kill), runs an HTTP API, and downloads data at build time. A formal threat model constrains every implementation decision.

### Attack Surface Inventory

| Surface | Exposure | Trust Level | Mitigation Strategy |
|---|---|---|---|
| Network packets (pcap input) | Untrusted — attacker-controlled content on the wire | Zero trust | Bounds-checked parsing, fuzz-tested, no unsafe on input paths |
| Pcap files (`-I`) | Untrusted — files may be crafted/malicious | Zero trust | Same as live capture. Validate pcap headers before processing. |
| HEP input (`-L`) | Network-facing UDP listener | Zero trust | Localhost-default bind, source allowlist, rate limiting, validate HEP structure before allocating |
| TLS key files (`-k`, `--keylog`) | Local filesystem, operator-provided | Medium trust | Validate format, check permissions, mlock to prevent swap, zeroize on drop |
| SRTP key files (`--srtp-keys`) | Local filesystem, operator-provided | Medium trust | Same as TLS keys |
| Config file (TOML) | Local filesystem, operator-written | High trust | Validate all values, reject unknown keys, no code execution from config |
| REST API (`--api`) | Network-facing HTTP/WS | Low trust | Localhost-default bind, API key auth, TLS option, rate limiting, read-only by default |
| Prometheus endpoint (`--metrics`) | Network-facing HTTP | Low trust | Localhost-default bind, read-only, optional basic auth |
| CLI arguments | Local, operator-provided | High trust | Validate via clap, but still bounds-check all numeric inputs |
| CFCA prefix list (build.rs) | External network at build time | Supply chain risk | Pinned URL + SHA-256 hash, bundled fallback, explicit opt-in for update |
| Cargo dependencies | External, build time | Supply chain risk | cargo-audit in CI, cargo-deny for license/dupes, cargo-geiger for unsafe audit, lockfile committed |

### Threat Categories

**T1 — Remote code execution via crafted packets.** Malformed SIP/RTP/RTCP/HEP designed to trigger parser bugs. The zero-copy `&[u8]` design mitigates heap corruption, but reassembly (IP fragments, TCP segments) builds new buffers — that's where overflows historically live. Mitigation: size caps on all reassembly buffers, fuzz testing from Phase 1, no `unsafe` blocks on any input-processing path.

**T2 — Denial of service against sipnab itself.** Hash flooding DialogStore/StreamStore, reassembly table exhaustion, regex catastrophic backtracking (ReDoS) on user-supplied filter patterns, event exec fork bombs. Mitigation: default size caps on all stores, regex size limits, rate limits on all network listeners, exec hooks rate-limited.

**T3 — Privilege escalation.** sipnab runs as root (or CAP_NET_RAW) for capture. Privilege drop after device open (D15). Scanner kill requires privileged capture fd — isolated in a child process (D16). API and metrics run unprivileged.

**T4 — Information disclosure.** Key material leakage (addressed by D11). API exposes dialog content which may contain PII (phone numbers, caller names, SIP credentials in malformed traffic). Prometheus metrics reveal traffic patterns. Mitigation: API key auth, localhost-default bind for all listeners, key material never crosses IPC boundaries, no key material in logs/metrics/API responses.

**T5 — Supply chain compromise.** `build.rs` downloading CFCA prefix data at compile time. Cargo dependencies with unsafe code or known vulnerabilities. Mitigation: pinned hashes for external data, bundled fallback, cargo-audit + cargo-deny + cargo-geiger in CI.

**T6 — Scanner kill amplification.** If `--kill-scanner` is tricked into sending responses to spoofed source IPs, sipnab becomes a traffic amplifier. Mitigation: rate limit (10 responses/sec, enforced in isolated child process), validate that scanner source IP was actually observed in capture, never respond to packets from broadcast/multicast addresses.

---

```
┌──────────────────────────────────────────────────────────────────────┐
│                           sipnab binary                              │
├──────────┬──────────┬──────────┬───────────┬────────────┬──────────┤
│ capture  │   sip    │   rtp    │   tui     │   output   │ security │
│          │          │          │           │            │          │
│ pcap     │ parser   │ stream   │ ratatui   │ cli print  │ stir/sha │
│ reassm   │ dialog   │ parser   │ call_list │ json/ndjson│ fraud    │
│ tls      │ filter   │ rtcp     │ call_flow │ dialog rpt │ scanner  │
│ dtls     │ sdp      │ quality  │ stream_ls │ pcap write │ digest   │
│ hep      │ matcher  │ dtmf     │ msg_raw   │ prometheus │ reg_fld  │
│ replay   │ stir     │ heurist  │ msg_diff  │ fail2ban   │ alerting │
│          │ siprec   │ srtp     │ stats     │ grpc/rest  │          │
│          │ dsl      │          │ dashboard │ wireshark  │          │
│          │          │          │           │ hexdump    │          │
└──────────┴──────────┴──────────┴───────────┴────────────┴──────────┘
         │                    │                     │
    ┌────┴────┐          ┌────┴────┐          ┌────┴────┐
    │ libpcap │          │ termios │          │  (none)  │
    └─────────┘          └─────────┘          └──────────┘
```

### Module Map

```
src/
├── main.rs
├── cli.rs                   # clap CLI — unified sngrep + sipgrep flags
├── config.rs                # Config file parsing
├── capture/
│   ├── mod.rs               # Capture orchestration, source management
│   ├── live.rs              # Live device capture
│   ├── file.rs              # Pcap/pcap-ng file reader
│   ├── replay.rs            # Pcap replay with original timing (-D)
│   ├── writer.rs            # Pcap/pcap-ng writer with rotation, decrypted/encrypted/raw export modes
│   ├── packet.rs            # Packet type, frame storage
│   ├── reassembly.rs        # IP fragment + TCP segment reassembly
│   ├── hep.rs               # HEP v2/v3 send/receive (Homer)
│   ├── tls.rs               # TLS record layer decryption (feature-gated)
│   ├── dtls.rs              # DTLS-SRTP key extraction (feature-gated)
│   └── websocket.rs         # WebSocket frame unwrapping
├── sip/
│   ├── mod.rs               # SIP message store, dialog registry
│   ├── parser.rs            # Zero-copy SIP parser
│   ├── message.rs           # SipMessage type
│   ├── dialog.rs            # SipDialog type, state machine
│   ├── sdp.rs               # SDP parser (media, codecs, ICE, crypto)
│   ├── filter.rs            # Display + header-specific filters
│   ├── matcher.rs           # Regex matcher (payload, word, multi-line)
│   ├── dsl.rs               # Filter DSL parser and evaluator (--filter expressions)
│   ├── timing.rs            # SIP transaction timing: PDD, setup time, per-hop latency
│   ├── correlation.rs       # Multi-leg B2BUA/SBC call correlation (X-Call-ID, Via, heuristic)
│   ├── response_codes.rs    # SIP response code → human-readable explanation + common causes
│   ├── sdp_timeline.rs      # SDP offer/answer timeline: hold, resume, codec change, T.38
│   ├── stir_shaken.rs       # Identity header, PASSporT, attestation
│   └── siprec.rs            # SIPREC metadata parsing
├── rtp/                         # RTP/RTCP — first-class peer of sip/
│   ├── mod.rs               # RTP stream store (top-level, peers with dialog store)
│   ├── stream.rs            # RtpStream type — top-level entity, not child of dialog
│   ├── parser.rs            # RTP header parser (version, PT, SSRC, seq, timestamp)
│   ├── rtcp.rs              # RTCP: Sender Report, Receiver Report, XR, NACK, PLI, BYE
│   ├── quality.rs           # Per-interval jitter, loss, MOS, burst/gap analysis
│   ├── dtmf.rs              # RFC 4733 telephone-event extraction
│   ├── heuristic.rs         # RTP discovery from traffic patterns (no SDP required)
│   ├── diagnosis.rs         # One-way audio detection, NAT mismatch, media path analysis
│   └── srtp.rs              # SRTP/SRTCP decryption (SDES, DTLS-SRTP keys)
├── security/
│   ├── mod.rs               # Security analysis orchestration
│   ├── scanner_detect.rs    # Friendly-scanner / sipvicious detection
│   ├── scanner_kill.rs      # Active response to scanners (-J/-K), isolated child process
│   ├── fraud_detect.rs      # Toll fraud / IRSF pattern detection
│   ├── digest_leak.rs       # SIP digest authentication leak detection
│   ├── reg_flood.rs         # Registration flood / brute force detection
│   └── alerting.rs          # Rule-based alerting engine + event exec hooks
├── output/
│   ├── mod.rs               # Output mode dispatcher
│   ├── cli_print.rs         # sipgrep-style colored terminal output
│   ├── dialog_report.rs     # Dialog summary report (-G)
│   ├── call_report.rs       # Structured call diagnosis report (--call-report)
│   ├── json.rs              # JSON / NDJSON streaming output
│   ├── hexdump.rs           # Raw hex+ASCII packet dump (--hexdump)
│   ├── fail2ban.rs          # Fail2ban-compatible log format
│   ├── prometheus.rs        # Prometheus /metrics HTTP endpoint
│   ├── grpc.rs              # gRPC API daemon mode (feature-gated)
│   └── wireshark.rs         # Wireshark/tshark filter export (--wireshark, --tshark-filter)
└── tui/
    ├── mod.rs               # UI manager, panel stack, event loop
    ├── call_list.rs         # Main call list view
    ├── stream_list.rs       # RTP stream list view (top-level, not child of call list)
    ├── call_flow.rs         # Ladder diagram view
    ├── msg_raw.rs           # Raw SIP message view with highlighting
    ├── msg_diff.rs          # Message diff view
    ├── filter_view.rs       # Filter dialog
    ├── save_view.rs         # Save dialog (pcap/txt/json)
    ├── settings.rs          # Settings view
    ├── stats.rs             # Statistics view
    ├── dashboard.rs         # Real-time dashboard (calls/sec, codes, etc.)
    ├── column_select.rs     # Column chooser
    └── theme.rs             # Colors and styling
```

### Crate Dependencies

| Crate | Purpose | Phase |
|-------|---------|-------|
| `pcap` | Packet capture (libpcap FFI) | 1 |
| `etherparse` | Zero-copy network header parsing | 1 |
| `ratatui` + `crossterm` | Terminal UI | 3 |
| `clap` (derive) | CLI argument parsing | 1 |
| `regex` | SIP header matching & filters | 1 |
| `chrono` | Timestamps | 1 |
| `log` + `env_logger` | Logging | 1 |
| `parking_lot` | Fast RwLock for shared state | 1 |
| `crossbeam-channel` | Lock-free capture→main channel | 1 |
| `serde` + `serde_json` | JSON serialization | 2 |
| `rustls` | TLS decryption (feature-gated) | 5 |
| `zeroize` | Secure key material memory zeroing | 5 |
| `ring` or `aws-lc-rs` | Pure-Rust crypto backend (default, no system deps) | 5 |
| `wolfssl` | wolfSSL crypto backend — FIPS 140-3, DTLS (feature-gated) | 5 |
| `openssl` | OpenSSL crypto backend — compat with existing infra (feature-gated) | 5 |
| `tonic` | gRPC server (feature-gated) | 6 |
| `axum` | HTTP server for Prometheus + REST | 5 |
| `base64` | PASSporT/STIR-SHAKEN JWT decoding | 5 |
| `pcap-file` | PCAP-NG read/write | 2 |
| `nom` or `pest` | Filter DSL expression parser | 2 |

### Feature Flags

```toml
[features]
default = []
tls = ["dep:zeroize"]                             # TLS decryption with pure-Rust crypto (default backend)
tls-wolfssl = ["tls", "dep:wolfssl"]               # wolfSSL backend (FIPS 140-3, DTLS, embedded)
tls-openssl = ["tls", "dep:openssl"]               # OpenSSL backend (compatibility with existing infra)
hep = []
grpc = ["dep:tonic", "dep:prost"]
api = ["dep:axum", "dep:tokio"]
full = ["tls", "hep", "grpc", "api"]
```

---

## Design Decisions

These decisions are foundational — they constrain every implementation phase that follows. Read them before reviewing the phase plans.

### D1 — One binary, two modes

VoIP engineers currently reach for sngrep (interactive TUI), sipgrep (CLI regex grep), ngrep (generic packet grep), tshark (Wireshark CLI), or tcpdump (raw capture) depending on the task. sipnab collapses the first two into a single binary with identical capture and parsing code paths:

- `sipnab` with no flags → interactive TUI (sngrep mode)
- `sipnab -N` → CLI output (sipgrep mode)
- `sipnab -N --json` → structured pipeline mode (new)

This means one SIP parser, one dialog engine, one reassembly implementation — tested once, used everywhere. No divergence between "the grep tool parsed it differently than the TUI tool."

### D2 — Synchronous core, async only at the edges

The capture path is inherently synchronous: `pcap_loop` is a blocking FFI call that must run in a dedicated OS thread. The TUI event loop is also synchronous (crossterm poll-based). Introducing tokio/async into the core would add complexity (pinning, Send/Sync bounds, executor overhead) with zero benefit for these use cases.

Async is used **only** for optional edge features that genuinely need concurrent I/O:
- Prometheus HTTP metrics server (`--metrics`)
- REST API daemon mode (`--api`)
- WebSocket event streaming

These features are behind feature gates and spawn their own tokio runtime. The core capture→parse→display pipeline never touches an async executor.

### D3 — Zero-copy SIP parsing with lazy extraction

SIP messages can be 1–10KB. On a busy B2BUA handling 1,000 calls/sec, parsing every header of every message upfront wastes CPU on data that is never displayed or filtered.

sipnab's SIP parser operates on `&[u8]` byte slices into the original packet buffer. Headers are located by scanning for `\r\n` boundaries but their values are **not** extracted or allocated until explicitly requested — by a display filter, a TUI column render, or an output formatter. This means:

- Filtering by Call-ID touches only the Call-ID header bytes, not the entire message
- The common path (capture → check filter → discard non-matching) does zero heap allocation
- Only messages that pass filters and are displayed/output pay the full parsing cost

This is a deliberate tradeoff: slightly more complex parser code in exchange for dramatically lower CPU and memory usage under load. The same approach is used by high-performance HTTP parsers like `httparse`.

### D4 — Rust ownership eliminates the C bug classes by construction

The 12 bugs found in sngrep's C codebase fall into categories that Rust's type system makes structurally impossible:

**Use-after-free (MEM-1):** Rust's borrow checker prevents using a reference after the owning value is dropped or moved. There is no equivalent of "free a pointer then pass it to another function."

**Memory leaks from forgotten frees (MEM-2,3,4,5,7,8):** All heap-allocated types implement `Drop`. When a `Vec<Packet>` is removed from a `HashMap`, every `Packet` in it is automatically dropped, which drops every `Frame`, which drops every `Vec<u8>` payload. There is no manual free to forget.

**Dangling pointers (MEM-6):** `Option<Vec<u8>>` replaces raw `*payload` pointers. Setting it to `None` drops the old buffer and leaves the field in a known state. There is no "freed but non-NULL pointer."

**Quadratic algorithms from bad data structures (CPU-2):** `Vec::clear()` is O(1) for types without `Drop` and O(n) with `Drop` — never O(n²). `Vec::retain()` is a single-pass O(n) filter. There is no "remove from front and shift" pattern.

**Realloc storms (CPU-1):** `Vec<T>` doubles capacity on growth. Filtering into a pre-allocated `Vec` with `.clear()` + `.extend()` does zero allocations in steady state.

**malloc/free churn (CPU-3):** Reusing a `Vec` across frames (clear + refill) means the backing allocation persists and grows monotonically to its high-water mark. No per-frame malloc/free cycle.

This is not aspirational — these guarantees are enforced at compile time by `rustc`. Code that violates them does not compile.

### D5 — Thread architecture

```
┌──────────────────────┐     crossbeam      ┌─────────────────────┐
│  Capture Thread(s)   │ ── channel ──────▶ │    Main Thread      │
│  (one per device)    │  Packet structs    │                     │
│                      │                    │  SIP parse           │
│  pcap_loop() blocks  │                    │  Dialog tracking     │
│  IP/TCP reassembly   │                    │  Filter evaluation   │
│  HEP receive         │                    │  TUI render OR       │
│                      │                    │  CLI output          │
└──────────────────────┘                    └──────┬──────────────┘
                                                   │ (optional)
                                            ┌──────▼──────────────┐
                                            │  Async Runtime      │
                                            │  (tokio, if needed) │
                                            │                     │
                                            │  Prometheus HTTP     │
                                            │  REST API            │
                                            │  WebSocket stream    │
                                            └─────────────────────┘
```

Capture threads own their reassembly state — no shared mutable state between capture threads. Parsed packets are sent to the main thread via a lock-free crossbeam channel. The main thread owns the `DialogStore` and is the only writer. The optional async runtime (if `--metrics` or `--api` is used) reads from the `DialogStore` through a `parking_lot::RwLock` — read-heavy, write-rare, so RwLock contention is minimal.

This eliminates the global `capture_lock` mutex from sngrep that blocked the capture thread during every TUI redraw.

### D6 — Adaptive TUI refresh

sngrep redraws at a fixed 5 Hz (200ms `halfdelay`), rebuilding the filtered call list from scratch on every frame. sipnab uses an event-driven approach:

1. **Data-driven refresh:** The capture→main channel delivers a "new data available" signal. The TUI only redraws when there is actually new data to show.
2. **Incremental filtering:** New dialogs are appended to the filtered list. The full filter is only re-run when the filter expression itself changes.
3. **Adaptive poll timeout:** 100ms when data is flowing, ramps to 500ms after 5 idle cycles, snaps back on keypress. This means near-zero CPU when idle, responsive UI when active.
4. **Visible-row-only rendering:** Only dialogs visible in the current scroll window have their column attributes formatted. A list of 100,000 dialogs with 40 visible rows formats 40 rows, not 100,000.

### D7 — Filter DSL replaces embedded scripting

Embedded scripting runtimes (Lua, Python) introduce unsafe FFI boundaries, sandbox escape risk, and supply chain dependencies disproportionate to their value in a focused protocol analysis tool. sipnab's extensibility model uses three mechanisms instead:

**1. Filter DSL (declarative, not Turing-complete):**

```
sipnab -N --filter "from.user =~ '1001' AND rtp.mos < 3.0"
sipnab -N --filter "method == 'INVITE' AND NOT ua =~ 'friendly-scanner'"
sipnab -N --filter "rtp.orphaned == true AND rtp.packets > 100"
```

The DSL operates over a known set of fields (SIP headers, RTP stream attributes, dialog state). It supports comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`), regex match (`=~`), boolean logic (`AND`, `OR`, `NOT`), and parenthetical grouping. No loops, no variables, no functions, no memory allocation beyond the compiled expression. ~500 lines of safe Rust.

**2. NDJSON pipeline (Unix composability):**

```bash
sipnab -N --json -d eth0 | python3 my_filter.py | jq '.call_id'
sipnab -N --json -d eth0 | grep -E '"mos":\s*[0-2]\.' > bad_quality.json
```

sipnab streams structured data to stdout. Users filter with any language in a separate process with its own permissions. No embedded runtime, no sandbox to escape, no attack surface. If the filter script crashes, sipnab keeps running.

**3. Event exec hooks (process isolation by design):**

```bash
sipnab -N -d eth0 --on-dialog-exec "curl -s -X POST http://hooks.internal/sip -d '%json'"
sipnab -N -d eth0 --on-quality-exec "python3 alert.py '%stream_json'" --quality-threshold 3.0
```

External processes handle complex logic. sipnab's responsibility ends at condition detection, event serialization, and exec. Rate-limited (default: 10 execs/sec) to prevent fork bombs. Executed as the invoking user, not as sipnab.

**Why not WASM?** WASM plugins (wasmtime) provide true sandbox-by-construction and would be the secure path if embedded extensibility is ever needed. But today, the DSL + pipeline + exec model covers the real use cases without adding a WASM runtime dependency. WASM is a v1.x consideration, not v0.x.

### D8 — Security features are passive-first

The scanner kill feature (`--kill-scanner`) sends response packets, which requires either a raw socket or cooperation from the capture interface. This is the **only** active/injection feature. All other security features (fraud detection, digest leak, registration flood) are purely passive analysis — they observe and alert, never inject.

Active response is opt-in, rate-limited (max 10 responses/sec to prevent amplification), isolated in a dedicated child process, and logged. It is never enabled by default.

### D9 — PCAP-NG as the forward-looking format

PCAP-NG supports multiple interfaces per file, nanosecond timestamps, packet comments, and interface metadata — all useful for multi-device capture and annotated analysis. sipnab reads both pcap and pcap-ng by default. The `--pcapng` flag selects pcap-ng for output. Plain pcap remains the default output format for compatibility with older tools.

### D10 — Feature gates keep the binary small

The default build (`cargo install sipnab`) includes only the core: capture, SIP parsing, TUI, CLI output, and JSON. Optional features add weight:

| Feature | Added dependency | Binary size impact |
|---|---|---|
| `tls` | ring or aws-lc-rs, zeroize | ~1 MB |
| `tls-wolfssl` | wolfssl (links libwolfssl) | ~500 KB over tls |
| `tls-openssl` | openssl (links libssl) | ~200 KB over tls |
| `grpc` | tonic, prost | ~2 MB |
| `api` | axum, tokio | ~1.5 MB |

`cargo install sipnab --features full` gets everything. Distro packages ship with `full`. The bare binary for minimal environments (containers, embedded) stays under 5 MB.

### D11 — Key material is toxic waste: handle accordingly

Decryption keys (RSA private keys, TLS session secrets, SRTP master keys) are the most sensitive data sipnab will ever touch. A single leaked key compromises every past and future session it protects. sipnab treats key material with the same discipline as a password manager:

**Memory:** All key material is stored in types that implement the `zeroize` crate's `Zeroize` and `ZeroizeOnDrop` traits. When a key is no longer needed (session ends, sipnab exits), the memory is overwritten with zeros before deallocation. This prevents keys from lingering in freed heap pages, swap, or core dumps.

**Files:** On startup, sipnab checks permissions on any key file (`-k`, `--keylog`, `--srtp-keys`). If the file is world-readable (mode `o+r`), sipnab prints a warning to stderr: `WARNING: key file /path/to/key has insecure permissions (0644), should be 0600`. It does NOT refuse to run — the operator may have a valid reason — but the warning is impossible to miss.

**Logging:** Key material is NEVER logged, even at TRACE level. Log messages reference keys by fingerprint or session ID, never by value. The log line `TLS session decrypted [session=abc123, cipher=TLS_AES_256_GCM_SHA384]` is acceptable. The log line `TLS master secret: 48a7f2...` is a bug.

**Output:** Decrypted SIP payloads appear in CLI output, JSON, TUI, and API responses — that is the purpose of decryption. But the keys themselves never appear in any output channel. The `--json` schema includes `"tls_decrypted": true` as a boolean flag, not the key used. SRTP keys extracted from SDP are used internally but never echoed.

**Pcap export:** When writing decrypted traffic to pcap (`-O`), the user chooses the behavior via `--pcap-export-mode`:
- `decrypted` (default when keys are loaded): write the decrypted SIP/RTP payloads as plaintext UDP packets, so the pcap is immediately usable without keys
- `encrypted+dsb`: write the original encrypted packets plus a Decryption Secrets Block (DSB) in PCAP-NG format, matching Wireshark's `editcap --inject-secrets` behavior. This preserves the original traffic and embeds the keys in the capture file for later analysis.
- `raw`: write original encrypted packets with no keys embedded. Useful for sharing captures without exposing key material.

**API:** The REST API (`--api`) never exposes key file paths, key material, or decryption configuration. Decrypted content is served only if the API consumer authenticated via `--api-key`. The `/v1/dialogs/:id` response includes `"encrypted": false` for decrypted dialogs but no key details.

**Startup banner:** When any decryption feature is active, sipnab prints a one-line banner to stderr:
```
sipnab: TLS decryption active (keyfile loaded). Decrypted traffic visible in output.
```
This makes it obvious in scrollback that decryption was enabled for this session.

### D12 — SRTP decryption is conditional on SIP decryption

SRTP keys are negotiated inside SDP, which is inside SIP. The decryption chain is:

```
TLS → SIP payload (contains SDP) → SDES a=crypto keys → SRTP decryption
```

This means:
1. **Unencrypted SIP + SDES SRTP:** sipnab reads `a=crypto:` from SDP directly. SRTP keys are available without any key file input. This is the most common case on internal networks.
2. **TLS-encrypted SIP + SDES SRTP:** sipnab must first decrypt TLS (via RSA key or keylog file), then read the SDP, then extract SDES keys. SRTP decryption is automatic once TLS is decrypted.
3. **DTLS-SRTP:** Keys are negotiated via DTLS between media endpoints, not in SDP. sipnab would need a DTLS keylog file from the endpoint. This is supported but requires explicit operator action (`--dtls-keylog`).
4. **ZRTP:** End-to-end key agreement in the media path. Cannot be decrypted without endpoint cooperation. sipnab detects ZRTP and displays it as such but does not attempt decryption. This is a non-goal.

sipnab never attempts to break or weaken encryption. It decrypts only when the operator provides legitimate keys they are authorized to possess.

### D13 — RTP is a first-class citizen, not a child of SIP

In every existing SIP analysis tool (sngrep, sipgrep, Homer), RTP is subordinate to SIP: you find a dialog first, then optionally look at its media. This matches the protocol hierarchy (SIP negotiates, RTP carries) but not the debugging reality. Most VoIP problems are RTP problems — one-way audio, quality degradation, orphaned streams, NAT traversal failures — and they often present without a captured SIP dialog in scope.

sipnab treats RTP streams as **top-level entities** that peer with SIP dialogs:

```
DialogStore ──────── stores SipDialog objects, keyed by Call-ID
StreamStore ──────── stores RtpStream objects, keyed by SSRC + src:port + dst:port
    │
    └── cross-referenced: a dialog links to its streams, a stream links to its dialog (if any)
```

**Consequences of this design:**

1. **RTP capture is on by default.** The `-r` flag from sngrep is inverted: sipnab captures RTP unless `--no-rtp` is specified. The performance cost is negligible — RTP header parsing is 12 bytes of fixed-format data.

2. **Orphaned streams are visible.** An RTP stream with no matching SIP dialog (because SIP went through a different path, or the capture started mid-call) appears in the Stream List view and in JSON output. sngrep makes these invisible.

3. **RTP discovery does not require SDP.** SDP tells sipnab where media *should* go. Heuristic detection finds where media *actually* goes — even-port UDP with RTP v2 header structure, valid payload type, incrementing sequence numbers. After NAT, after RTPEngine, after any middlebox that rewrites media addresses, the actual stream is discoverable.

4. **RTCP is parsed.** Sender Reports (SR) and Receiver Reports (RR) contain the remote side's quality experience. RTCP XR (RFC 3611) carries MOS, burst loss metrics, and round-trip delay. Ignoring RTCP means seeing only half the quality picture.

5. **Quality is per-interval, not per-call.** A call averaging 20ms jitter might have a 3-second burst at 200ms that caused the user to hang up. sipnab records quality metrics per configurable interval (default: 1 second) so the shape of degradation is visible, not just the average.

6. **The TUI has a Stream List view** alongside the Call List, switchable via Tab or keybinding. Columns: SSRC, codec, source, destination, packets, jitter, loss, MOS, duration, associated dialog (or "orphaned"), encryption status (RTP/SRTP/ZRTP).

### D14 — Pluggable crypto backend: pure Rust default, wolfSSL and OpenSSL optional

sipnab does not establish TLS connections — it passively decrypts captured traffic. It needs cryptographic primitives (AES-GCM, AES-CBC, ChaCha20-Poly1305, HMAC, RSA, HKDF, SRTP AES-CM) and TLS/DTLS record layer parsing, not a full handshake stack.

A `CryptoBackend` trait abstracts the primitives:

```rust
trait CryptoBackend: Send + Sync {
    fn aes_gcm_decrypt(&self, key: &[u8], nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn aes_cbc_decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn rsa_decrypt(&self, key: &RsaPrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn hkdf_expand(&self, prk: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>;
    fn srtp_decrypt(&self, key: &SrtpKey, header: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn hmac_sha1(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>>;
}
```

Three implementations, selected by feature flag:

| Backend | Feature flag | System dep | Binary impact | Best for |
|---|---|---|---|---|
| **Pure Rust** | `--features tls` (default) | None | ~1 MB (ring/aws-lc-rs) | `cargo install`, containers, portability, zero system deps |
| **wolfSSL** | `--features tls-wolfssl` | libwolfssl | ~500 KB | FIPS 140-3 compliance, government VoIP (CEE-2026-05), Jetson/embedded, first-class DTLS |
| **OpenSSL** | `--features tls-openssl` | libssl-dev | ~200 KB (dynamic link) | Systems where OpenSSL is already present, PEM key compat |

The TLS record parser and SSLKEYLOGFILE parser are backend-agnostic — they parse bytes and hand ciphertext + keys to whichever backend is compiled in. If multiple backends are compiled, runtime selection via config: `[crypto] backend = "wolfssl"`.

**Why wolfSSL deserves first-class support for this project:**
- FIPS 140-3 certified — required for government and carrier deployments
- Best-in-class DTLS implementation — critical for DTLS-SRTP decryption path
- ~100 KB footprint vs ~2 MB for OpenSSL — meaningful on Jetson AGX Thor
- Maintained Rust bindings via the `wolfssl` crate

### D15 — Privilege separation: drop early, drop hard

sipnab starts as root (or with CAP_NET_RAW) to open capture devices and bind privileged ports. Privileges are dropped **before processing any packets** — the moment all resources requiring elevated access are acquired.

```
Startup (root / CAP_NET_RAW)
  ├── Open capture device(s)
  ├── Open key files (read into memory, mlock)
  ├── Bind API/metrics ports (if configured)
  │
  ├── PRIVILEGE DROP POINT ◄── before any packet processing
  │
  ├── setgroups([])                       — drop supplementary groups
  ├── setgid(sipnab/nobody)              — drop to unprivileged group
  ├── setuid(sipnab/nobody)              — drop to unprivileged user
  ├── prctl(PR_SET_NO_NEW_PRIVS, 1)     — Linux: prevent regaining privs
  │
  └── Begin packet processing (unprivileged)
```

The drop-to user is configurable via `--user <name>` (default: `sipnab` if it exists, else `nobody`). `--no-priv-drop` disables this for development/debugging. `--chroot <dir>` is available for paranoid daemon deployments.

**Exception: scanner kill.** `pcap_inject()` requires the capture fd to remain writable. This is handled by D16 (process isolation).

### D16 — Process isolation for dangerous operations

Scanner kill (packet injection) and the REST API (network-facing service) run in isolated child processes, not in the main packet processing loop. This limits blast radius: a vulnerability in the API handler or an exploit via crafted scanner-kill responses cannot compromise the capture/parse pipeline.

**Daemon mode (`--api`) process architecture:**

```
┌──────────────────────────────────────────────────────────────┐
│  Main Process (unprivileged after priv drop)                 │
│  ├── Capture thread(s) → crossbeam → Main thread             │
│  ├── SIP/RTP parsing, dialog tracking, filtering             │
│  └── Unix socket pair → children                             │
├──────────────────────────────────────────────────────────────┤
│  API Child (unprivileged, no capture fd)                     │
│  ├── axum HTTP/WS server                                     │
│  ├── Reads dialog/stream data via IPC from main              │
│  ├── Cannot capture packets or inject traffic                │
│  └── Crash here does NOT affect capture pipeline             │
├──────────────────────────────────────────────────────────────┤
│  Scanner Kill Child (holds capture fd, optional)             │
│  ├── Receives kill requests via Unix socket from main        │
│  ├── Validates: was source IP actually observed in capture?  │
│  ├── Rate limits: 10/sec enforced independently              │
│  ├── Rejects broadcast/multicast targets                     │
│  └── Single-purpose: inject only, cannot read captured data  │
└──────────────────────────────────────────────────────────────┘
```

For non-daemon mode (TUI or CLI), single process is acceptable — the API surface isn't network-exposed. The scanner kill child is the only separation that always applies when `--kill-scanner` is active.

IPC mechanism: Unix socket pair with serde-serialized messages. Designed in Phase 2 (even if scanner-kill child ships in Phase 4 and API child in Phase 6) so the interface is stable.

### D17 — Defense-in-depth input validation

Every data store and input path has explicit resource limits to prevent denial-of-service against sipnab itself:

| Resource | Default Limit | Override | Behavior on Overflow |
|---|---|---|---|
| IP fragment reassembly entries | 10,000 | `--max-reassembly` | Drop oldest, log WARN, increment metric |
| TCP reassembly entries | 10,000 | `--max-reassembly` | Same |
| Assembled message size | 64 KB | — | Drop, log WARN |
| Reassembly entry TTL | 30 seconds | — | Swept every 5s |
| DialogStore entries | 100,000 | `-l <limit>` (`-l 0` = unlimited) | Rotate oldest, log INFO |
| StreamStore entries | 50,000 | `--max-streams` (`0` = unlimited) | Rotate oldest, log INFO |
| SIP message size | 64 KB | — | Drop, log WARN |
| Regex filter compiled size | 1 MB | — | Reject at parse time with clear error |
| HEP input rate | 50,000 msgs/sec | `--hep-rate-limit` | Drop silently, increment metric |
| API concurrent connections | 100 | `--api-max-conn` | Reject with 503 |
| API request body size | 1 MB | — | Reject with 413 |
| Event exec rate | 10/sec | `--exec-rate-limit` | Drop event, log WARN |
| Filter DSL expression depth | 50 nesting levels | — | Reject at parse time |

### D18 — Localhost-default for all network listeners

Every network-facing listener in sipnab binds to `127.0.0.1` by default. Binding to a non-loopback interface requires the operator to explicitly specify the address. This prevents accidental exposure of sensitive endpoints.

| Listener | Default Bind | Explicit Non-Local |
|---|---|---|
| HEP (`-L`) | `127.0.0.1:9060` | `-L 0.0.0.0:9060` |
| Prometheus (`--metrics`) | `127.0.0.1:9100` | `--metrics 0.0.0.0:9100` |
| REST API (`--api`) | `127.0.0.1:8080` | `--api 0.0.0.0:8080` |

When binding to a non-loopback address **without TLS**, sipnab prints a warning:
```
WARNING: API listening on 0.0.0.0:8080 without TLS. Traffic is unencrypted.
```

### D19 — Decryption material isolation

Key material has a strict lifecycle with explicit state transitions and isolation guarantees:

```
KeyMaterial<Loaded>     — read from file, validated, in zeroize-backed memory
    │
    ▼
KeyMaterial<Active>     — associated with a TLS/SRTP session, in use
    │
    ▼
KeyMaterial<Expired>    — session ended, zeroed immediately (not deferred to GC/drop)
```

**Isolation constraints:**
- Key material never crosses IPC boundaries. Child processes (API, scanner kill) receive boolean flags ("this dialog was decrypted"), never key data.
- No key material in core dumps. When any decryption flag is active: `prctl(PR_SET_DUMPABLE, 0)` on Linux. `--allow-coredump` flag available for debugging.
- Key files loaded via `mmap` + `mlock` to prevent swapping to disk. `munmap` + `madvise(MADV_DONTNEED)` on cleanup. Falls back to normal read if `mlock` fails (non-root without `RLIMIT_MEMLOCK`), with a warning.
- Decryption audit counter: atomic counter of sessions decrypted, exposed via Prometheus (`sipnab_decryption_sessions_total`) and API (`GET /v1/stats`). Security teams can monitor decryption usage without seeing key material.

### D20 — VoIP diagnosis is built-in, not bolted-on

Existing SIP tools show you packets. Diagnosing *why a call failed* or *why there's one-way audio* requires the engineer to mentally correlate SDP offers/answers, NAT translations, RTP flow direction, transaction timing, and error codes. sipnab automates the correlations that experienced VoIP engineers do in their heads:

1. **SIP transaction timing** is computed automatically for every dialog: PDD, setup time, ring duration, per-hop latency from Via headers. No flags needed — timing is always tracked.
2. **One-way audio detection** runs continuously when RTP is active: if a dialog has been in `InCall` state for >5 seconds with RTP flowing in only one direction, it's flagged. The diagnosis engine checks NAT mismatch (SDP c= vs actual source), firewall symptoms (SDP negotiated but zero packets), and asymmetric media (one side sending only CN/comfort noise).
3. **NAT mismatch detection** compares SDP `c=`/`m=` against observed RTP source for every stream. The mismatch is annotated on the stream, the dialog, the ladder diagram, and the JSON output. This is the single most common cause of one-way audio.
4. **SIP response code intelligence** maps every final response to a human-readable explanation with common causes. The engineer sees `488 Not Acceptable Here — Codec negotiation failed. Check SDP offer vs callee's allowed codecs.` instead of just `488`.
5. **SDP negotiation timeline** tracks every offer/answer exchange within a dialog and labels events: HOLD, RESUME, CODEC CHANGE, T.38 SWITCH, MEDIA ANCHOR CHANGE. Mid-call changes are where subtle bugs hide.

These features require no flags to activate — they are always computed. The diagnostic data is available in the TUI, CLI output, JSON, and call reports.

### D21 — Multi-leg correlation makes B2BUA debugging tractable

In production VoIP, nearly every call traverses at least one B2BUA (OpenSIPS, Oasis, FreeSWITCH, SBC). The B2BUA creates a new Call-ID for the outbound leg, rewrites headers, and may anchor media. Debugging requires correlating inbound and outbound legs — without this, the engineer sees two unrelated calls.

sipnab correlates legs automatically using a priority chain:
1. **X-Call-ID / X-CID header** — explicitly set by the B2BUA (OpenSIPS, Oasis)
2. **Via branch parameter** — matches if both legs pass through the same proxy
3. **Timing + identity heuristic** — INVITE on leg B within 500ms of INVITE on leg A, matching From or To user
4. **Manual linking** — TUI: select two dialogs → "Link as A-leg/B-leg"

Correlated legs are displayed as a unified multi-column ladder diagram in the TUI, with the B2BUA as a middle column. SDP diffs between legs highlight what the B2BUA changed. This is the whiteboard diagram every VoIP engineer draws — sipnab draws it automatically.

---

## Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| R1 | libpcap API differences across OS (Linux/macOS/FreeBSD) | High | Medium | Test on all three in CI from Phase 1. Pin `pcap` crate version. Document minimum libpcap version. |
| R2 | etherparse doesn't handle an encapsulation type (GRE, IP-in-IP, QinQ) | Medium | Medium | Verify in Phase 1.3; manual parsing fallback for unsupported types. |
| R3 | pcap-file crate bugs with PCAP-NG edge cases | Medium | High | Fuzz pcap-file early. Fallback: raw pcap output always works. |
| R4 | TCP reassembly correctness (out-of-order, overlaps, resets) | High | High | Budget extra time in Phase 1. Wireshark's reassembly as reference. Regression suite of pathological TCP pcaps from day one. |
| R5 | Rust `regex` crate lacks lookahead/lookbehind | Low | Medium | Document limitation. Consider `fancy-regex` as optional backend for complex patterns. |
| R6 | ratatui breaking API changes (pre-1.0) | Medium | Medium | Pin version in Cargo.toml. Track changelog. |
| R7 | Single-developer bus factor | High | Critical | MVP milestones create contribution entry points. Strong architecture documentation. CONTRIBUTING.md shipped early (Phase 1, not Phase 7). |
| R8 | Scope creep via "just one more feature" | High | High | Freeze scope after plan approval. New ideas → `backlog.md`. |
| R9 | Performance targets missed (100K SIP pps, 500K RTP pps) | Medium | Medium | Benchmark after Phase 2.1 (SIP parser), not at phase end. If miss by >2x, re-evaluate zero-copy strategy before building more on top. |
| R10 | CVE in a critical dependency (pcap, etherparse, crossterm) | Medium | High | cargo-audit in CI. Have a mitigation path: vendor the crate if upstream is slow to patch. |
| R11 | Real-world SIP traffic breaks assumptions (encoding, malformed headers, non-standard extensions) | High | Medium | "Warn and continue" error philosophy. Capture real production pcaps early for testing. |

---

## Performance & Memory Targets

These are measurable targets, not aspirations. Phase 1 and Phase 2 exit criteria include benchmarks against these numbers.

| Metric | Target | How measured |
|---|---|---|
| Packets/sec throughput (parse + filter, no TUI) | ≥ 100,000 pps | `sipnab -N -q -I large.pcap` on single core x86_64 ≥ 2.5 GHz, wall time. criterion benchmark in CI. |
| RTP packets/sec throughput | ≥ 500,000 pps | RTP-heavy pcap, same measurement method |
| Dialogs in memory (100K dialogs, 5 msgs each) | ≤ 500 MB RSS | `/proc/self/status` VmRSS, sampled at 10K-dialog intervals, growth < 1% between 50K and 100K |
| Streams in memory (50K streams, 300s quality history each) | ≤ 200 MB RSS | Same |
| TUI redraw latency (100K dialogs, 40 visible rows) | ≤ 5 ms per frame | Keypress-to-render measured via crossterm event timestamp to frame completion |
| Idle CPU (TUI open, no traffic) | < 0.5% of one core | `top` / `pidstat`, 60s sample |
| Startup to first packet captured | ≤ 100 ms | Measure from exec to first pcap callback |
| Static binary size (default features, musl, stripped) | ≤ 5 MB | `ls -la target/release/sipnab` |
| Static binary size (full features, musl, stripped) | ≤ 10 MB | Same (reduced from v5's 12 MB by removing Lua) |
| Transaction timing overhead | < 1µs per dialog update | Benchmark: process 100K dialogs, measure timing computation overhead vs baseline |
| One-way audio detection latency | ≤ 6s after call establishment | Time from 200 OK to one-way-audio flag when RTP is unidirectional |

---

## Error Handling Strategy

SIP in the wild is messy. Carriers send malformed headers. TCP segments arrive out of order. Pcap files get truncated. sipnab must handle all of this without crashing, panicking, or silently dropping data.

### Principle: warn and continue, never crash on input

- **Malformed SIP:** If a packet looks like SIP (first line matches) but headers are unparseable, store it as a raw message with `parse_error: true`. The TUI shows it in the call flow with a warning badge. It counts in statistics. It is never silently dropped.
- **Truncated packets:** If a pcap frame is shorter than its declared length, parse what is available and mark the message as truncated. Log at DEBUG level.
- **Invalid UTF-8 in SIP payload:** SIP is supposed to be UTF-8 but real-world traffic includes Latin-1, Windows-1252, and raw bytes. The parser operates on `&[u8]` and uses `String::from_utf8_lossy` for display. Matching operates on bytes, not decoded strings.
- **Reassembly overflow:** If IP fragments or TCP segments exceed 64KB assembled size, discard and log at WARN. The reassembly entry is removed and its memory freed (this is the bug sngrep had — MEM-3).
- **Reassembly timeout:** Stale entries (no new fragment/segment for 30s) are swept every 5s and dropped. This prevents the unbounded memory growth from sngrep's MEM-5.
- **Pcap read errors:** Log at ERROR, skip the packet, continue reading. A single corrupt frame does not abort the capture.
- **Permission errors:** If the capture device cannot be opened, print a clear error ("run with sudo or add CAP_NET_RAW") and exit non-zero. Do not silently fall back to a different device.

### Rust error types

- `anyhow::Result` for application-level errors (CLI parsing, config loading, file I/O)
- `thiserror` derive for domain-specific error enums (`CaptureError`, `ParseError`, `FilterError`)
- No `.unwrap()` on external input. Every `unwrap()` in the codebase must be preceded by a comment explaining why it is safe, or replaced with `?` / `.unwrap_or()` / `match`.

---

## Testing Strategy

Testing is not a phase — every phase includes its own tests. This section defines the testing types used across all phases.

### Testing Pyramid

| Level | What | When | Tool |
|---|---|---|---|
| **Unit tests** | Parser correctness, state machine transitions, quality calculations, DSL evaluation | Every module, from Phase 1 | `#[cfg(test)]` in each file |
| **Integration tests** | End-to-end: pcap file in → JSON out, validate content | Phase 2 onward | `tests/` directory, real pcap fixtures |
| **Fuzz tests** | Crash discovery in parsers and reassembly | **Phase 1 onward** (not deferred) | `cargo-fuzz`, 1 hour per CI run, 24h before each release milestone |
| **Property tests** | Invariants: "any valid SIP message round-trips through parser," "jitter is always ≥ 0" | Phase 2 onward | `proptest` or `quickcheck` |
| **Performance tests** | Throughput benchmarks against targets, regression detection | Phase 1 and 2 exit, then CI | `criterion` benchmarks, fail on >10% regression |
| **Comparison tests** | Same pcap through sipnab vs sngrep/sipgrep, diff outputs | Phase 2 onward | Custom test harness, sngrep installed in CI |
| **Security tests** | Malformed input corpus, oversized messages, hash flooding, ReDoS patterns, scanner-kill amplification | Phase 2 onward | Dedicated `tests/security/` directory |
| **TUI snapshot tests** | Render views to TestBackend buffer, snapshot with `insta`, detect layout/color regressions | Phase 3 onward | `ratatui::backend::TestBackend` + `insta` crate |
| **TUI state machine tests** | Key events → App state transitions, navigation, filter application, selection | Phase 3 onward | Unit tests on `App` struct, no terminal needed |
| **TUI end-to-end tests** | Spawn binary in PTY, send keystrokes, verify terminal output | Phase 3 onward | `expectrl` crate, ~2s/test |

### Pcap Test Corpus (≥ 50 pcaps, built incrementally)

Basic calls, REGISTER, SUBSCRIBE/NOTIFY, forked calls, fragmented IP, TCP SIP, TLS SIP, WebSocket SIP, HEP, malformed messages, scanner traffic, STIR/SHAKEN Identity headers, RFC 4733 DTMF, codec negotiation edge cases, orphaned RTP streams (no SIP in capture), RTP with quality degradation (jitter bursts, packet loss), RTCP SR/RR/XR reports, SRTP with SDES keys in SDP, one-way audio scenarios (RTP in one direction only), RTPEngine-rewritten media addresses, comfort noise (CN) and silence suppression.

---

## Dependency Audit Strategy

Added to Phase 1.1 project scaffold and enforced in CI from day one.

- **`cargo-audit`** — fail CI on known vulnerabilities in dependencies.
- **`cargo-deny`** — enforce GPLv3 license compatibility, reject duplicate dependencies, ban specific crates.
- **`cargo-geiger`** — audit `unsafe` usage in dependency tree. Report, don't block (some FFI crates require unsafe).
- **`Cargo.lock` committed** to git. sipnab is a binary, not a library.
- **Dependency review checklist** for any new dependency added after Phase 1:
  1. Is it maintained? (Last commit < 6 months)
  2. Does it have known advisories? (`cargo audit`)
  3. Does it use `unsafe`? (`cargo geiger`)
  4. Is the license GPLv3-compatible?
  5. Can we vendor it if it's abandoned?

---

## Configuration File Format

TOML. Readable, well-specified, native Rust support. Config file locations (first match wins):

1. `--config <path>` (explicit)
2. `$SIPNAB_CONFIG` (environment variable)
3. `~/.config/sipnab/sipnab.toml`
4. `~/.sipnabrc` (legacy convenience)
5. `/etc/sipnab/sipnab.toml` (system-wide)

```toml
[capture]
device = "eth0"
portrange = "5060-5061"
buffer_mb = 2
snaplen = 65535
rtp = true                      # RTP on by default (D13)

[display]
only_calls = false
autoscroll = true
columns = ["index", "method", "from", "to", "src", "dst", "state", "msgs", "time"]

[filter]
# Default filter applied on startup
from = ""
to = ""

[security]
scanner_patterns = ["friendly-scanner", "sipvicious", "sipcli", "sipsak"]
reg_flood_threshold = 50

[limits]
max_dialogs = 100000
max_streams = 50000
max_reassembly = 10000
hep_rate_limit = 50000
exec_rate_limit = 10
api_max_connections = 100

[privilege]
user = "sipnab"                 # drop-to user after device open
chroot = ""                     # chroot dir (empty = disabled)

[theme]
# sngrep-compatible color defaults
highlight = "white_on_blue"
invite = "green"
bye = "red"
error = "red_bold"

[keybindings]
# Override defaults
quit = "q"
filter = "F7"
save = "F2"
```

sngrep's `~/.sngreprc` format is NOT supported. A migration note in the README explains the differences.

---

## Release Milestones

Three release milestones replace the monolithic march to v0.1.0. Each milestone is independently useful and creates a feedback loop.

| Milestone | Scope | Content | Target |
|---|---|---|---|
| **v0.1.0-alpha** — "sipgrep replacement + VoIP diagnosis" | Phases 1 + 2 | CLI mode: capture, parse, filter, filter DSL, `--json`, `--report`, `--call-report`, RTP stream tracking, transaction timing/PDD, one-way audio detection, NAT mismatch detection, multi-leg correlation, SDP timeline, concurrent call tracking, diagnostic filter aliases, event exec hooks. No TUI, no security features, no decryption, no API. | 9-12 weeks |
| **v0.2.0-beta** — "sngrep replacement" | + Phase 3 + Phase 4 | Interactive TUI with diagnosis indicators and multi-leg ladder, scanner detection/kill, fraud alerting, digest leak detection, fail2ban output. | 15-20 weeks |
| **v0.3.0** — "full vision" | + Phase 5 + Phase 6 + Phase 7 | TLS/SRTP decryption, Prometheus (with PDD/timing/concurrent call metrics), STIR/SHAKEN, REST API, daemon mode, packaging. | 24-35 weeks |

**Why milestones matter:**
- v0.1.0-alpha is usable on day one for the most common VoIP engineering tasks: "show me the SIP on this interface, filtered by caller, with RTP quality, tell me why this call failed, find the one-way audio, show me what the SBC changed."
- The `--call-report` and `--problems` flags alone make v0.1.0-alpha more useful than sipgrep for troubleshooting.
- Early users find parser bugs before a TUI is built on top.
- Each milestone has its own GitHub release, changelog, and can attract contributors.
- Motivation: external validation before the halfway point.

---

## Phase Dependencies

```
Phase 1 ─────────► Phase 2 ─────────► Phase 3 (TUI)
(Capture)          (SIP + CLI)              │
                        │                    │
                        ├──────────► Phase 4 (Security)
                        │                    │
                        └──────────► Phase 5 (Analysis)
                                             │
                                     Phase 6 (API)
                                             │
                                     Phase 7 (Release)
```

- Phase 1 must complete before anything else — all other phases depend on the capture engine.
- Phase 2 must complete before Phase 3, 4, 5 — they all need the SIP parser and dialog store.
- Phases 3, 4, and 5 can be developed in parallel once Phase 2 is done. They share the dialog store as readers but do not depend on each other.
- Phase 6 depends on Phase 2 (API exposes dialogs) but not on Phase 3/4/5.
- Phase 7 depends on all prior phases.
- **Testing is not a phase.** Every phase includes its own exit criteria and required tests. Phase 7 adds cross-cutting tests (fuzzing, benchmarks, comparison) but does not introduce testing for the first time.
- **Fuzz testing starts in Phase 1.** Do not wait for Phase 7.

---

## CLI Design — Unified Flag Set

sipnab accepts **all** sngrep flags and **all** sipgrep flags. When invoked without `-N`, it launches the TUI. With `-N`, it operates in CLI print mode like sipgrep.

### sngrep-compatible flags

| Flag | Description |
|---|---|
| `-d <dev>` | Capture device (comma-separated for multi-device) |
| `-I <pcap>` | Read from pcap/pcap-ng file |
| `-O <pcap>` | Write matched packets to pcap |
| `-B <mb>` | Pcap buffer size in MB |
| `-c` | Only INVITE dialogs |
| `-r` | Accepted for sngrep compat (no-op: RTP is captured by default). Use `--no-rtp` to disable |
| `-l <limit>` | Dialog limit (default: 100,000) |
| `-i` | Case-insensitive match |
| `-v` | Invert match |
| `-N` | No TUI — CLI output mode |
| `-q` | Quiet (no dialog count in -N mode) |
| `-R` | Rotate dialogs when limit reached |
| `-D` | Dump config and exit |
| `-f <file>` | Read config from file |
| `-F` | Skip default config file |
| `-k <keyfile>` | TLS RSA private key file |
| `-H <url>` | HEP send destination |
| `-L <url>` | HEP listen address (default bind: 127.0.0.1) |
| `-E` | Enable HEP parsing |
| `-T <file>` | Text dump to file |
| `-t` | Capture telephone-event RTP |

### sipgrep-compatible flags

| Flag | Description |
|---|---|
| `--from <pattern>` | Match From header user (sipgrep `-f`) |
| `--to <pattern>` | Match To header user (sipgrep `-t`) |
| `--contact <pattern>` | Match Contact header (sipgrep `-c`) |
| `--ua <pattern>` | Match User-Agent header (sipgrep `-j`) |
| `--kill-scanner` | Auto-respond 200 to friendly-scanner (sipgrep `-J`). Launches isolated child process (D16). |
| `--kill-ua <name>` | Kill scanner with custom UA match (sipgrep `-j` + `-J`) |
| `--kill-response <code>` | Response code for kill mode (default: 200) |
| `--report` | Print dialog report on exit (sipgrep `-G`) |
| `--dialog-track` | Enable dialog tracking in CLI mode (sipgrep `-g`) |
| `--replay` | Replay pcap with original timing (sipgrep `-D`) |
| `--delta-time` | Print delta timestamps (sipgrep `-T`) |
| `--after <n>` | Print N trailing context packets after match (sipgrep `-A`) |
| `--autostop <cond>` | Stop after condition: `duration:N` or `filesize:N` (sipgrep `-q`) |
| `--split <cond>` | Rotate pcap output: `duration:N` or `filesize:N` (sipgrep `-Q`) |
| `--portrange <range>` | SIP port range (default: 5060-5061) (sipgrep `-P`) |
| `--word` | Word-regex match (sipgrep `-w`) |
| `--line-buffer` | Line-buffered stdout (sipgrep `-l`) |
| `--single-line` | Single-line match mode (sipgrep `-M`) |
| `--no-dialog` | Disable dialog matching (sipgrep `-m`) |
| `--show-empty` | Show empty packets (sipgrep `-e`) |
| `--snaplen <n>` | Set capture snaplen (sipgrep `-s`) |
| `--payload-limit <n>` | Max payload display size (sipgrep `-S`) |
| `--bpf-file <file>` | Read BPF filter from file (sipgrep `-F`) |
| `--duration <secs>` | Capture for N seconds then exit (sipgrep `-z`) |
| `--count <n>` | Capture N packets then exit (sipgrep `-n`) |

### sipnab new flags

| Flag | Description |
|---|---|
| `--filter <expr>` | Filter DSL expression (see D7): `"from.user =~ '1001' AND rtp.mos < 3.0"` |
| `--json` | JSON output per dialog/message (NDJSON to stdout) |
| `--json-pretty` | Pretty-printed JSON output |
| `--metrics <addr:port>` | Prometheus metrics HTTP endpoint (default bind: 127.0.0.1) |
| `--metrics-auth <user:pass>` | Basic auth for metrics endpoint |
| `--api <addr:port>` | REST/gRPC API daemon mode (default bind: 127.0.0.1) |
| `--api-key <key>` | API authentication key |
| `--api-tls-cert <path>` | TLS certificate for API endpoint |
| `--api-tls-key <path>` | TLS private key for API endpoint |
| `--fail2ban` | Output in fail2ban-parseable format |
| `--wireshark` | Print Wireshark display filters for matched dialogs |
| `--tshark-filter` | Translate matched dialogs into tshark display filter syntax for copy-paste |
| `--stir-shaken` | Decode and display STIR/SHAKEN Identity headers |
| `--fraud-detect` | Enable toll fraud / IRSF heuristic detection |
| `--reg-flood <threshold>` | Alert on registration flood (N regs/sec from same source) |
| `--digest-leak` | Detect SIP digest authentication vulnerabilities |
| `--alert <rule>` | Alerting rule (repeatable): `5xx-rate:10/min`, `reg-flood:50/sec`, etc. |
| `--alert-exec <cmd>` | Execute command on alert (template: `%src`, `%method`, `%reason`) |
| `--on-dialog-exec <cmd>` | Execute command on new/updated dialog (template: `%json`) |
| `--on-quality-exec <cmd>` | Execute command on quality degradation (template: `%stream_json`) |
| `--quality-threshold <mos>` | MOS threshold for `--on-quality-exec` (default: 3.0) |
| `--exec-rate-limit <n>` | Max event exec invocations per second (default: 10) |
| `--multi-device` | Capture from all listed devices simultaneously |
| `--no-rtp` | Disable RTP/RTCP capture and analysis (RTP is on by default) |
| `--rtp-interval <secs>` | Quality metrics interval in seconds (default: 1) |
| `--pcapng` | Use PCAP-NG format for input/output |
| `--tag <label>` | Tag/bookmark matched dialogs for later review |
| `--color <mode>` | Color mode: auto, always, never |
| `--user <name>` | Drop privileges to this user after device open (default: sipnab or nobody) |
| `--no-priv-drop` | Don't drop privileges after opening capture |
| `--chroot <dir>` | Chroot to directory after device open (daemon mode) |
| `--hexdump` | Raw hex+ASCII packet dump (replaces tcpdump for quick "is anything arriving" checks) |
| `--syslog` | Send alerts and security events to syslog (facility local0) |
| `--keylog <file>` | TLS key log file (NSS SSLKEYLOGFILE format) for TLS 1.2 DHE/ECDHE and TLS 1.3 |
| `--keylog-watch` | Watch keylog file for new keys in real-time (live SSLKEYLOGFILE tailing) |
| `--dtls-keylog <file>` | DTLS key log file for DTLS-SRTP media decryption |
| `--srtp-keys <file>` | Manual SRTP key file for testing (format: `ssrc=N key=base64`) |
| `--pcap-export-mode <m>` | When decryption active: `decrypted` (default), `encrypted+dsb`, `raw` |
| `--allow-coredump` | Allow core dumps even when decryption is active (debugging only) |
| `--hep-allow <cidr>` | HEP source IP allowlist (repeatable, default: accept all on localhost) |
| `--max-reassembly <n>` | Max reassembly table entries (default: 10,000) |
| `--max-streams <n>` | Max RTP stream entries (default: 50,000; 0 = unlimited) |
| `--call-report <call-id>` | Generate structured diagnosis report for a specific call |
| `--markdown` | Use Markdown format for `--call-report` output |
| `--problems` | Show only calls with detected issues (diagnostic filter alias) |
| `--slow-setup` | Show only calls with PDD > 3 seconds |
| `--short-calls` | Show only calls with duration < 5 seconds (wangiri pattern) |
| `--one-way` | Show only calls with one-way audio detected |
| `--nat-issues` | Show only calls with SDP/actual media address mismatch |
| `--group-by <field>` | Group concurrent call counts by field: `src.ip`, `dst.ip` |

---

## Phase 1 — Capture Engine & Packet Parsing

**Goal:** Raw packet capture, IP/TCP reassembly, pcap I/O, privilege separation.
**Milestone:** `sipnab -N -d eth0 --count 100` captures 100 packets and exits (as unprivileged user after priv drop).
**Release target:** Contributes to v0.1.0-alpha.

**Exit criteria — Phase 1 is done when:**
- [ ] Live capture from a device works with BPF filters
- [ ] Pcap file reading works (standard pcap and pcap-ng)
- [ ] Pcap writing works with `--split` rotation
- [ ] IP fragment reassembly passes test suite (fragmented INVITE pcap)
- [ ] TCP segment reassembly passes test suite (segmented SIP pcap)
- [ ] Reassembly TTL eviction verified: stale entries freed after 30s
- [ ] Reassembly table respects max entries cap (default 10,000); overflow logged
- [ ] `--count`, `--duration`, `--autostop` all terminate cleanly
- [ ] SIGINT/SIGTERM produce clean shutdown with no leaked file descriptors
- [ ] Privilege drop works: process runs as unprivileged user after device open (verified via `/proc/self/status` Uid)
- [ ] `--no-priv-drop` correctly skips privilege drop
- [ ] Memory: 1M packets processed with stable RSS (growth < 1% between packet 500K and 1M, sampled at 100K intervals)
- [ ] Throughput: ≥ 200K raw packets/sec from pcap file on single core x86_64 ≥ 2.5 GHz
- [ ] Fuzz testing: `cargo-fuzz` on packet parser and TCP reassembly for ≥ 1 hour with no crashes
- [ ] CI passes on Linux x86_64 and macOS (FreeBSD added in Phase 7)

### 1.1 — Project Scaffold & CI

- [ ] Initialize cargo workspace
- [ ] `Cargo.toml` with all planned dependencies and feature flags
- [ ] `cli.rs` with full unified flag set via `clap` derive macros
- [ ] `config.rs` — config file parsing (`~/.config/sipnab/sipnab.toml`, `/etc/sipnab/sipnab.toml`)
- [ ] Logging setup (`SIPNAB_LOG=debug`)
- [ ] Signal handling (SIGTERM, SIGINT, SIGUSR1 for pcap rotation)
- [ ] **CI pipeline (GitHub Actions):**
  - `cargo build`, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`
  - `cargo audit` (fail on known vulnerabilities)
  - `cargo deny check` (license compatibility, duplicate deps)
  - Linux x86_64 + macOS runners
- [ ] **`Cargo.lock` committed** to git
- [ ] **CONTRIBUTING.md** — contribution guide, build instructions, test instructions (shipped early, not deferred to Phase 7)
- [ ] **`deny.toml`** — cargo-deny configuration for license and advisory checks

**Gate — 1.1 is done when:**
- [ ] `cargo build` succeeds with no warnings
- [ ] `cargo test` passes (scaffold tests: CLI parsing, config loading, env logger init)
- [ ] `cargo clippy -- -D warnings` clean
- [ ] `cargo fmt --check` passes
- [ ] `cargo audit` reports no known vulnerabilities
- [ ] `cargo deny check` passes (license + advisory)
- [ ] Config file loads from all 5 locations (explicit, env, ~/.config, ~/.sipnabrc, /etc) with correct priority
- [ ] Unknown config keys produce a warning, not a silent ignore
- [ ] `SIPNAB_LOG=trace` produces log output; `SIPNAB_LOG=off` produces none
- [ ] SIGINT, SIGTERM, SIGUSR1 handlers fire correctly (verified via unit test with signal delivery)
- [ ] CI pipeline green on Linux x86_64 and macOS

**Docs — 1.1 deliverables:**
- [ ] `README.md` — initial: project description, build instructions, license, "under development" notice
- [ ] `CONTRIBUTING.md` — build from source, run tests, code style, PR process
- [ ] `SECURITY.md` — vulnerability reporting process (email, GPG key, disclosure timeline)
- [ ] Inline rustdoc on all public types and functions in `cli.rs` and `config.rs`
- [ ] `docs/cli-reference.md` — full unified flag set with descriptions (generated from clap derive if possible, manually maintained otherwise)
- [ ] `docs/config-reference.md` — all config file keys, types, defaults, and descriptions
- [ ] `man/sipnab.1` — man page skeleton with NAME, SYNOPSIS, DESCRIPTION, OPTIONS (populated as flags are implemented)

### 1.2 — Packet Capture Sources

- [ ] `capture::live` — live device capture via `pcap` crate
  - BPF filter support
  - Configurable snaplen, buffer size, promiscuous mode
  - Port range filtering (`--portrange`)
  - Multi-device capture (`--multi-device`)
  - **Privilege drop after device open** (D15):
    - `setgroups([])`, `setgid`, `setuid` to `--user` target
    - `prctl(PR_SET_NO_NEW_PRIVS, 1)` on Linux
    - `--no-priv-drop` to disable
    - Clear error if drop fails: "Failed to drop privileges to user 'sipnab': user not found"
- [ ] `capture::file` — pcap file reader
  - Standard pcap format
  - PCAP-NG format via `pcap-file` crate
  - BPF filter from file (`--bpf-file`)
- [ ] `capture::replay` — pcap replay with original inter-packet timing (`--replay`)
- [ ] `capture::writer` — pcap/pcap-ng output
  - Basic write (`-O`)
  - Rotation by filesize or duration (`--split filesize:20`, `--split duration:120`)
  - SIGUSR1-triggered rotation (sngrep compat)
  - PCAP-NG output format (`--pcapng`)
- [ ] `capture::hep` — HEP v2/v3 (Homer)
  - HEP listener mode (`-L`, default bind: 127.0.0.1 per D18)
  - HEP send mode (`-H`)
  - HEP parsing in captured packets (`-E`)
  - **Source IP allowlist** (`--hep-allow <cidr>`)
  - **Rate limiting** (default: 50,000 msgs/sec per D17)
  - **Validate HEP header structure before allocating buffers**
- [ ] Crossbeam channel: capture thread → main thread
- [ ] Autostop engine (`--autostop duration:N`, `--autostop filesize:N`)
- [ ] Capture duration limit (`--duration`)
- [ ] Packet count limit (`--count`)

**Gate — 1.2 is done when:**
- [ ] Live capture on loopback interface captures self-generated UDP packets (integration test)
- [ ] BPF filter `port 5060` correctly restricts captured packets
- [ ] Pcap file read: 5 test pcaps (standard pcap + pcap-ng, varying link types) all load without error
- [ ] Pcap write: captured packets written match originals when re-read (round-trip test)
- [ ] Pcap rotation: `--split filesize:1` produces multiple files at correct boundaries
- [ ] SIGUSR1 triggers rotation during active capture
- [ ] Pcap replay: inter-packet timing within 5% of original pcap timing
- [ ] HEP v3 round-trip: send HEP-encapsulated SIP → receive and extract SIP payload (loopback test)
- [ ] HEP listener binds to 127.0.0.1 by default; explicit `0.0.0.0` binds to all interfaces
- [ ] HEP rate limit: inject >50K msgs/sec → verify excess dropped, counter incremented
- [ ] HEP source allowlist: packets from non-allowed IPs dropped silently
- [ ] Privilege drop: after device open, `/proc/self/status` Uid shows unprivileged user
- [ ] `--no-priv-drop` correctly skips privilege drop (Uid remains root)
- [ ] Privilege drop failure produces clear error message (e.g., target user doesn't exist)
- [ ] `--count 10` exits after exactly 10 packets; `--duration 2` exits after ~2 seconds
- [ ] Crossbeam channel delivers packets from capture thread to main thread without loss (stress test: 100K packets)

**Docs — 1.2 deliverables:**
- [ ] Rustdoc on all public types/functions in `capture/` modules
- [ ] `docs/capture-guide.md` — how to capture: live devices, pcap files, HEP, replay, multi-device, privilege requirements
- [ ] `docs/hep-guide.md` — HEP v2/v3 setup: listen mode, send mode, source allowlist, rate limiting, integration with Homer
- [ ] `docs/privilege-guide.md` — privilege model: why root is needed, how priv drop works, `--user`, `--no-priv-drop`, `--chroot`, CAP_NET_RAW alternative
- [ ] Update `man/sipnab.1` with capture flags
- [ ] Update `docs/cli-reference.md` with capture flags
- [ ] Update `docs/config-reference.md` with `[capture]` section

### 1.3 — Packet Parsing & Reassembly

- [ ] `capture::packet` — Packet struct with frames, payload, metadata
- [ ] Ethernet / VLAN (802.1Q) / SLL / NFLOG header parsing via `etherparse`
- [ ] IPv4 and IPv6 header parsing
- [ ] Encapsulation stripping (iterate until transport layer reached):
  - IP-in-IP tunnels (proto 4) — sngrep had this, carrier networks use it
  - GRE encapsulation (proto 47) — common in MPLS/carrier paths
  - Double VLAN tagging (QinQ / 802.1ad)
- [ ] IP fragment reassembly
  - `HashMap<ReassemblyKey, ReassemblyEntry>` with 30s TTL
  - Periodic sweep (every 5s) to evict stale entries
  - Max assembled size cap (64KB)
  - **Max entries cap (default: 10,000 per D17)**
  - **Overlapping fragment detection** — drop and warn (overlapping fragments are a known evasion technique)
- [ ] TCP segment reassembly
  - Sequence tracking, out-of-order handling
  - PSH flag flush
  - Multi-SIP-per-segment splitting
  - 30s TTL eviction
  - **Max entries cap (default: 10,000 per D17)**
- [ ] UDP payload extraction
- [ ] `capture::websocket` — WebSocket frame unwrapping for SIP-over-WS
  - **Max frame size: 64KB**
- [ ] SCTP support (future — stub the interface)
- [ ] **Fuzz targets:** `fuzz/fuzz_targets/` for packet parser, IP reassembly, TCP reassembly. Run in CI.

**Gate — 1.3 is done when:**
- [ ] Ethernet, VLAN (802.1Q), SLL, NFLOG link-layer parsing: each tested with a dedicated pcap fixture
- [ ] IPv4 and IPv6 header parsing: verified against known-good pcaps
- [ ] GRE encapsulation stripping: test pcap with GRE-encapsulated SIP parses correctly
- [ ] IP-in-IP tunnel stripping: test pcap with tunneled SIP parses correctly
- [ ] Double VLAN (QinQ) stripping: test pcap with QinQ parses correctly
- [ ] IP fragment reassembly test suite (≥ 8 cases):
  - Normal fragmentation (2 and 3 fragments)
  - Out-of-order fragments
  - Duplicate fragments (idempotent)
  - Overlapping fragments → drop and WARN
  - Timeout (no final fragment within 30s) → entry evicted
  - Oversized assembly (>64KB) → drop and WARN
  - Max entries cap reached → oldest evicted, metric incremented
  - Fragment flood (10K entries) → table stays at cap, no OOM
- [ ] TCP segment reassembly test suite (≥ 8 cases):
  - In-order segments
  - Out-of-order segments (reordering)
  - PSH flag flush
  - Multi-SIP-per-segment splitting (two SIP messages in one TCP segment)
  - Retransmitted segments (dedup)
  - Timeout → eviction
  - Max entries cap → oldest evicted
  - Partial segment at connection close
- [ ] WebSocket frame unwrapping: test pcap with SIP-over-WS parses correctly
- [ ] WebSocket frame >64KB → drop and WARN
- [ ] Fuzz testing: `cargo-fuzz` on packet parser, IP reassembly, TCP reassembly — ≥ 1 hour, zero crashes
- [ ] Performance: ≥ 200K raw packets/sec from pcap (criterion benchmark)

**Docs — 1.3 deliverables:**
- [ ] Rustdoc on all public types/functions in `capture/packet.rs`, `capture/reassembly.rs`, `capture/websocket.rs`
- [ ] `docs/internals/reassembly.md` — internal design doc: fragment/segment reassembly algorithm, timeout logic, eviction policy, max entry handling
- [ ] `docs/internals/encapsulation.md` — supported encapsulations, stripping order, how to add new encapsulation types
- [ ] `tests/README.md` — test fixture inventory: which pcap tests what, how to add new fixtures

---

## Phase 2 — SIP Parser, Dialog Engine, RTP Streams & CLI Output

**Goal:** Parse SIP, track dialogs, discover RTP streams, diagnose VoIP issues, filter DSL, print output in CLI mode.
**Milestone:** `sipnab -N -d eth0 --from 1001 --report` shows matched dialogs with RTP streams, transaction timing, and diagnosis. `sipnab -N -I cap.pcap --call-report abc123` generates a structured troubleshooting report. `sipnab -N -d eth0 --problems` shows only calls with detected issues.
**Release target:** Completes v0.1.0-alpha (first usable release).

**Exit criteria — Phase 2 is done when:**
- [ ] SIP parser handles all test pcaps from sngrep test suite (11 pcaps)
- [ ] Compact header forms work (`i`=Call-ID, `f`=From, `t`=To, `v`=Via, `m`=Contact, `l`=Content-Length)
- [ ] Header folding (multi-line headers with WSP continuation) parsed correctly
- [ ] Multiple Via headers stacked correctly for proxied traffic
- [ ] Dialog state machine transitions verified for: basic call, cancelled call, failed call, REGISTER, SUBSCRIBE
- [ ] Forked calls (multiple 200 OKs for one INVITE) create correct dialog structure
- [ ] `--from`, `--to`, `--ua`, `--contact` filters work with regex
- [ ] `--filter` DSL expressions evaluate correctly for all supported fields and operators
- [ ] `--report` produces accurate dialog summary
- [ ] `--json` output validates against the documented schema
- [ ] Throughput: ≥ 100K SIP messages/sec parsed from pcap on single core x86_64 ≥ 2.5 GHz (criterion benchmark)
- [ ] Malformed SIP messages do not panic — verified by running cargo-fuzz on SIP parser for ≥ 1 hour
- [ ] Retransmission deduplication accuracy ≥ 99% against test corpus
- [ ] RTP streams correctly discovered from both SDP negotiation and heuristic detection
- [ ] Orphaned RTP streams (no dialog) are visible in output
- [ ] RTCP Sender/Receiver Reports parsed and quality metrics calculated
- [ ] Per-interval jitter and loss match Wireshark RTP analysis within 10% for same pcap
- [ ] DialogStore and StreamStore respect default limits (100K dialogs, 50K streams)
- [ ] Regex filter size limit enforced (1MB compiled size)
- [ ] SIP transaction timing computed: PDD, setup time, ring duration verified against manual measurement for test pcaps
- [ ] SIP response code intelligence: all 4xx/5xx/6xx codes have human-readable explanation
- [ ] One-way audio detection fires within 6s on test pcap with unidirectional RTP
- [ ] NAT mismatch detection flags when SDP c=/m= differs from observed RTP source
- [ ] SDP negotiation timeline correctly tracks hold/resume/codec change across re-INVITEs
- [ ] Multi-leg correlation via X-Call-ID matches correctly in test pcap with B2BUA traffic
- [ ] `--call-report` generates accurate structured report for a specific Call-ID
- [ ] `--problems` filter alias shows only calls with detected issues
- [ ] Per-endpoint concurrent call count tracked accurately against manual count
- [ ] **v0.1.0-alpha tagged and released on GitHub** after all criteria pass

### 2.1 — SIP Parser (Zero-Copy)

- [ ] `sip::parser` — operates on `&[u8]`, no allocation for header access
- [ ] Request line: method + Request-URI
- [ ] Status line: response code + reason phrase
- [ ] **SIP compact header form support** — the parser must recognize both long and compact forms:
  - `i` = Call-ID, `f` = From, `t` = To, `v` = Via, `m` = Contact
  - `l` = Content-Length, `c` = Content-Type, `e` = Content-Encoding
  - `k` = Supported, `s` = Subject
  - Carriers and B2BUAs use these in production; without support, sipnab misses headers
- [ ] **Header folding** — headers continued on the next line with leading whitespace (SP or HTAB per RFC 3261 §7.3.1) must be unfolded before value extraction
- [ ] **Multiple headers with same name** — Via, Record-Route, Route can appear multiple times; parser returns all instances, not just the first
- [ ] Header extraction (lazy, on-demand):
  - Call-ID, X-Call-ID
  - From (with display name, URI, tag)
  - To (with display name, URI, tag)
  - Via (with branch, received, rport)
  - CSeq (number + method)
  - Contact
  - Content-Length, Content-Type
  - User-Agent / Server
  - Reason (cause code + text)
  - Warning
  - Identity (STIR/SHAKEN PASSporT)
  - P-Asserted-Identity, Remote-Party-ID
  - Diversion
  - Supported, Require, Allow
- [ ] **Max SIP message size: 64KB** (D17). Drop and WARN if exceeded.
- [ ] SDP parser (`sip::sdp`):
  - Session-level: origin, connection
  - Media-level: m= lines (type, port, transport, formats)
  - Attributes: rtpmap, fmtp, ptime, sendrecv
  - ICE candidates (a=candidate)
  - Crypto (SRTP a=crypto)
- [ ] SIP message validation (complete / partial / non-SIP detection)
- [ ] Retransmission detection (CSeq + method + Call-ID dedup)
- [ ] **`sip::response_codes` — SIP response code intelligence:**
  - Embedded map of all standard SIP response codes (RFC 3261 + extensions) → human-readable explanation + common causes
  - Examples: `403 → "Callee rejected the request. Common causes: IP ACL block, auth required but not provided."`, `488 → "Codec negotiation failed. Check SDP offer vs callee's allowed codecs."`, `503 → "Upstream server overloaded or unreachable. Check trunk connectivity."`
  - Reason header parsing with context: `"location_service_out of memory"` → `"Possible insufficient shm_memory on kamailio."`, `"location_service_dns query failed"` → `"DNS resolution issue on proxy."`
  - Exposed in: CLI output (inline with response), TUI (tooltip/annotation in call list and ladder), JSON (`"response_context": "..."`, `"reason_context": "..."`), call reports
- [ ] **Fuzz targets:** SIP parser, SDP parser. Run in CI.

**Gate — 2.1 is done when:**
- [ ] All 11 sngrep test pcaps parse without errors or panics
- [ ] Compact header test: message using `i`, `f`, `t`, `v`, `m`, `l`, `c`, `e`, `k`, `s` produces identical field values as long-form equivalent
- [ ] Header folding test: multi-line Via header unfolds correctly
- [ ] Multiple same-name headers: 3 Via headers returns all 3 in order
- [ ] Lazy extraction: accessing Call-ID does not allocate for From/To/Via (verified via custom allocator or benchmark)
- [ ] Max SIP message size: 65KB message → drop and WARN; 64KB message → parse succeeds
- [ ] Content-Length validation: declared length exceeding remaining bytes → truncation warning
- [ ] SDP parser: test pcap with multi-media session (audio + video + T.38) → all media lines parsed
- [ ] SDP a=crypto: SDES key line extracted correctly (base64 key + salt)
- [ ] SDP ICE candidates: all candidate lines extracted
- [ ] Retransmission detection: pcap with known retransmits → correct dedup count
- [ ] Response code intelligence: all 4xx/5xx/6xx codes return non-empty human-readable string
- [ ] Reason header: `Reason: Q.850;cause=16;text="Normal call clearing"` parsed correctly
- [ ] Malformed SIP: fuzz SIP parser ≥ 1 hour, zero panics
- [ ] Malformed SIP: 10 known-bad SIP messages (truncated, invalid UTF-8, missing CRLF, binary garbage after headers) → all produce `parse_error: true`, none panic
- [ ] Performance: ≥ 100K SIP msgs/sec (criterion benchmark)

**Docs — 2.1 deliverables:**
- [ ] Rustdoc on all public types/functions in `sip/parser.rs`, `sip/message.rs`, `sip/sdp.rs`
- [ ] `docs/sip-parser.md` — supported headers, compact forms, folding behavior, Content-Length handling, malformed message behavior
- [ ] `docs/response-codes.md` — full table of SIP response codes with human-readable explanations and common causes (exportable as reference for VoIP engineers)
- [ ] `docs/sdp-parsing.md` — supported SDP attributes, media types, crypto parsing, ICE candidate extraction
- [ ] Update `man/sipnab.1` with SIP-related flags

### 2.2 — Matching Engine

- [ ] `sip::matcher` — unified matching for all filter types
- [ ] Payload regex match (sngrep `<match expression>`)
- [ ] Word-boundary regex (`--word`)
- [ ] Case-insensitive matching (`-i`)
- [ ] Inverted matching (`-v`)
- [ ] Multi-line vs single-line match mode (`--single-line`)
- [ ] Header-specific filters (sipgrep-style):
  - `--from <pattern>` — From URI user part
  - `--to <pattern>` — To URI user part
  - `--contact <pattern>` — Contact header
  - `--ua <pattern>` — User-Agent header
- [ ] Method filter (INVITE only with `-c`, or arbitrary method patterns)
- [ ] Combined filter logic: all specified filters must match (AND)
- [ ] **Regex size limit:** `regex::RegexBuilder::size_limit(1_000_000)` to prevent ReDoS (D17)

**Gate — 2.2 is done when:**
- [ ] Payload regex: known pattern matches in test pcap, non-matching pattern returns nothing
- [ ] Word-boundary: `--word "INVITE"` matches "INVITE" but not "REINVITE"
- [ ] Case-insensitive: `-i "invite"` matches "INVITE"
- [ ] Inverted: `-v "REGISTER"` shows all messages except REGISTER
- [ ] Multi-line vs single-line: `--single-line` restricts match to first line only
- [ ] Header filters: `--from 1001` matches From: <sip:1001@...>, `--to 1002` matches To, `--ua "Oasis"` matches User-Agent, `--contact "10.0.0"` matches Contact
- [ ] Method filter: `-c` shows only INVITE dialogs
- [ ] Combined: `--from 1001 --to 1002` matches only when BOTH match (AND logic)
- [ ] Regex size limit: 2MB compiled regex → rejected with clear error message

**Docs — 2.2 deliverables:**
- [ ] Rustdoc on `sip/matcher.rs`
- [ ] `docs/filtering.md` — all filter types with examples: regex, word-boundary, case-insensitive, inverted, header-specific, method filters, combined logic
- [ ] Update `docs/cli-reference.md` with filter flags

### 2.3 — Filter DSL

- [ ] `sip::dsl` — declarative filter expression language (D7)
- [ ] Expression parser (via `nom` or `pest`):
  - Field access: `from.user`, `to.user`, `method`, `ua`, `call_id`, `src.ip`, `dst.ip`, `src.port`, `dst.port`
  - RTP fields: `rtp.mos`, `rtp.jitter`, `rtp.loss`, `rtp.packets`, `rtp.orphaned`, `rtp.codec`, `rtp.ssrc`
  - Dialog fields: `state`, `duration`, `msg_count`, `pdd`, `setup_time`, `retransmits`, `one_way`, `nat_mismatch`, `no_media`, `concurrent_calls`
  - Comparison operators: `==`, `!=`, `<`, `>`, `<=`, `>=`
  - Regex match: `=~`
  - Boolean logic: `AND`, `OR`, `NOT`
  - Parenthetical grouping
  - String literals: single or double quotes
  - Numeric literals: integer and float
- [ ] Evaluator: walks compiled expression tree against SipMessage/SipDialog/RtpStream
- [ ] **Max expression nesting depth: 50 levels** (D17)
- [ ] **No Turing-completeness:** no loops, no variables, no functions, no side effects
- [ ] Clear error messages on parse failure: show position and expected token
- [ ] Unit tests for all operators, field types, and edge cases
- [ ] **Built-in diagnostic filter aliases** (compile to DSL expressions internally):
  - `--problems` — calls with any detected issue: failed (4xx/5xx/6xx final), one-way audio, loss >2%, jitter >50ms, MOS <3.0, NAT mismatch, retransmit storms (>3 retransmits), setup timeout (>32s), orphaned RTP
  - `--slow-setup` — PDD > 3 seconds (equivalent to `--filter "pdd > 3.0"`)
  - `--short-calls` — duration < 5 seconds with completed state (wangiri/robocall pattern)
  - `--one-way` — calls with one-way audio detected
  - `--nat-issues` — calls where SDP media address differs from observed RTP source
  - Aliases are syntactic sugar — they expand to `--filter` expressions and can be combined with explicit `--filter`

**Gate — 2.3 is done when:**
- [ ] All comparison operators: `==`, `!=`, `<`, `>`, `<=`, `>=` tested for string and numeric fields
- [ ] Regex match: `from.user =~ '100[0-9]'` matches 1000-1009
- [ ] Boolean logic: `AND`, `OR`, `NOT` tested in combination
- [ ] Parenthetical grouping: `(A OR B) AND C` vs `A OR (B AND C)` produce different results
- [ ] All SIP fields accessible: `from.user`, `to.user`, `method`, `ua`, `call_id`, `src.ip`, `dst.ip`, `src.port`, `dst.port`
- [ ] All RTP fields accessible: `rtp.mos`, `rtp.jitter`, `rtp.loss`, `rtp.packets`, `rtp.orphaned`, `rtp.codec`, `rtp.ssrc`
- [ ] All dialog fields accessible: `state`, `duration`, `msg_count`, `pdd`, `setup_time`, `retransmits`, `one_way`, `nat_mismatch`, `no_media`, `concurrent_calls`
- [ ] Nesting depth >50 → rejected with clear error
- [ ] Parse error: `from.user == ` (missing value) → error with position and expected token
- [ ] Diagnostic aliases: `--problems`, `--slow-setup`, `--short-calls`, `--one-way`, `--nat-issues` each expand to correct DSL expression
- [ ] Alias + explicit filter combination: `--problems --filter "from.user =~ '1001'"` works (AND logic)
- [ ] Performance: 100K dialogs evaluated against complex filter in <100ms

**Docs — 2.3 deliverables:**
- [ ] Rustdoc on `sip/dsl.rs`
- [ ] `docs/filter-dsl.md` — user-facing DSL reference: grammar, all fields, operators, examples, diagnostic aliases, combining filters
- [ ] `docs/internals/dsl-grammar.md` — formal grammar specification (EBNF or PEG)

### 2.4 — Dialog Tracking

- [ ] `sip::dialog` — SipDialog struct:
  - `call_id`, `x_call_id`, `messages`, `state`, `streams`
  - `created_at`, `updated_at`, `changed` flag, `locked` flag
  - `tags: Vec<String>` — user-applied tags
- [ ] `sip::mod` — DialogStore:
  - `HashMap<String, usize>` for O(1) Call-ID lookup
  - `Vec<SipDialog>` for ordered storage
  - Thread-safe via `parking_lot::RwLock`
  - Dialog rotation when limit reached (`-R`)
  - **Default limit: 100,000 dialogs** (D17). Configurable via `-l`.
  - X-Call-ID correlation
- [ ] Dialog state machine:
  - **INVITE dialogs:** Trying → Ringing → InCall → Completed/Cancelled/Failed
  - **REGISTER dialogs:** tracked by AOR + Contact (not Call-ID alone), state = Registered/Expired/Failed
  - **SUBSCRIBE/NOTIFY dialogs:** Pending → Active → Terminated, linked by Event header + Call-ID
  - **Forked calls:** A single INVITE may produce multiple 200 OKs from different endpoints (forking proxy). Each 200 OK with a distinct To-tag creates a separate dialog branch. The Call-ID lookup returns the parent, branches are stored as children.
- [ ] RTP stream tracking from SDP negotiation
- [ ] Dialog matching mode (`--dialog-track` / `--no-dialog`)
- [ ] Dialog tagging (`--tag <label>`)
- [ ] `sip::siprec` — SIPREC metadata XML parsing
- [ ] **`sip::timing` — SIP transaction timing analysis (D20):**
  - Automatically computed for every dialog, no flags required
  - Track timestamps of key SIP events within each dialog:
    - **PDD (Post-Dial Delay):** INVITE sent → first 180 Ringing received
    - **Setup time:** INVITE sent → 200 OK received
    - **100 Trying delay:** INVITE sent → 100 Trying (is the proxy responsive?)
    - **Ring duration:** first 180 Ringing → 200 OK (how long did it ring?)
    - **Teardown time:** BYE sent → 200 OK for BYE
    - **REGISTER round-trip:** REGISTER sent → 200 OK
    - **Re-INVITE timing:** re-INVITE sent → 200 OK (hold/resume/codec change latency)
  - Per-hop latency when multiple Via headers present (proxy chain timing)
  - Retransmission pattern detection: count retransmits per transaction, flag >3 retransmits as likely network loss or unresponsive UAS
  - Stored in `SipDialog` struct: `timing: DialogTiming { pdd_ms, setup_ms, ring_ms, teardown_ms, trying_delay_ms, retransmit_counts: HashMap<CSeq, u32> }`
  - Exposed in: TUI call list columns, ladder diagram annotations, JSON output, Prometheus histograms, filter DSL (`pdd > 3.0`, `setup_time > 10.0`, `retransmits > 3`)
- [ ] **`sip::sdp_timeline` — SDP negotiation tracking (D20):**
  - Track every SDP offer/answer exchange within a dialog as a timeline
  - Each entry: `{ timestamp, direction (offer/answer), codecs, media_addr, media_port, sendrecv_mode, crypto }`
  - Detect and label events automatically:
    - **HOLD:** re-INVITE with `a=sendonly` or `a=inactive`
    - **RESUME:** re-INVITE returning to `a=sendrecv`
    - **CODEC CHANGE:** offered/answered codec set differs from previous exchange
    - **T.38 SWITCH:** media type changes to `image` (fax switchover)
    - **MEDIA ANCHOR CHANGE:** media IP:port changed between exchanges (SBC re-anchoring, oasis-media-relay)
  - SDP diff between consecutive exchanges: highlight what changed
  - Stored in `SipDialog` struct: `sdp_timeline: Vec<SdpExchange>`
  - Exposed in: TUI ladder diagram annotations, raw message view SDP highlighting, JSON output (`"sdp_timeline": [...]`), call reports
- [ ] **`sip::correlation` — Multi-leg B2BUA/SBC call correlation (D21):**
  - Correlation methods (tried in priority order):
    1. **X-Call-ID / X-CID header** — explicitly set by B2BUA (OpenSIPS, Oasis)
    2. **Via branch parameter** — matches if both legs pass through same proxy
    3. **Timing + identity heuristic** — INVITE on leg B within 500ms of INVITE on leg A, matching From or To user part
    4. **Manual linking** — TUI: select two dialogs → "Link as A-leg/B-leg" (Phase 3)
  - `CorrelatedCall` struct: `legs: Vec<(LegRole, CallId)>` where `LegRole` = `ALeg | BLeg | CLeg`
  - Cross-leg SDP diff: show what the B2BUA changed in SDP (codec stripping, media anchoring, transport rewrite)
  - Cross-leg header diff: show what the proxy added, removed, or modified between inbound and outbound INVITE
  - Stored in DialogStore: `correlations: HashMap<CorrelationKey, CorrelatedCall>`
  - Exposed in: TUI (multi-column ladder diagram), JSON (`"correlated_legs": [{"call_id": "...", "role": "a-leg"}, ...]`), call reports
- [ ] **Per-endpoint concurrent call tracking:**
  - Track active calls (InCall state) grouped by source IP and destination IP
  - Atomic counters updated on dialog state transitions
  - `ConcurrentCallTracker`: `HashMap<IpAddr, AtomicU32>` for source and destination separately
  - Exposed in: TUI statistics view ("Top endpoints by active calls"), Prometheus gauge, filter DSL, alerting engine
- [ ] **IPC interface design:** Define the Unix socket message format for communicating dialog/stream data to child processes (used by scanner kill in Phase 4, API in Phase 6). Implement the serialization layer now even if children ship later.

**Gate — 2.4 is done when:**
- [ ] Dialog state machine: INVITE basic call (Trying→Ringing→InCall→Completed) verified step-by-step against test pcap
- [ ] Dialog state machine: cancelled call (Trying→Ringing→Cancelled) verified
- [ ] Dialog state machine: failed call (Trying→Failed with 4xx/5xx/6xx) verified
- [ ] REGISTER dialog: tracks AOR + Contact, state transitions (Registered/Expired/Failed)
- [ ] SUBSCRIBE/NOTIFY: Pending→Active→Terminated linked by Event header
- [ ] Forked calls: INVITE with 2 different 200 OKs → parent dialog with 2 branches
- [ ] X-Call-ID correlation: two dialogs with matching X-Call-ID linked correctly
- [ ] Dialog rotation: `-l 100 -R` → dialogs rotate at 100, no memory growth
- [ ] Default limit: 100K dialogs → 100,001st triggers rotation, WARN logged
- [ ] Tagging: `--tag important` → all matched dialogs have tag in output
- [ ] Transaction timing (PDD): test pcap with known INVITE→180 delay → PDD within 1ms of expected
- [ ] Transaction timing (setup): INVITE→200 OK delay accurate
- [ ] Transaction timing (retransmits): pcap with 3 INVITE retransmits → count = 3
- [ ] SDP timeline: re-INVITE with sendonly → labeled HOLD; follow-up sendrecv → labeled RESUME
- [ ] SDP timeline: codec change across re-INVITE → labeled CODEC CHANGE
- [ ] SDP timeline: T.38 switchover → labeled T.38 SWITCH
- [ ] Multi-leg correlation (X-Call-ID): two-leg pcap with X-Call-ID → legs linked, roles assigned
- [ ] Multi-leg correlation (heuristic): two-leg pcap without X-Call-ID → timing heuristic links legs correctly
- [ ] Cross-leg SDP diff: different codecs between A-leg and B-leg SDP → diff produced
- [ ] Concurrent calls: 5 simultaneous INVITEs from same source → concurrent count = 5
- [ ] IPC serialization: DialogStore data serializes/deserializes correctly over Unix socket

**Docs — 2.4 deliverables:**
- [ ] Rustdoc on all public types/functions in `sip/dialog.rs`, `sip/timing.rs`, `sip/correlation.rs`, `sip/sdp_timeline.rs`
- [ ] `docs/dialog-tracking.md` — state machine diagram for each dialog type (INVITE, REGISTER, SUBSCRIBE), forked call handling, rotation behavior
- [ ] `docs/transaction-timing.md` — what timing metrics are tracked, how PDD is measured, retransmission detection, per-hop latency
- [ ] `docs/sdp-timeline.md` — SDP event types (HOLD, RESUME, CODEC CHANGE, T.38, MEDIA ANCHOR), how they're detected, JSON format
- [ ] `docs/multi-leg-correlation.md` — correlation methods, priority order, heuristic parameters, cross-leg diff format, manual linking (TUI)
- [ ] `docs/internals/ipc-protocol.md` — Unix socket message format specification for child process communication

### 2.5 — RTP Stream Engine (First-Class)

RTP is parsed and tracked from Phase 2 onward — it is not deferred to a later phase.

- [ ] `rtp::parser` — RTP header parsing:
  - Version (must be 2), padding, extension, CSRC count, marker, payload type
  - Sequence number, timestamp, SSRC
  - CSRC list (if present)
  - Header extension (if present)
  - Validate structure: reject non-RTP (version ≠ 2, invalid PT) for heuristic path
- [ ] `rtp::rtcp` — RTCP packet parsing:
  - Sender Report (SR): NTP timestamp, RTP timestamp, packet/octet counts
  - Receiver Report (RR): fraction lost, cumulative lost, jitter, last SR, delay since last SR
  - BYE: SSRC leaving
  - Compound RTCP packets (multiple reports in one UDP payload)
- [ ] `rtp::stream` — RtpStream as top-level entity:
  - Keyed by (SSRC, src address:port, dst address:port)
  - Fields: ssrc, codec (from SDP or PT), src, dst, first_seen, last_seen, packet_count, octet_count, jitter, loss_fraction, associated_dialog (Option<CallId>), encryption_status (RTP/SRTP/ZRTP/unknown)
- [ ] `rtp::mod` — StreamStore:
  - `HashMap<StreamKey, usize>` for O(1) lookup
  - `Vec<RtpStream>` for ordered storage
  - Thread-safe via `parking_lot::RwLock`
  - **Default limit: 50,000 streams** (D17). Configurable via `--max-streams`.
  - Cross-reference with DialogStore: when SDP is parsed, link streams to their dialog by matching media IP:port. When a dialog is rotated/removed, unlink (but don't delete) its streams.
- [ ] `rtp::quality` — basic per-interval metrics:
  - Jitter calculation (RFC 3550 algorithm: running interarrival jitter)
  - Packet loss: gap detection from sequence number discontinuities
  - Per-interval recording (default: every 1 second, configurable via `--rtp-interval`)
  - Store as `Vec<QualityInterval>` per stream (circular buffer, configurable depth)
- [ ] `rtp::heuristic` — RTP discovery without SDP:
  - Classify unmatched UDP packets: even destination port, RTP v2 header, valid PT (0-34, 96-127), incrementing sequence numbers (at least 3 consecutive)
  - Create stream entry marked as "heuristic" (no SDP source)
  - Attempt to match to a dialog by timing correlation (stream appeared within 5s of INVITE 200 OK from same endpoint)
- [ ] **Orphaned stream handling:**
  - Streams with no associated dialog after 30s are marked "orphaned"
  - Orphaned streams remain visible in JSON output and CLI report
  - They are never silently dropped — this is the most common "why can't I find my audio" scenario
- [ ] **`rtp::diagnosis` — One-way audio detection and media path analysis (D20):**
  - **One-way audio detection:** For dialogs in `InCall` state >5 seconds, check:
    - RTP flowing A→B but not B→A (or vice versa): flag `one_way_audio: true`
    - RTP flowing A→B, B→A exists but packet count is <5 in 5s: flag as `near_silent`
    - SDP negotiated but zero RTP packets in either direction: flag as `no_media`
  - **NAT mismatch detection:** For every RTP stream with an associated SDP:
    - Compare SDP `c=` (connection address) + `m=` (media port) against actual observed RTP source IP:port
    - When they differ: `nat_detected: true, sdp_media: "10.1.1.5:20000", actual_media: "203.0.113.50:45678"`
    - This is the #1 cause of one-way audio — make it impossible to miss
  - **RTP timeout detection:** Distinguish:
    - "Stream never started" — SDP negotiated but no packets seen (routing/firewall issue)
    - "Stream died" — packets stopped after flowing for N seconds (network failure)
    - "Comfort noise only" — one side sending only CN (PT 13) — possible mute, not a failure
  - **Diagnosis hints:** When issues detected, include probable cause:
    - `"RTP from A→B only. SDP c= differs from packet source — likely NAT/firewall blocking return path."`
    - `"No RTP in either direction despite 200 OK with SDP. Check firewall rules on media port range."`
    - `"RTP flowing both directions but B→A sending only CN. Possible remote mute or hold without re-INVITE."`
  - Exposed in: TUI (warning badge + tooltip in call list, media path lines in ladder), CLI (inline warning), JSON (`"diagnosis": {"one_way_audio": true, "nat_mismatch": true, "hint": "..."}`), call reports, filter DSL (`one_way == true`, `nat_mismatch == true`)

**Gate — 2.5 is done when:**
- [ ] RTP header parsing: test packet with known SSRC, seq, timestamp, PT → all fields correct
- [ ] RTP validation: non-RTP packet (version ≠ 2) rejected by heuristic path
- [ ] RTCP SR: test pcap with Sender Report → NTP timestamp, packet/octet counts extracted correctly
- [ ] RTCP RR: test pcap with Receiver Report → fraction lost, jitter, DLSR extracted
- [ ] RTCP BYE: stream marked ended on BYE
- [ ] Compound RTCP: packet with SR + RR + BYE → all three parsed
- [ ] Stream creation: first RTP packet from new SSRC+src+dst → new stream created
- [ ] Stream lookup: subsequent packets from same key → same stream updated
- [ ] Default limit: 50K streams → 50,001st triggers rotation, WARN logged
- [ ] Cross-reference: SDP media port matches RTP stream → stream linked to dialog
- [ ] Heuristic detection: RTP stream without SDP → detected after 3 consecutive valid packets
- [ ] Heuristic timing correlation: stream appearing within 5s of 200 OK → linked to dialog
- [ ] Orphaned streams: stream with no dialog after 30s → marked orphaned
- [ ] Quality: jitter calculation matches Wireshark within 10% for test pcap
- [ ] Quality: packet loss detection from sequence gaps → correct count
- [ ] Quality: per-interval recording at 1-second boundaries
- [ ] One-way audio: test pcap with unidirectional RTP → flagged within 6s of call establishment
- [ ] One-way audio: bidirectional RTP → NOT flagged (no false positive)
- [ ] NAT mismatch: test pcap where SDP c= differs from RTP source → `nat_detected: true` with correct addresses
- [ ] NAT match: SDP c= matches RTP source → `nat_detected: false`
- [ ] RTP timeout: stream stops for 30s → marked as ended, distinguished from "never started"
- [ ] Comfort noise: CN-only stream → labeled as "comfort noise only", not flagged as one-way
- [ ] Diagnosis hints: correct hint string for each diagnosis type
- [ ] Performance: ≥ 500K RTP packets/sec (criterion benchmark)

**Docs — 2.5 deliverables:**
- [ ] Rustdoc on all public types/functions in `rtp/` modules
- [ ] `docs/rtp-analysis.md` — stream tracking, quality metrics (jitter, loss, MOS in Phase 5), RTCP parsing, heuristic discovery, orphaned streams
- [ ] `docs/media-diagnosis.md` — one-way audio detection: how it works, what triggers it, diagnosis hints, NAT mismatch detection, RTP timeout types, comfort noise handling
- [ ] `docs/internals/rtp-quality.md` — jitter calculation algorithm (RFC 3550), loss detection, per-interval recording, circular buffer depth

### 2.6 — CLI Output Modes (Non-TUI)

- [ ] `output::cli_print` — sipgrep-style colored terminal output
  - Timestamp + source → destination arrow
  - SIP first line (method/response)
  - Matched content highlighting
  - Delta timestamp mode (`--delta-time`)
  - Trailing context (`--after N`)
  - Empty packet display (`--show-empty`)
  - Line-buffered mode (`--line-buffer`)
  - Color mode control (`--color auto|always|never`)
  - Payload size limit (`--payload-limit N`) — truncate display at N bytes
- [ ] `output::dialog_report` — dialog summary on exit (`--report`)
  - Call-ID, From, To, State, Duration, Message count
  - **Associated RTP streams: SSRC, codec, packets, jitter, loss, MOS**
  - **Orphaned streams listed separately at end of report**
  - Tabular output
- [ ] No-interface mode (`-N`) — dialog count to stdout (sngrep compat)
- [ ] Quiet mode (`-q`) — suppress count output
- [ ] Text dump mode (`-T <file>`) — all messages to text file
- [ ] `output::hexdump` — raw hex+ASCII dump (`--hexdump`):
  - tcpdump-style output: offset, hex bytes, ASCII printable
  - Useful for quick "is anything arriving on this port" verification
  - Combinable with BPF filters: `sipnab -N --hexdump -d eth0 port 5060`
- [ ] **`output::call_report` — Structured call diagnosis report (`--call-report <call-id>`):**
  - Generate a comprehensive single-call report for troubleshooting and carrier escalation
  - Report sections:
    - **Summary:** Call-ID, From, To, time range, duration, final result
    - **Transaction timing:** PDD, setup time, ring duration, teardown time, retransmit counts
    - **SIP transaction log:** Each request → response chain with timing
    - **Media streams:** Per-stream: SSRC, codec, direction, packets, jitter, loss, MOS
    - **SDP negotiation timeline:** Offer/answer exchanges with labels (HOLD, RESUME, CODEC CHANGE)
    - **NAT analysis:** SDP c=/m= vs observed RTP source for each stream
    - **Issues detected:** One-way audio, NAT mismatch, high loss/jitter, retransmit storms, codec mismatch, etc.
    - **Correlated legs:** If multi-leg correlation found, show B2BUA changes
    - **STIR/SHAKEN:** Attestation level and certificate info (if present)
  - Output formats:
    - Plain text (default) — human-readable, paste into tickets
    - JSON (`--call-report <call-id> --json`) — machine-parseable
    - Markdown (`--call-report <call-id> --markdown`) — for documentation/wikis
  - Combined with pcap export: `--call-report <call-id> -O call.pcap` exports only this call's packets
  - Can be run against a pcap file: `sipnab -N -I capture.pcap --call-report <call-id>`

**Gate — 2.6 is done when:**
- [ ] Colored output: INVITE=green, BYE=red, error=bold red (verified against expected ANSI sequences)
- [ ] `--color never` produces no ANSI escape sequences
- [ ] Delta timestamp: each message shows time since previous message, not absolute time
- [ ] Trailing context: `--after 3` shows 3 packets after each match
- [ ] `--line-buffer` flushes after each line (verified by piping to `head -1`)
- [ ] `--payload-limit 200` truncates display at 200 bytes with "[truncated]" marker
- [ ] `--hexdump` produces tcpdump-style hex+ASCII output with correct offsets
- [ ] Dialog report: `--report` on test pcap → Call-ID, From, To, State, Duration, Msg count all correct
- [ ] Dialog report: RTP streams listed with SSRC, codec, packets, jitter, loss
- [ ] Dialog report: orphaned streams listed separately at end
- [ ] Call report (`--call-report <call-id>`): all sections present and accurate against manual analysis of test pcap
- [ ] Call report text format: readable, well-formatted, correct timing values
- [ ] Call report JSON format: valid JSON, all fields present, matches text report data
- [ ] Call report Markdown format: valid Markdown, renders correctly
- [ ] Call report + pcap export: `--call-report <call-id> -O call.pcap` → pcap contains only packets from that call (SIP + RTP)
- [ ] Call report diagnosis section: one-way audio / NAT mismatch / retransmit storm correctly reported when present
- [ ] Call report correlated legs: when multi-leg correlation exists, both legs shown with B2BUA diff

**Docs — 2.6 deliverables:**
- [ ] Rustdoc on `output/cli_print.rs`, `output/dialog_report.rs`, `output/call_report.rs`, `output/hexdump.rs`
- [ ] `docs/cli-output.md` — output modes: colored, hexdump, delta timestamps, trailing context, payload limit, color modes
- [ ] `docs/call-report.md` — call report format reference: all sections, all fields, example outputs in text/JSON/Markdown, how to use for carrier escalation
- [ ] `docs/dialog-report.md` — dialog report format, what each column means

### 2.7 — JSON & Structured Output

- [ ] `output::json` — JSON output per SIP message
  - NDJSON (one JSON object per line) for streaming (`--json`)
  - Pretty-printed JSON (`--json-pretty`)
  - **All JSON output includes `"schema_version": 1`** — consumers can check this before parsing. Schema changes bump the version. Breaking changes bump the major version.
  - Message schema: `{schema_version, timestamp, src, dst, method, call_id, from, to, ua, state, tls_decrypted, response_context, raw}`
  - Stream schema: `{schema_version, ssrc, codec, src, dst, packets, jitter_ms, loss_pct, mos, duration_sec, dialog_call_id, encryption, orphaned, nat_detected, sdp_media, actual_media, quality_intervals: [{timestamp, jitter_ms, loss_pct, mos}]}`
  - Dialog-level JSON (aggregated on exit with `--report --json`):
    - Associated streams with quality summaries
    - `"timing": {"pdd_ms": N, "setup_ms": N, "ring_ms": N, "teardown_ms": N, "trying_delay_ms": N, "retransmits": {"INVITE": N, ...}}`
    - `"sdp_timeline": [{"timestamp": "...", "direction": "offer|answer", "codecs": [...], "media": "ip:port", "mode": "sendrecv|sendonly|...", "event": "HOLD|RESUME|CODEC_CHANGE|..."}]`
    - `"diagnosis": {"one_way_audio": bool, "nat_mismatch": bool, "no_media": bool, "retransmit_storm": bool, "hints": ["..."]}`
    - `"correlated_legs": [{"call_id": "...", "role": "a-leg|b-leg"}]` (if multi-leg correlation found)
    - `"concurrent_calls": {"src": N, "dst": N}` (active calls on same source/dest at time of this call)
  - **Orphaned streams appear at top level** alongside dialogs in `--report --json` output, not hidden inside a dialog they don't belong to
- [ ] `output::fail2ban` — format for fail2ban log parsing (`--fail2ban`)
  - `YYYY-MM-DD HH:MM:SS sipnab[PID]: scanner_detected src=<IP> ua=<UA> method=<METHOD>`
  - `YYYY-MM-DD HH:MM:SS sipnab[PID]: reg_flood src=<IP> count=<N>`
- [ ] `output::wireshark` — Wireshark/tshark integration:
  - `--wireshark`: print Wireshark display filters for matched dialogs
    - `sip.Call-ID == "xxx" || sip.Call-ID == "yyy"`
  - `--tshark-filter`: generate full tshark command lines
    - `tshark -r capture.pcap -Y 'sip.Call-ID == "xxx"' -V`

**Gate — 2.7 is done when:**
- [ ] JSON message: valid JSON, `schema_version: 1` present, all documented fields present
- [ ] JSON stream: valid JSON with RTP fields, `nat_detected` field present
- [ ] JSON dialog: timing, sdp_timeline, diagnosis, correlated_legs, concurrent_calls fields all present and correctly populated
- [ ] NDJSON streaming: one JSON object per line, no trailing comma or array wrapper
- [ ] `--json-pretty` produces indented JSON
- [ ] Round-trip: parse JSON output back → all fields match original data
- [ ] Fail2ban format: `sipnab -N --fail2ban` output matches documented format exactly
- [ ] Fail2ban parseable: fail2ban filter regex matches sipnab output (tested with fail2ban-regex tool)
- [ ] Wireshark filter: `--wireshark` output is valid Wireshark display filter syntax (tested with `tshark -Y "<output>"`)
- [ ] tshark filter: `--tshark-filter` produces runnable tshark command (syntax-checked)
- [ ] Schema version: JSON output from `--report --json` has `schema_version: 1` in dialog and stream objects
- [ ] Orphaned streams at top level in `--report --json`, not nested inside a dialog

**Docs — 2.7 deliverables:**
- [ ] Rustdoc on `output/json.rs`, `output/fail2ban.rs`, `output/wireshark.rs`
- [ ] `docs/json-schema.md` — complete JSON schema reference: message schema, stream schema, dialog schema (with timing, sdp_timeline, diagnosis, correlation), schema versioning policy
- [ ] `docs/fail2ban-integration.md` — fail2ban setup: filter file, jail configuration, example, testing with fail2ban-regex
- [ ] `docs/wireshark-integration.md` — Wireshark/tshark integration: `--wireshark` usage, `--tshark-filter` usage, pcap export workflow
- [ ] `docs/ndjson-pipeline.md` — using NDJSON output for extensibility: piping to jq, python, custom scripts, examples for common VoIP queries

### 2.8 — Event Exec Hooks

- [ ] `--on-dialog-exec <cmd>` — execute command when a dialog is created or changes state
  - Template variables: `%json` (full dialog JSON), `%call_id`, `%from`, `%to`, `%state`, `%method`
  - Rate-limited: default 10 execs/sec (D17), configurable via `--exec-rate-limit`
  - Executed as invoking user via `std::process::Command`
  - Non-blocking: spawn and forget (don't wait for completion)
  - Log at DEBUG: which command was fired, exit code
- [ ] `--on-quality-exec <cmd>` — execute command when RTP quality drops below threshold
  - `--quality-threshold <mos>` (default: 3.0)
  - Template variables: `%stream_json`, `%ssrc`, `%mos`, `%jitter`, `%loss`, `%dialog_call_id`
  - Same rate limiting and execution model as dialog exec
- [ ] **Fork bomb prevention:** if exec queue depth exceeds 100 pending, drop new events and log WARN

**Gate — 2.8 is done when:**
- [ ] `--on-dialog-exec` fires on new dialog creation (verified: test command writes to temp file, file exists after capture)
- [ ] `--on-dialog-exec` fires on state change (InCall → Completed)
- [ ] `--on-quality-exec` fires when MOS drops below threshold
- [ ] Template expansion: `%json` produces valid JSON, `%call_id`/`%from`/`%to`/`%state`/`%method` produce correct values
- [ ] Stream template expansion: `%stream_json`/`%ssrc`/`%mos`/`%jitter`/`%loss` produce correct values
- [ ] Rate limiting: 20 events/sec with `--exec-rate-limit 10` → only 10 exec'd, rest dropped with WARN
- [ ] Non-blocking: slow exec command (sleep 5) does not block packet processing
- [ ] Fork bomb prevention: 200 rapid events → queue capped at 100, excess dropped with WARN
- [ ] Failing command: exec returning non-zero → logged at WARN, no crash, no retry

**Docs — 2.8 deliverables:**
- [ ] Rustdoc on event exec implementation in `security/alerting.rs`
- [ ] `docs/event-exec.md` — event exec hook reference: `--on-dialog-exec`, `--on-quality-exec`, template variables, rate limiting, examples (curl webhook, python script, syslog forward)
- [ ] Update `docs/cli-reference.md` with exec flags

---

## Phase 3 — Interactive TUI

**Goal:** Full sngrep-equivalent interactive terminal UI.
**Milestone:** `sudo sipnab -d eth0` launches interactive call list with ladder diagram.
**Release target:** Contributes to v0.2.0-beta.

**Exit criteria — Phase 3 is done when:**
- [ ] All sngrep F-key shortcuts work (F1 help, F2 save, F3 search, F7 filter, F8 settings, F10 columns)
- [ ] Call list displays and scrolls 100K dialogs with keypress-to-render < 50ms
- [ ] **Stream list displays and scrolls 50K streams with keypress-to-render < 50ms**
- [ ] **Tab switches between Call List and Stream List in < 50ms**
- [ ] Ladder diagram renders correctly for multi-leg calls (A→proxy→B)
- [ ] **Ladder diagram shows RTP quality bars with correct color coding**
- [ ] **Ladder diagram shows media path (SDP vs actual) with NAT mismatch highlighting**
- [ ] **Multi-leg correlated calls render as multi-column ladder**
- [ ] **One-way audio badge visible in call list for affected calls**
- [ ] Terminal resize (SIGWINCH) redraws correctly at any size ≥ 80×24
- [ ] Unicode display names and international caller IDs render correctly
- [ ] Idle CPU < 0.5% with TUI open and no traffic (60s sample)
- [ ] **TUI snapshot tests pass** for all views at 80×24 and 120×40 (insta snapshots committed)
- [ ] **TUI state machine tests pass** for all key events and view transitions
- [ ] **TUI end-to-end PTY tests pass** for launch, navigation, and quit

### 3.1 — UI Framework

- [ ] `ratatui` + `crossterm` backend
- [ ] Adaptive event loop:
  - 100ms poll when data changing
  - 500ms poll when idle (no changes for 5 cycles)
  - Immediate wake on keypress
- [ ] Panel stack manager (push/pop views)
- [ ] Theme system (sngrep-compatible color defaults)
- [ ] Configurable keybindings
- [ ] Scrollbar widget
- [ ] Mouse support (optional, crossterm feature)
- [ ] **Minimum terminal size handling:** detect < 80×24, display "terminal too small" message instead of crashing
- [ ] **SIGWINCH handling:** responsive relayout on terminal resize
- [ ] **Unicode/wide-character support:** use `unicode-width` crate for correct column alignment with CJK characters and international display names

**Gate — 3.1 is done when:**
- [ ] Adaptive poll: data flowing → 100ms poll verified; idle 5 cycles → 500ms poll verified; keypress → immediate wake
- [ ] Panel stack: push 3 views → pop all 3 → returns to original view
- [ ] Theme: custom theme in config → colors applied correctly
- [ ] Keybinding override: config maps "q" to quit → 'q' keypress exits
- [ ] Terminal < 80×24 → "terminal too small" message displayed, no crash
- [ ] SIGWINCH: resize terminal during display → redraws correctly (no artifacts, no crash)
- [ ] Unicode: CJK display name renders with correct column width (not misaligned)
- [ ] Mouse click on scrollbar (if enabled) → scrolls to correct position

**Docs — 3.1 deliverables:**
- [ ] Rustdoc on `tui/mod.rs`, `tui/theme.rs`
- [ ] `docs/tui-guide.md` — TUI overview: navigation, panel system, views available, how to switch between Call List and Stream List
- [ ] `docs/keybindings.md` — all default keybindings, how to customize in config file
- [ ] `docs/themes.md` — theme system: available color names, how to customize, sngrep-compatible defaults

### 3.2 — Call List View (F1-F10 keybindings)

- [ ] Sortable, filterable dialog list
- [ ] Configurable columns: Index, Method, From, To, Src, Dst, State, Msgs, Date, Time, Duration, PDD, Attestation
- [ ] Column resize and reorder (F10)
- [ ] Inline search/filter bar (F7) — supports filter DSL expressions
- [ ] Multi-select with spacebar
- [ ] Autoscroll toggle
- [ ] Status bar: mode, device, dialog count, **stream count**, filter, capture rate
- [ ] Filtered view with cached indices (rebuild only on change)
- [ ] STIR/SHAKEN attestation column (A/B/C/none) when `--stir-shaken`
- [ ] **RTP quality indicator column** — green/yellow/red dot based on worst-interval MOS for the call's streams
- [ ] **Diagnosis indicator column** — warning icons for: one-way audio (🔇), NAT mismatch (🔀), no media (❌), retransmit storm (🔄), slow setup (🐌). Multiple icons stack.
- [ ] **PDD column** — post-dial delay in seconds, color-coded: green (<1s), yellow (1-3s), red (>3s)
- [ ] **Response context tooltip** — hover/select a failed call to see human-readable error explanation
- [ ] Security alert indicator column when fraud/scanner detection active
- [ ] **Tab key switches between Call List and Stream List**

**Gate — 3.2 is done when:**
- [ ] 100K dialogs loaded → call list scrolls with keypress-to-render < 50ms
- [ ] Column sort: sort by PDD ascending → highest PDD calls at bottom
- [ ] Column resize: drag column boundary → column widens/narrows
- [ ] F7 filter: enter `from.user =~ '1001'` → list shows only matching dialogs
- [ ] Multi-select: spacebar on 3 rows → all 3 highlighted, F2 save operates on selection
- [ ] Autoscroll: new dialogs appear at bottom, scroll follows; toggle off → scroll stays put
- [ ] PDD column: shows correct value, green/yellow/red color coding at 1s/3s thresholds
- [ ] Diagnosis icons: one-way audio call shows warning icon, normal call shows no icon
- [ ] Response context: select failed call → tooltip/status bar shows human-readable error explanation
- [ ] Tab → switches to Stream List; Tab again → back to Call List, < 50ms

**Docs — 3.2 deliverables:**
- [ ] Rustdoc on `tui/call_list.rs`
- [ ] `docs/tui-call-list.md` — call list user guide: columns, sorting, filtering, multi-select, autoscroll, column customization (F10), PDD column, diagnosis indicators

### 3.2.1 — Stream List View (NEW)

Top-level RTP stream view, peer of Call List, accessible via Tab key.

- [ ] Columns: SSRC, Codec, Source, Destination, Packets, Jitter (ms), Loss (%), MOS, Duration, Dialog (Call-ID or "orphaned"), Encryption (RTP/SRTP/ZRTP)
- [ ] Sortable by any column (sort by MOS ascending to find worst streams first)
- [ ] Filterable: by codec, by quality threshold (`MOS < 3.5`), by orphaned status
- [ ] Color-coded rows: green (MOS ≥ 4.0), yellow (3.0–4.0), red (< 3.0), gray (orphaned)
- [ ] Select a stream → enter Stream Detail view showing per-interval quality graph (sparkline)
- [ ] Multi-select → show all selected streams' quality overlaid
- [ ] Link to dialog: press Enter on associated dialog column → jump to Call List with that dialog selected

**Gate — 3.2.1 is done when:**
- [ ] 50K streams loaded → scrolls with keypress-to-render < 50ms
- [ ] Sort by MOS ascending → worst-quality streams at top
- [ ] Filter `MOS < 3.5` → only low-quality streams shown
- [ ] Filter orphaned → only orphaned streams shown
- [ ] Color coding: MOS 4.2 → green row, MOS 3.5 → yellow, MOS 2.0 → red, orphaned → gray
- [ ] Select stream → Stream Detail view with sparkline quality graph
- [ ] Enter on dialog column → jumps to Call List with correct dialog selected
- [ ] Multi-select → quality overlay comparison view

**Docs — 3.2.1 deliverables:**
- [ ] Rustdoc on `tui/stream_list.rs`
- [ ] `docs/tui-stream-list.md` — stream list user guide: columns, sorting, filtering by quality/codec/orphaned status, color coding, navigation

### 3.3 — Call Flow View (Ladder Diagram)

- [ ] Classic SIP ladder diagram
- [ ] Arrows with method labels, color-coded by type
- [ ] Timestamp column
- [ ] **Transaction timing annotations on arrows:**
  - Delta time between request → response shown on response arrows (e.g., "+1.23s")
  - PDD annotated on first 180 Ringing arrow
  - Retransmission arrows shown as dashed/dimmed with retransmit count (e.g., "INVITE [retry 2/3]")
- [ ] Multi-dialog overlay
- [ ] **Multi-leg correlated call display (D21):**
  - When viewing a correlated call, show both legs with the B2BUA/proxy as a middle column
  - A-leg arrows on left, B-leg arrows on right, B2BUA in center
  - Highlight header/SDP differences between legs (what the B2BUA changed)
  - Toggle between: single-leg view, correlated view
- [ ] **RTP stream bars between endpoints:**
  - Colored bar spanning the duration of each RTP stream between two endpoints
  - Color reflects quality: green (MOS ≥ 4.0), yellow (3.0–4.0), red (< 3.0)
  - Codec label on the bar (e.g., "G.711a", "Opus")
  - SRTP lock icon if encrypted
  - RTCP report markers (small dots) at each SR/RR timestamp
  - Select a bar → popup with per-interval quality detail
- [ ] **Media path visualization:**
  - Show *actual* observed RTP endpoints alongside *SDP-negotiated* endpoints
  - When they differ (NAT), draw both paths: SDP path as dashed line, actual path as solid line
  - NAT mismatch highlighted in red with annotation: "NAT: SDP=10.1.1.5:20000 → Actual=203.0.113.50:45678"
  - One-way audio: missing return path drawn as a red dashed line with "NO RTP" label
- [ ] **SDP negotiation events in timeline:**
  - HOLD/RESUME/CODEC CHANGE/T.38 SWITCH shown as annotated markers between RTP bars
  - SDP offer vs answer diff popup on the re-INVITE arrow
- [ ] SDP media negotiation display (offered vs answered codecs)
- [ ] STIR/SHAKEN attestation badge on INVITE arrows
- [ ] SIP response code context: hover on error response → show human-readable explanation
- [ ] Scrollable, keyboard navigable
- [ ] Enter on message → raw view
- [ ] Enter on RTP bar → stream quality detail

**Gate — 3.3 is done when:**
- [ ] Basic ladder: A→B INVITE flow renders with correct arrows, labels, colors
- [ ] Multi-leg ladder: A→proxy→B renders 3 columns with arrows through proxy
- [ ] Timing annotations: "+1.23s" on response arrow matches actual timing from pcap
- [ ] PDD annotation: "PDD: 1.23s" on first 180 Ringing arrow
- [ ] Retransmit: dashed INVITE retransmit arrow with "[retry 2/3]" label
- [ ] Correlated legs: A-leg/B-leg renders with B2BUA middle column, header/SDP diffs highlighted
- [ ] RTP bars: colored bar between endpoints with codec label, SRTP lock icon
- [ ] Media path: SDP path as dashed line, actual path as solid line when NAT detected
- [ ] One-way audio: missing return path drawn as red dashed line with "NO RTP" label
- [ ] SDP events: HOLD/RESUME annotations between RTP bars at correct timestamps
- [ ] SDP diff popup: select re-INVITE → shows offer vs answer diff
- [ ] Response context: hover on error → human-readable explanation
- [ ] Scroll: ladder with 50+ messages scrolls smoothly
- [ ] Enter on message → raw view opens; Enter on RTP bar → quality detail opens

**Docs — 3.3 deliverables:**
- [ ] Rustdoc on `tui/call_flow.rs`
- [ ] `docs/tui-ladder.md` — ladder diagram guide: reading the diagram, timing annotations, RTP bars, media path visualization, NAT mismatch display, multi-leg view, SDP events, navigation

### 3.4 — Raw Message View

- [ ] Full SIP message with syntax highlighting
- [ ] Header colorization by type
- [ ] SDP section highlighting
- [ ] STIR/SHAKEN Identity header decoded inline
- [ ] Scrollable
- [ ] **Search within raw message** (`/` key, like vim/less)
- [ ] OSC 52 copy-to-clipboard

**Gate — 3.4 is done when:**
- [ ] SIP message renders with syntax highlighting: method=one color, headers=another, values=another
- [ ] SDP section visually distinct from SIP headers
- [ ] STIR/SHAKEN Identity header decoded inline (JWT payload shown)
- [ ] Scroll: message with 200+ lines scrolls smoothly
- [ ] Search: `/INVITE` highlights all occurrences, n/N navigates between matches
- [ ] Copy: OSC 52 copy sends selected text to clipboard (tested in supported terminals)

**Docs — 3.4 deliverables:**
- [ ] Rustdoc on `tui/msg_raw.rs`
- [ ] `docs/tui-raw-view.md` — raw message view guide: syntax highlighting, SDP highlighting, search, copy, STIR/SHAKEN decode

### 3.5 — Additional Views

- [ ] **Help view (F1)** — keybinding reference, version info
- [ ] Message diff view (side-by-side, highlight changes)
- [ ] Filter dialog (F7) — all filter types, including DSL expression editor
- [ ] Save dialog (F2) — pcap, pcap-ng, text, json
- [ ] Settings view (F8) — runtime toggleable options
- [ ] Column select (F10)
- [ ] Statistics view:
  - Method distribution, response code distribution
  - Calls/sec rate, active/completed/failed counts
  - Top callers, top destinations
  - **PDD distribution** — histogram of post-dial delay across calls
  - **Average setup time** and **p95 setup time**
  - **Top endpoints by concurrent calls**
  - **RTP stream count (active/ended/orphaned)**
  - **Codec distribution (how many streams per codec)**
  - **Quality distribution (MOS histogram across all active streams)**
  - **Worst active streams by MOS**
  - **One-way audio count** — how many active calls have unidirectional RTP
  - **NAT mismatch count** — how many streams have SDP/actual address mismatch
- [ ] **Dashboard view** (new):
  - Real-time call rate graph (sparkline)
  - Response code breakdown (bar chart)
  - Active call count gauge
  - **PDD gauge** — current average PDD, color-coded: green (<1s), yellow (1-3s), red (>3s)
  - **Top endpoints** — top 5 by concurrent active calls
  - **Active RTP stream count gauge**
  - **RTP quality distribution** — MOS histogram
  - **Worst streams panel** — top 5 active streams by lowest MOS, auto-updating
  - **Orphaned stream count** — highlighted if > 0 (indicates routing/NAT issues)
  - **One-way audio count** — highlighted if > 0
  - Security alerts feed
  - RTP quality summary (average MOS, worst MOS, total orphaned)

**Gate — 3.5 is done when:**
- [ ] Help view (F1): shows all keybindings, version info
- [ ] Message diff: two selected messages show side-by-side diff with change highlighting
- [ ] Filter dialog (F7): accepts DSL expressions, regex, header-specific filters
- [ ] Save dialog (F2): pcap, pcap-ng, text, json export all produce valid files
- [ ] Settings (F8): runtime option toggles take effect immediately
- [ ] Column select (F10): reorder columns, changes persist for session
- [ ] Statistics: method distribution matches known pcap content; PDD distribution shows correct histogram
- [ ] Statistics: top endpoints by concurrent calls shows correct counts
- [ ] Dashboard: sparklines update in real-time during live capture
- [ ] Dashboard: one-way audio count increments when one-way audio detected
- [ ] All views render without crash at terminal sizes 80×24, 120×40, 200×60, 300×80

**Docs — 3.5 deliverables:**
- [ ] Rustdoc on `tui/msg_diff.rs`, `tui/filter_view.rs`, `tui/save_view.rs`, `tui/settings.rs`, `tui/column_select.rs`, `tui/stats.rs`, `tui/dashboard.rs`
- [ ] `docs/tui-views.md` — guide for all additional views: help, diff, filter dialog, save dialog, settings, column select, statistics, dashboard
- [ ] `docs/tui-dashboard.md` — dashboard user guide: what each gauge/chart shows, how to interpret, real-time monitoring workflow
- [ ] Update `man/sipnab.1` with TUI section

### 3.6 — TUI Automated Testing

Automated testing for the interactive TUI using three complementary approaches.

- [ ] **Snapshot tests (ratatui TestBackend + insta):**
  - Render each view (call list, stream list, call flow, raw message, help, statistics) to `TestBackend` buffer
  - Snapshot buffer content via `insta::assert_snapshot!()`
  - Verify column alignment, color coding, diagnosis indicators
  - Test at multiple terminal sizes (80×24, 120×40, 200×60)
  - Snapshots committed to git; `cargo insta review` for visual diff on changes
- [ ] **State machine tests (App struct, no terminal):**
  - Tab switches between CallList and StreamList
  - Enter on dialog opens CallFlow, Esc returns to CallList
  - F1 opens Help, Esc returns
  - F7 opens filter dialog; typing + Enter applies DSL filter; invalid filter shows error
  - Up/Down changes selection index
  - Space toggles multi-select
  - 'q' sets should_quit
  - Filter applied → visible_dialog_count reflects filtering
  - Sort by column → order changes correctly
- [ ] **End-to-end PTY tests (expectrl):**
  - Launch `sipnab -I tests/fixtures/sip_call.pcap` → TUI renders, "Call-ID" visible
  - Tab → "SSRC" visible (stream list header)
  - Enter → ladder diagram with "INVITE" arrow
  - 'q' → clean exit (process terminates)
  - F1 → help text with "Keyboard Shortcuts" visible

**Gate — 3.6 is done when:**
- [ ] ≥ 10 snapshot tests covering all major views, committed via `insta`
- [ ] ≥ 10 state machine tests covering all key events and view transitions
- [ ] ≥ 5 end-to-end PTY tests covering launch, navigation, and quit
- [ ] All snapshot tests pass on 80×24 and 120×40 terminal sizes
- [ ] State machine tests verify filter DSL application narrows visible dialogs
- [ ] PTY tests run in CI (added to `.github/workflows/ci.yml`)
- [ ] No test depends on specific terminal emulator features

**Docs — 3.6 deliverables:**
- [ ] `docs/internals/tui-testing.md` — how TUI tests work: snapshot approach, state machine tests, PTY tests, how to update snapshots, how to add new tests
- [ ] `tests/snapshots/README.md` — snapshot inventory and regeneration instructions

---

## Phase 4 — Security & Detection

**Goal:** Active security features — scanner detection, fraud alerting, digest leak detection.
**Milestone:** `sipnab -N -d eth0 --kill-scanner --fraud-detect --fail2ban` protects and logs.
**Release target:** Completes v0.2.0-beta (with Phase 3).

**Exit criteria — Phase 4 is done when:**
- [ ] friendly-scanner and sipvicious detected with zero false negatives against test pcaps
- [ ] **False positive rate < 1%** against normal traffic test corpus
- [ ] `--kill-scanner` sends valid SIP responses that scanners accept
- [ ] **Scanner kill runs in isolated child process** (D16), verified by checking PID differs from main
- [ ] **Scanner kill rate limit enforced** (10/sec), verified by sending >10 scanner packets/sec and counting responses
- [ ] **Scanner kill rejects broadcast/multicast targets**
- [ ] Registration flood detection fires at correct threshold with ≤ 1s latency
- [ ] Digest leak detection flags known-vulnerable 401/407 exchanges
- [ ] Alert cooldown prevents more than 1 alert per source per 60s by default
- [ ] `--fail2ban` output parseable by fail2ban with the included filter file
- [ ] **v0.2.0-beta tagged and released** after Phase 3 + Phase 4 criteria pass

### 4.1 — Scanner Detection & Kill

- [ ] `security::scanner_detect` — detect SIP scanners:
  - friendly-scanner User-Agent
  - sipvicious, sipcli, sipsak, sundayddr patterns
  - Rapid sequential REGISTER/OPTIONS/INVITE from single source
  - Custom UA pattern matching (`--kill-ua <pattern>`)
- [ ] `security::scanner_kill` — active response (`--kill-scanner`):
  - **Runs in isolated child process** (D16):
    - Fork before privilege drop
    - Child holds capture fd for injection only
    - Main process sends kill requests via Unix socket pair
    - Child validates: was source IP actually observed in recent capture?
    - Child rejects requests targeting broadcast/multicast addresses
  - Send 200 OK to scanner INVITEs (cause them to think call connected)
  - Configurable response code (`--kill-response <code>`)
  - Rate-limited: max 10 responses/sec globally, enforced in child process independently
  - **Injection mechanism:** `pcap_inject()` on the capture handle. If `pcap_inject` is unavailable (e.g., pcap file input), log a warning and skip injection. Raw sockets (`AF_PACKET`) are a fallback.

**Gate — 4.1 is done when:**
- [ ] Detection: friendly-scanner UA → detected (zero false negatives against test pcap with all known scanner UAs)
- [ ] Detection: sipvicious sequential REGISTER → detected (behavioral pattern, not just UA string)
- [ ] Detection: custom UA `--kill-ua "my-scanner"` → detected
- [ ] Detection: normal SIP traffic (100 calls) → 0 false positive scanner alerts (<1%)
- [ ] Kill: isolated child process: main process PID ≠ scanner kill child PID
- [ ] Kill: 200 OK response sent to scanner INVITE → valid SIP (parseable by test SIP parser)
- [ ] Kill: configurable response code: `--kill-response 404` → sends 404
- [ ] Kill: rate limit: 15 scanner packets/sec → only 10 responses sent, 5 dropped
- [ ] Kill: broadcast destination (255.255.255.255) → rejected, not responded to
- [ ] Kill: multicast destination → rejected
- [ ] Kill: pcap file input (no injection possible) → warning logged, no crash
- [ ] Kill child crash: scanner kill child killed with SIGKILL → main process continues capturing (resilient)

**Docs — 4.1 deliverables:**
- [ ] Rustdoc on `security/scanner_detect.rs`, `security/scanner_kill.rs`
- [ ] `docs/scanner-detection.md` — scanner detection guide: detected patterns, custom UA matching, behavioral detection, false positive rate expectations
- [ ] `docs/scanner-kill.md` — scanner kill guide: how it works, safety model (isolated child process), rate limiting, injection mechanism, when to use, legal considerations
- [ ] `contrib/fail2ban/sipnab-scanner.conf` — fail2ban filter for scanner detection output

### 4.2 — Toll Fraud & IRSF Detection

- [ ] `security::fraud_detect` — heuristic fraud detection (`--fraud-detect`):
  - **IRSF destination database:** Embedded Rust `phf` (perfect hash) map of known high-risk E.164 prefixes, sourced from the CFCA public prefix list and ITU-T country code assignments.
  - **Supply chain hardening (D17):**
    - Bundled snapshot in-tree (`data/cfca-prefixes-YYYY-MM.csv`)
    - `build.rs` uses bundled data by default
    - Download only when explicitly requested: `SIPNAB_UPDATE_PREFIXES=1 cargo build`
    - Downloaded data verified against SHA-256 hash pinned in `build.rs`
    - If download fails or hash mismatches, build uses bundled snapshot and logs warning
    - Users can override with local file via config: `[security] irsf_prefixes = "/path/to/custom.csv"`
  - Unusual call volume spike from single source
  - Off-hours call patterns (configurable business hours in config)
  - Short-duration repeated calls (wangiri pattern: call, hangup < 3s, redial)
  - Sequential number scanning (e.g., +1555000**01**, +1555000**02**, ...)
  - Configurable thresholds via config file
- [ ] Alert output: stderr, JSON, fail2ban format, alert-exec

**Gate — 4.2 is done when:**
- [ ] IRSF prefix match: known high-risk prefix → fraud alert fires
- [ ] IRSF prefix match: normal domestic number → no alert (false positive check)
- [ ] CFCA data: bundled snapshot loads at startup; `SIPNAB_UPDATE_PREFIXES=1 cargo build` downloads and hash-verifies
- [ ] CFCA hash mismatch: build uses bundled fallback, logs warning
- [ ] Custom prefix file: config `irsf_prefixes = "/custom.csv"` → overrides bundled data
- [ ] Wangiri pattern: 5 calls <3s each to same destination in 60s → fraud alert
- [ ] Sequential scanning: calls to +15550001, +15550002, +15550003 → sequential pattern alert
- [ ] Off-hours: call at 3 AM (with business hours configured) → off-hours alert
- [ ] Volume spike: 10× normal call rate from single source → spike alert
- [ ] Alert output: all alert types produce correct stderr, JSON, and fail2ban output

**Docs — 4.2 deliverables:**
- [ ] Rustdoc on `security/fraud_detect.rs`
- [ ] `docs/fraud-detection.md` — fraud detection guide: IRSF prefix detection, wangiri pattern, sequential scanning, off-hours, volume spikes, configuring thresholds, updating CFCA prefix data
- [ ] `docs/internals/cfca-update.md` — how to update CFCA prefix data: build.rs process, hash verification, bundled fallback

### 4.3 — SIP Digest Leak Detection

- [ ] `security::digest_leak` — detect digest auth vulnerabilities (`--digest-leak`):
  - Detect 401/407 challenges with weak algorithms (MD5)
  - Detect responses where nonce reuse is possible
  - Detect cleartext credentials in Authorization headers
  - Flag missing `qop=auth` or missing `cnonce`

**Gate — 4.3 is done when:**
- [ ] MD5 algorithm detection: 401/407 with `algorithm=MD5` → flagged as weak
- [ ] Nonce reuse: same nonce in two different 401 challenges → flagged
- [ ] Cleartext credentials: Authorization header with credentials in clear → flagged
- [ ] Missing qop: 401 without `qop=auth` → flagged
- [ ] Missing cnonce: response without cnonce when qop present → flagged
- [ ] Normal auth (SHA-256, proper nonce, qop, cnonce) → no alert (no false positive)

**Docs — 4.3 deliverables:**
- [ ] Rustdoc on `security/digest_leak.rs`
- [ ] `docs/digest-leak.md` — digest leak detection guide: what vulnerabilities are detected, how to remediate each one, SIP auth best practices reference

### 4.4 — Registration Flood Detection

- [ ] `security::reg_flood` — REGISTER storm detection (`--reg-flood <threshold>`):
  - Track REGISTER rate per source IP
  - Alert when threshold exceeded (default: 50/sec)
  - Track failed auth rate per source
  - Output: stderr, JSON, fail2ban, alert-exec

**Gate — 4.4 is done when:**
- [ ] Threshold test: 50 REGISTERs/sec from one IP → alert fires within 1s
- [ ] Below threshold: 49 REGISTERs/sec → no alert
- [ ] Failed auth tracking: 20 failed 401 responses from one IP → auth-fail alert
- [ ] Per-source: 50/sec from IP-A and 10/sec from IP-B → alert only for IP-A
- [ ] Output: all formats (stderr, JSON, fail2ban, alert-exec) produce correct output

**Docs — 4.4 deliverables:**
- [ ] Rustdoc on `security/reg_flood.rs`
- [ ] `docs/reg-flood.md` — registration flood detection guide: thresholds, per-source tracking, integration with fail2ban, tuning for large environments

### 4.5 — Alerting Engine

- [ ] `security::alerting` — rule-based alerting (`--alert <rule>`):
  - Rule grammar: `<metric>:<threshold>/<window>[:<cooldown>]`
    - `<metric>` = `5xx-rate` | `reg-flood` | `invite-flood` | `scanner` | `fraud` | `auth-fail`
    - `<threshold>` = integer (events per window)
    - `<window>` = `Ns` (seconds) | `Nm` (minutes) | `Nh` (hours)
    - `<cooldown>` = optional, same format, default = window × 2
    - Examples: `5xx-rate:10/1m`, `reg-flood:50/10s:5m`, `auth-fail:20/1m`
  - Built-in rules: `5xx-rate`, `reg-flood`, `invite-flood`, `scanner`, `fraud`, `auth-fail`
  - Action: `--alert-exec <cmd>` with template variables (`%src`, `%type`, `%count`, `%window`, `%detail`)
  - Cooldown period per (source, rule) pair to avoid alert storms

**Gate — 4.5 is done when:**
- [ ] Rule parsing: `5xx-rate:10/1m`, `reg-flood:50/10s:5m` parse correctly
- [ ] Invalid rule: `5xx-rate:` → clear parse error
- [ ] All 6 built-in rules fire correctly against crafted test data
- [ ] Cooldown: `reg-flood:50/10s:5m` → second alert from same source within 5m suppressed
- [ ] Multiple rules: `--alert 5xx-rate:10/1m --alert reg-flood:50/10s` → both active simultaneously
- [ ] `--alert-exec`: template `%src %type %count` expanded correctly
- [ ] `--alert-exec`: executed within 1s of alert condition
- [ ] Cooldown reset: after cooldown expires, next alert fires normally

**Docs — 4.5 deliverables:**
- [ ] Rustdoc on `security/alerting.rs`
- [ ] `docs/alerting.md` — alerting rule reference: rule grammar (EBNF), all built-in rules, threshold examples, cooldown behavior, alert-exec templates, combining with fail2ban
- [ ] `docs/security-guide.md` — unified security features guide: scanner detection, fraud, digest leak, reg flood, alerting, recommended deployment configurations
- [ ] Update `man/sipnab.1` with security flags
- [ ] `contrib/fail2ban/sipnab-security.conf` — fail2ban filter for all security alert types

---

## Phase 5 — Advanced Analysis & Integration

**Goal:** Deep protocol analysis, monitoring integration, STIR/SHAKEN, TLS/SRTP decryption.
**Milestone:** `sipnab -d eth0 --stir-shaken --metrics :9100` with RTP quality analysis active by default.
**Release target:** Contributes to v0.3.0.

**Exit criteria — Phase 5 is done when:**
- [ ] STIR/SHAKEN Identity headers decoded correctly against test corpus
- [ ] RTP jitter/loss calculations match Wireshark RTP analysis within 5% for same pcap
- [ ] Prometheus `/metrics` endpoint scraped successfully by a real Prometheus instance
- [ ] **Prometheus endpoint binds to localhost by default** (D18), non-loopback requires explicit address
- [ ] TLS decryption works for TLS 1.2 with RSA key exchange against test pcap
- [ ] TLS decryption works for TLS 1.2 ECDHE via keylog file against test pcap
- [ ] TLS decryption works for TLS 1.3 via keylog file against test pcap
- [ ] SDES SRTP key extraction from plaintext SDP produces correct RTP decryption
- [ ] SDES SRTP key extraction from TLS-encrypted SDP works end-to-end (TLS→SDP→SRTP)
- [ ] Key material does not appear in any log output at any level (verified by grep on trace log)
- [ ] Key material is zeroed after use (verified by inspecting process memory or core dump)
- [ ] **Core dumps disabled when decryption active** (`PR_SET_DUMPABLE, 0`), re-enabled with `--allow-coredump`
- [ ] **Key files mlock'd to prevent swap** (or graceful fallback with warning)
- [ ] `--pcap-export-mode raw` produces pcap with no embedded keys
- [ ] Startup banner and legal notice display correctly
- [ ] **Key material never crosses IPC boundary** to API child or scanner kill child

### 5.1 — STIR/SHAKEN Analysis

- [ ] `sip::stir_shaken` — Identity header parsing:
  - Extract PASSporT JWT from Identity header
  - Decode header + payload (base64url)
  - Display attestation level (A/B/C)
  - Show originating number (`orig`), destination (`dest`), origination ID
  - Certificate chain display (issuer, validity)
  - Verification status (signature check against public cert if available)
  - TUI: attestation badge in call list and call flow

**Gate — 5.1 is done when:**
- [ ] PASSporT extraction: test Identity header → JWT header + payload decoded correctly
- [ ] Attestation: A, B, C levels correctly identified from `attest` claim
- [ ] orig/dest: originating and destination numbers extracted
- [ ] Certificate chain: issuer and validity period displayed
- [ ] Verification: valid signature with test certificate → "verified"; invalid → "failed"; no cert → "unverified"
- [ ] TUI: attestation badge (A/B/C) visible in call list and on INVITE arrow in ladder
- [ ] JSON: `"stir_shaken": {"attestation": "A", "orig": "+15551001", "verified": true}` present

**Docs — 5.1 deliverables:**
- [ ] Rustdoc on `sip/stir_shaken.rs`
- [ ] `docs/stir-shaken.md` — STIR/SHAKEN analysis guide: what sipnab extracts, attestation levels explained, certificate verification, JSON output format, TUI display

### 5.2 — Advanced RTP Analysis (builds on Phase 2.5 base)

Phase 2.5 provides basic stream tracking, jitter, loss, and RTCP SR/RR parsing. This phase adds advanced analysis.

- [ ] **MOS estimation** (E-model, ITU-T G.107 simplified):
  - Calculate R-factor from jitter, loss, codec, and delay
  - Convert R-factor to MOS (1.0–4.5 scale)
  - Codec-aware: different impairment factors for G.711, G.729, Opus, etc.
  - Per-interval MOS (uses quality intervals from Phase 2.5)
- [ ] **Burst/gap loss analysis** (RFC 3611 metrics):
  - Distinguish burst loss (consecutive or near-consecutive) from random loss
  - Burst density, gap density, burst duration
  - More diagnostic than simple loss percentage — burst loss is perceptually worse
- [ ] **RTCP Extended Reports (XR)** — RFC 3611:
  - VoIP Metrics Report Block: MOS-LQ, MOS-CQ, R-factor, jitter buffer metrics
  - Loss RLE Report Block: run-length encoded loss patterns
  - Round-trip delay from DLSR calculation
- [ ] **DTMF extraction** — RFC 4733 telephone-event:
  - Extract DTMF digits from telephone-event RTP payload
  - Display in call flow as digit annotations
  - Include in JSON output: `"dtmf_digits": "1234#"`
  - Works on both RTP and decrypted SRTP
- [ ] **Codec identification:**
  - Static payload types (PT 0 = G.711µ, PT 8 = G.711a, PT 18 = G.729, etc.)
  - Dynamic payload types resolved from SDP `a=rtpmap:` mapping
  - Heuristic fallback: infer codec from packet size and ptime when SDP unavailable
- [ ] **Silence detection:**
  - Identify comfort noise (CN, PT 13) and silence suppression periods
  - Distinguish "no audio" from "silence suppression active" in quality reporting
- [ ] JSON output enhanced: per-stream quality intervals, DTMF digits, codec timeline, burst analysis

**Gate — 5.2 is done when:**
- [ ] MOS: test pcap with known quality → MOS within 5% of Wireshark RTP analysis
- [ ] MOS: G.711 stream vs G.729 stream → different impairment factors applied (codec-aware)
- [ ] MOS: per-interval MOS calculated at 1-second boundaries
- [ ] Burst/gap: test pcap with 50-packet burst loss → burst detected, burst duration correct
- [ ] Burst/gap: random 1% loss → classified as gap loss, not burst
- [ ] RTCP XR: VoIP Metrics Report Block → MOS-LQ, MOS-CQ, R-factor extracted
- [ ] RTCP XR: round-trip delay from DLSR → correct within 5ms
- [ ] DTMF: test pcap with RFC 4733 telephone-event → digits "1234#" extracted in order
- [ ] DTMF: DTMF in decrypted SRTP → same extraction works
- [ ] Codec ID: static PT 0 → G.711µ, PT 8 → G.711a, PT 18 → G.729
- [ ] Codec ID: dynamic PT 96 with SDP `a=rtpmap:96 opus/48000` → Opus
- [ ] Codec ID: no SDP → heuristic from packet size and ptime
- [ ] Silence: CN (PT 13) packets → detected, not counted as normal audio loss
- [ ] JSON: per-interval quality, DTMF, codec timeline, burst analysis all present in output

**Docs — 5.2 deliverables:**
- [ ] Rustdoc on `rtp/quality.rs`, `rtp/dtmf.rs`
- [ ] `docs/rtp-quality.md` — update with: MOS calculation methodology (E-model G.107), burst/gap analysis (RFC 3611), RTCP XR metrics, codec impairment factors
- [ ] `docs/dtmf-extraction.md` — RFC 4733 DTMF extraction: how it works, JSON format, TUI display, limitations (out-of-band only)
- [ ] `docs/codec-identification.md` — static PT table, dynamic PT resolution from SDP, heuristic fallback

### 5.3 — TLS Decryption for SIP

SIP over TLS (SIPS, port 5061) is increasingly common. Without decryption, sipnab sees only encrypted application data. All cryptographic operations go through the `CryptoBackend` trait (D14).

**Key input methods (in priority order):**

| Method | Flag | TLS versions | Forward secrecy | Use case |
|---|---|---|---|---|
| RSA private key | `-k <pem/p12>` | TLS 1.2 RSA only | No (RSA key exchange) | Legacy VoIP systems, Asterisk/FreeSWITCH with RSA ciphers |
| Key log file | `--keylog <file>` | TLS 1.2 all + TLS 1.3 | Yes (ephemeral keys captured) | Production debugging when endpoint exports SSLKEYLOGFILE |
| Key log file (live) | `--keylog <file> --keylog-watch` | Same | Same | Live capture: endpoint writes keys, sipnab tails the file |
| PCAP-NG embedded DSB | (automatic) | All | Depends on capture | Pcap files with embedded Decryption Secrets Blocks |

- [ ] Feature-gated (`--features tls`)
- [ ] RSA private key loading (`-k`):
  - PEM format (`-----BEGIN PRIVATE KEY-----` or `-----BEGIN RSA PRIVATE KEY-----`)
  - PKCS#12 format (`.p12`/`.pfx`) with password prompt on stdin
  - Key validation: verify the key is a valid RSA private key before starting capture
  - **File permission check:** warn on `o+r` (D11)
  - **mlock key material** to prevent swap (D19). Fallback to normal read with warning if mlock fails.
  - Only works for TLS 1.2 with RSA key exchange (not DHE/ECDHE)
  - Print clear message if cipher suite is ephemeral: `TLS session uses ECDHE — RSA key cannot decrypt. Use --keylog instead.`
- [ ] Key log file (`--keylog`):
  - Parse NSS Key Log Format: `CLIENT_RANDOM <hex> <hex>`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET <hex> <hex>`, etc.
  - Load all keys at startup for pcap file analysis
  - `--keylog-watch`: tail the file for new keys during live capture (inotify on Linux, kqueue on macOS)
  - Match keys to TLS sessions by Client Random
  - Works for TLS 1.2 (all key exchanges) and TLS 1.3
  - **File permission check:** warn on `o+r`
- [ ] PCAP-NG Decryption Secrets Block (DSB):
  - Automatically detect and extract DSBs when reading pcap-ng files
  - No additional flags needed — if keys are in the capture, use them
- [ ] TLS record layer parsing:
  - Reassemble TLS records across TCP segments
  - Decrypt application data using negotiated cipher suite
  - Extract SIP payload from decrypted records
  - Feed decrypted SIP payload into the standard SIP parser
- [ ] **Decryption isolation (D19):**
  - All key material stored in `zeroize`-backed types (zeroed on drop)
  - Key material lifecycle: `Loaded → Active → Expired` (zeroed immediately on expiry, not deferred)
  - `prctl(PR_SET_DUMPABLE, 0)` when decryption active (disable core dumps). `--allow-coredump` to override.
  - Key material never crosses IPC boundaries to child processes
  - Startup banner on stderr when decryption is active
  - Key material never logged at any level
  - Key material never in JSON output, API responses, or pcap exports (unless `--pcap-export-mode encrypted+dsb`)
  - Audit log: `DECRYPTION session=<id> cipher=<suite> src=<ip> dst=<ip>` at INFO level (no key values)
  - Decryption session counter: `sipnab_decryption_sessions_total` Prometheus metric

**Gate — 5.3 is done when:**
- [ ] RSA decryption: test pcap with TLS 1.2 RSA key exchange + provided RSA key → SIP payload decrypted, matches known plaintext
- [ ] ECDHE rejection: TLS 1.2 ECDHE session + RSA key → clear message: "ECDHE — use --keylog"
- [ ] Keylog TLS 1.2: test pcap + keylog file → decryption successful for DHE/ECDHE
- [ ] Keylog TLS 1.3: test pcap + keylog file → decryption successful
- [ ] Keylog watch: `--keylog-watch` + new key appended during capture → new session decrypted
- [ ] PCAP-NG DSB: test pcap-ng with embedded DSB → automatic decryption, no flags needed
- [ ] Permission check: world-readable key file → WARNING printed to stderr
- [ ] mlock: key file loaded with mlock (verified via /proc/self/status VmLck > 0, or graceful fallback with warning)
- [ ] Core dump disabled: `PR_SET_DUMPABLE` = 0 when decryption active (verified via /proc/self/status)
- [ ] `--allow-coredump` overrides: core dumps re-enabled
- [ ] Key not in logs: `SIPNAB_LOG=trace` capture with decryption → `grep -i "secret\|master\|key=" trace.log` returns 0 matches (excluding "keylog" flag references)
- [ ] Key not in JSON: `--json` output for decrypted dialog → no key material, only `"tls_decrypted": true`
- [ ] Key not crosses IPC: if API child running, dialog detail response contains `"tls_decrypted": true` but no key data
- [ ] `--pcap-export-mode raw`: output pcap → no DSB section, no decrypted content
- [ ] `--pcap-export-mode decrypted`: output pcap → plaintext SIP in UDP frames
- [ ] `--pcap-export-mode encrypted+dsb`: output pcap-ng → original encrypted + DSB with keys
- [ ] Startup banner: "sipnab: TLS decryption active (keyfile loaded)." printed to stderr
- [ ] Audit log: decryption event logged at INFO with session ID, cipher, src/dst — no key values
- [ ] PKCS#12: `.p12` file with password → password prompt, successful decryption
- [ ] Invalid key file: corrupt PEM → clear error message, exit non-zero

**Docs — 5.3 deliverables:**
- [ ] Rustdoc on `capture/tls.rs`
- [ ] `docs/tls-decryption.md` — TLS decryption guide: key input methods (RSA, keylog, DSB), supported TLS versions, cipher suites, security guardrails, troubleshooting ("ECDHE — use --keylog")
- [ ] `docs/key-management.md` — key file security: permissions, mlock, zeroize, core dump behavior, audit trail, key lifecycle
- [ ] `docs/pcap-export-modes.md` — pcap export modes: decrypted, encrypted+dsb, raw — when to use each, implications for key material

### 5.4 — Prometheus Metrics

- [ ] `output::prometheus` — HTTP `/metrics` endpoint (`--metrics`, default bind 127.0.0.1:9100 per D18):
  - **Non-loopback bind prints warning** if no TLS configured
  - `--metrics-auth <user:pass>` for basic auth
  - `sipnab_dialogs_total{state="completed|failed|active"}`
  - `sipnab_messages_total{method="INVITE|REGISTER|..."}`
  - `sipnab_responses_total{code="2xx|3xx|4xx|5xx|6xx"}` — **bucketed by class, not individual code, to prevent cardinality explosion**
  - `sipnab_rtp_streams_active` — gauge
  - `sipnab_rtp_streams_total{status="active|ended|orphaned"}` — counter
  - `sipnab_rtp_jitter_seconds` — **histogram, no per-stream label**. Buckets: 0.01, 0.02, 0.05, 0.1, 0.2, 0.5s
  - `sipnab_rtp_packet_loss_ratio` — histogram. Buckets: 0.001, 0.005, 0.01, 0.02, 0.05, 0.1
  - `sipnab_rtp_mos` — histogram. Buckets: 1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 4.3
  - `sipnab_rtp_packets_total` — counter
  - `sipnab_rtp_orphaned_streams_total` — counter
  - `sipnab_rtcp_reports_total{type="sr|rr|xr|bye"}` — counter
  - `sipnab_security_alerts_total{type="scanner|fraud|reg_flood|auth_fail"}`
  - `sipnab_capture_packets_total`
  - `sipnab_capture_bytes_total`
  - `sipnab_capture_errors_total`
  - `sipnab_reassembly_timeouts_total{type="ip|tcp"}`
  - `sipnab_decryption_sessions_total` — counter (D19 audit)
  - `sipnab_store_overflow_total{store="dialog|stream|reassembly"}` — counter (D17 monitoring)
  - `sipnab_pdd_seconds` — histogram: post-dial delay. Buckets: 0.5, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 30.0
  - `sipnab_setup_time_seconds` — histogram: INVITE to 200 OK. Same buckets.
  - `sipnab_ring_duration_seconds` — histogram: 180 to 200 OK. Buckets: 1, 5, 10, 20, 30, 60
  - `sipnab_retransmissions_total{method="INVITE|REGISTER|..."}` — counter
  - `sipnab_concurrent_calls{endpoint="<ip>"}` — gauge: active calls per endpoint. **Cardinality controlled:** only top 100 endpoints by call volume; remaining aggregated as `endpoint="other"`.
  - `sipnab_one_way_audio_total` — counter: calls with one-way audio detected
  - `sipnab_nat_mismatch_total` — counter: streams where SDP/actual address differ
  - `sipnab_diagnosis_total{type="one_way|nat_mismatch|no_media|retransmit_storm|slow_setup"}` — counter

**Gate — 5.4 is done when:**
- [ ] `/metrics` endpoint returns valid Prometheus exposition format (tested with `promtool check metrics`)
- [ ] Real Prometheus instance scrapes endpoint successfully at 15s interval for 5 minutes
- [ ] All documented metrics present in output
- [ ] Histogram buckets correct for PDD, jitter, loss, MOS
- [ ] Localhost default: `--metrics :9100` binds 127.0.0.1 (verified with `ss -tlnp`)
- [ ] Non-loopback warning: `--metrics 0.0.0.0:9100` → WARNING printed
- [ ] Basic auth: `--metrics-auth user:pass` → unauthenticated request returns 401
- [ ] Cardinality: concurrent_calls endpoint metric limited to top 100 endpoints
- [ ] Diagnosis metrics: one-way audio in test pcap → `sipnab_diagnosis_total{type="one_way"}` incremented
- [ ] PDD metric: known PDD in test pcap → correct histogram bucket incremented

**Docs — 5.4 deliverables:**
- [ ] Rustdoc on `output/prometheus.rs`
- [ ] `docs/prometheus.md` — Prometheus integration guide: all metrics with descriptions, label values, histogram buckets, scrape configuration, recommended recording rules
- [ ] `docs/grafana-dashboard.md` — example Grafana dashboard: panels for call rate, PDD, MOS distribution, concurrent calls, security alerts (include JSON dashboard definition)
- [ ] `contrib/grafana/sipnab-dashboard.json` — importable Grafana dashboard
- [ ] `contrib/prometheus/sipnab-alerts.yml` — example alerting rules for Prometheus Alertmanager

### 5.5 — Wireshark & tshark Integration

- [ ] `--wireshark` — generate Wireshark display filters for matched dialogs
- [ ] `--tshark-filter` — generate full tshark command lines for copy-paste deep-dive
  - Auto-detect whether pcap file or live capture, adjust command accordingly
  - Include RTP stream filters when RTP is active
- [ ] Export selected dialogs as pcap for Wireshark analysis (TUI: F2 → pcap)
- [ ] `--hexdump` — raw hex+ASCII packet dump for quick port verification

**Gate — 5.5 is done when:**
- [ ] `--wireshark` output: valid Wireshark display filter (tested with `tshark -Y "<output>" -r test.pcap`)
- [ ] `--tshark-filter`: runnable tshark command (executed successfully against test pcap)
- [ ] RTP stream filters included when RTP active
- [ ] Pcap export (F2 in TUI): exported pcap opens in Wireshark without errors

**Docs — 5.5 deliverables:**
- [ ] `docs/wireshark-integration.md` — update with Wireshark/tshark workflow: find in sipnab → export filter → deep-dive in Wireshark

### 5.6 — SRTP Decryption

SRTP (RFC 3711) encrypts RTP media streams. Decryption requires the SRTP master key.

**Key source chain (automatic):**

```
SDP a=crypto (SDES)  ──► SRTP master key ──► decrypt RTP headers + payload
      │                                           │
      ├─ plaintext SIP → read directly            ├─ jitter/loss/MOS from decrypted headers
      └─ TLS SIP → decrypt TLS first (5.3)        └─ DTMF extraction from payload
                                                   └─ codec identification
```

- [ ] **SDES key extraction from SDP** (automatic, no user input needed):
  - Parse `a=crypto:<tag> <suite> <key-params>` from SDP
  - Supported suites: `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`, `AES_256_CM_HMAC_SHA1_80`
  - Extract base64-encoded master key + master salt
  - Associate key with the RTP stream by SSRC and media IP:port from SDP
  - When SIP is over TLS, SDES extraction happens after TLS decryption (see 5.3)
  - **SRTP keys stored in zeroize-backed types** (D19)
- [ ] **DTLS-SRTP key log** (`--dtls-keylog`):
  - Parse DTLS key log file (same NSS format as TLS keylog, but for DTLS sessions)
  - Extract SRTP master key from DTLS handshake
  - Associate with RTP streams by ICE candidate IP:port pairs
  - Used for WebRTC and other DTLS-SRTP endpoints
  - **Requires explicit operator action** — endpoint must export DTLS keys
- [ ] **Manual key file** (`--srtp-keys`, for testing/debugging only):
  - Format: one line per stream, `ssrc=<decimal> key=<base64> [salt=<base64>] [suite=<name>]`
  - Intended for controlled test environments, not production
  - Print warning: `WARNING: manual SRTP keys loaded — use only in test environments`
- [ ] **ZRTP detection (no decryption):**
  - Detect ZRTP `Hello` packets in RTP stream
  - Display ZRTP SAS (Short Authentication String) if captured
  - Mark stream as `ZRTP-encrypted` in TUI and JSON output
  - **No decryption attempted** — ZRTP is end-to-end
- [ ] **Decrypted RTP processing:**
  - Feed decrypted RTP headers to quality metrics engine (5.2)
  - Extract DTMF from RFC 4733 telephone-event payloads in decrypted stream
  - Codec identification from decrypted payload type
  - Display decryption status per stream in TUI call flow view
- [ ] **Security guardrails:**
  - SRTP keys zeroed from memory when stream ends (zeroize)
  - SDES keys extracted from SDP are used internally, never echoed in output
  - Manual key file (`--srtp-keys`) triggers explicit warning
  - Pcap export follows `--pcap-export-mode` setting

**Gate — 5.6 is done when:**
- [ ] SDES extraction: test pcap with `a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:base64key` → key extracted, SRTP decrypted
- [ ] SDES via TLS: TLS-encrypted SIP → TLS decrypted → SDP parsed → SDES key extracted → SRTP decrypted (end-to-end chain)
- [ ] All three SDES suites: AES_CM_128_HMAC_SHA1_80, AES_CM_128_HMAC_SHA1_32, AES_256_CM_HMAC_SHA1_80
- [ ] DTLS keylog: test pcap + DTLS keylog file → SRTP decrypted
- [ ] Manual keys: `--srtp-keys` file → SRTP decrypted, WARNING printed
- [ ] ZRTP detection: ZRTP Hello in test pcap → stream marked ZRTP-encrypted, SAS displayed, no decryption attempted
- [ ] Decrypted quality: decrypted RTP headers fed to quality engine → jitter/loss/MOS calculated
- [ ] Decrypted DTMF: DTMF in SRTP → extracted after decryption
- [ ] Key zeroize: after stream ends, SRTP key memory is zeroed (verified via memory inspection or zeroize test)
- [ ] SDES keys not in output: JSON for SRTP stream → `"encryption": "SRTP"`, no key material
- [ ] TUI: SRTP lock icon on encrypted streams in ladder

**Docs — 5.6 deliverables:**
- [ ] Rustdoc on `rtp/srtp.rs`, `capture/dtls.rs`
- [ ] `docs/srtp-decryption.md` — SRTP decryption guide: SDES automatic extraction, DTLS-SRTP keylog, manual key file, ZRTP detection, decryption chain diagram, security guardrails
- [ ] Update `docs/key-management.md` with SRTP key handling

### 5.7 — Decryption Legal & Compliance Guardrails

- [ ] **First-run notice:** On first invocation with any decryption flag, print to stderr:
  ```
  NOTICE: Decrypting network traffic may be subject to local laws including wiretap
  statutes, ECPA (US), RIPA (UK), and equivalent regulations. Ensure you have proper
  authorization before decrypting traffic you do not own. sipnab does not provide
  legal advice. See sipnab.com/legal for more information.
  ```
  The notice is shown once per terminal session (tracked via an environment variable `SIPNAB_LEGAL_ACK=1` that the user can set to suppress).
- [ ] **Audit trail:** When decryption is active, sipnab writes to syslog (if `--syslog` enabled) or a dedicated audit log:
  - Timestamp, user (UID), key source (keyfile/keylog/sdes/dtls/manual), number of sessions decrypted
  - No key material in the audit log
- [ ] **No key generation or MITM capability:** sipnab cannot generate TLS certificates, perform TLS interception, or act as a man-in-the-middle proxy. It only decrypts traffic for which the operator already possesses legitimate keys.
- [ ] **Documentation:** sipnab.com/legal page documents:
  - What sipnab can and cannot decrypt
  - When decryption is lawful (your own servers, authorized testing, CALEA compliance)
  - How to restrict decryption access (file permissions, separate user account)
  - How to verify decryption was not used (check audit log)

**Gate — 5.7 is done when:**
- [ ] First-run notice: first invocation with `-k` → NOTICE printed to stderr
- [ ] `SIPNAB_LEGAL_ACK=1` set → NOTICE suppressed
- [ ] Audit trail: `--syslog` enabled + decryption active → syslog entry with timestamp, UID, key source, session count (no key material)
- [ ] No MITM: sipnab cannot generate certificates or perform TLS interception (verified: no cert generation code exists)

**Docs — 5.7 deliverables:**
- [ ] `docs/legal-compliance.md` — legal and compliance guide: what sipnab can/cannot decrypt, lawful use cases, audit trail, restricting access, operator responsibilities
- [ ] `sipnab.com/legal` content draft — published as part of website in Phase 7

---

## Phase 6 — API & Daemon Mode

**Goal:** API access, daemon mode, systemd integration.
**Milestone:** `sipnab --api :8080 -d eth0` serves live capture data via REST.
**Release target:** Contributes to v0.3.0.

**Exit criteria — Phase 6 is done when:**
- [ ] REST API serves dialog list, detail, and pcap export with correct JSON
- [ ] **API runs in isolated child process** (D16), verified by PID check
- [ ] **API binds to localhost by default** (D18)
- [ ] **API with non-loopback bind + no TLS prints warning**
- [ ] WebSocket stream delivers events within 100ms of capture
- [ ] API key authentication works correctly (reject unauthenticated requests)
- [ ] **API rate limiting enforced** (100 req/sec per source IP)
- [ ] **API max connections enforced** (default: 100)

### 6.1 — REST API Daemon Mode

- [ ] Feature-gated (`--features api`)
- [ ] **Runs in isolated child process** (D16):
  - Fork after main process setup
  - Child receives dialog/stream data via Unix socket IPC from main process
  - Child has no access to capture fd or key material
  - Child crash does not affect capture pipeline
- [ ] REST via axum (`--api`, default bind 127.0.0.1:8080 per D18)
- [ ] **TLS support:** `--api-tls-cert` + `--api-tls-key` for HTTPS. Warning on non-loopback without TLS.
- [ ] Endpoints:
  - `GET /v1/dialogs?offset=0&limit=50&state=active&from=pattern` — paginated dialog list with filters
  - `GET /v1/dialogs/:call_id` — dialog detail with messages, streams, timing, SDP timeline, diagnosis, correlated legs
  - `GET /v1/dialogs/:call_id/flow` — ladder diagram as JSON (includes RTP bars)
  - `GET /v1/dialogs/:call_id/pcap` — download dialog as pcap (includes RTP if captured)
  - `GET /v1/streams?offset=0&limit=50&orphaned=true&mos_below=3.5` — paginated stream list with quality filters
  - `GET /v1/streams/:ssrc` — stream detail with per-interval quality metrics
  - `GET /v1/dialogs/:call_id/report` — structured call diagnosis report (same as `--call-report` CLI output)
  - `GET /v1/stats` — current statistics (dialogs + streams + quality summary + timing percentiles + concurrent calls + diagnosis counts + decryption session count)
  - `GET /v1/alerts?since=<iso8601>` — recent security alerts
  - `WS /v1/stream` — WebSocket stream of real-time events (NDJSON)
  - All responses include `"schema_version": 1` for forward compatibility
  - **No key material in any response** (D19). Decrypted dialogs show `"tls_decrypted": true`, nothing more.
- [ ] Authentication: `--api-key` required. Requests without valid `Authorization: Bearer <key>` get 401.
- [ ] **Rate limiting:** 100 requests/sec per source IP. 503 on exceed.
- [ ] **Max connections:** 100 concurrent (default). Configurable via `--api-max-conn`.
- [ ] **Max request body:** 1 MB. 413 on exceed.
- [ ] **Systemd integration:**
  - `Type=notify` readiness notification (sd_notify READY=1 after capture device opened)
  - Watchdog support (sd_notify WATCHDOG=1 periodic ping)
  - Example `sipnab.service` unit file in `contrib/`
- [ ] **Syslog output** (`--syslog`): alerts and security events to syslog facility `local0`

**Gate — 6.1 is done when:**
- [ ] All GET endpoints return valid JSON with `schema_version: 1`
- [ ] `/v1/dialogs`: pagination works (offset, limit), filters work (state, from pattern)
- [ ] `/v1/dialogs/:call_id`: returns complete dialog with messages, streams, timing, sdp_timeline, diagnosis, correlated_legs
- [ ] `/v1/dialogs/:call_id/report`: returns same content as CLI `--call-report`
- [ ] `/v1/dialogs/:call_id/flow`: returns ladder diagram as JSON (arrows, RTP bars, timing)
- [ ] `/v1/dialogs/:call_id/pcap`: returns valid pcap file download (SIP + RTP packets)
- [ ] `/v1/streams`: pagination and filters work (orphaned, mos_below)
- [ ] `/v1/streams/:ssrc`: returns per-interval quality metrics
- [ ] `/v1/stats`: timing percentiles, concurrent calls, diagnosis counts, decryption count present
- [ ] `/v1/alerts`: filters by since parameter, returns recent alerts
- [ ] WebSocket `/v1/stream`: connects, receives NDJSON events within 100ms of capture
- [ ] API key auth: request without `Authorization: Bearer <key>` → 401
- [ ] API key auth: valid key → 200
- [ ] Isolated child: API child PID ≠ main process PID
- [ ] API child crash: kill API child → main process continues capturing, API restarts (or logged)
- [ ] Localhost default: `--api :8080` binds 127.0.0.1
- [ ] Non-loopback without TLS: `--api 0.0.0.0:8080` → WARNING printed
- [ ] Non-loopback with TLS: `--api 0.0.0.0:8080 --api-tls-cert ... --api-tls-key ...` → no warning, HTTPS works
- [ ] Rate limiting: 150 req/sec from one IP → 50 get 503
- [ ] Max connections: 101st concurrent connection → 503
- [ ] Max body size: 2MB POST body → 413
- [ ] No key material: `/v1/dialogs/:call_id` for decrypted dialog → `"tls_decrypted": true`, no keys
- [ ] Systemd: `Type=notify` → sd_notify READY=1 after capture device opened (tested in systemd)
- [ ] Syslog: `--syslog` → security events appear in syslog (tested with `journalctl`)

**Docs — 6.1 deliverables:**
- [ ] Rustdoc on `output/grpc.rs` (API implementation)
- [ ] `docs/api-reference.md` — REST API reference: all endpoints, request/response schemas, authentication, rate limiting, pagination, WebSocket protocol (OpenAPI/Swagger spec recommended)
- [ ] `docs/api-guide.md` — API usage guide: getting started, authentication, common queries, WebSocket streaming, integration examples (curl, Python requests, JavaScript fetch)
- [ ] `docs/daemon-mode.md` — daemon deployment guide: systemd setup, syslog configuration, privilege model in daemon mode, monitoring the daemon
- [ ] `contrib/sipnab.service` — systemd unit file with documentation comments
- [ ] `contrib/sipnab-api.env` — example environment file for daemon mode
- [ ] Update `man/sipnab.1` with API and daemon flags

---

## Phase 7 — Polish, Packaging, Release

**Goal:** Production release.
**Milestone:** v0.3.0 on crates.io, .deb, .rpm, Docker, sipnab.com live.

### 7.1 — Cross-Cutting Tests (per-phase tests already complete)

- [ ] **Extended fuzz testing:** `cargo-fuzz` on all parsers and reassembly — run for ≥ 24 hours with no crashes
- [ ] **Comparison benchmarks:** same pcap files through sipnab, sngrep, and sipgrep — document throughput, memory, and correctness differences
- [ ] **Real-world validation:** run sipnab on a production SIP server (Planet Networks) for 24 hours, compare dialog counts against OpenSIPS CDR records
- [ ] **Pcap corpus complete:** ≥ 50 pcaps covering all documented scenarios
- [ ] **sngrep regression:** verify sipnab produces identical dialog counts and state for all 11 sngrep test pcaps
- [ ] **Security test suite:** malformed input corpus, oversized messages, hash flooding attempts, ReDoS patterns, scanner-kill amplification tests, API fuzzing
- [ ] **Privilege separation verification:** end-to-end test confirming main process drops privileges, scanner kill child is isolated, API child cannot access capture fd

**Gate — 7.1 is done when:**
- [ ] Fuzz: 24-hour run on all parsers (SIP, SDP, RTP, RTCP, HEP, TCP reassembly, IP reassembly, filter DSL) — zero crashes
- [ ] Comparison: sipnab dialog count matches sngrep for all 11 test pcaps
- [ ] Comparison: sipnab throughput ≥ sngrep for same pcap (documented benchmark results)
- [ ] Real-world: 24-hour production run dialog count within 1% of OpenSIPS CDR count
- [ ] Pcap corpus: ≥ 50 pcaps, each with documented expected output
- [ ] Security test suite: all malformed input, overflow, ReDoS, amplification tests pass
- [ ] Priv sep: end-to-end verified on Linux (priv drop, scanner kill child, API child)

**Docs — 7.1 deliverables:**
- [ ] `docs/testing.md` — test suite documentation: how to run tests, test categories, pcap fixture inventory, fuzz testing instructions, benchmark instructions
- [ ] `docs/internals/security-testing.md` — security test cases: what is tested, expected behavior, how to add new security tests
- [ ] `benchmarks/README.md` — benchmark results: throughput, memory, comparison with sngrep/sipgrep

### 7.2 — CI/CD (GitHub Actions)

- [ ] Build: Linux x86_64, aarch64 (Jetson), macOS, FreeBSD
- [ ] Test suite on all platforms
- [ ] Clippy + rustfmt + deny(unsafe)
- [ ] `cargo audit` + `cargo deny` (already in CI from Phase 1)
- [ ] Release builds with cross-compilation (musl static binaries)
- [ ] Publish to crates.io on tag
- [ ] Docker image build and push

**Gate — 7.2 is done when:**
- [ ] CI builds succeed on: Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64
- [ ] Test suite passes on all CI platforms
- [ ] Clippy + rustfmt + deny(unsafe) + cargo-audit + cargo-deny all pass in CI
- [ ] Release builds produce correct musl static binaries (verified: `file` command shows static)
- [ ] Docker image builds and runs (`docker run ghcr.io/normb/sipnab --version`)
- [ ] crates.io publish dry-run succeeds (`cargo publish --dry-run`)

**Docs — 7.2 deliverables:**
- [ ] `.github/workflows/` — CI workflow files with inline comments explaining each step
- [ ] `docs/internals/ci-cd.md` — CI/CD pipeline documentation: what runs, when, how to debug failures, how to add new platforms

### 7.3 — Packaging

- [ ] `cargo install sipnab`
- [ ] Static musl binaries on GitHub Releases (Linux x86_64, aarch64)
- [ ] Debian .deb package
- [ ] RPM package
- [ ] Homebrew formula
- [ ] Docker: `ghcr.io/normb/sipnab`
- [ ] AUR package
- [ ] Man page: `sipnab.1` (finalized — skeleton from Phase 1, populated across phases)
- [ ] `contrib/sipnab.service` — systemd unit file (from Phase 6)
- [ ] `contrib/fail2ban/` — fail2ban filter and jail configuration (from Phase 4)

**Gate — 7.3 is done when:**
- [ ] `cargo install sipnab` from crates.io (dry-run) installs working binary
- [ ] Static musl binary runs on minimal Alpine container (no glibc)
- [ ] `.deb` installs on Debian 12 / Ubuntu 22.04: `dpkg -i sipnab.deb && sipnab --version`
- [ ] `.rpm` installs on RHEL 9 / Fedora 39: `rpm -i sipnab.rpm && sipnab --version`
- [ ] Homebrew formula: `brew install sipnab && sipnab --version`
- [ ] Docker: `docker run --rm ghcr.io/normb/sipnab --version` returns correct version
- [ ] AUR: PKGBUILD builds successfully on Arch Linux
- [ ] Man page: `man sipnab` renders correctly with all sections populated
- [ ] aarch64 binary runs on Jetson AGX Thor (or equivalent ARM64)

**Docs — 7.3 deliverables:**
- [ ] `docs/install.md` — installation guide for all platforms: cargo, static binary, deb, rpm, homebrew, docker, AUR, building from source
- [ ] Package-specific READMEs in `contrib/deb/`, `contrib/rpm/`, `contrib/homebrew/`, `contrib/docker/`

### 7.4 — Documentation & Website

- [ ] README.md: feature matrix, install, quick start, screenshots
- [ ] SECURITY.md: vulnerability reporting process, security model overview
- [ ] sipnab.com (GitHub Pages):
  - Landing page with demo GIF
  - Feature comparison: sipnab vs sngrep vs sipgrep
  - Install guide (all platforms)
  - User manual
  - Filter DSL reference guide
  - Security features guide (threat model summary, privilege separation, key handling)
  - API reference
  - Blog: "Why we built sipnab"
- [ ] CHANGELOG.md, CONTRIBUTING.md (CONTRIBUTING.md shipped in Phase 1, updated here)
- [ ] **Migration guide for sngrep users:**
  - Keybinding comparison table (sngrep key → sipnab key)
  - CLI flag translation table (every sngrep flag → sipnab equivalent)
  - Config file migration (sngrep `.sngreprc` INI format → sipnab TOML, with a converter script)
  - Behavioral differences: what sipnab does differently by design
  - Known incompatibilities: sngrep features intentionally not replicated and why

**Gate — 7.4 is done when:**
- [ ] README.md: feature matrix accurate (cross-referenced with actual `--help` output)
- [ ] All `docs/*.md` files: no broken internal links, no placeholder text, no TODO markers
- [ ] sipnab.com builds and deploys (GitHub Pages or equivalent)
- [ ] sipnab.com/legal content reviewed and published
- [ ] Man page: `man sipnab` complete with all flags, examples, and SEE ALSO section
- [ ] Migration guide: every sngrep flag accounted for with sipnab equivalent or "not supported" explanation
- [ ] CHANGELOG.md: complete for v0.1.0-alpha through v0.3.0

**Docs — 7.4 deliverables:**
- [ ] All user-facing documentation finalized and cross-linked (docs/ directory)
- [ ] sipnab.com website content (landing page, feature comparison, install guide, user manual, all guides)
- [ ] `docs/migration-sngrep.md` — sngrep migration guide (keybindings, flags, config, behavioral differences)
- [ ] CHANGELOG.md — all changes from v0.1.0-alpha through v0.3.0
- [ ] Doc review: all docs proofread for technical accuracy, tested examples verified

### 7.5 — Release

- [ ] Tag v0.3.0
- [ ] Publish to crates.io
- [ ] Announce: VoIP mailing lists, OpenSIPS Summit, Reddit r/rust, r/VOIP, Hacker News

**Gate — 7.5 is done when:**
- [ ] `git tag v0.3.0` signed and pushed
- [ ] crates.io publish successful: `cargo install sipnab` works from crates.io
- [ ] GitHub Release: binaries uploaded, release notes written, checksums published
- [ ] Docker image tagged and pushed: `ghcr.io/normb/sipnab:0.3.0` and `ghcr.io/normb/sipnab:latest`
- [ ] sipnab.com updated with v0.3.0 content
- [ ] Announcement posts: drafted, reviewed, published

**Docs — 7.5 deliverables:**
- [ ] Release notes for v0.3.0 (GitHub Release + CHANGELOG.md)
- [ ] Announcement blog post: "Introducing sipnab" (sipnab.com/blog)
- [ ] Announcement posts: VoIP mailing lists, Reddit, Hacker News (drafted, factual, non-promotional)

---

## Timeline Estimate

Each phase includes its own exit criteria and tests. Estimates adjusted for single-developer reality on a greenfield Rust project with FFI boundaries, protocol edge cases, and cross-platform requirements.

| Phase | Scope | Effort | Depends on | Release |
|-------|-------|--------|------------|---------|
| 1 | Capture engine, reassembly, pcap I/O, priv drop, CI | 3-4 weeks | — | — |
| 2 | SIP parser, **RTP stream engine**, dialog engine, filter DSL, transaction timing, one-way audio diagnosis, multi-leg correlation, SDP timeline, call reports, CLI output, JSON, event exec | 6-8 weeks | Phase 1 | **v0.1.0-alpha** |
| 3 | Interactive TUI (all views including **Stream List**) | 4-5 weeks | Phase 2 | — |
| 4 | Security: scanner kill (isolated), fraud, digest, alerting | 2-3 weeks | Phase 2 | **v0.2.0-beta** (with Phase 3) |
| 5 | STIR/SHAKEN, **advanced RTP analysis**, TLS/SRTP decryption, Prometheus | 4-6 weeks | Phase 2 | — |
| 6 | REST API (isolated child), daemon mode, systemd | 2-3 weeks | Phase 2 | — |
| 7 | Cross-cutting tests, packaging, docs, release | 3-4 weeks | All | **v0.3.0** |
| **Total (serial)** | | **24-35 weeks** | | |
| **Total (phases 3-5 parallel)** | | **19-27 weeks** | | |

**Key milestones:**
- **Week 9-12:** v0.1.0-alpha — usable CLI tool with VoIP diagnosis, first external feedback
- **Week 15-20:** v0.2.0-beta — full TUI + security features
- **Week 24-35:** v0.3.0 — complete vision

---
