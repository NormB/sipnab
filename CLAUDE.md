# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

sipnab is a Rust binary that unifies **sngrep** (interactive SIP TUI) and **sipgrep** (CLI SIP regex matcher) into one tool, with first-class RTP support, security analysis, VoIP diagnosis, and extensibility. Licensed MIT OR Apache-2.0, authored by Norm Brandinger.

The canonical design reference is `implementation-plan-v6.md` — consult it for design decisions (D1–D21), CLI flags, module responsibilities, threat model, risk register, and phase-by-phase scope with per-subtask gates and documentation deliverables.

## Build & Development

```bash
cargo build                          # debug build
cargo build --release                # release build
cargo build --features full          # all feature gates
cargo test                           # all tests
cargo test sip::parser               # single module tests
cargo clippy -- -D warnings          # lint (treat warnings as errors)
cargo fmt --check                    # format check
cargo audit                          # check dependency vulnerabilities
cargo deny check                     # license + advisory checks
SIPNAB_LOG=trace cargo run -- -N -I test.pcap   # run CLI mode with trace logging
```

### Feature Flags

```
default = []           # core: capture, SIP parsing, TUI, CLI, JSON
tls                    # TLS decryption (pure-Rust: ring/aws-lc-rs)
tls-wolfssl            # wolfSSL backend (FIPS 140-3, DTLS)
tls-openssl            # OpenSSL backend (compat)
hep                    # HEP v2/v3 (Homer)
grpc                   # gRPC API (tonic/prost)
api                    # REST API + Prometheus (axum/tokio)
full                   # all of the above
```

No `lua` feature — embedded scripting was intentionally excluded (D7). Extensibility is via Filter DSL, NDJSON pipeline, and event exec hooks.

## Architecture

### Binary Modes (D1)

- `sipnab` → interactive TUI (sngrep-like)
- `sipnab -N` → CLI print mode (sipgrep-like)
- `sipnab -N --json` → NDJSON streaming

One parser, one dialog engine, one reassembly path — mode only affects output.

### Thread & Process Model (D5, D15, D16)

```
Capture Thread(s)  ──crossbeam──►  Main Thread  ──optional──►  Async Runtime
(pcap_loop, reassembly)            (parse, dialog, filter,     (Prometheus,
                                    TUI or CLI output)          REST API child)
                                         │
                                    Scanner Kill Child (isolated, optional)
```

- Capture threads own their reassembly state — no shared mutables
- Main thread is the **sole writer** to DialogStore and StreamStore
- Privilege drop after device open (D15): `setuid`/`setgid` to unprivileged user
- Scanner kill runs in isolated child process (D16): holds capture fd for injection only
- API runs in isolated child process (D16): no capture fd, no key material
- All network listeners bind to localhost by default (D18)

### Core Design Principles

- **Zero-copy SIP parsing (D3):** Parser operates on `&[u8]` slices. Common path does zero heap allocation.
- **RTP is first-class (D13):** `StreamStore` peers with `DialogStore`. RTP on by default. Orphaned streams visible.
- **VoIP diagnosis is built-in (D20):** Transaction timing, one-way audio detection, NAT mismatch, SDP timeline — always computed, no flags needed.
- **Multi-leg correlation (D21):** Automatic B2BUA leg matching via X-Call-ID, Via branch, timing heuristic.
- **No embedded scripting (D7):** Filter DSL + NDJSON pipeline + event exec hooks instead of Lua/Python.
- **Defense-in-depth (D17):** Explicit size limits on all stores, rate limits on all listeners, regex size limits.
- **Key material isolation (D11, D19):** zeroize-backed types, mlock, no core dumps, no IPC leakage.

### Module Layout

```
src/
├── main.rs / cli.rs / config.rs     # Entry, clap CLI, TOML config
├── capture/                          # Packet capture, reassembly, pcap I/O, HEP, TLS/DTLS
├── sip/                              # Zero-copy parser, dialog state machine, SDP, filters, STIR/SHAKEN
│   ├── dsl.rs                        # Filter DSL parser/evaluator
│   ├── timing.rs                     # Transaction timing: PDD, setup time, retransmit detection
│   ├── correlation.rs                # Multi-leg B2BUA/SBC call correlation
│   ├── response_codes.rs             # SIP response code intelligence
│   └── sdp_timeline.rs              # SDP offer/answer timeline tracking
├── rtp/                              # Stream tracking, RTCP, quality, DTMF, heuristic discovery, SRTP
│   └── diagnosis.rs                  # One-way audio, NAT mismatch, media path analysis
├── security/                         # Scanner detect/kill, fraud, digest leak, reg flood, alerting
├── output/                           # CLI print, JSON, call report, dialog report, hexdump, fail2ban, Prometheus
│   └── call_report.rs               # Structured call diagnosis reports (text/JSON/Markdown)
└── tui/                              # ratatui panels: call list, stream list, ladder, raw/diff, dashboard
```

### Error Handling

- `anyhow::Result` for application-level errors; `thiserror` for domain enums
- **No `.unwrap()` on external input.** Every `unwrap()` must have a safety comment.
- Malformed SIP: store as raw message with `parse_error: true` — never silently drop
- All stores have default size limits (D17): 100K dialogs, 50K streams, 10K reassembly entries

## Performance Targets

| Metric | Target |
|---|---|
| SIP parse throughput | ≥ 100K pps |
| RTP parse throughput | ≥ 500K pps |
| 100K dialogs RSS | ≤ 500 MB |
| 50K streams RSS | ≤ 200 MB |
| TUI redraw (100K dialogs) | ≤ 5 ms |
| Idle CPU | < 0.5% core |
| Default binary (musl, stripped) | ≤ 5 MB |
| One-way audio detection latency | ≤ 6s after call establishment |

## Implementation Phases & Release Milestones

Phase 1 (Capture) → Phase 2 (SIP + RTP + Diagnosis + CLI) → Phases 3/4/5 parallel (TUI, Security, Analysis) → Phase 6 (API) → Phase 7 (Release).

- **v0.1.0-alpha** (Phases 1+2): CLI tool with VoIP diagnosis, ~9-12 weeks
- **v0.2.0-beta** (+Phases 3+4): Full TUI + security features, ~15-20 weeks
- **v0.3.0** (+Phases 5+6+7): Complete vision, ~24-35 weeks

Every subtask has explicit **Gate** (test criteria) and **Docs** (documentation deliverables). Testing is per-phase; fuzz testing starts in Phase 1.
