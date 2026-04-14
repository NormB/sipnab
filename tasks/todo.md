# sipnab Feature Plan

> Last updated: 2026-04-13
> Based on audit of actual code vs implementation-plan-v6.md

## Current State

**Version:** 0.3.1
**Codebase:** ~33K lines of Rust across 42 source files
**Tests:** 847 total (486 unit, 85 CLI integration, 35 TUI snapshot, 174 TUI state, 5 fuzz targets, 13 E2E, etc.)
**CI:** GitHub Actions (multi-OS build, clippy, fmt, audit, deny, fuzz compile check)

### What's Solid

- Full SIP capture pipeline: live device, pcap file, HEP v2/v3, WebSocket
- Zero-copy SIP parser, dialog state machine, SDP parser
- RTP first-class: stream tracking, jitter/loss/MOS, burst/gap, DTMF, RTCP SR/RR/XR
- Interactive TUI: call list, stream list, ladder diagram, raw viewer, help, save, filter, settings
- CLI mode: sipgrep-compatible with JSON/NDJSON output
- Filter DSL: 27 fields, 7 operators, diagnostic aliases
- Security: scanner detect/kill, digest leak, reg flood, toll fraud, alerting
- TLS 1.2 + 1.3 decryption via SSLKEYLOGFILE (ring backend)
- SRTP auth verification (HMAC-SHA1, SDES key extraction)
- REST API: 8 endpoints, bearer auth, rate limiting, pagination
- Prometheus metrics: counters, histograms, HTTP server
- Privilege separation, process isolation, fail2ban output
- Call diagnosis reports (text, JSON, Markdown)
- VoIP diagnosis: PDD/timing, one-way audio (CN-aware), NAT mismatch, SDP timeline
- STIR/SHAKEN JWT parsing (attestation A/B/C, claims extraction)
- Multi-leg B2BUA/SBC correlation (X-Call-ID + Via branch + timing heuristic)
- REFER transfer detection with timing
- SIPREC metadata parsing (RFC 7866)
- RTCP XR parsing with VoIP Metrics (RFC 3611)
- Comfort noise / silence detection (reduces false-positive one-way audio)
- Wireshark display filter translation + tshark command generation
- PCAP-NG Decryption Secrets Block (DSB) export
- Semantic theme (10 configurable color slots, hex RGB support)
- Configurable keybindings (11 remappable actions via TOML config)

---

## Completed (this session)

- [x] **Cargo.toml cleanup** — Removed stub features (tls-wolfssl, tls-openssl, grpc), synced version to 0.3.1
- [x] **Clippy clean** — Fixed collapsible_if, stale doc comment, TransportProto callsite
- [x] **F4 Extended View** — Opens call flow in extended multi-leg mode from call list
- [x] **F8 Settings Popup** — Runtime toggle for color mode, timestamps, autoscroll, raw preview, SDP display, syntax highlighting
- [x] **Multi-leg correlation scoring** — X-Call-ID (100), Via branch (80), timing heuristic (50) with threshold filtering
- [x] **Transfer detection** — REFER → Transferring state, NOTIFY terminated → InCall, timing fields, SdpEvent::Transfer
- [x] **SIPREC metadata parsing** — Multipart/mixed boundary extraction, XML string parsing, session/participant/stream extraction
- [x] **Wireshark display filter export** — DSL field name translation to Wireshark syntax
- [x] **tshark command generation** — Build tshark CLI from capture config
- [x] **RTCP XR parsing** — Extended Reports (PT=207) with VoIP Metrics, ReceiverReferenceTime, Loss/Duplicate RLE
- [x] **Silence/CN detection** — PT=13 tracking, silence periods, CN-aware one-way audio diagnosis
- [x] **PCAP-NG DSB** — Decryption Secrets Block via UnknownBlock for TLS keylog embedding
- [x] **Config warning logs** — Warns when theme/keybindings config loaded but not applied
- [x] **TLS 1.2 doc fix** — Updated stale comment claiming TLS 1.2 PRF was unimplemented (it was)
- [x] **Semantic theme system** — 10-slot theme (background, foreground, header, selected, accent, good, warning, bad, muted, border) replaces 161 hardcoded Color:: refs. Supports named colors + #RRGGBB hex. Config: `[theme] header = "green"`
- [x] **Configurable keybindings** — 11-action keymap (quit, help, save, search, filter, settings, pause, autoscroll, extended_flow, clear_calls, column_selector) replaces hardcoded KeyCode checks. Config: `[keybindings] quit = "x"`

---

## Remaining Gaps

### Capture

- [ ] **SCTP transport parsing**
  - Currently: SCTP detected (proto 132) but logged and discarded
  - Scope: parse SCTP headers, extract SIP payloads from DATA chunks
  - Impact: needed for SIGTRAN/Diameter environments (3GPP IMS)

---

## Tier 3: Differentiating Features

New capabilities not in the original plan that would set sipnab apart.

- [ ] **Live call quality dashboard** — Real-time MOS/jitter/loss graphs in TUI
- [ ] **Pcap export from TUI** — Select dialogs in call list, F2 saves only those
- [ ] **SIP message search-in-body** — `/` search that matches inside SIP message bodies
- [ ] **Call timeline visualization** — Horizontal timeline showing call states
- [ ] **Packet loss map** — Visual representation of RTP packet loss patterns

---

## Tier 4: Long-Term / Exploratory

From implementation-plan-v6.md "Phase 7+" backlog.

- [ ] WASM plugin API (not Lua — D7 design decision)
- [ ] Machine learning anomaly detection (SIP/RTP patterns)
- [ ] Distributed capture cluster management
- [ ] Interactive pcap annotation and sharing
- [ ] YANG/NETCONF machine-readable diagnosis export
- [ ] Homebrew formula, deb/rpm packages, Docker Hub publishing

---

## Decision Log

| Decision | Status | Notes |
|----------|--------|-------|
| wolfSSL/OpenSSL backends | REMOVED | Stub features deleted. ring covers 95% of cases. Re-add if FIPS demand arises. |
| gRPC API | REMOVED | Stub feature + deps deleted. REST API is complete. Re-add if streaming demand arises. |
| STIR/SHAKEN cert verification | DEFERRED | Intentionally skipped — would require HTTP cert fetching, adds attack surface. |
| SCTP parsing | LOW PRIORITY | Only matters for IMS/SIGTRAN environments. |
| WASM plugins | FUTURE | Design decision D7 rules out Lua. WASM is the path if plugins are ever needed. |
| Theme/keybindings config | DONE | 10-slot semantic theme + 11-action keymap, fully wired through all render functions and key handlers. |
