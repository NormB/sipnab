# Changelog

All notable changes to sipnab will be documented in this file.

## [Unreleased]

### Added
- `--version` / `-V` now embeds the git commit (and a `-dirty` marker) alongside
  the version and feature list. In the TUI, press `v` to show it in the status
  line; it also appears on the help screen.
- `--setup-caps`: grants the binary the Linux capabilities needed for live
  capture (`cap_net_raw,cap_net_admin+ep` via `setcap`) so it runs without
  `sudo`, then exits. Re-invokes through `sudo` when not already root. An
  `install.sh` wrapper runs `cargo install` followed by this step.
- Call flow split view: `Tab` switches keyboard focus between the ladder and
  detail panes (focused pane is highlighted and shown in the status line), and
  vertical scrollbars appear on either pane when its content overflows.
- The file-open browser (`O`) now lists gzip-compressed captures
  (`*.pcap.gz`, `*.cap.gz`, …), matching the loader, which decompresses them.

### Fixed
- File-open browser: when a directory can't be read — most often because sipnab
  was started with `sudo` and dropped privileges to an unprivileged user that
  can't read a `0700` home directory — it now shows the reason and a "run
  without sudo" hint instead of an empty list.
- The embedded git commit now refreshes reliably on new commits (the build
  script watches the resolved `HEAD` ref and `packed-refs`), and the `-dirty`
  marker reflects only tracked changes (untracked scratch paths such as a local
  `harness/` or generated `website/public/` no longer mark a build dirty).

## [0.4.2] - 2026-06-13

### Added
- Debian/Ubuntu `.deb` packages for amd64 and arm64, plus fully-static musl tarballs for both architectures.
- Build-time audio include/exclude option for release binaries (gnu/macOS ship audio; musl stays static, no-audio).
- Standards-based quality metrics section on the website (ITU-T G.107 / RFC 3550).

### Fixed
- Release pipeline now builds all six targets (Linux gnu/musl + macOS, x86_64/aarch64), including ALSA build deps and aarch64-musl static libpcap.

## [0.4.1] - 2026-06-12

(Version 0.4.0 was skipped: its tag name was consumed and then
invalidated by an immutable-release deletion during the release
process; no 0.4.0 artifacts were ever published.)

Hardening, performance, and maintainability pass driven by a
four-dimension project analysis (maintainability, survivability,
performance, usability); roadmap and per-item status in `TODO.md`.

### Added
- Feature-combination CI matrix: each reduced feature set (`native`,
  `tls`, `api`, `mcp`, `hep`, combinations, `wasm` lib-only) is compiled
  with its tests; the documented headless recipe runs the full suite.
  Fixed the cfg-gating rot this exposed — 7 of 8 reduced combos no
  longer built their test code.
- HEP listener idle-stall detection: one rate-limited warning when no
  packets arrive for 30 s (a dead UDP sender produces no error), one
  recovery line when traffic resumes.
- `DialogStore::compact_idle`: dialogs idle >10 min keep only their last
  20 messages, bounding long-run memory; wired into the periodic sweeps
  with a lifetime eviction counter.
- `PcapWriter::finish()`: flushes buffered output at end of capture and
  reports the error — previously a deferred ENOSPC was discarded in
  `Drop`, silently truncating the output file with exit code 0.
- Scanner-kill worker health reporting: a dead worker thread now logs a
  one-time error and latches `defense_disabled()` instead of silently
  dropping every kill request.
- Invalid pcap timestamps are counted (`INVALID_PCAP_TIMESTAMPS`) and
  warned about instead of being silently replaced with the wall clock;
  a corrupt `tv_usec` no longer overflows in debug builds.
- Structured `sipnab::Error` (thiserror) across the library surface
  (config loading/validation, CIDR, alert rules, bind addresses, CLI
  validation) replacing `Result<_, String>`.
- `sipnab::pipeline`: the per-packet protocol-routing core extracted
  from `main.rs` as a testable library API.
- Store-layer criterion benchmarks (`store_bench`) and a full-decap
  benchmark, so per-packet costs are measured rather than asserted.
- Filter-DSL parse errors now render the expression with a caret at the
  failing position, a quoting hint for the classic `method == INVITE`
  mistake, the operator list, and a docs pointer.
- Docs: `docs/examples.md` cookbook (19 recipes), `docs/output-formats.md`
  (NDJSON schema + jq recipes), `docs/mcp-setup.md` (token bootstrap,
  systemd unit, troubleshooting), `contrib/sipnabrc.example` (validated
  by a test against the real config loader), and
  `docs/internals/zero-copy-payloads.md` (design + honest measurements).
- Doc-wide drift guard: a test extracts every `--flag` mentioned across
  all ten user-facing markdown files and asserts it exists in the CLI;
  README no longer advertises the five filter-DSL aliases as standalone
  flags.
- Build-time warning when the default `audio` feature is enabled for a
  Linux target, naming the libasound2 runtime dependency and the
  headless build recipe.
- "F1 Help" advertised in the call-list f-key bar at every terminal
  width (the help overlay was undiscoverable once calls appeared).
- Rustdoc on every public item, enforced with `#![warn(missing_docs)]`.

### Changed
- Zero-copy packet payloads: `Packet.data` and `ParsedPacket.payload`
  are refcounted `bytes::Bytes`; payloads are slice views of the
  captured frame. `SipMessage.raw`/`.body` share the same buffer via
  `parse_sip_bytes`, and `SipMessage::clone` (dialog-store insertion)
  no longer copies message bytes. Measured honestly: cost-neutral at
  typical packet sizes (the copies it removes were already ~15 ns);
  shipped for large-payload behaviour, allocator pressure, and the
  structural simplification — see `docs/internals/zero-copy-payloads.md`.
- `src/tui/mod.rs` (5,278 lines) split into `theme.rs`, `render.rs`,
  `events.rs`, `save.rs`, with state/App/entry point remaining; pure
  code motion, all TUI state tests and snapshots unchanged.
- Synthetic-packet construction moved from the TUI to
  `output::synthetic`, removing a TUI→capture layering violation.
- Dialog-store and reassembler eviction is batched (max(1, cap/100) per
  O(n) pass): under a unique-Call-ID or fragment flood at capacity,
  per-insert cost drops ~50x and the per-fragment warn! log flood
  becomes one summary line per batch. Stores may sit up to one batch
  below the cap; the cap remains a hard upper bound.
- Audio payload buffering is disabled in batch mode (nothing there can
  read it); TUI on-demand WAV export/playback unchanged.
- Test suites no longer use fixed sleeps: deadline polling replaces the
  13 timing-dependent waits in the security and process-isolation tests.

### Fixed
- Retransmission detection is O(1) via a per-dialog seen-CSeq set
  (~25x faster per in-dialog message) and survives message compaction —
  the previous stored-message scan re-parsed every CSeq header and
  forgot history once messages were capped or compacted.
- RTCP report matching is O(1) via an SSRC index (~10x at 1000 streams),
  preserving first-match insertion-order semantics across eviction.
- Dialog lookup no longer allocates a Call-ID `String` per message.
- `--filter`/`--json`/`--no-cli-print` help text documents alias
  acceptance, NDJSON, and summary-only usage.

### Analysis notes
- Several externally-reported findings were verified as invalid and are
  recorded with evidence in `TODO.md`: the multiple-stream-store-locks
  claim, HEP cumulative-memory exhaustion, the unwrap-density audit
  (all flagged unwraps are in test code), and the projected 20-30%
  hot-path win from payload copies (refuted by A/B measurement).

## [0.3.2] - 2026-05-05

### Added
- `--filter` now accepts diagnostic alias names (`codec-asym`,
  `ptime-asym`, `payload-asym`, `duration-asym`, `late-media`, plus the
  five existing `--problems`/`--slow-setup`/`--short-calls`/`--one-way`/
  `--nat-issues` aliases) directly. Raw DSL expressions still parse as
  before — alias resolution is tried first and falls back to the parser.
- `--no-cli-print` flag: suppress per-message CLI output so only the
  post-capture summary (`--report` / `--call-report`) reaches stdout.
- `--version` now lists the Cargo features compiled into the binary,
  e.g. `sipnab 0.3.2 (abc12345) features: native,tui,audio,tls,hep,api,mcp,mcp-http`,
  making it trivial to confirm a server build was produced with the
  expected feature set (e.g. that `mcp-http` is present).

### Changed
- Documentation refreshed for the three flag changes above (filter-DSL
  reference, CLI reference, install verification, cookbook recipes 11
  and 12).

- **MCP server mode (Phase 8).** Run sipnab as a Model Context Protocol
  server so an AI agent (Claude Code, Claude Desktop, …) can drive
  read-only analysis. Two transports:
  - `--mcp` (stdio, requires `mcp` feature) for local agents
  - `--mcp --mcp-transport http` (requires `mcp-http` feature) for
    remote agents — bearer-token auth via `--mcp-token` /
    `--mcp-token-file` / `SIPNAB_MCP_TOKEN`; non-loopback binds without
    a token are refused at startup
- `--mcp-bind`, `--mcp-token`, `--mcp-token-file`, `--mcp-allowed-host`
  CLI flags for the HTTP transport. `--mcp-allowed-host <HOST>` extends
  rmcp's DNS-rebind allowlist (default `localhost`/`127.0.0.1`/`::1`)
  so clients connecting via the public hostname or IP aren't rejected.
- Eleven read-only MCP tools: `list_dialogs`, `get_dialog_report`,
  `find_problems`, `get_dialog`, `get_message`, `render_ladder`,
  `rtp_stats`, `search_messages`, `tail_dialogs`, `security_findings`,
  `stats`. All bounded by `HARD_LIMIT = 1000` per call.
- `security_findings` is backed by a new in-memory `FindingsHistory`
  ring buffer (default 1000 entries) so recent scanner / fraud /
  digest-leak / reg-flood alerts can be queried after the fact.
- Five per-call asymmetry diagnostic signals (Phase 8.7) and matching
  filter-DSL fields and aliases:
  - `codec_asymmetry` / `codec-asym` — A/B legs negotiated different
    codecs
  - `ptime_asymmetry` / `ptime-asym` — different packetization
    intervals
  - `payload_asymmetry` / `payload-asym` — dynamic PT mismatch with
    matching codec
  - `duration_asymmetry` / `duration-asym` — materially shorter media
    on one leg
  - `late_media` / `late-media` — RTP starts noticeably after the
    answering 200 OK
- Interactive file-open browser for loading pcaps: directory listing
  with pcap filter, typed narrowing, manual-path mode, and selection
  state.
- `contrib/observability/` — Docker Compose stack (Prometheus + OTel
  Collector + Tempo + Grafana) plus a sample `sipnab-hep.service`
  systemd unit. Runs identically on a Mac dev box and on a dedicated
  capture host; switch via `SIPNAB_HOST` in `.env`.
- `scripts/deploy-website.sh` — environment-agnostic Zola build +
  rsync helper for static-hosting deploys (`DEPLOY_HOST` env var).

### Changed
- Logging facade migrated to `tracing` (Phase 8.0b). `tracing` is now
  unconditional; `tracing-subscriber` is gated under `native`. The
  `--mcp` stdio path requires `--quiet` (or no other stdout-writing
  flags) so JSON-RPC isn't clobbered by log lines on stdout.
- End-of-capture summary now distinguishes RTP packets from RTP
  streams, reporting `N RTP packets across M streams` instead of
  conflating the two.
- "No SIP traffic found" guidance softened to a media-only notice when
  RTP was successfully parsed, so media-only pcaps no longer look like
  parse failures.
- Documentation refresh on www.sipnab.com: new MCP page, new
  Enabling MCP / Runtime Dependencies / Cross-glibc sections in the
  install guide, full feature-flag table now matches `Cargo.toml`,
  homepage feature row for MCP, REST-API ↔ MCP cross-reference.

### Fixed
- **`--hep-listen` was silently dropping every received packet.** The
  listener was building a `Packet` with `link_type = DLT_RAW` plus
  payload-only data (no IP/UDP headers); the parser then mis-read SIP
  body bytes as IP headers and `processor.process()` swallowed the
  resulting parse errors. Fixed by introducing `PreParsed` metadata on
  `Packet` (src/dst addr+port, IP protocol) and a short-circuit in
  `parse_packet` that uses the metadata directly when present. The HEP
  listener now passes addressing through unchanged. End-to-end verified
  with synthetic HEP injection: dialogs and metrics now populate.
- `cargo build --no-default-features` no longer fails with 32 errors.
  `privilege`, `process_isolation`, and `signals` modules were gated
  only on `not(target_arch = "wasm32")` but each pulls a dependency
  (`libc`, `crossbeam-channel`) that's only present under the `native`
  feature. Added `feature = "native"` to those gates, set
  `required-features = ["native"]` on both `[[bin]]` entries, made
  `hep = ["native"]` (was `[]`), and added `serde` to `chrono`'s
  feature list so `--features api` compiles. `--features hep`,
  `--features audio`, `--features mcp`, `--features mcp-http`,
  `--features tls`, and `--features api` now all build standalone
  with `--no-default-features`.
- Audio playback init no longer corrupts the TUI on hosts without a
  usable audio device (e.g. Tegra/Jetson Ubuntu, headless): libasound
  stderr is redirected to `/dev/null` during device open, and a failed
  init is cached so repeated `P` presses don't retry and re-spam the
  terminal.
- Failed audio init now surfaces an actionable message suggesting
  `F2 Save WAV` as an offline alternative.
- Bundled `contrib/observability/` Grafana dashboard and Prometheus
  alert rules now reference correct metric names: `sipnab_mos_bucket`
  (was `sipnab_rtp_mos_bucket`), `sum(sipnab_dialogs_total{state=~
  "trying|ringing|incall"})` for active-dialog gauge (was
  `sipnab_active_dialogs`, which doesn't exist).
- Compiler/clippy warnings: silenced `function_casts_as_integer` in
  signal handlers; resolved all warnings in tests.

## [0.3.1] - 2026-04-14

### Changed
- Timestamp column redesigned with three diagnostic modes: absolute
  (`HH:MM:SS.mmm`), delta from previous message, delta from first message
- Delta timestamps are color-coded by latency (green <100ms, yellow <1s,
  red <5s, bold red >5s)
- Timestamp column widened from 10 to 13 characters for millisecond precision
- Absolute timestamps now show milliseconds (`HH:MM:SS.mmm`)
- Help screen (`F1`) rewritten with comprehensive per-view keybinding reference
- Man page updated with TUI keybindings section

### Added
- `docs/keybindings.md` -- full TUI keyboard shortcut reference
- README TUI section describing sngrep-compatible features

## [0.3.0] - 2026-04-10

### Added
- Complete SIP/RTP capture, analysis, and security tool
- Zero-copy SIP parser with compact header support and header folding
- First-class RTP stream tracking with jitter, loss, MOS (E-model G.107)
- Interactive TUI: call list, stream list, ladder diagram, raw message viewer
- Filter DSL with 25 fields, 7 operators, and diagnostic aliases (now 30 fields as of [Unreleased])
- Security: scanner detection, toll fraud, digest leak, registration flood
- REST API with bearer auth, rate limiting, Prometheus metrics
- TLS decryption via SSLKEYLOGFILE (ring crypto backend)
- SRTP auth verification (HMAC-SHA1)
- HEP v2/v3 protocol support
- WebSocket frame unwrapping for SIP-over-WS
- VoIP diagnosis: PDD/timing, one-way audio, NAT mismatch, SDP timeline
- STIR/SHAKEN Identity header parsing (JWT decode, attestation A/B/C)
- DTMF extraction (RFC 4733 telephone-event)
- Call diagnosis reports (text, JSON, Markdown)
- Privilege separation (setuid after device open)
- Docker, systemd, fail2ban, Grafana, Prometheus configs
- 5 fuzz targets (SIP, SDP, RTP, HEP, filter DSL)
- TUI automated testing (snapshots, state machine, PTY)

## [0.2.0-beta] - 2026-04-10

### Added
- Interactive TUI (ratatui + crossterm)
- Security detection features
- Advanced RTP analysis and Prometheus metrics
- REST API daemon mode

## [0.1.0-alpha] - 2026-04-09

### Added
- CLI mode with SIP/RTP analysis pipeline
- Capture engine with pcap file/live device support
- Dialog tracking with timing and SDP timeline
- JSON/NDJSON output, call reports, hexdump
- Filter DSL and regex matchers
