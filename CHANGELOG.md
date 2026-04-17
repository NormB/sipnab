# Changelog

All notable changes to sipnab will be documented in this file.

## [Unreleased]

### Added
- Interactive file-open browser for loading pcaps: directory listing with
  pcap filter, typed narrowing, manual-path mode, and selection state

### Changed
- End-of-capture summary now distinguishes RTP packets from RTP streams,
  reporting `N RTP packets across M streams` instead of conflating the two
- "No SIP traffic found" guidance is softened to a media-only notice when
  RTP was successfully parsed, so media-only pcaps no longer look like
  parse failures

### Fixed
- Audio playback init no longer corrupts the TUI on hosts without a usable
  audio device (e.g. Tegra/Jetson Ubuntu, headless): libasound stderr is
  redirected to `/dev/null` during device open, and a failed init is cached
  so repeated `P` presses don't retry and re-spam the terminal
- Failed audio init now surfaces an actionable message suggesting `F2 Save
  WAV` as an offline alternative

## [0.3.1] - 2026-04-09

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
- Filter DSL with 27 fields, 7 operators, and diagnostic aliases
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

## [0.1.0-alpha] - 2026-04-10

### Added
- CLI mode with SIP/RTP analysis pipeline
- Capture engine with pcap file/live device support
- Dialog tracking with timing and SDP timeline
- JSON/NDJSON output, call reports, hexdump
- Filter DSL and regex matchers
