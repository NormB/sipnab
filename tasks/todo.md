# sipnab — open backlog

Forward-looking feature backlog only. Shipped work is recorded in
`CHANGELOG.md`; this file tracks what is *not* yet built.

## Capture

- [x] **SCTP transport parsing** — **Done:** `parse_packet` now decodes the SCTP
  common header and iterates chunks, extracting the SIP payload from the first
  complete (B+E) DATA chunk (type 0) and recovering the real src/dst ports;
  fails closed to an empty payload on any truncation/malformed length. Single
  unfragmented DATA chunk per packet; multi-packet fragment reassembly (B/E
  spanning) is a documented follow-up. Enables SIGTRAN/Diameter (3GPP IMS).

## TUI

- [x] **Live call quality dashboard** — the `QualityDashboard` view already
  rendered MOS + jitter trend sparklines over retained per-stream history.
  **Done:** added the third metric — a packet-loss % trend row (`loss_to_block`,
  good/warn/bad thresholds) — plus a legend naming all three metrics with units,
  completing the real-time MOS/jitter/loss graph.
- [x] **Call timeline visualization** — **Done:** new `CallTimeline` view (opened
  with `T` from the call list) draws a horizontal, proportional time axis of call
  phases (setup → ringing → in-call → teardown, or the failed/cancelled path)
  from `DialogTiming` milestones, labeled with durations + units, phase colors,
  and a legend; degrades gracefully for never-answered / no-timing calls.
- [ ] **Packet loss map** — visual representation of RTP loss patterns.

## Security hardening (follow-ups from codex_analysis.md)

- [x] **HEP auth replay resistance** — SN-01 residual: `--hep-auth` carries a
  static secret in cleartext in the `0x000e` chunk, replayable by an on-path
  sniffer. *Docs (baseline commit):* the cleartext caveat + tunnel-over-
  WireGuard/IPsec/stunnel guidance. *Now done:* `--hep-auth-mode hmac` — the
  chunk carries a per-message token `version‖timestamp‖nonce‖HMAC-SHA256(key,
  version‖ts‖nonce‖payload)`; the receiver checks format → ±30 s window → MAC
  (constant-time, before the replay cache) → nonce freshness against a
  window-pruned cache. sipnab-to-sipnab only; opt-in. In-process HEP-over-TLS was
  **not** added (conflicts with the standing "no in-process TLS termination"
  decision) — tunnels remain the answer for a hostile path.
- [x] **HEP per-peer limiter ergonomics** — **Done:** the listener now logs the
  active limiters at startup (`describe_hep_limiters`), and
  `--hep-rate-limit-per-peer` accepts `off` (default), a number, or `auto`, which
  resolves to `global / allowlist_len` when a `--hep-allow` list is set (stays
  disabled with no allowlist). Documented in the CLI reference + website mirror.
- [x] **crash-dir ownership validation** — SN-03 deferred this. **Done:** before
  writing, `write_crash_report` refuses a report dir that is a symlink, not owned
  by the effective UID, or world-writable without the sticky bit. Group-writable
  is allowed on purpose (umask-0002 user-private-group default; group membership
  is the operator's responsibility). On refusal it returns an error and the panic
  hook prints the backtrace to stderr. *Remaining (defense-in-depth):* create the
  file via `openat()` on an `O_DIRECTORY|O_NOFOLLOW` dirfd to remove the
  parent-component symlink / `exists()→create→chmod` TOCTOU window.

## Long-term / exploratory

- [ ] WASM plugin API (design decision D7 rules out Lua; WASM is the path if
  plugins are ever needed).
- [ ] Machine-learning anomaly detection over SIP/RTP patterns.
- [ ] Distributed capture cluster management.
- [ ] Interactive pcap annotation and sharing.
- [ ] YANG/NETCONF machine-readable diagnosis export.

## Standing decisions

| Decision | Status | Notes |
|----------|--------|-------|
| wolfSSL/OpenSSL TLS backends | REMOVED | ring covers ~95% of cases; re-add only if FIPS demand arises. |
| gRPC API | REMOVED | REST API is complete; re-add only if streaming demand arises. |
| STIR/SHAKEN cert verification | DEFERRED | Would require HTTP cert fetching — added attack surface, intentionally skipped. |
| WASM plugins | FUTURE | D7 rules out Lua; WASM is the path if plugins are ever needed. |
