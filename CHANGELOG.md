# Changelog

All notable changes to sipnab will be documented in this file.

## [0.5.39] - 2026-07-25

### Security
- **Bearer tokens are now bound to the surface they were minted for.** Signed
  tokens gain an `aud` claim (`api` or `mcp`) and a new `s2` version prefix. A
  token minted from `--api-signing-key` is rejected by the HTTP MCP endpoint,
  and vice versa, **even when both surfaces are configured with the same
  signing key** — an easy misconfiguration, since the two read separate flags
  and separate environment variables, that previously granted cross-surface
  access silently. The version prefix is part of the signed input, so an `s2`
  token cannot be rewritten as `s1` to shed its binding.

  Legacy `s1` tokens carry no audience and are still accepted by either
  surface, so tokens minted before this change keep working until they expire;
  they are never minted any more, and accepting one logs a one-time deprecation
  warning. `s1` acceptance will be removed in a future release. Static
  `--api-key` / `--mcp-token` secrets are unaffected and remain audience-less.

## [0.5.38] - 2026-07-25

Documentation, plus one `--version` reporting fix. No packet-path or API
behavior changes.

### Added
- **Developer documentation** (`docs/internals/`, P5): a developer index with
  a reading order, a live-vs-archaeological map of the root-level design
  corpus, and a glossary (D1–D21/D22, WS0–WS8, P0–P5, SN-01/02/03); a
  subsystem guide tracing one packet from wire to screen across all four
  packet paths; ten invariants, each naming what enforces it; the test tiers
  and gate roster; six contributor walkthroughs; build/CI/release (the eleven
  features and their real implications, the eight workflows, what `ci-success`
  actually requires, the 1.97.1 toolchain pins, the release matrix); and a
  SIP/RTP domain primer. Seventeen sequence diagrams across the set.
- `tests/dev_docs_drift_test.rs`: nine assertions holding those pages to the
  code — cited paths must exist, `()`-suffixed symbols must resolve to a
  definition, links must be relative, every page must be registered for wiki
  publication, and the diagram conventions are enforced.
- `.githooks/pre-commit` gate 8: an advisory notice when a commit stages a file
  the developer docs cite without touching `docs/internals/`. It prints
  `REVIEW` and returns zero — it can never block a commit, which
  `scripts/test-pre-commit.sh` now pins.
- `scripts/build-wiki.py` rewrites relative code links to blob URLs, so a
  `../../src/pipeline.rs` link no longer reaches the flat wiki dead.

### Changed
- Rewrote the `/docs/` overview page: what sipnab is, who it is for, a
  capability tour, a quick start, and an explicit table of what each build
  variant actually includes. Every flag and capability claim was verified
  against the built binary, and the page is now in the flag-drift corpus so it
  stays that way.
- `ARCHITECTURE.md` and `CONTRIBUTING.md` delegate into the developer docs
  rather than duplicating them. `CONTRIBUTING.md`'s Git Hooks section was
  wrong — it described the pre-push clippy gate as a "soft warning" when it is
  a hard gate, omitted the rustdoc and fuzz gates, implied `SKIP_FMT_HOOK`
  skipped only formatting, and never mentioned the pre-commit hook at all.
- **The website's API page now documents every authentication method.** It had
  described only the static `--api-key`, never mentioning signed bearer tokens,
  minting, TTLs, signing-key rotation, or revocation — while the in-repo
  `docs/rest-api.md` documented both and linked to `docs/auth.md`, which has no
  website counterpart. A website reader was therefore shown the weakest option
  as the only option. The section now also covers the Bearer-only rule, what
  happens when no credential is configured, the non-loopback startup refusal,
  the 503-before-401 rate-limit ordering, and the two different metrics auth
  schemes. `website/content/docs/mcp.md` gained the same treatment for
  `--mcp-signing-key`, which appeared nowhere on the site.

### Fixed
- **`--version` never reported the `metrics` feature.** `compiled_features()`
  omitted it, so a `--features full` binary printed
  `features: native,tui,audio,tls,hep,api,mcp,mcp-http` while the Prometheus
  listener was compiled in. `--version` is what the install docs call "the
  fastest way to confirm a build was produced with the feature set you
  expected", so it was answering that question wrongly. Found while
  fact-checking the `/docs/` overview page; the sample outputs in the install
  and MCP-walkthrough pages are updated to match.
- **A startup error named a flag that does not exist.** The REST API's
  non-loopback refusal told operators to change `--api-bind`; the flag is
  `--api <ADDR>`. That message fires exactly when someone is correcting a
  security misconfiguration, so it pointed them at nothing.
- **Both theme guides said `status_bg` was "not configurable"** although
  `tui::theme::apply_color` applies it from config and a dedicated test asserts
  it round-trips — anyone wanting to restyle the status bar was told it was
  impossible. It is now a documented slot in both doc trees. The two config
  references also disagreed on the slot count (11 vs 10); `ThemeConfig` has 12
  fields, 11 semantic plus the `highlight` alias. A new drift test derives both
  the slot list and the count from the struct so neither can drift again.
- **musl and `-noaudio` release builds shipped without the Prometheus
  endpoint.** `release.yml` built them from a feature set described in its own
  comment as "full minus audio" that also dropped `metrics`, while the install
  pages told readers the `-noaudio` variant differs *only* in live playback.
  `metrics` is restored to that set, which takes effect on the next tagged
  release.
- **`all_schemas_compile` could not see a schema it was not told about.** It
  iterated four hardcoded filenames, so a malformed schema added to
  `tests/schemas/` left the suite green. It now enumerates the directory, with
  an anti-vacuity floor so a broken path fails rather than passes.
- `TransportProto::Sctp` was documented as a "stub for future use" although
  SCTP has been parsed since the capture path learned IP protocol 132.
- Three walkthrough checklists named gates that do not fire for the change they
  were attached to. Verified by executing each: a malformed schema added to
  `tests/schemas/` leaves `json_schema_test` green (it iterates four hardcoded
  names), a new `src/security/` module with an uncapped attacker-keyed map
  leaves `resource_bounds_test` and `security_test` green, and an unregistered
  `fuzz/fuzz_targets/*.rs` containing a compile error leaves
  `cd fuzz && cargo check` at exit 0. Those steps are now marked
  **(unenforced)**, and the gap is filed as a P4 item.
- `docs/benchmarks.md` claimed "current release 0.5.19" while the crate was at
  0.5.37: the version-marker gate's corpus covered the website copy but not the
  in-repo one. Both benchmark pages and both MCP walkthroughs are now in that
  corpus.
- `ARCHITECTURE.md` documented a `--jobs` flag that does not exist; the flag is
  `--cores`. `ARCHITECTURE.md` is now in the flag-drift corpus.
- The installation docs stated a glibc floor of 2.39; the floor enforced by
  `release.yml` is 2.36.
- The README feature table omitted `metrics` and misstated `full` and `native`.
- `tests/link_integrity_test.rs` was left unformatted by an earlier commit on
  this branch, which would have failed the pre-push `cargo fmt` gate.

## [0.5.37] - 2026-07-24

### Added
- **Packet loss map** (P5.1): a new Stream Loss Map view (key `L` from
  Stream Detail and the Quality Dashboard) showing WHERE RTP loss
  occurred across a stream's retained sequence window as a density
  strip, so bursty loss (a dark cluster) is distinguishable from diffuse
  loss (scattered specks) at a glance — with a summary header (loss %,
  burst count and pattern) and a sequence axis.

### Changed
- P4 test-quality tier (36 items): strengthened weak/vacuous assertions
  into ones that fail on regression (each mutation-checked), made flaky
  patterns deterministic (event-based E2E waits, synchronizing drop
  events instead of fixed sleeps, poll-based token rotation, serial_test
  for env-mutating tests), fixed test hygiene (tempdir guards,
  failure-only diagnostics, loud fixture-missing/wasm-absent failures),
  and consolidated duplicated fixtures into shared tests/support modules
  (run helpers, spawn_http, xorshift Rng, TUI fixture builders).

### Fixed
- The new docs-drift guard for website MCP examples caught 17
  invocations missing `-N`/`--no-tui` (copy-paste would fail) — fixed.
- Restored `--api-max-conn` test coverage lost in a test refactor, and
  gated security_test's counting allocator to the `api` feature so
  reduced-feature CI builds compile.

## [0.5.36] - 2026-07-24

### Changed
- Standardized the whole project on **Rust 1.97.1**. CI had pinned 1.94.1
  while local dev used 1.97.1 with no rust-toolchain.toml to force
  agreement, so a clippy lint (manual_is_multiple_of, warn-by-default in
  1.94.1 only) failed CI while passing locally. Bumped every pin — CI
  workflows, the Cargo.toml/sub-crate MSRV, the Dockerfiles
  (rust:1.97-slim-trixie), and the "Rust 1.97+" claims in the README,
  CONTRIBUTING, docs, and download page — so local `cargo clippy` now
  matches CI exactly.
- P3 code-health tier (57 items): dead-code removal, deduplication
  (shared bind-address parser, resamplers, loss-%, state-display,
  find_crlf, correlated-legs/header/pipe builders), naming corrections
  (mint_token, max_bytes, in-flight-request semaphore, ReDoS→memory-cap
  comment, fixed-window doc), API hygiene (Packet::new assert, checked
  RSA-KE bounds, SrtpProfile consts, injectable clocks for is_active/
  STIR iat), a MediaMode enum replacing a magic string, configurable
  theme status_bg, and small edge-case fixes (Delete key in
  manual-path/save dialogs, dual-error status line, crash-report partial
  cleanup).

### Fixed
- Flaky privilege_drop_test: the two tests shared a fixed /tmp fixture
  path and race under cargo's parallel test execution; each now uses a
  distinct per-test path.

## [0.5.35] - 2026-07-24

### Added
- Cross-packet SCTP DATA fragment reassembly (RFC 4960): a SIP message
  split across B/middle/E DATA chunks in separate packets is now
  reassembled via a bounded, fail-closed per-stream buffer.

### Changed
- P2 wave completing the tier across RTP, output, app, core, and CLI
  (32 items). RTP: O(1) quality-history eviction, retained-log-bounded
  burst gaps, CN-spacing silence durations, unified retroactive guards,
  SRTP session-key caching + clone elimination, amortized endpoint
  eviction, case-insensitive Opus export, correct NAT-mismatch media,
  loss-guarded ptime, negotiated DTMF clock, AudioPlayer !Send+!Sync
  pin. Output: filtered pagination totals, reg-flood CRLF sanitization,
  UTF-8-aware wireshark boundaries, RFC 7235 Authorization parsing,
  signed sub-second deltas, byte-safe truncation. App/core: PlanError
  instead of process::exit, negotiated DTMF PT, real tshark input,
  pause/count fix, allocation-free MCP search, removed unescaped auth
  JSON fallback, amortized rate-limiter cleanup, counted dead-worker
  drops, RFC 5761 muxed-RTCP recognition. CLI: corrected --help
  headings, parse-time value validation, atomic symlink-safe config
  writes, TOCTOU-hardened crash report dir.

## [0.5.34] - 2026-07-24

### Added
- TUI HTML export is now fully self-contained (no CDN): the Mermaid
  source is embedded in a copyable block with offline render
  instructions and an inline Copy button.

### Changed
- P2 TUI wave (26 items): display-width correctness across the call-flow
  ladder, arrows, and status lines (CJK/emoji, non-ASCII filenames);
  narrow-terminal underflow guards; an LCS message diff (a single
  inserted header highlights only that line); wrapped-row search-match
  scrolling; centered dashboard scroll; blank save-path rejection; F9
  clears filter+search consistently in both views; and efficiency work
  (no per-frame view/popup clones, ref-sorted merged ladder, HashSet
  clear_calls, cached wheel/flow counts, visible-only cell builds,
  single SDP parse, O(n^2)->O(n) retransmit folding, bounded
  sparklines). All buffer-then-write exporters are now atomic, so a
  failed export can't clobber a good file; NDJSON uses the canonical
  msg_count field. The call timeline is documented as an intentionally
  static single-screen view.
- Developer tooling: the pre-commit hook derives the homepage test count
  from its single validated test run (fixing an intermittent
  partial-count false failure), and CI reclaims runner disk before heavy
  Linux builds to avoid "No space left on device".

### Fixed
- SIP: update_invite_state matches the exact `terminated`
  Subscription-State token (RFC 6665 8.4), so `terminatedfoo` no longer
  ends a transfer (twin of the 0.5.33 timing.rs fix).

## [0.5.33] - 2026-07-24

### Changed
- P2 robustness/efficiency wave across the capture and SIP subsystems
  (39 items). Capture: HEP timestamp clamping, once/second nonce
  pruning, `0`-disables rate limits, `--count` counts received packets,
  DNS-free loopback check, 6in4 tunneled IPv6, unknown-protocol
  rejection (no more silent UDP mislabel), honest split backpressure
  metering, buffered atomic writes, split-borrow clone elimination in
  TLS decrypt, zero-copy TCP framing, interruptible replay sleeps,
  unified timestamp-fallback counting, post-2106 saturation, and
  multi-capture sibling teardown. SIP: dialog-merge state union, faster
  correlation scan, no-rotate capacity-drop counter, DSL quoted-string
  escapes + any-stream rtp matching + skip-unused-diagnosis + bytes
  payload matching, anchored `SIP/2.0` detection, visible header/
  Content-Length overflow flags, pre-copy validation, Request-URI
  trimming, copy-free `regex::bytes` matcher with case-sensitive method
  matching, 7-bit payload-type enforcement, delayed-offer SDP
  classification, folded MIME headers, the RFC 7865 nameID `aor`
  attribute, and an exact `terminated`-token transfer check.

## [0.5.32] - 2026-07-24

### Added
- TUI clipboard copy that works over SSH: OSC 52 (emitted to the
  controlling terminal, 72 KiB bound) with silent pbcopy/xclip
  belt-and-suspenders; `y` yanks the displayed raw message; F12 toggles
  mouse capture so native drag-to-select works in any view; help and
  keybindings docs gained a Copying-text section (including the
  Shift+drag bypass tip).
- Per-interface pcapng: the writer emits one IDB per source interface
  (mid-stream discovery, per-device link types, if_name, self-contained
  split files) and the reader keeps a per-section interface table so
  every EPB decodes with its own interface's timestamp resolution and
  link type; malformed interface ids are skipped, never default-decoded.

### Fixed
- P1 correctness wave (15 fixes): deterministic least-recently-updated
  eviction for the TCP/SIP leftover map; IP-reassembled fragmented TCP
  datagrams re-enter the TCP reassembler so spanning SIP messages frame
  correctly; TLS 1.2 keylog entries bind to the handshake with the exact
  matching ClientHello random; HEP forwarding to IPv6 collectors binds
  the right address family; SIPp export substitutes host/port
  structurally instead of digit string-replace; Mermaid export skips RTP
  bars and never silently drops RTP segments under lock contention; the
  call-flow ladder gives every endpoint its true column (6-endpoint cap
  removed); message-diff scroll reaches the wrapped bottom; MCP
  tail_dialogs pages losslessly via a compound cursor; DNS name caches
  and the resolver queue are bounded; the crash hook can no longer panic
  on a closed stderr; per-peer auto rate limits floor at 1; stream-store
  clear() drops stale SDP correlations; the wangiri threshold matches
  its documented minimum of 3.
- Deferred P1 completions: per-connection TLS ClientHello/ServerHello
  pairing (bounded, direction-normalized) and serial TCP sequence
  arithmetic across the 2^32 wrap with serial-order buffer draining.

### Changed
- Every Rust source file now carries an SPDX license header
  (MIT OR Apache-2.0); LICENSE-MIT year range aligned to 2024-2026.

## [0.5.31] - 2026-07-24

### Fixed
- SIP/DSL semantics batch (six P1 correctness fixes):
  - A dialog at its per-dialog message cap that keeps receiving
    retransmissions now counts as active — a dropped at-cap
    retransmission still advances `updated_at`, so idle compaction no
    longer evicts a dialog under a retransmission flood.
  - SIPREC multipart bodies are split only on line-anchored
    `--boundary` delimiters per RFC 2046; a boundary string occurring
    mid-line inside part content (metadata XML, SDP) no longer
    corrupts part extraction.
  - Repeated T.38 re-INVITEs (session refresh) emit `T38Switch` once
    at the genuine audio→T.38 transition instead of on every other
    exchange; a real return to audio and back re-emits correctly.
  - STIR/SHAKEN PASSporTs retain every `dest.tn` entry and the
    previously-unparsed `dest.uri` array (RFC 8225 §5.2.1) instead of
    keeping only the first TN.
  - Filter-DSL numeric equality (`==`/`!=`) uses a domain-grounded
    tolerance (5e-4, half the finest millisecond-derived step) instead
    of `f64::EPSILON`, which was effectively exact-match for values
    ≥ 2 — `duration == 5` now matches computed durations.
  - `src.port`/`dst.port` in the filter DSL read ports captured at
    dialog creation instead of the first *stored* message, which
    silently swapped to a response's reversed ports after idle
    compaction drained old messages.

## [0.5.30] - 2026-07-24

### Changed
- The standalone Prometheus `/metrics` server now has its own `metrics`
  feature (enabled by default) instead of being gated behind `api`. It uses
  a raw TCP listener with no axum/tokio, so `--metrics` now works in the
  default build (which does not enable `api`); previously it silently did
  nothing there.

### Fixed
- `sipnab_messages_total` now reports the same value from the REST `/metrics`
  endpoint and the standalone metrics server: both count SIP messages by
  method. The REST endpoint previously counted one per dialog, undercounting
  every multi-message dialog.
- The synthetic packet builder (pcap export of SIP messages) truncates a
  SIP payload larger than a single IPv4 datagram can hold, so the IP/UDP
  length fields match the bytes written instead of saturating while the
  full oversized payload is appended (which left header and content
  disagreeing).
- `GET /v1/streams/{ssrc}` now returns the most-active stream when several
  streams share an SSRC (endpoint collision), deterministically, instead of
  an arbitrary match that could let a colliding orphan shadow the real
  media stream.
- The event-exec engine now kills and reaps a child process whose status
  check errors, instead of forgetting it — the child could previously
  linger as a zombie.
- A 200 OK to INVITE that races a CANCEL now correctly establishes the call
  (Cancelled → InCall) per RFC 3261, instead of leaving a call that was
  actually answered stuck in the Cancelled state.
- A 401/407 auth challenge to REGISTER no longer marks the registration
  Failed: challenges are intermediate (the client re-registers with
  credentials), so the dialog stays auth-pending until a genuine failure or
  a 200 OK.
- Call answer time (`answered_at`) is now pinned to the initial INVITE's
  CSeq, so a re-INVITE's 200 OK can no longer be recorded as the call's
  answer time and corrupt setup/ring metrics.
- `cseq()` returns only the single RFC 3261 method token, dropping trailing
  garbage (`1 INVITE extra` → `INVITE`) that previously defeated method
  comparisons in timing.
- The From/To user is now extracted from the actual addressable URI (inside
  the `<...>` name-addr, or the bare addr-spec), never a quoted display
  name — a crafted `"sip:evil@x"` display name can no longer spoof the user,
  and a non-sip URI such as `tel:` yields no user.
- `--split filesize:N` now counts each record's on-disk framing (the pcap
  record header or the pcap-ng EPB overhead), not just the payload, so
  rotation fires at the intended file size instead of systematically
  overshooting it.
- HEP v3 packet building now truncates an oversized SIP payload to fit the
  protocol's 16-bit length fields instead of letting the total length wrap
  into a corrupt header a collector would misframe.
- The pcap-ng reader resets its timestamp resolution and link type to the
  defaults at each Section Header Block, so a multi-section capture whose
  later section omits `if_tsresol` no longer inherits the previous section's
  resolution and misreads packet timestamps.
- WAV export from the call list now saves the audio of the row the user has
  highlighted: the selection is resolved against the displayed order
  (filter + search + sort) instead of raw store order, which under an active
  filter or sort exported a different dialog's audio.
- The "clear matching / clear non-matching" call-list actions now evaluate
  each dialog against its real RTP streams. Previously they passed an empty
  stream slice to the filter, so a dialog that matched only via a stream
  criterion (`rtp.codec`/`rtp.mos`/`rtp.jitter`/`rtp.loss`) was misclassified
  — and, in "clear non-matching," wrongly deleted.
- RTCP-reported jitter is now converted from RTP-timestamp units to
  milliseconds (`jitter * 1000 / clock_rate`) before it overwrites a
  stream's jitter estimate, instead of being stored raw — the old code fed
  MOS a jitter 8x too large for an 8 kHz stream.
- The RTCP cumulative-packets-lost field is now decoded as the 24-bit
  *signed* value RFC 3550 specifies (sign-extended into an `i32`); a
  negative count (net duplicates) previously zero-extended into a huge
  positive loss total. Stream loss counters clamp a negative value to zero.
- Interarrival jitter now interprets the RTP-timestamp difference as a
  signed (`i32`) transit delta, so a reordered packet no longer produces a
  ~4.29e9-unit spike that corrupted the estimate.

## [0.5.29] - 2026-07-23

### Security
- The REST API now rate-limits **before** authenticating, so a flood of
  wrong-token requests is throttled per-IP (503) instead of returning an
  unbounded stream of 401s — closing an unlimited-speed Bearer-token
  brute-force window.
- The SIP parser's per-line length cap now bounds a single *unfolded* header
  line, not only folded continuations: a multi-megabyte header with no
  continuation lines is rejected (parse_error, header dropped) instead of
  being buffered whole.
- The HEP receiver's per-peer rate limiter fails closed when its tracking
  table is full: a brand-new source IP is dropped rather than bypassing the
  per-peer cap, so a many-source-IP flood can no longer exhaust the table to
  win a free pass. Already-tracked peers are unaffected.
- TLS keylog entries now zeroize all key material on drop — secret, client
  random, and the label — through the `zeroize` crate (a non-elidable write),
  replacing a plain byte loop that the compiler could optimize away and that
  never cleared the label.
- The generated `tshark` command now POSIX-quotes every interpolated value
  (input file, device, BPF and display filters) with proper `'\''` escaping
  of embedded single quotes, so a crafted filename or filter can no longer
  break out of the quoting to inject shell words.
- The Mermaid call-flow export escapes untrusted SIP-derived labels: message
  and participant labels are neutralized for the Mermaid layer (newlines
  become spaces; `#;<>` become Mermaid entity codes) and the standalone HTML
  export additionally HTML-escapes the whole diagram, closing an XSS where a
  crafted label could close the `<pre>` block and inject a live `<script>`.

### Fixed
- pcap loading in the TUI now routes packet timestamps through the shared,
  hardened `pcap_ts_to_chrono` converter, which clamps `tv_usec` before the
  microsecond→nanosecond multiply; the previous raw `(tv_usec as u32) * 1000`
  overflowed (panic in debug, wrong timestamp in release) on a crafted or
  nanosecond-precision capture.
- Four UTF-8 byte-boundary panics reachable from real input, all now going
  through a shared `text::floor_char_boundary` helper or whole-character
  slicing: `--payload-limit` truncation mid-character in CLI output; the
  TUI filter-field renderer (cursor on a multibyte character, cursor past
  the visible field width, unfocused truncation mid-character) plus the
  filter dialog's byte-stepping cursor when typing/editing multibyte text;
  the save/file-open path cursor cell (the two duplicated span builders are
  now one); and `--alert` duration parsing with a multibyte suffix, which
  now reads as an invalid suffix instead of panicking.

## [0.5.28] - 2026-07-23

### Documentation
- Crate-wide documentation pass: every module, function (public, private,
  and test), type, field, and constant — across `src/`, all integration
  test crates, and the fuzz targets — now carries rustdoc describing
  purpose, arguments, returns, errors, and explicit side effects (I/O,
  locks, subprocess execution, privilege drops, raw-socket sends,
  detector/cache state). Enforced going forward by
  `clippy::missing_docs_in_private_items` alongside the existing
  `missing_docs` gate (CI clippy runs `-D warnings`). Around twenty
  stale or misattached doc blocks were corrected to match the code, and
  ~250 code-improvement observations recorded during the audit are
  filed in `tasks/todo.md`.

### Added
- Capture: SIP over SCTP. `parse_packet` now decodes the SCTP common
  header and chunk stream, extracting the SIP payload from the first
  complete (B+E) DATA chunk and recovering the real source/destination
  ports; any truncated or malformed SCTP input fails closed to an empty
  payload so downstream never misreads transport bytes as SIP. Single
  unfragmented DATA chunk per packet; multi-packet fragment reassembly
  is a documented follow-up. Enables SIGTRAN/Diameter (3GPP IMS)
  environments.
- TUI: packet-loss % trend row on the quality dashboard alongside the
  existing MOS and jitter sparklines, colored by good/warn/bad loss
  thresholds, plus a legend naming all three metrics with units —
  completing the real-time MOS/jitter/loss view.
- TUI: call-timeline view (`T` from the call list) — a horizontal,
  proportional time axis of call phases (setup → ringing → in-call →
  teardown, or the failed/cancelled path) derived from dialog timing
  milestones, with per-phase duration labels, phase colors, a legend,
  and a PDD/ring/setup/teardown summary line. Degrades gracefully for
  never-answered calls and dialogs without timing data.

### Fixed
- Privilege drop: a nonexistent `--user` is now reported as "not found"
  with the `useradd`/`--user` guidance on hosts whose NSS stack (e.g.
  sss/systemd modules) signals a missing user via an `ENOENT`/`ESRCH`
  return from `getpwnam_r`, instead of surfacing a raw "No such file or
  directory" OS error. Plain-glibc hosts are unaffected.

## [0.5.27] - 2026-07-22

### Fixed
- Build: replace ambiguous TUI controller glob re-exports with explicit
  imports, eliminating 14 future-incompatible Rust warnings while preserving
  the public key-action API and narrower internal handler visibility.

## [0.5.26] - 2026-07-22

### Fixed
- TUI: on a call-flow page filtered to one transaction (`f`), the
  detail-pane header counted position/total over the whole dialog, so a
  short transaction late in a long dialog rendered a 3-row ladder titled
  `[12/13]` — a counter that looked stuck and read as broken arrow keys
  (the arrows worked). The header now counts within the filtered
  transaction (`[1/3]`..`[3/3]`); unfiltered pages keep whole-dialog
  counts.

## [0.5.25] - 2026-07-22

### Performance
- TUI: the 0.5.24 churn-rebuild floor now covers every store-derived
  view, not just the call list. Stream-list rows were re-filtered from
  the whole store on every frame and every keypress (under a blocking
  read); they now derive once per tick into a keyed cache and keypresses
  navigate it lock-free. The quality-dashboard snapshot (rebuilt every
  tick while open), the statistics aggregation (every dialog, every
  frame), and the call-flow ladder relayout (forced per tick on busy
  captures, worst in extended/multi-leg flows) all refresh at the floor
  (~3/s) under data churn, while user actions still refresh immediately.
  A completed background pcap load clears the floors so every view
  reflects the file on the very next tick.

## [0.5.24] - 2026-07-22

### Performance
- TUI: arrow-key navigation no longer crawls on busy captures. The
  displayed dialog list (filter + search + sort) was re-derived on every
  event-loop tick whenever the store changed — on a loaded server that
  meant a full filter-DSL pass, sort, and per-row clone after every
  keypress. Generation-driven rebuilds are now floored to one per 300 ms
  (~3 refreshes/s); explicit user actions (filter, search, sort) still
  rebuild immediately. Sticky-bottom autoscroll follows at the refresh
  cadence.

## [0.5.23] - 2026-07-22

### Added
- Docs: MCP walkthrough client-registration section — per-client config
  table and copy-paste snippets for Codex CLI (`config.toml` +
  `bearer_token_env_var`), Cursor, VS Code Copilot agent mode
  (`.vscode/mcp.json`), Gemini CLI (`httpUrl`), and Windsurf
  (`serverUrl` + `${file:...}` token interpolation), covering stdio,
  remote-SSH, and streamable-HTTP wirings.

### Fixed
- Site: the MCP Walkthrough page now appears in the docs sidebar and
  header dropdown (it was reachable only from the /docs index cards); a
  new drift test pins every docs page into all three hardcoded nav lists,
  keeps both sidebar templates in agreement, and enforces unique page
  weights so prev/next order stays deterministic.

## [0.5.22] - 2026-07-22

### Added
- Docs: step-by-step MCP deployment walkthrough (`docs/mcp-walkthrough.md`,
  website, wiki) — same-box stdio, the three remote wirings (SSH-launched
  stdio, HTTP + bearer token, SSH tunnel to a loopback bind), a central HEP
  capture host with OpenSIPS/Kamailio mirror config and Homer coexistence,
  nginx-TLS exposure, fleets, and headless automation, plus sizing, security,
  and troubleshooting guidance. Every step tagged by the host it runs on.

### Changed
- Homepage media ships as lossless animated WebP (4.86 MB → 3.23 MB,
  pixel-identical); `demos/Makefile` converts each VHS render and drops the
  intermediate GIF.
- ops: the Cloudflare CSP transform rule refreshes automatically after every
  Pages deploy, hashed from the exact deployed artifact
  (`refresh_csp_hashes.py --site-dir`); stale-rule outages (dead homepage
  JS after an inline-script change) can no longer recur.

## [0.5.21] - 2026-07-22

### Added
- TUI: live call-quality dashboard on `D` — worst-first ranking of active
  streams by MOS with jitter and packet-loss columns and per-stream trend
  history, plus Enter drill-down to the stream detail view. Covered by
  snapshot tests (empty and populated states) and listed in the help view
  and `docs/keybindings.md`.

## [0.5.20] - 2026-07-21

### Performance
- `-N --json` export rewritten: buffered batch sink plus direct JSON
  serialization (no intermediate `Value` tree). ~29% faster wall-clock and
  98.5% fewer `write()` syscalls on the export path; output is
  byte-identical to 0.5.19.

### Fixed
- `-N` CLI output: `--show-empty` was a dead flag — bodyless SIP messages
  (all responses, `OPTIONS`, `REGISTER`, `ACK`, `BYE`, in-dialog `SUBSCRIBE`)
  could only ever show their one-line summary; their header block
  (From/To/Call-ID/CSeq/Via/Contact/...) was unreachable. `--show-empty`
  (new alias `--full`) now prints the full headers of bodyless messages as
  documented. The terse one-line default is unchanged.
- TUI: call-list Method column widened so `SUBSCRIBE` never truncates; the
  multi-leg ladder widens per leg count so arrow method labels don't
  truncate or collide, and label collisions in dense multi-leg flows are
  resolved instead of overdrawn.
- MCP stdio tests no longer race async pcap-replay ingestion on slow
  runners (`list_dialogs` is polled until the fixture dialog appears) —
  fixes a macOS CI flake.

### Changed
- TUI demo GIFs now carry synced keycap overlays showing the keys pressed
  (`demos/keycast.py` pipeline).

## [0.5.19] - 2026-07-20

No packet-path code changes versus 0.5.18 — this release exists to ship
build provenance and the reworked website/download experience.

### Added
- Sigstore build-provenance attestations on every release artifact
  (tarballs, `.deb`, `.rpm`, `SHA256SUMS.txt`) and on the ghcr container
  image. Verify a download with
  `gh attestation verify <file> --repo NormB/sipnab`, or the image with
  `gh attestation verify oci://ghcr.io/normb/sipnab:<tag> --repo NormB/sipnab`.
- Download page: "Docker & automation" section (ghcr image with pin-vs-latest
  tags, version-pinned scripted install via `SIPNAB_VERSION`, raw-URL
  fetch-and-verify, latest-version discovery through the releases API);
  source archives, `cargo install`, and build-docs links on the Source tab;
  sha256 column and complete artifact inventory in the all-files table.
- Site footer states authorship and content licensing:
  MIT / Apache-2.0 (code) · CC BY 4.0 (docs) · copyright.

### Fixed
- Download page platform tabs (Deb/RPM, Linux, Source) were dead in
  production: the tab script's sha256 no longer matched the CSP header's
  allowlist, so browsers silently blocked it. The CSP rule is refreshed and
  a pinned-hash test gate now fails any inline-script edit until the rule
  is updated.
- Footer rendered as three unstyled rows for returning visitors: the
  stylesheet cache-buster was the release version, which site-only changes
  never bump, so new HTML shipped against stale cached CSS. The stylesheet
  URL now carries a content hash.
- GitHub Wiki benchmarks were stale (0.4.16 tables and a retracted perf
  claim): the wiki-source docs are re-synced and a drift gate keeps the
  benchmark tables identical between the wiki source and the website.

### Changed
- Site footer is a single non-wrapping row; the Patreon / GitHub Sponsors /
  GitHub links moved out of the top nav into the footer as icons.

## [0.5.18] - 2026-07-20

### Changed
- `-O` pcap output is written by a hand-rolled buffered writer instead of
  libpcap's `Savefile` (WS8.3): classic pcap records go through a 512 KiB
  `BufWriter` rather than one FFI call + locked stdio `fwrite` per packet.
  Per-packet write cost −43% (same-toolchain A/B), +8–16% end-to-end
  single-core on x86; end-to-end unchanged on the aarch64 reference host,
  where re-emit is bound by data volume rather than per-packet overhead
  (this corrects the +8.3% first published for this entry, which compared
  binaries of different build provenance). Write errors (full disk, dead
  mount) now surface as errors instead of being silently discarded by
  libpcap.

## [0.5.17] - 2026-07-20

### Added
- `--strip-secrets` now reads gzip-compressed input (`.pcapng.gz`) like every
  other path; the sanitized output is always written uncompressed.

### Fixed
- wasm32 builds are warning-free again: the six `SipnabSession` counter
  accessors were missing doc comments.

### Changed
- Dependencies: clap 4.6.2, regex 1.13.1, serde 1.0.229, anyhow 1.0.104,
  thiserror 2.0.19, rustls 0.23.42, tokio 1.53.0, http-body-util 0.1.4,
  jsonschema 0.48.1, and friends (minor/patch group).
- Benchmarks re-measured on 0.5.16/thor-02: multi-core scaling +13–30%,
  carrier sweep +31–107% vs the 0.4.16 session; two regressions tracked as
  WS8.1/WS8.2. The ruby CodeQL job (matched only the Homebrew formula) is
  gone from CI.

## [0.5.16] - 2026-07-19

### Added
- **Gzip-compressed captures open transparently everywhere.** A
  `.pcap`/`.pcapng` file that is gzip-compressed — including one mislabeled
  as plain `.pcap`, which previously failed with
  `Not a pcap/pcapng file (magic: 0x00088b1f)` (that magic is the gzip
  header read as a little-endian word) — is now decompressed automatically,
  the way Wireshark does. The native CLI/TUI paths already gunzipped;
  the browser analyzer and the TUI's pcapng-metadata pass (NRB names /
  DSB secrets) now do too, sharing one bounded core: 1 GiB inflation cap
  (a decompression bomb is refused, not materialized), concatenated gzip
  members supported, zero-copy passthrough for plain files. The analyze
  page accepts `.pcap.gz`/`.pcapng.gz`, shows a notice with
  compressed → decompressed sizes when it gunzipped, and a gzip stream
  wrapping non-capture data reports the decompressed magic instead of a
  bare parse failure.
- The download page now carries the same left "On this page" sidebar as the
  docs pages: quick install, the four platform choices (which also switch
  the matching tab), the all-files table, and download verification — with
  a scrollspy tracking the reading position.

### Fixed
- **The analyze page had no site footer** — the template blanked the footer
  block. Every page keeps the footer now, enforced by a journey gate.
- **The filter demo showed nothing filtering.** It searched `INVITE`, which
  matches every dialog via `Allow:` headers, so the list never narrowed.
  The tape now types queries that visibly narrow, and a journey gate
  replays every tape query against the tape's own pcap through the real
  TUI search path.

### Changed
- The site footer is restructured into two deliberate tiers (brand + nav
  links; license and credits under a hairline) instead of one overloaded
  row that wrapped raggedly.

## [0.5.15] - 2026-07-18

### Fixed
- **Homepage demo images rendered with a broken font.** The VHS demo tapes
  named "JetBrains Mono", which was not installed on the render host, so
  ttyd/VHS silently fell back with broken metrics (stretched letter-spacing,
  clipped glyphs). Pinned an installed monospace family (DejaVu Sans Mono) and
  re-rendered every demo GIF and the hero still; bumped the asset cache-bust so
  the fixed images are served.

### Added
- End-to-end journey tests for the site artifacts (`tests/site_journey_test.rs`,
  `tests/link_integrity_test.rs`): every demo tape must name an *installed*
  monospace font, every referenced demo asset must exist (no orphans), every
  nav/docs link must resolve, docs page weights must be unique, and link text
  must not misdescribe its destination.

### Changed
- Documentation & site overhaul (also landing in this release): per-parameter
  CLI examples with a coverage ratchet, RFC 5737 example-IP sweep, the animated
  demos rebuilt on one shared style, the Wiki gaps closed (Troubleshooting +
  REST API ported, MCP docs merged), site navigation and learning-path
  reordered, and the oversized `api.md`/`install.md` split into focused pages.

## [0.5.14] - 2026-07-17

### Fixed

- **Config**: a config using the valid `[sip]` section (`xcid_headers`) or the
  `[capture] promisc` key no longer emits a spurious "Unknown config key"
  warning at load. `known_keys()` had omitted both even though the code reads
  them; typos inside `[sip]` are still flagged.

## [0.5.13] - 2026-07-17

### Added

- **Security**: scanner-kill source-port spoofing (`--kill-spoof`, added in
  0.5.12) now covers **IPv6** as well as IPv4. A raw `AF_INET6` socket
  (`IPV6_HDRINCL`) forges the victim's IPv6 `ip:port` so the reply appears to
  come from the targeted listener; the `sipnab_kill_responses_sent_total{mode}`
  metric is unchanged. Each family is opened best-effort, so a host with only
  one stack still spoofs that family.

## [0.5.12] - 2026-07-17

### Added

- **Security**: scanner-kill responses (`-K`/`--kill-target`, `--kill-scanner`)
  can now **source-spoof** the victim's `ip:port` via a raw socket, so the
  reply appears to come from the SIP listener the scanner targeted rather than
  sipnab's ephemeral port. Controlled by `--kill-spoof {auto|raw|ephemeral}`
  (default `auto`): `auto` spoofs when `CAP_NET_RAW` is available (already
  granted for live capture) and falls back to the ephemeral source otherwise;
  `raw` requires spoofing and errors if the raw socket cannot be opened;
  `ephemeral` never spoofs. Linux-only; other platforms always use the
  ephemeral source. New metric `sipnab_kill_responses_sent_total{mode="raw"|"ephemeral"}`
  exposes which path was used.

## [0.5.11] - 2026-07-17

### Fixed

- **Security**: `-K` / `--kill-target` and `--kill-scanner` now actually
  transmit the SIP kill response to the scanner over UDP. The worker
  previously matched the target, built the response, and rate-limited it, but
  only logged `would send …` without putting anything on the wire (pcap
  injection was a stub). Send failures now surface as an error instead of
  silently vanishing. The response leaves from an ephemeral source port, not
  the SIP listener port the scanner targeted (source-port matching would need
  raw sockets / `CAP_NET_RAW`, tracked as future work).

## [0.5.10] - 2026-07-17

### Added

- **Display**: `--proto-number` (sipgrep `-N`) — annotate the transport tag
  with the IANA IP protocol number (`UDP(17)`, `TCP(6)`). TLS and WS report
  their TCP carrier's number, since the number identifies the IP-layer
  transport, not the SIP framing.
- **Capture**: `-x` / `--quiet-bad-parse` (sipgrep `-x`) — suppress the
  per-packet SIP parse-error diagnostic for SIP-looking-but-unparseable
  packets. The packet is dropped either way; only the notice is silenced.

## [0.5.9] - 2026-07-16

### Added

- **TUI**: the F10 column selector now saves the current column layout with
  `s`, writing `[display] visible_columns` into your sipnabrc so it persists
  across runs (previously the layout had to be hand-edited into the config).
- **Capture**: `-S` / `--limitlen <BYTES>` (sipgrep `-S`) — parse only the
  first N bytes of each packet, independent of the capture snaplen and the
  display truncation.
- **Capture**: `--no-reassembly` — disable IP-fragment and TCP-segment
  reassembly (inverse of sipgrep `-a`); every packet is parsed standalone.

## [0.5.8] - 2026-07-16

### Added

- **Capture**: `-p` / `--no-promisc` — do not put the interface into
  promiscuous mode (sipgrep `-p`). Promiscuous mode stays on by default for a
  named device (never for the `any` pseudo-device). Also settable via
  `[capture] promisc`.
- **SIP**: `[sip] xcid_headers` — configurable B2BUA leg-correlation header
  names (sngrep `sip.xcid`). Defaults to `["X-Call-ID"]`; add carrier-specific
  headers (e.g. `["X-Call-ID", "X-CID"]`) so multi-leg calls correlate.
- **HEP**: `--hep-auth <KEY>` (Homer authenticate-key `0x000e` chunk, also read
  from `SIPNAB_HEP_AUTH`) and `--hep-id <ID>` (capture-agent id `0x000c` chunk,
  default 1) for `--hep-send`. Previously the sender emitted no auth key and a
  hardcoded capture id of 1.

## [0.5.7] - 2026-07-16

### Added

- **Security**: `-K` / `--kill-target <ADDR[:PORT-RANGE]>` — targeted scanner
  kill (sipgrep `-K`). Sends the kill response to any SIP request whose source
  matches the given address and an optional port range (e.g.
  `10.0.0.1:5060-5090`, `[::1]:5060`), regardless of UA/behavioral detection.
  Repeatable; spawns the kill worker on its own, so `--kill-scanner` is not
  required. Malformed targets are rejected at startup.

## [0.5.6] - 2026-07-16

### Added

- **Matching**: new `-e` / `--match <PATTERN>` flag — the sngrep/sipgrep
  payload match-expression. A regex is tested against the whole raw SIP
  message; once any message in a dialog matches, every later message of that
  dialog is emitted too (dialog-following). Honors `-i`/`-v`/`-w`/
  `--single-line` and is independent of the trailing BPF filter positional.

### Fixed

- **CLI**: corrected a misleading `--help` example that presented
  `'INVITE sip:'` as a BPF filter (it is not valid BPF); the examples now show
  a real BPF filter and the new `-e` payload grep.

## [0.5.5] - 2026-07-13

### Added

- **TUI**: `w` toggles line wrapping in the call-flow detail panel. With
  wrapping off, long header lines truncate, ←/→ scroll the focused panel
  horizontally, and a horizontal scrollbar tracks the widest line along
  the panel's bottom edge. `End` in the focused panel now jumps to the
  bottom of the message; `Home` also rewinds the horizontal scroll.

### Fixed

- **TUI**: the call-flow detail panel's scrollbar and scroll range are
  now computed from the *wrapped* rows that actually render. Messages
  whose long headers wrapped past the pane height (while their logical
  line count fit) showed no scrollbar and ignored Up/Down; line wrapping
  also switched from word-wrap to full-width character wrap so row
  accounting is exact.

## [0.5.4] - 2026-07-13

### Added

- **Packaging**: releases now include `.rpm` packages (RHEL/Fedora) for
  `x86_64` and `aarch64`, each in standard and `-noaudio` variants —
  mirroring the `.deb` set (`contrib/rpm/build-rpm.sh`). The v0.5.3
  release was backfilled with RPMs built from the released binaries.

### Fixed

- **TUI**: the screen no longer flashes blank every few seconds on busy
  live captures, even when the displayed page isn't changing. A render
  tick that lost the store-lock race to the processing thread used to
  flush a frame with an empty main pane (which the next frame repainted);
  a tick now draws from a consistent snapshot of both stores or skips the
  frame entirely, leaving the previous frame on screen. Sustained
  contention forces a blocking frame after a few skipped ticks, so a
  write-saturated capture degrades to a briefly stale frame instead of a
  flickering or frozen UI. Deferred "Saving…"/"Decoding…" work now only
  runs after its status frame actually painted.

## [0.5.3] - 2026-07-09

### Added

- **TUI**: pcap files now load on a background worker with a live
  "Loading… N packets" status line — opening a large capture no longer
  freezes the interface, and dialogs appear progressively while the file
  parses (saves and audio decode likewise defer behind a visible
  "Saving…"/"Decoding…" status; the Mermaid clipboard copy runs detached
  with a bounded wait so a wedged xclip can't hang the UI).
- **TUI**: `n`/`N` jump to the next/previous search match in the
  raw-message view (wrapping, vim/less style); `?` opens the help overlay
  from any view.
- **TUI**: `NO_COLOR` is honored (the theme collapses to terminal
  defaults, including the previously hardcoded RGB status-bar
  background); terminals below 40x6 get an explicit too-small notice
  instead of a garbled screen; the live-capture empty state says it is
  waiting for traffic instead of speculating about pcap files.
- **TUI**: rebinding a key that a view already uses as a built-in (or
  binding two actions to the same key) now warns at startup — such
  rebinds silently never fired.
- **CLI**: `--completions <shell>` generates bash/zsh/fish/elvish/
  powershell completion scripts; `--help` groups its flags under section
  headings instead of one flat list.
- **CLI**: an unknown `--filter` field now names the field, suggests the
  closest valid one, and lists the valid set; a typo'd `-d <device>`
  lists the available interfaces; exit codes (0/1/2) are documented.

### Fixed

- `--mcp` in a build without the `mcp` feature silently ran a plain
  batch capture with no server; it now fails fast with exit 2, like
  every other feature-gated flag (`--hep-listen` gates early too).
- A busy `--api` port (or unauthenticated non-loopback bind, or TLS
  flags) failed silently on a detached thread behind the TUI; the
  listener is now bound before the TUI starts and the error is fatal
  and visible. Bad `--mcp-bind`/`--mcp-transport` values are fatal
  instead of log-and-skip.
- The MCP `tail_dialogs` tool's `source_exhausted` field was a
  hardcoded `false` stub; it now flips to `true` when a pcap replay is
  fully consumed, so polling clients can stop.
- `--json-pretty` produced byte-identical output to `--json`; it now
  pretty-prints each message (still a parseable JSON stream).
- `--call-report` with an unknown Call-ID warned on stderr but exited
  0; it now exits 1.
- An explicit `--portrange 5060-5061` lost to a config-file range
  because clap couldn't distinguish it from the default.
- A filter expression with exotic whitespace before a multibyte character
  at the error position could panic while rendering the parse error
  (found by the `filter_dsl_parse_is_total` property test; parsing is
  total again).
- The man page declared the wrong license (GPL-3.0-only instead of
  MIT OR Apache-2.0) and a stale version; both fixed and now guarded by
  drift tests plus a pre-commit gate covering docs version strings.
- **TUI**: the F7 filter and `N` name dialogs closed and discarded the
  typed input on a validation error; they now stay open with the error
  shown inline. The help overlay's stale `u` (From/To modes) and F2
  (save formats) descriptions were corrected and are drift-tested.

### Changed

- **TUI**: in the F7 filter dialog the **All** master checkbox moved
  above the method grid (above REGISTER), and Tab/arrow traversal
  follows the new order: text fields → All → methods → buttons.

## [0.5.2] - 2026-07-08

### Added

- **TUI**: `h` cycles the header-name display form — as captured /
  expanded / compact — in every view that shows full message text (raw
  message, call-flow detail pane, combined detail, message diff). A
  purely visual transform of the IANA-registered compact forms
  (`From:` ↔ `f:`, `Call-ID:` ↔ `i:`, …); the capture is never modified.

### Fixed

- **TUI**: one Enter now commits the search prompt *and* opens the
  selection — the flow of the starred ([*]) rows, or of the highlighted
  row, in the call list; the highlighted stream in the stream list.
  Previously the first Enter only silently closed the prompt and a second
  press was needed.
- **TUI**: Space during stream-list search types into the query again —
  the stream list has no row starring, so 0.5.1's pass-through made it a
  dead key there. Call-list behavior (Space stars) is unchanged.
- **TUI**: the raw message view now binds End (jump to bottom), matching
  every other scrollable view and what F1 help already claimed.
- **TUI**: a flow-ladder label wider than the gap between its two
  participant pipes is truncated with an ellipsis instead of dropped —
  OpenSIPS' default "100 trying -- your call is important to us"
  previously rendered as a blank arrow.
- **TUI**: the F2 save popup was fixed at 20 rows, clipping the
  RTP/Media formats (WAV, RTP JSON) off the bottom — the "save the
  stream as a WAV file" hint pointed at an option the popup never
  showed. The popup now sizes to its content and scrolls the selected
  format into view on short terminals.
- **TUI**: cycling save formats mutated the path into
  `x.rtp.rtp.rtp...` — the two-segment `rtp.json` extension defeated
  the replace-after-last-dot logic. The full extension is now replaced,
  and a user-edited path is left alone.
- Crash reports get a per-process sequence number in the filename — two
  panics in the same second from the same process previously overwrote
  each other's report.
- A `[crash]` config section no longer logs a spurious
  "Unknown config key: crash" warning.

## [0.5.1] - 2026-07-08

### Fixed

- **TUI**: while the search prompt is open (`/` or F3), Up/Down/PgUp/PgDn/
  Home/End now move the highlight in the live-narrowed call and stream
  lists, and Space stars ([*]) the highlighted row in the call list —
  previously every key went to the query editor, so the narrowed rows
  could not be navigated or selected until Enter committed the search.
  Space remains a literal query character in the call-flow and
  raw-message searches, where message content legitimately contains
  spaces.

## [0.5.0] - 2026-07-06

> The v0.5.0 release assets were rebuilt on 2026-07-08 from the re-pointed
> tag and additionally contain the fixes below (plus the new
> `-noaudio.deb` variants); checksums differ from the 2026-07-06 build.
>
> - TUI: call/stream-list selection clamped on display-list shrink
>   (slice-out-of-range panic when a narrowed list got shorter).
> - TUI: Enter with two or more starred rows opens one chronologically
>   merged flow of all of them (sngrep-style), with per-row dialog
>   attribution in detail/raw/naming.
> - TUI: a persisted search query that narrows the list is shown on the
>   status line (`Search: /q`) and cleared by F9 with the filter.
> - New `[crash]` config section: panic hook restores the terminal and
>   writes a crash report with a full backtrace; optional core-dump mode.
> - Filter popup gained an "All" master checkbox for the method grid.
> - pcapng writer now declares `if_tsresol=9` — files previously read with
>   all times inflated ×1000 ("year 58484"); a repair script for old
>   captures ships as `scripts/repair_pcapng_tsresol.py`.
> - Call list gained a sortable Duration column alongside PDD.

### Added — activated the dormant fuzzing & property-test safety nets (WS7)

The 11 compile-only libFuzzer targets now actually run on a schedule,
four new targets cover untrusted-input surfaces that had none, and
three proptest properties assert semantic invariants the fuzzers can't:

- **Weekly `Fuzz` workflow** (`.github/workflows/fuzz.yml`): a 15-target
  matrix runs each libFuzzer target (default 300s, configurable via
  `workflow_dispatch`) on nightly, primed from the tracked seed corpora,
  uploading any crash/timeout reproducer as an artifact. CI's existing
  `fuzz-check` still compile-checks the targets on every push.
- **New fuzz targets** for the untrusted-input surfaces that lacked one:
  the pure-Rust pcap/pcapng reader (`sipnab -I hostile.pcapng`), the
  DTLS-SRTP handshake observer, TCP stream reassembly (structured
  segment interleavings), and the hand-rolled SIPREC XML scanner.
- **Property tests** (`tests/property_test.rs`, proptest): SIP
  build→parse field round-trip, SDP build→parse→rebuild stability, and
  the filter DSL as a total function on arbitrary text (parse + evaluate
  never panic).

### Changed — **BREAKING (library API, 0.5.0)**: typed errors for the crate-root parse/capture surface (WS6.1)

The functions and types re-exported at the crate root no longer return
`anyhow::Result`; they return structured, matchable error enums
(`sipnab::ParseError` / `sipnab::CaptureError`, both `#[non_exhaustive]`):

- `parse_sip` / `parse_sip_bytes` / `parse_rtp_header` / `parse_sdp`
  → `Result<_, ParseError>` with variants like
  `TooShort { what, need, got }`, `BadRtpVersion { version }`,
  `NotSip { line }`, `BadSdpVersion { version }`.
- `parse_packet` / `PcapReader::new` → `Result<_, CaptureError>` with
  variants like `UnsupportedLinkType(i32)`, `EncapTooDeep { kind, limit }`,
  `NetMonFormat`, `UnknownFormat { magic }`.

Callers that propagated these errors into `anyhow::Result` (or only
`Display`ed them) keep working unchanged — both enums implement
`std::error::Error`. Callers that matched on message text must switch to
matching variants, which is the point of the change.

Additionally **BREAKING**: `Error::ConfigRead` / `Error::ConfigParse` now
carry the underlying `std::io::Error` / `toml::de::Error` as a real
`#[source]` (field renamed `reason: String` → `source`), so the error
chain is inspectable via `source()`.

### Changed — **BREAKING (library API, 0.5.0)**: API-guidelines sweep (WS6.2)

Sixteen growth-prone public enums are now `#[non_exhaustive]`, so adding
a variant (new fraud pattern, RTCP packet type, cipher suite, transport,
…) stops being a semver-major event: `FraudType`,
`DigestVulnerability`, `RtcpPacket`, `XrBlock`, `TransportProto`,
`SdpEvent`, `OfferAnswer`, `CorrelationReason`, `Attestation`,
`VerificationStatus`, `HepProtocol`, `CipherSuite`, `SrtpProfile`,
`TlsContentType`, `TlsVersion`, `SrtpSuite`. Downstream `match`es on
these enums now need a wildcard arm. Closed RFC sets (e.g.
`SdpDirection`, `G711Codec`) deliberately stay exhaustively matchable.

Non-breaking in the same sweep: `DialogStore` and `StreamStore` now
implement `Debug`; the semver status of `#[doc(hidden)]` modules is
documented in the crate root (no guarantee); the `SipMessage::to_*`
accessors and the `as_str` receiver difference are documented in place
as deliberate naming decisions. The wasm `get_*` exports also stay as
they are — they are a JavaScript-facing API consumed by the website's
analyzer page, where `get`-prefixed accessors are idiomatic, and the
exported names are the stable JS contract.

### Added — compiled doctests for the top library entry points (WS6.3)

Every major entry point now carries a compiled, asserted example —
`parse_sip`, `parse_rtp_header`, `parse_sdp`, `parse_packet`,
`PcapReader` (in-memory and `no_run` file variants), `FilterExpr`
(previously an `ignore`d fence), `DialogStore`, `StreamStore`,
`estimate_mos`, `SipMethod::as_str`, and matchable-error examples on
`ParseError` / `CaptureError`. 17 doctests run in CI (up from 4 compiled
+ 1 ignored); compiled examples are the only ones CI keeps honest.

## [0.4.19] - 2026-07-03

### Fixed — multi-stream (audio + video) SDP timeline

Calls offering more than one media stream (e.g. `m=audio` **and**
`m=video`) had the video leg dropped from the per-dialog SDP timeline /
`--json` output: `extract_media_info` recorded only the first `m=` line.
The timeline now aggregates codecs across **all** media descriptions
(`m=` order, de-duplicated), so a video call lists both PCMU and H264/VP8.
(RTP stream *linking* already tracked every media stream correctly — both
audio and video streams associate to the dialog and resolve their codecs;
this only fixes the timeline/report view.)

### Added — all 19 IANA-registered compact header forms

sipnab previously expanded only the ten RFC 3261 core compact header names
(`c e f i k l m s t v`). The nine IANA-registered extension forms now
expand too: `a` Accept-Contact, `b` Referred-By, `d` Request-Disposition,
`j` Reject-Contact, `o` Event, `r` Refer-To, `u` Allow-Events, `x`
Session-Expires, `y` Identity. Two of these fixed real analysis gaps:

- **STIR/SHAKEN evasion fixed:** an INVITE carrying its PASSporT in the
  compact `y:` form (RFC 8224) was invisible to `--stir-shaken` analysis
  while remaining fully valid to real verifiers. Compact-form Identity
  headers are now extracted identically to the long form (regression test:
  `compact_identity_header_cannot_evade_extraction`).
- **Transfer tracking:** a REFER using `r:` (RFC 3515) now drives the
  `Transferring` dialog state and `refer_to` like the long form.

Determination and design in COMPACT-HEADERS-SPEC.md. SigComp (RFC 3320
"compressed SIP") remains explicitly out of scope.

### Changed — one canonical dialog/stream summary across all surfaces (WS3)

"Dialog summary" was implemented five times (CLI/NDJSON, REST API, MCP, TUI
save, reports) and had drifted on the wire. All surfaces now project through
`output::model::{DialogSummary, StreamSummary}` — a consistency test pins
the shared shape. **Wire changes:**

- **MCP** `list_dialogs`/`tail_dialogs`/`find_problems`: `message_count` →
  `msg_count`; `method` is now the canonical SIP form (`INVITE`, previously
  the Debug form `Invite`); rows gain `duration_sec` and `timing`.
- **REST API** `/v1/dialogs`: `from`/`to` → `from_user`/`to_user` (the
  values always were the URI user parts).
- **TUI JSON save**: `message_count` → `msg_count`; `created_at` gains full
  RFC 3339 precision and rows gain `updated_at`/`duration_sec`. RTP JSON
  save: `mos`/`jitter_ms`/`loss_pct` are no longer rounded to 1 decimal,
  MOS now comes from the single E-model in `rtp::quality` (this path
  carried its own divergent copy), and an unset codec serializes as `null`
  instead of `"unknown"`.
- The browser/WASM `get_dialogs` surface intentionally keeps its current
  shape (website JS consumes it); unifying it is tracked in
  MAINTAINABILITY-PERF-SPEC.md.

## [0.4.18] - 2026-07-02

### Fixed — TUI correctness sweep

**Message visibility (critical):**
- **OPTIONS/REGISTER keepalives are no longer misclassified as retransmissions.**
  Retransmission identity now includes the top Via branch (the RFC 3261
  transaction ID), so distinct transactions that reuse Call-ID + CSeq — the
  common keepalive pattern — all render in the ladder. Messages without a
  branch (RFC 2543 peers) keep the CSeq-identity fallback.
- **Folding is identical in every timestamp mode.** Fold decisions were keyed
  on list positions that `Scaled` mode's spacer rows shifted, so which
  messages were visible depended on the time-unit setting. Every ladder row
  now carries the index of the raw message it renders; folds, expansion and
  selection are keyed on that.
- **Fold headers show their count on the arrow** (`OPTIONS (+2 retx)`); the
  off-arrow annotation was hidden under the split detail pane, making folds
  read as silent data loss. Annotations are clipped to the ladder pane.
- **`e` expands the fold you have selected** (header-keyed, all
  retransmissions of the run revealed) and re-collapses it.

**Selection & filters:**
- **Enter opens the row the user sees.** Selection, navigation bounds, counts
  and endpoint lookups all resolve against the same displayed list
  (filter + search + sort) the renderer draws; sorting or searching no longer
  opens the wrong call.
- **Reversing the sort on the default `#` column works** (it was a no-op).
- **Multi-select checkmarks are keyed by Call-ID**, so re-sorting, filtering
  or new traffic can no longer silently transfer a checkmark to a different
  call before save/clear acts on it.
- **Filter fields match literally.** User text is regex-escaped: `a+b` means
  the user `a+b`, and `(`/quotes/backslashes can no longer break the filter.
- **The Payload filter field works** (new `payload` DSL field matching the
  raw message content of a dialog).
- **The stream list honors search and the active SIP display filter** (via
  each stream's associated dialog; unassociated streams stay visible).
- Search reopen keeps the query for refining; the call-flow detail pane shows
  the selected message even with folds or a transaction filter active;
  per-call state (marks, folds, diff selection) resets when opening a
  different call; Esc from a raw message returns to the view it was opened
  from.

**Navigation:**
- **Scroll offsets are clamped to content everywhere** (raw message, combined
  detail, stream detail, call-flow ladder, statistics, diff): `End` lands on
  the last page instead of a blank screen, and over-scrolling no longer
  strands `Up` presses.
- **The Statistics and Message-diff views scroll** (arrows, PgUp/PgDn,
  Home/End) — long content was previously truncated with no way to see it.
- Missing keys added: `End` (raw message, stream detail), `PgUp`/`PgDn`
  (stream list). The call-flow ladder keeps the selection inside the real
  viewport (no more hardcoded 20-row guess).
- **Mouse wheel scrolls every view.**
- Key bursts/pastes are drained per frame instead of one event per redraw.

**Keymap & settings:**
- Custom keybindings apply in the diff and combined-detail views (quit/help
  were hardcoded), and a key rebound in the keymap wins over the built-in
  global `v`/`n` fallbacks.
- **Autoscroll works**: with the toggle on and the selection at the bottom,
  new calls pull the selection down (sticky-bottom); a selection elsewhere is
  never yanked.
- **The syntax-highlight toggle works**: `s` in the raw view now actually
  renders plain text when off.
- `←`/`→` in the call flow explain themselves when the split pane is off
  instead of doing nothing; the dead `call_flow_cache` was removed.

## [0.4.17] - 2026-06-24

### Call flow
- **RTP-in-flow is shown in every media segment, not just the first.** A bar is
  now drawn after each INVITE transaction that carries media — the initial call
  *and* each re-INVITE that re-establishes the stream — keyed on the INVITE CSeq
  so a single transaction (early media + its confirming ACK) still draws only
  one. Previously a same-codec re-INVITE drew nothing, making the ladder look
  like media stopped before the re-INVITE when it actually flowed through to the
  BYE. A re-INVITE that switches codecs still shows the new codec.
- **Dropped the redundant "active" from the bar label** — it now reads
  `RTP · PCMU` (the codec on the in-flow channel already conveys "active").
- Homepage hero regenerated: the call now shows RTP flowing in both segments
  (before and after the re-INVITE), label `RTP · PCMA`.

## [0.4.16] - 2026-06-24

### Call flow
- **RTP-in-flow rendered as a centered double-rail channel.** The media bar in
  the call-flow ladder now draws as a centered `═` double rail spanning the gap
  between the two endpoint pipes (`render::rtp_channel_bar`) — a sustained media
  channel, visually distinct from the single-line `─` SIP arrows. Fixes the old
  byte-width centering that left a wide label aligned off to the left.
- **The bar shows the codec actually USED, not the SDP offer list.** When an
  INVITE offers several codecs but the call lands on one, the bar now shows that
  single codec — sourced from the observed RTP stream's payload type
  (authoritative), falling back to the negotiated SDP answer codec for SIP-only
  captures. A re-INVITE that switches codecs (PCMU → G722) draws a fresh bar with
  the new codec for the second media segment.
- **Early-media placement.** A provisional (1xx) response carrying SDP opens the
  channel at that point (ringback/IVR), rather than after the ACK.

### Performance
- **Batched reader→worker hand-off removes the `--cores` regression.** Focused
  research isolated the cause of the throughput collapse past `--cores 2`: it was
  *not* the RTP/dialog reconstruction (idle workers regressed identically) and
  *not* CPU starvation (14 idle cores) — it was the **per-packet channel hop**.
  Every send bounced a cache line across cores, and that coherency traffic scaled
  with worker count. The reader now batches ~128 packets per shard into one
  channel send (channel depth measured in batches, so the in-flight packet cap is
  unchanged), amortizing the cross-core hop ~128×. On thor-02 (Jetson Thor, 14
  cores, 535k-packet carrier corpus, median-of-5) the cliff is gone — throughput
  holds **flat at ~2.2–2.5M pkts/s from cores 2 through 8** instead of collapsing
  1.9M → 842k → 500k:

  | cores | before | after |
  |---|---|---|
  | 2 | 1.91M | **2.51M** |
  | 4 | 0.84M | **2.26M** |
  | 8 | 0.50M | **2.16M** |

  `--cores 4/8`, previously *slower* than single-threaded, are now the fastest.
  The remaining flatness past cores 2 is the single sequential pcap reader's raw
  ceiling (read + buffer copy + host-pair peek), the expected serial stage.
  CPU pinning was measured and ruled out as a fix (+3–5% at cores 2/4 within
  noise, ~0% at cores 8) — affinity cannot eliminate coherency traffic on a
  single-cluster SoC with per-core-private L1d/L2.

## [0.4.15] - 2026-06-24

### Performance
- **SIMD CRLF scanning in the SIP parser** (`memchr`). `find_crlf` (called per
  header line) replaced its scalar `windows(2).position()` with SIMD `memchr` —
  byte-identical semantics, validated by a parity test over the adversarial edge
  cases (bare `\r`, trailing `\r`, embedded NUL, empty).
- **Fused offline multi-core front-end.** `--cores N` now reads the pcap directly
  and shards in one thread (`run_offline_parallel_file` + `peek_host_pair`),
  eliminating the separate capture-reader thread and the semaphore-capped channel
  between read and shard. This lifts the `--cores 2` peak (carrier 40k corpus,
  thor-02: ~1.81M pkts/s — **2.4× sngrep** while fully reconstructing calls + RTP
  streams). `--cores 2` is the sweet spot; past 2–3 the single sequential pcap
  reader (and SoC memory bandwidth) is the ceiling — not CPU count.

### Added
- **`Ctrl+R` toggles RTP-in-flow** in the TUI (alias for `F6`, for terminals/
  recorders that can't send function keys).

### Changed
- Homepage hero now shows **real bidirectional RTP media** flowing in the
  call-flow ladder (REGISTER → INVITE → RTP → re-INVITE → RTP → BYE), regenerated
  from a real PII-free capture.

## [0.4.14] - 2026-06-24

### Changed
- **`--jobs N` renamed to `--cores N`** (clearer for a capture analyzer; `--jobs`
  was build-tool jargon). Same semantics — offline reconstruction worker count.

### Added / Performance
- **Parse parallelization.** The multi-core engine now shards *raw* packets (via a
  cheap link+IP-header host-pair peek, `capture::parse::peek_host_pair`) so each
  worker does its own parse + reassembly, instead of a single dispatcher parsing
  serially. A flow's packets share a host pair and route to one worker, keeping
  reassembly correct.
- **mimalloc** is now the native binary's global allocator. Offline ingestion does
  one heap allocation per packet, so the allocator was on the hot path (~7.5% of
  instructions in a callgrind profile). This was the single biggest win.
- **`ahash`** replaces SipHash for the per-packet stores (`StreamStore`,
  `DialogStore` maps/indexes). SipHash was ~7% of instructions; ahash is far
  faster while staying DoS-resistant (random-seeded) for attacker-controlled keys.
- **`profiling` build profile** (`cargo build --profile profiling`) — release
  codegen with full symbols for perf/valgrind.

  Combined result (40k-call carrier corpus, thor-02): **`sipnab --cores 2` runs at
  ~1.57M pkts/s — 1.87× faster than sngrep** (840k) while reconstructing all calls
  and full RTP-stream stats (which sngrep does not). The sweet spot is 2–3 cores;
  higher core counts regress (the single dispatcher + store merge is the next
  bottleneck).

## [0.4.13] - 2026-06-24

### Added
- **Multi-core offline reconstruction (`--jobs N`).** For an offline pcap (`-I`)
  with `N>1`, a dispatcher runs the serial L2/L3/L4 parse + reassembly and shards
  each packet by **host pair** (direction-independent, so a flow and its
  bidirectional RTP stay on one worker) to `N` worker threads with thread-local
  dialog + stream stores. At EOF the stores merge with a global stream↔dialog
  reassociation, reproducing the single-threaded result even when a call's SDP and
  its RTP were sharded to different workers. Default `--jobs 1` is unchanged.
  Covers dialog + RTP-stream reconstruction and `--report`/`--json`; advanced
  features (live capture, per-message output ordering, security detectors, SRTP)
  stay single-threaded. Measured 2.14× on a 40k-call carrier corpus; parity
  validated at jobs 1/2/4/8/12.

### Fixed
- **Per-RTP-packet quality-event overhead.** The hot path rebuilt a `StreamKey`
  and did a second stream-store lookup for every RTP packet only to call
  `fire_quality_event`, which no-ops when `--on-quality` is unset. Now guarded on
  `EventExecEngine::quality_events_enabled()` — +21% throughput on the 20k-call
  carrier corpus (5.15s → 4.07s).

## [0.4.12] - 2026-06-24

### Fixed
- **O(n²) carrier-scale throughput collapse eliminated** (SNB-0015). Processing a
  pcap with many concurrent calls collapsed super-linearly — at 20k→30k→40k calls
  throughput fell 340k→116k→47k pkts/s (load ×1.6, wall-time ×10) despite idle
  cores and <1 GiB RSS, i.e. algorithmic, not resource-bound. Two independent
  O(n²) sources in `StreamStore`, both keyed on the active-stream count:
  1. `link_endpoint`/`link_to_dialog` scanned the **entire** stream table on every
     SDP-bearing SIP message to find the streams on a media endpoint — O(streams)
     per message, O(calls²) overall. Now uses an `endpoint_index`
     (`HashMap<(IpAddr,u16), Vec<StreamKey>>`, maintained on insert/evict/clear
     like the existing `ssrc_index`), so linking is O(matching streams).
  2. `ensure_capacity` evicted one stream at a time with `shift_remove_index(0)`,
     which is O(n) on an `IndexMap`. Past `--max-streams` (default 50000, reached
     at ~25k calls) every new stream paid an O(streams) shift → O(calls²) — the
     **dominant** term, and the same bug `DialogStore` already fixed. Now evicts in
     batches (10%) via `drain`, amortizing the shift to ~O(1) per insertion.

  Result (14-core host, carrier SIP+RTP corpus ~93% RTP, offline): 30k calls
  27.68s→8.19s (3.4×), 40k calls 90.95s→17.02s (5.3×), 40k throughput 47k→251k
  pkts/s; all calls still reconstructed.

### Added
- **`SIPNAB_PERF_STATS=1` batch probe.** Emits `endpoint_link_scan_visits` and
  `evict_shift_work` at end of a batch run — the per-run work that was quadratic —
  so the scaling is observable and a regression is caught early. Each is guarded by
  a performance-contract unit test.

## [0.4.11] - 2026-06-24

### Added
- **`--alert-json` structured alert channel.** Security alerts could previously
  only be consumed by scraping the human `[ALERT] <type> src=<ip> <detail>`
  stderr line, which is brittle to any format change. With `--alert-json`, each
  fired alert is also emitted as one JSON object per line on **stderr** —
  `{"ts","alert","src","detail"}` — a stable machine channel. stdout stays
  reserved for `--json` message output and the stdio MCP wire, so the JSON alert
  lines go to stderr (safe even mid-MCP-session). `serde_json` escapes
  attacker-controlled detail, so a crafted UA/Call-ID can't break the line or
  inject a field.

## [0.4.10] - 2026-06-23

### Fixed
- **IPv6-fragmented SIP is now reassembled and decoded** (SNB-0014). The
  IPv4-fragment fix (SNB-0011, 0.4.9) handled IPv4 only. IPv6 carries
  fragmentation in a **Fragment extension header**, not the base header, but
  `parse_packet` hardcoded `ip_id`/`fragment_offset`/`more_fragments` to
  `None/None/false` for IPv6 — so `PacketProcessor` never routed IPv6 fragments
  to the reassembler and each fragment was mis-parsed as a whole datagram,
  silently dropping the message (a large INVITE with SDP over IPv6 decoded to
  0; tshark saw it). `parse_packet` now walks the IPv6 extension headers and, on
  a Fragment header, pulls its offset / MF / 32-bit identification so the
  reassembler keys and reassembles it; `reparse_transport` then recovers the
  transport header from the reassembled payload. `ParsedPacket.ip_id` widened
  `u16 → u32` (the IPv6 fragment id is 32-bit; the IPv4 16-bit id casts up).

## [0.4.9] - 2026-06-23

Hardening release driven by an adversarial review of the `siptest` harness: new
fixtures and a field-level cross-check surfaced five real defects, each fixed
tests-first (red → green) with adversarial-input coverage.

### Added
- **`--json` now emits `contact` and the raw `sdp` body** (SNB-0009). `contact`
  carries the `Contact` header; `sdp` is the raw body, emitted only for
  `Content-Type: application/sdp` with a valid-UTF-8 body. Lets consumers
  cross-check the routing target and the negotiated media (connection / `m=` /
  `a=rtpmap`) that dynamic-PT decode relies on. `schema_version` stays 1
  (optional fields); schema and `docs/output-formats.md` updated.
- **Extension-enumeration detection** (SNB-0010). The scanner detector now tracks
  the set of distinct target extensions (To user, falling back to R-URI) probed
  by a single source within the window and raises `detection=enumeration` when it
  exceeds a threshold — catching a **UA-randomized, INVITE-based, or low-and-slow**
  sweep that signature (`ua_pattern`) and pure-rate detection both miss. INVITE is
  now also counted toward the rate signal. Bounded per source.
- **Deterministic parser-robustness test** (`tests/fuzz_corpus_replay.rs`): a
  stable-toolchain no-panic gate driving `parse_sip`/`parse_sdp`/
  `parse_rtp_header`/`parse_rtcp` with an adversarial seed set and a fixed
  mutation sweep, complementing the nightly `cargo fuzz` targets.

### Fixed
- **IP-fragmented SIP is now reassembled and decoded** (SNB-0011). After IP
  fragment reassembly the buffer is the full IP payload (transport header + data);
  the transport header was never re-parsed, so ports stayed `0` and the SIP
  parser saw the UDP header before the start line — dropping the message entirely
  (e.g. a >MTU INVITE with a large SDP on a real NIC). Added
  `parse::reparse_transport`, which recovers the ports/transport and strips the
  header before SIP parsing.
- **Out-of-order TCP: a gap-filling segment now completes a stalled push**
  (SNB-0012). When the final segment (carrying PSH) arrived before an earlier
  one, the push could not drain (gap) and the later gap-filling segment had no
  PSH, so the now-contiguous data was buffered forever and never decoded. The
  reassembler now remembers a pending push and flushes once the gap fills.
- **stdio MCP server exits on client disconnect** (SNB-0013). `--mcp` over stdio
  spun until SIGINT and ignored stdin EOF, leaking the process after a client
  disconnected. The wait loop now also breaks when the stdio serve thread
  finishes (HTTP transport, which only ends on a signal, is unaffected).

## [0.4.8] - 2026-06-23

### Fixed
- **TCP: every SIP message in a coalesced segment is now decoded** (SNB-0008).
  Over TCP, message boundaries are delimited by `Content-Length`, not packet
  boundaries, so one segment can carry several complete messages. The reassembly
  consumer previously wrapped each flush as a single message and parsed only the
  first, silently dropping the rest — the classic sngrep (#466) weakness. The TCP
  branch of `PacketProcessor::process` now frames the reassembled stream
  message-by-message (`frame_tcp_sip`: scan to `\r\n\r\n`/`\n\n`, read
  `Content-Length` incl. compact `l`, `message_end = headers_end + CL`), emitting
  one packet per complete message. A trailing incomplete message is held as
  bounded per-stream leftover (`tcp_sip_leftover`) and prepended to the next
  flush, so a body split across segments completes cleanly instead of being
  false-flagged malformed; on FIN/RST the held partial is surfaced (truncated)
  rather than dropped. Framing is gated by `sip::is_sip_message`, so
  TLS/WebSocket/binary TCP still passes through whole.

## [0.4.7] - 2026-06-22

### Fixed
- **Dynamic RTP payload types now resolve codec and clock rate from the SDP
  `a=rtpmap`** (SNB-0007). Streams created after their SDP (the normal order —
  always so in offline pcap replay, where the INVITE/200 is parsed before any
  RTP packet) were left at the 8 kHz default, reporting `Codec ?` and a wrongly
  ~11×-inflated RFC-3550 jitter for 90 kHz media. The negotiated endpoint is now
  remembered and applied at stream creation, so e.g. H.264 on PT 96 reports
  `H264 / 90000` with correct jitter, and the stream associates to its dialog.

### Added
- **TUI call flow: combined transaction/dialog detail.** `a` opens a single
  scrollable view stacking the full raw text of every message in the selected
  message's transaction; `A` does the same for the whole dialog.
- **TUI call flow: transaction filter.** `f` toggles the ladder between showing
  only the selected message's transaction (CSeq number + method, with ACK folded
  into its INVITE) and the whole dialog.
- **TUI Name popup: multi-endpoint.** `N` now offers every participant of the
  flow (or both ends of a stream/dialog); `Tab`/`Shift-Tab` switch between them
  and `Enter` applies all — previously only the first endpoint was editable.

### Changed
- **TUI call flow: the current row is shown by a full-row highlight** instead of
  a leading accent glyph that shifted the whole row's content right by one column
  as the cursor moved.

## [0.4.6] - 2026-06-22

### Added
- Dialog report (`--report`) RTP Streams table gains critical per-stream analysis
  columns alongside SSRC/Codec/Source/Destination: **PT** (payload type number),
  **Clock** (RTP clock rate), **Lost** (absolute count) next to **Loss%**,
  **Dur** (stream duration), and **Kbps** (mean payload bitrate). Makes
  codec/clock mismatches, one-way/short streams, and bitrate anomalies visible
  at a glance.

## [0.4.5] - 2026-06-22

### Added
- Dialog report (`--report`) gains a `Code` column showing the terminating SIP
  response behind each dialog's `State` — `Completed 200`, `Failed 486`,
  `Cancelled 487` — so the precise outcome (486 busy vs 503 unavailable vs 408
  timeout …) is visible, not just the generic state word. Backed by a new
  `SipDialog::final_status_code()` (highest final response on the INVITE CSeq;
  `-` while the call is still in progress).

### Fixed
- Auth-challenged calls no longer report the 401/407 challenge as their outcome.
  An INVITE challenged with 407 (or 401) and then answered now reports `200`
  (the challenge is an intermediate step); a call that is only ever challenged,
  with no authenticated retry, still reports the 401/407.

## [0.4.4] - 2026-06-19

### Added
- Cycleable From/To column display (press `u`): when a SIP URI has no username
  the column now falls back to the host (and optional port) instead of a bare
  `-`. Four modes — default (user else host:port), host:port, user, and
  user@host:port. Set the startup default with `--from-to-mode` or
  `[display] from_to`. IP-literal hosts are name-resolved like Source/Dest.
- Name mappings can be persisted into sipnabrc: `[names] persist_to_config`
  writes `N`-dialog edits into a `[names.manual]` table (comments and other
  sections preserved), and that table is loaded at startup. Mappings continue to
  embed into PCAP-NG Name Resolution Blocks on save.
- The in-TUI F1 help now documents every keybinding (including name resolution
  `n`/`N`, statistics `s`, open `O`, settings `F8`, audio `Shift+P`, and the new
  `u`) and is scrollable (`↑`/`↓`/`PgUp`/`PgDn`). A test guards against future
  keybinding/help drift.

### Fixed
- Filter dialog: SIP method checkboxes now start **all checked** (show
  everything) and toggling them actually filters. Unchecking every method shows
  nothing; clearing (`F9`) restores show-all.
- Corrected the `Ctrl+L` documentation (it clears calls, same as `F5`).

## [0.4.3] - 2026-06-18

### Added
- Address name resolution (Wireshark-style): display `host:port` / `fqdn:port`
  instead of `ip:port` in the call list, call-flow participants, and RTP stream
  views. Press `n` to cycle Off / Static / DNS; press `N` to name the selected
  address in context (saved to `~/.config/sipnab/hosts`). Sources, in priority
  order: operator mappings, `/etc/hosts`, then reverse DNS (PTR, on a
  background worker, off by default). New `--resolve`, `--reverse-dns`, and
  `--names <FILE>` flags and a `[names]` config section.
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
- pcapng metadata: name mappings are persisted into a Name Resolution Block
  (NRB) when saving with resolution active, and embedded NRB names are read back
  when a pcapng is opened. Embedded TLS Decryption Secrets Blocks (DSB) are fed
  to the decryptor on open (with a status-line alert that the file carries
  secrets), and `--strip-secrets <OUTPUT>` writes a secret-free copy of an input
  pcapng (the `editcap --discard-all-secrets` analog) without touching the
  original. See `docs/design/pcapng-metadata.md`.

### Security
- SRTP auth-tag verification now uses a constant-time comparison (shared with
  the API/MCP token check) instead of `==`, closing a MAC timing side channel.
- SRTP session-key derivation now uses the real RFC 3711 §4.3.1 AES-CM KDF
  (validated against the RFC 3711 Appendix B.3 test vectors) instead of an
  HMAC stand-in, so the auth-tag verifier interoperates with standard SRTP.
  Verification also tries the first two ROC epochs (~131072 packets) rather
  than assuming ROC 0; long sessions still need stateful ROC tracking.
- SRTP key material is no longer exposed: `SrtpKeyMaterial` has a hand-written
  `Debug` that redacts the master key/salt, and the keys are now always wiped
  on drop (the zeroizing `Drop` was previously gated behind the `tls` feature,
  so non-tls builds left keys in freed heap).
- SRTP key-parsing error messages (SDP `a=crypto` and the manual key file) no
  longer echo the candidate base64 key/salt bytes — they report only the length.
- New `SrtpRocTracker` verifies SRTP auth tags with stateful per-SSRC rollover
  tracking (RFC 3711 §3.3.1 index estimation), so streams longer than 65536
  packets verify correctly instead of relying on the stateless two-epoch guess.
- User resolution (`--user` / privilege drop) now uses the reentrant
  `getpwnam_r` instead of `getpwnam`, which returns a pointer into a shared
  static buffer that a concurrent lookup on another thread can overwrite mid-read
  (a data race that surfaced as a flaky `nobody`-resolution test).
- TLS 1.2 CBC records are no longer decrypted: those suites are MAC-then-encrypt
  and the record MAC was not verified, so a crafted capture could inject forged
  "decrypted" SIP. The decryptor now declines CBC and emits nothing rather than
  surfacing unauthenticated plaintext. AEAD suites (AES-GCM), which `ring`
  authenticates on decrypt, are unaffected and remain the supported path.
- Manual name mappings are now persisted atomically (temp file in the same
  directory + rename): an interrupted or failing write can no longer truncate
  the operator's names file, and a symlink at the destination is replaced rather
  than written through.
- The REST API now refuses to start on a non-loopback bind when no
  authentication is configured (matching the MCP HTTP transport), instead of
  serving an open, unauthenticated read API. Bind `127.0.0.1` or configure
  `--api-key` / `--api-signing-key`.
- Manual names are validated (`is_valid_name`) before they reach the
  hosts-format file: a name containing a newline / tab / control char can no
  longer inject a second host record on round-trip. The in-TUI `N` dialog
  rejects such names, and the serializer skips them as defense in depth.
- The API and MCP HTTP servers now cap request body size, and the REST API
  applies a per-request timeout, so a slow or oversized client cannot pin a
  connection slot.
- pcapng metadata reading and `--strip-secrets` now reject files above a 2 GiB
  in-memory cap instead of risking an OOM on a hostile multi-GB "pcapng".

### Fixed
- Timestamp conversion no longer overflows on a crafted capture/HEP packet: a
  `tv_usec`/`TS_USEC` outside `[0, 1_000_000)` is clamped before the µs→ns
  multiply, which previously panicked in debug/test builds (overflow-checked)
  and wrapped silently in release.
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
