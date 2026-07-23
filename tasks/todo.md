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


## Code-improvement backlog (from the 2026-07-23 documentation audit)

Observations logged while documenting every function; none are fixed yet.
Grouped by area. Categories: bug/correctness, security, efficiency,
edge-case, dead-code, duplication, test-quality, naming/api.


### capture A (hep, parse, packet, channel, atomic, device)
- [ ] src/capture/hep.rs:934 — [edge-case] `build_hep_v3_bytes`: `timestamp.timestamp() as u32` silently truncates post-2106 / wraps pre-1970; no guard.
- [ ] src/capture/hep.rs:959 — [potential-bug] `build_hep_v3_bytes`: total_length `as u16` wraps past 65535 → corrupt header (same in test helper at 1732).
- [ ] src/capture/hep.rs:1566 — [missed-edge-case] `HepSender::new` binds `0.0.0.0:0` (IPv4-only); IPv6 dest fails — bind family should follow destination.
- [ ] src/capture/hep.rs:381 — [efficiency] `verify_hmac_auth_token` prunes the whole nonce map per accepted packet; amortize (e.g. once/second).
- [ ] src/capture/hep.rs:1162 — [api] global rate limit 0 drops everything while per-peer 0 means disabled — inconsistent knob semantics.
- [ ] src/capture/hep.rs:1146 — [missed-edge-case] at HEP_MAX_TRACKED_PEERS, new peers bypass the per-peer cap for the rest of the window (many-source-IP attacker).
- [ ] src/capture/hep.rs:~1380 — [behavior] `--count` counts only forwarded packets, not received; may surprise operators.
- [ ] src/capture/hep.rs (hep_bind_is_loopback) — [latency] possible blocking DNS lookup in a security decision at startup.
- [ ] src/capture/parse.rs:460 — [missed-edge-case] no IPv6-in-IP (protocol 41) encapsulation support; tunneled IPv6 SIP dropped.
- [ ] src/capture/parse.rs:203 — [known-gap] SCTP DATA fragment reassembly across packets unimplemented (documented follow-up).
- [ ] src/capture/parse.rs:650 — [efficiency] `v6.extensions().clone()` per IPv6 packet on hot path.
- [ ] src/capture/parse.rs:163 — [robustness] `ip_protocol_to_transport` silently maps unknown protocols to UDP; mislabels e.g. ESP.
- [ ] src/capture/channel.rs:140 — [metric-accuracy] backpressure counter can overstate blocking (failed try_send then instant send).
- [ ] src/capture/atomic.rs:53 — [efficiency] closure gets unbuffered File; wrap in BufWriter internally (flush before sync_all).
- [ ] src/capture/packet.rs:81 — [api-hygiene] `Packet::new` allows `caplen != data.len()`; debug assert or derive caplen.
- [ ] src/capture/device.rs (test list_devices_returns_vec) — [test-quality] asserts only "does not panic".
- [ ] src/capture/hep.rs:~1408 — [style] mixed `Instant::now()` vs fully-qualified in same fn.

### capture B (decrypt, tls, dtls, rsa_key, websocket)
- [ ] src/capture/decrypt.rs:263 — [dead-code] `hmac_sha256` takes unused `_crypto: &dyn CryptoBackend` param.
- [ ] src/capture/decrypt.rs:856 — [efficiency] clones entire observed-handshake vector per `ensure_sessions_populated` pass to sidestep borrow.
- [ ] src/capture/decrypt.rs:846 — [correctness] TLS 1.2 CLIENT_RANDOM derivation accepts first ServerHello that works; concurrent handshakes can mis-bind.
- [ ] src/capture/decrypt.rs:742 — [efficiency] `try_decrypt` clones all session keys per ApplicationData record.
- [ ] src/capture/tls.rs:191 — [security] `KeyLogEntry::drop` wipes with elidable plain loop and skips `label`; use `zeroize` like `TlsSession`.
- [ ] src/capture/decrypt.rs:414 — [robustness] `parse_client_key_exchange_rsa` couples length guard and indexing implicitly; fragile to edits.
- [ ] src/capture/dtls.rs:48 — [minor] `SrtpProfile::key_len`/`salt_len` ignore `self`, always 16/14.

### capture C (mod, writer, pcap_reader, pcapng_meta, file, reassembly, live, native)
- [ ] src/capture/mod.rs:295 — [correctness] leftover-map eviction victim is arbitrary (`keys().next()`), not oldest; active session's partial can be evicted.
- [ ] src/capture/mod.rs:284 — [efficiency] TCP framing double-copies; `Bytes::from(buf).slice(r)` would be zero-copy.
- [ ] src/capture/mod.rs:210 — [missed-edge-case] reassembled fragmented TCP datagram bypasses TCP reassembler/SIP framer.
- [ ] src/capture/file.rs:195 — [missed-edge-case] replay mode sleeps full inter-packet delta in one `thread::sleep`; delays shutdown. Sleep in bounded slices.
- [ ] src/capture/file.rs:249 — [consistency] `pcap_ts_to_chrono` silently falls back to now() here but counts+warns in live.rs; unify.
- [ ] src/capture/writer.rs:348 — [correctness] `--split filesize:N` counts only payload bytes, not record framing; systematic underestimate.
- [ ] src/capture/writer.rs:335 — [missed-edge-case] every EPB written with interface_id 0; multi-device capture loses per-interface attribution.
- [ ] src/capture/pcap_reader.rs:484 — [correctness] `if_tsresol` not reset at new SHB; multi-interface/multi-section pcapng gets wrong resolution/link type (EPB interface_id ignored).
- [ ] src/capture/pcap_reader.rs:225 — [edge-case] seconds `as u32` truncation past 2106 baked into public type.
- [ ] src/capture/pcap_reader.rs:299 — [dead-code] `opt_data_end` computed then discarded.
- [ ] src/capture/reassembly.rs:520 — [correctness] TCP sequence comparison is non-wrapping; streams crossing 2^32 misclassify in-order segments as retransmits (needs serial arithmetic).
- [ ] src/capture/reassembly.rs:286 — [dead-code] `TcpStream.created` never read.
- [ ] src/capture/native.rs:329 — [missed-edge-case] multi-capture: one device open failure doesn't tear down sibling capture threads.

### sip A (dialog_store, dsl, dialog)
- [ ] src/sip/dialog_store.rs:313 — [correctness] retransmission floods at message cap never advance `updated_at`; dialog can be wrongly compacted as idle.
- [ ] src/sip/dialog_store.rs:617 — [dead-code] `.filter(score >= 50)` can never filter (min emitted score is 50).
- [ ] src/sip/dialog_store.rs:426 — [missed-edge-case] `merge` drops losing duplicate's seen_cseq/retransmit counts/timing instead of unioning.
- [ ] src/sip/dialog_store.rs:511 — [efficiency] `find_correlated_scored` O(dialogs × messages × headers) with per-candidate allocs; hot per TUI frame.
- [ ] src/sip/dialog_store.rs — [observability] no-rotate capacity drops are uncounted (idle evictions are counted).
- [ ] src/sip/dsl.rs:1069 — [correctness] `compare_num` absolute-epsilon equality is effectively exact for values ≥2; `duration == 5.0` ~never matches.
- [ ] src/sip/dsl.rs:829 — [missed-edge-case] quoted strings have no escape mechanism; delimiter char inexpressible.
- [ ] src/sip/dsl.rs:956 — [missed-edge-case] `rtp.ssrc`/`rtp.codec` only consider the first stream, asymmetric with worst-across-streams quality fields.
- [ ] src/sip/dsl.rs:965 — [correctness] `src.port`/`dst.port` read `messages.first()`, which drifts after `compact_idle` drains oldest messages.
- [ ] src/sip/dsl.rs:333 — [efficiency] `matches_dialog` always runs media/asymmetry diagnosis even when no diagnosis field in expression.
- [ ] src/sip/dsl.rs:939 — [efficiency] `payload` field does lossy String conversion per message per evaluation.
- [ ] src/sip/dsl.rs:685 — [missed-edge-case] quoting-hint keyword exclusion is lowercase-only while parser is case-insensitive; `method == TRUE` gets misleading hint.
- [ ] src/sip/dialog.rs:178 — [efficiency] `final_status_code` collects a Vec per call on the render path.
- [ ] src/sip/dialog.rs:369 — [missed-edge-case] CANCEL/200-OK race: 2xx after CANCEL leaves state Cancelled though the call was established per RFC 3261.
- [ ] src/sip/dialog.rs (update_register_state) — [missed-edge-case] 401/407 challenge marks REGISTER dialog Failed; challenge-only capture reads as failure rather than auth-pending.

### sip B (parser, message, matcher, sdp, sdp_timeline, siprec, stir_shaken, timing, method, response_codes, mod)
- [ ] src/sip/mod.rs:84 — [duplication] `find_crlf` duplicated verbatim in parser.rs.
- [ ] src/sip/mod.rs:72 — [edge-case] request detection accepts `ASIP/2.0` (ends_with not delimiter-anchored); same in parser.rs.
- [ ] src/sip/parser.rs:317 — [adversarial] MAX_HEADER_LINE_LEN enforced only on folded continuations; single unfolded multi-MB header accepted whole.
- [ ] src/sip/parser.rs:279 — [silent-loss] headers beyond MAX_HEADERS_PER_MESSAGE silently dropped without parse_error.
- [ ] src/sip/parser.rs:369 — [edge-case] non-numeric Content-Length silently ignored, no parse_error.
- [ ] src/sip/parser.rs:97 — [efficiency] `parse_sip` copies input before any validation.
- [ ] src/sip/parser.rs:215 — [edge-case] Request-URI not trimmed; double space yields URI with leading space.
- [ ] src/sip/message.rs:117 — [edge-case] `cseq()` keeps trailing garbage in method (`"INVITE extra"`), defeating comparisons in timing.rs; untested.
- [ ] src/sip/message.rs:294 — [adversarial] `extract_uri_user` finds `sip:` anywhere; crafted display name parses from wrong position.
- [ ] src/sip/matcher.rs:170 — [efficiency] payload matching allocates lossy String per message; `regex::bytes` would be copy-free.
- [ ] src/sip/matcher.rs:179 — [efficiency] from_user/to_user allocations computed even when full-header match already succeeded.
- [ ] src/sip/matcher.rs:160 — [inconsistency] `calls_only` matches method case-insensitively while `SipMethod::parse` is case-sensitive.
- [ ] src/sip/matcher.rs:13 — [naming] REGEX_SIZE_LIMIT comment says "ReDoS"; regex crate is linear-time — limit bounds memory/compile cost.
- [ ] src/sip/sdp.rs:127 — [efficiency] `parse_sdp` collects all lines into a Vec up front.
- [ ] src/sip/sdp.rs:307 — [edge-case] `parse_rtpmap` accepts payload types 128–255 (doc says 0–127).
- [ ] src/sip/sdp_timeline.rs:184 — [bug-risk] repeated T.38 re-INVITEs re-emit T38Switch every other exchange (suppression checks only previous event).
- [ ] src/sip/sdp_timeline.rs:116 — [limitation] delayed-offer INVITEs (offer in 200, answer in ACK) mislabeled by request/response classification.
- [ ] src/sip/sdp_timeline.rs:103 — [modeling] REFER transfers reuse Offer + magic `mode: "transfer"`; dedicated variant cleaner.
- [ ] src/sip/siprec.rs:66 — [adversarial] `split_multipart` splits on `--boundary` anywhere, not line-anchored per RFC 2046.
- [ ] src/sip/siprec.rs:83 — [limitation] per-part Content-Type requires line-start, no folded MIME headers.
- [ ] src/sip/siprec.rs:121 — [gap] participant AOR misses `<nameID aor="...">` attribute form common in RFC 7865 metadata.
- [ ] src/sip/stir_shaken.rs:152 — [silent-loss] only first `dest.tn` kept; multi-destination PASSporTs drop the rest.
- [ ] src/sip/stir_shaken.rs:160 — [testability] `parse_identity_header` reads Utc::now() internally; inject clock for deterministic iat tests.
- [ ] src/sip/stir_shaken.rs:278 — [naming] test `malformed_jwt_too_few_parts` actually exercises too many parts.
- [ ] src/sip/timing.rs:135 — [edge-case] `answered_at` matches any 200-to-INVITE without CSeq check; re-INVITE 200 can be recorded as answer time.
- [ ] src/sip/timing.rs:117 — [edge-case] `starts_with("terminated")` also matches `terminatedfoo`.

### root A (cli, config, names, crash)
- [ ] src/cli.rs:878 — [bug] HEP/syslog/alert-json flags carry `help_heading = "MCP (Model Context Protocol)"`; wrong `--help` section.
- [ ] src/cli.rs:64 — [edge-case] `PerPeerLimit::Auto.resolve` integer division yields 0 (disabled) when allowlist_len > global; should floor at 1.
- [ ] src/cli.rs:1291 — [dead-code] `warn_unimplemented_flags` is an empty no-op still called from main.rs:38.
- [ ] src/cli.rs:517,797,1028 — [refactor] `--color`, `--mcp-transport`, `--pcap-export-mode` are free-text Strings validated late; `value_enum` would reject at parse time (`--mcp-transport bogus` without `--mcp` passes silently).
- [ ] src/config.rs:19 — [efficiency] `known_keys()` rebuilds HashMap per call; LazyLock static.
- [ ] src/config.rs:749 — [efficiency] `parse_toml` parses TOML twice; deserialize Config from parsed Value.
- [ ] src/config.rs:860,915 — [missed-edge-case] `write_display_columns_file`/`write_manual_mappings_file` are non-atomic, symlink-following; share names.rs atomic temp+rename helper.
- [ ] src/names.rs:70 — [resource-leak] `dns_requested`/`dns_cache` unbounded; long captures accumulate forever (no LRU).
- [ ] src/names.rs:120 — [resource-leak] DNS worker channel unbounded; burst of unique IPs queues arbitrarily.
- [ ] src/names.rs:229 — [nit] `remove_manual` bumps generation even when nothing removed.
- [ ] src/crash.rs:137 — [race] `create_report_dir` exists→create_dir_all TOCTOU; only leaf tightened to 0700.
- [ ] src/crash.rs:407 — [missed-edge-case] `hook_body` claims nothing may panic, but `eprintln!` panics on closed stderr; use `writeln!(io::stderr()).ok()`.
- [ ] src/crash.rs (write_crash_report) — [nit] write_all failure leaves partial report file behind.


### tui call_flow (mod, render, prepare, arrows, export)
- [ ] src/tui/call_flow/export.rs:86 — [correctness] RTP-bar rows export as Mermaid self-arrows; want `is_rtp_bar` skip like `is_spacer`.
- [ ] src/tui/call_flow/export.rs — [correctness/security] labels interpolated unescaped into Mermaid/HTML; `;#<`/newlines can break rendering or inject markup.
- [ ] src/tui/call_flow/export.rs:48 — [robustness] exported HTML loads mermaid.js from CDN; unviewable offline (conflicts with no-external-deps stance).
- [ ] src/tui/call_flow/render.rs:493 — [correctness] badge x-position uses byte len; `Δ` misplaces badge one column left.
- [ ] src/tui/call_flow/render.rs:1239 — [dead-code] `format_ladder` `_first_ts` unused.
- [ ] src/tui/call_flow/render.rs:291 — [dead-code] `render_call_flow_lines` `_call_id` unused.
- [ ] src/tui/call_flow/render.rs:1503 — [simplification] pointless `let fsty = sty;` alias.
- [ ] src/tui/call_flow/render.rs — [duplication] Correlated-Legs section + arrow-width math duplicated across builders; header/pipe builders duplicated across format_ladder variants.
- [ ] src/tui/call_flow/prepare.rs:604 — [efficiency] SDP badge pass re-parses `msg.sdp()` per message though main loop already parsed into msg_sdp.
- [ ] src/tui/call_flow/prepare.rs:1184 — [simplification] `first_sdp_codec` round-trips through format+re-split; duplicates payload-type table.
- [ ] src/tui/call_flow/prepare.rs:306 — [correctness] endpoints capped at 6; 7th endpoint messages silently draw between wrong participants.
- [ ] src/tui/call_flow/prepare.rs:956 — [efficiency] retransmit folding rescans emitted rows per retx — O(n²) on a storm.
- [ ] src/tui/call_flow/arrows.rs (truncate) — [edge-case] byte-based truncation; display-width-aware would be correct for CJK.
- [ ] src/tui/call_flow/mod.rs (ladder_split_width) — [test-coverage] no test pins `total < DETAIL_FLOOR` geometry.

### tui core (mod, state, theme, help, test_api)
- [ ] src/tui/mod.rs:645 — [duplication] sync_caches CallFlow branch inlines what `rtp_codec_segments` implements.
- [ ] src/tui/mod.rs:922 — [missed-edge-case] `rtp_codec_segments` returns empty on try_read contention; Mermaid export silently omits RTP segments.
- [ ] src/tui/mod.rs:1264 — [missed-edge-case] event-loop dialog-count try_read under sustained write contention keeps poll in slow idle mode.
- [ ] src/tui/mod.rs:716 — [efficiency] merged-calls ladder clones every message before sorting; extended branch sorts refs.
- [ ] src/tui/mod.rs:2149 — [dead-attribute] redundant nested `#[cfg(test)]`.
- [ ] src/tui/mod.rs:1055 — [organization] NameSetup/TuiOptions defined in mod.rs; siblings live in state.rs.
- [ ] src/tui/theme.rs:37 — [missing-config] `status_bg` is the only theme color users cannot configure.
- [ ] src/tui/help.rs:169 — [fragile-coupling] `help_line_count()` hardcodes +1 for the synthesized version line; no test ties them.
- [ ] src/tui/state.rs:966 — [unclear-naming] `FilterDialogState::is_empty` dead_code-allow rationale undocumented.

### tui controllers
- [ ] src/tui/controllers/file_open.rs:353 — [potential-bug] `tv_usec as u32 * 1000` overflows for nanosecond-precision pcaps (panic in debug, wrong ts in release).
- [ ] src/tui/controllers/mod.rs:351 — [efficiency/inconsistency] stream-list wheel path re-filters store per event; keyboard path uses cached keys.
- [ ] call-list F9 vs call-flow F9 — [inconsistency] one clears search_query, the other leaves it narrowing the list.
- [ ] src/tui/controllers/call_flow.rs:413 — [efficiency] `flow_visible_msg_count` computes raw_count even when cached value wins.
- [ ] src/tui/controllers/call_list.rs:307 — [efficiency] `clear_calls` Vec::contains inside retain O(n·m); HashSet.
- [ ] src/tui/controllers/call_list.rs:324,342 — [missed-edge-case] clear_non_matching/matching pass `&[]` streams to matches_dialog; stream-criteria rows misclassified and deleted.
- [ ] src/tui/controllers/mod.rs:254 — [fragility] settings popup hardcodes item indexes 0-5 in sync with renderer order.
- [ ] src/tui/controllers/file_open.rs:206 — [missed-edge-case] manual-path mode lacks Delete key handling (filter dialog has it); same in save dialog.
- [ ] src/tui/controllers/name_dialog.rs:174 — [missed-edge-case] second failure overwrites first on status line.
- [ ] src/tui/controllers/name_dialog.rs:34 — [efficiency] de-dupe allocates String per (target × ip).
- [ ] src/tui/controllers/mod.rs:341 — [duplication] dashboard wheel handler re-implements dashboard.rs row clamp.
- [ ] src/tui/controllers/save_dialog.rs:35 — [missed-edge-case] Enter queues PendingSave with empty path; validate at dialog.
- [ ] src/tui/timeline.rs — [tracking] timeline wheel/navigation are placeholders; don't ship navigation-less.

### tui render/detail
- [ ] src/tui/render/popups.rs:653 — [bug] byte-slicing UTF-8 in filter fields panics on multi-byte at boundary (also :666, :677, save/file-open cursors).
- [ ] src/tui/render/popups.rs:677 — [bug] range start > end panic when focused cursor beyond inner_width; cursor never clamped.
- [ ] src/tui/render/popups.rs:648 — [edge-case] `field_width - 2` debug underflow on very narrow terminal.
- [ ] src/tui/render/popups.rs:801 — [edge-case] `(iw - 4)` underflow below ~6 cols.
- [ ] src/tui/render/status.rs:48 — [edge-case] byte-offset slicing vs char-count padding misaligns styled span for non-ASCII filenames.
- [ ] src/tui/render/status.rs:96 — [edge-case] `styled_len` counts bytes not display width.
- [ ] src/tui/render/mod.rs:123 — [efficiency] per-frame clones of current_view/active_popup.
- [ ] src/tui/render/mod.rs:206 — [refactor] fold-label duplicates "(+N retx)" format knowledge owned by prepare.
- [ ] src/tui/render/mod.rs:750 — [missed-edge-case] positional diff; one inserted header highlights entire tail — LCS diff better.
- [ ] src/tui/render/mod.rs:764 — [bug] scroll clamp ignores wrapping; true bottom unreachable for long header lines.
- [ ] src/tui/msg_raw.rs:170 — [missed-edge-case] search match lines unwrapped vs wrapped-row scrolling; n/N lands short.
- [ ] src/tui/stream_detail.rs:222 — [missed-edge-case] sparklines emit one glyph per interval uncapped; overflow pane width — downsample to last N.
- [ ] src/tui/stream_detail.rs:109 — [naming] MOS label/color band boundaries inconsistent at 3.0–3.5.
- [ ] stream_list.rs:307 / stream_detail.rs:91 — [refactor] loss-% computation duplicated in three places.

### tui views (call_list, save, dashboard, timeline)
- [ ] src/tui/save.rs:676 — [correctness] `save_to_wav_path` indexes raw store order, not displayed order — wrong dialog's audio exported under filter/sort.
- [ ] src/tui/call_list.rs:637 — [simplification] DeltaPrev and Scaled arms byte-identical; merge.
- [ ] src/tui/call_list.rs:521 — [duplication] `base_labels` restates COLUMN_LABELS with one divergence.
- [ ] call_list.rs:880 vs save.rs:206 — [duplication] near-identical 12-arm state-display matches ("FAILED" vs "Failed").
- [ ] src/tui/call_list.rs:697 — [efficiency] builds all 11 cells per row then clones visible subset per frame.
- [ ] src/tui/call_list.rs:835 — [edge-case] narrow layout `addr_each` can exceed flex below ~72 cols.
- [ ] src/tui/save.rs:414 — [consistency] NDJSON `duration_ms` inline + `message_count` vs JSON `msg_count` field-name mismatch.
- [ ] src/tui/save.rs:783 — [edge-case] SIPp export string-replaces destination port digits; can corrupt unrelated URI parts.
- [ ] src/tui/save.rs:60 — [edge-case] mid-stream write error leaves partial capture; all exporters silently overwrite.
- [ ] src/tui/save.rs:1113 — [test-hygiene] `tmp_path` leaks a tempdir per call.
- [ ] src/tui/call_list.rs:659 — [naming] Scaled silently renders as delta-prev in call list; document on the enum.
- [ ] src/tui/dashboard.rs:264 — [edge-case] scroll window anchors selection to bottom row rather than centering.

### rtp core (srtp, stream_store, stream, parser, quality, rtcp)
- [ ] src/rtp/stream.rs:270 — [correctness] reordered packet inflates jitter (wrapping_sub as u64 → 4.29e9 spike); cast wrapped diff to i32 for RFC 3550 signed semantics.
- [ ] src/rtp/stream_store.rs:259 — [correctness] RTCP jitter (RTP timestamp units) overwrites millisecond jitter; feeds MOS 8x off at 8kHz.
- [ ] src/rtp/rtcp.rs:284 — [correctness] 24-bit signed cumulative_lost zero-extended; negative becomes huge positive.
- [ ] src/rtp/stream.rs:134 — [testability] `is_active` uses Utc::now(); offline replay streams never active.
- [ ] src/rtp/stream.rs:310 — [efficiency] `quality_intervals.remove(0)` O(n) at cap; VecDeque.
- [ ] src/rtp/stream.rs:349 — [edge-case] burst_gap window can exceed 1000-entry lost_sequences log; understates burstiness.
- [ ] src/rtp/stream.rs:62 — [accuracy] SilencePeriod assumes 20ms CN cadence; durations are lower bounds.
- [ ] src/rtp/quality.rs:179 — [robustness] three retroactive guards checked independently; silent desync possible.
- [ ] src/rtp/srtp.rs:547 — [dead-code] `decrypt_srtp_payload` unused crypto param.
- [ ] src/rtp/srtp.rs:560 — [efficiency] session keys re-derived via two AES-CM PRF runs per packet; cache per key material.
- [ ] src/rtp/srtp.rs:977 — [efficiency] clones full key material (zeroizing Drop) per candidate key per packet.
- [ ] src/rtp/stream_store.rs:405 — [efficiency] `remember_sdp_endpoint` shift_remove_index(0) per insert at cap — quadratic pattern SNB-0015 fixed elsewhere.
- [ ] src/rtp/stream_store.rs:513 — [edge-case] `clear()` retains sdp_endpoints; post-clear streams re-link to pre-clear dialogs.
- [ ] src/rtp/stream_store.rs:909 — [test-quality] dead first computation; `i % 64_000` aliasing.
- [ ] src/rtp/rtcp.rs:1 — [doc/code gap] header claims no silent drops; known-type body parse failures are dropped.


### rtp audio + security
- [ ] src/rtp/audio_export.rs:124 — [inconsistency] `is_exportable_codec` exact-case opus spellings vs case-insensitive `is_opus_codec`; "OpUs" decodes but is filtered from export.
- [ ] audio_export.rs:182 / playback.rs:261 — [duplication] near-identical i16/f32 linear resamplers.
- [ ] src/security/fraud_detect.rs:224 — [off-by-one] wangiri entry gate (>=3) and per-prefix trigger (>=4) disagree by one.
- [ ] src/security/alerting.rs:110 — [robustness] `parse_duration` split_at panics on non-boundary last byte (multibyte suffix).
- [ ] src/rtp/diagnosis.rs:192 — [edge-case] NAT detection reports last-evaluated sdp_media, not the mismatching one.
- [ ] src/rtp/diagnosis.rs:374 — [accuracy] inferred ptime inflated by packet loss; add loss guard.
- [ ] src/rtp/dtmf.rs:81 — [assumption] hardcodes 8 kHz telephone-event clock; 16 kHz reports double duration.
- [ ] src/rtp/playback.rs:32 — [safety] AudioPlayer raw fn pointers + handle; add invariant note/PhantomData for Send/Sync fragility.

### output
- [ ] src/output/cli_print.rs:199 — [panic] `--payload-limit` byte-slices str mid-UTF-8 → process panic on multibyte raw messages.
- [ ] api.rs:949 vs prometheus_server.rs:433 — [correctness] `sipnab_messages_total` divergent semantics between the two servers.
- [ ] src/output/api.rs:536 — [security] auth checked before rate limit; unlimited-speed Bearer-token brute force.
- [ ] src/output/api.rs:827 — [correctness] `get_stream` matches SSRC alone; collisions return arbitrary stream.
- [ ] src/output/mod.rs:36 — [config] prometheus_server gated behind `api` feature though built to avoid it; `--metrics` without api can't work.
- [ ] src/output/wireshark.rs:122 — [security] single-quotes values without escaping embedded quotes in generated shell command.
- [ ] src/output/event_exec.rs:231 — [resource-leak] `try_wait` error drops Child from tracking without kill/wait.
- [ ] src/output/prometheus_server.rs:266 — [robustness] Authorization header matching only two casings, exactly one space.
- [ ] api.rs / prometheus_server.rs — [duplication] identical bind-address parsers in two files.
- [ ] src/output/cli_print.rs:130 — [edge-case] negative sub-second deltas render as `+0.500s`.
- [ ] src/output/dialog_report.rs:220 — [edge-case] truncate_str max_len<=3 char-count can exceed byte contract.
- [ ] src/output/api.rs (list_*) — [api-design] `total` is unfiltered size while rows are filtered; paging broken.
- [ ] src/output/synthetic.rs — [correctness] >64KiB payloads: length fields saturate but payload appended; header/size disagree.
- [ ] src/output/json.rs:8 — [dead-code] redundant `use serde_json;`.
- [ ] src/output/api.rs (serve_on) — [naming] "max connections" semaphore actually caps in-flight requests.
- [ ] src/output/fail2ban.rs — [consistency] reg-flood src_ip not sanitized (scanner event is).
- [ ] src/output/wireshark.rs — [edge-case] byte-to-char boundary checks misclassify around UTF-8 continuation bytes.

### app + mcp
- [ ] src/mcp/server.rs:745 — [correctness] tail_dialogs truncates before sorting; next_cursor can permanently skip updates when >limit dialogs changed.
- [ ] src/app/bootstrap.rs:966 — [naming] `mint_token_and_exit` never exits.
- [ ] src/app/bootstrap.rs:970 — [dead-code] duplicated #[cfg] attribute pair.
- [ ] src/app/bootstrap.rs:807,869 — [design] build_filter_expr/build_capture_config call process::exit inside PlanError-based plan(); should return PlanError.
- [ ] src/app/batch.rs:132 vs 193 — [simplification] ParallelConfig construction duplicated verbatim.
- [ ] src/app/batch.rs:1464 — [missed-edge-case] DTMF hardcodes PT 101 instead of SDP-negotiated payload type.
- [ ] src/app/batch.rs:988 — [missed-edge-case] custom --tshark-filter without -I references placeholder capture.pcap.
- [ ] src/mcp/server.rs:668 — [efficiency] search_messages allocates format!+to_lowercase per message per call.
- [ ] src/mcp/shape.rs:29 — [naming] `max_chars` is a byte cap; rename max_bytes.
- [ ] src/app/servers.rs:158 — [clarity] tuple let _ suppression obscures intent.
- [ ] src/mcp/transport.rs:96 — [dead-code] auth_layer extracts ConnectInfo it never uses.
- [ ] src/app/tui_mode.rs:246 — [missed-edge-case] pause still counts/writes packets; --count can stop capture mid-pause with packets never processed.
- [ ] src/app/batch.rs:1102 — [test-coverage] mcp_stdio_done exit path untested.

### root infra
- [ ] src/auth.rs:73 — [dead-code+latent-bug] infallible-serialization fallback builds JSON by hand without escaping id.
- [ ] src/process_isolation.rs:432 — [efficiency] PerDstRateLimiter::cleanup O(n) on every send.
- [ ] src/process_isolation.rs:388 — [naming] "sliding window" doc vs fixed-window implementation.
- [ ] process_isolation.rs:204 / parallel.rs:204,336 — [error-handling] `let _ = tx.send` drops dead-worker shard packets silently.
- [ ] src/pipeline.rs:57 — [edge-case] is_rtcp_packet requires odd dst port; RFC 5761 mux RTCP on even port never recognized.
- [ ] src/wasm.rs:24 — [style] new() without Default (intentional; note).
- [ ] src/crypto.rs:13 — [doc-staleness] CryptoBackend doc mentions wolfSSL/OpenSSL backends that don't exist (removed by decision).

### tests A (tui/site)
- [ ] tests/tui_snapshot_test.rs:872,885,1012 — [naming] timestamp-mode tests/snapshots off-by-one vs DeltaPrev default; rename tests + snaps.
- [ ] tests/tui_state_test.rs:3514 — [weak-assertion] enum tautology test can't fail.
- [ ] tests/tui_state_test.rs:1951 — [weak-assertion] page-up assert vacuous when after_down==0.
- [ ] tests/tui_state_test.rs:2206 — [weak-assertion] F9 test passes if F9 did nothing; assert ==3.
- [ ] tests/tui_state_test.rs:2587 — [test-hygiene] writes /tmp/sipnab_test_save.pcap outside tempdir, never cleaned.
- [ ] tests/tui_state_test.rs:3267,3293,3325 — [silent-skip] pcap tests pass vacuously when fixtures missing.
- [ ] tui_state/tui_snapshot — [duplication] fixture builders duplicated across crates; `localhost_*` misnomer (10.0.0.x).
- [ ] tests/tui_state_test.rs:4200 — [duplication] 40-line RTP feed block copy-pasted three times.
- [ ] tests/tui_state_test.rs:4604 — [drift-risk] body_search tests re-implement production search predicate inline.
- [ ] tests/tui_e2e_test.rs:151 — [flaky-pattern] fixed 120ms sleeps; raw screen() reads race render loop.
- [ ] tests/docs_drift_test.rs:278 — [coverage-gap] website/content/docs/mcp.md examples unguarded.
- [ ] tests/docs_drift_test.rs:14 — [weak-guard] FOREIGN_FLAGS whitelists broad names globally.
- [ ] tests/site_journey_test.rs:1290 — [test-hygiene] unconditional eprintln of 30-row screen.

### tests B (rest)
- [ ] tests/cli_options_test.rs:392,401,490,498,507,514 — [weak-assertion] accepted-only / proxy assertions for -w, single-line, color, -A, show-empty, payload-limit and the exit-0-only flag group.
- [ ] tests/cli_options_test.rs:611 — [coverage-contradiction] call_report_nonexistent_call accepts 0|1 while output_behavior pins 1.
- [ ] tests/security_test.rs:467 — [weak-assertion] four H4 cap tests assert nothing (OOM-only failure); add size probes.
- [ ] tests/security_test.rs:310 — [weak-assertion] injection path never fired.
- [ ] tests/security_test.rs:1098 — [weak-assertion] path-traversal warning not captured.
- [ ] tests/security_test.rs:1174 — [weak-assertion] rate-limiter cleanup unverified.
- [ ] tests/security_test.rs:1285 — [flaky] process-global env mutation races concurrent tests (serial_test candidate).
- [ ] tests/resource_bounds_test.rs:88 — [copy-paste] drop-new mode should assert exact cap, not rotate-mode range.
- [ ] tests/parse_path_test.rs:102 — [weak-assertion] _code_b discarded; post-flush crash still passes.
- [ ] tests/mcp_token_rotation_test.rs:364 — [slow] real 7s sleep per run.
- [ ] tests/hep_test.rs:222 — [flaky-pattern] 1.5s absence-of-output negative proof.
- [ ] tests/api_test.rs:169 — [weak-assertion] limiter can't be exhausted; sequential 200s only.
- [ ] tests/integration_test.rs:257 — [environment-dependence] accepts exit 0|1 by capture permissions.
- [ ] tests/wasm_exports_test.rs:10 — [silent-skip] silently never runs if wasm build absent.
- [ ] eight binary-spawn run() helpers — [duplicated-fixture] inconsistent env across cli/config/output/integration test crates; tests/support candidate.
- [ ] spawn_http/post_status/shutdown — [duplicated-fixture] triplicated across mcp token/http tests.
- [ ] fuzz_corpus_replay.rs:131 / smoke_fuzz_test.rs:20 — [duplicated-fixture] two independent xorshift Rng+mutate impls.
- [ ] tests/mockup_alignment_test.rs — [heuristic-limit] lifeline reference = most-pipes line; misaligned reference flags everything else.

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
