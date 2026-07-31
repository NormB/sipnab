# sipnab — open backlog (priority-ranked)

Re-ranked by priority on 2026-07-23 (previously grouped by source area).
Every open item from the 2026-07-23 documentation audit is retained
verbatim with its file:line and category tag. Shipped work is recorded
in `CHANGELOG.md`; completed audit-period features are kept at the
bottom for context.

Tiers:

- **P0 — panics & security**: crashes reachable from real input,
  injection, auth/limit bypass, key-material hygiene.
- **P1 — wrong results in real use**: incorrect exports/metrics/state,
  data corruption or loss, resource leaks, protocol misclassification.
- **P2 — robustness, observability & efficiency**: hot-path costs,
  silent drops, UX edge cases, feature gaps.
- **P3 — code health**: dead code, duplication, naming, docs, style.
- **P4 — test quality**: weak/vacuous assertions, flaky patterns,
  fixture hygiene.
- **P5 — features & long-term / exploratory.**

## P0 — panics & security

- [x] src/tui/render/popups.rs:653 — [bug] byte-slicing UTF-8 in filter fields panics on multi-byte at boundary (also :666, :677, save/file-open cursors). **Done:** all slices go through `text::floor_char_boundary` / whole-char cursor cells; save + file-open path lines share one `path_with_cursor_spans` builder; the filter-dialog *controller's* byte-stepping cursor (insert/remove/arrows) was the same bug at input time and is now char-based.
- [x] src/tui/render/popups.rs:677 — [bug] range start > end panic when focused cursor beyond inner_width; cursor never clamped. **Done:** after-cursor slice is clipped to a boundary-floored visible window and only drawn when `cursor_end < visible_end`.
- [x] src/output/cli_print.rs:199 — [panic] `--payload-limit` byte-slices str mid-UTF-8 → process panic on multibyte raw messages. **Done:** cut point floors to the previous char boundary.
- [x] src/security/alerting.rs:110 — [robustness] `parse_duration` split_at panics on non-boundary last byte (multibyte suffix). **Done:** splits on the last *char*; a multibyte suffix is now just an invalid suffix (`None`).
- [x] src/tui/controllers/file_open.rs:353 — [potential-bug] `tv_usec as u32 * 1000` overflows for nanosecond-precision pcaps (panic in debug, wrong ts in release). **Done:** now routes through the shared hardened `capture::file::pcap_ts_to_chrono`, which clamps `tv_usec` before the µs→ns multiply (the local raw conversion was the last copy that skipped it).
- [x] src/output/api.rs:536 — [security] auth checked before rate limit; unlimited-speed Bearer-token brute force. **Done:** `guard` now rate-limits before authenticating, so every request (including one that will fail auth) is charged to the per-IP budget, throttling token brute-force.
- [x] src/output/wireshark.rs:122 — [security] single-quotes values without escaping embedded quotes in generated shell command. **Done:** all four values (file/device/bpf/display) go through a POSIX `shell_single_quote` that renders embedded quotes via the `'\''` idiom, so a crafted filename/filter is inert data, not injectable shell words.
- [x] src/tui/call_flow/export.rs — [correctness/security] labels interpolated unescaped into Mermaid/HTML; `;#<`/newlines can break rendering or inject markup. **Done:** message + participant labels neutralized via `escape_mermaid_label` (newlines→space, `#;<>`→Mermaid entity codes) and the HTML export additionally HTML-escapes the whole diagram, killing the `</pre><script>` XSS.
- [x] src/sip/parser.rs:317 — [adversarial] MAX_HEADER_LINE_LEN enforced only on folded continuations; single unfolded multi-MB header accepted whole. **Done:** a new unfolded header line `>= max_header_line` now sets parse_error and is dropped (both the CRLF-terminated and truncated-remainder paths), so the cap bounds unfolded lines too.
- [x] src/capture/hep.rs:1146 — [missed-edge-case] at HEP_MAX_TRACKED_PEERS, new peers bypass the per-peer cap for the rest of the window (many-source-IP attacker). **Done:** the map-full guard now fails *closed* — a new untracked peer is dropped (counted) instead of skipping the per-peer check; already-tracked peers are unaffected.
- [x] src/capture/tls.rs:191 — [security] `KeyLogEntry::drop` wipes with elidable plain loop and skips `label`; use `zeroize` like `TlsSession`. **Done:** extracted `zeroize_material` (Drop calls it) that `zeroize`s secret, client_random, AND label via the crate (non-elidable).

## P1 — wrong results in real use

- [x] **`--version` never reports the `metrics` feature** — `compiled_features()`
  in `src/cli.rs` walked `native, tui, audio, tls, hep, api, mcp, mcp-http, wasm`
  and omitted `metrics`, so a `--features full` binary printed
  `features: native,tui,audio,tls,hep,api,mcp,mcp-http` even though the
  Prometheus listener was compiled in. **Done:** `metrics` is now emitted after
  `mcp-http`. Verified: a `full` build prints
  `native,tui,audio,tls,hep,api,mcp,mcp-http,metrics` and a default build prints
  `native,tui,audio,metrics`, matching `default` in `Cargo.toml` exactly. The
  sample outputs in `docs/install.md`, `website/content/docs/install.md` and
  both MCP walkthroughs were updated to match. The version-string fixtures in
  `src/tui/help.rs` and `tests/tui_snapshot_test.rs` are synthetic inputs to the
  renderer and do not call `compiled_features()`, so they were unaffected.
- [x] **musl and `-noaudio` release builds silently shipped without `/metrics`**
  — `release.yml` computed `noaudio_set="native,tui,tls,hep,api,mcp,mcp-http"`
  under a comment describing it as "full minus audio", but it dropped `metrics`
  as well, so every static musl binary and the `-noaudio` package lacked the
  Prometheus endpoint. Nothing said so: the install pages describe the
  `-noaudio` variant as differing *only* in live playback, which was false.
  **Done:** `metrics` added to `noaudio_set`, making the set genuinely "full
  minus audio" and the existing install-page wording true. Takes effect on the
  next tagged release.

- [x] src/tui/save.rs:676 — [correctness] `save_to_wav_path` indexes raw store order, not displayed order — wrong dialog's audio exported under filter/sort. **Done:** the call-list path now resolves the selection via `get_selected_call_id` (filter+search+sort display order), so the highlighted row's audio is exported.
- [x] src/tui/controllers/call_list.rs:324,342 — [missed-edge-case] clear_non_matching/matching pass `&[]` streams to matches_dialog; stream-criteria rows misclassified and deleted. **Done:** both clear ops gather each dialog's real streams (`streams_for`) under dialog-then-stream locks and pass them to `matches_dialog`, so stream-criteria filters classify correctly.
- [x] src/rtp/stream_store.rs:259 — [correctness] RTCP jitter (RTP timestamp units) overwrites millisecond jitter; feeds MOS 8x off at 8kHz. **Done:** `process_rtcp` now converts the report jitter to ms via `jitter * 1000 / clock_rate` (guarded for clock_rate 0) before storing it.
- [x] src/rtp/stream.rs:270 — [correctness] reordered packet inflates jitter (wrapping_sub as u64 → 4.29e9 spike); cast wrapped diff to i32 for RFC 3550 signed semantics. **Done:** wrapped diff cast `as i32 as f64` so a reordered packet yields a small signed transit delta, not a ~33M-ms jitter spike.
- [x] src/rtp/rtcp.rs:284 — [correctness] 24-bit signed cumulative_lost zero-extended; negative becomes huge positive. **Done:** `cumulative_lost` is now `i32`, sign-extended from the 24-bit field (`(raw24 << 8) as i32 >> 8`); `stream_store` clamps negatives to 0 lost.
- [x] src/capture/hep.rs:959 — [potential-bug] `build_hep_v3_bytes`: total_length `as u16` wraps past 65535 → corrupt header (same in test helper at 1732). **Done:** an oversized payload is truncated to what fits within the u16 length field so the declared total matches the actual size (both per-chunk and total lengths stay valid). Test-only helper at ~1744 left as-is.
- [x] src/capture/pcap_reader.rs:484 — [correctness] `if_tsresol` not reset at new SHB; multi-interface/multi-section pcapng gets wrong resolution/link type (EPB interface_id ignored). **Done (multi-section):** a new SHB resets `if_tsresol`/`link_type` to defaults so a later section's IDB without `if_tsresol` no longer inherits stale resolution. **Done (per-interface):** the pcapng reader now keeps a per-section interface table (one entry per IDB in file order: link type, `if_tsresol`, `if_name`; a new SHB clears it) and each EPB resolves its `interface_id` against it — timestamp decoded with THAT interface's resolution, packet stamped with its link type and (new `PcapPacket.link_type`/`interface` fields) its name, which the WASM path now forwards into `Packet.interface`. An EPB referencing an undeclared `interface_id` is skipped like other bounded malformed blocks (no panic, no default-decode); a runt IDB still occupies its id slot so later interfaces' numbering stays aligned. Round-trip locked against the writer's multi-IDB output (eth0/eth1, differing link types, names + timestamps per packet).
- [x] src/capture/reassembly.rs:520 — [correctness] TCP sequence comparison is non-wrapping; streams crossing 2^32 misclassify in-order segments as retransmits (needs serial arithmetic). *Scope note:* the drain buffer is a raw-`u32`-keyed BTreeMap, so a fully correct cross-wrap fix needs a serial-ordered buffer (or serial-next scan), not just swapping the `<` comparison — larger than a one-liner; deferred until tackled properly. **Done:** RFC 793/1982 serial arithmetic via a private `seq_lt` helper (`(a.wrapping_sub(b) as i32) < 0`; total order within any <2^31 window); the SYN-less downward-adjust in `insert` and retransmit classification in `drain_in_order` now use it. Design: kept the raw-`u32` BTreeMap and instead made `drain_in_order` select by serial position — direct `remove(&expected_seq)` lookup for the in-order segment, a serial-below scan to purge retransmits, never key-iteration order — chosen over relative-offset keys because SYN-less streams have no stable ISN (`expected_seq` can be adjusted downward), so there is no safe anchor for a relative keying scheme; stream eviction is time-based (`last_seen`) so "oldest" needed no change. Covered by wrap-crossing in-order/out-of-order/retransmit scenario tests + `seq_lt` boundary tests.
- [x] src/capture/mod.rs:295 — [correctness] leftover-map eviction victim is arbitrary (`keys().next()`), not oldest; active session's partial can be evicted. **Done:** `tcp_sip_leftover` is now an `IndexMap` where every touch removes-then-reinserts at the tail (map order = update recency) and eviction is `shift_remove_index(0)` — deterministic least-recently-updated victim, matching the crate's existing bounded-map pattern.
- [x] src/capture/mod.rs:210 — [missed-edge-case] reassembled fragmented TCP datagram bypasses TCP reassembler/SIP framer. **Done:** when a completed IP reassembly re-parses as TCP, the segment's seq/flags are recovered from the reassembled TCP header and the datagram is routed through the normal TCP path (`process_tcp`), so it joins its stream at the correct sequence position and spanning SIP messages frame correctly; UDP reassemblies keep the direct path.
- [x] src/capture/writer.rs:348 — [correctness] `--split filesize:N` counts only payload bytes, not record framing; systematic underestimate. **Done:** `bytes_written` now adds the on-disk record framing (16-byte classic-pcap header, or the 32-byte-plus-padded EPB) so rotation fires at the real file size.
- [x] src/capture/writer.rs:335 — [missed-edge-case] every EPB written with interface_id 0; multi-device capture loses per-interface attribution. *Scope note:* the writer emits a single IDB by design, so proper per-interface attribution needs multi-IDB support (one IDB per source interface + mapping `Packet.interface` to an id) — a feature, not a one-liner; deferred. **Done:** `PcapWriter` now keeps an interface table (index = pcapng `interface_id`; entry 0 = the constructor-supplied capture source) and maps each packet's `Packet.interface` to its id, writing a new IDB mid-stream (with `if_name` + the tagging packet's own link type, since devices can differ, e.g. `any` = Linux SLL) the first time an unseen interface appears — pcapng explicitly allows interleaved IDBs, and `pcap-file`'s writer validates EPB ids against them. No `Packet` change was needed: live capture already tags every packet with its device name (one `capture_live` per device in multi-capture), file replay tags `None` (→ id 0, byte-identical single-interface output). `--split` rotation re-emits SHB + IDBs for ALL seen interfaces in id order so every file is self-contained, and the size accounting now counts SHB/IDB header bytes (EPB/IDB sizes come from `write_pcapng_block`'s return; SHB measured via a throwaway `Vec` serialization so the `BufWriter` is never flushed early; classic pcap accounting unchanged). Reader-side per-interface handling remains tracked separately (pcap_reader.rs entry above).
- [x] src/capture/decrypt.rs:846 — [correctness] TLS 1.2 CLIENT_RANDOM derivation accepts first ServerHello that works; concurrent handshakes can mis-bind. **Done:** ClientHello randoms are queued FIFO and each ServerHello is paired with the oldest unanswered one; a keylog CLIENT_RANDOM entry now binds only to the handshake whose ClientHello random matches exactly (fallback to unknown-client_random handshakes for mid-handshake captures). **Done (cross-connection):** `process_record` now takes the TCP 4-tuple as src/dst `SocketAddr`s (caller in batch.rs passes `pp.src_addr`/`pp.dst_addr` + ports); the pending-ClientHello FIFO is per-connection, keyed by the direction-normalized (ordered) endpoint pair, so a ServerHello pops only its own connection's queue and CH1(A),CH2(B),SH2(B),SH1(A) pairs correctly. Map bounded at 4096 connections (IndexMap, oldest-inserted out, matching `names.rs`) with a 32-entry per-connection queue cap.
- [x] src/sip/dialog_store.rs:313 — [correctness] retransmission floods at message cap never advance `updated_at`; dialog can be wrongly compacted as idle. **Done:** the retransmission branch stamps `updated_at` from the arriving message's timestamp (not the stored tail's), so a dropped at-cap retransmission still counts as activity and `compact_idle` sees the dialog as live.
- [x] src/sip/dialog.rs:369 — [missed-edge-case] CANCEL/200-OK race: 2xx after CANCEL leaves state Cancelled though the call was established per RFC 3261. **Done:** a 2xx to INVITE now transitions Cancelled → InCall (the 2xx wins the race per RFC 3261 §9/§15).
- [x] src/sip/dialog.rs (update_register_state) — [missed-edge-case] 401/407 challenge marks REGISTER dialog Failed; challenge-only capture reads as failure rather than auth-pending. **Done:** 401/407 leave the state unchanged (auth pending); only a genuine 4xx-6xx marks Failed, a later 2xx marks Registered.
- [x] src/sip/timing.rs:135 — [edge-case] `answered_at` matches any 200-to-INVITE without CSeq check; re-INVITE 200 can be recorded as answer time. **Done:** `DialogTiming` records the initial INVITE's CSeq; the 100/180/200 INVITE-response milestones are pinned to it (fallback to first-match when the INVITE wasn't captured).
- [x] src/sip/message.rs:117 — [edge-case] `cseq()` keeps trailing garbage in method (`"INVITE extra"`), defeating comparisons in timing.rs; untested. **Done:** `cseq()` returns only the single method token via `split_whitespace`.
- [x] src/sip/message.rs:294 — [adversarial] `extract_uri_user` finds `sip:` anywhere; crafted display name parses from wrong position. **Done:** the user is read from inside the `<...>` name-addr (or the bare addr-spec), never a quoted display name; a non-sip URI (e.g. `tel:`) yields None.
- [x] src/sip/siprec.rs:66 — [adversarial] `split_multipart` splits on `--boundary` anywhere, not line-anchored per RFC 2046. **Done:** the split is a manual scan that only accepts `--boundary` at the start of a line (body start or preceded by `\n`, covering CRLF and the parser's existing bare-LF tolerance); mid-line occurrences inside part content are literal text. Preamble, missing-terminator, and `--boundary--` handling unchanged.
- [x] src/sip/sdp_timeline.rs:184 — [bug-risk] repeated T.38 re-INVITEs re-emit T38Switch every other exchange (suppression checks only previous event). **Done:** `SdpExchange` now records `is_t38` and suppression compares the previous exchange's media *state* (`is_t38 && !prev.is_t38`), matching how hold/resume compare `prev.mode` — one T38Switch per genuine audio→T.38 transition, re-emitted only after a real return to audio.
- [x] src/sip/dsl.rs:1069 — [correctness] `compare_num` absolute-epsilon equality is effectively exact for values ≥2; `duration == 5.0` ~never matches. **Done:** `==`/`!=` use `NUM_EQ_TOLERANCE = 5e-4` — half the finest domain step, since every numeric field is integral (ports, counts) or millisecond-derived (duration/pdd/setup, jitter, MOS/loss to ≥0.1) — absorbing float noise while keeping adjacent domain values (5.001 vs 5.0) distinct.
- [x] src/sip/dsl.rs:965 — [correctness] `src.port`/`dst.port` read `messages.first()`, which drifts after `compact_idle` drains oldest messages. **Done:** `SipDialog` captures `src_port`/`dst_port` at creation (alongside the existing `src_addr`/`dst_addr`; nothing else preserved the initial transport ports) and the DSL reads those, so the fields are stable across compaction instead of silently swapping to a response's reversed ports.
- [x] src/sip/stir_shaken.rs:152 — [silent-loss] only first `dest.tn` kept; multi-destination PASSporTs drop the rest. **Done:** `dest_tn` widened to `Vec<String>` and the previously-unparsed `dest.uri` array (RFC 8225 §5.2.1) is now kept as `dest_uri`; new `dest_display()` joins all destinations for the one log consumer (`app/batch.rs`).
- [x] src/mcp/server.rs:745 — [correctness] tail_dialogs truncates before sorting; next_cursor can permanently skip updates when >limit dialogs changed. **Done:** collects everything past the cursor, sorts by `(updated_at, call_id)` on real DateTimes (also killing a variable-precision RFC 3339 string-compare hazard), *then* truncates; `next_cursor` is a compound `<RFC3339>|<Call-ID>` derived from the last returned row, so tie groups split across pages are neither dropped nor duplicated. Bare-timestamp legacy cursors still work.
- [x] src/output/api.rs:827 — [correctness] `get_stream` matches SSRC alone; collisions return arbitrary stream. **Done:** on an SSRC collision the endpoint now returns the most-active matching stream (`max_by_key(packet_count)`) deterministically, so a colliding orphan can't shadow the real media stream.
- [x] api.rs:949 vs prometheus_server.rs:433 — [correctness] `sipnab_messages_total` divergent semantics between the two servers. **Done:** the REST `/metrics` handler now counts messages (`+= d.messages.len()`) like the standalone server, instead of one per dialog; both agree.
- [x] src/output/mod.rs:36 — [config] prometheus_server gated behind `api` feature though built to avoid it; `--metrics` without api can't work. **Done:** new `metrics = ["native", "dep:base64"]` feature (in `default` + `full`) gates the standalone server and its wiring instead of `api`, so `--metrics` works in the default build (which has no `api`); CI gained a `metrics`-only build to keep the decoupling enforced.
- [x] src/output/synthetic.rs — [correctness] >64KiB payloads: length fields saturate but payload appended; header/size disagree. **Done:** the SIP payload is truncated to `u16::MAX - 28` so the IP/UDP length fields equal the bytes actually written (a single IPv4 datagram can't carry more), instead of a saturated length with a longer body.
- [x] src/output/event_exec.rs:231 — [resource-leak] `try_wait` error drops Child from tracking without kill/wait. **Done:** a `try_wait` error now kills and waits the child before dropping it (via the extracted, testable `reap_action`), so it is reaped instead of leaked as a zombie.
- [x] src/tui/save.rs:783 — [edge-case] SIPp export string-replaces destination port digits; can corrupt unrelated URI parts. **Done:** new `sipp_placeholder_uri` parses the R-URI structurally (userinfo/hostport/params, IPv6 brackets) and substitutes `[remote_ip]`/`[remote_port]` only for the actual host and port components — a user part like `15080` with dst port 5080 survives intact.
- [x] src/tui/call_flow/export.rs:86 — [correctness] RTP-bar rows export as Mermaid self-arrows; want `is_rtp_bar` skip like `is_spacer`. **Done:** the exporter skips `is_rtp_bar` rows exactly like spacers; bars still render in the TUI ladder.
- [x] src/tui/mod.rs:922 — [missed-edge-case] `rtp_codec_segments` returns empty on try_read contention; Mermaid export silently omits RTP segments. **Done:** the sole caller is the (non-frame-critical) Mermaid export, so the `try_read` early-return became a blocking `read()` — dialog→stream lock order preserved; empty now genuinely means "no resolved codec".
- [x] src/tui/render/mod.rs:764 — [bug] scroll clamp ignores wrapping; true bottom unreachable for long header lines. **Done:** the diff view's content height now uses per-pane wrapped-row estimates (same ceil-of-display-width contract as `msg_raw::estimated_rows`), so the clamp reaches the true wrapped bottom.
- [x] src/tui/call_flow/prepare.rs:306 — [correctness] endpoints capped at 6; 7th endpoint messages silently draw between wrong participants. **Done:** the cap was removable — the renderer is generic in participant count and already degrades explicitly ("Terminal too narrow for ladder") when geometry can't fit, so `endpoints.truncate(6)` is gone and every endpoint gets its true column; no snapshot changed.
- [x] src/security/fraud_detect.rs:224 — [off-by-one] wangiri entry gate (>=3) and per-prefix trigger (>=4) disagree by one. **Done:** standardized on 3 — `WANGIRI_THRESHOLD = 3` is documented as the *minimum* short calls to trigger, and the entry gate already used >=3, so the trigger's `>` became `>=`.
- [x] src/rtp/stream_store.rs:513 — [edge-case] `clear()` retains sdp_endpoints; post-clear streams re-link to pre-clear dialogs. **Done:** `clear()` drops `sdp_endpoints` too (field audit: `generation` correctly survives as a monotonic cache-invalidation counter; diagnostics/config fields are not correlation state).
- [x] src/names.rs:70 — [resource-leak] `dns_requested`/`dns_cache` unbounded; long captures accumulate forever (no LRU). **Done:** both are IndexMap/IndexSet bounded at `MAX_DNS_CACHE_ENTRIES = 4096` (matched to `HEP_MAX_TRACKED_PEERS`) with oldest-first `shift_remove_index(0)` eviction; a landed result clears its in-flight marker so `dns_requested` can't starve the cache.
- [x] src/names.rs:120 — [resource-leak] DNS worker channel unbounded; burst of unique IPs queues arbitrarily. **Done:** `sync_channel(DNS_QUEUE_CAPACITY = 1024)` with `try_send`; on Full the request is dropped, the IP un-marked (stays re-requestable), and a debug log records the drop — the capture/render path never blocks.
- [x] src/cli.rs:64 — [edge-case] `PerPeerLimit::Auto.resolve` integer division yields 0 (disabled) when allowlist_len > global; should floor at 1. **Done:** `(global / allowlist_len).max(1)`.
- [x] src/crash.rs:407 — [missed-edge-case] `hook_body` claims nothing may panic, but `eprintln!` panics on closed stderr; use `writeln!(io::stderr()).ok()`. **Done:** all five `eprintln!` sites in the hook path route through `hook_write_line` (`writeln!(...).ok()`), so a closed stderr can no longer abort the process from inside the panic hook.
- [x] src/capture/hep.rs:1566 — [missed-edge-case] `HepSender::new` binds `0.0.0.0:0` (IPv4-only); IPv6 dest fails — bind family should follow destination. **Done:** the destination is resolved first and the bind follows its family (`[::]:0` for IPv6, `0.0.0.0:0` for IPv4).

## P2 — robustness, observability & efficiency

- [x] **TUI copy/paste (user-reported 2026-07-24)** — mouse capture blocks the terminal's native drag-select on every view, and the only clipboard feature (call-flow `E` Mermaid export) shells out to pbcopy/xclip, which fails over SSH. Plan: OSC 52 as primary clipboard mechanism (terminal puts text on the local clipboard; works over SSH) with pbcopy/xclip fallback; `y` copy binding on the message-detail pane; a mouse-capture toggle key so native selection works everywhere; help + docs updated (including the Shift+drag bypass tip). **Done:** new `tui::clipboard` module — OSC 52 written to /dev/tty (72 KiB raw bound, char-boundary truncation, xterm-safe base64 size) with silent pbcopy/xclip belt-and-suspenders and honest status wording; `y` yanks the displayed raw message (detached worker + status line, same pattern as `E`); F12 toggles mouse capture (audited free across views; rebind wins; persistent status reminder while off); help view, keybindings docs and website mirror updated with a Copying-text section.

- [x] src/capture/hep.rs:934 — [edge-case] `build_hep_v3_bytes`: `timestamp.timestamp() as u32` silently truncates post-2106 / wraps pre-1970; no guard. **Done:** clamps the timestamp to the u32 wire range with a one-shot debug log.
- [x] src/capture/hep.rs:381 — [efficiency] `verify_hmac_auth_token` prunes the whole nonce map per accepted packet; amortize (e.g. once/second). **Done:** nonce-map pruning amortized to at most once/second; a regression test proves the pre-lookup timestamp-window check keeps correctness regardless of prune timing.
- [x] src/capture/hep.rs:1162 — [api] global rate limit 0 drops everything while per-peer 0 means disabled — inconsistent knob semantics. **Done:** `0` now means DISABLED for both the global and per-peer knobs (aligned to the documented per-peer convention); `describe_hep_limiters` and docs updated.
- [x] src/capture/hep.rs:~1380 — [behavior] `--count` counts only forwarded packets, not received; may surprise operators. **Done:** `--count` counts RECEIVED packets (the less-surprising reading for a capture tool); CLI help + docs updated to say so.
- [x] src/capture/hep.rs (hep_bind_is_loopback) — [latency] possible blocking DNS lookup in a security decision at startup. **Done:** the loopback check is now purely syntactic (literal-IP parse, no DNS); hostnames are conservatively non-loopback with a startup warning, preserving fail-closed posture.
- [x] src/capture/parse.rs:460 — [missed-edge-case] no IPv6-in-IP (protocol 41) encapsulation support; tunneled IPv6 SIP dropped. **Done:** IPv4 protocol 41 is routed through the existing inner-IP path (depth-bounded), so tunneled IPv6 SIP is decoded.
- [x] src/capture/parse.rs:203 — [known-gap] SCTP DATA fragment reassembly across packets unimplemented (documented follow-up). **Done:** cross-packet SCTP DATA fragment reassembly (RFC 4960 §3.3.1) via a bounded per-(association,SID,SSN) buffer on `PacketProcessor`; B/middle/E fragments accumulate in TSN order and emit the SIP payload on E, fail-closed on gap/overflow. Single-packet B+E path unchanged.
- [x] src/capture/parse.rs:650 — [efficiency] `v6.extensions().clone()` per IPv6 packet on hot path. **Done:** the hot-path IPv6 extension-header clone is skipped for the common empty-chain case (guarded on `exts.is_empty()`, provably behavior-preserving).
- [x] src/capture/parse.rs:163 — [robustness] `ip_protocol_to_transport` silently maps unknown protocols to UDP; mislabels e.g. ESP. **Done:** `ip_protocol_to_transport` returns `Option` and the pre-parsed path rejects unknown protocols with a new `UnsupportedIpProtocol` error instead of mislabeling them UDP (skip chosen over an `Other` variant after a ~45-consumer audit).
- [x] src/capture/channel.rs:140 — [metric-accuracy] backpressure counter can overstate blocking (failed try_send then instant send). **Done:** split into two counters — raw `capacity_hits` (every try_send Full, visible live) and `backpressure_blocks` (only fall-back sends that waited ≥1ms), so the Prometheus metric's meaning is honest instead of overstated.
- [x] src/capture/atomic.rs:53 — [efficiency] closure gets unbuffered File; wrap in BufWriter internally (flush before sync_all). **Done:** the closure writer is wrapped in a `BufWriter`, flushed before `sync_all`; atomic temp+rename and all error paths preserved.
- [x] src/capture/decrypt.rs:856 — [efficiency] clones entire observed-handshake vector per `ensure_sessions_populated` pass to sidestep borrow. **Done:** split-borrow destructuring replaces the per-pass handshake-vector clone with a borrowed lazy iterator; binding tests unchanged.
- [x] src/capture/decrypt.rs:742 — [efficiency] `try_decrypt` clones all session keys per ApplicationData record. **Done:** `try_decrypt` iterates `sessions.iter_mut()` via split borrow instead of cloning all keys per record; `try_decrypt_with_session` is now a free fn on the borrowed session, zeroization ownership preserved.
- [x] src/capture/mod.rs:284 — [efficiency] TCP framing double-copies; `Bytes::from(buf).slice(r)` would be zero-copy. **Done:** TCP framing freezes the stream buffer once via `Bytes::from(buf)` and emits refcounted `.slice()` views — the per-message copy is gone (the held-partial tail keeps its single owned copy).
- [x] src/capture/file.rs:195 — [missed-edge-case] replay mode sleeps full inter-packet delta in one `thread::sleep`; delays shutdown. Sleep in bounded slices. **Done:** replay sleeps in ≤200ms interruptible slices polling the shutdown signal, so a large inter-packet gap no longer delays shutdown.
- [x] src/capture/file.rs:249 — [consistency] `pcap_ts_to_chrono` silently falls back to now() here but counts+warns in live.rs; unify. **Done:** `pcap_ts_to_chrono` delegates to the single hardened `live.rs` converter, so file/replay/parallel/TUI paths all count (`INVALID_PCAP_TIMESTAMPS`) and warn identically instead of silently stamping now().
- [x] src/capture/pcap_reader.rs:225 — [edge-case] seconds `as u32` truncation past 2106 baked into public type. **Done:** the pcapng seconds conversion saturates to `u32::MAX` past 2106 (mirroring the writer's guard) instead of wrapping; documented on the public field.
- [x] src/capture/native.rs:329 — [missed-edge-case] multi-capture: one device open failure doesn't tear down sibling capture threads. **Done:** the multi-capture coordinator (extracted as a testable `run_multi_capture`) signals siblings to stop and surfaces one named error on any device-open/spawn failure, reaping all threads instead of hanging.
- [x] src/sip/dialog_store.rs:426 — [missed-edge-case] `merge` drops losing duplicate's seen_cseq/retransmit counts/timing instead of unioning. **Done:** `merge` unions the losing duplicate's state — seen_cseq set (bounded), summed retransmit counts, earliest-non-None timing milestones, min created_at / max updated_at — instead of discarding it.
- [x] src/sip/dialog_store.rs:511 — [efficiency] `find_correlated_scored` O(dialogs × messages × headers) with per-candidate allocs; hot per TUI frame. **Done:** `find_correlated_scored` uses O(1) HashSet X-Call-ID membership and allocation-free short-circuiting branch overlap; scoring semantics unchanged.
- [x] src/sip/dialog_store.rs — [observability] no-rotate capacity drops are uncounted (idle evictions are counted). **Done:** no-rotate capacity drops now increment a lifetime `capacity_dialogs_dropped` counter with a public getter and merge accumulation, mirroring the idle-eviction plumbing.
- [x] src/sip/dsl.rs:829 — [missed-edge-case] quoted strings have no escape mechanism; delimiter char inexpressible. **Done:** `scan_quoted_string` adds backslash escaping (`\'`/`\"` collapse; backslash always consumes the next char) so the delimiter is expressible; `\\` and regex escapes are preserved verbatim to stay compatible with the TUI's `escape_filter_text` builder (documented).
- [x] src/sip/dsl.rs:956 — [missed-edge-case] `rtp.ssrc`/`rtp.codec` only consider the first stream, asymmetric with worst-across-streams quality fields. **Done:** `rtp.ssrc`/`rtp.codec` match if ANY linked stream matches (`streams.iter().any`), symmetric with the worst-across-streams quality fields; docs updated.
- [x] src/sip/dsl.rs:333 — [efficiency] `matches_dialog` always runs media/asymmetry diagnosis even when no diagnosis field in expression. **Done:** a parse-time `needs_diagnosis` flag (single AST walk) skips media/asymmetry diagnosis when no diagnosis field is referenced; semantics unchanged.
- [x] src/sip/dsl.rs:939 — [efficiency] `payload` field does lossy String conversion per message per evaluation. **Done:** `payload` matches on `&[u8]` via a new `Value::ReBytes`/`compare_bytes` path (regex bytes engine) — no per-message lossy String allocation, and no fabricated U+FFFD matches on non-UTF-8 bodies.
- [x] src/sip/dialog.rs:178 — [efficiency] `final_status_code` collects a Vec per call on the render path. **Done:** `final_status_code` scans once tracking max-non-auth and max-any instead of collecting a Vec; behavior identical.
- [x] src/sip/mod.rs:72 — [edge-case] request detection accepts `ASIP/2.0` (ends_with not delimiter-anchored); same in parser.rs. **Done:** request/response detection anchors on the space-delimited ` SIP/2.0` token in both `mod.rs` and `parser.rs`, so `ASIP/2.0` no longer parses as SIP.
- [x] src/sip/dialog.rs:348 — [edge-case] `update_invite_state` has the same `sub_state.starts_with("terminated")` false-positive fixed in timing.rs:117 (matches `terminatedfoo`); apply the exact-token match. *Found during the 2026-07-24 P2 wave.* **Done:** matches the exact `Subscription-State` value token (`split(';').next().trim() == "terminated"`) per RFC 6665 §8.4, so `terminatedfoo` no longer ends the transfer; pinned by `notify_terminatedfoo_does_not_return_to_incall`.
- [x] src/tui/controllers/file_open.rs:411 — [doc-staleness] comment says the shared converter "clamps an out-of-range tv_usec"; after the file.rs:249 unification it rejects+counts+warns instead. Update the wording. *Found during the 2026-07-24 P2 wave.* **Done:** comment updated: the shared converter rejects+counts+warns on an unrepresentable tv_usec rather than clamping.
- [x] src/sip/parser.rs:279 — [silent-loss] headers beyond MAX_HEADERS_PER_MESSAGE silently dropped without parse_error. **Done:** headers past `MAX_HEADERS_PER_MESSAGE` now set `parse_error` (verified: no downstream reader gates on it) so the truncation is visible.
- [x] src/sip/parser.rs:369 — [edge-case] non-numeric Content-Length silently ignored, no parse_error. **Done:** a non-numeric Content-Length now sets `parse_error` (body bytes retained) instead of being silently treated as absent.
- [x] src/sip/parser.rs:97 — [efficiency] `parse_sip` copies input before any validation. **Done:** an allocation-free `precheck_first_line` runs the hard-error checks on the borrowed slice before `parse_sip` copies, so garbage input errors without allocating.
- [x] src/sip/parser.rs:215 — [edge-case] Request-URI not trimmed; double space yields URI with leading space. **Done:** the Request-URI is trimmed, tolerating sloppy multi-space request lines instead of yielding a leading-space URI.
- [x] src/sip/matcher.rs:170 — [efficiency] payload matching allocates lossy String per message; `regex::bytes` would be copy-free. **Done:** payload matching uses `regex::bytes` on `&msg.raw` directly — copy-free and correct on non-UTF-8 bodies.
- [x] src/sip/matcher.rs:179 — [efficiency] from_user/to_user allocations computed even when full-header match already succeeded. **Done:** `from_user`/`to_user` are computed lazily only when the full-header regex misses, short-circuiting the allocation.
- [x] src/sip/matcher.rs:160 — [inconsistency] `calls_only` matches method case-insensitively while `SipMethod::parse` is case-sensitive. **Done:** `calls_only` matches the method case-SENSITIVELY (RFC 3261 §7.1), aligned with `SipMethod::parse`; the case-insensitive compare was an undocumented one-off.
- [x] src/sip/sdp.rs:127 — [efficiency] `parse_sdp` collects all lines into a Vec up front. **Done:** `parse_sdp` iterates `text.lines()` lazily instead of collecting a Vec; behavior unchanged.
- [x] src/sip/sdp.rs:307 — [edge-case] `parse_rtpmap` accepts payload types 128–255 (doc says 0–127). **Done:** `parse_rtpmap` rejects payload types >127 (RFC 3551 7-bit) per the parser's skip-on-malformed convention.
- [x] src/sip/sdp_timeline.rs:116 — [limitation] delayed-offer INVITEs (offer in 200, answer in ACK) mislabeled by request/response classification. **Done:** delayed-offer INVITEs are classified by position — an ACK is the answer, and a response bearing SDP with no prior offer is the delayed offer; normal flows and T.38 suppression unchanged.
- [x] src/sip/siprec.rs:83 — [limitation] per-part Content-Type requires line-start, no folded MIME headers. **Done:** part headers are unfolded (RFC 5322 SP/HTAB continuations) before the Content-Type scan; the line-anchored splitter is unchanged.
- [x] src/sip/siprec.rs:121 — [gap] participant AOR misses `<nameID aor="...">` attribute form common in RFC 7865 metadata. **Done:** participant AOR reads the RFC 7865 `<nameID aor="...">` attribute form (precedence: attribute > `<aor>` element > nameID content).
- [x] src/sip/timing.rs:117 — [edge-case] `starts_with("terminated")` also matches `terminatedfoo`. **Done:** the transfer-complete check matches the exact `terminated` token (`split(';').next().trim()`), so `terminatedfoo` no longer false-matches.
- [x] src/cli.rs:878 — [bug] HEP/syslog/alert-json flags carry `help_heading = "MCP (Model Context Protocol)"`; wrong `--help` section. **Done:** HEP flags moved to a new `HEP` help heading; `--syslog`/`--alert-json` to `Security` (with the other alert-channel flags).
- [x] src/cli.rs:517,797,1028 — [refactor] `--color`, `--mcp-transport`, `--pcap-export-mode` are free-text Strings validated late; `value_enum` would reject at parse time (`--mcp-transport bogus` without `--mcp` passes silently). **Done:** `--color`/`--mcp-transport`/`--pcap-export-mode` use a clap `PossibleValuesParser` (rejects invalid values at parse time; kept as String for off-limits `.as_str()`/`parse_mode` consumers).
- [x] src/config.rs:860,915 — [missed-edge-case] `write_display_columns_file`/`write_manual_mappings_file` are non-atomic, symlink-following; share names.rs atomic temp+rename helper. **Done:** `write_display_columns_file`/`write_manual_mappings_file` go through a `write_sipnabrc_atomic` helper (temp+rename via `capture::atomic::write_atomic`) — atomic and symlink-replacing, not symlink-following.
- [x] src/crash.rs:137 — [race] `create_report_dir` exists→create_dir_all TOCTOU; only leaf tightened to 0700. **Done:** `create_report_dir` re-lstats and re-classifies the leaf after create, failing closed (`PermissionDenied`) if it became a symlink or foreign-owned — closes the exists→create TOCTOU.
- [x] src/tui/call_flow/export.rs:48 — [robustness] exported HTML loads mermaid.js from CDN; unviewable offline (conflicts with no-external-deps stance). **Done:** the HTML export is self-contained — it embeds the Mermaid source in a copyable `<pre id="src">` block with offline render instructions (mermaid-cli / any Mermaid editor) and an inline Copy button; no CDN. Vendoring the ~3MB mermaid.min.js was rejected as too heavy; tradeoff (no inline auto-render) documented.
- [x] src/tui/call_flow/render.rs:493 — [correctness] badge x-position uses byte len; `Δ` misplaces badge one column left. **Done:** badge x-position uses `UnicodeWidthStr::width`, so a leading `Δ` no longer shifts the badge one column left.
- [x] src/tui/call_flow/prepare.rs:604 — [efficiency] SDP badge pass re-parses `msg.sdp()` per message though main loop already parsed into msg_sdp. **Done:** the SDP badge pass reuses the already-parsed `msg_sdps[ri]` instead of re-calling `msg.sdp()` — one parse per message.
- [x] src/tui/call_flow/prepare.rs:956 — [efficiency] retransmit folding rescans emitted rows per retx — O(n²) on a storm. **Done:** retransmit folding tracks `last_header_idx` (index of the most recent real row) instead of rescanning the emitted prefix per retx — O(n²)→O(n).
- [x] src/tui/call_flow/arrows.rs (truncate) — [edge-case] byte-based truncation; display-width-aware would be correct for CJK. **Done:** truncation and arrow fit/centering are display-width-aware (unicode-width, whole-glyph budget), correct for CJK/emoji.
- [x] src/tui/mod.rs:1264 — [missed-edge-case] event-loop dialog-count try_read under sustained write contention keeps poll in slow idle mode. **Done:** the poll-cadence decision moved into a testable `reconcile_dialog_count`; a contended `try_read` (None) now signals activity and keeps the responsive poll instead of dropping to the 500ms idle cadence.
- [x] src/tui/mod.rs:716 — [efficiency] merged-calls ladder clones every message before sorting; extended branch sorts refs. **Done:** the merged-calls ladder sorts message references and clones once after sorting (matching the extended branch), eliminating the pre-sort per-message clone.
- [x] src/tui/controllers/mod.rs:351 — [efficiency/inconsistency] stream-list wheel path re-filters store per event; keyboard path uses cached keys. **Done:** the stream-list wheel path uses the cached `stream_displayed.keys.len()` like the keyboard path instead of re-filtering the store per event.
- [x] call-list F9 vs call-flow F9 — [inconsistency] one clears search_query, the other leaves it narrowing the list. **Done:** F9 clears both the active filter and the persisted `search_query` in BOTH views (call-flow aligned to call-list per the documented spec); keybindings docs updated in both mirrors.
- [x] src/tui/controllers/call_flow.rs:413 — [efficiency] `flow_visible_msg_count` computes raw_count even when cached value wins. **Done:** `flow_visible_msg_count` returns the cached count early, computing `raw_count` only on a cache miss.
- [x] src/tui/controllers/call_list.rs:307 — [efficiency] `clear_calls` Vec::contains inside retain O(n·m); HashSet. **Done:** `clear_calls` builds a HashSet of the ids to remove once — O(n+m) instead of O(n·m).
- [x] src/tui/controllers/save_dialog.rs:35 — [missed-edge-case] Enter queues PendingSave with empty path; validate at dialog. **Done:** Enter on a blank/whitespace path is rejected with a status message and keeps the dialog open instead of queuing a doomed save.
- [x] src/tui/timeline.rs — [tracking] timeline wheel/navigation are placeholders; don't ship navigation-less. **Done:** resolved as: the CallTimeline is a static single-screen view (one call, always fits, no scroll/selection), so "no navigation" is correct — the placeholder wording was the defect. Misleading language removed, the static contract documented in code + help, and tests pin that wheel/nav keys are inert.
- [x] src/tui/render/popups.rs:648 — [edge-case] `field_width - 2` debug underflow on very narrow terminal. **Done:** `field_width.saturating_sub(2)` — no debug underflow on a sub-2-column field.
- [x] src/tui/render/popups.rs:801 — [edge-case] `(iw - 4)` underflow below ~6 cols. **Done:** `iw.saturating_sub(4)` for the separator — no underflow below ~6 columns.
- [x] src/tui/render/status.rs:48 — [edge-case] byte-offset slicing vs char-count padding misaligns styled span for non-ASCII filenames. **Done:** status line 1 is assembled from discrete width-placed spans with a display-width trailing fill, eliminating byte-offset-into-padded-string slicing and the fragile `find("PAUSED")`; non-ASCII capture-mode labels align.
- [x] src/tui/render/status.rs:96 — [edge-case] `styled_len` counts bytes not display width. **Done:** `line2_used_cols` uses display width (unicode-width) instead of byte length, so wide/multibyte filter/BPF text sizes the trailing fill correctly.
- [x] src/tui/render/mod.rs:123 — [efficiency] per-frame clones of current_view/active_popup. **Done:** the per-frame `current_view`/`active_popup` clones are gone — the match/if-let borrow the fields directly (arms use disjoint `&mut` fields or shared `&App`).
- [x] src/tui/render/mod.rs:750 — [missed-edge-case] positional diff; one inserted header highlights entire tail — LCS diff better. **Done:** the message diff uses an LCS line alignment (`lcs_line_alignment`), so a single inserted header highlights only that line, not the whole tail; both panes emit equal row counts, keeping the shared scroll in step. Snapshot regenerated.
- [x] src/tui/msg_raw.rs:170 — [missed-edge-case] search match lines unwrapped vs wrapped-row scrolling; n/N lands short. **Done:** `search_match_lines` takes the wrap width and returns cumulative wrapped-row offsets (ceil(width/w)), so n/N lands exactly on a match even when earlier lines wrap.
- [x] src/tui/stream_detail.rs:222 — [missed-edge-case] sparklines emit one glyph per interval uncapped; overflow pane width — downsample to last N. **Done:** sparklines render only the last `pane-width` intervals (budget = width − label − suffix); averages still span full history.
- [x] src/tui/call_list.rs:697 — [efficiency] builds all 11 cells per row then clones visible subset per frame. **Done:** only the visible cells are built per row (hidden columns and their formatting work skipped), eliminating the per-row visible-subset clone.
- [x] src/tui/call_list.rs:835 — [edge-case] narrow layout `addr_each` can exceed flex below ~72 cols. **Done:** narrow-layout address columns clamp to `flex/2`, so the two address columns never exceed the flex budget below ~83 cols.
- [x] src/tui/save.rs:414 — [consistency] NDJSON `duration_ms` inline + `message_count` vs JSON `msg_count` field-name mismatch. **Done:** the NDJSON exporter emits the canonical `msg_count` (matching `DialogSummary`, the JSON/MCP/REST/DSL consumers) instead of `message_count`.
- [x] src/tui/save.rs:60 — [edge-case] mid-stream write error leaves partial capture; all exporters silently overwrite. **Done:** all 8 buffer-then-write exporters use `capture::atomic::write_atomic` (temp + fsync + atomic rename), so a mid-write failure leaves the prior good file intact instead of a partial overwrite.
- [x] src/tui/dashboard.rs:264 — [edge-case] scroll window anchors selection to bottom row rather than centering. **Done:** the scroll window centers the selection (clamped to `[0, total-visible]`) instead of bottom-anchoring it, giving context both above and below.
- [x] src/rtp/stream.rs:310 — [efficiency] `quality_intervals.remove(0)` O(n) at cap; VecDeque. **Done:** `quality_intervals` is a `VecDeque`-backed `QualityHistory` wrapper (keeps the pub `.push/.first/.last/.iter` surface) with O(1) `pop_front` eviction instead of `Vec::remove(0)`.
- [x] src/rtp/stream.rs:349 — [edge-case] burst_gap window can exceed 1000-entry lost_sequences log; understates burstiness. **Done:** the burst-gap window is bounded to the range the 1000-entry loss log actually retains (anchored at the newest retained loss), so a long clean tail can't evict losses and silently report zero burstiness.
- [x] src/rtp/stream.rs:62 — [accuracy] SilencePeriod assumes 20ms CN cadence; durations are lower bounds. **Done:** `SilencePeriod` duration derives from observed CN packet spacing (RTP-timestamp delta / clock rate); only the opening/closing frame uses the nominal cadence, documented as a residual lower bound.
- [x] src/rtp/quality.rs:179 — [robustness] three retroactive guards checked independently; silent desync possible. **Done:** the three retroactive gap→burst guards are subtracted under one combined all-or-nothing condition with a `debug_assert!` pinning the invariant, so a partial desync can't corrupt the loss partition.
- [x] src/rtp/srtp.rs:560 — [efficiency] session keys re-derived via two AES-CM PRF runs per packet; cache per key material. **Done:** session keys (cipher/salt/auth) are derived once and cached per candidate key, re-derived only when the master-key fingerprint changes; the cached auth key gates decryption so a fingerprint collision fails the HMAC rather than serving wrong plaintext.
- [x] src/rtp/srtp.rs:977 — [efficiency] clones full key material (zeroizing Drop) per candidate key per packet. **Done:** the per-candidate key-material clone is eliminated via split-field borrows in the decrypt loop; the cached secrets zeroize on drop.
- [x] src/rtp/stream_store.rs:405 — [efficiency] `remember_sdp_endpoint` shift_remove_index(0) per insert at cap — quadratic pattern SNB-0015 fixed elsewhere. **Done:** `remember_sdp_endpoint` uses amortized batch eviction (drain oldest ~cap/10 in one shift) like the SNB-0015 fix, so a unique-endpoint flood is O(1) amortized instead of O(calls²).
- [x] src/rtp/audio_export.rs:124 — [inconsistency] `is_exportable_codec` exact-case opus spellings vs case-insensitive `is_opus_codec`; "OpUs" decodes but is filtered from export. **Done:** `is_exportable_codec` treats Opus case-insensitively (via `is_opus_codec`), matching the decoder, so `OpUs` exports as it decodes; PCMU/PCMA stay exact (what the decoder accepts).
- [x] src/rtp/diagnosis.rs:192 — [edge-case] NAT detection reports last-evaluated sdp_media, not the mismatching one. **Done:** NAT detection breaks at the FIRST mismatching media (labeled loop), so `sdp_media`/`actual_media` report the media that actually mismatched, not the last-evaluated one.
- [x] src/rtp/diagnosis.rs:374 — [accuracy] inferred ptime inflated by packet loss; add loss guard. **Done:** inferred ptime divides by `packet_count + lost_packets - 1`, so packet loss no longer inflates the packetization interval.
- [x] src/rtp/dtmf.rs:81 — [assumption] hardcodes 8 kHz telephone-event clock; 16 kHz reports double duration. **Done:** new `extract_dtmf_with_clock` scales duration by the negotiated telephone-event clock rate (`duration_ts * 1000 / clock_rate`); the old `extract_dtmf` is an 8000 Hz wrapper. Wired to the SDP-negotiated rate in batch.rs.
- [x] src/rtp/playback.rs:32 — [safety] AudioPlayer raw fn pointers + handle; add invariant note/PhantomData for Send/Sync fragility. **Done:** `AudioPlayer` carries a `PhantomData<*const c_void>` pinning `!Send + !Sync` structurally (independent of the handle repr), with a thread-safety invariant doc and `compile_fail` doctests guarding against accidental Send/Sync.
- [x] src/output/prometheus_server.rs:266 — [robustness] Authorization header matching only two casings, exactly one space. **Done:** Authorization handling is case-insensitive on both field name and scheme and tolerates OWS/multiple spaces (RFC 7235); the token comparison stays constant-time and exact.
- [x] src/output/cli_print.rs:130 — [edge-case] negative sub-second deltas render as `+0.500s`. **Done:** the delta sign is derived from the full signed value before formatting the magnitude, so a negative sub-second delta renders `-0.500s` instead of `+0.500s`.
- [x] src/output/dialog_report.rs:220 — [edge-case] truncate_str max_len<=3 char-count can exceed byte contract. **Done:** `truncate_str` with tiny `max_len` walks down to a char boundary within the byte budget and drops the ellipsis when there's no room, so the result never exceeds `max_len` bytes on multibyte input.
- [x] src/output/api.rs (list_*) — [api-design] `total` is unfiltered size while rows are filtered; paging broken. **Done:** `list_dialogs`/`list_streams` materialize the filtered set first and set `total` to the filtered count, so paging by total terminates correctly instead of over-paging the unfiltered size.
- [x] src/output/fail2ban.rs — [consistency] reg-flood src_ip not sanitized (scanner event is). **Done:** the reg-flood event's `src_ip` is run through `sanitize_log_value` like the scanner event, closing a CRLF log-injection path.
- [x] src/output/wireshark.rs — [edge-case] byte-to-char boundary checks misclassify around UTF-8 continuation bytes. **Done:** the DSL→wireshark word-boundary checks decode the actual neighbouring char (not a single UTF-8 byte cast to char), so a field adjacent to a multibyte char isn't wrongly split/substituted.
- [x] src/app/bootstrap.rs:807,869 — [design] build_filter_expr/build_capture_config call process::exit inside PlanError-based plan(); should return PlanError. **Done:** `build_filter_expr`/`build_capture_config` return `Err(PlanError)` instead of `process::exit(2)`, making `plan()` testable/composable (same exit code and messages via the caller).
- [x] src/app/batch.rs:1464 — [missed-edge-case] DTMF hardcodes PT 101 instead of SDP-negotiated payload type. **Done:** DTMF extraction uses the SDP-negotiated telephone-event payload type (and clock rate via `extract_dtmf_with_clock`) from the stream, falling back to 101/8000 without SDP.
- [x] src/app/batch.rs:988 — [missed-edge-case] custom --tshark-filter without -I references placeholder capture.pcap. **Done:** a new `tshark_input_file` helper resolves the tshark input as `-I` then the saved live pcap (`-O`), else a clear error — no more referencing the nonexistent `capture.pcap` placeholder.
- [x] src/mcp/server.rs:668 — [efficiency] search_messages allocates format!+to_lowercase per message per call. **Done:** `search_messages` lowercases the needle once and scans each SIP field in place via `ascii_contains_ci` (short-circuit), eliminating the per-message `format!`+`to_lowercase` allocations.
- [x] src/app/tui_mode.rs:246 — [missed-edge-case] pause still counts/writes packets; --count can stop capture mid-pause with packets never processed. **Done:** paused packets are still written/reassembled but no longer counted toward `--count` (via `count_and_check_limit`), so `--count N` can't stop capture mid-pause with packets unprocessed.
- [x] src/auth.rs:73 — [dead-code+latent-bug] infallible-serialization fallback builds JSON by hand without escaping id. **Done:** the hand-built JSON fallback (unescaped `id`) is removed — serialization of the concrete payload is provably infallible, so `unwrap_or_default` handles the impossible error fail-closed with no hand-interpolation.
- [x] src/process_isolation.rs:432 — [efficiency] PerDstRateLimiter::cleanup O(n) on every send. **Done:** `PerDstRateLimiter` cleanup is gated to at most once/second (`cleanup_if_due`, injected clock) like the HEP nonce-prune; the 60s window in `allow()` still governs limiting so a not-yet-swept bucket never mis-limits.
- [x] process_isolation.rs:204 / parallel.rs:204,336 — [error-handling] `let _ = tx.send` drops dead-worker shard packets silently. **Done:** parallel.rs dead-worker shard sends go through `shard_send`, which returns a lost-packet count accumulated into `ReconResult.dropped_count` and warned — no more silent `let _ = tx.send`. (process_isolation's own dead-worker send was already handled loudly.)
- [x] src/pipeline.rs:57 — [edge-case] is_rtcp_packet requires odd dst port; RFC 5761 mux RTCP on even port never recognized. **Done:** `is_rtcp_packet` recognizes RFC 5761 muxed RTCP on even ports by content (v2, PT 192-223, self-consistent RTCP length) while keeping the classic odd-port path; the length-consistency guard keeps existing even-port non-RTCP tests passing.

## P3 — code health

- [x] **Proofread the active-voice rewrite** — `99e6ab8` rewrote 331 prose
  lines across 28 files to name their actor, and three of them shipped as
  grammatical garbage that Vale, codespell and the full suite all passed:
  `auth.md` "an explicit id, so that it a denylist can name later",
  `walkthroughs.md` "the compiler turns away an MCP tool … by the compiler",
  and a `goes unfound` that was not a word. Each was a substitution that left
  the old subject or agent stranded — a class no gate catches, because the
  result is well-formed English that means nothing. **Done:** all 331 lines
  re-read line by line; the three known breaks were already fixed, and a
  stranded-agent/doubled-word scan over the whole set turned up nothing else
  outstanding. Worth remembering that the only reason this was tractable is
  that the rewrite was one commit — the same edits spread over a month would
  have had no reviewable boundary.

- [x] **`TransportProto::Sctp` doc comment said "stub for future use"** —
  `src/net.rs`. SCTP is implemented: `src/capture/parse.rs` recognizes IP
  protocol 132, walks the chunk list, and extracts SIP from the first complete
  (B+E) DATA chunk, recovering the real src/dst ports from the common header.
  The comment predated that work and understated what the tree supports.
  **Done:** the variant now documents the real behavior.

- [x] src/capture/packet.rs:81 — [api-hygiene] `Packet::new` allows `caplen != data.len()`; debug assert or derive caplen. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/capture/hep.rs:~1408 — [style] mixed `Instant::now()` vs fully-qualified in same fn. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/capture/decrypt.rs:263 — [dead-code] `hmac_sha256` takes unused `_crypto: &dyn CryptoBackend` param. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/capture/decrypt.rs:414 — [robustness] `parse_client_key_exchange_rsa` couples length guard and indexing implicitly; fragile to edits. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/capture/dtls.rs:48 — [minor] `SrtpProfile::key_len`/`salt_len` ignore `self`, always 16/14. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/capture/pcap_reader.rs:299 — [dead-code] `opt_data_end` computed then discarded. **Done:** resolved as a side effect of the per-interface table work — `opt_data_end` now bounds the `if_name` option read, so the `let _ =` suppression is gone.
- [x] src/capture/reassembly.rs:286 — [dead-code] `TcpStream.created` never read. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/dialog_store.rs:617 — [dead-code] `.filter(score >= 50)` can never filter (min emitted score is 50). **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/dsl.rs:685 — [missed-edge-case] quoting-hint keyword exclusion is lowercase-only while parser is case-insensitive; `method == TRUE` gets misleading hint. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/mod.rs:84 — [duplication] `find_crlf` duplicated verbatim in parser.rs. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/matcher.rs:13 — [naming] REGEX_SIZE_LIMIT comment says "ReDoS"; regex crate is linear-time — limit bounds memory/compile cost. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/sdp_timeline.rs:103 — [modeling] REFER transfers reuse Offer + magic `mode: "transfer"`; dedicated variant cleaner. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/stir_shaken.rs:160 — [testability] `parse_identity_header` reads Utc::now() internally; inject clock for deterministic iat tests. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/sip/stir_shaken.rs:278 — [naming] test `malformed_jwt_too_few_parts` actually exercises too many parts. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/cli.rs:1291 — [dead-code] `warn_unimplemented_flags` is an empty no-op still called from main.rs:38. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/config.rs:19 — [efficiency] `known_keys()` rebuilds HashMap per call; LazyLock static. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/config.rs:749 — [efficiency] `parse_toml` parses TOML twice; deserialize Config from parsed Value. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/names.rs:229 — [nit] `remove_manual` bumps generation even when nothing removed. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/crash.rs (write_crash_report) — [nit] write_all failure leaves partial report file behind. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_flow/render.rs:1239 — [dead-code] `format_ladder` `_first_ts` unused. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_flow/render.rs:291 — [dead-code] `render_call_flow_lines` `_call_id` unused. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_flow/render.rs:1503 — [simplification] pointless `let fsty = sty;` alias. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_flow/render.rs — [duplication] Correlated-Legs section + arrow-width math duplicated across builders; header/pipe builders duplicated across format_ladder variants. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_flow/prepare.rs:1184 — [simplification] `first_sdp_codec` round-trips through format+re-split; duplicates payload-type table. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/mod.rs:645 — [duplication] sync_caches CallFlow branch inlines what `rtp_codec_segments` implements. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/mod.rs:2149 — [dead-attribute] redundant nested `#[cfg(test)]`. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/mod.rs:1055 — [organization] NameSetup/TuiOptions defined in mod.rs; siblings live in state.rs. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/theme.rs:37 — [missing-config] `status_bg` is the only theme color users cannot configure. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/help.rs:169 — [fragile-coupling] `help_line_count()` hardcodes +1 for the synthesized version line; no test ties them. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/state.rs:966 — [unclear-naming] `FilterDialogState::is_empty` dead_code-allow rationale undocumented. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/controllers/mod.rs:254 — [fragility] settings popup hardcodes item indexes 0-5 in sync with renderer order. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/controllers/file_open.rs:206 — [missed-edge-case] manual-path mode lacks Delete key handling (filter dialog has it); same in save dialog. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/controllers/name_dialog.rs:174 — [missed-edge-case] second failure overwrites first on status line. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/controllers/name_dialog.rs:34 — [efficiency] de-dupe allocates String per (target × ip). **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/controllers/mod.rs:341 — [duplication] dashboard wheel handler re-implements dashboard.rs row clamp. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/render/mod.rs:206 — [refactor] fold-label duplicates "(+N retx)" format knowledge owned by prepare. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/stream_detail.rs:109 — [naming] MOS label/color band boundaries inconsistent at 3.0–3.5. **Done (P3 code-health wave, 2026-07-24).**
- [x] stream_list.rs:307 / stream_detail.rs:91 — [refactor] loss-% computation duplicated in three places. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_list.rs:637 — [simplification] DeltaPrev and Scaled arms byte-identical; merge. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_list.rs:521 — [duplication] `base_labels` restates COLUMN_LABELS with one divergence. **Done (P3 code-health wave, 2026-07-24).**
- [x] call_list.rs:880 vs save.rs:206 — [duplication] near-identical 12-arm state-display matches ("FAILED" vs "Failed"). **Done (P3 code-health wave, 2026-07-24).**
- [x] src/tui/call_list.rs:659 — [naming] Scaled silently renders as delta-prev in call list; document on the enum. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/rtp/stream.rs:134 — [testability] `is_active` uses Utc::now(); offline replay streams never active. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/rtp/srtp.rs:547 — [dead-code] `decrypt_srtp_payload` unused crypto param. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/rtp/rtcp.rs:1 — [doc/code gap] header claims no silent drops; known-type body parse failures are dropped. **Done (P3 code-health wave, 2026-07-24).**
- [x] audio_export.rs:182 / playback.rs:261 — [duplication] near-identical i16/f32 linear resamplers. **Done (P3 code-health wave, 2026-07-24).**
- [x] api.rs / prometheus_server.rs — [duplication] identical bind-address parsers in two files. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/output/json.rs:8 — [dead-code] redundant `use serde_json;`. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/output/api.rs (serve_on) — [naming] "max connections" semaphore actually caps in-flight requests. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/app/bootstrap.rs:966 — [naming] `mint_token_and_exit` never exits. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/app/bootstrap.rs:970 — [dead-code] duplicated #[cfg] attribute pair. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/app/batch.rs:132 vs 193 — [simplification] ParallelConfig construction duplicated verbatim. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/mcp/shape.rs:29 — [naming] `max_chars` is a byte cap; rename max_bytes. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/app/servers.rs:158 — [clarity] tuple let _ suppression obscures intent. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/mcp/transport.rs:96 — [dead-code] auth_layer extracts ConnectInfo it never uses. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/process_isolation.rs:388 — [naming] "sliding window" doc vs fixed-window implementation. **Done (P3 code-health wave, 2026-07-24).**
- [x] src/wasm.rs:24 — [style] new() without Default (intentional; note). **Done (P3 code-health wave, 2026-07-24).**
- [x] src/crypto.rs:13 — [doc-staleness] CryptoBackend doc mentions wolfSSL/OpenSSL backends that don't exist (removed by decision). **Done (P3 code-health wave, 2026-07-24).**

## P4 — test quality

- [x] **Unlabeled code fences carry a copy button no gate reads** (2026-07-28).
  `shell_fence_is_one_clipboard_payload` reads fences whose info string names a
  shell, but `website/templates/page.html:90` attaches the copy button to every
  `pre`, so an unlabeled fence gets a button no gate reads. **Done:** every
  fence in the scanned corpus now declares its language — 492 fences, 0
  unlabeled.

  **The figure that motivated this item was wrong.** It read "230 unlabeled, 132
  command-looking"; the real number was **28**. The measuring script used
  `^```$ … ^```$`, which matches a *labelled* fence's closing ``` as an
  unlabelled opener — the same fence-parsing bug `tests/docs_drift_test.rs`
  documents when it warns against reusing `fenced_blocks`, made in the script
  written to find it. A proper open/close walk gives 28. Recorded because the
  wrong number reached this file, two commits and a release-cycle decision
  before anything checked it.

  Labelling was not the whole job: a shell fence becomes visible to the gate the
  moment it is labelled, so the pass had to remediate what it exposed in the
  same commit or leave the tree red between two. Output samples, transcripts and
  diagrams are labelled `text` deliberately — labelling them `bash` would put an
  unrunnable block under a gate demanding it be one command, and the next author
  would reach for the sentinel to silence it.

- [x] **Gates that hardcode their subjects cannot see a new one** — surfaced by
  executing the `docs/internals/walkthroughs.md` checklists rather than
  reasoning about them (2026-07-25). Three cases, each proven by making the
  change and watching the gate pass: a deliberately malformed
  `zzz_gate_probe.schema.json` in `tests/schemas/` left `json_schema_test` at
  6 passed / 0 failed, because `all_schemas_compile` iterates four hardcoded
  filenames instead of reading the directory; a new `src/security/` module with
  an uncapped `HashMap<IpAddr, u64>` left `resource_bounds_test` at 3/3 and
  `security_test` at 38/38; and an unregistered `fuzz/fuzz_targets/*.rs` holding
  a hard compile error left `cd fuzz && cargo check` at exit 0 (registering it
  made the same error exit 101). Cheapest real fix is the first: have
  `all_schemas_compile` enumerate `tests/schemas/*.json`, so a schema that is
  added but not wired is parsed and fails. The other two need a discovery
  mechanism or an accepted "convention only" status — they are documented as
  **(unenforced)** in the walkthroughs page either way.
  **Done (schema half):** `all_schemas_compile` now enumerates
  `tests/schemas/*.json` instead of four hardcoded names, with a `seen >= 4`
  anti-vacuity floor. Verified both ways: replanting the malformed
  `zzz_gate_probe.schema.json` now fails with `parse schema …: expected ident
  at line 1 column 15` (previously 6 passed / 0 failed), and removing it
  returns the suite to 6 passed. The detector and fuzz-target cases remain
  convention-only and stay marked **(unenforced)**.

- [x] .githooks/pre-commit test-count check — [flaky] `cargo test --features full` intermittently reports a partial sum (2291/2308 vs true count) when run immediately after another cargo build, aborting the commit; self-heals on retry. Observed 4× on 2026-07-24 (never in 5 isolated back-to-back runs). Suspect a suite aborting under fingerprint invalidation from an interleaved build (wasm-pack/rustup activity correlated twice). Capture the failing suite's output from inside the hook before fixing. **Done:** root cause was step 5 running `cargo test --features full` a SECOND time purely to count — that run could race a concurrent cargo, abort a binary's compile, drop its `test result:` line, and undercount. Step 5 now derives the count from step 2's already-captured `$TEST_OUTPUT`, and step 2 gates on the test exit code so a partial/aborted run fails there ("retry") instead of feeding a truncated sum downstream. Halves per-commit test time. Regression pinned by `scripts/test-pre-commit.sh` (asserts exactly one full-suite invocation + the exit-code gate).

- [x] src/capture/device.rs (test list_devices_returns_vec) — [test-quality] asserts only "does not panic". **Done (P4 test-quality wave, 2026-07-24).**
- [x] src/tui/call_flow/mod.rs (ladder_split_width) — [test-coverage] no test pins `total < DETAIL_FLOOR` geometry. **Done (P4 test-quality wave, 2026-07-24).**
- [x] src/tui/save.rs:1113 — [test-hygiene] `tmp_path` leaks a tempdir per call. **Done (P4 test-quality wave, 2026-07-24).**
- [x] src/rtp/stream_store.rs:909 — [test-quality] dead first computation; `i % 64_000` aliasing. **Done (P4 test-quality wave, 2026-07-24).**
- [x] src/app/batch.rs:1102 — [test-coverage] mcp_stdio_done exit path untested. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_snapshot_test.rs:872,885,1012 — [naming] timestamp-mode tests/snapshots off-by-one vs DeltaPrev default; rename tests + snaps. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:3514 — [weak-assertion] enum tautology test can't fail. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:1951 — [weak-assertion] page-up assert vacuous when after_down==0. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:2206 — [weak-assertion] F9 test passes if F9 did nothing; assert ==3. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:2587 — [test-hygiene] writes /tmp/sipnab_test_save.pcap outside tempdir, never cleaned. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:3267,3293,3325 — [silent-skip] pcap tests pass vacuously when fixtures missing. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tui_state/tui_snapshot — [duplication] fixture builders duplicated across crates; `localhost_*` misnomer (10.0.0.x). **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:4200 — [duplication] 40-line RTP feed block copy-pasted three times. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_state_test.rs:4604 — [drift-risk] body_search tests re-implement production search predicate inline. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/tui_e2e_test.rs:151 — [flaky-pattern] fixed 120ms sleeps; raw screen() reads race render loop. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/docs_drift_test.rs:278 — [coverage-gap] website/content/docs/mcp.md examples unguarded. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/docs_drift_test.rs:14 — [weak-guard] FOREIGN_FLAGS whitelists broad names globally. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/site_journey_test.rs:1290 — [test-hygiene] unconditional eprintln of 30-row screen. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/cli_options_test.rs:392,401,490,498,507,514 — [weak-assertion] accepted-only / proxy assertions for -w, single-line, color, -A, show-empty, payload-limit and the exit-0-only flag group. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/cli_options_test.rs:611 — [coverage-contradiction] call_report_nonexistent_call accepts 0|1 while output_behavior pins 1. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/security_test.rs:467 — [weak-assertion] four H4 cap tests assert nothing (OOM-only failure); add size probes. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/security_test.rs:310 — [weak-assertion] injection path never fired. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/security_test.rs:1098 — [weak-assertion] path-traversal warning not captured. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/security_test.rs:1174 — [weak-assertion] rate-limiter cleanup unverified. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/security_test.rs:1285 — [flaky] process-global env mutation races concurrent tests (serial_test candidate). **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/resource_bounds_test.rs:88 — [copy-paste] drop-new mode should assert exact cap, not rotate-mode range. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/parse_path_test.rs:102 — [weak-assertion] _code_b discarded; post-flush crash still passes. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/mcp_token_rotation_test.rs:364 — [slow] real 7s sleep per run. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/hep_test.rs:222 — [flaky-pattern] 1.5s absence-of-output negative proof. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/api_test.rs:169 — [weak-assertion] limiter can't be exhausted; sequential 200s only. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/integration_test.rs:257 — [environment-dependence] accepts exit 0|1 by capture permissions. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/wasm_exports_test.rs:10 — [silent-skip] silently never runs if wasm build absent. **Done (P4 test-quality wave, 2026-07-24).**
- [x] eight binary-spawn run() helpers — [duplicated-fixture] inconsistent env across cli/config/output/integration test crates; tests/support candidate. **Done:** consolidated into `tests/support/run.rs` with a documented env baseline (cwd=MANIFEST_DIR, NO_COLOR=1, explicit SIPNAB_LOG per caller — fixing cli_help's shell-inherited log); 5 files migrated (pipeline_test's run() was a trait-method false positive). Also gated security_test's counting-allocator block behind `feature=api` (its only consumer) to fix reduced-feature builds.
- [x] spawn_http/post_status/shutdown — [duplicated-fixture] triplicated across mcp token/http tests. **Done (P4 test-quality wave, 2026-07-24).**
- [x] fuzz_corpus_replay.rs:131 / smoke_fuzz_test.rs:20 — [duplicated-fixture] two independent xorshift Rng+mutate impls. **Done (P4 test-quality wave, 2026-07-24).**
- [x] tests/mockup_alignment_test.rs — [heuristic-limit] lifeline reference = most-pipes line; misaligned reference flags everything else. **Done (P4 test-quality wave, 2026-07-24).**

## P5 — features & long-term / exploratory

- [x] **Packet loss map** — visual representation of RTP loss patterns. **Done:** new `StreamLossMap` view (key `L` from Stream Detail / Quality Dashboard) rendering a sequence-space density strip from `RtpStream.lost_sequences` — bursty loss shows as a dark cluster, diffuse as scattered specks — with a summary header (loss %, burst count/pattern from `burst_gap_analysis`) and sequence axis. Pure wraparound-aware `build_loss_map` binning core in `src/rtp/loss_map.rs` (9 unit tests); spec at docs/superpowers/specs/2026-07-24-packet-loss-map-design.md.
- [ ] **OpenSSF Best Practices Badge** — answer sheet prepared and grounded at
  `docs/design/openssf-badge-answers.md`; no criterion is unmet. Blocked on the
  maintainer's own bestpractices.dev session, since registration assigns the
  project ID the README badge URL needs. Two criteria (`report_responses`,
  `vulnerability_report_response`) have no history to cite because no issue or
  vulnerability report has ever been filed — say so rather than claim a number.
- [x] **WASM plugin API** — **Done in 0.5.69:** specced at
  [`wasm-plugin-api.md`](./wasm-plugin-api.md), implemented behind the
  non-default `plugins` feature, with a worked example at
  `crates/sipnab-plugin-example`. D7's three objections were answered
  individually and the supply-chain one measured (+1.56 MB, 15 crates) rather
  than argued. A plugin has no imports at all, so the sandbox is an empty
  import table rather than an allowlist.
- [ ] **Machine-learning anomaly detection over SIP/RTP patterns** —
  **researched and specced 2026-07-30**, see
  [`ml-anomaly-detection.md`](./ml-anomaly-detection.md). Recommendation: do
  not build the obvious version. A scoring model breaks the evidence rule every
  other detection follows, cannot be reproduced from a pcap, has no ground
  truth to train on, and costs more supply chain than D7 rejected Lua over. The
  real gap is *population* questions — "is this hour unlike the last hundred" —
  answered by statistical baselining with named evidence, not by a model.
  Blocked regardless on persistence across runs, which sipnab has none of.
- [ ] Distributed capture cluster management.
- [ ] Interactive pcap annotation and sharing.
- [ ] YANG/NETCONF machine-readable diagnosis export.
- [x] **Metrics-only token scope for the REST API** — **Done.** `s2` tokens
  carry an optional `scope` claim (`full` / `metrics`) alongside `aud`;
  `--token-scope metrics` mints a credential that reaches `GET /metrics` and
  returns `401` everywhere else. `full` is the default and satisfies every
  requirement, and an absent claim means `full`, so no existing token or
  deployment was narrowed — the opposite of `aud`, which fails closed when
  missing, because pre-scope tokens are live in the field. The claim is signed,
  so it cannot be widened by editing the payload. Routes default to requiring
  `full`, which is the restrictive direction: a route added later and wired to
  the plain `guard` admits only full tokens rather than silently accepting a
  scrape-only one. Verified end to end against the real server, not just the
  verifier — a route wired to the wrong guard passes every unit test and still
  hands a scrape job the call content.
- [x] **SIP problem diagnosis** — the signalling-side complement to
  `rtp/diagnosis.rs`. **Done in 0.5.68:** all seven detections ship (final
  failure with cause, auth loop, retransmission storm, ACK-never-received,
  abandoned/cancelled, high PDD, registration failure), rendered on every
  surface from one `SignalingDiagnosis`. The spec's two load-bearing rules
  held: every detection names the messages it is drawn from, and a truncated
  capture reports as unknown rather than as failure.

  Three thresholds are quoted from numbered clauses rather than chosen — PDD
  11.0s from Table 2/E.721, the ACK window 32s from Timer H, the
  no-final-response window 180s from Timer C. Two guards exist only because
  the naive versions fired on healthy traffic: a `BYE` suppresses the
  missing-ACK finding (RFC 3261 §15 means a hangup proves the ACK arrived),
  and Timer C bounds the no-final-response case so calls in flight when the
  capture stopped stay quiet. Verified across 1398 real dialogs in the sample
  captures: 2 findings, both genuine.
- [x] **Developer documentation** — **Done:** `docs/internals/` now carries a
  developer index (reading order, the live-vs-archaeological map of the
  root-level design corpus, and a glossary for D1–D21/D22, WS0–WS8, P0–P5,
  SN-01/02/03), a `subsystem-guide.md` walking one packet from wire to screen
  across all four packet paths, `invariants.md` (ten rules, each naming what
  enforces it), `testing.md` (tiers, `tests/support/` helpers, the gate
  roster), `walkthroughs.md` (ordered checklists for a new TUI view, detector,
  CLI flag, MCP tool, output format and SIP header accessor),
  `build-ci-release.md` (the eleven features and their real implications, the
  eight workflows, what `ci-success` actually requires, hooks, the 1.97.1
  toolchain pins, and the release matrix) and `domain-primer.md` (the SIP/RTP
  model the code assumes). Seventeen `sequenceDiagram`s across the set. Held
  true by `tests/dev_docs_drift_test.rs`: cited paths must exist, `()`-suffixed
  symbols must resolve to a definition, links must be relative, every page must
  be registered in `build-wiki.py`, and the diagram conventions are enforced.
  `build-wiki.py` gained `CODE_LINK_RE` so code links rewrite to blob URLs
  instead of reaching the flat wiki dead. ../docs/architecture.md and CONTRIBUTING.md
  delegate into the set rather than duplicating it. Note the **SIP problem
  diagnosis** item above is a separate P5 and is untouched by this work.
- [ ] **Confirm visually that the wiki renders the developer-doc mermaid
  diagrams** — mostly answered after the 2026-07-25 merge. `wiki-sync.yml` ran
  green; cloning `sipnab.wiki.git` shows all 10 `Internals-*` pages published,
  4 ```` ```mermaid ```` fences intact in `Internals-Subsystem-Guide.md`, and no
  unrewritten `](../` links anywhere. Fetching the published page shows GitHub
  emitting its **"Loading" placeholder** for each fence, which is the state
  GitHub uses for blocks it has *recognized as mermaid* and queued for
  client-side rendering — an unrecognized fence would render as a static code
  block with no placeholder. What is still unconfirmed is only the final
  painted output, which needs a JavaScript-capable browser (none available on
  this host). Open one page in a real browser to close this out. Low risk
  either way: every diagram has a prose line above it carrying the same point,
  so the pages degrade to correct rather than to broken.
- [x] **glibc floor: installer runtime value** — **Already done; this entry was
  stale.** `website/static/install.sh` and `website/config.toml` both carry
  `2.36`, matching the floor `release.yml` enforces, and
  `published_glibc_floor_matches_release_gate` in `site_journey_test.rs` now
  compares the published value against the release gate so they cannot drift
  again. The entry survived describing a 2.39 that no longer existed, which is
  worth noting on its own: a backlog is a document, and documents drift the same
  way the gates in this repository did. Re-read the code before trusting one.

## Shipped (audit-period features, kept for context)

- [x] **SCTP transport parsing** — **Done:** `parse_packet` now decodes the SCTP
  common header and iterates chunks, extracting the SIP payload from the first
  complete (B+E) DATA chunk (type 0) and recovering the real src/dst ports;
  fails closed to an empty payload on any truncation/malformed length. Single
  unfragmented DATA chunk per packet; multi-packet fragment reassembly (B/E
  spanning) is a documented follow-up. Enables SIGTRAN/Diameter (3GPP IMS).
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

## Closed: the ThreadSanitizer "race" was the uninstrumented allocator

*Diagnosed 2026-07-29. Not a defect in sipnab.* The reported race was
**mimalloc**, which `src/main.rs` installs as the global allocator. mimalloc is
C compiled by the `cc` crate, and `-Zsanitizer=thread` instruments Rust only, so
TSan sees neither its alloc/free (no shadow reset when a block is recycled) nor
its internal cross-thread synchronisation (no happens-before edges). Every block
the allocator hands from one thread to another therefore reads as a data race.

The bisect: the same binary, same fixture, same TSan options, differing only in
the allocator.

| Allocator | Runs | Races | Process |
|-----------|------|-------|---------|
| mimalloc | 5 | 5 | aborted by `halt_on_error` (exit 66) |
| system | 9 | 0 | healthy; served the API for the full 60 s |

Locally the report surfaced with `_mi_memset` → `__rust_alloc` on **both**
sides, which named the cause outright. The CI report did not: its stacks were
`read`/`Vec::append_elements_unreserved` with no allocator frame at all, because
the recorded shadow was the *user's* write to a block mimalloc later recycled.
That is why a name-based TSan suppression was never an option — there is no
allocator frame to match. `src/main.rs` now drops mimalloc under
`--cfg sipnab_tsan`, set by the job; the shipped binary is unchanged.

Four further defects fell out of this, all fixed:

- **Every fatal startup path after the capture thread spawned abandoned it.**
  Once the allocator noise was gone, one real finding was left underneath it: a
  thread leak. `bootstrap::launch` spawns the capture thread *before* the
  readiness hand-shake, the chroot and the privilege drop, and all nineteen
  fatal exits from there on called `std::process::exit`, which joins nothing —
  so the process died with a capture thread still holding an open source.
  `BatchRunner::new` had four more of the same, and could not fix them locally
  because it does not own the handle; it now returns `PlanError` and `run`
  cleans up. `sipnab -I /nonexistent.pcap` — a mistyped filename — was enough to
  produce a leak. All twenty-three paths now go through
  `capture::stop_and_join`, verified by mutation: removing it brings the leaks
  straight back. `thread leak` is now in the job's fatal set rather than
  tolerated, and `cli_flag_behavior_test` (one of the five suites the job runs)
  exercises both shapes so a regression fails there.
- **`tests/support/server.rs` named a timeout it never waited out.** When the
  spawned server died, stderr closed, and the `Disconnected` arm broke out of
  the wait loop to a panic that reported the whole budget — "did not report a
  listening address within 180s" for a suite that finished in 55s. All nine
  failures were one abort, not nine slow starts, and the message sent the first
  round of this investigation after runner speed.
- **The gate could not see child processes.** The suites spawn `sipnab` and
  consume its stderr, so a report from a child reached the log only if some test
  printed that stderr into an assertion message. The first run's "0 races" meant
  "nothing was printed", not "nothing was found". `log_path` now gives every
  process its own file and the verdict reads all of them.
- **The verdict announced a finding type it had not matched.** It failed on any
  `WARNING: ThreadSanitizer` and called it "a data race", which would have
  labelled the thread leak above a race. It now names what it matched, and a
  missing `__tsan_init` fails the job rather than passing as a clean run.
- **The verdict was green exactly when the tree was dirty.** Written inline in
  the workflow, its warning loop was a bare `grep … | sort -u | while read`, and
  `run:` blocks execute under `bash -e -o pipefail`: with no findings, `grep`
  exits 1, `pipefail` promotes it, and `-e` killed the step before it printed
  anything. So the job **failed silently on a clean tree and passed while a
  thread leak was present** — it went green on `e14a549` for that reason. Its
  instrumentation guard had the mirror-image bug: `grep -q` exits on the match
  while `nm` is still writing, `nm` dies of SIGPIPE (141), `pipefail` promotes
  that, and an instrumented binary is reported as uninstrumented — deterministic
  on a 284,000-symbol binary, invisible on a small one. Both now live in
  `ops/tsan/verdict.sh` with `ops/tsan/test-verdict.sh` beside it and a CI job
  running it on every push, because inline YAML cannot be run against a fixture.
  The `nm` stub there emits ~100k symbols with the match first: a compiled
  fixture could not reproduce the SIGPIPE case at all, since the linker placed
  `__tsan_init` last in every ordering tried.

All five suites now run clean under ThreadSanitizer: 58 tests, zero races, zero
leaked threads, no TSan log file written by any process.

The original report, kept because it is the shape this class of false positive
takes — on `api_test`, inside the `sipnab` binary itself (one process, not the
test harness):

```
WARNING: ThreadSanitizer: data race
  Write of size 8 at 0x...098 by main thread:
    #0 read
    #1 <std::sys::fd::unix::FileDesc>::read_buf
    #2 <std::sys::fs::unix::File>::read_buf
  Previous write of size 4 at 0x...09c by thread T1:
    #0 __tsan_memcpy
    #1 core::ptr::copy_nonoverlapping::<u8>
    #2 <alloc::vec::Vec<u8>>::append_elements_unreserved
  Thread T1 created by:
    #2 std::thread::...spawn_unchecked::<sipnab::capture::native::start_capture::{closure#1}, ...>
```

The two writes overlap: an 8-byte write at `…098` covers `098`–`09f`, and the
4-byte write at `…09c` covers `09c`–`09f`. Both are in the same process and one
is on the capture thread spawned in
[`start_capture`](../../src/capture/native.rs) — all true, and all consistent
with the allocator handing the same block to both. The objects themselves were
the tell: a `Vec<u8>` local to `read_pcapng_metadata` and `tracing-subscriber`'s
**thread-local** format buffer cannot alias, so the only way they share an
address is reuse.

Two structural facts made the reuse visible rather than harmless. The capture
thread is not joined until [`batch.rs` `run_loop`](../../src/app/batch.rs),
which runs *after* `BatchRunner::new` reads the pcapng metadata, so no
happens-before edge covers the thread's exit; and TSan reset no shadow on the
free, because the free was mimalloc's.

`SIPNAB_TEST_TIMEOUT_SCALE` survives this — instrumented builds really are
several times slower — but see `tests/support/timeout.rs` for the corrected
reason it was introduced.

## Standing decisions

| Decision | Status | Notes |
|----------|--------|-------|
| Release tarball names carry the Rust target triple | KEPT | `x86_64-unknown-linux-gnu`, not a friendlier alias. The `unknown` is the triple's *vendor* field — the canonical value for "no specific vendor", which is why the macOS artifacts say `apple` in the same slot — and it reads as a failure to people who have not met it. Renaming was considered and rejected: the name is derived from the build matrix, matches `rustc -vV`, is what `SHA256SUMS.txt` and the provenance attestation cover, and is what `install.sh` constructs. A friendly alias would be a second, hand-maintained name for the same file — the drift class this repo has spent a lot of effort removing. The gap was that nothing *explained* it, so `ops/release/platform-table.sh` now renders a decode table into the release body. |
| wolfSSL/OpenSSL TLS backends | REMOVED | ring covers ~95% of cases; re-add only if FIPS demand arises. |
| gRPC API | REMOVED | REST API is complete; re-add only if streaming demand arises. |
| STIR/SHAKEN cert verification | DEFERRED | Would require HTTP cert fetching — added attack surface, intentionally skipped. |
| WASM plugins | FUTURE | D7 rules out Lua; WASM is the path if plugins are ever needed. |
