# Changelog

All notable changes to sipnab will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

sipnab is pre-1.0: the public API and the CLI surface are not stable, and a
breaking change may land in any release. Breaking changes are called out in the
entry that carries them.

## [Unreleased]

### Added

- **`GET /v1/report` — the whole-capture analysis over REST.** Findings across
  every dialog and stream, orphaned media, STUN and ICMP evidence, and what the
  retention caps shed. `GET /v1/dialogs/{call_id}/report` answers for one call;
  this answers for the capture, and it is the only REST route that can, because
  orphaned media and shed retention belong to no single dialog. The CLI has had
  it as `--report` since before either server existed and MCP as
  `get_capture_report`; a REST client wanting it had to reimplement the analysis
  it came to sipnab for.

- **`GET /v1/stats` says which capture its counts came from.**
  `capture_identity` pairs the capture's instance with both store generations,
  and `source` / `capture_name` / `uptime_sec` / `source_exhausted` /
  `writing_to` / `unsaved` describe what the server is attached to — the same
  fields, under the same names, that MCP `capture_status` has had. It is the
  same identity from the same object, not a copy: `CaptureState` moved out of
  the MCP module so one instance serves both doors, because the identity
  rotates when `open_capture` swaps the file and two copies would disagree from
  that moment on. `get_stats` also now holds the capture, dialog and stream
  locks across the read, in the order `CaptureState` documents; it released the
  dialog guard before taking the stream guard, which was survivable until one
  etag claimed the counts belong to each other.

- **Several rtpengine instances behind one proxy, documented and pinned.** Run
  one sipnab per host and a call's media lands on exactly one relay. Finding it
  is a routed lookup rather than a broadcast: the proxy's own SDP names the
  relay, because the `c=` address it negotiated IS the rtpengine it steered the
  call to. Ask the proxy which relay has the call, then ask that one and no
  others. A relay that never carried it answers 404 rather than an empty
  success, because "I do not have this call" and "this call had no media" are
  different findings. `tests/multi_node_relay_fanout_test.rs` pins all three
  properties. sipnab still aggregates nothing across nodes, which is a limit
  `docs/design/positioning.md` sets rather than one nobody got to.

### Fixed

- **`get_capture_report` returned TEXT under its `json` default.**
  `print_analysis_report_as` looks like it has a JSON arm and does not — its
  `format` argument only chooses between markdown headings and plain text — so
  the tool asked for JSON, got prose, failed to parse the prose, and fell
  through to a text block. Because `json` is the default, every agent that
  called this tool without an argument received a text blob with nothing to say
  the structure it asked for was never there. Both doors now serialize the
  analysis directly, and the silent fallback is gone: a serialization failure
  there is a bug, and swallowing it is what hid this one.

## [0.5.124] - 2026-08-24

### Added

- **sipnab can ask an rtpengine relay which calls it is carrying
  (`--rtpengine-control <ADDR>`).** A passive decoder sees the `offer` that
  created a stream, or it sees nothing: a call already in progress when sipnab
  started has no control exchange left to read, and its media arrives as an
  orphan. Incident response usually begins mid-call, which is exactly when that
  gap is worst. sipnab now closes it by asking, at two moments and no others --
  once at startup, before the capture opens, and again when a stream turns up
  that nothing explains. Confirmed against rtpengine 12.5.1.

  **Read-only in the type system, not by convention.** Only `list` and `query`
  are representable in the type that reaches the relay, so `offer`, `answer`,
  `delete` and `start recording` cannot be sent from this path at all. Adding
  one would mean adding a method, which a diff shows.

  **Not a poller.** There is no timer and no interval flag. Three bounds hold
  it, none of which grow with how much traffic the capture carries: sipnab asks
  about each relay-side socket at most once for the run, a per-run ceiling caps
  the total transactions, and the queue handing sockets to the reconciler is
  bounded. When any of them bites, sipnab counts it and says so -- a stream it
  never asked about is not a stream the relay disowned, and the answer names
  which of the two it has.

  **Refused on `-I <file>`.** The calls in a capture ended in the past, so a
  live relay's answer would describe whatever is up today: other people's
  traffic, arriving with the authority of a direct answer and correlated
  against a capture it has nothing to do with.

  **The asking runs on its own thread.** The ask is a UDP round trip with a
  two-second ceiling, and making it from the packet path would stall capture
  for as long as the relay stayed quiet -- dropped packets traded for an
  attribution.

  Endpoints the relay names carry their own provenance. sipnab asked for them
  rather than capturing them, so there is no capture source to record and a
  binding made from one withholds the cross-source claim instead of inventing
  one.

### Changed

- **The published binary-size claim is 13 MB, and it is measured.** The claim
  said "Under 12 MB" and the x86_64 musl release binary had grown past it, which
  failed the release build's own size gate. Rather than relax the claim, the
  duplication that caused the growth was removed: `slice::sort_by` is generic
  over the COMPARATOR, so each of seventeen call sites emitted its own complete
  copy of the stable sort. Routing them through one `&mut dyn FnMut` collapses
  that to one copy per element type and returned 75,648 bytes of `.text`. No
  feature or capability was dropped.

  The ceiling that replaced it was then derived from the artifact rather than
  chosen: the binary this release publishes is 12,527,432 bytes (11.94 MB),
  rounded up to the next megabyte. One value in `website/config.toml` feeds the
  home page tile, the feature table, `docs/install.md` and `docs/build.md`, and
  a test fails if any of them disagrees with the number the release gate
  enforces.

### Fixed

- **`--kill-ua` detected nothing on its own, and said nothing about it.** The
  flag promised "Detect specific User-Agent strings associated with scanners"
  with no condition attached, and `batch::run` reads the pattern INSIDE
  `if kill_scanner_active` -- so given alone it fed a detector nobody built.
  Measured on the shipped binary: `--kill-ua sipnab-test` over a capture
  carrying `User-Agent: sipnab-test/1.0` produced zero alerts, and adding
  `--kill-scanner` produced `detection=ua_pattern` on the same capture. The
  symptom was silence, which is what a network with no scanners on it looks
  like.

  sipnab now refuses the combination and names the remedy. It does NOT arm the
  detector for the operator: arming scanner detection also arms the path that
  TRANSMITS SIP responses on a live run, so a flag whose help says "detect"
  would have started sending packets at third parties. The refusal lives in
  `bootstrap`, not in clap's `requires`, because `[security] kill_scanner =
  true` arms the same detector and clap sees only the command line -- a
  `requires` would refuse a run that works. A test pins that case.

  The test that should have caught this ran `--kill-ua` alone and asserted all
  seven messages survived, which passes whether or not the flag does anything.
  It is now two tests: one that the refusal names `--kill-scanner`, one that
  the pattern reaches the detector and matches.

- **sipnab counted the relay commands it could not attribute and never said
  so.** `note_media_creating_command` has tallied `subscribe`, `publish` and
  `start recording` since the `ng` decoder landed, and the counter's own doc
  comment calls a run that sees one and stays silent "the failure this project
  already named once -- a forensics tool that cannot say what it did not
  attribute". No surface ever read the tally, so that is what every run did,
  while two documentation pages said sipnab "counts them and says so instead".
  The dialog report now carries the count, beside the calls a media relay
  named, because both answer the same question: what did the relay do that
  this report does not show as an ordinary call leg. A test renders a real
  report and fails if the line stops appearing -- the formatting helper alone
  would have stayed green through exactly the deletion that caused this.

- **The home page's engineering-notes count said three where the template caps
  at three.** 0.5.123 recorded that "the home page carries the three most recent
  engineering notes"; the template takes `slice(end=3)`, which is a CAP, and the
  section holds two -- so the page carries two, correctly, and the sentence
  describing it did not. Both the entry's wording and the template comment now
  state the cap, which stays true whether the section holds two notes or ten.
  The generated list never went stale, which is what that change was for; the
  prose counting it did.

## [0.5.123] - 2026-08-22

### Added

- **MCP gains the two answers only `--report` and the REST API could give.**
  `get_capture_report` returns the capture-level report -- findings across every
  dialog and stream, STUN, and ICMP evidence quoting SIP or media -- which
  `get_dialog_report` and `render_ladder` could only ever answer for one
  Call-ID. `rtp_stats` gains an `orphaned` filter: `capture_status` reported
  `orphaned_stream_count` as a bare number, and an agent told "three orphaned
  streams exist" had no way to list them. The filter is applied before the MOS
  bounds and independently of them, because an orphan usually has no dialog to
  ground its clock and folding it into the bounded arm would have dropped most
  orphans from the query that asked for exactly them.

- **The MCP server exposes resources, so a remote agent can fetch an export.**
  `export_capture` returns a server-LOCAL absolute path. Over stdio that is
  fine; over the HTTP transport the client is elsewhere and has no filesystem,
  so the tool reported success and the agent still could not obtain the bytes.
  There was no download path at all. A resource is read-only by construction,
  so a host can grant resource reads WITHOUT granting tool calls -- a
  distinction no tool annotation can express.

- **Field projection on the four tools that return dialog pages.** `fields` on
  `list_dialogs`, `find_problems`, `tail_dialogs` and `search_by_time`. Rows
  were bounded three ways and columns were not bounded at all, so an agent that
  wanted `call_id` and `state` for 200 dialogs still paid for `timing`,
  `frame`, `updated_at` and two display names on every one of them. `call_id`
  survives every projection, listed or not, because every follow-up tool takes
  a Call-ID and a row an agent cannot address is a row it can do nothing with.
  An unknown name is refused, naming the typo and the fields the row carries.

- **`aggregate_dialogs`, so counting happens in the store rather than in the
  model's head.** The only aggregate on this surface was `total_matched` for
  one filter, so a response-code histogram or a top-destinations-by-failure
  question meant either N filtered queries with the buckets guessed in advance,
  or paging every row and tallying it. Counting is the operation a language
  model gets wrong most reliably. The buckets plus `other_count` always equal
  `total_matched`, and a null becomes the literal `(none)` rather than
  vanishing.

- **`response_code` and `response_class` in the filter DSL.** The DSL had 30
  fields and none of them was the response code, so `state == 'Failed'` was the
  only way to ask about a failure -- and it collapses 403, 404, 408, 486, 503
  and 603 into one word, though those have different owners. `response_code` is
  numeric, so classes work directly. `response_class` takes either the number
  or the IANA registry's own name, so `5xx` and `server failure` are one query,
  and `failure` names all three failure classes. Matching is membership rather
  than string equality, which is what keeps `!=` honest.

- **`list_captures` reports `first_packet`.** It returned `{filename, bytes}`,
  so the only way to learn anything about a second file was `open_capture` --
  documented "Destructive. Replaces every dialog and stream", voiding every
  cursor the agent holds. Asking "which of these rotated files could hold this
  call" cost the capture the agent was already working on. `first_packet` costs
  one open and one record read, and it is what narrows forty rotated files to
  the two worth opening.

- **The library page now carries three worked examples.** `examples/` had two
  programs, both reporting on the host rather than on a capture, so the library
  path -- the published crate's actual API -- had none. `call_summary` runs
  file to frame to message to call; `rtp_quality` reports per-stream jitter,
  loss and MOS, including a stream `StreamStore` declines to score because no
  `a=rtpmap` grounded its clock rate; `filter_dialogs` compiles one
  `FilterExpr` and applies it through `select_dialogs`, the join across both
  stores that `--report` and `--json-dialogs` also pass through. Each shows
  something a doctest structurally cannot, because each needs state accumulated
  across a whole capture.

### Fixed

- **The batch applier dropped SDP provenance, and a comment asserted it did
  not.** Three of the four packet appliers pass `SdpProvenance::observed(..)`;
  the batch applier called `link_to_dialog_with_sdp`, which hardcodes
  `unknown()`. Nothing errored, which is why it survived: with `unknown()`,
  `sdp_endpoint_expired` returns false for every endpoint, so F3 stale-offer
  aging was inert on the `-N -I file` path -- the most-used offline path there
  is. An offer stale enough to belong to a PREVIOUS call on the same socket
  could still claim a stream, and cross-source binding could not report that it
  had crossed sources.

- **The late-decrypt hold never reported what it discarded.** `late_evicted`
  and `late_still_held` were computed, carried through `TlsDecryptReport`, and
  read by nobody; only `late_recovered` reached a log line. Without the
  eviction count, "we never had the keys for those records" and "we had them
  and had already thrown the ciphertext away" produce identical output, and
  only one of those is fixed by starting the key source earlier. The reason it
  never fired was structural: `tls_decrypt_guidance` returned early on any run
  that decrypted anything, and an eviction only happens on a capture that was
  otherwise working.

- **`docs/library.md`'s only `PcapReader` example had never compiled.** It used
  `?` inside what rustdoc wraps as a `()`-returning `main`, which is E0277 --
  so a reader's first paste failed, while the suite stayed green because no
  target ever read the page. Every Rust block on that page is now a doctest,
  via a `#[cfg(doctest)]` module that includes the file, so the page is
  compiled by a suite that already ran. The snippet itself is now the whole
  bridge from a pcap record to a decoded frame, which is the one step between a
  path and a parsed frame that a reader cannot guess.

- **The codespell path list had drifted between its three copies.**
  `.githooks/pre-push` omitted `bench` while `.github/workflows/quality.yml`
  and `scripts/preflight.sh` carried it, so a misspelling in `bench/` passed
  the hook that exists to catch it and turned main red instead -- under a
  comment reading "CI invokes codespell over this exact path list; keep them
  identical". All three now agree, and all three gained `examples`: Vale skips
  `.rs` and codespell was never pointed at that tree, so the prose in
  `examples/*.rs` was ungated.

### Changed

- **The tree spells in US English, and a gate now holds it there.** 0.5.105
  made 2,904 replacements across 274 files and shipped with no gate; by 0.5.122
  the tree had drifted back to 166. A repository that spells one word two ways
  teaches a reader that neither spelling is meant, and a grep for either finds
  half the matches.

- The MCP deployment page no longer carries the four estate scenarios that are
  not "get MCP running" -- several SIP servers feeding one capture host over
  HEP, reaching sipnab from outside the network, one agent holding many capture
  hosts, and following one call across an estate. They are their own page now.

- The home page carries the three most recent engineering notes, pulled from
  the section itself rather than hand-listed, so the list cannot go stale.

## [0.5.122] - 2026-08-21

### Fixed

- **Offline reconstruction was 27% slower than this project measured, for ten
  releases.** `is_merged` — the probe that decides whether a capture is a
  merged pcapng — read the ENTIRE file into memory with `std::fs::read` and
  then rejected it on the first four bytes. Three call sites run it before a
  single packet is read, so every offline run over an ordinary pcap loaded the
  whole capture, threw it away, and only then started work. The doc comment
  directly above it promised the opposite: "Cheap: reads interface description
  blocks only ... costs one short read."

  Measured on the 128 MB fixed-state corpus at four cores: 3.29M packets per
  second on 0.5.117, 2.40M from 0.5.118 onward, 3.26M with this fix. Resident
  memory 97 -> 143 -> 97 MiB. Every release from 0.5.108 to 0.5.117 measures
  ~3.26M; 0.5.118 is the first that does not.

  The magic is now checked against four bytes before anything else is read. A
  pcapng still reads in full, because interface blocks may sit anywhere in the
  section and a bounded guess that fell short would mis-detect one.

- **The benchmark gate could not see it.** `bench/regression-gate.sh` exists to
  catch exactly this and passed on every release from 0.5.118 to 0.5.121,
  because `bench/baseline.json` still recorded 0.5.104's 2.28M. 0.5.108 lifted
  the real figure to 3.30M by mapping the capture file; `docs/benchmarks.md`
  was updated that day and the baseline was not. A drop to 2.40M is 105% of a
  four-release-old baseline, so a 20% gate had silently become a 31% one — the
  failure that file's own comment warns about in writing. The baseline is now
  3.25M, the lowest of three replicates, giving a 2.60M floor that the
  regression trips.

### Added

- **The write-verb table in `docs/mcp-protocol.md` was missing its two
  highest-privilege entries.** The security section said "All 32 ...
  Twenty-seven are `readOnlyHint: true` ... These five are not" while the
  server registered 35 tools with 7 write verbs, and the table omitted
  `start_tls_capture` and `stop_tls_capture` — the two that attach uprobes to a
  process that is not sipnab. An auditor reading it got a list of write verbs
  without the two carrying the largest blast radius. A gate now derives the
  totals and the table's membership from `src/mcp/server.rs`.

- Documentation for the late-keylog recovery that shipped in 0.5.120 and was
  never written down, including the bounds on what it holds (4 MiB, 16 records
  per direction, 5 s), and for 0.5.121's mirror-vs-wire disagreement report,
  which existed only in a design note.

## [0.5.121] - 2026-08-21

### Added

- **When two capture sources disagree, sipnab now says so.** 0.5.120 let a live
  interface and a HEP listener run in one process, and sold it as redundancy:
  the mirror as a robust path when key extraction is fragile. Dan Jenkins
  ([@danjenkins](https://github.com/danjenkins)) reframed it after using it,
  and his framing is the better one — HEP reports what the proxy *believes* it
  did, the wire reports what actually left the box. When the question is "is
  the proxy misbehaving, or did I configure it to", a mirror produced by the
  suspect cannot answer it: it is the same witness twice.

  So the two sources are complementary rather than redundant, and their
  DISAGREEMENT is the finding. A composite run now reports, per call: messages
  seen by both, mirror-only, wire-only, and present on both but with differing
  SDP — the last carrying both accounts of the media endpoint side by side. A
  mirrored message the wire never carried is a proxy that believes it sent
  something it did not. A message on the wire the mirror never reported is
  tracing that is lying to its operator.

  The trap here is that the mirror usually arrives FIRST, because the proxy
  mirrors as it processes while the wire copy takes a network hop — so any
  rule shaped "first one wins" silently makes the proxy's account
  authoritative, which is the one thing the wire capture exists to check.
  Three things prevent it: copies are paired by transaction identity
  (RFC 3261 §17.1.3/§17.2.3), never by arrival position; both accounts are
  reported by name, with no expected/actual pair a surface could render as
  truth-and-deviation; and the two gap lists come from one closure applied
  twice with its arguments swapped, so a rule favouring either witness would
  have to be written where it is visible.

  A single-source run reports nothing new and allocates nothing.

- **Every frame from a live or HEP source now carries a resolvable ordinal.**
  Both readers stamped a source name without one, so `first_frame` was absent
  for everything except a file. Ordinals are per SOURCE, not per reader: a HEP
  listener is a fan-in, so each sending node gets its own sequence rather than
  a listener-wide counter full of holes.

  Under `PACKET_FANOUT` — `--cores N` on a live device — several sockets share
  one device, so a per-socket counter would mint `eth0#0` from each of them:
  different frames under one name, which is worse than no pointer at all. The
  source name now carries the socket index (`eth0[2]`), which removes the
  collision without a shared counter on the very path fanout exists to relieve.

  `input_origin` reaches the dialog and the stream, a stream records when its
  dialog arrived over a *different* source, and SDP endpoints expire after
  300 s — grounded on RFC 3261 §16.8 Timer C, measured on the capture clock so
  a replay behaves like the live run.

### Fixed

- **Every download the release makes is now pinned, bounded and retried.** Four
  builds failed on a fetch in a single session and none on the code: the Ubuntu
  archives hung fifteen minutes and cancelled the CI gate; Trivy's DB mirror
  stalled and failed Docker after the image had already passed its smoke test;
  and the 0.5.120 release died on netmap headers from `raw.githubusercontent.com`.
  That last one published **nothing** — the release and the Homebrew bump were
  skipped, so a public tag existed with no artefacts behind it.

  These inputs are fixed and versioned, so they are now fetched under a timeout
  with retries and verified against a recorded sha256 — checksums confirmed
  against a second independent source before being written down. Previously the
  netmap headers were pulled from a mutable host with no integrity check at all.

  A failed fetch is also no longer indistinguishable from a failed build. The
  cross image was one long `&&` chain, so Docker quoted the `apt-get` at its
  head when a `wget` forty lines later failed — naming a command that had in
  fact succeeded. It is now one step per stage, and a fetch failure says so.

## [0.5.120] - 2026-08-21

### Fixed

- **A SIP message split across two TLS records lost everything after the
  first, so an INVITE arrived with no SDP offer.** TLS delivers a byte stream,
  not messages, and a sender is free to write one SIP message as several
  records — a real trunk writes the INVITE headers in one and the SDP body in
  the next. sipnab tested each decrypted record with "does this look like SIP"
  and emitted the ones that did, which keeps the headers and discards the
  body.

  The cost is out of all proportion to a missing body. The INVITE carries the
  ORIGINAL SDP offer, so without it the first SDP sipnab stores is whatever
  the next hop rewrote — and the run then reports a media/NAT mismatch that is
  not in the capture. Reported by Dan Jenkins
  ([@danjenkins](https://github.com/danjenkins)), who found it exactly that
  way: sipnab kept telling him he had a NAT problem on a trunk that did not.
  Framing now happens after decryption, on the stream, as it already did for
  cleartext SIP over TCP.

- **TLS 1.3 handshake plaintext was handed to the SIP layer.** Every protected
  record in TLS 1.3 carries outer content type 23, so a `NewSessionTicket` is
  indistinguishable from a SIP message until it is opened; only the inner type
  separates them (RFC 8446 §5.2). Returning that plaintext looked harmless
  while each record was judged alone — it does not parse as SIP — and stopped
  being harmless the moment records became a stream: ticket bytes prepend
  themselves to the next real message and frame it as garbage. Measured on a
  generated TLS 1.3 call, two tickets ahead of the responses cost the
  `100 Trying` outright.

- **Records that arrived before their keys are now recovered rather than
  dropped.** eCapture and similar `SSLKEYLOGFILE` writers emit a session's
  traffic secrets only after the handshake completes, so the first application
  record — the INVITE — is on the wire before any keylog line exists for it.
  Measured in the field at 56 ms. Polling faster cannot close that: the keys
  are written after the record they protect, so the only fix is to keep the
  ciphertext and try it again. Undecryptable ApplicationData is now held per
  TCP direction, bounded in bytes, and replayed when the keylog grows, keeping
  the timestamp and endpoints of the packet it arrived in.

  A replay tries the sequence it already has and never advances the lock-on
  floor. That rule is Dan Jenkins's, and it is what makes the feature safe: in
  TLS 1.3 the hold fills with handshake-epoch records sealed under a secret no
  application key can open, and reading each failed open as "the sequence must
  be later" walks the floor past the INVITE at sequence 0 — burying the record
  the feature exists to recover. The same rule now applies once the handshake
  has been seen, because then there is no question where the stream starts.

  The hold is skipped entirely when no further keys can arrive, which is the
  ordinary `-I capture.pcap --keylog keys.log` run, and retired by age so
  ciphertext that will never open is not re-swept for the rest of the run.
  Recovered, evicted and still-held counts are reported.

  On the reproduction capture Dan supplied, sipnab previously decrypted **0 of
  17 application-data records in 32.9 seconds**. It now reads the whole call —
  all 8 messages, INVITE carrying its SDP offer — in 0.55 seconds.

### Added

- **The harness can make an encrypted call.** `harness/opensips-tls` builds
  OpenSIPS 4.0.1 with `tls_mgm`, `proto_tls` and `tls_openssl` and binds
  `tls:5061`; the stock harness image excludes those modules, so until now the
  project could not make a TLS call against its own OpenSIPS and every TLS
  defect had to be chased with someone else's production capture.
  `harness/tls/make-tls-call.py` generates a real TLS 1.3 call on loopback
  with the INVITE deliberately split across two records and a keylog written
  by the client itself, so the keys are correct by construction and the run is
  not also testing an extraction tool.

## [0.5.119] - 2026-08-21

### Added

- **A live interface and a HEP listener can now run in one process.** Until
  now `plan()` resolved the capture source as a single if/else chain — File >
  Live > Uprobe > Hep > None — so one run got exactly one source, and an
  operator had to choose between signaling that always works and having any
  media at all. Taking HEP cost RTP entirely: a stream is only ever created
  from real RTP packets, and RTCP arriving over HEP has nothing to attach to
  without them.

  Raised by Dan Jenkins ([@danjenkins](https://github.com/danjenkins))
  alongside #245, from real deployment experience — when eCapture keylog
  extraction proves fragile against a given daemon, OpenSIPS's own HEP mirror
  is a far more robust way to obtain decrypted SIP, because it is already
  plaintext at the source and involves no key extraction at all. Now HEP
  supplies the signaling and the NIC supplies the RTP for the same calls:

  ```bash
  sipnab -N -d eth0 -L 0.0.0.0:9060 --hep-allow 192.0.2.0/24
  ```

  The correlation this needed turned out to already exist, which reverses the
  original framing of the problem. The dialog-to-stream binding keys on the SDP
  media endpoint and never reads the capture source, so a HEP-delivered dialog
  already claims a locally-captured stream. What this release adds is tests
  pinning that across sources rather than a new mechanism.

  Two things only running it could find: a composite with no BPF filter
  captures **no media**, because the generated filter is signaling-only —
  self-defeating for two sources, and it doubled every dialog's message ladder;
  and `is_live` did not recognise a composite, so the interface would have
  opened with no filter at all. Both are now handled, the first with a warning
  that names the fix.

  Refused, deliberately and with the reason stated: `-I` with `-L` (a file run
  must not open a listening socket), `--multi-device` with `-L`, and writing a
  capture file from a composite.

  This is stage 1. Per-source frame ordinals, `input_origin` on dialogs and
  streams, a weaker-tie flag for cross-source bindings, and multi-node keying
  remain open and are tracked rather than implied.

### Changed

- **A multi-file `-I` set is now read by one thread per file.** `--cores`
  stopped paying past four because a single thread read the whole set: open a
  file, read and copy and host-pair-peek every packet of it, then the next,
  while N workers waited. Since `-I` routinely names a directory or a glob of
  rotated captures, there are N files to read and no reason one thread should
  read them all.

  Measured over eight rotated members of 535,000 packets, two builds of the
  same tree alternated run by run, median of nine, on an idle host:

  | `--cores` | before | after | after pkts/s | change |
  |---|---|---|---|---|
  | 1 | 2.815s | 2.822s | 1,516,403 | -0.3% (control) |
  | 2 | 1.794s | 1.821s | 2,350,470 | **-1.5%** |
  | 4 | 1.168s | 1.215s | 3,521,261 | **-4.0%** |
  | 8 | 1.146s | 0.909s | 4,707,963 | +20.7% |
  | 12 | 1.228s | 0.957s | 4,471,376 | +22.1% |

  Peak throughput moves from 3.66M packets/s at four cores to 4.71M at eight,
  a 28% higher ceiling.

  **The two- and four-core rows are a real regression, and they are the trade
  rather than an oversight.** Where the workers are the bottleneck the
  read-ahead buys nothing and still costs a second reader competing for memory
  bandwidth, one more channel hop, and 48 MiB of buffered packets moving
  through the caches the workers are using. `--cores 1` is the control — it
  does not use this path in either build — and its 0.3% is the noise floor the
  rest sit against. Peak RSS rises with the runway: 168 to 286 MiB at two
  cores, 205 to 293 MiB at eight.

  **Ordering is preserved exactly, and that is what shapes the design.** The
  readers cannot send to the workers directly: a worker must see its shard in
  capture order, because `RtpStream::update` derives loss and jitter from
  consecutive sequence numbers and arrival gaps. A reader that let file 3
  overtake file 1 would not merely reorder output — it would report loss that
  is not in the capture. So each reader fills its own queue and a dispatcher
  releases them file by file, and every worker's inbox is packet-for-packet
  the sequence the serial reader gave it. Verified against a private corpus:
  serial and parallel `--report` output compare identical across 71 files.

  A single-file `-I` is unchanged, and that is not a limitation to lift later:
  a pcap record's length is known only from the record before it, so a lone
  file cannot be cut into pieces without first walking it. `--count` also
  keeps the serial reader, because "the first N packets of the set" is defined
  in read order.

### Fixed

- **The corpus gate could not tell "read it, found nothing" from "never opened
  it".** Every corpus suite walked its capture directory the same way: take
  each file, try to open it, `continue` on the error. A file the reader refused
  contributed nothing to the totals and said nothing on the way out, so the
  binary reported `ok` having measured one capture fewer than the operator
  believed. That is how a merged pcapng sat unread while all fourteen corpus
  binaries passed — the condition 0.5.118's reader fixed for exactly one class
  of unreadable file, leaving the silence in place for the next one.

  The sweep now counts every capture it could not read, prints the count
  **whether or not it is zero**, and fails when it rises. A count rather than a
  per-file warning, because a warning inside a passing run is not read — that
  is the same defect at a lower volume. An empty sweep is also a failure: a
  directory with no captures would otherwise satisfy "nothing was unread"
  perfectly, which is the shape of passing over nothing.

  It checks both read paths — the suites' own and the product's merged-pcapng
  routing — because gating only the former would leave it blind to the very
  file that prompted it.

## [0.5.118] - 2026-08-20

### Fixed

- **No published binary carried the eBPF uprobe backend it advertised.**
  `--uprobe-tls` has two backends and they are not equivalent: the default
  `tracefs` one sees no socket, so its dialogs name a process rather than a
  peer, while the `bpf` one pairs each write with its `tcp_sendmsg` and
  recovers the real addresses. `bpf` was not in the `full` feature set and
  every release built `full`, so the capable backend existed and shipped to
  nobody. It now ships on the four `*-linux-gnu` targets — the headless
  servers the `.deb` and `.rpm` serve, which is where a uprobe is reached for.

  Not on musl, and that is measured rather than assumed. The published 0.5.117
  musl binary is 12,252,424 bytes against the 12 MB ceiling the release
  enforces, leaving 330,488 bytes; the backend adds 589,952, which would land
  it 259,464 over. A gate now runs the workflow's own feature step for every
  matrix entry and fails if musl or macOS is ever given it.

- **The build script's strictness depended on which prerequisite was missing.**
  A missing `bpf-linker` warned and embedded an empty kernel object; a missing
  nightly toolchain panicked. Nobody chose that split, and the lenient half is
  the dangerous one for a release: it produces a binary that advertises `bpf`
  and refuses at runtime. There is now one rule with two modes — every
  prerequisite degrades by default, for contributors, and
  `SIPNAB_BPF_REQUIRED=1`, which the release sets, makes every one of them a
  hard error.

- **`sipnab --version` omitted `bpf` and `plugins`.** An operator told at
  runtime that "this binary does not carry it" had no way to check which build
  they held. Both are now reported.

- **The third-party notices and the SBOM described a different binary from the
  one shipped.** Both are generated with `--features full` while the release
  now builds `full,bpf`, so they would have omitted `aya`, `aya-obj`, `object`
  and `assert_matches` — and the drift gate compares against the same
  generator, so it would have stayed GREEN while the artefact carried four
  unlisted dependencies. The feature set is named once and both read it, and
  the gate derives the union from the workflow rather than trusting three
  copies to agree.

- **The Homebrew formula generator met real input for the first time on a
  release tag.** Its 21 assertions ran against a fixture; the real
  `SHA256SUMS.txt` was only ever seen at publish time, so a failure that
  depends on what the last release actually published — a new artifact name, a
  platform that did not build, a change in asset count — surfaced with the tag
  already cut. CI now fetches the previous release's real sums file and runs
  the real generator on it, and never skips: a failed or unshaped download is a
  failure, not a pass. The fixture was widened to the real 17-line shape and is
  itself proved against that check, so the two cannot drift apart.

- **A merged pcapng could not be read at all.** libpcap refuses a file whose
  interfaces disagree, and it refuses on two independent grounds. Measured
  against [The Ultimate PCAP](https://weberblog.net/the-ultimate-pcap/) by
  Johannes Weber ([@webernetz](https://github.com/webernetz)), a real capture
  carrying 313 interface description blocks — it is what surfaced this, and it
  is published precisely so tools can be held to it: first the
  snapshot lengths — the file declares six distinct ones — and then, once every
  one of those is rewritten to a single value, the link types, because it
  carries four encapsulations at once. Per-packet encapsulation is the *point*
  of a merged capture, so no rewrite makes libpcap read one. Anything produced
  by `mergecap`, or captured across interfaces that differ, was unreadable.

  sipnab now decodes such a file itself, taking each frame's link type from the
  interface that recorded it. That turned out to cost very little, because the
  parser never had the restriction: `Packet::from_bytes` has always taken
  `link_type` per packet, and only the readers collapsed it to one value for a
  whole file by asking libpcap once at open. On the capture above the run goes
  from refusing outright to reading 51,328 packets, finding 21 SIP messages and
  101 RTP streams — and reporting the 33.7% of frames it could not decode,
  broken down by link type and EtherType, rather than implying it read
  everything.

  Chosen up front rather than by catching libpcap's complaint, because libpcap
  does not complain at open: it accepts the file, reads the first interface's
  description, and fails on the first PACKET naming a different one. An
  open-time fallback never fires. Matching the text of the read error would be
  worse — it is libpcap's wording, it differs between the snaplen and link-type
  cases, and it differs between versions. A single-interface file, which is
  almost every file, costs one short read of the interface blocks and takes the
  ordinary streaming path untouched.

  Blocks naming an interface the file never described are counted and reported,
  not dropped in silence: a frame discarded without a word is indistinguishable
  from a capture that never held it.

## [0.5.117] - 2026-08-20

### Security

### Fixed

- **A TLS 1.3 KeyUpdate ended decryption for the rest of the connection.**
  RFC 8446 §5.3 is explicit: "The 64-bit sequence number is reset to zero at
  each key change". A rekey therefore changes two things at once — the peer
  seals under a new application traffic secret, and its record counter restarts
  — and sipnab followed neither. Every later record from that direction was
  sealed under a secret it did not hold at a number it was not expecting, which
  looks exactly like a session whose keys were simply wrong: no error, nothing
  decrypts, and the operator is told the keys loaded fine. On a long-lived
  carrier trunk a rekey is not an edge case; OpenSSL performs one on its own
  once a connection passes its AES-GCM record limit.

  sipnab now recognises the post-handshake message — inner content type 22
  carrying handshake type 24, inside an ordinary application_data record — and
  derives the next secret the way the RFC specifies,
  `HKDF-Expand-Label(secret, "traffic upd", "", Hash.length)` (§4.6.3), rather
  than needing it extracted again. The record counter for that direction
  returns to zero with it.

  Only the SENDER's direction rotates. A KeyUpdate carrying `update_requested`
  obliges the peer to send its own, which arrives as its own record and is
  followed when it does; inferring the peer's rotation from this message would
  rotate a direction that has not actually changed.

  This is also the answer to a trunk older than any practical search window:
  the counter returns to zero at the rekey, so a connection that has been up
  for months becomes readable at its next key change without restarting it.

  The negative control matters as much as the fix. Rotating on anything but a
  real KeyUpdate discards a working secret mid-connection and causes the very
  failure this prevents, so a decoy is tested: application data whose first
  byte is 0x18 must decrypt as data and must not ratchet. That control was
  written weaker first — with ordinary SIP text, which never starts with 0x18 —
  and passed while the type check was removed. Both cases are now
  mutation-verified.

- **Key material could be written to swap, where it outlives the process.**
  `disable_core_dumps` is fatal on failure, and its reasoning is exact: "a
  later crash writes those keys to a file on disk that any local user with read
  access can recover". Swap writes them to disk with no crash required. Nothing
  locked those pages, so TLS master secrets, derived record keys and SRTP keys
  were ordinary pageable memory — and `zeroize` on drop cannot help, because it
  clears the RAM copy, not a page the kernel already wrote to the swap device.
  That copy survives the process and is readable by anyone who can read the
  device or a later forensic image: a weaker attacker than the one
  `PR_SET_DUMPABLE` defends against, who needs root and live ptrace.

  sipnab now calls `mlockall(MCL_CURRENT | MCL_FUTURE)` when key material is
  loaded, on the same trigger as the core-dump hardening. `MCL_FUTURE` matters
  as much as `MCL_CURRENT`, because the secrets are read from the key log after
  that point.

  Unlike core dumps this is **not** fatal on failure. `RLIMIT_MEMLOCK` is
  commonly 64 KiB on stock systems and an operator often cannot change it;
  refusing to capture would trade a control the deployment may not need for the
  availability it certainly does. The outcome is reported either way — locked,
  or not locked and why, naming `ulimit -l` and `LimitMEMLOCK=` — because
  claiming hardening that did not happen is the failure the core-dump path was
  rewritten to remove. The test asserts the kernel's own `VmLck` rather than
  the return value, and is mutation-verified: a version that reports success
  while pinning nothing fails it.

## [0.5.116] - 2026-08-20

### Fixed

- **Two behaviours shipped in 0.5.115 without tests now have them, both
  sides.** The warning that reports a traffic secret logged twice with
  different values had none at all, and `--tls-lockon-window 0` was documented
  as refused — because obeying it would blind every mid-stream capture, and
  silently, since a record that opens under no key looks exactly like a record
  that is not SIP — but nothing proved the guard existed. Each is pinned with a
  negative control (an ordinary key log must stay quiet; a real ceiling must
  genuinely bound a search) and each was mutation-tested: disabling the branch
  it guards turns it red.

- **A trunk older than the lock-on ceiling could never be read, however much
  traffic arrived.** 0.5.115 raised the ceiling to a million records and made
  the search widen as records fail, which reaches a trunk up for about a day.
  It did not help one up for months: the search restarted from zero on every
  record, so the ceiling bounded not just what a single record could cost but
  what the connection could ever reach. At ten records a second a trunk is past
  a million within a day and past a hundred million within a year.

  The search now carries a floor. Failing over `[floor, floor + window)` proves
  the record's number is at least `floor + window`, and a direction's records
  only count upward, so the next record starts there rather than at zero.
  Coverage accumulates across records while the cost of any single record stays
  capped, which makes the ceiling a cost limit rather than a reachability
  limit — a hundred records reach a hundred windows. Records the capture missed
  only make the bound more conservative, never wrong, so the floor can lag the
  true number but cannot pass it.

  The floor is keyed by wire direction, `(src, dst)`, and not by client/server
  role. Role is unknown until something decrypts — which is exactly the case
  this serves — so every record is tried under both keys, and a role-keyed
  floor let a failure in one role advance the other's counter, blinding a
  direction that never saw the record. Keyed by address pair the inference
  holds: both guesses failing for one direction proves that direction's own
  number is past the span, whichever role turns out to be right. For the same
  reason the floor is read once per record and advanced once after every guess
  has failed; advancing between guesses would try one key over one span and the
  other key over the next, which proves nothing about either.

  The same rule applies to the window and to the attempt counter that widens
  it, and it took a third bug to see the shape: incrementing per direction gave
  the two key guesses different spans, so a client record at 138 was covered
  only by the wider search the SERVER key was doing. The correct key never got
  the wide range, the record was missed, and the floor then ran far past the
  answer — measured at 2,796,190 while the record sat at 137. Anything the
  search depends on is now fixed for the whole record before the first guess:
  floor, window, and attempt count. Found by a test that runs the operator's
  actual flow — a key log read from disk, then a record from a connection whose
  handshake predates the capture — which is the regression gate for the
  originally reported failure and is what the unit tests could not see.

## [0.5.115] - 2026-08-20

### Fixed

- **A TLS 1.3 trunk held open for hours could not be decrypted without
  restarting it.** The per-record nonce comes from a counter both endpoints
  keep privately, and no TLS version puts it on the wire, so sipnab searches
  forward for it. That search was bounded at 4096 records — which sounds
  generous and is about seven minutes of a trunk ticking over at ten records a
  second. Found in the field within hours of 0.5.114: on one host a
  fresh-per-call carrier decrypted immediately while a carrier that holds its
  TLS connection open stayed unreadable until OpenSIPS itself was restarted.
  The difference was never the carrier; it was how far into the record stream
  the capture began. Restarting a live carrier trunk is not a debugging step an
  operator can take, which is what made this worth fixing rather than
  documenting.

  The ceiling is now 1,048,576 records — roughly a day at that rate — and the
  search **widens as records fail to open** rather than spending the ceiling on
  the first packet. That distinction matters both ways round: a wide search is
  free when the answer is near, because it stops at the first candidate that
  authenticates, so a connection captured from its handshake still costs one
  trial; and it costs its full width only when there is no match at all, which
  is a session whose keys belong to some other connection at least as often as
  it is a trunk joined late. Escalating keeps the first case instant, reaches
  the second within a handful of records a busy trunk passes in moments, and
  never stalls a live capture on one packet. The run-wide trial budget moved
  with it, to four full windows: at parity the first unopenable record spends
  the entire allowance and a session that would have locked on gets nothing.

- **`--tls-lockon-window` sets that ceiling**, in records, because the right
  value is a property of the deployment rather than of sipnab — how far into an
  established connection a capture may start and still be readable. Raise it
  for a trunk held open for days; lower it where a key log carries secrets for
  many unrelated connections and the search is wasted effort.

### Changed

- **The homepage advertised an eBPF capability no published binary carries.**
  It said "The eBPF backend additionally reports the real peer addresses"
  without saying that the backend needs the `bpf` feature, which is not in
  `full` — and every release builds `full`. So a reader could install a release,
  reach for the capability the front page promised, and find only the default
  backend, which names the process rather than the peer because it sees no
  socket. The page now says which backend a released binary has and what the
  other one needs. Whether `bpf` should ship is a separate question, tracked as
  UPR1: it builds for every target and is inert on macOS, but adds 576 KiB,
  which the x86_64 musl artifact does not have under the published 12 MB
  ceiling. `docs/internals/build-ci-release.md` said "`full` is everything
  except `wasm`" and had been wrong since `bpf` was added; it now names both
  exclusions and why a stock build refuses `--uprobe-backend bpf` rather than
  downgrading to the backend that cannot report addresses.

- **The "no key material" diagnostic names the TLS libraries this host maps
  instead of explaining how to find them.** It told the operator to derive a
  `--libssl` path from `/proc/<pid>/maps` themselves, while sipnab already
  enumerates exactly that for `--uprobe-list`. It now lists every mapped
  library — never picking one, since choosing for the operator is the guess the
  message exists to remove — ends in a command that can be pasted, and points
  at `--uprobe-tls`, which needs no external extractor at all. A host where
  discovery finds nothing keeps the wording that promises no paths.

- **A traffic secret logged twice with different values is now reported.** One
  key log can carry two generations of the same `CLIENT_TRAFFIC_SECRET_0` when
  it was reloaded across an extractor restart, and TLS 1.3 `KeyUpdate` rotates
  that secret in place, so the later value cannot open records from before the
  rotation. Which one is right is not decidable from the log, so sipnab says so
  rather than choosing in silence — the remedy is a connection restarted while
  capturing, which produces an unambiguous log.

## [0.5.114] - 2026-08-20

### Fixed

- **A live SIP-over-TLS 1.3 trunk decrypted almost nothing, for five separate
  reasons.** Found against real carrier traffic, each verified independently —
  bugs four and five with a reference AES-GCM decrypt in Python against the real
  captured key material, to rule out a red herring. Diagnosed and patched by
  Dan Jenkins ([@danjenkins](https://github.com/danjenkins)), who supplied all
  five fixes with regression tests (#245).

  - **`--keylog-watch` read new keys only once every five seconds.**
    `poll_keylog_file()` ran inside the reassembly sweep, so a call that
    completed faster than the sweep — an INVITE and its ACK — was over before
    the key that would have decrypted it was read. The poll now runs on its own
    ~100ms wall clock, independent of packet timestamps, which do not advance on
    a quiet link: the packet that matters is an INVITE after silence, and the key
    has to be loaded before it arrives.

  - **A TLS record split across TCP segments was dropped silently.** Records run
    to ~18KB and routinely span segments — most visibly a large INVITE whose SDP
    body lands separately from its headers. `parse_tls_records` stops at a
    truncated record by design, but `try_tls_decrypt` fed it one segment at a
    time and never reassembled, so the record, and the SIP message inside it,
    vanished. A `TlsRecordReassembler` now holds the undecoded tail per stream
    direction, mirroring the `tcp_sip_leftover` pattern already used for SIP
    framing.

  - **The reassembler was then unreachable.** Every chunk was gated on
    `tls::is_tls()` before reaching it, and the tail half of a split record is
    bare ciphertext with no record header, so it fails that heuristic nearly
    always. `is_tls` now decides only whether to *start* tracking a stream;
    `has_held()` admits a continuation regardless of how it looks alone.

  - **Any second TLS handshake wiped every session already derived.** Both the
    ServerHello handler and the keylog poll called `sessions.clear()`
    unconditionally. That is right for TLS 1.2, whose CLIENT_RANDOM/ServerHello
    pairing stays ambiguous until a ServerHello resolves it, and never right for
    TLS 1.3, which derives from `CLIENT_TRAFFIC_SECRET_0` keyed on
    `client_random` alone. On a trunk carrying a keepalive or a second
    concurrent call, a ready session was destroyed before its own traffic
    arrived. Both sites now retain everything that is not TLS 1.2. The failure
    looked exactly like a missing key: no error anywhere, `try_decrypt` simply
    stopped finding a session it had already keyed.

  - **The wrong secret was chosen when a `client_random` had more than one.**
    eCapture's hooks fire on every `SSL_write`, not once per handshake, so the
    same `client_random` can be logged a dozen times and an early firing can
    record a premature secret under the same label. Session derivation took the
    first match; it now takes the latest.

- **TLS 1.3 decryption never recovered from a missed record.** The per-record
  nonce comes from a counter each endpoint keeps privately (RFC 8446 §5.3), and
  nothing on the wire carries it. TLS 1.2 already searched a small window for
  it; TLS 1.3 tried one value and gave up, so a single dropped or unreassembled
  record froze the counter and killed decryption for the rest of the connection
  — and a capture attached to a connection already running never decrypted at
  all. Measured on a real session whose records opened at client sequence 8 and
  server sequence 10 while sipnab tried only zero. Both directions now search
  forward, wide enough to lock on to a stream joined part-way through and narrow
  once decrypting. The AEAD tag makes the search safe: a wrong sequence number
  cannot forge a passing tag.

- **A capture full of unreadable TLS reported the same thing as a capture with
  no SIP in it.** Supplying `--keylog` and getting `No SIP traffic found` was
  consistent with an empty capture and with a capture full of SIP sipnab could
  not open, and the run rendered both identically. It now reports how many
  application-data records it saw against how many it opened, and says which of
  three situations it is in — no key material, keys but no matching session, or
  sessions that decrypt nothing — naming the remedy for each.

- **The `.rpm` refused to install on any Fedora or RHEL host.** `dnf` rejected
  it with `nothing provides libpcap.so.0.8()(64bit)`, on machines that already
  had libpcap. Debian patched libpcap's SONAME to `libpcap.so.0.8` in the 0.x
  days and never bumped it; upstream, and so every RPM distribution, ships
  `libpcap.so.1`. The release workflow builds the gnu binaries and packages the
  `.rpm` inside a Debian container, so the packaged ELF recorded Debian's name
  and rpmbuild's automatic generator copied it into the metadata.
  `build-rpm.sh` now rewrites the staged binary's `DT_NEEDED` to
  `libpcap.so.1` before rpmbuild reads it, so the generator names the library
  the binary genuinely loads. Filtering the generated `Requires` instead would
  have been worse than the bug: the loader reads the same `DT_NEEDED`, so the
  package would install and then fail to start. The builder now also checks the
  finished artifact and deletes it rather than emit one `dnf` cannot install.
  Reported by Ihor Olkhovskyi
  ([@igorolhovskiy](https://github.com/igorolhovskiy)), who hit it installing
  on Fedora 44 (#244).

- **The audio plugin turned ALSA into a hard dependency of the full `.rpm`.**
  The spec declares `Recommends: alsa-lib` on purpose, because the plugin is
  `dlopen`ed lazily and a headless server should not drag in the ALSA stack for
  a feature it never uses. The automatic generator read `libasound.so.2` out of
  the plugin's `DT_NEEDED` anyway and wrote a hard `Requires`, which blocks the
  install outright on any host whose repositories carry no alsa-lib. Only the
  plugin directory is now excluded from dependency generation; the binary's own
  dependencies still come from its ELF, which is what makes the libpcap
  `Requires` above correct.

### Added

- **`packaging/rpm/test-build-rpm.sh`, and a CI job that runs it.** The `.deb`
  builder and the Homebrew formula have each had a test on every push for a
  while. `build-rpm.sh` had none, and ran for the first time on a release tag —
  which is how four `.rpm`s naming a SONAME no RPM distribution provides
  reached users, and why a user reported it rather than CI. The harness links
  real stub ELFs with `-Wl,-soname,libpcap.so.0.8`, because a shell-script
  stand-in carries no `DT_NEEDED` and so cannot express this bug at all, and
  asserts both the generated metadata and the packaged ELF.

## [0.5.113] - 2026-08-19

### Fixed

- **`scripts/rfc-links.py` did nothing anywhere but one machine.** It
  hardcoded `root = /home/gator/Development/sipnab`, so everywhere else the
  glob matched no files and it reported "0 section citations across 0 files"
  and exited 0. A no-op that reports success is worse than a crash, because the
  gate that points contributors at this script kept pointing them at one that
  could not act. The root now comes from `__file__`, as in every sibling
  script. It immediately finds 13 unlinked RFC first mentions across 6 files
  that it had been skipping.

- **The pre-push hook ran whichever Vale was on `PATH`.** `Vale.Spelling`
  consults a dictionary that changes between releases, so a different binary
  answers a different question: on identical committed bytes, the 3.16.0 CI
  pins reported 0 errors while Homebrew's 3.17.1 reported 475. The hook blocked
  pushes while CI was green, and could equally have passed something CI
  rejects. It now checks the version against the pin, declines to run on a
  mismatch while naming both versions, and accepts `VALE_BIN` — the convention
  `CODESPELL_BIN` already established beside it.

## [0.5.112] - 2026-08-19

### Changed

- **The MCP documentation is four pages instead of one.** `docs/mcp.md` was
  3435 lines and changed kind four times — introduction, how-to, 2639 lines of
  tool reference, protocol contract, then how-to again. A reader met "Choosing
  a transport" at line 64 and "Token bootstrap" at 232 before seeing a single
  tool return a single result. It is now `mcp.md` (what it is, one working
  example, where to go next), `mcp-deploy.md` (deployment scenarios),
  `mcp-tools.md` (every tool, its arguments and its response) and
  `mcp-protocol.md` (security model, write verbs, the stdio invariant). First
  real output in the introduction is now at line 32.

  This partly reverses the 0.5.15-era merge, which consolidated three MCP pages
  because each restated the `--mcp` requires `-N` boilerplate. That reason was
  about duplication, not page count, and the duplication had already partly
  returned on its own — two pages, three mentions, before anything was split.
  After the split the total is unchanged and the introduction is down to one,
  with `mcp-protocol.md` owning the normative statement.

  Existing links keep working: `mcp.md` is still `mcp.md`, and the anchors that
  moved are repointed. `docs/mcp-walkthrough.md` is now `docs/mcp-deploy.md`.

- **`docs/design/documentation-pattern.md`** records how prose docs are
  organised: pages split by task rather than reader skill, depth collapsed into
  `<details>` on the page it belongs to, and one owner per topic.

### Fixed

- **A macOS developer could not push at all.** Two intra-doc links pointed at
  `capture::uprobe`, which is Linux-only, so `RUSTDOCFLAGS="-D warnings" cargo
  doc` failed on any other host — and that is what the pre-push hook runs. CI
  stayed green throughout, because CI is Linux. The failure named a doc link
  rather than a platform, so it read as a broken reference instead of an
  unpassable gate.

## [0.5.111] - 2026-08-18

### Added

- **STUN evidence now settles the private-SDP-address question instead of only
  raising it.** `private_media_address` flags a `c=` line the far end cannot
  route to, but it needed an observed stream aimed at a public peer — so a call
  whose media never arrived had no peer to test and stayed silent, which is the
  worst case and the one most likely to be captured. A mapped or relayed
  address in public space settles the same question without a stream and raises
  the flag on its own. Silence counts too, but only from a STUN server that is
  itself public: a probe to a server on the LAN proves nothing about internet
  reachability, and treating it as a fault would fire on every LAN-only
  capture.

  Carried as `diagnosis.stun_sdp_mismatch`, evidence on the existing flag
  rather than a second finding. It describes one condition — an unroutable
  address in the SDP — and reported twice it would read as two independent
  problems about one address. The correlation is by client IP with nothing
  shared between the STUN exchange and the dialog, so evidence from outside the
  call says so rather than presenting an inference as an observation.

- **`--analyze` / `--json-analyze`: every problem in a capture, worst first,
  with the frames behind each finding.** It aggregates the per-dialog diagnosis
  already computed and the capture-level evidence already held — it derives
  nothing new — and refuses to report a clean verdict over a capture that did
  not fully decode.

- **`--stun` / `--json-stun`: the STUN and TURN transactions, and what each one
  learned.** Method, client, server, attempts, response, RTT, mapped and
  relayed addresses, plus the TURN allocation and channel tables.

- **A lapsed TURN allocation is a finding.** An allocation still carrying
  traffic past the lifetime it was last granted, with no Refresh seen, means
  the relay tore down and the media stopped mid-call with no SIP message to
  explain it. Reported on stderr, as `LAPSED` in the `--stun` table, as
  `lapsed: true` in `--json-stun`, as `turn_allocation_lapsed` in `--analyze`,
  and as `sipnab_nat_lapsed_turn_allocations` for a dashboard.

- **The TURN attributes that change a diagnosis but were not read**: `DATA`,
  `REQUESTED-ADDRESS-FAMILY`, `EVEN-PORT`, `DONT-FRAGMENT`,
  `RESERVATION-TOKEN`. A truncated `LIFETIME` is refused rather than
  zero-extended — reading it short invents an expiry the sender never claimed.

- **The LLMNR host roster.** Queries name hosts that are looking, responses
  name hosts that own a hostname, and a name nothing on the segment answers for
  is reported as unresolved. LLMNR being enabled at all is the exposure the
  Responder tool abuses.

### Fixed

- **Windows name lookups were becoming phantom RTP streams.** An LLMNR query is
  a DNS-format message whose random transaction ID supplies the RTP version
  bits one time in four, and the rest of the strict RTP pre-filter a 23-byte
  query passes trivially — two of them appeared as one-packet streams with SSRC
  `0x00000000` in a real capture. The existing guard for this collision only
  covers ports below 1024 and LLMNR is at 5355. LLMNR is now claimed during
  classification, before any media check, which removes the class by
  construction rather than by tuning the heuristic. sipnab is not becoming a
  general dissector: the packet is claimed because it corrupts media analysis,
  and nothing here feeds call diagnosis.

- **TURN ChannelData framing was too permissive.** Accepting any frame whose
  declared length merely fit let a stray datagram with the right two leading
  bytes be unwrapped and re-classified. The frame must now account for the
  whole datagram, padded or not.

- **The test that wedged the suite for 20 minutes once and 1d17h once**, cause
  recorded as unknown in the pre-commit hook. It is
  `no_source_auto_detects_device`: with no source, auto-detection opens a live
  device and follows it forever, and on an idle link pcap never returns. CI
  never saw it because an unprivileged runner fails to open the device and
  exits 1 in milliseconds, so it reproduces only where the user holds capture
  rights — on macOS, anywhere BPF access is granted. The capture is bounded
  now; both assertions are unchanged.

### Changed

- **`docs/troubleshooting.md` no longer says sipnab "cannot tell those apart
  from one capture"** about an SDP address something downstream may or may not
  rewrite. The STUN evidence separates them, and the page now gives the three
  cases and what each proves — including the one that proves nothing.

## [0.5.110] - 2026-08-18

### Added

- **STUN and TURN parsing reads every attribute that changes a diagnosis.**
  0.5.109 read enough to say a request went unanswered. This reads enough to
  say what the answer meant, and three of the additions fixed a WRONG reading
  rather than a missing one:

  - **`MAPPED-ADDRESS`** (the pre-RFC5389 form). Servers older than the magic
    cookie still answer with it, and without reading it their *successful*
    response reported as no answer at all. When both forms arrive the XOR one
    wins whatever order they come in, because it is the one a NAT cannot
    rewrite on the way back.
  - **`REALM` / `NONCE`.** A `401` with a realm is an **authentication
    challenge, not a blocked path**, and each sends you somewhere completely
    different. The run now says so on its own line rather than letting
    "answered" read as "fine". The nonce is recorded as present only — its
    value is a server-chosen opaque string that means nothing to an observer.
  - **`ALTERNATE-SERVER`**, so a `300` redirect names where it points instead
    of reading as a dead end.

- **`FINGERPRINT` is verified**, which corrects what the module said when it
  landed. It grouped `FINGERPRINT` with `MESSAGE-INTEGRITY` as unverifiable and
  that was wrong: it is a CRC-32 over the message with no key involved, so a
  passive reader can check it honestly. Verified, present-and-wrong, and absent
  stay three distinct states — reporting absent as wrong would accuse a message
  nobody examined. It is also what separates a real STUN message from a payload
  that merely happened to carry the cookie bytes.

- **ICE attributes**: `USE-CANDIDATE`, `PRIORITY`, and the
  controlling/controlled roles. The nomination is the finding — without it, an
  ICE exchange that converged and one that never did look alike — and a capture
  where *both* sides claim controlling is a role conflict whose only other
  symptom is media that never starts. Reported, never decided: sipnab is not an
  ICE agent.

- **TURN `CHANNEL-NUMBER` and `REQUESTED-TRANSPORT`**, so a relay path can be
  described rather than merely detected.

  `MESSAGE-INTEGRITY` and `MESSAGE-INTEGRITY-SHA256` stay deliberately unread.
  They decide whether a message is *authentic*, which needs credentials a
  passive observer does not have, and claiming a verification that never
  happened is worse than not checking.

### Changed

- **Prometheus has its own page.** The homepage said "REST API + Prometheus"
  and led to a 1,195-line page whose Prometheus content started at line 1021 —
  86% of the way down, under the endpoint reference. They are different
  surfaces for different readers: everything else on that page returns what
  sipnab *saw*, while `/metrics` returns numbers *about* sipnab, polled on a
  timer and authenticated differently. Now [Prometheus
  Metrics](https://sipnab.com/docs/metrics/), sitting beside Integrations in
  the nav — next to HEP, because both are how sipnab plugs into a monitoring
  estate, and **not merged with it**, because HEP is a transport for SIP
  messages while a scrape carries no SIP at all.

### Fixed

- **STUN and TURN are documented at all.** 0.5.109 shipped the parsing with no
  user-facing documentation: the only `STUN` mention was troubleshooting advice
  to *configure* it on the phone, written before sipnab could read it.
  Troubleshooting now carries the diagnosis — leading with the distinction that
  directs the work, that a reply which never comes is a different fault from a
  reply that says no — and the encapsulations page carries the coverage table,
  including what is deliberately not read.

## [0.5.109] - 2026-08-17

### Added

- **sipnab reads STUN and TURN, and says when a NAT question went
  unanswered.** Raised by two field captures of a one-way-audio complaint.
  sipnab read one of them as *"No SIP traffic found. Check that the capture
  contains SIP packets"* — true, useless, and pointing the operator at a
  capture problem when the capture already held the cause.

  It held two STUN Binding Requests, the same transaction sent twice, and no
  reply. That is the whole failure: an endpoint that cannot learn its
  reflexive address falls back to advertising its **private** address in SDP,
  and the far end then sends media to an address the internet cannot route,
  while the call signals cleanly and answers `200`.

  A retransmission counts as one unanswered question with N attempts, not N
  questions. An **error response counts as answered** — the server was
  reachable and refused, which is a different fault pointing somewhere else,
  and reporting it as silence would send someone hunting a blocked path that
  is not there.

  The reports name the likely cause, not only the symptom: silence rather than
  a refusal points at something in the path discarding the packets, and on
  school, campus and corporate networks that is most often a security
  appliance — web filter, secure web gateway, firewall or IPS — dropping UDP
  it does not recognise.

- **TURN, including the parts that do not come free.** RFC 5766 reuses the
  STUN header, so `Allocate` parses without the parser knowing TURN exists.
  Its attributes did not (`XOR-RELAYED-ADDRESS`, `XOR-PEER-ADDRESS`,
  `LIFETIME`), an unanswered `Allocate` is a different fault from an
  unanswered `Binding` and is labelled so, and **ChannelData is not
  STUN-shaped at all** — no cookie, no transaction ID — so it is recognised by
  channel number. The three multiplexed protocols separate on their high bits:
  STUN `00`, ChannelData `01`, RTP `10`.

- **`--capture-profile signaling|full`**, which picks a `--snaplen` by purpose
  instead of by hand. `signaling` uses 1500: one INVITE carrying a full
  `Record-Route` set, ISUP encapsulation or a fat SDP offer passes 400 bytes
  routinely, and a snaplen that cuts a HEADER is far worse than one that keeps
  some payload — the message stops parsing and the peer that sent a valid
  message is the one reported as broken. A named profile rather than a smaller
  default, because truncation breaks `--retain-audio`, WAV export and Opus
  decode and degrades `-O` re-emit. An explicit `--snaplen` overrides it.

- **`sipnab_capture_snapped_frames_total`** and
  **`sipnab_nat_unanswered_requests`**, in the capture-quality block on all
  three surfaces (Prometheus, `/v1/stats`, MCP `capture_status`). The NAT one
  is a **gauge**, not a counter: a late answer removes a transaction, which a
  monotonic counter could never record.

### Changed

- **The stream list shows the media verdict every other surface already had.**
  Media hints were produced once and consumed by the text report, `--json`,
  MCP and REST — 9 references in `src/output/` and `src/mcp/`, and 0 in
  `src/tui/`. `media_origin` is now split out of `diagnose_media`, which
  reaches its own `nat_mismatch` verdict *through* it, and the stream list
  calls the same function per row, so the column and the hint cannot disagree.

- **`--cores` reaches live capture.** `PACKET_FANOUT` was implemented, tested
  and wired into `live.rs`, and `capture_live_fanout` had no caller outside its
  own module — built, tested and unreachable. `--cores N` on a live device now
  asks the kernel for N capture sockets. **Processing stays on one thread**, so
  it buys ring capacity against a dropping interface, not cores of analysis.
  `--cores 1` and every non-Linux host still capture on exactly one socket.

### Fixed

- **A private media address offered to a public peer is flagged.** An SDP `c=`
  line carrying an RFC 1918 / RFC 4193 / link-local address is correct inside
  one LAN and correct behind an SBC that rewrites it downstream — and wrong
  when nothing rewrites it, silently. Raised only when the peer is itself
  public, and carrier-grade NAT space is deliberately excluded: it is routable
  within the carrier that assigned it, and flagging it would fire on a large
  share of working mobile calls.

- **TURN-relayed media reaches reconstruction.** The RTP inside a ChannelData
  wrapper was recognised and then dropped, so a call whose audio went through a
  relay reported as having **no media** — the same answer sipnab gives for a
  call that genuinely carried nothing. Opposite conclusions, rendered
  identically.

- **A truncating snaplen says how much it cut.** The `--snaplen` warnings fire
  once per run, so a run that decoded every packet and truncated 94% of them
  reported as clean. Counted in `Packet::from_bytes`, the one constructor every
  reader passes through.

## [0.5.108] - 2026-08-17

### Changed

- **Offline reads map the capture file instead of streaming it through
  libpcap: 37% more throughput at four cores and 51% at eight.** The `--cores`
  reader is one serial thread doing read, copy and host-pair-peek for every
  packet while the workers wait, and reading through libpcap charged it a
  `read` into libpcap's buffer *and* a copy out of it. Mapping the file drops
  the first: records are parsed in place out of page cache. Measured on the
  535,000-packet corpus, median-of-7 on an idle host, same binary either way —
  3.27M against 2.38M packets/second at four cores, 3.30M against 2.18M at
  eight. Two cores is within the noise floor, and the gain arrives at four,
  where the serial reader is what the workers are waiting on. Peak resident
  memory stays within ~10 MiB of the old path, because the read hands pages
  back to the kernel as it passes them.

  **This applies to `--cores 2` and above only.** `--cores 1`, and a run with
  no `--cores` at all, use the single-threaded reader, which still goes through
  libpcap and is unchanged by this release — so the default offline read is no
  faster. Teaching that reader to map as well is the obvious next step and is
  not part of this change.

  Classic uncompressed pcap only. pcapng, gzip, anything that is not a regular
  file, and any read with a BPF filter set all fall back to libpcap
  unchanged — a filter is libpcap's to apply, and bypassing it would silently
  widen the capture. `SIPNAB_NO_MMAP=1` forces the fallback everywhere, for a
  filesystem where mapping misbehaves.

  Worth recording that the obvious version of this change is a *regression*:
  handing each frame out as a refcounted slice of the mapping, copying nothing
  at all, measures 1.88M at four cores — well under libpcap. One mapping means
  one atomic refcount, and 535k frames cloned by the reader and dropped by the
  workers drive ~1M atomic updates through a single cache line: free on one
  core, 21% on four. Keeping the block copy is what makes the mapping pay.
  `docs/internals/zero-copy-payloads.md` has the failed hypotheses too.

### Fixed

- **A truncated capture is still reported as truncated on the mapped path.**
  A file cut off mid-record is missing the end of whatever it was recording,
  so stopping quietly at the cut would report "read in full" over an
  incomplete capture. Found by comparing both readers across 62 real captures
  rather than against fixtures; the byte counts now match libpcap's own
  message exactly.

## [0.5.107] - 2026-08-17

### Added

- **A page that picks a TLS capture method for you.** Prompted by a VoIP
  engineer who tried to get TLS capture working and could not figure it out —
  and who then said *"all my traffic comes in via TLS, we don't even open up
  5060 on that server."* That is the case this page is written for. sipnab has
  had every method he needed since 0.5.102; what it did not have was a door.

  The failure was visible in the navigation. It offered "TLS Without Keys" and
  "Uprobe TLS Capture" — both the same exotic eBPF path, named after the kernel
  mechanism rather than the goal, and both demanding root, BTF and a
  non-default build. The ordinary route, a key log from the endpoint, sat
  inside the cookbook as §7. The menu advertised the hard road and hid the easy
  one.

  The new page opens with a table you read down until you reach a row you can
  satisfy, ordered by **what access you have** rather than by how sipnab works:
  set `SSLKEYLOGFILE`, or hold root without being able to restart the daemon,
  or hold root on a BTF kernel, or run eCapture, or face an old RSA server.
  Each row names one command and what it costs. For the reader who is new to
  this it states plainly that a capture alone can never be decrypted and why —
  forward secrecy means the information is not in the pcap and never was. For
  the reader who already knows that, there is a "what does not work" section so
  they stop trying, and a symptom table for the failures that look like bugs
  and are not: `--uprobe-list` silent without `sudo`, zero messages from a
  daemon that calls `SSL_write_ex`, `0.0.0.0:0` peers on the tracefs backend.

  It sits above the mechanism-named pages in the navigation, and the homepage's
  TLS row now lands on it rather than on one recipe among eight.

### Security

- **The compiled browser analyzer is no longer committed.** OpenSSF Scorecard
  flagged `website/static/wasm/sipnab_bg.wasm` at high severity under
  Binary-Artifacts, correctly: a binary in a repository cannot be audited from
  its source. It was already dead weight — the Pages workflow rebuilds it at
  deploy time, precisely because the committed copy had served eleven releases
  of stale analysis.

  Removing it retires the pre-commit gate that demanded it be restaged
  alongside any `src/wasm.rs` change. That gate had to go rather than stay:
  with the binary untracked it could never be satisfied and would have blocked
  every future commit touching that file. It never worked anyway — the eleven
  stale releases happened while it was green, because `src/wasm.rs` had no
  commits in that window and the interface held still while the implementation
  moved. `sipnab.js` stays committed: it is text, Scorecard does not flag it,
  and the export guard reads it.

### Added

- **A published WASM plugins page.** The homepage advertised plugins as a
  capability and the only WASM documentation was a design specification on
  GitHub, which that spec's own "Not done yet" already admitted. The page is
  written for someone deciding whether to load one: when a plugin is the right
  answer against a filter or a `jq` pipeline, what the sandbox does and does
  **not** bound — it bounds CPU, memory, output size and blast radius, and it
  does not bound what a plugin reads — and the worked example from crate to
  finding.

- **A published authentication page.** The site's API and MCP pages name bearer
  tokens seventeen times between them and sent the reader to GitHub to learn
  how to mint one. Minting a token is an operator task, so it now lives with
  the other operator tasks: token format, audience binding, signing keys,
  expiry and rotation.

  Both gaps are the same shape as the eBPF one 0.5.102 fixed: a capability that
  ships, works and is written up somewhere a reader on the site never reaches.

### Fixed

- **The benchmarks page claimed its tables came from a release that did not
  exist when they were measured.** The 0.5.105 bump swept
  `sipnab 0.5.104 (` to `sipnab 0.5.105 (` across the docs to move the
  `--version` examples, and the benchmarks method block carries a line in
  exactly that shape. The page shipped naming 0.5.104 in its header and
  0.5.105 in its method block, and nothing caught it: every other version
  marker here tracks the crate or the last published release, and this one
  tracks neither — it records what a measurement was taken against, which a
  later release does not change.

  Restored to 0.5.104, and a gate now asserts the page agrees with **itself**
  rather than with `Cargo.toml`, so it stays right when the crate moves on and
  fails when a sweep drags the line along. Reintroducing the corruption fails
  it; that is checked rather than assumed.

### Changed

- **The build table and the next-steps list name `plugins` and `bpf`.** Both
  are non-default features an operator chooses deliberately, and neither
  appeared in the table that tells a reader what is in their binary.

## [0.5.105] - 2026-08-17

### Changed

- **US English throughout: 2,904 replacements across 274 files.** The tree
  mixed British and US spellings — `flavour` beside `flavor`, `signalling`,
  `cancelled`, `behaviour`, `colour`, `analyse`, `honour`, `licence` and
  thirty more — in prose, doc comments, test names and one released CLI flag.
  A repository that spells the same word two ways teaches a reader that
  neither spelling is meant, and a grep for either finds half the matches.

  **Two surfaces were contracts rather than prose, and both keep working:**

  - `--uprobe-flavour` is now `--uprobe-flavor`, with the old spelling kept as
    an alias. A flag that shipped through 0.5.104 is a promise to every script
    that names it. A test asserts the old spelling still reaches the same
    field, and it fails if the alias is removed.
  - The MCP `start_tls_capture` parameter `flavours` is now `flavors`, with
    `#[serde(alias = "flavours")]`. A JSON field an agent was told to send is
    wire format; wire format does not change because the prose around it did.

  Identifiers containing an underscore (`parse_flavour`) were renamed
  deliberately rather than by the sweep, which matches whole words only.

- **The homepage capability rows link where they claim to.** Five were wrong
  or imprecise, found by measuring each target for its own topic rather than
  by reading them:

  - **WASM plugins** pointed at the integrations page, which contains no
    occurrence of "WASM", "WebAssembly" or "plugin" — it documents HEP, event
    execution and fail2ban. It now points at the plugin API specification,
    which is the only WASM documentation that exists. (That there is no
    published plugins page is a real gap, recorded in that spec's own "Not
    done yet".)
  - **HEP v2/v3** pointed at the cookbook; the integrations page *is* the HEP
    page. Those two rows were effectively swapped.
  - **VoIP diagnosis**, **Security** and **TLS/SRTP decryption** landed on the
    cookbook's top rather than on the recipe each names, so a click left the
    reader to find it among eleven others.

- **The Inspect, Diagnose and Export tiles are links.** They already had the
  hover lift and shadow of something clickable and were not, which is a
  promise the markup did not keep.


## [0.5.104] - 2026-08-17

### Changed

- **Offline file reads are 29% faster on one core.** A file source now hands
  the capture channel batches of 128 packets instead of one packet at a time.
  Measured against the released 0.5.103 artifact, checksum-verified, on an
  idle host, median-of-5 across three interleaved replicates: **1.00M to 1.29M
  packets/s at `--cores 1`**, with four-core throughput unchanged (2.31M vs
  2.30M, inside the run-to-run spread) and RSS 3 MiB lower.

  A profiler found it, after a bisect-style reading of the code did not. On a
  single-core reconstruction the channel machinery — the per-packet slot
  claim, the storage send and the receiver wake-up — was **~35% of wall time**,
  against ~9% for the SIP and RTP analysis the tool exists to do. At four
  cores that cost hides behind the parallel analysis, which is why the same
  profile at `--cores 4` shows nothing worth fixing and why the win here is
  one-core-shaped.

  A live capture is deliberately excluded and still sends one packet per
  channel item: batching would hold a packet back until its batch filled, and
  the scanner-kill path reacts to single packets. Replay is excluded for the
  same reason at a different timescale — it reproduces inter-packet gaps, so a
  packet has to be visible when its moment arrives. Non-regular inputs (a
  FIFO) keep the per-packet send too, because a trickling producer would leave
  up to a batch parked in the reader.

  The batched channel divides its slot pool by the batch size, so the
  in-flight PACKET cap an operator asks for still means what it said, and
  backpressure still blocks the reader at that cap. Analysis output is
  unchanged: the same corpus produces a byte-identical report through either
  shape.

## [0.5.103] - 2026-08-16

### Fixed

- **The pre-push hook now lints the whole workspace, as CI does.** CI was
  widened to `cargo clippy --workspace` without the hook or the documentation
  following, so a warning in `sipnab-audio`, `sipnab-bpf-types` or the example
  plugin passed every local gate and failed in CI -- spending a round trip to
  learn something the hook could have said in seconds, which is the one thing a
  local gate exists to prevent. The hook, its `--fix` hint, the Code Scanning
  report and all seven pages that quote the command now carry the same flag:
  measured, a lint in a workspace crate exits 0 under the old command and 101
  under the new one.

### Security

- **A plugin file is now read through a 16 MiB bound.** Loading a plugin
  allocated the file's whole length up front, so the largest thing an operator
  could point `--plugin` at was the largest allocation sipnab would make -- and
  a plugin path can arrive from a config file rather than from the command
  line. The read is bounded rather than the length checked, so the bound also
  holds against a file that grows between the check and the read.

### Changed

- **`aya` 0.13 to 0.14**, for the eBPF backend. The upgrade is a breaking API
  change on `aya`'s side -- `UProbe::attach` takes an attach point and a scope
  instead of four positional arguments, and the synchronous perf reader yields
  events to a closure instead of filling caller-supplied buffers. Verified
  against a live SIP-over-TLS trunk, recovering the same peer addresses as
  before. The new reader borrows samples straight from the kernel ring, which
  retires sipnab's per-CPU scratch buffers and the sharp edge that came with
  them: a `BytesMut` clone copies contents rather than capacity, so a set of
  cloned buffers read no events and reported no error -- silence a reader could
  not tell from a quiet trunk.


- **The homepage no longer invites the reading that sipnab breaks TLS.** "Read
  SIP over TLS with no key and no certificate" is a severe claim, and stated
  alone it sounds like an attack on the protocol. It is not one: nothing is
  decrypted, no other machine is read, and no session key is recovered. sipnab
  reads plaintext inside a process on a host where the operator already has
  root, before the TLS library encrypts it. The capability row now says so
  first, names the constraint in its title, and links to a walkthrough.

### Added

- **[A walkthrough for reading SIP over TLS without keys](https://sipnab.com/docs/uprobe-walkthrough/).**
  What the feature is and is NOT, its security implications as their own
  section rather than a footnote, the limitations up front with a command to
  test each -- no Linux, no tracefs, no root or no BTF are hard stops rather
  than degraded modes -- and both backends step by step. Carries the trap that
  a probe on the wrong symbol captures nothing while looking perfectly healthy.

- **Every capability on the homepage links to the page that documents it.**

- **A discoverability gate.** Each user-facing feature must name the phrase a
  reader would search for on the homepage. It exists because eBPF TLS capture
  shipped fully documented and unfindable -- zero occurrences of "eBPF" on the
  homepage -- and on its first run it found a second one: the WASM plugin host.

### Fixed

- **The non-Linux gate now catches the break that turned main red twice.**
  Rewriting `target_os` inverts the code, but cargo still resolves dependencies
  for the host, so a Linux-scoped dependency was present in the graph the shim
  compiled against. Two new phases check resolution against a macOS target and
  compilation against FreeBSD, reproducing both breaks locally with no Mac.

## [0.5.102] - 2026-08-15

### Added

- **eBPF TLS capture that recovers the peer (`--uprobe-backend bpf`).** The
  default `tracefs` backend reads SIP plaintext out of a process's TLS library
  but sees no socket, so its dialogs name a process rather than a peer. This one
  pairs each write with its own `tcp_sendmsg` -- same thread, back to back --
  and reports the addresses the plaintext actually went out on. No key, no
  certificate, no restart of the daemon.

  Verified live: a `REGISTER` and its `200 OK` came back as
  `127.0.0.1:36160 -> 127.0.0.1:15061` and the reverse, each connection carrying
  its own ephemeral port.

  When the pairing does not hold -- a write the library buffered rather than
  sent -- the message is reported with **no addresses** rather than a guessed
  peer. Filling one in would make the honest case worthless, because nothing
  downstream could tell them apart.

  Socket offsets come from the running kernel's own BTF (BPF Type Format), so
  the program keeps working across kernels instead of matching only the one that
  compiled it. Off by default and outside `full`: building it needs a nightly
  toolchain and `bpf-linker`, running it needs `CONFIG_DEBUG_INFO_BTF`, and
  sipnab refuses it rather than quietly downgrading when either is missing.

- **Uprobe TLS capture reaches the command line.** `--uprobe-tls` probes every
  TLS library the host is running -- OpenSSL and wolfSSL coexist on an ordinary
  machine -- rather than one an operator named. `--uprobe-list` reports what a
  capture would probe without installing anything, and exits non-zero when
  nothing is visible. `--uprobe-library`, `--uprobe-symbol` and
  `--uprobe-flavor` narrow or override it; `--uprobe-backend` chooses between
  `tracefs` and `bpf`.

  Libraries are identified by inode, not path: three distinct `libssl.so.3`
  files can share one path string on a host running containers, and probing the
  path attaches to the host's copy while missing every container.

- **`start_tls_capture` / `stop_tls_capture` MCP tools**, behind the new
  `--mcp-allow-tls-capture`. The first tools on that surface that create kernel
  state, which is why the opt-in is separate from `--mcp-allow-open-capture`:
  reading a file an operator placed in a directory and attaching probes to a
  live daemon are not the same act. `list_tls_libraries` reports what a capture
  would see and needs no opt-in at all.

### Fixed

- **Uprobe reads were swallowed by the TCP reassembler.** A uprobe read is a
  complete application write, not a segment of a byte stream, and carries no
  sequence number -- so every message was held for neighbors that could never
  arrive. Both uprobe backends captured packets and produced **zero SIP
  messages**, which reads exactly like a quiet trunk.

- **The MCP walkthrough's security section claimed no tool alters the
  analysis.** `start_tls_capture` does. The section now separates what remains
  true -- no MCP tool sends SIP -- from the one tool that creates kernel state.

## [0.5.101] - 2026-08-15

### Added

- **`--hep-allow` accepts a bare address.** It demanded CIDR, so
  `--hep-allow 10.0.0.40` exited with `missing /prefix` and the listener never
  bound — which reads as a HEP problem and is a spelling problem, in exactly the
  situation the flag exists for. A bare address now means that host alone: `/32`
  for IPv4, `/128` for IPv6. Which way that defaults is the point: a host route
  is the NARROWEST reading, so a missing prefix can only ever admit less.
  Inferring a classful network from `10.0.0.0` would silently admit sixteen
  million addresses nobody named, which is the opposite of what an allowlist is
  for.

### Security

- **The runtime container takes Debian security updates.** `util-linux` 2.41-5
  in the pinned base carries CVE-2026-53613 and CVE-2026-53614, both fixed in
  2.41.5-0+deb13u1. Pinning the base by digest is right for reproducibility and
  is also why the fix never arrived; bumping the digest would not have helped,
  as the pin was already the newest published `debian:trixie-slim`. The runtime
  stage now upgrades before it installs, verified to produce the fixed version.

- **Uprobe-sourced input can never trigger an active response.** `ParsedPacket`
  now carries `InputOrigin` — `Wire`, `Hep` or `Uprobe` — in place of
  `from_hep: bool`, and scanner-kill answers each on its own terms: wire traffic
  is always eligible, HEP only with `--hep-allow-kill`, and uprobe input NEVER,
  with no opt-in. Bytes lifted out of a process carry no socket, so a response
  would be aimed at a guess, and an opt-in there would be an invitation to send
  one. The old boolean could describe only two of the three cases, so making the
  third safe would have meant labeling it HEP.

### Fixed

- **Two MCP annotation claims that the code contradicted.** `docs/mcp.md` said
  "All 31" tools carry annotations where the same page said "the 32 tools" three
  paragraphs later — it is 32, counted from the source as 27 `readOnlyHint` plus
  5 write verbs. It also said "No tool sets `openWorldHint`" when all 32 set it
  explicitly to `false`, which is the opposite of what a reader would find.

### Internal

- **Groundwork for reading SIP over TLS from a process (TK7), not yet reachable
  by an operator.** The read path is complete and measured against a live
  kernel — ELF symbol offsets translated through their `PT_LOAD` segment,
  length-banded uprobes, a `perf_event_open` ring reader, record decoding at the
  offsets the kernel publishes, and acceptance rules that truncate to the length
  the application wrote and wipe the rest. There is no flag to switch any of it
  on: nothing calls `install()`, and the 5-tuple recovery that would let such
  dialogs name a peer is not built. Frame pointers minted from it refuse to
  resolve and say why, since the bytes were never on a wire.

### Changed

- **Media hints name the ports, not just the addresses.** The one-way-audio
  hint read `RTP from 10.0.2.15 -> 10.0.2.20 only`, which stops exactly where
  the operator's next action begins: one-way audio is fixed through port-based
  artifacts — a firewall rule, a NAT pinhole, an RTP port range, the
  `m=audio <port>` line — and none of them is reachable from an address. It now
  reads `RTP flowed 10.0.2.15:27942 -> 10.0.2.20:6000 only (SSRC 0x343da99b)`,
  and the SSRC ties the sentence to a row in `stream_count`'s stream list.

  Each side advertises a RECEIVE port in its SDP and, under symmetric RTP
  (RFC 4961), sends from that same port; NATs and many endpoints break that,
  the far end replies to a port nothing is sending from, no pinhole was ever
  opened there, and the audio is one-way. That comparison is now made in both
  directions and stated when it fails — `10.0.2.15 advertised 16384 to receive
  RTP but sends from 41002 — not symmetric (RFC 4961), so 10.0.2.20 replies to
  16384, where nothing is sending and no NAT pinhole was opened` — and stays
  silent when the ports agree, which is most calls.

  `nat_mismatch` and `no_media` carry the same evidence: the NAT hint names the
  5-tuple it saw against the endpoint the SDP advertised, and the no-media hint
  names the advertised receive endpoints nothing arrived at. Both flags are
  verdicts, and a verdict a reader cannot check against the SDP is one they can
  only take on trust. Ports are reported where the SDP supplied them and are
  never inferred: an address the dialog advertised no port for — an FQDN `c=`
  line, or a source a NAT rewrote — draws no comparison at all.

  The detection rules are unchanged. `nat_mismatch` still compares addresses
  only, because NATs and RTP proxies rewrite the port on a large share of
  perfectly healthy calls; the ports are evidence in the hint, not a new
  trigger. Every surface that renders hints — the text and Markdown call
  reports, `--json-dialogs`, the REST API and the MCP tools — carries the new
  text, because it is produced once in `rtp::diagnosis` rather than formatted
  per surface.

## [0.5.100] - 2026-08-14

### Added

- **`--split-keep N`** bounds what `--split` leaves on disk: sipnab keeps the
  newest N files and DELETES the older ones as rotation creates new ones,
  turning `-O` into a ring buffer. Rotation was unbounded — a long capture with
  `--split` filled the volume and there was no way to say "the last hour is
  enough" short of a cron job racing the writer.

  This flag deletes capture files, so it fails safe in four ways. It is off
  unless you pass it, and off at `0`, because a capture is very often the only
  copy of the evidence. sipnab deletes only the files the running process
  created and named, remembered as it creates them — the directory is never
  listed and no name pattern is ever matched against it, so a file left by an
  earlier run, another tool, or an operator survives however closely its name
  resembles a rotation. Deletion happens after the previous file is closed,
  never to the file being written. A run killed mid-capture leaves behind
  whatever it had not yet deleted, and the next run starts an empty list rather
  than adopting them. sipnab names each deleted file in the log and counts them
  in the closing summary.

- **`--api-max-rows` / `[limits] api_max_rows`** sets the row ceiling on one
  list-style REST response, which was a hard-coded 1000. The MCP surface
  documents the identical policy — the right ceiling is a property of the
  consumer, not of sipnab — and made it settable; the REST surface stated it
  and did not. A batch consumer piping `/v1/dialogs` to a file could never
  exceed a thousand rows, and a dashboard could never ask for fewer.
- **`--api-rate-limit-per-peer` / `[limits] api_rate_limit_per_peer`** sets the
  REST per-peer request rate, which was a hard-coded 100/s. The limiter counts
  by source address, so a dashboard polling `/v1/streams` on a short timer, or
  several collectors behind one NAT, shared a single allowance and got `503`
  with no knob to raise. `0` disables the cap, matching
  `--mcp-rate-limit-per-peer` and `--hep-rate-limit` — and the REST limiter now
  reads a zero that way instead of refusing everything.
- **`[limits] max_tracked_peers`** sets how many distinct peers one rate-limit
  window holds, on every surface `rate_limit` meters: HEP source addresses and
  MCP callers. It was a fixed 4096, and past it a peer inside every rate limit
  is REFUSED — so a collector aggregating from more agents than that never saw
  the surplus. The fail-closed direction is right; the number is a deployment
  property. Config-only, with a floor of 2 refused by name: a map of one turns
  the per-peer cap into a global lock, where the first sender in a window takes
  the only slot.
- **The homepage leads with MCP.** The demo strip opened on seven terminal
  recordings, which argue "a better sngrep" — the local-tool position
  `docs/design/positioning.md` declines. Four MCP examples now come first,
  labeled by what an agent asks rather than by the tool it calls: why a call
  failed, which RFC a dialog breaks, the captured bytes behind an answer, and
  which other leg is the same call across a B2BUA.
- **`demos/mcp-stdio.sh`** runs one MCP tool call over stdio against a capture
  in the tree. Unlike `demos/mcp-call.sh`, which drives the HTTP transport, it
  needs no harness, no port and no bearer token, so a reader who clones the
  repo can reproduce any published example with one command.
- **`demos/gen-mcp-examples.sh`** regenerates those four answers from the
  binary and writes both `website/data/mcp-examples/*.json` and the blocks in
  the homepage. `--check` re-runs all four and fails on any difference, so a
  published answer cannot outlive the code that gave it. The examples are text
  rather than a recording for exactly this reason: a recording cannot be
  compared against anything, and JSON is what an agent actually receives.
- **`--reassembly-ttl` / `[limits] reassembly_ttl_secs`** sets how long an
  incomplete IP datagram or half-read TCP stream is held before a sweep evicts
  it, which was a hard-coded 30 seconds. `--max-reassembly` bounds how MANY
  entries are held and says nothing about how long. Thirty seconds describes IP
  fragments in flight and the TCP reassembler inherited it: a persistent
  SIP/TCP or SIP/TLS trunk to a carrier goes quiet for far longer on any
  ordinary night, and sweeping its half-read stream means the next segment
  re-initializes mid-message — so the peer that sent a valid message is the one
  sipnab reports as broken.
- **`--hep-hmac-window` / `[security] hep_hmac_window_secs`** sets the
  acceptance window for a `--hep-auth-mode hmac` token's timestamp, which was a
  hard-coded 30 seconds. On an agent/collector pair with poor NTP every packet
  is rejected as out-of-window and the symptom is a collector that receives
  NOTHING — attributed to routing, a firewall or a dead agent long before a
  clock. The refusal warning now quotes the window this run enforces and names
  the flag. Bounded 1-300: the window is exactly how long a captured packet
  stays replayable and how far back the receiver's nonce cache must remember,
  and past 300 s the sender has no working time daemon, which is what to
  repair.
- **`--mcp-max-findings` / `[limits] mcp_max_findings`** sets how many findings
  the MCP `save_findings` tool accepts, which was a hard-coded 1000. The one
  WRITE budget on that surface — `--mcp-max-rows` and `--mcp-max-body-bytes`
  bound what an agent may read — and a long session on a large capture reaches
  it legitimately. Past the budget the write is still REFUSED rather than
  evicted, and deliberately: nothing is retained to evict, because a finding is
  a log line the operator's journal already holds.
- **`--metrics-max-conn` / `[limits] metrics_max_conn`** sets how many metrics
  scrapes are served at once, which was a hard-coded 16. The gate stops a burst
  of slow clients exhausting threads and taking monitoring down, and sixteen
  suits one Prometheus; an HA pair, a federating parent, a `remote_write`
  shard, an alertmanager sidecar and one engineer's `curl` reach it without
  anything unusual happening — and a refused scrape leaves a hole in the series
  that reads as a capture that died. Floor of 1, refused by name: a gate of 0
  answers `503` forever.
- **`--dns-cache-entries` / `[names] dns_cache_entries`** sets how many
  reverse-DNS results are held at once, which was a hard-coded 4096. Past the
  cap the oldest entry is evicted, so a capture touching more hosts than that —
  a carrier edge, a peering point, any long `--reverse-dns` window — keeps
  re-looking-up addresses it already resolved, and the symptom is names that
  flicker rather than an error. The worker queue's depth is DERIVED from this
  rather than being a second number to keep in step.
- **`--active-idle-window` / `[sip] active_idle_window_secs`** sets how long a
  dialog may go untouched and still count toward the active-dialog and
  active-call gauges, which was a hard-coded hour. Twice RFC 4028's default
  `Session-Expires` grounds the DEFAULT, not the number being fixed: a contact
  center parks callers on hold past an hour and its gauge stops counting every
  one of them.
- **`[media.codec_ie]`** declares ITU-T G.107 `Ie` values for codecs sipnab has
  no published figure for. sipnab knows G.711, G.729 and Opus; G.722, G.726,
  iLBC, AMR and EVS all fell to one placeholder and scored identically to a
  stream whose codec was never identified. A map rather than a scalar because
  the answer is per codec. A declared codec reports
  `mos_grounding: "operator_declared"` — a new `rtp_stats` field beside
  `mos_grounded` — with a note saying the figure came from this deployment, so
  a declaration is never presented as a G.113 citation, and a codec nobody
  declared still says its MOS is a placeholder. Values are refused, not
  clamped, outside `0.0..95.0`: at 95 the E-model's loss term vanishes and
  above it more packet loss would RAISE the score.
- **A poster rule in `demos/Makefile`.** Every animated demo ships a first
  frame for `prefers-reduced-motion`, and `site_journey_test` refuses a demo
  whose poster is missing — but nothing generated them. All seven had been made
  by hand, so the gate demanded a file the build could not produce.

### Changed

- **BREAKING: `CryptoBackend::hkdf_expand` takes the hash to derive under.**
  TLS binds that to the negotiated cipher suite and names it in the suite, so it
  is a parameter of the derivation, never a property of the backend. Callers
  pass `CipherSuite::hash()`. Inferring it from the PRK length was considered
  and rejected: it works for TLS 1.3 traffic secrets and not for TLS 1.2, whose
  master secret is 48 bytes whatever the hash.

- **BREAKING: `HepEndpoint` carries the transport.** It is the fifth element of
  the 5-tuple the struct already modeled, and the value the HEP IP-protocol
  chunk reports.

- **BREAKING: `Cli` is 18 `#[command(flatten)]` sub-structs, one per help
  section.** Field access moves from `cli.field` to `cli.<group>.field`; the
  parsing surface and every flag are unchanged. Clap's generated parser built
  all 215 flags in one stack frame, which crossed the 2 MiB stack libtest gives
  each test: two tests overflowed, and `.cargo/config.toml` had been raising the
  stack to 8 MiB to hide it. The largest generated group is now 37 fields, the
  override is gone, and the measurement that justified it is recorded where the
  override used to be.

- **BREAKING: `--autostop filesize:N` and `--split filesize:N` now count
  MEBIBYTES, not decimal megabytes.** Both multiplied by 1 000 000 while
  `-B/--buffer` had already been corrected to MiB, and while the `--split` help
  text, `docs/cli-reference.md` and the site all said MiB. **This changes what
  an existing invocation does**: `--autostop filesize:100` used to stop at
  100 000 000 bytes and now stops at 104 857 600, so a run relying on the old
  meaning writes 4.9 % more before it stops, and `--split filesize:50` rotates
  4.9 % later. Nothing reported the old behavior, which is why it survived: a
  capture that stopped early looks exactly like a capture that stopped when
  asked. Divide by 1.048576 to keep the old byte figure. The conversion now has
  one definition, `capture::writer::mib_to_bytes`, which both conditions read,
  and a test asserts the two agree.
- **The shipped `--group-by` key cap is now the store's, 100000 rather than
  10000.** Its doc comment claimed it "matches the store default so a grouped
  run cannot outgrow an ordinary capture", and that was the stated
  justification for the number while being false by a factor of ten: a
  `--group-by call-id` run over 20,000 calls reported an incomplete grouping of
  a capture the store held whole. The default is now derived from
  `Cli::DEFAULT_DIALOG_LIMIT` rather than restated, so the two cannot drift
  apart again, and `max_grouped_messages` remains the cap that bounds the
  memory.

### Fixed

- **TLS keylog decryption produced nothing for `TLS_AES_256_GCM_SHA384`.** The
  record layer derived its key material with HKDF-SHA256 whatever the cipher
  suite said, because `CryptoBackend::hkdf_expand` had no hash parameter for
  `derive_key_iv` to pass. Every SHA-384 suite therefore derived a key and IV
  that could not open a single record, and nothing said so: the session was
  still logged as ready and the AEAD failure was discarded. That suite is
  OpenSSL's FIRST TLS 1.3 preference, so a default Kamailio, OpenSIPS or
  Asterisk negotiates it — `--keylog` silently decrypted nothing against the
  configuration most deployments run. `tls12_prf` had the same defect for the
  TLS 1.2 PRF, which RFC 5246 also takes from the suite.

- **TLS 1.2 sessions were never built for any suite a deployment negotiates.**
  The cipher-suite table listed eight static-RSA code points and no ECDHE at
  all, so a ServerHello offering `ECDHE-RSA-AES256-GCM-SHA384` (0xC030,
  OpenSSL's default) was unidentified and no session was derived from a
  `CLIENT_RANDOM` keylog entry. The ECDHE, ECDSA and DHE GCM suites are now
  recognized, plus two ECDHE CBC ones. ChaCha20-Poly1305 stays deliberately
  unmapped: the backend implements no such AEAD, so claiming the suite would
  derive key material that can never be opened.

- **HEP export labeled every message UDP.** `build_hep_v3` wrote a literal 17
  into the IP-protocol chunk, three lines after correctly deriving the address
  family from the address. sipnab knows the transport — the pipeline goes out
  of its way to stamp TLS-recovered SIP as `Tls` "so the pipeline parses (and
  reports) the true transport origin" — and then discarded it at the HEP
  boundary, so a collector filtering on transport was given a wrong answer for
  every TCP and TLS capture. The receiving side already honored the chunk.

- **`PR_SET_NO_NEW_PRIVS` is now set on the install sipnab recommends.** It was
  set from inside `drop_privileges`, below the early return taken whenever the
  process is not root — so `sipnab --setup-caps`, which grants
  `cap_net_raw,cap_net_admin+ep` on the binary precisely so capture needs no
  root, ran every capture without it. On that path there is no uid to shed, so
  the flag was the only barrier there was, and it was never raised. It has no
  precondition and cannot be undone, so it moved out of the drop entirely:
  `privilege::block_privilege_escalation()` is called once at startup, on every
  run mode, root or not. **Behavior change:** an event hook
  (`--on-dialog-exec`, `--on-quality-exec`, `--alert-exec`) that relies on a
  setuid helper such as `sudo` will find it unprivileged on an unprivileged
  run. Root runs already behaved this way.
- **Two hardening calls stopped reporting success they had not achieved.**
  `set_no_new_privs` warned on a failed `prctl` and returned `Ok(())` anyway;
  `disable_core_dumps` did the same and then logged "Core dumps disabled
  (decryption active)" unconditionally, so a refused `PR_SET_DUMPABLE` produced
  a warning *and* a confident success line while its caller's `exit(1)` sat
  unreachable. Both now return the failure, and the decision is made per call:
  no-new-privs failing warns and continues (a kernel too old for the `prctl` is
  not a reason to refuse to capture) and reads the flag back with
  `PR_GET_NO_NEW_PRIVS` rather than trusting the return code; core dumps
  failing is **fatal**, which is what the caller already assumed — it runs only
  when decryption keys are resident and `--allow-coredump` was not passed, and
  `--allow-coredump` remains the way to say the trade is acceptable.
- **`CONTRIBUTING.md` no longer claims `license/cla` blocks a merge.** The CLA
  Assistant bot is real and does run — it has commented on every pull request
  since 2026-08-06 and posts a `license/cla` status — but that status is not on
  the branch-protection required list, so nothing enforces it. All nine
  Dependabot pull requests opened since the bot went live still carry a pending
  `license/cla`, and five of them merged that way. The contributing guide now
  quotes the exact sentence the bot accepts as a signature, and states which two
  steps only the repository owner can take to make the check binding.
  `MAINTAINERS.md` gained the owner-side half: the gist that holds the words a
  signer agrees to, and why editing `CLA.md` means editing that gist in the same
  sitting.
- **Two gates over the Contributor License Agreement.**
  `cla_page_reproduces_the_agreement` pins `website/content/cla.md` to `CLA.md`
  byte for byte — the site page is hand-written, not generated, because the
  page generator writes only into `website/content/docs/` and would move it off
  the `/cla/` URL. `the_signing_route_names_this_repository_and_quotes_the_bot_verbatim`
  takes the owner and repository from `Cargo.toml` and checks every
  cla-assistant.io link against it, so a fork or a copied badge cannot send a
  contributor to sign against a different project.
- **`scripts/preflight.sh` no longer reports a gate it never ran as a pass.**
  An absent `vale` or `codespell` printed `WARN` and the run still ended
  "Preflight clean" — right for a contributor who has not installed the tool,
  and wrong for everything else. A background script whose hardened `PATH`
  omitted `~/.local/bin` got exactly that answer with both blocking gates
  silently downgraded, and two Vale errors reached CI. Strictness is now
  decided rather than assumed: `PREFLIGHT_STRICT=1` makes a check that cannot
  run a failure carrying the same install hint the warning carried, `CI` and a
  non-terminal stdout both default to it, and `PREFLIGHT_STRICT=0` keeps the
  warning anywhere. A human at a terminal still only gets warned. Four more
  silent passes went with it: `cd "$(git rev-parse --show-toplevel)"` looked
  like a guard but `cd ""` succeeds, so a run without git measured whatever
  directory it started in; an unreadable `VALE_VERSION` pin skipped the
  version comparison and ran Vale anyway; a site generator that exited
  non-zero read as "the mirror is current" because its status was discarded;
  and an untracked `*.rs` file was invisible to the homepage-count heuristic
  the same way an untracked `*.md` was to the documentation ratchets. Vale
  failing to LOAD its styles now says `vale sync` rather than printing `E100`
  and leaving a reader to think the prose is broken.
- **A capture that begins mid-dialog reports how the call ended.** Starting a
  capture while calls are already up is the normal way this tool is used, and
  it was the case the dialog state machine got wrong: the first message of a
  call was then a `BYE` or a `CANCEL`, the dialog took its label from that
  method, and the state machine dispatched on the label — so every later
  message reached a handler that inspects only responses and has no rule for
  either request. The call sat at `Trying`, reported as still in progress,
  hours after it ended, with a complete message log to make it look right.
  Two operator-visible numbers move as a result: `active_dialog_count` falls on
  any capture that began mid-dialog, and `active_call_count` behaves
  differently. That is the defect being fixed, and it will read as a change on
  a dashboard.

  The dispatch is not the whole fix, and the reason five earlier attempts each
  failed on a different cell is that the family a message belongs to is coarser
  than the transaction it answers. `INVITE`, `ACK`, `BYE`, `CANCEL` and `PRACK`
  share the INVITE dialog family and four of them carry responses of their own,
  so routing by family alone hands `200 OK (CSeq 1 CANCEL)` to the arm that
  establishes a call — and a canceled call then reports `InCall`, counted as a
  channel in use, which is worse than the `Trying` it replaced. The transitions
  now live in one total table keyed on the dialog's family, the transaction the
  arriving message belongs to, and the current state, with no wildcard arm at
  the family or class level and a stated reason on every cell that
  deliberately changes nothing. `docs/design/mid-dialog-state-machine.md` is
  the specification, and its §0 records where that page was wrong.

  Measured over the reference corpus, 61 captures and 39,236 dialogs, before
  and after: 100 dialogs move into `Canceled` — 90 from `Completed`, 8 from
  `Failed`, 2 from `Trying` — and nothing else changes. Every one is a
  canceled call that used to report some other outcome, and `InCall` does not
  move.
- **A call whose `BYE` was lost no longer counts as a channel in use.** A UAS
  answers a `BYE` only after terminating the session ([RFC 3261
  §15.1.2](https://www.rfc-editor.org/rfc/rfc3261#section-15.1.2)), so the
  `200` is proof the call ended even when the `BYE` itself fell outside the
  capture — a dropped packet, a one-directional tap, a rotated file. Such a
  call used to sit in `InCall` until it aged out of the active window.
- **`--stir-shaken` no longer marks every token in a stored capture `Expired`.**
  The RFC 8224 Section 4.4 `iat` freshness window was measured against the wall
  clock, so the answer depended on when you opened the file rather than on
  anything in it: any capture read more than 60 seconds after it was taken
  reported `Expired` for every Identity header in it, including the ones a
  carrier signed correctly, and the one check sipnab does apply locally was
  reporting the age of the pcap. The window is now measured against the capture
  timestamp of the packet carrying the header — the same capture-clock-versus-
  wall-clock distinction `SweepClock` draws for dialog and stream expiry, and
  the scanner and fraud detectors before it. A live capture is unaffected,
  because there the packet's timestamp is the current time.

### Changed

- **BREAKING: `sip::stir_shaken::parse_identity_header` takes the clock as an
  argument.** There is no wall-clock-reading overload beside it, so a later
  caller cannot pick one up by accident. Callers pass the capture timestamp of
  the message; `SipMessage::stir_shaken()` does this for you.

- **BREAKING: `--rtp-interval` is removed rather than accepted and ignored.**
  It parsed, defaulted, documented itself and reached nothing for its whole
  life — the periodic RTP statistics report it named was never built. 0.5.9x
  kept it with a warning so an existing invocation would keep working, which
  left a flag that reads as configured from the outside. sipnab now refuses it
  and names it. Stream statistics are unchanged: they arrive once, at end of
  capture.

- **BREAKING: `rtp::dtmf::extract_dtmf` is removed.** It was a convenience
  wrapper baking in the RFC 4733 default 8000 Hz telephone-event clock, so a
  16 kHz wideband event reported double its true duration to any caller who
  reached for the shorter name. `extract_dtmf_with_clock` takes the negotiated
  rate and is now the only entry point. Nothing in sipnab called the wrapper —
  the batch path already passed the SDP-negotiated rate — so no reported
  duration changes.

### Removed

- **The unwired SDP media-declaration registry (`capture::declared_media`).**
  It was a complete, tested design for vetoing tunnel decapsulation on sockets
  that SDP had declared as media, and nothing in the codebase called `declare`,
  `unless_declared` or `clear`. Its own module documentation described the
  wiring in the present tense, so the rustdoc promised a defense sipnab did not
  have. Retired rather than kept as dead code with an honest sign on it; the
  design is intact in git at 1466cd86 for whoever schedules the work.

## [0.5.99] - 2026-08-13

Four numbers an operator could not reach became settable, a pane stopped
disagreeing with itself, and the MCP surface stopped answering confidently
where it did not know.

### Added

- **Four Tier 1 assumptions are now reachable.** `[limits] max_tcp_buffer` — a
  SIP/TCP or TLS message over 64 KiB was flushed MID-MESSAGE, so both halves
  parsed as malformed and a peer that sent a valid message was reported broken.
  `[diagnosis] cn_suppression_ratio` — comfort noise above 30 percent of packets
  suppressed the one-way-audio finding outright, which on a VoLTE or mobile
  trunk with aggressive VAD is routine, so the most-reported VoIP fault was
  undetectable there.

- **SIP-over-WebSocket now says what it skipped.** sipnab unwrapped it only on
  ports 80, 443, 8080 and 8443, so a deployment terminating WSS anywhere else —
  Kamailio, OpenSIPS and Janus defaults among them, or anything behind a reverse
  proxy — had its entire WebRTC signaling leg vanish, and unlike `--portrange`
  was told nothing at all. `[capture] ws_ports` / `--ws-portrange` sets the
  ports, and sipnab now tallies the SIP-over-WebSocket it declines to unwrap and
  names the ports it arrived on.

Four MCP tools answered confidently and wrongly. The docs described the
behavior honestly; the behavior is what changed.

### Changed

- **Packetization time is derived, not assumed.** `burst_gap_analysis`
  hardcoded 20 ms while the diagnosis path already inferred ptime from
  inter-arrival and validated it, so on G.729 at 30 ms or a satellite trunk at
  40 ms every reported burst and gap was understated by a third to a half.
  sipnab now uses the inferred value, else the SDP `a=ptime`, else 20 ms.

- **BREAKING: `search_messages` returns a page object.** The rows moved from
  the top level into `hits`, beside `returned`, `total_matched`, `truncated`,
  `next_cursor` and `capture_identity` — the shape `list_dialogs` already used,
  for the reason that page gives: a bare array hides its own size. On
  `tests/pcap-samples/sipp-branch-scenario.pcapng`, `{"query":"REGISTER"}`
  returned 50 rows and `limit: 1000` returned 1000, and neither said that 1334
  matched. A client doing `parsed[0]` now reads `parsed.hits[0]`.

- **BREAKING: `security_findings` returns a page object, and refuses an unknown
  `kinds` value.** `[]` used to mean three different things — nothing tripped,
  no detector armed, or a `kinds` name outside the vocabulary. The third is now
  an `invalid_params` error naming `scanner`, `fraud`, `digest`, `reg_flood`
  (and suggesting `reg_flood` for the `reg-flood` spelling `--alert` uses), and
  the second is `armed_kinds` / `detection_armed` / `note` in the response. A
  server watching for scanners alone now says so, instead of answering an
  agent's fraud question with an empty list.

- **BREAKING: `rtp_stats` reports `orphaned` as "no dialog claims this
  stream".** It was a flag a sweep set 30 seconds after an unclaimed stream's
  first packet, so on `tests/pcap-samples/codec-negotiation.pcap` — four
  streams, zero dialogs, three seconds long — all four reported
  `orphaned: false`, and an agent filtering for orphans to find a NAT or
  one-way-audio fault found nothing. It is now derived from
  `associated_dialog`, so the field and the association can never disagree.
  `capture_status.orphaned_stream_count`, `/v1/streams?orphaned=`,
  `sipnab_rtp_streams_total{status}`, the TUI and the `--report` orphan section
  all moved with it: a short unclaimed stream now counts as an orphan
  everywhere. `StreamStore::mark_orphaned` and the 30-second sweep are gone.

- **`search_by_time` carries `next_cursor`** (and `capture_identity`), so
  `truncated: true` is no longer a dead end. Paging a busy window no longer
  means re-cutting it into shorter ones.

- **BREAKING: every MOS sipnab reports is scored on the path delay the capture
  measured, not on an assumed 100 ms.** ITU-T G.107's `Id` term reads a one-way
  delay, and only the TUI's stream-detail pane supplied one. `rtp.mos` in the
  filter DSL, the TUI call list, `StreamSummary.mos` (REST `/v1/streams`, MCP
  `rtp_stats`, the CLI JSON, the TUI's saved stream JSON), REST `?mos_below=`,
  the `sipnab_rtp_mos` histogram, the `--on-quality` alert threshold and the
  browser analyzer all assumed a domestic 100 ms path. They now resolve it the
  way the detail pane does: what the operator declared, then what an endpoint
  reported in an RTCP XR VoIP-metrics block, then what sipnab derives from a
  receiver report's sender-report echo, then the assumption — and say which.
  Measured over 4041 streams of real captures, 558 carry a delay that is not
  the assumption, 556 scores move, 6 move by more than a FULL MOS point, and
  the worst read 4.36 where the truth is 1.00 on a 740 ms path. A `mos` value
  is therefore expected to change for any stream whose call carried RTCP, and
  `rtp.mos < X` now selects calls it used to miss.

- **BREAKING (library): `StreamSummary::from(&RtpStream)` is now
  `StreamSummary::of(&RtpStream, MosDelay)`.** A conversion from a stream could
  not see the delay, because a round trip is not on the stream — it is filed in
  the store's provenance table. `FilterExpr::matches_dialog` takes the same
  evidence as a fourth argument, `sip::dsl::stream_mos` as a second,
  `DashboardSnapshot::from_streams` takes the declared figure, and
  `stream_list::displayed_streams` takes the evidence.
  `sipnab::estimate_mos` is unchanged and still exported; nothing inside the
  crate calls it any more.
### Fixed

- **The stream-detail pane gave two answers about one stream.** The headline
  `MOS:` scored on the measured path while the MOS Trend sparkline drawn beside
  it kept the 100 ms assumption, so a long-haul call rendered `MOS: 1.00`
  against a flat, healthy trend. Both now score on the same delay — as does
  every other surface, per the delay entry above.

- **The documentation gate and its fixer now derive from one list.**
  `repo_paths_in_docs_are_clickable` tells a failing contributor to run
  `scripts/link-repo-paths.py --apply`, and running it damaged the docs: the
  fixer wrote 33 links the gate had never asked for, including branch-pinned
  `blob/main/` URLs into `docs/internals/`, where the gate demands the exact
  opposite and `linked_code_uses_relative_paths` rejects them. The tree list
  behind that rule had been written out six times — in the Rust helper, in the
  gate, once per site generator, and again in the fixer — and the copies
  disagreed. It now lives in `.config/code-trees.txt`: the Rust gates read it
  with `include_str!`, the three generators build their link-rewriting pattern
  from it, and the fixer applies the same `docs/internals/` exemption the gate
  applies, emitting a relative link there and an absolute one everywhere else.
  A dry run against a clean tree now reports zero changes rather than 33.
  `code_tree_list_matches_the_repository` holds the file equal to the
  repository's tracked top-level directories, and
  `no_script_respells_the_code_tree_alternation` fails if anyone pastes the
  list back into a script.

## [0.5.98] - 2026-08-13

An export can no longer destroy a capture, and the last detector with
unreachable thresholds became tunable.

### Fixed

- **`export_capture` and `export_audio` could destroy any file in
  `--mcp-file-root`, and reported success.** The overwrite guard knew only the
  captures the server had opened, so a capture staged in the root for
  `open_capture` — the documented way to hand one over — fell to a name
  collision the moment an agent chose that output name. An audit reproduced it
  twice, losing a 198 KB capture and replacing a staged pcapng.

  All three writers now refuse a name already in use and say which file blocked
  them: `export_capture`, `export_audio`, and `shutdown_server`'s `save_to`.
  sipnab checks the name without following a symlink, so a link is refused as
  itself rather than judged by its target, and a dangling link still counts as
  taken. An agent that means to replace a file picks another name and removes
  the old one deliberately; one that did not mean to cannot lose a capture by
  accident.

### Added

- **Seven `[security] scanner_*` keys, with flags to match.** The scanner
  detector was the last of the three left unwired after 0.5.94 gave the fraud
  and REGISTER-flood detectors their thresholds. Two deployments it got wrong:
  behind an SBC every source collapses to one address, so ordinary aggregated
  traffic tripped a rate detection, and a low-and-slow sweep at one probe every
  ten seconds never accumulated inside the fixed five-second window.

  `scanner_window_secs` is the one that matters for the second case, and it is
  why the window is settable rather than only the counts: no count reaches a
  sweep whose probes never share a window. Every key refuses `0` by name from
  the flag and from the file. `scanner_answer_grace_ms` keeps
  [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) Timer T1 as its default,
  and both references say so.

### Changed

- Every documented link points at `sipnab.com` rather than `www.sipnab.com`.
  The apex answers directly and the `www` host redirects to it, so the old
  links cost a redirect — including the `curl ... | sh` install one-liners,
  where it meant an extra round trip before piping to a shell.

## [0.5.97] - 2026-08-13

Thresholds became settings, and MOS stopped guessing on calls that carried the
answer all along.

### Added

- **The quality color bands are yours.** Eight `[quality]` keys and eight
  matching flags — `jitter_warn_ms`, `jitter_bad_ms`, `loss_warn_pct`,
  `loss_bad_pct`, `mos_warn`, `mos_bad`, `rtt_warn_ms`, `rtt_bad_ms` — set
  where the color column turns yellow and where it turns red. The shipped
  figures suit a general-purpose trunk, and 30 ms of jitter is already a fault
  on a LAN PBX while 1 percent loss is unremarkable on an international one, so
  a column tuned for neither was wrong in both directions. sipnab validates the
  RESOLVED set, after the file and the flags merge, because a warn boundary can
  arrive from one and its matching bad boundary from the other. A boundary that
  is not a finite, non-negative number fails first and for a worse reason:
  every comparison against `NaN` is false, so one would paint the whole column
  green in the middle of an outage.

- **Six caps that truncated an answer or refused a file now move.**
  `[limits] max_lost_sequences` (the Packet Loss Map and the burst/gap analysis
  covered only the tail of a long lossy call), `max_groups` and
  `max_grouped_messages` (`--group-by` could not finish on a big capture),
  `max_metadata_file_bytes`, `max_gunzip_bytes`, and `mcp_max_body_bytes` (an
  agent could not read a whole `INVITE` with a long SDP). The last three are
  memory-exhaustion guards: their defaults do not move, and the reference now
  states what raising each one exposes.

- **Every MCP parameter is answerable where a reader meets it.** The tool
  reference states, for every parameter of every tool, what it is, what values
  are legal, what happens if you omit it, and what comes back. Every JSON
  sample was recaptured from a live server; several had drifted enough to break
  a client written from them.

### Changed

- **BREAKING: detection flags refuse in the default mode instead of warning.**
  `--kill-scanner` and its neighbors were accepted in the interactive mode and
  armed nothing, silently — indistinguishable, from the operator's side, from a
  detector that ran and found nothing. They now exit 2 naming the flag, which
  is the requirement `--fail2ban` already carried. A run that relied on the
  warning will now stop.

- **BREAKING: `--problems`, `--slow-setup` and `--short-calls` read your
  configuration.** They expanded from fixed strings carrying `pdd > 32.0`,
  `rtp.loss > 2.0` and `duration < 5.0` — none of which any operator could
  reach. They now come from the effective diagnosis thresholds, quality bands
  and fraud settings, so tuning `[diagnosis]` to an SLA moves the filter with
  it. `slow-setup` and the post-dial-delay term of `problems` now read the SAME
  threshold; under the old pair a call could be slow enough for sipnab to
  report and not slow enough for `--problems` to select. Expect a different set
  of dialogs from an unchanged command.

### Fixed

- **MOS was assumed on 97 percent of streams that carried the evidence.**
  A round trip derived from a receiver report's sender-report echo now feeds
  the delay term, ranked below a figure the far end reported because it is
  weaker evidence. Measured over a 6635-stream corpus: 2212 streams moved off
  the assumed baseline, and of the 22 sitting past [ITU-T
  G.114](https://www.itu.int/rec/T-REC-G.114)'s knee, 20 lose more than a full
  MOS point — the worst reading 4.36 before and 1.00 after. Those calls were
  being reported as excellent. Note the delay-aware score reaches the TUI only;
  the other surfaces still assume 100 ms.

- **Two gates were reading a fraction of what they claimed to check.** One
  scanned 15 of 1237 lines and reported a fully documented metrics exposition
  while an undocumented family was being emitted. The other kept the wrong side
  of its split, so a single comment swept 3493 of `src/cli.rs`'s 3503 lines into
  a corpus meant to hold only tests — and a new flag's own help text counted as
  its own test coverage. Both now cut at the attribute rather than the text, and
  all four related gates are proven to fail on a real violation.

## [0.5.96] - 2026-08-12

Latency became a first-class number, and a documented threshold became one you
can actually set.

### Added

- **Round-trip time on every surface.** Jitter, packet loss and latency are the
  three numbers that decide whether a call was acceptable. sipnab treated the
  first two as first-class and lost the third: `round_trip_delay` was decoded
  out of the RTCP XR VoIP-metrics block and carried nowhere — zero references in
  the REST API. A call with clean jitter and no loss can still be unusable on
  delay alone ([ITU-T G.114](https://www.itu.int/rec/T-REC-G.114)), and sipnab
  called it healthy.

  It now reaches MCP, the REST API, the TUI and the web UI, with
  `round_trip_source` naming where it came from:

  | Source | What it is |
  |---|---|
  | `xr_voip_metrics` | The reporting endpoint's own round trip between the two RTP interfaces. The quantity G.114 is about. Accurate, and rare — most stacks never emit an XR |
  | `sender_report_echo` | Derived from a receiver report's `LSR`/`DLSR` pair per RFC 3550 §6.4.1. The full round trip when the capture point sits with the sender of the SR, a lower bound otherwise |

  The second source is why this is useful at all: plain receiver reports are
  mandatory, so latency is now available on almost every call rather than the
  few carrying an XR. The figure is anchored on the CAPTURE clock, so it is
  correct on an offline pcap.

  **Absent is not zero.** Where nothing reported a round trip the key is
  omitted, the TUI shows `n/a`, and MCP says latency is unknown rather than
  good. A measured zero still reports as zero.

- **Seventeen thresholds that were tunable in signature and fixed in practice.**
  Each took a parameter, was documented as configurable, and had no production
  caller that ever supplied one: the REGISTER-flood rate, the scanner-kill
  transmit budget, five fraud constants, the off-hours window (which made a
  documented detector unreachable), three signaling-diagnosis timers, three
  media-asymmetry thresholds, the per-rule lint cap and the findings history.
  All now carry a flag and a config key. Signaling and media thresholds moved
  to a new `[diagnosis]` section — they decide whether a WORKING call gets
  reported as broken, which is neither `[security]`'s question nor `[limits]`'.

### Fixed

- **`--kill-rate-limit` did not do what its own help text said.** "`0` is
  refused" was true of the config key and false of the flag: the check lived in
  `SecurityConfig::validate`, which guards the config file. Two spellings of one
  policy that disagreed, with the documentation describing whichever one the
  reader was not using. The flag now refuses it too. (Reading the limiter
  settled what 0 would have done — it denies everything, so this was
  fail-closed, not the reflector the wording implied.)

- The multi-node MCP walkthrough's transcripts were real output from 0.5.87,
  eight releases back, presented as current behavior. Re-run end to end
  against this release rather than search-and-replaced.

### Documentation

- A line citation now has to point at the code it names.
  `maintainability-perf-spec.md` cited `src/main.rs:1996` in a file 172 lines
  long. Twenty-one drifted citations corrected, and
  `scripts/check-line-drift.py` is both the gate and the fixer, so the two
  cannot diverge.
- A design doc claiming something is unbuilt must evidence that against the
  tree that would hold it. `live-fanout.md` said "Nothing here is implemented"
  over a grep of `src/cli.rs` — which proves no FLAG reaches the feature, while
  221 lines of `src/capture/fanout.rs` sat outside what the command could see.

## [0.5.95] - 2026-08-12

sipnab no longer discards captured data without a knob or a word.

### Fixed

- **`active_call_count` grew with uptime, not concurrency.** Nothing aged an
  `InCall` dialog out, so a call whose `BYE` was never captured — a lost
  teardown, a truncated capture, a leg that simply stopped — counted as up
  forever. A soak harness read **38,509 active calls against 100 RTP streams**.
  Dialogs now leave the count after an idle window of 3600s, twice RFC 4028's
  default `Session-Expires`, so a session-timer refresh keeps a live call
  counted. The window is measured from the newest message in the store rather
  than the wall clock: an offline capture would otherwise age every dialog out
  at once.

- **A SIP/TCP message over 64 KiB was cut in half in silence.** It is flushed
  mid-message and parses as malformed, so an operator sees a broken message
  from a peer that sent a good one. An over-cap SCTP message is worse — dropped
  whole, so the calls it carried never appear at all. Neither ceiling comes
  from TCP or from RFC 4960; both are sipnab's, and both now say so on stderr.

- **The same stream was `Good` in the call list and `Warning` in its own detail
  view.** Four views banded jitter, loss and MOS independently and disagreed:
  25 ms jitter was good under one set of thresholds and a warning under
  another. `loss_map.rs` even documented an agreement it did not have. One
  `QualityBands` now answers for every view.

- `PacketProcessor::with_max_sessions` passed an inline `Duration::from_secs(30)`
  instead of `reassembly::DEFAULT_TTL` — two spellings of one policy that
  happened to agree, so changing the constant would have moved the default
  everywhere except the path every live capture takes.

### Added

- **`[limits] idle_compact_after_secs` and `keep_messages_per_idle_dialog`.**
  Idle compaction is the only limit that discards data sipnab already captured
  — every other one refuses to take something in — and it was the only one an
  operator could not reach. Raise them when the ladder matters more than the
  footprint: a call parked on hold, or a paused capture, goes quiet for longer
  than ten minutes while still being the thing under investigation. Compaction
  also warns once per run when it first drops messages, naming both keys.

### Documentation

- Nine cross-page contradictions resolved, each checked against source rather
  than against another page: recipes that bound `--api` and `--hep-listen` to
  `0.0.0.0` without credentials (those commands exit non-zero at startup), the
  `--problems` flag versus the `problems` filter alias, `--rotate`'s default,
  `/v1/dialogs` field names, the default Cargo feature set, and memory per call.
- Five design docs claimed unbuilt work that had already shipped — one of them
  was overtaken 36 minutes after it was written.
- `check_codec_negotiation` returns **five** results, not four;
  `sdp_present_but_no_codecs` is documented for the first time.
- The `contrib/observability` systemd unit and README shipped commands that
  refuse to start. Both now carry the credential flags that make them run.

## [0.5.94] - 2026-08-12

What sipnab claims about itself is now checked against what it does.

### Changed

- **The site and README stated things that were not true.** Every number here
  was checked against the source it describes, not against the previous copy:

  - The homepage advertised **24** MCP tools in prose and **31** in the tile
    beside it, and README said **25**. There are 31 — confirmed by asking a
    running server for `tools/list` and by counting the registrations.
  - "none of them alters the analysis" was wrong: 5 tools carry
    `read_only_hint = false`, and `open_capture` swaps the capture being read.
    The page now says which 5 and that each stays off until enabled.
  - The filter DSL has **30** fields, not 31.
  - HEP **sending** is v3 only; v2 appears on the receive path.
  - The recommended static musl build omits `plugins` as well as `audio`, so
    `--plugin` does not exist in it — the download page said audio alone, and a
    reader would go looking for a flag that was compiled out.
  - The download page's asset arithmetic named 19 files and claimed 23. The
    real release has 23: it never mentioned the 6 `.sha256` sidecars and
    counted 2 source archives GitHub synthesizes rather than publishes.
  - The homepage said "one dependency" where the download page said "zero";
    both were true of different builds, and neither said which.

  The throughput tile is the interesting one. It was authored `2.32` and
  rendered `2.3`, because the count-up animation ended in `toFixed(1)` — so
  only readers with `prefers-reduced-motion` ever saw the measured value. The
  authored number is correct and a test pins it, so the ANIMATION was fixed to
  take its precision from the attribute rather than the authored value being
  rounded to match the bug.

- **The MCP server told every agent something no longer exact.** Its
  instructions said "No tool alters the analysis", which stopped being true
  when `open_capture` gained the ability to swap captures — the second time
  that sentence drifted. It now states the invariant that actually holds and
  that `docs/internals/invariants.md` argues for: a swap is allowed, gated, and
  impossible to hide, because every response names the capture it answered
  from.

### Added

- **A gate for the invariant two other gates silently depend on.** The homepage
  advertises one automated-test count, and two gates pin it to a measurement:
  the pre-commit hook counts `cargo test --features full`, CI counts `cargo
  test --all-features`. One number, two suites. They agree only because those
  feature sets differ by exactly `wasm` and nothing is tested behind it — a
  coincidence with nothing holding it. One `#[cfg(feature = "wasm")] #[test]`
  would make the number unsatisfiable by construction: the hook demands N, CI
  demands N+1, and the fix for one gate breaks the other.

  The commands cannot simply be merged — CI needs `--all-features` for
  `plugins`, whose test builds for `wasm32-unknown-unknown`, a target CI
  installs and a contributor may not have. Both are right; what has to hold is
  the relationship between them, so that is now a test. It derives the feature
  gap from `Cargo.toml` rather than hard-coding `wasm`, catches both ways a
  test can be gated, and names the offending file and line. Both gates now
  carry a comment pointing at it.

- **The browser analyzer opens a capture inside a zip or tar.** Dropping a
  `.zip` produced "does not look like a capture file" — and zipped is how
  shared captures actually arrive: conference material, incident-response
  bundles, vendor escalations. The page turned away the common case and sent
  the reader off to find a shell, on the one page whose promise is that no
  install is needed.

  zip (stored and deflated) and tar are now unwrapped in the page, and the
  capture inside is analyzed. Nothing leaves the browser and nothing is added
  to the bundle: `DecompressionStream` is a browser built-in, which also
  matters because the site's CSP forbids loading a third-party zip library.
  Verified byte-identical extraction from a deflated zip, a stored zip and a
  tar built from a real sample.

  Members are located through the zip central directory rather than local
  headers, which may carry zeroed sizes with a trailing data descriptor — the
  shape a streamed archive has, and so the shape most likely to be shared.

### Fixed

- **The browser size guard measured the wrong number.** `file.size` is the size
  ON DISK, so a 200 MB gzip expanding to 2 GB passed the guard whose entire
  purpose was to stop the tab freezing — wrong in the dangerous direction. The
  uncompressed length is knowable without decompressing: gzip stores it in the
  ISIZE trailer and zip in its central directory. Checked against a real
  fixture, ISIZE reports 198831 bytes for a file that is exactly 198831 bytes.

- **A failed analysis asked every user to file a bug.** The catch-all ended
  every parse failure with "please open a GitHub issue", including truncated
  downloads and files that were never captures — blaming the tool for the input
  and sending noise to the tracker. It now invites a report only when the bytes
  really did look like a capture, and otherwise says what to check.

- **A refused `--metrics` endpoint let the run report success.** sipnab
  correctly refuses an unauthenticated non-loopback metrics bind, then logged
  the refusal and carried on, exiting 0. `sipnab --metrics 0.0.0.0:9109 && echo
  up` printed `up` with nothing listening: the scrape endpoint never arrives,
  and the exit status says it did.

  `--api` enforces the same policy on the same kind of bind and fails the run,
  exiting 2. Two flags, one policy, opposite exit codes — measured, not
  inferred. The metrics startup error now propagates like its sibling's, so
  both exit 2 and a loopback bind still starts.

- **Six documented commands failed when a reader pasted them.** Each was run
  before and after, not read:

  - The flagship capture-tuning recipe passed both `-N` and `--no-tui`. They
    are the same flag, so clap refused the repeat and the recipe exited 2.
  - `--tshark-filter` was shown sipnab's own filter DSL. The expression is
    handed to tshark's `-Y` verbatim, so it needs WIRESHARK syntax: tshark
    answered `'1001' is too long to be a valid character constant` and
    `"=" was unexpected in this context`. The emitted command was also
    mis-quoted, collapsing `-Y 'from.user == '1001''` in the shell.
  - Five `curl` examples posted `tools/call` with no `Mcp-Session-Id`. The
    Streamable HTTP transport answers `422 Unexpected message, expect
    initialize request`. The walkthroughs now capture the session id the
    server returns and send the `initialized` notification first.
  - A MOS example asserted exact float equality against a computed value. The
    real result is 4.33709615132886; the crate's own test uses a 5e-4
    tolerance, and the example now does too.

  Two failed SILENTLY, which is worse than failing:

  - `jq -r '.user_agent // empty'` for "distinct User-Agents". The field is
    `ua`, so the pipeline matched nothing and `// empty` swallowed the miss —
    a reader got zero lines and concluded the capture had no User-Agents.
  - `jq -r '.status_code'` counted `null` as a status code, because requests
    have none. It now selects responses first.

  A new gate makes the silent class impossible to reintroduce: every field the
  docs tell a reader to `jq` must exist in the output that same block produces,
  checked against real captures. It found a seventh case on its first run —
  which turned out to be the gate's own blind spot rather than a doc error, and
  the fixture set was widened rather than the documentation "corrected".

- **Two documented config keys were silently ignored.** `[display] color` and
  `[security] kill_response` were parsed, validated and documented, and
  changed nothing. Both flags carried a clap `default_value`, which fills the
  field whether or not the operator types the flag — so "not given" and "given
  the default" were indistinguishable and the config key had nothing left to
  override. Both now resolve as flag, then key, then a named default, the way
  every other setting in the file already did.

  Proved by measurement rather than inspection: the same capture read with
  `[display] color = "always"` produces no ANSI escapes on the previous build
  and colored output on this one.

  `[security] kill_response` also gained the range check its flag always had.
  `--kill-response 9999` is refused by clap, while the config file accepted it
  and put a malformed status line on the wire — the file must not be the
  lenient way in. `[security]` is now validated at startup alongside
  `[limits]`, naming the key and the offending value.

  The tests that let this ship asserted `cli.color == "auto"` — the field clap
  had just filled, which passes identically whether the key works or not. They
  now assert the resolved value, and two new probes drive the real binary and
  the real wire bytes.

- **`rtp.mos < 3.0` reported that every call had bad audio.** A dialog with no
  RTP has no MOS, but the filter substituted `0.0` for "never measured" — and
  `0.0` is below every threshold anyone would type. REGISTERs, OPTIONS and
  failed INVITEs, none of which carry audio to judge, came back as the
  worst-sounding calls in the capture: 2292 of 2311 dialogs on one real trunk
  capture, against 2 genuine ones.

  Five fields did this — `pdd`, `setup_time`, `rtp.mos`, `rtp.jitter` and
  `rtp.loss`. An unknown now matches no numeric comparison, `!=` included: it
  is not "different from 3.0", it is unknown, which is the rule SQL uses for
  `NULL`. Fixing only `rtp.mos` would have left the identical trap in four
  fields beside it, so the rule lives in one comparison helper.

  Nothing is lost by it. To select the calls carrying no media, ask for that
  directly — `rtp.packets == 0` is a real count of zero, and `no_media` is the
  diagnosis itself. A saved filter carrying `AND rtp.packets > 0` as a guard is
  now redundant rather than wrong.

  This was one line of code behind three reports: the TUI's F7 filter, the same
  filter in the browser analyzer, and a `setup_time` p95 quietly padded with
  calls that were never timed. The browser build corrects on its next CI build,
  which now happens every push.

- **A call report showed `Setup: -27.98s`.** A negative duration is not a
  measurement. The capture had opened after the call was already up, so the
  dialog's first message was the 200 OK of an INVITE transaction that had
  already finished, and 28 seconds later the far end sent a re-INVITE. sipnab
  took `invite_sent` from that re-INVITE and `answered_at` from the earlier
  transaction, then subtracted one from the other.

  Two rules now stand between those milestones and a number. An INVITE that
  carries a To-tag is in-dialog (RFC 3261 §8.1.1.2) and is never recorded as
  the call's first INVITE, so a re-INVITE cannot start the clock however late
  the capture began — the message says so itself, rather than the answer
  depending on what the recording happened to catch. And no derived interval
  is ever negative: where the milestones cannot belong to one transaction, the
  time is reported as unknown rather than as a duration.

  Matching CSeq numbers could not have caught this. Each side of a dialog keeps
  its own CSeq space (RFC 3261 §12.2.1.1), and here both were at 102.

  Across a 2,740-dialog corpus the fix withdraws 11 setup times, every one a
  session-timer re-INVITE (RFC 4028, `Session-Expires: 1800;refresher=uac`)
  whose 164 ms round trip had been published as a call's setup time. No call
  that was genuinely timed loses its measurement.

  The rules live in the timing accessors, which every surface reads, so the
  call report, `--json-dialogs`, REST, MCP, the DSL's `setup_time`, the TUI
  timeline and the WASM build all correct together.

## [0.5.93] - 2026-08-11

MOS stops guessing, and the browser analyzer stops being eleven releases old.

### Added

- **One-way delay is an input to MOS, not a constant.** `estimate_mos` assumed
  100 ms of network delay and fed it to G.107's `Id` term for every score
  sipnab reported. G.107's delay penalty has a knee at 177.3 ms, so the
  assumption did not merely shift the answer, it kept the calculation on the
  wrong side of that knee: at a true 300 ms one-way, sipnab reported **4.35**
  where the truth is **1.00**. A satellite leg was called excellent.

  `--one-way-delay`, or `[media] one_way_delay_ms`. The figure is resolved in
  order — what the operator declared, then a round trip the far end reported in
  an RFC 3611 VoIP-metrics block (halved), then the assumption — and the stream
  detail says which of the three it used: `(delay 280ms declared)`,
  `(delay 225ms per far end)`, `(delay 100ms assumed)`. The remedies differ,
  which is why the source is shown: a wrong declared value is yours to fix, a
  wrong reported one means suspecting the endpoint, and an assumed one means
  the delay was never known.

  The operator's figure wins because it is the only one no packet on the wire
  can change. The default is unchanged at 100 ms, so no existing reading moves.

- **`--mcp-max-rows` / `[limits] mcp_max_rows`.** The MCP response ceiling was a
  compile-time constant. The right value belongs to the consumer — a
  small-context agent wants far fewer than 1000 rows, a batch client piping to
  a file wants far more.

### Fixed

- **The browser analyzer at sipnab.com/analyze ran a 0.5.80 build.** `zola
  build` copies `static/` verbatim, so the committed WASM was what shipped, and
  nothing rebuilt it. Eleven releases of analysis fixes never reached anyone
  using the page. It is rebuilt, and `pages.yml` now builds it from source, so
  the committed copy is no longer what ships.

- **A dialog with one endpoint drew no ladder.** Where a PBX talks to itself —
  every message `10.0.0.1:5060 -> 10.0.0.1:5060`, as any hairpinned leg looks
  when captured at a single tap — the participants collapsed to one column and
  the arrow was skipped, leaving a sized, empty pane beside a detail view
  showing the whole message. Self-messages now draw the way a sequence diagram
  draws them.

- **`--filter "rtp.mos < 3.0"` scored streams differently from the display.**
  The DSL carried its own formula with no codec term and no delay term,
  diverging from the E-model by up to 1.7 MOS, so the filter selected calls the
  detail view showed as fine. One scorer now, and a gate that fails if a second
  appears.

- **RUSTSEC-2026-0253** — `lru` 0.18.0 to 0.18.2, a potential use-after-free
  from missing panic safety in `LruCache::pop()`.

## [0.5.92] - 2026-08-11

Remote capture becomes usable on more than one box, and on RHEL.

### Added

- **`--hep-send` forwards RTCP, not only SIP.** RTCP now travels as HEP
  protocol type 5 alongside signaling as type 1, so a remote collector can
  report media quality — loss, jitter, MOS — rather than only whether calls
  connect. The receiving half of `capture/hep.rs` has understood type 5 since
  it was written; only the sender never emitted it, which made a remote viewer
  strictly worse than running sngrep on the box, because sngrep at least sees
  the media.

  **RTP is not forwarded.** RFC 3550 §6.2 holds RTCP to a small fraction of
  session bandwidth, so the quality summary crosses at a rate a WAN link and a
  UDP feed can absorb. Media is the opposite on both counts, and forwarding it
  would turn a monitoring feed into a call recorder aimed at the collector.

  The `-I <file>` export notice moves with the behavior rather than after it.
  It exists because naming the socket described the plumbing and not the
  consequence, and a notice that still said "every SIP message" while RTCP also
  left the machine would have reintroduced exactly the silence it was written
  to end. It now names both, and says the audio is never forwarded.

- **Exported frames carry the sender's identity.** Every HEP frame now sets the
  capture-agent chunk (`0x000c`) and labels itself `{id}@{peer}`, so a
  collector receiving a fan-in from several SBCs can tell which box a leg came
  from. Frames from every node previously arrived indistinguishable, which left
  multi-node capture — the reason to run HEP export at all — unable to answer
  the first question anyone asks of it.

### Changed

- **The MCP walkthrough's smoke test called the tool this release removes.**
  `docs/mcp-walkthrough.md` Step 0 -- the first thing an operator runs to check
  their server works -- called `stats`, so a CORRECTLY working server answered
  "tool not found" and the page told them it was broken. Caught by an audit of
  this release, not after it. It now calls `capture_status`.

- **BREAKING (MCP): `stats` is gone; `capture_status` replaces it.** Capture
  health was split across two tools that had to be called together and
  reconciled by the caller, so the first question an operator asks — is this
  capture healthy enough to trust what it is telling me? — cost two round trips
  and some arithmetic. `capture_status` answers it in one call and adds
  `orphaned_stream_count`, `active_dialog_count`, `active_call_count` and a
  `capture_quality` summary. The MCP `schema_version` moves 1 → 2; a client
  pinned to `stats` must move to `capture_status`.

### Fixed

- **The installer failed on every RHEL-family host.** `parse_glibc_version`
  read a fixed field position that is only correct on Debian and Ubuntu, so
  RHEL, Rocky, Alma and Fedora all reported `no glibc detected` and fell
  through to the musl build. It now reads the version from the end of the line,
  where every distribution puts it, and the test matrix covers RHEL 8/9/10,
  Fedora, Gentoo and Alpine rather than Debian alone.

- **`sudo sipnab` reported "command not found" after a successful install.**
  RHEL's `secure_path` excludes `/usr/local/bin`, so the binary the installer
  had just placed was invisible to the one shell that most needs it. The
  installer now detects this and prints an invocation that works.

- **The capture-permission error named `CAP_NET_RAW` and stopped there.** It
  told an operator which capability was missing but not how to obtain it, which
  is the only part they needed. It now gives the `setcap` command.

- **The call list rendered distinct hosts identically.** Source and destination
  truncated to 11 cells, so `10.0.0.41` and `10.0.0.412` — different endpoints
  — displayed as the same string, and the header set a background color
  without ever setting a foreground, leaving it unreadable on light terminals.
  Addresses now elide in the middle, keeping both ends, and the header derives
  its foreground from the background's luminance.

- **Documentation bookmarks resolved to the wrong section.** Zola strips a
  trailing `{...}` from a heading before slugifying, so `GET /v1/dialogs/{call_id}`
  and `GET /v1/dialogs` produced the same anchor and the second became
  `…-1` — a suffix that moves whenever a heading is added above it. Path
  params are now written `:call_id`, repeated headings in three design
  documents name the feature they belong to, and a gate refuses any two
  headings that slugify alike under GitHub, Zola or wiki rules. Repo paths in
  the docs are links rather than bare code spans, and sample captures point at
  `/raw/` so they download instead of rendering as markup.

## [0.5.91] - 2026-08-10

Most of the 0.5.84 throughput regression, recovered.

### Changed

- **`--cores` reconstruction is ~23% faster at four cores**, measured
  interleaved against 0.5.90 on the reference host:

  | cores | 0.5.90 | 0.5.91 |
  |------:|-------:|-------:|
  | 4 | 1.84–1.90M | **2.28–2.29M** |

  For scale: 0.5.47, measured before the 0.5.84 regression, reached 2.02M at
  four cores. This is **faster than sipnab has ever been on this corpus**, not
  a recovery to where it was.

  Two changes, both found by profiling after a bisect had blamed the wrong
  thing entirely.

  **The frame pointer.** `parse_packet` built a `FrameRef` for every packet.
  A `FrameRef` owns an `Arc<str>`, so that is one atomic increment per packet
  and a decrement when it drops — for a pointer roughly **93% of frames never
  keep**. `ParsedPacket` now carries a `Copy` locator and the two sites that
  actually retain a pointer build the owned one: ~35,000 materialisations
  instead of 535,000.

  **The frame bytes.** The reader called `pkt.data.to_vec()` per frame and a
  *worker* freed it, so the allocator's cross-thread path ran 535,000 times.
  Frames are now cut from a shared 64 KiB block, so one allocation serves ~270
  frames and both it and its free amortise across all of them. This landed
  above its own predicted ceiling, because frames sharing a block are also
  sequential in memory.

  `parse_packet` built a `FrameRef` for every packet. A `FrameRef` owns an
  `Arc<str>`, so that is one atomic increment per packet and a decrement when
  it drops — for a pointer that roughly **93% of frames never keep**. A
  profiler put ~40% of the packet path in outlined atomics with this as the
  second-largest driver; the bisect that preceded it had blamed hashing, and
  was wrong.

  `ParsedPacket` now carries a `Copy` locator — the same `FrameOrigin` plus an
  interned source — and the two sites that actually retain a pointer build the
  owned `FrameRef` themselves. On the benchmark corpus that is ~35,000
  materialisations instead of 535,000.

  Four cores reaches the ceiling a diagnostic build predicted for removing the
  provenance stamp **entirely**, so this captures essentially all of the
  available win at the operating point the tool comparison and the nightly gate
  use.

  Nothing about provenance changes. `frame_ref()` is untouched and still a pure
  accessor; `frame_digest` keeps its published FNV-1a vectors, so every stored
  pointer still verifies; and the parse-boundary test now asserts the locator
  round-trips to the *identical* `FrameRef` the old path built.

### Added

- **A multi-file provenance gate for the parallel reader.** The existing gate
  covered only the single-threaded path, so a reader that stamped one source
  for every packet would have passed every test while pointers from the second
  file silently named the first. Written and mutation-proved *before* the
  change above, since that is the property it could plausibly break.

### Fixed

- **`actions/checkout` left `GITHUB_TOKEN` in `.git/config`** on 26 of 27
  steps, where any later step or third-party action could read it. All 27 now
  set `persist-credentials: false`. Nothing depended on the persisted
  credential — the two workflows that write pass the token explicitly.

- **`font-src` omitted `'self'`**, overriding `default-src` rather than adding
  to it, so a self-hosted font would have been blocked. Fixed in all three
  places the policy is defined.

- **Concurrent CI jobs raced for `apt`'s machine-wide lock**, failing with
  `Could not get lock /var/lib/dpkg/lock-frontend` before compiling anything.
  Steps now check `dpkg -s` first.

### Dependencies

- **`rmcp` 3.0.1 → 3.1.1**, which carries the upstream fix for
  [SEP-2260](https://github.com/modelcontextprotocol/rust-sdk): an MCP *client*
  accepted restricted server-to-client requests (`sampling/createMessage`,
  `roots/list`, `elicitation/create`) without confirming they belonged to the
  originating request context, so a malicious server could drive client-side
  capabilities as a confused deputy. The fix rejects unassociated restricted
  requests with `-32602`.

  **sipnab was never exposed to it.** `rmcp` is declared
  `default-features = false` with only the `server` feature, and there is no
  client handler in the tree — sipnab is the server in every deployment, so it
  never occupies the vulnerable role. The bump is taken because running a
  version with a known advisory invites the reachability argument on every
  scan, not because anything here was reachable.

  Also `base64` 0.23.0 → 0.23.1 and `jsonschema` in the same group. `rmcp-macros`
  pulls in `darling`, `darling_core` and `darling_macro` as new transitive
  dependencies; `THIRD-PARTY-NOTICES.md` records them, since that file is
  generated from the dependency graph rather than maintained by hand.

## [0.5.90] - 2026-08-09

Profiling, and what it overturned.

### Changed

- **The packet path was profiled, and the answer was not what bisection said.**
  `perf` over the profiling build puts **~40% of samples in outlined atomics**
  — `__aarch64_ldadd8_relax`, `__aarch64_ldadd8_rel`, `__aarch64_cas8_acq_rel`,
  `__aarch64_swp4_rel` — reproduced on both the 535k and 2.14M corpora.
  `frame_digest` does not appear in the top 18 symbols at all.

  The drivers, by nearest caller: mimalloc's cross-thread free path, then
  `parse_packet` cloning an `Arc<str>` per packet for a pointer ~93% of frames
  discard, then `bytes` refcounting. The reader allocates every packet with
  `pkt.data.to_vec()` and the workers free it, so the allocator's cross-thread
  path runs 535,000 times.

  PERF1 had said the cost was hashing every frame. That came from a bisect and
  a diff, and it was wrong. `docs/design/packet-path-allocation.md` records the
  measurement, the corrected diagnosis, and the fixes that follow from it.

- **Both proposed fixes were measured before either was implemented**, and the
  numbers reversed their order. P1 (build no `FrameRef` for frames that keep no
  pointer) is worth **+13% at two cores and +10% at four**. P2 (stop allocating
  per packet on the reader) is worth **+16% at two cores and nothing at four** —
  and four is the operating point the tool comparison and the nightly gate both
  use. P1 goes first.

  One of those measurements was initially wrong in a way worth recording: P2's
  first diagnostic ended in `b.clone()`, allocating a fresh `Vec` per packet, so
  it kept the allocation it meant to remove. It reported "no improvement", which
  would have killed a real change on the strength of a harness bug.

- **P1's design is decided and specified, not yet built.** Its two consumers
  cannot reach the `Packet`, so the source must arrive as something `Copy`: the
  reader keeps a small `Vec<Arc<str>>` and stamps a source index beside each
  ordinal, and the two retention sites build the `FrameRef` themselves.
  `FrameRef` is unchanged, so `--json`, the REST API and MCP keep their shape
  and every stored pointer still resolves.

### Added

- **A nightly throughput gate** (`bench.yml`, `bench/regression-gate.sh`,
  `bench/baseline.json`). Nothing in this repository measured speed, which is
  why a 40% regression shipped in four consecutive releases. Verified against
  the actual history rather than asserted: 0.5.88 measures 70.4% of baseline
  and fails; 0.5.83 measures 106.9% and passes.

- **`docs/internals/profiling.md`** — how to profile on this hardware without
  relearning it, including that plain `perf` reports "not found for kernel
  6.8.12-rt" while the working binary sits in `/usr/lib/linux-tools`.

- **`scripts/preflight.sh`** — the gates that actually bounce a commit, in about
  a minute, instead of discovering them from a 25-minute hook run.

### Fixed

- The license appeared twice on the homepage; the pill is gone and the footer
  credit stands. The signed-provenance badge now links to the instructions for
  verifying a download rather than to a raw attestations list.

## [0.5.89] - 2026-08-08

A 40% throughput regression that shipped in four releases, found because the
benchmarks page finally got re-run instead of re-dated.

### Fixed

- **`--cores` throughput lost 40% in 0.5.84 and nobody noticed for four
  releases.** Bisected against checksum-verified release artifacts on the
  reference host, fixed-state 535k-packet corpus, two cores, interleaved
  replicates: 0.5.83 measures 2.27-2.34M pkts/s and 0.5.84 through 0.5.88
  measure 1.37-1.42M. In the same runs voipmonitor measured 0.40M in both
  arms, exactly, so this was not host drift.

  The cause was the frame-provenance stamp added in 0.5.84. It fixed a real
  bug -- the parallel path was silently dropping frame pointers on exactly the
  large captures where provenance matters most -- but it computed the digest on
  the **serial reader**, the one stage the whole `--cores` design waits on: a
  single thread reads, copies and host-pair-peeks every packet while N workers
  idle. That charged it ~240 bytes of dependent FNV multiplies per packet, or
  129 MB hashed one byte at a time on this corpus.

  The digest is a pure function of bytes the reader has already finished with,
  so the workers compute it now. The reader still stamps the ordinal, which is
  the one fact only it can know. **Same input, same FNV-1a, same value** -- a
  pointer from a `--cores` run resolves identically to one from a
  single-threaded run, and stored pointers are unaffected. Measured 1.64-1.66M,
  **+18%**.

  That is a third of the loss, and the rest is written down rather than
  implied. Roughly 20% more is hashing every frame when only a *retained*
  pointer needs one -- a dialog's `first_frame`, a stream's `first_frame`, a
  finding's `frame_ref`, which on this corpus is ~35k of 535k frames. Two
  obvious shortcuts are already ruled out by tests that predate this work:
  computing it in `frame_ref()` breaks that method's pure-accessor contract,
  and a faster hash is barred by the FNV-1a spec vectors that exist so a stored
  pointer still verifies against a future build. A further ~12% is not the
  digest at all and is unidentified. All of it is PERF1 in
  `docs/design/backlog.md`.

  **Nothing in CI measures throughput**, and `docs/benchmarks.md` was 41
  releases stale. That combination is why this shipped four times.

## [0.5.88] - 2026-08-08

Two call legs learn they are one call, a laptop learns to follow that call
across three boxes without an agent in the loop, and a doc comment stops
claiming a field that was never there.

### Added

- **Correlation on RFC 7315 `P-Charging-Vector`, as two strategies rather than
  one.** In IMS and carrier networks this header is already on the wire, so it
  correlates a call across nodes with no configuration change from the
  operator — unlike RFC 7989 `Session-ID`, which is the durable fix but needs
  the SBC touched.

  It went in as two reasons because the RFC makes them two different claims,
  and the difference is the whole point:

  | Strategy | Score | What a match means |
  |---|---|---|
  | `charging_vector_related_icid` | 95 | one leg's `related-icid` names the other's `icid-value` — the intermediary **declared** the link |
  | `charging_vector_icid` | 85 | plain `icid-value` equality — an intermediary carried a per-dialog identifier onto a second dialog |

  **Plain `icid-value` does not cross a B2BUA, and a design that assumes it
  does is wrong about the case it was built for.** §4.6 scopes the value to "a
  dialog or a transaction outside a dialog" and makes uniqueness a MUST, so a
  conformant back-to-back user agent emits a *different* icid on each side.
  §4.6.4.1 is the parameter that survives it: a B2BUA MAY add `related-icid`
  carrying "the icid value of the original dialog towards the remote end".
  Plain equality across a re-origination is a vendor behavior, not a
  guarantee, and it scores accordingly.

  Both report `identifier_match: true` — an icid comparison compares values,
  not timing — so `heuristic_only` stays false on an icid-only match.
  **Neither value ever reaches a response.** §4.6's suggested construction
  embeds the generating proxy's hostname, so the identifier is
  operator-internal by design and only the strategy name is surfaced.

  Two limits worth knowing before planning around it. The first proxy
  generates the icid (§5.6), so the leg arriving from an endpoint carries
  none — this helps on internal hops and **not at the access edge**. And there
  is no cardinality guard: a proxy that stamps one icid on every dialog would
  make plain-icid matching a false-match generator. No threshold was invented
  for it, because every candidate number was arbitrary;
  `docs/design/icid-correlation.md` records it as open.

  The header parser is quote-aware (RFC 3261 `quoted-pair` escapes included)
  and compares parameter names by equality rather than containment, so
  `x-icid-value`, `related-icid-value` and `related-icid-generated-at` are not
  mistaken for the thing. It refuses rather than guesses on an empty value, an
  unterminated quote, text after a closing quote, or two disagreeing copies of
  one parameter. `icid-generated-at`, `orig-ioi`, `term-ioi` and `transit-ioi`
  are never read at all, and a test proves two legs sharing a generating
  address do not correlate.

- **A step-by-step walkthrough for watching one call cross an SBC, a proxy and
  a PBX**, in `docs/mcp-walkthrough.md`, written for the case where a box runs
  back-to-back on one call and as a proxy on the next. That is the case where
  no strategy can be chosen in advance, so the page teaches reading what
  matched — the `strategy` and `identifier_match` the answer carries — instead
  of predicting the topology. A proxy-mode hop returning **zero** correlated
  legs is a finding, not a failure: the Call-ID crossed unchanged and the same
  id is what to ask the next node for.

  It also covers the wiring for readers who do not have direct reach: SSH
  tunnels per node, NAT (the tunnel dials outward, so nothing changes), and a
  jump host via `ProxyJump` in the SSH config rather than in the sipnab
  configuration.

- **`contrib/mcp/trace-call.py`** — follows one call across several nodes with
  no interactive agent. Standard library only, because a support laptop may not
  permit `pip install`. It documents the three transport details that each fail
  in a way that does not look like its cause: the reply is `text/event-stream`
  even for a single message, `Accept` must offer both media types or the server
  answers 406 before any tool runs, and the `mcp-session-id` from `initialize`
  must be echoed or later calls get 422.

### Fixed

- **A doc comment claimed `capture_health` carries `capture_identity`. It does
  not, and it should not.** That tool reads relaxed atomics and nothing else so
  it can be polled against a live production capture, and taking a store
  generation would cost exactly the locks that property exists to avoid. The
  comment now names the two responses that do carry it and says why the third
  cannot, and a test asserts the **absence** — so adding the field has to be a
  deliberate act that deletes the test, which is the moment to re-argue the
  locking rather than discover it later from a health poll that started
  blocking.

### Changed

- The `find_correlated` strategy table in `docs/mcp-walkthrough.md` had been
  missing `via_branch`, which is real, reachable, and reports
  `identifier_match: true`. The page now lists all seven strategies and the
  four decision fields an answer carries.

- **The non-Linux gate's scratch directory was documented at 1.7 GB and
  measured at 78 GB.** `scripts/check-non-linux.sh` keeps a second set of
  check artifacts under `target/nonlinux-shim`, and cargo retains the
  artifacts of every source version it has seen — so the directory scales with
  the number of **distinct source states** checked, not with the number of
  runs, which is what the old "1.7 GB after a dozen runs" figure actually
  measured. Across a day of commits it exhausted a 3.6 TB disk and failed a
  release build mid-`cargo test`, which is how the discrepancy was found. Both
  copies of the claim now carry the real number and the real mechanism, and
  both say to delete the directory as routine maintenance rather than only
  when space is tight. No cap and no prune were added — but the argument the
  previous review gave against one ("a gigabyte on a machine with terabytes")
  does not survive the measurement, and that is recorded where the decision
  lives rather than left implied.

## [0.5.87] - 2026-08-07

Streams learn where they came from, the MCP surface learns to say no, an
audit line learns whose call it was, and a caller can no longer choose the
host they are reported under.

**Includes everything prepared as 0.5.86, which was never released.** Its
release commit landed and its CI wedged on the self-hosted runner without
ever dispatching, so no tag and no assets exist for that number. Rather than
publish it late and out of order, its entries are folded here — a version a
reader cannot download is worse than a merged section.
### Security

- **A quoted display name could spoof the host and user a call is attributed
  to.** `extract_uri_host_port` scanned the raw header for a scheme anywhere —
  `find("<sip:")`, then `<sips:`, then a bare `find("sip:")`, then `sips:`. RFC
  3261 § 25.1 lets a `quoted-string` display name hold any octet except an
  unescaped `"`, including `<`, `>` and a complete URI, so that scan reads
  caller-controlled text and `find` returns the **first textual match, not the
  addressable URI**:

  ```
  From: "<sip:evil@attacker.test>" <sip:alice@real.test>
        `-------- decoy --------'  `----- real URI ----'
  ```

  `from_host()` and `to_host()` are built on this, so the wrong host flows into
  reports, scanner detection and the conformance linter — a caller choosing what
  it is reported as, in a tool whose value is not asserting things confidently
  and wrongly.

  `extract_uri_user` was defeated by the same input despite a comment asserting
  a display name "must NEVER be scanned for the user": it did `find('<')`, which
  lands on the `<` inside the quotes, and returned `evil`. An earlier fix had
  closed the unquoted case only; neither function was quote-aware.

  Both now share one `addr_spec()`. That is the fix, rather than another
  fallback arm: two independent URI locators is **why** hardening one left the
  other exposed thirty lines below it. The display-name skipper honors `\`
  quoted-pairs and walks `char_indices` rather than bytes, because a `\` may
  escape a multi-byte character and stepping two *bytes* past it slices
  mid-character and panics — a crash reachable from the same header. An
  unterminated quote yields nothing rather than the remainder, since resuming
  the scan past it reads the exact region the quote encloses.

  Tests were written first and confirmed failing. Three of four failed; the
  fourth passed and is kept as a regression guard, and it corrects the record —
  a bare `sip:` in a display name was already safe, because `find('<')` still
  found the real name-addr. The exploitable form needs `<...>` **inside** the
  quotes.

### Changed

- **A default that is ON: MCP tool calls are now rate limited to 100 per second
  per peer.** A client that sustains more than that starts seeing refusals after
  upgrading. `--mcp-rate-limit-per-peer 0` restores the previous behavior.

  The concurrency cap that shipped in 0.5.83 bounds calls *in flight*; it does
  nothing about an agent that stays under the cap and loops as fast as it is
  answered. That agent can still pin a capture host, which is what HEP's
  per-peer limiter and REST's `--api-max-conn` already existed to prevent on
  their surfaces.

  It refuses with the same retryable `-32000` the concurrency cap uses, and the
  check runs *ahead* of the concurrency permit so a flooding peer cannot also
  occupy a slot. Refusals are counted and appear in the `mcp_audit` line.

  The limiter is **shared** with HEP rather than reimplemented — `hep.rs` now
  delegates to the same `FixedWindowLimiter`. Proven rather than asserted: one
  mutation to the per-peer check fails four limiter tests, the MCP effect test
  *and* HEP's own isolation test in a single run, which a second implementation
  could not do. This tree has been bitten repeatedly by one concept getting two
  implementations that then drift; the URI-parsing bug fixed in 0.5.86 was
  exactly that.

  A peer is what the transport can prove, so clients behind one proxy share an
  allowance. There is no per-token accounting and no global calls/second
  ceiling.

### Added

- **RTP streams carry the frame they began in.** Every other fact sipnab emits
  already pointed at its bytes; streams did not (`grep -rn frame_ref src/rtp/`
  matched nothing). `RtpStream` now records a `FrameRef`, stamped only in the
  branch that runs for a key the store has never seen — so it is the frame the
  stream *opened* in, not its most recent packet. Surfaced through the existing
  projections: `--json`, the `streams` array of `--call-report --json`, MCP
  `rtp_stats`, REST `/v1/streams`, and the TUI stream export.

- **The MCP audit line names which token made the call.** `AcceptedToken` now
  carries the `id` that `mint` signs; the middleware stamps it, and the caller
  field reads `bearer-verified scope=<scope> token=<id>`.

  The id is recorded **verbatim**, percent-encoded and capped, not digested. It
  is the same string the operator set with `--token-id` and would list in
  `--mcp-revoked-file`, so a digest would break the hop from an audit line to
  the credential to revoke — while buying no secrecy, since token ids are
  low-entropy operator labels a wordlist reverses in seconds. Encoding matters
  because the line is flat `key=value` text: an unencoded id could close the
  quoted `caller="…"` field, forge a field, or forge a whole line.

  stdio, loopback-unauthenticated and static shared secrets emit **no `token=`
  key at all** — not blank, not a placeholder.

- **`PACKET_FANOUT` support (`src/capture/fanout.rs`), not yet wired in.** A
  live capture is one socket with one ring drained by one thread; when that ring
  overflows the drops are counted by the kernel, not by anything sipnab parses,
  so they never reach the output. This adds the mechanism — a `setsockopt` on a
  handle libpcap already opened, no fork of libpcap — verified against the
  running kernel rather than only against `af_packet.c`, including a second
  socket joining the same group, since one socket in a group proves nothing.

  It fans out **capture only**, and nothing calls it yet. Fanning out processing
  is a larger change: the offline `--cores` path resolves cross-worker splits at
  merge time and a live capture has no EOF at which to merge.

### Fixed

- **A wedged test run now has a deadline and leaves evidence.** The suite could
  hang indefinitely at ~0% CPU; the hook had no timeout and captured output into
  a shell variable, so a hung run wrote nothing and killing it to recover the
  machine destroyed the only evidence. Output now streams to a file, and a
  watchdog dumps per-thread `comm`, `wchan` and state before killing anything.

  `/proc` first, not gdb: under the default `ptrace_scope=1` a process may
  attach only to its own descendants, and the hook's gdb is a sibling of the
  test binary, so it can never attach. Proved by running the watchdog with the
  cap forced low — the gdb-only version wrote a file containing nothing but
  "Could not attach to process", which is worse than no file because it looks
  like evidence.

  The hang itself was subsequently root-caused and is **not** a sipnab defect:
  the first `getpwnam_r` in a process triggers a lazy `dlopen` of an NSS module,
  whose `update_tls_slotinfo` waits for every thread to reach a safe point while
  those threads are blocked in the dynamic loader on the lock it holds. It
  reproduces only under a multithreaded harness, which is why isolated runs
  always passed.


- **`docs/mcp.md` claimed every query tool returns `frame_ref`.** It does not,
  and the two tools that do return a pointer use *different key names* —
  `frame_ref` for `lint_dialog` findings, `frame` for the dialog and message
  projections. A caller planning around the old sentence would have looked for a
  key most responses never carried. The page now enumerates which tools return
  which key and which return none.

- **The test suite could hang indefinitely, and it was not a sipnab defect.**
  The first `getpwnam_r` in a process makes glibc `dlopen` the NSS backends; on
  an already-multithreaded process that dlopen waits for every thread to reach a
  safe point while those threads are blocked in the dynamic loader on the lock
  it holds. A `.init_array` constructor in test builds now loads the backends
  before `main`, on the initial thread, when no other thread exists to wait for.

## [0.5.85] - 2026-08-07

Two defects where the thing on screen and the thing underneath disagreed: a
tile that hovered like a link across its whole face while only a line of text
answered a click, and a test that named a path every concurrent run would agree
on.

Nothing here changes the shipped binary. Every `src/` edit sits inside a
`#[cfg(test)]` module, and the website is deployed by Pages on push rather than
by a release, so this tag carries a changelog record and identical artifacts —
upgrading from 0.5.84 gains a user nothing at runtime.

### Fixed

- **The homepage's "Engineered for Production" tiles are clickable across their
  whole surface.** Reported as "only one of the four tiles is clickable". All
  four had always carried a link; the defect was that the affordance and the hit
  area were different shapes. `.arch-item:hover` lifts the card 4px, adds a 40px
  shadow and brightens its border — over the entire tile — while the anchor was
  an inline element inside `.arch-label`, so the only place a click did anything
  was one short line of text at the bottom. Clicking the big number, which is the
  visual center and the thing the hover advertises, did nothing.

  Whether a given tile "worked" therefore depended on where in it you clicked,
  and the labels differ sharply in length at four columns — "Automated tests" is
  one short line, while two others wrap. Each tile is now the `<a>` itself, with
  the inner anchors removed rather than nested, and `:focus-visible` carries an
  explicit ring because the tile is now a single focus stop rather than a bare
  inline link. Verified in Chromium at 1440 and 900 px: 8 of 8 clicks on the
  stat number navigate, where previously that area was inert.

- **Test temp paths are unique per process.** `build_capture_config_bpf_file_-
  takes_precedence` wrote a fixed name into the shared temp directory and removed
  it on the way out, so two concurrent runs of the harness raced: 3170 passed and
  that one failed with "Failed to read BPF filter file … No such file or
  directory". The symptom names the wrong component — it reads as `--bpf-file`
  being broken, with nothing pointing at a second process. It reaches past one
  machine, because CI runs on a self-hosted runner that shares `/tmp` with
  whatever else is building there.

  It was 19 sites, not one: of roughly 30 `temp_dir()` uses only 6 were
  process-unique. All now use `std::process::id()` or `tempfile::tempdir()`.

### Added

- **A gate that fails when a temp path is not process-unique.** It reads to the
  end of the statement rather than the line, because a line-based scan reports
  multi-line `format!` calls that already carry `process::id()` as offenders —
  that error inflated the first count of this defect. It skips its own source via
  `file!()`, since a scanner containing the pattern it hunts finds itself. Two
  sites stay shared deliberately and carry their reasons: the production report
  directory, where a predictable path is the point, and a filename that asserts a
  file does *not* exist. Mutation-proved by restoring the old pattern.

## [0.5.84] - 2026-08-07

The conformance linter reaches the command line, a provenance pointer becomes
something you can follow back to the bytes it names, and a run of claims that
had drifted from the code are now what the code does.

### Changed

- **BREAKING for MCP deployments that export audio: retention is now an
  explicit opt-in.** Every `--mcp` run used to hold decoded call audio in
  memory so `export_audio` could succeed — whether or not anything would ever
  call it. Call audio is content, not signaling; holding it should be a
  decision the operator makes, not a side effect of enabling an MCP server.
  A new `--retain-audio` flag is that decision. It requires `--mcp` at parse
  time, because the MCP server is the only batch-mode consumer that can read
  the buffers back — the wasteful combination is unrepresentable rather than
  silently ignored.

  A deployment that calls `export_audio` must add `--retain-audio` to its
  server invocation. Without it the tool refuses, and the refusal reports the
  media sipnab measured and names the flag — a capture setting, not a finding
  that the call was silent. All four predicate combinations are pinned in
  tests, because this predicate has now been wrong in both directions:
  hardcoded off (export_audio could never succeed) and then armed for every
  MCP run (this entry). The TUI's F2 WAV export is unaffected — it keeps its
  own retention decision.

- **BREAKING for dashboards: `active_call_count` now counts calls.** It used to
  count dialogs in any of six active states — `Trying`, `Ringing`, `InCall`,
  `Transferring`, `Pending`, `Active` — two of which are SUBSCRIBE dialogs that
  carry no media at all. A box serving presence traffic reported "active calls"
  with nothing on the phone, and every graph built on it read high. The old
  number has not gone away: it is published unchanged under
  `active_dialog_count`, a name that says what it counts. `active_call_count`
  now means `InCall` only — the concurrent-call figure, channels in use.

  The meaning of an existing key changed, so `stats` moves to
  `schema_version` 2 on both MCP and the REST API. **A dashboard that reads
  `active_call_count` and does not check the version is now graphing a
  different quantity than it was**, lower by however many calls are ringing and
  however many subscriptions are open. Renaming without adding the call gauge
  was rejected: it would have left nobody able to answer "how many calls are up
  right now" without recomputing it client-side, which is the question the
  metric exists for.

  Surfaces: MCP `stats` gains `active_dialog_count` beside the narrowed
  `active_call_count`; the REST `/v1/stats` response gains `dialogs.in_call`
  alongside the correctly-named `dialogs.active`; Prometheus gains
  `sipnab_dialogs_active` and `sipnab_calls_active`, neither of which existed
  before; the TUI statistics pane replaces its single mislabelled "Active
  Calls" line with "Active Dialogs" and "Calls In Progress".

- **`--limit` says what it actually bounds, and it is not concurrency.** The
  help read "Maximum number of dialogs to track simultaneously". Nothing
  removes a completed dialog, so the bound scales with **uptime** rather than
  load: a box carrying five concurrent calls still evicts once 100,000 calls
  have *completed*. An operator sizing the flag against their busy-hour call
  count gets a number that has nothing to do with when it will bite. Two
  things make it worse — eviction drops the *oldest* dialogs, which are the
  ones a post-mortem wants, and a multi-file set feeds one store, so a 27-file
  directory reaches the cap 27× sooner than a single file.

  Behavior is deliberately unchanged. Completed dialogs are retained on
  purpose, because `--report` and `--call-report` answer about calls that have
  already ended, and evicting on completion would break the after-the-fact
  analysis sipnab exists for. Whether the answer is a separate window for
  completed dialogs, a time-based bound, or something else belongs to the
  retention umbrella (#160–#170), not to one flag's help text. What is fixed
  here is the claim: the flag now says it bounds the total over the run, says
  it is not a concurrency limit, says eviction takes the oldest first, and
  points at #160 for the open question. Both doc mirrors carried the same
  sentence and are corrected with it. `--max-streams` says "track
  simultaneously" too and may have the same problem — not verified, not
  touched.

- **One SIP sniffer, not two.** `sip::is_sip_message` walked its own
  fourteen-entry method table while `parser::starts_sip_message` accepts any
  RFC 3261 token method. The TCP framing path, the WASM entry point and the
  HEP and TLS paths therefore classified traffic by a **narrower** rule than
  the one that would go on to parse it: a request whose method was not in the
  table was not SIP to them. `is_sip_message` now delegates to the parser, and
  the table is deleted rather than kept in step.

  The measured effect on the local corpus is **zero additional messages** —
  that traffic uses no method outside the old fourteen. This is consistency,
  not a recovered loss, and the doc comment says so rather than implying a fix.
  The value is structural: a method added to the parser can no longer leave a
  second sniffer behind, because there is no second sniffer. RTP is still
  rejected, because delegation that widened the sniffer into accepting binary
  media would be a worse defect than the one it replaced.

### Added

- **MCP tokens can be scoped read-only.** Every HTTP MCP bearer token used to
  be full authority: the credential that reads dialogs could also call
  `shutdown_server` or `open_capture`. A new `--token-scope read` (alongside
  `full`/`metrics`, refused for the `api` audience) mints a token that reaches
  only the tools annotated `readOnlyHint`; the five write verbs
  (`shutdown_server`, `open_capture`, `export_capture`, `export_audio`,
  `save_findings`) are refused. The check lives at the one hand-written
  `call_tool` dispatch point and derives the required privilege from each
  tool's own annotation, so the scope a token needs and the hint a client is
  shown cannot drift apart — no second hand-kept "destructive tools" list, and
  a registered-but-unannotated tool fails closed under a narrow scope. stdio
  and unauthenticated loopback remain full authority (the boundary there is
  process ownership / network position). A scope refusal is audited like any
  other refusal, naming the tool and the scope it needed. Verified end to end
  over HTTP and mutation-tested both directions.

- **The MCP server caps concurrent tool calls.** Nothing bounded how many tool
  calls could run at once, so a flooding client — the network-exposed HTTP
  server is the case that matters — could pile up unbounded concurrent work.
  A new `--mcp-max-concurrent N` (default `100`, `0` = unlimited) installs a
  shared semaphore at the one `call_tool` dispatch point; a call that cannot
  take a slot immediately is refused with a retryable server-error code
  (`-32000`, distinct from invalid-params and internal-error so a client can
  tell "retry shortly" from "never"), never queued — queueing an unbounded
  backlog behind the cap is the exhaustion the cap exists to prevent, only
  deferred. The cap is server-wide, not per-session: the semaphore is one
  `Arc` shared by every per-session clone, so N sessions cannot each run the
  full budget. The default mirrors `--api-max-conn` and applies to stdio and
  HTTP alike; refusals land on the audit line as `outcome=refused`. The gate is
  a plain function the tests drive directly — a real refusal at the boundary,
  and `0` proven to mean unlimited rather than a zero-permit server that
  refuses every call.

- **A truncating `--snaplen` feeding `-O` is now warned about.** `--snaplen N`
  copies only the first N bytes of each live frame; below the 65535-byte
  default, a larger packet is captured short. sipnab's own analysis is
  unaffected — it parses what it captured — but `-O` re-emits those truncated
  frames, and a short pcap is structurally a valid one, so a later reader cannot
  tell payload dropped at capture from payload that was never on the wire. That
  is the same silent data-loss class as an `-O` file cut off by `ENOSPC`, so a
  live capture that combines a sub-default `--snaplen` (from the flag or
  `[capture] snaplen`) with `-O` now prints a warning naming the snaplen and the
  output it feeds. Warned, not refused: the run is correct, only the written
  file is short. A saved-file read (`-I`) is unaffected — it copies whole
  records, so `--snaplen` never shortens it. The default stays 65535, so a run
  that does not set a snaplen never sees the warning.

- **`--json` message lines now carry their frame pointer.** Each parsed message
  already knew the frame it came from (`SipMessage.frame`), and the dialog JSON,
  REST, and MCP surfaces already emitted it — but the per-message `--json` /
  NDJSON output dropped it, so a message-level answer could not be traced back
  to its bytes. Each message object now includes a `frame` field, the resolvable
  `<source>#<ordinal>@<digest>` string that `sipnab --show-frame` accepts,
  omitted (never null) when the message has no frame. Added to
  `message.schema.json` as an optional property, matching the dialog schema.

- **`--cores` runs now carry packet provenance.** The parallel offline reader
  built every packet with no source and no frame ordinal, so a `--cores` run
  produced dialogs whose `first_frame` was `None` and dropped the frame pointer
  from every surface — the `--json` `frame`, a finding's `frame_ref`,
  `--show-frame` — silently, on the one path built for the large captures where
  provenance matters most. The shard reader now stamps the source, per-file
  ordinal and verifying digest exactly as the single-threaded reader does (it is
  the one stage that sees every packet of every file in order, so the ordinal it
  assigns is the same one a resolver counts to), and a pointer from a `--cores`
  run resolves identically to one from a single-threaded run. Pinned by reading
  a real fixture through the parallel path and requiring every dialog to carry a
  digest-verified pointer into it.

- **The text `--report` shows the call's opening frame.** The per-call text
  report — the default `--report` format — now carries a `Frame:` line with the
  dialog's opening pointer, `<source>#<ordinal>@<digest>`, so a human reading a
  problem-call report can jump straight to the bytes with `sipnab --show-frame`,
  the same pointer the JSON, REST and MCP surfaces already provide. Omitted, not
  blank, when the dialog has no frame. The markdown and JSON report formats do
  not carry it yet — a deliberate, recorded follow-on, not a silent gap.

- **Every MCP tool call is audited.** One log line per call under the
  `mcp_audit` tracing target: tool name, JSON-RPC request id, caller, outcome
  (`ok`, `tool_error`, or `refused`), elapsed milliseconds, and the arguments
  bounded to one line with the withheld byte count named. Refused calls are
  audited too — an agent probing for tools that do not exist is exactly the
  traffic an audit record exists to show, and an implementation that logged
  only successes would hide it.

  The caller field states what the transport can prove and no more: `stdio`
  for the local pipe, and for HTTP the peer socket address plus whether the
  request was `bearer-verified` or admitted `unauthenticated` in loopback-only
  mode. The admission verdict is stamped by the auth middleware at the moment
  it decides, because nothing downstream can re-derive it — the Authorization
  header is never forwarded into tool code.

  Structurally, this adds the one hand-written dispatch point the MCP surface
  did not have: `#[tool_handler]` generates `call_tool` only when the impl
  block lacks one, so a manual wrapper covers all 31 tools without touching
  any of them, and a 32nd is covered the day it is registered. Per-tool
  authorization (the SCOPE_FULL ticket) now has a place to live. Gated end to
  end over real stdio — the audit line greped out of the child's stderr, not
  the `tracing::info!` in the source — and mutation-tested both ways: deleting
  the wrapper regenerates silent dispatch and fails the gate, and auditing
  only successes fails the refused-call half.

- **The pre-push corpus gate now has a gate of its own.** `.githooks/pre-push`
  drives every corpus binary against the real captures and refuses the push
  when one fails — and until now nothing checked that it still did. Deleting
  the block, dropping its `exit 1`, or quietly swapping its derived target list
  for a hand-written one all left a green tree, which is the same shape as the
  defect the block exists to prevent, one layer up.

  `tests/corpus_push_gate_test.rs` extracts the block VERBATIM between two
  markers and runs it with a stub `cargo`, so it proves the shipped text rather
  than a paraphrase that can drift from it: a failing corpus run must exit
  non-zero, a clean one must exit zero and say `VALIDATED`, an absent corpus
  must stay a skip that announces itself, and the bypass must be its own
  variable and say on the record that nothing was validated. Mutation-tested
  three ways — removing the `exit 1`, removing a marker, and replacing the
  derivation with a hand-list — each caught by a different assertion.

  Worth recording from the first mutation: with `exit 1` removed the gate still
  printed "Push blocked: the real capture corpus did not validate" and exited
  0. The message and the effect are separate things, and only one of them stops
  a push.

- **The website's JSON-LD block cannot be broken out of by a config value.**
  `base.html` renders four `website/config.toml` values inside a
  `<script type="application/ld+json">` element through Tera's `json_encode`,
  which does not escape the forward slash — a value containing `</script>`
  would close the element early and hand the rest of the page to the HTML
  parser as markup. The values are static today, so nothing is exploitable;
  the point is that the safety was assumed, not enforced. A new gate sweeps
  every string in the parsed config — with a real TOML parser, because the
  property is about the parsed value and a line-regex form was shown to pass a
  `</script>` payload written as a single-quoted or triple-quoted string that
  the parser sees identically. The four keys the block actually interpolates
  are held to the stricter rule that they carry no angle bracket at all, and
  the sweep is anti-vacuity-guarded (it fails if it reads no strings) and
  mutation-tested against the payload in all four TOML quoting forms.

- **The SIP conformance linter has a CLI entry point.** `grep -c lint
  src/cli.rs` returned 0: the 31-rule linter was reachable only through an MCP
  client, which put the project's most distinctive capability out of reach of
  the place it matters most — a pipeline gating a proxy config change. Two
  flags, driving the same engine rather than a second implementation:
  `--lint`, which prints every finding with its rule id and the RFC section it
  reads from, and `--lint-fail-on <severity>`, which exits 3 when a finding
  reaches that severity.

  **Exit 3, deliberately not 1 or 2.** A pipeline has to tell three states
  apart: sipnab broke (1), the invocation was wrong (2), and the *capture* is
  non-conformant (3). The response to each differs completely, and a gate
  reporting 1 is indistinguishable from a crashed tool. The check sits after
  the existing failure exits, so a run that both failed to write its output and
  found findings reports the failure — those findings came from a partial read
  and are not trustworthy anyway. `--lint` alone leaves the exit code alone,
  because making a report silently become a gate is how a pipeline ends up
  failing on something nobody asked it to check. `--lint-fail-on` requires
  `--lint`, so a threshold with no linter running is a usage error rather than
  a silently ignored flag.

  `--cores` runs the same gate. The linter shipped wired only into the batch
  path, so `--cores N --lint` printed nothing and exited 0 — a pipeline adding
  `--cores 8` for speed would have stopped failing on non-conformant captures,
  and nothing would have said so. Both paths now call one `run_lint_stage`. The
  test asserts the two paths produce the *same* exit code rather than a fixed
  expectation, because agreement is the property and what this fixture happens
  to contain is beside the point; both must also print the summary with its
  denominator, so a `--cores` run cannot report "0 findings" while having
  examined nothing.

- **`capture_status` reports the SIP the portrange skipped.** `stats` already
  carried `unanalysed_sip_messages` and the busiest skipped ports.
  `capture_status` — the tool whose own description tells an agent to call it
  "before reasoning about" a capture — answered `dialog_count` and
  `stream_count` with nothing beside them, so its response was byte-identical
  whether or not a third of the SIP had been analyzed. The corpus sweep
  measured what that costs: **2,311 dialogs reported against 3,712 real, 1,401
  lost, 37.7%**, because a third of the messages never touch 5060/5061,
  cross-checked against tshark at 4,247 of 13,455.

  The asymmetry is the whole finding. On the CLI that loss is four stderr
  warnings and a summary line that reconciles exactly, and an operator who sees
  it can ask a follow-up. An agent reading `capture_status` saw a clean answer
  and would report on "the calls in this capture" from two-thirds of them with
  full confidence — and the agent is the surface that cannot notice a warning
  scrolling past. The busiest ports come with it, because they are what the
  operator passes to `--portrange`, and an answer that names the loss without
  naming the remedy is only half of one. Both tools use the same field names,
  so a client cannot learn the loss from one and miss it in the other.

- **A stream carrying more payload than its codec can produce now says so.**
  Reading two byte-identical copies of a capture as one `-I` set reported a
  PCMU stream at 128 kbps over an unchanged 8-second span. G.711 is 64 kbps
  *by definition* — that figure is not surprising, it is arithmetically
  impossible — and sipnab emitted it with no warning. Message counts doubled
  6→12 and RTP packets 425→850, so the whole thing read as a busier network
  rather than a duplicated input. sipnab already knew both halves and never
  compared them: `octet_count` over the observed span, and `octets_per_ms` from
  the RFC 3551 table the `FRAME_SIZE_IMPOSSIBLE` rule already reads.
  `codec_shape()` is reused rather than a second rate table written, because
  two tables of codec rates is how they drift.

  The check generalises past duplicates — a clock-rate error, a timestamp bug
  or a misidentified payload type all land here — so it says a number cannot be
  right without claiming to know why, and it names duplicate input as the
  common cause rather than the certain one. It stays silent where it cannot
  know: unknown codecs, variable-rate codecs such as Opus and AMR that have no
  ceiling to exceed, spans under 500 ms, and single-packet streams. The 15%
  tolerance clears ordinary span-measurement error while a 2× duplicate exceeds
  it by a mile, and the test pins both directions, because exactly-at-rate must
  not fire. This is deliberately **not** de-duplication: two legitimate
  captures of one call from different vantage points are a real and useful
  input, and collapsing them silently would destroy the asymmetry analysis that
  exists to compare the two directions.

- **A truncating `--snaplen` feeding `--retain-audio` is warned about too.**
  The existing warning covers `-O`, where it can honestly say the analysis is
  unaffected: sipnab parses what it captured, and only the written file is
  short. `--retain-audio` is the path where that reassurance is false. It
  buffers RTP payload for `export_audio` to decode later, so a snaplen sized
  for signaling — 200–400 bytes is the usual guidance for SIP headers —
  truncates the payload before retention ever sees it, and the exported WAV or
  Opus is short or corrupted for exactly the truncated packets, with nothing
  marking which. It carries its own message, which names `export_audio` rather
  than `-O` and does not claim the analysis is intact.

- **Session-ID: the RFC 7329 legacy form is reported as an interop notice.**
  `SessionId::legacy_rfc7329_form` was computed at parse time and read by
  nothing outside `session_id.rs`. RFC 7989 §5 states the `remote` parameter as
  a MUST with a named exception for backwards compatibility with RFC 7329, and
  §11 details that case. The rule is cited to §11 and raised as **interop at
  notice severity, not as a MUST violation**: one message cannot tell a peer
  genuinely interworking with an RFC 7329 stack — which the RFC permits — from
  a modern peer that simply omits the parameter, and reporting a violation
  would assert the second when only the first is observable. It is still worth
  reporting, because the consequence is real and asymmetric: a half-populated
  Session-ID correlates in one direction only, so a call crossing a B2BUA can
  be reported as two unrelated calls. The test asserts severity and basis, not
  merely that the rule fires.

- **Lint findings cite the frame that provoked them, and `show_evidence` turns
  a pointer back into bytes.** A finding named a rule, a citation and a message
  *index*, which means nothing away from the message list it indexes — a
  reviewer may not have that list, and compaction reshuffles it — so a finding
  on its own was an assertion again, which is the state this mechanism exists
  to leave behind. `lint_dialog` now attaches the message's `frame_ref`, done
  at the MCP projection rather than on `Finding` itself, so the lint engine's
  result stays a pure conformance verdict and a transport concern stays out of
  the rule catalog.

  The omission is the load-bearing half. A message with no pointer produces
  **no key at all** — not `""`, not frame 0, both of which read as a real
  pointer. A finding citing frame 0 of nothing is worse than one citing
  nothing, because a reader cannot tell the difference.

  `show_evidence` reports three states that are deliberately not collapsible:
  `verified`, where the frame is there and hashes to what the pointer recorded;
  `unverified`, where it was found but carried no digest, so *nothing* was
  checked; and `unresolvable` with a reason. Folding unverified into verified
  would be the manufactured confidence the feature exists to prevent, and a
  digest mismatch is unresolvable rather than a resolved frame with a warning.
  It takes a caller-supplied string and returns the bytes at a path, so it
  resolves only the final component and pushes it through `resolve_in_root`:
  resolving the pointer's own `source` would make it an arbitrary-file-read
  primitive wearing a `readOnlyHint`.

### Fixed

- **A capture beginning mid-dialog reported the call as still in progress,
  indefinitely.** The dialog-*creation* branch called `SipDialog::new`,
  `update_timing` and `track_sdp`, and never `update_state`, so the creating
  message's own state transition was dropped. In timestamp order that is
  invisible: the first message is the INVITE, whose transition is exactly the
  `Trying` that `SipDialog::new` already set. It stops being invisible the
  moment the first message is not the INVITE, and the common way that happens
  is a capture that **begins mid-dialog**, leading with a 486, a BYE or a
  CANCEL. That outcome was discarded and the call reported `Trying` hours after
  it ended. The message log and response list stay complete, so no count
  catches it. Measured on a canceled call fed `[CANCEL, 487, INVITE, 100,
  180]`: timestamp order reaches `Canceled`, the permuted order reached
  `Trying`.

  One divergence is deliberately left, pinned by its own test rather than
  hidden: a non-INVITE *request* arriving first sets `dialog.method` from that
  request, so a leading CANCEL routes every later message to
  `update_generic_state`, which inspects only responses and has no CANCEL rule.
  The obvious fix — dispatching on the method a request implies — was tried and
  reverted, because the INVITE machine guards its 2xx, 487 and 3xx arms on
  conditions a BYE/CANCEL-seeded dialog does not meet, so routing there leaves
  cells unmodelled rather than filled. Landing a half-modeled state machine in
  the code that decides whether a call is up is worse than the bug it closes.

- **`--markdown` was a no-op alongside `--report`.** It was parsed, documented
  as "Format report output as Markdown", and did nothing: the outputs were
  byte-identical, `cmp` clean. It worked only for `--call-report`. A flag that
  is read, documented and ignored is the same defect class as a config key that
  validates and never applies. The markdown form also carries Call-ID in
  **full** where the text form truncates it to 30 characters — `--report`
  columns overflow on long From/To values and corrupt the fixed-width
  alignment, which breaks anything parsing the table, and a markdown table
  cannot be corrupted that way because it does not depend on width. The test
  asserts inequality plus a markdown-shape check rather than a fixed rendering,
  and pins that the text form does not quietly become markdown too.

- **Two single-input features read only the first `-I` argument.**
  `cli.primary_input()` returns the first `-I` *argument*, which after
  chronological resolution is often not even the first file read — and for
  `-I /pcaps` is a directory.

  *Embedded TLS secrets.* With `-I plain.pcapng -I withdsb.pcapng`, where the
  keys sit in the second file, there were zero "TLS decryption" lines and the
  second file's TLS stayed encrypted; naming `withdsb.pcapng` alone produced
  "TLS decryption active: 1 secret(s) from embedded DSB". A directory holding
  both behaved like the first case. The run read exactly like a capture that
  carried no keys — no warning, no hint that file order decided it. Every file
  in the set is now offered to the decryptor.

  *`--wireshark` and `--tshark-filter`.* `tshark -r` takes one file, and the
  emitted command named the first `-I` argument beside a `-Y` filter built from
  every Call-ID sipnab had found. Measured with two sample captures, the filter
  named three Call-IDs, the first of which exists only in the file that command
  never opens; pasted into a terminal it returns a strict subset of what sipnab
  just reported, silently, exit 0. That one is **refused** rather than fixed,
  and the refusal names every file, because a command covering half the
  evidence is worse than no command.

- **The TUI f-key bar advertised the wrong action for F9, and clipped.**
  Reported from the call list as "pressing F9 does nothing", and both halves of
  that were true, for independent reasons. The bar advertised `F9 Addrs`, but
  `call_list.rs` binds `F(9)` to `ClearFilter`; the Name-Address popup is on
  `N`. With no filter active — the normal state — clearing nothing renders
  nothing, so the key read as dead. The help overlay and both doc pages had it
  right, and the bar was the only surface lying — the bar being where most
  operators learn a binding. F9 now reads `Unfilter` rather than `Clear
  filter`, because F5 already clears the *call list* and two entries both
  reading "Clear" would leave the operator guessing which one drops their
  capture. `N Addrs` joins the widest tier, so the feature that was being
  mis-advertised is reachable from the bar.

  The bar also overflowed the row it was drawn into. `render_fkey_bar` draws a
  one-row Paragraph with no wrap, so anything past the right edge is clipped
  silently, and the last items are the least-known bindings. Measured against
  the width that *selects* each tier: the call list at 80 needed 91 columns and
  at 100 needed 135, and the call flow at 120 needed 125. The committed
  snapshots had been recording this verbatim, ending `F7 Filte` and `F6 Ra`
  mid-word, and nobody read them as a defect. Call-list tiers are rebuilt from
  measured column cost — 62 / 94 / 112 / 142 — with the 112 tier added so a
  ~120-column terminal, the common wide default, keeps `O Open` and `F5 Clear`.
  The call flow's threshold moves 120 → 126, its measured need.

- **The TUI's BPF slot now says which source its filter belongs to.** After an
  in-session `O` open, the mode label flips to `Offline (<file>)` while the BPF
  slot kept showing the filter the *live* capture was compiled with. The two
  rows sit one above the other and read as one statement about one source: not
  a lie in any single field, and wrong as a whole. The slot is **marked, not
  cleared** — the live capture is still running and still writing to the same
  stores, so its filter remains in force, and blanking it would claim no filter
  was compiled, which is a different and false thing to say. `[live capture]`
  is appended, so the expression itself stays readable. The flag is one-way on
  purpose: there is no later event after which the mark becomes wrong, and
  clearing it on some subsequent action would invent a transition that does not
  exist.

## [0.5.83] - 2026-08-05

Things the code already knew that nothing could reach, and one run that
reported success after reading only part of its input.

### Changed

- **BREAKING for scripts: a capture that does not finish now exits non-zero.**
  Reading a set of files, `sipnab` joined its capture thread and downgraded a
  returned error to a warning, so the run printed a whole-looking report and
  exited 0 — while the same input under `--cores` exited 1. One input, two
  answers, and the reassuring one was the default path. Both failure arms, the
  error and the panic, now exit 1. Reports still print above it, because a
  partial capture is worth looking at; it just must not be mistaken for a whole
  one by anything reading `$?`. A clean shutdown is unaffected: the live loop
  returns success when the stop signal ends it and reserves failure for a
  failed open, a rejected filter or a fatal read.
- **BREAKING for scripts: `--cores` refuses a BPF filter that will not compile
  against a later file instead of skipping that file.** A filter that cannot
  compile against a member of a set is a static misconfiguration — the text
  does not change between files, so it was always going to fail on that one —
  and answering a forty-file question with the members the filter happened to
  fit is the worse of the two outcomes. The refusal names the FILE, not just
  the filter, and still reports how much of the set it read before stopping.

### Added

- **Two RFC 7989 Session-ID lint rules.** The deviation detector was computed,
  tested, and surfaced nowhere. `SIP-7989-5-SESSION-ID-MALFORMED` fires when a
  half is not 32 characters of `[0-9a-f]`; `SIP-7989-5-SESSION-ID-UPPERCASE`
  fires on uppercase hexadecimal, which §5 rules out twice over — its ABNF
  admits `%x61-66` with no uppercase alternative, and the section closes by
  saying the values appear as lowercase. sipnab still correlates on an
  uppercase half, but a peer, SBC or log pipeline comparing bytes sees two
  identifiers for one session. Catalog: 29 rules to 31.

### Fixed

- **The TUI's BPF filter slot showed nothing, ever.** No option carried the
  filter into the interface, so the slot was blank in every real session while
  its comment described what it would show "if set via CLI". It now shows the
  EFFECTIVE filter — the expression handed to libpcap, which on a live capture
  is not what the operator typed, because with no filter given sipnab generates
  one and the kernel drops what it does not match. Long generated filters end
  in an ellipsis rather than being clipped at the terminal edge, where they
  read as a complete expression that happens to stop there.
- **Left and right arrows did nothing, and said nothing, in the message detail
  pane.** With the pane focused and wrapping off, the arrows scroll
  horizontally — but whenever no line overflowed there was nothing to scroll,
  and the press was silent. The pane now reports its own headroom back after
  each frame, so a press that cannot move anything says why.
- **An explicit pane resize is no longer undone by the automatic label fit.**
  Once the operator sets the split, it stays where they put it.

### Documentation

- The privilege-drop group ordering is now recorded as a MEASUREMENT rather
  than as a reading of the xnu source. On macOS, `setgroups(0, NULL)` leaves
  `[0]` — wheel — in the group vector, and the following `setgid` is what
  clears it; the same call also demonstrates that `setgid` rewrites the list,
  which is the `cr_gid` aliasing that makes reversing the two land on effective
  GID 0 with an unprivileged UID.
- The fault model called a fatal capture error "logged, clean exit", which was
  written when that meant exit 0.

## [0.5.82] - 2026-08-05

A pass over things that were declared but not done: a metrics endpoint that
bound nothing, a flag that claimed to validate, capture text handed to a
language model unmarked, and four gates that could not fail.

### Security

- **DTMF digits no longer reach the log in cleartext.** Decoded RFC 4733 digits
  are PINs, calling-card numbers and account numbers. They were written at
  `info`, so anyone with read access to the log, journald or a shipped
  aggregate got them. The value is now masked at the decoder, and cleartext
  needs TWO independent acts — `--dtmf-cleartext` AND raising `SIPNAB_LOG` to
  debug — so a stale flag in a systemd unit still leaks nothing at the default
  level. The mask is `x` rather than `*`, because `*` is RFC 4733 event code 10
  and masking with it would make "the caller pressed star" and "the value is
  withheld" the same line.
- **`--stir-shaken` no longer claims to validate.** It read "Validate
  STIR/SHAKEN identity headers"; sipnab decodes the RFC 8224 PASSporT and never
  fetches the certificate or checks a signature. On fraud traffic that reads as
  the exact opposite of the truth. A forged Identity header reports exactly like
  a genuine one, and the help now says so.
- **MCP: capture-derived free text is fenced.** sipnab's input is written by
  whoever sent the packets and its MCP caller is a language model, so a `From`
  display name reading "ignore previous instructions" arrived in the same
  channel as sipnab's own words. Free text is now wrapped in
  `⟦untrusted-capture-data⟧` markers; identifiers stay verbatim so they can be
  passed back to other tools, and a provenance note explains the split. The
  fence cannot be forged: its bracket code points are rewritten inside the
  payload before wrapping.
- **Every MCP tool declares what it does.** All 31 carry annotations — 26
  `readOnlyHint`, five writes with `destructiveHint` and `idempotentHint` set
  explicitly. Previously one tool was annotated and thirty were not, so a host
  had to treat them all as the worst case or all as harmless.
- **New gate: the privilege-drop path cannot be silently weakened.** A scan
  caught `src/privilege.rs` mid-mutation with `PR_SET_DUMPABLE`, the
  `chdir("/")` after `chroot()`, `drop_supplementary_groups()` and
  `set_no_new_privs()` all disabled at once. Every one of those still compiles
  and still passes tests that do not cover it. `scripts/check-privilege-drop.py`
  reads the source rather than running it, so it also answers when the tree does
  not build — which is exactly when a half-restored mutation hides behind an
  unrelated compile error.

### Fixed

- **`--metrics` was a silent no-op headless.** `start_metrics_server` had one
  call site, in the TUI path, so `sipnab -N --metrics` parsed the address,
  validated it, refused an unsafe bind — and bound nothing. Every container and
  systemd unit runs `-N`. Fixing it also removed a hard-zero capture-queue gauge
  on the newly reachable path, and added a warning for `--cores N`, which still
  exits before a scrape could land.
- `check-unwrap.py` failed OPEN: it counted braces with no awareness of string
  literals, so an unmatched `{` in a string extended a `#[cfg(test)]` exemption
  over the production code that followed and silently exempted every `unwrap()`
  there.
- `--cores` now reports what it read, through the same `ReadTally` the
  single-threaded path uses, so the two readers cannot drift.
- Below ~62 columns the TUI call list no longer renders zero-width identity
  columns.
- Content-Security-Policy: `script-src-attr 'none'` closes the injected-handler
  class on the published site.

### Removed

- `VerificationStatus::{Valid, Invalid, NoCert}` — unreachable by construction,
  since sipnab never fetches the STIR/SHAKEN certificate. The enum is
  `#[non_exhaustive]`, so a downstream match already carries a wildcard and
  degrades to an unreachable-pattern warning rather than an error.
- `tui::run_tui`, `App::filter_dialog_state` and `App::filter_dialog_state_mut`
  — zero callers. **Library API, technically breaking**, though sipnab is
  distributed as binaries (.deb, .rpm, tarball, Homebrew) and has never been
  published to crates.io, so only a git-dependency embedder could be affected.

### Documentation

Ten backlog entries marked open had shipped and four "verified absent" claims
were false. `CONTRIBUTING.md` told contributors to hand-maintain files that CI
generates and byte-compares. `contrib/sipnabrc.example` set `buffer = 16` — a
quarter of the default — under a comment saying "raise". Counts recomputed
rather than adjusted: 25 → 31 MCP tools, 31 → 30 DSL fields, 12 → 13 features.

### Note for MCP client authors

Tools returning capture-derived data now append a provenance note as an extra
content block. It is appended LAST, so `content[0]` is still the payload and
existing clients keep working.

## [0.5.81] - 2026-08-04

Follow a call across an SBC. Two new MCP tools, two new correlation strategies,
and the provenance a federated setup needs.

### Added

- **`find_correlated` MCP tool.** `DialogStore` has computed scored, deduplicated
  multi-leg correlations for a long time and nothing on the MCP surface could
  reach it. Every response now names the STRATEGY that matched, not just a
  score, plus `identifier_match` as a boolean — two strategies score 100 and are
  not the same claim.
- **RFC 7989 `Session-ID` correlation.** The one identifier designed to survive a
  B2BUA. Matching is set intersection over the non-nil halves, because the two
  halves swap perspective across an SBC and a string comparison would report
  "unrelated". `nil` (32 zeros) is absence and never matches.
- **RFC 8866 SDP origin correlation.** Fallback for SBCs that emit no
  correlation header. Compares the whole uniqueness tuple the RFC defines, never
  `sess-id` alone — the RFC recommends deriving that from a timestamp, so two
  unrelated calls from one user agent can share it. `sess-version` is excluded
  deliberately, so a re-INVITE for hold does not break the match.
- **`save_findings` MCP tool**, off by default behind `--mcp-allow-save-findings`.
  The first write verb on sipnab's network surface. An agent can record a
  conclusion; nothing can read it back — no tool, no query result, no analysis.
  That dead end is enforced by module visibility rather than convention.
- **`capture_identity.node`** on every answer, via `--node-name`, `[capture]
  node_name`, or the hostname. Says WHICH box saw a fact, which is what an agent
  querying an SBC and two PBXes at once cannot otherwise know. Deliberately not
  part of the rotating capture instance: a capture restart is not a topology
  change.
- **Clock discipline in `capture_health`** — `synchronized`, `max_error_us`,
  `est_error_us`, `available`, read from `adjtimex(2)`. Irrelevant within one
  capture, where a constant offset cancels; decisive across nodes, where the
  timing heuristic's two-second window is smaller than a day's skew.
  `find_correlated` carries the same reading as `timing_clock`, and only when a
  time-based match is actually in the results.

### Fixed

- **`bench/field-report.sh` compared the filter against itself.** It passed the
  old BPF expression to `--filter`, which is the display-filter DSL; the BPF
  filter is a trailing positional. That run died on an invalid expression while
  the report presented it as a completed A/B. Rewritten onto MCP
  `capture_health`, with the safety gate moved ahead of the version check and
  mutation-tested against five injected flags.
- **`--metrics` is a silent no-op in headless mode** — `start_metrics_server` has
  one call site, in TUI mode. Documented against, and the harness no longer
  depends on it. The defect itself is tracked separately.

### Documentation

- Every MCP section now opens with its own diagram, and the three deployment
  shapes link to the sections documenting them.
- A federated-tracing walkthrough: ask the SBC first, read the strategy before
  believing the tree, and what federation cannot prove.

## [0.5.80] - 2026-08-04

### Breaking

- **`start_metrics_server` now returns `(SocketAddr, JoinHandle<()>)`** instead
  of `JoinHandle<()>`. Library callers must destructure; the CLI is unaffected.

  Read this even though it is a patch-level bump. Cargo resolves `^0.5.78` to
  this release, so a build depending on the old signature breaks without
  warning. That is the pre-1.0 policy this project states at the top of this
  file — the API is not stable and a break may land in any release — but the
  practical consequence is worth spelling out rather than leaving to be
  discovered at compile time.

  The change exists because the address was previously discoverable only by
  reading a log line. With `--metrics 127.0.0.1:0` the OS assigns the port, and
  a caller had no way to learn it. Returning it also removed a genuine
  time-of-check/time-of-use race in the test suite: the old helper bound `:0`,
  took the assigned address, then released the port so the server could rebind
  it, and under a full-suite run another test could take it in between.

### Fixed

- **A capture full of INVITEs could be reported as "No SIP traffic found", and
  nothing said otherwise.** Given frames it could not decode, sipnab printed
  `N packets captured, 0 SIP messages` and `No SIP traffic found.` — output
  textually identical to a capture it had read perfectly that genuinely held no
  SIP. An operator had no way to tell "there is no SIP here" from "I could not
  read one single frame of this".

  Two proven instances were sitting in this repository's own test corpus.
  `DTMFsipinfo.pcap` is PPPoE-encapsulated (EtherType `0x8864`), the access
  encapsulation on DSL and much FTTH. `h263-over-rtp.pcap` is `DLT_NULL`, and
  its first frame carries `INVITE sip:auto@localhost SIP/2.0` on UDP 5060 — 49
  of 49 frames were dropped at debug level, exit 0, while `--hexdump`, the
  escape hatch that error message recommends, printed nothing at all because it
  runs on parsed packets. A comment in `rtp_integration_test.rs` had recorded
  the `DLT_NULL` limitation for months; it never reached runtime.

  Both now decode, and the class behind them is closed: every frame the parser
  cannot turn into a packet is counted by reason, carrying the number that
  identifies it — the DLT, the EtherType, the IP protocol. The count reaches the
  run summary, `--report`, `--json`, `/v1/stats`, MCP `stats` and the Prometheus
  capture family, and `No SIP traffic found.` is never printed unqualified after
  a failed decode. A run that could read nothing now says so emphatically.

  Measured against 62 real captures totalling 4,616,136 frames: **19 files carry
  frames sipnab could not decode, 5,653 in total**, one file at 9.0%. None of it
  was visible before.

- **`--cores` could invent a host pair out of unrelated bytes.** On a frame
  tagged with the legacy QinQ EtherType `0x9100`, the shard peek read at an
  offset it had not advanced past the tag. A TCI with PCP=2 gives a first byte
  of `0x4X`, which passes the "is this IPv4?" nibble check, so the peek returned
  addresses assembled from TTL, protocol and checksum bytes. Reproduced, fixed,
  and pinned both ways: the correct pair asserted present, that exact
  fabrication asserted absent.

- **The Ethernet tag walk was unbounded over attacker-controlled bytes.** It
  terminated, but a 64 KB frame of repeated tags walked ~16k iterations. Now
  capped, with the cap justified against what 802.1Q and 802.1ad actually permit
  and matched to `etherparse`'s own limit so the peek and the full parse cannot
  disagree.

- **MPLS accepted label stacks that the defining RFCs forbid.** The
  bottom-label cross-check covered only the two Explicit NULLs, so a stack
  bottomed with the Router Alert label (1, illegal at the bottom per RFC 3032
  §2.1), the Entropy Label Indicator (7, always followed by the entropy label
  per RFC 6790 §4.2) or the GAL (13, "MUST always be followed by an ACH" per
  RFC 5586 §4.2) was decoded as though it carried a user packet.

### Added

- **Tunnel decapsulation.** SIP wrapped in any of these is now read rather than
  discarded: MPLS (`0x8847`/`0x8848` and IP protocol 137), NSH (`0x894F`),
  PPPoE Session (`0x8864`), PBB I-TAG (`0x88E7`), MACsec (`0x88E5`), legacy
  QinQ (`0x9100`), GRE Transparent Ethernet Bridging (`0x6558`), GTP-U (UDP
  2152 — how VoLTE signaling crosses a mobile core), VXLAN (4789), GENEVE
  (6081), Teredo (3544), and AH (IP protocol 51, which authenticates without
  encrypting, so its payload was readable and was being thrown away). Link
  types `DLT_NULL` (0) and `DLT_LOOP` (108) join the four already supported.

  Encapsulations that are recognized but genuinely cannot be decoded report
  that rather than vanishing: UDP-encapsulated ESP (4500) and
  confidentiality-protected MACsec are named as encrypted. MACsec that is
  integrity-protected but *not* encrypted is read normally — the distinction
  turns on TCI bits whose position had to be settled from IEEE 802.1AE's Annex C
  conformance vectors, because Figure 9-4 of the 2018 standard is defective.

  The governing rule throughout: **over-eager decapsulation is worse than the
  silence it replaces.** A missed tunnel is now counted and named; a false one
  would invent a call — inner addresses and ports assembled from unrelated
  bytes — with nothing marking the flow fictional. UDP ports 2152, 4789 and 6081
  all occur as the ephemeral source port of ordinary RTP, so every port-keyed
  decoder is required to reject a realistic RTP packet on its own port, and that
  is a test rather than an aspiration. L2TPv3 over UDP is refused outright: its
  cookie length is signaled on the control channel and guessing it is precisely
  how a decapsulator fabricates a flow.

- **`--capture-tunnels[=<PORTS>]`**, opt-in, for capturing UDP-tunneled SIP
  live. BPF cannot parse a variable-length GTP-U header to reach the inner port,
  so covering these means capturing everything on those ports — a firehose on a
  mobile core, and not something to switch on by default. The default path warns
  and names the flag rather than omitting them silently.

### Changed

- **The auto-generated live-capture filter now sees encapsulated SIP.** With no
  explicit `--filter`, sipnab installed `portrange 5060-5061`, which libpcap
  compiles against the EtherType chain it knows — so on an encapsulated link it
  matched nothing, in the kernel, where no userspace counter could ever see it.
  Measured with tcpdump against the PPPoE fixture: 0 of 32 frames before, 32 of
  32 after, while a plain-Ethernet capture is unchanged at 23 and 250 frames of
  RTP noise stay excluded.

  The filter is built from absolute `ether[N:M]` offsets rather than libpcap's
  `vlan`/`mpls`/`pppoes` qualifiers. Those qualifiers cannot express this: their
  offset shift is cumulative and leaks across `or`, and they are *compile
  errors* on `DLT_LINUX_SLL`, `SLL2`, `RAW` and `NULL` — which is what sipnab
  opens when no interface is named, so using them would have stopped captures
  starting. 27 → 133 BPF instructions, 3% of the 4096 limit.

  **Known limit:** the added arms are Ethernet-shaped, so on `SLL`/`SLL2` they
  compile but sit inert and only untagged traffic matches. Naming a real
  interface is the workaround, and it is documented on both the CLI reference
  and the troubleshooting page.

## [0.5.78] - 2026-08-04

### Fixed

- **The call list truncated SIP methods, and the fix for that had never
  reached a screen.** The homepage Search tab clipped every method to six
  characters, so `REGISTER`, `PUBLISH` and `SUBSCRIBE` each lost their tail.
  The Method column was widened to nine cells in July precisely so
  `SUBSCRIBE` would fit, and a test asserted that continuously — green for the
  entire time the defect was visible.

  A `Constraint` is a *request*, not a rendered width. The four flexible
  columns over-claimed the row: the eleven-cell floor on the address columns
  plus the four-cell floors on From and To could total more cells than the row
  has. Ratatui charges an over-subscribed layout's whole deficit to one column,
  and it picks a fixed one — Method. So widening Method could never show up on
  screen: the constraint was honest and the pool was not. From, To, Source and
  Destination now reserve their floors before the address columns are sized,
  and the remainder is exact rather than saturating, so every cell handed out
  is one the row owns.

  The committed TUI snapshots had been recording the truncation as correct
  output: `Metho`, `INVIT`, `Destinati`, `+0.000`. Even the column header and
  the six-character `INVITE` were clipped. A new gate walks every terminal
  width from 61 to 200 and fails if the columns plus their spacing exceed the
  row; reinstating the old arithmetic fails it while leaving the original
  Constraint-based test green, which is exactly the gap that let this ship.

### Added

- **A benchmark harness for the live capture path** (`bench/live-capture.sh`).
  The capture work in 0.5.76 shipped throughput claims reasoned from syscall
  counts and ring arithmetic, never measured; this is the instrument that can
  settle them. It replays a synthetic corpus through a `veth` pair in a private
  network namespace and reads sipnab's own counters. It accepts no capture path
  — not a denylist, there is no argument through which one could be supplied —
  and generates its corpus itself. Two controls gate every result: a canary
  proving the capture point can observe anything at all, since a down link
  reports zero packets and zero drops exactly like a flawless run, and a
  calibration proving the drop counters can move at all. 371 assertions run
  without root, without a namespace and without a capture device.

  **Nothing has been measured with it yet.** Every performance claim in the
  documentation remains reasoned rather than measured.

### Changed

- The demo recordings are rendered against a binary built from the tree, and
  the render refuses on a version mismatch. They were previously rendered
  against whatever `sipnab` happened to be installed, which is how a fix merged
  in July was still absent from the published screenshot in August.

- The acceptance criterion for capture-loss measurement is corrected in
  `docs/research/capture-performance.md`. It called for
  `ethtool -S <iface> | grep rx_dropped`, which is unsatisfiable on the harness
  interface: the `veth` driver exposes no such counter. The harness reads the
  counters that exist and says which they are.

## [0.5.77] - 2026-08-03

**0.5.76 was never published**, so this release carries its entry as well as
this one. Read both: the capture-sizing work described under 0.5.76 reaches
users here for the first time.

Both fixes below came out of reviewing that capture work before releasing it,
and both are the same shape — a value computed correctly and then either not
applied or not reported. Each had a test that passed throughout, because each
test asserted the decision rather than its effect.

### Fixed

- **Every batch run buffered RTP audio that nothing in it could read.**
  `StreamStore` arms payload retention by default, which is right for the TUI —
  its stream-detail view plays a stream straight out of that buffer. The batch
  path then read `if audio_retention_wanted(&cli) { set(true) }` with no `else`,
  and a one-armed `if` cannot switch off something already on, so the condition
  gated the operator *notice* and never the behavior. Only the MCP
  `export_audio` tool consumes those buffers in batch mode, so every run without
  `--mcp` retained up to 1500 frames per stream across up to 50,000 streams at
  the defaults, bounded per frame only by `--snaplen`, for a reader that did not
  exist. It stayed invisible because the auto-generated filter is
  `portrange 5060-5061` and no RTP reaches the store to retain — it would have
  armed the moment an operator widened the filter to capture media, which is the
  first thing anyone does when they want audio.

- **The packet-drop warning told operators the buffer default was 2 MiB after
  it became 64.** The number in that message is the one an operator acts on, and
  it named a figure 32x below the truth: someone dropping packets at the default
  read that they were on a small ring with obvious headroom, so the suggested
  remedy looked untried and the real causes — interface drops, snaplen, an
  over-broad filter — went unexamined. The warning now reports the ring this run
  actually received, which is not always the one requested: the open walks a
  ladder that halves to a 2 MiB floor when the kernel refuses, and past
  `MAX_BUFFER_MB` (2047, the last whole MiB that fits a positive C `int`) the
  request and the allocation diverge. Both the reported figure and the byte count
  libpcap receives now derive from one clamp, so the message cannot name a
  buffer that was never allocated.

### Internal

- The pre-push hook runs Vale and codespell, the two CI-blocking prose gates
  that no cargo command builds. Both reddened `main` on 2026-08-03 — twelve
  passive-voice errors, then two misspellings — each found only after a push. A
  missing tool reports `NOT CHECKED` and never a pass, on the same principle as
  the corpus gate: a check that goes quiet when its tool is absent is worse than
  no check, because green then means nothing.
- Both fixes above added the observable their absence had hidden —
  `StreamStore::audio_capture()`, and a `drop_warning()` that returns the text
  instead of logging it from behind a once-per-run latch — and both new tests
  were verified by reinstating the original defect and confirming they fail
  while the old tests stay green.
- The capture-performance roadmap no longer describes the 2 MiB default and the
  fixed-size packet channel as current, and cites symbols rather than line
  numbers, all of which had rotted.

## [0.5.76] - 2026-08-03

### Fixed

- **A capture that lost packets said nothing about it.** libpcap has reported
  kernel-ring and interface drops through `pcap_stats()` since forever and
  sipnab never called it, so a run that dropped half the wire produced the
  same confident report as a complete one. Every conclusion downstream — a
  dialog that "never got a 200", a stream "losing 4%" — inherited the gap
  silently, which is the worst failure a capture tool has. The counters are
  now polled on a timer, warned about on the first drop, summarized at exit,
  and carried into `/v1/stats`, the MCP `stats` tool and Prometheus alongside
  the invalid-timestamp count, which had the identical gap: a run with
  unusable pcap timestamps has unreliable post-dial delay, jitter and MOS and
  no surface said so. They stay three counters rather than one total because
  the remedies disagree — a kernel drop wants a bigger buffer, an interface
  drop cannot be recovered by one, and a bad timestamp loses no packet at all.

- **`-B/--buffer` was documented in MiB and implemented in megabytes, and went
  negative past 2047.** The multiplier was decimal, so every value handed to
  libpcap was ~4.8% smaller than the one asked for; and the product was cast
  to a C `int` unbounded, so `--buffer 2148` reached
  `pcap_set_buffer_size()` as −2,146,967,296. It is a MiB multiplier now, on
  saturating arithmetic, clamped to the largest whole MiB that fits a positive
  `i32`, and page-aligned for 4, 16 and 64 KiB pages.

- **The receive loop waited for packets it already had.** `poll(2)` ran before
  every packet, including when the mmap'd ring still held data. The wait moved
  to the ring-empty path.

- **`--cores N` on a live source silently ran on one core.** `--cores` selects
  offline parallel reconstruction, which needs the whole file up front, so a
  live device and `--multi-device` fall through to the single-threaded path —
  correctly, and until now without a word. An operator sizing a host on its
  core count was doing it on a false premise. It warns; it does not refuse,
  because the output is complete and only the parallelism is missing.

- **`architecture.md` said active responses "run in an isolated child".** They
  run in a thread, and have since D15 was written.

### Changed

- **The kernel capture buffer defaults to 64 MiB instead of 2 MiB.** 2 MiB
  holds a few milliseconds of a busy trunk. A larger fixed default can fail
  where a smaller one worked — a constrained host, a locked-down container —
  so the open halves down a ladder to a 2 MiB floor and reports the size it
  actually got, because a bigger default must never turn a working capture
  into a failing one.

- **The per-packet critical section no longer forks, locks or writes.**
  `--on-dialog-exec`, `--on-quality-exec` and `--alert-exec` each reached
  `Command::spawn()` — a real `fork`/`exec`, hundreds of microseconds against
  a per-packet budget of hundreds of nanoseconds — while both store write
  locks were held, with the alert engine's own lock taken as a third beneath
  them on an ordering rule written down nowhere; per-message output went
  straight at the stdout sink, putting `write(2)` in there too. All three are
  now decided under the guards, where they need the store, and performed after
  the guards drop, where they do not. Rate-limit budgets, queue-depth caps and
  child reaping are unchanged: a decision parked between the two is declared to
  the rate window, so `--exec-rate-limit N` still means N.

### Security

- **`$SIPNAB_AUDIO_PLUGIN` was `dlopen`ed ahead of the trusted paths.** An
  environment variable selected native, unsandboxed code into a process
  holding TLS key material, bearer tokens and the capture handle — including
  when that process had gained `cap_net_raw` at `execve` and so had inherited
  its environment from an unprivileged invoker. It is tried last now, and only
  when the process gained no privileges at exec and the file is a regular file
  owned by root or the invoker, not group- or world-writable, in a directory
  that is not either.

### Added

- **`docs/tuning-capture.md`** — how to size the ring, read the drop counters,
  tell a kernel drop from an interface drop, and why `any` costs what it costs
  against named interfaces.

- **netmap in the static musl builds.** libpcap moves to 1.10.6 (the first
  release that reports netmap in `pcap_lib_version()`, so its presence can be
  asserted rather than assumed) and the image build fails if `pcap-netmap.o` is
  not in the archive.

**Not measured.** The throughput changes here are reasoned from syscall counts
and libpcap's ring arithmetic, not benchmarked against a live NIC at line rate.
The drop counters added above are the instrument that measurement needs.

## [0.5.75] - 2026-08-03

### Added

- **A frame read from a capture can be named, and the name can be followed
  back to the bytes.** sipnab tells you a call failed because the far end
  never answered, that a stream lost 4% of its packets, that a message
  violates RFC 3261 — each drawn from specific bytes in a specific capture,
  and until now none of them said which bytes. That is fine while the reader
  is the person holding the capture. It stops being fine the moment the
  conclusion travels into a ticket, a mail to a carrier, or an agent's
  context, where it becomes an assertion with nothing behind it. The problem
  was never that sipnab is wrong; it is that sipnab could not be checked.

  Every frame read from a file now carries a pointer, rendered
  `<source>#<ordinal>`, and `capture::resolve` follows one back to the frame.
  The ordinal counts within ONE file rather than across the run, so the same
  frame keeps its name however the run was invoked — read alone, as a
  directory, or as the second of a glob. A run-global counter would have been
  simpler and useless, because two runs could then never be compared.

  Following a pointer has four outcomes and never blurs them: the frame is
  there and its digest matches, the frame is there and no digest was recorded
  to check, the frame is there and the digest DIFFERS, or the frame is not
  there at all. The third refuses rather than returning bytes. A pointer that
  resolves to the wrong frame is worse than no pointer — it manufactures
  confidence, exactly as naming the wrong input file in an exported pcapng
  did — and "the capture was rotated since this pointer was made" is not
  something a reader can otherwise detect. `Unverified` stays a distinct
  answer from `Verified` for the same reason: "nobody checked these bytes" and
  "these are the bytes the finding was about" are different statements.

  Digesting every frame costs nothing measurable — 0.41s against a 0.42s
  baseline over a 100 MB capture — and uses FNV-1a rather than
  `DefaultHasher`, whose output is explicitly unstable across Rust releases
  and would silently stop verifying valid frames after a toolchain upgrade.

  Nothing emits these pointers yet. `docs/design/packet-provenance.md` sets
  out the remaining stages.

- **Three more conformance rules: the dialog target, and reliable
  provisionals.** A 2xx answer to `INVITE` with no `Contact` (RFC 3261 §12.1.1)
  creates a dialog with no remote target, so the call answers and then cannot
  be acknowledged or hung up cleanly. A provisional demanding `100rel` with no
  `RSeq` (RFC 3262 §3) asks its receiver to acknowledge a response it cannot
  name. And a reliable provisional the dialog never acknowledged with a `PRACK`
  (RFC 3262 §4), which the caller hears as ringing that never becomes a call.

  The `PRACK` rule is the first dialog-scoped rule with a truncation guard. A
  capture is a window, not a transcript, and the naive version fires on every
  dialog whose file stopped between the provisional and the acknowledgment. It
  reports only where the capture already proved it saw the rest: the dialog
  carries a final response to the `INVITE`, so an absent `PRACK` is genuinely
  absent rather than off the end of the file.

  The `Contact` rule immediately caught three of this repository's own
  fixtures, which claimed to be conformant calls while answering `INVITE`
  without a `Contact`. The fixtures were wrong and are fixed.

  Corpus evidence, and it does not say the same thing for all three. The
  `Contact` rule is well exercised: 1,989 2xx answers to `INVITE`, every one
  carrying a `Contact`, so the rule reaches its own code path 1,989 times and
  declines each time. The two RFC 3262 rules are not exercised — the corpus
  holds exactly one reliable provisional and one `PRACK` — and the rules page
  says so rather than presenting their zero as a measurement.

- **RFC 4028 session timers, four rules.** The linter knew nothing about
  session timers, which are a routine interop breaker: a call that drops at
  exactly 30 minutes is almost always a refresher nobody claimed. All four read
  one message on its own, so a message linted alone still settles them.
  `Session-Expires` below the `Min-SE` carried beside it (§7.1) contradicts
  itself inside a single request and draws a 422 from any UAS honoring the
  floor. `Session-Expires` and `Min-SE` each below the 90-second minimum (§4,
  §5). And a 2xx answer to `INVITE` that negotiates a timer without naming a
  refresher (§9), where both ends can end up believing the other refreshes.

  The §9 citation was checked against the table of contents in RFC 4028 rather
  than recalled, and the check earned itself: the behavior sections run 7 UAC,
  8 Proxy, 9 UAS, and the recollection that put UAS at §8 would have sent
  readers to the proxy's rules about the same header field.

  All four report zero against the local corpus, and that number was taken
  apart rather than trusted. The corpus carries 1,849 messages with
  `Session-Expires`, 471 of them 2xx answers to `INVITE`, and every one of the
  471 names a refresher — so the rule reaches its own code path 471 times and
  declines each time. Nothing in the corpus sits below the 90-second floor
  either. Silence with evidence behind it, rather than a rule that cannot fire.

- **The linter's suppression file exists now, and it cannot hide silently.**
  `LintConfig::suppress_list` parsed the file *shape* and nothing loaded a file
  or exposed a way to name one, so the `.sipnablint` a CI user needs on day one
  was a parser with no reader — the same parsed-and-never-consumed shape as the
  RTCP Extended Reports and the Prometheus counters this cycle already fixed.

  sipnab now looks for a `.sipnablint` beside the capture and climbs toward the
  project root, stopping at the nearest ancestor holding a `.git`. A capture
  living outside any project — a corpus mount, a shared drop, `/tmp` — adopts
  nothing from above itself, because inheriting a stranger's suppression list
  would switch off rules nobody here turned off and the run would come back
  clean for a reason four directories away. `lint_dialog` and
  `validate_message` take a `suppression_file` that overrides the search
  outright, and a file it names that sipnab cannot open is refused rather than
  quietly linted with every rule on.

  Every response now carries `suppressions` (the file applied, its patterns,
  and how many findings it silenced) and `findings_withheld`, **including when
  every number is zero**. A response with no field and a response with zero are
  not the same claim: the first says nothing about whether the run hid
  findings, the second says it hid none.

  The three reasons stay apart — `suppressed`, `below_severity`, `capped` —
  because they send an operator to three different places. Making the
  suppressed count exact meant `FindingSink::wants` had to stop
  short-circuiting on suppression: skipping the rule saved the work and
  destroyed the only thing that could count its findings, so a suppressed rule
  now runs and the sink drops and counts the result. `capped` remains a lower
  bound and says so, since a rule may stop once it hits the cap and nothing can
  count what it never raises.

- **The conformance linter is reachable from an agent.** 0.5.74 shipped the
  linter as a library module with 83 unit tests and corpus-measured hit rates,
  and registered no MCP tool for it. The capability existed and nothing could
  call it — the same shape as the RTCP Extended Reports that were parsed and
  dropped, and the Prometheus metrics that were declared and never incremented.
  Three tools close it:

  `lint_dialog` runs the whole catalog against one call, media included, and
  is described to the model with the declaration-versus-observation rules
  first, because those are the ones no other tool can run: SDP declaring PCMU
  on payload type 0 while the wire carries payload type 8, RTP arriving on a
  port no `m=` line advertised, `sendrecv` negotiated with media flowing one
  way. `validate_message` checks one message by index. `explain_rule` turns an
  identifier from a finding, a CI log or a suppression file back into its
  catalog entry with a link to the cited section.

  Findings cross the wire exactly as the library shapes them, `rfc` and
  `section` as separate typed fields rather than folded into the explanation.
  That is the whole point of the shape: an agent quotes RFC 3264 section 6.1
  out of the data instead of inventing a section number that reads plausibly.

  `rulesets` narrows a run by catalog name (`all`, `must`, `rfc`, `interop`,
  `observation`, `syntax`) or by the RFC a rule cites (`rfc3261`, `rfc3264`,
  `rfc4566`, `rfc3551`, `rfc5761`), and only RFCs the catalog really cites
  parse — `rfc3621` is one transposition from `rfc3261`, and accepting it would
  have selected nothing and returned an empty finding list that reads as a
  clean call.

  Every response names the rules the run could not evaluate, grouped by reason.
  A rule that found nothing and a rule that never ran leave identical finding
  lists behind, and only that field separates them.
  `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` is named there on every call: the stream
  store folds an RTCP report into the stream it describes and keeps no record
  of the endpoint pair it arrived on, which is exactly what RFC 5761 section
  5.1.1 asks about, so no MCP tool can raise it yet.

  Measured over the local corpus: 24,062 dialogs across 60 captures, every one
  linted and message-checked through the MCP surface with zero tool errors.

### Changed

- **The homepage advertises the binary size the artifact actually is.** The
  v0.5.74 release build tripped its own honesty gate — the musl binary is
  10,926,024 bytes against a 10 MB ceiling — so the claim moves to 12 MB rather
  than the number being hidden, across the homepage, the architecture tile,
  `install.md`, the build page and the WASM plugin design note.

- **`docs/sip-lint-rules.md` is on the website.** It was registered in the wiki
  generator and not the site one, so a reader following the rule catalog out
  of the MCP tool reference left the site for a GitHub blob URL.

### Fixed

- **The documented `problems` alias no longer names a field `--filter`
  refuses.** `rtp.orphaned` was withdrawn as a DSL field — it asked whether a
  stream *belonging to this dialog* was orphaned, a contradiction, so it
  matched nothing anywhere while `NOT rtp.orphaned` matched everything — but
  `docs/examples.md` and the site cookbook both still spelled it out inside
  the `problems` alias. So the published documentation promised a broader
  sweep than `--filter problems` performs and named a field that exits 2, and
  anyone building on the quoted expression got an error listing fields that
  do not include what they had just copied. A gate now compares the quoted
  expansion in both documents against `expand_alias` itself.

- **A pcapng frame names the capture file it actually came from.** Reading a
  set — `-I a.pcap -I b.pcap`, a directory, a glob — and writing `--pcapng`
  recorded a SINGLE Interface Description Block named after the FIRST input,
  with every Enhanced Packet Block pointing at it. Frames read out of the
  second file claimed, in the exported file's own metadata, to have been
  captured from the first, and nothing looked wrong: the file opens, the frame
  count is right, and a reader has no reason to doubt it. That is worse than
  recording no source at all, because an exported pcapng is evidence. Each
  input now gets its own IDB and each frame references the one it came from,
  for repeated `-I`, a directory and a glob alike.

- **ICMP media findings reach the machine-readable surfaces.** A finding could
  be recorded, attributed and printed on stderr while `--report`,
  `--json-dialogs`, the REST dialog document and MCP all saw nothing —
  evidence that reaches no consumer, the same shape as the RTCP Extended
  Reports and the Prometheus counters this cycle already fixed. On the
  reference corpus the structured surfaces carried none of the findings stderr
  carried. Each finding now travels with its attribution tier as a stable
  token, because a flow-level guess and an exact five-tuple match are not the
  same claim and no surface may emit one without saying which it is. A media
  flow is not a dialog, so the section is capture-wide — a large share of these
  errors name no call at all, and hanging them off dialogs would have hidden
  exactly those.

- **A hook that fails says so.** `--on-dialog` and `--on-quality` are an
  automated-response path — an operator wires one to a firewall command and,
  seeing nothing in the log, concludes the ban landed. The reaper matched the
  child's exit status with a wildcard and discarded it, so a command that
  exited 7 and one that exited 0 produced byte-identical output: silence.
  Silence meaning "it worked" and silence meaning "it never worked" are the
  two answers an operator must never have to tell apart. Exit status is now
  reported, alongside counts of what settled, what never finished and what
  the rate limiter suppressed.

- **`--cores N` compacts and flags orphans, like the single-threaded path.**
  The receive loop sweeps every five seconds of capture time; the parallel
  path never swept at all, so the two modes answered differently on the same
  input — on one reference set `--cores 4` reported no orphaned streams where
  single-threaded reported 613. A `final_sweep` now runs exactly once, after
  the merge, against the merged capture clock: per-worker sweeping would
  measure each fragment against its own clock. Order matters and is pinned —
  orphan marking before compaction, because compaction sheds the messages
  orphan detection reads.

- **The pre-commit hook names what failed.** Clippy and the test run both
  printed `FAIL` and a "run it yourself" line, so whoever hit it paid for a
  second full run of the same suite just to learn the name of the test — and
  until that run finished could not tell whether the break was theirs or
  already on HEAD. Every failure path now prints the part of the capture that
  names the problem, writes the whole capture beside it, and stays bounded: a
  wall of text on every commit is read as carefully as no text.

- **A generated docs page can no longer ship unreachable.** Registering the
  rules page produced a published page that no nav pointed at, reachable only
  by a URL nobody had. The gate that existed covered `docs/internals/` only,
  and the first attempt to widen it read the header dropdown alone — which
  passed while the page was missing from the sidebar that every reader inside
  the docs actually uses. `every_site_operator_page_is_in_every_docs_nav` now
  reads the generator's own page registry and requires an entry in all three
  navs: the dropdown in `base.html`, and the `nav_group` lists in `page.html`
  and `section.html`.

## [0.5.74] - 2026-08-02

### Added

- **An agent can open a different capture, and every answer says which capture
  it came from.** The `open_capture` MCP tool loads another file from
  `--mcp-file-root` and replaces the dialogs and streams the server holds. It
  needs `--mcp-allow-open-capture`, off by default, and the tool is registered
  either way so a refusal names the flag rather than the tool going missing.

  Two things had to exist first, and both are reusable rather than particular to
  this tool. `capture_status`, `stats` and every paged whole-store response now
  carry a `capture_identity`: a capture-instance id plus the dialog and stream
  generation counters, which were bumped on every mutation and exposed nowhere.
  A poller can finally tell "the capture grew" from "this is a different
  capture, throw away your cursor". And the read runs on its own thread rather
  than inside the handler — the REST API and MCP share one runtime thread, so a
  multi-gigabyte pcap read in a tool handler stopped every other client for its
  duration. `capture_status.load` reports the packet count while it runs.

  The tool refuses a live source outright, because a live capture's writer never
  finishes and a second writer would race it for the life of the process. It
  also refuses while the current source is still filling the stores, or while
  another load is running. `server_capabilities` gained a `runtime` object
  reporting `--mcp-file-root`, `--mcp-allow-shutdown` and
  `--mcp-allow-open-capture`, so an agent can check what a server permits
  instead of discovering it by being refused.

- **A SIP conformance linter, led by the class only sipnab can check.** Every
  other linter compares text against a grammar. sipnab holds the media in the
  same process, so it checks what the SDP *declared* against what the wire
  actually *carried*: a payload type negotiated but not sent, a media port
  advertised but not used, `sendrecv` agreed and media flowing one way. Across
  the local corpus those fire 15, 43 and 1 time. The RFC rules follow —
  mandatory headers, Content-Length disagreeing with the body, the `z9hG4bK`
  cookie that identifies a pre-3261 stack on sight, `To`-tag in an initial
  request, ACK CSeq mismatch, and the RFC 3264 answer rules.

  Every finding carries its RFC section as a field rather than as prose inside a
  string, which is what lets an agent cite RFC 3261 section 20.10 instead of
  inventing a plausible-looking one. Rule ids are stable, so a finding is
  suppressible in CI and citable in a carrier ticket. Documented in
  `docs/sip-lint-rules.md`.

- **RTCP Extended Reports are kept, as the far end's claim.** The parser
  decoded all 19 VoIP Metrics fields and the store dropped them. Across the
  corpus that is 589 XR packets and 575 VoIP Metrics blocks. They now land in
  the same provenance side-table the reception reports use, and nothing
  overwrites sipnab's own jitter, loss or MOS with them — `MosProvenance` gains
  a third category, `ReportedByEndpoint`, distinct from both a grounded estimate
  and a placeholder. The TUI shows them below everything measured and
  deliberately does not color them like a sipnab MOS, so two numbers cannot
  read as one.

- **ICMP errors that quote media are visible.** 3,262 quoting a SIP request were
  read and 514 quoting anything else were parsed and dropped. Attribution is
  tiered and the tier is reported, because an exact 5-tuple match and a
  no-match guess are not equally strong claims.

- **A gate that every CLI flag reaches something that reads it.** This project
  kept rediscovering flags that parse, validate, document themselves and do
  nothing. All 151 are swept.

### Changed

- **The MCP surface is described as it is, not as "read-only".** That stopped
  being true when file export and shutdown landed. The invariant that does hold
  is narrower: no tool alters the analysis an operator is reading. Ending a
  session is visible. Rewriting the evidence underneath someone mid-incident
  would not be. The surface is 25 tools.

- **`--rtp-interval` says it is accepted and ignored.** Periodic RTP statistics
  reporting is not built. The flag stays so an existing invocation keeps
  working, and sipnab warns when a value is passed, because the documentation
  taught "stats every 5 seconds" as a worked example.

- **`-t` describes what it does.** It decodes DTMF and logs each digit. Both
  documented examples showed it in modes that hide the log.

### Fixed

- **`export_audio` could never succeed.** RTP payload retention was off for
  every MCP run, so the tool decoded an always-empty buffer — for every call, in
  every capture, in every build. Retention now follows whether the run can read
  it back, and the memory bound is stated at startup.

- **A mixed-link-type export mislabelled every frame.** Exporting an Ethernet
  capture with a Linux SLL2 capture exited 0 and wrote 235,769 frames that
  `capinfos` called Ethernet, where tshark found 7 SIP frames against the
  source's 2,598. Plain pcap now refuses and names both link types. pcapng
  represents it faithfully and recovers all 2,605.

- **`--alert-exec` had no rate limit.** A detector naming 180 peers spawned
  against all 180. On a real capture the fix took 231 spawns to 24 with every
  alert still firing. All of the suppression came from the per-source cap and
  none from the global one, so a global-only limit would have changed nothing.

- **`--hep-send` says what a capture file forwards**, before it opens the file.
  The export is byte-identical either way.

- **`-I` resolution says what it left out.** Against a real corpus sipnab read
  15 files and said nothing about 122 more in three subdirectories, in a line
  identical to the one a complete read produces.

- **The dialog store reports what it shed.** Three loss counters existed and
  none had a consumer. On the corpus, 402 messages were evicted while the
  summary reported 103,234 and said nothing.

- **The Prometheus metrics move.** They were declared, rendered, and never
  incremented, with two reporting a hard 0.

- **The MCP handshake names sipnab.** Every client was told it had connected to
  "rmcp" and the rmcp crate version.

- **`capture_status` reads `source_exhausted` after `done`, not before.** One
  answer could carry a finished load beside a stale flag, so a poller that
  stopped on `done` waited for an update that never came.

- **`--exec-rate-limit` reaches `--alert-exec`**, and the HEP destination is
  minted at the call site rather than inside the constructor.

## [0.5.73] - 2026-08-02

### Added
- **ICMP errors quoting a SIP request are now evidence, not invisible.** A
  router answering "host unreachable" for an INVITE is the most diagnostic
  packet a capture can hold — it is a categorical statement that the far end is
  not there — and sipnab never looked inside ICMP at all. Five corpus captures
  each lost about 26% of their SIP to it; the deficits matched their ICMP counts
  exactly.

  ICMPv4 (RFC 792) and ICMPv6 (RFC 4443) errors are parsed, the quoted datagram
  is read as a *prefix* rather than a message, and the evidence is filed against
  the dialog by `Call-ID`. It surfaces as the `icmp_unreachable` finding in
  `--json-dialogs`, `--report`, the REST API and MCP, and as a capture-wide line
  in the batch summary.

  On one capture: **97 dialogs gained a stated cause where none had one**, and
  the SIP message total is unchanged at 1902 — a quote is evidence about a
  message, never a message. The quote is truncated by design, so a partial
  request is never counted as a complete one. `unreachable_endpoint` and
  `reported_by` are kept distinct: the reporter is usually a router in the path,
  and blaming it sends an engineer to the wrong device. `errors` is exact while
  `samples` is capped — 720 of 3,232 real errors fell past the sample cap, so
  counting samples would have reported "8 times" for a peer that failed thirty.

### Fixed
- **Scanner detection flagged the carrier's own PBX and customer phones.** The
  behavioral rules stood on a request rate, and volume does not separate
  reconnaissance from operation — a trunk sends OPTIONS keepalives by design.
  On an ordinary 11-second carrier capture the busiest "scanner" was an Asterisk
  PBX with 2,713 keepalives.

  Both rules now require an **outcome the capture already holds**: five or more
  refusals matched to a probe transaction by top-`Via` branch, or five or more
  probes still unanswered after RFC 3261's T1. Auth challenges and ordinary call
  outcomes are not refusals, and `5xx` blames the server. A peer that completed
  a registration or a call needs four times either number.

  Across ten captures of one trunk: **25,738 scanner alerts became 21**, all
  from User-Agent matches, with no behavioral source at all. Corpus-wide, six
  behavioral sources remain and every one is supported by an outcome in the
  packets.

  **What it misses is documented rather than tuned away**: a sweep the box
  answers `200` — which is what the corpus's own real scanner traffic is — is
  invisible to the behavioral rules and caught only by User-Agent.

- **Three fraud detectors had the same error as the scanner.** `VolumeSpike`
  started from a *guessed* baseline of 1.0, truncated it to an integer, and
  froze it on the first alert — so any source's sixth call in a minute was
  "5× its baseline", permanently. `Wangiri` counted `Failed` and `Redirected`
  dialogs as short calls, and a `404` returns in milliseconds, so three wrong
  numbers to one prefix were call-back fraud. `SequentialScanning` ran over
  every call, so a contiguous DID block tripped it. **405 fraud alerts became
  zero** on the same ten captures.

- **`no_media` and `nat_mismatch` could never be true.** Both need the
  negotiated SDP, and every production caller — CLI, MCP, REST and the filter
  DSL — passed `None`. `--nat-issues` matched nothing on any capture, so an
  operator checking for NAT problems got a clean result and stopped looking.

  `diagnose_media` now takes a `MediaContext` rather than an `Option`, so the
  diagnosis can no longer be asked for while withholding what it needs. The
  context makes each choice explicit: advertised addresses are the **union of
  every exchange**, because RTP spans the whole call and reading only the newest
  offer reports every hold and re-INVITE as a NAT fault.

  The NAT rule had to be rewritten, not merely wired: comparing a stream source
  against one `c=` line would have flagged one direction of **every** healthy
  two-way call. It is now set membership — a source no SDP in the dialog named —
  and addresses only, never ports, since NAT and RTP proxies rewrite ports on
  healthy calls. Verified against `tshark`, including a negative control on the
  exact call the naive rule would have falsely flagged.

- **`rtp.orphaned` is now a parse error rather than a silent falsehood.** It
  asked whether a stream belonging to a dialog belongs to no dialog — the two
  halves exclude each other by construction. It matched nothing on any capture
  while `NOT rtp.orphaned` matched everything, and the `problems` alias carried
  it as a dead term. Orphaned media is real and still reachable through
  `--report` and the REST API, both of which model streams rather than dialogs.

- **`--filter` was ignored by every CLI output path, silently, exit 0.** The
  expression compiled, and then `--report` and `--json-dialogs` rendered the
  whole store anyway; the filter was only ever consulted per-packet in the
  streaming path. `--cores N` never received it at all. On a 2311-dialog
  capture, **every valid expression returned all 2311 rows** — an operator
  narrowing to failed calls got the entire capture back and no indication.

  Now `state == 'Failed'` selects 10, `state == 'Completed'` selects 1712, and
  `--cores 4` agrees with the single-threaded path. `--call-report <ID>` is
  deliberately not narrowed: a lookup by name is not a listing.

- **The alias flags expanded to different expressions than the documentation
  specified.** `--short-calls` was `duration < 10.0` with no state gate rather
  than the documented `duration < 5.0 AND state == 'Completed'`, selecting
  **2310 of 2311 dialogs**. `--slow-setup` tested `setup_time` where the alias
  says `pdd`. `--problems` used a 2-term expression against a documented
  13-term one, and neither was a superset of the other. The flags now route
  through the same expansion the documentation describes.

### Documented
- **`rtp.*` fields read `0` for a dialog with no media, not "unknown"**, and a
  scored stream never goes below `1.0`. So `rtp.mos < 3.5` selects 2292 of 2311
  dialogs on a signaling-heavy capture — nearly everything — while
  `AND rtp.packets > 0` selects 2. The documented low-MOS recipe now carries
  that guard.
- **`no_media`, `nat_mismatch` and `rtp.orphaned` can never be true.** Not
  "absent from your capture" — structurally unsatisfiable. The first two only
  become true when the media diagnosis receives the negotiated SDP, and every
  caller (CLI, MCP, REST, and the DSL itself) passes none. `rtp.orphaned` asks
  whether a stream belonging to the dialog belongs to no dialog. Documented
  where the fields are defined, with the working alternatives.
- **`--fail2ban` emitted a line for every SIP request, with no detector in the
  path at all.** The flag exists to hand detections to a tool whose entire job
  is to ban what it is given, and it was handing over the trunk. On an ordinary
  11-second carrier capture: **4611 lines naming 180 distinct peers** — the
  carrier's SBCs, the PBX and the customer phones. It was pinned that way by a
  golden test, which expected a `scanner_detected` line for a normal two-party
  call's INVITE, ACK and BYE.

  Per-message emission is gone from both the plain and `--group-by` paths.
  Detections still reach the same sink from the detector paths. With a detector
  armed the same capture now yields 2397 lines from 14 sources instead of 7153
  from 180.

  `--fail2ban` alone now produces nothing, and says so — an empty jail log reads
  as "nothing attacked me", which is the most dangerous way for a security tool
  to be silent.

- **Scanner and fraud detection measured their windows in wall-clock time**, so
  a capture replayed from disk had no window at all: nothing ever expired and
  every counter was a lifetime total. Same defect class as the `SweepClock` fix
  in 0.5.72. A source reported as "6 calls in 60s" had a true busiest minute of
  **4**. Now driven by packet timestamps; on one capture, scanner sources fall
  from 17 to 14 and detections unsupported by packet time from 2 to 0.

- **Wangiri fraud detection counted every call as a short call.** The duration
  was read at the INVITE, when the dialog had just been created from that very
  message — so every call measured 0 seconds. The per-prefix tally then walked
  *every* call in the window rather than the short ones, so the prefix it named
  could be one where nothing short ever happened. The one alert on the sample
  set claimed "3 short calls to prefix … in 60s" from a source that sent 3
  INVITEs and got **no response at all** — no call ended, none was short.
  Duration is now measured when a dialog reaches a terminal state, keyed by
  Call-ID so a `200 OK` to a `BYE` cannot count it twice.

- **The 60-second volume window was 61 seconds**, from `<=` on a truncated
  `as_secs()`. Fixed to a strict comparison. Reported separately from the
  over-count above, which had a different cause.

- **`--kill-scanner` could wedge the entire MCP surface permanently.** The
  worker published outcomes with a *blocking* send onto a 256-slot channel that
  nothing in production ever drained, so it stalled on outcome 257, stopped
  draining requests, and the request queue filled behind it. `send_kill` then
  blocked forever — on the capture thread, while holding the dialog and stream
  write locks, which every MCP tool needs to read. Reachable in seconds on a
  live interface: one sample capture produces 7153 detections.

  Neither direction can make a thread wait now. Outcomes are booked in a tally
  before being offered, so a dropped stream event is never a dropped outcome,
  and totals are logged at shutdown.

- **SIP requests with an extension method were dropped from every output.**
  11,623 messages across the sample corpus. The parser matched a 14-name list,
  when RFC 3261 §7.1 makes the ` SIP/2.0` token the discriminator, not the
  method. One capture had 1,215 dialogs holding only a `200 OK` whose request
  had been deleted.

- **`--portrange` discarded a third of the SIP and reported the remainder as
  complete** — 31.2% of messages, 37.7% of dialogs on one capture. Widening the
  default was rejected because it trades a silent 32% loss for a silent 15% one
  and merely looks fixed: the traffic spans 1,198 distinct service ports. Out-of-range
  SIP is now counted per service port and reported beside the totals it reduced,
  so the numbers reconcile. Live capture cannot report this — `--portrange`
  becomes the BPF filter, so the kernel drops the traffic first.

### Security
- The documented fail2ban jail in `docs/examples.md` used `maxretry = 1` and
  `bantime = 86400` with no `ignoreip`, which on a real trunk is a day-long ban
  of the carrier on first contact. Rewritten with `maxretry = 5`,
  `bantime = 3600`, a commented `ignoreip` for trunk peers, a `fail2ban-regex`
  dry run, and an offline step that counts who the jail would ban from a capture
  of a normal hour before anything is enabled.

## [0.5.72] - 2026-08-01

### Security
- **Reading a capture FILE with `--kill-scanner` transmitted real packets to
  third parties.** Offline analysis is supposed to be inert. It was not: the
  scanner-kill responder fired on packets read from a pcap, sending SIP
  responses to the addresses recorded inside it. Those addresses belong to
  whoever was on the wire when the capture was taken — not to the person
  analyzing it, and not to their network. Verified during development: three
  responses (317/317/322 bytes) left the machine for three public addresses on
  ports 5060/5060/5080, from a capture file.

  Fixed structurally rather than with a check. `TransmitPermit` (new,
  `src/security/transmit_guard.rs`) is a zero-size token whose only constructor
  takes the `CaptureSource` and returns `Some` for live capture and HEP, `None`
  for a file. `send_to_v4`, `send_to_v6` and `KillUdpSocket::send_to` all
  require one, so transmitting from an offline run is a compile error, not a
  runtime condition that a future code path can forget to test. Detection,
  alerting and reporting still run offline; the run explains that it will not
  answer, and why.

- **`-O` pointed at the input capture destroyed it and exited 0.** Naming the
  same path for input and output truncated the file being read — frequently the
  only copy of the evidence — and the run reported success. `ProtectedInputs`
  (new, `src/capture/output_guard.rs`) compares canonical paths, so symlinks,
  `./` prefixes and glob expansions cannot slip past, and refuses before the
  first byte is written. Wired into every route that can name an output file:
  the CLI plan, startup commands, the MCP root resolver and the TUI save path.

### Fixed
- **RTCP reception reports overwrote sipnab's own measurements, so the quality
  numbers described someone else's path.** `process_rtcp` wrote the far end's
  `jitter` and `cumulative_lost` straight into the stream, and MOS scored those.
  Two consequences: an unauthenticated packet could move the quality figure, and
  on a mid-path capture the report describes a *different* segment from the one
  in front of sipnab.

  Measured against `tshark` ground truth: sipnab's own measurement agreed with
  tshark on all 533 streams of one capture; its *reported* loss disagreed on 10,
  every one a false positive. A 1302-packet PCMU stream with zero measured loss
  was reported at 5.5% loss and MOS 2.94. The single worst jitter figure in the
  corpus — 272,087 ms — came from RTCP, where the stream's own measurement was
  0.985 ms. The overwrite also erased real loss: a stream with 78 measured lost
  packets reported 0. Corpus-wide, 553 streams had measurements overwritten.

  Reports now go to a provenance side-table (`StreamStore::remote_report`) and
  never reach the score. A remote assertion is no longer reachable through
  `RtpStream` at all, and reports attach to every stream carrying the SSRC
  rather than an arbitrary first match. MOS values will move: 104 of 542 streams
  changed in one capture alone.

- **RTCP XR on an odd port was parsed as RTP and invented streams.** The
  separate-port branch of `is_rtcp_packet` accepted only types 200–204, so an XR
  (207) was handed to the RTP path, where the first report-block header read as
  an SSRC. Corpus-wide: 374 RTCP datagrams misrouted, producing 28 phantom
  streams, all payload type 79. The branch now accepts the whole RFC 5761 range.

- **Jitter was quantised to whole milliseconds, which is larger than the signal
  being measured.** The interarrival delta used `num_milliseconds()`; on a 20 ms
  stream the variation is itself sub-millisecond, so truncation discarded it and
  inflated the result. Against tshark over 529 streams: streams reported above
  tshark's *maximum* jitter fell from 319 to 6, streams inside tshark's
  [min,max] band rose from 210 to 522, and the median ratio to tshark's mean
  went from 2.73× to 1.10× (worst case 39.5× to 3.0×).

- **Static payload types assumed an 8 kHz clock.** `clock_rate_from_pt` knew 8
  of RFC 3551's 24 assigned types and defaulted the rest to 8000, so JPEG, H.261,
  MPV, MP2T and MPA (all 90 kHz) plus L16 and DVI4 were off by up to 11.25× —
  one corpus stream measured 88,336,408 ms of jitter. The full RFC 3551 Tables
  4/5 mapping is applied at stream creation, before the first jitter sample. A
  stream whose clock is still a guess now reports its jitter as unknown rather
  than publishing a number, and late SDP that corrects the clock restarts the
  estimate instead of rescaling history it cannot rescale.

- **Registration diagnosis said "the endpoint is offline" for every rejection
  code.** It said so for `403` in dialogs where the endpoint had already
  answered a `401` challenge — that is, had demonstrably transmitted and been
  answered — and for `480 No DNS results`, where the reason phrase contradicts
  it outright. Corpus-wide the sentence fired 46 times across codes 403, 404,
  480 and 483, and was wrong every time.

  Each code now maps to one RFC 3261 clause: a challenged `403` points at the
  credentials offered, an unchallenged `403` says only that the registrar
  refused, `404` is an unknown address-of-record, `423` reports the expiry
  negotiation, `408` says "consistent with" a reachability problem rather than
  asserting one, and anything not determined by the code reads back the reason
  phrase and stops. The two surfaces that printed this had hand-copied the
  prose, so both said the same wrong thing; they now render one shared string,
  pinned character-for-character by test.

- **Idle compaction evicted the final status code, so completed calls reported
  no outcome.** A 25-message `INVITE` that completed with `200` returned `None`
  from `final_status_code()` after compaction — the report's Code column showed
  `-`, and "no final response" is a fault sipnab diagnoses in its own right, so
  the loss read as a specific failure that never happened.

  `compact_idle` now keeps the messages that carry meaning wherever they sit —
  the opening request, `BYE`/`CANCEL`, and every final response plus `401`/`407`
  — de-duplicated by `(status, CSeq method)` so a `200` sent eight times pins one
  message. The remaining budget goes to the most recent messages, so the middle
  is what compacts. The message cap is unchanged.

- **Offline analysis was not deterministic — the same capture gave different
  answers on different machines.** `compact_idle` and `mark_orphaned` compared
  `Utc::now()` against PACKET timestamps, and the sweep itself was gated on a
  wall-clock `Instant`. Offline those have no relationship: a 2016 capture is
  always "idle", so what survived depended on how many 5-second sweeps fitted
  into the run.

  Measured on a 4.5M-packet set: the release build kept 84,882 messages and a
  44-rung flow ladder; the debug build over the same bytes kept 84,568 and 24
  rungs — 314 messages gone, 1,410 differing report lines. Two engineers reading
  one capture saw different ladders.

  A `SweepClock` now drives both the gate and the sweep's `now` from the
  timestamp of the most recent packet when reading files, and keeps wall time
  for live capture, where it is correct. Monotonic, so a reordered packet cannot
  rewind the schedule. After: byte-identical, zero differing lines.

  The speed-dependence test uses `--replay` as its slow arm rather than a test
  hook, and cannot flake in the failing direction: after the fix the report is a
  pure function of the fixture bytes, so a loaded CI machine makes the two arms
  agree rather than disagree.

- **Input resolution dropped files silently, seven ways.** Symlinked captures
  vanished (`follow_links(false)` makes `is_file()` false for the link itself);
  walkdir and glob errors were discarded by `filter_map(Result::ok)`; the dedup
  keyed on the canonical path while the explicit-file upgrade compared raw
  paths; `--input-name` was read in one place and so did nothing for globs;
  a glob matching a directory was dropped; and `warn_on_overlap` had never
  fired — it applied an absolute `f64::EPSILON` to epoch seconds of magnitude
  1.5e9, which degenerates to exact bit equality, and compared starts rather
  than ranges.

  The run summary reported `paths.len()` — the size of the set decided before
  any file was opened — so a run that opened 3 of 27 files still claimed 27.
  It now reports what actually happened: *"Read 4532272 packets: 14 of 15
  file(s) read in full, 1 stopped early"*.

- **MCP query tools truncated silently.** `list_dialogs` returned 50 of 2311
  dialogs as a bare array with no total, no flag and no cursor — the remainder
  unreachable, not merely unshown. It matters more here than elsewhere because
  the consumer is an LLM: an agent asked "how many calls failed?" counts the
  rows it received and answers confidently.

  `list_dialogs` and `find_problems` now return `{dialogs, returned,
  total_matched, truncated, next_cursor}`, matching `search_by_time`, which
  already did this. Paging reaches all 2311 in 3 pages. The cursor is
  `tail_dialogs`' compound form via one shared parser, but keyed on `created_at`
  rather than `updated_at`: a full listing must not follow records as they move,
  or a dialog gaining a message mid-sweep jumps past a cursor already gone by
  and vanishes.

  `find_problems` and `search_by_time` gained `filter`; `rtp_stats` gained a
  capture-wide mode reaching streams no `call_id` can — `codec-negotiation.pcap`
  has four streams and zero dialogs, and orphans are what NAT and one-way faults
  look like from the media side.

  A MOS bound **excludes ungrounded streams and reports how many**. Silent
  filtering fails both directions: a healthy AMR-WB stream never appears under
  `max_mos`, and a degraded one gets selected on a placeholder. On one file,
  `max_mos: 4.3` returns 36 matched and 18 excluded — every one of the 18
  scoring the identical 4.216 placeholder.

- **`--strip-secrets` sanitised only the first `-I` and exited 0.** Given two
  pcapng inputs it stripped one and left the other's `CLIENT_RANDOM` intact,
  reporting success. It now resolves the full set and refuses anything but a
  single capture, naming every file — a privacy control doing a fraction of its
  job silently is the failure being fixed. `-I <dir>` naming exactly one capture
  now works, where it previously died with `Is a directory`.

- A shipped rpm had no documented install command. Four variants publish;
  `docs/install.md` documented three.

### Added
- `docs/design/large-capture-memory.md` — what happens when a capture's
  retained data exceeds memory. sipnab does not run out; it silently analyses
  less. Includes a measured memory model, the caps that are parsed and never
  read, and eviction that discards the oldest dialogs uncounted.
- `docs/design/deferred-and-declined.md` — four long-open design questions
  resolved, each with what would reopen it. A declined feature with a recorded
  reason is finished work; an undecided one comes back forever.


### Fixed
- **`[limits]` config keys were parsed, validated, documented — and never
  read.** A config saying `dialog_limit = 100` loaded cleanly, printed no
  warning, and still returned 18948 dialogs. `max_streams`, `max_reassembly`
  and `hep_rate_limit` were dead the same way.

  Worse than an absent key, because `config.rs` *validates* them — rejecting 0
  with a helpful message — so sipnab confirms the setting loaded and the
  operator believes the cap is real. Someone capping dialogs on a shared host
  to be a good tenant had no cap at all.

  The cause was in the flags, not the config: each had a clap `default_value`,
  so the field was filled whether or not the operator passed anything. "Not
  given" and "given the default" were indistinguishable, leaving the config key
  nothing to override. The four flags are now `Option`, with the defaults moved
  to `Cli::DEFAULT_*` and resolvers establishing the precedence — explicit flag,
  then `[limits]`, then the default. `--portrange` already worked this way and
  its comment says why; the caps now match it.

  Gated by `every_documented_limits_key_changes_observable_behaviour`, which
  runs the binary with and without each key over a fixture that exceeds it and
  fails if the output is identical. Parsing tests passed throughout — they
  always would, which is exactly how four keys shipped dead.

- **`--cores` lost about half the messages of proxied calls.** Verified on a
  single file: 1173 of 2311 dialogs reported a different `msg_count` under
  `--cores 4` than single-threaded — 4 against 2, 8 against 4. The dialog *set*
  matched exactly, so anything checking Call-IDs saw nothing wrong.

  `parallel.rs` shards by host pair and its module doc asserted that a call's
  SIP between two hosts stays together. That is false through a proxy: the
  messages shard to different workers, and `merge` kept whichever fragment had
  more messages instead of combining them. Now 0 of 2311 differ.

- **`merge` bypassed the dialog capacity cap**, so `--cores N` permitted up to
  N times the configured limit — the setting an operator uses to bound memory,
  silently multiplied by the core count.

- **Dialog eviction was uncounted on the path actually taken.**
  `capacity_dialogs_dropped` was incremented only in the `--no-rotate` branch;
  on the default drop-oldest path nothing counted at all.


### Fixed
- **`--cores N` ignored multi-file input entirely.** `-I <dir> --cores 4`
  returned **0 dialogs** where the single-threaded path returned 18948.
  `run_cores_file` reached for `cli.primary_input()` — the first `-I`
  *argument*, not a resolved file — and handed that raw string to the pcap
  opener, so a directory, a glob, or a repeated `-I` all collapsed to one
  unopenable path. `main.rs` dispatched this mode before `bootstrap::launch`,
  discarding the resolved, timestamp-ordered list the plan already held.

  The genuinely silent form was repeated `-I a -I b`: it read only `a`,
  reported 2 dialogs instead of 3, and exited 0. (The directory form did print
  "Is a directory" and exit 1 — my own reproduction hid that behind
  `2>/dev/null`, which is worth recording as a reminder that a discarded
  stderr turns a loud failure into a silent one.)

  `run_offline_parallel_file` now takes the resolved path set and reads it
  through one worker pool, so cross-file dialog stitching survives: both halves
  of a split call route to the same worker by host pair and land in the same
  store, matching `capture_files`. Error policy now matches too — the first
  file's open failure is fatal, later files are skipped with a log, and a
  mid-file read error stops that file only.

  That last part mattered more than expected: `--cores` previously turned a
  truncated file into exit 1 with **no report at all**, so it discarded the
  analysis of every `tcpdump -C -W` ring buffer it was pointed at, a truncated
  final member being the normal state of one.

  Tests compare dialog *fingerprints* (`call_id state msg_count`), not Call-ID
  sets: `merge` is Call-ID-keyed, so cross-worker fragments union back into one
  entry and an ID-only assertion passes while the reconstruction is wrong.
  Mutation-tested four ways, including restoring the original bug and rotating
  the shard per file.


## [0.5.71] - 2026-07-31

### Fixed
- **The analyze page refused real capture filenames.** `sipnab.com/analyze/`
  gated on a suffix allowlist (`.pcap`, `.pcapng`, `.cap`), which is wrong in
  both directions on files that come out of actual capture tooling.
  `tcpdump -C -W` writes `tg.pcap0` .. `tg.pcap9`, so every member of a ring
  buffer was turned away; captures with no extension were too; one file named
  `.pcap` in a real directory is pcapng inside, which the check accepted under
  the wrong label; and any junk renamed to `.pcap` passed.

  The page now identifies a capture by its leading bytes — the four libpcap
  magic variants, the pcapng Section Header Block, and gzip — and the OS file
  picker no longer filters by suffix either, since that greyed out exactly the
  files people were trying to open. Verified against a real directory: 27
  captures accepted, 15 non-captures (`.sh`, `.log`, `-stamp`) rejected,
  matching the CLI's own resolution file for file.

  **This is not a weakening of security.** The analyze page is client-side
  WASM: the file never leaves the browser, so there is no server to attack, and
  a filename check is defeated by renaming — it never was a control. The real
  boundaries are the WASM sandbox, the parser's own validation, and the
  existing ~250 MB size cap, all unchanged. Rejecting by content is strictly
  more accurate than rejecting by name.


### Fixed
- **A truncated capture file aborted the whole set, and truncation is the
  normal state of a ring buffer.** Shipped in 0.5.70 with multi-file input.
  `capture_files` propagated a libpcap read error with `?`, abandoning every
  remaining file.

  Found by pointing `--recursive` at a directory whose oldest member was a
  partial capture. That file sorts **first**, so the run stopped at file 1 of
  27 and reported **1 dialog instead of 19358** — while exiting 0 and printing
  a summary. The only visible sign was a single `WARN` line.

  It nearly escaped notice twice. In the first directory the truncated member
  happened to sort *last*, so 15 files started and 14 finished with nothing
  lost; and the test written to catch it passed against the unfixed code twice
  — once because the fixture was cut at a record boundary, which libpcap reads
  happily, and once because it asserted on the file read *before* the break.
  A read error now stops that file and the set continues, matching how open
  failures were already handled.

  `tcpdump` leaves the newest ring-buffer member short whenever a capture is
  still running, so this is the common case, not a corrupt-file edge case.


## [0.5.70] - 2026-07-31

### Fixed
- **DNS traffic was reported as RTP streams.** Found by running the new
  multi-file input over 921 MB of real traffic: four one-packet "streams" with
  SSRC `0x00000000` between a host and `1.1.1.1:53`, out of 1217 streams total.

  `is_rtp_packet` inspects the payload only — 12+ bytes, version bits `10`,
  payload type outside the RTCP range — which accepts roughly a quarter of
  arbitrary bytes on the version check alone, and a DNS transaction ID supplies
  the pattern. The strict heuristic (even destination port, three consecutive
  packets agreeing on SSRC, payload type and sequence) would have rejected
  every one, but it never ran: the payload-only branch returns first.

  Below port 1024 the payload now has to be corroborated by that heuristic
  instead of taken on its own word. Real media is untouched — RFC 3550 §11
  places RTP in the dynamic range, and nothing legitimately carries it on a
  system port. Re-run on the same corpus: 1213 streams, the four phantoms gone,
  every real stream and all 18241 dialogs unchanged.

  A phantom stream is not harmless. It is one more row an operator reads past
  during an outage, attached to an endpoint that never carried media.

### Added
- **`-I` reads a directory, a glob, or several files — and reads them in the
  order the packets were captured.** It took a single path; a directory errored
  "Is a directory", a glob errored "No such file or directory" (the shell does
  not expand a quoted one, and over SSH or in an MCP config there is no shell),
  and a second `-I` errored "cannot be used multiple times".

  **The ordering is the part that matters.** `tcpdump -C 100 -W 10` writes a
  ring buffer and then *wraps*, overwriting the oldest file in place. A real
  10-file set measured for this ran `tg.pcap7`, `tg.pcap8`, `tg.pcap9`,
  `tg.pcap0` … `tg.pcap6` in time order — the numeric suffix records where
  tcpdump was in its cycle, not when the packets arrived. Neither lexicographic
  nor natural-numeric filename order reconstructs it, so sipnab sorts by each
  file's **first packet timestamp**. Every timing derivation assumes monotonic
  timestamps: post-dial delay, setup time, retransmission detection, and the
  RFC 3261 Timer B/C/H bounds in the signaling diagnosis.

  **What it buys:** the files feed one dialog store, so a call whose INVITE
  lands in one file and whose BYE lands in the next is reconstructed instead of
  fragmented. On that 921 MB set, reading the files individually reported 20512
  dialogs and reading them together reported 18241 — **2271 calls, 11% of the
  capture, crossed a boundary.** Read one at a time each of those appears as a
  call that never ends plus a stray BYE, and neither half is the truth.

  A file is recognized as a capture by **opening it**, not by its extension:
  `tg.pcap0` has the extension `pcap0`, and `SIP_CALL_RTP_G711` has none.
  Since the first packet must be read anyway to order the set, the open doubles
  as the test and accepts exactly what libpcap accepts. gzip members are
  decompressed transparently, so a directory mixing `.pcap` and `.pcap.gz`
  needs nothing special.

  A file named directly with `-I` that cannot be read is an error; one
  *discovered* by expanding a directory or glob is skipped with a warning,
  because directories hold README files, partial captures, and — in this
  repository's own sample directory — a NetMon capture libpcap cannot open.

  `--recursive` descends into subdirectories, off by default: recursing
  silently can analyze several times the traffic you pointed at and nothing in
  the output would say so. `--input-name` filters by filename glob at every
  depth.

  Packet count, duration and the replay timeline are shared across the set, so
  `--count 100` over four files means a hundred packets, not four hundred.

  Single-file behavior is unchanged, and a test asserts the long-standing
  2-dialog result for the G.711 fixture to keep it that way. One behavior did
  change: `-I` now validates during planning, so a mistyped path fails before
  any thread starts rather than inside the capture reader.


### Added
- **The MCP walkthrough now teaches the tools, not just the wiring.** Every
  deployment scenario was documented in detail and the page stopped at
  *connected* — a reader finished it knowing how to reach sipnab from a laptop
  and nothing about what to ask it. Twenty-four tools, zero worked examples.

  "Diagnose a real problem with the tools" adds six task-first recipes, each a
  question an operator actually arrives with: why one call failed, whether
  codecs caused a 488, why a phone will not register, why audio was bad on a
  call that connected, what you are connected to, and how to save a live
  capture before stopping it. A flowchart puts `triage_call` first, because its
  signaling/media verdict decides which half of the stack to search and
  getting it wrong costs an hour.

  **Every output block was produced by running the tool against a capture in
  `tests/pcap-samples/`**, not written to look plausible. Gathering them is how
  the two codec bugs below were found.

- **The AMR-WB impairment values, from the ITU-T tables that publish them.**
  Follow-up to the MOS placeholder below, which left open what the number
  *should* be for cellular codecs. `src/rtp/emodel_wb.rs` implements the
  wideband E-model — ITU-T G.107.1 (06/2019) as amended by **Corrigendum 1
  (01/2020)** — with the `Ie,WB` values from G.113 (09/2024) Tables IV.1
  (monotic, nine modes) and IV.3 (diotic, six), and the `Bpl,wb` loss factors
  from Table IV.4.

  Deliberately a separate model rather than new rows in `estimate_mos`. Those
  are wideband values anchored at `Ro,WB = 129`; `estimate_mos` is narrowband
  G.107 anchored at 93.2, and mixing them is a 35.8-point scale error, not an
  approximation. A `MOS_CQEW` and a `MOS_CQE` must not be averaged or held to
  one threshold, so the scale is reported with the number.

  Every function returns `Option` and returns `None` wherever nothing is
  published, which is more often than expected:
  - **AMR narrowband has no published value at all.** G.113 has no AMR-NB row.
    GSM-EFR (12.2 kbit/s, `Ie = 5`) and TIA IS-641 (7.4 kbit/s, `Ie = 10`) are
    close relatives at coincident bitrates and are **not** substituted.
  - **EVS is published on the fullband scale only**, SWB mode, diotic. There is
    no EVS `Ie,WB`. G.113's `Ie,fb ≈ Σ Ie,wb + 19` bridge is one-directional.
  - **AMR-WB under loss on a handset is not computable** — `Bpl,wb` exists for
    three modes, diotic only. Borrowing the diotic figure would mix listening
    contexts inside one equation.
  - Three modes have no diotic value and are not interpolated.

  Scoring also needs the **mode**, which the codec name does not carry: the nine
  modes span `Ie,WB` 1 to 41, about 4.49 down to 3.51 MOS. `amr_wb_kbps_from_fmtp`
  pins it from an SDP `mode-set` naming exactly one mode (RFC 4867 §8.1); a
  multi-mode set says what the stream may do, not what it did.

  Two published oddities are preserved rather than smoothed: 23.85 kbit/s scores
  *worse* than the slower 23.05 (`Ie,WB` 8 against 1), an inversion recurring
  across three tables; and listening context is worth up to 15 R-points, so it
  is a required input with no default.

  New reference page [MOS and codecs](docs/mos-and-codecs.md). Its tables are
  gated against the model by `the_published_amr_wb_tables_match_the_model` —
  added because five of the fifteen MOS figures were hand-computed and rounded
  wrong on the first pass, an error small enough to read as plausible.

  Sourced by three independent extractions of the ITU-T PDFs plus an
  adjudicating pass that re-fetched every document and read the equation pages
  as rendered images, the text layer having dropped the Symbol-font operators.
  That pass caught six disagreements, two of which would have shipped wrong on
  a majority vote: Eq (7-13)'s `25 × 1.29` delay factor (understating delay
  impairment by 22.5%) and Eq (7-9)'s `K = 0.08·T + 10`.

### Fixed
- **`rtp_stats` reported `mos_grounded` beside no MOS at all.** The grounding
  flag was added to the tool that publishes stream quality, but that tool
  builds on the NDJSON stream shape, which carries no `mos` field — MOS lives
  on the dialog there. So the flag described a number absent from the payload,
  which is worse than saying nothing: it implies a MOS is present. `rtp_stats`
  now carries the score itself, and the test asserts a real value in the G.107
  range rather than merely that the flag exists.

- **`check_codec_negotiation` reported `no_common_codec` for a call that
  connected.** `SIP_CALL_RTP_G711` offers `PCMA`/`PCMU` and answers
  `pcma`/`pcmu` — each vendor's own spelling — and the comparison was an exact
  string match. A call that answered **200 OK** and carried real G.711 audio
  was reported as a codec mismatch. RFC 4855 §1 makes the encoding name
  case-insensitive; the comparison now folds case while `offered` and
  `answered` keep each side's wire spelling, which is the evidence.

  Not an error but a confident wrong answer, which is worse: mid-outage it
  sends an operator to reconfigure a codec list that was already working.

- **Codecs went unnamed whenever SDP carried no `a=rtpmap`.** Codec names were
  read only from `a=rtpmap`, but RFC 3551 assigns payload types 0-34
  permanently and an rtpmap is required only for the dynamic range (96-127). A
  plain `m=audio 8000 RTP/AVP 0 8` — what most SBCs and hardware phones send
  for G.711 — yielded an empty codec list, which reaches an operator as "the
  far end offered nothing". `static_payload_name` supplies the RFC 3551 Table
  4/5 names; an explicit rtpmap still wins, and dynamic types with no rtpmap
  stay unnamed rather than guessed at. Codec order now follows the `m=` line,
  which is the offerer's stated preference.

- **A link-checker exclusion for LinkedIn.** It answers non-browser user agents
  with HTTP 999 and rejects `HEAD` with 405 even from a browser UA, while
  serving the page normally to a browser `GET` — verified all three ways. The
  link is in the site footer, so one denial failed every built page at once.

- **MOS was a guess wearing the shape of a measurement for every codec except
  three.** `estimate_mos` has a `_ => 5.0` arm commented "Unknown codec,
  moderate impairment", so AMR, AMR-WB, EVS and G.722 all score **4.216** at
  10 ms jitter — byte-identical to a stream whose codec was never identified.
  Verified by calling the function directly.

  For AMR-WB that is wrong by roughly a full MOS point in either direction: its
  nine modes genuinely span about 4.49 down to 3.51. The number reached JSON,
  REST, MCP, both TUI views, Prometheus, the filter DSL's `rtp.mos` and the
  WASM exports, with no caveat anywhere.

  `estimate_mos` still returns a number — an abrupt `Option` would break the
  REST schema, `rtp.mos`, the Prometheus series and the WASM exports at once —
  but the confidence is now published beside it. `mos_grounding()` reports
  `Published` or `Unpublished`, and the `rtp_stats` MCP tool carries
  `mos_grounded` plus a note when false, because an agent reading a bare
  `mos: 4.2` will reason about it either way.

  A test asserts the two cannot disagree: a codec claiming `Published` must not
  score the same as an unidentified stream. Mutation-tested by marking AMR-WB
  grounded, which fails.

  Found by an adversarially-verified spec review. **The deeper question — what
  the number should BE for cellular codecs — is unresolved and needs a
  decision**: ITU-T G.113 publishes wideband values for AMR-WB on a different
  R-scale, but has no AMR-NB row at all and covers EVS only in SWB mode.

### Fixed
- **`--alert syslog` did nothing.** The flag is declared *"Alert channels
  (repeatable: syslog, json, exec)"* and every documented example passes a
  channel name — but it was fed to `AlertRule::parse`, whose grammar is
  `<name>:<threshold>/<window>`. So `--alert syslog` warned *"Skipping invalid
  alert rule"* and enabled nothing, while `docs/examples.md` told the reader it
  was writing to `LOCAL0`.

  For a security path this is the worst available shape: not a crash, not a
  wrong answer, but an operator who believes alerting is on. Nothing fires and
  nothing says so. It affected `README.md`, three cookbook recipes, two CLI
  reference examples and the website mirrors.

  A bare word is now a channel, as advertised. A value containing `:` is still
  parsed as a rule, so anyone who found the old grammar in the source keeps
  working, and an unrecognised word draws a warning naming the valid channels
  instead of vanishing.

  Found by the synthesis step of an adversarial spec review — none of the five
  specs that reviewed this area caught it; it surfaced from reading the flag's
  declaration against its consumer.

### Fixed
- **MCP tool documentation was thinner than the table suggested.** Five tools —
  `triage_call`, `search_by_time`, `list_captures`, `export_capture`,
  `export_audio` — had a row in the tool table and no section of their own. Ten
  more, all predating this release, had a section and a parameter table but no
  worked example.

  The cause was the gate: `mcp_tool_table_lists_every_registered_tool` checks
  the **index**, and an index is not documentation. It was green throughout, so
  nothing signaled the gap.

  Every one of the 24 tools now has its own heading and a real captured example.
  `every_mcp_tool_has_a_documented_section_with_an_example` attributes each
  example to the heading it sits under, so a fenced block elsewhere on the page
  cannot satisfy it, and it is mutation-tested both ways — removing a section
  and removing an example each fail it.

### Fixed
- **The MCP diagnostic tests raced the pcap reader and passed on Linux by
  luck.** They sent a tool call as soon as the server initialized, before
  sipnab had finished reading the capture into the store. Linux won that race
  every time; macOS did not, and reported exactly what an empty store looks
  like — "nothing to export: no messages are held", "call_id not found", and a
  search window covering everything matching nothing.

  A test that wins a race on one platform is an unobserved failure, not a pass.
  The helper now polls `capture_status` until the file source reports
  exhausted, which is what that tool exists to answer, and both call paths
  share one implementation — they were separate, and fixing only one would have
  let the same race back in through the other door. Verified over eight
  consecutive runs and once under synthetic CPU load to widen the window.

### Added
- **`docs/sip-parameters.md` — the IANA SIP parameter registries.** 35 URI
  parameters, 201 header-field parameters and 36 option tags, each with the RFC
  that defines it, built from IANA directly the way `sip-response-codes.md` and
  `sip-methods.md` were. Option tags get a note that a `420 Bad Extension` is
  usually one end requiring a tag the other does not support.

  The "sipnab parses" column claims **three** parameters — `branch`, `tag`,
  `expires` — and says why it is conservative. An earlier draft computed it by
  grepping the source for each name and reported 41 of 204, which was wrong and
  flattering: `m`, `code`, `alg` and `count` all appear in unrelated code, and a
  substring match is not evidence of parsing. The column now names only what
  traces to a real extraction site.

  The page is explicit that unparsed does **not** mean discarded: sipnab keeps
  the full header, so every parameter here is visible in `get_message`, the TUI
  detail pane and any export.

  `sip_parameter_claims_match_the_parser` ties each claim to the accessor
  justifying it, keeps the note that stops the grep being reinstated, and floors
  the registry sizes so a failed fetch cannot ship a short table.

### Added
- **The remaining MCP tools: `list_captures`, `export_capture`, `export_audio`
  and `shutdown_server`.** 20 → 24 tools.

  All three file tools are confined to `--mcp-file-root` and take a **bare
  filename, never a path**. That is the whole security model and it is
  deliberate: `export_capture(path="/etc/cron.d/x")` is a remote code execution
  primitive, not an export. Anything with a separator, a `..`, or a root prefix
  is refused before any filesystem call. Without the flag the tools refuse to
  run rather than guessing a directory.

  `shutdown_server` needs `--mcp-allow-shutdown` (off by default), dry-runs
  unless told otherwise, refuses to discard an unsaved live capture unless the
  caller names the discard, and requests the same graceful stop SIGTERM does
  rather than inventing a second path.

### Fixed
- **The path-traversal test passed against a deliberately broken validator.**
  It asserted only that an error came back — and `/etc/passwd` and
  `sub/dir.pcap` *did* error, from the filesystem, after the code had already
  accepted them and attempted the write. On a root-running server the same
  input would have succeeded. The test now asserts the refusal came from
  validation, and mutation-testing confirms it: the weakened validator's error
  is `writing /etc/passwd: Failed to create output file`, which is the code
  trying, not refusing.

### Added
- **Seven MCP tools, three of them shaped by how VoIP is actually diagnosed.**

  Research on SIP troubleshooting gives one steer above all others: *almost
  every issue that stops a call connecting is a SIP problem, while one-way
  audio and quality are RTP problems*. That split is the **first** triage
  decision and no tool made it, so an agent had to infer it from a pile of
  fields.

  - **`triage_call`** — signaling, media, both, or none, with the evidence for
    each. Start here; the two halves have different causes and different fixes.
  - **`check_codec_negotiation`** — codecs offered against codecs answered, for
    488 Not Acceptable Here, which usually means the far end was offered nothing
    it accepts.
  - **`diagnose_registration`** — registered, rejected, looping on auth, or
    granted a short expiry. "Is this phone online?" is a different question from
    "why did this call fail?".

  Plus four from the roadmap: `explain_response_code` (the IANA registry rather
  than an agent's memory), `compare_dialogs` (two calls, with the differences
  named), `get_sdp_timeline` (codec negotiation over the life of a call) and
  `search_by_time`.

### Fixed
- **`check_codec_negotiation` conflated "no SDP" with "no answer".** A call can
  legitimately carry no SDP — hold with inactive media, a reject before any
  offer — and reporting `no_answer` for it sends an operator hunting a reply
  that was never expected. During an outage that is time spent on a question the
  capture cannot answer. Now four outcomes, with `sdp_exchange_count` so the
  reader can tell absent SDP from SDP carrying no codecs.

  Found by checking a demonstration instead of trusting it: the tool returned
  empty lists on `sip-488-codec-reject.pcapng`, which was *correct* — that
  capture has no `m=audio` line at all — but identical to what a broken
  extractor produces. `mcp_diagnostic_tools_test` now runs the real binary over
  real captures and asserts specific expected values verified from the packets,
  because a plausible-looking result is not evidence.

### Changed
- **Documented what omitting `-d` actually does, which is platform-dependent.**
  The CLI reference said "auto-detects the default interface", which reads as
  *one* interface everywhere and is wrong on Linux in the direction that
  matters. With no `-d`, no `-I` and no `-L`:

  | Platform | Default | Scope |
  |---|---|---|
  | Linux | the `any` pseudo-device | **every interface at once**, loopback included |
  | macOS / BSD | libpcap's default from the routing table, else the first non-loopback | **one interface** |

  Both directions of the old wording misinform. A Linux reader concludes they
  are missing loopback traffic when they are already capturing it; a macOS
  reader assumes the Linux behavior and sees nothing when SIP is not on the
  interface libpcap happened to pick — a capture that looks merely quiet.

  Corrected in `-d`'s CLI help and both CLI reference trees, with promiscuous
  mode's non-application to `any` noted where it belongs.
  `device_default_is_documented_per_platform` holds the wording, mutation-tested
  against the phrasing it replaced.

  `capture_status` now names the resolved default too — `"any (all
  interfaces)"` rather than the `"auto"` it reported when first added, which
  told an agent nothing about whether one interface or all of them were in
  scope.

### Added
- **`capture_status` and `server_capabilities` MCP tools.** Tier 1 of
  `docs/design/mcp-tool-roadmap.md`, which came out of "how do I shut down the
  remote sipnab?" — and found that an agent could not answer a more basic
  question first.

  Every one of the previous eleven tools queried *what was captured*. None said
  **what the server is attached to**. An agent could not tell a live interface
  from a file replay, how long it had run, or whether stopping would lose
  anything, which is precisely why it could not reason about stopping. That gap
  is worth closing on its own, and it is also the prerequisite for a safe
  shutdown tool.

  `capture_status` reports source, name, uptime, counts, exhaustion, and
  `unsaved` — true only for a live capture with no output file, packets held in
  memory and nowhere else. With no capture context attached it reports
  `"unknown"` rather than guessing, because a wrong `"live"` is worse than an
  admission of ignorance when it is the field consulted before destroying
  something.

  `server_capabilities` reports the version and compiled-in features, read from
  `cfg!` so it cannot claim a feature the binary lacks. An agent asking for
  decryption on a build without `tls` previously got a confusing failure rather
  than a clear one.

  Both are read-only, preserving the invariant that no MCP tool mutates a store.

### Fixed
- **Passing both `-I` and `-d` silently read the file.** They parse together
  and `-I` wins: sipnab reads the capture, never opens the interface, and the
  output is byte-identical to a correct run — no warning, no error, no
  indication anything was ignored. Someone adapting a documented pcap command
  to watch live traffic naturally adds `-d` and leaves `-I` in place, and an
  agent then answers questions about a stale capture with total confidence.
  For a diagnostic tool a confident wrong answer is worse than a crash, because
  nobody has cause to doubt it. sipnab now warns on stderr, naming both flags
  and saying which one to remove. A warning rather than an error, since the
  precedence is long-standing and someone may rely on it.

### Changed
- **Live capture is now a first-class step in the MCP walkthrough**, not a
  footnote after the pcap recipe. Reported by a user who had the SSH setup
  working against a file and could not tell whether `-I` was still required for
  real-time capture. The section now shows the `-I` / `-d` choice as a table,
  gives the live command in full, and warns about passing both.

### Changed
- **How-to headings now name the reader's goal, not the mechanism.** Someone
  looking for "sipnab on a remote server, Claude Code on my laptop" could not
  find the instructions, because the section was called *"Scenario 2A —
  SSH-launched stdio: ad-hoc, zero server configuration"*. Accurate, and
  useless to anyone who did not already know that "SSH-launched stdio" was the
  thing they wanted.

  Measured before changing anything: task-first headings ran 90% in
  `tui-walkthrough.md`, 62% in the cookbook and **8%** in `mcp-walkthrough.md`.
  The repo knew how to do this everywhere except its newest surface, whose docs
  were written from the implementation outward. Researched against
  [Diátaxis](https://diataxis.fr/how-to-guides/) — "Choose titles that say
  exactly what a how-to guide shows" — which also names the deeper fault:
  `mcp-walkthrough.md` is a set of how-tos wearing a tutorial's name, which is
  where a label like "2A" comes from.

  16 headings renamed with the mechanism preserved as a subtitle, so nothing
  accurate is lost. The page opens with an "I want to…" index and states that
  it is a set of independent how-tos rather than a sequence.
  `mcp-walkthrough.md` went 8% → 64%; the remainder are legitimately nouns
  (`Codex CLI`, `Cursor`), which is why the new gate is a per-page ratchet
  rather than a threshold. Anchors changed — acceptable pre-1.0, and
  `link_integrity_test` proved no internal link was left dangling.

### Added
- **Diagrams in the user-facing docs.** `build-site-pages.py` had no mermaid
  handling at all, so a diagram in a user doc would have shipped to the site as
  literal fence text — the feature silently did not exist there while working
  one directory over. It now reuses the internals generator's `convert_mermaid`
  and sets `has_diagrams`, which gates the 3.4 MB bundle. `mcp-walkthrough.md`
  gains a block diagram of the three deployment shapes and a sequence diagram
  of the SSH-launched stdio flow.

- **`how_to_headings_stay_task_first`** — a per-page ratchet on the task-first
  ratio. Floors may rise; lowering one needs an argument. Mutation-tested by
  restoring the original headings, which drops the walkthrough to 48% and fails
  the gate.

### Fixed
- **The plugin example tests raced each other.** All five call the same
  `build_example()`, libtest runs them in parallel, so five concurrent
  `cargo build`s hit one target directory. They serialize on cargo's
  package-cache lock but the artifact check does not, so a test could stat the
  path while another build was still writing it — "build reported success but
  produced no artifact". It passed on Linux and failed on macOS, which is what
  a race looks like when you only run it twice. The build now happens once per
  test binary behind a `OnceLock`. Confirmed over six clean-slate runs, and it
  is faster: one build rather than five.

- **The plugin example test failed under coverage.** It shells out to
  `cargo build --target wasm32-unknown-unknown`, and that nested build cannot
  carry `cargo llvm-cov`'s instrumentation — wasm32 ships no
  `profiler_builtins`, so it fails with `E0463`. Scrubbing the coverage
  variables from the child environment fixed the reproduction I could build
  locally and *did not* fix CI, so the flags reach the child by a route that
  simulation did not cover.

  Rather than keep guessing at plumbing that cannot be reproduced here
  (`cargo-llvm-cov` is not installed locally), the coverage job now skips these
  tests by name — the same treatment `cli_goldens` already gets, and for the
  same reason. They run in full in the CI workflow's plain `cargo test`; only
  their coverage contribution is dropped, and the wasm artifact was never
  instrumented anyway. The tests share a `wasm_plugin_` prefix *because* it is
  the skip filter, which the module comment says so a rename cannot silently
  put them back in the coverage run.

### Changed
- **The MCP docs sent remote users down the wrong path.** `docs/mcp.md` said
  "When the agent runs on a different host, switch to the HTTP transport",
  which points the most common setup — Claude Code on a laptop, captures on a
  server you already SSH into — at ports, bearer tokens and a systemd unit it
  does not need. That setup wants stdio over SSH, where nothing listens on the
  server and the SSH key is the authentication. The recipe existed, in
  `mcp-walkthrough.md` scenario 2A, and `mcp.md` linked to it nowhere.

  `mcp.md` now opens with a transport-choice table keyed on *whether anything
  must keep listening* rather than on where the agent runs, and carries a full
  step-by-step SSH quick start: each step tagged `[laptop]` or `[server]`, the
  non-interactive-SSH precheck that prevents the silent hang, a symptom/cause/
  fix table, and the one-line manual invocation that surfaces the error the MCP
  client swallows. The HTTP section now says what it is actually for — a
  capture that must outlive the agent session — instead of "remote".

## [0.5.69] - 2026-07-31

### Fixed
- **CI went red on the plugin work in two ways, both from adding a
  feature-gated flag and a test that builds a real wasm32 artifact.**
  `plugin_example_test` runs `cargo build --target wasm32-unknown-unknown`
  exactly as the docs instruct, which passes locally and fails on a runner
  without that target (`can't find crate for std`) — so the `Check` and
  `Coverage` jobs now install it. The test is not weakened: building the
  artifact is the whole point of it.

  Separately, `readme_long_flags_exist_in_cli` enumerates flags from the clap
  command *as built*, so `--plugin` is invisible under a reduced feature set
  while the docs still describe it. The gate now carries an explicit
  `FEATURE_GATED` list, so a `#[cfg(feature)]` flag is a deliberate entry
  rather than something a reader discovers from a red matrix job.

  Local verification now covers what CI actually runs: all eleven feature
  combinations in the matrix, not just `--all-features`.

### Security
- **A hostile plugin could exhaust host memory before the cap was checked.**
  The WASM host validated `mem.size()` *after* `instantiate_and_start`, but
  WASM allocates a module's declared minimum linear memory at instantiation —
  so a module declaring 2 GiB was handed 2 GiB and only then refused. The test
  that caught it passed, taking 25 seconds to do so, which is what a check that
  reports a problem after causing it looks like. The cap is now a `wasmi`
  `StoreLimits` installed on the store before instantiation, so the engine
  refuses in 0.00s without allocating. Found by adversarial review of the code
  added earlier in this release.

- **Privilege-drop verification now checks EFFECTIVE uid/gid, not only real.**
  The effective ids are what the kernel enforces against and what an attacker
  with code execution inherits. `setuid()` called by root sets real, effective
  and saved together, so the current sequence cannot diverge — which is why
  asserting it costs two syscalls once per process and is worth doing: it is
  the line that catches a future edit switching to `setresuid`, inserting a
  `seteuid`, or reordering the drop. A half-completed drop would leave every
  parser in the program running with authority it was never meant to have.

### Fixed
- **`site_release_date_matches_changelog` enforced the bug it was written to
  prevent.** It compared `release_date` against the CHANGELOG date for
  `version` — the *crate* version — while `download.html` does
  `{% set v = config.extra.published_version %}` and renders that version
  beside `release_date` in a single sentence. So at every release cut the gate
  demanded the date of a release that did not exist yet, and satisfying it
  would have made /download read "v0.5.68 — released <the day 0.5.69 was
  cut>". That is the exact version/published-version conflation the split
  exists to prevent, enforced by the gate meant to catch it. Now reads
  `published_version`, and mutation-tested against the date the old gate asked
  for.

### Added
- **WASM plugin API — third-party dialog detections.** `--plugin <path.wasm>`
  loads a sandboxed module that contributes its own findings, which appear
  under `plugin_findings` in `--json-dialogs`. Behind the **non-default**
  `plugins` feature: the stock build gains no interpreter, no dependency, and
  no flag.

  The backlog said "D7 rules out Lua; WASM is the path if plugins are ever
  needed", which is a conditional nobody had tested. So the spec at
  `docs/design/wasm-plugin-api.md` answers D7's three objections one at a time
  and measures the third rather than arguing it: wasmi costs **+1.56 MB and 15
  transitive crates** (4% on 352), against a 5.0 MB binary and a public "under
  10 MB" claim. It also names the gap the existing three mechanisms leave —
  the filter DSL selects, the NDJSON pipe reshapes, exec hooks react, and none
  of them lets a site-specific *detection* report through sipnab's own
  surfaces.

  A plugin has **no imports at all** — no WASI, filesystem, network or clock —
  so the sandbox is an empty import table rather than an allowlist, and
  `a_plugin_that_imports_anything_cannot_instantiate` holds it. Fuel metering
  cuts off an infinite loop; a fresh instance per dialog stops a plugin
  carrying state between calls, keeping findings a pure function of their
  dialog. Every failure is reported against that dialog and never fails the
  capture.

  Findings must cite evidence indices, exactly as the built-ins must — which
  forced a correction while writing it: the input was specified as the
  `--json-dialogs` document, and that document has no message list, so a plugin
  would have had to produce indices it could not compute. The input now carries
  the messages.

  `crates/sipnab-plugin-example` is a worked example detecting short answered
  calls, built for `wasm32-unknown-unknown` and exercised end to end: the test
  runs the documented build command, loads the artifact, and asserts the
  finding reaches real CLI output. Across the sample captures it fires on five
  and stays quiet on the 60-second call.

- **The OpenSSF badge answer sheet is now gated.** A badge submission is a
  self-certification that nobody audits, which is exactly why its claims need
  something holding them up. `openssf_badge_test` checks the mechanically
  checkable subset: cited files exist, the quoted `test_policy` line is still
  in `CONTRIBUTING.md`, clippy is still deny-on-warning, the named crypto
  crates are real dependencies, and — the one that would have caught the
  original error — the fuzz-target count and every target name match the
  directory. The sheet first claimed 10 targets against a real 15.

### Fixed
- **`SUPPORT.md` and `SECURITY.md` disagreed about where to report a
  vulnerability.** `ISSUE_TEMPLATE/config.yml` routes reporters to a GitHub
  private advisory, `SECURITY.md` asks for email, and `SUPPORT.md` asserted the
  advisory route without checking. Both channels are private so nothing leaked,
  but which inbox a report landed in depended on which page the reporter read.
  `SUPPORT.md` now defers to `SECURITY.md` instead of keeping a second copy of
  the answer, and the gate fails if it starts naming a channel `SECURITY.md`
  does not. **Which route is canonical is still an open question for the
  maintainer** — the docs merely stopped contradicting each other.
- **`js/xss-through-dom` in the hero image swap (CodeQL, high).** The swap
  shipped in 0.5.68 stored the animated demo's URL in a `data-animated`
  attribute and assigned it to `hero.src`. An image `src` is a script-URL
  sink, so a DOM-sourced string reaching it is an XSS flow no matter what the
  value happens to be — "it is a constant I control" describes the current
  template, not the code, and the next edit is under no obligation to keep
  that promise. The URL now comes from Zola via
  `get_url(...) | json_encode | safe`, the same idiom `base.html` already uses
  for config values, which removes the source rather than arguing with the
  sink. The template gate now rejects the data-attribute shape outright.

## [0.5.68] - 2026-07-30

### Added
- **`--json-dialogs` — one JSON object per call, from the CLI.** `--json` has
  always been a per-message stream, and the aggregated per-dialog document
  existed only over REST and MCP. So the documented way to ask "which calls
  failed and why" was `--json` piped through jq, joining `status_code` back to
  `call_id` by hand across a stream that also carries every provisional
  response — which is why a bare `100 Trying` turned up under a
  `state == 'Failed'` filter. The filter selects *dialogs*; the output was
  *messages*.

  Same document the REST API returns, one compact line per call, emitted after
  capture. Pair with `--no-cli-print` to get only the objects.

- **The dialog document now carries `final_status_code` and
  `final_status_reason`.** Without them `state` said `Failed` and the reader
  still had to go back to the message stream to learn whether that was a 486, a
  503 or a 404 — the exact workaround the new flag exists to remove. Auth
  challenges are excluded, so a call challenged and then answered reports 200,
  not the 401. The reason phrase is verbatim from the wire and RFC 3261 §7.2
  leaves it free text, so match on the code.

- **`DialogState::Redirected` — a 3xx is no longer indistinguishable from an
  unanswered call.** RFC 3261 §21.3: a redirect names a Contact the UAC should
  try instead. The dialog ended, the call did not fail, and the retry is a new
  dialog with a new Call-ID. No handler matched 3xx at all before this, so a
  redirected call kept its pre-answer state and read as one nobody answered.

  All four state machines redirect now, guarded on the pre-answer states like
  every other final-response transition, so a late or spurious 3xx cannot
  un-answer a live call. `state == 'Redirected'` works in the filter DSL, the
  REST `state` parameter and the `sipnab_dialogs_total{state}` metric.

  Adding the variant broke five `match` arms loudly — the compiler found every
  one — and would have left four hand-written enumerations quietly wrong: two doc
  pages, a metric list, and a test array. That asymmetry is why
  `documented_dialog_states_cover_the_enum` now checks the pages carry every
  state. A filter value nobody documents is a filter nobody uses.

- **An auth challenge no longer fails an INVITE dialog, and every
  method-by-response pair is now checked.** All four dialog handlers classify
  through `response_class()` instead of carrying their own ranges, and
  `every_method_and_class_has_a_declared_transition` drives 14 methods × 75
  registered response codes — 1050 pairs — against a rule stated per
  (family, class) rather than a transcript.

  The bug that found: a 401 or 407 on an INVITE set `Failed`, and the 2xx that
  followed could not lift it back out, because that transition only admits the
  pre-answer states. So a challenged call that authenticated and connected
  reported **Failed** — while `outcome_code()` correctly reported 200.
  `domain-primer.md` had documented the intermediate rule all along and
  `update_register_state` implemented it; the INVITE handler never did. A
  captured `BYE` hid it by forcing `Completed`, which is why the sample captures
  read correctly. The calls it misreported were the ones still up, or the ones
  whose BYE never made the capture — live capture, in other words.

  `SUBSCRIBE` gets the same rule: a challenge no longer terminates a
  subscription.

  **3xx remains a known gap, now pinned.** A redirect leaves the dialog in its
  pre-answer state, because sipnab has no `Redirected` variant and adding one
  changes the JSON schema, the filter DSL and the TUI column. The matrix records
  the current behavior so the gap is a decision on the record, and closing it
  fails there first.

- **`response_class()` — one classifier, replacing inline ranges in four
  handlers.** `provisional`, `success`, `redirect`, `challenge`, `canceled`,
  `declined`, `failure`. The dialog state machine answered this with `400..=699`
  in one arm, `401 | 407` in another and a bare `487` in a third, restated per
  handler, and two defects lived in the gaps: a 487 could not move a dialog at
  all, and 3xx was handled nowhere. `response_class_matches_the_documented_table`
  reads `docs/sip-response-codes.md` and holds the two together, so adding a code
  to the page without teaching the classifier fails.

- **The hero animates, without costing the LCP metric.** The static screenshot
  stays the `fetchpriority="high"` element and the animated demo swaps in on
  `load`, once first paint is already recorded. Both files are 1200x700, so
  nothing shifts; the animated image decodes before the swap, so a slow fetch
  leaves the screenshot up rather than blanking the hero; and
  `prefers-reduced-motion` skips the swap *and* the fetch, since that
  animation loops forever.

  Video was measured and rejected. 18 frames of terminal text over 14.2s is a
  slideshow, not motion, and video codecs have no temporal continuity to
  exploit: the h264 encodes that beat the 350 KiB lossless WebP do it at SSIM
  0.985 on the text the demo exists to show, and the encode that holds
  fidelity costs 415 KiB — 18% *more* than the WebP already shipping.

- **SIP diagnosis detections 4–7 — missing `ACK`, abandoned/canceled, high
  post-dial delay, registration failure.** The set is complete: a dialog now
  reports an answered `INVITE` that was never acknowledged, a call canceled or
  left without an outcome, ring-back slower than the E.721 target, and a
  `REGISTER` that was rejected or granted less time than it asked for. Every
  finding carries the message indices it was drawn from, and every surface —
  `--json`, `--json-dialogs`, REST, MCP, the call report, both TUI views —
  renders them from the same structure.

  Three detections need a threshold and each is quoted from a numbered clause
  rather than chosen: post-dial delay 11.0 s (Table 2/E.721, 95th-percentile
  international at normal load — post-selection delay is `INVITE` to first
  `18x` under ISDN names), the `ACK` window 32 s (Timer H), and the
  no-final-response window 180 s (Timer C, whose defining sentence is "the case
  where an INVITE request never generates a final response"). `SignalingThresholds`
  makes all three configurable.

  The care is in what these *do not* report. A missing `ACK` is suppressed by a
  `BYE`, because RFC 3261 §15 means a hangup proves the `ACK` arrived — without
  that guard an ordinary completed call whose capture dropped one packet was
  reported as broken, which a TUI snapshot caught and no unit test would have.
  A call with no final response is `NoFinalResponse`, never a failure, and is
  bounded by Timer C so that in-flight calls at the end of a capture stay
  quiet. `Expires: 0` is excluded from registration analysis, since that is a
  phone deliberately going offline.

### Fixed
- **`signaling_diagnosis` was never declared in the call-report JSON schema.**
  `call_report.schema.json` sets `additionalProperties: false`, so every
  diagnosed call report failed validation — and had since detections 1–3
  shipped, not since 4–7. The schema test never caught it because both of its
  fixtures are healthy calls that emit no diagnosis at all, so the one shape
  that could fail was the one shape never tested. The field is now fully
  declared, and a diagnosed fixture is asserted to actually carry a diagnosis
  before being validated.

### Added
- **`SUPPORT.md` and `MAINTAINERS.md`.** The routing already existed —
  `ISSUE_TEMPLATE/config.yml` has sent questions to Discussions and security
  reports to a private advisory for some time — but a reader had to open the
  YAML to find it. Both files state what is already configured rather than
  inventing process, including the parts nobody enjoys writing down: one
  maintainer, no SLA, no maintenance branches, no succession plan.

  Vale now lints both (`CONTRIBUTING.md` and `SECURITY.md` stay out for now:
  35 alerts between them, which is a backlog, not a gate), codespell covers
  them, and `root_community_file_links_resolve` checks that the six root
  community files' cross-references and anchors resolve. Nothing had been
  checking those — the link tests walk `docs/` and the Zola content, so a
  rename of `SECURITY.md` would have broken the sidebar files in silence.

### Fixed
- **`explain_response_code()` had drifted from the registry in both
  directions.** It explained **409 Conflict**, an RFC 2543 code that RFC 3261
  removed and that appears in no registry — the same phantom Wikipedia lists — and
  had no explanation at all for **424 Bad Location Information**, **425 Bad Alert
  Message** or **430 Flow Failed**, all registered. The three are written now,
  and 409 stays with its obsolescence stated, because a capture from an old
  implementation can still carry one and a reader deserves to be told it is dead
  rather than shown nothing.
- **Nine descriptions on the response-code page were table-of-contents
  fragments** — "8.3.1. 202 (Accepted) Response Code ." and similar — from an
  extractor that matched a heading in the TOC instead of the body. Re-extracted
  with the rule that body headings sit at column 0. Only 402 still reads short,
  and "Reserved for future use." is RFC 3261's complete text for it.

- **`docs/sip-header-fields.md` — every header field, and the nineteen compact
  forms pinned to the registry.** All 134 fields from the IANA *Header Fields*
  registry, each with its compact alias where one exists and the RFC that defines
  it, plus RFC 3261 §20's own description for the 47 it defines.

  The compact forms are the part that matters. RFC 3261 §7.3.3 makes `v:` and
  `Via:` exactly equivalent, so a parser that knows only the long form does not
  merely miss a header — it can be walked past deliberately, which is the `y:`
  STIR/SHAKEN evasion `docs/design/compact-headers-spec.md` already records.
  `COMPACT_HEADERS` carries all nineteen and matches the registry exactly;
  `compact_headers_match_the_iana_registry` now holds it there, and separately
  checks that each one actually expands through the parser — a correct table
  wired to nothing would pass a comparison on its own.

- **`docs/sip-methods.md` — every SIP method, recorded the way the response
  codes are.** All 14 in the IANA *Methods* registry, each with the RFC section
  that defines it, a deep link, the RFC's own words, and which of sipnab's four
  dialog state machines it drives. `INVITE`, `REGISTER` and `SUBSCRIBE` each get
  their own; the other eleven share a generic one, which is worth knowing before
  reading a state a method never had semantics for.

- **`SipMethod` is pinned to the IANA methods registry.** All 14 registered
  methods parse to a named variant, and each round-trips to its canonical token.
  Nothing enforced that before, and the failure was silent by construction: an
  unrecognised method becomes `Custom` and falls to the generic dialog handler,
  which is right for a private extension and wrong for a registered one nobody
  noticed. A new registration is now a decision rather than a default.

### Fixed
- **A `487 Request Terminated` with no `CANCEL` in the capture left the dialog
  in `Ringing` forever.** The `487` match arm did nothing unless the dialog was
  *already* `Canceled`, and because it matches before the `400..=699` arm the
  response did not fall through to `Failed` either. So a canceled call whose
  CANCEL went uncaptured reported as one still waiting for an answer — a
  different diagnosis from the one the wire carried.

  RFC 3261 §21.4.25 says a 487 means the request "was terminated by a BYE or
  CANCEL request". The 487 is itself the proof; seeing the CANCEL is not a
  precondition. A CANCEL can take a different path from the response, a capture
  can start mid-dialog, and sampling can drop it. A 487 whose CSeq method is
  INVITE now sets `Canceled` from `Trying`, `Ringing` or `Canceled`, guarded on
  those pre-answer states for the same reason the 2xx arm is: once a final 2xx
  has established the call the CANCEL has no effect (§9, §15), so a late 487 must
  not un-answer it.

  Neither path had a test and no sample capture in the repo contains a 487 at
  all, which is why it survived. Both now have one.

### Added
- **`docs/sip-response-codes.md` — every SIP response code, from the registry
  rather than a summary of it.** All 75 codes in the IANA *Response Codes*
  registry, each with its canonical reason phrase, a deep link to the RFC
  section that defines it, the RFC's own words describing it, and how sipnab
  classifies it.

  Sourced from
  <https://www.iana.org/assignments/sip-parameters/sip-parameters-7.csv>, not
  Wikipedia, which disagrees with the registry in five phrases and lists two
  codes no registry has. 437 is *Unsupported Credential*, not *Unsupported
  Certificate* — RFC 8224 §6.2.2 names the latter as the previous name. 500 is
  *Server Internal Error*, not *Internal Server Error*. 202 reads *Accepted
  (Deprecated)*. 409 and 411 come from RFC 2543, which RFC 3261 obsoleted.

  IANA leaves `Reference` blank for the 50 codes RFC 3261 defines and cites an
  RFC for the other 25. Those 50 line up exactly with the 50 per-code
  subsections in RFC 3261 §21, which is how the convention was confirmed rather
  than assumed.

  The classification is the part sipnab needs: `provisional`, `success`,
  `redirect`, `challenge`, `canceled`, `declined`, `failure`. Only the last is
  a failed call. Folding the others into "failed" loses what an operator acts
  on — a call that drew a `challenge` and never authenticated is a provisioning
  problem, one that ended `canceled` is a caller who hung up, and one that came
  back `declined` reached a human who said no.

  The tables sit inside `<!-- vale off -->`: the descriptions quote normative
  text, which is not ours to reword for a house style guide. `requestor` joins
  the codespell ignore list for the same reason — it is RFC 3261's spelling.

### Changed
- **The Vale style package is pinned to a release, and a gate holds it there.**
  `Packages = Google` resolved through the registry to a `releases/latest`
  download URL, and CI runs `vale sync` on every job — so every prose gate
  depended on whatever upstream published most recently, with no commit in this
  repository. A local styles tree is only as fresh as the last manual sync, which
  means a green local run was not evidence about CI.

  Google v0.7.0 shipped 2026-07-30 13:43 UTC, mid-session, and rewrote
  `Google.OxfordComma`'s regex. A rule measured, mutation-tested and enabled
  against the previous package reported 0 alerts locally and 35 in CI, and main
  went red. Every GitHub Action and container base image here is pinned by digest
  for exactly this reason; the style package was the one dependency that floated.

  `vale_style_package_is_pinned_to_a_release` now fails on a bare registry name,
  on a `latest` URL, and on a URL carrying no `vX.Y.Z`. `build-ci-release.md`
  gains a section on the prose gates, which it had never documented — its
  workflow table described `quality.yml` as coverage and clippy only.

- **The last five backlog rules worked: two enforced, three rejected.** 14
  authored alerts, 28 counting the generated mirrors, and they split four ways.

  Enforced after a small pass: **`Google.Ellipses`** (three ellipses standing in
  for "and so on" in a parenthetical list).

  **`Google.OxfordComma` was enforced and reverted the same day**, and the reason
  matters more than the rule. It was measured, mutation-tested and shipped
  against a local styles tree that was hours stale: `.vale/styles/Google/` is
  gitignored and CI runs `vale sync` on every job, so CI always has whatever the
  registry published last. Between that local sync and the push, Google rewrote
  the rule from a pattern allowing one word before the conjunction to a
  lookahead-based one allowing five. Local reported zero; CI failed with 35.
  Eleven missing serial commas are fixed across both passes. The rest of the new
  rule's alerts do not distinguish a three-item list from a pair — "found and
  fixed", "not by packet or by call" — so enforcing it would mean suppressing
  twelve correct sentences.

  Nothing pins that package. Every enforced rule can change under CI without a
  commit here, and a green local run proves nothing until `vale sync` has run.
  `.vale.ini` now says so.

  Rejected, with the reason recorded in `.vale.ini`:

  - **`Google.We` and `Google.FirstPerson`** — every authored alert sits inside
    quoted user speech. The cookbook opens each recipe with the complaint that
    sends someone looking: **Problem:** *"We had a spike in failures around
    14:00"*, *"I can hear them but they can't hear me."* The pronoun is the
    user's, not the project's, and it is the point of the sentence. The one real
    first-person plural, "a viewer we control", is fixed.
  - **`Google.Ranges`** — all four alerts are the same false positive. The token
    is `(?:from|between)\s\d+\s?-\s?\d+`, so any ISO date after "from" reads
    as a range: "the sentence dates from 2026-07-25" is parsed as "from 2026 to
    07". A repository that writes dates cannot enforce this.

  Two things were misjudged on the first pass and corrected. An apparent
  `OxfordComma` false positive was real — the match started at an odd offset, and
  the list it pointed into genuinely read "two SBOMs, a provenance attestation, a
  GHCR image and a Homebrew formula". And `~1-2 us copy` was flagged as the
  pronoun "us" when it meant *microseconds*; it now says so.

- **Present tense where the docs said "will", and `Google.Will` is enforced.**
  20 authored alerts across 12 files, 38 counting the generated mirrors, and
  every one was real: "the gates that will reject it" became "the gates that
  reject it", "it will never under-report" became "it never under-reports". The
  smallest of the four backlog rules worked this session and the only one that
  needed no exception, no suppression and no fork.

- **Semicolons that joined two sentences are now two sentences, and
  `Google.Semicolons` is enforced.** 137 authored alerts across 27 files, 221
  counting the generated mirrors. **115 were a semicolon standing between two
  independent clauses** — "The core is synchronous; async exists only at the
  edges" — and read better split, which is the whole of Google's advice here.

  The other 22 are kept, because the rule is blunter than the guidance it cites:
  its entire definition is `tokens: [';']`. Semicolons separating list items that
  carry their own commas are the one use Google's own page keeps, and this tree
  has three such lists — the eight pre-commit gates, the bounded-input audit, and
  the workstream history. Those are bracketed with
  `<!-- vale Google.Semicolons = NO -->` in place.

  Three pages are switched off by name instead, with their generated mirrors,
  because a comment directive does not reach the content their semicolons live
  in: `;branch=` and `;tag=` inside SIP headers in a raw-HTML terminal mockup,
  `;` between CSS declarations in a `style` attribute, and an OpenSIPS `trace_id`
  URI in a fence indented inside a numbered list item. Placing a directive inside
  the `<pre>` was tried first and injected blank lines into the rendered mockup —
  the failure `mockup_alignment_test` exists to catch.

### Fixed
- **Two capitals after a colon that should have been lowercase**, in
  `docs/rest-api.md` and `docs/troubleshooting.md`, where a bold label
  introduced a noun phrase rather than a sentence.

  These came out of working `Google.Colons`, which the config listed as 71
  backlog alerts. **That rule is now measured and rejected, not deferred.** Its
  token is `: [A-Z]` — a colon, a space, a capital — with no exception for any
  of the three cases the page it links actually permits. Of 36 authored alerts,
  34 were correct English: 22 where a complete sentence follows the colon (which
  Google capitalises), 9 where an acronym or identifier does (`MOS score`,
  `SN-01`, `D2`), and 3 a proper noun (`Ubuntu 24.04`, `**Dialogs**`). Enforcing
  it would have meant lowercasing 34 correct sentences or suppressing them one
  at a time. `.vale.ini` now carries that breakdown, so the number stops reading
  as 71 pending defects.

- **Two sentences this session's active-voice pass had broken.** `docs/auth.md`
  read "an explicit id, so that it a denylist can name later" and
  `docs/internals/walkthroughs.md` said the compiler "turns away an MCP tool …
  by the compiler". Both were substitutions that replaced a passive clause and
  left its old subject or agent stranded. Found by reading the surrounding lines
  while fixing semicolons in the same paragraphs, which is the argument for
  re-reading a rewritten sentence whole rather than trusting that the replaced
  span was the only part that mattered.

- **Sentence-case headings across the published documentation, enforced.**
  `Google.Headings` was the largest item in the config's known backlog at 311
  alerts. That number counted the generated `website/content` mirrors; the
  authored scope was **156 across 18 files**. 87 were genuine Title Case and are
  rewritten — `Build Dependencies` becomes `Build dependencies`, `Exit Codes`
  becomes `Exit codes`. The rest were the rule not knowing the domain.

  **No anchor moved and no link changed.** Every slugger in the repo lowercases
  before slugging, so `## Call List` and `## Call list` both produce `call-list`.
  Verified rather than assumed: zero link targets added or removed across the
  changed files.

  Forked as `sipnab.Headings` rather than used as shipped, following the
  `sipnab.LyHyphens` precedent. Google's exception list knows Azure and
  TypeScript; it does not know that RTP and DTMF are not words, that `GET` names
  an HTTP method, or that `488 Not Acceptable Here` is a reason phrase from
  RFC 3261. Four sets of headings keep their capitalisation behind scoped
  `<!-- vale sipnab.Headings = NO -->` comments, each explaining itself where it
  sits: the literal TOML tables heading each section of the config reference, the
  alphanumerically numbered sub-sections in the cookbook and the MCP walkthrough
  (Vale reads `10a.` as the first word and lowercases what follows, while
  handling a plain `13.` correctly), and that SIP reason phrase.

  Three things worth knowing before touching this rule again:

  - **An unescaped bracket in the exceptions list silently disables all of it.**
    Vale compiles the list into a regex, so `[capture]` is a character class
    matching any of `c/a/p/t/u/r/e` — which matches nearly every word in every
    heading. The authored count fell from 120 to 11 and read like progress; a
    planted `## A Deliberately Title Cased Heading` went unreported. Escaped, it
    matches nothing; as a bare word it pins `## Capture` lowercase. All three
    forms are recorded in the rule file.
  - **The auto-generated vocabulary fights this rule in both directions.**
    `boolean` and `dialog` sit in `accept.txt` lowercase, so Vale demanded
    lowercase even at the start of a heading; `Combinators` sits there
    capitalised, captured from a Title Case heading, so it demanded a capital
    mid-sentence. Both are the self-referential defect `.vale.ini` already
    records for `Vale.Terms`: the vocabulary was generated from what the docs
    happened to say. Five entries corrected.
  - **`build-site-pages.py` pins an expected H1 per page and fails closed.**
    Renaming six page titles aborted the generator rather than publishing a
    mismatched mirror. Only the expected-H1 field moved; the sidebar label beside
    it is a separate field the script warns not to touch, because changing it
    silently reorders the docs navigation.

## [0.5.67] - 2026-07-30

### Changed
- **Active voice across the published documentation, and `Google.Passive`
  enforced so it stays that way.** The Vale config had carried this rule
  disabled with a note: "866 alerts. Worth fixing, unlike the four above —
  passive voice in a how-to genuinely hides who does what. It is a real editing
  pass, not a config change." Both halves held up. The 866 was measured over the
  whole tree, counting the exempt `docs/design`, `docs/research` and
  `docs/superpowers` subtrees and the generated `website/content` mirrors; the
  authored, enforced scope was **353 alerts across 29 files**, plus 33 in
  hand-authored site-only pages. All of them are now rewritten to name the actor,
  and `Google.Passive = error` holds the result.

  Not forked with an exception list, unlike `Google.LyHyphens`. About a fifth of
  the alerts were adjectives rather than passives — "is unsigned", "is
  unchanged", "is malformed", "is unbounded" — caught by the rule's `[\w]+ed`
  catch-all. Excepting those needs either negative lookahead, which Go's RE2 does
  not have, or swapping the catch-all for an allowlist of participles, which would
  quietly stop catching every verb nobody thought to list. Rewording won on both
  counts: "the token is unsigned" became "the token carries no signature".

  Two places kept their passive because changing it would have been a lie. A
  quoted error string (`cursor position could not be read`) is what the binary
  actually prints, so it became inline code rather than prose. And in
  `domain-primer.md`'s table of wrong assumptions, "`cumulative_lost` is
  unsigned" *is* the mistaken belief being cataloged; it reads "has no sign bit"
  now, which preserves the claim instead of inverting it.

  The promotion needed a matching `Google.Passive = NO` in each of the three
  exempt glob sections. Emptying `BasedOnStyles` drops a section's styles, but a
  rule named explicitly in `[*.md]` is added back on top of that — so the
  promotion linted all three working-document subtrees (506 alerts) until each
  one switched it off again. Any future promotion needs the same three lines.

### Fixed
- **`docs/rest-api.md` opened by introducing itself twice.** The commit that
  merged two REST API pages into one, shipped in 0.5.55, kept both intros: the same "sipnab
  includes an optional REST API and Prometheus metrics endpoint…" sentence
  appeared at lines 3 and 9, and the same "MCP serves the same stores" pointer at
  lines 5 and 11, one as prose and one as a callout. A reader hit the page's first
  claim, then hit it again four lines later in slightly different words, which
  reads like the page is describing two different things. One intro survives, plus
  the callout, which is the better wayfinding device of the two forms.

  `wiki_intra_docs_links_resolve` caught the side effect: the page linked
  `mcp.md` twice, so removing the duplicate removed a real link and the pin went
  180 -> 179. Its comment now says how to tell that apart from the failure it
  exists for — a drop nobody can name is the extractor's regex breaking, and
  editing the number is how that gets missed.
- **Three places claimed the release does not set `MACOSX_DEPLOYMENT_TARGET`.**
  It has set it since 0.5.65, when the pin landed in `release.yml` alongside
  `published_macos_floors_match_the_toolchain` — the workflow step and the
  sentences denying it shipped in the same release. `docs/install.md` told
  readers the floors were incidental compiler defaults that nothing in the
  repository pinned; `website/config.toml` said "release.yml never sets
  MACOSX_DEPLOYMENT_TARGET" directly above the two values it pins; and the gate's
  own doc comment explained that it asks rustc "precisely because `release.yml`
  does not set a deployment target", while its body had already been rewritten to
  read the workflow's pin. The first of the three was fixed a commit earlier and
  the other two survived, which is the argument for grepping the claim rather
  than the file you happened to be reading.
- **The release-artifact counts in `docs/internals/build-ci-release.md` were
  wrong, and now come from the build matrix.** The page said a tag publishes
  "eight artifacts" and called the `noaudio` builds a `.deb`-only variant. A
  release publishes twenty-three assets, fourteen of them installable — six
  `.tar.gz`, four `.deb`, four `.rpm` — and the `noaudio` builds ship an `.rpm`
  too, because both packaging steps gate on the target and never on the variant.
  Neither number had drifted into being wrong: `noaudio` landed 2026-07-07 and
  gained `.rpm` 2026-07-09, while the `.deb`-only sentence was written 2026-07-25
  and the artifact count 2026-07-29. Both were wrong the day they were typed, by
  reading the matrix and counting its rows — eight is the number of *builds*, and
  it stopped equalling the tarball count the moment a build existed that produces
  packages and no tarball.

  `release_artifact_counts_match_the_build_matrix` now derives every count from
  the matrix and the packaging steps' own `if` conditions, so the prose cannot
  restate them freely. It reads the doc's number words and compares numbers,
  rather than formatting expected words and string-matching: the first version did
  the latter, and adding one build to the matrix made it panic about its
  number-word list instead of naming the stale sentence. It also fails when a
  claim is deleted rather than corrected, and refuses to state one count for
  `.deb` and `.rpm` if their conditions ever diverge.

## [0.5.66] - 2026-07-30

### Added
- **SIP problem diagnosis: detections 1–3.** `src/rtp/diagnosis.rs` could say a
  call had one-way audio; nothing could say it failed on a `503` after three
  retransmitted INVITEs, or that a phone had been looping on `401` for an hour
  without ever authenticating. The evidence was always captured and never read as
  a diagnosis. `src/sip/diagnosis.rs` now reads it, per the spec shipped in
  0.5.62, which names these three as the slice carrying the value:
  - **Final failure with cause** — the dialog's outcome `4xx`/`5xx`/`6xx`, with the
    `Reason:` (RFC 3326) and `Warning:` headers that usually hold the real cause
    behind a generic code. The *last* failure before any `2xx` wins: a dialog
    challenged `401` then failed `503` failed on the `503`, and a rejected
    mid-call re-INVITE is not the dialog failing at all.
  - **Authentication loop** — three or more `401`/`407` with no `2xx`, split into
    credential failure (client answers, gets re-challenged) and silent drop
    (client never sends `Authorization`), because the fixes differ. Two challenges
    is normal: the first request is unauthenticated by design.
  - **Retransmission storm** — a request retransmitted with nothing coming back,
    grouped by CSeq *and* top-`Via` branch, since CSeq alone would call three
    distinct INVITEs a storm. Reports count and elapsed span, because "7 INVITEs
    over 32 seconds" is diagnostic and "retransmissions detected" is not. ACK is
    excluded: it is never answered, so counting its repeats would flag every
    dialog.

  Every finding names the messages it was drawn from, as indices into the
  dialog's own message list — the spec's rule that a detection which cannot cite
  its evidence is a guess the reader has to re-derive. Rendered as
  `signaling_diagnosis` in the dialog JSON, omitted entirely when nothing is
  detected, so a healthy dialog serializes exactly as before. Fields for
  detections 4–7 are absent rather than always-null: a field that is never
  populated reads as "checked, nothing found", which would be false.
- **The call report carries the signaling findings.** Text and Markdown both get a
  Signaling section listing each detection with its evidence — which is also what
  MCP's `get_dialog_report` returns for its non-JSON formats. Evidence is labeled
  with the message rather than printed as a bare index: JSON emits `[1]` because a
  machine will join it against the message list, but a report pasted into a ticket
  has no such list to hand, so it reads `#1 503 Service Unavailable`. An index
  outside the message list is reported as out-of-range rather than silently
  dropped, since a quiet drop would make the report claim less evidence than the
  diagnosis found.
- **The TUI call list marks diagnosed dialogs.** A `⚠` in the State cell when a
  dialog has any signaling finding. The spec asked for this "in the style of the
  existing media badge" — there was no existing media badge, though
  `src/tui/call_list.rs` had claimed in its module documentation to show
  "diagnosis warning indicators" for some time. The marker shares the State cell
  rather than claiming a twelfth column, which would have meant widening the label
  list, the visibility array, the column selector and the width table at three
  breakpoints. It is deliberately only a marker: the call list is a dense scan
  view, and what a badge on a row owes the reader is "this one is worth opening".
- **The TUI call flow points at the evidence.** Each message cited by a detection
  carries a `[FAILURE]`, `[AUTH]` or `[NO-RSP]` tag on its arrow, which is the
  surface where "evidence, not verdicts" stops being a data-model decision and
  becomes something a reader sees. A message cited twice keeps both tags rather
  than the last detection overwriting the first. The tag rides on the arrow rather
  than in the annotation zone right of the ladder, for the reason already written
  next to the retransmission-fold count: that zone begins one column left of the
  rightmost pipe and is clipped to roughly a single character at 80 columns, so a
  tag drawn there would be invisible — and an invisible "this is where your
  problem came from" is worse than none, because the reader trusts the ladder to
  be showing them everything.

## [0.5.65] - 2026-07-30

### Added
- **Documentation CI: prose style, spelling, and dead links.** The Rust suite
  compares documented values against the code that produces them and is thorough
  at that, but it cannot tell whether a word is misspelled or a URL still
  resolves — and a page of correct-but-dead links fails a reader as hard as a
  wrong version number. Three checks now run in `Quality`: Vale with the Google
  developer style guide, codespell, and lychee over both the docs Markdown (257
  unique links) and the built site, which is the only pass that can resolve
  site-absolute URLs or see the download page at all, since it is a template.
  Every exclusion in the three configs records the alert count it produced on
  first run, so a considered exemption is distinguishable from a silenced
  inconvenience: Vale went from 13,892 alerts to zero, and the disabled rules are
  the ones whose advice is wrong here — "spell out SIP" on a SIP analyzer (3,675),
  "command-line tool" for CLI (171), and American quote placement in prose that
  quotes exact protocol literals (47).

### Changed
- **The macOS floor is now a decision, not an inherited default.** `release.yml`
  pins `MACOSX_DEPLOYMENT_TARGET` per darwin target instead of letting each one
  take whatever the pinned rustc happens to default to. The values are the current
  defaults, so no binary changes; what changes is that a toolchain bump can no
  longer move the published floor silently.
  `published_macos_floors_match_the_toolchain` now compares `website/config.toml`
  against `release.yml` and additionally refuses a pinned floor *below* the
  compiler's own default — that combination would satisfy a naive
  config-matches-workflow check while still promising an OS the binary cannot run
  on.
- **The Vale config overstated what it was doing.** Five of the eight disabled
  rules sit at `suggestion` or `warning` severity, below the enforced
  `MinAlertLevel = error`, so they reported nothing whether on or off — but their
  comments cited counts from a probe run at `suggestion`, which read as though
  each was suppressing thousands of live alerts. The counts are now measured at
  the enforced level, the preemptive disables are labeled as such, the 670-alert
  backlog that a threshold change would surface is written down, and the rules
  that actually fire are listed by name and verified by mutation.

- **The release-artifact reference has one home instead of two.** `/download` held
  a 19-row artifact table that `docs/install.md` restated in full, and that
  duplication is what produced this release's version drift: the download markers
  moved on one surface and not the other, and two of the three `rpm -i` recipes
  were never gated at all. Diátaxis puts it plainly — a how-to should "refer to
  the x reference guide for a full list of options" rather than inline it. The
  table, the architecture-name mapping, and the platform floors now live in
  `docs/install.md#release-artifacts`; `/download` keeps the task paths (installer,
  per-platform packages, Docker, verify) and links to the reference. The docs table
  uses `<version>` placeholders rather than 19 concrete version strings, so
  consolidating did not trade one drift surface for a larger one.
- **`docs/install.md` had the same `.rpm` omission as the download page.** Its
  architecture-naming paragraph said tarballs use one spelling and `.deb` packages
  the other, never mentioning that `.rpm` packages use the first — the identical
  gap, on the second surface, which is what having two copies produces.

### Fixed
- **The two checksum commands on `/download` could only be copied together.**
  The macOS `shasum` and Linux `sha256sum` recipes shared one terminal block and
  one copy button, so a drag-select or the button took both lines. Whichever
  command was wrong for the visitor's machine came along with the right one, and
  pasting that into a shell runs a command they did not choose. Each is now its
  own block with its own copy button, titled by OS.
- **"View install.sh" downloaded the script instead of showing it.** The link
  pointed at the Pages-served copy, which is sent as `application/x-sh` with
  `nosniff`, so the browser saved a shell script to disk. A link inviting a
  reader to audit the code before piping it to `sh` must not hand them the file
  to run, and `Content-Type` is the server's to set — no markup attribute
  overrides it. It now points at the GitHub blob view, where the same
  `website/static/install.sh` renders as text.
- **The verify section justified itself with the product tagline.** "sipnab is a
  security tool" was the stated reason to check a checksum, which is circular:
  the reason is that you are about to run a binary fetched over the network and
  install it into `/usr/local/bin` under `sudo`. Both the section lead and the
  download-tile hint now say that instead.
- **`/download` invented a macOS floor.** The artifact table said "macOS 12+" for
  both darwin tarballs. Nothing produced that number: `release.yml` never sets
  `MACOSX_DEPLOYMENT_TARGET`, so the real floor is whatever the pinned rustc
  defaults to — 11.0 for `aarch64-apple-darwin` and 10.12 for
  `x86_64-apple-darwin`. It was wrong for both, and printing one number for both
  hid the fact that they differ, so an Intel Mac on 10.15 was told to give up on a
  binary that runs there. The two floors are now config constants and
  `published_macos_floors_match_the_toolchain` reads them back out of `rustc
  --print deployment-target`, which also refuses a hand-written floor on the page.
- **"Every file, one table" was missing two files.** The section heading and the
  table caption both claimed completeness while omitting the two CycloneDX SBOMs —
  the artifacts an auditor opens that table to find. Both are listed now, and the
  `SHA256SUMS.txt` row no longer describes its coverage by row position
  ("every artifact above"), which adding rows underneath had quietly falsified.
- **The verify section told readers a checksum proves authenticity.** "An `OK`
  line means it's authentic" is wrong in the dangerous direction: a checksum
  compares a file to a list, so anyone serving both files passes it. The page
  already said so correctly one paragraph later, and `docs/install.md` says it
  correctly too, so the page contradicted itself on a security claim. Integrity
  and origin are now two labeled steps, with the `gh attestation verify` command
  promoted out of a parenthetical into its own copyable block.
- **`/download` hard-coded the repo slug and container image.** `NormB/sipnab`
  appeared literally in a `gh attestation verify --repo` command and a releases-API
  URL, and `ghcr.io/normb/sipnab` in the Docker recipes, while `github_url` sat in
  `config.toml`. A rename would have left copy-pasteable commands aimed at a
  repository that no longer exists. Both come from config now, pinned by
  `published_repo_slugs_agree`. Two older gates asserted the literal strings and
  therefore directly contradicted the new one; they now check the same intent
  through config.
- **Copy buttons failed silently.** `navigator.clipboard.writeText` had no
  rejection handler, so on an insecure origin, with the permission denied, or with
  the document unfocused, the button did nothing and looked identical to a
  successful copy. Failure is now visible and selects the command as a fallback.
  The accompanying `&amp;` unescaping was dead code — `getAttribute` already
  returns decoded values — and would have corrupted any command containing that
  literal text.
- **Windows visitors got a run-on sentence.** The detector put its advice in the
  platform-name slot, rendering "Detected: Windows — use WSL or build from source ·
  Intel/AMD (x86_64 / amd64) — the highlighted choice below is the one you want."
  The advice moved to the note field the iOS branch already used correctly.
- **The architecture name map skipped `.rpm`.** It explained that tarballs and
  `.deb` files spell the same chip differently but never said which spelling `.rpm`
  packages use, leaving RHEL readers to guess. It also referred to the names by
  where they sat on screen ("the left name", "the middle one"), which stops being
  true when the chips wrap on a narrow viewport.
- **Two of the three `rpm -i` recipes in `docs/install.md` were ungated.**
  `docs_current_version_markers_match_cargo` pinned `-1.x86_64.rpm` literally, so
  the `-noaudio` and `aarch64` lines sitting in the same section — same
  copy-paste, same 404 if stale — were invisible to it. Verified by reverting the
  pattern and watching the gate pass with a stale version present. The arch and
  variant are now alternations, so a new package flavor is covered the day it is
  documented.

## [0.5.64] - 2026-07-29

### Fixed
- **Every download link on `/download` 404ed between a release commit and its
  tag.** The page built its URLs from `config.extra.version`, which the Pages
  step overwrites from `Cargo.toml` on every build — so the moment a release
  *commit* landed on main, the site advertised assets for a tag nobody had
  pushed yet. The file tiles, the sha256 column and `SHA256SUMS.txt` all pointed
  at a release that did not exist. The window is the whole commit → CI → tag →
  release-build cycle, and on 0.5.61 it was far longer: that release commit went
  red and was never tagged. `website/config.toml` now carries
  `published_version` — the last version that exists as a release — and every
  download link and version badge is built from it.
  `site_advertises_only_a_released_version` requires a matching `v<x.y.z>` tag,
  so advertising something unreleased fails the suite rather than the visitor.
- **The documented `curl … SIPNAB_VERSION=x.y.z` could name an unreleased
  version.** The same defect as the download page, one surface over:
  `docs_current_version_markers_match_cargo` gated the docs' version markers
  against `Cargo.toml`, and three of them are copy-pasteable download
  instructions — `SIPNAB_VERSION=`, `e.g. <version>`, `rpm -i sipnab-<v>`. At a
  release commit they would name the new version while nothing was published,
  so a reader copying the first line got a 404 from `install.sh`. Those three
  now track `published_version`; the `sipnab <version> (<hash>)` samples still
  track the crate, because they show what a build of this tree prints. One gate
  was serving two different facts.
- **CI could not run the new release gate at all.** `actions/checkout` fetches
  no tags, so `site_advertises_only_a_released_version` saw zero and refused to
  answer — correctly, but it turned CI red on the 0.5.64 release commit. The
  three checkouts that run the suite now fetch full history, so the gate is real
  in CI rather than skipped where it matters most. The assertion message had
  named this exact failure mode ("a shallow clone fetches no tags") before it
  happened.
- **The latest-version `curl` on `/download` rendered as prose.** It sat inline
  in a paragraph rather than in a terminal block like the fetch-and-verify
  command directly above it, so it could not be copied cleanly. It now has the
  same block treatment and a copy button.

## [0.5.63] - 2026-07-29

### Added
- **`pre-push` refuses a `v*` tag whose commit's CI is not green.** A tag is not
  a request to build — it publishes eight artifacts, checksums, two SBOMs, a
  provenance attestation, a GHCR image and a Homebrew formula, from whatever
  that commit contains. Until now the only safeguard was whoever was tagging
  remembering to look, and that failed once already: the 0.5.61 release commit
  went red in `Features (tls)`. The gate blocks a failed run, runs still in
  flight, and a commit with no runs at all; it skips with a warning when `gh` is
  unavailable, because forcing `SKIP_FMT_HOOK=1` would switch off every other
  gate too. Six scenarios cover it against a stubbed `gh`, and it was verified
  against the real repository in both directions — the red 0.5.61 commit is
  blocked, the green 0.5.62 one passes.

### Changed
- **The release runbook documents the order.** It opened with "a release is a
  pushed `v*` tag" and its diagram started at the tag push, so a reader
  following it literally would publish from an unverified commit.
- **The `## [Unreleased]` convention is written down**, next to the gate that
  depends on it: `no_changelog_entry_precedes_its_version_heading` accepts that
  heading, which is what lets work accumulate between releases without
  orphaning entries under no version at all.

## [0.5.62] - 2026-07-29

### Added
- **Spec for SIP problem diagnosis** — the signaling-side complement to
  `rtp/diagnosis.rs`, which can already report one-way audio and NAT mismatch
  but cannot say a call failed on a `503` after three retransmitted INVITEs.
  `docs/design/sip-problem-diagnosis.md` scopes seven detections in build
  order, the `SignalingDiagnosis` shape, and where each surface renders it.
  Two rules are load-bearing: every detection names the messages it is drawn
  from, and a truncated capture is reported as unknown rather than as failure.
  Not implemented.
- **`pre-push` now checks reduced feature combinations** (`tls`, `api`, `wasm`).
  Everything else in that hook builds with `--all-features`, which is blind to
  `#[cfg]`-gating rot by construction — and that broke `Features (tls)` on the
  0.5.61 release commit, costing a red `main`, a fix commit and a delayed
  release for something a three-second check catches. A combination the crate
  does not define is skipped, the way the fuzz gate skips a missing `fuzz/`.

### Changed
- **Four more coverage counters pinned to reality.** Measuring the whole class
  rather than the two fixed last time: wiki links `>= 40` against a true 179,
  documentation tables `>= 40` against 292, tracked markdown files `>= 50`
  against 93, and changelog version headings `>= 10` against 85 — the last of
  those in the gate added one day earlier *to fix this defect class*. The first
  three are exact pins; the changelog count keeps a floor, tightened to 80,
  because it grows by one on every release and pinning it would put a mandatory
  edit on the release path.
- **The design-status gate now checks the doc's subject**, the flag in its H1,
  rather than every flag it mentions. A spec legitimately references existing
  flags while describing something unbuilt, and the first draft reported three
  findings for one contradiction.

## [0.5.61] - 2026-07-29

### Fixed
- **A design doc told readers a shipped feature did not exist.**
  `docs/design/dialog-tracking-modes.md` read "**Status:** spec, not yet
  implemented" for six releases after `--dialog-track` shipped in 0.5.54 —
  while `src/cli.rs` declared it, `cli_flag_behavior_test` exercised it under a
  section header citing that page, and `dialog_store.rs` pointed readers at it
  for the design. `docs/internals/README.md` had even recorded the drift, so it
  was noticed and left. `an_unimplemented_design_doc_does_not_name_a_shipped_flag`
  now fails when a design doc calls itself unimplemented while naming a long
  flag `Cli` accepts.

### Changed
- **Two coverage counters were floored far below reality.**
  `every_docs_page_is_linked_from_the_index` asserted `checked >= 10` against a
  true 28 — the gate audit reported that floor as "10 against a true 19", and
  the fix widened the walk to recurse without touching the floor, leaving the
  guard looser than when it was flagged. `packaging_scripts_reference_existing_paths`
  asserted `>= 10` against a true 52, so four fifths of the packaging references
  could stop being checked silently. Both are exact pins now, matching how
  `linked_code_targets_exist` pins its link count: a DROP is the failure, which
  is the only direction that matters. Verified by mutation — a non-recursive
  docs walk sees 19 pages, the audit's original number, and the pin catches what
  the floor allowed.

## [0.5.60] - 2026-07-29

### Fixed
- **A malformed response could permanently mislabel a real dialog.**
  `SipDialog::new` fabricated `SipMethod::Custom("UNKNOWN")` when a response
  carried no parseable `CSeq`. `method` is set once at creation and never
  corrected, and dialogs are keyed by Call-ID — so such a response arriving
  *before* the INVITE created a dialog labeled `UNKNOWN`, and the genuine
  INVITE then matched that entry and left the label wrong for the rest of the
  capture. `dialog_store`'s INVITE-specific matching stops working on that
  dialog, and every per-method count, filter and export reports it under a
  method nothing sent. A message whose method cannot be determined now creates
  no dialog, exactly as one without a Call-ID already did — the message is still
  captured, counted and searchable; only the correlation that could not be
  established is withheld, which leaves the later INVITE free to create the
  dialog correctly.

- **The SIPp scenario export could write an invented SIP method onto the
  wire.** `tui/save.rs` substituted the literal `UNKNOWN` when a request's
  method was absent, and both arms write it straight into the scenario — a
  `<send>` request line and a `<recv request="...">` — so the export produced
  something SIPp will run and a peer will reject. A request whose method cannot
  be parsed is now skipped. (`parse_first_line` sets `Some(..)` for every
  request it accepts, so this was unreachable; it is written as a skip because
  the alternative is only safe while that stays true and nothing here would
  notice if it stopped.)

### Changed
- **Thread teardown is documented, not just enforced.** The rule that every
  fatal exit after `start_capture()` goes through `capture::stop_and_join()` was
  enforced by a test and by ThreadSanitizer treating `thread leak` as fatal, but
  written down nowhere: `threading.md` had Topology, Named threads, Lock
  discipline and Channels, and no section on how a thread *ends*. It now has
  one, and `invariants.md` gains invariant 12. Enforcement without documentation
  is how the next person reintroduces the defect.
- **`WAIVED` now ratchets both ways.** Its doc comment claimed to mirror the
  `KNOWN_UNTESTED` convention in `flag_coverage_test.rs`, which fails when a
  listed flag *becomes* tested — the half that caught `--chroot`. `WAIVED` only
  checked that a waiver named a real flag, so a flag that later gained examples
  stayed excused forever. Both gates now measure examples through one shared
  helper, so the ratchet cannot disagree with the gate it ratchets against.
  Nothing was stale when this landed; a ratchet is installed before it is
  needed.

## [0.5.59] - 2026-07-29

### Added
- **`no_changelog_entry_precedes_its_version_heading`** — a gate for a blind
  spot in this file's own guard. `site_release_date_matches_changelog` searches
  for the heading naming the current site version and asserts its date, which
  says nothing about the entries: a `### Added` block belonging to no `## [x.y.z]`
  at all satisfies it, because the heading it looks for is still further down.
  That happened here — an edit replaced the `## [Unreleased]` heading along with
  the text it anchored on, orphaning two sections under the file header, and it
  survived a commit, a push and a full CI run with the changelog's own gate
  green throughout.

- **Metrics-only token scope for the REST API.** `s2` tokens carry an optional
  `scope` claim alongside `aud`; `--token-scope metrics` mints a credential that
  reaches `GET /metrics` and returns `401` everywhere else. This is a
  TLS-decrypting capture tool, so `/v1/dialogs` and `/v1/streams` return message
  bodies — the call content — and until now a monitoring system that needed one
  counter had to be trusted with all of it. `full` is the default and satisfies
  every requirement, an absent claim means `full`, and static `--api-key`
  secrets remain `full`, so no existing token or deployment is narrowed. The
  claim is signed and cannot be widened by editing the payload. Routes default
  to demanding `full`, which is the restrictive direction — a route added later
  inherits "full tokens only" rather than quietly accepting a scrape-only
  credential.

### Changed
- **BREAKING (log format): the fail2ban `method=` field is now quoted too, and
  `-` means absent.** 0.5.58 routed the `ua=` field through a single
  absent-marker renderer and left `method=` behind — where the same defect was
  live twice over: an absent method rendered as `UNKNOWN` on the scanner path
  and `-` on the kill-target path, so two lines describing identical input
  disagreed about what absence looks like. `SipMethod::Custom` can hold either
  spelling, since it keeps whatever token preceded the first space on the
  request line, so neither was safe as a marker. Both fields now go through
  `render_absent`, which makes the "one place decides" claim on that function
  true rather than aspirational. `src=` stays unquoted: it is a parsed IP
  address, not text from the wire. The documented `failregex` anchors on
  `src=<HOST>` and is unaffected.

## [0.5.58] - 2026-07-29

### Fixed
- **Every fatal startup path abandoned the running capture thread.**
  `bootstrap::launch` spawns the capture thread *before* the readiness
  hand-shake, the chroot and the privilege drop, and all nineteen fatal exits
  from there on called `std::process::exit`, which joins nothing — so the
  process died with a capture thread still running and still holding an open
  capture source. `BatchRunner::new` had four more of the same shape and could
  not fix them locally, because it does not own the handle. `sipnab -I
  <missing-file>` — a mistyped filename — was enough to produce one, as was an
  unusable `--chroot`. All twenty-three paths now go through
  `capture::stop_and_join`, which sets the shutdown flag, drops the receiver and
  joins; `BatchRunner::new` returns a `PlanError` so `batch::run` can clean up in
  the scope holding both the handle and the receiver. Exit codes and messages are
  unchanged, and a HEP listener blocked on its socket still exits in
  milliseconds rather than hanging the join.

- **`unknown` no longer stands in for an absent header.** Three spellings of
  the same condition were in the tree at once — `"unknown"` in the fail2ban
  path, `""` in `ScannerAlert`, `"-"` in the kill-target alert — so the same
  missing `User-Agent` read differently depending on which line printed it.
  `ScannerAlert::ua` and `format_scanner_event`'s `ua` are now `Option`, with a
  single `output::render_absent` deciding how absence renders. A `REFER`
  carrying no `Refer-To` now records `SdpEvent::Transfer { target: None }`
  instead of a transfer to a party literally named "unknown" — a URI-typed
  field should not be made to hold a non-URI. JSON output already emitted
  `null` and is unchanged.

### Changed
- **BREAKING (log format): the fail2ban `ua=` field is now quoted, and `-`
  means absent.** A scanner line reads
  `... src=203.0.113.42 ua="friendly-scanner" method=OPTIONS`, and a request
  with no `User-Agent` reads `ua=-` — distinct from a client sending the string
  `-`, which renders as `"-"`. The documented `failregex` anchors on
  `src=<HOST>` and is unaffected; a custom filter that captures `ua=(\S+)` will
  need the quotes. Quoting closes a field-injection hole at the same time:
  `sanitize_log_value` strips CR/LF so a forged *line* was impossible, but the
  fields are space-separated, and a `User-Agent` of
  `evil method=REGISTER src=1.2.3.4` produced a line carrying two `src=` values
  — the second attacker-chosen, in the output that feeds a ban decision.
  Embedded `"` and `\` are escaped.

- **Release downloads say which one you want.** A release page lists twenty-odd
  files whose Linux names carry `unknown-linux-gnu` — the *vendor* field of the
  Rust target triple, the canonical value for "no specific vendor", which is why
  the macOS files say `apple` in the same position — and nothing on the page
  explained it or said which to take. `ops/release/platform-table.sh` now
  renders a table into the release body, derived from the artifacts that
  actually built rather than a hand-kept list, so it cannot advertise a missing
  build or omit a new one; an unmapped target fails the release step. Filenames
  are deliberately unchanged: they match `rustc -vV`, they are what
  `SHA256SUMS.txt` and the provenance attestation cover, and `install.sh`
  constructs them.

- **ThreadSanitizer is now meaningful on this codebase.** The `sanitizers.yml`
  job reported a data race on the file-capture path; it was **mimalloc**, which
  `src/main.rs` installs as the global allocator. mimalloc is C compiled by the
  `cc` crate and `-Zsanitizer=thread` instruments Rust only, so TSan sees neither
  its alloc/free (no shadow reset on a recycled block) nor its internal
  cross-thread synchronisation — every block handed from one thread to another
  reads as a race. The reported stacks named `read` and
  `Vec::append_elements_unreserved` with no allocator frame anywhere, so no
  suppression could have matched it. The allocator is now dropped under
  `--cfg sipnab_tsan`, set only by that job; **the shipped binary is
  unchanged**. All five sanitizer suites run clean: 58 tests, zero races, zero
  leaked threads.

- **The sanitizer gate could not fail correctly, in either direction.** Its
  verdict lived inline in the workflow, where `run:` blocks execute under
  `bash -e -o pipefail`: a bare `grep … | while read` warning loop exited 1 when
  there were **no** findings, killing the step before it printed anything. The
  job therefore failed silently on a clean tree and passed while a thread leak
  was present. Its instrumentation guard had the mirror-image bug — `grep -q`
  closing the pipe on a still-writing `nm`, whose SIGPIPE read as "not
  instrumented". Both now live in `ops/tsan/verdict.sh` with
  `ops/tsan/test-verdict.sh` beside it and a `tsan-verdict` job running the eight
  scenarios on every push, not only inside the weekly job they gate. `thread
  leak` is in the fatal set rather than tolerated.

- **The test harness reported a timeout it had never waited out.** When a
  spawned API server died, its stderr closed and the `Disconnected` arm broke to
  a panic naming the whole budget — "did not report a listening address within
  180s" for a suite that finished in 55s. It now reports the child's exit status,
  which is the actual cause.

- Legacy-gate audit, tiers D and E (27 findings): the shared CommonMark lexer
  behind the docs gates, WASM exports derived from `src/wasm.rs` rather than a
  hand-kept list, pre-commit and pre-push hooks executed rather than grepped,
  and the license-election table deduplicated. Each fix verified by
  reintroducing the demonstrated defect and observing the gate fire.

## [0.5.57] - 2026-07-29

### Fixed
- **The installer never verified a checksum on macOS.** `verify_checksum` has
  three branches — `sha256sum`, `shasum`, and a refusal when neither exists —
  and every test ran under a PATH that always had the first, so two of the three
  never executed. On a macOS-shaped PATH the function returned success for an
  artifact whose recorded digest was all zeros: **a tampered download installed
  silently**, on a platform with its own published tarballs. Each branch is now
  exercised under a PATH exposing exactly one tool, and the no-tool case asserts
  refusal — an installer that cannot verify must not install.

- **The Homebrew formula could ship each URL with another architecture's
  digest.** Its test grepped for each checksum anywhere in the document, which
  says nothing about which URL carries it; all four pairs could be rotated and
  the test passed, while every `brew install` aborted on a sha256 mismatch. The
  URL and its digest are now compared as a pair.

- **`.unwrap()`/`.expect()` were unbanned across ~10,800 production lines.** The
  pre-commit scanner treated the first `#[cfg(test)]` in a file as entering test
  code and never left, so a per-item attribute above a `use` exempted everything
  below it — eleven files under `src/`, one latching at line 23 of 1659. The
  exemption is now scoped to the item the attribute annotates. The clean tree
  reports zero, so this was a gate that could not have found a violation rather
  than one that found none.

- **The container image could ship unattested.** The gate asserted `docker.yml`
  contains `actions/attest-build-provenance@`, which stays true when the step is
  commented out — and the workflow never verified the attestation it created,
  while the download page tells users to run `gh attestation verify`. The gate
  now reads live steps, and `docker.yml` verifies its own attestation the way
  `release.yml` has since 0.5.49.

- **A release could publish no tarball for a target while the gate stayed
  green.** `installer_targets_match_release_matrix` compared the build matrix,
  not the packaging step that actually produces a tarball; excluding a target
  from packaging left every `install.sh` run for that platform 404ing.

### Changed
- **Dependencies:** `aes` 0.9.1 → 0.9.2, `clap_complete` 4.6.7 → 4.6.8,
  `jsonschema` 0.49.1 → 0.49.2 (patch), with `THIRD-PARTY-NOTICES.md`
  regenerated.

- **Every code fence declares its language.** An unlabeled fence still gets a
  copy button on every surface, but the one-command gate only reads fences whose
  info string names a shell, so unlabeled shell blocks were invisible to it.
  Output, transcripts and diagrams are labeled `text` deliberately — labeling
  them `bash` would put an unrunnable block under a gate demanding it be one
  command.

### Internal
- Coverage floors that sat far below the truth are now exact or near it: one
  asserted a corpus of at least 40 links where 265 existed, so an extractor that
  stopped matching most of its corpus still passed. Measured: narrowing it to
  read one tree instead of thirteen drops it to 136 links — above the old floor.
- `ci_success_gates_every_job` matched job ids against this repository's naming
  style rather than the charset GitHub accepts, so a job named with an
  underscore could fail on every push while the single required check reported
  green.
- Pre-commit gate 5 printed `OK` after comparing nothing: both of its greps
  could return empty and the comparison loop iterate zero times.

## [0.5.56] - 2026-07-28

### Fixed
- **`--call-report` wrote terminal escape codes instead of a report.**
  `sipnab -I capture.pcap --call-report <id> --markdown > report.md` — the form
  published in six places — launched the TUI and put 122 bytes of alt-screen and
  mouse-tracking sequences into `report.md`, then exited 0. Measured against the
  release binary on a pty: 6911 bytes with `-N`, 122 without.

  The flag was not overridden by the TUI, it was discarded: `call_report` is read
  in exactly one place, the batch runner, which the TUI path never reaches. The
  CLI already stated the contract — `Cli::validate` waives the `-N` requirement
  for `--call-report` because the flag "implies non-interactive output" — and
  nothing applied it. `Cli::normalize` now applies it once at the parse boundary,
  so the run-mode selector, the three output gates in the batch runner and log
  suppression all read one settled value. The documented form is now
  byte-identical to the `-N` form, and `--report`/`--json` alongside
  `--call-report` emit output where they previously produced none.

- **Nine documentation statements were false against the shipped code.** Two broke
  things silently: `GET /v1/dialogs` documented its rows as `from`/`to` when the
  endpoint emits `from_user`/`to_user`, so a client written to the page got
  `undefined` for the two most-used fields and the documented `jq` CSV export
  produced two empty columns; and `tail_dialogs` told MCP clients
  `source_exhausted` "is always false" when it is implemented and wired, which is
  the field an agent polls to learn a replay finished. Also corrected: the
  `sipnab_rtp_streams_active` definition (the `--api` and `--metrics` servers
  count different things under one name, so an alert threshold does not transfer
  between scrape targets), the un-wired counters' failure modes, and a feature
  table that omitted `metrics` entirely.

- **Site links with anchors did not resolve.** GitHub and Zola slugify the same
  heading differently — GitHub drops an em dash and keeps its spaces, Zola
  collapses the run — so anchors written for GitHub died on the site. The
  generator now translates them, including same-page links.

### Changed
- **A fenced code block is one clipboard payload.** Every surface puts a single
  copy button on a fence and copies the whole body, so a block holding two
  recipes handed the reader both. Mostly untidy; not always — one block's second
  command was `openssl rand -hex 32 > /etc/sipnab/mcp-token`, which destroys a
  live MCP bearer token. 135 blocks across 26 files are now one command each, an
  ordered procedure that declares itself, or a list with inline code (which
  carries no copy button anywhere).

- **`docs/` is the single source for the operator pages.** Ten page pairs were
  hand-maintained on both sides and had drifted: the site's Filter DSL page
  carried fourteen operational recipes `docs/` did not, so every wiki reader got
  that page without them. `benchmarks.md` stays deliberately un-generated — its
  two copies frame the numbers differently on purpose.

- **Supply chain.** Every GitHub Action and container base image is pinned by
  commit SHA or digest, including the `container:` images that build the released
  gnu binaries and `.deb` packages. Workflow tokens are least-privilege, with
  write restated only on the job that needs it. `dependabot.yml` covers all eight
  Dockerfiles rather than the root one, so the pins are maintained rather than
  frozen.

- **`docs/install.md` now states that `gh attestation verify` needs `gh` 2.49.**
  Below that it prints help text and exits 0, so the documented verification step
  reads as success while checking nothing.

### Internal
- Fourteen CI gates were found asserting a proxy rather than the thing they
  claimed to check, each green because of the substitution: a feature table gated
  on `README.md` alone, a link check blind to anchors floored below the real card
  count, a registry floored one under its size, a slug rule unioned across three
  renderers on a page only one renders, `.yml` standing in for "is a workflow",
  `no_tui` standing in for "batch mode", a step's name standing in for the step
  still failing the build, and a directory walk counting gitignored output. All
  are now derived from the artifact — the generator's own banner, the real card
  array, `git ls-files`, the renderer's own slug rule — and each was observed
  failing on the specific defect before being accepted. The rule and its
  corollary are recorded in `docs/design/lessons.md`.

## [0.5.55] - 2026-07-28

### Added
- **Two `docs/` pages were linked from the index by nothing.**
  `architecture.md` (169 lines, and published to the wiki) and `backers.md`
  were both reachable only if you already knew they existed. Neither was
  broken or stale, which is why nothing noticed: an unreferenced file looks
  exactly like a file nobody needs. Both are linked now, and
  `every_docs_page_is_linked_from_the_index` fails on any `docs/*.md` the index
  does not reach.

- **`docs/mcp.md`'s tool table listed 7 of the 11 tools the server registers.**
  `search_messages`, `tail_dialogs` and `security_findings` were documented in
  the prose below it but missing from the table, and `stats` was absent from
  both copies of the page. Nothing was factually wrong; a reader scanning the
  table for what MCP can do just would not have learned those tools exist. The
  table now carries all 11 plus a Parameters column, and
  `mcp_tool_table_lists_every_registered_tool` derives the truth from the
  `#[tool(name = "…")]` attributes in `src/mcp/server.rs` rather than from a
  second hand-written list.

- **The REST API page was two divergent documents; now it is one.**
  `docs/rest-api.md` was 430 lines and the site's was 893, sharing 5 of their
  17 commands — and each side held whole sections the other did not. The site
  had the richer endpoint reference and a four-step getting-started; `docs/`
  uniquely had Status codes, the curl+jq recipes, the Prometheus scrape config,
  and Client examples. Merged to 960 lines, keeping the better of each, with
  the docs' bind-address section (which also explains the base URL, the
  loopback default and the `/v1/` prefix) replacing the site's thinner
  Connection Limits. The wiki page goes from 430 lines to 961.

- **The wiki cookbook is no longer a third of the real one.** `docs/examples.md`
  and the site's Cookbook were maintained by hand and had drifted almost
  completely apart — 740 lines against 122, sharing 2 of their 36 commands.
  The wiki renders from `docs/`, so wiki readers were served the short version
  as though it were the whole cookbook. Nothing was broken and nothing was
  stale, so nothing could have noticed.

  `docs/examples.md` is now the single source (857 lines: the 14 long-form
  recipes plus the dense one-liner quick-reference that only ever existed in
  `docs/`), and `scripts/build-site-cookbook.py` generates the site page from
  it. `cookbook_mirror_is_current` re-runs the generator and fails if the
  committed mirror is stale, matching how `docs/internals/` already works.

- **CycloneDX SBOMs ship with every release**, covered by `SHA256SUMS.txt` and
  by the sigstore attestation. Two of them, because sipnab ships as two
  binaries: `sipnab-<version>.cdx.json` for the binary and
  `sipnab-audio-<version>.cdx.json` for the playback plugin. The plugin is a
  separate workspace crate loaded with `dlopen`, and it pulls in seven
  dependencies the main crate's graph does not contain at all — `alsa`,
  `alsa-sys`, `cpal`, `dasp_sample`, `num-bigint`, `num-rational`, `rodio`. An
  SBOM of the main crate alone would have omitted exactly the C-adjacent
  dependencies a vulnerability scan looks for, while appearing complete.

  The binary SBOM is built with `--features full` deliberately: the `noaudio`
  artifacts resolve a strict subset (measured: the two differ by exactly one
  component, `libloading`), so one document over-covers rather than
  under-covers every binary published.

- **OpenSSF Scorecard** (`scorecard.yml`) analyses supply-chain posture on
  every push to `main`, on branch-protection changes, and weekly. Report-only
  and deliberately not a gate — Scorecard grades practices, and several of its
  checks are questions this project has already answered differently on
  purpose. Its value is being an outside opinion that notices posture drift no
  in-repo test was written for.

- **`docs/install.md` now explains how to verify a download** — checksum,
  `gh attestation verify`, and feeding either SBOM to a scanner. The release
  had been attesting every artifact since 0.5.49 without telling anyone how to
  check one.

### Fixed
- **`packaging_scripts_reference_existing_paths` flagged a build output as a
  missing input.** `pages.yml` names `website/public`, Zola's render target,
  which is absent from a fresh checkout — so the test passed on a machine that
  had built the site and failed in CI. Build outputs are now skipped via an
  explicit list. Deliberately not "skip anything git does not track": a stale
  reference to a moved file is untracked too, which is the exact bug the test
  exists to catch.
- **The one required status check on `main` did not cover three of the seven CI
  jobs.** `ci-success` exists to be a single aggregate gate, and its comment
  says it is "green only if every other job succeeded" — but its `needs:` list
  named four jobs. `install-sh` (the test suite for the installer sipnab.com
  serves), `deb-package`, and the new `homebrew-formula` job sat outside it.
  Any of them could fail with the required check still green and the branch
  still mergeable. `needs:` now lists every job, and
  `ci_success_gates_every_job` compares it against the jobs actually defined in
  the file, so a job added later either joins the gate or fails the test.
- **`packaging/homebrew/test-update-formula.sh` had never run.** 21 assertions
  covering the Homebrew formula generator — which runs on every release —
  and the only reference to the file anywhere in the repo was its own header
  comment saying how to run it. Its deb-builder sibling has had a CI job all
  along. It now has one too; it passes 21/21.
- **The source-install wrapper was putting a second, dev-only binary in your
  `~/.cargo/bin`.** It ran `cargo install --path .`, which installs *every*
  `[[bin]]` whose `required-features` are satisfied. `gen_fixture` — the test
  fixture generator — declares `required-features = ["native"]`, and `native`
  is a default feature, so it qualified. Anyone who used the script got
  `gen_fixture` on their `PATH` alongside `sipnab`. Now `--bin sipnab`.

  Verified by installing into a throwaway `--root` both ways: with the flag,
  only `sipnab` appears; without it, `gen_fixture` and `sipnab` both do.

### Removed
- **`contrib/rpm/sipnab.spec` is gone.** `build-rpm.sh` writes its own spec into
  the rpmbuild tree at build time, so the checked-in copy was read by nothing —
  and having drifted unwatched it had every fact wrong: `License: GPL-3.0-only`
  (sipnab is `MIT OR Apache-2.0`), `BuildRequires: cargo >= 1.92` (MSRV is
  1.97), `%license LICENSE` (no such file; there are LICENSE-MIT and
  LICENSE-APACHE), and a build-from-source recipe the real builder does not
  use. It looked authoritative enough for a distro packager to adopt verbatim,
  which would have shipped sipnab under the wrong license. Deleted rather than
  repaired: a second spec is what allowed the drift.

### Changed
- **`docs/README.md` is now grouped by what the reader is trying to do**, along
  the four [Diátaxis](https://diataxis.fr/) modes — tutorials, how-to guides,
  reference, explanation — with a compass table at the top saying which to pick.
  Deliberately a regrouping of the existing index, not a folder restructure:
  Diátaxis itself advises against big-bang reorganisation, and every page kept
  its path, so no link anywhere in the repo, the site, or the wiki moved.

- **Packaging moved out of `contrib/` into `packaging/`.** `contrib/` says
  "community-contributed, unsupported"; what lived there was the `.deb`,
  `.rpm`, and Homebrew builders that `release.yml` runs on every tag, plus the
  systemd unit both packages install. `packaging/` now holds those four, and
  `contrib/` keeps what the name actually describes — fail2ban, Grafana,
  Prometheus, the observability stack, and `sipnabrc.example`. Both directories
  gained a README stating which is which.

  Guarded by `packaging_scripts_reference_existing_paths`: the builders name
  repo paths as bare shell literals (`readlink -f packaging/sipnab.service`),
  and `build-rpm.sh` and `update-formula.sh` only run on a release tag, so a
  stale path would have surfaced mid-publish. The test asserts every such
  literal resolves, on every push.

- **`install.sh` moved to `scripts/install-from-source.sh`.** The repo had two
  files named `install.sh` with unrelated jobs: this one builds the working
  tree, while `website/static/install.sh` is the end-user one-liner served at
  sipnab.com that downloads a prebuilt binary and compiles nothing. Only the
  latter had tests, CI, and documentation, so the name was going to the wrong
  file. The source wrapper is now named for what it does and documented under
  *Building from Source* in `docs/install.md` and the site's build page.

## [0.5.54] - 2026-07-27

### Added
- **`--dialog-track` is back, and this time it does something.** It groups
  messages by `call-id` (default, one unit per dialog) or `branch` (one unit
  per SIP transaction), for captures where a single Call-ID is reused across
  many transactions — load generators, proxies under test.

  The version removed in 0.5.52 was declared in `src/cli.rs` and read nowhere,
  so every value including invented ones produced identical output and exit 0.
  This one is wired through the single-core store, the TUI store and the
  `--cores` parallel config, and proven by the modes *disagreeing*: on
  `sipp-branch-scenario.pcapng` (one Call-ID, many transactions) `call-id`
  reports 1,334 units and `branch` reports 3,907, identically under `--cores 4`.

  An unknown method is now **rejected** (`exit 2`, naming the value) rather
  than silently selecting the default.

  **`branch` counts transactions, not calls.** RFC 3261 gives the ACK to a 2xx
  a new branch (§17.1.1.3) and the BYE another, so one ordinary call appears as
  three units. That is the transaction view working as intended, it is asserted
  by a test rather than left to be discovered, and it means `--limit` counts
  transactions in this mode. Design notes and the rejected alternatives are in
  `docs/design/dialog-tracking-modes.md`.

  A Call-ID still resolves to a dialog in `branch` mode — `--call-report`, the
  REST API, the MCP tools, the TUI and the WASM analyzer all look up by
  Call-ID, and `DialogStore::get` returns the first matching unit so none of
  them changed behavior. `get_by_key` addresses one specific transaction.

  The default path still allocates no per-message key: `call-id` mode keeps the
  original borrowed lookup, and only `branch` composes an owned key.

## [0.5.53] - 2026-07-27

### Fixed
- **Output that could not be written is no longer reported as success.** Three
  paths disagreed about what a full disk means, and `src/app/batch.rs` already
  carried a comment naming the problem — *"an ENOSPC at end of capture would
  truncate the file silently with exit code 0"*. The detection half had been
  fixed; the exit code in that very sentence had not.

  | path | before | after |
  |---|---|---|
  | `-O` pcap | error logged, exit 0 | error logged, **exit 1** |
  | `--json` | silent, exit 0 | error logged, **exit 1** |
  | `--report` | **panic**, exit 101 | error logged, **exit 1** |

  A closed pipe is unchanged and still succeeds: `sipnab --json \| head` is a
  reader that stopped caring, not data loss. `BatchSink` now keeps the first
  non-`BrokenPipe` error rather than swallowing every error alike — its doc
  always said the intent was broken pipes, but the code did not distinguish.

  The inconsistency was visible in one screen: failing to *open* the output
  called `exit(1)`, failing to *write* it fell through to success.
- **`--call-report` with an unknown Call-ID exited 0 on the `--cores` path.**
  `generate_reports` returns `false` for exactly this, and its doc says the
  caller exits non-zero so "scripts must be able to trust the exit code" — but
  two of the three callers discarded the value. Both now honor it.
- The fuzz workspace is scanned and updated. `fuzz/Cargo.lock` sits outside the
  root workspace, so `cargo audit`, `cargo deny` and Dependabot all missed it —
  194 packages, drifted 39 crates behind the root. Adding the scan immediately
  found RUSTSEC-2026-0190 (`anyhow`, unsound) present only there. Dependabot now
  covers `/fuzz` and the Docker base images.
- The pre-commit hook no longer re-implements the docs version-marker rule in
  shell. The two copies had diverged and the shell one rejected a correct
  release commit; the Rust test it duplicated runs in the hook *and* in CI.

## [0.5.52] - 2026-07-27

### Removed
- **`--dialog-track` is gone. It never did anything.** `dialog_track` was
  declared in `src/cli.rs` and read nowhere else in the codebase, so
  `--dialog-track call-id`, `--dialog-track branch` and `--dialog-track
  telepathy` all produced byte-identical output on an 8989-packet capture and
  all exited 0, while `--help` advertised "Track dialogs using this method".

  Anyone passing it was getting nothing; they will now get a clap error, which
  is strictly better than a silent lie. Removed with its docs table rows, both
  worked examples in the CLI reference, and the test asserting its default was
  `None` — a test that passed *precisely because* the flag did nothing.

  Dialog tracking itself is unaffected: it is on by default, `--no-dialog`
  still disables it, and `--limit`/`--rotate`/`--no-rotate` still govern
  capacity.

### Fixed
- **The flag-coverage gate could be satisfied by a comment.** It counted a flag
  as tested if `--name` appeared anywhere under `tests/`, so prose counted as
  coverage. A comment written while wiring an unrelated gate silently "covered"
  three flags at once. Rust comments are now stripped before the text counts;
  string literals are not, since a `--flag` in a string is nearly always an
  argument being passed to the binary.

  The ratchet had read 106 of 143 flags covered; the honest figure was 101.
  Four of the five gaps now have real behavior tests — `--rotate`,
  `--duration`, `--strip-secrets` and `--hep-parse` — and the fifth was
  `--dialog-track`, removed above.

- **The release ran a `strip` that had never worked on cross-compiled targets.**
  It sat behind `|| true`, so nothing was visible either way. On the
  cross-compiled targets the host's GNU strip cannot even read the output
  (`Unable to recognize the format of the input file`) and had failed on every
  release for the project's history; on native targets it was a no-op against a
  binary `[profile.release] strip = true` had already stripped at link time. It
  looked like the thing doing the stripping while doing nothing at all.

  Removed, and replaced with a check that the property actually holds:
  `readelf -S` must find no `.symtab`. readelf reads cross-architecture ELF, so
  it can verify what strip could not even open. This would fail loudly if the
  profile setting that does the real work were ever removed.

### Added
- A dependency-free pcap/pcapng builder for tests (`tests/support/pcap_build.rs`).
  The `pcap` crate is an optional *main* dependency and unreachable from
  integration tests, which is why flags needing crafted traffic stayed untested.
  It can emit a Decryption Secrets Block, so `--strip-secrets` — whose entire
  job is removing them — finally has something to be tested against.

## [0.5.51] - 2026-07-27

No shipped-code changes. Cut to prove that the release's attestation check now
records what it verified, which can only be observed by cutting a release.

### Fixed
- **The attestation check passed without evidence.** 0.5.50 ran it successfully
  and the job log contained the echoed command and nothing else:
  `gh attestation verify` prints its summary only on a TTY, so on a runner a
  passing verification is completely silent. That left the step resting on an
  exit code, which cannot distinguish a real verification from a command that
  silently did nothing — the same "trust the tick" evidence the step was added
  to stop accepting, reintroduced one layer down.

  The log now shows the signing issuer, source repository and commit sha that
  were checked. The verification exit code remains the gate; the rendering is
  deliberately incapable of failing the release, because a wrong `jq` path
  turning a good release red is how a step earns distrust and gets removed.
- **Coverage no longer fails intermittently on a corrupt profile.** A process
  killed by a signal never flushes its coverage profile, leaving a truncated
  `.profraw` that fails `llvm-profdata merge` for the whole job. Three suites
  kill the binary they spawn — `crash_test` (SIGABRT via `core = true`),
  `hep_test` (`Child::kill()`, uncatchable), and `parse_path_test` (SIGKILL on
  timeout, so it corrupted only on slow runs). Their children's
  `LLVM_PROFILE_FILE` now points outside the collection directory. Not fixed by
  retrying the job or deleting corrupt files before the report: both keep the
  signal and discard the meaning.

## [0.5.50] - 2026-07-27

No shipped-code changes. This release exists to exercise two new release-time
gates that, by their nature, cannot be tested except by cutting a release.

### Added
- **The release now refuses to build if the tag disagrees with `Cargo.toml`.**
  Artifact filenames, the `.deb` `Version:`, the `.rpm` version and the Homebrew
  formula all derive from `${GITHUB_REF_NAME#v}`, while the version the binary
  reports comes from `Cargo.toml`. Nothing compared them, so tagging `v0.6.0`
  without bumping the crate would ship packages labeled 0.6.0 containing a
  binary reporting 0.5.49 — into package managers, checksummed and attested,
  with every badge green, because each half is internally consistent. A
  `preflight` job now blocks the build on a mismatch.
- **The release verifies its own attestation before publishing.** Attestation
  was previously "gated" by a test asserting that the string
  `actions/attest-build-provenance@` appears in `release.yml` — true whether or
  not the result is usable. `release.yml` now runs the exact command the
  install docs give downloaders (`gh attestation verify`) against a real
  artifact, so a changed subject path, digest mismatch or permissions change
  fails the release instead of reaching a user.

### Fixed
- **The TUI end-to-end suite had never run on macOS, and was enforced nowhere.**
  Its 11 tests drive the real TUI through a tmux PTY and are the only coverage
  that exercises a terminal. They are `#[ignore]` by default, so every plain
  `cargo test` skips them — locally, in the pre-commit hook, in CI's `Test`
  step, under coverage. The one step that ran them carried
  `continue-on-error: true`, discarding the result.

  Removing that revealed what it had hidden: `Install system deps` is
  Linux-only, macOS runners have no tmux, and all 11 tests were failing on
  **every** macOS run with `failed to run tmux (is it installed?)`. sipnab ships
  two macOS targets and had no terminal-level coverage of either. tmux is now
  installed on macOS and the suite gates on both platforms.

  Worth recording how well this hid: `continue-on-error` rewrites a step's
  `conclusion` to `success` and leaves the true result in `outcome`, which the
  REST API does not expose on step objects. Querying step conclusions — the
  obvious way to check — returns `success` for a step that failed. Only the job
  logs show the truth.
- The fuzz-target count and the enumerated target list in `docs/fault-model.md`
  and `docs/architecture.md` are gated against `fuzz/fuzz_targets/`. A new target
  previously left the security-facing page describing a smaller fuzz surface
  than the tree actually has.

## [0.5.49] - 2026-07-27

### Fixed
- **`fuzz/Cargo.lock` shipped stale in 0.5.48.** It pins sipnab's own version,
  and the fuzz workspace is separate, so a hand-edited bump updates
  `Cargo.toml`, `website/config.toml` and the man page — each of which is gated
  — and leaves this one behind. 0.5.48 published with the lockfile still naming
  0.5.47. No hook, workflow or test looked at the file; it was noticed only
  because a stray `cargo` invocation regenerated it and left the change in the
  working tree. Now gated, with the fix command in the failure message.

## [0.5.48] - 2026-07-27

No shipped-code changes: this release is the benchmark and documentation work
below. The binaries are functionally identical to 0.5.47, which is also the
artifact every number on the benchmarks page is measured against.

### Added
- **voipmonitor is back in the comparison, built in a container.** It is not
  packaged for the reference host and a host install pulls in a database
  service, so `bench/voipmonitor.Dockerfile` builds it from source (2026.07.1)
  and `bench/compare.sh` picks it up via `VM_IMAGE`. Container startup is ~0.8 s
  — longer than sipnab's entire run on this corpus — so the timing loop runs
  *inside* one container; timing `docker run` would have fabricated a
  several-fold sipnab win out of the measurement apparatus. The config disables
  spooling, not analysis, and that was verified rather than assumed by
  re-running with `savesip`/`savertp` on and reading the output back with
  sipnab: one SIP and one RTP capture per call, both directions, 50 packets
  each way.
- **The benchmark harness is published, so "reproducible" is finally true.**
  `bench/carrier.py`, `bench/scaling.sh` and `bench/compare.sh` are the corpus
  generator and timing harness the benchmarks page has cited since 0.5.18 while
  they lived in an unpublished repository. The page claimed "every number here
  is reproducible … the exact commands above are the full recipe"; in fact
  nobody could re-run a single number, including on the reference host the
  methodology names. The generator was rewritten from the documented corpus
  parameters and reproduces every one exactly — 535,000 packets, 35,000 SIP,
  500,000 RTP, 93.5% RTP, 100 Call-IDs, 200 streams — and is gated at 1/100
  scale so the page cannot describe a corpus the generator stopped producing.

### Changed
- **Benchmarks re-measured on the 0.5.47 release artifact**, checksum-verified,
  on an idle host: 1.06M / 2.32M / 2.03M / 1.89M pkts/s at 1 / 2 / 4 / 8 cores.
  Homepage tiles now quote 2.32M pkts/s and 11.0× sngrep, both traceable to a
  row on the page they link to, and both gated against it.
- **The "packet path is unchanged since 0.5.18" claim is now a measurement.**
  Twenty-nine releases carried it on judgement while a gate mechanically
  advanced the version number in the sentence. A controlled A/B — both release
  artifacts, identical corpus, same host, same session, three interleaved
  replicates — puts the version delta (~2%) inside the noise floor (~3.4%
  within-version spread), with one replicate showing 0.5.47 ahead. The
  judgement was correct; it is no longer a guess.
- The same A/B explains the gap to the pre-0.5.47 tables: 0.5.18 measures 1.06M
  single-core on the new corpus against the 1.20M it published. Same binary,
  same host — the difference is the corpus, not a regression.

### Fixed
- **A gate that manufactured the appearance of freshness.** Both benchmark pages
  were required to contain "current release X.Y.Z" matching Cargo.toml, so every
  release re-stamped the sentence as current while the measurement behind it
  aged. The marker is gone; the pages now state which artifact and date produced
  the numbers, and a gate requires both doc trees to agree on it.
- **A published memory advantage that measurement does not support.** The page
  advertised ~9.2× less RSS than voipmonitor at 20k calls. Measured against
  voipmonitor 2026.07.1 it is **~3.2×**, steady across the whole sweep, because
  voipmonitor's footprint is far below what this page reported for it (1.46 GiB
  against a published 4.7 GiB). Different version and corpus, so not strictly
  comparable — but 9.2× was being published, 3.2× is what measurement shows, and
  only one of them has a recipe attached.
- **The homepage headlined a number readers could not reproduce.** The tile
  quoted 2.32M pkts/s, the 2-core peak, which is the least stable point on the
  curve: a clean-clone rerun of the published recipe got 2.23M and replicates
  spanned 2.32–2.36M. Both tiles now quote the four-core operating point
  (2.06M pkts/s, 11.1× sngrep) from a single comparison run, and are gated
  against the page they link to.
- **The wiki published a working link to the wrong page.** `build-wiki.py`
  resolved links by basename, so every `README.md` in the repo collapsed onto
  whichever page `internals/README.md` maps to — the Benchmarks page rendered
  ``[`bench/README.md`](Internals-Index)``. No link checker would flag it; the
  target was a real page. Links now resolve against the source document's
  directory. The gate that should have caught it asserted that the string
  `CODE_LINK_RE` appeared in the script, which stayed true throughout; it now
  builds the wiki and fails if any relative link survives into the output.
- voipmonitor is reported as `MISSING` by `bench/compare.sh` when neither a
  native binary nor `VM_IMAGE` is available, rather than being silently skipped.
  A comparison whose competitor is absent is not a comparison.

## [0.5.47] - 2026-07-27

### Added
- **Third-party notices, generated and shipped.** `THIRD-PARTY-NOTICES.md`
  covers 373 distributed crates plus the two system libraries the binaries link
  — libpcap (BSD-3-Clause) and libasound (LGPL-2.1-or-later). Attribution is a
  license obligation, not a courtesy: MIT and Apache-2.0 both require the notice
  to travel with the binary. It is generated from `cargo metadata` and gated, so
  it cannot go stale on the next `cargo update`, and it now ships in the
  tarballs, the `.rpm` and the `.deb`. The `.deb` previously shipped **no**
  license files at all.
- **Every released binary is now executed before it is published.** `release.yml`
  built eight targets, gated their glibc floor and their size, attested their
  provenance and shipped them without ever running one — those gates check facts
  *about* a binary, not that it works. Each target now runs `--version`,
  `--help` and a real capture parse before packaging, with aarch64 Linux under
  `qemu-user`, every invocation bounded by a timeout.

  Two targets are exercised less than the rest, and both say so in the run
  rather than passing quietly. x86_64 macOS cannot run on an arm64 builder at
  all. And gnu binaries under emulation get `--version` and `--help` but not the
  capture parse: reading a capture drops privileges, `getpwnam()` sends glibc
  through NSS, NSS `dlopen`s `libnss_files.so`, and `dlopen` under `qemu-user`
  deadlocks — the first version of this step hung for 37 minutes on exactly that
  before being canceled by hand. The static musl aarch64 binary completes the
  same parse under the same emulator, because it resolves users without NSS. So
  it is a limit of emulating glibc, not a property of the shipped binary.
- **The Docker image is run before it is pushed.** `docker.yml` went from build
  straight to push to sigstore attestation without ever invoking the image, so a
  broken runtime layer would ship attested. It is now built locally, exercised,
  and only then published.

### Fixed
- **The build docs told Alpine users to build something that cannot work.**
  "Most users: `cargo build --release` — default features give you … audio
  playback" is false on musl: the plugin is loaded with `dlopen`, static musl
  has no dynamic loader, and the binary happily reports `audio` in `--version`
  while playback can never succeed. Both doc trees now state the constraint and
  give the two verified Alpine recipes — static without audio, or dynamically
  linked with `alsa-lib` for audio. `release.yml`'s own comment called this
  "impractical"; it is impossible, and saying so invited someone to try.

- **The benchmarks had never run in CI.** Four criterion suites live in
  `benches/` — parser, pipeline, store, tui_derived — and the only reference to
  them in any workflow was clippy's `--all-targets` lint pass. A benchmark that
  panicked, or stopped compiling against a changed API, would have sat broken
  indefinitely. A `Benchmarks (execute)` job now runs all four. It is named for
  what it does: it proves the suites still execute, not that performance has
  held, because criterion's baselines live in `target/criterion` and do not
  survive a cache miss.
- **Coverage was measured and never enforced.** `quality.yml` collected it,
  summarized it, uploaded HTML and pushed to Codecov with
  `fail_ci_if_error: false`, while nothing asserted a minimum — it could decline
  release after release with every run green. Now gated at
  `--fail-under-lines 92`, chosen from the real figure in CI's own coverage
  artifact (lines 92.85%, functions 94.29%, regions 93.15%) so it ratchets
  rather than blocks.
- **`benches/BASELINES.md` read as current and was not.** Its newest entry
  predates the 1.97.1 toolchain pin, nothing re-verifies it and no job compares
  against it. It now says so, and says that entries must never be edited — a
  baseline's value is recording what was actually measured.

### Verified
- The full suite passes on Alpine/musl — 3010 tests, 0 failures, 55 binaries
  including doctests — matching the glibc host exactly. This is the first time
  musl has been tested at all.
- The `.deb` now provably carries its license files: `test-build-deb.sh`
  asserts `LICENSE-MIT`, `LICENSE-APACHE` and `THIRD-PARTY-NOTICES.md` are
  inside the built package, not merely that the build succeeded. Those are
  different claims, and only the second one was ever checked.

## [0.5.46] - 2026-07-27

### Fixed
- **The diagram viewer assigned mermaid's output to `innerHTML`** (CodeQL
  `js/xss-through-dom`, high). Diagram source is read from the page with
  `textContent` and the rendered SVG went back in through an HTML sink. The
  code carried a comment arguing this was safe — the source is authored in this
  repository, no visitor input reaches it, and mermaid runs under
  `securityLevel: "strict"`. Each of those is true today and none is enforced;
  the argument stops holding the moment a diagram is rendered from anything a
  visitor typed. The viewer now calls `mermaid.run()` to render in place and
  moves the resulting `<svg>` node with `appendChild`, so no string crosses back
  through a markup parser in this file at all and sanitizing stays mermaid's
  own DOMPurify under `securityLevel: "strict"`.

  Two earlier attempts are worth recording, because both looked like fixes and
  neither was. Replacing `innerHTML` with `DOMParser` moved the sink instead of
  removing it — `parseFromString` interprets markup whatever MIME type it is
  handed, and an inert parse only defers the problem, since `importNode` makes
  any surviving handler attribute live. Hand-rolling a scrubber on top then
  introduced a *new* high-severity finding of its own
  (`js/incomplete-url-scheme-check`): a scheme denylist that missed `vbscript:`.
  The recurring error was marshaling markup by hand; the fix was to stop.
  All 17 diagrams verified rendering afterwards with drag, zoom and collapse
  intact.

## [0.5.45] - 2026-07-27

### Fixed
- **The wasm32 build was broken, and the CI job meant to catch it compiled for
  the wrong target.** `.cargo/config.toml` sets
  `--cfg getrandom_backend="wasm_js"` for `wasm32-unknown-unknown`; rustflags
  are per-target, so that cfg reaches every `getrandom` in the graph, and any
  0.3+ line seeing it without the matching feature refuses to compile.
  `Cargo.toml` enabled `wasm_js` on 0.4 only — beneath a comment correctly
  naming ahash and the 0.3 line — so the fix never applied to the version ahash
  actually resolves and `cargo check --target wasm32-unknown-unknown --lib`
  failed. CI's wasm job ran `cargo check --features wasm --lib` with no
  `--target`, compiling for the host where the `cfg(target_arch = "wasm32")`
  dependency block is inert: it proved the feature builds for Linux and nothing
  about wasm. The job now targets wasm32, and a static gate checks every
  getrandom major line in the lockfile.
- **The glibc floor was still wrong in doc prose after the constants were
  fixed.** `build.md` went on telling readers "requires glibc >= 2.39" under a
  green gate, because the gate compared only the two constants and
  `release.yml`. Both install pages also described the 2.39 installer cutover as
  deliberate; it now matches the enforced 2.36. The floor gate reads doc prose
  as well — a floor stated in a sentence is what a reader acts on.

- **The site and the installer published a glibc floor five minor versions
  above the real one.** `release.yml` moved the gnu builds into
  `rust:1-bookworm` and enforces a 2.36 floor; `website/config.toml` and
  `website/static/install.sh` both went on saying 2.39. The installer compares
  the host's glibc against that number, so every Debian 12 machine was handed
  the static musl build — which the installer's own message notes has no TUI
  audio — instead of the gnu build it can run. Verified against the released
  v0.5.44 artifacts: both the x86_64 and aarch64 gnu binaries need only
  GLIBC_2.34. The installer's own test suite had asserted the wrong behavior
  (`glibc 2.36 → musl`), so it passed for the same reason the bug existed.
- **The homepage understated the binary by 87%.** The stat tile and the build
  docs said 5 MB; the shipped stripped musl binary is 9.34 MB. The tile's gate
  compared `data-count` to the tile's own fallback text, so it never looked at
  a binary. The claim is now a 10 MB ceiling, single-sourced from
  `website/config.toml` and enforced against the real artifact in `release.yml`.

### Changed
- **`getrandom` 0.4.2 → 0.4.3** (Dependabot, cargo-minor-patch group). Drops 15
  build dependencies (`wit-bindgen`, `wasmparser`, `wasip3` and friends), −172
  lines of lockfile.

### Added
- **Four gates for claims nothing was measuring.** The glibc floor across
  `release.yml`, the site config and the installer; the binary-size ceiling
  across the config, the homepage, both doc trees and the release workflow;
  every Rust toolchain pin across six workflow steps, the Dockerfile and both
  `rust-version` fields; and every target `install.sh` can request against the
  release matrix, so a renamed target cannot 404 on a user's machine. Each was
  verified by planting the original defect and watching it fail.

## [0.5.44] - 2026-07-26

### Added
- **The developer documentation is now published on the website**, not only to
  the GitHub wiki. `docs/internals/` stays the single source of truth;
  `scripts/build-site-internals.py` renders it into
  `website/content/docs/internals/`, which is committed so the site still builds
  with Zola alone. The Docs dropdown and the docs sidebar carry all ten pages —
  their absence from the dropdown is what surfaced this.
- **A mermaid viewer we control.** The wiki renders these diagrams with GitHub's
  viewer, which pins its controls to the bottom-right corner *over the diagram
  text*, with no way to move or hide them. The site now renders the same
  diagrams with a vendored mermaid bundle and a control box that can be
  collapsed and dragged anywhere in the figure; position and collapsed state
  persist across pages and reloads. Pan with a drag, zoom with the buttons or
  Ctrl/⌘+wheel — a bare wheel still scrolls the page, so a diagram never traps
  the reader's scroll. The 3.4 MB bundle loads only on pages whose frontmatter
  declares `has_diagrams`, a flag the generator sets from the content itself.
- **`--group-by <FIELD>` is implemented.** It was documented, parsed into
  `Cli::group_by`, and **never read** — any value, including a typo, was
  accepted and produced ungrouped output. It now groups batch output so messages
  sharing a field value are emitted contiguously, on one of `call-id`, `from`,
  `to`, `method`, `src`, `dst`.

  Messages are reordered, not reformatted, so `--json` stays one valid object per
  line with no schema change — the grouping *is* the contiguity. Human-readable
  output gains a `-- field value --` header per group. An unknown field is now
  rejected at startup with the accepted list, and the flag requires `-N`/`--no-tui`
  like every other output flag.

  Grouping cannot stream (the last packet may belong to the first group), so it
  buffers until the capture ends. That buffer is keyed on attacker-supplied data
  (`Call-ID`, `From`), so it is bounded like every other such map in the tree
  (invariant 4): 10,000 groups and 200,000 messages, warning that output is
  incomplete rather than silently truncating.

### Fixed
- **Pre-commit gate 6 never ran.** `grep -rn "TODO\|FIXME" src/ -g '*.rs'` uses
  `-g`, a ripgrep/ugrep flag. Under GNU grep that is an invalid option; the error
  went to `2>/dev/null` and the count came back `0` unconditionally, so the
  no-TODO-stubs gate silently passed on any machine whose `grep` was GNU grep.
  Now uses `--include`, which both accept. Verified under GNU grep 3.11 and
  ugrep 7.5.0, and with a planted `TODO` to confirm it has teeth.
- **The Filter DSL has 31 fields, not 30** — wrong in both troubleshooting pages
  while `filter-dsl.md` said 31.
- **`--on-quality-exec` passes `SIPNAB_STREAM_JSON`, not `SIPNAB_JSON`** — both
  output-format pages named the wrong variable, so a hook written from the docs
  would have read an unset one.
- **A four-agent audit fixed 48 factual disagreements between the two doc trees
  and 15 wrong claims in the developer docs.** User-facing highlights: the site
  said the `-gnu` build needs glibc 2.39 (enforced floor is 2.36); its tarball
  install command could not work, since releases tar a staging directory;
  `--keylog` was said to decrypt SRTP (that needs `--dtls-keylog` or
  `--srtp-keys`); `--alert-exec` examples used `%type%`/`%source_ip%`
  placeholders that do not exist; `--kill-scanner` was said to answer 403 (it
  defaults to 200); the Call Flow pane-resize keys were documented with both the
  key and the pane inverted; `/metrics` on the REST server was called optionally
  authenticated though it shares the guarded router; and two REST client samples
  read fields (`messages`, `diagnosis.summary`) the API does not emit. In the
  developer docs, two pages claimed `process_packet()` was the only lock-taking
  applier while a third correctly documented `run_pcap_load()` as a second writer.
- The stale "verified against a real build (`sipnab 0.5.20 ...`)" claim in both
  MCP walkthroughs. The version-marker gate's regex requires a `(` after the
  version, so a bare `sipnab 0.5.20 features:` line slipped through and sat stale
  for 23 releases; the remaining mention is now explicitly historical.
- **Two link gates silently skipped every subdirectory link.** The `@/docs/…`
  patterns in `site_journey_test` and `link_integrity_test` had no `/` in their
  character class, so a link into a docs subsection did not match and was never
  checked — the gates reported clean because they never looked. The docs
  frontmatter gate had the same shape of hole: it read the docs directory
  flat, so a subsection's weights and descriptions were ungated. Both now
  recurse, with weight collisions scoped per section the way Zola sorts them.
- **The download page advertised the wrong release date.** `release_date` in
  `website/config.toml` had no gate anywhere — the version beside it was
  checked against `Cargo.toml` by both a test and the pre-commit hook, the date
  next to it by nothing — and it had drifted two days behind the CHANGELOG. It
  is now asserted equal to the CHANGELOG heading for the version the site
  claims to be serving.

## [0.5.42] - 2026-07-26

### Fixed
- **Hovering the GitHub icon highlighted the entire footer row.**
  `.footer-icon:hover` applied `transform: scale(1.1)`, and a transform
  contributes to the scrollable overflow area of its ancestors. `.footer-row` is
  a scroll container by design (`overflow-x: auto`, deliberately one line), so
  scaling the right-most icon pushed the content past the container width — a
  scrollbar spanning the whole footer flicked in on hover and out on mouse-out.
  Hover now changes color only. The single-row layout is unchanged, so the
  `flex-wrap: nowrap` contract pinned by `site_journey_test` still holds.
- The footer GitHub link was missing the `target="_blank" rel="noopener"` its
  Patreon and GitHub Sponsors siblings carry.
- **The transport match in `parse_packet()` is exhaustive again.** 0.5.41
  handled etherparse 0.21's new `TransportSlice::Igmp` with a `_` catch-all,
  which silenced the compile error but gave up the guarantee that a future
  etherparse transport gets reviewed. `TransportSlice` is not
  `#[non_exhaustive]`, so IGMP is now matched explicitly and the wildcard is
  gone: when etherparse adds a transport, the build fails and someone decides
  whether it can carry SIP or RTP, instead of it being silently dropped.

## [0.5.41] - 2026-07-26

### Changed
- Dependency updates, covering every open Dependabot recommendation. Five are
  semver-breaking `0.x` bumps and were applied and compiled rather than merged
  on trust: **base64** 0.22→0.23, **getrandom** 0.3→0.4, **jsonschema**
  0.48→0.49, **etherparse** 0.20→0.21, and **serial_test** 3→4. Patch/minor:
  clap 4.6.2→4.6.3, libc 0.2.186→0.2.189, serde_json 1.0.150→1.0.151, tokio
  1.53.0→1.53.1, trycmd 1.2.0→1.2.1. Only etherparse required a code change
  (below); the rest were API-compatible with sipnab's usage.
- `actions/download-artifact` in `pages.yml` bumped v4→v8, aligning it with
  `release.yml`, which was already on v8.

### Fixed
- **etherparse 0.21 added `TransportSlice::Igmp`**, which made the transport
  match non-exhaustive. IGMP now reaches that match and is reported as "not
  UDP/TCP" (`CaptureError::NoTransport`) rather than being folded into the ICMP
  arm, which would have mislabeled it. The arm is now a catch-all so a future
  etherparse variant does not break the build — sipnab's own SCTP handling runs
  earlier (IP protocol 132), so it is unaffected. Pinned by a new test that
  fails if IGMP is reported as ICMP.

## [0.5.40] - 2026-07-25

### Removed
- **BREAKING: the legacy `s1` bearer-token format is no longer accepted.**
  0.5.39 introduced audience-bound `s2` tokens while continuing to verify `s1`
  tokens so pre-existing ones kept working. `s1` carries no `aud`, so every
  such token authenticated against *both* the REST API and HTTP MCP — which
  left the audience binding best-effort rather than absolute for as long as any
  `s1` token remained alive. It is now rejected outright.

  **Impact:** any `s1` token still in circulation returns `401`. Re-mint with
  `--mint-token`. The default TTL is one hour, so most callers will already
  have rotated; long-TTL tokens minted before 0.5.39 are the ones to check.
  Static `--api-key` / `--mcp-token` secrets are unaffected.

  A side effect worth knowing: a static secret shaped like `s1.x.y` used to be
  claimed by the signed-token path and always failed. It is now treated as an
  ordinary opaque secret and works. The caveat still applies to `s2.x.y`.

### Security
- The audience check is now unconditional — there is no accepted token version
  that reaches a surface without one.

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
- `docs/architecture.md` and `CONTRIBUTING.md` delegate into the developer docs
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
- `docs/architecture.md` documented a `--jobs` flag that does not exist; the flag is
  `--cores`. `docs/architecture.md` is now in the flag-drift corpus.
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
  (Canceled → InCall) per RFC 3261, instead of leaving a call that was
  actually answered stuck in the Canceled state.
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
  teardown, or the failed/canceled path) derived from dialog timing
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

Determination and design in docs/design/compact-headers-spec.md. SigComp (RFC 3320
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
  docs/design/maintainability-perf-spec.md.

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
  `Canceled 487` — so the precise outcome (486 busy vs 503 unavailable vs 408
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
  shipped for large-payload behavior, allocator pressure, and the
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
