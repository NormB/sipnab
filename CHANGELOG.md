# Changelog

All notable changes to sipnab will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

sipnab is pre-1.0: the public API and the CLI surface are not stable, and a
breaking change may land in any release. Breaking changes are called out in the
entry that carries them.

## [Unreleased]

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
  reader assumes the Linux behaviour and sees nothing when SIP is not on the
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
  `cargo build`s hit one target directory. They serialise on cargo's
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
  the current behaviour so the gap is a decision on the record, and closing it
  fails there first.

- **`response_class()` — one classifier, replacing inline ranges in four
  handlers.** `provisional`, `success`, `redirect`, `challenge`, `cancelled`,
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

- **SIP diagnosis detections 4–7 — missing `ACK`, abandoned/cancelled, high
  post-dial delay, registration failure.** The set is complete: a dialog now
  reports an answered `INVITE` that was never acknowledged, a call cancelled or
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
  *already* `Cancelled`, and because it matches before the `400..=699` arm the
  response did not fall through to `Failed` either. So a cancelled call whose
  CANCEL went uncaptured reported as one still waiting for an answer — a
  different diagnosis from the one the wire carried.

  RFC 3261 §21.4.25 says a 487 means the request "was terminated by a BYE or
  CANCEL request". The 487 is itself the proof; seeing the CANCEL is not a
  precondition. A CANCEL can take a different path from the response, a capture
  can start mid-dialog, and sampling can drop it. A 487 whose CSeq method is
  INVITE now sets `Cancelled` from `Trying`, `Ringing` or `Cancelled`, guarded on
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
  `redirect`, `challenge`, `cancelled`, `declined`, `failure`. Only the last is
  a failed call. Folding the others into "failed" loses what an operator acts
  on — a call that drew a `challenge` and never authenticated is a provisioning
  problem, one that ended `cancelled` is a caller who hung up, and one that came
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
  unsigned" *is* the mistaken belief being catalogued; it reads "has no sign bit"
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
- **The call report carries the signalling findings.** Text and Markdown both get a
  Signalling section listing each detection with its evidence — which is also what
  MCP's `get_dialog_report` returns for its non-JSON formats. Evidence is labelled
  with the message rather than printed as a bare index: JSON emits `[1]` because a
  machine will join it against the message list, but a report pasted into a ticket
  has no such list to hand, so it reads `#1 503 Service Unavailable`. An index
  outside the message list is reported as out-of-range rather than silently
  dropped, since a quiet drop would make the report claim less evidence than the
  diagnosis found.
- **The TUI call list marks diagnosed dialogs.** A `⚠` in the State cell when a
  dialog has any signalling finding. The spec asked for this "in the style of the
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
  the ones whose advice is wrong here — "spell out SIP" on a SIP analyser (3,675),
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
  the enforced level, the preemptive disables are labelled as such, the 670-alert
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
  and origin are now two labelled steps, with the `gh attestation verify` command
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
  variant are now alternations, so a new package flavour is covered the day it is
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
- **Spec for SIP problem diagnosis** — the signalling-side complement to
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
  *before* the INVITE created a dialog labelled `UNKNOWN`, and the genuine
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
  and the licence-election table deduplicated. Each fix verified by
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
  Output, transcripts and diagrams are labelled `text` deliberately — labelling
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
  which would have shipped sipnab under the wrong licence. Deleted rather than
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
  them changed behaviour. `get_by_key` addresses one specific transaction.

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
  two of the three callers discarded the value. Both now honour it.
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
  Four of the five gaps now have real behaviour tests — `--rotate`,
  `--duration`, `--strip-secrets` and `--hep-parse` — and the fifth was
  `--dialog-track`, removed above.

- **The release ran a `strip` that had never worked on cross-compiled targets.**
  It sat behind `|| true`, so nothing was visible either way. On the
  cross-compiled targets the host's GNU strip cannot even read the output
  (`Unable to recognise the format of the input file`) and had failed on every
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
  without bumping the crate would ship packages labelled 0.6.0 containing a
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
  licence obligation, not a courtesy: MIT and Apache-2.0 both require the notice
  to travel with the binary. It is generated from `cargo metadata` and gated, so
  it cannot go stale on the next `cargo update`, and it now ships in the
  tarballs, the `.rpm` and the `.deb`. The `.deb` previously shipped **no**
  licence files at all.
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
  before being cancelled by hand. The static musl aarch64 binary completes the
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
  summarised it, uploaded HTML and pushed to Codecov with
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
- The `.deb` now provably carries its licence files: `test-build-deb.sh`
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
  The recurring error was marshalling markup by hand; the fix was to stop.
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
  GLIBC_2.34. The installer's own test suite had asserted the wrong behaviour
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
