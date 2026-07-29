# Developer index

Documentation for people changing sipnab, not people running it. Operator
documentation lives one level up in `docs/`; the polished site is
[sipnab.com](https://www.sipnab.com).

Pages here link directly into the source tree. That is deliberate: docs and
code share one repository, so a claim about the code should be one click from
the code, and a moved file or renamed function should fail the build rather
than rot quietly. [`tests/dev_docs_drift_test.rs`](../../tests/dev_docs_drift_test.rs)
enforces it.

## Start here

A reading order, not a table of contents:

1. [Domain primer](domain-primer.md) — the SIP and RTP model the code assumes
   you already have. Start here if you are a Rust engineer rather than a VoIP
   engineer; nearly every subtle bug in this tree is a protocol-semantics bug
   wearing a Rust costume.
2. [Subsystem guide](subsystem-guide.md) — one packet's journey from the wire
   to the screen, across all four packet paths.
3. [Invariants](invariants.md) — the rules that must not break. Read before
   your first pull request; each entry names what enforces it.
4. [Testing](testing.md) — the test tiers and the self-enforcing gate tests.
   Read when one of them fails you.
5. [Walkthroughs](walkthroughs.md) — ordered checklists for the common
   changes: a new TUI view, a new detector, a new CLI flag, a new MCP tool.
6. [Build, CI and release](build-ci-release.md) — features, workflows, hooks,
   and how a release is cut.

Already written, and narrower:

- [Threading](threading.md) — thread topology, the channels between them, and
  the lock discipline.
- [Zero-copy payloads](zero-copy-payloads.md) — the `bytes::Bytes` spine from
  capture to output, including a performance claim the page itself refutes.
- [TUI testing](tui-testing.md) — snapshot and state testing for the terminal
  UI.

The one-screen map of the tree is [`../architecture.md`](../architecture.md);
contributor mechanics (setup, hooks, PR expectations) are in
[`CONTRIBUTING.md`](../../CONTRIBUTING.md). Failure behavior — what sipnab
does when something goes wrong — is [the fault model](../fault-model.md).

## The corpus: live vs archaeological

The long design documents live in `docs/design/` and `docs/research/`, with the
codemap one level up in `docs/` itself. They are not all current, and reading
the wrong one as current is the main way to be misled here.

**Live:**

| Document | What it is |
|---|---|
| [`../architecture.md`](../architecture.md) | The codemap: module layout, data flow, and the design decisions that still hold. Maintained; a phantom flag in it fails `docs_drift_test`. |
| [`../design/maintainability-perf-spec.md`](../design/maintainability-perf-spec.md) | The rationale behind the current shape of the code — why the pipeline was unified, why `main.rs` was decomposed into `src/app/`. Sections 0–9 are the 2026-07-03 review of v0.4.18 and read as history; §10 (WS8) is the only live section — read it before any performance work. |
| [`docs/design/backlog.md`](../design/backlog.md) | The open backlog, priority-ranked P0–P5. The working list — start here for "what needs doing". |
| [`../design/lessons.md`](../design/lessons.md) | Four defects that reached a release, each with the rule derived from it: TUI state no renderer read, feature flags gating nothing, config parsed and never used, and the 2026-05-05 audit that found four blocking and ~17 major doc drifts accumulated since 0.3.1. Its cheap-regression greps have themselves rotted — the field-count one calls 30 current, and `dsl.rs` now has 31. |
| [`../research/codex-analysis.md`](../research/codex-analysis.md) | Adversarial security review of `698585e` (2026-07-22). Findings SN-01/02/03, all fixed; the analysis of *why* each was reachable is still the best description of the HEP trust boundary. |
| [`../research/capture-performance.md`](../research/capture-performance.md) | The packet-capture throughput roadmap: four phases ordered cheapest-first, each after the first carrying an explicit trigger condition so the complexity is only paid once the previous phase proves insufficient. Research, not committed work — one item is marked done, the auto-grow capture channel. Its baseline section still cites `file:line` positions that have moved: `src/main.rs:428` names a file that is now 130 lines long. |

**Archaeological** — kept for the determination record, superseded in places:

| Document | Read it for | Do not trust |
|---|---|---|
| [`../design/implementation-plan-v6.md`](../design/implementation-plan-v6.md) | The design-decision catalog D1–D21 and the original phase plan. | Its feature tables. The `tls-wolfssl`, `tls-openssl` and `grpc` features described there were never implemented and are not in `Cargo.toml`. D14's pluggable crypto backend was dropped: one backend ships (`ring` + `rustls`). |
| [`../design/implementation-plan-phases-8-10.md`](../design/implementation-plan-phases-8-10.md) | The MCP, HEP and observability designs, and the "Resolved Decisions" section that formally retires parts of v6. | Its D-numbering. It defines its own D20 (infrastructure-optional integration) and D21 (capture vs enrichment sources), which collide with v6's D20 and D21. Always say which document a D-number comes from. |
| [`../design/compact-headers-spec.md`](../design/compact-headers-spec.md) | Why all 19 RFC 3261 / IANA compact header forms are supported, and the `y:` STIR/SHAKEN evasion case that motivated it. | Nothing — it is implemented and pinned by tests. |
| [`../design/kill-target-spoofing-spec.md`](../design/kill-target-spoofing-spec.md) | The scope and ethics of sending a scanner-kill response from the victim's `ip:port` rather than an ephemeral one. | Nothing — but read `--kill-scanner`'s guard rails in [`cli.rs`](../../src/cli.rs) alongside it. |
| [`../design/dialog-tracking-modes.md`](../design/dialog-tracking-modes.md) | Why `--dialog-track` keys on Call-ID or on Call-ID plus top-Via branch, what the branch view costs everything downstream of the store, and the rejected alternatives. | Nothing outstanding. Its status line read "spec, not yet implemented" for six releases after the flag shipped in 0.5.54 — recorded here and left — and now reads IMPLEMENTED. `an_unimplemented_design_doc_does_not_name_a_shipped_flag` fails if a design doc calls itself unimplemented while naming a flag `Cli` accepts, so this column no longer has to carry that job. |

## Glossary

Identifiers that appear in commit messages, code comments and the backlog
without expansion.

**D1–D21 — design decisions.** The catalog in
[`../design/implementation-plan-v6.md`](../design/implementation-plan-v6.md). The ones cited
most often in code: D2 (synchronous core, async only at the edges — the packet
path in [`pipeline.rs`](../../src/pipeline.rs) never awaits), D3 (zero-copy
payload spine), D10 (feature gates keep the binary small), D11 (key material is
toxic waste — [`crypto.rs`](../../src/crypto.rs) zeroizes), D13 (RTP is
first-class: [`stream_store.rs`](../../src/rtp/stream_store.rs) discovers
streams with no SIP at all), D15/D16 (privilege drop and process isolation),
D17 (warn and continue on malformed input), D18 (localhost default for every
listener). Beware the numbering collision noted above. **D22, D23 and D24**
also exist, but only in
[`../design/implementation-plan-phases-8-10.md`](../design/implementation-plan-phases-8-10.md)
— v6's catalog stops at D21. D22 is competitive-feature-borrowing discipline,
whose prompt-injection rule is the one cited in
[`src/mcp/server.rs`](../../src/mcp/server.rs); D23 makes documentation a
tier-1 deliverable that lands in the same pull request as the code it
describes; D24 makes tests a phase-completion gate, which is why every
code-bearing sub-phase in that plan carries a `Tests — X.Y deliverables` block
beside its `Gate` and `Docs` blocks.

**WS0–WS8 — workstreams.** The refactor program in
[`../design/maintainability-perf-spec.md`](../design/maintainability-perf-spec.md). WS0 was a
batch of independent quick wins; WS1 unified the per-packet pipeline into the
single [`classify_packet()`](../../src/pipeline.rs) router; WS2 decomposed
`main.rs` into [`src/app/`](../../src/app); WS3–WS5 were structural and
performance work; WS6–WS7 hardened the API surface. WS0–WS7 shipped in v0.5.0;
WS8 (performance) is the only live section.

**P0–P5 — backlog priority tiers** in [`docs/design/backlog.md`](../design/backlog.md):
P0 panics and security, P1 wrong results in real use, P2 robustness and
efficiency, P3 code health, P4 test quality, P5 features and exploratory work.
A "P1" in a commit message means the commit fixed something that produced a
wrong answer, not that it was merely important.

**SN-01/02/03 — security findings** from
[`../research/codex-analysis.md`](../research/codex-analysis.md), all fixed: SN-01 unauthenticated
HEP metadata driving active network responses (the reason
[`parse_packet()`](../../src/capture/parse.rs) tracks HEP origin per packet and
scanner-kill refuses HEP-origin packets without `--hep-allow-kill`), SN-02 an
unauthenticated non-loopback metrics bind, SN-03 crash-report creation that
followed symlinks.

**The gate suite** — the self-enforcing checks that run without anyone asking:
the numbered gates in [`.githooks/pre-commit`](../../.githooks/pre-commit)
(clippy, the full test suite, no `unwrap()`/`expect()` in production, WASM
exports in sync, the homepage *test count*, sub-gate 5b for the site version —
a different claim from the crate version — no TODO stubs, WASM rebuild, and an
advisory notice when a commit touches code these pages cite; the TODO scan and
that notice are the two advisory gates, printing `WARN`/`REVIEW` and letting the
commit through). Sub-gate 5c is gone: it re-implemented a Rust test in shell,
the copies diverged, and the surviving Rust version runs here *and* in CI. Also
four in
[`.githooks/pre-push`](../../.githooks/pre-push) (`fmt`,
`clippy --all-features --all-targets`, `cargo doc` with `-D warnings`, and a
`fuzz` workspace check), and the CI jobs behind them.

**The drift tests** — the subset of the gate suite that compares documentation
and configuration against the code and fails on divergence:
[`docs_drift_test`](../../tests/docs_drift_test.rs) (flags, version markers,
feature table, `[theme]` slots),
[`link_integrity_test`](../../tests/link_integrity_test.rs)
(every relative link and anchor resolves),
[`flag_coverage_test`](../../tests/flag_coverage_test.rs),
[`keybinding_drift_test`](../../tests/keybinding_drift_test.rs), and
[`dev_docs_drift_test`](../../tests/dev_docs_drift_test.rs) for these pages.
They exist because every one of them was, at some point, a doc that lied.

**The smoke fuzz floor** —
[`tests/smoke_fuzz_test.rs`](../../tests/smoke_fuzz_test.rs), which feeds tens
of thousands of random and mutated inputs to every parser reachable from
attacker-controlled bytes under `catch_unwind`, on the stable toolchain, in
every `cargo test` run. It is the always-on regression floor beneath the
coverage-guided targets in [`fuzz/fuzz_targets/`](../../fuzz/fuzz_targets),
which need nightly and run weekly. A panic there is a remote DoS on a capture
process, so the floor is not optional.

## Conventions for these pages

- **Cite code as a link, never as `file:line`.** Line numbers rot within a
  commit; a path plus a `()`-suffixed symbol in the link text survives, and
  [`dev_docs_drift_test`](../../tests/dev_docs_drift_test.rs) checks both.
- **Relative links only.** An absolute `github.com/NormB/sipnab/blob/main/…`
  URL pins a branch and goes stale silently;
  [`build-wiki.py`](../../scripts/build-wiki.py) rewrites the relative form
  into a blob URL when publishing to the wiki.
- **Write heading anchors in GitHub's spelling.** That is what `docs/` is read
  in, and the generators translate on the way out:
  [`build-site-pages.py`](../../scripts/build-site-pages.py) rewrites an
  anchor to Zola's slug when it emits a site link, because the two renderers
  disagree — GitHub drops an em dash and keeps its surrounding spaces
  (`step-0--install-…`) where Zola collapses the run (`step-0-install-…`), and
  GitHub keeps an underscore where Zola makes it a dash. `generated_site_anchors_resolve_under_zola`
  checks the generated tree under Zola's rule alone; the older
  `anchor_candidates` unions all three slug rules, which is right for `docs/`
  and too generous for a page only Zola will ever render.
- **Diagrams are mermaid `sequenceDiagram`, and every one is preceded by a
  prose line** that carries the same point, so a page still reads where mermaid
  does not render.
- **A change to linked code updates the page that links it, in the same pull
  request.** The hard gate is `dev_docs_drift_test` in CI.
- **These pages publish twice, and this tree is the source of both.**
  [`build-wiki.py`](../../scripts/build-wiki.py) renders them into the GitHub
  wiki; [`build-site-internals.py`](../../scripts/build-site-internals.py)
  renders them into `website/content/docs/internals/`, which is committed so
  the site builds with Zola alone. Never edit either mirror — regenerate it.
  `dev_docs_drift_test` re-runs the site generator and fails if the committed
  output is stale. The same arrangement covers the operator
  pages: [`build-site-pages.py`](../../scripts/build-site-pages.py) renders
  each entry in its `PAGES` registry from `docs/` into `website/content/docs/`,
  gated by `site_pages_mirror_is_current`. All thirteen registered pages got
  there the same way — hand-maintained on both sides until they diverged. The
  cookbook shared 2 of its 36 commands with the site copy; the REST API page was
  430 lines against the site's 893, each side holding sections the other lacked;
  the MCP page was 672 lines against the site's 440, and its tool table listed 7
  of the 11 registered tools where the site's listed all 11. The ten that
  followed were the same story: the site's Filter DSL page carried fourteen
  operational recipes `docs/` did not have, so every wiki reader got that page
  without them.

  `benchmarks.md` is the deliberate exception — both copies exist, neither is
  generated, and only the measured tables are gated
  (`benchmark_tables_match_between_docs_and_website`), because the framing
  around them is meant to differ.
  The wiki renders from `docs/`, so it showed whichever copy was thinner as
  though it were the whole page. Register a page there; never copy the script. The site mirror exists because GitHub's wiki mermaid viewer
  pins its controls over the diagram with no way to move them; the site
  renders the same diagrams with a viewer we control.
