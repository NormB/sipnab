# Developer Documentation — Design Spec

**Date:** 2026-07-25
**Status:** Approved (design); implementation plan to follow
**Backlog item:** `tasks/todo.md` P5 — "Developer documentation"

## Problem

sipnab is ~106k LOC of Rust across 130 files, with 12 self-enforcing
documentation gate tests, 12 Cargo features, 8 GitHub workflows, and 11
pre-commit/pre-push hook gates. A new contributor can find *what* the project
does (the `docs/` tree is a strong user manual) but cannot answer:

- Where does code live, and how does one packet actually flow through it?
- What invariants must I not break?
- Which of the ~50 test files will fail my PR, and why?
- How do I add a view / detector / flag / MCP tool?
- What is the SIP/RTP mental model this code assumes I already have?

The last question is the steepest wall. Nearly every P1 entry in
`tasks/todo.md` is a domain-semantics bug rather than a Rust bug — RTCP jitter
left in RTP-timestamp units, 24-bit signed `cumulative_lost` zero-extended,
unsigned wrapping subtraction spiking jitter on reorder, TCP sequence
comparison without RFC 1982 serial arithmetic, `answered_at` matching a
re-INVITE's 200, delayed-offer misclassification. A contributor without the
domain model will reintroduce exactly these.

## Goals

1. A contributor can locate any subsystem and trace a packet end to end.
2. A contributor knows, before opening a PR, which gates will fire and why.
3. The invariants that are currently tribal knowledge are written down once.
4. The docs are machine-checked against the code, so they rot loudly.

## Non-goals

- Mirroring developer docs to the Zola website (`docs/internals/` is
  wiki-only, by existing convention).
- Generated rustdoc / API reference.
- Adding a `rust-toolchain.toml` (documented as a known gap, not fixed here).
- Shrinking the `KNOWN_UNTESTED` flag-waiver ratchet.
- The P5 "SIP problem diagnosis" feature, which is a separate backlog item.

## Decisions

| # | Decision | Rationale |
|---|---|---|
| D-1 | Expand `docs/internals/`; do not create a sibling directory | The dir already exists with 3 pages and is already registered in `build-wiki.py`. Zero migration, no link rewrites, `docs/README.md` already points there. |
| D-2 | All 8 pages in scope | The gap analysis found none of them exist anywhere in the tree. |
| D-3 | Fix existing doc drift as Phase 0 | New pages link into `README.md`, `ARCHITECTURE.md`, and `threading.md`. Shipping docs that point at wrong statements makes the drift worse. |
| D-4 | Add `tests/dev_docs_drift_test.rs` | Matches house style — the project already has 12 such tests. Docs that aren't enforced decay silently. |
| D-5 | Code references are **markdown links into the code**, never `file:line` | Docs and code live in one repo, so a relative link is clickable on GitHub and takes the reader straight to the file. Line numbers are wrong within a release; a link plus a `()`-suffixed symbol in the link text is stable, greppable, and machine-checkable. |
| D-6 | 17 mermaid `sequenceDiagram` blocks | sipnab already emits this exact format from its own call-flow ladder ([`export_mermaid()`](../../../src/tui/call_flow/export.rs)), so readers can regenerate the domain diagrams from a real capture with the `E` key. |
| D-7 | `build-wiki.py` rewrites code links to blob URLs | `LINK_RE` matches `.md` only, so a relative `../../src/pipeline.rs` link passes through untouched and is dead on the flat wiki. `rewrite_link()` already contains the `../`-climbing → `BLOB` logic; it generalizes. |
| D-8 | Code↔docs coupling is enforced in two tiers | A rename or move must not be able to land while the docs still describe the old shape. See "Keeping docs in step with code" below. |

## Structure

```
docs/
├── README.md                      (+1 "Contributing to sipnab" pointer)
├── *.md                           (15 user-facing pages, unchanged)
└── internals/                     ← the developer documentation
    ├── README.md              NEW  start-here index, corpus map, glossary
    ├── domain-primer.md       NEW  SIP + RTP mental model
    ├── subsystem-guide.md     NEW  one packet's journey, all four paths
    ├── invariants.md          NEW  consolidated must-not-break list
    ├── testing.md             NEW  test tiers, support helpers, gate tests
    ├── walkthroughs.md        NEW  add a view / detector / flag / tool
    ├── build-ci-release.md    NEW  features, workflows, hooks, releases
    ├── threading.md           FIX  corrected + pcap-load thread added
    ├── zero-copy-payloads.md       unchanged
    └── tui-testing.md              unchanged
```

**Known fragility (record, do not fix):** `build-wiki.py`'s `SLUG_TO_PAGE` is
keyed on basename stem, so `internals/README.md` claims the stem `README`.
Nothing links to a bare `README.md` today (verified 2026-07-25), so this is
latent, not active.

## Citation form

Docs and code share one repository, so every code reference is a **relative
markdown link**, not backticked prose. A reader clicks through to the file
instead of grepping for it.

```markdown
The router is [`classify_packet()`](../../src/pipeline.rs), and every packet
path reaches it — [live](../../src/pipeline.rs),
[batch](../../src/app/batch.rs), [sharded](../../src/parallel.rs) and
[TUI file-open](../../src/tui/controllers/file_open.rs).
```

Rules:

- Paths are relative from `docs/internals/`, so a repo-root file is `../../`.
- Link text carries the symbol, `()`-suffixed: `` [`classify_packet()`](…) ``.
  A link whose text is a bare filename is a file reference and needs no symbol.
- Never `file:line`. Line numbers are wrong within a release.
- Directories may be linked (`[capture/](../../src/capture)`) when the
  reference is to a subsystem rather than a definition.

Two mechanisms make this work outside the repo view:

- **Wiki:** `build-wiki.py` rewrites relative code links to
  `{BLOB}/<path>` (D-7). Without this they are dead on the flat wiki.
- **Validation:** `link_integrity_test` explicitly skips non-`.md` targets, so
  nothing validates code links today. The new drift test owns that.

## Keeping docs in step with code

D-8, in two tiers. A rename must not be able to land while the docs still
describe the old shape.

**Tier 1 — hard, in CI.** `dev_docs_drift_test` resolves every linked path and
every `()`-suffixed symbol. A moved file, deleted module, or renamed function
fails the build until the docs are updated. Precise, with no false positives:
it fires only when a doc has actually become wrong.

**Tier 2 — advisory, at commit time.** A new pre-commit gate, modelled on the
existing `src/wasm.rs` → `website/static/wasm/` gate, notices when a commit
stages a change to a file the developer docs link to without staging any
`docs/internals/` change, and prints the symbols that file is cited for.

Tier 2 is deliberately **advisory, not blocking**, which is where it differs
from the wasm gate. That gate guards one file with a mechanical regeneration
step. This one guards hundreds of files whose edits are usually typo fixes and
internal refactors that invalidate no prose. A hard gate there would fail
routine commits, train contributors to bypass the hook, and cost more than it
catches. The blocking check is Tier 1, which fires only on real breakage.

## Page contracts

Every page states its audience and scope at the top, and **links out rather
than restating**. `invariants.md` cross-links `threading.md` and
`fault-model.md`; it does not duplicate them.

### `internals/README.md`
Developer index. Classifies the existing corpus as live vs archaeological —
`ARCHITECTURE.md` and `MAINTAINABILITY-PERF-SPEC.md` are live;
`implementation-plan-v6.md` and `implementation-plan-phases-8-10.md` are
historical design records with known phantom content. Glossary of project
shorthand used freely and defined nowhere: D1–D21, WS0–WS8, P0–P5, SN-01/02/03,
"the gate suite", "the drift tests", "the smoke fuzz floor".

### `internals/domain-primer.md`
The protocol model the code assumes. Dialog vs transaction; Call-ID/From-tag/
To-tag as dialog identity and why `dialog_store.rs` keys on them; CSeq method
pinning that `timing.rs` depends on; Via branch and B2BUA leg correlation;
SDP offer/answer including delayed offer and re-INVITE hold/resume/T.38; the
INVITE 3-way handshake vs non-INVITE transactions; why 401/407 is auth-pending
rather than failure. Then RTP: SSRC as stream identity and why streams exist
without dialogs; 16-bit sequence wraparound; RTP timestamps vs wall-clock and
the clock-rate divisor; RFC 3550 signed transit-delta jitter; MOS/E-model;
burst-gap loss; payload types and ptime; RFC 4733 telephone-event DTMF and its
clock-rate dependence; symmetric RTP, NAT mismatch, one-way audio.

Each concept names the file that encodes it, so the primer doubles as an index.

### `internals/subsystem-guide.md`
One packet's journey through named functions, covering all four packet paths
(live, batch, `--cores` sharded, TUI file-open) and the fact that they all
route through the single `pipeline::classify_packet` router with only the
appliers differing. Explicitly covers `src/app/` as the program spine
(`bootstrap.rs` → `RunPlan` → `batch.rs` | `tui_mode.rs` | `servers.rs`) and
`output/model.rs` as the one canonical wire shape for every serializing
surface.

### `internals/invariants.md`
One consolidated list: single-writer store discipline; dialog-store-before-
stream-store lock ordering, never both held; all four packet paths must route
through `classify_packet`; every attacker-keyed map bounded with a defined
eviction policy; `zeroize` on anything key-shaped; MCP tools are read-only;
`output/model.rs` is the only dialog/stream wire shape; the TUI render pass is
read-only; no lock held across `.await`; warn-and-continue on malformed input.
Also the two cultural norms that are real and unwritten: cite the RFC/ITU
standard for any analysis claim (the PR template already requires it), and the
honesty norm about refuted performance claims.

### `internals/testing.md`
Test tiers and what each asserts; the 7 `tests/support/` helper modules and
which to reach for; fixtures and corpora (`tests/fixtures/`, `pcap-samples/`,
`schemas/`, `cli/`, `install-sh/`, `fuzz/corpus/`) and how each is regenerated;
`SIPNAB_LOG` for debugging; `cargo nextest` and its unused-by-CI status; and
**the complete roster of self-enforcing gate tests with what trips each** —
the single most surprising thing about contributing here.

### `internals/walkthroughs.md`
Ordered checklists, each listing every file, test, and doc mirror to touch:
add a TUI view; add a security detector; add a CLI flag; add an MCP tool; add
an output format; add a fuzz target. Each step names the test that fails if
the step is skipped.

### `internals/build-ci-release.md`
The 12 features and what each gates, including which imply which and the fact
that `tls` and `audio` do **not** imply `native`. The 8 workflows, their
triggers, and which single job is the required branch-protection gate. The 7
pre-commit and 4 pre-push hook gates. Where the toolchain pins live and why
lockstep matters. How a release is actually cut, including every version-bump
location and the CHANGELOG convention.

## Diagram inventory — 17 sequence diagrams

| Page | Diagrams |
|---|---|
| `subsystem-guide.md` | 4 — startup → `RunPlan` → mode dispatch; live packet lifecycle with permit pool and lock ordering; TUI frame tick including the `try_read` skip path; `--cores N` shard → thread-local stores → merge → `reassociate_all` |
| `domain-primer.md` | 6 — INVITE 3-way handshake and dialog identity; auth 401/407 challenge loop; delayed offer; re-INVITE hold/resume; CANCEL vs 200 OK race resolving to InCall; RTCP SR/RR exchange showing where jitter units and 24-bit `cumulative_lost` bite |
| `walkthroughs.md` | 2 — "add a CLI flag" as developer vs. the four gate tests in firing order; "add an MCP tool" showing acquire → snapshot → `drop(guard)` → `.await` |
| `build-ci-release.md` | 2 — tag push → 8-job matrix → glibc floor check → attestation → Homebrew tap, with `docker.yml` in parallel; commit → pre-commit → pre-push → CI → `ci-success`, showing `install-sh` and `deb-package` outside the aggregate |
| `invariants.md` | 2 — correct lock sequence vs. forbidden simultaneous hold; single-writer store discipline |
| `threading.md` | 1 — the `pcap-load` thread as the second concurrent writer |

### Diagram conventions

- **`sequenceDiagram` only.** Where a structure genuinely is not a message
  exchange (module map, decision tree), use prose or a table.
- **Participants are real code identifiers** (`PacketProcessor`,
  `pipeline::classify_packet`, `DialogStore`), never prose roles.
- **`autonumber`** on any diagram whose steps prose references by number.
- **A one-sentence prose summary precedes every diagram**, so the page reads
  correctly where mermaid does not render.
- **No markdown-link syntax inside labels** — `build-wiki.py::transform()`
  applies `LINK_RE.sub()` to the whole body with no fence awareness.
- **No hardcoded colors and no `%%{init}%%` theme blocks** — must render in
  both GitHub light and dark.

### Gate-test safety (verified 2026-07-25)

| Gate | Why mermaid cannot trip it |
|---|---|
| `docs_drift_test::mcp_examples_always_pass_no_tui` | `read_dir("docs")` is non-recursive; `docs/internals/` is not scanned |
| `doc_example_coverage_test` | regex matches ` ```bash ` only |
| `link_integrity_test` | scans `prose()` = `strip_fences(strip_frontmatter(..))` |
| `site_journey_test` | website tree only; `docs/internals/` is not mirrored there |

## Drift test — `tests/dev_docs_drift_test.rs`

Eight assertions over `docs/internals/**`:

1. Every linked code target resolves to a file or directory in the repo.
2. Every `()`-suffixed symbol in link text resolves to a definition.
3. Code links use the relative form, not an absolute URL — an absolute URL
   pins a branch and silently goes stale.
4. Every `docs/internals/*.md` is registered in `build-wiki.py` `PAGES` **and**
   `GROUPS`. This closes a real hole: `build-wiki.py` errors on a `PAGES` entry
   with no source file, but silently declines to publish a `docs/*.md` missing
   from `PAGES`.
5. Every ` ```mermaid ` fence opens with `sequenceDiagram`.
6. No markdown-link syntax inside any mermaid fence.
7. Every mermaid fence is immediately preceded by a prose line.
8. The designed diagram set is present — at least 17 across the tree.

Assertions carry anti-vacuity floors, matching the house pattern in
`docs_drift_test.rs` and `link_integrity_test.rs`.

## Integration points

- `docs/README.md` — one "Contributing to sipnab" pointer to
  `internals/README.md`.
- `CONTRIBUTING.md` — link to the developer index; the currently undocumented
  pre-commit gates; the two-doc-tree mirroring obligation; and the citation
  form with the rule that a change to linked code updates the page that links
  it.
- `ARCHITECTURE.md` — stays the codemap; delegates depth to
  `subsystem-guide.md`.
- `scripts/build-wiki.py` — 5 new `PAGES` entries, `GROUPS` placement, and
  code-link rewriting to `BLOB` URLs (D-7).
- `.githooks/pre-commit` — advisory code↔docs coupling gate (D-8, Tier 2).

## Phase 0 — drift fixes

New pages link into these, so they are corrected first.

| File | Defect | Verified |
|---|---|---|
| `README.md` | 2 dead links: `./docs/mcp-overview.md`, `docs/mcp-setup.md` | yes, 2026-07-25 |
| `README.md` | Feature table omits `metrics`; misstates `full` and `native` | reported |
| `ARCHITECTURE.md` | Says `--jobs`; the flag is `--cores` with no alias | reported |
| `internals/threading.md` | Prometheus shown as a tokio task; it is a raw `TcpListener` thread | reported |
| `internals/threading.md` | `pcap-load` thread missing — the only second writer to the live stores | reported |
| `internals/threading.md` | Channel-flavor table stale for the batch path | reported |
| `docs/install.md`, website, installer | glibc floor says 2.39; the build enforces 2.36 | reported |

`README.md`'s dead links survive because
`link_integrity_test::no_references_to_merged_away_mcp_pages` scans `docs/` and
`website/content/docs/` recursively but **not** the root `README.md`. Extending
that test's corpus to include root-level markdown is in scope for Phase 0.

## Verification

- `cargo test --features full` green, including the new drift test.
- `python3 scripts/build-wiki.py build/wiki` builds clean and emits the 5 new
  pages in the "Development & internals" group.
- Every walkthrough checklist validated against the test that would fail if a
  step were skipped — the checklists are claims about CI behavior and must be
  executed, not reasoned about.
- `cargo fmt --check` and `cargo clippy --all-features --all-targets -D
  warnings` for the new test file.

## Authoring rule

Subagent reports and this spec are **leads, not sources**. Every factual claim
written into a page must be verified against the source file at authoring
time. Where a claim cannot be verified, it is omitted rather than hedged.

## Risks and assumptions

| Item | Handling |
|---|---|
| GitHub wiki mermaid rendering is unverified (repo markdown does render) | Check the first synced page in Phase 1. If the wiki does not render, keep the fenced source — the "prose precedes every diagram" rule already guarantees the page reads without it. |
| Code links are dead on the wiki unless `build-wiki.py` rewrites them | D-7 extends the existing `rewrite_link()` blob logic to non-`.md` targets, with a test asserting no relative code link survives into `build/wiki`. |
| Tier-2 coupling gate could become noise contributors learn to ignore | Kept advisory and scoped to files the docs actually link, and it names the cited symbols rather than saying "docs may be stale". If it proves noisy, the fix is to narrow the file set, not to escalate it to blocking. |
| `walkthroughs.md` is the page most likely to rot; the drift test catches moved files but not a changed *sequence* | Accepted. Each step cites the enforcing test, so a changed sequence surfaces as a failing gate rather than silently wrong prose. |
| Scope is large — 8 pages, 17 diagrams, a new test, and a fix phase | Sequenced so it lands incrementally: Phase 0 fixes, Phase 1 core four, Phase 2 the rest. Each phase is independently shippable. |
| Phase 0 touches version-marker-gated files | `README.md` and `ARCHITECTURE.md` carry no version markers; `docs/install.md` does. Its glibc edit must not disturb the four `docs_current_version_markers_match_cargo` patterns. |
