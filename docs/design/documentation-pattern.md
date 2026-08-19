# Documentation pattern

How sipnab's prose documentation is organised, and why. Written 2026-08-18
against [`docs/mcp.md`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md), which is the page that made the question unavoidable.

This is a decision record, not a style guide. It settles one question — *when a
document has to serve both a first-time reader and someone writing a client
against the protocol, what do you split, and where does the depth go?* — and
the answer is meant to be applied to every page, not only the MCP ones.

## What this repo had already decided

This question was not open when this record was written, and the first draft
was written as though it were. Two prior decisions bear on it, and both were
found only after the MCP split was already under way:

- **`task-first-docs.md`** (DONE, released in 0.5.70) settled that how-to
  headings name the reader's GOAL, not the mechanism, and left a per-page
  ratchet — `how_to_headings_stay_task_first` — enforcing it. The pattern below
  does not replace that; it assumes it.
- **#145 merged three MCP pages into one.** `mcp-overview.md`, `mcp-setup.md`
  and `mcp-tools.md` became [`docs/mcp.md`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md), and a gate was added to stop them
  coming back. The stated reason was narrow: each page restated the `--mcp`
  requires `-N` / stdout-is-the-wire boilerplate, and consolidating gave that
  invariant one owner.

That second decision is the one this record reverses in part, so it is worth
being exact about why. #145 removed a duplication problem. By 0.5.111 the
merged page had reached 3435 lines — 2639 of them tool reference — and the
duplication had already partly returned anyway: `mcp.md` stated the invariant
twice and `mcp-walkthrough.md` a third time. Splitting the reference back out
left the total unchanged at three mentions and reduced the introduction to one.
The problem #145 solved is not re-created by splitting; it is re-created by
splitting *without* giving one page ownership, which rule 3 below forbids.

**Amended 2026-08-19, after a corpus-wide audit.** The paragraph above says
"two prior decisions" and the lesson says to read `docs/design/` first. Both
were written without doing so completely, and the audit found three more:

- **`codebase-improvement-review-2026-08-16.md` DOC-01 through DOC-07**, all
  triaged `accepted` in `backlog.md` §CR (1945-1963) and none of them done.
  DOC-04, *"Split and refresh the MCP learning path"*, IS the work this record
  describes — with a numeric acceptance criterion (beginner path under ~200
  lines) that `mcp.md` at 111 happens to meet. This record was written two days
  after that review and does not cite it. Anyone extending this pattern should
  reconcile against §CR first, so the pattern and the accepted backlog are one
  plan and not two.
- **DOC-02** names the corpus's worst reader problem, and it is not structural:
  `tui-walkthrough.md` is the tutorial [`docs/README.md`](https://github.com/NormB/sipnab/blob/main/docs/README.md) sends new readers to,
  and it contains three fenced blocks, all commands, and no output anywhere. Of
  the five pages a reader can land on, exactly one shows real output.
- **[`docs/README.md`](https://github.com/NormB/sipnab/blob/main/docs/README.md) already publishes a taxonomy** — see the correction in
  "The pattern" below.

**The lesson stands, sharpened: read `docs/design/` first, and read
`backlog.md` §CR with it.** A page that looks badly organised may be the
deliberate outcome of a decision that is still sound, and the work you are
about to propose may already be accepted and waiting under a different name.

## The problem, in numbers

[`docs/mcp.md`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md) is 3435 lines. The tool reference is roughly 2600 of them: 75% of
the page is material nobody reads linearly. A reader arriving for the first
time meets "Choosing a transport" at line 64 and "Token bootstrap" at line 232
before they have seen a single tool return a single result. `mcp-deploy.md`
adds another 1878 lines and re-covers installation and quick-start, so the two
pages already disagree in the way duplicated content always eventually does.

Both failures are the same failure: one document is trying to be an
introduction, an operations manual, a reference and a specification at once, so
it is ordered for none of them.

## What was rejected: "novice" and "advanced" pages

The obvious split is by reader skill. It does not work, for three reasons, and
each has been observed rather than theorised:

- **Nobody self-identifies as a novice.** A reader who has used sipnab for a
  week takes the advanced page and bounces off it. The label sorts by ego, not
  by need.
- **It duplicates, and duplicates drift.** Both pages need install, both need a
  first example. `mcp.md` and `mcp-deploy.md` are already a live instance
  of this, split by no principle at all.
- **Experts need the simple page too.** Someone fluent in the tool but new to
  *this* task needs the five-minute version, and a page labelled for beginners
  discourages them from opening it.

Splitting by **task** produces the same depth gradient without any of that,
because depth correlates with task: "can I see it work" is shallow by nature and
"how do I write a client" is deep by nature. The gradient falls out of the
content instead of being asserted by a label.

## The pattern

### 1. A page answers one question for one task

**Corrected 2026-08-19.** The first draft invented four kinds — Introduction /
How-to / Reference / Protocol — without noticing that [`docs/README.md`](https://github.com/NormB/sipnab/blob/main/docs/README.md) already
organises this same corpus by **Diataxis**, and that `task-first-docs.md`
argues from Diataxis by name. Shipping a taxonomy that disagrees with the page
readers navigate from is worse than having none. The published one wins, plus
one addition this corpus genuinely needs:

| Kind | Answers | Ends when |
|---|---|---|
| **Tutorial** | "Can you walk me through it once?" | the reader has seen real output |
| **How-to** | "How do I do it *my* way?" | the reader's specific setup runs |
| **Reference** | "What does this return?" | looked up, not read |
| **Explanation** | "Why is it this way?" | the reasoning is stated |
| **Protocol** | "How do I build against it, or audit it?" | the contract is fully stated |

**Explanation is not optional and the first draft had no slot for it.** Nine
pages are pure explanation — `architecture.md`, `benchmarks.md`,
`fault-model.md`, and six under `internals/`. They answer "why is it this way",
they are read start to finish, and none is a protocol contract. Forcing
`benchmarks.md` ("how fast sipnab is, measured honestly, and what that speed is
for") into "how do I build against it or audit it" is a category error that
makes the page worse. Protocol stays as a fifth kind because
`mcp-protocol.md` and `internals/uprobe-capture.md` are genuinely contracts,
not explanations.

**Index is a ROLE, not a kind.** [`docs/README.md`](https://github.com/NormB/sipnab/blob/main/docs/README.md) and `internals/README.md`
route rather than teach, and `task-first-docs.md` rule 3 *mandates* an
"I want to..." table at the top of every how-to page. A page may carry an index
and still be one of the five kinds; a page may also be only an index. The first
draft named neither case, which left its own outcome page — `mcp.md`, whose
last section is a routing table — unclassifiable by its own rules.

A tutorial that has not produced output has failed, however complete it is. A
reference that reads well top-to-bottom is probably a tutorial wearing the
wrong hat.

### 2. Depth lives in `<details>`, on the same page

The rule that resolves the competing goals:

> Every section leads with the shortest thing that works. Every justification,
> edge case, tuning knob and failure mode goes in a `<details>` block whose
> summary names what is inside.

Collapsed depth beats a separate advanced page on two counts. The detail cannot
drift from the thing it explains, because it is in the same file. And the expert
finds it at the moment the question occurs, rather than having to know another
page exists. It degrades well everywhere sipnab's docs render — GitHub, the Zola
site, and plain text.

**Label summaries by content, never by difficulty.** "Why the port matters
here", "When this fails", "Tuning the retention cap" — never "Advanced", never
"More detail". The reader decides from the label whether the block is for them,
and "Advanced" gives them nothing to decide with.

### 3. Nothing is duplicated between pages, only linked

If two pages need the same install steps, one page owns them and the other
links. The duplication in `mcp.md` and `mcp-deploy.md` is what this rule
exists to prevent.

**Rule 3 beats rule 2 where they conflict, and they do conflict.** Rule 2's
justification is that depth cannot drift from what it explains because it is in
the same file — which is an argument for COPYING a fact to wherever the
question occurs. Rule 3 says a fact has one owner. On any fact two pages need,
following one rule breaks the other, and the first draft did not say which
wins.

The audit found the first draft violating rule 3 inside its own showcase of
rule 2: the "Building with MCP support" block in `mcp.md` carries a
`cargo build` line byte-identical to `install.md:456`, restated a third time in
`mcp-deploy.md`. So: **a `<details>` may hold elaboration, never a fact another
page owns.** Under that reading that block collapses to one sentence and a
link, which is tracked work, not a hypothetical.

### 4. Reference material is uniform before it is good

**Status: NOT applied.** The "Applying it" table below records `mcp-tools.md`
as "templated". It is not, and stating an intention as an outcome is the
failure this record was supposed to guard against. Measured 2026-08-19 across
its 35 tool sections: 4 carry `**Returns**`, 20 have an argument table, 0 have
a `<details>`. Rule 4's own justification — a reader jumping to their
fourteenth tool must not re-learn the layout — is unrealised in the only page
it was applied to.

Note also that nothing enforces this rule. `task-first-docs.md` shipped its
heading rule with a per-page ratchet, which is why that rule held. Rule 4 has
no gate, which is why it did not.

A fixed per-entry template, applied without variation:

```
### tool_name
One sentence: what question it answers.

**Arguments** — table
**Returns** — table
**Example** — one call, one abridged response

<details><summary>Field semantics and edge cases</summary> … </details>
```

Uniformity matters more than prose quality here. A reader jumping to their
fourteenth tool must not have to re-learn the layout, and a template makes a
missing section visible in review and in diff.

## Applying it

[`docs/troubleshooting.md`](https://github.com/NormB/sipnab/blob/main/docs/troubleshooting.md) already follows this instinctively — a symptom table
that routes to one section per symptom, each starting with the command to run —
and is the page worth copying.

The MCP set becomes four pages:

| Page | Kind | From |
|---|---|---|
| `mcp.md` | Introduction | first ~60 lines, one example, transport table |
| `mcp-deploy.md` | How-to | `mcp-deploy.md`, install de-duplicated |
| `mcp-tools.md` | Reference | the ~2600-line tool section — templating still PENDING, see rule 4 |
| `mcp-protocol.md` | Protocol | security model, error model, response bounding, stdio invariant, untrusted text, raw JSON-RPC |

## Gates this interacts with

Moving pages is not a pure content change. **Corrected 2026-08-19: the first
draft named three gates, described one of them wrongly, and omitted the two
that actually turned CI red on the MCP split.** That section was written after
being bitten and still got it wrong, which is the argument for checking rather
than recalling.

**The two that bite, and were missing:**

- **[`.vale.ini`](https://github.com/NormB/sipnab/blob/main/.vale.ini) carries per-file sections keyed on filename.**
  `[docs/keybindings.md]`, `[docs/theme-guide.md]`, `[docs/mcp-deploy.md]`,
  their site mirrors and `[website/content/cla.md]` each switch off a rule for
  content an inline comment cannot reach. Rename or split any of them and the
  suppression silently stops applying — that is exactly how the MCP rename
  un-suppressed twelve semicolons and turned CI red.
- **`how_to_headings_stay_task_first` carries PER-PAGE floors** and a fixed page
  list: `tui-walkthrough.md` 90, `examples.md` 93, `mcp-deploy.md` 64. Split a
  page and the ratio on what remains changes; a NEW page is not covered at all
  until it is added. This is `task-first-docs.md`'s own ratchet, which this
  record cites as binding and then failed to mention.

**And the site slug is not the source filename.** `cli-reference.md` publishes
as `cli.md`, `config-reference.md` as `config.md`, `examples.md` as
`cookbook.md`, `tui-walkthrough.md` as `tui.md`, `theme-guide.md` as
`theme.md`. Every rename is two renames, and [`.vale.ini`](https://github.com/NormB/sipnab/blob/main/.vale.ini) keys on both.

**The three originally named, one of them corrected:**

- `dev_docs_drift_test::every_site_operator_page_is_in_every_docs_nav` — a new
  page needs an entry in [`scripts/build-site-pages.py`](https://github.com/NormB/sipnab/blob/main/scripts/build-site-pages.py) PAGES *and* a place in
  every docs nav.
- `dev_docs_drift_test::docs_to_site_map_is_complete` — the source-to-site map
  must cover it.
- `doc_example_coverage_test::every_flag_has_at_least_two_examples` — **not
  what the first draft claimed.** Its `doc_corpus()` reads `docs/*.md` and
  `website/content/docs/*.md` NON-recursively, as a union, skipping generated
  mirrors — so moving examples between top-level `docs/` pages changes no count
  at all. It breaks on DELETION, and on any move into `docs/internals/`. As
  originally written the warning sent a reader looking for a problem that was
  not there and hid the one that was: 13 flags draw an example from
  `cli-reference.md:9-211` alone. Move those, never delete them.

[`scripts/build-site-pages.py`](https://github.com/NormB/sipnab/blob/main/scripts/build-site-pages.py) regenerates the website mirror; run it after any
move, and `scripts/check-line-drift.py --apply` if cited line numbers shifted.
