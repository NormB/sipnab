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

**The lesson for anyone applying this pattern further: read `docs/design/`
first.** A page that looks badly organised may be the deliberate outcome of a
decision that is still sound.

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

Four kinds of page, and a page is exactly one of them:

| Kind | Answers | Ends when |
|---|---|---|
| **Introduction** | "What is this and can I see it work?" | the reader has seen real output |
| **How-to** | "How do I do it *my* way?" | the reader's specific setup runs |
| **Reference** | "What does this return?" | looked up, not read |
| **Protocol / internals** | "How do I build against it, or audit it?" | the contract is fully stated |

An introduction that has not produced output has failed, however complete it
is. A reference that reads well top-to-bottom is probably an introduction
wearing the wrong hat.

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

### 4. Reference material is uniform before it is good

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
| `mcp-tools.md` | Reference | the ~2600-line tool section, templated |
| `mcp-protocol.md` | Protocol | security model, error model, response bounding, stdio invariant, untrusted text, raw JSON-RPC |

## Gates this interacts with

Moving pages is not a pure content change. Three gates must be updated in the
same commit or the split fails CI:

- `dev_docs_drift_test::every_site_operator_page_is_in_every_docs_nav` — a new
  page needs an entry in [`scripts/build-site-pages.py`](https://github.com/NormB/sipnab/blob/main/scripts/build-site-pages.py) PAGES *and* a place in
  every docs nav.
- `dev_docs_drift_test::docs_to_site_map_is_complete` — the source-to-site map
  must cover it.
- `doc_example_coverage_test::every_flag_has_at_least_two_examples` — flags keep
  their two worked examples wherever the examples end up, so moving examples
  between files can break a flag that was never touched.

[`scripts/build-site-pages.py`](https://github.com/NormB/sipnab/blob/main/scripts/build-site-pages.py) regenerates the website mirror; run it after any
move, and `scripts/check-line-drift.py --apply` if cited line numbers shifted.
