# Task-first titling for walkthroughs and the cookbook

**Status:** analysis and spec, 2026-07-31. Nothing rewritten yet — this document
is the plan, and the rewrite is deliberately a separate piece of work.

**Trigger.** A user looking for "run sipnab on a remote server, drive it from
Claude Code on my laptop" could not find the instructions. They exist, in
`mcp-walkthrough.md`, under the heading:

> ### Scenario 2A — SSH-launched stdio: ad-hoc, zero server configuration

Every word of that is accurate. None of it is what the reader typed into their
head. They wanted *"connect Claude Code to a remote server"*; the heading offers
a transport name, a launch mechanism, and two adjectives about operational
character. The reader has to already know that "SSH-launched stdio" is the thing
they want before the heading can tell them it is the thing they want.

## The measurement

A heading is *task-first* when it begins with a verb the reader would use for
their own goal. Counting `##`/`###` headings, ignoring leading numbering:

| Page | Task-first | |
|---|---|---|
| `tui-walkthrough.md` | 9/10 | **90%** |
| `examples.md` (cookbook) | 27/43 | 62% |
| `mcp-walkthrough.md` | 2/24 | **8%** |

**The problem is not that sipnab does not know how to write headings.** The TUI
walkthrough is almost perfectly task-first — "Open a capture", "Measure the
delay between two messages", "Trace a call through proxies". It reads like
someone asked what a user wants and then wrote that down.

The MCP walkthrough is the same repo, the same author, a different instinct:
`Scenario 1`, `Scenario 2A`, `Scenario 2B`, `Scenario 2C`, `Scenario 3` … The
organising unit is a *deployment topology*, and topologies are how the
implementer sees it. The reader arrives with a goal, not a topology.

The cookbook sits between the two and shows the fault line inside one page:

- "Diagnose a one-way audio complaint" — a reader recognises their own problem.
- "8a. Stdio (local agent)" / "8b. HTTP (remote agent, single user)" — the same
  mechanism-first instinct, in the same section that failed this user.

Every place the naming breaks down is an MCP section. That is not coincidence:
MCP is the newest surface, and the docs were written from the implementation
outward while the TUI docs were written from the user inward.

## What the research says

**[Diátaxis](https://diataxis.fr/)** is the standard taxonomy here, and its
guidance on [how-to guides](https://diataxis.fr/how-to-guides/) is directly on
point:

> "Choose titles that say exactly what a how-to guide shows."

It also draws a line sipnab currently blurs. [Tutorials and how-to
guides](https://diataxis.fr/tutorials-how-to/) serve different readers: a
tutorial serves someone *studying*, a how-to serves someone *at work* who
already knows what they want. Conflating them is named as a common failure.

sipnab has both and does not distinguish them:

- `tui-walkthrough.md` is a **tutorial** — sequential, teaches the tool, read
  start to finish.
- `mcp-walkthrough.md` is a **collection of how-tos** wearing a tutorial's name.
  Nobody reads scenarios 1 through 6 in order. They want exactly one.

That mismatch explains the numbering. "Scenario 2A" implies a sequence that does
not exist, and gives the reader a label they cannot search for, because nobody
searches for "2A".

**The O'Reilly cookbook format** — Problem / Solution / Discussion — is worth
adapting for the same reason: it leads with the reader's *problem*, so scanning
the page means scanning problems rather than mechanisms.

**Kubernetes' Tasks section** organises by real-world use case rather than by
subsystem, and is searchable by what you are trying to do. The lesson sipnab
needs is narrower: an entry point that maps goals to pages.

## The rule

**A heading names the reader's goal in the reader's words. The mechanism may
follow, after a dash.**

```
### Connect Claude Code on your laptop to sipnab on a server
    — SSH-launched stdio, nothing listening on the server
```

The goal is searchable and scannable; the mechanism is still there for the
reader who knows what they want and is scanning for the transport. This keeps
what is genuinely useful about the current headings — they *are* precise —
while putting the precision second, where it costs nothing.

Three supporting rules:

1. **No bare ordinals as identifiers.** "Scenario 2A" is not a name. Numbering
   may stay for ordering where a sequence is real (the TUI walkthrough's steps),
   but it must never be the only handle on a section.
2. **Tutorials and how-tos get different pages, and say which they are.** A
   walkthrough is read once, in order. A cookbook entry is landed on from a
   search. `mcp-walkthrough.md` is currently the second wearing the name of the
   first.
3. **Every how-to page opens with a goal index** — a table mapping "I want to…"
   to the section, so the reader's first scan is over goals.

## The rewrite

Concrete renames for the worst offenders. The mechanism is preserved as a
subtitle in every case; nothing accurate is lost.

| Now | Proposed |
|---|---|
| Scenario 1 — agent and sipnab on the same machine (stdio) | Run sipnab and your agent on the same machine |
| 1A. Post-mortem on a capture file | Analyse a capture file you already have |
| 1B. Live capture on the same box | Watch live traffic on the machine you are sitting at |
| **Scenario 2A — SSH-launched stdio: ad-hoc, zero server configuration** | **Connect Claude Code on your laptop to sipnab on a server** — *ad-hoc, nothing listening on the server* |
| Scenario 2B — persistent HTTP service with a bearer token | Keep a capture running between agent sessions — *HTTP service with a token* |
| Scenario 2C — SSH tunnel + loopback HTTP: persistent, nothing exposed | Keep a capture running without exposing a port — *SSH tunnel to loopback HTTP* |
| Scenario 3 — central capture host fed by HEP | Collect captures from several SIP servers in one place — *HEP* |
| Scenario 4 — internet-exposed endpoint (nginx TLS in front) | Reach sipnab from outside your network — *nginx TLS in front* |
| Scenario 5 — a fleet of capture hosts | Query many capture hosts from one agent |
| Scenario 6 — headless / scheduled diagnostics | Run diagnostics on a schedule, with no agent attached |
| Which remote wiring? | Which remote setup should I use? |
| 8a. Stdio (local agent) | Drive sipnab from an agent on the same machine |
| 8b. HTTP (remote agent, single user) | Drive sipnab from an agent on another machine |
| 8c. Test the JSON-RPC handshake from a shell | Check the MCP server responds, without an agent |
| 9. Prometheus + Grafana end-to-end | Graph sipnab metrics in Grafana |
| 11. Per-call asymmetry diagnosis | Find calls where the two directions disagree |
| 14. Browser pcap analysis (no install) | Analyse a pcap in a browser, with nothing installed |

`mcp-walkthrough.md` also needs a goal index at the top — the "Choosing a
scenario" table already exists and is genuinely good, but it is keyed on
topology. Re-key it on "I want to…".

## Plan

Four steps, each independently shippable, in value order:

1. **`mcp-walkthrough.md`** — the page that failed the user, and the worst
   measured (8%). Renames, goal-keyed index, and an explicit note that it is a
   collection of how-tos rather than a sequence to read through.
2. **`docs/mcp.md`** — already partly fixed today (a transport-choice table and
   a step-by-step SSH quick start landed in 0.5.69), but its cross-links should
   point at the renamed anchors.
3. **`examples.md`** — the 16 non-task-first headings above, plus a goal index.
   Lower priority: at 62% it mostly works, and its failures cluster in the MCP
   section that step 1 fixes conceptually.
4. **A gate.** The repo's rule is that a documented convention without a gate
   rots. `docs_drift_test` should measure the task-first ratio per page and
   ratchet: the percentage may rise, never fall. A ratchet rather than a
   threshold, because the honest number today differs per page and the goal is
   direction, not a cliff.

### Anchor churn

Renaming headings changes anchors, and `link_integrity_test` walks both doc
trees plus the website — so every internal link and every `#anchor` must move
with them. That gate turns this from a risky rename into a mechanical one: it
fails on a stale link rather than shipping one. External links (blog posts,
issues) will break, which is the real cost and is worth paying once rather than
accruing.

## What this does not change

The *content* is good. The MCP walkthrough is thorough, correct and unusually
honest about trade-offs — the "Which remote wiring?" comparison is genuinely
useful, and the troubleshooting ladder is better than most projects ship. This
is a titling and navigation problem, not a rewrite. The fix is to make the
existing material findable by someone who does not already know its vocabulary.
