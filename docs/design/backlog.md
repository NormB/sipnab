# sipnab backlog

**The backlog is one local document, and it is not in this repository.**

Open work lives in `docs/design/backlog.local.md`, beside this file and ignored
by git. It is the single list: every item, in every state, in one place. This
page stays tracked so the links that point here keep resolving, and so the
convention below is written down somewhere the repository can show you — but it
carries no items, and none are pushed upstream.

## The four states

| Written as | Means |
|---|---|
| `- [ ] item` | open — nobody has started it |
| `- [ ] 🟡 I item` | in progress |
| `- [x] ✅ item` | complete |
| `- [x] ❌ REJECTED — reason` | rejected, with the reason it was turned down |

A rejected item keeps its box ticked so it leaves the open list, and carries the
red mark and the reason so the decision is not relitigated later. An item is
never deleted: the record of having considered it is the point.

## Why it is local

The list carries half-formed ideas, competitor readings, customer specifics and
judgements about what is not worth doing. That is working material, not a
published roadmap, and a public backlog invites being held to it.

## What the repository still enforces

`only_the_backlog_tracks_open_work` (in [`tests/docs_drift_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/docs_drift_test.rs)) fails when a
file in this tree starts carrying `- [ ]` items, so a second todo list cannot
quietly appear. The historical planning records under `docs/design/`,
`docs/research/` and `docs/superpowers/` are named there with the count each
held: they are acceptance criteria written before the work shipped and never
ticked afterwards, not lists of what is left, and they are left exactly as
written rather than retro-edited.

[`scripts/backlog-status.py`](https://github.com/NormB/sipnab/blob/main/scripts/backlog-status.py) regenerates the status summary inside the local
file, and the pre-commit hook runs it when the file is present. Neither does
anything in a clone that has no local backlog, which includes CI.
