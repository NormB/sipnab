# Write-back MCP tools against the read-only invariant

**Status:** DECIDED — approved to move forward, 2026-08-02. Write-back tools are
accepted for managing the MCP server; section 7 records what has to be true.
**Verified against:** `63b771b`, working tree. Every file:line below was read at
that revision.
**Relationship to [`deferred-and-declined.md`](deferred-and-declined.md) §2.**
That page argued against write-back on one point: silent divergence between what
an agent did and what an operator sees. This page does not repeat it. It exists
because the request came back asking for the *pros and cons*, and a verdict with
only the cons written down is the kind of decision that gets re-litigated every
quarter. So section 2 argues the other side properly, section 6 costs the four
middle options nobody had priced, and section 5 supplies evidence that did not
exist when §2 was written — two shipped fixes for tools that did to a capture
exactly what a badly-scoped write tool would do. The conclusion is the same. The
reasoning is different, and one claim in §2 has since gone stale (section 8).

## 1. The invariant, quoted from all four places it lives

The rule is stated four times, in four registers. All four matter, because the
fourth is not documentation — it is a promise sipnab transmits to every client
at handshake.

**As an invariant.** [`docs/internals/invariants.md`](../internals/invariants.md)
§7, in full:

> ## 7. MCP tools never mutate, and every response has a ceiling
>
> **Rule.** No MCP tool mutates a store, and every response hits a size ceiling
> before serialization.
>
> **Why.** An LLM agent drives the MCP surface: it must not be able to
> change what an operator is looking at, and an unbounded response is a
> denial-of-service against the agent's context window as much as against
> sipnab.
>
> **Enforced by.** [`shape.rs`](../../src/mcp/shape.rs) — `DEFAULT_LIMIT` 50,
> `HARD_LIMIT` 1000, `MAX_BODY_BYTES` 4096, applied by
> [`resolve_limit()`](../../src/mcp/shape.rs) — with
> [`mcp_stdio_test`](../../tests/mcp_stdio_test.rs) and
> [`mcp_http_test`](../../tests/mcp_http_test.rs) end to end.
>
> **Fails as.** An agent that quietly truncates or floods, and an operator who
> cannot tell which.

**As a security-model bullet.** [`docs/mcp.md`](../mcp.md) line 1205:

> - **Read-only by design.** No tool mutates the dialog/stream/alert
>   stores or sends SIP. systemd owns the capture lifecycle, or the
>   CLI flags, not by the LLM.

**As a module contract.** [`src/mcp/mod.rs:5`](https://github.com/NormB/sipnab/blob/main/src/mcp/mod.rs#L5) and
[`src/mcp/server.rs:3-4`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L3-L4) respectively:

> //! This module exposes sipnab's read-only analysis surface (dialogs, streams,
> //! diagnostics, security findings, call reports) as MCP tools […]

> //! `SipnabMcp` server: the read-only MCP tools backed by the existing
> //! dialog/stream stores (plus the optional alert engine).

**As a runtime assertion to the client.** `get_info`
([`server.rs:2364-2368`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2364-L2368)) sets the handshake
`instructions` string every MCP client reads before it calls anything:

> "sipnab MCP server — read-only access to captured SIP dialogs, RTP streams,
> diagnostics, and security findings."

That last one changes the character of the question. The other three are claims
sipnab makes about itself in its own documentation. This one is a claim sipnab
makes to a caller, in-band, at connection time. Adding a write tool without
changing that string ships a lie on the wire. Changing it tells every existing
client that the surface it trusted is no longer the surface it connected to.
Neither is a documentation edit.

## 2. The case for write-back, taken seriously

The request is not frivolous, and three of its motivations survive scrutiny.

**An investigation produces findings that have nowhere to go.** An agent works
through a capture, concludes that four dialogs share a root cause and that a
fifth is a red herring, and then the session ends. The conclusion exists only in
the transcript. The next agent — or the same one after a context reset — starts
from zero against the same store. Every read tool it has will return the same
raw material and none of the interpretation. This is a real dead end, and it is
the strongest argument on this page.

**The read surface is rich enough that the asymmetry is conspicuous.** There are
36 tools ([`server.rs`](../../src/mcp/server.rs), `#[tool(` at `:938` through
`:2260`), and several of them do genuine analysis rather than projection:
`triage_call` (`:1927`), `check_codec_negotiation` (`:1999`),
`diagnose_registration` (`:2085`), `compare_dialogs` (`:1722`). An agent that
can run a differential diagnosis and cannot record its answer looks like a tool
with a missing half.

**Precedent exists for shipping an agent-callable destructive verb.**
`shutdown_server` (`:2261`) stops the process on an LLM's say-so. It shipped
because its failure mode was made structurally impossible rather than unlikely:
off unless `--mcp-allow-shutdown` is passed (`allow_shutdown` at `server.rs:70`,
`false` in `new()` at `:112`, set only by `with_shutdown()` at `:158`), dry run
by default, and a refusal to discard an unsaved live capture unless the caller
names the discard. "It writes" is therefore not, on its own, a reason to refuse.
Anyone arguing against write-back has to say what is different, not merely that
it mutates.

There is a fourth motivation that does *not* survive, and it should be named so
it stops being offered. "The agent could set a filter" — `set_filter`,
`apply_filter`, saved views — buys nothing. Filters are already arguments to the
query tools (`ListDialogsParams.filter`, `server.rs:226`), so the state is
reachable without mutating anything. [`mcp-tool-roadmap.md`](mcp-tool-roadmap.md)
reached the same conclusion independently.

## 3. What the invariant is actually protecting

Not "the store", and not "correctness" in the abstract. Three specific things,
and they are worth separating because the middle options in section 6 protect
different subsets of them.

**The capture is frequently the only copy.** The `-O` guard says this outright
in [`src/capture/output_guard.rs:5-14`](https://github.com/NormB/sipnab/blob/main/src/capture/output_guard.rs#L5-L14):

> `sipnab -I capture.pcap -O capture.pcap` opened the capture, truncated the
> same file as the output, wrote back whatever it had already read, and exited
> 0. The original is gone. One tab-completion reaches it, and an incident
> capture is very often the only copy that will ever exist.
>
> There is no correct interpretation of that command.

An incident capture is evidence. It gets read once, weeks later, by someone
reconstructing what happened, and there is no second collection run available
because the incident is over.

**The operator's screen is the tool's output.** sipnab has no other product. Every
mutating verb proposed so far — tag a dialog, acknowledge a finding, name a host
— edits the thing the operator is reading, and does so with no signal that it
happened. `DialogStore::generation` ([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573))
is bumped by every mutating method and exposed on no wire format: not in
`DialogSummary` ([`model.rs:54-56`](https://github.com/NormB/sipnab/blob/main/src/output/model.rs#L54-L56)), not in any REST
response (`build_router`, [`api.rs:204-213`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L204-L213) — eight
routes, all `get`), not in any MCP payload.

**The caller is a language model reading text a stranger wrote.** This is the
part that makes the MCP surface different from the REST surface, and it is
concrete rather than theoretical:

- `DialogSummary.from_user` / `to_user` ([`model.rs:54-56`](https://github.com/NormB/sipnab/blob/main/src/output/model.rs#L54-L56),
  populated at `:91-92`) are copied off the From/To URIs.
- `get_message` ([`server.rs:3563`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L3563)) returns headers and
  body.
- `search_messages` ([`server.rs:3855`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L3855)) returns a
  `snippet` built at [`:1391`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L1391) from
  `truncate_string(&String::from_utf8_lossy(&msg.raw), …)` — raw bytes off the
  wire, unmodified.

A `From:` display name is a string a stranger chose. sipnab returning it verbatim
is the tool working correctly; there is no version of a SIP analyzer that
withholds the From header. So the model driving the tools reads
attacker-authored text on every call, by design, and will continue to.

## 4. What breaks if the invariant goes

The chain has three links and none of them requires anything exotic.

1. An attacker places instruction-shaped text in a `From` display name, a
   `User-Agent`, or a reason phrase, on a network sipnab is watching. Cost to
   the attacker: one INVITE.
2. An agent reads it verbatim through `search_messages`, `get_message` or any
   list tool. This is not a bug to be fixed — it is the tool answering the
   question it was asked.
3. With a write verb present, that text can reach it.

Today link 3 terminates. The worst an injected instruction can reach is a read,
a file write confined to `--mcp-file-root` (section 5), or — only when armed,
only on a second call, only having named the discard — a process stop. Adding a
store-mutating verb turns a terminating chain into a completing one, and the
completion is silent: the process still runs, the counts still look plausible,
and a `/v1/dialogs` poller sees changed data with nothing in the payload
explaining it.

Note what this argument does not rest on. MCP does not run alongside the TUI —
[`tui_mode.rs`](../../src/app/tui_mode.rs) passes `Selection { api: true, mcp:
false }`. An agent cannot rewrite the store under a live TUI. The exposure is
the REST consumer and the next agent session, which is narrower than "the
operator's live screen" but not narrow enough to dismiss.

## 5. The two fixes this session shipped, and why they settle it

This is the evidence that did not exist when §2 of
[`deferred-and-declined.md`](deferred-and-declined.md) was written, and it is
decisive because in both cases the tool was doing something a reasonable person
had asked it to do.

**A tool destroyed its own input.** `-O` onto `-I`, above. The fix was not a
warning and not a confirmation prompt. It was a *precondition*, decided before
anything opens, on canonical paths so that `a.pcap`, `./a.pcap`, `dir/../a.pcap`
and a symlink to any of them are one file
([`output_guard.rs:16-24`](https://github.com/NormB/sipnab/blob/main/src/capture/output_guard.rs#L16-L24)), covering the
whole resolved `-I` set and every `--split` rotation name (`:26-39`).

**A tool transmitted while reading a file.** `--kill-scanner` on `-I
customer.pcap` sent SIP at addresses recorded in the capture.
[`src/security/transmit_guard.rs:11-19`](https://github.com/NormB/sipnab/blob/main/src/security/transmit_guard.rs#L11-L19)
states the reasoning, and `:21-29` states why the fix is a type:

> The failure is silent and irreversible, so it must not depend on anyone
> remembering.

Both fixes reached MCP, and how they reached it is the point. `resolve_in_root`
([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487)) accepts a bare filename and rejects
any separator, `..`, root prefix or drive letter *before* touching the
filesystem — its doc comment (`:163-173`) argues that requiring one component
has no middle ground, where "every clever normaliser eventually meets a symlink,
a unicode separator, or a `..%2f`". And it then runs the `-O` precondition:

```rust
// Refuse before the caller opens anything: every file tool writes with
// truncation, so a check made after the open has already destroyed the
// capture.
self.protected_inputs
    .check(&target, "the requested filename", false)
```

([`server.rs:206-211`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L206-L211); the field is declared at `:68`
with a comment noting that `--mcp-file-root` and `-I` routinely name the same
directory, so "an export named after an input is one autocompletion away".)

Read those two fixes together and they say one thing. **Both failures were
authorized.** Nobody bypassed a check. The operator typed the flag; the agent
called the tool with a plausible filename. What went wrong was that a write was
permitted to land somewhere the caller had no way to know was precious. The
defenses that worked were the ones that removed the possibility — a type with a
private constructor, a precondition evaluated before the open — and the ones
that would not have worked are exactly the ones proposed for write-back:
a flag, a confirmation, a documented convention.

An MCP write tool is that same shape with a worse caller. The `-O` case had a
human who typed the command. Write-back has a language model choosing arguments
from text an attacker supplied.

## 6. The middle options, priced

Four proposals soften write-back rather than accepting it whole. Each is
evaluated against the three protected things from section 3 and against one
further test: **can a reviewer decide, by reading the diff, whether a new call
site is safe?** That test matters more than it looks, because every guard in
this codebase that held up is one where the answer is yes.

| Option | Protects the capture | Protects the screen | Survives an injected instruction | Reviewable locally |
|---|---|---|---|---|
| A. Write to a copy | Yes | **No** | No | Yes |
| B. Require an explicit flag | Yes | No | **No** | Yes |
| C. Scope writes to a sandbox directory | Yes | **N/A — wrong target** | Yes, for files | Yes |
| D. Propose-and-confirm | Yes | Partly | **No** | **No** |

**A. Write to a copy.** Snapshot the store, apply the mutation to the copy, hand
the agent a handle to it. This genuinely protects the capture and the live
store, and it is the only option that changes the shape of the problem rather
than the odds. Its cost is that it is a different feature: the copy has no
readers. REST serves the live store (`api.rs:204-213`), the TUI is not running
(section 4), and the report generators read `DialogStore` directly. So an agent
writes to something nobody looks at, which answers the motivation in section 2
only if a later tool reads the copy back — at which point two stores can
disagree and every consumer needs to say which it meant. The complexity lands on
`output/model.rs`, whose whole job under
[invariant 9](../internals/invariants.md) is that there is *one* wire shape per
concept.

**B. Require an explicit flag.** `--mcp-allow-write`, following
`--mcp-allow-shutdown`. This is the weakest option and the most likely to be
proposed, because the precedent looks so clean. It fails on the asymmetry that
made `shutdown_server` safe: the flag governs whether the *operator* consented,
and the injected instruction arrives afterwards, inside the data, on a run where
the flag is already set. `shutdown_server` does not rely on its flag either —
the flag is guard 1 of four, and guards 2 and 4 (dry run by default; a blast
radius that either happened or did not) are the ones doing the work. Write-back
gets neither. There is no dry run for "the store now says something different",
because the second call is the one that matters and the first has already told
the agent what to send.

**C. Scope writes to a sandbox directory.** Already built, already shipped, and
mis-aimed at this problem. `resolve_in_root` plus `--mcp-file-root` plus
`ProtectedInputs` is a good answer to *file* writes and is why `export_capture`
(`:2177`) and `export_audio` (`:2219`) are defensible tools. It has nothing to
say about store mutation, which does not go through a path. Listing it here is
worth the space only to stop it being offered as though it did: the sandbox
bounds where bytes land, and the thing under discussion is what the analysis
says.

**D. Propose-and-confirm.** The tool returns a proposed change; a human approves
it. This is the option that sounds safest and is the worst, and the reason is
worth stating plainly. The approving human is reading a rendering of
attacker-supplied text, in a client whose confirmation UI sipnab does not
control and cannot inspect. Approving 200 tag-a-dialog proposals in a session
trains exactly the reflex the mechanism depends on not existing. And it is the
only option in the table that fails the reviewability test: whether a given
write is safe now depends on what a human did in another program, which no diff
shows and no test can pin. Every other guard in this tree —
`TransmitPermit::for_source`, `resolve_in_root`, `ProtectedInputs::check` — is
decidable from the code.

## 7. Decision

**Approved to move forward, 2026-08-02.** The argument that ran the other way is
kept below in full, because it names the failure the implementation has to design
against — not a reason to stop.

The reasoning as it stood, in one paragraph. Guards work here when they make
a failure impossible rather than unlikely, and the two failures fixed this
session were both *authorized* actions that landed somewhere precious — which is
why the fixes were a type with a private constructor and a precondition
evaluated before the open, not a flag and not a prompt. Write-back cannot be
given a guard of that kind, because the thing it must prevent is not a
destination or a capability but an *intent* the caller does not have: a language
model, reading a `From:` header a stranger wrote, deciding to write. Options A
and C protect something other than what is at risk; options B and D reduce the
odds and leave the failure reachable, and D moves the deciding step somewhere no
reviewer can see it. Against that, the benefit is one genuine dead end —
findings with nowhere to go — which section 7's narrower tool addresses without
touching the analysis at all.

**Build this instead: `save_findings`, a file-scoped, analysis-inert export.**

- One tool. Writes a JSON document of the agent's own conclusions —
  Call-IDs, a verdict per call, free text — to a bare filename under
  `--mcp-file-root`.
- It reaches the filesystem through `resolve_in_root`
  ([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487)) exactly as `export_capture` and
  `export_audio` do, and therefore inherits `ProtectedInputs::check` and cannot
  land on a capture.
- **Nothing reads it back.** No tool, no report, no REST route, no diagnosis.
  That is the property that makes it safe, and it must be stated in the tool's
  doc comment so a later change that adds a reader is visibly a different
  proposal.
- Invariant 7 is untouched: no store is mutated, and the response is a filename.
- The handshake `instructions` string (`server.rs:2364`) stays accurate, because
  read-only access to *dialogs, streams, diagnostics and findings* remains a
  true description of what the tools return.

This is the same conclusion [`deferred-and-declined.md`](deferred-and-declined.md)
§2 reached by a different route — its build requirement 2 asks for "an
annotation store that a tool may edit and that no analysis reads". A file that
nothing reads back is the cheapest possible instance of that, and it needs no
store, no schema migration and no wire-visible generation counter.

**What would change this.** Both of the following, not either:

1. A wire-visible store identity — `generation`
   ([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573)) surfaced on REST and
   MCP responses — so a consumer can detect that what it is reading changed
   underneath it.
2. A demonstrated need that `save_findings` does not meet, from someone who has
   used it. Not a hypothesis about one.

**Do not reopen** on the `shutdown_server` precedent. That argument is answered
in section 6B: the flag is not what makes that tool safe.

## 8. Two documentation defects found while verifying this

Neither is fixed here. Both are recorded so the next person does not re-derive
them. Neither is a behavior change.

**The read-only claim in [`docs/mcp.md:1205`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md#L1205) is now imprecise, and its second
sentence is ungrammatical and false.** "No tool mutates the dialog/stream/alert
stores" is exactly true. "systemd owns the capture lifecycle, or the CLI flags,
not by the LLM" contradicts `--mcp-allow-shutdown`, which hands the capture
lifecycle to precisely the LLM. `deferred-and-declined.md` §2 flagged this and
proposed the repair — that the guarantee is *no tool alters the analysis an
operator is reading while leaving them reading it*. The repair has still not
been made, and the same wording drift affects
[`src/mcp/mod.rs:5`](https://github.com/NormB/sipnab/blob/main/src/mcp/mod.rs#L5) and the handshake string at
[`server.rs:2365`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2365).

**`deferred-and-declined.md` §2 has itself gone stale on one claim.** It states
that the prompt-injection rule for tool descriptions "is convention, not
enforcement", because [`src/mcp/server.rs:10`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L10) cited
`scripts/check-tool-descriptions.sh` and no such file existed. That is no longer
true. [`tests/mcp_tool_descriptions_test.rs`](../../tests/mcp_tool_descriptions_test.rs)
exists and carries two tests —
`tool_descriptions_do_not_instruct_the_model_to_trust_content` (`:77`) and
`the_cited_description_gate_actually_exists` (`:127`), the second of which
asserts that any gate named in the module doc is real, closing the loop that
produced the phantom in the first place. The module doc
([`server.rs:6-13`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6-L13)) now names the test and records the
history. The rule is enforced. That page's §2 should be corrected by whoever
owns it; this page does not edit it.

Line numbers in §2 have also drifted with the tree — it cites `export_capture`
at `server.rs:2136` where `63b771b` has `:2177` — which is the ordinary cost of
citing lines and not a defect. The tool *names* it cites are all still correct.
