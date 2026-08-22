# Deferred and declined: four feature decisions, and five technologies

**Status:** §§1–4 decided 2026-08-01; §2 and §4 approved to move forward
2026-08-02. §1 and §3 remain unscheduled. Verified against `main` at 1998303.
**§5 (declined capture technologies) added 2026-08-03**, verified against the
tree at that date.
**Updated 2026-08-05: §2 and §4 have both shipped.** Each section keeps the
analysis that decided it, in the tense it was written in, and ends with a
"What shipped" table rather than being rewritten — the reasoning is the point of
this page, and a decision doc that silently back-edits itself teaches nothing.
Where a section's prose and the tree disagree, the correction notes say so in
place.

Four requests sat open a long time each, and they had one thing in common: the
honest answer turned out to be some version of *not as asked*. An undecided
feature comes back every quarter with the same arguments; one with a written
reason and a named trigger does not. So the deliverable here is the
writing-down, and each section ends with the specific fact that governs it.

A note on method, because it changed several of the answers below. Every claim
was re-checked against the current tree rather than carried over from the review
that raised it, and three inherited framings did not survive:

- that the recent `-I` multi-file work gives sipnab a cross-capture story §1
  could be built on — it is the opposite operation, and §1 measures the damage;
- that `shutdown_server` is an exception to the read-only invariant — it is not,
  and §2 shows what actually broke instead;
- the recorded rationale against `open_capture`, which §4 rebuilt from scratch
  rather than repairing — and which §4 has since withdrawn.

Where a conclusion still holds it holds on different evidence, and this page
shows the work rather than the verdict.

| # | Request | Decision |
|---|---|---|
| 1 | TUI multi-session / multi-capture comparison | **Re-scoped.** The want is real; the specification is not buildable and the `-I` set does not substitute for it |
| 2 | Write-back MCP tools | **Shipped.** Approved to move forward 2026-08-02; `save_findings` and `CaptureEtag` landed against the requirements §2 set, and Invariant 7 was amended in the same change |
| 3 | Automated threat-mitigation hooks | **Fixes extracted and shipped; the action ledger deferred** on a named prerequisite |
| 4 | `open_capture` MCP tool | **Approved to move forward** (2026-08-02). §4 records what has to change first |

**§5 is a different kind of entry, and it is why this page exists.** §§1–4 are
*feature* requests. §5 records *technologies* that were evaluated as ways to
make capture faster and rejected — process forking, PF_RING, DPDK, AF_XDP and
XDP-as-a-filter. Each had a real advocate and each has one decisive fact
against it. They were missing from this page entirely until 2026-08-03, which
is precisely the gap this page is supposed to close: an unrecorded rejection
comes back every quarter with the same arguments.

---

## 1. TUI multi-session / multi-capture comparison

**Decision: still wanted, and different. Do not build the side-by-side view.
Build capture provenance first, or build nothing.**

### The founding premise is false, and the tree already says so

The request was to open two captures at once and compare them side by side,
keyed on Call-ID. That works only if a Call-ID identifies at most one call in
the combined view. It does not.

The clearest statement of this is in the code that had to cope with it.
`DialogStore::merge` ([`dialog_store.rs:986`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L986))
carries a doc section headed *"Same-Call-ID collisions are the normal case, not
the rare one"* ([`:554`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L554)), and explains that a
call through a proxy or SBC reconstructs as two fragments keyed on the same
Call-ID — *"measured at 1173 of 2311 dialogs in one 100 MB file."*
That is within a single capture. Across two captures of
the same traffic the collision rate is 100% by construction: a proxy preserves
Call-ID end to end, so a call captured on the access side and on the trunk side
carries the identical value in both files.

`--dialog-track` exists because of the same problem seen from another angle.
[`dialog-tracking-modes.md`](dialog-tracking-modes.md) documents
[`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng) as *"8,989 packets in which one
Call-ID is reused across many transactions"*, and adds that under proxies and
B2BUAs *"the same Call-ID legitimately recurs"*. A comparison view keyed on
Call-ID would silently pair unrelated calls in exactly the populations —
generators and proxies — where operators most want to compare two captures.

### What the `-I` set actually gave us, and why it is not this

`-I` now accepts a file, a directory, a glob, or a repeated set
([`cli.rs:234-247`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L234-L247)), resolves it into one chronologically
ordered list (`input_set::resolve`,
[`input_set.rs:216`](https://github.com/NormB/sipnab/blob/main/src/capture/input_set.rs#L216)), and streams every file
into **one** `DialogStore` through one channel
(`capture_files`, [`file.rs:302`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L302)). It is tempting to
read that as "sipnab now has a cross-capture story, so the comparison request is
satisfied."

It is the opposite operation, and the module that implements it says so in as
many words. `warn_on_overlap`
([`input_set.rs:585`](https://github.com/NormB/sipnab/blob/main/src/capture/input_set.rs#L585)) exists precisely to warn
an operator away from the comparison use case:

```
'{}' and '{}' start at the same instant — if these are two captures of
the same traffic, packets present in both are counted twice
```

and its companion in the read path, `overlap_message`
([`file.rs:643`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L643)), repeats the consequence for the
end-against-start case: *"they overlap by {by} ms, so packets present in both
are counted twice."* The doc comment above `warn_on_overlap` is explicit that
*"Overlap means the set is not one sequence — most often two capture runs, or
the same traffic collected on two interfaces, mixed into one directory."*

Measured, not assumed. Two byte-identical copies of
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap) read as one `-I` set:

| | one file | the same file twice |
|---|---|---|
| dialogs | 2 | 2 |
| `1-1966@10.0.2.20` messages | 6 | **12** |
| `1-1968@10.0.2.20` messages | 4 | **8** |
| SSRC `0x343da99b` packets | 425 | **850** |
| SSRC `0x343da99b` duration | 8s | 8s |
| SSRC `0x343da99b` **kbps** | 64 | **128** |

The dialog count is unchanged because the Call-IDs collided and merged. Every
per-dialog and per-stream quantity doubled. A PCMU stream that ran at 64 kbps is
reported at 128 kbps over an unchanged 8-second span — a rate G.711 cannot
produce — silently, with `--problems` adding nothing.

The `same instant` warning did fire, which is the design working. But the
warning detects overlap in *time*, not overlap in *identity*: `same_instant_pairs`
compares consecutive files' first-packet timestamps against `SAME_INSTANT_SECS`
(1 ms, [`input_set.rs:610`](https://github.com/NormB/sipnab/blob/main/src/capture/input_set.rs#L610)) and
`overlap_message` compares the previous file's end against the next one's start.
Two captures that share Call-IDs without overlapping in time trip neither — and
that population is not exotic, since a load generator reuses Call-IDs across
runs, which is the same property `sipp-branch-scenario.pcapng` exhibits within a
single file. Those merge silently.

So: `-I` unions, comparison distinguishes. Feeding two captures to the merge and
calling it a comparison is not an approximation of the feature, it is the
failure mode the feature exists to prevent.

### What is actually missing is not a view — it is identity

The reason the comparison view cannot be built on today's data model is simpler
than the Call-ID problem, and it survives even if Call-IDs were unique: **sipnab
retains no record of which capture anything came from.**

- `Packet` carries `interface: Option<String>`
  ([`packet.rs:50`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L50)), and the file reader hard-codes
  it to `None` — [`file.rs:633`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L633):
  `None, // File captures have no interface name`, with the invariant asserted in
  the module's own tests at [`file.rs:1107`](https://github.com/NormB/sipnab/blob/main/src/capture/file.rs#L1107).
- `ParsedPacket` ([`parse.rs:49-84`](https://github.com/NormB/sipnab/blob/main/src/capture/parse.rs#L49-L84)) does not carry
  `interface` forward at all, so even the live-capture device name is dropped
  before SIP parsing.
- `SipMessage` ([`message.rs:34-70`](https://github.com/NormB/sipnab/blob/main/src/sip/message.rs#L34-L70)) and `SipDialog`
  ([`dialog.rs:87-140`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L87-L140)) have no source field. `tags` on
  `SipDialog` is the operator's `--tag` string, not provenance.
- The TUI's only notion of where its data came from is one display string,
  `capture_mode` ([`tui/mod.rs:145`](https://github.com/NormB/sipnab/blob/main/src/tui/mod.rs#L145)), overwritten wholesale
  on each in-TUI open ([`file_open.rs:520`](https://github.com/NormB/sipnab/blob/main/src/tui/controllers/file_open.rs#L520)).
  The `-I` set never reaches the TUI: `plan.source` is consumed by
  `bootstrap::launch` ([`main.rs:134`](https://github.com/NormB/sipnab/blob/main/src/main.rs#L134)) and `TuiOptions`
  ([`state.rs:218-229`](https://github.com/NormB/sipnab/blob/main/src/tui/state.rs#L218-L229)) carries no path.
- Opening a capture from inside the TUI **clears** both stores rather than
  merging — `reset_for_load`
  ([`file_open.rs:333`](https://github.com/NormB/sipnab/blob/main/src/tui/controllers/file_open.rs#L333)), whose caller
  `load_pcap_file` is documented as *"replacing all existing data."* There is no
  merge-on-open branch anywhere in that path.

The `View` enum ([`state.rs:1036-1084`](https://github.com/NormB/sipnab/blob/main/src/tui/state.rs#L1036-L1084)) reflects the
same absence: every data-bearing variant is keyed on a Call-ID or a `StreamKey`
and nothing else, so two dialogs from two captures would be
indistinguishable at the routing layer even before they reached a renderer.

The one comparison the TUI does have is `View::MessageDiff`, and its controller
refuses to cross even a dialog boundary —
[`call_flow.rs:634-641`](https://github.com/NormB/sipnab/blob/main/src/tui/controllers/call_flow.rs#L634-L641):

```rust
if first_cid != cur_cid {
    app.flow.diff_selected = None;
    app.status_error = Some("Diff across dialogs is not supported".to_string());
    return;
}
```

### What goes wrong if someone builds multi-session comparison anyway

Two failure modes, in order of how quickly they bite.

The cheap version — load both captures into one store and add a "capture A / B"
column — cannot work, because the column has nothing to read. There is no field
to populate. Adding one means touching `Packet`, `ParsedPacket`, `SipMessage`
and `SipDialog`, which is the zero-copy payload spine (D3) and the hot path;
`process_message` ([`dialog_store.rs:734`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L734)) is
written to avoid even a single owned-key allocation per message. A per-message
`String` source label is a straightforward regression of that work.

The version that looks like it works is worse. Because the merge is Call-ID
keyed, two observations of one call fold into a single dialog whose message list
is the concatenation and whose state machine has been re-run over the union
(`absorb_messages` then `replay_message_derived_state`,
[`dialog_store.rs:612-613`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L612-L613)). A comparison view
sitting on top of that would render one row and report the *merged* verdict as
if it were both captures agreeing. The disagreement it was built to find is the
thing the store destroyed before the view ran.

### Decision on multi-session comparison, and what would change it

**Re-scoped, not built as specified. The underlying want — "these two captures should be
telling the same story and they are not" — is real and is not addressed by
anything shipped.** It is blocked on a prerequisite that is larger than the
feature:

1. **Per-dialog capture provenance**, propagated from the reader through
   `ParsedPacket` to `SipDialog`, cheap enough not to regress D3. An interned
   `u16` capture index rather than a `String` is the shape that could plausibly
   pay for itself.
2. **A dialog identity that is not the Call-ID**, or an explicit decision that
   the comparison is keyed on `(capture_index, call_id)` and that cross-capture
   correlation is a separate, fallible step the operator confirms. The
   `tracking_key` design in [`dialog-tracking-modes.md`](dialog-tracking-modes.md)
   is the nearest existing precedent, and its own "blast radius" section is the
   honest estimate of what re-keying costs.

**Reopen when** provenance exists for another reason — the most likely one being
multi-device live capture, where per-interface attribution is already a live
concern (the pcapng writer now keeps an interface table and maps
`Packet.interface` to a pcapng `interface_id`). If that plumbing ever reaches
`SipDialog`, this feature becomes a view over data that already exists, and the
calculation changes completely. Until then it is a view over a field that does
not exist.

**Do not reopen** on the argument that `-I` already reads several captures. It
does, and it unions them, and the union is a measured 2× on every count.

---

## 2. Write-back MCP tools

**Decision: approved to move forward, 2026-08-02. Shipped since.** Write-back
tools are accepted for managing the MCP server. The analysis below is unchanged
and still load-bearing — including its finding that the reconciliation once
offered for this, "`shutdown_server` is a documented exception to the read-only
invariant", is wrong on the facts. What moved is the verdict, not the evidence.

**What the tree looks like now**, because the analysis below is written in the
present tense of 2026-08-02 and no longer describes it: `save_findings` exists
([`src/mcp/findings.rs`](../../src/mcp/findings.rs)), gated by
`--mcp-allow-save-findings`, and `CaptureEtag`
([`src/provenance.rs`](../../src/provenance.rs)) puts capture identity on the
wire. The "What shipped" table at the end of this section records what was built
against which requirement. Read the sections between here and there as the
argument that produced those two things, not as a description of the surface.

### Invariant 7, read literally, is not violated by anything in the tree

[Invariant 7](../internals/invariants.md) stated, when this analysis was
written:

> **Rule.** No MCP tool mutates a store, and every response hits a size ceiling
> before serialization.

**Updated 2026-08-05.** That is no longer the wording. The invariant is now
headed *"MCP tools never edit the analysis, and every response has a ceiling"*,
and its rule reads: *"No MCP tool edits a store in place, and every response
hits a size ceiling before serialization. One tool replaces a store wholesale —
`open_capture`, behind `--mcp-allow-open-capture` — and it rotates the capture
identity in the same critical section that clears the stores, so no answer can
change meaning without saying so."* It goes on to name the one write:
*"One tool accepts a WRITE: `save_findings`, behind
`--mcp-allow-save-findings`."* The old quotation is kept above because the
analysis that follows was reasoned against it and reads wrong without it. Where
the two differ, [`invariants.md`](../internals/invariants.md) §7 governs.

There were 24 MCP tools when this analysis was written
([`server.rs`](../../src/mcp/server.rs), `#[tool(name = …)]` attributes); the
registry has grown since, and the count is pinned by
`mcp_tool_table_lists_every_registered_tool` rather than by this sentence.
The argument below does not depend on the number. Four
of them touch something other than the stores: `export_capture`
([`server.rs:6057`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6057)) writes a pcap, `export_audio`
([`server.rs:6132`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6132)) writes a WAV, `list_captures`
([`server.rs:6005`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6005)) reads a directory, and
`shutdown_server` ([`server.rs:6570`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6570)) ends the process.

**None of them mutates a store.** `shutdown_server` reads `dialog_store` and
`stream_store` for its report, optionally writes a file, and then calls
`crate::signals::request_shutdown()`
([`server.rs:2288`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2288)) — the same flag SIGTERM sets. The
rule as written is intact, unqualified, across every tool. It does not need an
exception because nothing has taken one.

What *is* now false is the invariant's stated **Why**:

> **Why.** An LLM agent drives the MCP surface: it must not be able to
> change what an operator is looking at […]

A tool that stops the process changes what an operator is looking at more
completely than any mutation could. So the rule survived and its rationale did
not, and pretending otherwise by declaring an exception would leave the page
saying something untrue about a rule that is actually fine. The correct repair
is to the *Why*, not to the rule: what the surface guarantees is that **no tool
alters the analysis an operator is reading while leaving them reading it**.
Ending the process is loud, terminal, and visible from outside. Editing the
store underneath a live reader is none of those things. That distinction is the
real line, and it is the line write-back crosses.

**Corrected 2026-08-05: all three repairs have been made.** This paragraph used
to read *"That repair has not been made yet"* and named two other places that
had drifted the same way. Every one of them is now fixed.
[`invariants.md:324-330`](https://github.com/NormB/sipnab/blob/main/docs/internals/invariants.md#L324-L330) states the *Why* as the
distinction this section argued for — an agent must not be able to change what
an operator is looking at *and leave it looking like what they were looking at*
— and adds that the old wording *"was true until a capture swap existed and is
the wrong test anyway: what protects the operator is the identity on the wire,
not the absence of the verb."* [`mcp/mod.rs:10-12`](https://github.com/NormB/sipnab/blob/main/src/mcp/mod.rs#L10-L12) no
longer says "read-only"; it says *"No tool changes the analysis without changing
its identity"*, and names that as *"narrower than 'read-only', which this doc
used to claim"*. And the *"systemd owns the capture lifecycle"* sentence is gone
from [`docs/mcp.md`](../mcp.md). All three were wording, not behavior — the
code was doing the right thing and the prose had fallen behind it; it has since
caught up.

### What actually carries the safety, and why write-back cannot borrow it

`shutdown_server` is safe not because of the invariant but because of four
guards, each visible in the code:

1. **Off unless armed.** `allow_shutdown: bool`
   ([`server.rs:57`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L57)) is `false` in `new()`
   ([`server.rs:426`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L426)) and only set by `with_shutdown()`
   ([`server.rs:426`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L426)), which `servers.rs` calls only
   when `cli.mcp_allow_shutdown` is set
   ([`servers.rs:258-262`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L258-L262)). Refusal is the first
   statement of the handler ([`server.rs:2226`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2226)).
2. **Dry run by default.** `params.dry_run.unwrap_or(true)`
   ([`server.rs:2237`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2237)) — an agent that omits the
   argument gets a report.
3. **The destructive path must be named.** An unsaved live capture is refused
   unless `save_to` or `discard_unsaved=true`
   ([`server.rs:2268-2277`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2268-L2277)).
4. **The blast radius is bounded and legible.** The process either exists or it
   does not; there is no partially-shut-down state to misread. And a live
   capture is the only thing that can be lost, which is exactly what guard 3
   checks.

Write-back gets none of guards 2 or 4 for free. There is no dry run for "the
store now says something different" — the second call is the one that matters
and the first has already told the agent what to send. And there is no
observable "it happened" from outside: the process is still running, the counts
still look plausible, and the operator reading `/v1/dialogs` has no way to tell
a mutated store from a merely-changed one, because `DialogStore::generation`
([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573)) is internal to
cache invalidation and appears on no wire format.

### The prompt-injection chain, grounded

Every MCP response contains attacker-controlled text. This is not hypothetical
and it is not incidental — it is the tool working:

- `DialogSummary.from_user` / `to_user`
  ([`model.rs:53-57`](https://github.com/NormB/sipnab/blob/main/src/output/model.rs#L53-L57)) are copied straight off the
  From/To URIs.
- `get_message` ([`server.rs:3885`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L3885)) returns the parsed
  message through `message_to_json_value`, headers and body included.
- `search_messages` ([`server.rs:4177`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4177)) returns
  `snippet`, built as
  `truncate_string(&String::from_utf8_lossy(&msg.raw), MAX_BODY_BYTES)` — the
  raw bytes off the wire.

D22's prompt-injection rule already governs the *descriptions* (never instruct
the model to "trust", "verify" or "act on" content), and
[`walkthroughs.md`](../internals/walkthroughs.md) restates it as step 2 of
adding a tool.

**Corrected 2026-08-02.** This section used to say the rule was convention
rather than enforcement, because `mcp/server.rs` cited
`scripts/check-tool-descriptions.sh` and no such file existed. A cited gate that
is absent reads as enforced while nothing checks it, which is worse than an
admitted convention — the rule survived only as long as everyone adding a tool
happened to follow it. [`tests/mcp_tool_descriptions_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/mcp_tool_descriptions_test.rs) now implements it
as a Rust test, and its second test asserts that any gate named in the module
doc actually exists, so the citation cannot go stale again. The rule is
enforced. That removes one argument against write-back and leaves the rest of
this section standing.

The chain is then short. An attacker places a `From` display name, `User-Agent`
or reason phrase containing instructions on a network sipnab is watching; an
agent reads it verbatim through any of the three tools above; and with a
write-back tool present, the text it reads can reach a verb that changes what
the operator sees. Today the worst that text can reach is a read, a file write
confined to `--mcp-file-root` by `resolve_in_root`
([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487)), or — only if armed, only on a
second call, only having named the discard — a process stop. That is a
qualitative gap, not a matter of degree.

### What goes wrong if someone builds write-back anyway

The plausible requests here are the mild-sounding ones: tag a dialog,
acknowledge a finding, name a host, set a filter. Each is individually harmless
and collectively they are the whole problem, because the operator's screen is
the tool's output and every one of them edits it.

Concretely: `--api` and `--mcp` share the same `Arc<RwLock<DialogStore>>`, on
the same server thread — [`batch.rs:924-932`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L924-L932) starts both
with `Selection { api: true, mcp: true }`, and the comment above it states *"They
read the SAME stores the packet loop writes to."* Every REST route is a `GET`
([`api.rs:204-211`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L204-L211)); there is no mutating verb anywhere
on sipnab's network surface today. A write-back MCP tool would be the first, and
it would be reachable from the one surface whose caller is a language model
reading attacker-supplied text. A monitoring system polling `/v1/dialogs` would
observe the change with nothing in the payload explaining it.

Note what this argument does *not* rest on: MCP does **not** run alongside the
TUI. [`tui_mode.rs:366-374`](https://github.com/NormB/sipnab/blob/main/src/app/tui_mode.rs#L366-L374) passes
`Selection { api: true, mcp: false }`, commented *"The TUI owns stdio, so MCP
stdio is never selected here."* An earlier version of this argument claimed an
agent could rewrite the store under a live TUI. It cannot, and that claim is
retired here rather than repeated.

The roadmap's own "not proposed" list already reaches the same place for
`set_filter` / `apply_filter` — *"mutates what the operator is looking at, which
is exactly the invariant's target, and buys nothing: filters are already
arguments to the query tools"*
([`mcp-tool-roadmap.md`](mcp-tool-roadmap.md)). Generalise that: for every
write-back verb proposed so far, the same state is reachable as an argument to a
read tool, or as a CLI flag at startup. The mutation buys convenience and
spends the one property that makes an agent-driven surface safe to point at
production.

### Decision on write-back, and what would change it

**Approved to move forward, 2026-08-02.** Write-back tools are accepted for
managing the MCP server. The concern is not withdrawn — the failure to design
against is *silent divergence between what the agent did and what the operator
sees*, and sipnab has no mechanism to surface that today. It is now a
requirement to satisfy rather than a reason to stop.

**Both of these are build requirements**, not conditions on reconsidering:

1. **A wire-visible store identity** — a generation or etag on REST and MCP
   responses — so a consumer can detect that the thing it is reading changed
   underneath it. `DialogStore::generation` already exists internally
   ([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573)) and is bumped by every
   mutating method; exposing it is small. Without it, "who changed this" has no
   answer at any layer. §4 needs the same primitive, so it is built once.
2. **The write-back state is separate from the analysis** — an annotation store
   that a tool may edit and that no analysis reads. A note attached to a Call-ID
   in a side-car map changes no derived verdict, so nothing an operator is
   reading becomes wrong; the argument above simply does not apply to it. A
   field on `SipDialog` is a different proposal, because every diagnosis reads
   that struct, and should be judged on its own.

**Invariant 7 moves with the first tool that ships.**
[Invariant 7](../internals/invariants.md) says no MCP tool mutates a store, and
the analysis above establishes that this is still true of the tree. The first
write-back tool makes it false. Amend it in the same change, rather than leaving
a stated invariant the code has quietly stopped honoring.

**What shipped**, against those two requirements and that instruction:

| Requirement | Built as |
|---|---|
| 1. Wire-visible store identity | [`src/provenance.rs`](../../src/provenance.rs): a `CaptureEtag` carrying a capture-instance id plus both store generations, stamped on `capture_status` and every paged whole-store response. §4 consumes the same primitive, as planned — it was built once |
| 2. Write-back state separate from the analysis | [`src/mcp/findings.rs`](../../src/mcp/findings.rs), reached by `save_findings` behind `--mcp-allow-save-findings` (off by default: `allow_save_findings` at [`server.rs:74`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L74), `false` in `new()` at `:161`, set only by `with_save_findings()` at `:233`) |
| Invariant 7 amended in the same change | [`invariants.md`](../internals/invariants.md) §7 is retitled and now names `save_findings` explicitly, so nobody has to discover the write by reading the tool list |

The annotation store went further than requirement 2 asked, and the reason is
worth recording because it is not the obvious build. There **is** no annotation
store: a retained log of findings was written first and then deleted, because
every field of it was dead — nothing could read the text, the Call-ID or the
timestamp back, by construction. So an annotation goes to `tracing` and is gone
from the process. There is no `list_findings`, and that omission is the feature:
an agent cannot launder a conclusion into evidence and then cite it. The dead
end is enforced by the compiler rather than by prose — the annotation types are
`pub(in crate::mcp)`, so no analysis path can name them, and widening that
visibility is the change a reviewer should treat as breaking the invariant.

The REST half of requirement 1 is still open, the same gap §4 records: `/v1/dialogs`
carries no etag.

---

## 3. Automated threat-mitigation hooks

**Decision: the concrete fixes were extracted and have shipped. The "action
ledger" is deferred on a stated prerequisite, not on scheduling.**

### What was worth extracting, and it is done

The original request bundled two things: specific defects in the existing active-
response paths, and a general design for recording what those paths did. The
defects were the part with a bounded scope, and every one of them is now in the
tree.

**Kill-target source spoofing.**
[`kill-target-spoofing-spec.md`](kill-target-spoofing-spec.md) §10 records the
decisions as *"Fully implemented (P1–P5)"*, and the code matches claim for
claim: the pure builders `build_ipv4_udp` / `build_ipv6_udp`
([`kill_packet.rs:34`, `:98`](../../src/security/kill_packet.rs)), the raw
socket opened in the privileged window and handed to the worker
(`RawKillSocket::open`, [`process_isolation.rs:111`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L111)),
`--kill-spoof {auto|raw|ephemeral}` with a loud failure for `raw`
([`bootstrap.rs:554-562`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L554-L562)), and the property that
matters most — the forged source is never a parameter. It is always the sniffed
packet's own destination ([`batch.rs:1775-1776`, `:1816-1817`](../../src/app/batch.rs)),
so `-K` is a targeted transaction reply and not a general spoofer.

**HEP-origin packets cannot drive an active response.** The whole policy is
three lines ([`scanner_kill.rs:141-143`](https://github.com/NormB/sipnab/blob/main/src/security/scanner_kill.rs#L141-L143)):

```rust
pub fn kill_response_eligible(from_hep: bool, hep_allow_kill: bool) -> bool {
    !from_hep || hep_allow_kill
}
```

with the reason stated above it: *"a HEP sender asserts the inner src/dst
addresses, so absent receiver-side authentication an attacker could steer the
kill response at a chosen victim (SSRF-style)."* `--hep-allow-kill` is off by
default and a test pins that it stays off
([`cli.rs:1830-1835`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L1830-L1835), asserting *"HEP-origin scanner-kill must
be opt-in (SN-01)"*).

**Field injection into the input of a ban decision.** `fail2ban.rs`'s
`render_absent` ([`fail2ban.rs:51`](https://github.com/NormB/sipnab/blob/main/src/output/fail2ban.rs#L51)) quotes and
escapes every attacker-controlled field, and its doc comment records the exact
attack it closes: a `User-Agent` of `evil method=REGISTER src=1.2.3.4` produced a
line with *"two `src=` values, one of them attacker-chosen, in the output that
feeds a ban decision."* It also unified five spellings of "absent", which is
what made the hole invisible to the filters that were supposed to catch it.

**Rate limiting on both the receive and the transmit side.** The HEP receiver
has a per-peer cap checked ahead of the global one
([`hep.rs:1206-1208`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1206-L1208)) that fails closed when its
tracking table fills; the kill worker has a global limiter (10/s,
[`process_isolation.rs:650`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L650)) and a
per-destination one (3/min, [`process_isolation.rs:411`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L411))
both applied *before* any send ([`:559`, `:565`](../../src/process_isolation.rs)).

Every arming flag is off by default — `--kill-scanner`, `-K`, `--hep-allow-kill`,
`--fail2ban`, `--alert-exec`, `--on-dialog-exec`, `--on-quality-exec`. That is
the standing rule for anything that transmits, restated in
[`walkthroughs.md`](../internals/walkthroughs.md).

### What the ledger would be, and the three gaps it would close

The deferred half is a durable, queryable record of *what sipnab did and why* —
one entry per automated action, linking the detection that triggered it to the
packet that went out or the command that ran. Three specific gaps make the case
that this is a real absence rather than a nice-to-have, and all three are
verified:

**Outcomes are computed and thrown away.** The kill worker produces a
`KillResponse` for every request — `Sent`, `RateLimited`, `Rejected { reason }`,
`Error { message }` ([`process_isolation.rs:256-271`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L256-L271))
— and sends it on `resp_tx` ([`:529`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L529)). Nothing
in production reads it. `try_recv_response`
([`:331`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L331)) has exactly three call sites: two in
`process_isolation.rs` itself, both below the `#[cfg(test)] mod tests` boundary
at [`:712`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L712), and one in
[`tests/security_test.rs:1392`](https://github.com/NormB/sipnab/blob/main/tests/security_test.rs#L1392). Both dispatch
sites discard the send result too — [`batch.rs:1772`, `:1813`](../../src/app/batch.rs)
are `let _ = handle.send_kill(...)`.

**Suppressed actions are invisible.** A kill dropped by either rate limiter logs
at `tracing::debug!` ([`process_isolation.rs:560`, `:566`](../../src/process_isolation.rs)),
below the default level. An event-exec dropped by *its* rate limiter logs
nothing at all: `check_rate_limit`
([`event_exec.rs:222-241`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L222-L241)) returns `false` and
the caller simply returns. Only the queue-depth drop warns
([`:288-295`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L288-L295)).

**Hooks that ran are never checked.** `reap_action`
([`event_exec.rs:68-74`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L68-L74)) is
`Ok(Some(_)) => ReapAction::Remove` — the child's exit status is matched with a
wildcard and discarded. sipnab fires `sh -c <operator command>` and never learns
whether the ban it asked for happened.

Nothing persists. `fail2ban.rs`'s own doc says *"the caller is responsible for
emitting it — nothing is written here"*
([`fail2ban.rs:99-100`](https://github.com/NormB/sipnab/blob/main/src/output/fail2ban.rs#L99-L100)); the alert engine's
findings ring buffer is annotated *"In-memory only"*
([`alerting.rs:387`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs#L387)) and holds the *alert*, not
the *action* — a `Finding` has no field saying whether a kill went out. The only
durable-ish signal is two success counters,
`sipnab_kill_responses_sent_total{mode}`
([`process_isolation.rs:208-230`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L208-L230),
[`prometheus.rs:172-187`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L172-L187)), which count sends
and nothing else. `sipnab_security_alerts_total` is declared
([`prometheus.rs:40`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L40)) and formatted
([`:161-165`](https://github.com/NormB/sipnab/blob/main/src/output/prometheus.rs#L161-L165)) but written only in that file's
own tests, so it renders empty in a live process.

### Why the ledger is deferred, which is not the same as "not now"

The reason is the same one that stopped
[`ml-anomaly-detection.md`](ml-anomaly-detection.md): **sipnab has no persistence
across runs, and a ledger that dies with the process is not a ledger.** A record
of what was blocked is consulted after the incident, by someone who was not
watching — which is precisely when the process that held it is gone. Adding
durable state is a larger architectural decision than the feature that wants it,
and it is the same decision in both cases, so it should be made once and on its
own merits rather than smuggled in behind an audit trail.

There is a second reason, and it is the one that makes a half-measure actively
harmful. A ledger's value is that its absence of an entry means the action did
not happen. Given the three gaps above, a ledger built today would faithfully
record sends and silently omit rate-limited drops, rejections, and failed hooks
— and an operator who reads "no entries" as "nothing was suppressed" would be
wrong in exactly the case they are investigating. A ledger with known blind
spots is worse than no ledger, because it converts an obvious absence of
information into a confident false statement.

### Decision on the mitigation ledger, and what would change it

**The concrete fixes are shipped and this half is closed. The ledger is deferred
behind two prerequisites, in this order:**

1. **Close the three blind spots first, independently of any ledger.** Drain
   `try_recv_response` and log the outcome; promote suppressed-kill logging above
   `debug`; record the event-exec rate-limit drop and check the child's exit
   status. These are small, they improve today's `tracing` output on their own,
   and they are what makes a later ledger honest. They are not part of the
   deferral — they should be filed as ordinary defects.
2. **A decision about durable state.** Until sipnab has one, there is nothing for
   a ledger to be written to.

**Reopen when** persistence lands for any reason — population baselining
(`ml-anomaly-detection.md` §1 names the same prerequisite), historical trending,
or an operator requirement for retention. At that point the ledger is a schema
and a writer over data that already exists in memory, and the estimate changes
by an order of magnitude.

**One finding from this review that is not part of the deferral and should not
wait for it.** Because nothing drains `resp_rx`, and both the request and
response channels are `crossbeam_channel::bounded(256)`
([`process_isolation.rs:674-675`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L674-L675)), and
`crossbeam_channel::Sender::send` on a bounded channel is documented to *"block
until the send operation can proceed"* when full, the worker's
`let _ = self.resp_tx.send(response)` at
[`:529`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L529) appears able to block once 256
responses accumulate. The request channel would then fill, and `send_kill`'s
`self.tx.send(request)` ([`:302`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L302)) would block
the caller — which is the capture path. That is a code reading, not an observed
failure; it was not run. It wants a test before it wants a fix, and it wants both
before anything is built on top of this worker.

---

## 4. The `open_capture` MCP tool

**Decision: approved to move forward, 2026-08-02.** The analysis below was built
from the current tree rather than inherited — the previously recorded rationale
did not survive re-checking and is not reused here, in whole or in part. It
argued against building this; that argument is set out in full, and then
withdrawn at the end of the section, so the reasoning is auditable rather than
merely reversed.

### Taking the case *for* building it seriously first

Three things changed since [`mcp-tool-roadmap.md`](mcp-tool-roadmap.md) filed
`open_capture` under *"Tier 3 — plausible, lower value"* with the note *"Mutates
state — needs the same opt-in treatment as shutdown."*

**The opt-in treatment now exists and is proven.** `shutdown_server` shipped with
a flag ([`cli.rs:1019-1032`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L1019-L1032)), an off-by-default field
([`server.rs:70`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L70)), a builder
([`server.rs:207`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L207)) and a first-statement refusal
([`server.rs:2734`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L2734)). Copying that shape costs almost
nothing.

**The path-confinement problem is solved.** The roadmap's other Tier 3 entry,
`list_captures`, was filed with *"needs a path allowlist or it is an
arbitrary-file-read"*. It shipped ([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487))
with `--mcp-file-root` and `resolve_in_root`
([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487)), which accepts a bare filename and
rejects anything with a separator, a `..`, a root prefix or a drive letter before
touching the filesystem. So an agent can already *see* the corpus, safely, and
`open_capture` would need no new security machinery.

**The precedent argument is real.** `shutdown_server` demonstrates that this
project will ship a destructive agent-callable verb when the failure mode is
made impossible rather than unlikely. "It mutates state" is therefore not, by
itself, a reason.

The residual want is also real and should not be waved away: an agent that has
searched the loaded capture and found nothing cannot look at the next one. That
is a genuine dead end in the middle of an investigation.

### The costs, each verified

**It would be a second writer against the live stores.** Invariant 1 is *"Exactly
one thread writes `DialogStore` and `StreamStore` in a given run"*, and the page
names its single exception: opening a pcap from inside the TUI, whose *"whole
design — progress via `async_messages`, never a blocking read on the render side
— exists to make that safe."* An MCP handler filling the stores would be a second
such writer, and would need its own equivalent of that design. Note that this is
survivable in the file case — `source_exhausted`
([`server.rs:58`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L58)) already tells the tool when the
original reader is done — but a live capture's writer never finishes, so the tool
would have to refuse outright when `capture.live`.

**A long read inside a handler stalls every other surface.** The API and MCP
servers share one thread running one `tokio::runtime::Builder::new_current_thread()`
([`servers.rs:327`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L327)). Reading a multi-gigabyte pcap
inside a tool handler blocks that thread for the duration — every other MCP tool
call and every REST request behind it. This is not a lock-across-await violation
(invariant 8 is enforced by `clippy::await_holding_lock = "deny"` and would not
fire), which makes it worse: nothing catches it. Avoiding it means a background
thread plus a progress-polling tool, which is the TUI's `pcap-load` design ported
to MCP — the real cost of the feature, and it is not small.

**The server's own idea of what it is holding is per-session and immutable.**
`SipnabMcp` is cloned per HTTP session — [`transport.rs:124`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs#L124)
documents *"the tool server; cloned per HTTP session"* and
[`:192-193`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs#L192-L193) does it. `capture: Option<CaptureContext>`
([`server.rs:82`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L82)) is a plain field, not an `Arc`,
built once at startup ([`servers.rs:224-249`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L224-L249)) with
`name` taken from `cli.primary_input()` — which returns only the *first* `-I`
argument ([`cli.rs:1363-1365`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L1363-L1365)). So after an `open_capture`,
`capture_status` ([`server.rs:4525`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4525)) would keep naming
the old file, in the calling session as well as every other one, unless the
field moves behind a shared lock. Two agents on one HTTP server would read the
same store and disagree about which capture it is.

**Nothing on the wire would reveal the swap.** `DialogStore::generation`
([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573)) is bumped by every
mutating method and is exposed nowhere: not in `DialogSummary`
([`model.rs`](../../src/output/model.rs)), not in any REST response
([`api.rs:204-211`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L204-L211), all `GET`), not in any MCP payload.
A `/v1/dialogs` poller would see the dialog set change completely between two
requests with nothing indicating that it is now reading a different capture. This
is the same missing primitive that §2 requires, which is not a coincidence.

### The decisive one, as it was argued

The three costs above are engineering: real, quantifiable, and payable. The
argument against rested on the benefit being near zero in two of sipnab's three
deployment shapes, and the roadmap already enumerated them
([`mcp-tool-roadmap.md`](mcp-tool-roadmap.md) Part 1): SSH-launched stdio, local
stdio, and persistent HTTP. In both stdio shapes the sipnab process is a child of
the agent's own session — switching captures is *"start it again with a different
`-I`"*, which costs one process spawn and produces a clean store, correct
`capture_status`, correct uptime, and no second writer. `open_capture` would be a
worse version of something already free.

That leaves persistent HTTP, where a restart is genuinely disruptive. But there
`-I` now takes a whole directory, a glob, or a repeated set
([`cli.rs:234-247`](https://github.com/NormB/sipnab/blob/main/src/cli.rs#L234-L247)), so the corpus can be loaded at start —
subject, and this is the honest caveat, to §1's finding that the load is a union
and not a set of separable captures.

So the feature is worth building only for an operator who runs sipnab as a
long-lived HTTP service, over a corpus too large or too heterogeneous to union,
and who is willing to pay for a ported `pcap-load` design. That operator may
exist. Nobody has asked to be them.

### What goes wrong if someone builds `open_capture` anyway

The obvious implementation — clear both stores, read the new file synchronously
inside the handler — produces a server that stops answering anything for however
long the read takes, reports the wrong filename from `capture_status`
afterwards, and hands a REST consumer a completely different dataset with no
signal. Each of those individually looks like a bug in something else. Together
they are hard to attribute, because the tool call that caused them succeeded.

The subtler failure is the one worth stating plainly. An agent that can switch
captures will switch captures, and the transcript of an investigation stops being
a record of one thing examined from several angles and becomes a sequence of
observations about an unnamed sequence of files. Every tool response would need a
capture identity for that transcript to be reconstructable — and that identity
does not exist, at any layer, for the same reason §1 is blocked.

### Decision on `open_capture`, and what would change it

**Approved to move forward, 2026-08-02.** The argument above rested on the
benefit being near zero outside persistent HTTP, on the grounds that the cheapest
correct alternative — restart with a different `-I` — is free in the two stdio
shapes. That reasoning is withdrawn: persistent HTTP is a shape sipnab is
expected to serve, and a restart is not an acceptable substitute there. What was
filed as the load-bearing condition is therefore treated as met by decision
rather than by an operator hitting the dead end first.

None of the three cost findings above is retracted, because none of them was
what the argument turned on. They are the build requirements, and each names the
file that has to change. **All three shipped on 2026-08-02**, and the two
primitives they produced are written up in
[`capture-identity-and-async-load.md`](capture-identity-and-async-load.md) —
each requirement below therefore describes the tree as it stood when the
decision was taken, not as it stands now:

1. **`CaptureContext` must become shared, not per-session.** It is a plain
   `Option<CaptureContext>` field ([`server.rs:82`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L82)) on
   a `SipnabMcp` cloned per HTTP session
   ([`transport.rs:192`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs#L192)). Until it moves behind
   a shared lock, a swap leaves `capture_status`
   ([`server.rs:4525`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4525)) naming the old file in the
   calling session and in every other one.
2. **Capture identity must be visible on the wire.** `DialogStore::generation`
   ([`dialog_store.rs:573`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L573)) is bumped by every
   mutating method and exposed nowhere, so a `/v1/dialogs` poller cannot tell the
   dataset changed underneath it. This is the same primitive §2 requires;
   building it once settles both.
3. **The load must not run inside the handler.** A synchronous read stops the
   server answering for its duration. The shape that works is the TUI's
   `pcap-load` design ported to MCP — a load thread plus a progress-polling tool.

The opt-in machinery and the path confinement are already solved and should be
reused rather than redesigned: the `shutdown_server` flag, off-by-default field,
builder and first-statement refusal
([`server.rs:6570`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L6570)), and `--mcp-file-root` with
`resolve_in_root` ([`server.rs:487`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L487)).

**What shipped**, against those three:

| Requirement | Built as |
|---|---|
| 1. Shared `CaptureContext` | `CaptureState` behind one `Arc<RwLock<..>>` on `SipnabMcp`, holding the identity, the description and the in-flight load together, with the lock order written down |
| 2. Wire-visible identity | [`src/provenance.rs`](../../src/provenance.rs): a capture-instance id plus both store generations, stamped on `capture_status` and every paged whole-store response. §2's write-back tools consume the same `CaptureEtag` |
| 3. Non-blocking load | [`src/mcp/load.rs`](../../src/mcp/load.rs): an `mcp-pcap-load` thread the runtime never waits on, polled through `capture_status.load` |

The REST half of requirement 2 is still open: `/v1/dialogs` carries no etag, for
the reason the design note records.

A narrower tool is worth building alongside it, and carries none of the above:
**`capture_sources` (read-only)** — report the *full* resolved `-I` set
rather than `primary_input()`'s first element, with each file's first-packet
timestamp. `input_set::resolve` already computes that timestamp into
`ResolvedInput.first_packet` ([`input_set.rs:88-97`](https://github.com/NormB/sipnab/blob/main/src/capture/input_set.rs#L88-L97))
and `bootstrap` then throws it away —
[`bootstrap.rs:182`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L182) is
`resolved.into_iter().map(|r| r.path).collect()`. An agent's actual complaint in
the persistent case is usually *"I do not know what I am holding"*, and that is
the tool for it. It is Tier 1 by the roadmap's own criterion — *"the agent
cannot see its own context"* — and it mutates nothing.

---

## 5. Declined capture technologies

Five things that would make capture faster, if they worked here. Each entry is
the verdict and the **one** fact that decides it — the full investigations are
in [`process-isolation-and-hot-path-cost.md`](process-isolation-and-hot-path-cost.md)
and in the `CT*`/`PI*` entries of [`backlog.md`](backlog.md), and the detail
belongs there rather than repeated here. Recorded so none of these is
re-proposed from first principles.

### 5a. Forking as an architecture — **declined**

**Decisive: the shared `Arc<RwLock<..>>` stores are the product.** Every
surface sipnab has — the REST API, the MCP tools, the TUI, the reports — is a
read of those stores. Putting a process boundary anywhere in the middle turns
each of those reads into a wire protocol, which is a new distributed system
rather than a refactor. The scaling argument that motivated it does not
survive measurement either: what caps `--cores` is the single sequential pcap
reader, not lock contention.

Detail, including the fault- and memory-isolation arguments taken at their
strongest: [`process-isolation-and-hot-path-cost.md`](process-isolation-and-hot-path-cost.md)
§§2–4. **One exception survives** — scanner-kill, the only component that
transmits and the only one with no shared state, tracked as **`PI2`** in
[`backlog.md`](backlog.md) at P5 and conditional on `--kill-scanner` ceasing
to be niche. That is the whole of the surviving case; it is not a license to
fork anything else. Related history: `implementation-plan-v6.md` D16 specified
forked children for scanner-kill *and* the REST API, with acceptance gates
reading "verified by checking PID differs from main". Neither was built; both
are threads. That section is annotated in place.

### 5b. DPDK — **declined**

**Decisive: `pcap-dpdk.c` sets `selectable_fd = portid`, so `dpdk:0` polls
stdin and captures nothing.** File descriptor 0 is standard input, and libpcap
hands it to `poll()` as though it were the capture handle. Compounding it: the
DPDK module was **deleted in libpcap 1.11**, and Debian's libpcap — what the
`.deb`, the Docker image and the `gnu` builds link — never enabled it. So the
device string cannot work, will not be supported upstream, and is absent from
the library sipnab actually ships against. Context in
[`backlog.md`](backlog.md) `CT6` (the backend-verification entry that covers
DPDK, netmap and AF_XDP together); netmap, from the same investigation, is the
one alternate backend that *did* survive.

### 5c. PF_RING — **declined, on licensing**

**Decisive: proprietary ntop-EULA blobs are linked into `libpfring`, which is
incompatible with sipnab's MIT-OR-Apache-2.0 redistribution.** The build
`ar -x`s ntop's object files straight into the shared library, so there is no
"just the open-source part" package to ship, and the EULA reads *"for your own
personal, non-commercial use"*. That alone makes the Docker image and the
`.deb` undistributable. ZC mode additionally needs a paid per-MAC license.
Moot regardless on two technical counts. Full verdict:
[`backlog.md`](backlog.md) **`CT10`**.

### 5d. AF_XDP — **declined**

**Decisive: it is ingress-only, so it loses one direction of every call.** A
SIP dialog and its RTP are bidirectional; half a call is not a smaller answer,
it is a wrong one. Independently fatal: there is **no tee** — once an XSK binds
a queue it takes every packet on it, so sipnab would steal the production
traffic it is there to observe. And there is **no AF_XDP module in any version
of libpcap**, so this is a from-scratch backend, not a device string. Full
verdict: [`backlog.md`](backlog.md) **`CT13`**.

### 5e. XDP as a capture filter — **declined, on architecture**

**Decisive: XDP runs upstream of the AF_PACKET taps, so it can only filter
*from* sipnab, never *for* it.** An `XDP_DROP` happens before the tap sipnab
reads, so the packets it discards are invisible to sipnab — and on a live SIP
server they are the production traffic being observed. It is the wrong side of
the hook. Note that it fails on **architecture, not permissions**: do not
re-propose it on the grounds that the privilege drop now allows it. The one
surviving eBPF use was `PACKET_FANOUT_EBPF`/`_CBPF` for fanout steering, a
different mechanism at a fraction of the cost — and that use, `CT11`, has since
been **measured and refused**: the correlation it would fix costs nothing while
live capture has one processing thread, and its program widens the SIP/media
split rather than closing it (§6 of [`live-fanout.md`](live-fanout.md)). So no
eBPF use survives on the capture path today. Full verdict:
[`backlog.md`](backlog.md) **`CT12`**.

---

## 6. Native TLS **secret** extraction (`TK6`) — **REVERSED: approved 2026-08-15**

Decided 2026-08-14, after `TK7`'s mechanism was measured. Note carefully what
this declines and what it does not: it declines sipnab growing its own
extractor for **TLS master secrets**. It does **not** decline eBPF, and it does
not touch `TK7`, which reads **plaintext** and is being built.

**Decisive: it buys one thing — "no second tool on the SBC" — and pays for it
with a struct-offset table per OpenSSL release, forever.** Reading
`ssl->session->master_key` means knowing the layout of OpenSSL's internal
structs, which change between releases and differ across BoringSSL, LibreSSL,
GnuTLS and NSS. ecapture carries roughly forty version-specific objects for
exactly this. That is a permanent maintenance obligation on a project whose
[positioning](positioning.md) is that it is *run*, not *operated*.

**And the thing it buys is already bought, twice.** [`examples.md`](https://github.com/NormB/sipnab/blob/main/docs/examples.md) §7e
documents `ecapture tls -m keylog` feeding `--keylog`, measured on a daemon with
no `SSLKEYLOGFILE` anywhere. `TK4`'s `--keylog-fd` takes the same secrets over a
pipe so they never reach disk. A native extractor would duplicate a mature
Apache-2.0 tool to remove one install step.

**The comparison that settled it:** `TK7` reads plaintext from `SSL_write` and
`SSL_read`, whose signatures are **ABI**, not internals. It needs only ELF
function symbols, resolvable from the library file, and it was measured working
against a live OpenSIPS. Same eBPF-shaped capability, none of the offset debt.

**Reopens if** sipnab needs the *encrypted bytes plus their secrets* rather than
the plaintext — the `--pcap-export-mode encrypted+dsb` case, where a third party
must be able to verify the capture independently. `TK7` cannot serve that, since
it never sees ciphertext. Until someone asks for that, this stays declined.

### Prior art that confirms the cost, and softens one argument

[`pcap-sip`](https://gitlab.com/wisteriabg/pcap-sip/) (Sergey Safarov, the
author of sngrep PR 539) is a Rust SIP capture workspace that implements this
exact feature with [`aya`](https://aya-rs.dev). Read 2026-08-15. It is
**GPL-3.0-or-later** and sipnab is MIT OR Apache-2.0, so nothing there can be
vendored, copied or derived from — this entry records what it demonstrates,
not code to take.

**It confirms the decisive cost.** `crates/pcap-sip-core/src/ebpf/offsets.rs`
is the struct-offset table this section declines, made concrete — `ssl_session:
0x918`, `session_master_key: 0x50`, `ssl_s3_client_random: 0x160`, one set per
OpenSSL version — and its own doc comment records that the values come from
ecapture's profiles. Those constants must be re-derived for every OpenSSL
release, by someone, forever.

**It weakens one of the supporting arguments, and only that one.** This entry
leaned partly on aya being a heavy build commitment. `pcap-sip` shows a clean
pattern: the `no_std` BPF crate is a separate package **excluded** from the host
workspace, carrying its own empty `[workspace]` table so cargo treats it
independently, built for `bpfel-unknown-none` by `aya-build` from the parent's
[`build.rs`](https://github.com/NormB/sipnab/blob/main/build.rs), behind an `aya_build_skip` cfg so a host build can opt out entirely.
That is a demonstrated route rather than a theoretical one.

**Why the decline still stands.** The offset table is a consequence of the
TARGET, not of choosing aya. `pcap-sip` reads master secrets out of `SSL`
internals, which requires knowing that struct's layout. `TK7` reads plaintext
from `SSL_write`, whose signature is **ABI** rather than internals, so it needs
only ELF function symbols and no struct layout at all. Same toolkit, different
target, and only one of them owes a table.

**A correction to this section, made the same day it was written.** The
paragraph here first claimed that in-kernel filtering was the one thing that
would make `aya` worth its cost, since these probes see every process that maps
the library and sngrep prefilters in kernel space for exactly that reason. That
was wrong, and measurement rather than argument settled it: **tracefs filters do
content matching in the kernel already.**

A fetch argument typed `:string` can be glob-matched by the event filter, and
the kernel evaluates that filter *before recording the event*. Measured on a 6.8
kernel: a probe filtered to `s ~ "INVITE*"` delivered an `INVITE` written
through `SSL_write` and **suppressed a non-SIP write on the same connection
entirely** — one event, not two. A 15-term chain covering every SIP method plus
the `SIP/2.0` response form is accepted by the same parser, and one probe can
carry the string to filter on *alongside* the banded byte fetches that deliver
the payload.

So sipnab prefilters in kernel space today, with no BPF program, no
`bpf-linker` and no nightly toolchain — see `kernel_filter_for` in
[`src/capture/uprobe/mod.rs`](https://github.com/NormB/sipnab/blob/main/src/capture/uprobe/mod.rs). The userspace `is_interesting` check
remains as a second line, because a band is a bound and a glob is a prefix.

That removes the last argument for `aya` in this feature. `TK6` stays declined
on the offset table, which is a property of reading `SSL` internals and is not
addressed by any of this.

### Decision reversed by the owner, 2026-08-15

**`TK6` is approved and being built.** The analysis above is kept in the tense
it was written in, per this page's method — it is the reasoning that produced a
decline, and a reversal that erased it would teach nothing. What changed is the
decision, not the facts: the offset table is still a real, permanent cost, and
the owner has accepted it.

Three findings from the day the decline was written now shape the build rather
than argue against it:

- **The offsets cannot be copied from `pcap-sip`.** Its `offsets.rs` is
  GPL-3.0-or-later and sipnab is MIT OR Apache-2.0. sipnab needs its own
  derivation.
- **There is a license-clean source for them.** OpenSSL 3.x is **Apache-2.0**
  (confirmed from this host's `libssl3t64` copyright), which is compatible, so
  offsets may be derived from OpenSSL's own struct definitions.
- **No exported symbol hands the secret over.** `SSL_SESSION_get_master_key`
  and `SSL_get_client_random` are exported, but a uprobe cannot *call* a
  function — it can only observe one an application already calls, and
  applications do not call these. So a struct read is unavoidable, which is
  exactly what makes the offsets load-bearing.

**The mechanism is available today.** tracefs fetch arguments support **nested
dereference** — `+0x50(+0x918(%x0)):x8[48]` is accepted by a 6.8 kernel — so
`ssl->session->master_key` is readable through the same probe machinery `TK7`
already uses. `TK6` therefore does not depend on adopting `aya`.

**The guard that makes a wrong offset loud** still stands and is now a build
requirement rather than a nice-to-have: sipnab holds the decryptor in the same
process, so an extracted secret is **validated by attempting a decryption before
it is accepted**. A bad offset then produces a named error instead of a capture
that silently decrypts nothing — a check a standalone extractor cannot make,
having no decryptor to check against.

---

---

## Conditions, in one place

| Decision | Condition |
|---|---|
| §1 Multi-capture comparison | Reopens when per-dialog capture provenance exists for another reason (most likely multi-device attribution reaching `SipDialog`) |
| §2 Write-back MCP tools | Approved. **Both** a wire-visible store generation/etag *and* an annotation store no analysis reads are build requirements — see §2 |
| §3 Threat-mitigation ledger | Reopens when sipnab gains durable cross-run state — and only after the three blind spots in §3 are closed as ordinary defects |
| §4 `open_capture` | **Built 2026-08-02.** The three build requirements shipped with it; the REST etag is the one piece still open — see §4 |
| §5a Forking as an architecture | Does not reopen. The one surviving fork candidate is scanner-kill (`PI2`), and only if `--kill-scanner` stops being niche |
| §5b DPDK | Does not reopen. The module is deleted upstream and absent from every libpcap sipnab links |
| §5c PF_RING | Reopens only if ntop relicenses the `libpfring` blobs compatibly with MIT-OR-Apache-2.0. Not otherwise |
| §5d AF_XDP | Reopens only if the kernel grows a tee (`clone_redirect` in `xdp_func_proto`) **and** an egress path. Both, not either |
| §5e XDP as a capture filter | Does not reopen. It is on the wrong side of the tap; no permission change affects that |
| §6 Native TLS secret extraction (`TK6`) | **Reversed 2026-08-15 — approved and being built.** The offset cost is accepted; offsets derive from OpenSSL's Apache-2.0 sources, never from GPL prior art |

The two feature decisions still open, §1 and §3, do not move on "someone asked
again"; they move on the facts named above. The §5 technologies do not move on
a benchmark either — every one of them fails before throughput is reached.
