# Comparing two captures

**Status:** DESIGN. Nothing here is implemented, and section 7 recommends
implementing only the first of five parts.
**Verified against:** `63b771b`, working tree.
**Relationship to [`deferred-and-declined.md`](deferred-and-declined.md) §1.**
That page re-scoped the side-by-side view rather than building it as specified,
and named the blocker:
sipnab retains no record of which capture anything came from, so the comparison
column has no field to read. This page accepts that finding and does not re-argue
it. It answers the question §1 left open — *what is this feature, exactly, if the
provenance prerequisite ever lands* — and it spends most of its length on the
part §1 identified but did not specify: correlation. The layout is the easy half
and gets one section.
**Check:** `grep -rn 'capture_id' src/sip/dialog.rs` exits 1 — a dialog still carries no
record of WHICH capture it came from, which is the prerequisite §3 names and the
reason the comparison column would have no field to read. This replaces a check on
[`src/cli.rs`](https://github.com/NormB/sipnab/blob/main/src/cli.rs), which proved only that no FLAG exists: a built-but-unwired comparison
would have passed it while the claim above was false. (`compare` alone is no good
either — `compare_dialogs` is a real MCP tool, and it compares two dialogs in ONE
capture, which is a different feature.)

## 1. The two questions an operator is actually asking

"Compare two captures" is one phrase covering two problems with almost nothing
in common. Conflating them is why the request has never converged on a spec.

**Question A: before and after.** *"I changed the SBC config at 14:00. Are calls
worse?"* Two captures of different traffic, taken at different times. Nothing in
capture A is in capture B. There are no shared Call-IDs, no shared SSRCs, no
shared dialogs. What the operator wants compared is **distributions**: answer-seizure
ratio, response-code histogram, codec mix, MOS spread, median post-dial delay.

**Question B: two legs of one call.** *"The customer says we sent a 488. Did we?
Here is the access-side capture and here is the trunk-side capture."* One call,
observed twice, at two points in a signaling path. What the operator wants
compared is **one specific call**, message by message, and the interesting output
is the header that differs between the two observations.

These need different data, different keys and different screens. A is a
statistical summary over two disjoint populations; B is a diff of two message
lists that are supposed to describe the same event. **A is easy and unbuilt. B is
what everyone asks for and is the hard one.** The rest of this document is mostly
about B, and section 7 recommends shipping A first for exactly that reason.

## 2. What "the same call in two captures" means, and why no single key works

This is the hard part, and it is hard in an unusual way: the two common
deployments fail with *opposite* symptoms, so a fix for one makes the other
worse.

### Through a proxy, the Call-ID is preserved — and therefore collides

[RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) requires a proxy to pass the Call-ID through unchanged. So a call
captured on the access side and again on the trunk side carries the identical
Call-ID in both files. That sounds like the answer. It is the problem, because
sipnab's store is Call-ID-keyed and will *merge* the two observations rather than
distinguish them.

`DialogStore::merge` ([`dialog_store.rs:986`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L986))
carries a doc section headed *"Same-Call-ID collisions are the normal case, not
the rare one"* ([`:719`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L719)), and its stated
resolution is a sum, not a choice:

> So a collision is not a contest to be won. The fragments are disjoint
> observations of one call and the merged dialog is their SUM: the message
> lists are concatenated in capture-timestamp order and the state machine
> is re-run over the result […]

That is correct for `--cores N`, which is what it was written for: the shards
*are* disjoint observations that should sum. It is exactly wrong for question B,
where the two observations are not disjoint — they overlap almost completely,
and the whole point is where they do not. A comparison view sitting on top of a
merged store renders one row, reports the merged verdict as though both captures
agreed, and destroys the disagreement it was built to find.

### Through a B2BUA, the Call-ID changes — and there is no key at all

A back-to-back user agent terminates one dialog and originates another. New
Call-ID, new tags, new branch, frequently a rewritten From and To. Nothing in
`SipDialog` ([`dialog.rs:87-140`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L87-L140)) survives the crossing
as a stable identifier. `call_id`, `from_tag`, `to_tag`, `src_addr`, `dst_addr`,
`src_port` and `dst_port` all change by definition; `from_user` and `to_user`
change whenever the B2BUA does number translation, which is most of why it is
there.

So the two regimes need opposite treatment:

| | Proxy / SBC (transparent) | B2BUA |
|---|---|---|
| Call-ID across captures | identical | different |
| Failure of a Call-ID key | **silent merge** — two rows become one | **silent miss** — one call becomes two unpaired rows |
| What the operator sees | agreement that was manufactured | "not found in capture B" |
| Which is worse | this one | this one is at least honest |

A comparison keyed on Call-ID is not merely incomplete. In the proxy case it
produces a confident wrong answer, and the proxy case is the population where
operators most want to compare two captures.

### The correlation function, and why it must be fallible

There is no exact key, so pairing must be a *scored candidate match* that the
operator confirms. That is a different kind of feature from a view, and pretending
otherwise is how this gets built wrong. A workable scorer, in decreasing order of
strength:

1. **Call-ID equality** — near-certain, and near-useless on its own because a
   load generator reuses Call-IDs across runs. [`dialog-tracking-modes.md`](dialog-tracking-modes.md)
   documents [`tests/pcap-samples/sipp-branch-scenario.pcapng`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sipp-branch-scenario.pcapng) as *"8,989 packets
   in which one Call-ID is reused across many transactions"*. Equality must be
   scored, not trusted.
2. **Time proximity of the first INVITE.** `SipDialog.created_at`
   ([`dialog.rs`](../../src/sip/dialog.rs)) exists. A B2BUA adds milliseconds,
   not minutes. This is the strongest signal that survives a B2BUA — and it is
   the one that fails hardest on two captures taken hours apart, which is
   question A's shape, which is why A and B must not share a screen.
3. **Called-number equality after normalization.** `to_user` survives a
   transparent proxy and survives many B2BUAs. It does not survive number
   translation, and translation is the case an operator most wants to inspect.
4. **Media correlation.** Two legs of one call through a media-relaying B2BUA
   share no SSRC and no ports. Through a signaling-only B2BUA they may share
   both. When they do it is decisive; when they do not, its absence proves
   nothing.
5. **Duration and outcome.** Weak, and the tiebreaker only.

None of these is sound alone. A useful scorer combines 2 and 3, uses 1 as a
strong prior and 4 as confirmation, produces a ranked candidate list, and shows
the operator *why* it paired two dialogs. **The output of correlation is a
proposal with its evidence attached, not a join.**

That has a consequence worth stating up front, because it is the thing that
makes this feature expensive: a wrong pairing is not a cosmetic bug. It renders
two unrelated calls as one call whose legs disagree, which is precisely the
signature of the fault the operator is hunting. **A correlator that is quietly
wrong manufactures the bug it was built to find.** Every design choice below
follows from that.

## 3. The prerequisite, restated in one line

Nothing in section 2 is reachable today, for the reason
[`deferred-and-declined.md`](deferred-and-declined.md) §1 established: there is no
capture provenance anywhere in the data model. `Packet.interface`
([`packet.rs:50`](https://github.com/NormB/sipnab/blob/main/src/capture/packet.rs#L50)) is the only source-identifying
field and the file reader hard-codes it to `None`; `ParsedPacket` does not carry
it forward; `SipMessage` and `SipDialog` have no source field at all. `-I`
resolves a whole set into **one** store, and `warn_on_overlap`
([`input_set.rs:585`](https://github.com/NormB/sipnab/blob/main/src/capture/input_set.rs#L585)) exists specifically to warn
operators away from feeding it two captures of the same traffic.

This document assumes an interned `u16` capture index reaching `SipDialog` — §1's
own suggested shape, chosen because a per-message `String` label would regress
the zero-copy spine that `process_message` is written around. Everything below
is void without it.

## 4. Sessions: what gets selected, and how

A "session" here is one loaded capture with its own store. Two sessions means two
`DialogStore` / `StreamStore` pairs, not one merged store with a label column —
that distinction is the whole design, and getting it wrong reproduces the merge
failure from section 2.

**Selection is explicit and ordered.** `-I a.pcap -I b.pcap` cannot mean this,
because that spelling already means "union these into one timeline" and changing
it would silently alter every existing invocation. A new flag — `--compare
b.pcap`, taking exactly one file and pairing it against the primary input — is
the only spelling that does not collide. Two captures, not N: the correlation
output is pairwise, and an N-way version has no defined meaning for "differs".

**The TUI needs a session concept it does not have.** `TuiOptions`
([`state.rs:218-232`](https://github.com/NormB/sipnab/blob/main/src/tui/state.rs#L218-L232), whose only capture-related field
is the `protected_inputs` save guard at `:231`) carries no path — the `-I` set is
consumed by `bootstrap::launch` and never reaches the TUI. Opening a capture from
inside the TUI *clears* both stores rather than adding a session: `reset_for_load`
([`file_open.rs`](../../src/tui/controllers/file_open.rs)), whose caller is
documented as *"replacing all existing data."* There is no merge-on-open branch
and no second-store branch. A comparison mode is a second writer against a second
pair of stores, which puts it under
[invariant 1](../internals/invariants.md)'s single-writer rule and needs the same
treatment the in-TUI `pcap-load` path already got.

**`View` cannot address a second session.** Every data-bearing variant of the
`View` enum ([`state.rs:1039-1087`](https://github.com/NormB/sipnab/blob/main/src/tui/state.rs#L1039-L1087)) is keyed on a
Call-ID or a `StreamKey` and nothing else: `CallFlow(String)`,
`CallTimeline(String)`, `RawMessage { call_id, message_index }`, `MessageDiff {
call_id, msg1_idx, msg2_idx }`, `StreamDetail(StreamKey)`. Two dialogs from two
captures are indistinguishable at the routing layer before they reach a
renderer. Comparison adds variants; it does not reuse these.

## 5. What the screen shows

Three views, in the order an operator needs them. This is the short section on
purpose — none of it is hard once section 2 is solved, and all of it is wasted if
section 2 is solved badly.

**Correlation list.** The landing view. One row per candidate pair, ranked by
score, with the evidence that produced the score in its own column ("Call-ID +
2 ms + same called number"). Unpaired dialogs from each capture are shown in
their own sections rather than hidden, because *"this call appears in A and not
in B"* is frequently the answer. The operator confirms, rejects or re-pairs a
row, and confirmation is sticky for the session.

**Paired call flow.** Two ladders, side by side, for one confirmed pair. Time
runs down; the two ladders share a time axis anchored on each side's first
INVITE, so a B2BUA's processing delay reads as a visible offset rather than as
drift. Messages the correlator matched are drawn level; messages present on one
side only are the point of the view and get the strongest emphasis available.

**Message diff.** Reached from a matched message pair. This one already exists in
useful form — `View::MessageDiff` — and its controller currently refuses to cross
even a dialog boundary ([`call_flow.rs:639`](https://github.com/NormB/sipnab/blob/main/src/tui/controllers/call_flow.rs#L639)):

```rust
app.status_error = Some("Diff across dialogs is not supported".to_string());
```

That refusal is correct today, since two dialogs in one store are two different
calls. Under comparison it becomes the exact operation wanted, and the refusal
must be relaxed *only* for a confirmed cross-session pair — not removed.

The MCP surface has the single-capture ancestor of all three: `compare_dialogs`
([`server.rs:4964`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4964)) takes two Call-IDs, projects state,
final status code, message count, methods and hints for each, and names the keys
that differ. Its shape is right and its scope is one store — both Call-IDs are
looked up in the same `dialog_store`. Extending it to cross sessions is the same
prerequisite and the same correlation problem, and it should follow the TUI
rather than lead it.

## 6. What goes wrong if someone builds it anyway

Three failures, in the order they appear.

**The cheap version cannot be written.** "Load both into one store, add a capture
column" has no field to populate (section 3), and adding one touches `Packet`,
`ParsedPacket`, `SipMessage` and `SipDialog` — the hot path.

**The version that compiles is the dangerous one.** Load both captures into one
store and the Call-ID-keyed merge folds each proxied call into a single dialog
whose message list is the concatenation and whose state machine has been re-run
over the union. The comparison view then renders one row and reports the merged
verdict as agreement. Measured, in
[`deferred-and-declined.md`](deferred-and-declined.md) §1: two byte-identical
copies of one fixture read as one `-I` set produced an unchanged dialog count,
double the messages per dialog, double the RTP packets per stream, and a PCMU
stream reported at 128 kbps over an unchanged 8-second span — a rate G.711
cannot produce, with `--problems` adding nothing.

**The version that works most of the time is the one to fear.** A correlator
tuned on transparent-proxy captures will pair on Call-ID, score confidently, and
be right until it meets a load generator or a B2BUA. Then it pairs two unrelated
calls and renders their differences as a fault in one call. There is no error
state and no warning; the screen looks exactly like a successful comparison.
This is why section 2 insists the correlator surface its evidence and require
confirmation, and why an auto-pairing default would be a mistake even though it
is the obvious convenience.

## 7. Recommendation

**Do not build question B until provenance exists for another reason.** The
prerequisite is larger than the feature, the correlator is a genuinely hard
component whose failure mode is a manufactured bug, and neither is justified by
a request that has never been narrowed to one deployment.

**Do build question A, which is independent of all of it.** A distribution
comparison across two runs needs no per-dialog provenance, because it never
identifies a call: run the existing report over capture A, run it over capture
B, print the two summaries against each other with deltas. Response-code
histogram, answer-seizure ratio, codec mix, MOS distribution, post-dial-delay
percentiles. It is a batch-mode feature, not a TUI mode; it needs no `View`
variant, no second store, no session concept and no correlator; and it answers
*"did my config change make things worse"*, which is the more common of the two
questions and the one no current output addresses at all.

Naming it separately matters. If A ships as "capture comparison", B must be
named for what it is — **leg correlation** — so nobody reads A's existence as
evidence that B is nearly done. They share a noun and nothing else.

**Reopen question B when** an interned capture index reaches `SipDialog` for
another reason. The likeliest driver is multi-device live capture, where
per-interface attribution is already a live concern — the pcapng writer keeps an
interface table and maps `Packet.interface` to a pcapng `interface_id`. If that
plumbing ever reaches the dialog layer, section 2's correlator becomes the whole
remaining cost, and it can be judged on its own.
