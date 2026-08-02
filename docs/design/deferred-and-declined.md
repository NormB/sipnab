# Four decisions: three declined, one re-scoped

**Status:** decided, 2026-08-01. Nothing on this page is scheduled. Verified
against `main` at 1998303.

Four requests sat open a long time each, and they had one thing in common: the
honest answer turned out to be some version of *not as asked*. An undecided
feature comes back every quarter with the same arguments; a declined one with a
written reason and a named trigger does not. So the deliverable here is the
writing-down, and each section ends with the specific fact that would reopen it.

A note on method, because it changed several of the answers below. Every claim
was re-checked against the current tree rather than carried over from the review
that raised it, and three inherited framings did not survive:

- that the recent `-I` multi-file work gives sipnab a cross-capture story §1
  could be built on — it is the opposite operation, and §1 measures the damage;
- that `shutdown_server` is an exception to the read-only invariant — it is not,
  and §2 shows what actually broke instead;
- the recorded rationale for declining `open_capture`, which §4 rebuilds from
  scratch rather than repairing.

Where a conclusion still holds it holds on different evidence, and this page
shows the work rather than the verdict.

| # | Request | Decision |
|---|---|---|
| 1 | TUI multi-session / multi-capture comparison | **Re-scoped.** The want is real; the specification is not buildable and the `-I` set does not substitute for it |
| 2 | Write-back MCP tools | **Declined.** The invariant survives intact; its stated rationale does not, and §2 says which |
| 3 | Automated threat-mitigation hooks | **Fixes extracted and shipped; the action ledger deferred** on a named prerequisite |
| 4 | `open_capture` MCP tool | **Declined**, on a rationale rebuilt from scratch |

---

## 1. TUI multi-session / multi-capture comparison

**Decision: still wanted, and different. Do not build the side-by-side view.
Build capture provenance first, or build nothing.**

### The founding premise is false, and the tree already says so

The request was to open two captures at once and compare them side by side,
keyed on Call-ID. That works only if a Call-ID identifies at most one call in
the combined view. It does not.

The clearest statement of this is in the code that had to cope with it.
`DialogStore::merge` ([`dialog_store.rs:595`](../../src/sip/dialog_store.rs))
carries a doc section headed *"Same-Call-ID collisions are the normal case, not
the rare one"* ([`:554`](../../src/sip/dialog_store.rs)), and explains that a
call through a proxy or SBC reconstructs as two fragments keyed on the same
Call-ID — *"measured at 1173 of 2311 dialogs in one 100 MB file."*
That is within a single capture. Across two captures of
the same traffic the collision rate is 100% by construction: a proxy preserves
Call-ID end to end, so a call captured on the access side and on the trunk side
carries the identical value in both files.

`--dialog-track` exists because of the same problem seen from another angle.
[`dialog-tracking-modes.md`](dialog-tracking-modes.md) documents
`tests/pcap-samples/sipp-branch-scenario.pcapng` as *"8,989 packets in which one
Call-ID is reused across many transactions"*, and adds that under proxies and
B2BUAs *"the same Call-ID legitimately recurs"*. A comparison view keyed on
Call-ID would silently pair unrelated calls in exactly the populations —
generators and proxies — where operators most want to compare two captures.

### What the `-I` set actually gave us, and why it is not this

`-I` now accepts a file, a directory, a glob, or a repeated set
([`cli.rs:234-247`](../../src/cli.rs)), resolves it into one chronologically
ordered list (`input_set::resolve`,
[`input_set.rs:106`](../../src/capture/input_set.rs)), and streams every file
into **one** `DialogStore` through one channel
(`capture_files`, [`file.rs:203`](../../src/capture/file.rs)). It is tempting to
read that as "sipnab now has a cross-capture story, so the comparison request is
satisfied."

It is the opposite operation, and the module that implements it says so in as
many words. `warn_on_overlap`
([`input_set.rs:395`](../../src/capture/input_set.rs)) exists precisely to warn
an operator away from the comparison use case:

```
'{}' and '{}' start at the same instant — if these are two captures of
the same traffic, packets present in both are counted twice
```

and its companion in the read path, `overlap_message`
([`file.rs:486`](../../src/capture/file.rs)), repeats the consequence for the
end-against-start case: *"they overlap by {by} ms, so packets present in both
are counted twice."* The doc comment above `warn_on_overlap` is explicit that
*"Overlap means the set is not one sequence — most often two capture runs, or
the same traffic collected on two interfaces, mixed into one directory."*

Measured, not assumed. Two byte-identical copies of
`tests/pcap-samples/sip-rtp-g711.pcap` read as one `-I` set:

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
(1 ms, [`input_set.rs:420`](../../src/capture/input_set.rs)) and
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
  ([`packet.rs:50`](../../src/capture/packet.rs)), and the file reader hard-codes
  it to `None` — [`file.rs:633`](../../src/capture/file.rs):
  `None, // File captures have no interface name`, with the invariant asserted in
  the module's own tests at [`file.rs:1107`](../../src/capture/file.rs).
- `ParsedPacket` ([`parse.rs:49-84`](../../src/capture/parse.rs)) does not carry
  `interface` forward at all, so even the live-capture device name is dropped
  before SIP parsing.
- `SipMessage` ([`message.rs:34-70`](../../src/sip/message.rs)) and `SipDialog`
  ([`dialog.rs:87-140`](../../src/sip/dialog.rs)) have no source field. `tags` on
  `SipDialog` is the operator's `--tag` string, not provenance.
- The TUI's only notion of where its data came from is one display string,
  `capture_mode` ([`tui/mod.rs:145`](../../src/tui/mod.rs)), overwritten wholesale
  on each in-TUI open ([`file_open.rs:520`](../../src/tui/controllers/file_open.rs)).
  The `-I` set never reaches the TUI: `plan.source` is consumed by
  `bootstrap::launch` ([`main.rs:134`](../../src/main.rs)) and `TuiOptions`
  ([`state.rs:218-229`](../../src/tui/state.rs)) carries no path.
- Opening a capture from inside the TUI **clears** both stores rather than
  merging — `reset_for_load`
  ([`file_open.rs:333`](../../src/tui/controllers/file_open.rs)), whose caller
  `load_pcap_file` is documented as *"replacing all existing data."* There is no
  merge-on-open branch anywhere in that path.

The `View` enum ([`state.rs:1036-1084`](../../src/tui/state.rs)) reflects the
same absence: every data-bearing variant is keyed on a Call-ID or a `StreamKey`
and nothing else, so two dialogs from two captures would be
indistinguishable at the routing layer even before they reached a renderer.

The one comparison the TUI does have is `View::MessageDiff`, and its controller
refuses to cross even a dialog boundary —
[`call_flow.rs:634-641`](../../src/tui/controllers/call_flow.rs):

```rust
if first_cid != cur_cid {
    app.flow.diff_selected = None;
    app.status_error = Some("Diff across dialogs is not supported".to_string());
    return;
}
```

### What goes wrong if someone builds it anyway

Two failure modes, in order of how quickly they bite.

The cheap version — load both captures into one store and add a "capture A / B"
column — cannot work, because the column has nothing to read. There is no field
to populate. Adding one means touching `Packet`, `ParsedPacket`, `SipMessage`
and `SipDialog`, which is the zero-copy payload spine (D3) and the hot path;
`process_message` ([`dialog_store.rs:353`](../../src/sip/dialog_store.rs)) is
written to avoid even a single owned-key allocation per message. A per-message
`String` source label is a straightforward regression of that work.

The version that looks like it works is worse. Because the merge is Call-ID
keyed, two observations of one call fold into a single dialog whose message list
is the concatenation and whose state machine has been re-run over the union
(`absorb_messages` then `replay_message_derived_state`,
[`dialog_store.rs:612-613`](../../src/sip/dialog_store.rs)). A comparison view
sitting on top of that would render one row and report the *merged* verdict as
if it were both captures agreeing. The disagreement it was built to find is the
thing the store destroyed before the view ran.

### Decision, and what would change it

**Declined as specified. The underlying want — "these two captures should be
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

**Decision: declined. And the reconciliation that was offered for it —
"`shutdown_server` is a documented exception to the read-only invariant" — is
wrong on the facts.**

### Invariant 7, read literally, is not violated by anything in the tree

[Invariant 7](../internals/invariants.md) states:

> **Rule.** No MCP tool mutates a store, and every response hits a size ceiling
> before serialization.

There are 24 MCP tools today
([`server.rs`](../../src/mcp/server.rs), `#[tool(name = …)]` attributes). Four
of them touch something other than the stores: `export_capture`
([`server.rs:2136`](../../src/mcp/server.rs)) writes a pcap, `export_audio`
([`server.rs:2177`](../../src/mcp/server.rs)) writes a WAV, `list_captures`
([`server.rs:2096`](../../src/mcp/server.rs)) reads a directory, and
`shutdown_server` ([`server.rs:2222`](../../src/mcp/server.rs)) ends the process.

**None of them mutates a store.** `shutdown_server` reads `dialog_store` and
`stream_store` for its report, optionally writes a file, and then calls
`crate::signals::request_shutdown()`
([`server.rs:2288`](../../src/mcp/server.rs)) — the same flag SIGTERM sets. The
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

That repair has not been made yet, and two other places drifted the same way and
want the same pass: [`mcp/mod.rs:5`](../../src/mcp/mod.rs) still describes the
surface as *"read-only"*, and [`docs/mcp.md`](../mcp.md)'s security model still
says *"systemd owns the capture lifecycle, or the CLI flags, not by the LLM"*,
which `--mcp-allow-shutdown` contradicts. All three are wording, not behaviour —
the code is doing the right thing and the prose has fallen behind it.

### What actually carries the safety, and why write-back cannot borrow it

`shutdown_server` is safe not because of the invariant but because of four
guards, each visible in the code:

1. **Off unless armed.** `allow_shutdown: bool`
   ([`server.rs:57`](../../src/mcp/server.rs)) is `false` in `new()`
   ([`server.rs:98`](../../src/mcp/server.rs)) and only set by `with_shutdown()`
   ([`server.rs:134`](../../src/mcp/server.rs)), which `servers.rs` calls only
   when `cli.mcp_allow_shutdown` is set
   ([`servers.rs:258-262`](../../src/app/servers.rs)). Refusal is the first
   statement of the handler ([`server.rs:2226`](../../src/mcp/server.rs)).
2. **Dry run by default.** `params.dry_run.unwrap_or(true)`
   ([`server.rs:2237`](../../src/mcp/server.rs)) — an agent that omits the
   argument gets a report.
3. **The destructive path must be named.** An unsaved live capture is refused
   unless `save_to` or `discard_unsaved=true`
   ([`server.rs:2268-2277`](../../src/mcp/server.rs)).
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
([`dialog_store.rs:163`](../../src/sip/dialog_store.rs)) is internal to
cache invalidation and appears on no wire format.

### The prompt-injection chain, grounded

Every MCP response contains attacker-controlled text. This is not hypothetical
and it is not incidental — it is the tool working:

- `DialogSummary.from_user` / `to_user`
  ([`model.rs:53-57`](../../src/output/model.rs)) are copied straight off the
  From/To URIs.
- `get_message` ([`server.rs:1135`](../../src/mcp/server.rs)) returns the parsed
  message through `message_to_json_value`, headers and body included.
- `search_messages` ([`server.rs:1306`](../../src/mcp/server.rs)) returns
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
happened to follow it. `tests/mcp_tool_descriptions_test.rs` now implements it
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
([`server.rs:150`](../../src/mcp/server.rs)), or — only if armed, only on a
second call, only having named the discard — a process stop. That is a
qualitative gap, not a matter of degree.

### What goes wrong if someone builds it anyway

The plausible requests here are the mild-sounding ones: tag a dialog,
acknowledge a finding, name a host, set a filter. Each is individually harmless
and collectively they are the whole problem, because the operator's screen is
the tool's output and every one of them edits it.

Concretely: `--api` and `--mcp` share the same `Arc<RwLock<DialogStore>>`, on
the same server thread — [`batch.rs:924-932`](../../src/app/batch.rs) starts both
with `Selection { api: true, mcp: true }`, and the comment above it states *"They
read the SAME stores the packet loop writes to."* Every REST route is a `GET`
([`api.rs:204-211`](../../src/output/api.rs)); there is no mutating verb anywhere
on sipnab's network surface today. A write-back MCP tool would be the first, and
it would be reachable from the one surface whose caller is a language model
reading attacker-supplied text. A monitoring system polling `/v1/dialogs` would
observe the change with nothing in the payload explaining it.

Note what this argument does *not* rest on: MCP does **not** run alongside the
TUI. [`tui_mode.rs:366-374`](../../src/app/tui_mode.rs) passes
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

### Decision, and what would change it

**Declined.** Not "not yet" — the shape is wrong, and no amount of guarding
fixes it, because the failure the guards would have to prevent is *silent
divergence between what the agent did and what the operator sees*, and sipnab has
no mechanism to surface that.

**Reopen when both of these are true**, not either:

1. **There is a wire-visible store identity** — a generation or etag on REST and
   MCP responses — so a consumer can detect that the thing it is reading changed
   underneath it. `DialogStore::generation` already exists internally
   ([`dialog_store.rs:163`](../../src/sip/dialog_store.rs)) and is bumped by every
   mutating method; exposing it is small. Without it, "who changed this" has no
   answer at any layer.
2. **The write-back state is separate from the analysis** — an annotation store
   that a tool may edit and that no analysis reads. A note attached to a Call-ID
   in a side-car map changes no derived verdict, so nothing an operator is
   reading becomes wrong; the argument above simply does not apply to it. A
   field on `SipDialog` is a different proposal, because every diagnosis reads
   that struct.

A proposal that satisfies both is a different feature from the one declined
here, and should be judged on its own.

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
(`RawKillSocket::open`, [`process_isolation.rs:90`](../../src/process_isolation.rs)),
`--kill-spoof {auto|raw|ephemeral}` with a loud failure for `raw`
([`bootstrap.rs:554-562`](../../src/app/bootstrap.rs)), and the property that
matters most — the forged source is never a parameter. It is always the sniffed
packet's own destination ([`batch.rs:1775-1776`, `:1816-1817`](../../src/app/batch.rs)),
so `-K` is a targeted transaction reply and not a general spoofer.

**HEP-origin packets cannot drive an active response.** The whole policy is
three lines ([`scanner_kill.rs:141-143`](../../src/security/scanner_kill.rs)):

```rust
pub fn kill_response_eligible(from_hep: bool, hep_allow_kill: bool) -> bool {
    !from_hep || hep_allow_kill
}
```

with the reason stated above it: *"a HEP sender asserts the inner src/dst
addresses, so absent receiver-side authentication an attacker could steer the
kill response at a chosen victim (SSRF-style)."* `--hep-allow-kill` is off by
default and a test pins that it stays off
([`cli.rs:1830-1835`](../../src/cli.rs), asserting *"HEP-origin scanner-kill must
be opt-in (SN-01)"*).

**Field injection into the input of a ban decision.** `fail2ban.rs`'s
`render_absent` ([`fail2ban.rs:51`](../../src/output/fail2ban.rs)) quotes and
escapes every attacker-controlled field, and its doc comment records the exact
attack it closes: a `User-Agent` of `evil method=REGISTER src=1.2.3.4` produced a
line with *"two `src=` values, one of them attacker-chosen, in the output that
feeds a ban decision."* It also unified five spellings of "absent", which is
what made the hole invisible to the filters that were supposed to catch it.

**Rate limiting on both the receive and the transmit side.** The HEP receiver
has a per-peer cap checked ahead of the global one
([`hep.rs:1206-1208`](../../src/capture/hep.rs)) that fails closed when its
tracking table fills; the kill worker has a global limiter (10/s,
[`process_isolation.rs:650`](../../src/process_isolation.rs)) and a
per-destination one (3/min, [`process_isolation.rs:411`](../../src/process_isolation.rs))
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
`Error { message }` ([`process_isolation.rs:256-271`](../../src/process_isolation.rs))
— and sends it on `resp_tx` ([`:529`](../../src/process_isolation.rs)). Nothing
in production reads it. `try_recv_response`
([`:331`](../../src/process_isolation.rs)) has exactly three call sites: two in
`process_isolation.rs` itself, both below the `#[cfg(test)] mod tests` boundary
at [`:712`](../../src/process_isolation.rs), and one in
[`tests/security_test.rs:1392`](../../tests/security_test.rs). Both dispatch
sites discard the send result too — [`batch.rs:1772`, `:1813`](../../src/app/batch.rs)
are `let _ = handle.send_kill(...)`.

**Suppressed actions are invisible.** A kill dropped by either rate limiter logs
at `tracing::debug!` ([`process_isolation.rs:560`, `:566`](../../src/process_isolation.rs)),
below the default level. An event-exec dropped by *its* rate limiter logs
nothing at all: `check_rate_limit`
([`event_exec.rs:222-241`](../../src/output/event_exec.rs)) returns `false` and
the caller simply returns. Only the queue-depth drop warns
([`:288-295`](../../src/output/event_exec.rs)).

**Hooks that ran are never checked.** `reap_action`
([`event_exec.rs:68-74`](../../src/output/event_exec.rs)) is
`Ok(Some(_)) => ReapAction::Remove` — the child's exit status is matched with a
wildcard and discarded. sipnab fires `sh -c <operator command>` and never learns
whether the ban it asked for happened.

Nothing persists. `fail2ban.rs`'s own doc says *"the caller is responsible for
emitting it — nothing is written here"*
([`fail2ban.rs:99-100`](../../src/output/fail2ban.rs)); the alert engine's
findings ring buffer is annotated *"In-memory only"*
([`alerting.rs:175`](../../src/security/alerting.rs)) and holds the *alert*, not
the *action* — a `Finding` has no field saying whether a kill went out. The only
durable-ish signal is two success counters,
`sipnab_kill_responses_sent_total{mode}`
([`process_isolation.rs:208-230`](../../src/process_isolation.rs),
[`prometheus.rs:172-187`](../../src/output/prometheus.rs)), which count sends
and nothing else. `sipnab_security_alerts_total` is declared
([`prometheus.rs:40`](../../src/output/prometheus.rs)) and formatted
([`:161-165`](../../src/output/prometheus.rs)) but written only in that file's
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

### Decision, and what would change it

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
([`process_isolation.rs:674-675`](../../src/process_isolation.rs)), and
`crossbeam_channel::Sender::send` on a bounded channel is documented to *"block
until the send operation can proceed"* when full, the worker's
`let _ = self.resp_tx.send(response)` at
[`:529`](../../src/process_isolation.rs) appears able to block once 256
responses accumulate. The request channel would then fill, and `send_kill`'s
`self.tx.send(request)` ([`:302`](../../src/process_isolation.rs)) would block
the caller — which is the capture path. That is a code reading, not an observed
failure; it was not run. It wants a test before it wants a fix, and it wants both
before anything is built on top of this worker.

---

## 4. The `open_capture` MCP tool

**Decision: declined. The rationale below is built from the current tree rather
than inherited — the previously recorded one did not survive re-checking and is
not reused here, in whole or in part.**

### Taking the case *for* building it seriously first

Three things changed since [`mcp-tool-roadmap.md`](mcp-tool-roadmap.md) filed
`open_capture` under *"Tier 3 — plausible, lower value"* with the note *"Mutates
state — needs the same opt-in treatment as shutdown."*

**The opt-in treatment now exists and is proven.** `shutdown_server` shipped with
a flag ([`cli.rs:988-1001`](../../src/cli.rs)), an off-by-default field
([`server.rs:57`](../../src/mcp/server.rs)), a builder
([`server.rs:134`](../../src/mcp/server.rs)) and a first-statement refusal
([`server.rs:2226`](../../src/mcp/server.rs)). Copying that shape costs almost
nothing.

**The path-confinement problem is solved.** The roadmap's other Tier 3 entry,
`list_captures`, was filed with *"needs a path allowlist or it is an
arbitrary-file-read"*. It shipped ([`server.rs:2096`](../../src/mcp/server.rs))
with `--mcp-file-root` and `resolve_in_root`
([`server.rs:150`](../../src/mcp/server.rs)), which accepts a bare filename and
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
([`server.rs:53`](../../src/mcp/server.rs)) already tells the tool when the
original reader is done — but a live capture's writer never finishes, so the tool
would have to refuse outright when `capture.live`.

**A long read inside a handler stalls every other surface.** The API and MCP
servers share one thread running one `tokio::runtime::Builder::new_current_thread()`
([`servers.rs:314`](../../src/app/servers.rs)). Reading a multi-gigabyte pcap
inside a tool handler blocks that thread for the duration — every other MCP tool
call and every REST request behind it. This is not a lock-across-await violation
(invariant 8 is enforced by `clippy::await_holding_lock = "deny"` and would not
fire), which makes it worse: nothing catches it. Avoiding it means a background
thread plus a progress-polling tool, which is the TUI's `pcap-load` design ported
to MCP — the real cost of the feature, and it is not small.

**The server's own idea of what it is holding is per-session and immutable.**
`SipnabMcp` is cloned per HTTP session — [`transport.rs:124`](../../src/mcp/transport.rs)
documents *"the tool server; cloned per HTTP session"* and
[`:192-193`](../../src/mcp/transport.rs) does it. `capture: Option<CaptureContext>`
([`server.rs:64`](../../src/mcp/server.rs)) is a plain field, not an `Arc`,
built once at startup ([`servers.rs:224-249`](../../src/app/servers.rs)) with
`name` taken from `cli.primary_input()` — which returns only the *first* `-I`
argument ([`cli.rs:1363-1365`](../../src/cli.rs)). So after an `open_capture`,
`capture_status` ([`server.rs:1548`](../../src/mcp/server.rs)) would keep naming
the old file, in the calling session as well as every other one, unless the
field moves behind a shared lock. Two agents on one HTTP server would read the
same store and disagree about which capture it is.

**Nothing on the wire would reveal the swap.** `DialogStore::generation`
([`dialog_store.rs:163`](../../src/sip/dialog_store.rs)) is bumped by every
mutating method and is exposed nowhere: not in `DialogSummary`
([`model.rs`](../../src/output/model.rs)), not in any REST response
([`api.rs:204-211`](../../src/output/api.rs), all `GET`), not in any MCP payload.
A `/v1/dialogs` poller would see the dialog set change completely between two
requests with nothing indicating that it is now reading a different capture. This
is the same missing primitive that §2 requires, which is not a coincidence.

### The decisive one

The three costs above are engineering: real, quantifiable, and payable. The
reason to decline is that the benefit is near zero in two of sipnab's three
deployment shapes, and the roadmap already enumerated them
([`mcp-tool-roadmap.md`](mcp-tool-roadmap.md) Part 1): SSH-launched stdio, local
stdio, and persistent HTTP. In both stdio shapes the sipnab process is a child of
the agent's own session — switching captures is *"start it again with a different
`-I`"*, which costs one process spawn and produces a clean store, correct
`capture_status`, correct uptime, and no second writer. `open_capture` would be a
worse version of something already free.

That leaves persistent HTTP, where a restart is genuinely disruptive. But there
`-I` now takes a whole directory, a glob, or a repeated set
([`cli.rs:234-247`](../../src/cli.rs)), so the corpus can be loaded at start —
subject, and this is the honest caveat, to §1's finding that the load is a union
and not a set of separable captures.

So the feature is worth building only for an operator who runs sipnab as a
long-lived HTTP service, over a corpus too large or too heterogeneous to union,
and who is willing to pay for a ported `pcap-load` design. That operator may
exist. Nobody has asked to be them.

### What goes wrong if someone builds it anyway

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

### Decision, and what would change it

**Declined.** Not on "it mutates state" — `shutdown_server` retired that argument
— but because the cheapest correct alternative (restart with a different `-I`) is
free in two of three deployment shapes, and because the tool cannot report what it
did without a capture identity sipnab does not have.

**Reopen when both of these are true:**

1. **Persistent HTTP MCP is a primary deployment shape**, evidenced by an
   operator running it that way and hitting the dead end — not by it being
   listed as possible. This is the load-bearing condition; everything else is
   engineering.
2. **`CaptureContext` is shared rather than per-session**, and its identity is
   visible in tool responses. That is roughly the same change §2 requires and
   §1 needs a stronger version of, so if any of the three moves, this one gets
   cheaper.

A narrower tool would be worth considering sooner and does not carry any of the
above: **`capture_sources` (read-only)** — report the *full* resolved `-I` set
rather than `primary_input()`'s first element, with each file's first-packet
timestamp. `input_set::resolve` already computes that timestamp into
`ResolvedInput.first_packet` ([`input_set.rs:88-97`](../../src/capture/input_set.rs))
and `bootstrap` then throws it away —
[`bootstrap.rs:182`](../../src/app/bootstrap.rs) is
`resolved.into_iter().map(|r| r.path).collect()`. An agent's actual complaint in
the persistent case is usually *"I do not know what I am holding"*, and that is
the tool for it. It is Tier 1 by the roadmap's own criterion — *"the agent
cannot see its own context"* — and it mutates nothing.

---

## Reopening conditions, in one place

| Decision | Reopen when |
|---|---|
| §1 Multi-capture comparison | Per-dialog capture provenance exists for another reason (most likely multi-device attribution reaching `SipDialog`) |
| §2 Write-back MCP tools | **Both**: a wire-visible store generation/etag, *and* a proposal that writes to an annotation store no analysis reads |
| §3 Threat-mitigation ledger | sipnab gains durable cross-run state — and only after the three blind spots in §3 are closed as ordinary defects |
| §4 `open_capture` | **Both**: persistent HTTP is a primary deployment shape in practice, *and* `CaptureContext` becomes shared and wire-visible |

None of these reopens on "someone asked again".
