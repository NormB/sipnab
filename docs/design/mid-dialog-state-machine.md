# The mid-dialog state machine

**Status:** DESIGN. Nothing here is implemented.
**Verified against:** `3267b08`, working tree.
**Backlog:** [`backlog.md`](backlog.md) **PR1**, the defect content at `:539-586`.
**Pinned by:** `a_capture_beginning_mid_dialog_reports_trying_a_known_defect`
([`arrival_order_parity_test.rs:389`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L389)).

**Read `15b6337`'s commit message before this page.** Its closing sentence is the
constraint everything below is written under:

> Landing a half-modelled state machine in the code that decides whether a call
> is up is worse than the bug it closes.

**One correction to where this lives.** The defect is routinely referred to as
being in [`src/sip/message.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/message.rs). It is not — that file has no state dispatch at
all. Everything below is [`src/sip/dialog.rs`](../../src/sip/dialog.rs), with the
creation-branch call site in
[`src/sip/dialog_store.rs`](../../src/sip/dialog_store.rs).

## 1. The defect, in four lines of code

```rust
pub fn update_state(dialog: &mut SipDialog, msg: &SipMessage) {
    match dialog.method {
        SipMethod::Invite => update_invite_state(dialog, msg),
        SipMethod::Register => update_register_state(dialog, msg),
        SipMethod::Subscribe => update_subscribe_state(dialog, msg),
        _ => update_generic_state(dialog, msg),
```

[`dialog.rs:353-362`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L353-L362). `SipMethod::Bye` and
`SipMethod::Cancel` fall into `_`.

`dialog.method` is set once, by `SipDialog::new`
([`dialog.rs:285-297`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L285-L297)), from the request's own method
when the first message is a request and from CSeq when it is a response — and the
rustdoc at [`:269-284`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L269-L284) says plainly that it is *"set
once here and never corrected"*. A leading response is therefore safe: CSeq says
INVITE, so the INVITE machine is selected. A leading **request** that is not an
INVITE is not.

`update_generic_state` ([`dialog.rs:572-586`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L572-L586)) opens
with `if !msg.is_request`, so every later *request* is a no-op, and its last arm
discards `ResponseClass::Cancelled` — a 487 changes nothing. A capture that opens
on a CANCEL therefore reports `Trying` forever.

That is most captures on a busy server. Starting a capture while calls are
already up is the normal way this tool is used.

### What it costs, which is more than a wrong label

`Trying` is in the **active** set
([`dialog_store.rs:876-886`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L876-L886)) and is not `InCall`,
so a mid-dialog-seeded call is wrong in both directions on the two numbers
operators graph: counted in `active_dialog_count` forever, invisible to
`active_call_count` ([`:910-915`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L910-L915)), whose doc calls
it *"the concurrent-call figure — the one that maps to channels in use, to a
carrier's simultaneous-call limit, and to the alert an operator actually
wants."*

And two security detectors are **silently off** for every such call.
`record_if_short_call` — wangiri detection — takes an early `return None` unless
the dialog is `Completed | Cancelled`
([`fraud_detect.rs:267-275`](https://github.com/NormB/sipnab/blob/main/src/security/fraud_detect.rs#L267-L275)), and
`record_if_refused_call` — the sequential-scan signal — unless it is `Failed`
([`:324`](https://github.com/NormB/sipnab/blob/main/src/security/fraud_detect.rs#L324)). A wrong state does not merely
mislabel a row; it turns off two detectors with no error anywhere.

**Both gates have a second clause that §6 has to come back to:**

```rust
if dialog.method != crate::sip::SipMethod::Invite
    || !matches!(dialog.state(), DialogState::Completed | DialogState::Cancelled)
```

They test `dialog.method` as well as the state.

Also affected: `Result: Trying` in the text report
([`call_report.rs:276-283`](https://github.com/NormB/sipnab/blob/main/src/output/call_report.rs#L276-L283)); a dialog counted
in none of the three outcome buckets in every machine-readable summary
([`api.rs:936-938`](https://github.com/NormB/sipnab/blob/main/src/output/api.rs#L936-L938)); an empty result set for
`state == "Cancelled"` in the filter DSL
([`dsl.rs:1374-1378`](https://github.com/NormB/sipnab/blob/main/src/sip/dsl.rs#L1374-L1378)); and an ended call rendering amber
"in setup" indefinitely in the TUI, where `Trying` shares an arm with `Ringing`
and `Pending` ([`timeline.rs:472`](https://github.com/NormB/sipnab/blob/main/src/tui/timeline.rs#L472)).

## 2. Why the obvious fix failed five times

The obvious fix is to dispatch on the method a request *implies* — a BYE or a
CANCEL cannot open a dialog ([RFC 3261 §9](https://www.rfc-editor.org/rfc/rfc3261#section-9), §15), so it belongs to an INVITE. The
backlog is right that this *"is almost certainly the right shape"*. Here is why
routing to `update_invite_state` on its own makes things worse.

`update_invite_state` has two kinds of arm. The **request** arms are unguarded
and fire from any state ([`dialog.rs:390-395`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L390-L395)):

```rust
Some(SipMethod::Cancel) => { dialog.state = DialogState::Cancelled; }
Some(SipMethod::Bye)    => { dialog.state = DialogState::Completed; }
```

The **response** arms are all guarded on `cseq_method == "INVITE"` — four of
them, at [`:438`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L438), [`:459`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L459),
[`:485`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L485) and [`:494`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L494). A
BYE-seeded dialog's responses carry `CSeq: n BYE`. So routing a BYE-seeded dialog
into the INVITE machine gains the two request arms and **loses every response
arm**. That is the backlog's *"leaves cells unmodelled rather than filled"*,
stated mechanically.

The last narrowing's failing cell reproduces by construction rather than by
inference: for `method = "BYE"`, `code = 300`, the prover's expectation table
falls into its `_ =>` family arm and declares `Redirect → Redirected`
([`dialog.rs:967-972`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L967-L972)); the implementation reaches the
3xx arm whose guard is `cseq_method == "INVITE"`, false for `CSeq: 1 BYE`, so the
state stays `Trying`. Verbatim the backlog's *"a BYE dialog in `Trying` receiving
`300` stayed `Trying` instead of reaching `Redirected`."*

### The deeper reason there was a different cell each time

`every_method_and_class_has_a_declared_transition` is a **differential between two
hand-written tables**. `expected()`
([`dialog.rs:940-974`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L940-L974)) is keyed on the dialog's method
string, grouped into exactly the four families the dispatch uses; the
implementation is keyed the same way. Change the dispatch and family membership
changes — so a *different* `(family, class)` pair falls out of agreement, and the
prover reports a different cell. Five narrowings, five cells.

The trap that follows is the one worth naming: the way to make it green is to
edit `expected()` to match the new dispatch, at which point the prover has stopped
stating a rule and started restating the implementation. It would be green and it
would prove nothing. **This is the failure mode the spec has to design around,
and it is not fixed by trying harder at the same shape.**

### There is no revert diff

[`src/sip/dialog.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs) has not been touched since `82abe03` (2026-08-03), three days
before the attempts. The five narrowings lived in a working tree and were never
committed. The surviving record is PR1 in the backlog and `15b6337`'s message —
and now this page. Nobody picking this up can read the code that failed.

## 3. The central design decision: the dispatch key is wrong

`dialog.method` answers *"what opened this dialog, as far as we saw"*. The state
machine needs to answer a different question: **which transaction does the
arriving message belong to?**

For a response, that is its **CSeq method**. For a request, it is its own method.
Neither is `dialog.method`.

Read the four guards again in that light. `cseq_method == "INVITE"` is not a
guard at all — it is a **dispatch decision written inside the wrong function**.
It is there because the dispatch above it used the wrong key and the response
arms had to re-derive the right one locally.

So the proposal is:

```
family(msg) = family_of(msg.method)                if msg.is_request
              family_of(cseq_method(msg))          otherwise
```

and `update_state` dispatches on `family(msg)`, not on `dialog.method`. The four
`cseq_method == "INVITE"` tests then disappear from the response arms because
dispatch has already established the family. What stays behind in those arms is
the part that was always the real content — the **state** guards:

```rust
matches!(dialog.state, DialogState::Trying | DialogState::Ringing | DialogState::Cancelled)
```

That is the [RFC 3261 §9](https://www.rfc-editor.org/rfc/rfc3261#section-9)/§15 rule the domain primer already documents
([`domain-primer.md:168-180`](https://github.com/NormB/sipnab/blob/main/docs/internals/domain-primer.md#L168-L180)): once a final 2xx
has established the call, a CANCEL has no effect, so a late 487 must not
un-answer it.

Three consequences, all of which make the change smaller than it looks:

**`dialog.method` stays exactly as it is.** It remains the user-visible label and
is not relabelled. The backlog records that the first narrowing already had this
instinct — *"dispatch-only rather than relabelling the user-visible
`dialog.method`"* — and it was right. What that narrowing was missing was moving
the guards at the same time.

**The seed method's only remaining job is the initial state**
([`dialog.rs:293-296`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L293-L296)), and for the two methods that
matter it barely matters: since the creation branch now applies the creating
message's own transition ([`dialog_store.rs:654`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L654)),
a BYE-seeded dialog goes `Trying → Completed` on its own first message, and a
CANCEL-seeded one goes `Trying → Cancelled`. Which is exactly the outcome the
pinned defect test is waiting for.

**Two tests must change in the same commit, not afterwards.**
`a_capture_beginning_mid_dialog_reports_trying_a_known_defect`
([`arrival_order_parity_test.rs:389`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L389))
flips red **by design** — its own doc says *"When the dispatch fix lands
properly, this test FAILS — and that is the signal to replace it with the
convergence assertion it is standing in for."* And the `continue` at
[`:336-342`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L336-L342) that excuses the
`late_terminal` ordering must be deleted, or the convergence property is still
being skipped for exactly the case that was broken.

## 4. What "complete" has to mean here

### "Cannot occur" is almost always the wrong claim in a capture tool

A capture tool sees malformed and adversarial traffic by definition — scanner
detection is a shipped feature. Any (seed, arrival) pair can appear on a wire.
So a transition table whose completeness rests on cells marked *impossible* would
be asserting something about the world that the tool's own threat model denies.

The obligation is therefore stronger and simpler: **every cell declares a
transition or declares a no-change with a reason.** Three cell kinds:

| Kind | Meaning | How it is justified |
|---|---|---|
| `To(state)` | the arrival moves the dialog | an RFC rule, cited |
| `Stay(reason)` | the arrival is legal here and correctly changes nothing | a reason in the table, not a comment near it |
| `Unconstructible(reason)` | no input can reach this cell | proven by the enumerator failing to build it |

`Unconstructible` is reserved for cells the **constructor** refuses, not cells the
network is unlikely to produce. There is exactly one such family today, and it is
already load-bearing: a message with no CSeq and no method never reaches
`update_state` at all, because `SipDialog::new` returns `None`
([`dialog.rs:286-291`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L286-L291)). The existing prover already
guards this in miniature with its `pairs` count assertion
([`dialog.rs:1000-1006`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L1000-L1006)): *"a method stopped
constructing a dialog and its whole row went unchecked."*

### The coordinate is wrong on two axes, not one

**Axis 1 — CSeq method.** `make_response(code, "x", method)` emits
`CSeq: 1 {method}` ([`dialog.rs:647`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L647)) and is called with
the *dialog's* method ([`:988`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L988)). So the prover's
responses always carry a CSeq matching the seed. **The cells the fix has to get
right are cells the prover cannot currently generate.** The real mid-dialog shape
— a CANCEL-seeded dialog receiving a 487 whose CSeq is INVITE, which is precisely
what `a_capture_beginning_mid_dialog_reports_trying_a_known_defect` constructs
([`arrival_order_parity_test.rs:192`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L192)) —
does not exist anywhere in the 1050-cell sweep.

**Axis 2 — starting state.** The prover builds a fresh dialog per cell and applies
exactly one response, so `start` is only ever `Trying` or `Pending`
(the two `SipDialog::new` initial states,
[`dialog.rs:293-296`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L293-L296)). **The state axis is entirely
unexercised.** That is not a minor gap: three of the four INVITE response arms are
*state*-guarded, and the CANCEL-versus-200 race the domain primer documents —
`Cancelled → InCall` on a 2xx ([`dialog.rs:433-447`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L433-L447)) —
can never fire in the sweep, because a fresh dialog is never `Cancelled`. A rule
this project deliberately implemented and documented has no pairwise coverage at
all.

So the widened coordinate is:

```
(seed method, arrival, starting state)

arrival = Request(method)
        | Response(cseq_method, code)
```

with 14 methods ([`dialog.rs:913-928`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L913-L928)), 75 codes
([`:930-936`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L930-L936)), 7 response classes
([`response_codes.rs:26-42`](https://github.com/NormB/sipnab/blob/main/src/sip/response_codes.rs#L26-L42)) and 13 dialog
states ([`dialog.rs:23-58`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L23-L58)).

`SipMethod::Custom(Box<str>)` ([`method.rs:47`](https://github.com/NormB/sipnab/blob/main/src/sip/method.rs#L47)) is the
one arm that cannot be enumerated. It gets **one declared cell** with a stated
reason, not a wildcard escape — the distinction being that a declared cell is
something a reader can disagree with.

## 5. How completeness is proven, rather than asserted

Five obligations. The first is the one that does the real work; the rest exist
because it is not sufficient on its own.

### O1. Totality is proven by the compiler, not by a test

Express the arrival as a type and write the transition function as a `match` with
**no wildcard arm** at the family and class level:

```rust
enum Arrival<'a> {
    Request(&'a SipMethod),
    Response(&'a SipMethod /* CSeq method */, ResponseClass),
}

fn transition(family: Family, arrival: &Arrival, state: &DialogState) -> Cell;
```

A wildcard is exactly how a cell goes unmodelled — it is what `_ =>` at
[`dialog.rs:358`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L358) did, and what the `_ =>` family arm in
`expected()` ([`:967`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L967)) does. Remove the wildcards and
adding a `DialogState` variant or a `ResponseClass` variant becomes a compile
error at every cell it affects, which is a stronger and cheaper guarantee than
any test. `#[non_exhaustive]` on `DialogState`
([`dialog.rs:22`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L22)) does not obstruct this: it constrains
downstream crates, not matches inside the defining crate.

This obligation is what turns "budget for completing the INVITE machine's guard
set" from an estimate into a bounded task: the compiler enumerates the remaining
work.

### O2. Widen the prover before touching the machine

Add both axes from §4 to
`every_method_and_class_has_a_declared_transition` **first**, with the current
implementation unchanged. It will fail, and the cells it fails on are the
specification of the fix. That ordering is this project's TDD rule and it is also
the only way to get a red test that means something: widening the coordinate
after the fix would be writing the test to the answer.

Cell counts at the widened coordinate — responses `14 × 14 × 75`, requests
`14 × 14`, each crossed with reachable starting states — are large but the
existing sweep already drives 1050 cells, and the enumerator is cheap.

Keep the `pairs` anti-vacuity count and raise it to the new total. Add a second
anti-vacuity guard the current prover does not have: **a coverage bitmap over the
declared table, asserting every declared cell was actually reached.** A table
entry nobody exercises is indistinguishable from a typo, and the difference
between a complete table and a complete-and-exercised one is the whole subject of
this page.

### O3. Do not rebuild the differential that failed

§2 established that the prover is a differential between two hand-written tables
and that the fix moves one of them. Rebuilding that arrangement at a wider
coordinate reproduces the failure at greater expense.

**Recommendation: the implementation reads the declared table**, and the prover
asserts **properties of the table** rather than agreement with a second copy of
it. Properties, each a quantified statement over every cell:

- **Terminal states are absorbing for the wrong family.** No arrival whose family
  differs from the dialog's may move `Completed`, `Cancelled`, `Failed`,
  `Expired` or `Terminated`. This is the rule the four `cseq_method == "INVITE"`
  guards were expressing, stated once instead of four times.
- **No cell moves an answered call back to a pre-answer state.** Nothing may take
  `InCall` to `Trying` or `Ringing`.
- **The 2xx/CANCEL race resolves one way.** A 2xx in the INVITE family from
  `Cancelled` reaches `InCall`; no 487 may move `InCall`. [RFC 3261 §9](https://www.rfc-editor.org/rfc/rfc3261#section-9) and §15,
  and [`domain-primer.md:168-180`](https://github.com/NormB/sipnab/blob/main/docs/internals/domain-primer.md#L168-L180).
- **Provisional and Challenge never decide an outcome.**
  `ResponseClass::Provisional` and `ResponseClass::Challenge` may only produce
  `To(Ringing)` or `Stay(_)` — never a terminal state.
- **Every `Stay` carries a reason string**, checked non-empty at table-build
  time. This is the mechanism that makes "a declared reason it cannot occur" a
  gate rather than a convention.

A property gate can fail on a table nobody hand-wrote a second time, which is
precisely what the differential could not do.

### O4. Corpus differential — the acceptance gate

The fix changes state for real captures, so the acceptance evidence is a
before/after over the reference corpus at `/home/gator/pcaps`: every dialog's
state before, every dialog's state after, and **every change attributable to a
declared cell**. A state change nobody can point at a cell for is a failure of
this spec, not a surprise.

Anything less than 100% on that corpus is a critical failure by this project's
own standard. The corpus is outside the repository and neither it nor any
identifier derived from it may be committed.

**Not done.** No corpus run has been performed for this page.

### O5. The arrival-order gate closes with the fix

`arrival_order_parity_test.rs` currently pins the defect twice — the XFAIL at
[`:389`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L389) and the `continue` at
[`:336-342`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L336-L342). Both are deleted as part
of the change, and `arrival_order_converges_when_the_invite_machine_is_selected`
becomes unconditional. If it cannot be made unconditional, the fix is not
finished — that test is the statement of the property this whole exercise exists
to obtain.

PR1's own constraint lifts at the same moment: *"Until that is fixed, N parallel
readers **must** preserve per-dialog ordering, or sort before the worker's state
machine sees the messages."*

## 6. What this does not fix

- **`dialog.method` still says `BYE` for a call that was an INVITE dialog.** The
  label is deliberately left alone (§3), following the first narrowing's
  instinct. That looked like a cosmetic deferral when this page was drafted. The
  third bullet below shows it is not.
- **Operator-visible numbers move.** `active_dialog_count` falls and
  `active_call_count` behaves differently on any capture that began mid-dialog.
  That is the defect being fixed, and it will read as a regression on somebody's
  dashboard. It belongs in the release notes, not in a footnote.
- **The two fraud detectors stay off, and that is a defect this change does not
  close.** Both gates open with `dialog.method != SipMethod::Invite`
  ([`fraud_detect.rs:268`](https://github.com/NormB/sipnab/blob/main/src/security/fraud_detect.rs#L268),
  [`:324`](https://github.com/NormB/sipnab/blob/main/src/security/fraud_detect.rs#L324)). §3 deliberately leaves
  `dialog.method` reading `BYE` or `CANCEL` on a mid-dialog-seeded call, so those
  calls fail the *first* clause however correct their state becomes. Wangiri and
  sequential-scan detection remain silently disabled for exactly the population
  this page is about.

  That makes "should `dialog.method` be corrected" load-bearing rather than
  cosmetic (§7). Three ways out, none free: relabel `dialog.method` once the
  dialog's family is known and accept a user-visible change plus whatever the
  first narrowing was avoiding by not doing it; give `SipDialog` a separate
  `family` field and re-gate the detectors on that; or leave both and record the
  detectors' blind spot as a known defect with its own pinned test, the way this
  one was. **The third is the only one that is honest if the first two are not
  done in the same change** — shipping a correct state machine while two
  detectors quietly ignore the calls it fixed would recreate the shape
  `15b6337` warned about, one layer out.
- **`DialogState` is public API.** It is re-exported at
  [`lib.rs:110`](https://github.com/NormB/sipnab/blob/main/src/lib.rs#L110) and is `serde::Serialize`, so any new variant
  is a semver event. `#[non_exhaustive]` leaves room to add one; §7 has the
  question of whether one is needed.

## 7. Open questions

- **Does `dialog.method` have to be corrected after all, and if so how?** §6's
  third bullet turns this from a presentation choice into a correctness one: two
  fraud detectors gate on it, and leaving it alone leaves them off for the
  population this change exists to fix. Relabelling is what the first of the five
  narrowings deliberately avoided, and the record does not say what it was
  avoiding — the diff was never committed. **Whoever picks this up has to decide
  this without that evidence.** A separate `family` field on `SipDialog` sidesteps
  the user-visible change and costs a field on a hot struct; nobody has priced it.
- **What state should a dialog seeded by a mid-dialog re-INVITE, in-dialog
  OPTIONS, or INFO start in?** The capture may begin at any point. `InCall` is
  arguably right — those messages only occur within an established dialog — but
  nothing *observed* proves the call was answered, and asserting `InCall` from an
  unobserved 200 OK invents an event. The alternatives are `Trying` with a
  declared reason (honest, and wrong on a dashboard) or a new variant meaning
  "observed mid-dialog, outcome unknown" (honest, and a public-API change). **Not
  decidable from the code. This is the one open question that could change the
  shape of the fix.**
- **Which family does each method belong to?** INVITE, ACK, CANCEL and PRACK are
  clearly the INVITE family; REGISTER and SUBSCRIBE have their own machines
  today. NOTIFY, REFER, UPDATE, PUBLISH, INFO and MESSAGE are not obviously
  assigned by anything in the current code — the existing `_` arm has never had
  to decide. Each needs an RFC citation, not a preference.
- **Does the dialog's own family need inferring at all, or only the arrival's?**
  §3 dispatches purely on the arriving message. That may be sufficient, in which
  case `Family` is a property of the message and never of the dialog, and the
  transition function's first parameter disappears. Not resolved here, and it
  changes the table's shape.
- **How many of the widened cells are genuinely reachable?** The count in §4 is
  arithmetic, not a claim about traffic. The coverage bitmap in O2 will answer
  it, and the answer decides whether the table can be hand-written or has to be
  generated.
- **Should `expected()` survive at all?** O3 recommends replacing the differential
  with property assertions. If some differential is kept for cells whose rule is
  genuinely per-cell rather than per-property, the trap in §2 reopens for those
  cells and needs its own answer.
- **Does the merge path need the same treatment?** `update_state` has a third
  call site on the absorb/merge path
  ([`dialog_store.rs:1269`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1269)), and
  `merge_recovers_timestamp_order_from_permuted_stores`
  ([`arrival_order_parity_test.rs:416`](https://github.com/NormB/sipnab/blob/main/tests/arrival_order_parity_test.rs#L416))
  shows the offline merge is order-tolerant today. Whether it stays so under a
  dispatch keyed on the arriving message has not been checked.
