# SIP problem diagnosis

**Status:** detections 1–3 implemented in [`src/sip/diagnosis.rs`](../../src/sip/diagnosis.rs)
and rendered on every surface in the table below; detections 4–7 remain specified
and unbuilt, per the build order at the end of this document.
**Complements:** [`src/rtp/diagnosis.rs`](../../src/rtp/diagnosis.rs), which does
the same job for the media side.

sipnab can already tell you a call had one-way audio, a NAT mismatch, or media
that never arrived. It cannot tell you the call failed because the far end
answered `503` after three retransmitted INVITEs, or that a phone has been
looping on `401` for an hour without ever authenticating. The signalling
evidence is all captured — it is simply never read as a diagnosis.

This spec scopes that: what is detected, what shape it takes, and where it
renders. It follows the media side's design closely, because the value of
`MediaDiagnosis` is not the detections themselves but that every surface —
`--json`, the REST API, MCP, the call report, the TUI — reads one structure.

## Principle: evidence, not verdicts

Every detection names the messages it is drawn from. A diagnosis that says "auth
loop" and cannot say *which* 401s is a guess the reader has to re-derive by
hand, and a capture tool exists to stop that.

Concretely: each detection carries the indices of the messages in the dialog's
own message list that triggered it. That keeps the payload small, survives
serialization, and lets any surface render "because of these four messages"
without a second lookup.

## The detection set

Ordered by how often they are the actual answer in a support queue, which is
also the order to build them.

### 1. Final failure with cause

A dialog that ended on a `4xx`/`5xx`/`6xx` final response. Records the code, the
reason phrase, and — where present — `Reason:` (RFC 3326) and
`Warning:`, which frequently carry the real cause when the status code is
generic.

**Why first.** It is the single most common question ("why did this call
fail?"), it needs no state beyond the dialog, and the answer is already sitting
in a header nobody reads.

### 2. Authentication loop

Repeated `401`/`407` challenges on the same dialog with no `2xx` reached.
Distinguish two shapes, because the fix differs:

- **Credential failure** — the UAC answers each challenge with an `Authorization`
  header and is challenged again. Wrong password.
- **Silent drop** — the UAC never sends `Authorization` at all. Usually a client
  that does not know the realm, or a proxy stripping the header.

Threshold: 2 challenges is normal (the first is unauthenticated by design). 3+
without a `2xx` is the signal.

### 3. Retransmission storm / no-response transaction

A request retransmitted per RFC 3261 §17 timers with no response — the classic
signature of a one-way network path or a dead peer. Detected by CSeq plus
identical branch on repeated requests.

Report the count and the elapsed span, since "7 INVITEs over 32 seconds" is
diagnostic and "retransmissions detected" is not.

### 4. ACK never received

A `200 OK` to an `INVITE` with no matching `ACK` within Timer H. RFC 3261 §17.1.1
makes this a definite fault, and it is invisible without correlation: both
sides look fine in isolation.

### 5. Abandoned / cancelled

`CANCEL` before a final response, or no final response at all before the capture
ended. The second case must be reported as *unknown*, not as failure — the
capture may simply have stopped. This is the detection most likely to lie if
written carelessly.

### 6. High post-dial delay

Elapsed time from `INVITE` to the first `18x`. Slow provisional responses are a
routing problem the caller experiences as dead air.

Threshold configurable, defaulting to a value chosen the way
`AsymmetryThresholds` was: an industry triage figure, not a round number picked
for looking reasonable.

### 7. Registration failure

For `REGISTER` dialogs: a final non-`2xx`, or an expiry so short the endpoint
will re-register immediately. Separate from call failure because the operator
question is different — "is this phone online?" rather than "why did this call
fail?".

## Shape

Mirrors `MediaDiagnosis`: one struct per dialog, every field optional, absent
meaning "not detected" rather than "not checked".

```rust
pub struct SignalingDiagnosis {
    pub final_failure: Option<FinalFailure>,
    pub auth_loop: Option<AuthLoop>,
    pub retransmissions: Option<Retransmissions>,
    pub ack_missing: Option<AckMissing>,
    pub abandoned: Option<Abandoned>,
    pub post_dial_delay: Option<PostDialDelay>,
    pub registration_failure: Option<RegistrationFailure>,
    /// Plain-language lines, one per detection above.
    pub hints: Vec<String>,
}
```

Each detection struct carries its own evidence indices. `hints` exists for the
same reason `MediaDiagnosis::hints` does: surfaces that render one line per
problem should not each re-invent the phrasing.

**One deliberate difference from the media side.** `MediaDiagnosis` uses `bool`
for its first three signals, which cannot distinguish "checked and absent" from
"never checked" — a distinction that matters once a detection can be disabled or
skipped for want of data. Every field here is `Option`, and absence means
detected-as-absent.

## Where it renders

| Surface | Rendering |
|---|---|
| `--json` / NDJSON | **Done** — `signaling_diagnosis` object beside the existing media one, omitted entirely when every field is `None` |
| REST API | **Done** — the same object, via `dialog_to_json`; no separate code path |
| MCP | **Done** — through `get_dialog_report`: the JSON format inherits the object, and the text and Markdown formats get the report section below |
| Call report | **Done** — a Signalling section in both text and Markdown, each detection with its evidence labelled by message rather than by index |
| TUI call list | **Done** — a `⚠` in the State cell. Note the spec said "in the style of the existing media badge"; there was no existing media badge, though the module documentation claimed one |
| TUI call flow | **Done** — a `[FAILURE]`/`[AUTH]`/`[NO-RSP]` tag on the arrow of each cited message. On the arrow, not in the annotation zone right of the ladder, which clips to roughly one column at 80 wide |

## What this must not do

- **No detection without evidence.** If a check cannot name the messages behind
  it, it is not ready to ship.
- **No verdict on a truncated capture.** "No final response" means the capture
  ended, or the call is still up, at least as often as it means a fault. Report
  the state, not a conclusion.
- **No new top-level flag.** This is a property of a dialog, computed alongside
  the media diagnosis, not a mode the user opts into.

## Build order

1, 2 and 3 carry most of the value and need no new plumbing — build, ship and
use them before touching 4–7. Each lands with its own detection tests over
fixture pcaps, in the pattern `rtp/diagnosis.rs` already establishes.
