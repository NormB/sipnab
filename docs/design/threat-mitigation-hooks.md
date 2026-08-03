# Automated threat mitigation

**Status:** DESIGN, with one hard rule that applies immediately (section 3).
**Verified against:** `63b771b` plus an uncommitted in-flight change to
`src/security/scanner_detect.rs` that section 4 describes and deliberately does
not cite by line, because it is moving.
**Relationship to [`deferred-and-declined.md`](deferred-and-declined.md) §3.**
That page covered the *action ledger* — a durable record of what sipnab did — and
deferred it behind a decision about cross-run persistence. This page is about the
question that comes before a ledger: **when may sipnab act at all.** §3 says the
record is missing. This page says the evidence bar is missing, and that the bar
is the more urgent of the two, because a ledger of wrong bans is still a list of
wrong bans.

## 1. The rule this document exists to state

**Automated mitigation multiplies the cost of a false positive into an outage.**

A detector that is wrong produces a wrong line in a log. Nobody is harmed, and
the next person to read the log discovers it. The *same detector*, wired to
fail2ban, produces a firewall rule. Wired to `--kill-scanner`, it produces SIP
responses aimed at the peer. Wired to `--alert-exec`, it produces whatever the
operator's script does, which in practice is a ban.

Everything downstream is unchanged. The only thing that changed is who acts on
the output, and that single change converts a false positive from a nuisance into
a severed trunk. The peers a SIP analyser sees most of are, by construction, the
ones sending the most traffic — which on a carrier network are the carrier's own
SBCs, the PBX, and the busiest customer phones. **A signature that ranks by
volume ranks your own infrastructure first.** Any automated response therefore
inherits an obligation the alerting path does not have, and this document is
about what that obligation is.

Two shipped defects make the point better than an argument does, and neither was
hypothetical.

## 2. What went wrong, twice

### `--fail2ban` handed over the trunk

`--fail2ban` shipped for a long time emitting a line for **every SIP request**,
with no detector anywhere in the path. The flag exists to feed a tool whose only
job is to ban what it is given.

Measured on ordinary carrier traffic and recorded in commit `56c6645`: **4,611
lines naming 180 distinct peers from an 11-second capture** — the carrier's SBCs,
the PBX, and customer phones. A golden test pinned the behaviour in place,
expecting a "detection" for a normal call's INVITE, ACK and BYE.

The fix removed per-message emission from both output paths. Today exactly three
sites emit, all behind a detector, all in
[`src/app/batch.rs`](../../src/app/batch.rs): a scanner detection (`:1860`), a
`-K/--kill-target` match (`:1909`), and a registration flood (`:1967`).

The fix also had to handle a second-order problem, and the handling is worth
copying. `--fail2ban` on its own now arms no detector, so it emits nothing — and
an operator who asked for a jail log and receives an empty file will read it as
"nothing attacked me". That is the most dangerous way for a security tool to be
silent, so it says so, once, at startup
([`batch.rs:721-728`](../../src/app/batch.rs)):

> "--fail2ban writes scanner detections, but no detector is running, so this run
> will emit nothing. An empty jail log means 'nothing was detected', not
> 'nothing happened'. […]"

**The generalisable lesson: a mitigation path that produces no output must say so
out loud, because silence on a security surface is indistinguishable from
safety.**

### The scanner signature convicts the PBX

The obvious repair for the above — arm the existing behavioural scanner detector
from `--fail2ban` — was measured before it was made, and the measurement is
recorded in the tree at [`batch.rs:698-706`](../../src/app/batch.rs):

> on a real carrier trunk […] produces 7008 detections naming 180 peers, because
> the behavioural signature counts OPTIONS and the busiest "scanners" are the
> carrier's own PBXes sending keepalives (2713 from one peer in 11 seconds).
> That is the same mass-ban as the blanket emission this replaced, only wearing
> the authority of a real detection.

That last clause is the finding. Replacing an obviously-broken output with a
plausibly-broken one is not progress; it is the same 180 bans with a detector's
name on them, which makes them harder to disbelieve.

The signature as committed counts REGISTER, OPTIONS and INVITE toward one
per-source counter
(`git show HEAD:src/security/scanner_detect.rs`, the method gate at its `:234`),
against `BEHAVIORAL_THRESHOLD = 10` (`:34`) and `ENUMERATION_THRESHOLD = 5`
distinct targets (`:41`) in a `BEHAVIORAL_WINDOW_SECS = 5` window (`:48`).
A device sending OPTIONS keepalives to 5 peers at better than 2 per second is
indistinguishable from a scanner under that rule — and that describes a healthy
SBC exactly.

## 3. The rule that follows, and it applies now

**A detector may not be wired to an automated response until its false-positive
behaviour has been measured against real traffic.** Not fixtures. Fixtures
contain what their author thought a scanner looks like; they do not contain the
carrier's keepalives, and both defects above were invisible to the entire test
suite.

This is already how the tree behaves, and it should be written down as policy
rather than left as a judgement call that happened to go well once. The
`scanner_detector` is `Some` only when the kill path is active
([`batch.rs:707-716`](../../src/app/batch.rs)), and the comment above it declines
to arm it from `--fail2ban` "until the signature can tell a keepalive from an
enumeration". That is the rule being applied. Section 4 is what it takes to
satisfy it.

## 4. What a defensible signature looks like

Volume is not evidence. A busy peer is a busy peer. The distinguishing property
of a scanner is not that it sends many requests but that **its requests do not
land** — it probes addresses that do not exist, credentials that do not work,
extensions nobody answers. That is an *outcome* signal, and it requires reading
responses, which a volume counter does not do.

Work in flight on `src/security/scanner_detect.rs` (uncommitted at `63b771b`,
owned by another change, cited without line numbers because they are moving)
takes exactly this shape, and its structure is the right one regardless of where
that particular change lands:

- **Outcome gating.** Volume alone can no longer fire. A source must additionally
  show rejections, or show that a majority of its probes went unanswered.
- **Transaction keying.** Probes are counted per top-`Via` branch, so
  retransmissions of one request count once. A retransmitting phone behind a
  lossy link was previously indistinguishable from a prober.
- **A benign-response list.** A 401 or 407 is a *challenge*, not a rejection —
  it is the normal first half of an authenticated REGISTER. Counting it as
  evidence convicts every correctly-behaving phone on the network. 408, 480,
  486, 487, 488, 491, 600 and 603 are likewise ordinary call outcomes.
- **An established-peer multiplier.** A source that has completed a registration
  or a call has proved it belongs on the network. Requiring several times more
  evidence before convicting such a peer is the single highest-value rule in the
  list, because it is what separates the customer's phone from the stranger's
  scanner, and it is cheap.
- **Request-only captures stand down.** If no responses were captured at all,
  every probe looks unanswered, and the unanswered signal must be disabled
  outright rather than firing on the busiest peer. This case is not exotic — a
  one-direction span port produces it.

**The gap that remains, and it is the important one.** Two untracked corpus
tests exist (`tests/scanner_signature_corpus_test.rs`,
`tests/zz_scanner_measure.rs`), both gated on a `SIPNAB_CORPUS` environment
variable and skipping silently when it is unset. The first asserts *soundness*:
no behavioural alert may name a source unless the capture itself shows the
rejections or unanswered probes to support it, and no alert may name a peer that
completed a registration or a call and whose probes were mostly answered. Those
are the right assertions and they would have caught both defects in section 2.

They are also **one-sided**. Neither measures recall, because there is no
labelled corpus of known scanners to measure it against. A signature that
alerted on nothing at all would pass both tests. That is an acceptable state for
an *alerting* path, where the cost of a miss is a missed alert. It is not
acceptable as the sole evidence for arming an automated response, because a
detector tuned only against false positives drifts toward silence, and section 2
already established that silence on this surface reads as safety.

## 5. The evidence threshold: act, or tell a human

Two tiers, and the boundary is not about detector confidence. It is about
**whether being wrong is recoverable.**

### Tier 1 — alert a human. The default for everything.

Every detection reaches `tracing::warn!` under the `sipnab::alert` target
([`alerting.rs:323`](../../src/security/alerting.rs)), optionally a JSON line on
stderr, optionally syslog, and the in-memory findings ring buffer
(`DEFAULT_FINDINGS_HISTORY = 1000`, [`alerting.rs:138`](../../src/security/alerting.rs)).
Being wrong here costs a log line.

**Everything belongs in tier 1 unless it meets every condition in tier 2.**

### Tier 2 — act automatically. Four conditions, all required.

**(a) The evidence is an outcome, not a volume.** Section 4. A count of requests
is not evidence, no matter how large. This condition alone disqualifies the
committed scanner signature.

**(b) The evidence is a property of the traffic, not of a threshold.** A rule
that fires on "more than N in T seconds" is a rule whose correctness depends on
N and T matching a network nobody measured. `-K/--kill-target`, by contrast, is
an operator naming an address: the operator supplied the evidence, and the
detector has no opinion. That is why `-K` is defensible on a signature the
behavioural detector is not.

**(c) The action is proportionate and self-limiting.** The kill path already
does this and the numbers are the model: a global limiter at
`DEFAULT_RATE_LIMIT = 10` per second
([`process_isolation.rs:971`](../../src/process_isolation.rs)) and a
per-destination limiter at `MAX_PER_DST_PER_MINUTE = 3`
([`:712`](../../src/process_isolation.rs)), both applied before any send. The
per-destination cap is the one that matters: it bounds the damage to *one* peer
when the signature is wrong about that peer, which is the failure that actually
happens. A global-only limiter would happily spend its whole budget on a single
misidentified SBC.

**(d) The blast radius is bounded and reversible.** A SIP `200 OK` at a scanner
is a transaction reply. A firewall ban is a state change on another system with
its own lifetime, and sipnab neither sets nor knows that lifetime. This is why
`--fail2ban` deserves a *higher* bar than `--kill-scanner` despite looking more
passive: the kill path's effect ends with the transaction, and the ban outlives
the process that asked for it.

And the standing rule that already holds across all of it: **every arming flag
is off by default** — `--kill-scanner`, `-K`, `--hep-allow-kill`, `--fail2ban`,
`--alert-exec`, `--on-dialog-exec`, `--on-quality-exec`
([`cli.rs:645-798`](../../src/cli.rs)). Nothing in this document proposes
changing that, and nothing should.

## 6. Three blind spots that make the tiers unverifiable

[`deferred-and-declined.md`](deferred-and-declined.md) §3 filed these as ordinary
defects to be closed independently of any ledger. They are restated here with
their current state, because a threshold nobody can audit is not a threshold.

**Per-event outcomes are unobserved in production.** The kill worker produces a
`KillResponse` — `Sent`, `RateLimited`, `Rejected { reason }`, `Error { message }`
([`process_isolation.rs:330-345`](../../src/process_isolation.rs)) — and offers
it on a 256-slot channel. Commit `56c6645` fixed the serious half of this: the
offer is now `try_send`, and a full channel calls `note_unobserved_outcome()`
([`:461`](../../src/process_isolation.rs), fired at [`:849`](../../src/process_isolation.rs))
instead of blocking. Before that fix, outcome 257 stalled the worker, which
stopped draining requests, which blocked `send_kill` on the capture thread while
it held the dialog and stream write locks every MCP tool reads — a wedge of the
entire surface. Outcomes are now also booked in an atomic `KillTally`
([`:408`](../../src/process_isolation.rs)) before being offered, so totals
survive and are logged at shutdown (`log_totals`, [`:621`](../../src/process_isolation.rs)).
What remains: nothing in `src/` calls `try_recv_response()`
([`:593`](../../src/process_isolation.rs)) or `counts()`
([`:582`](../../src/process_isolation.rs)) — the only callers are two integration
tests. Per-event attribution is still unavailable while a run is in progress.

**Suppressed event-exec actions were completely silent — now fixed.**
`check_rate_limit` returned `false` and both callers simply returned. No log, no
counter, no finding. Only the queue-depth drop warned (`MAX_QUEUE_DEPTH = 100`).
So with the default `--exec-rate-limit 10`, the eleventh event of a second
vanished without trace — and a flood is exactly when the eleventh event matters.
Both callers now book the suppression in `ExecOutcomeCounts::rate_limited`, the
queue-depth drop books `queue_full`, and a failed spawn books `spawn_failed`; the
teardown line states all three.

**Hooks that ran were never checked — now fixed.** `reap_action` was
`Ok(Some(_)) => ReapAction::Remove`: the child's exit status was matched with a
wildcard and discarded. sipnab ran `sh -c <operator command>` and never learned
whether the ban it asked for happened. A failing hook and a succeeding one were
indistinguishable — measured, before the fix, as ten seconds of a hook exiting 7
producing an empty log.

`ReapAction::Exited` now carries the `ExitStatus` out of the reaper, and each
finished child is booked as `succeeded`, `failed` or — when the status check
itself errors — `unknown`. A failure warns with the exit status **and the command
template that produced it**, because "a command exited 7" is not actionable and
"`nft add element …` exited 7" is. The warn escalates by order of magnitude, the
same way `--alert-exec` reports its suppressions, so a hook broken at packet rate
does not turn the log into the flood it is reporting; `Drop for EventExecEngine`
states the exact totals. Nothing is retried and nothing aborts the capture — a
failing hook is reported and otherwise ignored, per section 5's rule that the
evidence must survive the conditions under which a response matters most.
`EventExecEngine::outcomes` exposes the same ledger during a run.

**A fourth, not previously recorded — now fixed.** `--alert-exec` had **no rate
limit at all.** It lives in `alerting.rs`, not `event_exec.rs`, and shared none
of that module's limiting. Its only bound was a hardcoded cap of 100 concurrent
children, over which the alert dropped with a warning. The cooldown in
`AlertRule` is per `(source IP, rule name)`, which bounds repeats against *one*
source and does nothing against many, and `--exec-rate-limit` did not reach this
path. A detector naming 180 peers therefore spawned against all 180 — precisely
the shape of both defects in section 2.

It now carries two budgets, both in capture time: 10 per second globally, which
is `--exec-rate-limit`'s own default and the kill worker's `DEFAULT_RATE_LIMIT`,
and 3 per minute per source IP, which is the kill path's
`MAX_PER_DST_PER_MINUTE` that section 5(c) below already named as the model. The
per-source check runs first, so a noisy source never spends the shared window.
Every alert still fires. Only the command is held back, and the teardown line
counts the suppressions by reason.

**Keep this measurement when designing the next limiter.** On `tg.pcap0` —
43,300 messages over 11.165 s — the fix took 231 spawns down to 24. All 207
suppressions came from the **per-source** cap and none from the global one. The
obvious fix, a single global rate limit, would have changed nothing on that
traffic. Only a real capture showed that. A synthetic flood from one address
would have made the global limiter look sufficient.

**And the record itself cannot answer the question.** `Finding`
([`alerting.rs:143-152`](../../src/security/alerting.rs)) carries `rule_name`,
`src_ip`, `detail` and `timestamp`, and **no field recording whether an action
was taken.** Findings are written after the cooldown check
([`:307-317`](../../src/security/alerting.rs)), so suppressed firings are absent
from history. Asked "did we ban this peer, and why", sipnab today cannot answer
from its own state.

## 7. Recommendation

**Close the blind spots first, as ordinary defects, before building anything
new.** Log the event-exec rate-limit drop — **done**. Check the child's exit
status — **done**. Expose the kill tally during a run rather than only at
shutdown — **done**: `ScannerKillHandle::counts` returns the live snapshot and
does not depend on anyone draining the outcome channel. These were small, they
improved today's `tracing` output on their own, and no threshold in section 5
could be verified from the outside until they were.

The fourth item on that list — giving `--alert-exec` a real rate limit — is
**done**, and section 6 records both what shipped and the measurement that
picked per-source over global. One wiring remains: `--exec-rate-limit` still
does not reach the alert path, so the global budget sits at its default and the
flag stays inert there.

**Do not add new automated-response wiring in the meantime.** Specifically: do
not arm the behavioural scanner detector from `--fail2ban`, and do not add a
mitigation hook to the alert engine, until section 4's outcome-gated signature is
committed *and* measured against a real corpus for both false positives and
recall. Section 2 is what happens otherwise, twice.

**Then, and only then, consider the ledger** — on the terms
[`deferred-and-declined.md`](deferred-and-declined.md) §3 already set, which
require a decision about durable cross-run state first. That ordering is not
arbitrary. A ledger's whole value is that an absent entry means the action did
not happen; built today, it would faithfully record sends and silently omit
rate-limited drops, silent exec suppressions and failed hooks. An operator
reading "no entries" as "nothing was suppressed" would be wrong in exactly the
case they are investigating.

**What would change this.** A labelled corpus — real traffic with known scanners
marked — measured for both false-positive and false-negative rate against a
candidate signature. That artefact is the missing prerequisite for every
automated-response decision on this page, and it is worth building before any of
them.
