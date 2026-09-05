# Machine-learning anomaly detection over SIP/RTP patterns

**Status:** DECISION, 2026-08-13. **Declined as specified, and re-scoped.**
Nothing implemented, and nothing here should be built as written: the model is
declined permanently, and so is the cross-run baselining this page proposed in
its place — on the positioning test, and on this page's own objection 2, which
it never turned on itself. One bounded piece survives, peer comparison inside a
single capture, which needs no store and is buildable today.
**Check:** `grep -rniE 'chi.square|baseliner' src/` exits 1 — no baseliner exists to anomaly-detect against.
**Check:** `grep -rniE 'rusqlite|sled|redb|sqlite' Cargo.toml` exits 1 — no store exists for a cross-run baseline to live in.
**Check:** `grep -c 'fn sample_baseline' src/security/fraud_detect.rs` prints 1 — within-capture baselining already ships, so the third answer below is not speculative.

The decision section at the end of this page carries that argument, in three
answers because the three questions have three answers. Everything above it is
the 2026-07-30 research, kept in the tense it was written, with correction notes
where the prose and the decision now disagree — the reasoning is the point of
this page, and a decision doc that back-edits itself teaches nothing.

Supersedes the one-line backlog entry "Machine-learning anomaly detection over
SIP/RTP patterns", which named a technique rather than a problem.

## The question the backlog entry skipped

"Anomaly detection" is a method. Before choosing one, the useful question is
what sipnab currently *cannot* tell an operator. The answer, after this
release, is narrower than it was:

| Question | Today | Gap? |
|---|---|---|
| Why did this call fail? | `final_failure` with `Reason`/`Warning` | no |
| Is this phone online? | `registration_failure` | no |
| Why is there no audio? | `MediaDiagnosis` — one-way, NAT mismatch, no media | no |
| Is this call slow to ring? | `post_dial_delay` vs E.721 | no |
| Is someone scanning me? | `scanner_detect`, `reg_flood`, `fraud_detect` | no |
| **Is this hour unlike the last hundred hours?** | — | **yes** |
| **Is this endpoint behaving unlike its peers?** | — | **yes** |

The seven signaling detections and the media diagnosis all answer *per-dialog*
questions with a rule. The gap is **population** questions: a call that is
individually unremarkable but collectively wrong — an ASR that quietly fell from
71% to 64%, a codec that started appearing on a trunk that never used it, a
gateway whose PDD distribution shifted a second to the right.

Every one of those is invisible to a per-dialog rule, because no single dialog
in the population is faulty.

## Why the obvious implementation is wrong

The tempting version is: featurize dialogs, fit an autoencoder or isolation
forest, flag high reconstruction error. It should be rejected, for reasons that
have nothing to do with model quality.

**1. It breaks the tool's core promise.** Every existing detection names the
messages it is drawn from — the spec's first load-bearing rule, enforced even on
third-party plugins. An isolation forest produces a score. "Dialog 4417 has
anomaly score 0.93" cannot be checked, argued with, or acted on, and an operator
who cannot verify a finding learns to ignore it. sipnab's value proposition is
*evidence, not verdicts*; an unexplainable score is precisely a verdict.

**2. It cannot be reproduced from a pcap.** A capture analyzed twice must give
the same answer — the property that motivated fuel metering over wall-clock in
the plugin host. A model introduces weights, a training set, and a version, none
of which live in the pcap. Two operators running the same command on the same
file would legitimately disagree.

**3. It has no ground truth to train on.** There is no labeled corpus of
"anomalous" SIP. Unsupervised training on live traffic learns whatever that
network does, including its faults — the model would flag a *fixed* network as
anomalous, having normalized the breakage.

**4. The dependency cost is disproportionate.** D7 rejected an embedded
scripting runtime on supply-chain grounds; a tensor runtime is a great deal
heavier than wasmi's 15 crates and 1.56 MB.

## What to build instead

> **Correction, 2026-08-13.** Two of these three are now declined. §1 and §3
> both put the comparison set outside the capture, which is the defect
> objection 2 above rejects the model for — see the decision. §2 survives
> intact, and is the only part of this page that should ever be written.

**Statistical baselining with named, checkable outputs.** Same operator value,
none of the four problems.

### 1. Population baselines

Track distributions per grouping key — trunk, gateway IP, User-Agent, called
prefix — over a rolling window:

- ASR (answer-seizure ratio)
- PDD percentiles
- Failure-code mix
- Codec mix
- Mean call duration

Report a *shift*, with both sides shown:

```
gateway 192.0.2.7: ASR 64% over the last 200 calls, against 71% over the
previous 2000 (p < 0.01, chi-square). Failure mix moved: 503 12% -> 31%.
```

That is checkable. An operator can pull the 503s and look. A score cannot be.

### 2. Peer comparison

Same-role endpoints should behave alike. A phone model whose registration
interval, PDD or failure mix diverges from the other 200 of its model is worth a
line — and the evidence is the peer set, which is nameable.

### 3. Seasonality, only where it earns its place

Traffic is strongly diurnal and weekly. A drop at 02:00 is not news. The cheap
form is comparing like periods (this Tuesday 14:00 against previous Tuesdays)
rather than fitting a model.

## Why this is honest about being statistics

Calling this "ML" would be marketing. Chi-square tests and rolling percentiles
are statistics, they are what the problem actually needs, and every output names
its evidence. If a genuine learning problem appears later — one with labels, and
where a shift test provably underperforms — that is the point to revisit, with
this document as the record of what was ruled out and why.

## Prerequisites, none of which exist yet

> **Correction, 2026-08-13.** Item 1 is not a prerequisite. It is the
> disqualifier, and calling it a prerequisite is what left this page reading
> like a plan waiting for one more thing to land. Items 2 and 3 are real and
> small, and item 2 has an answer that needs no modeling: group by the
> address a dialog already carries.

This is the real reason it is not next:

1. **Persistence across runs.** Baselines need history. sipnab is a
   single-capture process today: `[limits]` bounds tracked state, nothing
   survives exit. A store is a bigger architectural decision than the detection.
2. **A grouping key.** "Trunk" and "gateway" are not modeled; only
   `src_addr`/`dst_addr` exist.
3. **A statistics dependency, or hand-rolled tests.** Chi-square and a
   percentile tracker are small enough to write, which is preferable to a crate.

## Recommendation

> **Superseded 2026-08-13 by the decision below.** It was right to refuse the
> model and right that the honest version is not machine learning. It was wrong
> about which part to keep: §1 is the part that cannot be built in position,
> and §2 is the part that can.

**Do not schedule this.** It is correctly a P5. The prerequisites — persistent
state above all — are individually larger than the feature, and the honest
version of it is not machine learning.

If it is ever picked up, take population baselining (§1) alone. It is the whole
operator value, it needs no model, and every finding it produces can name its
evidence — which is the bar every other detection in this tool already clears.

## Decision, 2026-08-13

Re-checked against [`positioning.md`](positioning.md), which exists to decline
features that pull sipnab toward being a platform. Three questions are answered
separately below, because they have three different answers, and collapsing
them is how a page like this declines the useful part along with the rest.

### 1. The model, as specified: declined permanently

The four objections above hold. Positioning adds a fifth the 2026-07-30
analysis did not have, and it is the one that settles it.

Objection 4 measures the model in *crates*. The larger cost is the *release*.
A trained model is a second artifact: it ships beside the binary, it carries a
version that has to stay compatible with the binary's, it goes stale as the
networks it was fitted to change, and somebody has to retrain it on a cadence.
sipnab's distribution story is one static file an operator copies and runs. A
companion artifact fails the positioning test — *if a feature requires sipnab
to be operated rather than run, it is out of position* — at the distribution
layer rather than the runtime one, which is why an audit that counted
dependencies never surfaced it.

Recorded as declined rather than left unscheduled. An open item with a plan
attached comes back every quarter carrying the same arguments; this one now has
an answer and a trigger.

**What would reverse it:** a labeled corpus of anomalous SIP that somebody
else maintains and that ships separately from sipnab, *and* a demonstration
that a shift test underperforms on that corpus. Both halves are required.
Labels alone change nothing if the statistics already win.

### 2. Cross-run population baselines: declined, on this page's own objection

§1 proposed rolling baselines per grouping key as the honest replacement for
the model. That recommendation does not survive objection 2.

Objection 2 rejects the model because a capture analyzed twice must give the
same answer, and a model's weights, training set and version do not live in the
pcap. **A rolling cross-run baseline has exactly that defect.** "ASR 64% over
the last 200 calls, against 71% over the previous 2000" is a claim about 2200
calls, of which the file in front of the operator holds some fraction; the rest
lives in a store. Two operators run the same command on the same capture and
legitimately disagree — the sentence objection 2 already wrote, about a
different mechanism.

The page named the defect *a model*. The defect is *state outside the capture*,
and a baseline store is state outside the capture.

That reclassifies prerequisite 1. Persistence across runs is not the thing this
feature waits for, it is the thing that rules it out. A store has to be
created, located, sized, expired and migrated when its shape changes, and
reasoned about when it goes stale — which is what it means for software to be
operated. [`positioning.md`](positioning.md) §4 forbids it and names the
mechanism: "the moment there is a schema to migrate, somebody owns a service."

§7 of that page named this argument in advance, as one of three things that
would falsify the position: *retention keeps growing... treat the second such
argument as the signal, not the fifth.* A baseline over the previous 2000 calls
is that argument, and it arrives before the bounded retention positioning §3
asks for has shipped at all.

§3 above — seasonality — is the same argument one step further out. Comparing
this Tuesday against previous Tuesdays needs weeks, which is Homer's window.
Declined for the same reason, with less room to argue it.

### 3. Peer comparison inside one capture: in position, and buildable now

Do not decline this because the model failed. The axis that decides all three
answers is not statistics against learning. It is **where the comparison set
lives**.

Cross-run baselining puts it outside the capture, which is what needs a store
and what breaks reproducibility. Peer comparison puts it inside: the reference
is the other endpoints in the same file. That version needs no store, no
weights, no training corpus and no ground truth; the same pcap yields the same
answer forever, which is the property objection 2 demanded; and the evidence it
names is a peer set an operator can open and read.

The strongest argument for it is that the tree already holds a working example.
`FraudDetector` baselines within a capture today. It keeps a rolling call rate
per source address, folded one window at a time by `sample_baseline`
([`src/security/fraud_detect.rs:152`](https://github.com/NormB/sipnab/blob/main/src/security/fraud_detect.rs#L152))
so the average stays slower than the burst it exists to catch. A volume spike
is reported when a source exceeds the rate it established itself, and the alert
prints both sides — "12 calls in 60s (baseline: 2.4/min)" — which is the
sentence shape §1 proposed, produced with no store, no model and no history.

So "is statistical baselining in position?" is already answered by the tree:
yes, when the baseline is established inside the capture.

What is missing is narrower than this page assumed. That detector baselines one
metric, the call rate, against a source's own recent past. It never compares a
source against its peers, and it never baselines the outcome metrics — failure
mix, PDD, codec — at all.

### The smallest honest first component

One metric, one grouping key, one comparison, no new configuration:

**Per-source failure-mix divergence across the dialogs in one capture.** Group
the capture's INVITE dialogs by `src_addr`, the only grouping key that exists —
"trunk" and "gateway" are still not modeled, and inventing them is a second
feature. For each source carrying enough dialogs, compare its distribution of
final status codes, which `final_status_code`
([`src/sip/dialog.rs:237`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog.rs#L237))
already returns, against the pooled distribution of the other sources in the
same capture. Report the sources that diverge, printing both distributions and
the dialog identifiers behind them, so an operator opens the calls rather than
trusting the number.

Failure mix before ASR, because ASR summarizes the failure mix and shows less.
Failure mix before PDD, because percentiles need a sketch, and that is more
machinery than a first component should carry.

**One thing §1 asks for that this must not do: print a p-value.** The example
output reads "p < 0.01, chi-square". A p-value over one capture's dialogs
shrinks as the capture runs longer, and the operator chooses how long to
capture — so a long enough capture makes every real difference "significant",
and a reader who takes the number for the probability that a gateway is broken
has been misled by the tool. That is the unverifiable verdict objection 1
rejects, wearing a statistician's coat. Report the effect: the two
distributions and the counts behind them. Let the operator judge.

### The honesty field it has to carry

A divergence figure fails the way a MOS fails. The number a two-source capture
produces is byte-identical to the number a two-hundred-source capture produces,
and only one of them means anything — which is exactly why an RTP score says
whether it is grounded. `mos_is_grounded`
([`src/mcp/server.rs:3215`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L3215))
exists because a placeholder 4.2 and a measured 4.2 are the same bytes, and an
agent that cannot tell them apart reasons confidently from a guess.

So the finding carries the size of what it compared — how many peers, how many
dialogs — beside a boolean in the shape of `mos_grounded`, false whenever the
peer set or the sample is too small for the comparison to mean anything, and a
note in the register `mos_note` already uses: a ranking inside a small capture,
not a claim about a population. Any summary that filters the ungrounded
findings out then reports how many it dropped, the way the capture-wide MOS
floor reports `ungrounded_excluded` rather than filtering silently.

### Where it sits

Behind the three items positioning §5 ranks: RTCP over `--hep-send`, multi-node
correlation, bounded on-disk retention. Nothing here jumps that queue. What
this decision changes is status, not priority — it stops being blocked on an
architectural decision nobody is going to take, and becomes a small piece of
work available when its turn comes.
