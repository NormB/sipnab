# Machine-learning anomaly detection over SIP/RTP patterns

**Status:** research and spec only, 2026-07-30. Nothing implemented, and the
recommendation is **not to implement the obvious version**.

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

The seven signalling detections and the media diagnosis all answer *per-dialog*
questions with a rule. The gap is **population** questions: a call that is
individually unremarkable but collectively wrong — an ASR that quietly fell from
71% to 64%, a codec that started appearing on a trunk that never used it, a
gateway whose PDD distribution shifted a second to the right.

Every one of those is invisible to a per-dialog rule, because no single dialog
in the population is faulty.

## Why the obvious implementation is wrong

The tempting version is: featurise dialogs, fit an autoencoder or isolation
forest, flag high reconstruction error. It should be rejected, for reasons that
have nothing to do with model quality.

**1. It breaks the tool's core promise.** Every existing detection names the
messages it is drawn from — the spec's first load-bearing rule, enforced even on
third-party plugins. An isolation forest produces a score. "Dialog 4417 has
anomaly score 0.93" cannot be checked, argued with, or acted on, and an operator
who cannot verify a finding learns to ignore it. sipnab's value proposition is
*evidence, not verdicts*; an unexplainable score is precisely a verdict.

**2. It cannot be reproduced from a pcap.** A capture analysed twice must give
the same answer — the property that motivated fuel metering over wall-clock in
the plugin host. A model introduces weights, a training set, and a version, none
of which live in the pcap. Two operators running the same command on the same
file would legitimately disagree.

**3. It has no ground truth to train on.** There is no labelled corpus of
"anomalous" SIP. Unsupervised training on live traffic learns whatever that
network does, including its faults — the model would flag a *fixed* network as
anomalous, having normalised the breakage.

**4. The dependency cost is disproportionate.** D7 rejected an embedded
scripting runtime on supply-chain grounds; a tensor runtime is a great deal
heavier than wasmi's 15 crates and 1.56 MB.

## What to build instead

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
gateway 10.0.0.7: ASR 64% over the last 200 calls, against 71% over the
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

This is the real reason it is not next:

1. **Persistence across runs.** Baselines need history. sipnab is a
   single-capture process today: `[limits]` bounds tracked state, nothing
   survives exit. A store is a bigger architectural decision than the detection.
2. **A grouping key.** "Trunk" and "gateway" are not modelled; only
   `src_addr`/`dst_addr` exist.
3. **A statistics dependency, or hand-rolled tests.** Chi-square and a
   percentile tracker are small enough to write, which is preferable to a crate.

## Recommendation

**Do not schedule this.** It is correctly a P5. The prerequisites — persistent
state above all — are individually larger than the feature, and the honest
version of it is not machine learning.

If it is ever picked up, take population baselining (§1) alone. It is the whole
operator value, it needs no model, and every finding it produces can name its
evidence — which is the bar every other detection in this tool already clears.
