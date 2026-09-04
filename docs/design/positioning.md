# Where sipnab sits: between the terminal viewer and Homer

**Status:** DECISION. Taken 2026-08-10. This page exists to **decline**
features, not to describe them — if it only ever ratifies what was already
built, it has failed at its job.
**Verified against:** `fcabc436`, working tree. First taken against `c3befb9`;
the §2 facts and every line citation were re-verified 2026-09-02.
**Backlog:** the four items this page authorizes are tracked separately; §5
ranks them and §6 lists what it refuses.

**No claim on this page is a measurement.** The capability facts in §2 are
verified against the source and cited to file and line. The market judgements
in §1 and §7 are judgements. Do not upgrade one to the other by restating it
somewhere with fewer qualifiers — the same rule
[`capture-tuning-tasks.md:22`](https://github.com/NormB/sipnab/blob/main/docs/design/capture-tuning-tasks.md#L22) applies to throughput
claims.

## 1. The gap

Two tools own the ends of this space and neither reaches the middle.

**the terminal viewer** is local. You are logged into one box, you run it, you see that
box's SIP. Zero infrastructure, seconds to first use, and it stops at the
machine boundary. It displays; it does not analyze.

**Homer** is a system. Capture agents feed a collector, the collector feeds a
database, a web UI queries it. Many nodes, weeks of retention, multiple users —
and a deployment project before the first packet.

The middle wants three properties at once that neither provides:

| | the terminal viewer | **the gap** | Homer |
|---|---|---|---|
| reach | one box you are on | **many nodes, no agent to deploy** | many nodes |
| infrastructure | none | **none** | collector + DB + UI |
| analysis | display | **lint, triage, correlation, evidence** | search + dashboards |
| retention | none | **minutes to hours** | weeks |
| time to first use | seconds | **seconds** | a project |

The wedge is not "lighter Homer" and not "better the terminal viewer". It is **multi-node
reach with zero infrastructure**. That slot is open because the terminal viewer never tried
to leave the box and Homer never tried to avoid the database.

## 2. What already fits, verified

| Property | Where | State |
|---|---|---|
| Single binary, no database | — | ships |
| Receives HEP from Kamailio/OpenSIPS/Asterisk | `-L`/`--hep-listen`, [`hep.rs`](../../src/capture/hep.rs) | ships — **nothing need be installed on production** |
| Sender-side HEP | `--hep-send`, [`batch.rs:3281`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L3281) (SIP) and [`batch.rs:3297`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L3297) (RTCP) | ships — SIP as protocol type 1 and RTCP as type 5 since 0.5.92; RTP is never forwarded |
| RTCP understood on the wire | `CHUNK_PROTO_TYPE` ([`hep.rs:61`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L61)) — `1=SIP, 5=RTCP, 32=RTP` | ships — the receiver decodes type 5 and `HepSender::send_rtcp` ([`hep.rs:3581`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L3581)) emits it, pinned by `send_rtcp_puts_protocol_type_5_on_the_wire` ([`hep.rs:4672`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L4672)) |
| Bounded memory | `--limit` (100k dialogs, oldest-first), `--max-streams` (50k) | ships |
| Conformance lint with RFC citations, triage, MOS diagnosis | — | ships |
| Frame pointers with verifiable digests | `--show-frame` | ships |
| Agent access | MCP | ships |
| Bounded on-disk retention | `--split` rotates files; **nothing caps the set** | absent |

The single most useful fact here: for OpenSIPS and Kamailio, **sipnab does not
go on the production host at all** — the proxy's own HEP module points at a
listener elsewhere. The lightest configuration is the one where sipnab never
touches production.

## 3. What the position demands

**Media quality at the HEP receiver.** Without media quality a remote viewer is
*worse than the terminal viewer run locally*, because the terminal viewer sees
RTP and this would not. The sender-side half of this closed in 0.5.92: RTCP
travels over `--hep-send` as protocol type 5 (§2). The receiver-side half is
open, and it is what decides whether the remote viewer shows a MOS at all.
`--hep-send` never forwards RTP, and `StreamStore::process_rtcp`
([`stream_store.rs:810`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L810)) files a report only
against a stream whose SSRC it has already seen from the media itself — a
report for an unknown SSRC records nothing, which `rtcp_unknown_ssrc_is_noop`
([`stream_store.rs:3431`](https://github.com/NormB/sipnab/blob/main/src/rtp/stream_store.rs#L3431)) pins. So a
viewer fed by HEP alone decodes every RTCP report and can show no quality figure
for any of them. Received RTCP reaches the MOS delay term (`MosDelay::resolve`,
[`quality.rs:540`](https://github.com/NormB/sipnab/blob/main/src/rtp/quality.rs#L540)) only when the same
process also sees the media, which is the `-L` plus `-d` arrangement of cookbook
recipe 6d. This was established 2026-09-02 by reading the path, not by running
it end to end; the end-to-end run is still owed.

**Multi-node correlation.** Without it, sipnab-plus-HEP is "the terminal viewer that can see
one remote box" — a convenience, not a category. This is the differentiator,
and it needs provenance, which
[`multi-capture-comparison.md`](multi-capture-comparison.md) already found
missing for the two-capture view. Same prerequisite, so do not solve it twice.

**Bounded on-disk retention.** the terminal viewer keeps nothing, Homer keeps weeks, the
middle keeps *this shift*. Today `--split` rotates output files and nothing
bounds the set, so "keep the last 2 GB and let me search it" does not exist.
This is the feature that makes it a scope with a memory rather than a live view
you had to already be watching.

## 4. What the position forbids

A database. A web UI. Multi-user authentication. Dashboards. Alert history.

The test is not a feature list, it is a verb: **if a feature requires sipnab to
be _operated_ rather than _run_, it is out of position.** Retention stays
bounded and file-based for exactly this reason — the moment there is a schema to
migrate, somebody owns a service.

Building these does not merely add scope. It puts sipnab on a mature
incumbent's ground having spent the lightness that was the reason to choose it.
The end state of that path is a worse Homer.

## 5. Order

1. Media quality from RTCP alone at the HEP receiver — the sender half shipped
   in 0.5.92; the receiver files a report only against media it has seen (§3).
   The prerequisite for judging the rest in real use
2. Multi-node correlation — the differentiator; shares provenance with §3
3. Bounded on-disk retention — the "this shift" primitive

## 6. Consequence for the published materials

The site currently leads with throughput: 2.31M pkts/s, 12.2× the CLI matcher, the
homepage tiles. **That is a local-tool argument.** It competes on
the terminal viewer-and-the CLI matcher turf, which is the position this page says sipnab is not
taking.

The number stays; what it argues changes. Throughput is what lets **one binary
absorb a HEP fan-in from a whole estate without a collector cluster** — it is
the evidence for reach, not a benchmark win to be enjoyed on its own.

## 7. What would falsify this

Stated so the position can lose rather than absorb every outcome:

- **Nobody uses the remote path.** If the HEP-listener workflow of §2 sees no
  real use over a few months of availability, the gap is theoretical and the
  honest response is to stop building for it, not to build harder.
- **Retention keeps growing.** If "minutes to hours" is repeatedly argued up
  toward days and then weeks, the middle is not stable and the product is
  drifting into Homer's slot one requirement at a time. Treat the second such
  argument as the signal, not the fifth.
- **The analysis is not the reason people choose it.** If users want it purely
  as a faster the terminal viewer and ignore lint, triage and correlation, then the local
  tool position is the real one and §6 is wrong.
