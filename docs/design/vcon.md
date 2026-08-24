# vCon: sipnab contributes to a conversation record, it does not produce one

**Status:** DECISION (Phase 0). Taken 2026-08-24. **Nothing is built, and this
page is not a build plan.** It records what sipnab may put in a vCon, what it
refuses to put in one, and the one structural gap in the format that governs
both answers.
**Verified against:** `draft-ietf-vcon-vcon-core-03` (1 July 2026) — an adopted
IETF working-group document, Standards Track, before working-group last call —
whose syntax version string is `"0.4.0"`; and the sipnab tree at `1ce2416d`.

Draft section numbers on this page are written `core-03 §2.1`. Bare `§N` refers
to a section of this page.

**If you read one section, read §3.** The five refusals in §2 are each
defensible on their own, and a reader can accept or argue with them one at a
time. §3 is different: it is a property of the format rather than a preference
of this project, it survives every implementation choice, and it is the finding
that decides how the feature has to be shaped if it is built at all.

## 1. What vCon is, and what sipnab is to it

vCon — "Conversation Data Container" — is a JSON object describing one
conversation: `parties[]` (who was in it), `dialog[]` (what passed between them
and when), `analysis[]` (what some machine concluded about that), and
`attachments[]` (documents carried alongside). It is the interchange format a
conversation travels in when it leaves the system that captured it.

The ecosystem assumes that system is a **recorder**: something inside the
conversation, which obtained the media from a party, and which can be asked
what that party agreed to. A recorder can say *"I received this audio from the
caller."*

sipnab was never inside the conversation. It reads a mirror port. The strongest
sentence it can honestly write is *"I saw packets claiming to be this call go
past this tap."* Those two sentences look alike in JSON and are not alike at
all, and almost every decision below follows from keeping them apart.

**The decision: sipnab emits OBSERVER vCons.** It may produce a container
saying *here is signaling a passive instrument observed, contributed by this
party, with these named gaps*. It must never produce one that claims to **be**
the conversation.

That role is in the specification rather than around it. `core-03` §2.1 defines
a party as "an observer or participant to the conversation, either passive or
active", and §4.4.3 says an organization that processes or constructs the vCon
and adds attachments SHOULD be represented as a Party Object. So a passive
observer contributing to someone else's record is a shape the format already
names. sipnab occupies that shape and stops there.

### The decisions, in one place

| # | Decision | The fact it turns on |
|---|---|---|
| §2.1 | Emit **observer** vCons, never a producer-of-record vCon | sipnab saw a tap, not a conversation |
| §2.2 | **Never** sign (JWS) and **never** encrypt (JWE) | A signature over an observation is indistinguishable from a signature over a recording |
| §2.3 | **Never** emit consent or lawful-basis attachments | sipnab obtained no consent, and silence must not read as "none was recorded" |
| §2.4 | **Never** populate Party `name`; always `validation: "none"` | `From` and `To` are a claim by the caller, trivially spoofed |
| §2.5 | **Never** host artefacts; inline base64url only, under a cap | sipnab hosts nothing, so it cannot assert where a file lives |
| §2.6 | Parties come from the observed dialog only, never from inference | Party indices are load-bearing, and a wrong count corrupts every cross-reference |

## 2. The five refusals, and the one role

### 2.1 Observer, never producer-of-record

The observer party is the honest self-description and it is also the anchor for
everything else. A vCon whose contributing party is a passive instrument, and
which says so in the container, gives a downstream consumer the one fact it
needs to weigh the rest: this material was not obtained from a participant.

A vCon that omits that fact does not become neutral. It becomes a recording
system's output with a missing field, because that is what a consumer of the
format is built to expect.

### 2.2 Never sign (JWS), and never encrypt (JWE)

vCon's signature answers a specific question: *the domain that constructed this
vouches for it as it crosses a trust boundary.* What sipnab could truthfully
sign is a different sentence: *these bytes are what sipnab observed and wrote.*

JWS cannot tell those apart. A verifier sees a valid RS256 signature over a
container shaped like a recording system's output, checks it, and gets back
"authentic". The cryptography is correct and the conclusion it invites is
false. The chain of custody starts at a mirror port rather than at an endpoint,
and no signature algorithm carries that distinction.

Technically valid, semantically misleading — which is the worse failure of the
two, because a signature is exactly the field a consumer stops thinking after.

JWE goes with it. Encrypting an observation for a recipient asserts a
custody relationship with that recipient which sipnab does not have, and the
key management it would need is infrastructure that
[`positioning.md`](positioning.md) §4 already refuses on independent grounds.

### 2.3 Never emit consent or lawful-basis attachments

Two companion drafts exist for this — `draft-howe-vcon-consent-00` and
`draft-howe-vcon-lawful-basis-02` — and both exist because the ecosystem
assumes a recorder that obtained consent and can attest to it. sipnab obtained
none. It was not asked, it did not ask, and it has nothing to attest.

The reason this is a refusal rather than an omission is what the absence has to
read as. An empty consent attachment, or a lawful-basis object with a null
field, reads as **"no consent recorded"** — a statement about the call.
The truth is **"the producer was not in a position to record consent"** — a
statement about the producer. sipnab has no field in which to say the second,
so it emits neither, and the reader who wants that question answered has to go
to the party that could answer it.

This is a regulatory hazard rather than a theoretical one.
`draft-howe-vcon-sip-signaling-00` §1 cites the TRACED Act, so the consumers
this format is aimed at include the ones for whom a consent claim is a legal
artefact. Handing them a container whose consent field is empty because sipnab
never had one is the kind of mistake that gets read years later by someone with
no access to this page.

### 2.4 Never populate Party `name`, and always set `validation: "none"`

What sipnab holds is the `From` and `To` header fields of an observed dialog.
That is a claim made by the caller about the caller, unverifiable at the tap
and trivially spoofed — the whole reason SIP identity mechanisms exist at all.

`core-03` §4.2.7 says `validation` SHOULD be provided if `name` is provided, so
the format already treats a name as something a producer is expected to stand
behind. sipnab cannot.

The honest shape is therefore to emit `sip` and `sip_display_name`, leave
`name` unset, and set `validation: "none"` on every party sipnab writes. A
consumer then sees exactly what arrived on the wire, marked as unvalidated,
which is what it is. Promoting a display name into `name` would launder a
caller's assertion into the producer's.

### 2.5 Never host artefacts

`core-03` §2.4.1 requires a by-reference `url` to use HTTPS. sipnab hosts
nothing and is not going to: a URL is a promise that a file is somewhere and
stays there, and a tool that is *run* rather than *operated* cannot make it.

So media, if sipnab ever emits any, goes inline as base64url only, with a size
cap and an explicit refusal above it rather than a silent truncation. The
refusal is the important half — a container that quietly dropped the media over
the cap is a container claiming the call had none.

Taking an operator-supplied base URL is the tempting middle path and it is
worse than either end. It would have sipnab assert where an artefact **will**
live, on infrastructure sipnab does not control, cannot check, and never sees
again. A dead link inside a signed-looking record is indistinguishable from
evidence that was removed.

### 2.6 Parties come from the observed dialog, never from inference

`parties` is mandatory, and its **indices are load-bearing**: `dialog.parties`,
`attachment.party`, `analysis.dialog`, `originator` and `party_history.party`
all index into that array. A wrong party count does not degrade the container.
It corrupts every cross-reference in it, silently, in a way that reads as
data rather than as an error.

sipnab does not reliably know how many parties a conversation has. One tap on a
proxied call sees two legs of one conversation, or one leg of three, and the
tree already says so in as many words: `DialogStore::merge` carries a doc
section headed *"Same-Call-ID collisions are the normal case, not the rare
one"*, measured at 1173 of 2311 dialogs in one 100 MB file
([`deferred-and-declined.md`](deferred-and-declined.md) §1). Whatever a capture
point saw, it is a view of the conversation and not a census of it.

So parties are emitted strictly from the `From` and `To` of the dialog actually
observed, one entry each, and nothing is inferred, merged or added. A second
tap that saw the other leg produces its own container, and reconciling them is
the consumer's problem — which is the correct place for it, because the
consumer is the only one holding both.

## 3. The gap: vCon cannot say "this container is an incomplete record"

This is the finding that shapes the feature, and it is a property of the format
rather than an opinion about it.

**vCon has no field for "this container is an incomplete record of the
conversation."** Not a weak one, not an awkward one — none.

sipnab, meanwhile, is a tool whose central discipline is saying exactly that.
Its totals describe what it understood rather than what the wire held, and the
ranked problem list in [`src/analysis.rs`](../../src/analysis.rs) enforces the
rule structurally: incompleteness findings are not a footnote beside the list,
they are findings **in** it, at `Severity::Blind`, sorting above every call
fault. The consequence, in that module's own words, is that a capture that
failed to decode, had SIP discarded by a port gate, or hit a retention cap *"can
never render as clean, because the list is not empty"*.

Export that capture as a vCon and the property evaporates. In vCon, absence is
just absence.

### 3.1 `incomplete` means the CALL failed, not the RECORD

The nearest-looking token is `dialog.type: "incomplete"`, and it means the
opposite of what an exporter would want it for. `core-03` §4.3.1 defines it as
"the call or conversation failed to be setup to the point of exchanging any
conversation" — a fact about the traffic.

Emitting `incomplete` because sipnab did not capture the `200 OK` would state
that the call failed, when what happened is that the instrument missed a
packet. That substitution — the tool's own limits reported as a finding about
the traffic — is precisely the collapse `nothing_to_decode` in
[`src/rtp/audio_export.rs`](../../src/rtp/audio_export.rs) was written to
refuse. Its message says *"This is a statement about what this run kept, not a
finding that the call was silent"*, and a unit test asserts that exact
disclaimer is present, because an earlier version of the same message asserted
a cause it had only inferred.

Reaching for `incomplete` would reintroduce the defect in a format where no
disclaimer can travel with it.

### 3.2 Every PARTIAL clause sipnab already builds is homeless

The audio exporter builds a clause per way a file can fall short of the call it
came from, and the WAV's embedded note and the summary printed beside it are
built from **one** string so they cannot drift. Here is where each of those
clauses lands in vCon:

| sipnab clause | vCon home |
|---|---|
| ring wrapped (`wrap_clause`) | Partial. Expressible only through a `recording-set` Dialog Object whose `start` and `duration` are the call's while the `recording` object's are the file's (`core-03` §4.3.3). Nothing obliges a consumer to compare the two |
| streams past two, undecodable codecs (`omitted_clause`) | Partial. §4.3.4 lets a recording object name only the parties it captured — but only when some object names them all, and sipnab may not know them all. Codec identity has no home at all |
| decode failure (`decode_failure_clause`) | None |
| one direction only (`direction_clause`) | None. §4.3.4's null-channel placeholder means "no party on this channel", not "we could not see the other leg" |
| retention off (`--retain-audio` absent) | **None, and this is the dangerous one.** A vCon with an empty `dialog[]` reads as a conversation with no media — a claim about the call |
| dialog compaction (`messages_evicted`) | **None.** A `sip-message-trace` attachment is a `messages` array with no gap marker, so compaction silently removes its middle |

Read the last two rows together. Both turn a fact about **this run's
configuration** into an apparent fact about **the conversation**, which is the
single failure mode every one of these clauses exists to prevent. The audio
exporter has a whole test named for it —
`a_run_that_kept_nothing_never_reads_as_a_silent_call` — and vCon reintroduces
it by construction.

### 3.3 The extension mechanism does not fix it

The obvious repair is a custom extension carrying a completeness caveat, and it
does not work, for a reason written into the format.

`core-03` §4.1.3 and §4.1.4 offer exactly two levels. A **Compatible**
extension is one an unsupporting consumer safely ignores. A **critical**
extension is one an unsupporting implementation "MUST NOT attempt to process or
operate on… except to reject it".

There is no third level meaning *you must read this caveat before trusting the
contents*. A completeness caveat is therefore either ignorable — in which case
the consumer that most needs it is the one that drops it — or fatal, in which
case an ordinary consumer refuses the container outright and sipnab has emitted
something no one can read. Neither is the behavior the caveat needs, and no
choice between them produces it.

### 3.4 `Severity::Blind` has no structural counterpart

`Severity::Blind` works because of where it sits, not because of what it says.
It is inside the list, above everything else in it, so "no problems found"
becomes structurally unreachable for an incomplete read. Nobody has to remember
a guard.

vCon offers no position with that property. `analysis[]` is a list of
conclusions about the conversation, and a caveat placed there is one entry
among others, rankable and skippable, carrying no obligation. The strength of
`Blind` was never its wording. It was that the wording could not be routed
around, and vCon has nowhere that is true.

## 4. What follows for the design

If this feature is built, the completeness caveat is the hard part and the rest
is serialization.

**Duplicate the caveat into surfaces a consumer cannot skip, from ONE source
string, with a test that fails if they diverge.** That pattern already exists
in this repository: `provenance_note` in
[`src/rtp/audio_export.rs`](../../src/rtp/audio_export.rs) builds the note
embedded in the WAV and the summary printed beside it from the same `partial`
string, and the comment above the stereo path records what happened when they
were built separately — a clause was added to one and not the other, and a test
comparing them caught it. Same discipline here, same reason: a container whose
embedded caveat disagreed with the run that produced it would be worse than one
with no caveat, because it would look authoritative while contradicting itself.

**Do not put the caveat in `subject`.** `core-03` §4.1.7 defines `subject` as
the subject or topic of the conversation. Borrowing a content field to carry a
producer's disclaimer is the kind of misuse that reads as authoritative to
every consumer that renders it — the caveat arrives styled as a fact about the
call, which is the exact inversion §3 spends its length arguing against.

**The refusal has to be reachable.** Wherever sipnab cannot express a gap it
knows about, refusing to emit is a supported outcome and not a bug. That is
already how the size cap in §2.5 behaves, and it is the same rule
`nothing_to_decode` follows: a tool that cannot say it lost evidence should say
that, rather than emit a clean-looking artefact.

## 4a. Measured against a real consumer

Everything above §4 reasons from the draft. This section reasons from a running
backend: a vCon store reachable over NATS and HTTP, probed on 2026-08-24 with
synthetic containers, every claim checked against the stack rather than read off
upstream documentation.

These are properties of ONE consumer, not of the format. They are recorded
because they change what the emitter must do, and because two of them are
things upstream does not say.

### 4a.1 A `204` does not mean the container was stored

The finding that matters most. A container carrying roughly 12 MB of inline
base64 returned **HTTP 204**, landed in Postgres, and the file spool rejected
it — `16777749 > 10485760`. The bridge acknowledges on that 204, so the message
leaves the queue. **Neither transport reports the partial write.**

A producer is told "accepted" while one storage backend silently dropped the
payload.

This is the shape §3.2 describes, one layer out. There, a run's limits present
as a fact about the conversation. Here, a limit of the CONSUMER presents as
nothing at all — it reaches no one, not even the producer that could have
retried.

Three points were measured, not one: roughly 1 MB and roughly 5 MB store in
both backends, and roughly 12 MB stores in Postgres alone.

**The constraint on sipnab: keep the encoded container under 10 MB, and prefer
to stay near the 5 MB that was observed landing everywhere.** Base64 inflates
by four thirds, so the media budget behind the hard ceiling is roughly 7.8 MB.
§2.5's "size cap and an explicit refusal above it" now has a measured number to
be set from rather than a guess, and the refusal has to happen in sipnab,
because the acknowledgement cannot be trusted to carry the failure back.

### 4a.2 What is stored is not, byte for byte, what was emitted

The store adds `subject`, `amended` and the empty collections; the chain
appends a tags attachment. A checksum taken before emission does not match the
container at rest.

That costs nothing today, and it is evidence for §2.2 rather than a new
problem: a signature over the emitted bytes would not verify against the stored
object. Anyone reopening the signing decision has to answer this as well as the
semantic argument, and the semantic argument was already the harder one.

### 4a.3 Unknown top-level fields survive, and that does not solve §3

A container sent with `"sipnab_capture_gap": "ring wrapped"` came back intact.
Custom provenance at the top level does reach the far side.

**It is tempting and it is not the answer.** §3.3 is about whether anyone is
obliged to READ a caveat, not whether it survives transport. A field that
arrives and is never looked at is the ignorable half of the extension
mechanism wearing a different hat. The duplication rule of §4 stands unchanged;
this finding widens where a caveat may be put, not whether one place suffices.

### 4a.4 The consumer solved the role problem the format cannot

The most interesting finding, because it answers §3 halfway and says so.

§3 proves vCon has no position inside a container that a consumer is obliged to
read. This backend therefore enforces role **outside** the container entirely:
the subject a producer publishes to selects the ingress list, which selects the
chain, which selects the storage table. An observer's containers land in one
table and a recorder's in another, and a consumer holds `SELECT` on views only
— querying the wrong one is `permission denied` rather than a wrong answer.

Nothing can label itself as sipnab, and sipnab cannot label itself as anything
else, because the routing key is the subject rather than any field in the
payload.

That is a real guarantee and it is worth naming what it does NOT do. Its own
documentation is explicit: the completeness gap of §3 **is not solved, and
cannot be, here or anywhere in the format**. What the backend guarantees is
only that nobody mistakes an observation for a recording. The duplication rule
of §4 remains sipnab's problem.

It also declines correlation: two taps on one conversation produce two
containers with two uuids, and reconciling them belongs to the consumer holding
both. That matches what sipnab already declines to do across nodes.

### 4a.5 A malformed container is dropped, not retried

The bridge retries a 5xx, a 429 and an unreachable store, and **drops a 4xx**
— correctly, because retrying a malformed container cannot help.

So a missing required field is not a delayed delivery. The container is logged
and gone, while the producer's own queue shows it acknowledged. That is why
§4a.6 is a gate and not a note.

### 4a.6 The three fields that are actually required

`uuid` must parse as a UUID, `created_at` must be present, and `vcon` must
carry the syntax version. Any of them missing or malformed is a **422**;
everything else defaults to an empty collection.

Cheap to guarantee and worth a gate, because a 422 at ingest is a container
that never arrives at all —
[`tests/vcon_ingest_contract_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/vcon_ingest_contract_test.rs)
holds sipnab to it.

## 5. Declined outright

Recorded as declined with reasons rather than filed as future work, so that
none of them returns next quarter as a fresh idea. This is the method
[`deferred-and-declined.md`](deferred-and-declined.md) exists to enforce: an
unrecorded rejection comes back with the same arguments.

| Declined | Decisive reason |
|---|---|
| JWS signing | A signature over an observation verifies as a signature over a recording (§2.2) |
| JWE encryption | Asserts a custody relationship sipnab does not have, and needs key infrastructure the positioning refuses |
| Consent attachments | sipnab obtained no consent, and an empty field reads as "none recorded" (§2.3) |
| Lawful-basis attachments | Same, with a named regulatory consumer behind it |
| A vCon store | A database, which [`positioning.md`](positioning.md) §4 forbids by name |
| An HTTPS artefact host | sipnab would assert where a file lives on infrastructure it does not control (§2.5) |

Note what is **not** declined: emitting an observer vCon at all. Phase 0 says
the shape is honest and the caveat problem is unsolved, not that the feature is
dead.

## 6. What would falsify this

Stated so the feature can lose, on the model of
[`positioning.md`](positioning.md) §7:

- **Nobody round-trips one.** If no operator feeds a sipnab vCon into a
  conserver or any other consumer within a few months of it being available,
  the interchange demand is theoretical and the honest response is to retire
  the feature rather than to build more of it.
- **The caveat gets argued down.** If the duplication rule of §4 is repeatedly
  relaxed — first to one surface, then to a field a consumer renders as
  content — then this project is producing recording-system output with extra
  steps, and the observer framing has stopped doing any work.
- **A consumer treats it as a recording anyway.** If the containers get read as
  authoritative records of the calls despite §2, the distinction this whole
  page is built on is one the ecosystem cannot hold, and emitting nothing is
  better than emitting something misread.
