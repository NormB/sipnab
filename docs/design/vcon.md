# vCon: sipnab contributes to a conversation record, it does not produce one

**Status:** DECISION (Phase 0). Taken 2026-08-24. **Nothing is built, and this
page is not a build plan.** It records what sipnab may put in a vCon, what it
refuses to put in one, and the one structural gap in the format that governs
both answers.
**Verified against:** `draft-ietf-vcon-vcon-core-04` (7 September 2026) — an adopted
IETF working-group document, Standards Track, before working-group last call —
whose syntax version string is `"0.4.0"`; and the sipnab tree at `1ce2416d`
for sections 1 to 6, and at `da3d0069` for section 7.

This page writes a draft section number as `core-04` section 2.1 and links it
to that section of the draft on the IETF Datatracker. A section number without
`core-04` names a section of this page, and links to its heading.
[Section 7](#7-what-changed-between-core-03-and-core-04) compares `core-04`
with `core-03`, the revision this page was first verified against.

**If you read one section, read [section 3, "The gap"](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record).**
The five refusals in [section 2](#2-the-five-refusals-and-the-one-role) are each
defensible on their own, and a reader can accept or argue with them one at a
time. Section 3 is different: it is a property of the format rather than a preference
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

That role is in the specification rather than around it.
[`core-04` section 2.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.1) defines
a party as "an observer or participant to the conversation, either passive or
active", and [`core-04` section 4.4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.3) says an organization that processes or constructs the vCon
and adds attachments SHOULD be represented as a Party Object. So a passive
observer contributing to someone else's record is a shape the format already
names. sipnab occupies that shape and stops there.

### The decisions, in one place

| # | Decision | The fact it turns on |
|---|---|---|
| [Section 2.1](#21-observer-never-producer-of-record) | Emit **observer** vCons, never a producer-of-record vCon | sipnab saw a tap, not a conversation |
| [Section 2.2](#22-never-sign-jws-and-never-encrypt-jwe) | **Never** sign (JWS) and **never** encrypt (JWE) | A signature over an observation is indistinguishable from a signature over a recording |
| [Section 2.3](#23-never-emit-consent-or-lawful-basis-attachments) | **Never** emit consent or lawful-basis attachments | sipnab obtained no consent, and silence must not read as "none was recorded" |
| [Section 2.4](#24-never-vouch-for-a-party-name-and-always-set-validation-none) | **Never** vouch for a Party `name`; always `validation: "none"` | `From` and `To` are a claim by the caller, trivially spoofed |
| [Section 2.5](#25-never-host-artefacts) | **Never** host artefacts; inline base64url only, under a cap | sipnab hosts nothing, so it cannot assert where a file lives |
| [Section 2.6](#26-parties-come-from-the-observed-dialog-never-from-inference) | Parties come from the observed dialog only, never from inference | Party indices are load-bearing, and a wrong count corrupts every cross-reference |

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
[section 4 of `positioning.md`, "What the position forbids"](positioning.md#4-what-the-position-forbids)
already refuses on independent grounds.

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
[Section 1 of `draft-howe-vcon-sip-signaling-00`](https://datatracker.ietf.org/doc/html/draft-howe-vcon-sip-signaling-00#section-1)
cites the TRACED Act, so the consumers
this format is aimed at include the ones for whom a consent claim is a legal
artefact. Handing them a container whose consent field is empty because sipnab
never had one is the kind of mistake that gets read years later by someone with
no access to this page.

### 2.4 Never vouch for a Party `name`, and always set `validation: "none"`

What sipnab holds is the `From` and `To` header fields of an observed dialog.
That is a claim made by the caller about the caller, unverifiable at the tap
and trivially spoofed — the whole reason SIP identity mechanisms exist at all.

[`core-04` section 4.2.7](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.7) says `validation` SHOULD be provided if `name` is provided, so
the format already treats a name as something a producer is expected to stand
behind. sipnab cannot.

sipnab therefore emits `sip` and `sip_display_name`, emits `name` with the
display name from `From` or `To` when the wire carried one, and sets
`validation: "none"` on every party it writes. `name` travels under the
declared key so a generic vCon reader shows a named party rather than an
anonymous one, and `validation: "none"` beside it states that sipnab did not
establish the identity. A consumer then sees exactly what arrived on the wire,
marked as unvalidated. The display name can be anything the sender wrote: in
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap) the caller's `name` is `PCMU/8000`.

### 2.5 Never host artefacts

[`core-04` section 2.4.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.4.1) requires a by-reference `url` to use HTTPS. sipnab hosts
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
([section 1 of `deferred-and-declined.md`](deferred-and-declined.md#1-tui-multi-session--multi-capture-comparison)).
Whatever a capture
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
opposite of what an exporter would want it for.
[`core-04` section 4.3.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5) defines it as
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
| ring wrapped (`wrap_clause`) | Partial. Expressible only through a `recording-set` Dialog Object whose `start` and `duration` are the call's while the `recording` object's are the file's ([`core-04` section 4.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3)). Nothing obliges a consumer to compare the two |
| streams past two, undecodable codecs (`omitted_clause`) | Partial. [`core-04` section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4) lets a recording object name only the parties it captured — but only when some object names them all, and sipnab may not know them all. Codec identity has no home at all |
| decode failure (`decode_failure_clause`) | None |
| one direction only (`direction_clause`) | None. The null-channel placeholder of [`core-04` section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4) means "no party on this channel", not "we could not see the other leg" |
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

`core-04` sections [4.1.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.3) and [4.1.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4)
offer exactly two levels. A **Compatible**
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

**Do not put the caveat in `subject`.** [`core-04` section 4.1.7](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.7)
defines `subject` as
the subject or topic of the conversation. Borrowing a content field to carry a
producer's disclaimer is the kind of misuse that reads as authoritative to
every consumer that renders it — the caveat arrives styled as a fact about the
call, which is the exact inversion [section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) spends its length
arguing against.

**The refusal has to be reachable.** Wherever sipnab cannot express a gap it
knows about, refusing to emit is a supported outcome and not a bug. That is
already how the size cap in [section 2.5](#25-never-host-artefacts) behaves, and it is the same rule
`nothing_to_decode` follows: a tool that cannot say it lost evidence should say
that, rather than emit a clean-looking artefact.

## 4a. Measured against a real consumer

Everything above [section 4](#4-what-follows-for-the-design) reasons from the draft. This section reasons from a running
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

This is the shape [section 3.2](#32-every-partial-clause-sipnab-already-builds-is-homeless)
describes, one layer out. There, a run's limits present
as a fact about the conversation. Here, a limit of the CONSUMER presents as
nothing at all — it reaches no one, not even the producer that could have
retried.

Three points were measured, not one: roughly 1 MB and roughly 5 MB store in
both backends, and roughly 12 MB stores in Postgres alone.

**The constraint on sipnab: keep the encoded container under 10 MB, and prefer
to stay near the 5 MB that was observed landing everywhere.** Base64 inflates
by four thirds, so the media budget behind the hard ceiling is roughly 7.8 MB.
The "size cap and an explicit refusal above it" of [section 2.5](#25-never-host-artefacts) now has
a measured number to be set from rather than a guess, and the refusal has to happen in sipnab,
because the acknowledgement cannot be trusted to carry the failure back.

### 4a.2 What is stored is not, byte for byte, what was emitted

The store adds `subject`, `amended` and the empty collections; the chain
appends a tags attachment. A checksum taken before emission does not match the
container at rest.

That costs nothing today, and it is evidence for [section 2.2](#22-never-sign-jws-and-never-encrypt-jwe) rather than a new
problem: a signature over the emitted bytes would not verify against the stored
object. Anyone reopening the signing decision has to answer this as well as the
semantic argument, and the semantic argument was already the harder one.

### 4a.3 Unknown top-level fields survive, and that does not solve the section 3 gap

A container sent with `"sipnab_capture_gap": "ring wrapped"` came back intact.
Custom provenance at the top level does reach the far side.

**It is tempting and it is not the answer.**
[Section 3.3](#33-the-extension-mechanism-does-not-fix-it) is about whether anyone is
obliged to READ a caveat, not whether it survives transport. A field that
arrives and is never looked at is the ignorable half of the extension
mechanism wearing a different hat. The duplication rule of [section 4](#4-what-follows-for-the-design) stands unchanged;
this finding widens where a caveat may be put, not whether one place suffices.

### 4a.4 The consumer solved the role problem the format cannot

The most interesting finding, because it answers [section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) halfway and says so.

[Section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) proves vCon has no position inside a container that a consumer is obliged to
read. This backend therefore enforces role **outside** the container entirely:
the subject a producer publishes to selects the ingress list, which selects the
chain, which selects the storage table. An observer's containers land in one
table and a recorder's in another, and a consumer holds `SELECT` on views only
— querying the wrong one is `permission denied` rather than a wrong answer.

Nothing can label itself as sipnab, and sipnab cannot label itself as anything
else, because the routing key is the subject rather than any field in the
payload.

That is a real guarantee and it is worth naming what it does NOT do. Its own
documentation is explicit: the completeness gap of [section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) **is not solved, and
cannot be, here or anywhere in the format**. What the backend guarantees is
only that nobody mistakes an observation for a recording. The duplication rule
of [section 4](#4-what-follows-for-the-design) remains sipnab's problem.

It also declines correlation: two taps on one conversation produce two
containers with two uuids, and reconciling them belongs to the consumer holding
both. That matches what sipnab already declines to do across nodes.

### 4a.5 A malformed container is dropped, not retried

The bridge retries a 5xx, a 429 and an unreachable store, and **drops a 4xx**
— correctly, because retrying a malformed container cannot help.

So a missing required field is not a delayed delivery. The container is logged
and gone, while the producer's own queue shows it acknowledged. That is why
[section 4a.6](#4a6-the-three-fields-that-are-actually-required) is a gate and not a note.

### 4a.6 The three fields that are actually required

`uuid` must parse as a UUID, `created_at` must be present, and `vcon` must
carry the syntax version. Any of them missing or malformed is a **422**;
everything else defaults to an empty collection.

Cheap to guarantee and worth a gate, because a 422 at ingest is a container
that never arrives at all —
[`tests/vcon_ingest_contract_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/vcon_ingest_contract_test.rs)
holds sipnab to it.

## 4b. Media: a `recording` Dialog Object is not a recording

sipnab exports audio today. `export_dialog_to_wav` decodes retained RTP into a
WAV and stamps it with a provenance note that ends:

> …bounded by where the capture point sat and by what retention kept, **and is
> not a recording made by the endpoints**.

That sentence decides where the media goes, and the decision is easy to get
backwards because two vocabularies collide on one word.

| Term | Means | Who emits it |
|---|---|---|
| `dialog.type: "recording"` | a Dialog Object carrying media — a FORMAT term | any producer with audio |
| a consumer's `recordings` table | containers from an in-path recorder — a PROVENANCE term | a recorder, in the media path |

**sipnab emits the first and must never be routed to the second.** A relay or an
SBC that terminates media can say "I received this audio from the party". sipnab
reconstructed it from a mirror port, and the reconstruction is bounded by where
the tap sat, which codecs it could decode, and what the retention caps kept.

The consumer probed in [section 4a](#4a-measured-against-a-real-consumer) enforces role by routing — the subject selects the
chain, which selects the table, and a consumer holds `SELECT` on one view. So
publishing sipnab's audio anywhere but the observer subject would put an
observation where readers expect a recorder's output, and defeat the single
guarantee that backend offers. **The media travels inside an observer container
or not at all.**

### What that permits, and what it costs

Permitted, because [section 2.5](#25-never-host-artefacts) already allows it: a `recording` Dialog Object carrying
the WAV **inline as base64url**, with a `content_hash` of `sha512-` plus the
Base64url SHA-512 of the body. No `url`, because sipnab hosts nothing.

Two costs travel with it.

**The size ceiling stops being theoretical.** [Section 4a.1](#4a1-a-204-does-not-mean-the-container-was-stored) measured a store that
answers `204` and drops the payload above roughly 10 MB. Base64 inflates by
four thirds, so a 5 MB encoded budget is about 3.7 MB of audio — around four
minutes of one-channel G.711 at 8 kHz. A thirty-minute call does not fit, and
nothing downstream reports the loss. **sipnab refuses above the cap rather than
emitting a container it has been told is accepted and knows is not.**

**The completeness note has to travel with the audio.** It already exists as a
string on the exported WAV, and the duplication rule of [section 4](#4-what-follows-for-the-design) already says where a
caveat goes. What media adds is the case [section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) calls the dangerous one: a container
with an empty `dialog[]` reads as *a conversation with no media*, which is a
claim about the call rather than about the capture.

`recording-set` is the one in-spec answer, and only for one of the cases.
[`core-04` section 4.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3) lets a `recording-set` Dialog Object carry the CALL's `start` and
`duration` while the `recording` object beneath it carries the FILE's. That is
how "the ring wrapped and the file is shorter than the call" gets said in the
format's own vocabulary. Nothing obliges a consumer to compare the two, which is
[section 3](#3-the-gap-vcon-cannot-say-this-container-is-an-incomplete-record) again — so the note is duplicated as well, not instead.

## 5. Declined outright

Recorded as declined with reasons rather than filed as future work, so that
none of them returns next quarter as a fresh idea. This is the method
[`deferred-and-declined.md`](deferred-and-declined.md) exists to enforce: an
unrecorded rejection comes back with the same arguments.

| Declined | Decisive reason |
|---|---|
| JWS signing | A signature over an observation verifies as a signature over a recording ([section 2.2](#22-never-sign-jws-and-never-encrypt-jwe)) |
| JWE encryption | Asserts a custody relationship sipnab does not have, and needs key infrastructure the positioning refuses |
| Consent attachments | sipnab obtained no consent, and an empty field reads as "none recorded" ([section 2.3](#23-never-emit-consent-or-lawful-basis-attachments)) |
| Lawful-basis attachments | Same, with a named regulatory consumer behind it |
| A vCon store | A database, which [section 4 of `positioning.md`](positioning.md#4-what-the-position-forbids) forbids by name |
| An HTTPS artefact host | sipnab would assert where a file lives on infrastructure it does not control ([section 2.5](#25-never-host-artefacts)) |

Note what is **not** declined: emitting an observer vCon at all. Phase 0 says
the shape is honest and the caveat problem is unsolved, not that the feature is
dead.

Nor is delivering containers to somebody else's store. `sipnab --vcon-forward`
is a separate process that POSTs the spool to a store and keeps nothing but
the files it moved; the store is still the store's. The capture process makes
no outbound connection for a container, and the forwarder reads no packet.

## 6. What would falsify this

Stated so the feature can lose, on the model of
[section 7 of `positioning.md`, "What would falsify this"](positioning.md#7-what-would-falsify-this):

- **Nobody round-trips one.** If no operator feeds a sipnab vCon into a
  conserver or any other consumer within a few months of it being available,
  the interchange demand is theoretical and the honest response is to retire
  the feature rather than to build more of it.
- **The caveat gets argued down.** If the duplication rule of [section 4](#4-what-follows-for-the-design) is repeatedly
  relaxed — first to one surface, then to a field a consumer renders as
  content — then this project is producing recording-system output with extra
  steps, and the observer framing has stopped doing any work.
- **A consumer treats it as a recording anyway.** If the containers get read as
  authoritative records of the calls despite [section 2](#2-the-five-refusals-and-the-one-role), the distinction this whole
  page is built on is one the ecosystem cannot hold, and emitting nothing is
  better than emitting something misread.

<!-- vcon-core-03-comparison:start -->
## 7. What changed between `core-03` and `core-04`

[`draft-ietf-vcon-vcon-core-04`](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04)
was published on 7 September 2026. This section compares it with
[`draft-ietf-vcon-vcon-core-03`](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-03)
(1 July 2026). The comparison read three pairs of sources:

- The plain-text drafts from the IETF archive, with page breaks removed and
  paragraphs joined before a word-level diff.
- The working group's `vcon_json_schema.json` at the repository tags
  `draft-ietf-vcon-vcon-core-03` (commit `2342aba6`) and
  `draft-ietf-vcon-vcon-core-04` (commit `99589dd0`). The `-03` file has the same
  bytes as the copy vendored at
  [`tests/schemas/publisher/vcon_json_schema.json`](../../tests/schemas/publisher/vcon_json_schema.json)
  (SHA-256 `c0501eb6…`). The `-04` file matches the schema printed in
  [`core-04` Appendix B](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B)
  once `description`, `$comment` and `title` are set aside.
- The working group's `vcon.cddl` at the `-04` tag, whose text matches
  [`core-04` Appendix C](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-C)
  apart from white space.

The syntax version string does not change. In both drafts
[section 4.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.1)
requires the value `"0.4.0"` and marks the `vcon` parameter DEPRECATED as of
RFC publication. The DEPRECATED sentence is word for word the same in `-03`, so
it is not a `-04` change.

### 7.1 Section numbers

Every section of `-03` keeps its number and its heading in `-04`, with one
retitle and two additions:

- [Section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4)
  is retitled from "Differentiation of unsigned, signed and encrypted forms of
  vCon" to "Differentiation of vCon forms".
- [Section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1)
  gains six subsections: 4.3.1.1 `recording`, 4.3.1.2 `recording-set`,
  4.3.1.3 `text`, 4.3.1.4 `transfer`, 4.3.1.5 `incomplete`, and
  [4.3.1.6, "Dialog Object Parameter Applicability by Type"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6),
  which holds Table 1.
- [Appendix C, "vCon CDDL"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-C)
  is new.

A number that did not change can still point at text that moved. These are
the `-03` passages sipnab relies on whose text moved or changed:

| `-03` section | Text | Where that text is in `-04` |
|---|---|---|
| 4.3, "Dialog Object" | "it is possible to have a Dialog Object with no parameters in it" | **Removed.** [Section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) now describes a placeholder Dialog Object "which contains only the type parameter and, for the "incomplete" type, the required disposition parameter" |
| 4.3, "Dialog Object" | "Metadata for failed or incompleted communications" | Unchanged, [section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) |
| 4.3.1, "type" | the five type values | Unchanged, [section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1) |
| 4.3.1, "type" | `incomplete` means the call "failed to be setup to the point of exchanging any conversation" | [Section 4.3.1.5, "incomplete"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5) |
| 4.3.1, "type" | an `incomplete` Dialog Object MUST have a disposition | [Section 4.3.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5) ("a required disposition parameter") and the MUST in [section 4.3.11, "disposition"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11) |
| 4.3.1, "type" | `incomplete`, `transfer` and `recording-set` MUST NOT have Dialog Content | [Section 4.3.10, "Dialog Content"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.10), which said it in `-03` as well |
| 4.3.14, "Dialog Transfer" | a `transfer` object MUST NOT carry `parties`, `originator`, `mediatype`, `filename` or Dialog Content | Each prohibition is now stated in that parameter's own section (4.3.4, 4.3.5, 4.3.8, 4.3.9, 4.3.10) and summarized in [Table 1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6) |

Every other section sipnab cites — 2.1, 2.2, 2.3, 2.3.2, 2.4.1, 4.1.2,
4.1.3, 4.1.4, 4.1.5, 4.1.7, 4.1.8, 4.2, 4.2.1, 4.2.3, 4.2.5, 4.2.7, 4.3.3,
4.3.4, 4.3.6, 4.3.7, 4.3.11, 4.3.12 and 4.4.3 — still says in `-04` what sipnab
cites it for, under the same number. Where `-04` added text to one of them,
the addition is listed in [section 7.2](#72-normative-changes).

### 7.2 Normative changes

Each row names the `-04` section that states the rule.

| `-04` section | Change from `-03` |
|---|---|
| [4, "Unsigned Form of vCon Object"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4) | New SHOULD: an unsigned vCon contains at least one of `parties`, `dialog`, `analysis` or `attachments` |
| [4.1.2, "uuid"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.2) | New sentence: "All vCon documents MUST have the uuid parameter and value set." `-03` already made `uuid` mandatory through the default rule of [section 2.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2) and through its schema |
| [4.1.8, "redacted"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8) and [4.1.9.1, "Amended Object"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9.1) | The prior vCon is referenced by UUID or by URL only. `-03` also allowed "direct inclusion" (redacted) and an "inline" reference (amended). The Amended Object's `uuid` is now "optional if external reference provided" |
| [4.1.10, "parties Objects Array"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.10) | The vCon-level `parties` array is now optional. It was mandatory in `-03` |
| [4.2.10, "uuid"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.2.10) | A Party Object's `uuid` is a free-form unique string "not constrained to the syntax defined in [UUID]", and operators MAY use any unique string |
| [4.3, "Dialog Object"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) | Media in a `text` or `recording` object SHOULD be part of the conversation itself as well as transcribable. A placeholder Dialog Object replaces the `-03` Dialog Object "with no parameters": it contains only `type`, plus `disposition` for `incomplete`. A placeholder for the consultative call of a transfer MUST be `recording` if the call was set up and `incomplete` if it was not |
| [4.3.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.1) to [4.3.1.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.5) | Per-type semantics. A `recording-set` object has no Dialog Content, and its `start`, `duration`, `parties` and `session_id` describe the whole call |
| [4.3.1.6](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6) | Table 1 marks each Dialog Object parameter MUST, SHOULD, optional, SHOULD NOT, MUST NOT or undefined for each type. The parameter sections are definitive and the table summarizes them |
| [4.3.2, "start"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.2) | `start` "SHOULD be present unless it is not known", and is optional for `transfer`. It was mandatory in `-03`, in the prose and in the schema |
| [4.3.3, "duration"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3) | `duration` is not applicable to `transfer`. On `incomplete` it may carry the time from the setup attempt to the failure |
| [4.3.4, "parties"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4) | SHOULD be present on `recording`, `recording-set` and `text`; MUST NOT be present on `transfer`; optional on `incomplete` |
| [4.3.5, "originator"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.5) | MUST NOT be present on `transfer`. For a meeting the originator is the organizer. An unknown originator may be represented by an empty Party Object |
| [4.3.8, "mediatype"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.8) | Not required when the Dialog Content is absent, as in a placeholder or a redacted object. MUST NOT be present on `recording-set`, `transfer` or `incomplete`. `-03` prohibited it on `transfer` only |
| [4.3.9, "filename"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.9) | MUST NOT be present on `recording-set`, `transfer` or `incomplete`. `-03` prohibited it on `transfer` only |
| [4.3.11, "disposition"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11) | When the reason a call failed is not known, as in a placeholder, the value `"failed"` SHOULD be used. The lowercase "must" of `-03` is now MUST |
| [4.3.12, "session_id"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.12) | MUST NOT be present on `transfer`. A `recording-set` object is named as "the appropriate place" for a session identifier of the whole call (no [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keyword) |
| [4.3.13, "party_history Objects Array"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13) and [4.3.13.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.13.1) | `party_history` MUST NOT be present on `transfer`. `button` is marked optional, and still required for `keydown` and `keyup` |
| [4.3.14, "Dialog Transfer"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.14) | `transfer_target`, `original`, `consultation` and `target_dialog` each take one `UnsignedInt`. The `UnsignedInt[]` form of `-03` is removed. `transfer_target` is optional, for a transfer abandoned before a target was identified. `original`, `consultation` and `target_dialog` may name a `recording-set` object |
| [4.3.16, "message_id"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.16) | Applies to `recording` and `text`. MUST NOT be present on `recording-set`, `transfer` or `incomplete` |
| [4.4.5, "mediatype"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.5) | An Attachment Object's `mediatype` MUST be present for inline content, and for external content without an HTTPS `Content-Type`. Not required when the content is absent |
| [4.5.4, "mediatype"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.5.4) | An Analysis Object's `mediatype` is now marked optional, and SHOULD be present for inline content. When no media type exists for the format, `vendor`, `product` and `schema` SHOULD identify it |
| [5.4, "Differentiation of vCon forms"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4) | A gzip-compressed vCon SHOULD be identified by the media type `application/vcon+gzip` when a media type is available, and otherwise by the gzip magic numbers, before the JSON form is identified |
| [6.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-6.3.3) and [6.3.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-6.3.5) | The IANA registries gain `did` (Party Object) and `button` (party_history Object), and the Party `uuid` entry is described as a "participant unique identifier" |

### 7.3 Appendix B: the schema

Compared as parsed JSON, the `-04` schema differs from the `-03` schema as
follows:

- `Dialog.required` is `["type"]`. It was `["type", "start"]`.
- `Dialog` gains an `allOf` of nine `if`/`then` rules: `incomplete` requires
  `disposition`; `recording-set` requires `recordings`; `transfer`,
  `recording-set`, `incomplete`, `recording` and `text` each prohibit the
  parameters Table 1 marks MUST NOT; and a non-empty `body` requires
  `encoding` and `mediatype`. The prohibitions follow [Table 1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6).
- `Dialog`, `Attachment` and `Analysis` gain `dependencies: {"url":
  ["content_hash"]}`.
- `Attachment` requires `encoding` and `mediatype` with a non-empty `body`.
  `Analysis` requires `encoding` with one.
- `transfer_target`, `original`, `consultation` and `target_dialog` are a
  non-negative integer. Each was `oneOf` an integer or an array of integers.
- `PartyHistory` requires `button` when `event` is `keydown` or `keyup`.
- The top level forbids `redacted` and `amended` together. The prose said
  they were mutually exclusive in `-03` as well; the schema did not enforce it.
- `amended` requires `uuid` when it has no `url`.
- The keywords `allOf`, `if`, `then` and `not` appear for the first time.

[Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-A) names six unsigned examples by file: A.1, A.2, A.4, A.5, A.8 and
A.9. Read from the repository at each tag, all six `-04` copies validate
against the `-04` schema, and all six `-03` copies failed the `-03` schema:
five lacked `created_at`, and A.2 carried `"redacted": {}`, which the Redacted
Object's required `type` rejects.

### 7.4 Appendix C: the CDDL

Appendix C says it is informative and that the prose governs where they
differ. Read against the prose and Appendix B:

- **Agrees:** `type` is required on every Dialog Object, `start` is optional,
  the transfer indices are single integers, `incomplete` requires
  `disposition`, `recording-set` requires `recordings`, and `keydown` and
  `keyup` require `button`.
- **Weaker than Appendix B, by its own statement:** every object ends in the
  wildcard `* tstr => any`, so a parameter Table 1 prohibits still matches the
  wildcard. A container that a CDDL validator accepts can fail [Appendix B](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-B).
- **Contradicts the prose and Appendix B:** `inline_content_type` pairs every
  `body` with `encoding`, including an empty string. [Table 1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.6) note (3) requires
  `encoding` only "when the body parameter is present and is not an empty
  string", and Appendix B tests `body` against `const: ""` before requiring it.
- **Contradicts Appendix B:** the Redacted and Amended Objects group `url` with
  `content_hash`, so `content_hash` without `url` matches neither branch.
  Appendix B and [section 4.1.8.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8.1) only require `content_hash` when `url` is
  present.

### 7.5 Where `-04` is ambiguous or contradicts itself

1. **Which placeholders the MUST covers.** [Section 4.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3) says "a placeholder
   Dialog Object for it MUST be of type "recording" if the call was set up,
   or of type "incomplete" if it was not", and "it" is the consultative call
   of a transfer. [Appendix C](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-C)'s comment drops that scope: "A placeholder Dialog
   Object MUST be of type "recording" if the call was set up, or of type
   "incomplete" if it was not." One reading limits the rule to consultative
   calls; the other applies it to every placeholder. Neither defines "set
   up" for a producer that did not see the call's outcome.
2. **Inline references survive in section 5.** [Sections 4.1.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.8) and [4.1.9.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.9.1)
   dropped the inline reference to a prior vCon, but
   [section 5, "Security Considerations"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5)
   still says the vCon referenced in `redacted`, "if inline, SHOULD be
   encrypted".
3. **An incompatible change without a version change.** `-04` narrows the
   transfer indices to one integer and requires `type` on a Dialog Object that
   `-03` allowed to have no parameters, so some `-03` containers are invalid
   under `-04`. The syntax version stays `"0.4.0"`, and
   [section 7.1, "Version 0.3.0 to 0.4.0"](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-7.1)
   lists no change. A consumer cannot tell a container written to `-03` from
   one written to `-04` by its version string.
4. **`mediatype` is "M" with an exception.** Table 1 marks `mediatype` M for
   `recording` and `text`, and note (1) and [section 4.3.8](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.8) waive it whenever the
   content is absent. Appendix B requires it only beside a non-empty `body`.
5. **`duration` on `transfer`.** [Section 4.3.3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.3) says `duration` "is not
   applicable to the "transfer" type". Table 1 gives it the symbol for "MAY be
   present but its semantics are undefined".
6. **Unchanged from `-03`, still unresolved:** the `vcon` parameter line in
   [section 4.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.1) carries no "(optional)" marker, and [section 2.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.2) makes every
   unmarked parameter mandatory, while Appendices B and C make it optional.

### 7.6 Editorial changes

- [Section 3](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-3): the signed form is defined "using [JWS]" (it read "[JWE]"), and
  the encrypted form gains "using [JWE]".
- [Section 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2): the payload construction cites
  [RFC 7515 section 7.2.1](https://www.rfc-editor.org/rfc/rfc7515#section-7.2.1)
  as [JWS] (it read [JWK]), and [JWK] leaves the normative references.
- [Section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4): "UnisignedInt" corrected to "UnsignedInt"; [section 4.3.12](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.12):
  "[SESSION-ID}" corrected.
- Spelling and punctuation: "other wise" and a misspelled "string" in
  [section 4.3.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1) corrected, the
  `signatures` and `signature` parameter lines of [sections 5.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2) and [5.2.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.2.1) gain
  their missing colons, and `message_id` is typed "String" rather than
  "string".
- IANA tables renumbered after the new Table 1, and reflowed.
- [Appendix A](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#appendix-A): every example regenerated with new UUIDs, signatures and
  timestamps; `created_at` added where it was missing; `"group": []` and
  `"redacted": {}` removed; the analysis example's transcription output
  regenerated.
### 7.7 What sipnab does about each open question

Each choice below is the one the code makes, with the reading it rejected.

1. **The placeholder type.** sipnab types its signaling Dialog Object
   `recording`, with no content, for every outcome except an observed final
   failure (an answered call, a call whose final response the capture never
   saw, and a redirect), and `incomplete` with a disposition for an observed
   failure, as before. The consultative-call placeholder of an attended
   transfer is `{"type": "recording"}`: the `Replaces` in the `Refer-To`
   names an existing dialog, so the call was set up.
   - Rejected: `incomplete` with `"failed"` (the SHOULD of
     [section 4.3.11](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.11)) for a call whose final response
     was not seen. It would report a failure sipnab did not observe, which
     [section 3.1](#31-incomplete-means-the-call-failed-not-the-record) refuses.
   - Rejected: a `recording-set` with `"recordings": []` for a call with no
     media. It validates, and the conserver transcription links skip it,
     but [section 4.3.1.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.1.2) defines a `recording-set` by
     the recordings it groups, and an empty set groups none.
   - The cost, measured in the vcon-server conserver source at commit
     `8ffbfcf`: `deepgram_link` reads `dialog["url"]`, and
     `hugging_face_whisper` and `groq_whisper` read `dialog["duration"]`,
     with a bracket on any object typed `recording`, so they raise on the
     placeholder. All four transcription links, `openai_transcribe`
     included, read `dialog["type"]` with a bracket, so they raised on the
     type-free object sipnab wrote under `core-03`.
2. **Inline references in section 5.** sipnab's `redacted` object carries
   neither `uuid` nor `url`, because no unredacted container exists to point
   at. Neither reading changes what it writes.
3. **The version string.** sipnab writes `"0.4.0"`, which
   [section 4.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.1) requires. A consumer that has to know
   which revision a sipnab container follows reads the release notes; the
   container cannot say.
4. **`mediatype`.** sipnab writes `mediatype` beside every `body` it emits,
   and none on a placeholder, which satisfies both readings.
5. **`duration` on `transfer`.** sipnab writes none, which satisfies both
   readings.
6. **The `vcon` parameter.** sipnab always writes it, which satisfies both
   readings.

Not adopted, and why:

- **CDDL validation.** Appendix C is informative, its wildcard makes it
  weaker than Appendix B, and validating against it needs a CDDL
  implementation this repository does not depend on. The validators check the
  publisher's Appendix B schema instead, which the working group publishes as
  a file and which matches the draft.
- **`session_id` on a `recording-set`.** [Section 4.3.12](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.12)
  calls the set "the appropriate place" for a session identifier of the whole
  call, without a requirement keyword. sipnab's ring-wrapped export replaces
  the signaling object with the set and does not carry the observed
  `session_id` across. Carrying it is a candidate change, not a conformance
  fix.
- **`parties` on a `recording-set` or a placeholder.** A SHOULD in
  [section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4), as it was in `core-03`. sipnab names a
  party per channel only from evidence, and a placeholder "contains only the
  type parameter".
- **gzip identification** ([section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4)). sipnab neither
  writes nor reads a gzip-compressed vCon.
<!-- vcon-core-03-comparison:end -->
