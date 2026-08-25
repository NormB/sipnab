# The vCon exporter

What [`src/output/vcon.rs`](../../src/output/vcon.rs) holds, which sipnab type
feeds each part of the container, and the two mechanisms an editor has to
respect: the duplicated completeness caveat, and the deterministic uuid.

Read [Export one observed call as a vCon](../vcon.md) for the operator's view
and [the Phase 0 decision](../design/vcon.md) for why the module refuses what it
refuses. This page is about the code.

## Shape of the module

One file behind the non-default `vcon` feature, which `full` carries. It has no
submodules and no state: every input arrives as an argument, and nothing in it
reads a process global except the node name.

The public surface is a struct per vCon section — `Vcon`, `Party`, `Dialog`,
`Attachment`, `Analysis` — plus `BlindSpot` and `CaptureCompleteness` for the
caveat, `ExportContext` for everything the dialog itself does not carry, and
three functions: [`export_dialog()`](../../src/output/vcon.rs),
[`export_dialog_at()`](../../src/output/vcon.rs) and
[`dialog_uuid()`](../../src/output/vcon.rs).

`export_dialog_at()` is the pure form and the one every test drives. Its third
argument is the container's `created_at`, so two exports compare byte for byte
and any difference between them came from the capture rather than from the
clock. `export_dialog()` is the same function with `Utc::now()` supplied.

Serialization is `serde`'s. Each struct maps one-to-one onto its vCon object,
with `skip_serializing_if = "Option::is_none"` doing the work of "sipnab did
not observe this" — an absent field, never a null.

## Where each section comes from

| vCon section | Read from | Built by |
|---|---|---|
| `vcon`, `extensions` | module constants | inline in `export_dialog_at()` |
| `uuid` | the dialog's `Call-ID` and clock, the capture id, the node name | [`dialog_uuid()`](../../src/output/vcon.rs) |
| `created_at` | the caller's clock, not the dialog's | the `exported_at` argument |
| `parties[0]`, `parties[1]` | `SipDialog`'s `from_*`/`to_*` fields, the opening message, the first response | [`observed_parties()`](../../src/output/vcon.rs) |
| `parties[last]` | [`node_name()`](../../src/provenance.rs) and the crate version | [`observer_party()`](../../src/output/vcon.rs) |
| `dialog[0]` | the `Call-ID` and [`final_status_code()`](../../src/sip/dialog.rs) | [`dialog_object()`](../../src/output/vcon.rs) |
| `attachments[0]` | the message ladder, through [`message_to_json_value()`](../../src/output/json.rs) | [`message_trace_attachment()`](../../src/output/vcon.rs) |
| `attachments[1]` | `CaptureFacts` and the ranked `CaptureAnalysis` | [`completeness_attachment()`](../../src/output/vcon.rs) |
| `analysis[0]` | [`diagnose_signaling()`](../../src/sip/diagnosis.rs) and the same completeness value | [`report()`](../../src/output/vcon.rs) |

Two of those rows carry a decision rather than a mapping.

**The message trace reuses `--json`'s projection.** One serializer produces both,
so a vCon and an NDJSON line describing one message cannot disagree about it. The
cost of that reuse is the credential strip, further down.

**The report reuses the signaling diagnosis.** It is already the wire shape the
dialog-JSON surface emits, and a second projection of one analysis is two
definitions waiting to drift apart.

`ExportContext` exists for the same reason `CaptureFacts` does: it makes visible,
in one place, exactly which facts a completeness claim stands on, and it lets a
test state the capture it describes instead of mutating a global.

## The completeness carrier

This is the mechanism the whole module exists for, and the one an edit is most
likely to break.

sipnab's ranked problem list puts incompleteness findings **inside** the list at
`Severity::Blind`, above every call fault, so "no problems found" is
structurally unreachable for an incomplete read. vCon offers no position with
that property. `analysis[]` is a list of conclusions, and a caveat placed there
is one entry among others.

### Why duplication rather than one field

The obvious repair is a custom extension carrying the caveat, and the format
rules it out. An extension is either **compatible** — a consumer that does not
implement it ignores it safely — or **critical**, which a consumer that does not
implement it MUST NOT process except to reject. There is no third level meaning
*read this before trusting the contents*.

Pick either and the caveat fails. Ignorable, and the consumer that most needs it
drops it. Critical, and an ordinary vCon reader refuses the whole container, so
sipnab has emitted something nobody can read.

So the caveat goes into two surfaces a consumer walks past anyway:

1. `capture_completeness` inside `analysis[0].body`, beside the diagnosis.
   `body` is a JSON-encoded **string**, so that is a path through the decoded
   text, not a path a reader can index directly — see below.
2. An attachment with purpose `sipnab-capture-completeness`, whose `party`
   index names the sipnab observer.

### One value, embedded twice

[`completeness_of()`](../../src/output/vcon.rs) builds **one**
`CaptureCompleteness`. `export_dialog_at()` then hands the same value to
`completeness_attachment()` and to `report()`. Nothing rebuilds it, and nothing
formats it a second time.

That distinction is the whole rule. Two strings built twice drift, and a
container whose two caveats disagree reads as authoritative while contradicting
itself — worse than one carrying no caveat at all. The audio exporter learned
this the expensive way: it built its embedded note and its printed summary
separately, a clause reached one and not the other, and a comparison test caught
it. This module copies that shape deliberately.

**The divergence gate is
`the_two_completeness_surfaces_carry_one_value`.** It exports one dialog against
facts carrying two distinct losses, then asserts that the attachment body and the
report's `capture_completeness` compare equal as JSON values. Rebuild the caveat
in either place and it fails.

Two more tests hold the ends of it:

- `the_completeness_carrier_discriminates_a_lossy_run_from_a_clean_one` exports
  one dialog twice, against a run that lost seven captured messages and a run
  that lost none, and requires the two notes to differ. Without it the carrier
  could be decoration — identical on every run, and equal to itself. Deleting
  the `messages_evicted` clause fails it.
- `an_absent_analysis_is_not_a_clean_bill` separates "nobody looked" from
  "looked and found nothing". `blind_spots` stays absent when no analysis
  reached the export and becomes `[]` when one ran and ranked nothing.
  Collapsing the two lets a run that skipped the analysis read as clean.

## The spec is the gate, not our reading of it

Two decisions in this module came from reading
[the draft](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/) and
the reference implementation rather than from what looked natural in Rust. Both
were wrong in the first cut, and a hand-written test agreed with the wrong
answer, because the same misreading produced both.

**`body` is a String, never an object.** §2.3.2 says so, and
`vcon-server`'s own model enforces it: hand its `Vcon` a `dict` and it
JSON-encodes the value before anything else sees the attachment. So
[`json_text()`](../../src/output/vcon.rs) serializes every structured body to
text on the way out, and every test that reads one parses it back. A body typed
as `serde_json::Value` round-trips fine through `serde_json` and fails against a
real store, which is exactly the class of defect a local test cannot see.

**The format demands some fields even when there is nothing to say.** The
working group's schema makes `type` and `start` mandatory on every dialog
object and `start`, `party` and `dialog` mandatory on every attachment. An
empty dialog object reads as tidy and is invalid. `dialog_object()` therefore
always names a `type` and always carries a `start`.

**The `type` follows the CONTENT, not the call.** `dialog_object()` builds
`incomplete`, because at construction the object carries nothing. The media
path retypes it to `recording` when audio actually arrives, and clears
`disposition` with it. Typing an object `recording` when it carries no
content — which this module did until 0.5.125 — is an ingest hazard rather than
an imprecise label. The conserver's transcription link selects
`type == "recording"` and then reads `dialog["url"]` with a bracket, so the
link raises, and the conserver dead-letters the entire container. The converse
costs as much: every `type == "recording"` selector skips audio left on an
`incomplete` object, so the WAV sits in the container unreachable. `audio_never_rides_on_an_object_typed_incomplete`
and `nothing_is_typed_a_recording_without_content_to_reach` pin both directions,
and the second lives in the SIGNALING-ONLY test file on purpose: over a media
fixture every object has a body, so the assertion passes vacuously and the
mutation survives.

**The repository carries the schema, so the gate runs offline.**
[`tests/schemas/vcon.schema.json`](../../tests/schemas/vcon.schema.json) is the
working group's own schema, vendored.
`a_container_validates_against_the_working_group_schema` in
[`tests/vcon_ingest_contract_test.rs`](../../tests/vcon_ingest_contract_test.rs)
validates a real export against it. That one test found six violations that the
hand-written assertions around it had all missed, because those assertions
encoded what we believed the format required. Add a field and this gate — not
a reviewer — tells you whether the format agrees.

**Media enriches the signaling object rather than appending a second one.** A
dialog is one conversation, and a container that carries a `recording` object
beside a separate signaling object describes it as two. When audio decodes,
`export_dialog_at()` fills the existing object's `start`, `duration`,
`parties`, `mediatype`, `encoding`, `content_hash` and `body` in place. The one
exception is a wrapped ring buffer, where the retained audio genuinely is a
subset of a longer call: there the object becomes a `recording-set` and the
audio hangs beneath it, which is what that type is for.

## Adding a field without breaking the divergence gate

The gate compares whole JSON objects, so the rule is short: **add the field to
`CaptureCompleteness`, and to nothing else.**

1. Add the field to the struct. Both surfaces serialize the same value, so both
   gain it at once and the equality assertion still holds.
2. Populate it in `completeness_of()`, from `ExportContext` and from nothing
   else. Reading a process global here is what stops an export from reproducing.
3. If the field describes a loss, add a clause to
   [`completeness_note()`](../../src/output/vcon.rs) so the prose surface says
   what the structured surface counts. Write it as a measurement of the run.
   Never as a conclusion about the call: "the capture missed the answer" is a
   fact about the tap, and "the call went unanswered" is a fact about the
   traffic, and this module exists because vCon cannot tell them apart.
4. Extend `the_completeness_carrier_discriminates_a_lossy_run_from_a_clean_one`
   with a run that moves the new field, or the clause is unproven.

What breaks the gate is building a value inside `report()` or inside
`completeness_attachment()`. Both take a `&CaptureCompleteness` and serialize
it. Keep it that way.

Two adjacent rules an edit trips over:

- **Never put a caveat in `subject`.** The core draft defines it as the topic of
  the conversation, so a disclaimer there arrives styled as a fact about the
  call. `the_container_declares_its_version_and_signs_nothing` asserts `subject`
  stays absent, together with `signatures`, `payload`, `protected`, `jwe`,
  `jws` and `consent`.
- **Never widen `failure_disposition()` below 400.** A 3xx redirect did not
  fail, and a container claiming it did sends an operator after a fault that is
  not there. The redirect case sits inside the mapping test on purpose, so
  widening the range fails there rather than shipping.

## The uuid: deterministic by construction

[`dialog_uuid()`](../../src/output/vcon.rs) writes a UUIDv8 laid out like a
UUIDv7 — a 48-bit millisecond timestamp, a 12-bit `rand_a`, a 62-bit `rand_b` —
with three choices that make it a function of the observation rather than of the
run:

| Field | Source | Why |
|---|---|---|
| 48-bit timestamp | the **dialog's** `created_at` | the export clock here would mint a new identifier on every re-export |
| `rand_a`, 12 bits | SHA-256 of `Call-ID`, a `0x1e` separator, then `capture_id` | ties the value to the dialog and the capture it came from |
| `rand_b`, 62 bits | the high 62 bits of SHA-256 over the node name | the draft asks for a host-derived value here |

The separator byte matters: a bare concatenation collides `("ab", "c")` with
`("a", "bc")`.

Version bits go in the high nibble of octet 6 and the variant `10` in the two
high bits of octet 8, per RFC 9562. `rand_b` shifts **down** by two rather than
masking its top bits off, so the variant bits overwrite nothing the draft asked
for.

`created_at` still carries the export time, where the draft puts it. Two exports
of one dialog days apart therefore share a uuid and differ in `created_at`, and
`the_uuid_separates_dialogs_captures_and_clocks` asserts exactly that pair.

**The collision window.** A host-derived `rand_b` spends the entropy a v7 would
have used, so two dialogs that opened in the same millisecond on the same node
have 12 bits between them. That is inherent in the layout the draft asks for.
The module documents it rather than leaving a consumer to assume otherwise, and
the operator page repeats it. Deduplication on `uuid` is safe for the case it
exists for — the same dialog exported twice — and is not a uniqueness guarantee
across a busy node.

One more substitution to know about: the draft names SHA-1, and this tree has
none. Adding a broken hash as a dependency to fill 62 bits of a non-security
identifier is the worse trade, and UUIDv8 constrains only the version and
variant bits, both of which this function writes. What changes is which bits
land in `rand_b`, and nothing reads them.

## The credential strip, and what it does today

[`strip_credentials()`](../../src/output/vcon.rs) walks a JSON value at every
depth and drops any key matching `CREDENTIAL_HEADERS` —
`Authorization`, `Proxy-Authorization`, `WWW-Authenticate` and
`Proxy-Authenticate` — comparing case-insensitively, because SIP header names
are case-insensitive on the wire and a filter keyed on exact case is one an
ordinary peer walks through.

`Proxy-Authenticate` is on the list although the SIP-signaling extension names
only three. It is the proxy-side twin of `WWW-Authenticate`, carries the same
realm and nonce, and leaving it off would hold the rule for one hop and not the
other.

**It removes nothing today, and the module docs say so.** It guards a
projection: `message_to_json_value()` carries no raw header map, so no message
sipnab parses now reaches the filter with a banned key on it. The filter is a
**regression gate at the publication boundary**, and the boundary is where the
rule has to live. Giving that projection a `headers` field is an ordinary,
sensible change to a debugging surface, and it would start putting digest
credentials into a container that leaves this machine.

Do not describe this filter as protecting the current export, and do not delete
it because a coverage run shows it removing nothing. Two tests keep the
distinction visible:

- `the_credential_filter_removes_banned_headers_at_every_depth` is the half that
  discriminates today. It runs against a hand-built value, because an end-to-end
  export cannot reach the filter with anything to remove. Mutation-proven:
  deleting the `retain` fails it, and its anti-vacuity assertions fail a filter
  that emptied the object instead.
- `no_credential_survives_an_export` is the end-to-end half. It passes on the
  strength of the projection rather than of the filter, and it is what refuses
  the digest response the day that changes.

## What the tests cover

Unit tests live in the module and reach its private helpers.
[`tests/vcon_export_test.rs`](../../tests/vcon_export_test.rs) is the other half
and proves two things the unit tests structurally cannot: that the whole export
is reachable through the crate's **public** surface, and that a dialog off a
real parsed capture carries what the hand-built fixtures carry. A projection can
agree with a synthetic dialog and disagree with the parser.

Both halves gate on the feature, so a build without `vcon` compiles neither.

## See also

- [Export one observed call as a vCon](../vcon.md) — the operator page
- [The Phase 0 decision](../design/vcon.md) — the five refusals, and the
  structural gap in the format that decides the module's shape
- [Invariants](invariants.md) — the rules that must not break, and what enforces
  each one
- [Testing](testing.md) — the test tiers this module's two halves sit in
