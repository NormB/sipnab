# SIP conformance rules

Every rule the conformance linter runs, the RFC section behind it, and how to
turn it off.

Each rule carries a stable identifier such as
`SIP-3261-8.1.1.7-BRANCH-COOKIE`. Quote that identifier in a carrier ticket,
and use it to suppress the rule in CI. Identifiers never change meaning, and
nothing reuses a retired one.

## What makes these rules different

Most SIP linters read messages against a grammar. They catch a malformed
`Contact` header. They cannot catch the far end sending payload type 8 when the
SDP declared payload type 0, because they never see the RTP.

sipnab holds the signalling and the media in one process. The `OBS-` rules
compare what the SDP declared against what the wire carried, and that class of
defect stays invisible to any tool that reads only text.

## Conformance is not the same question as outcome

[`src/sip/diagnosis.rs`](../src/sip/diagnosis.rs) answers "why did this call
fail". This linter answers "does this traffic obey the specification". A call
can complete over messages that break four MUSTs, and a fully conformant call
can hit a busy signal. Keep the two questions apart.

## Reading a finding

A finding carries the rule identifier, a severity, a basis, the RFC number and
section as separate fields, the index of the message it came from, what the
capture held, what the section calls for, and why the difference matters.

The RFC number and the section are data, not prose inside a sentence. That
choice caught a mistake while this module was still new: three sources place
the angle-bracket rule for a `Contact` URI in RFC 3261 §20.10, and the sentence
actually sits in the preamble of Section 20, above §20.1. A citation nothing
can read is a citation nothing can check.

## Severity and basis are separate axes

Severity says how much attention a finding deserves: `error`, `warning`,
`notice`, `info`.

Basis says what kind of claim the rule makes, and the four values do not
overlap:

| Basis | Meaning |
|---|---|
| `must` | The cited section says MUST or MUST NOT, and the message disobeys it. |
| `should` | The cited section says SHOULD or RECOMMENDED. Deviating stays legal. |
| `interop` | No specification forbids this. Deployed equipment mishandles it anyway. |
| `observation` | The declaration and the observed media disagree. |

Keeping `must` apart from `interop` matters more than it looks. A reader who
cannot tell a broken MUST from a vendor-compatibility hint learns to discount
both, and the MUST is the one worth acting on.

## Rulesets

Select a named subset by name:

| Name | Contents |
|---|---|
| `all` | Every rule. The default. |
| `must` | Only MUST violations. Defensible in a carrier ticket without argument. |
| `rfc` | MUST and SHOULD. Excludes the vendor heuristics and the media rules. |
| `interop` | Only the "this breaks real equipment" heuristics. |
| `observation` | Only the declaration-versus-observation rules. |
| `syntax` | Only the rules that read a single message with no dialog context. |

## Suppression

A suppression pattern is an exact rule identifier, or a prefix ending in `*`:

```text
# Our carrier rewrites Contact and we have stopped arguing about it
SIP-3261-19.1.1-URI-PARAM-DEMOTED

# No media in these captures, so the observation rules have nothing to read
OBS-*
```

Patterns separate on commas, spaces or newlines, and `#` starts a comment.

One further guard rail keeps CI readable: a single rule reports at most 25
findings per dialog by default. A dialog retransmitting an `INVITE` eleven
times trips a message rule eleven times, and every one of them is true, but
printing all eleven buries the other rules.

## Observation rules

These read the media against the declaration. Every one of them needs RTP or
RTCP that sipnab attributed to the dialog.

| Rule | Severity | Cites | Fires when |
|---|---|---|---|
| `OBS-3264-6.1-PT-UNDECLARED` | error | [RFC 3264 §6.1](https://www.rfc-editor.org/rfc/rfc3264#section-6.1) | The wire carries an RTP payload type that no offer or answer in the dialog declared. Comfort noise on payload type 13 stays exempt, because equipment sends it without ever listing it. |
| `OBS-4566-5.14-MEDIA-PORT-MISMATCH` | warning | [RFC 4566 §5.14](https://www.rfc-editor.org/rfc/rfc4566#section-5.14) | RTP arrives at a declared media address on a port nobody advertised. The RTCP port one higher stays exempt. |
| `OBS-3264-6.1-DIRECTION-UNMET` | warning | [RFC 3264 §6.1](https://www.rfc-editor.org/rfc/rfc3264#section-6.1) | Both ends negotiated `sendrecv`, media flowed, and one negotiated endpoint received none of it. |
| `OBS-4566-6-PTIME-MISMATCH` | notice | [RFC 4566 §6](https://www.rfc-editor.org/rfc/rfc4566#section-6) | The packetization on the wire differs from `a=ptime` by more than half. |
| `OBS-5761-5.1.1-RTCP-MUX-UNANSWERED` | error | [RFC 5761 §5.1.1](https://www.rfc-editor.org/rfc/rfc5761#section-5.1.1) | An offer asked for `a=rtcp-mux`, the answer stayed silent, and RTCP arrived on the RTP port regardless. |
| `OBS-3551-4.2-FRAME-SIZE-IMPOSSIBLE` | warning | [RFC 3551 §4.2](https://www.rfc-editor.org/rfc/rfc3551#section-4.2) | The payload size implies more media per packet than §4.2 asks a receiver to accept, or more media than the elapsed time between packets. |

### One-sided thresholds

Three of these rules compare one duration against another, and every comparison
runs in one direction only.

Silence suppression, comfort noise and a congested path all stretch the gap
between packets. None of them compresses it. A rule that fires on "slower than
declared" therefore fires on a large share of ordinary traffic, and a rule that
fires on "carrying more media than time elapsed" fires only on the impossible.

The packetization measurement reads payload size rather than arrival times
wherever the codec has a fixed octet rate, for the same reason: 20 ms packets
stay 20 ms packets however far apart they arrive.

### Codec shapes

Deriving a duration from a payload size needs a codec with a fixed octet rate.
[RFC 3551](https://www.rfc-editor.org/rfc/rfc3551) Table 1 supplies five, and
only those five participate:

| Codec | Octets per millisecond | Frame |
|---|---|---|
| PCMU | 8 | sample-based |
| PCMA | 8 | sample-based |
| G722 | 8 | sample-based |
| G729 | 1 | 10 octets per 10 ms |
| GSM | 1.65 | 33 octets per 20 ms |

Opus, AMR and the other variable-rate codecs have no such number, so the two
size rules skip them rather than invent a threshold.

## Syntactic rules

These read one message on its own.

| Rule | Severity | Basis | Cites | Fires when |
|---|---|---|---|---|
| `SIP-3261-8.1.1-MANDATORY-HEADER-MISSING` | error | must | [RFC 3261 §8.1.1](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1) | One of `Call-ID`, `CSeq`, `From`, `To` or `Via` is absent. |
| `SIP-3261-20.16-CSEQ-MALFORMED` | error | must | [RFC 3261 §20.16](https://www.rfc-editor.org/rfc/rfc3261#section-20.16) | A `CSeq` arrives that nothing can read as a number and a method. |
| `SIP-3261-20.14-CONTENT-LENGTH-MISMATCH` | error | must | [RFC 3261 §20.14](https://www.rfc-editor.org/rfc/rfc3261#section-20.14) | `Content-Length` exceeds the body that arrived. |
| `SIP-3261-25.1-HEADER-CONTROL-BYTE` | error | must | [RFC 3261 §25.1](https://www.rfc-editor.org/rfc/rfc3261#section-25.1) | A header name or value holds a control byte other than tab. |
| `SIP-3261-20-URI-BRACKETS` | error | must | [RFC 3261 §20](https://www.rfc-editor.org/rfc/rfc3261#section-20) | A `Contact`, `From` or `To` URI holds a comma or a question mark outside angle brackets. |
| `SIP-3261-19.1.1-URI-PARAM-DEMOTED` | warning | interop | [RFC 3261 §19.1.1](https://www.rfc-editor.org/rfc/rfc3261#section-19.1.1) | A URI parameter — `transport`, `user`, `method`, `ttl`, `maddr` or `lr` — sits outside the angle brackets, where the receiver reads it as a header parameter. |
| `SIP-3261-8.1.1.6-MAX-FORWARDS-MISSING` | warning | must | [RFC 3261 §8.1.1.6](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.6) | A request carries no `Max-Forwards`. |
| `SIP-3261-20.22-MAX-FORWARDS-RANGE` | notice | should | [RFC 3261 §20.22](https://www.rfc-editor.org/rfc/rfc3261#section-20.22) | `Max-Forwards` reads zero, exceeds the recommended 70, or holds no integer. |
| `SIP-3261-8.1.1.7-BRANCH-COOKIE` | warning | must | [RFC 3261 §8.1.1.7](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.7) | A request's top `Via` branch lacks the `z9hG4bK` magic cookie, or carries no branch at all. |
| `SIP-3261-8.1.1.5-CSEQ-METHOD-MISMATCH` | error | must | [RFC 3261 §8.1.1.5](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.5) | The `CSeq` method disagrees with the request line. |

### Why the bracket rules split in two

RFC 3261 §20 gives one sentence for three characters, and the three do not
behave alike.

A comma or a question mark in a bare URI breaks the MUST outright: the receiver
splits the value there and reads a different URI than the one sent. That is
`SIP-3261-20-URI-BRACKETS`, and it goes in the `must` ruleset.

A semicolon is different. `Contact: sip:a@b;transport=tcp` parses as perfectly
legal SIP that means something the sender did not intend, because `transport`
is a URI parameter and outside the brackets it lands on the header. Nothing on
the wire breaks a MUST, so `SIP-3261-19.1.1-URI-PARAM-DEMOTED` reports as
interop and stays out of the `must` ruleset. It remains the defect most often
found at the bottom of a "calls reach the wrong trunk" ticket.

A bare `From: sip:alice@example.com;tag=1928301774` trips neither, and RFC 3261
uses that form in its own examples. `tag` is a header parameter, so it belongs
where it sits.

## Dialog rules

These read a dialog's messages against each other.

| Rule | Severity | Basis | Cites | Fires when |
|---|---|---|---|---|
| `SIP-3261-8.1.1.2-TO-TAG-IN-INITIAL-REQUEST` | warning | must | [RFC 3261 §8.1.1.2](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.2) | A `REGISTER` carries a `To` tag, or the dialog's first request carries one and its own transaction answers with a different tag. |
| `SIP-3261-17.1.1.3-ACK-CSEQ-MISMATCH` | error | must | [RFC 3261 §17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.1.3) | An `ACK` carries a sequence number belonging to no `INVITE` in the dialog. |
| `SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT` | error | must | [RFC 3264 §6.1](https://www.rfc-editor.org/rfc/rfc3264#section-6.1) | An answer shares no media format with the offer, on a stream it did not decline. |
| `SDP-3264-6.1-ANSWER-EXTRA-FORMAT` | info | interop | [RFC 3264 §6.1](https://www.rfc-editor.org/rfc/rfc3264#section-6.1) | An answer lists a format the offer never carried. |
| `SDP-3264-6.1-ANSWER-DIRECTION-ILLEGAL` | error | must | [RFC 3264 §6.1](https://www.rfc-editor.org/rfc/rfc3264#section-6.1) | The answer's direction attribute contradicts what the offer's admits. |
| `SDP-3264-8.4-HOLD-CONNECTION-ZERO` | warning | should | [RFC 3264 §8.4](https://www.rfc-editor.org/rfc/rfc3264#section-8.4) | A re-offer blanks the connection address to signal hold. |

### An answer listing an extra codec stays legal

A widely repeated claim holds that an answer containing a codec absent from the
offer breaks RFC 3264. It does not. §6.1 permits the extra listing in as many
words, and explains why it rarely helps: the answerer cannot send with a format
the offer never listed.

So the MUST violation is the *absence* of any shared format, which
`SDP-3264-6.1-ANSWER-NO-COMMON-FORMAT` reports as an error. The extra listing
reports separately, as info, under `interop`. Equipment that reads the answer
as the negotiated set picks one of the extras and sends media the far end
drops, which is worth knowing and is not a broken MUST.

### Hold by blanking the address

sipnab has always found hold through `a=sendonly` and `a=inactive`. RFC 3264
§8.4 describes a third mechanism that RFC 2543 defined and §8.4 discourages:
setting the connection address to `0.0.0.0`. Until this rule, a call held that
way looked to sipnab like a call that simply stopped.

§8.4 keeps one legitimate use — an *initial* offer from an agent that does not
yet know its own address — so the first SDP body in a dialog stays exempt and a
later one does not. A stream declined with port zero stays exempt as well.

### Why the `To` tag rule is hard to trigger

One message cannot say whether a request sits inside a dialog. A message-scoped
version of this rule fires on every re-`INVITE` in every capture that starts
mid-call, which is most captures.

Two shapes settle it. A `REGISTER` never sits inside a dialog, so a `To` tag
there is wrong wherever the capture started. Otherwise the rule needs the
answer to that same transaction, matched on the §8.1.1.7 branch, to carry a
*different* tag — proof that the responder treated the request as new and chose
its own.

An earlier form of this rule compared against every response in the dialog and
fired on 2,182 dialogs of the validation corpus, 2,160 of them `SUBSCRIBE`. The
cause was not subscriptions. A `SUBSCRIBE` dialog carries `NOTIFY` requests in
the reverse direction, and a response to a `NOTIFY` correctly carries the
subscriber's tag, which is not the tag the `SUBSCRIBE` addressed. Matching on
the transaction took the count to zero.

## Validating a rule against real traffic

A rule that fires on nearly every dialog is a bug in the rule, not a discovery
about the traffic. `tests/corpus_lint_test.rs` runs the whole catalogue over a
directory of captures named by `SIPNAB_CORPUS`, prints a hit count per rule,
and fails when any rule trips more than 95% of dialogs.

That test also reports how many dialogs carried media the observation rules
could read. A zero hit rate on an `OBS-` rule means one of two very different
things — the traffic is clean, or the rule saw nothing — and the rule table
alone cannot tell them apart.

## Using the linter from Rust

```rust
use sipnab::sip::lint::{LintConfig, Linter, ObservedMedia, Ruleset};

let config = LintConfig::new()
    .with_ruleset(Ruleset::Must)
    .suppress_list("OBS-*, SIP-3261-19.1.1-URI-PARAM-DEMOTED");
let linter = Linter::new(config);

// Signalling only.
// let findings = linter.lint_dialog(&dialog);

// Signalling against the media observed for it.
// let media = ObservedMedia::from_streams(streams.streams_for(&dialog.call_id));
// let findings = linter.lint_dialog_with_media(&dialog, &media);
```

`ObservedMedia::from_streams` projects the RTP the stream store attributed to
the dialog. RTCP arrives separately through `with_rtcp`, because the stream
store folds reception reports into the stream they describe and keeps no record
of which port they landed on — which is the question RFC 5761 §5.1.1 asks.

See [Library API](library.md) for the wider crate surface.
