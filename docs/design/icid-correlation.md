# Correlating on `P-Charging-Vector`'s `icid-value`

**Status:** IMPLEMENTED (`315d8d3`, 2026-08-08). Both strategies proposed here
shipped, at the scores this document proposed for them:
[`ChargingVectorRelatedIcid`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs) (95) and
`ChargingVectorIcid` (85), parsed by
[`charging_vector.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/charging_vector.rs), scored in
[`dialog_store.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs), and reported on the MCP
surface as `charging_vector_related_icid` / `charging_vector_icid`.
**Check:** `grep -rin 'icid' src/` exits 0. It exited 1 when this was written,
which is what the original Status line said.

This document was accurate for thirty-six minutes. It cites `748134f` (10:00)
and was committed at 10:40; the implementation landed at 11:15 the same
morning. Nobody ignored it — a design doc is written when its author
understands the problem, which is often shortly before they solve it. It is
kept for the reasoning behind the scores, which the implementation adopted
unchanged, and not as a description of what is missing.
**Recommendation:** section 9 — **adopt with caveats**, in a shape that is not
the obvious one, and behind one measurement that has not been taken.
**Upstream argument:** [`multi-capture-comparison.md`](multi-capture-comparison.md)
§2, which establishes that a correlator that is quietly wrong *manufactures the
bug it was built to find*. That constraint governs every ranking decision below
and is not re-argued here.

**Every RFC claim on this page was read out of the RFC text**, fetched from
`rfc-editor.org` while writing it, and is quoted rather than paraphrased where
the exact words matter. Claims that could **not** be checked that way are
marked **UNCHECKED** and collected in section 8. Nothing about 3GPP TS 24.229,
about any vendor's shipped behavior, or about the contents of any local
capture was verifiable here, and none of it is asserted.

## 1. The gap, and the deployment it comes from

sipnab correlates legs **seven** ways. It was five when this was written, and
the two added since are the ones proposed below.
[`CorrelationReason`](../../src/sip/dialog_store.rs) at
[`dialog_store.rs:43`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L43) enumerates them, and
[`find_correlated_scored`](../../src/sip/dialog_store.rs) at
[`:981`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L981) evaluates them in a fixed order,
first match wins:

| Strategy | Score | Code | Reported `identifier_match` |
|---|---|---|---|
| `session_id` — [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) `Session-ID` | 100 | [`:1078`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1078) | `true` |
| `x_call_id` — a configured header, `X-Call-ID` by default | 100 | [`:1096`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1096) | `true` |
| `charging_vector_related_icid` — [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) `related-icid` | 95 | [`:1129`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1129) | `true` |
| `sdp_origin` — the [RFC 8866](https://www.rfc-editor.org/rfc/rfc8866) origin tuple | 90 | [`:1153`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1153) | `true` |
| `charging_vector_icid` — a shared [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) `icid-value` | 85 | [`:1174`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1174) | `true` |
| `via_branch` — a shared INVITE branch | 80 | [`:1196`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1196) | `true` |
| `timing_heuristic` — endpoint overlap plus a 2 s window | 50 | [`:1214`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1214) | `false` |

The middle two rows are what this document proposed, and they are here because
it was adopted. Evaluation order follows score, so `related-icid` sits ABOVE
`sdp_origin` rather than below it as §4 sketched — the one divergence from the
plan, and it is the plan's own scoring that produced it.

The `identifier_match` column is assigned in one place, the exhaustive match at
[`server.rs:4475`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4475), which carries a comment saying the
absence of a catch-all is deliberate so that *"a new strategy is a COMPILE ERROR
here rather than something that quietly reports as 'unknown, not an identifier'"*.
That is the single most useful fact for this proposal: adding an eighth reason
cannot skip the decision this page exists to make.

**The motivating deployment is an SBC, a proxy and a PBX where the SBC and/or
the proxy may be in B2BUA mode or not**, depending on call type, endpoints and
runtime configuration. The correlation strategy therefore cannot be chosen in
advance. Whatever identifier happens to survive a given call's path is the one
that matters, which is an argument for *more* strategies rather than for one
better one — provided each added strategy is honest about when it is silent and
about what a match does and does not prove.

**The argument for `icid-value` is deployment cost, not correlation strength.**
`Session-ID` is the durable fix and this page does not dispute that; it is a
Proposed Standard whose entire purpose is to survive intermediaries, as
[`session_id.rs:1-67`](https://github.com/NormB/sipnab/blob/main/src/sip/session_id.rs#L1-L67) already sets out at length.
Its cost is that somebody has to configure the SBC. In an IMS or carrier
network, `P-Charging-Vector` is generated and carried by the operator's own
equipment already, so a strategy that reads it costs the operator nothing.
Sections 3 and 4 test whether that is worth anything, and the answer is
narrower than the pitch.

## 2. Which RFC defines it, and which one is current

**Cite [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315), not [RFC 3455](https://www.rfc-editor.org/rfc/rfc3455).** RFC 3455 (Informational, 2003) is marked on
its own info page as *"This RFC is now obsolete, see RFC 7315"*. RFC 7315,
*"Private Header (P-Header) Extensions to the Session Initiation Protocol (SIP)
for the 3GPP"* (Informational, July 2014), obsoletes it.

RFC 7315 is itself **updated by three RFCs**, and the repo convention of naming
obsoletes and errata applies to all of them:

| RFC | Relationship | Touches `P-Charging-Vector`? |
|---|---|---|
| [RFC 7913](https://www.rfc-editor.org/rfc/rfc7913) | Updates 7315 | No — P-Access-Network-Info ABNF only |
| [RFC 7976](https://www.rfc-editor.org/rfc/rfc7976) | Updates 7315 | Obsoleted by [RFC 9878](https://www.rfc-editor.org/rfc/rfc9878); superseded, do not cite |
| RFC 9878 | Updates 7315, obsoletes 7976 | Yes — where the header may appear |

RFC 9878's change is about **placement, not semantics**. It replaces RFC 7315
§5.7's *"The P-Charging-Vector header field can appear in all SIP methods except
CANCEL"* with *"The P-Charging-Vector header field can appear in all SIP
requests and the associated non-100 responses, except in CANCEL requests, CANCEL
responses, and ACK requests triggered by non-2xx responses."* Nothing in RFC
9878 alters what `icid-value` means or how it is generated.

**Two of the parameters this page discusses do not exist in RFC 3455 at all.**
`grep -c` over RFC 3455's text returns 0 for both `related-icid` and
`transit-ioi`; both are new in RFC 7315. A design that had cited the obsolete
RFC would have missed `related-icid`, which section 3 shows is the only part of
the mechanism that addresses a B2BUA.

**Errata: four reported, none verified.** The RFC 7315 errata list shows IDs
4474, 4540, 4447 and 4448, all in state *Reported*. Two of them (4447, 4448,
both filed by an author of the RFC) correct wrong section cross-references
inside §4.6 — §4.6.3.1 and §4.6.4.2 each point at §4.5.2.2 where they mean
§4.6.2.2. Section 3.4 below concerns a third instance of the same copy-paste
defect for which **no erratum has been filed**, and it is flagged there as this
page's own reading rather than as an accepted correction.

sipnab's published header table already knows the mapping:
[`sip-header-fields.md:119`](https://github.com/NormB/sipnab/blob/main/docs/sip-header-fields.md#L119) lists `P-Charging-Vector`
against RFC 7315. So the header name is in the shipped reference data while no
line of `src/` looks at it — a documentation surface ahead of the code, which
is the ordinary way a gap like this stays invisible.

## 3. Correlation properties, honestly

### 3.1 What it is, and who puts it there

The ABNF, [RFC 7315 §5.6](https://www.rfc-editor.org/rfc/rfc7315#section-5.6), verbatim:

```text
P-Charging-Vector  = "P-Charging-Vector" HCOLON icid-value
                            *(SEMI charge-params)
charge-params      = icid-gen-addr / orig-ioi / term-ioi /
                     transit-ioi / related-icid /
                     related-icid-gen-addr / generic-param
icid-value                = "icid-value" EQUAL gen-value
icid-gen-addr             = "icid-generated-at" EQUAL host
orig-ioi                  = "orig-ioi" EQUAL gen-value
term-ioi                  = "term-ioi" EQUAL gen-value
related-icid              = "related-icid" EQUAL gen-value
related-icid-gen-addr     = "related-icid-generated-at" EQUAL host
```

`icid-value` is mandatory — §5.6: *"The P-Charging-Vector header field contains
icid-value as a mandatory parameter."* Its value is `gen-value`, which in RFC
3261's grammar is `token / host / quoted-string`. **There is no format
constraint sipnab could use to tell a well-formed icid from a degenerate one**,
which matters in section 7.

Who generates it, §5.6: *"The first proxy that receives the request generates
this value."* §4.6.2.2 softens that for any later proxy: one that receives a
request without the header *"MAY insert"* one.

### 3.2 Uniqueness is a MUST, and it is the strongest thing on this page

[RFC 7315 §4.6](https://www.rfc-editor.org/rfc/rfc7315#section-4.6), verbatim:

> ICID is a charging value that identifies a dialog or a transaction outside a
> dialog.  It is used to correlate charging records.  ICID MUST be a globally
> unique value.  One way to achieve globally uniqueness is to generate the ICID
> using two components: a locally unique value and the hostname or IP address of
> the SIP proxy that generated the locally unique value.

That is a genuine normative uniqueness requirement, and it is what makes an
icid match an identifier comparison rather than a guess. Note the second
sentence for section 5: the RFC's own suggested construction **embeds an
internal hostname or IP inside the value**.

### 3.3 It identifies a dialog, not a session — and that is the whole problem

Read the first sentence of §4.6 again: ICID *"identifies a dialog or a
transaction outside a dialog"*. RFC 7989's `Session-ID` identifies the
end-to-end communication session. **These are different granularities, and the
difference lands exactly on the hop this proposal is meant to help.**

A B2BUA terminates one dialog and originates another. Two dialogs, by
definition. An ICID that identifies a dialog therefore *should* differ across a
B2BUA if both sides are conformant. RFC 7315 does not leave that implicit — it
provides a separate parameter for the case, §4.6.4.1:

> The UAS acting as a B2BUA MAY add the related-icid into the P-Charging-Vector
> header field into SIP request or SIP responses.  For example, the UAS can
> include the related-icid in a response to an INVITE request when the received
> INVITE request creates a new call leg towards the same remote end.  The value
> of the related-icid is the icid value of the original dialog towards the
> remote end.

and §5.6:

> The related-icid parameter contains the icid-value of a related charging
> record when more than one call leg is associated with one session.  This
> optional parameter is used for correlation of charging information between two
> or more call legs related to the same remote-end dialog.

So the mechanism for crossing a B2BUA is `related-icid`, it is **optional**
("MAY", "This optional parameter"), and it is a **one-way pointer** from the new
leg to the old one — structurally the same shape as `X-Call-ID`, not the
symmetric set-intersection shape of `Session-ID`.

The consequence for a naive design is severe and worth stating plainly:

| Hop | What plain `icid-value` equality means |
|---|---|
| Transparent proxy, Call-ID preserved | Nothing new — the two observations already share a Call-ID and sipnab merges them into one dialog, so `find_correlated_scored` skips the candidate at [`:989`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L989) before any strategy runs |
| B2BUA, conformant | **No match** — two dialogs, so two ICIDs; the link, if any, is in `related-icid` |
| B2BUA that copies the header verbatim onto the new leg | A match, but it is an observation about that vendor's implementation, not a property the RFC grants |
| Call-ID-rewriting proxy that forwards the header | A match, and a useful one |

**Plain `icid-value` equality across two differing Call-IDs is therefore
evidence of an intermediary that copied a per-dialog identifier onto a second
dialog.** Whether real equipment does that — whether an SBC passes an unknown
`P-` header through onto a leg it originated — is **UNCHECKED** here and is
open question 2 in section 8. What can be said from the RFC is only that it is
not prescribed, so the spec must not describe such a match as something the RFC
guarantees.

### 3.4 Survival: the RFC never says the header is forwarded unchanged

This is where the pitch weakens most. §4.6.2.2, verbatim:

> If a proxy that supports this extension receives a request or response with
> the P-Charging-Vector header field, it MAY retrieve the information from the
> header value to use with application-specific logic, i.e., charging.  If the
> next hop for the message is within the trusted domain, then the proxy SHOULD
> include the P-Charging-Vector header field in the outbound message.  If the
> next hop for the message is outside the trusted domain, then the proxy MAY
> remove the P-Charging-Function-Addresses header field.
>
> Per local application-specific logic, the proxy MAY modify the contents of the
> P-Charging-Vector header field prior to sending the message.

and the security considerations, §6.6:

> It is expected as normal behavior that proxies within a closed network will
> modify the values of the P-Charging-Vector header field and insert it into a
> SIP request or response.

So the normative posture is **SHOULD include, MAY modify** — and modification is
described as *normal behavior*, not as an edge case. Contrast RFC 7989, whose
purpose is that the identifier stays constant end to end. **`icid-value` has no
end-to-end constancy requirement of any kind.** Anything sipnab correlates on it
is correlating on a value the RFC explicitly permits the next hop to rewrite.

**The boundary sentence in §4.6.2.2 names the wrong header.** In the middle of
the P-Charging-Vector section it says the proxy *"MAY remove the
P-Charging-Function-Addresses header field"*. §4.5.2.2, the P-Charging-Function-
Addresses section, says of the same situation: *"if the next hop for the message
is outside the administrative domain of the proxy, then the proxy MUST remove
the P-Charging-Function-Addresses header field."* §4.6.2.2 reads as a copy of
§4.5.2.2 with the header name not updated — the same class of defect as the two
cross-reference errata already filed against §4.6.3.1 and §4.6.4.2.

**This reading is this page's own, not an accepted correction.** No erratum has
been filed against §4.6.2.2; the four on record are 4474 (§5.4), 4540 (§5.1),
4447 (§4.6.3.1) and 4448 (§4.6.4.2), all *Reported*, none *Verified*. Two
possible readings follow and sipnab cannot choose between them:

- the sentence was meant to say "MAY remove the P-Charging-Vector header field",
  in which case removal at the boundary is permitted but not required; or
- it is simply misplaced text, in which case **RFC 7315 contains no normative
  rule at all about removing `P-Charging-Vector` at a trust-domain boundary**,
  and only the non-normative applicability statement in §4.6.1 speaks to it:
  *"The P-Charging-Vector header field is not included in a SIP message sent to
  another network if there is no trust relationship."*

Either way the operational answer is the same and it is the one the spec has to
carry: **whether `P-Charging-Vector` survives a given boundary is local policy,
not something an RFC decides.** A Trust Domain is defined in [RFC 3324 §2.3](https://www.rfc-editor.org/rfc/rfc3324#section-2.3) as
*"a set of SIP nodes (UAC, UAS, proxies or other network intermediaries) that
are trusted to exchange Network Asserted Identity information"*, and §2.4 makes
the governing document Spec(T) — a per-deployment agreement, not an IETF
document. [RFC 3325](https://www.rfc-editor.org/rfc/rfc3325)'s normative stripping rules ("proxies MUST remove all the
P-Asserted-Identity header fields") bind `P-Asserted-Identity` and say nothing
about the charging vector.

### 3.5 The asymmetry that decides where this helps

Combine §5.6's *"The first proxy that receives the request generates this
value"* with §4.6.1's applicability inside a trust domain, and the header's
distribution over the motivating topology falls out:

| Hop | Header present on both sides? | Useful? |
|---|---|---|
| Endpoint to SBC (access edge) | **No** — if the SBC is the first proxy, it generates the icid, so the inbound leg has none | Useless: nothing to compare |
| SBC to proxy (inside the trust domain) | Likely yes | Useful when the intermediary forwards or emits `related-icid` |
| Proxy to PBX (inside the trust domain) | Likely yes | Same |
| Any hop out to a peer with no trust relationship | Unknown, local policy (§3.4) | Cannot be relied on |

**So icid is useless at exactly the hop where the operator has least control,
and potentially useful at the internal hops.** That is not the pitch's claim —
the pitch is "it is already there end to end" — and the difference should be
settled before anyone writes code, which is section 9's condition.

## 4. Ranking, and whether it is `identifier_match: true`

**Yes, `identifier_match: true`, for both proposed reasons.** The field's
meaning is documented at [`server.rs:4501`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4501) and in
[`mcp.md:1268`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md#L1268) as *identifiers were compared* versus *this was a
guess*. An icid comparison compares an opaque value that RFC 7315 requires to be
globally unique. It is not a guess from timing or endpoint overlap, and
reporting it as `false` would put it in a bucket whose defining property —
`observed_gap_ms` being the evidence — does not apply to it. The
`heuristic_only` flag would correctly stay `false` on an icid-only match.

That is a separate question from *how much it is worth*, which is what the score
carries. **Two reasons, not one**, because §3.3 shows they are different claims:

| Proposed reason | Proposed score | What a match means | Survives a B2BUA? |
|---|---|---|---|
| `ChargingVectorRelatedIcid` — one leg's `related-icid` equals the other's `icid-value` | 95 | The intermediary declared the link, in the parameter the RFC provides for it | **Yes, by design** — but only when the B2BUA chose to emit it (MAY) |
| `ChargingVectorIcid` — plain `icid-value` equality across differing Call-IDs | 85 | An intermediary carried a per-dialog identifier onto a second dialog | Not by design; a vendor behavior |

The placements, argued rather than asserted:

**95, below both 100s, for `related-icid`.** `Session-ID` keeps 100 because it
is a Proposed Standard whose stated purpose is surviving intermediaries and
whose match is symmetric set intersection. `X-Call-ID` keeps 100 because it only
ever appears when an operator deliberately configured a header to mean "this is
the other leg" — a match is near-certain by construction. `related-icid` is
standardized, which beats a vendor convention, but it is optional, one-way, and
lives in a header the next hop is explicitly permitted to modify. A distinct
score keeps it distinguishable in the sort at
[`:1100`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1100) without claiming parity.

**85, between `sdp_origin` (90) and `via_branch` (80), for plain icid.** Below
`sdp_origin` because the SDP origin tuple is an identifier whose uniqueness is
structural — the whole tuple, which
[`dialog_store.rs:43`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L43) already records as *"a
real identifier that the RFC defines as globally unique"* — and whose failure
mode (an SBC re-originating SDP) is a *silence*, not a false match.
Plain icid equality is a value the next hop MAY rewrite, whose semantic scope
(one dialog) does not match what it is being used for (two dialogs), and whose
false-match mode is a degenerate generator (section 7). Above `via_branch`
because a branch match is a transaction coincidence with no uniqueness
requirement behind it, whereas icid at least carries a MUST.

**Order of evaluation follows score**, so both new checks sit between the
`sdp_origin` block at [`:1034`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1034) and the
`via_branch` block at [`:1058`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1058), with
`related-icid` first. The existing `continue`-on-first-match structure is
preserved; nothing about the other five strategies changes.

## 5. Privacy: what may be surfaced, and what must not

`P-Charging-Vector` is a trust-domain header carrying operator-internal
identifiers, and this project's rule is that no capture-derived identifier
leaks into reports or docs. The header is worse than average for this, because
three of its parameters are *designed* to name infrastructure.

| Parameter | What it reveals | Rule |
|---|---|---|
| `icid-generated-at` | *"the hostname or IP address of the proxy that generated the icid-value"* (§5.6) — internal topology | **Never surfaced.** Used, if at all, only inside the matcher |
| `orig-ioi`, `term-ioi` | Operator identities on each side of the session | **Never surfaced** — commercially sensitive interconnect data |
| `transit-ioi` | The ordered list of transit operators, or `void` where policy hides one | **Never surfaced** — same, and the `void` convention exists precisely because operators consider this secret |
| `related-icid-gen-addr` | Hostname or IP of the proxy that generated the `related-icid` | **Never surfaced** |
| `icid-value` | Opaque — but §4.6's own suggested construction embeds *"the hostname or IP address of the SIP proxy that generated the locally unique value"* | **Never surfaced.** Treat as sensitive, not as opaque |

The last row is the one that gets waved through, and it should not be. The RFC's
recommended way to make an icid globally unique is to concatenate a local value
with an internal hostname or address, so a "meaningless token" is frequently a
router name in disguise.

**The good news is that the existing surface already does the right thing and
needs no new discipline.** `find_correlated`'s response
([`server.rs:5819`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L5819)) returns, per leg, `call_id`,
`score`, `strategy`, `identifier_match` and `observed_gap_ms` — and never the
matched identifier. `session_id` matches today without the `Session-ID` value
ever reaching a client. **A sixth strategy that reports only its name inherits
that property for free**, and the spec commits to exactly that: the strategy
name is surfaced, the value is not, and no parameter of `P-Charging-Vector` is
added to any response, hint, finding, log line or rendered ladder.

Three concrete follow-ons:

- **This document contains no captured value.** The only icid literal anywhere
  near it is [RFC 7315 §4.6.2.3](https://www.rfc-editor.org/rfc/rfc7315#section-4.6.2.3)'s own example, and it is not reproduced here
  because it is not needed. Fixtures in section 7 must use synthetic values, and
  any address in a fixture or a doc must come from [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737)'s documentation
  ranges. (RFC 7315's own example uses `192.0.6.8`, which is **not** a
  documentation address — do not copy it.)
- **[`backlog.md`](backlog.md) PA5's redaction inventory
  ([`:1280`](https://github.com/NormB/sipnab/blob/main/docs/design/backlog.md#L1280)) does not list `P-Charging-Vector`.** It lists
  `Call-ID` and SDP `o=` as *"internal hostnames and IPs"*, which is the same
  category. Adding this strategy without adding the header to that inventory
  would leave a redaction mode that redacts the two lesser sources of the same
  leak and not the greater one. That inventory line is a prerequisite of
  shipping, not a follow-up.
- **A conformance lint is not proposed.** `Session-ID` earned one because
  malformedness there explains a *failed* correlation
  ([`session_id.rs:52-66`](https://github.com/NormB/sipnab/blob/main/src/sip/session_id.rs#L52-L66)). An icid has no
  well-formedness to check beyond `gen-value`, so a lint would have nothing to
  say that was not either trivially true or a guess about a vendor.

## 6. Where it attaches in the code

No parser change is required, and that is worth stating because it is the part
people assume is expensive. [`SipMessage.headers`](../../src/sip/message.rs) at
[`message.rs:48`](https://github.com/NormB/sipnab/blob/main/src/sip/message.rs#L48) holds *"All headers in message order,
with compact forms expanded"*, and [`header()`](../../src/sip/message.rs) at
[`:175`](https://github.com/NormB/sipnab/blob/main/src/sip/message.rs#L175) is a case-insensitive lookup over that vector.
`msg.header("P-Charging-Vector")` works today and returns the raw value.

The shape, by file:

| File | Change |
|---|---|
| [`src/sip/charging_vector.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/charging_vector.rs) (new) | Parse the header value into its parameters. Sibling of [`session_id.rs`](../../src/sip/session_id.rs) and of [`SdpOriginKey`](../../src/sip/sdp.rs) at [`sdp.rs:133`](https://github.com/NormB/sipnab/blob/main/src/sip/sdp.rs#L133), both of which model an identifier as a small owned struct with a `parse` returning `Option` |
| [`dialog_store.rs:43`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L43) | Two new `CorrelationReason` variants, each with the doc comment explaining its survival properties that the existing five carry |
| [`dialog_store.rs:1034-1058`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1034-L1058) | Two new candidate blocks between `sdp_origin` and `via_branch`, following the established pattern: hoist the source dialog's values into a `HashSet` once before the candidate loop (as `src_origins` does at [`:964`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L964)), parse the candidate side lazily inside the loop |
| [`server.rs:4501`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L4501) | Two new arms. **This is a compile error until written**, by design |
| [`mcp.md:1264`](https://github.com/NormB/sipnab/blob/main/docs/mcp.md#L1264), [`mcp-deploy.md:824`](https://github.com/NormB/sipnab/blob/main/docs/mcp-deploy.md#L824), [`domain-primer.md:202`](https://github.com/NormB/sipnab/blob/main/docs/internals/domain-primer.md#L202) | Strategy tables and the "correlates legs five ways" sentence |

Three code-level facts that a naive implementation would get wrong:

**The existing `xcid_headers` knob cannot be repurposed for this.** It is
tempting: [`config.rs:246`](https://github.com/NormB/sipnab/blob/main/src/config.rs#L246) exposes `[sip] xcid_headers` and
[`with_xcid_headers`](../../src/sip/dialog_store.rs) at
[`:391`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L391) accepts any header name, so
`xcid_headers = ["P-Charging-Vector"]` looks like a zero-code answer. It is not.
The strategy at [`:1017`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1017) compares the header's
**value** against the candidate's **Call-ID**. A `P-Charging-Vector` value is
`icid-value=…;icid-generated-at=…`, which is never equal to a Call-ID, so the
configuration would be accepted, would never match, and would look like "we
tried icid correlation and it found nothing". Recording this is most of the
value of writing the section.

**Message retention is not a hazard here, which is not obvious.** The header is
usually on the initial INVITE, and sipnab drops messages in two places. The
per-dialog cap at [`:625`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L625) drops the *newest*
message when full, never the first. `compact_idle`'s
[`retained_indices`](../../src/sip/dialog_store.rs) at
[`:268`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L268) treats the opening request as an anchor
that takes budget first. So the INVITE — and its charging vector — survives both.

**Two doc comments in the file are already stale and this work has to fix
them.** `find_correlated_scored`'s doc at [`:919`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L919)
says *"Checks three correlation strategies"* and lists X-Call-ID, Via branch and
timing; `find_correlated`'s at [`:1107`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L1107) says
*"All three correlation strategies emit a score of at least 50"*. Both predate
`session_id` and `sdp_origin` and describe a three-strategy function that has
not existed for some time. A sixth strategy that leaves them saying "three" adds
a second wrong number to a comment that is already wrong.

## 7. Testing, and the vacuous test to avoid

**The failure mode is specific: a correlation test that passes on a capture
where the identifier is absent proves nothing.** There are two distinct ways to
write that test by accident, and they need different guards.

**Vacuity 1 — another strategy produced the match.** `find_correlated_scored`
returns results from five strategies. A test asserting `!results.is_empty()` on
a fixture with a charging vector passes whether or not the icid code exists,
because `timing_heuristic` fires on any two INVITEs sharing an endpoint IP
within 2000 ms — which two hand-built fixture legs almost always do. The guard
is the one the existing suite already uses: **assert the reason, not the
count.** [`session_id_lint_test.rs:194`](https://github.com/NormB/sipnab/blob/main/tests/session_id_lint_test.rs#L194)
asserts `r.reason != CorrelationReason::SessionId` rather than "nothing
correlated", precisely so the other strategies cannot answer for it.

Beyond that, the fixture must **deny every other strategy explicitly**, and each
denial is a line someone can check:

| Strategy | How the fixture denies it |
|---|---|
| `session_id` | No `Session-ID` header on either leg |
| `x_call_id` | No `X-Call-ID`, and no configured alternative |
| `sdp_origin` | No body, or two origin tuples differing in a field other than `sess-version` |
| `via_branch` | Distinct branch parameters on the two INVITEs |
| `timing_heuristic` | Disjoint endpoint IPs, **and** `created_at` more than 2000 ms apart — both, since either alone leaves the other free to match |

With all five denied, a non-empty result set can only have come from the new
code, and the assertion may then be the strong one: exactly one result, with the
expected reason.

**Vacuity 2 — the population is zero.** This is the one that survives review,
because it looks like a corpus test. "Run over the capture corpus and check that
icid correlation works" passes trivially on a corpus in which no capture carries
`P-Charging-Vector` at all: nothing correlates, nothing is asserted to
correlate, green. **Any corpus-level test must first count the dialogs carrying
the header and fail if that count is zero**, so the population is an assertion
rather than an assumption. That check is the same shape as the pinned counts in
[`docs_drift_test.rs`](../../tests/docs_drift_test.rs) — a floor that fails when
the thing being swept silently stops being present.

**Mutation guards, per the project rule that a gate nobody has broken on purpose
is not known to work.** Four, each stating what it would catch:

1. **Positive, `related-icid`.** Leg B's `related-icid` equals leg A's
   `icid-value`; every other strategy denied. Expect exactly
   `ChargingVectorRelatedIcid` at 95.
2. **Positive, plain icid.** Both legs carry the same `icid-value`, no
   `related-icid`; every other strategy denied. Expect `ChargingVectorIcid` at
   85. Together with (1) this proves the two reasons are distinguishable, which
   a single test covering "icid matched somehow" would not.
3. **Negative control on the same fixture.** Identical to (1) and (2) except the
   icid values differ by one character. Expect **no** result — not "a lower
   score", none. This is the test that fails if the implementation matches on
   header *presence* rather than on value, which is the single likeliest bug and
   is invisible to (1) and (2).
4. **Parameter isolation.** Two legs whose `icid-value` differs but whose
   `icid-generated-at` is identical (the normal case: one proxy generating both).
   Expect no match. Without this, an implementation that compares whole header
   values or falls back to the generating address correlates every call the same
   proxy touched — the confidently-wrong answer
   [`multi-capture-comparison.md`](multi-capture-comparison.md) §6 describes.

**A fifth test that is a design decision, not a test.** A degenerate generator —
one emitting a constant or low-entropy icid — would correlate every dialog in
the capture with every other. Nothing in the ABNF (`gen-value`) lets sipnab
detect that from one value. The proposed guard is a **cardinality limit**: if a
single `icid-value` appears in more than a small number of distinct dialogs,
stop treating it as an identifier and emit nothing rather than a combinatorial
fan-out. [`dialog-tracking-modes.md:18`](https://github.com/NormB/sipnab/blob/main/docs/design/dialog-tracking-modes.md#L18) documents the
analogous Call-ID case —
`sipp-branch-scenario.pcapng`, *"8,989 packets in which one Call-ID is reused
across many transactions"* — so a fixture with a reused icid is buildable from
material the repo already understands. **The threshold is not proposed here**,
because a number chosen without a measurement would be exactly the kind of
ungrounded default this project rejects. It is an open question in section 8.

**Corpus validation is required and could not be done from this worktree.** The
project rule is that anything less than 100% against the local corpus is a
critical failure; this agent must not read that corpus, so the corpus question
is stated, not answered.

## 8. Open questions and unverified claims

Everything in this section is either unanswerable from the RFCs and the code, or
answerable only with access this page did not have.

**Blocking — the measurement section 9 is conditioned on:**

1. **Does any capture the operator has carry `P-Charging-Vector` at all, and on
   which legs?** Unanswered. Not readable from here. If it is present on only
   one side of the hop being correlated, section 3.5 says this feature cannot
   help there, and everything else is moot. The cheapest possible probe is a
   header-presence count per capture, per leg.
2. **When it is present on both legs, does the intermediary forward the same
   `icid-value`, mint a new one, or emit `related-icid`?** All three are
   RFC-conformant. Which one the operator's SBC and proxy actually do determines
   whether the 95 strategy, the 85 strategy, or neither ever fires.

**Unanswerable from the RFCs:**

3. **Whether 3GPP TS 24.229 requires an IBCF or equivalent to remove
   `P-Charging-Vector` at a network boundary.** **UNCHECKED** — TS 24.229 was not
   fetched or read. [RFC 7315 §4.6.1](https://www.rfc-editor.org/rfc/rfc7315#section-4.6.1) says only that the header *"is not included
   in a SIP message sent to another network if there is no trust relationship"*,
   which is an applicability statement without an [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keyword. If TS 24.229
   does impose a strip, the boundary behavior is stricter than section 3.4
   concludes, and section 3.5's last row becomes a firm "no" rather than an
   "unknown".
4. **Whether the §4.6.2.2 wrong-header reading in section 3.4 is correct.** It
   is this page's own reading. No erratum exists. It should be checked against
   RFC 3455's corresponding section before anyone relies on it — RFC 3455 was
   fetched here but that specific comparison was not made.
5. **What `related-icid` deployment actually looks like.** It is new in RFC 7315
   (2014) and absent from RFC 3455; whether any shipping SBC emits it is
   **UNCHECKED**. If nothing does, the 95 strategy is dead code and only the 85
   one matters — which changes the recommendation's balance materially.

**Design questions this page deliberately does not settle:**

6. **The cardinality threshold** for the degenerate-generator guard (section 7).
   No measurement exists to ground it, and a guessed default would be worse than
   an explicit gap.
7. **Whether `related-icid` matching should be direction-aware.** §4.6.4.1
   describes the B2BUA adding it to the *new* leg pointing at the *original*.
   Matching both directions is simpler and finds more; matching one direction
   preserves information about which leg came first. Not decided.
8. **Whether an icid match should ever be allowed to correlate dialogs whose
   Call-IDs are equal.** Today the candidate loop skips same-Call-ID dialogs at
   [`:989`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L989) and the store merges them anyway, so
   the question is theoretical until capture provenance exists —
   [`multi-capture-comparison.md`](multi-capture-comparison.md) §3.
9. **Whether the two reasons should be one.** This page argues two because they
   are different claims with different survival properties. A reviewer who
   thinks the MCP surface should stay small could reasonably argue for one
   reason plus a sub-field. The argument against is the same one that keeps
   `session_id` and `x_call_id` separate at equal scores: *"a reader deciding how
   much to trust a call tree needs to know which they have"*
   ([`dialog_store.rs:43`](https://github.com/NormB/sipnab/blob/main/src/sip/dialog_store.rs#L43)).

**Not verified, and not asserted anywhere above:** any claim about performance,
about how common the header is in the wild, about which vendors implement it,
or about the contents of any capture file.

## 9. Recommendation

**Adopt with caveats, conditional on question 1 in section 8, and in the
two-reason shape of section 4.** Not the shape it was proposed in.

**Why adopt.** The cost is small and bounded: one parser module beside two that
already model exactly this kind of identifier, two enum variants, two candidate
blocks in a loop whose pattern is established, two match arms the compiler will
demand, and three documentation tables. It adds a strategy that is silent when
the header is absent, which is the correct behavior in a deployment whose
B2BUA-ness varies per call and cannot be configured for in advance. The
`identifier_match: true` classification is defensible against the field's
documented meaning, and the existing response shape already surfaces the
strategy name without the value, so the privacy commitment in section 5 costs
nothing to keep.

**Why with caveats, and what the caveats are.**

- **It is not a substitute for `Session-ID`, and the docs must not let it read
  as one.** RFC 7989 requires the identifier to survive intermediaries. RFC 7315
  permits the next hop to *"modify the contents"* and calls that normal
  behavior. An operator who adopts icid correlation and skips the SBC change
  has bought a strategy that works until a proxy rewrite, with no signal when it
  stops.
- **It is useless at the access edge** (section 3.5), which is where the pitch
  implied it would help most. If the SBC is the first proxy, it generates the
  icid, and the leg arriving from the endpoint has none.
- **The B2BUA case runs on `related-icid`, which is a MAY** (section 3.3). Plain
  `icid-value` equality across a B2BUA is a vendor behavior, not a guarantee.
- **The degenerate-generator guard is a prerequisite, not a refinement**
  (section 7). Without a cardinality limit, one badly implemented proxy turns
  the strategy into a combinatorial false-match generator, which is precisely
  the manufactured-bug failure this project's correlation work is organized
  around avoiding.
- **PA5's redaction inventory must gain `P-Charging-Vector` in the same change**
  (section 5).

**Why not reject.** The honest case for rejection is that the header may be
absent exactly where it is needed and rewritable everywhere else, so the
strategy could fire rarely and prove little when it does. That case is real, and
it is why the recommendation is conditional rather than unqualified — but the
condition is one cheap measurement, and if the header *is* present on both sides
of the operator's internal hops then a standardized, uniqueness-required
identifier that costs the operator no configuration is worth 85 points and a
name in the strategy table.

**Do not start with code.** Start by counting: how many dialogs in the
operator's captures carry `P-Charging-Vector`, on which legs, and whether the
value is preserved, replaced, or accompanied by `related-icid` across the hop
that matters. That probe needs no new strategy — `msg.header("P-Charging-Vector")`
already works — and its result decides whether the rest of this page is worth
building. **If the answer is that the header does not survive the hop the
operator cares about, this document has done its job by costing an afternoon
instead of a release.**
