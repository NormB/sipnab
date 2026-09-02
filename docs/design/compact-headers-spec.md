# sipnab — Full [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) / IANA Compact-Form Header Support

**Status:** IMPLEMENTED (2026-07-03) — table extended to all 19 forms,
three gap tests (parser expansion, `r:` transfer tracking, `y:` STIR/SHAKEN
evasion regression) written red-first and green, edge pins added, fuzz
corpus seeded. Kept for the determination record.
**Date:** 2026-07-03.
**Effort:** S (hours, single PR).

## 1. What the standard requires

[RFC 3261 §7.3.3](https://www.rfc-editor.org/rfc/rfc3261#section-7.3.3) ("Compact Form"):

> SIP provides a mechanism to represent common header field names in an
> abbreviated form. This may be useful when messages would otherwise become
> too large to be carried on the transport available to it (exceeding the
> maximum transmission unit (MTU) when using UDP, for example). These
> compact forms are defined in Section 20. A compact form MAY be substituted
> for the longer form of a header field name at any time without changing
> the semantics of the message.

Plus §7.3.1: header field names are always compared **case-insensitively**
(so `I:`, `i:`, `V:`, `v:` are all valid compact forms). Long and compact
forms may be mixed freely within one message.

RFC 3261 itself defines ten compact forms, but the authoritative list is the
**IANA SIP Header Fields registry**, which as of 2026 registers **19**:

> **Note (current state):** every form below is ✅ today — the table's last
> column is the *pre-fix* determination from 2026-07-03, kept as the record
> of what motivated the change. All 19 forms expand since v0.5.0.

| Compact | Header field | Defined by | sipnab before this change |
|---|---|---|---|
| `c` | Content-Type | RFC 3261 | ✅ |
| `e` | Content-Encoding | RFC 3261 | ✅ |
| `f` | From | RFC 3261 | ✅ |
| `i` | Call-ID | RFC 3261 | ✅ |
| `k` | Supported | RFC 3261 | ✅ |
| `l` | Content-Length | RFC 3261 | ✅ (parser **and** TCP framer) |
| `m` | Contact | RFC 3261 | ✅ |
| `s` | Subject | RFC 3261 | ✅ |
| `t` | To | RFC 3261 | ✅ |
| `v` | Via | RFC 3261 (+7118) | ✅ |
| `a` | Accept-Contact | [RFC 3841](https://www.rfc-editor.org/rfc/rfc3841) | ❌ |
| `b` | Referred-By | [RFC 3892](https://www.rfc-editor.org/rfc/rfc3892) | ❌ |
| `d` | Request-Disposition | RFC 3841 | ❌ |
| `j` | Reject-Contact | RFC 3841 | ❌ |
| `o` | Event | [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665) (+6446) | ❌ |
| `r` | Refer-To | [RFC 3515](https://www.rfc-editor.org/rfc/rfc3515) | ❌ |
| `u` | Allow-Events | RFC 6665 | ❌ |
| `x` | Session-Expires | [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028) | ❌ |
| `y` | Identity | [RFC 8224](https://www.rfc-editor.org/rfc/rfc8224) | ❌ |

## 2. Determination: what sipnab supports today

**Partial.** The RFC 3261 core ten are fully supported end to end:

- [`src/sip/parser.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/parser.rs) — `COMPACT_HEADERS` table + `expand_compact_header()`
  expands single-letter names case-insensitively at parse time; all
  downstream lookups (`SipMessage::header()`, matcher, filter DSL,
  dialog/store logic, output surfaces) operate on the expanded long form,
  so the core forms work everywhere by construction. Pinned by the
  `compact_headers` parser test.
- `src/capture/mod.rs::parse_content_length` — the **pre-parse** TCP SIP
  framer independently recognizes compact `l` (case-insensitive) when
  splitting stream data into messages, so compact-form messages over
  TCP/TLS/WS frame correctly.

The **nine extension compact forms are not expanded**. A message using them
parses fine, but the header retains its single-letter name, so every
long-form lookup misses it. Concrete consumer impact found by audit:

1. **`r:` (Refer-To)** — `sip/dialog_store.rs:224` drives call-transfer
   tracking (the `Transferring` dialog state) and
   `sip/sdp_timeline.rs:97` records the transfer target. A REFER sent with
   the compact form silently produces no transfer event.
2. **`y:` (Identity)** — `sip/stir_shaken.rs:186` extracts the STIR/SHAKEN
   PASSporT from `Identity`. A compact-form Identity header is **silently
   invisible to STIR/SHAKEN analysis** — for a security-analysis tool this
   is the worst gap: a caller-ID–spoofing party could deliberately emit
   `y:` to evade sipnab's attestation inspection while remaining fully
   standards-compliant toward RFC 8224 verifiers.
3. The remaining seven (`a b d j o u x`) have no direct consumer today, but
   they surface in the TUI/JSON with the bare single-letter name, and any
   future feature (session-timer analysis via Session-Expires, SUBSCRIBE
   dialog enrichment via Event/Allow-Events) would inherit the same silent
   miss.

**Explicitly out of scope — SigComp.** "Compressed SIP" can also mean
signaling compression (SigComp, [RFC 3320](https://www.rfc-editor.org/rfc/rfc3320), negotiated via the `comp=sigcomp`
Via/URI parameter, [RFC 3486](https://www.rfc-editor.org/rfc/rfc3486)). That is a bytecode-VM decompression layer,
essentially specific to 3GPP/IMS deployments; sipnab does not implement it
and this spec does not propose to. If a capture contains SigComp-compressed
SIP, sipnab will (correctly) not detect it as SIP. A future feature request
should be filed separately if IMS captures become a use case.

## 3. Specification of the change

### 3.1 Parser table (the fix)

Extend `COMPACT_HEADERS` in [`src/sip/parser.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/parser.rs) from 10 to the full IANA 19:

```rust
const COMPACT_HEADERS: &[(u8, &str)] = &[
    // RFC 3261 §20
    (b'c', "Content-Type"),
    (b'e', "Content-Encoding"),
    (b'f', "From"),
    (b'i', "Call-ID"),
    (b'k', "Supported"),
    (b'l', "Content-Length"),
    (b'm', "Contact"),
    (b's', "Subject"),
    (b't', "To"),
    (b'v', "Via"),
    // IANA-registered extensions
    (b'a', "Accept-Contact"),      // RFC 3841
    (b'b', "Referred-By"),         // RFC 3892
    (b'd', "Request-Disposition"), // RFC 3841
    (b'j', "Reject-Contact"),      // RFC 3841
    (b'o', "Event"),               // RFC 6665
    (b'r', "Refer-To"),            // RFC 3515
    (b'u', "Allow-Events"),        // RFC 6665
    (b'x', "Session-Expires"),     // RFC 4028
    (b'y', "Identity"),            // RFC 8224
];
```

No other parser change is needed: `expand_compact_header()` already matches
single-letter names case-insensitively and returns `Cow::Borrowed` statics
(zero-allocation, consistent with the WS4.1 canonical-name work), and the
existing linear scan over ≤19 pairs is cheaper than any table lookup at this
size. Update the doc comment to name the IANA registry as the source of
truth and require new registrations to be added here.

### 3.2 Ripple checks (verified, no code change required)

- **TCP framer** (`parse_content_length`): only `Content-Length`/`l` affects
  framing; already handled.
- **Lookups**: all consumers use expanded names via case-insensitive
  `SipMessage::header()` — extension forms start working everywhere the
  moment the table expands (that is the point of expanding at parse time).
- **Response builder** (`security/scanner_kill.rs`): reads via
  `from_header()`/`to_header()`/`header("CSeq")` — post-expansion; CSeq has
  no compact form. Unaffected.
- **WS4.1 `canonical_header_name()`**: already contains the long forms that
  matter (`Refer-To`, `Referred-By`, `Event`, `Session-Expires`,
  `Identity`, `Subscription-State`); optionally add `Accept-Contact`,
  `Reject-Contact`, `Request-Disposition`, `Allow-Events` for allocation
  parity — cosmetic, not correctness.
- **Generation**: sipnab never emits SIP with compact names (exports echo
  `msg.raw`; the scanner-kill response is built with long forms). No
  generation support is required by RFC 3261 (compact emission is a MAY).

### 3.3 Display consideration (decision)

Expansion rewrites the header *name* seen in the TUI/JSON (`r:` renders as
`Refer-To`). `msg.raw` retains the original bytes, so hexdump/raw views and
pcap export are unaffected. This matches the terminal viewer behavior and the existing
handling of the core ten. **Decision: keep normalizing; no config knob.**

## 4. TDD plan (mandatory order)

Write these failing tests first, run RED, then apply §3.1:

1. **Parser expansion** ([`src/sip/parser.rs`](https://github.com/NormB/sipnab/blob/main/src/sip/parser.rs) tests): a message using all
   nine extension compact forms (mixed upper/lower case, e.g. `R:`/`y:`)
   parses with all nine long names present and no single-letter names
   remaining. RED today.
2. **Transfer detection** (`sip/dialog_store.rs` tests): a REFER using
   `r: <sip:transfer-target>` drives the same state transition /
   `Refer-To` visibility as the long form. RED today.
3. **STIR/SHAKEN evasion regression** (`sip/stir_shaken.rs` tests): an
   INVITE carrying the PASSporT in `y:` yields the identical
   `stir_shaken()` result as `Identity:`. RED today (this is the security
   fix — name the test so it reads as an evasion regression, e.g.
   `compact_identity_header_cannot_evade_extraction`).
4. **Adversarial/edge pinning** (should pass before AND after — add if
   missing): unknown single letters (`z:`, `q:`) keep their name as-is;
   mixed long+compact duplicates of the same header in one message are both
   retained (RFC: mixing is legal); compact name with surrounding
   whitespace (`i : x`) — current trim behavior preserved; a compact form
   as the *last* header before a truncated (no-CRLF) tail.
5. **Fuzz corpus**: add compact-form seeds (including `y:`) to the
   `sip_parser` fuzz corpus so coverage-guided runs exercise the table.

Then: full suite, clippy/doc gates, feature combos, and a one-line
CHANGELOG entry under `[Unreleased]` ("Added: all 19 IANA-registered
compact header forms; previously only the RFC 3261 core ten…"), CHANGELOG
should explicitly flag the STIR/SHAKEN evasion fix.

## 5. Acceptance criteria

- All 19 IANA compact forms expand, case-insensitively, with zero
  allocations for the name.
- The three RED tests above are GREEN; the edge pins unchanged.
- `grep -c` on `COMPACT_HEADERS` = 19 entries; doc comment cites the IANA
  registry as source of truth.
- Docs: `docs/` page that describes header handling (if any mentions
  compact forms) updated to say "all IANA-registered compact forms".
