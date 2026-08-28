// SPDX-License-Identifier: MIT OR Apache-2.0

//! VAL9: `--hep-auth-mode hmac` must authenticate the addresses a packet
//! asserts, not merely its payload.
//!
//! # What was wrong
//!
//! The version-1 token computed its MAC over `version || timestamp || nonce ||
//! payload` and nothing else. Every HEP chunk — source address, destination
//! address, both ports, the correlation id — sat outside the signature, and
//! the chunk walk took the LAST value it saw for each field. So an observed,
//! validly signed packet could be re-sent with extra address chunks appended
//! to it and it still verified: the payload the MAC covered had not been
//! touched. **No key was needed.** The receiver then recorded the appended
//! addresses.
//!
//! That is not an abstract loss of integrity. `--hep-allow-kill` documents
//! itself as safe to enable when "HEP input is authenticated", and the kill
//! response is aimed at exactly these fields — so a forged chunk pointed
//! sipnab's transmission at a third party.
//!
//! # What the tests assert
//!
//! Effects on real bytes, at the receiver's own entry point: a datagram is
//! built by the production sender, modified the way an attacker would, and
//! handed to the production verifier. Each test says which of the two guards
//! catches it — the parser refusing a repeated chunk, or the MAC refusing a
//! changed byte — because they are independent and both are load-bearing.
//!
//! The regression direction is asserted too. A fix that refuses everything
//! would be worse than the bug, so an untouched signed datagram must still be
//! accepted AND still record the addresses that were signed.

#![cfg(feature = "hep")]

use sipnab::capture::hep::{
    DEFAULT_HMAC_WINDOW_SECS, HMAC_TOKEN_LEN, HMAC_TOKEN_VERSION, HepEndpoint, HepProtocol,
    HmacAuthError, HmacNonceCache, build_hep_v3_hmac, parse_hep, verify_hmac_datagram,
};
use sipnab::net::TransportProto;
use std::net::IpAddr;

/// The shared secret every signed datagram here is built and checked under.
const KEY: &[u8] = b"val9-shared-hmac-key";
/// A fixed token timestamp, so the acceptance window is never the reason a
/// test passes or fails.
const NOW: u64 = 1_700_000_000;

/// The addresses a legitimate sender signs.
const HONEST_SRC: &str = "10.0.0.1";
const HONEST_DST: &str = "10.0.0.2";
/// The addresses the reported attack substituted by appending chunks.
const FORGED_SRC: &str = "203.0.113.9";
const FORGED_DST: &str = "198.51.100.7";
/// The source port the reported attack substituted.
const FORGED_SRC_PORT: u16 = 31337;

// ── HEP v3 chunk types this file appends or duplicates ──────────────
const CHUNK_SRC_IPV4: u16 = 0x0003;
const CHUNK_DST_IPV4: u16 = 0x0004;
const CHUNK_SRC_IPV6: u16 = 0x0005;
const CHUNK_SRC_PORT: u16 = 0x0007;
const CHUNK_DST_PORT: u16 = 0x0008;
const CHUNK_AUTH_KEY: u16 = 0x000e;
const CHUNK_PAYLOAD: u16 = 0x000f;
const CHUNK_CORRELATION_ID: u16 = 0x0011;
/// A vendor-0 type this parser does not read, used to prove that unknown
/// chunks stay repeatable and that the MAC still covers them.
const CHUNK_UNKNOWN: u16 = 0x7fff;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test address literal")
}

fn endpoint() -> HepEndpoint {
    HepEndpoint {
        src_addr: ip(HONEST_SRC),
        dst_addr: ip(HONEST_DST),
        src_port: 5060,
        dst_port: 5060,
        transport: TransportProto::Udp,
    }
}

/// A datagram signed by the production sender, asserting [`HONEST_SRC`] →
/// [`HONEST_DST`].
fn signed(payload: &[u8], nonce_byte: u8) -> Vec<u8> {
    build_hep_v3_hmac(
        &endpoint(),
        chrono::Utc::now(),
        HepProtocol::Sip,
        1,
        KEY,
        NOW,
        &[nonce_byte; 16],
        payload,
    )
}

/// Append one chunk to a finished HEP v3 datagram and fix up the total-length
/// header, exactly as an attacker replaying an observed packet would.
fn append_chunk(pkt: &mut Vec<u8>, chunk_type: u16, data: &[u8]) {
    let len = (6 + data.len()) as u16;
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&chunk_type.to_be_bytes());
    pkt.extend_from_slice(&len.to_be_bytes());
    pkt.extend_from_slice(data);
    let total = pkt.len() as u16;
    pkt[4..6].copy_from_slice(&total.to_be_bytes());
}

/// The `0x000e` chunk's data span in a datagram, as the receiver derives it.
fn auth_span(pkt: &[u8]) -> (usize, usize) {
    parse_hep(pkt)
        .expect("datagram must parse for its span to be read")
        .auth_span
        .expect("a signed datagram carries an auth chunk")
}

/// Run the receiver's verification exactly as the listener does.
fn verify(pkt: &[u8], span: (usize, usize)) -> Result<(), HmacAuthError> {
    let mut cache = HmacNonceCache::new();
    verify_hmac_datagram(KEY, pkt, span, NOW, DEFAULT_HMAC_WINDOW_SECS, &mut cache)
}

/// Byte offset of the first occurrence of `needle` in `hay`.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

// ── The regression direction, first ──────────────────────────────────

/// An untouched, validly signed datagram is still ACCEPTED, and the
/// addresses it records are the ones that were signed.
///
/// First in the file on purpose. Every rejection below is only evidence if
/// this passes: a verifier that refused everything would satisfy all of them
/// while being strictly worse than the bug it replaced. It is also the
/// arrival proof for the rest — it establishes that a datagram built this way
/// reaches the verifier and is understood.
#[test]
fn an_unmodified_signed_datagram_is_accepted_and_records_the_addresses_it_signed() {
    let pkt = signed(b"REGISTER sip:example.com SIP/2.0\r\n", 0x11);
    let parsed = parse_hep(&pkt).expect("a datagram the sender built must parse");
    assert_eq!(parsed.src_addr, ip(HONEST_SRC), "records the signed source");
    assert_eq!(
        parsed.dst_addr,
        ip(HONEST_DST),
        "records the signed destination"
    );
    assert_eq!(parsed.src_port, 5060);
    assert_eq!(
        verify(&pkt, auth_span(&pkt)),
        Ok(()),
        "an untouched signed datagram must still authenticate"
    );
}

// ── VAL9's core: appended chunks ─────────────────────────────────────

/// The reported attack: address and port chunks APPENDED to a validly signed
/// packet. Refused.
///
/// Refused by the parser, before anything reads the appended values — a
/// repeated chunk type is now a hard error rather than an overwrite. The
/// test proves the attack was well formed by first showing the same appended
/// bytes are present and that the unappended original is accepted; a crafted
/// packet that never arrived would pass a rejection test for the wrong reason.
#[test]
fn appended_address_chunks_after_signing_are_refused() {
    let payload = b"INVITE sip:victim@example.com SIP/2.0\r\n";
    let original = signed(payload, 0x21);
    assert_eq!(
        verify(&original, auth_span(&original)),
        Ok(()),
        "premise: the packet being attacked is one that verifies"
    );

    let mut forged = original.clone();
    append_chunk(&mut forged, CHUNK_SRC_IPV4, &[203, 0, 113, 9]);
    append_chunk(&mut forged, CHUNK_SRC_PORT, &FORGED_SRC_PORT.to_be_bytes());
    append_chunk(&mut forged, CHUNK_DST_IPV4, &[198, 51, 100, 7]);

    assert!(
        forged.len() > original.len(),
        "premise: the forgery really did append bytes"
    );
    assert_eq!(
        &forged[6..original.len()],
        &original[6..],
        "premise: every signed chunk is byte-identical — this is an observed \
         packet re-sent with chunks appended, not a re-signing. Only the \
         two-byte total-length header moved, which the attacker must rewrite \
         for the receiver to walk as far as the appended chunks"
    );
    assert_ne!(
        &forged[4..6],
        &original[4..6],
        "premise: the total length really was extended to cover the forgery"
    );

    let err = parse_hep(&forged)
        .err()
        .map(|e| e.to_string())
        .unwrap_or_default();
    assert!(
        err.contains("more than once") || err.contains("twice"),
        "a repeated address chunk must be refused, not taken last-wins; \
         parse said: {err:?}"
    );
}

/// A chunk the parser tolerates repeating — an unknown type — still breaks
/// the signature.
///
/// The independent half of the guard. The test above is caught by the
/// duplicate rule; this one gets past it and is caught by the MAC, which
/// proves the signature genuinely covers bytes appended after signing rather
/// than the parser merely happening to notice this one shape.
#[test]
fn an_appended_chunk_the_parser_tolerates_still_breaks_the_signature() {
    let original = signed(b"OPTIONS sip:probe SIP/2.0\r\n", 0x22);
    let span = auth_span(&original);
    assert_eq!(verify(&original, span), Ok(()), "premise: it verified");

    let mut forged = original.clone();
    append_chunk(&mut forged, CHUNK_UNKNOWN, b"appended-after-signing");
    let parsed = parse_hep(&forged).expect("an unknown chunk is still parsed, by design");
    assert_eq!(
        parsed.src_addr,
        ip(HONEST_SRC),
        "premise: the forgery is well formed and reaches the verifier"
    );
    assert_eq!(
        verify(&forged, span),
        Err(HmacAuthError::BadMac),
        "bytes appended after signing must break the MAC"
    );
}

/// Address chunks MODIFIED IN PLACE — same length, same offsets, no repeat —
/// are refused.
///
/// The parser cannot see this one: there is no duplicate, and the datagram is
/// structurally perfect. The assertion below shows the parse happily reports
/// the attacker's addresses, so the MAC is the only thing standing between a
/// forged packet and a recorded one.
#[test]
fn address_chunks_modified_in_place_are_refused() {
    let original = signed(b"INVITE sip:x SIP/2.0\r\n", 0x31);
    let span = auth_span(&original);
    assert_eq!(verify(&original, span), Ok(()), "premise: it verified");

    let mut forged = original.clone();
    let src_at = find(&forged, &[10, 0, 0, 1]).expect("the signed source is in the datagram");
    forged[src_at..src_at + 4].copy_from_slice(&[203, 0, 113, 9]);
    let dst_at = find(&forged, &[10, 0, 0, 2]).expect("the signed destination is in the datagram");
    forged[dst_at..dst_at + 4].copy_from_slice(&[198, 51, 100, 7]);

    assert_eq!(
        forged.len(),
        original.len(),
        "premise: an in-place edit, so every offset — the token's included — \
         is exactly where it was"
    );
    let parsed = parse_hep(&forged).expect("structurally still a valid datagram");
    assert_eq!(
        parsed.src_addr,
        ip(FORGED_SRC),
        "premise: the parser has no way to see this and reports the \
         attacker's source — the MAC is the only guard"
    );
    assert_eq!(parsed.dst_addr, ip(FORGED_DST));
    assert_eq!(
        verify(&forged, span),
        Err(HmacAuthError::BadMac),
        "an address chunk changed in place must break the MAC"
    );
}

/// Every other field that steers attribution is inside the signature too:
/// the ports, and the correlation id that names the call.
///
/// One test rather than four, because the property is the same and the point
/// is that the signed region is the whole datagram rather than a hand-picked
/// list of fields somebody has to remember to extend.
#[test]
fn ports_and_correlation_id_are_inside_the_signature_as_well() {
    for (label, needle, replacement) in [
        ("source port", 5060u16.to_be_bytes(), 31337u16.to_be_bytes()),
        (
            "destination port",
            5060u16.to_be_bytes(),
            5061u16.to_be_bytes(),
        ),
    ] {
        let original = signed(b"BYE sip:x SIP/2.0\r\n", 0x41);
        let span = auth_span(&original);
        let mut forged = original.clone();
        let at = find(&forged, &needle).unwrap_or_else(|| panic!("{label} is in the datagram"));
        forged[at..at + 2].copy_from_slice(&replacement);
        assert_eq!(
            verify(&forged, span),
            Err(HmacAuthError::BadMac),
            "{label} changed in place must break the MAC"
        );
    }

    // The correlation id is not emitted by this builder, so append one and
    // watch the signature refuse it: an attacker adding the field that names
    // the call is the same class of forgery as one changing an address.
    let original = signed(b"BYE sip:x SIP/2.0\r\n", 0x42);
    let span = auth_span(&original);
    let mut forged = original.clone();
    append_chunk(
        &mut forged,
        CHUNK_CORRELATION_ID,
        b"attacker-chosen-call-id",
    );
    assert_eq!(
        parse_hep(&forged)
            .expect("premise: still parses")
            .correlation_id
            .as_deref(),
        Some("attacker-chosen-call-id"),
        "premise: the appended correlation id is what the parser would use"
    );
    assert_eq!(
        verify(&forged, span),
        Err(HmacAuthError::BadMac),
        "an appended correlation id must break the MAC"
    );
}

// ── Duplicate chunks, independent of any auth mode ───────────────────

/// A repeated chunk is refused rather than taken last-wins — in EVERY auth
/// mode, including none.
///
/// The sniffed and `--hep-parse` paths read the same chunks with no token at
/// all, so last-wins was exploitable there whatever `--hep-auth-mode` said.
/// Both families of address chunk count as one assertion about one field:
/// `SRC_IPV4` followed by `SRC_IPV6` is two claims about the source, not two
/// fields.
#[test]
fn duplicate_chunks_are_refused_rather_than_last_wins() {
    // The unduplicated baseline: proves the builder below emits a datagram
    // the parser accepts, so every rejection under it is about the repeat.
    let base = hep3(&[
        (CHUNK_SRC_IPV4, vec![10, 0, 0, 1]),
        (CHUNK_DST_IPV4, vec![10, 0, 0, 2]),
        (CHUNK_SRC_PORT, 5060u16.to_be_bytes().to_vec()),
        (CHUNK_DST_PORT, 5060u16.to_be_bytes().to_vec()),
        (CHUNK_AUTH_KEY, vec![0u8; HMAC_TOKEN_LEN]),
        (CHUNK_PAYLOAD, b"OPTIONS sip:x SIP/2.0\r\n".to_vec()),
    ]);
    let parsed = parse_hep(&base).expect("premise: the baseline datagram parses");
    assert_eq!(parsed.src_addr, ip(HONEST_SRC));
    assert_eq!(parsed.src_port, 5060);

    let cases: [(&str, (u16, Vec<u8>)); 7] = [
        ("source address", (CHUNK_SRC_IPV4, vec![203, 0, 113, 9])),
        (
            "destination address",
            (CHUNK_DST_IPV4, vec![198, 51, 100, 7]),
        ),
        (
            "source address, other family",
            (CHUNK_SRC_IPV6, vec![0u8; 16]),
        ),
        (
            "source port",
            (CHUNK_SRC_PORT, 31337u16.to_be_bytes().to_vec()),
        ),
        (
            "destination port",
            (CHUNK_DST_PORT, 31337u16.to_be_bytes().to_vec()),
        ),
        (
            "payload",
            (CHUNK_PAYLOAD, b"INVITE sip:elsewhere SIP/2.0\r\n".to_vec()),
        ),
        ("auth key", (CHUNK_AUTH_KEY, vec![0u8; HMAC_TOKEN_LEN])),
    ];
    for (label, (chunk_type, data)) in cases {
        let mut forged = base.clone();
        append_chunk(&mut forged, chunk_type, &data);
        let parsed = parse_hep(&forged);
        assert!(
            parsed.is_err(),
            "a repeated {label} chunk must be refused; instead it parsed to \
             src={:?} dst={:?} sport={:?}",
            parsed.as_ref().ok().map(|p| p.src_addr),
            parsed.as_ref().ok().map(|p| p.dst_addr),
            parsed.as_ref().ok().map(|p| p.src_port),
        );
    }
}

/// Unknown chunk types may still repeat.
///
/// Anti-over-fix. HEP's whole forward-compatibility story is that a receiver
/// skips what it does not know, and a repeated unknown chunk steers nothing
/// because nothing reads it. Refusing those would break senders that are not
/// attacking anything.
#[test]
fn an_unknown_chunk_type_may_still_repeat() {
    let mut pkt = hep3(&[
        (CHUNK_SRC_IPV4, vec![10, 0, 0, 1]),
        (CHUNK_DST_IPV4, vec![10, 0, 0, 2]),
        (CHUNK_PAYLOAD, b"OPTIONS sip:x SIP/2.0\r\n".to_vec()),
    ]);
    append_chunk(&mut pkt, CHUNK_UNKNOWN, b"one");
    append_chunk(&mut pkt, CHUNK_UNKNOWN, b"two");
    let parsed = parse_hep(&pkt).expect("repeated unknown chunks must stay acceptable");
    assert_eq!(parsed.src_addr, ip(HONEST_SRC));
}

// ── The version decision ─────────────────────────────────────────────

/// Version 1 — the payload-only scheme — is refused BY NAME, and no other
/// version byte is accepted either.
///
/// The whole 0..=255 sweep, not just the byte 1, because the failure this
/// guards against is a silent fallback: a receiver that quietly accepted some
/// other encoding would look fixed and still be forgeable. Exactly one value
/// verifies, and it is the current one.
#[test]
fn only_the_current_token_version_is_accepted_and_version_one_is_refused_by_name() {
    let pkt = signed(b"REGISTER sip:x SIP/2.0\r\n", 0x51);
    let (start, end) = auth_span(&pkt);
    assert_eq!(
        pkt[start], HMAC_TOKEN_VERSION,
        "premise: the sender stamps the current version"
    );
    assert_eq!(HMAC_TOKEN_VERSION, 2, "the bound scheme is version 2");

    for v in 0u8..=255 {
        let mut probe = pkt.clone();
        probe[start] = v;
        let got = verify(&probe, (start, end));
        if v == HMAC_TOKEN_VERSION {
            assert_eq!(got, Ok(()), "the current version must verify");
        } else if v == 1 {
            assert_eq!(
                got,
                Err(HmacAuthError::UnsupportedVersion),
                "version 1 must be refused by name, so an operator running an \
                 old sender is told to upgrade rather than silently accepted"
            );
        } else {
            assert_eq!(
                got,
                Err(HmacAuthError::BadFormat),
                "version {v} names no scheme and must be refused"
            );
        }
    }
}

// ── Malformed input stays harmless ───────────────────────────────────

/// Truncations, absurd lengths and zero lengths: no panic, no hang, and no
/// unbounded allocation.
///
/// The lengths are the ones a fuzzer finds first and the ones a hostile
/// sender writes on purpose: a chunk claiming zero bytes, a chunk claiming
/// more than the datagram holds, a 16-bit length at its maximum, a 32-bit
/// field at 4294967295, and every prefix of a valid datagram.
///
/// Resident memory is measured rather than assumed. A parser that answered
/// a declared length by reserving it would pass a "does not panic" test
/// while being a one-datagram denial of service.
#[test]
fn malformed_datagrams_do_not_panic_hang_or_allocate() {
    let valid = signed(b"INVITE sip:x SIP/2.0\r\n", 0x61);
    let mut corpus: Vec<Vec<u8>> = Vec::new();

    // Every truncation of a valid datagram, header included.
    for n in 0..valid.len().min(64) {
        corpus.push(valid[..n].to_vec());
    }
    // A chunk header claiming zero length: the walk must not stall on it.
    corpus.push(hep3_raw(&[0x00, 0x00, 0x00, 0x03, 0x00, 0x00]));
    // A chunk claiming more than the datagram holds, and the 16-bit maximum.
    corpus.push(hep3_raw(&[0x00, 0x00, 0x00, 0x03, 0xff, 0xff]));
    corpus.push(hep3_raw(&[0x00, 0x00, 0x00, 0x0f, 0x7f, 0xff, 0x41, 0x42]));
    // 4294967295 in the two 32-bit fields that carry one.
    corpus.push(hep3(&[
        (CHUNK_SRC_IPV4, vec![10, 0, 0, 1]),
        (CHUNK_DST_IPV4, vec![10, 0, 0, 2]),
        (0x000a, vec![0xff, 0xff, 0xff, 0xff]), // TS_USEC
        (0x000c, vec![0xff, 0xff, 0xff, 0xff]), // CAPTURE_ID
        (CHUNK_PAYLOAD, b"x".to_vec()),
    ]));
    // A total-length header claiming 65535 over a short datagram.
    let mut lying = valid.clone();
    lying[4..6].copy_from_slice(&u16::MAX.to_be_bytes());
    corpus.push(lying);
    // HEP v2 with a header length past the end, and one at its maximum.
    corpus.push(vec![0x02, 0xff, 0, 0, 0, 0, 0, 0]);
    corpus.push(vec![0x02, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    // Not HEP at all.
    corpus.push(b"\x80\x00\x00\x01not rtp either".to_vec());

    // Warm the allocator so the measurement below is about the parse loop and
    // not about first-touch growth.
    for _ in 0..10_000 {
        for datagram in &corpus {
            let _ = parse_hep(datagram);
        }
    }

    let before = resident_bytes();
    let started = std::time::Instant::now();
    let mut cache = HmacNonceCache::new();
    for _ in 0..20_000 {
        for datagram in &corpus {
            let _ = parse_hep(datagram);
            // The verifier sees hostile spans too: an auth span that runs off
            // the end of the datagram must be a rejection, not an index panic.
            let _ = verify_hmac_datagram(
                KEY,
                datagram,
                (0, usize::MAX),
                NOW,
                DEFAULT_HMAC_WINDOW_SECS,
                &mut cache,
            );
            let _ = verify_hmac_datagram(
                KEY,
                datagram,
                (datagram.len(), datagram.len() + HMAC_TOKEN_LEN),
                NOW,
                DEFAULT_HMAC_WINDOW_SECS,
                &mut cache,
            );
        }
    }
    let elapsed = started.elapsed();
    let after = resident_bytes();

    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "the malformed sweep must not hang; it took {elapsed:?}"
    );
    if let (Some(before), Some(after)) = (before, after) {
        let grew = after.saturating_sub(before);
        assert!(
            grew <= 800 * 1024,
            "parsing {} malformed datagrams {} times must not grow resident \
             memory: it went from {before} to {after} bytes ({grew} more), \
             outside the 0.8 MB band this is held to",
            corpus.len(),
            20_000,
        );
    }
}

/// Resident set size in bytes, or `None` where `/proc` does not answer.
fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages * 4096)
}

/// A HEP v3 datagram carrying `chunks` in the order given, vendor 0.
fn hep3(chunks: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (chunk_type, data) in chunks {
        let len = (6 + data.len()) as u16;
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&chunk_type.to_be_bytes());
        body.extend_from_slice(&len.to_be_bytes());
        body.extend_from_slice(data);
    }
    hep3_raw(&body)
}

/// A HEP v3 datagram whose chunk area is `body` verbatim, with a truthful
/// total-length header — so a test can put a deliberately wrong chunk header
/// inside a structurally sound envelope.
fn hep3_raw(body: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(6 + body.len());
    pkt.extend_from_slice(b"HEP3");
    pkt.extend_from_slice(&((6 + body.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(body);
    pkt
}
