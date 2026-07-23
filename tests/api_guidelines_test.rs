//! API-guidelines drift nets (WS6.2).
//!
//! Growth-prone public enums must be `#[non_exhaustive]` so adding a
//! variant is not a semver-major event, and the two shared stores must
//! be `Debug` for embeddability. These are source-scan tests (the
//! attribute's effect is only observable from *another* crate, so a
//! compile-time assertion here would vacuously pass).

/// Every growth-prone public enum on the library surface, with the file
/// that defines it. Closed sets (e.g. `SdpDirection` — RFC 4566's four
/// direction attributes, `G711Codec` — PCMU/PCMA) are deliberately NOT
/// listed: they are complete by definition and exhaustive matching on
/// them downstream is legitimate.
// `FilterExpr` (the other spec-named candidate) is a struct wrapping a
// PRIVATE expression-tree enum, so its variants can grow freely already.
const NON_EXHAUSTIVE_ENUMS: &[(&str, &str)] = &[
    ("src/security/fraud_detect.rs", "FraudType"),
    ("src/security/digest_leak.rs", "DigestVulnerability"),
    ("src/rtp/rtcp.rs", "RtcpPacket"),
    ("src/rtp/rtcp.rs", "XrBlock"),
    ("src/net.rs", "TransportProto"),
    ("src/sip/sdp_timeline.rs", "SdpEvent"),
    ("src/sip/sdp_timeline.rs", "OfferAnswer"),
    ("src/sip/dialog_store.rs", "CorrelationReason"),
    ("src/sip/stir_shaken.rs", "Attestation"),
    ("src/sip/stir_shaken.rs", "VerificationStatus"),
    ("src/capture/hep.rs", "HepProtocol"),
    ("src/capture/decrypt.rs", "CipherSuite"),
    ("src/capture/dtls.rs", "SrtpProfile"),
    ("src/capture/tls.rs", "TlsContentType"),
    ("src/capture/tls.rs", "TlsVersion"),
    ("src/rtp/srtp.rs", "SrtpSuite"),
];

/// True when `pub enum <name>` in `text` is directly preceded (within the
/// attribute/doc block above it) by `#[non_exhaustive]`.
fn enum_is_non_exhaustive(text: &str, name: &str) -> bool {
    let needle = format!("pub enum {name} ");
    let Some(pos) = text.find(&needle) else {
        return false;
    };
    // Walk back over the contiguous attribute/doc-comment block.
    let head = &text[..pos];
    let block_start = head.rfind("\n\n").map(|i| i + 2).unwrap_or(0);
    head[block_start..].contains("#[non_exhaustive]")
}

/// Scans each source file in `NON_EXHAUSTIVE_ENUMS` and asserts every listed
/// `pub enum` still exists and carries `#[non_exhaustive]` in its attribute block.
#[test]
fn growth_prone_public_enums_are_non_exhaustive() {
    let root = env!("CARGO_MANIFEST_DIR");
    let mut missing = Vec::new();
    for (file, name) in NON_EXHAUSTIVE_ENUMS {
        let path = format!("{root}/{file}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {file}: {e}"));
        assert!(
            text.contains(&format!("pub enum {name} ")),
            "{file} no longer defines `pub enum {name}` — update this list"
        );
        if !enum_is_non_exhaustive(&text, name) {
            missing.push(format!("{file}: {name}"));
        }
    }
    assert!(
        missing.is_empty(),
        "growth-prone public enums missing #[non_exhaustive]:\n  {}",
        missing.join("\n  ")
    );
}

/// Compile-time check that `DialogStore` and `StreamStore` implement `Debug`
/// (API guideline C-DEBUG) so embedders can log them.
#[test]
fn shared_stores_are_debug() {
    // Compile-time: both stores must implement Debug (C-DEBUG) so
    // embedding applications can log them.
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<sipnab::DialogStore>();
    assert_debug::<sipnab::StreamStore>();
}
