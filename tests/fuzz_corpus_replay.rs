// SPDX-License-Identifier: MIT OR Apache-2.0

//! Deterministic, stable-toolchain robustness gate over the wire parsers.
//!
//! The `fuzz/` crate holds the real cargo-fuzz (libFuzzer) targets, but they
//! need a nightly toolchain and run unbounded, so they can't be a `cargo test`
//! gate. This file is the always-runnable counterpart: it drives the same parser
//! entry points (`parse_sip` / `parse_sdp` / `parse_rtp_header` / `parse_rtcp`)
//! with a fixed adversarial seed set AND a deterministic mutation sweep, and
//! asserts none of them ever **panics** — a privileged parser of hostile traffic
//! (priority #2: robustness) must reject bad input with `Err`/empty, never
//! unwind. Returning `Err` is fine; panicking is the failure.
//!
//! "Validate the validator": `harness_actually_catches_a_panic` proves the
//! catch_unwind harness has teeth, so a parser that *did* panic could not slip
//! through as a false pass.

use std::net::{IpAddr, Ipv4Addr};
use std::panic::{AssertUnwindSafe, catch_unwind};

use sipnab::capture::parse::TransportProto;
use sipnab::rtp::parser::parse_rtp_header;
use sipnab::rtp::rtcp::parse_rtcp;
use sipnab::sip::parser::parse_sip;
use sipnab::sip::sdp::parse_sdp;

/// Run `f` and return Err(label) if it panicked (panic output is suppressed so
/// a deliberate self-test panic doesn't spam the log).
///
/// # Arguments
/// * `label` — identifier returned in the `Err` when `f` panics.
/// * `f` — closure driving one parser call.
///
/// # Returns
/// `Ok(())` if `f` completed; `Err(label)` if it unwound.
///
/// # Side effects
/// Temporarily replaces the global panic hook (restored before returning).
fn ran_without_panic<F: FnOnce()>(label: &str, f: F) -> Result<(), String> {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let res = catch_unwind(AssertUnwindSafe(f));
    std::panic::set_hook(prev);
    res.map_err(|_| label.to_string())
}

/// Feeds `data` to `parse_sip` with fixed localhost endpoints, discarding the
/// result — only panic-vs-no-panic matters here.
fn drive_sip(data: &[u8]) {
    let _ = parse_sip(
        data,
        chrono::Utc::now(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        5060,
        5060,
        TransportProto::Udp,
    );
}

/// A spread of nasty raw inputs that hit boundary/special-char paths the CLAUDE
/// directive calls out (backslash, NUL, empty, lying lengths, huge counts).
///
/// # Returns
/// The fixed SIP-oriented adversarial seed set, identical every run.
fn adversarial_seeds() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        vec![],                   // empty
        vec![0u8],                // single NUL
        vec![0u8; 4096],          // all-NUL block
        vec![0xFFu8; 512],        // invalid UTF-8 block
        b"\r\n\r\n\r\n".to_vec(), // only line endings
        b"INVITE".to_vec(),       // truncated request line
        b"SIP/2.0 200".to_vec(),  // truncated status line
    ];
    // Lying Content-Length (declares a body far larger than present).
    v.push(
        b"INVITE sip:a@b SIP/2.0\r\nVia: SIP/2.0/UDP h\r\nFrom: <sip:a@b>;tag=1\r\n\
          To: <sip:c@d>\r\nCall-ID: x@h\r\nCSeq: 1 INVITE\r\nContent-Length: 99999\r\n\r\nshort"
            .to_vec(),
    );
    // Embedded NUL and backslash inside a header value.
    v.push(b"OPTIONS sip:a@b SIP/2.0\r\nFrom: <sip:a\\b@h>\x00evil;tag=1\r\nCall-ID: n\x00l@h\r\nCSeq: 1 OPTIONS\r\n\r\n".to_vec());
    // Header with no colon, then a giant single line.
    v.push(b"REGISTER sip:a SIP/2.0\r\nthisHasNoColon\r\n\r\n".to_vec());
    v.push({
        let mut s = b"INVITE sip:a@b SIP/2.0\r\nX-Long: ".to_vec();
        s.extend(std::iter::repeat_n(b'A', 100_000));
        s.extend_from_slice(b"\r\n\r\n");
        s
    });
    // Thousands of headers (allocation / loop bounds).
    v.push({
        let mut s = b"INVITE sip:a@b SIP/2.0\r\n".to_vec();
        for _ in 0..5000 {
            s.extend_from_slice(b"X: y\r\n");
        }
        s.extend_from_slice(b"\r\n");
        s
    });
    // A plausible SDP-bearing INVITE with a malformed SDP body.
    v.push(b"INVITE sip:a@b SIP/2.0\r\nCall-ID: s@h\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 9\r\n\r\nm=audio x".to_vec());
    v
}

/// SDP-specific adversarial bodies (overflowing ports, NULs in codec names,
/// tens of thousands of rtpmap lines).
///
/// # Returns
/// The fixed SDP adversarial seed set, identical every run.
fn sdp_seeds() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0u8; 256],
        b"v=0".to_vec(),
        b"=\r\n=\r\n=".to_vec(), // lines that are just '='
        b"m=audio 99999999999999999999 RTP/AVP 8".to_vec(), // overflow-y port
        b"a=rtpmap:notanumber FOO/abc".to_vec(), // non-numeric pt/clock
        b"c=IN IP4 \r\nm=audio -1 RTP/AVP 0 8 9 96 97 98 99 100 101 102".to_vec(),
        b"a=rtpmap:96 \x00\x00\x00/8000".to_vec(), // NUL in codec
        {
            let mut s = b"v=0\r\n".to_vec();
            for i in 0..10_000 {
                s.extend_from_slice(format!("a=rtpmap:{} X/8000\r\n", i % 128).as_bytes());
            }
            s
        },
    ]
}

// Shared deterministic xorshift PRNG (see `smoke_fuzz_test.rs` for the mirror
// consumer). The `mutate` helper below is a deliberately simpler 4-op strategy
// than smoke's richer 6-op sweep, so it stays local: sharing it would change
// the byte stream and break this file's corpus reproducibility. The two take
// their arguments in the SAME order, though — the strategies differ on
// purpose, the signatures differed by accident.
#[path = "support/fuzz.rs"]
mod fuzz;
use fuzz::Rng;

/// Mutate a seed by flipping/overwriting/truncating bytes — deterministic.
///
/// Argument order matches `smoke_fuzz_test.rs`'s `mutate` on purpose. The two
/// BODIES stay different for the reason given at the top of this file, but
/// they used to differ in signature as well — `(seed, rng)` here against
/// `(rng, seed)` there — so the same name meant two different call shapes.
/// The compiler catches a swapped call (the types differ), but a reader moving
/// between the two files does not, and there is no benefit to the divergence.
///
/// Aligning the order cannot disturb this file's corpus reproducibility: the
/// body is untouched, so the sequence of PRNG draws is identical.
///
/// # Arguments
/// * `rng` — deterministic PRNG driving 1-6 mutation ops.
/// * `seed` — base input to mutate.
///
/// # Returns
/// The mutated byte vector.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    if out.is_empty() {
        out.push(rng.byte());
    }
    let ops = 1 + (rng.next_u64() % 6);
    for _ in 0..ops {
        match rng.next_u64() % 4 {
            0 if !out.is_empty() => {
                let i = (rng.next_u64() as usize) % out.len();
                out[i] = rng.byte();
            }
            1 => out.push(rng.byte()),
            2 if out.len() > 1 => {
                let i = (rng.next_u64() as usize) % out.len();
                out.truncate(i);
            }
            _ => out.insert((rng.next_u64() as usize) % (out.len() + 1), rng.byte()),
        }
    }
    out
}

/// Validates the validator: `ran_without_panic` reports a deliberately
/// panicking closure as `Err` and a clean closure as `Ok`.
#[test]
fn harness_actually_catches_a_panic() {
    // validate the validator: a panicking closure MUST be reported as a failure.
    assert!(ran_without_panic("boom", || panic!("deliberate")).is_err());
    // and a clean closure must pass.
    assert!(ran_without_panic("ok", || {}).is_ok());
}

/// None of the four parsers (SIP/RTP/RTCP on every SIP seed, SDP on the SDP
/// seeds) panics on the fixed adversarial seed set.
#[test]
fn parsers_never_panic_on_adversarial_seeds() {
    let mut failures = Vec::new();
    for (i, seed) in adversarial_seeds().iter().enumerate() {
        let s = seed.clone();
        if let Err(l) = ran_without_panic(&format!("sip seed #{i}"), move || drive_sip(&s)) {
            failures.push(l);
        }
        let s = seed.clone();
        if let Err(l) = ran_without_panic(&format!("rtp seed #{i}"), move || {
            let _ = parse_rtp_header(&s);
        }) {
            failures.push(l);
        }
        let s = seed.clone();
        if let Err(l) = ran_without_panic(&format!("rtcp seed #{i}"), move || {
            let _ = parse_rtcp(&s);
        }) {
            failures.push(l);
        }
    }
    for (i, seed) in sdp_seeds().iter().enumerate() {
        let s = seed.clone();
        if let Err(l) = ran_without_panic(&format!("sdp seed #{i}"), move || {
            let _ = parse_sdp(&s);
        }) {
            failures.push(l);
        }
    }
    assert!(failures.is_empty(), "parsers panicked on: {failures:?}");
}

/// ~20k deterministic xorshift mutations (5000 rounds × 4 parsers) of the seed
/// set never panic; fails fast on the first crashing input class.
#[test]
fn parsers_never_panic_on_mutation_sweep() {
    // ~20k deterministic mutations across all four parsers from the seed set.
    let mut rng = Rng::new(0x9E3779B97F4A7C15);
    let seeds: Vec<Vec<u8>> = adversarial_seeds().into_iter().chain(sdp_seeds()).collect();
    let mut failures = Vec::new();
    for round in 0..5000u32 {
        let base = &seeds[(round as usize) % seeds.len()];
        let m = mutate(&mut rng, base);
        let s = m.clone();
        if let Err(l) = ran_without_panic(&format!("sip mut #{round}"), move || drive_sip(&s)) {
            failures.push(l);
        }
        let s = m.clone();
        if let Err(l) = ran_without_panic(&format!("sdp mut #{round}"), move || {
            let _ = parse_sdp(&s);
        }) {
            failures.push(l);
        }
        let s = m.clone();
        if let Err(l) = ran_without_panic(&format!("rtp mut #{round}"), move || {
            let _ = parse_rtp_header(&s);
        }) {
            failures.push(l);
        }
        let s = m.clone();
        if let Err(l) = ran_without_panic(&format!("rtcp mut #{round}"), move || {
            let _ = parse_rtcp(&s);
        }) {
            failures.push(l);
        }
        if !failures.is_empty() {
            break; // fail fast with the first crashing input class
        }
    }
    assert!(
        failures.is_empty(),
        "mutation sweep crashed on: {failures:?}"
    );
}
