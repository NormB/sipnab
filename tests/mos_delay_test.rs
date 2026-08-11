// SPDX-License-Identifier: MIT OR Apache-2.0

#![cfg(feature = "native")]

//! One-way delay is an INPUT to MOS, not a constant.
//!
//! `estimate_mos` computed `delay_ms = 100.0 + jitter_ms` — a fixed 100 ms
//! one-way baseline — and that term feeds `Id` in every MOS sipnab reports:
//! call list, stream detail, dashboard, JSON, REST, MCP and alerts.
//!
//! On an intercontinental or satellite leg the real one-way delay is 150-400 ms.
//! G.107's `Id` has a knee at 177.3 ms, above which the penalty grows with a
//! square-root term, so an assumed 100 ms does not merely shift the answer, it
//! stays on the wrong side of the knee entirely. The reported MOS is then wrong
//! by more than a full point on the number operators escalate on.
//!
//! This tree already reasons carefully about how trustworthy a MOS is:
//! `MosGrounding` says whether G.113 publishes an impairment factor for the
//! codec, and `MosProvenance` distinguishes what sipnab estimated from what an
//! endpoint asserted. The delay term is an unmeasured input standing in for a
//! measurement — the same species of assumption — and it was the one dimension
//! that model did not cover.

use sipnab::rtp::quality::{
    DEFAULT_ONE_WAY_DELAY_MS, estimate_mos, estimate_mos_with_delay, one_way_delay_from_rtt_ms,
};

/// The default is unchanged, so no existing reading moves silently.
#[test]
fn the_default_delay_reproduces_the_old_score() {
    assert_eq!(
        DEFAULT_ONE_WAY_DELAY_MS, 100.0,
        "changing the default silently re-scores every capture ever compared"
    );
    for (jitter, loss, codec) in [
        (5.0, 0.0, Some("PCMU")),
        (30.0, 2.0, Some("G729")),
        (80.0, 15.0, None),
    ] {
        assert_eq!(
            estimate_mos(jitter, loss, codec),
            estimate_mos_with_delay(jitter, loss, codec, DEFAULT_ONE_WAY_DELAY_MS),
            "the uncapped entry point must stay exactly the old function"
        );
    }
}

/// A real long-haul delay scores WORSE than the assumed 100 ms.
///
/// This is the defect: a satellite leg was scored as if it were a LAN.
#[test]
fn a_long_haul_delay_scores_lower_than_the_assumption() {
    let assumed = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), DEFAULT_ONE_WAY_DELAY_MS);
    let satellite = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), 300.0);
    assert!(
        satellite < assumed,
        "300 ms one-way must score below the assumed 100 ms; got {satellite} vs {assumed}"
    );
    // The gap is the size of the defect, not a rounding difference: G.107's Id
    // knee at 177.3 ms means a 300 ms path is penalised by the sqrt term the
    // assumption never reaches.
    assert!(
        assumed - satellite > 1.0,
        "the assumption should cost more than a full MOS point on a 300 ms \
         path; got {assumed} vs {satellite}"
    );
}

/// Below the knee the model stays linear, so a short path is barely affected.
#[test]
fn a_lan_path_scores_at_or_above_the_assumption() {
    let lan = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), 20.0);
    let assumed = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), DEFAULT_ONE_WAY_DELAY_MS);
    assert!(
        lan >= assumed,
        "a 20 ms path cannot score worse than an assumed 100 ms one; got {lan} vs {assumed}"
    );
}

/// Jitter still contributes on top of whatever the path delay is.
///
/// The old code folded jitter into the same term; keeping that relationship
/// means a jittery long-haul leg is worse than a smooth one, which is the
/// whole point of the term.
#[test]
fn jitter_still_worsens_the_score_at_any_delay() {
    for delay in [20.0, DEFAULT_ONE_WAY_DELAY_MS, 300.0] {
        let smooth = estimate_mos_with_delay(1.0, 0.0, Some("PCMU"), delay);
        let jittery = estimate_mos_with_delay(60.0, 0.0, Some("PCMU"), delay);
        assert!(
            jittery <= smooth,
            "at {delay} ms, jitter must never IMPROVE the score; got {jittery} vs {smooth}"
        );
        // Strictly worse only where there is room to be worse. MOS is defined
        // on 1.0..=5.0, and a 300 ms path is already at the floor before any
        // jitter is added — asserting a strict decrease there would be
        // asserting that the scale extends below its own minimum.
        if smooth > 1.0 {
            assert!(
                jittery < smooth,
                "at {delay} ms, with headroom above the floor, jitter must \
                 lower the score; got {jittery} vs {smooth}"
            );
        }
    }
}

/// A nonsense delay cannot produce a nonsense MOS.
///
/// MOS is defined on 1.0..=5.0. A negative or absurd input is a bug upstream,
/// and returning 7.3 or NaN would launder it into a number an operator reads
/// as a measurement.
#[test]
fn an_absurd_delay_still_yields_a_mos_in_range() {
    for delay in [-50.0, 0.0, 10_000.0, f64::MAX] {
        let mos = estimate_mos_with_delay(10.0, 1.0, Some("PCMU"), delay);
        assert!(
            (1.0..=5.0).contains(&mos) && mos.is_finite(),
            "delay {delay} produced {mos}, which is not a MOS"
        );
    }
}

/// A reported round trip becomes the one-way delay; absent means absent.
///
/// RFC 3611 uses 0 for "not available", and a genuinely zero round trip does
/// not happen on a path with two endpoints — so 0 must not become "0 ms of
/// delay", which would score BETTER than the honest assumption and hand the
/// operator a flattering number for a stream that measured nothing.
#[test]
fn a_reported_round_trip_halves_into_one_way_and_zero_means_unknown() {
    assert_eq!(one_way_delay_from_rtt_ms(600), Some(300.0));
    assert_eq!(one_way_delay_from_rtt_ms(40), Some(20.0));
    assert_eq!(
        one_way_delay_from_rtt_ms(0),
        None,
        "RFC 3611 uses 0 for not-available; treating it as a measurement of \
         zero would score an unmeasured stream better than an honest guess"
    );
}

/// The measured path changes the score — the whole point of measuring.
#[test]
fn a_measured_satellite_round_trip_scores_far_below_the_assumption() {
    let measured = one_way_delay_from_rtt_ms(600).expect("600ms rtt is a measurement");
    let scored = estimate_mos_with_delay(10.0, 0.0, Some("PCMU"), measured);
    let assumed = estimate_mos(10.0, 0.0, Some("PCMU"));
    assert!(
        assumed - scored > 3.0,
        "a 600 ms round trip is a satellite hop: the assumption reports \
         {assumed:.2} where the measurement gives {scored:.2}"
    );
}

/// The operator's figure beats a remote claim, and both beat the assumption.
///
/// Order matters for a reason that is not aesthetic: the declared value is the
/// only one an attacker on the media path cannot change.
#[test]
fn declared_delay_wins_over_reported_which_wins_over_assumed() {
    use sipnab::rtp::quality::{DelaySource, resolve_one_way_delay};

    assert_eq!(
        resolve_one_way_delay(Some(280.0), Some(600)),
        (280.0, DelaySource::Declared),
        "an operator who declared 280ms must not be overridden by a packet"
    );
    assert_eq!(
        resolve_one_way_delay(None, Some(600)),
        (300.0, DelaySource::ReportedByEndpoint),
        "with nothing declared, a reported round trip is better than a guess"
    );
    assert_eq!(
        resolve_one_way_delay(None, None),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "with nothing at all, say so rather than imply a measurement"
    );
    assert_eq!(
        resolve_one_way_delay(None, Some(0)),
        (DEFAULT_ONE_WAY_DELAY_MS, DelaySource::Assumed),
        "RFC 3611 uses 0 for not-available; it must not read as a 0ms path"
    );
    // A nonsense declared value falls through rather than poisoning the score.
    assert_eq!(
        resolve_one_way_delay(Some(f64::NAN), Some(600)),
        (300.0, DelaySource::ReportedByEndpoint)
    );
}

/// The FLAG reaches the resolver, and config fills in when it is absent.
///
/// `--one-way-delay` is the operator's half of the contract, so it is tested
/// through the same parser the binary uses rather than by calling the resolver
/// directly: a value that parses but never reaches `declared_one_way_delay_ms`
/// would satisfy every other test in this file and change nothing a user sees.
#[test]
fn the_one_way_delay_flag_parses_and_beats_config() {
    use sipnab::cli::Cli;
    use sipnab::config::Config;

    let mut cfg = Config::default();
    cfg.media.one_way_delay_ms = Some(120.0);

    // Nothing on the command line: the config value is the declared one.
    let bare = Cli::parse_from_args(["sipnab"]);
    assert_eq!(bare.declared_one_way_delay_ms(&cfg), Some(120.0));

    // And with neither, "undeclared" — NOT the default, which is what lets the
    // resolver fall through to what the far end reported.
    assert_eq!(
        bare.declared_one_way_delay_ms(&Config::default()),
        None,
        "undeclared must stay None, or the RTCP fallback becomes unreachable"
    );

    // The flag wins, the way every other numeric setting here behaves.
    let flagged = Cli::parse_from_args(["sipnab", "--one-way-delay", "280"]);
    assert_eq!(flagged.declared_one_way_delay_ms(&cfg), Some(280.0));
    assert_eq!(
        flagged.declared_one_way_delay_ms(&Config::default()),
        Some(280.0)
    );

    // And it actually moves the score it exists to move.
    let assumed = estimate_mos(10.0, 0.0, Some("PCMU"));
    let declared = estimate_mos_with_delay(
        10.0,
        0.0,
        Some("PCMU"),
        flagged.declared_one_way_delay_ms(&cfg).expect("declared"),
    );
    assert!(
        assumed - declared > 1.0,
        "a declared 280ms satellite path must score well below the 100ms \
         assumption; got {assumed:.2} vs {declared:.2}"
    );
}
