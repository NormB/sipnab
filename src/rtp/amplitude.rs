// SPDX-License-Identifier: MIT OR Apache-2.0

//! What the decoded audio sounds like, as an amplitude measurement.
//!
//! sipnab's only quiet-call signal was counting Comfort Noise frames, which
//! detects a gateway that says it is sending silence. It cannot detect the
//! ordinary shape of a dead-air complaint: a gateway sending FULL-RATE frames
//! of digital silence. Those frames arrive on time, in sequence, at the right
//! rate; the packet statistics are perfect, the E-model scores them 4.36 with
//! `mos_grounded: true`, and nothing in the report says the call was silent.
//! Everything sipnab looked at was the envelope.
//!
//! `--retain-audio` already decodes the payload to PCM for WAV export, so the
//! samples are in hand and nothing looked at them. This module looks.
//!
//! **This is an amplitude measurement and it is not a MOS.** It reports what
//! the samples DID — how long they sat below a named floor, and how many ran
//! at the codec's own ceiling — and it converts none of that into a quality
//! score. A perceptual score needs a subjectively-labeled corpus that does not
//! exist here and could not be reproduced from the pcap by a reader who
//! doubted it. Every threshold below travels in the output beside the number
//! it produced, so a reader can disagree with the threshold rather than having
//! to take the finding on faith.

/// RMS below this, in dB relative to the stream's own full scale, is silence
/// for this measurement's purpose.
///
/// Grounded at both ends rather than chosen. Below it: true digital silence
/// decodes to 0 under mu-law and to ±8 under A-law's idle codes, both far
/// under this. Above it: ITU-T P.56 measures active speech against a nominal
/// -30 dBov, and even a quiet line's background noise sits some 30 dB above
/// this floor, so ordinary room tone does not read as dead air.
///
/// -60 dBFS is an amplitude of 32 in a 32768-scale container — five bits of
/// sixteen. A gateway sending anything at all lands above it.
pub const DEAD_AIR_FLOOR_DBFS: f64 = -60.0;

/// The window RMS is measured over.
///
/// Short enough to place a dead-air span within a tenth of a second, long
/// enough that one glottal stop between words is not a window of its own: at
/// 8 kHz this is 800 samples.
pub const WINDOW_MS: u32 = 100;

/// The shortest run of silent windows worth reporting.
///
/// A second, because shorter gaps are speech. Normal conversation is roughly
/// half silence — between words, between phrases, and while the other party
/// talks — and a measurement that reported every one of those would report
/// every healthy call.
pub const MIN_DEAD_AIR_MS: u32 = 1_000;

/// Fraction of full scale at or above which a sample counts as clipped.
///
/// Not 1.0. A decoder's largest output is one specific integer, and a signal
/// driven into the ceiling by a gain stage upstream lands on the two or three
/// codes below it as often as on the top one — so an exact-equality test
/// misses most of the clipping it exists to find.
pub const CLIP_FRACTION: f64 = 0.99;

/// The shortest run of consecutive clipped samples that counts as clipping.
///
/// One sample at the ceiling is a loud sample. Three consecutive is a
/// waveform with its top cut off, which is the thing that is audible.
pub const MIN_CLIP_RUN: usize = 3;

/// A run of one is not a run, and the test below builds its fixture by
/// subtracting one from this. At 1 that fixture would be empty and the test
/// would pass by measuring nothing, so the floor is checked where it cannot be
/// a runtime assertion on a constant: here, at compile time.
const _: () = assert!(MIN_CLIP_RUN >= 2);

/// A stretch of audio, located within the decoded stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Span {
    /// Milliseconds from the first decoded sample.
    pub start_ms: u64,
    /// How long the stretch ran.
    pub duration_ms: u64,
}

/// What the decoded samples did, with the thresholds that decided it.
///
/// The thresholds are FIELDS and not documentation. A reader who thinks the
/// floor is too generous can see the floor; a reader comparing two captures
/// can see whether they were measured the same way. A finding whose threshold
/// lives only in the source is a finding nobody can argue with.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AmplitudeReport {
    /// Sample rate the measurement ran at.
    pub sample_rate: u32,
    /// Total decoded audio.
    pub duration_ms: u64,
    /// The largest magnitude this stream's decoder can produce. Never
    /// `i16::MAX` for G.711 — see [`full_scale_for`].
    pub full_scale: i16,
    /// [`DEAD_AIR_FLOOR_DBFS`], carried so the output states it.
    pub floor_dbfs: f64,
    /// [`WINDOW_MS`], likewise.
    pub window_ms: u32,
    /// [`MIN_DEAD_AIR_MS`], likewise.
    pub min_dead_air_ms: u32,
    /// The absolute sample magnitude a clip was counted at, derived from
    /// `full_scale` and [`CLIP_FRACTION`].
    pub clip_threshold: i16,
    /// [`MIN_CLIP_RUN`], likewise.
    pub min_clip_run: usize,
    /// Dead-air spans, in order.
    pub dead_air: Vec<Span>,
    /// Total dead air, which is not the same as the longest span.
    pub dead_air_ms: u64,
    /// Clipped runs, in order.
    pub clipping: Vec<Span>,
    /// Samples inside those runs.
    pub clipped_samples: u64,
}

impl AmplitudeReport {
    /// Whether any dead-air span was long enough to report.
    #[must_use]
    pub fn has_dead_air(&self) -> bool {
        !self.dead_air.is_empty()
    }

    /// Whether any run of samples sat at the codec's ceiling.
    #[must_use]
    pub fn is_clipping(&self) -> bool {
        !self.clipping.is_empty()
    }

    /// The longest single dead-air span, which is the one a complaint is
    /// about. Zero when there is none.
    #[must_use]
    pub fn longest_dead_air_ms(&self) -> u64 {
        self.dead_air
            .iter()
            .map(|s| s.duration_ms)
            .max()
            .unwrap_or(0)
    }
}

/// The largest magnitude a codec's decoder can produce.
///
/// **Not `i16::MAX`.** G.711 decodes into a 16-bit container it never fills:
/// mu-law tops out at 32124 and A-law at 32256, so a clip test written against
/// 32767 can never fire on the two codecs most telephony runs on. The number
/// comes from the decode tables themselves rather than from a constant here,
/// so it cannot drift from the decoder it describes.
///
/// # Arguments
///
/// * `codec` — the stream's codec name.
///
/// # Returns
///
/// `None` for a codec whose PCM sipnab cannot produce, because a measurement
/// of samples that were never decoded is not a measurement.
#[must_use]
pub fn full_scale_for(codec: Option<&str>) -> Option<i16> {
    match codec? {
        "PCMU" => Some(table_max(crate::rtp::g711::ulaw_to_pcm)),
        "PCMA" => Some(table_max(crate::rtp::g711::alaw_to_pcm)),
        // Opus decodes to the full container. Its own limiter, not a companding
        // table, decides the ceiling.
        c if c.eq_ignore_ascii_case("opus") => Some(i16::MAX),
        _ => None,
    }
}

/// The largest magnitude a 256-entry decode table produces.
fn table_max(decode: fn(u8) -> i16) -> i16 {
    (0u8..=255)
        .map(|b| decode(b).saturating_abs())
        .max()
        .unwrap_or(i16::MAX)
}

/// Measure decoded PCM.
///
/// # Arguments
///
/// * `pcm` — decoded 16-bit linear samples, mono.
/// * `sample_rate` — samples per second, used to convert positions to time.
/// * `full_scale` — the decoder's own ceiling, from [`full_scale_for`].
///
/// # Returns
///
/// `None` when there is nothing to measure — no samples, or a sample rate of
/// zero. "Not measured" and "measured, and found nothing" are different
/// answers, and a caller that cannot tell them apart reports a silent call as
/// a clean one.
#[must_use]
pub fn measure(pcm: &[i16], sample_rate: u32, full_scale: i16) -> Option<AmplitudeReport> {
    if pcm.is_empty() || sample_rate == 0 || full_scale <= 0 {
        return None;
    }
    let window = ((u64::from(sample_rate) * u64::from(WINDOW_MS)) / 1000).max(1) as usize;
    let ms_per_sample = |n: usize| (n as u64 * 1000) / u64::from(sample_rate);

    // ── dead air ────────────────────────────────────────────────────
    // The floor is a RATIO of full scale, so a codec with a lower ceiling is
    // held to a proportionally lower floor rather than to an absolute one that
    // would mean something different on each codec.
    let floor = f64::from(full_scale) * 10f64.powf(DEAD_AIR_FLOOR_DBFS / 20.0);
    let mut silent_run_start: Option<usize> = None;
    let mut dead_air: Vec<Span> = Vec::new();
    let close = |start: usize, end: usize, out: &mut Vec<Span>| {
        let duration = ms_per_sample(end - start);
        if duration >= u64::from(MIN_DEAD_AIR_MS) {
            out.push(Span {
                start_ms: ms_per_sample(start),
                duration_ms: duration,
            });
        }
    };
    let mut at = 0usize;
    while at < pcm.len() {
        let end = (at + window).min(pcm.len());
        let chunk = &pcm[at..end];
        // Sum of squares in i64: 32767^2 * 48000 overflows an i32 and is
        // comfortable in an i64, so the RMS of a full-scale second is computed
        // rather than wrapped.
        let energy: i64 = chunk.iter().map(|&s| i64::from(s) * i64::from(s)).sum();
        let rms = (energy as f64 / chunk.len() as f64).sqrt();
        if rms < floor {
            silent_run_start.get_or_insert(at);
        } else if let Some(start) = silent_run_start.take() {
            close(start, at, &mut dead_air);
        }
        at = end;
    }
    if let Some(start) = silent_run_start.take() {
        close(start, pcm.len(), &mut dead_air);
    }
    let dead_air_ms = dead_air.iter().map(|s| s.duration_ms).sum();

    // ── clipping ────────────────────────────────────────────────────
    let clip_threshold = (f64::from(full_scale) * CLIP_FRACTION).floor() as i16;
    let mut clipping: Vec<Span> = Vec::new();
    let mut clipped_samples = 0u64;
    let mut run_start: Option<usize> = None;
    for i in 0..=pcm.len() {
        let at_ceiling = i < pcm.len() && pcm[i].saturating_abs() >= clip_threshold;
        match (at_ceiling, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(start)) => {
                let len = i - start;
                if len >= MIN_CLIP_RUN {
                    clipping.push(Span {
                        start_ms: ms_per_sample(start),
                        duration_ms: ms_per_sample(len),
                    });
                    clipped_samples += len as u64;
                }
                run_start = None;
            }
            _ => {}
        }
    }

    Some(AmplitudeReport {
        sample_rate,
        duration_ms: ms_per_sample(pcm.len()),
        full_scale,
        floor_dbfs: DEAD_AIR_FLOOR_DBFS,
        window_ms: WINDOW_MS,
        min_dead_air_ms: MIN_DEAD_AIR_MS,
        clip_threshold,
        min_clip_run: MIN_CLIP_RUN,
        dead_air,
        dead_air_ms,
        clipping,
        clipped_samples,
    })
}

/// One stream's amplitude measurement, with enough to find it again.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct StreamAmplitude {
    /// The stream's synchronization source, hex, as every other surface spells
    /// it.
    pub ssrc: String,
    /// Where the media came from.
    pub src: String,
    /// Where it went.
    pub dst: String,
    /// The codec whose decoder produced the samples, so a reader can check the
    /// ceiling the clip threshold was derived from.
    pub codec: String,
    /// What the samples did.
    pub report: AmplitudeReport,
}

/// The amplitude half of a dialog's media diagnosis.
///
/// Carried as an `Option` on [`MediaDiagnosis`](crate::rtp::diagnosis::MediaDiagnosis)
/// and absent when no audio was retained. That is the whole reason it is one
/// field rather than two booleans: `dead_air: false` on a call nobody decoded
/// reads as "checked, and fine", and it is the same shape of wrong answer as a
/// MOS on a codec with no impairment value.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct AmplitudeFindings {
    /// Streams whose audio was decoded and measured.
    pub streams_measured: usize,
    /// Any measured stream sat below the floor for longer than the minimum.
    pub dead_air: bool,
    /// Any measured stream ran at its codec's ceiling for longer than the
    /// minimum run.
    pub clipping: bool,
    /// The per-stream measurements, thresholds included.
    pub streams: Vec<StreamAmplitude>,
}

/// Measure every stream of a dialog whose audio was retained.
///
/// # Arguments
///
/// * `streams` — the dialog's streams. Ones with no retained payload are
///   skipped, which on a run without `--retain-audio` is all of them.
///
/// # Returns
///
/// `None` when nothing could be measured. A caller must not read that as a
/// clean call: it means the samples were never kept.
#[must_use]
pub fn findings_for(streams: &[&crate::rtp::stream::RtpStream]) -> Option<AmplitudeFindings> {
    let mut measured: Vec<StreamAmplitude> = Vec::new();
    for s in streams {
        let Some(full_scale) = full_scale_for(s.codec.as_deref()) else {
            continue;
        };
        let Some((pcm, rate)) = crate::rtp::audio_export::stream_pcm(s) else {
            continue;
        };
        let Some(report) = measure(&pcm, rate, full_scale) else {
            continue;
        };
        measured.push(StreamAmplitude {
            ssrc: format!("0x{:08x}", s.key.ssrc),
            src: s.key.src.to_string(),
            dst: s.key.dst.to_string(),
            codec: s.codec.clone().unwrap_or_default(),
            report,
        });
    }
    if measured.is_empty() {
        return None;
    }
    Some(AmplitudeFindings {
        streams_measured: measured.len(),
        dead_air: measured.iter().any(|m| m.report.has_dead_air()),
        clipping: measured.iter().any(|m| m.report.is_clipping()),
        streams: measured,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CLIP_FRACTION, DEAD_AIR_FLOOR_DBFS, MIN_CLIP_RUN, MIN_DEAD_AIR_MS, WINDOW_MS,
        full_scale_for, measure,
    };

    const RATE: u32 = 8000;

    /// `n` milliseconds of samples, all `v`.
    fn flat(v: i16, ms: u32) -> Vec<i16> {
        vec![v; (RATE as usize * ms as usize) / 1000]
    }

    /// `ms` of a 440 Hz sine at `peak`.
    fn tone(peak: i16, ms: u32) -> Vec<i16> {
        let n = (RATE as usize * ms as usize) / 1000;
        (0..n)
            .map(|i| {
                let t = i as f64 / f64::from(RATE);
                (f64::from(peak) * (2.0 * std::f64::consts::PI * 440.0 * t).sin()) as i16
            })
            .collect()
    }

    // ── dead air ────────────────────────────────────────────────────

    /// THE case this module exists for: full-rate frames of digital silence.
    ///
    /// Every packet arrived, in sequence, on time. Loss is zero, jitter is
    /// zero, and the E-model scores it 4.36 with `mos_grounded: true`. The only
    /// thing wrong with the call is the one thing nothing looked at.
    #[test]
    fn full_rate_digital_silence_is_dead_air() {
        let pcm = flat(0, 3000);
        let r = measure(&pcm, RATE, 32124).expect("three seconds is measurable");
        assert!(r.has_dead_air(), "three seconds of zeros read as audio");
        assert_eq!(r.dead_air.len(), 1);
        assert_eq!(r.dead_air[0].start_ms, 0);
        assert!(
            r.longest_dead_air_ms() >= 2900,
            "the span must cover the silence, not a window of it: {}ms",
            r.longest_dead_air_ms()
        );
    }

    /// A-law's idle codes decode to ±8, not to 0. A floor that only caught
    /// exact zeros would report a silent A-law call as healthy.
    #[test]
    fn the_a_law_idle_level_is_still_silence() {
        let pcm = flat(8, 3000);
        let r = measure(&pcm, RATE, 32256).expect("measurable");
        assert!(
            r.has_dead_air(),
            "A-law idle at ±8 must sit under the floor, or the floor is set \
             below the quietest thing a gateway can send"
        );
    }

    /// Speech does not read as dead air. The other half of the pair: a floor
    /// high enough to catch everything catches every call.
    #[test]
    fn ordinary_speech_level_audio_is_not_dead_air() {
        // -20 dBFS, a normal active speech level and 40 dB above the floor.
        let peak = (f64::from(32124i16) * 0.1) as i16;
        let r = measure(&tone(peak, 3000), RATE, 32124).expect("measurable");
        assert!(
            !r.has_dead_air(),
            "a -20 dBFS tone was reported as silence: {:?}",
            r.dead_air
        );
    }

    /// Conversation is roughly half silence. A measurement that reported the
    /// gap between two words would report every healthy call.
    #[test]
    fn a_gap_shorter_than_the_minimum_is_not_reported() {
        let peak = (f64::from(32124i16) * 0.1) as i16;
        let mut pcm = tone(peak, 1000);
        pcm.extend(flat(0, 500));
        pcm.extend(tone(peak, 1000));
        let r = measure(&pcm, RATE, 32124).expect("measurable");
        assert!(
            !r.has_dead_air(),
            "a 500 ms pause between words was reported as dead air: {:?}",
            r.dead_air
        );
        assert!(
            u64::from(MIN_DEAD_AIR_MS) > 500,
            "this test rests on the minimum being above 500 ms"
        );
    }

    /// The span says WHERE, because "this call had dead air" and "this call
    /// went silent 40 seconds in" are different findings.
    #[test]
    fn a_span_names_where_the_silence_started() {
        let peak = (f64::from(32124i16) * 0.1) as i16;
        let mut pcm = tone(peak, 2000);
        pcm.extend(flat(0, 2000));
        pcm.extend(tone(peak, 1000));
        let r = measure(&pcm, RATE, 32124).expect("measurable");
        assert_eq!(r.dead_air.len(), 1, "one span, not one per window");
        let span = r.dead_air[0];
        assert!(
            (1900..=2100).contains(&span.start_ms),
            "the silence starts two seconds in, not at {}ms",
            span.start_ms
        );
        assert!(
            (1900..=2100).contains(&span.duration_ms),
            "and runs two seconds, not {}ms",
            span.duration_ms
        );
    }

    /// Two separate outages are two findings, and the total is not the longest.
    #[test]
    fn the_total_and_the_longest_are_different_numbers() {
        let peak = (f64::from(32124i16) * 0.1) as i16;
        let mut pcm = tone(peak, 500);
        pcm.extend(flat(0, 1500));
        pcm.extend(tone(peak, 500));
        pcm.extend(flat(0, 2500));
        pcm.extend(tone(peak, 500));
        let r = measure(&pcm, RATE, 32124).expect("measurable");
        assert_eq!(r.dead_air.len(), 2, "got {:?}", r.dead_air);
        assert!(r.dead_air_ms > r.longest_dead_air_ms());
        assert_eq!(
            r.dead_air_ms,
            r.dead_air.iter().map(|s| s.duration_ms).sum::<u64>()
        );
    }

    // ── clipping ────────────────────────────────────────────────────

    /// The pinned-value trap, stated as a test.
    ///
    /// mu-law's decoder tops out at 32124 and A-law's at 32256. A clip test
    /// written against `i16::MAX` never fires on either — which is every
    /// ordinary telephony call.
    #[test]
    fn clipping_is_measured_against_the_codec_ceiling_not_the_container() {
        let ceiling = full_scale_for(Some("PCMU")).expect("PCMU decodes");
        assert!(
            ceiling < i16::MAX,
            "mu-law fills its container after all, and this whole test is moot"
        );
        let r = measure(&flat(ceiling, 500), RATE, ceiling).expect("measurable");
        assert!(
            r.is_clipping(),
            "a mu-law stream pinned at its own maximum ({ceiling}) reported no \
             clipping, which is what a threshold of {} would do",
            i16::MAX
        );
        assert!(
            r.clip_threshold < i16::MAX,
            "the threshold reported was {} — a value this codec cannot reach",
            r.clip_threshold
        );
    }

    /// A-law's ceiling is not mu-law's. The threshold has to follow the stream.
    #[test]
    fn each_companding_law_has_its_own_ceiling() {
        let u = full_scale_for(Some("PCMU")).expect("PCMU");
        let a = full_scale_for(Some("PCMA")).expect("PCMA");
        assert_ne!(u, a, "the two laws decode to different maxima");
        // A signal at mu-law's ceiling is BELOW A-law's, so measuring one
        // against the other's threshold changes the answer.
        let r = measure(&flat(u, 500), RATE, a).expect("measurable");
        assert!(
            r.clip_threshold > (f64::from(u) * CLIP_FRACTION) as i16,
            "the A-law threshold must be above the mu-law one, or the two \
             ceilings are not being told apart"
        );
    }

    /// One loud sample is a loud sample. Three in a row is a flat top.
    #[test]
    fn a_run_shorter_than_the_minimum_is_not_clipping() {
        let ceiling = 32124i16;
        let mut pcm = tone(1000, 200);
        // Exactly one sample below the minimum run, in the middle.
        let at = pcm.len() / 2;
        for i in 0..(MIN_CLIP_RUN - 1) {
            pcm[at + i] = ceiling;
        }
        let r = measure(&pcm, RATE, ceiling).expect("measurable");
        assert!(
            !r.is_clipping(),
            "{} consecutive samples at the ceiling was reported as clipping",
            MIN_CLIP_RUN - 1
        );
    }

    /// Negative peaks clip too. A magnitude test that only looked at the
    /// positive half would miss a waveform cut off at the bottom.
    #[test]
    fn the_negative_rail_clips_as_well_as_the_positive() {
        let ceiling = 32124i16;
        let r = measure(&flat(-ceiling, 500), RATE, ceiling).expect("measurable");
        assert!(
            r.is_clipping(),
            "a run at the negative rail was not counted"
        );
        assert!(r.clipped_samples > 0);
    }

    // ── the thresholds travel with the answer ───────────────────────

    /// A finding whose threshold lives only in the source is a finding nobody
    /// can argue with. Every one of them is a field.
    #[test]
    fn the_report_states_the_thresholds_that_produced_it() {
        let r = measure(&flat(0, 2000), RATE, 32124).expect("measurable");
        assert!((r.floor_dbfs - DEAD_AIR_FLOOR_DBFS).abs() < f64::EPSILON);
        assert_eq!(r.window_ms, WINDOW_MS);
        assert_eq!(r.min_dead_air_ms, MIN_DEAD_AIR_MS);
        assert_eq!(r.min_clip_run, MIN_CLIP_RUN);
        assert_eq!(r.full_scale, 32124);
        assert_eq!(r.sample_rate, RATE);
        assert_eq!(r.duration_ms, 2000);
    }

    // ── not measured is not clean ───────────────────────────────────

    /// A call with no retained audio has not been measured, and saying "no
    /// dead air" about it would be the confident wrong answer this project
    /// refuses everywhere else.
    #[test]
    fn nothing_to_measure_returns_no_measurement() {
        assert!(measure(&[], RATE, 32124).is_none(), "no samples");
        assert!(measure(&flat(0, 100), 0, 32124).is_none(), "no sample rate");
        assert!(measure(&flat(0, 100), RATE, 0).is_none(), "no ceiling");
    }

    /// A codec whose PCM sipnab cannot produce has no ceiling to measure
    /// against, and inventing one would measure samples that were never
    /// decoded.
    #[test]
    fn a_codec_without_a_decoder_has_no_full_scale() {
        assert!(full_scale_for(None).is_none());
        assert!(full_scale_for(Some("AMR-WB")).is_none());
        assert!(full_scale_for(Some("G729")).is_none());
        assert_eq!(full_scale_for(Some("opus")), Some(i16::MAX));
        assert_eq!(full_scale_for(Some("Opus")), Some(i16::MAX));
    }
}
