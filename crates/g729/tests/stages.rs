// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stage tests: each decoder stage, fed its inputs from the oracle's traces,
//! must reproduce the trace's outputs exactly, subframe by subframe.
//!
//! Built only with the `g729_oracle` cfg flag (`RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`): the traces exist only in the
//! main checkout's `.git/g729-traces`. Run with
//! `RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729 --test stages`.
#![cfg(g729_oracle)]

pub mod common;

use common::trace::{self, ALL, ANNEX_A, Frame};
use g729::basic_op::Ctx;
use g729::tables::formula;
use g729::{adaptive, fixed, gain, lpc, lsp, post_process, postfilter, synth};

fn arr<const N: usize>(v: &[i32]) -> [i16; N] {
    assert_eq!(v.len(), N, "trace vector length");
    core::array::from_fn(|i| v[i] as i16)
}

/// Report the first mismatch with its location.
fn check<T: PartialEq + core::fmt::Debug>(
    name: &str,
    fi: usize,
    sf: usize,
    what: &str,
    got: T,
    want: T,
) {
    assert_eq!(got, want, "{name} frame {fi} subframe {sf}: {what}");
}

fn is_active(f: &Frame) -> bool {
    f.f.s("frame_type_decoded") == "speech"
}

#[test]
fn lsp_decoding_matches_clause_3_2_4_and_4_4_1() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut st = lsp::LsfQuantizerMemory::new(t);
        for (fi, fr) in frames.iter().enumerate() {
            let f = &fr.f;
            if !is_active(fr) {
                // Non-active frames are covered by the CNG stage test; keep
                // the memory in step with the trace.
                st.replace_past_outputs(&arr::<40>(f.a("lsf_quantizer_memory_q13")));
                continue;
            }
            let mut c = Ctx::default();
            let idx = if f.i("erasure_flag") == 1 {
                None
            } else {
                Some([
                    f.i("L0") as u16,
                    f.i("L1") as u16,
                    f.i("L2") as u16,
                    f.i("L3") as u16,
                ])
            };
            let lsf = st.decode_frame(&mut c, t, idx);
            check(name, fi, 0, "lsf_q13", lsf, arr::<10>(f.a("lsf_q13")));
            check(
                name,
                fi,
                0,
                "lsf_quantizer_memory_q13",
                st.past_outputs(),
                arr::<40>(f.a("lsf_quantizer_memory_q13")),
            );
            let q = lsp::lsf_to_lsp(&mut c, t, &lsf);
            check(name, fi, 0, "lsp_q15", q, arr::<10>(f.a("lsp_q15")));
        }
    }
    Ok(())
}

#[test]
fn lsp_interpolation_and_lp_conversion_match_clauses_3_2_5_and_3_2_6() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut prev: [i16; 10] = t.decoder_initial_previous_lsp();
        for (fi, fr) in frames.iter().enumerate() {
            let mut c = Ctx::default();
            let cur = arr::<10>(fr.f.a("lsp_q15"));
            let q0 = lsp::interpolate(&mut c, &prev, &cur);
            check(
                name,
                fi,
                0,
                "lsp_interpolated_q15",
                q0,
                arr::<10>(fr.s[0].a("lsp_interpolated_q15")),
            );
            for (sf, s) in fr.s.iter().enumerate() {
                let q = arr::<10>(s.a("lsp_interpolated_q15"));
                check(
                    name,
                    fi,
                    sf,
                    "lp_coefficients_q12",
                    lpc::lsp_to_lp(&mut c, &q),
                    arr::<11>(s.a("lp_coefficients_q12")),
                );
            }
            prev = cur;
        }
    }
    Ok(())
}

#[test]
fn pitch_delay_decoding_matches_clauses_4_1_2_4_1_3_and_4_4() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut st = adaptive::PitchState::new(t);
        for (fi, fr) in frames.iter().enumerate() {
            if !is_active(fr) {
                continue;
            }
            let f = &fr.f;
            let erased = f.i("erasure_flag") == 1;
            let mut t1 = 0;
            for (sf, s) in fr.s.iter().enumerate() {
                let (int, frac) = if erased {
                    st.erased()
                } else if sf == 0 {
                    let ok = adaptive::parity_ok(f.i("P1") as u16, f.i("P0") as u16);
                    check(name, fi, sf, "parity_error", !ok, f.i("parity_error") == 1);
                    let d = st.first(f.i("P1") as u16, ok);
                    t1 = d.0;
                    d
                } else {
                    st.second(f.i("P2") as u16, t1)
                };
                check(
                    name,
                    fi,
                    sf,
                    "pitch delay",
                    (int, frac),
                    (
                        s.i("pitch_delay_integer") as i16,
                        s.i("pitch_delay_fraction") as i16,
                    ),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn adaptive_codebook_vector_matches_equation_40() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut past = [0i16; adaptive::PAST];
        for (fi, fr) in frames.iter().enumerate() {
            for (sf, s) in fr.s.iter().enumerate() {
                if is_active(fr) {
                    let mut c = Ctx::default();
                    let mut buf = [0i16; adaptive::PAST + 40];
                    buf[..adaptive::PAST].copy_from_slice(&past);
                    adaptive::adaptive_vector(
                        &mut c,
                        t,
                        &mut buf,
                        adaptive::PAST,
                        s.i("pitch_delay_integer") as i16,
                        s.i("pitch_delay_fraction") as i16,
                    );
                    check(
                        name,
                        fi,
                        sf,
                        "adaptive_codebook_vector",
                        &buf[adaptive::PAST..],
                        &arr::<40>(s.a("adaptive_codebook_vector"))[..],
                    );
                }
                let e = s.a("excitation_after_rescale");
                past.copy_within(40.., 0);
                for (k, v) in e.iter().enumerate() {
                    past[adaptive::PAST - 40 + k] = *v as i16;
                }
                if s.i("synthesis_overflow_rescaled") == 1 {
                    let after = s.a("excitation_memory_after_rescale");
                    let end = 154 + 40 * (sf + 1);
                    for k in 0..adaptive::PAST {
                        past[k] = after[end - adaptive::PAST + k] as i16;
                    }
                }
            }
        }
    }
    Ok(())
}

#[test]
fn fixed_codebook_matches_clauses_3_8_and_4_1_4() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut seed = fixed::ERASURE_SEED;
        for (fi, fr) in frames.iter().enumerate() {
            if !is_active(fr) {
                continue;
            }
            let f = &fr.f;
            for (sf, s) in fr.s.iter().enumerate() {
                let mut c = Ctx::default();
                let (ci, si) = if f.i("erasure_flag") == 1 {
                    fixed::random_index(&mut seed)
                } else if sf == 0 {
                    (f.i("C1") as u16, f.i("S1") as u16)
                } else {
                    (f.i("C2") as u16, f.i("S2") as u16)
                };
                check(
                    name,
                    fi,
                    sf,
                    "fixed codebook index",
                    (ci, si),
                    (
                        s.i("fixed_codebook_index_used") as u16,
                        s.i("fixed_codebook_sign_index_used") as u16,
                    ),
                );
                let (pos, sign) = fixed::pulses(ci, si);
                let pos_i: Vec<i32> = pos.iter().map(|&p| p as i32).collect();
                let sign_i: Vec<i32> = sign.iter().map(|&b| i32::from(b)).collect();
                check(
                    name,
                    fi,
                    sf,
                    "pulse positions",
                    &pos_i[..],
                    s.a("fixed_codebook_pulse_positions"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "pulse signs",
                    &sign_i[..],
                    s.a("fixed_codebook_pulse_signs"),
                );
                let mut code = fixed::codevector(t, &pos, &sign);
                check(
                    name,
                    fi,
                    sf,
                    "before sharpening",
                    code,
                    arr::<40>(s.a("fixed_codebook_vector_before_sharpening")),
                );
                fixed::sharpen(
                    &mut c,
                    &mut code,
                    s.i("pitch_delay_integer") as i16,
                    s.i("pitch_sharpening_used") as i16,
                );
                check(
                    name,
                    fi,
                    sf,
                    "fixed_codebook_vector",
                    code,
                    arr::<40>(s.a("fixed_codebook_vector")),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn gains_match_clauses_3_9_4_1_5_and_4_4_2_to_4_4_3() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut st = gain::GainState::new();
        let mut sharp = g729::tables::text::PITCH_SHARPENING_MIN;
        for (fi, fr) in frames.iter().enumerate() {
            if !is_active(fr) {
                // Annex B non-active frames leave the gain-predictor memory
                // unchanged and reset the sharpening factor.
                sharp = g729::tables::text::PITCH_SHARPENING_MIN;
                continue;
            }
            let f = &fr.f;
            for (sf, s) in fr.s.iter().enumerate() {
                let mut c = Ctx::default();
                check(
                    name,
                    fi,
                    sf,
                    "pitch_sharpening_used",
                    sharp,
                    s.i("pitch_sharpening_used") as i16,
                );
                let code = arr::<40>(s.a("fixed_codebook_vector"));
                let g = if f.i("erasure_flag") == 1 {
                    st.conceal(&mut c, t)
                } else {
                    let (ga, gb) = if sf == 0 {
                        ("GA1", "GB1")
                    } else {
                        ("GA2", "GB2")
                    };
                    let (g0, e) = gain::predict(&mut c, t, &code, st.memory());
                    check(
                        name,
                        fi,
                        sf,
                        "predicted gain",
                        (g0, e),
                        (
                            s.i("predicted_fixed_codebook_gain") as i16,
                            s.i("predicted_fixed_codebook_gain_exponent") as i16,
                        ),
                    );
                    st.decode(&mut c, t, f.i(ga) as u16, f.i(gb) as u16, &code)
                };
                check(
                    name,
                    fi,
                    sf,
                    "gains",
                    (g.gp, g.gc),
                    (
                        s.i("adaptive_codebook_gain") as i16,
                        s.i("fixed_codebook_gain") as i16,
                    ),
                );
                check(
                    name,
                    fi,
                    sf,
                    "gain_predictor_memory",
                    *st.memory(),
                    arr::<4>(s.a("gain_predictor_memory")),
                );
                sharp = gain::sharpening(t, g.gp);
            }
        }
    }
    Ok(())
}

#[test]
fn excitation_and_synthesis_match_clause_4_1_6_with_rescaling() -> common::TestResult {
    for name in ALL {
        let frames = trace::load(name)?;
        let mut mem = [0i16; 10];
        for (fi, fr) in frames.iter().enumerate() {
            for (sf, s) in fr.s.iter().enumerate() {
                let mut c = Ctx::default();
                if s.has("fixed_codebook_vector") {
                    let u = synth::excitation(
                        &mut c,
                        &arr::<40>(s.a("adaptive_codebook_vector")),
                        &arr::<40>(s.a("fixed_codebook_vector")),
                        s.i("adaptive_codebook_gain") as i16,
                        s.i("fixed_codebook_gain") as i16,
                    );
                    check(name, fi, sf, "excitation", u, arr::<40>(s.a("excitation")));
                }
                let a = arr::<11>(s.a("lp_coefficients_q12"));
                let (out, overflow) =
                    synth::synthesize(&mut c, &a, &arr::<40>(s.a("excitation")), &mem);
                check(
                    name,
                    fi,
                    sf,
                    "synthesis_overflow_rescaled",
                    overflow,
                    s.i("synthesis_overflow_rescaled") == 1,
                );
                let out = if overflow {
                    synth::synthesize(
                        &mut c,
                        &a,
                        &arr::<40>(s.a("excitation_after_rescale")),
                        &mem,
                    )
                    .0
                } else {
                    out
                };
                check(
                    name,
                    fi,
                    sf,
                    "synthesis_output",
                    out,
                    arr::<40>(s.a("synthesis_output")),
                );
                mem.copy_from_slice(&out[30..]);
            }
        }
    }
    Ok(())
}

#[test]
fn postfilter_matches_clause_a_4_2() -> common::TestResult {
    let t = common::tables()?;
    for name in ALL {
        let frames = trace::load(name)?;
        let mut pf = postfilter::AdaptivePostfilter::new();
        for (fi, fr) in frames.iter().enumerate() {
            for (sf, s) in fr.s.iter().enumerate() {
                let mut c = Ctx::default();
                let a = arr::<11>(s.a("lp_coefficients_q12"));
                let syn = arr::<40>(s.a("synthesis_output"));
                let active = is_active(fr);
                let input = postfilter::PostfilterInput {
                    a_hat: &a,
                    s_hat: &syn,
                    pitch_delay: s.oi("pitch_delay_integer").unwrap_or(0) as i16,
                    long_term: active,
                };
                let st = pf.run_traced(&mut c, t, &input);
                check(
                    name,
                    fi,
                    sf,
                    "postfilter_residual",
                    st.r_hat,
                    arr::<40>(s.a("postfilter_residual")),
                );
                check(
                    name,
                    fi,
                    sf,
                    "long_term_postfilter_on",
                    st.long_term_on,
                    s.i("long_term_postfilter_on") == 1,
                );
                check(
                    name,
                    fi,
                    sf,
                    "long_term_postfilter_delay",
                    st.long_term_delay.map(i64::from),
                    s.oi("long_term_postfilter_delay"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "ltp gains",
                    (
                        st.weight_current.map(i64::from),
                        st.weight_delayed.map(i64::from),
                    ),
                    (
                        s.oi("long_term_postfilter_gain_current"),
                        s.oi("long_term_postfilter_gain_delayed"),
                    ),
                );
                check(
                    name,
                    fi,
                    sf,
                    "long_term_postfilter_output",
                    st.long_term_output,
                    arr::<40>(s.a("long_term_postfilter_output")),
                );
                check(
                    name,
                    fi,
                    sf,
                    "tilt_compensation_coefficient",
                    st.tilt_factor,
                    s.i("tilt_compensation_coefficient") as i16,
                );
                check(
                    name,
                    fi,
                    sf,
                    "tilt_compensation_output",
                    st.tilt_output,
                    arr::<40>(s.a("tilt_compensation_output")),
                );
                check(
                    name,
                    fi,
                    sf,
                    "short_term_postfilter_output",
                    st.short_term_output,
                    arr::<40>(s.a("short_term_postfilter_output")),
                );
                check(
                    name,
                    fi,
                    sf,
                    "agc_target_gain",
                    st.gain_target.map(i64::from),
                    s.oi("agc_target_gain"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "agc_gain_end",
                    st.gain_end,
                    s.i("agc_gain_end") as i16,
                );
                check(
                    name,
                    fi,
                    sf,
                    "postfilter_output",
                    st.output,
                    arr::<40>(s.a("postfilter_output")),
                );
            }
        }
    }
    Ok(())
}

#[test]
fn post_processing_matches_clause_4_2_5() -> common::TestResult {
    for name in ALL {
        let frames = trace::load(name)?;
        let mut hp = post_process::HighPass::new();
        for (fi, fr) in frames.iter().enumerate() {
            for (sf, s) in fr.s.iter().enumerate() {
                let mut c = Ctx::default();
                let out = hp.process(&mut c, &arr::<40>(s.a("postfilter_output")));
                check(name, fi, sf, "output", out, arr::<40>(s.a("output")));
            }
        }
    }
    Ok(())
}

#[test]
fn formula_tables_are_the_ones_the_stages_use() -> common::TestResult {
    // The stage modules take the cosine and interpolation-free lookups from
    // `formula`; a smoke check that the module is linked as intended.
    assert_eq!(formula::LSP_COSINE.len(), 64);
    assert_eq!(ANNEX_A.len(), 10);
    Ok(())
}

// ---------------------------------------------------------------------------
// Annex B (clause B.4): comfort-noise stages.
// ---------------------------------------------------------------------------

#[cfg(feature = "annex-b")]
const ANNEX_B: [&str; 6] = [
    "tstseq1a", "tstseq2a", "tstseq3a", "tstseq4a", "tstseq5", "tstseq6",
];

#[cfg(feature = "annex-b")]
#[test]
fn sid_lsf_decoding_and_cng_lsp_match_clause_b_4_2_2() -> common::TestResult {
    let t = common::tables()?;
    for name in ANNEX_B {
        let frames = trace::load(name)?;
        let mut st = lsp::LsfQuantizerMemory::new(t);
        let mut sid_lsp = t.sid_initial_lsp_for_tests();
        for (fi, fr) in frames.iter().enumerate() {
            let f = &fr.f;
            if f.has("sid_lsf_q13") {
                let mut c = Ctx::default();
                let p = g729::bitstream::SidParams {
                    switch: f.i("sid_lsf_predictor_switch") as u16,
                    stage1: f.i("sid_lsf_stage1_index") as u16,
                    stage2: f.i("sid_lsf_stage2_index") as u16,
                    energy: f.i("sid_energy_index") as u16,
                };
                let lsf = g729::cng::decode_sid_lsf(&mut c, t, &mut st, &p);
                check(
                    name,
                    fi,
                    0,
                    "sid_lsf_q13",
                    lsf,
                    arr::<10>(f.a("sid_lsf_q13")),
                );
                check(
                    name,
                    fi,
                    0,
                    "memory after SID",
                    st.past_outputs(),
                    arr::<40>(f.a("lsf_quantizer_memory_q13")),
                );
                sid_lsp = lsp::lsf_to_lsp(&mut c, t, &lsf);
            }
            if !is_active(fr) {
                check(
                    name,
                    fi,
                    0,
                    "cng lsp_q15",
                    sid_lsp,
                    arr::<10>(f.a("lsp_q15")),
                );
            }
            st.replace_past_outputs(&arr::<40>(f.a("lsf_quantizer_memory_q13")));
        }
    }
    Ok(())
}

#[cfg(feature = "annex-b")]
#[test]
fn sid_gain_and_target_gain_match_clauses_b_4_2_1_and_b_4_4() -> common::TestResult {
    for name in ANNEX_B {
        let frames = trace::load(name)?;
        let mut prev_active = true;
        let mut target = 0i16;
        let mut sid_gain = 0i16;
        for (fi, fr) in frames.iter().enumerate() {
            let f = &fr.f;
            if is_active(fr) {
                prev_active = true;
                continue;
            }
            if let Some(i) = f.oi("sid_energy_index_used") {
                sid_gain = formula::SID_GAIN[i as usize];
            }
            check(
                name,
                fi,
                0,
                "sid_decoded_gain",
                sid_gain,
                f.i("sid_decoded_gain") as i16,
            );
            let mut c = Ctx::default();
            target = g729::cng::smooth_target(&mut c, target, sid_gain, prev_active);
            check(
                name,
                fi,
                0,
                "cng_target_gain",
                target,
                f.i("cng_target_gain") as i16,
            );
            prev_active = false;
        }
    }
    Ok(())
}

#[cfg(feature = "annex-b")]
#[test]
fn saved_excitation_energy_and_lost_sid_recovery_match_clause_b_4_5() -> common::TestResult {
    let t = common::tables()?;
    for name in ANNEX_B {
        let frames = trace::load(name)?;
        let mut saved = (0i16, 0i16);
        let mut prev_active = true;
        for (fi, fr) in frames.iter().enumerate() {
            let f = &fr.f;
            let mut c = Ctx::default();
            if !is_active(fr)
                && prev_active
                && !f.has("sid_lsf_q13")
                && let Some(i) = f.oi("sid_energy_index_used")
            {
                check(
                    name,
                    fi,
                    0,
                    "recovered SID energy index",
                    g729::cng::quantize_energy(&mut c, t, saved),
                    i as u16,
                );
            }
            if f.i("erasure_flag") == 0 {
                let mut e: Vec<i16> = fr.s[0].a16("excitation_after_rescale");
                e.extend(fr.s[1].a16("excitation_after_rescale"));
                saved = g729::cng::frame_energy(&mut c, &e);
            }
            check(
                name,
                fi,
                0,
                "saved excitation energy",
                saved,
                (
                    f.i("saved_excitation_energy_mantissa") as i16,
                    f.i("saved_excitation_energy_exponent") as i16,
                ),
            );
            prev_active = is_active(fr);
        }
    }
    Ok(())
}

/// Run the comfort-noise generator over a trace, calling `each` with the
/// random parameters and Gaussian draws of every non-active subframe.
#[cfg(feature = "annex-b")]
fn for_each_cng_subframe(
    name: &str,
    mut each: impl FnMut(usize, usize, &g729::cng::RandomParams, &[i16; 40], &Frame),
) -> common::TestResult {
    let t = common::tables()?;
    let frames = trace::load(name)?;
    let mut seed = t.scalar(g729::tables::Scalar::CngRandomSeedInitial);
    for (fi, fr) in frames.iter().enumerate() {
        if is_active(fr) {
            seed = t.scalar(g729::tables::Scalar::CngRandomSeedInitial);
            continue;
        }
        for sf in 0..2 {
            let p = g729::cng::draw_params(t, &mut seed);
            let raw = g729::cng::draw_gaussian(&mut seed);
            each(fi, sf, &p, &raw, fr);
        }
    }
    Ok(())
}

#[cfg(feature = "annex-b")]
#[test]
fn comfort_noise_random_parameters_match_clause_b_4_4() -> common::TestResult {
    for name in ANNEX_B {
        for_each_cng_subframe(name, |fi, sf, p, _raw, fr| {
            let s = &fr.s[sf];
            if s.oi("cng_pitch_delay_integer").is_none() {
                return;
            }
            check(
                name,
                fi,
                sf,
                "cng delay",
                (p.delay, p.frac),
                (
                    s.i("cng_pitch_delay_integer") as i16,
                    s.i("cng_pitch_delay_fraction") as i16,
                ),
            );
            let pos: Vec<i32> = p.positions.iter().map(|&x| x as i32).collect();
            let sg: Vec<i32> = p.signs.iter().map(|&b| i32::from(b)).collect();
            check(
                name,
                fi,
                sf,
                "cng pulse positions",
                &pos[..],
                s.a("cng_pulse_positions"),
            );
            check(
                name,
                fi,
                sf,
                "cng pulse signs",
                &sg[..],
                s.a("cng_pulse_signs"),
            );
            check(
                name,
                fi,
                sf,
                "cng_adaptive_gain_random",
                p.adaptive_gain,
                s.i("cng_adaptive_gain_random") as i16,
            );
        })?;
    }
    Ok(())
}

#[cfg(feature = "annex-b")]
#[test]
fn comfort_noise_adaptive_vector_and_composition_match_clause_b_4_4() -> common::TestResult {
    let t = common::tables()?;
    for name in ANNEX_B {
        let frames = trace::load(name)?;
        let mut past = [0i16; adaptive::PAST];
        for (fi, fr) in frames.iter().enumerate() {
            for (sf, s) in fr.s.iter().enumerate() {
                if !is_active(fr) && s.oi("cng_pitch_delay_integer").is_some() {
                    let mut c = Ctx::default();
                    let mut buf = [0i16; adaptive::PAST + 40];
                    buf[..adaptive::PAST].copy_from_slice(&past);
                    adaptive::adaptive_vector(
                        &mut c,
                        t,
                        &mut buf,
                        adaptive::PAST,
                        s.i("cng_pitch_delay_integer") as i16,
                        s.i("cng_pitch_delay_fraction") as i16,
                    );
                    let ea: [i16; 40] = core::array::from_fn(|n| buf[adaptive::PAST + n]);
                    check(
                        name,
                        fi,
                        sf,
                        "cng_adaptive_vector",
                        ea,
                        arr::<40>(s.a("cng_adaptive_vector")),
                    );
                    let gauss = arr::<40>(s.a("cng_gaussian_excitation"));
                    let mut x =
                        g729::cng::compose(&mut c, &ea, s.i("cng_adaptive_gain") as i16, &gauss);
                    let pos: [usize; 4] =
                        core::array::from_fn(|k| s.a("cng_pulse_positions")[k] as usize);
                    let sg: [bool; 4] = core::array::from_fn(|k| s.a("cng_pulse_signs")[k] == 1);
                    g729::cng::add_pulses(&mut c, &mut x, &pos, &sg, s.i("cng_fixed_gain") as i16);
                    check(
                        name,
                        fi,
                        sf,
                        "cng excitation",
                        x,
                        arr::<40>(s.a("excitation")),
                    );
                }
                past.copy_within(40.., 0);
                for (k, v) in s.a("excitation_after_rescale").iter().enumerate() {
                    past[adaptive::PAST - 40 + k] = *v as i16;
                }
                if s.i("synthesis_overflow_rescaled") == 1 {
                    let after = s.a("excitation_memory_after_rescale");
                    let end = 154 + 40 * (sf + 1);
                    for k in 0..adaptive::PAST {
                        past[k] = after[end - adaptive::PAST + k] as i16;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Clause B.4.4: the Gaussian excitation, from this decoder's own random
/// draws to the scaled ex2(n), against every step of the oracle's
/// round-2 comfort-noise traces.
#[cfg(feature = "annex-b")]
#[test]
fn gaussian_excitation_matches_clause_b_4_4() -> common::TestResult {
    let t = common::tables()?;
    for name in ANNEX_B {
        let detail = trace::load_cng(name)?;
        let mut records = detail.iter().filter(|r| r.oi("subframe").is_some());
        for_each_cng_subframe(name, |fi, sf, _p, raw, fr| {
            if fr.s[sf].oa("cng_gaussian_excitation").is_none() {
                return;
            }
            let r = records.next();
            assert!(
                r.is_some(),
                "{name}: a detail record per comfort-noise subframe"
            );
            let Some(r) = r else { return };
            check(
                name,
                fi,
                sf,
                "record order",
                (r.i("frame_index") as usize, r.i("subframe") as usize),
                (fi, sf),
            );
            check(
                name,
                fi,
                sf,
                "gaussian_raw",
                *raw,
                arr::<40>(r.a("gaussian_raw")),
            );
            let mut c = Ctx::default();
            let g = g729::cng::gaussian_steps(&mut c, t, raw, r.i("target_gain") as i16);
            check(
                name,
                fi,
                sf,
                "gaussian_energy",
                i64::from(g.energy),
                r.i("gaussian_energy"),
            );
            check(
                name,
                fi,
                sf,
                "inverse sqrt",
                i64::from(g.inverse_sqrt),
                r.i("gaussian_energy_inverse_sqrt"),
            );
            check(
                name,
                fi,
                sf,
                "inverse sqrt split",
                (
                    i64::from(g.inverse_sqrt_high),
                    i64::from(g.inverse_sqrt_low),
                ),
                (
                    r.i("gaussian_energy_inverse_sqrt_high"),
                    r.i("gaussian_energy_inverse_sqrt_low"),
                ),
            );
            check(
                name,
                fi,
                sf,
                "gaussian_gain_factor",
                i64::from(g.gain_factor),
                r.i("gaussian_gain_factor"),
            );
            check(
                name,
                fi,
                sf,
                "gaussian_scale",
                i64::from(g.scale),
                r.i("gaussian_scale"),
            );
            check(
                name,
                fi,
                sf,
                "normalization",
                i64::from(g.normalization),
                r.i("gaussian_scale_normalization"),
            );
            check(
                name,
                fi,
                sf,
                "mantissa",
                i64::from(g.mantissa),
                r.i("gaussian_scale_mantissa"),
            );
            check(
                name,
                fi,
                sf,
                "final shift",
                i64::from(g.final_shift),
                r.i("gaussian_final_shift"),
            );
            check(
                name,
                fi,
                sf,
                "before shift",
                g.before_shift,
                arr::<40>(r.a("gaussian_scaled_before_shift")),
            );
            check(
                name,
                fi,
                sf,
                "gaussian_scaled",
                g.scaled,
                arr::<40>(r.a("gaussian_scaled")),
            );
            check(
                name,
                fi,
                sf,
                "round-1 cng_gaussian_excitation",
                g.scaled,
                arr::<40>(fr.s[sf].a("cng_gaussian_excitation")),
            );
        })?;
        assert!(records.next().is_none(), "{name}: detail records left over");
    }
    Ok(())
}

/// Equations B.20 to B.23: the fixed gain Gf, every step, including the
/// case where the adaptive gain is dropped. The reference computes E_x and I
/// on the mixed excitation Ga ea(n) + ex2(n).
#[cfg(feature = "annex-b")]
#[test]
fn comfort_noise_fixed_gain_matches_equations_b_20_to_b_23() -> common::TestResult {
    let t = common::tables()?;
    for name in ANNEX_B {
        for r in trace::load_cng(name)?
            .iter()
            .filter(|r| r.oi("subframe").is_some())
        {
            let (fi, sf) = (r.i("frame_index") as usize, r.i("subframe") as usize);
            let mut c = Ctx::default();
            let ea = arr::<40>(r.a("adaptive_excitation"));
            let ex2 = arr::<40>(r.a("gaussian_scaled"));
            let pos: [usize; 4] = core::array::from_fn(|k| r.a("pulse_positions")[k] as usize);
            let sg: [bool; 4] = core::array::from_fn(|k| r.a("pulse_signs")[k] == 1);
            let ga = r.i("adaptive_gain_random") as i16;
            let mixed = g729::cng::compose(&mut c, &ea, ga, &ex2);
            check(
                name,
                fi,
                sf,
                "mixed_excitation",
                mixed,
                arr::<40>(r.a("mixed_excitation")),
            );
            let sub = g729::cng::CngSubframe {
                mixed: &mixed,
                gaussian: &ex2,
                positions: &pos,
                signs: &sg,
                adaptive_gain: ga,
                target: r.i("target_gain") as i16,
            };
            let st = g729::cng::fixed_gain_steps(&mut c, t, &sub);
            let wide = |exc: i32| i64::from(exc);
            check(
                name,
                fi,
                sf,
                "max abs",
                i64::from(st.max_abs),
                r.i("mixed_excitation_max_abs"),
            );
            check(
                name,
                fi,
                sf,
                "rescale_shift",
                wide(st.rescale_shift.into()),
                r.i("rescale_shift"),
            );
            check(
                name,
                fi,
                sf,
                "rescaled",
                st.rescaled,
                arr::<40>(r.a("mixed_excitation_rescaled")),
            );
            check(
                name,
                fi,
                sf,
                "energy_ex",
                wide(st.energy_ex),
                r.i("energy_ex"),
            );
            check(
                name,
                fi,
                sf,
                "correlation_i",
                wide(st.correlation_i.into()),
                r.i("correlation_i"),
            );
            check(
                name,
                fi,
                sf,
                "k_factor",
                wide(st.k_factor.into()),
                r.i("k_factor"),
            );
            check(
                name,
                fi,
                sf,
                "k_target_energy",
                wide(st.k_target_energy),
                r.i("k_target_energy"),
            );
            check(
                name,
                fi,
                sf,
                "k_aligned",
                wide(st.k_aligned),
                r.i("k_aligned"),
            );
            check(
                name,
                fi,
                sf,
                "k_minus_energy",
                wide(st.k_minus_energy),
                r.i("k_minus_energy"),
            );
            check(
                name,
                fi,
                sf,
                "correlation_i_halved",
                wide(st.correlation_i_halved.into()),
                r.i("correlation_i_halved"),
            );
            check(
                name,
                fi,
                sf,
                "discriminant",
                wide(st.discriminant),
                r.i("discriminant"),
            );
            check(
                name,
                fi,
                sf,
                "root_shift",
                wide(st.root_shift.into()),
                r.i("root_shift"),
            );
            check(
                name,
                fi,
                sf,
                "adaptive_gain_dropped",
                i64::from(st.dropped.is_some()),
                r.i("adaptive_gain_dropped"),
            );
            if let Some(d) = &st.dropped {
                check(
                    name,
                    fi,
                    sf,
                    "dropped_root_shift",
                    wide(d.root_shift.into()),
                    r.i("dropped_root_shift"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "dropped_correlation_i",
                    wide(d.correlation_i.into()),
                    r.i("dropped_correlation_i"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "dropped_k_times_k0",
                    wide(d.k_times_k0),
                    r.i("dropped_k_times_k0"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "dropped_k_aligned",
                    wide(d.k_aligned),
                    r.i("dropped_k_aligned"),
                );
                check(
                    name,
                    fi,
                    sf,
                    "dropped_discriminant",
                    wide(d.discriminant),
                    r.i("dropped_discriminant"),
                );
            }
            check(
                name,
                fi,
                sf,
                "discriminant_sqrt",
                wide(st.sqrt.into()),
                r.i("discriminant_sqrt"),
            );
            check(
                name,
                fi,
                sf,
                "roots",
                (
                    wide(st.root_a.into()),
                    wide(st.root_b.into()),
                    wide(st.root_chosen.into()),
                ),
                (r.i("root_a"), r.i("root_b"), r.i("root_chosen")),
            );
            check(
                name,
                fi,
                sf,
                "fixed_gain_unbounded",
                wide(st.unbounded.into()),
                r.i("fixed_gain_unbounded"),
            );
            check(
                name,
                fi,
                sf,
                "fixed_gain",
                wide(st.fixed_gain.into()),
                r.i("fixed_gain"),
            );
            check(
                name,
                fi,
                sf,
                "adaptive_gain",
                wide(st.adaptive_gain.into()),
                r.i("adaptive_gain"),
            );
            let mut exc = if st.dropped.is_some() {
                g729::cng::compose(&mut c, &ea, 0, &ex2)
            } else {
                mixed
            };
            g729::cng::add_pulses(&mut c, &mut exc, &pos, &sg, st.fixed_gain);
            check(
                name,
                fi,
                sf,
                "excitation",
                exc,
                arr::<40>(r.a("excitation")),
            );
        }
    }
    Ok(())
}

/// Clauses B.4.2.1 and B.4.5: the recovery of a lost first SID frame.
#[cfg(feature = "annex-b")]
#[test]
fn lost_sid_recovery_matches_clauses_b_4_2_1_and_b_4_5() -> common::TestResult {
    let t = common::tables()?;
    let mut n = 0;
    for name in ANNEX_B {
        for r in trace::load_cng(name)?
            .iter()
            .filter(|r| r.oi("subframe").is_none())
        {
            let fi = r.i("frame_index") as usize;
            let mut c = Ctx::default();
            let q = g729::cng::recovery_steps(
                &mut c,
                t,
                (
                    r.i("saved_energy_mantissa") as i16,
                    r.i("saved_energy_exponent") as i16,
                ),
            );
            check(
                name,
                fi,
                0,
                "saved_energy_value",
                i64::from(q.value),
                r.i("saved_energy_value"),
            );
            check(
                name,
                fi,
                0,
                "split",
                (i64::from(q.high), i64::from(q.low)),
                (
                    r.i("saved_energy_split_high"),
                    r.i("saved_energy_split_low"),
                ),
            );
            check(
                name,
                fi,
                0,
                "energy_per_sample",
                i64::from(q.per_sample),
                r.i("energy_per_sample"),
            );
            check(
                name,
                fi,
                0,
                "log2",
                (i64::from(q.log2_integer), i64::from(q.log2_fraction)),
                (r.i("log2_integer"), r.i("log2_fraction")),
            );
            check(
                name,
                fi,
                0,
                "log2_energy",
                i64::from(q.log2_energy),
                r.i("log2_energy"),
            );
            check(
                name,
                fi,
                0,
                "energy_index",
                i64::from(q.index),
                r.i("energy_index"),
            );
            check(
                name,
                fi,
                0,
                "sid_gain_recovered",
                i64::from(formula::SID_GAIN[usize::from(q.index)]),
                r.i("sid_gain_recovered"),
            );
            n += 1;
        }
    }
    assert_eq!(n, 1, "the vectors hold one recovery (tstseq6 frame 75)");
    Ok(())
}

/// Equation B.18, against the oracle's step-by-step derivation.
#[cfg(feature = "annex-b")]
#[test]
fn b18_matches_the_oracle_derivation() -> common::TestResult {
    let path = trace::reference_dir().join("sid_ma_predictor_derivation.json");
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let get = |k: &str| -> Result<[[i16; 10]; 4], String> {
        let a = v[k].as_array().ok_or_else(|| format!("{k} missing"))?;
        let ints: Option<Vec<i16>> = a.iter().map(|x| x.as_i64().map(|n| n as i16)).collect();
        let ints = ints
            .filter(|v| v.len() == 40)
            .ok_or_else(|| format!("{k}: not 40 integers"))?;
        Ok(core::array::from_fn(|k4| {
            core::array::from_fn(|i| ints[10 * k4 + i])
        }))
    };
    assert_eq!(
        g729::tables::b18_mix(&get("predictor_1")?, &get("predictor_2")?),
        get("sid_predictor_2")?
    );
    Ok(())
}
