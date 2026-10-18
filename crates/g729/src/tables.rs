// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The decoder's constant data, split by where it may come from.
//!
//! * [`formula`]: tables the Recommendation defines by a formula, computed
//!   here at compile time (cosine, base-2 power and inverse square root
//!   lookups of clauses 3.2.6, 3.9.1 and 4.2.4; the gain-prediction
//!   coefficients of clause 3.9.1; the output high-pass filter of equation
//!   (91); the initial LSF quantizer memory and gain-predictor memory of
//!   Table 9; the Annex B SID gain grid of clause B.4.2.1; and the bit
//!   allocations of Table 8 and Table B.2).
//! * [`text`]: scalar constants the Recommendation states (clauses 3 to 4.4,
//!   A.4.2 and B.4.4), plus the serial test-vector format words.
//! * [`Tables`]: everything else, which the text neither states nor defines by
//!   formula: the trained codebooks (clauses 3.2.4 and 3.9.2, B.4.2.2), the
//!   adaptive-codebook interpolation filter b30 of equation (40), the base-2
//!   logarithm lookup, initial states and implementation scalars. These are
//!   user-supplied: no source file of this crate holds them. They are read
//!   from a table file ([`FILE_MAGIC`], built by `import_from_itu`) whose
//!   values must hash to [`VALUES_SHA256`].
//!
//! [`CLASSIFICATION`] records the class of each of the 30 tables and 59
//! scalars the oracle extracted, and why.

/// Magic header of the table file.
pub const FILE_MAGIC: &[u8; 8] = b"G729TBL\0";
/// Version of the table file layout described in [`ENTRIES`].
pub const FILE_VERSION: u16 = 1;
/// sha256 of the user-supplied values: every entry of [`ENTRIES`] in order,
/// each value as a little-endian i16. Computed once from the oracle's
/// extraction (see `PROVENANCE.md`); a hash is not the data.
pub const VALUES_SHA256: &str = "e4846d29f3da09451781e61187fceac230d12cb0c6be0a85348a524137852ac2";

/// Where a value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Computed in [`formula`] from a formula the text gives.
    Formula,
    /// A constant the text states, in [`text`].
    TextConstant,
    /// A word of the serial test-vector format, measured from the vector
    /// files themselves (no ITU code needed), in [`text`].
    VectorFormat,
    /// Neither stated nor defined by formula: imported from the ITU package.
    UserSupplied,
    /// Computed by the importer from a text formula over user-supplied
    /// values (the second SID LSF MA predictor, equation (B.18)).
    ComputedAtImport,
}

/// One classified table or scalar.
#[derive(Debug, Clone, Copy)]
pub struct Classified {
    /// The oracle's name for it.
    pub name: &'static str,
    /// A scalar rather than a table.
    pub scalar: bool,
    /// Its class.
    pub class: Class,
    /// Why: the clause or the measured reason.
    pub basis: &'static str,
}

const fn c(name: &'static str, scalar: bool, class: Class, basis: &'static str) -> Classified {
    Classified {
        name,
        scalar,
        class,
        basis,
    }
}

use Class::{
    ComputedAtImport as Computed, Formula, TextConstant as Text, UserSupplied as User, VectorFormat,
};

/// The class of every table and scalar.
pub const CLASSIFICATION: &[Classified] = &[
    c(
        "lsp_codebook_stage1",
        false,
        User,
        "trained codebook L1, clause 3.2.4",
    ),
    c(
        "lsp_codebook_stage2",
        false,
        User,
        "trained codebooks L2/L3, clause 3.2.4",
    ),
    c(
        "lsp_ma_predictor",
        false,
        User,
        "trained MA predictor, clause 3.2.4",
    ),
    c(
        "lsp_ma_predictor_complement",
        false,
        User,
        "1 - sum p, but tabulated within 3 LSB of the formula",
    ),
    c(
        "lsp_ma_predictor_complement_inverse",
        false,
        User,
        "reciprocal of the above, within 2 LSB",
    ),
    c(
        "lsp_quantizer_initial_memory",
        false,
        Formula,
        "i*pi/11 truncated to Q13, clause 3.2.4 and Table 9",
    ),
    c(
        "lsp_cosine_table",
        false,
        Formula,
        "cos(i*pi/64) in Q15, 1.0 saturated",
    ),
    c(
        "lsp_cosine_slope_table",
        false,
        Formula,
        "2^19 (cos((i+1)pi/64) - cos(i pi/64)), rounded",
    ),
    c(
        "adaptive_codebook_interpolation_filter",
        false,
        User,
        "b30 of clause 3.7.1: the stated Hamming-windowed sinc differs from the table in 28 of 31 taps",
    ),
    c(
        "gain_prediction_coefficients",
        false,
        Formula,
        "0.68 0.58 0.34 0.19 in Q13, clause 3.9.1",
    ),
    c(
        "gain_codebook_ga",
        false,
        User,
        "trained codebook GA, clause 3.9.2",
    ),
    c(
        "gain_codebook_gb",
        false,
        User,
        "trained codebook GB, clause 3.9.2",
    ),
    c(
        "gain_index_map_ga",
        false,
        User,
        "index map, clause 3.9.3 gives no values",
    ),
    c(
        "gain_index_map_gb",
        false,
        User,
        "index map, clause 3.9.3 gives no values",
    ),
    c(
        "log2_table",
        false,
        User,
        "log2(1+i/32): rounding differs in 16 of 33 entries, truncation in 11",
    ),
    c(
        "pow2_table",
        false,
        Formula,
        "2^(i/32) in Q14, last saturated",
    ),
    c(
        "inverse_sqrt_table",
        false,
        Formula,
        "1/sqrt(1+i/16) in Q15, first saturated",
    ),
    c(
        "highpass_postprocessing_numerator",
        false,
        Formula,
        "equation (91) in Q13",
    ),
    c(
        "highpass_postprocessing_denominator",
        false,
        Formula,
        "equation (91) in Q13",
    ),
    c("speech_frame_bit_allocation", false, Formula, "Table 8"),
    c(
        "decoder_initial_previous_lsp",
        false,
        User,
        "initial state not given by the text",
    ),
    c(
        "gain_predictor_initial_memory",
        false,
        Formula,
        "-14 dB in Q10, Table 9",
    ),
    c("sid_frame_bit_allocation", false, Formula, "Table B.2"),
    c(
        "sid_lsf_ma_predictor",
        false,
        Computed,
        "equation (B.18) over lsp_ma_predictor",
    ),
    c(
        "sid_lsf_ma_predictor_complement",
        false,
        User,
        "not given by the text",
    ),
    c(
        "sid_lsf_stage1_subset",
        false,
        User,
        "subset lookup of clause B.4.2.2, values not given",
    ),
    c(
        "sid_lsf_stage2_subset",
        false,
        User,
        "subset lookup of clause B.4.2.2, values not given",
    ),
    c(
        "sid_gain_table",
        false,
        Formula,
        "8 * 10^(E/20) on the clause B.4.2.1 quantizer grid",
    ),
    c("sid_energy_scale", false, User, "not given by the text"),
    c(
        "sid_initial_lsp",
        false,
        User,
        "initial state not given by the text",
    ),
    c("pitch_sharpening_min", true, Text, "0.2 in Q14, clause 3.8"),
    c(
        "pitch_sharpening_max",
        true,
        User,
        "13017 is not 0.8 in Q14 (13107)",
    ),
    c("pitch_delay_min", true, Text, "clause 3.7"),
    c("pitch_delay_max", true, Text, "clause 3.7"),
    c(
        "initial_previous_pitch_delay",
        true,
        User,
        "initial state not given by the text",
    ),
    c(
        "fixed_codebook_pulse_positive",
        true,
        User,
        "8191 is not +1.0 in Q13",
    ),
    c(
        "fixed_codebook_pulse_negative",
        true,
        Text,
        "-1.0 in Q13, clause 3.8",
    ),
    c(
        "gain_prediction_log_scale",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "gain_prediction_mean_energy_mantissa",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "gain_prediction_mean_energy_multiplier",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "gain_prediction_db_to_log2",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "gain_update_log2_to_db",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "erasure_pitch_gain_attenuation",
        true,
        Text,
        "0.9 in Q15, equation (94)",
    ),
    c(
        "erasure_pitch_gain_limit",
        true,
        User,
        "compared in Q14, where it is 1.8, not the 0.9 of equation (94)",
    ),
    c(
        "erasure_fixed_gain_attenuation",
        true,
        User,
        "32111 is not 0.98 in Q15 (32113)",
    ),
    c(
        "erasure_gain_memory_offset",
        true,
        Text,
        "4 dB in Q10, equation (95)",
    ),
    c(
        "erasure_gain_memory_floor",
        true,
        Text,
        "-14 dB in Q10, equation (95)",
    ),
    c("random_multiplier", true, Text, "equation (96)"),
    c("random_increment", true, Text, "equation (96)"),
    c("erasure_random_seed_initial", true, Text, "clause 4.4.4"),
    c(
        "lsf_to_lsp_frequency_scale",
        true,
        User,
        "implementation constant, not stated",
    ),
    c(
        "lsf_expansion_gap_1",
        true,
        Text,
        "J = 0.0012 in Q13, clause 3.2.4",
    ),
    c(
        "lsf_expansion_gap_2",
        true,
        Text,
        "J = 0.0006 in Q13, clause 3.2.4",
    ),
    c(
        "lsf_stability_low_limit",
        true,
        User,
        "40 is not 0.005 in Q13 (41)",
    ),
    c(
        "lsf_stability_high_limit",
        true,
        User,
        "25681 is not 3.135 in Q13 (25682)",
    ),
    c(
        "lsf_stability_min_distance",
        true,
        User,
        "321 is not 0.0391 in Q13 (320)",
    ),
    c(
        "postfilter_numerator_weight",
        true,
        Text,
        "gamma_n = 0.55, clause A.4.2.2",
    ),
    c(
        "postfilter_denominator_weight",
        true,
        Text,
        "gamma_d = 0.70, clause A.4.2.2",
    ),
    c(
        "long_term_postfilter_gamma",
        true,
        Text,
        "gamma_p = 0.5, clause 4.2.1",
    ),
    c(
        "long_term_postfilter_unit_g0",
        true,
        Text,
        "1/(1+gamma_p), equation (A.11) with g = 1",
    ),
    c(
        "long_term_postfilter_unit_gl",
        true,
        Text,
        "gamma_p/(1+gamma_p), equation (A.11) with g = 1",
    ),
    c(
        "long_term_postfilter_search_half_range",
        true,
        Text,
        "[Tcl-3, Tcl+3], clause A.4.2.1",
    ),
    c(
        "tilt_compensation_factor",
        true,
        Text,
        "gamma_t = 0.8, clause A.4.2.3",
    ),
    c(
        "tilt_impulse_response_length",
        true,
        Text,
        "22 terms, equation (A.14)",
    ),
    c("agc_factor", true, Text, "0.9, clause A.4.2.4"),
    c(
        "agc_factor_complement",
        true,
        Text,
        "1 - 0.9 with 1.0 saturated to 32767, clause A.4.2.4",
    ),
    c(
        "agc_initial_gain",
        true,
        Text,
        "g(-1) = 1.0 in Q12, clause 4.2.4",
    ),
    c(
        "serial_sync_word",
        true,
        VectorFormat,
        "measured from the vector files",
    ),
    c(
        "serial_bit_zero",
        true,
        VectorFormat,
        "measured from the vector files",
    ),
    c(
        "serial_bit_one",
        true,
        VectorFormat,
        "measured from the vector files",
    ),
    c(
        "serial_size_speech",
        true,
        VectorFormat,
        "80 bits, Table 1; measured",
    ),
    c(
        "serial_size_sid",
        true,
        VectorFormat,
        "measured from the vector files",
    ),
    c(
        "serial_size_no_transmission",
        true,
        VectorFormat,
        "measured from the vector files",
    ),
    c(
        "cng_random_seed_initial",
        true,
        User,
        "not given by the text",
    ),
    c("cng_gain_smoothing_old", true, Text, "7/8, equation (B.19)"),
    c("cng_gain_smoothing_new", true, Text, "1/8, equation (B.19)"),
    c(
        "cng_gaussian_scale_fraction",
        true,
        User,
        "uses alpha = 0.5; the text's mixing uses 0.6",
    ),
    c(
        "cng_k0",
        true,
        User,
        "1 - alpha^2 with alpha = 0.5, not stated",
    ),
    c("cng_fixed_gain_limit", true, User, "not given by the text"),
    c(
        "cng_pitch_delay_min",
        true,
        Text,
        "lag in [40, 103], clause B.4.4",
    ),
    c(
        "cng_adaptive_gain_mask",
        true,
        User,
        "not given by the text",
    ),
    c(
        "sid_lsf_min_distance",
        true,
        Text,
        "J = 0.0012 per clause 3.2.4, applied by clause B.4.2.2",
    ),
    c(
        "sid_energy_q_low_threshold",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_high_threshold",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_knee",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_low_offset",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_low_step",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_high_offset",
        true,
        User,
        "quantizer implementation constant",
    ),
    c(
        "sid_energy_q_high_step",
        true,
        User,
        "quantizer implementation constant",
    ),
];

/// Where the importer finds an entry in the ITU-T package.
#[derive(Debug, Clone, Copy)]
pub struct Source {
    /// Path below `Software/G729_Release3/` (informational: files are
    /// located by `sha256`).
    pub file: &'static str,
    /// sha256 of the whole source file.
    pub sha256: &'static str,
    /// First line of the initializer, 1-based.
    pub first_line: u32,
    /// Last line, inclusive.
    pub last_line: u32,
    /// For a scalar, which integer literal of the line holds it.
    pub token: Option<usize>,
}

const TAB_A: &str = "deefd5e1b7d02d6994cdbc65491d9eafe40fe52e5291eaaf26848cd2132fe5a1";
const TAB_B: &str = "d2e9271cd7e1931fe1fabe3029881f6fbf83576e9360c9b2bd6a2fffdd9e6226";
const DEC_LD8A: &str = "981d1047fb350b46f391bc1585df50cd4f7c3da216e9789efcbaf303eb594f5c";
const DEC_GAIN: &str = "07fb8695db5d46e76af9cf6e8c23faa5c3ca26bff202ba36db806b6e8fb2932c";
const DEC_SID: &str = "951942993deb24afdcd82f7a4265f7072b3b4cf8b768a20b404fe0dd64f11f1d";
const TAB_DTX: &str = "165ed446bc179aaad30673aa8390139bdfab13f7ea6e0322285f14d0320ba325";
const LD8A_H: &str = "e53cb6066d554792260ad7b19756e01dda035a0ca1dd266c23d25a199e8ca43c";
const DE_ACELP: &str = "1e517c5cf1fb3cb6ea9330edd911482f7fe146dfa5d72da9a781ec35e3664f5d";
const GAINPRED: &str = "c9f9a64d895a2212f4b59adda2db6063d54bea766671df32b53960da60d2a426";
const UTIL: &str = "8f0bd79ab8807ad1d5b350c0ec3a1cf9423dcf7abc4a74d5a9e165d591564fc5";
const LPCFUNC: &str = "e87de93a75c715507bd26c5a6cc76a6a06efd6149e34fd422c382ae1911fe80d";
const POSTFILT: &str = "5cb46384777ddac5764684790f4578632eabcf0085c5094750b635fa179cd614";
const DTX_H: &str = "1abf6fd06e46e1d25e55b39dce27d3704b711d563f9f618a3c3287706116d352";
const OCTET_H: &str = "813afebb43e88174e1c6a9669136d8782f804b3867b9e6fb5251ba0a7f865941";
const CALCEXC: &str = "997fc1954fadf89a4e6aab181456144f54a0b37d55202d6f39308eef8dbf988d";
const QSIDGAIN: &str = "931663dd17a7095233bb9c4e0b3d54bac9ed5c3aa5575bbcfc501494e7909eb7";

const fn t(file: &'static str, sha256: &'static str, first_line: u32, last_line: u32) -> Source {
    Source {
        file,
        sha256,
        first_line,
        last_line,
        token: None,
    }
}

const fn s(file: &'static str, sha256: &'static str, line: u32, token: usize) -> Source {
    Source {
        file,
        sha256,
        first_line: line,
        last_line: line,
        token: Some(token),
    }
}

const A: &str = "g729AnnexA/c_code/TAB_LD8A.C";
const B: &str = "g729AnnexB/c_codeBA/tab_ld8a.c";
const LD8A: &str = "g729AnnexA/c_code/LD8A.H";
const DTX: &str = "g729AnnexB/c_codeBA/dtx.h";
const QSG: &str = "g729AnnexB/c_codeBA/qsidgain.c";
const DTXC: &str = "g729AnnexB/c_codeBA/tab_dtx.c";

/// The locator of every table and scalar that has one in the ITU package
/// (all but the run-time computed SID LSF MA predictor). Used by the
/// importer for the user-supplied entries, and by the tests to check the
/// formula and text entries against the reference.
pub const SOURCES: &[(&str, Source)] = &[
    ("lsp_codebook_stage1", t(A, TAB_A, 164, 293)),
    ("lsp_codebook_stage2", t(A, TAB_A, 296, 329)),
    ("lsp_ma_predictor", t(A, TAB_A, 330, 343)),
    ("lsp_ma_predictor_complement", t(A, TAB_A, 344, 347)),
    ("lsp_ma_predictor_complement_inverse", t(A, TAB_A, 348, 351)),
    ("lsp_quantizer_initial_memory", t(B, TAB_B, 383, 385)),
    ("lsp_cosine_table", t(A, TAB_A, 129, 137)),
    ("lsp_cosine_slope_table", t(A, TAB_A, 141, 149)),
    (
        "adaptive_codebook_interpolation_filter",
        t(A, TAB_A, 383, 394),
    ),
    ("gain_prediction_coefficients", t(A, TAB_A, 416, 416)),
    ("gain_codebook_ga", t(A, TAB_A, 419, 429)),
    ("gain_codebook_gb", t(A, TAB_A, 431, 449)),
    ("gain_index_map_ga", t(A, TAB_A, 488, 490)),
    ("gain_index_map_gb", t(A, TAB_A, 492, 494)),
    ("log2_table", t(A, TAB_A, 535, 539)),
    ("pow2_table", t(A, TAB_A, 525, 529)),
    ("inverse_sqrt_table", t(A, TAB_A, 545, 551)),
    ("highpass_postprocessing_numerator", t(A, TAB_A, 502, 502)),
    ("highpass_postprocessing_denominator", t(A, TAB_A, 503, 503)),
    (
        "decoder_initial_previous_lsp",
        t("g729AnnexA/c_code/DEC_LD8A.C", DEC_LD8A, 43, 44),
    ),
    (
        "gain_predictor_initial_memory",
        t("g729AnnexA/c_code/DEC_GAIN.C", DEC_GAIN, 54, 54),
    ),
    ("sid_frame_bit_allocation", t(B, TAB_B, 530, 533)),
    ("sid_lsf_ma_predictor_complement", t(DTXC, TAB_DTX, 45, 48)),
    ("sid_lsf_stage1_subset", t(DTXC, TAB_DTX, 55, 57)),
    ("sid_lsf_stage2_subset", t(DTXC, TAB_DTX, 58, 59)),
    ("sid_gain_table", t(DTXC, TAB_DTX, 36, 40)),
    ("sid_energy_scale", t(DTXC, TAB_DTX, 34, 34)),
    (
        "sid_initial_lsp",
        t("g729AnnexB/c_codeBA/dec_sid.c", DEC_SID, 33, 35),
    ),
    ("pitch_sharpening_min", s(LD8A, LD8A_H, 38, 0)),
    ("pitch_sharpening_max", s(LD8A, LD8A_H, 37, 0)),
    ("pitch_delay_min", s(LD8A, LD8A_H, 29, 0)),
    ("pitch_delay_max", s(LD8A, LD8A_H, 30, 0)),
    (
        "initial_previous_pitch_delay",
        s("g729AnnexA/c_code/DEC_LD8A.C", DEC_LD8A, 76, 0),
    ),
    (
        "fixed_codebook_pulse_positive",
        s("g729AnnexA/c_code/DE_ACELP.C", DE_ACELP, 67, 0),
    ),
    (
        "fixed_codebook_pulse_negative",
        s("g729AnnexA/c_code/DE_ACELP.C", DE_ACELP, 70, 0),
    ),
    (
        "gain_prediction_log_scale",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 62, 0),
    ),
    (
        "gain_prediction_mean_energy_mantissa",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 66, 0),
    ),
    (
        "gain_prediction_mean_energy_multiplier",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 66, 1),
    ),
    (
        "gain_prediction_db_to_log2",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 85, 0),
    ),
    (
        "gain_update_log2_to_db",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 124, 1),
    ),
    (
        "erasure_pitch_gain_attenuation",
        s("g729AnnexA/c_code/DEC_GAIN.C", DEC_GAIN, 60, 0),
    ),
    (
        "erasure_pitch_gain_limit",
        s("g729AnnexA/c_code/DEC_GAIN.C", DEC_GAIN, 61, 0),
    ),
    (
        "erasure_fixed_gain_attenuation",
        s("g729AnnexA/c_code/DEC_GAIN.C", DEC_GAIN, 62, 0),
    ),
    (
        "erasure_gain_memory_offset",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 150, 0),
    ),
    (
        "erasure_gain_memory_floor",
        s("g729AnnexA/c_code/GAINPRED.C", GAINPRED, 152, 0),
    ),
    (
        "random_multiplier",
        s("g729AnnexA/c_code/UTIL.C", UTIL, 60, 0),
    ),
    (
        "random_increment",
        s("g729AnnexA/c_code/UTIL.C", UTIL, 60, 0),
    ),
    (
        "erasure_random_seed_initial",
        s("g729AnnexA/c_code/UTIL.C", UTIL, 57, 0),
    ),
    (
        "lsf_to_lsp_frequency_scale",
        s("g729AnnexA/c_code/LPCFUNC.C", LPCFUNC, 199, 0),
    ),
    ("lsf_expansion_gap_1", s(LD8A, LD8A_H, 311, 0)),
    ("lsf_expansion_gap_2", s(LD8A, LD8A_H, 312, 0)),
    ("lsf_stability_low_limit", s(LD8A, LD8A_H, 308, 0)),
    ("lsf_stability_high_limit", s(LD8A, LD8A_H, 309, 0)),
    ("lsf_stability_min_distance", s(LD8A, LD8A_H, 313, 0)),
    ("postfilter_numerator_weight", s(LD8A, LD8A_H, 557, 0)),
    ("postfilter_denominator_weight", s(LD8A, LD8A_H, 558, 0)),
    ("long_term_postfilter_gamma", s(LD8A, LD8A_H, 553, 0)),
    ("long_term_postfilter_unit_g0", s(LD8A, LD8A_H, 554, 0)),
    ("long_term_postfilter_unit_gl", s(LD8A, LD8A_H, 555, 0)),
    (
        "long_term_postfilter_search_half_range",
        s("g729AnnexA/c_code/POSTFILT.C", POSTFILT, 127, 0),
    ),
    ("tilt_compensation_factor", s(LD8A, LD8A_H, 560, 0)),
    ("tilt_impulse_response_length", s(LD8A, LD8A_H, 551, 0)),
    ("agc_factor", s(LD8A, LD8A_H, 561, 0)),
    ("agc_factor_complement", s(LD8A, LD8A_H, 562, 0)),
    (
        "agc_initial_gain",
        s("g729AnnexA/c_code/POSTFILT.C", POSTFILT, 389, 0),
    ),
    ("serial_sync_word", s(LD8A, LD8A_H, 543, 0)),
    ("serial_bit_zero", s(LD8A, LD8A_H, 541, 0)),
    ("serial_bit_one", s(LD8A, LD8A_H, 542, 0)),
    ("serial_size_speech", s(DTX, DTX_H, 91, 0)),
    (
        "serial_size_sid",
        s("g729AnnexB/c_codeBA/octet.h", OCTET_H, 18, 0),
    ),
    ("serial_size_no_transmission", s(DTX, DTX_H, 93, 0)),
    ("cng_random_seed_initial", s(DTX, DTX_H, 78, 0)),
    ("cng_gain_smoothing_old", s(DTX, DTX_H, 85, 0)),
    ("cng_gain_smoothing_new", s(DTX, DTX_H, 89, 0)),
    ("cng_gaussian_scale_fraction", s(DTX, DTX_H, 97, 0)),
    ("cng_k0", s(DTX, DTX_H, 98, 0)),
    ("cng_fixed_gain_limit", s(DTX, DTX_H, 99, 0)),
    (
        "cng_pitch_delay_min",
        s("g729AnnexB/c_codeBA/calcexc.c", CALCEXC, 80, 1),
    ),
    (
        "cng_adaptive_gain_mask",
        s("g729AnnexB/c_codeBA/calcexc.c", CALCEXC, 106, 0),
    ),
    (
        "sid_lsf_min_distance",
        s("g729AnnexB/c_codeBA/dec_sid.c", DEC_SID, 170, 0),
    ),
    ("sid_energy_q_low_threshold", s(QSG, QSIDGAIN, 107, 0)),
    ("sid_energy_q_high_threshold", s(QSG, QSIDGAIN, 113, 0)),
    ("sid_energy_q_knee", s(QSG, QSIDGAIN, 119, 0)),
    ("sid_energy_q_low_offset", s(QSG, QSIDGAIN, 121, 0)),
    ("sid_energy_q_low_step", s(QSG, QSIDGAIN, 122, 0)),
    ("sid_energy_q_high_offset", s(QSG, QSIDGAIN, 128, 0)),
    ("sid_energy_q_high_step", s(QSG, QSIDGAIN, 129, 0)),
];

/// The locator of a named entry: where the importer reads it in the ITU-T
/// package. `None` for a name that is not in [`SOURCES`].
///
/// # Panics
///
/// Does not panic.
///
/// # Examples
///
/// ```
/// use g729::tables::{ENTRIES, source};
///
/// assert!(ENTRIES.iter().filter(|e| e.name != "sid_lsf_ma_predictor").all(|e| source(e.name).is_some()));
/// assert!(source("no such entry").is_none());
/// ```
pub fn source(name: &str) -> Option<&'static Source> {
    SOURCES.iter().find(|(n, _)| *n == name).map(|(_, s)| s)
}

/// One entry of the table file.
#[derive(Debug, Clone, Copy)]
pub struct Entry {
    /// The oracle's name for it.
    pub name: &'static str,
    /// Number of values.
    pub len: usize,
}

const fn e(name: &'static str, len: usize) -> Entry {
    Entry { name, len }
}

/// The user-supplied entries, in table-file order.
pub const ENTRIES: [Entry; 44] = [
    e("lsp_codebook_stage1", 1280),
    e("lsp_codebook_stage2", 320),
    e("lsp_ma_predictor", 80),
    e("lsp_ma_predictor_complement", 20),
    e("lsp_ma_predictor_complement_inverse", 20),
    e("adaptive_codebook_interpolation_filter", 31),
    e("gain_codebook_ga", 16),
    e("gain_codebook_gb", 32),
    e("gain_index_map_ga", 8),
    e("gain_index_map_gb", 16),
    e("log2_table", 33),
    e("decoder_initial_previous_lsp", 10),
    e("sid_lsf_ma_predictor", 80),
    e("sid_lsf_ma_predictor_complement", 20),
    e("sid_lsf_stage1_subset", 32),
    e("sid_lsf_stage2_subset", 32),
    e("sid_energy_scale", 3),
    e("sid_initial_lsp", 10),
    e("pitch_sharpening_max", 1),
    e("initial_previous_pitch_delay", 1),
    e("fixed_codebook_pulse_positive", 1),
    e("gain_prediction_log_scale", 1),
    e("gain_prediction_mean_energy_mantissa", 1),
    e("gain_prediction_mean_energy_multiplier", 1),
    e("gain_prediction_db_to_log2", 1),
    e("gain_update_log2_to_db", 1),
    e("erasure_pitch_gain_limit", 1),
    e("erasure_fixed_gain_attenuation", 1),
    e("lsf_to_lsp_frequency_scale", 1),
    e("lsf_stability_low_limit", 1),
    e("lsf_stability_high_limit", 1),
    e("lsf_stability_min_distance", 1),
    e("cng_random_seed_initial", 1),
    e("cng_gaussian_scale_fraction", 1),
    e("cng_k0", 1),
    e("cng_fixed_gain_limit", 1),
    e("cng_adaptive_gain_mask", 1),
    e("sid_energy_q_low_threshold", 1),
    e("sid_energy_q_high_threshold", 1),
    e("sid_energy_q_knee", 1),
    e("sid_energy_q_low_offset", 1),
    e("sid_energy_q_low_step", 1),
    e("sid_energy_q_high_offset", 1),
    e("sid_energy_q_high_step", 1),
];

/// Index of the first scalar in [`ENTRIES`].
const FIRST_SCALAR: usize = 18;
/// Number of user-supplied scalars.
pub const SCALARS: usize = ENTRIES.len() - FIRST_SCALAR;
/// Total number of user-supplied values.
pub const VALUE_COUNT: usize = {
    let mut n = 0;
    let mut i = 0;
    while i < ENTRIES.len() {
        n += ENTRIES[i].len;
        i += 1;
    }
    n
};

/// Index of each user-supplied scalar in [`Tables`]'s scalar array.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum Scalar {
    /// Upper bound of the pitch-sharpening factor, Q14.
    PitchSharpeningMax,
    /// Integer pitch delay assumed before the first frame.
    InitialPreviousPitchDelay,
    /// Amplitude of a positive fixed-codebook pulse, Q13.
    FixedCodebookPulsePositive,
    /// Gain prediction: base-2 log to dB scale, Q13.
    GainPredictionLogScale,
    /// Gain prediction: mean energy, mantissa.
    GainPredictionMeanEnergyMantissa,
    /// Gain prediction: mean energy, multiplier.
    GainPredictionMeanEnergyMultiplier,
    /// Gain prediction: dB to base-2 exponent, Q15.
    GainPredictionDbToLog2,
    /// Gain-predictor update: base-2 log to dB, Q12.
    GainUpdateLog2ToDb,
    /// Erasure: upper limit of the attenuated pitch gain.
    ErasurePitchGainLimit,
    /// Erasure: fixed-codebook gain attenuation, Q15.
    ErasureFixedGainAttenuation,
    /// LSF to LSP: radians to table index scale, Q17.
    LsfToLspFrequencyScale,
    /// LSF stability: lowest first LSF, Q13.
    LsfStabilityLowLimit,
    /// LSF stability: highest last LSF, Q13.
    LsfStabilityHighLimit,
    /// LSF stability: minimum distance, Q13.
    LsfStabilityMinDistance,
    /// Comfort noise: initial generator seed.
    CngRandomSeedInitial,
    /// Comfort noise: Gaussian excitation scale fraction, Q15.
    CngGaussianScaleFraction,
    /// Comfort noise: K0, Q15.
    CngK0,
    /// Comfort noise: fixed gain magnitude limit.
    CngFixedGainLimit,
    /// Comfort noise: adaptive gain mask.
    CngAdaptiveGainMask,
    /// SID energy quantizer: low threshold.
    SidEnergyQLowThreshold,
    /// SID energy quantizer: high threshold.
    SidEnergyQHighThreshold,
    /// SID energy quantizer: knee.
    SidEnergyQKnee,
    /// SID energy quantizer: low-region offset.
    SidEnergyQLowOffset,
    /// SID energy quantizer: low-region step.
    SidEnergyQLowStep,
    /// SID energy quantizer: high-region offset.
    SidEnergyQHighOffset,
    /// SID energy quantizer: high-region step.
    SidEnergyQHighStep,
}

/// The user-supplied tables and scalars.
///
/// Built only by a loader (`Tables::from_bytes`, feature `std`), from a table
/// file whose values hash to [`VALUES_SHA256`].
#[derive(Clone, PartialEq, Eq)]
pub struct Tables {
    pub(crate) lsp_cb1: [[i16; 10]; 128],
    pub(crate) lsp_cb2: [[i16; 10]; 32],
    pub(crate) lsp_ma: [[[i16; 10]; 4]; 2],
    pub(crate) lsp_ma_sum: [[i16; 10]; 2],
    pub(crate) lsp_ma_sum_inv: [[i16; 10]; 2],
    pub(crate) b30: [i16; 31],
    pub(crate) gain_ga: [[i16; 2]; 8],
    pub(crate) gain_gb: [[i16; 2]; 16],
    pub(crate) map_ga: [i16; 8],
    pub(crate) map_gb: [i16; 16],
    pub(crate) log2: [i16; 33],
    pub(crate) initial_lsp: [i16; 10],
    pub(crate) sid_ma: [[[i16; 10]; 4]; 2],
    pub(crate) sid_ma_sum: [[i16; 10]; 2],
    pub(crate) sid_cb1_subset: [i16; 32],
    pub(crate) sid_cb2_subset: [[i16; 16]; 2],
    pub(crate) sid_energy_scale: [i16; 3],
    pub(crate) sid_initial_lsp: [i16; 10],
    pub(crate) scalars: [i16; SCALARS],
}

impl core::fmt::Debug for Tables {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the values.
        f.write_str("Tables { .. }")
    }
}

impl Tables {
    #[cfg(any(feature = "std", fuzzing))]
    const fn zeroed() -> Self {
        Tables {
            lsp_cb1: [[0; 10]; 128],
            lsp_cb2: [[0; 10]; 32],
            lsp_ma: [[[0; 10]; 4]; 2],
            lsp_ma_sum: [[0; 10]; 2],
            lsp_ma_sum_inv: [[0; 10]; 2],
            b30: [0; 31],
            gain_ga: [[0; 2]; 8],
            gain_gb: [[0; 2]; 16],
            map_ga: [0; 8],
            map_gb: [0; 16],
            log2: [0; 33],
            initial_lsp: [0; 10],
            sid_ma: [[[0; 10]; 4]; 2],
            sid_ma_sum: [[0; 10]; 2],
            sid_cb1_subset: [0; 32],
            sid_cb2_subset: [[0; 16]; 2],
            sid_energy_scale: [0; 3],
            sid_initial_lsp: [0; 10],
            scalars: [0; SCALARS],
        }
    }

    #[cfg(any(feature = "std", fuzzing))]
    fn slices_mut(&mut self) -> [&mut [i16]; FIRST_SCALAR + 1] {
        [
            self.lsp_cb1.as_flattened_mut(),
            self.lsp_cb2.as_flattened_mut(),
            self.lsp_ma.as_flattened_mut().as_flattened_mut(),
            self.lsp_ma_sum.as_flattened_mut(),
            self.lsp_ma_sum_inv.as_flattened_mut(),
            &mut self.b30,
            self.gain_ga.as_flattened_mut(),
            self.gain_gb.as_flattened_mut(),
            &mut self.map_ga,
            &mut self.map_gb,
            &mut self.log2,
            &mut self.initial_lsp,
            self.sid_ma.as_flattened_mut().as_flattened_mut(),
            self.sid_ma_sum.as_flattened_mut(),
            &mut self.sid_cb1_subset,
            self.sid_cb2_subset.as_flattened_mut(),
            &mut self.sid_energy_scale,
            &mut self.sid_initial_lsp,
            &mut self.scalars,
        ]
    }

    fn slices(&self) -> [&[i16]; FIRST_SCALAR + 1] {
        [
            self.lsp_cb1.as_flattened(),
            self.lsp_cb2.as_flattened(),
            self.lsp_ma.as_flattened().as_flattened(),
            self.lsp_ma_sum.as_flattened(),
            self.lsp_ma_sum_inv.as_flattened(),
            &self.b30,
            self.gain_ga.as_flattened(),
            self.gain_gb.as_flattened(),
            &self.map_ga,
            &self.map_gb,
            &self.log2,
            &self.initial_lsp,
            self.sid_ma.as_flattened().as_flattened(),
            self.sid_ma_sum.as_flattened(),
            &self.sid_cb1_subset,
            self.sid_cb2_subset.as_flattened(),
            &self.sid_energy_scale,
            &self.sid_initial_lsp,
            &self.scalars,
        ]
    }

    /// Build from all [`VALUE_COUNT`] values in file order. Only the loader
    /// calls this, after checking the layout and the values hash.
    #[cfg(any(feature = "std", fuzzing))]
    pub(crate) fn from_values(values: &[i16]) -> Option<Self> {
        if values.len() != VALUE_COUNT {
            return None;
        }
        let mut t = Self::zeroed();
        let mut at = 0;
        for slot in t.slices_mut() {
            let n = slot.len();
            slot.copy_from_slice(&values[at..at + n]);
            at += n;
        }
        Some(t)
    }

    /// Tables from arbitrary values in file order, WITHOUT the values-hash
    /// check: only in a cargo-fuzz build (`cfg(fuzzing)`). `None` when the
    /// count is not [`VALUE_COUNT`].
    ///
    /// # Panics
    ///
    /// Does not panic.
    #[cfg(fuzzing)]
    pub fn from_values_unverified(values: &[i16]) -> Option<Self> {
        Self::from_values(values)
    }

    /// Visit every value in file order.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn for_each_value(&self, mut f: impl FnMut(i16)) {
        for slot in self.slices() {
            slot.iter().for_each(|&v| f(v));
        }
    }

    /// Visit every entry of [`ENTRIES`] with its values.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn for_each_entry(&self, mut f: impl FnMut(&Entry, &[i16])) {
        let slots = self.slices();
        for (i, entry) in ENTRIES.iter().enumerate() {
            if i < FIRST_SCALAR {
                f(entry, slots[i]);
            } else {
                let k = i - FIRST_SCALAR;
                f(entry, &slots[FIRST_SCALAR][k..k + 1]);
            }
        }
    }

    /// A user-supplied scalar.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn scalar(&self, s: Scalar) -> i16 {
        self.scalars[s as usize]
    }

    /// The LSP vector assumed for the frame before the first (clause 3.2.5).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn decoder_initial_previous_lsp(&self) -> [i16; 10] {
        self.initial_lsp
    }

    /// The base-2 logarithm lookup, log2(1 + i/32) in Q15 (clause 3.9.1).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn log2_table(&self) -> &[i16; 33] {
        &self.log2
    }

    /// The comfort-noise LSP vector before any SID frame (clause B.4.4).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn sid_initial_lsp_for_tests(&self) -> [i16; 10] {
        self.sid_initial_lsp
    }

    /// The switched MA predictors of the LSF quantizer (clause 3.2.4).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn lsp_ma_predictor(&self) -> &[[[i16; 10]; 4]; 2] {
        &self.lsp_ma
    }

    /// The SID LSF MA predictors (clause B.4.2.2, equation (B.18)).
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn sid_lsf_ma_predictor(&self) -> &[[[i16; 10]; 4]; 2] {
        &self.sid_ma
    }
}

/// Equation (B.18): the second SID predictor, 0.6 p1 + 0.4 p2, with 0.6 and
/// 0.4 truncated to Q15 (clause 2.5: "int denotes truncation") and the sum
/// truncated back to Q15.
///
/// # Panics
///
/// Does not panic: each sum is at most 32768 x 32767 in magnitude, which fits
/// an `i32`.
///
/// # Examples
///
/// ```
/// use g729::tables::b18_mix;
///
/// // 0.6 x 1000 + 0.4 x 1000, with both weights truncated to Q15.
/// let mixed = b18_mix(&[[1000; 10]; 4], &[[1000; 10]; 4]);
/// assert_eq!(mixed, [[999; 10]; 4]);
/// ```
pub fn b18_mix(p1: &[[i16; 10]; 4], p2: &[[i16; 10]; 4]) -> [[i16; 10]; 4] {
    // 0.6 and 0.4 in Q15, truncated.
    const SIX_TENTHS: i32 = 19660;
    const FOUR_TENTHS: i32 = 13107;
    let mut out = [[0i16; 10]; 4];
    for k in 0..4 {
        for i in 0..10 {
            let acc = i32::from(p1[k][i]) * SIX_TENTHS + i32::from(p2[k][i]) * FOUR_TENTHS;
            out[k][i] = (acc >> 15) as i16;
        }
    }
    out
}

/// Tables computed from the formulas of the Recommendation.
pub mod formula {
    const PI: f64 = core::f64::consts::PI;

    const fn round(x: f64) -> i64 {
        if x >= 0.0 {
            (x + 0.5) as i64
        } else {
            -((-x + 0.5) as i64)
        }
    }

    const fn floor(x: f64) -> i64 {
        let t = x as i64;
        if (t as f64) > x { t - 1 } else { t }
    }

    const fn sat16(x: i64) -> i16 {
        if x > i16::MAX as i64 {
            i16::MAX
        } else if x < i16::MIN as i64 {
            i16::MIN
        } else {
            x as i16
        }
    }

    /// cos(x) for 0 <= x <= pi, by its Taylor series.
    const fn cos(x: f64) -> f64 {
        let x2 = x * x;
        let mut term = 1.0;
        let mut sum = 1.0;
        let mut k = 1;
        while k < 40 {
            term = -term * x2 / (((2 * k - 1) * (2 * k)) as f64);
            sum += term;
            k += 1;
        }
        sum
    }

    /// e^x for |x| < 10, by its Taylor series.
    const fn exp(x: f64) -> f64 {
        let mut term = 1.0;
        let mut sum = 1.0;
        let mut k = 1;
        while k < 120 {
            term = term * x / (k as f64);
            sum += term;
            k += 1;
        }
        sum
    }

    /// sqrt(x) for x > 0, by Newton's iteration.
    const fn sqrt(x: f64) -> f64 {
        let mut y = if x > 1.0 { x } else { 1.0 };
        let mut i = 0;
        while i < 100 {
            y = 0.5 * (y + x / y);
            i += 1;
        }
        y
    }

    const fn cosine() -> [i16; 64] {
        let mut out = [0; 64];
        let mut i = 0;
        while i < 64 {
            out[i] = sat16(round(32768.0 * cos(i as f64 * PI / 64.0)));
            i += 1;
        }
        out
    }

    const fn cosine_slope() -> [i16; 64] {
        let mut out = [0; 64];
        let mut i = 0;
        while i < 64 {
            let d = cos((i + 1) as f64 * PI / 64.0) - cos(i as f64 * PI / 64.0);
            out[i] = sat16(round(524288.0 * d));
            i += 1;
        }
        out
    }

    const fn powers_of_two() -> [i16; 33] {
        let mut out = [0; 33];
        let mut i = 0;
        while i < 33 {
            out[i] = sat16(round(
                16384.0 * exp(i as f64 / 32.0 * core::f64::consts::LN_2),
            ));
            i += 1;
        }
        out
    }

    const fn inverse_sqrt() -> [i16; 49] {
        let mut out = [0; 49];
        let mut i = 0;
        while i < 49 {
            out[i] = sat16(round(32768.0 / sqrt(1.0 + i as f64 / 16.0)));
            i += 1;
        }
        out
    }

    const fn q(x: f64, bits: i32) -> i16 {
        sat16(round(x * (1i64 << bits) as f64))
    }

    const fn lsp_quantizer_initial_memory() -> [i16; 10] {
        let mut out = [0; 10];
        let mut i = 0;
        while i < 10 {
            out[i] = sat16(floor(8192.0 * (i + 1) as f64 * PI / 11.0));
            i += 1;
        }
        out
    }

    const fn sid_gain() -> [i16; 32] {
        // Clause B.4.2.1: one level at -12 dB, 4 dB steps from -4 to 16 dB,
        // 2 dB steps from 18 to 66 dB; the gain is 10^(E/20), held in Q3.
        let mut out = [0; 32];
        let mut i = 0;
        while i < 32 {
            let db = if i == 0 {
                -12.0
            } else if i <= 6 {
                -4.0 + 4.0 * (i - 1) as f64
            } else {
                18.0 + 2.0 * (i - 7) as f64
            };
            out[i] = sat16(round(8.0 * exp(db / 20.0 * core::f64::consts::LN_10)));
            i += 1;
        }
        out
    }

    /// cos(i*pi/64), i = 0..63, Q15 (clauses 3.2.6 and 4.1.1).
    pub const LSP_COSINE: [i16; 64] = cosine();
    /// Slope between consecutive [`LSP_COSINE`] points of the exact cosine,
    /// Q19.
    pub const LSP_COSINE_SLOPE: [i16; 64] = cosine_slope();
    /// 2^(i/32), i = 0..32, Q14 (clause 3.9.1, equation (71)).
    pub const POW2: [i16; 33] = powers_of_two();
    /// 1/sqrt(1 + i/16), i = 0..48, Q15 (clause 4.2.4).
    pub const INVERSE_SQRT: [i16; 49] = inverse_sqrt();
    /// b1..b4 of equation (69), Q13.
    pub const GAIN_PREDICTION_COEFFICIENTS: [i16; 4] =
        [q(0.68, 13), q(0.58, 13), q(0.34, 13), q(0.19, 13)];
    /// Numerator of equation (91), Q13.
    pub const HIGHPASS_NUMERATOR: [i16; 3] =
        [q(0.93980581, 13), q(-1.8795834, 13), q(0.93980581, 13)];
    /// Denominator of equation (91), Q13: 1.0, then the feedback weights as
    /// added in the recursion y(n) = ... + 1.9330735 y(n-1) - 0.93589199 y(n-2).
    pub const HIGHPASS_DENOMINATOR: [i16; 3] = [q(1.0, 13), q(1.9330735, 13), q(-0.93589199, 13)];
    /// i*pi/11, i = 1..10, Q13 truncated (clause 3.2.4, Table 9).
    pub const LSP_QUANTIZER_INITIAL_MEMORY: [i16; 10] = lsp_quantizer_initial_memory();
    /// -14 dB in Q10 (Table 9).
    pub const GAIN_PREDICTOR_INITIAL_MEMORY: [i16; 4] = [-14 * 1024; 4];
    /// SID gain per energy index, Q3 (clause B.4.2.1).
    pub const SID_GAIN: [i16; 32] = sid_gain();
    /// Field widths of an active frame in transmission order (Table 8).
    pub const SPEECH_FRAME_BIT_ALLOCATION: [i16; 11] =
        [1 + 7, 5 + 5, 8, 1, 13, 4, 3 + 4, 5, 13, 4, 3 + 4];
    /// Field widths of a SID frame in transmission order (Table B.2).
    pub const SID_FRAME_BIT_ALLOCATION: [i16; 4] = [1, 5, 4, 5];
}

/// Scalar constants stated by the Recommendation, and the serial format words.
pub mod text {
    /// beta lower bound 0.2, Q14 (clause 3.8, equation (47)).
    pub const PITCH_SHARPENING_MIN: i16 = 3277;
    /// Minimum integer pitch delay (clause 3.7).
    pub const PITCH_DELAY_MIN: i16 = 20;
    /// Maximum integer pitch delay (clause 3.7).
    pub const PITCH_DELAY_MAX: i16 = 143;
    /// -1.0 in Q13, a negative pulse (clause 3.8).
    pub const FIXED_CODEBOOK_PULSE_NEGATIVE: i16 = -8192;
    /// 0.9 in Q15 (equation (94)).
    pub const ERASURE_PITCH_GAIN_ATTENUATION: i16 = 29491;
    /// 4 dB in Q10 (equation (95)).
    pub const ERASURE_GAIN_MEMORY_OFFSET: i16 = 4096;
    /// -14 dB in Q10 (equation (95)).
    pub const ERASURE_GAIN_MEMORY_FLOOR: i16 = -14336;
    /// Multiplier of equation (96).
    pub const RANDOM_MULTIPLIER: i16 = 31821;
    /// Increment of equation (96).
    pub const RANDOM_INCREMENT: i16 = 13849;
    /// Initial seed, clause 4.4.4.
    pub const ERASURE_RANDOM_SEED_INITIAL: i16 = 21845;
    /// J = 0.0012 in Q13 (clause 3.2.4).
    pub const LSF_EXPANSION_GAP_1: i16 = 10;
    /// J = 0.0006 in Q13 (clause 3.2.4).
    pub const LSF_EXPANSION_GAP_2: i16 = 5;
    /// gamma_n = 0.55, Q15 (clause A.4.2.2).
    pub const POSTFILTER_NUMERATOR_WEIGHT: i16 = 18022;
    /// gamma_d = 0.70, Q15 (clause A.4.2.2).
    pub const POSTFILTER_DENOMINATOR_WEIGHT: i16 = 22938;
    /// gamma_p = 0.5, Q15 (clause 4.2.1).
    pub const LONG_TERM_POSTFILTER_GAMMA: i16 = 16384;
    /// 1/(1 + gamma_p), Q15 (equation (A.11) with g = 1).
    pub const LONG_TERM_POSTFILTER_UNIT_G0: i16 = 21845;
    /// gamma_p/(1 + gamma_p), Q15 (equation (A.11) with g = 1).
    pub const LONG_TERM_POSTFILTER_UNIT_GL: i16 = 10923;
    /// Delay search half-range (clause A.4.2.1).
    pub const LONG_TERM_POSTFILTER_SEARCH_HALF_RANGE: i16 = 3;
    /// gamma_t = 0.8, Q15 (clause A.4.2.3).
    pub const TILT_COMPENSATION_FACTOR: i16 = 26214;
    /// Impulse-response length of equation (A.14).
    pub const TILT_IMPULSE_RESPONSE_LENGTH: i16 = 22;
    /// alpha = 0.9, Q15 (clause A.4.2.4).
    pub const AGC_FACTOR: i16 = 29491;
    /// 1 - alpha with 1.0 saturated to 32767, Q15 (clause A.4.2.4).
    pub const AGC_FACTOR_COMPLEMENT: i16 = i16::MAX - AGC_FACTOR;
    /// g(-1) = 1.0, Q12 (clause 4.2.4).
    pub const AGC_INITIAL_GAIN: i16 = 4096;
    /// Serial format: synchronization word of a frame.
    pub const SERIAL_SYNC_WORD: i16 = 0x6B21;
    /// Serial format: a 0 bit.
    pub const SERIAL_BIT_ZERO: i16 = 0x007F;
    /// Serial format: a 1 bit.
    pub const SERIAL_BIT_ONE: i16 = 0x0081;
    /// Serial format: size word of an active frame (80 bits, Table 1).
    pub const SERIAL_SIZE_SPEECH: i16 = 80;
    /// Serial format: size word of a SID frame (15 bits and a pad bit).
    pub const SERIAL_SIZE_SID: i16 = 16;
    /// Serial format: size word of an untransmitted frame.
    pub const SERIAL_SIZE_NO_TRANSMISSION: i16 = 0;
    /// 7/8, Q15 (equation (B.19)).
    pub const CNG_GAIN_SMOOTHING_OLD: i16 = 28672;
    /// 1/8, Q15 (equation (B.19)).
    pub const CNG_GAIN_SMOOTHING_NEW: i16 = 4096;
    /// Smallest comfort-noise pitch lag (clause B.4.4).
    pub const CNG_PITCH_DELAY_MIN: i16 = 40;
    /// J = 0.0012 in Q13, applied to the SID LSF (clause B.4.2.2).
    pub const SID_LSF_MIN_DISTANCE: i16 = 10;

    /// Every constant of this module by the oracle's name.
    pub const ALL: &[(&str, i16)] = &[
        ("pitch_sharpening_min", PITCH_SHARPENING_MIN),
        ("pitch_delay_min", PITCH_DELAY_MIN),
        ("pitch_delay_max", PITCH_DELAY_MAX),
        (
            "fixed_codebook_pulse_negative",
            FIXED_CODEBOOK_PULSE_NEGATIVE,
        ),
        (
            "erasure_pitch_gain_attenuation",
            ERASURE_PITCH_GAIN_ATTENUATION,
        ),
        ("erasure_gain_memory_offset", ERASURE_GAIN_MEMORY_OFFSET),
        ("erasure_gain_memory_floor", ERASURE_GAIN_MEMORY_FLOOR),
        ("random_multiplier", RANDOM_MULTIPLIER),
        ("random_increment", RANDOM_INCREMENT),
        ("erasure_random_seed_initial", ERASURE_RANDOM_SEED_INITIAL),
        ("lsf_expansion_gap_1", LSF_EXPANSION_GAP_1),
        ("lsf_expansion_gap_2", LSF_EXPANSION_GAP_2),
        ("postfilter_numerator_weight", POSTFILTER_NUMERATOR_WEIGHT),
        (
            "postfilter_denominator_weight",
            POSTFILTER_DENOMINATOR_WEIGHT,
        ),
        ("long_term_postfilter_gamma", LONG_TERM_POSTFILTER_GAMMA),
        ("long_term_postfilter_unit_g0", LONG_TERM_POSTFILTER_UNIT_G0),
        ("long_term_postfilter_unit_gl", LONG_TERM_POSTFILTER_UNIT_GL),
        (
            "long_term_postfilter_search_half_range",
            LONG_TERM_POSTFILTER_SEARCH_HALF_RANGE,
        ),
        ("tilt_compensation_factor", TILT_COMPENSATION_FACTOR),
        ("tilt_impulse_response_length", TILT_IMPULSE_RESPONSE_LENGTH),
        ("agc_factor", AGC_FACTOR),
        ("agc_factor_complement", AGC_FACTOR_COMPLEMENT),
        ("agc_initial_gain", AGC_INITIAL_GAIN),
        ("serial_sync_word", SERIAL_SYNC_WORD),
        ("serial_bit_zero", SERIAL_BIT_ZERO),
        ("serial_bit_one", SERIAL_BIT_ONE),
        ("serial_size_speech", SERIAL_SIZE_SPEECH),
        ("serial_size_sid", SERIAL_SIZE_SID),
        ("serial_size_no_transmission", SERIAL_SIZE_NO_TRANSMISSION),
        ("cng_gain_smoothing_old", CNG_GAIN_SMOOTHING_OLD),
        ("cng_gain_smoothing_new", CNG_GAIN_SMOOTHING_NEW),
        ("cng_pitch_delay_min", CNG_PITCH_DELAY_MIN),
        ("sid_lsf_min_distance", SID_LSF_MIN_DISTANCE),
    ];

    /// Which integer literal of the reference line holds the named constant:
    /// the position [`source`](super::source) records, or 0 when it records
    /// none.
    ///
    /// # Panics
    ///
    /// Does not panic.
    pub fn reference_token(name: &str) -> usize {
        super::source(name).and_then(|s| s.token).unwrap_or(0)
    }
}
