// SPDX-License-Identifier: MIT OR Apache-2.0

//! Conformance: the 16 ITU-T decoder test vectors (spec fact F4), each
//! decoded from its G.192 bit stream and compared with the expected output
//! sample for sample. The tables come through the real import path
//! (`import_from_itu` from the fetched ITU sources). A missing vector fails
//! the test, naming the fetch command.

pub mod common;

fn conformance(index: usize) -> common::TestResult {
    let (bit, expected_path) = common::PAIRS[index];
    let got = common::decode_g192(common::tables()?, &common::read_vector(bit)?, bit)?;
    let expected = common::samples(&common::read_vector(expected_path)?);
    common::compare(&format!("{bit} -> {expected_path}"), &got, &expected)?;
    Ok(())
}

#[test]
fn annex_a_algthm() -> common::TestResult {
    conformance(0)
}
#[test]
fn annex_a_erasure() -> common::TestResult {
    conformance(1)
}
#[test]
fn annex_a_fixed() -> common::TestResult {
    conformance(2)
}
#[test]
fn annex_a_lsp() -> common::TestResult {
    conformance(3)
}
#[test]
fn annex_a_overflow() -> common::TestResult {
    conformance(4)
}
#[test]
fn annex_a_parity() -> common::TestResult {
    conformance(5)
}
#[test]
fn annex_a_pitch() -> common::TestResult {
    conformance(6)
}
#[test]
fn annex_a_speech() -> common::TestResult {
    conformance(7)
}
#[test]
fn annex_a_tame() -> common::TestResult {
    conformance(8)
}
#[test]
fn annex_a_test() -> common::TestResult {
    conformance(9)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq1a() -> common::TestResult {
    conformance(10)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq2a() -> common::TestResult {
    conformance(11)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq3a() -> common::TestResult {
    conformance(12)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq4a() -> common::TestResult {
    conformance(13)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq5() -> common::TestResult {
    conformance(14)
}
#[cfg(feature = "annex-b")]
#[test]
fn annex_b_tstseq6() -> common::TestResult {
    conformance(15)
}
