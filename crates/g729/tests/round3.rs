// SPDX-License-Identifier: MIT OR Apache-2.0

//! The oracle's round-3 streams (`.git/g729-reference/round3`): an erasure
//! after a top-of-range pitch delay (case A, 21 streams), an untransmitted
//! frame right after an active or concealed-active frame (case B, 31 streams,
//! plus the full SID-energy quantizer grid), and 10 general A+B streams of
//! 40,000 frames each. Every file's sha256 must match its manifest.
//!
//! Built only with the `g729_oracle` cfg flag
//! (`RUSTFLAGS='--cfg g729_oracle' cargo test -p g729 --test round3`), with or
//! without `--no-default-features`: case A compares the Annex A output when
//! Annex B is off and the A+B output when it is on. A missing file fails.
#![cfg(g729_oracle)]

pub mod common;

#[cfg(feature = "annex-b")]
use std::io::BufRead;
use std::path::PathBuf;

#[cfg(feature = "annex-b")]
use g729::basic_op::Ctx;
use sha2::{Digest, Sha256};

fn round3() -> PathBuf {
    common::trace::reference_dir().join("round3")
}

fn manifest(dir: &str) -> Result<serde_json::Value, String> {
    let path = round3().join(dir).join("manifest.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// A file of the stream, checked against the manifest's `key` sha256.
fn read_checked(
    dir: &str,
    file: &str,
    entry: &serde_json::Value,
    key: &str,
) -> Result<Vec<u8>, String> {
    let path = round3().join(dir).join(file);
    let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let digest: String = Sha256::digest(&data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    if Some(digest.as_str()) != entry[key].as_str() {
        return Err(format!("{file}: sha256 differs from the manifest"));
    }
    Ok(data)
}

/// Decode `<name>.bit` and compare it with `out_file`; collect a failure
/// line instead of stopping, so that every stream is reported.
fn check_stream(
    dir: &str,
    name: &str,
    out_file: &str,
    out_key: &str,
    failures: &mut Vec<String>,
) -> common::TestResult {
    let manifest = manifest(dir)?;
    let entry = &manifest[name];
    let input = read_checked(dir, &format!("{name}.bit"), entry, "bit_sha256")?;
    let expected = common::samples(&read_checked(dir, out_file, entry, out_key)?);
    let got = common::decode_g192(common::tables()?, &input, name)?;
    if let Err(e) = common::compare(name, &got, &expected) {
        failures.push(e);
    }
    Ok(())
}

fn all_pass(failures: Vec<String>) -> common::TestResult {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n").into())
    }
}

#[test]
fn case_a_erasure_after_a_top_of_range_delay() -> common::TestResult {
    let (out, key) = if cfg!(feature = "annex-b") {
        ("annex_ab.out", "annex_ab_out_sha256")
    } else {
        ("annex_a.out", "annex_a_out_sha256")
    };
    let mut failures = Vec::new();
    for n in 1..=21 {
        let name = format!("A{n:02}");
        check_stream(
            "case_a",
            &name,
            &format!("{name}.{out}"),
            key,
            &mut failures,
        )?;
    }
    all_pass(failures)
}

#[cfg(feature = "annex-b")]
#[test]
fn case_b_untransmitted_frame_after_an_active_frame() -> common::TestResult {
    let mut failures = Vec::new();
    let names = std::iter::once("B1".to_string()).chain((1..=30).map(|n| format!("B3_{n:02}")));
    for name in names {
        check_stream(
            "case_b",
            &name,
            &format!("{name}.out"),
            "out_sha256",
            &mut failures,
        )?;
    }
    all_pass(failures)
}

#[cfg(feature = "annex-b")]
#[test]
fn case_b_energy_quantizer_matches_the_full_grid() -> common::TestResult {
    let tables = common::tables()?;
    let path = round3()
        .join("case_b")
        .join("sid_energy_quantization_grid.jsonl.gz");
    let file = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut rows = 0usize;
    let mut differ = Vec::new();
    for line in std::io::BufReader::new(flate2::read::GzDecoder::new(file)).lines() {
        let row: [i64; 4] = serde_json::from_str(&line?)?;
        let [exponent, mantissa, index, _level] = row;
        let got = g729::cng::quantize_energy(
            &mut Ctx::default(),
            tables,
            (mantissa as i16, exponent as i16),
        );
        if i64::from(got) != index {
            differ.push((exponent, mantissa, index, got));
        }
        rows += 1;
    }
    if rows != 1_343_488 {
        return Err(format!("{rows} grid rows read, 1343488 expected").into());
    }
    if differ.is_empty() {
        return Ok(());
    }
    let shown: Vec<String> = differ.iter().take(8).map(|d| format!("{d:?}")).collect();
    Err(format!(
        "{} of {rows} rows differ; first (exponent, mantissa, expected, got): {}",
        differ.len(),
        shown.join(" ")
    )
    .into())
}

#[cfg(feature = "annex-b")]
#[test]
fn general_streams() -> common::TestResult {
    let mut failures = Vec::new();
    for n in 0..10 {
        let name = format!("G{n:02}");
        check_stream(
            "general",
            &name,
            &format!("{name}.out"),
            "out_sha256",
            &mut failures,
        )?;
    }
    all_pass(failures)
}
