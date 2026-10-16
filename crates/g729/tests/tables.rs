// SPDX-License-Identifier: MIT OR Apache-2.0

//! The table file, its loader and its importer (spec item U1, U2).
//!
//! The trained codebooks and the other ITU-derived values reach the decoder
//! only through `Tables::from_bytes`, fed by `import_from_itu`. These tests run
//! the real import path on the fetched ITU sources, prove the loader refuses
//! anything but the pinned values, and prove that every table the crate
//! computes from a formula, and every constant it takes from the text, equals
//! the value in the ITU reference sources.

pub mod common;

use g729::tables::{self, Class, formula, text};
use g729::{TableError, Tables, import};

#[test]
fn the_imported_file_loads_and_carries_the_pinned_values() -> common::TestResult {
    let file = common::table_file()?;
    assert_eq!(&file[..8], tables::FILE_MAGIC);
    assert_eq!(u16::from_le_bytes([file[8], file[9]]), tables::FILE_VERSION);
    let t = Tables::from_bytes(file)?;
    assert_eq!(t.values_sha256_hex(), tables::VALUES_SHA256);
    Ok(())
}

#[test]
fn the_loader_refuses_a_wrong_magic_version_length_or_value() -> common::TestResult {
    let good = common::table_file()?.to_vec();

    let mut bad = good.clone();
    bad[0] ^= 1;
    assert_eq!(Tables::from_bytes(&bad).unwrap_err(), TableError::Magic);

    let mut bad = good.clone();
    bad[8] = bad[8].wrapping_add(1);
    assert!(matches!(
        Tables::from_bytes(&bad).unwrap_err(),
        TableError::Version(_)
    ));

    assert!(matches!(
        Tables::from_bytes(&good[..good.len() - 1]).unwrap_err(),
        TableError::Length { .. }
    ));
    let mut longer = good.clone();
    longer.push(0);
    assert!(matches!(
        Tables::from_bytes(&longer).unwrap_err(),
        TableError::Length { .. }
    ));

    // One changed value: the layout is valid, the values hash is not.
    let mut bad = good.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert_eq!(
        Tables::from_bytes(&bad).unwrap_err(),
        TableError::ValuesHash
    );

    // A wrong entry length at the first entry header.
    let mut bad = good;
    bad[14] ^= 1;
    assert!(matches!(
        Tables::from_bytes(&bad).unwrap_err(),
        TableError::Entry { index: 0, .. }
    ));
    Ok(())
}

/// The 12-byte header of a table file: magic, version, entry count.
fn header(entries: u16) -> Vec<u8> {
    let mut file = tables::FILE_MAGIC.to_vec();
    file.extend_from_slice(&tables::FILE_VERSION.to_le_bytes());
    file.extend_from_slice(&entries.to_le_bytes());
    file
}

/// A header declaring another number of entries is refused as a wrong entry
/// count, and the message speaks of entries, not of an entry's values.
#[test]
fn the_loader_names_a_wrong_entry_count() -> common::TestResult {
    let expected = tables::ENTRIES.len();
    for declared in [0u16, 43, 45, u16::MAX] {
        let err = Tables::from_bytes(&header(declared))
            .err()
            .ok_or("a wrong entry count must be refused")?;
        assert_eq!(
            err,
            TableError::EntryCount {
                expected,
                actual: usize::from(declared)
            }
        );
        assert_eq!(
            err.to_string(),
            format!("table file declares {declared} entries, expected {expected}")
        );
    }
    Ok(())
}

/// An entry header carrying another entry's number is refused as a wrong
/// entry number, even when its value count is right.
#[test]
fn the_loader_names_a_misnumbered_entry() -> common::TestResult {
    let mut file = header(tables::ENTRIES.len() as u16);
    file.extend_from_slice(&1u16.to_le_bytes());
    file.extend_from_slice(&(tables::ENTRIES[0].len as u32).to_le_bytes());
    let err = Tables::from_bytes(&file)
        .err()
        .ok_or("a misnumbered entry must be refused")?;
    assert_eq!(
        err,
        TableError::EntryNumber {
            position: 0,
            actual: 1
        }
    );
    assert_eq!(
        err.to_string(),
        format!(
            "table file entry 0 ({}) is numbered 1",
            tables::ENTRIES[0].name
        )
    );
    Ok(())
}

#[test]
fn the_importer_reads_the_zip_as_well_as_the_directory() -> common::TestResult {
    use std::io::Write;
    let dir = common::source_dir()?;
    let tmp = std::env::temp_dir().join(format!("g729-import-zip-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let zip_path = tmp.join("package.zip");
    let build = || -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut zip = zip::ZipWriter::new(std::fs::File::create(&zip_path)?);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for entry in walk(&dir)? {
            let rel = entry
                .strip_prefix(&dir)?
                .to_string_lossy()
                .replace('\\', "/");
            zip.start_file(format!("Software/G729_Release3/{rel}"), opts)?;
            zip.write_all(&std::fs::read(&entry)?)?;
        }
        zip.finish()?;
        Ok(g729::import_from_itu(&zip_path)?)
    };
    let from_zip = build();
    std::fs::remove_dir_all(&tmp)?;
    assert_eq!(from_zip?, common::table_file()?);
    Ok(())
}

#[test]
fn the_importer_names_a_missing_source_file() -> common::TestResult {
    let dir = common::source_dir()?;
    let tmp = std::env::temp_dir().join(format!("g729-import-missing-{}", std::process::id()));
    std::fs::create_dir_all(&tmp)?;
    let mut skipped = None;
    let copy = |skipped: &mut Option<String>| -> std::io::Result<()> {
        for entry in walk(&dir)? {
            let name = entry
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == "tab_dtx.c" {
                *skipped = Some(name);
                continue;
            }
            std::fs::copy(&entry, tmp.join(&name))?;
        }
        Ok(())
    };
    let copied = copy(&mut skipped);
    let result = g729::import_from_itu(&tmp);
    std::fs::remove_dir_all(&tmp)?;
    copied?;
    assert_eq!(skipped.as_deref(), Some("tab_dtx.c"));
    let err = result
        .expect_err("an incomplete source set must be refused")
        .to_string();
    assert!(err.contains("tab_dtx.c"), "{err}");
    Ok(())
}

fn walk(dir: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            out.extend(walk(&path)?);
        } else {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn reference(name: &str) -> Result<Vec<i32>, String> {
    import::reference_values(&common::source_dir()?, name)
        .map_err(|e| format!("reference values of {name}: {e}"))
}

fn widen(v: &[i16]) -> Vec<i32> {
    v.iter().map(|&x| i32::from(x)).collect()
}

#[test]
fn every_formula_table_equals_the_reference() -> common::TestResult {
    let cases: [(&str, &[i16]); 11] = [
        ("lsp_cosine_table", &formula::LSP_COSINE),
        ("lsp_cosine_slope_table", &formula::LSP_COSINE_SLOPE),
        ("pow2_table", &formula::POW2),
        ("inverse_sqrt_table", &formula::INVERSE_SQRT),
        (
            "gain_prediction_coefficients",
            &formula::GAIN_PREDICTION_COEFFICIENTS,
        ),
        (
            "highpass_postprocessing_numerator",
            &formula::HIGHPASS_NUMERATOR,
        ),
        (
            "highpass_postprocessing_denominator",
            &formula::HIGHPASS_DENOMINATOR,
        ),
        (
            "lsp_quantizer_initial_memory",
            &formula::LSP_QUANTIZER_INITIAL_MEMORY,
        ),
        (
            "gain_predictor_initial_memory",
            &formula::GAIN_PREDICTOR_INITIAL_MEMORY,
        ),
        ("sid_gain_table", &formula::SID_GAIN),
        (
            "sid_frame_bit_allocation",
            &formula::SID_FRAME_BIT_ALLOCATION,
        ),
    ];
    for (name, ours) in cases {
        assert_eq!(widen(ours), reference(name)?, "{name}");
    }
    Ok(())
}

#[test]
fn the_speech_frame_bit_allocation_is_table_8() -> common::TestResult {
    // Table 8 lists L0..GB2; the 11 serial fields join L0+L1, L2+L3 and
    // GA+GB. The reference writes these widths as sums, which the
    // integer-only importer does not evaluate, so the check is against the
    // Recommendation's own table.
    let table8 = [1 + 7, 5 + 5, 8, 1, 13, 4, 3 + 4, 5, 13, 4, 3 + 4];
    assert_eq!(formula::SPEECH_FRAME_BIT_ALLOCATION, table8);
    assert_eq!(formula::SPEECH_FRAME_BIT_ALLOCATION.iter().sum::<i16>(), 80);
    Ok(())
}

#[test]
fn every_text_constant_equals_the_reference() -> common::TestResult {
    for &(name, value) in text::ALL {
        let reference = reference(name)?;
        let value = i32::from(value);
        match name {
            // eq. (96) states the increment; the reference line holds it in a
            // form the integer-only importer does not read.
            "random_increment" => assert!(!reference.contains(&value), "{name}"),
            // 1 - alpha with 1.0 saturated to Q15: the reference line holds
            // the 32767 and names alpha.
            "agc_factor_complement" => {
                assert_eq!(reference[0] - i32::from(text::AGC_FACTOR), value)
            }
            _ => assert_eq!(
                reference[text::reference_token(name)],
                value,
                "{name}: ours {value}, reference tokens {reference:?}"
            ),
        }
    }
    Ok(())
}

#[test]
fn the_classification_covers_30_tables_and_59_scalars_once() -> common::TestResult {
    let mut names: Vec<&str> = tables::CLASSIFICATION.iter().map(|c| c.name).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "a name is classified twice");
    let tables_n = tables::CLASSIFICATION.iter().filter(|c| !c.scalar).count();
    assert_eq!((tables_n, total - tables_n), (30, 59));
    let user = tables::CLASSIFICATION
        .iter()
        .filter(|c| matches!(c.class, Class::UserSupplied | Class::ComputedAtImport))
        .count();
    assert_eq!(user, tables::ENTRIES.len());
    for c in tables::CLASSIFICATION {
        if matches!(c.class, Class::UserSupplied | Class::ComputedAtImport) {
            assert!(
                tables::ENTRIES.iter().any(|e| e.name == c.name),
                "{} not in the file",
                c.name
            );
        }
    }
    Ok(())
}

#[test]
fn the_b18_sid_predictor_is_computed_not_imported() -> common::TestResult {
    // Annex B equation (B.18): the second SID predictor is 0.6 p1 + 0.4 p2 of
    // the main LSF quantizer's two predictors; the first is p1 itself.
    let t = common::tables()?;
    let p = t.lsp_ma_predictor();
    let s = t.sid_lsf_ma_predictor();
    assert_eq!(s[0], p[0]);
    assert_eq!(s[1], tables::b18_mix(&p[0], &p[1]));
    Ok(())
}
