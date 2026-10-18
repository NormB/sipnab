// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Extra conformance: the oracle's 20 synthetic Annex A+B bit streams
//! (`.git/g729-reference/conformance/synthNN`), each decoded by the
//! unmodified reference. Between them they exercise 59 recoveries of a lost
//! first SID frame (clause B.4.5), every frame type erased, and long-term
//! postfilter subframes with a negative maximum correlation (clause A.4.2.1).
//!
//! Built only with the `g729_oracle` cfg flag (`RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`): the streams live only in the
//! main checkout's `.git`. Each file's sha256 must match the oracle's
//! manifest; a missing file fails.
//! The streams are A+B streams: the file is built only with the `annex-b`
//! feature.
#![cfg(all(g729_oracle, feature = "annex-b"))]

pub mod common;

use sha2::{Digest, Sha256};

fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn synthetic(n: usize) -> common::TestResult {
    let dir = common::trace::reference_dir().join("conformance");
    let name = format!("synth{n:02}");
    let manifest_path = dir.join("manifest.json");
    let manifest: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path)
            .map_err(|e| format!("{}: {e}", manifest_path.display()))?,
    )?;
    let entry = &manifest[&name];
    let read = |ext: &str| -> Result<Vec<u8>, String> {
        let path = dir.join(format!("{name}.{ext}"));
        let data = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let want = entry[format!("{ext}_sha256")].as_str();
        if Some(sha256_hex(&data).as_str()) != want {
            return Err(format!(
                "{name}.{ext}: sha256 differs from the manifest's {want:?}"
            ));
        }
        Ok(data)
    };
    let got = common::decode_g192(common::tables()?, &read("bit")?, &name)?;
    common::compare(&name, &got, &common::samples(&read("out")?))?;
    Ok(())
}

macro_rules! synth_tests {
    ($($name:ident = $n:expr),* $(,)?) => { $( #[test] fn $name() -> common::TestResult { synthetic($n) } )* };
}

synth_tests!(
    synth00 = 0,
    synth01 = 1,
    synth02 = 2,
    synth03 = 3,
    synth04 = 4,
    synth05 = 5,
    synth06 = 6,
    synth07 = 7,
    synth08 = 8,
    synth09 = 9,
    synth10 = 10,
    synth11 = 11,
    synth12 = 12,
    synth13 = 13,
    synth14 = 14,
    synth15 = 15,
    synth16 = 16,
    synth17 = 17,
    synth18 = 18,
    synth19 = 19,
);
