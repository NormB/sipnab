// SPDX-License-Identifier: MIT OR Apache-2.0

//! Build the table file from the ITU-T package and write it to a path.
//!
//! `cargo run -p sipnab-g729 --features std --example import_tables -- PACKAGE OUT`
//!
//! PACKAGE is the package zip or a directory extracted from it, such as the
//! `crates/g729/test-vectors/itu-source` that `scripts/fetch-g729-vectors.py`
//! fills. The release workflow uses this to give `scripts/no-itu-values.py`
//! the values to look for in the built binaries; operators install with
//! `sipnab g729 install`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args_os().skip(1);
    let (Some(package), Some(out)) = (args.next(), args.next()) else {
        return Err("usage: import_tables PACKAGE OUT".into());
    };
    let table = g729::import_from_itu(std::path::Path::new(&package))?;
    std::fs::write(&out, table)?;
    Ok(())
}
