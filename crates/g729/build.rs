// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Declares the crate's two cfg flags, so `unexpected_cfgs` accepts them (the
//! workspace lints table cannot be extended per crate; the root package
//! declares `sipnab_tsan` the same way, in its build script):
//!
//! - `g729_oracle`: build the tests that read the oracle's local data under
//!   the main checkout's `.git` (traces, reference rows, synthetic streams).
//!   Run them with `RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`. Under
//!   that flag, missing data fails the tests. A cfg flag, not a feature, so
//!   that `--all-features` (as CI runs it) cannot switch them on.
//! - `fuzzing`: set by cargo-fuzz. Only a fuzz build may build `Tables`
//!   without the values-hash check (`Tables::from_values_unverified`).

fn main() {
    println!("cargo::rustc-check-cfg=cfg(g729_oracle)");
    println!("cargo::rustc-check-cfg=cfg(fuzzing)");
}
