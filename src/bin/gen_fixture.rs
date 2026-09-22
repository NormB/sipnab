// SPDX-License-Identifier: MIT OR Apache-2.0

//! Writes the synthetic capture fixtures from their generator.
//!
//! Run with: cargo run --features native --bin gen_fixture
//!
//! The builders live in `tests/support/synthetic_captures.rs`, which
//! `tests/synthetic_captures_test.rs` also includes, so the bytes this writes
//! and the bytes the suite checks come from one definition. The test only
//! compares; this binary is the one thing that writes.

#[path = "../../tests/support/synthetic_captures.rs"]
mod synthetic_captures;

fn main() {
    let root = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let root = std::path::PathBuf::from(root);
    for owned in synthetic_captures::OWNED {
        let path = root.join(owned.path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).expect("create the fixture directory");
        }
        let bytes = (owned.build)();
        std::fs::write(&path, &bytes).expect("write the fixture");
        println!("{}: {} bytes", owned.path, bytes.len());
    }
}
