// SPDX-License-Identifier: MIT OR Apache-2.0

//! Fixture key and nonce material, minted at RUNTIME rather than pasted.
//!
//! `#[cfg(test)]` at the declaration, so this module exists only for the
//! crate's own tests and is compiled out of every shipped binary.
//!
//! # Why a module rather than a literal
//!
//! CodeQL's `rust/hard-coded-cryptographic-value` scans `src/` whole. A
//! `mod tests` inside a source file is analyzed exactly like production code,
//! and there is no CodeQL configuration that scopes a rule to inline test
//! code: `paths-ignore` is path-based, so the `tests/` tree is excluded and a
//! `#[cfg(test)]` module is not. A fixture key written as `b"router-signing-key"`
//! is therefore an open security alert on the default branch, and on
//! 2026-09-09 ten of them turned `main` red hours after a release.
//!
//! Equality is all any of these fixtures needs. Nothing asserts on the BYTES
//! of a signing key -- only that the same key verifies and a different key
//! does not -- so material minted per label satisfies every test that used a
//! literal, and gives the scanner nothing to point at.
//!
//! # Why the clock, and not a constant seed
//!
//! An earlier fix derived fixture nonces by hashing a label from a fixed FNV
//! offset. That closed eight alerts of nine and opened one on the seed:
//! **derived from a constant is still constant**, and the detector is right
//! about that. The seed here is the wall clock mixed with how many labels have
//! already been minted, so no literal in this file is the material.
//!
//! # Stable within a run, different between runs
//!
//! Minting is memoized per label, so two calls with the same label inside one
//! test process return the same bytes -- which is what lets a test sign with
//! `key_for("router")` and verify with `key_for("router")`. Across runs the
//! value differs, which is the point: a test that only passes for one
//! particular key was asserting on the wrong thing.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Every label minted so far in this process, and what it was minted as.
fn minted() -> &'static Mutex<HashMap<String, Vec<u8>>> {
    static MINTED: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    MINTED.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Fixture bytes for `label`: 32 bytes, stable within this process.
///
/// Use it anywhere a test needs "a key" or "a different key" and asserts only
/// on whether two of them match.
#[must_use]
pub fn key_for(label: &str) -> Vec<u8> {
    // The lock is recovered rather than unwrapped. This module lives under
    // `src/`, so the unwrap ban reads it as production code however
    // `#[cfg(test)]` is spelled, and recovering is the better answer anyway: a
    // poisoned mint means some other test panicked, and failing every
    // subsequent test with a second panic hides the first one.
    let mut m = minted().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(k) = m.get(label) {
        return k.clone();
    }
    // A clock before 1970 yields zero here, which the label count below still
    // separates. It cannot happen, and a panic in a fixture mint would be a
    // worse answer than a duller seed.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    // The count of distinct labels keeps two mints inside the same nanosecond
    // apart -- a coarse clock would otherwise hand two labels one key, and a
    // test asserting that a DIFFERENT key is rejected would pass for the wrong
    // reason.
    let distinct = m.len() as u64;
    let seed = nanos.rotate_left(13) ^ distinct.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(32);
    let mut state = seed;
    for _ in 0..4 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(&state.to_be_bytes());
    }
    m.insert(label.to_string(), out.clone());
    out
}

/// [`key_for`] as a borrowed slice that lives for the process.
///
/// The shape a call site wants when it replaces a `const KEY: &[u8] = b"..."`:
/// the type is the same, so `mint(key_bytes("x"), ..)` compiles wherever
/// `mint(KEY, ..)` did. Leaking is bounded by the number of distinct labels a
/// test binary uses, and only test builds contain this module at all.
#[must_use]
pub fn key_bytes(label: &str) -> &'static [u8] {
    static LEAKED: OnceLock<Mutex<HashMap<String, &'static [u8]>>> = OnceLock::new();
    let mut m = LEAKED
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    if let Some(k) = m.get(label) {
        return k;
    }
    let leaked: &'static [u8] = Vec::leak(key_for(label));
    m.insert(label.to_string(), leaked);
    leaked
}

/// Fixture material for `label` as lower-case hex, for the places that want a
/// string: a challenge nonce, a `cnonce`, an opaque token.
#[must_use]
pub fn nonce_for(label: &str) -> String {
    key_for(label)
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One label mints one value, however often it is asked.
    #[test]
    fn a_label_is_stable_within_the_process() {
        assert_eq!(key_for("alpha"), key_for("alpha"));
        assert_eq!(nonce_for("alpha"), nonce_for("alpha"));
    }

    /// Different labels mint different material.
    ///
    /// This is the property every "a different key is rejected" test rests on.
    /// Without it those tests would pass because both keys were the same and
    /// the code refused for some other reason.
    #[test]
    fn different_labels_mint_different_material() {
        let a = key_for("beta");
        let b = key_for("gamma");
        assert_ne!(a, b, "two labels must not collide");
        assert_eq!(a.len(), 32);
        assert_eq!(b.len(), 32);
    }

    /// The borrowed form is the same material as the owned one.
    #[test]
    fn the_borrowed_form_matches_the_owned_one() {
        assert_eq!(key_bytes("zeta"), key_for("zeta").as_slice());
        assert_eq!(key_bytes("zeta").as_ptr(), key_bytes("zeta").as_ptr());
    }

    /// Nothing in the output is a literal from this file.
    ///
    /// A weak assertion on purpose: what it pins is that the mint is not a
    /// constant. The previous fix derived from a fixed seed and the scanner
    /// was right to keep complaining.
    #[test]
    fn material_is_not_a_constant() {
        let first = key_for("delta");
        assert!(
            first.iter().any(|b| *b != 0),
            "an all-zero key would be a constant by another route"
        );
        assert_ne!(
            first,
            key_for("epsilon"),
            "two labels minted back to back must still differ"
        );
    }
}
