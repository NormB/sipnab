// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The basic operators against the oracle's black-box rows
//! (`.git/g729-reference/basic_operations.json`): 16- and 32-bit
//! normalization, the high/low split and split multiply, and the log2, pow2
//! and inverse-square-root lookups.
//!
//! Built only with the `g729_oracle` cfg flag (`RUSTFLAGS='--cfg g729_oracle' cargo test -p sipnab-g729`): the rows live only in the main
//! checkout's `.git` (some log2 rows are outputs of the user-supplied table).
#![cfg(g729_oracle)]

pub mod common;

use g729::basic_op::{Ctx, norm_l, norm_s};
use serde_json::Value;

fn rows(key: &str) -> Result<Vec<Vec<i64>>, String> {
    let path = common::trace::reference_dir().join("basic_operations.json");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let rows = v[key].as_array().ok_or_else(|| format!("{key} missing"))?;
    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let row = r
            .as_array()
            .ok_or_else(|| format!("{key}: a row is not an array"))?;
        let ints: Option<Vec<i64>> = row.iter().map(Value::as_i64).collect();
        out.push(ints.ok_or_else(|| format!("{key}: a value is not an integer"))?);
    }
    if out.is_empty() {
        return Err(format!("{key}: no rows"));
    }
    Ok(out)
}

/// Run `f` on every row; report every mismatch.
fn table(key: &str, f: impl Fn(&[i64]) -> (Vec<i64>, Vec<i64>)) -> common::TestResult {
    let all = rows(key)?;
    let bad: Vec<String> = all
        .iter()
        .filter_map(|r| {
            let (got, want) = f(r);
            (got != want).then(|| format!("{r:?}: got {got:?}"))
        })
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{key}: {} of {} rows differ:\n{}",
            bad.len(),
            all.len(),
            bad.join("\n")
        )
        .into())
    }
}

#[test]
fn normalize_16() -> common::TestResult {
    table("normalize_16", |r| {
        (vec![i64::from(norm_s(r[0] as i16))], vec![r[1]])
    })
}

#[test]
fn normalize_32() -> common::TestResult {
    table("normalize_32", |r| {
        (vec![i64::from(norm_l(r[0] as i32))], vec![r[1]])
    })
}

#[test]
fn split_32() -> common::TestResult {
    table("split_32", |r| {
        let (hi, lo) = Ctx::default().split_high_low(r[0] as i32);
        (vec![i64::from(hi), i64::from(lo)], vec![r[1], r[2]])
    })
}

#[test]
fn split_multiply_32x16() -> common::TestResult {
    table("split_multiply_32x16", |r| {
        let got = Ctx::default().multiply_split_by_16(r[0] as i16, r[1] as i16, r[2] as i16);
        (vec![i64::from(got)], vec![r[3]])
    })
}

#[test]
fn log2_lookup() -> common::TestResult {
    let t = common::tables()?;
    table("log2_lookup", |r| {
        let (e, f) = Ctx::default().base2_log(r[0] as i32, t.log2_table());
        (vec![i64::from(e), i64::from(f)], vec![r[1], r[2]])
    })
}

#[test]
fn pow2_lookup() -> common::TestResult {
    table("pow2_lookup", |r| {
        (
            vec![i64::from(
                Ctx::default().base2_power(r[0] as i16, r[1] as i16),
            )],
            vec![r[2]],
        )
    })
}

#[test]
fn inverse_sqrt_lookup() -> common::TestResult {
    table("inverse_sqrt_lookup", |r| {
        (
            vec![i64::from(Ctx::default().inverse_square_root(r[0] as i32))],
            vec![r[1]],
        )
    })
}
