// SPDX-License-Identifier: MIT OR Apache-2.0

//! A byte budget for one whole page, cut at row boundaries.
//!
//! # What it bounds that nothing else did
//!
//! Three limits already shape a page: `limit` and `--mcp-max-rows` bound how
//! many rows it carries, `--mcp-max-body-bytes` bounds how wide a SIP body or
//! snippet in a row can be, and inline media has its own ceiling. None of them
//! bounds the page AS A WHOLE. Fifty `get_dialog` messages that each carry a
//! full-size SDP body are fifty rows inside every row limit, and the response
//! that holds them is still larger than a small model's context window. The
//! sizes were only measured after the fact, by
//! [`crate::mcp::metrics::response_bytes`].
//!
//! # The rule
//!
//! A page whose text content would exceed the budget drops WHOLE rows from its
//! end until it fits, and then says so: `truncated: true`,
//! `truncated_by: "bytes"`, `returned` set to the rows it kept, and a
//! `next_cursor` naming the last row kept, so following the cursor resumes at
//! the first row the budget left out. A row is never split: half a SIP message
//! is a different message, and half a dialog summary reads as a dialog with
//! fewer fields.
//!
//! One row always survives, even when that row alone is over the budget. A
//! page of zero rows with a cursor pointing where the caller already is would
//! hand back the same empty page forever; a page of one row always makes
//! progress, and each row is already bounded by `--mcp-max-body-bytes`.
//!
//! # What is counted
//!
//! The same figure [`crate::mcp::metrics::response_bytes`] reports: the text
//! of every content block. That is the JSON page, the provenance note the
//! fencing tools append after it, and the two completeness booleans the
//! dispatcher stamps on the page after the tool returns
//! ([`crate::mcp::completeness::stamp`]). The cut runs inside the tool, BEFORE
//! that stamp, so the stamp's bytes are reserved in advance with
//! [`crate::mcp::completeness::stamp_growth_bound`] rather than measured.
//! The JSON-RPC framing and the `structuredContent` copy of the same object
//! are not counted, for the reason the metric gives.

use serde_json::Value;

/// Envelope key naming which bound cut a page short.
pub const TRUNCATED_BY_KEY: &str = "truncated_by";

/// `truncated_by` value: the row limit (`limit`, clamped by `--mcp-max-rows`)
/// withheld matching rows.
pub const TRUNCATED_BY_ROWS: &str = "rows";

/// `truncated_by` value: the byte budget (`max_response_bytes`, clamped by
/// `--mcp-max-response-bytes`) withheld rows the row limit would have kept.
pub const TRUNCATED_BY_BYTES: &str = "bytes";

/// The budget one call runs under: the caller's `max_response_bytes`, clamped
/// to the operator's ceiling.
///
/// `None` and `0` both resolve to the ceiling, the same reading `limit` gets
/// on this surface: `0` is the value a computed budget collapses to, and
/// answering it with an empty page would read as "no matches".
///
/// # Arguments
///
/// * `requested` — the per-call `max_response_bytes`, if any.
/// * `cap` — the operator's `--mcp-max-response-bytes` ceiling.
///
/// # Returns
///
/// The budget in bytes, never above `cap` and never below 1.
#[must_use]
pub fn resolve(requested: Option<u64>, cap: usize) -> usize {
    let cap = cap.max(1);
    match requested {
        None | Some(0) => cap,
        Some(n) => usize::try_from(n).map_or(cap, |n| n.min(cap)),
    }
}

/// How many leading rows fit in `budget`, given the bytes the rest of the
/// response costs.
///
/// The pure half of [`fit`], so the arithmetic is driven directly: rows are
/// joined by one comma each, so `k` rows cost their own bytes plus `k - 1`.
///
/// # Arguments
///
/// * `fixed` — bytes of everything that is not a row: the envelope with an
///   empty row array, plus any reserved bytes outside it.
/// * `rows` — the serialized length of each row, in page order.
/// * `budget` — the bytes allowed for the whole response.
///
/// # Returns
///
/// The largest `k` such that the first `k` rows and `fixed` fit in `budget`.
/// May be 0; [`fit`] raises that to 1.
#[must_use]
pub fn rows_within(fixed: usize, rows: &[usize], budget: usize) -> usize {
    let mut used = fixed;
    for (k, len) in rows.iter().enumerate() {
        let separator = usize::from(k > 0);
        used = used.saturating_add(*len).saturating_add(separator);
        if used > budget {
            return k;
        }
    }
    rows.len()
}

/// Cut a serialized page to `budget`, at a row boundary.
///
/// Measures the page; when it fits, nothing changes. When it does not, keeps
/// the longest prefix of rows that fits (at least one), and rewrites the
/// envelope to say so: `truncated: true`, `truncated_by: "bytes"`,
/// `next_cursor` set to `row_cursors[kept - 1]`, and `returned` set to the
/// rows kept when the page carries a `returned`.
///
/// The envelope is sized for its worst case before the cut is chosen — the
/// longest cursor any row could hand on, `truncated: true`, the
/// `truncated_by` key — so the page that results is never larger than the
/// estimate it was cut against.
///
/// # Arguments
///
/// * `page` — the page object, already projected to the fields the caller
///   asked for.
/// * `rows_key` — the key holding the row array (`dialogs`, `messages`, ...).
/// * `row_cursors` — the cursor that resumes AFTER each row, in page order.
/// * `budget` — the resolved budget, from [`resolve`].
/// * `outside` — bytes the response carries outside this object: the
///   provenance note, if the tool appends one, and the completeness stamp.
///
/// # Returns
///
/// `Ok(true)` when rows were cut, `Ok(false)` when the page already fit or
/// holds one row or none.
///
/// # Errors
///
/// When `page` is not an object, `rows_key` is not an array, or
/// `row_cursors` does not hold one cursor per row — each a defect in the
/// caller, reported rather than guessed around.
pub fn fit(
    page: &mut Value,
    rows_key: &str,
    row_cursors: &[String],
    budget: usize,
    outside: usize,
) -> Result<bool, String> {
    if serialized_len(page)?.saturating_add(outside) <= budget {
        return Ok(false);
    }
    let obj = page
        .as_object_mut()
        .ok_or("a page to fit must be a JSON object")?;
    let rows = match obj.get_mut(rows_key) {
        Some(Value::Array(rows)) => std::mem::take(rows),
        _ => return Err(format!("page has no '{rows_key}' array")),
    };
    if rows.len() != row_cursors.len() {
        let held = rows.len();
        obj.insert(rows_key.to_string(), Value::Array(rows));
        return Err(format!(
            "{held} rows but {} cursors; every row needs the cursor that resumes after it",
            row_cursors.len()
        ));
    }
    if rows.len() <= 1 {
        obj.insert(rows_key.to_string(), Value::Array(rows));
        return Ok(false);
    }

    let mut sizes = Vec::new();
    for row in &rows {
        sizes.push(serialized_len(row)?);
    }

    // The envelope at its largest: every field the cut may write, at the
    // longest value it may take.
    let longest = row_cursors
        .iter()
        .max_by_key(|c| c.len())
        .cloned()
        .unwrap_or_default();
    let had_returned = obj.contains_key("returned");
    mark(obj, rows.len(), had_returned, longest);
    let envelope = serialized_len(&Value::Object(obj.clone()))?;

    let kept = rows_within(envelope.saturating_add(outside), &sizes, budget).max(1);
    if kept >= rows.len() {
        // Not reachable while the envelope estimate is an upper bound, which
        // is what it is built to be. Reported as an error rather than
        // asserted, so a defect here fails one call instead of the process.
        return Err("the byte budget estimate kept every row of a page that did not fit".into());
    }
    let mut rows = rows;
    rows.truncate(kept);
    let cursor = row_cursors
        .get(kept - 1)
        .cloned()
        .ok_or("cursor for the last kept row")?;
    mark(obj, kept, had_returned, cursor);
    obj.insert(rows_key.to_string(), Value::Array(rows));
    Ok(true)
}

/// Write the envelope fields a byte cut sets.
fn mark(obj: &mut serde_json::Map<String, Value>, kept: usize, had_returned: bool, cursor: String) {
    obj.insert("truncated".to_string(), Value::Bool(true));
    obj.insert(
        TRUNCATED_BY_KEY.to_string(),
        Value::String(TRUNCATED_BY_BYTES.to_string()),
    );
    obj.insert("next_cursor".to_string(), Value::String(cursor));
    if had_returned {
        obj.insert("returned".to_string(), Value::from(kept));
    }
}

/// Bytes of `v` as `ContentBlock::json` writes it: compact `serde_json`.
fn serialized_len(v: &Value) -> Result<usize, String> {
    serde_json::to_string(v)
        .map(|s| s.len())
        .map_err(|e| format!("page does not serialize: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    type TestError = Box<dyn std::error::Error>;

    /// A page of `n` rows, each `{"id":"<i>","pad":"<width x's>"}`.
    fn page(n: usize, width: usize) -> (Value, Vec<String>) {
        let rows: Vec<Value> = (0..n)
            .map(|i| serde_json::json!({ "id": i.to_string(), "pad": "x".repeat(width) }))
            .collect();
        let cursors = (0..n).map(|i| format!("c{i}")).collect();
        (
            serde_json::json!({
                "schema_version": 1,
                "returned": n,
                "rows": rows,
                "truncated": false,
                "next_cursor": null,
            }),
            cursors,
        )
    }

    fn len(v: &Value) -> Result<usize, TestError> {
        Ok(serde_json::to_string(v)?.len())
    }

    #[test]
    fn resolve_clamps_to_the_ceiling_and_reads_zero_as_unset() {
        assert_eq!(resolve(None, 5000), 5000);
        assert_eq!(resolve(Some(0), 5000), 5000);
        assert_eq!(resolve(Some(100), 5000), 100);
        assert_eq!(resolve(Some(9000), 5000), 5000);
        assert_eq!(resolve(None, 0), 1, "a zero ceiling still bounds to one");
    }

    #[test]
    fn rows_within_counts_one_comma_between_rows() {
        // fixed 10, rows of 5: one row = 15, two = 21 (5 + 1 + 5), three = 27.
        assert_eq!(rows_within(10, &[5, 5, 5], 14), 0);
        assert_eq!(rows_within(10, &[5, 5, 5], 15), 1);
        assert_eq!(rows_within(10, &[5, 5, 5], 20), 1);
        assert_eq!(rows_within(10, &[5, 5, 5], 21), 2);
        assert_eq!(rows_within(10, &[5, 5, 5], 27), 3);
        assert_eq!(rows_within(10, &[], 0), 0);
    }

    #[test]
    fn a_page_that_fits_is_left_byte_for_byte_alone() -> Result<(), TestError> {
        let (mut p, cursors) = page(5, 40);
        let before = p.clone();
        let budget = len(&p)?;
        assert!(!fit(&mut p, "rows", &cursors, budget, 0)?);
        assert_eq!(p, before);
        Ok(())
    }

    #[test]
    fn an_oversize_page_keeps_whole_rows_and_says_so() -> Result<(), TestError> {
        let (mut p, cursors) = page(10, 100);
        let whole = len(&p)?;
        let budget = whole / 2;
        assert!(fit(&mut p, "rows", &cursors, budget, 0)?);
        let rows = p["rows"].as_array().ok_or("rows")?;
        let kept = rows.len();
        assert!(kept > 0 && kept < 10, "kept {kept}");
        assert!(len(&p)? <= budget, "{} > {budget}", len(&p)?);
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(
                row["pad"].as_str().map(str::len),
                Some(100),
                "row {i} was cut"
            );
            assert_eq!(row["id"], i.to_string());
        }
        assert_eq!(p["truncated"], true);
        assert_eq!(p[TRUNCATED_BY_KEY], TRUNCATED_BY_BYTES);
        assert_eq!(p["returned"], kept);
        assert_eq!(p["next_cursor"], format!("c{}", kept - 1));
        // The cut is the LARGEST that fits: one more row would not.
        let mut more = p.clone();
        let (full, _) = page(10, 100);
        let extra = full["rows"][kept].clone();
        more["rows"].as_array_mut().ok_or("rows")?.push(extra);
        assert!(len(&more)? > budget, "a row that fit was dropped");
        Ok(())
    }

    #[test]
    fn bytes_outside_the_object_are_reserved() -> Result<(), TestError> {
        let (p, cursors) = page(10, 100);
        let budget = len(&p)? - 1;
        let mut without = p.clone();
        let mut with = p;
        fit(&mut without, "rows", &cursors, budget, 0)?;
        fit(&mut with, "rows", &cursors, budget, 300)?;
        let kept = |v: &Value| v["rows"].as_array().map_or(0, Vec::len);
        assert!(kept(&with) < kept(&without));
        assert!(len(&with)? + 300 <= budget);
        Ok(())
    }

    #[test]
    fn one_row_survives_a_budget_smaller_than_it() -> Result<(), TestError> {
        let (mut p, cursors) = page(3, 500);
        assert!(fit(&mut p, "rows", &cursors, 10, 0)?);
        assert_eq!(p["rows"].as_array().map(Vec::len), Some(1));
        assert_eq!(p["next_cursor"], "c0", "the cursor must move past the row");
        // A page of one row is never cut, and keeps its own envelope.
        let (mut single, one) = page(1, 500);
        let before = single.clone();
        assert!(!fit(&mut single, "rows", &one, 10, 0)?);
        assert_eq!(single, before);
        Ok(())
    }

    #[test]
    fn a_cursor_per_row_is_required() -> Result<(), TestError> {
        let (mut p, cursors) = page(4, 100);
        let err = fit(&mut p, "rows", &cursors[..3], 10, 0)
            .err()
            .ok_or("a short cursor list must be refused")?;
        assert!(err.contains("4 rows but 3 cursors"), "{err}");
        assert_eq!(p["rows"].as_array().map(Vec::len), Some(4), "rows restored");
        Ok(())
    }

    #[test]
    fn a_page_without_returned_does_not_gain_one() -> Result<(), TestError> {
        let (mut p, cursors) = page(6, 100);
        p.as_object_mut().ok_or("object")?.remove("returned");
        assert!(fit(&mut p, "rows", &cursors, 300, 0)?);
        assert!(p.get("returned").is_none());
        assert_eq!(p["truncated_by"], "bytes");
        Ok(())
    }
}
