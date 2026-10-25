// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! The call-volume histogram: how many dialogs opened in each fixed-width
//! interval.
//!
//! One answer, [`Timeline`], built by [`timeline`]: `GET /v1/timeline`
//! serializes it and `--timeline` prints it. The bucketing rule itself is
//! [`crate::sip::dialog_store::bucket_by_start`], which the MCP `timeline`
//! tool and the TUI's call-volume view also read, so every surface buckets a
//! capture the same way: aligned to the epoch rather than to the first call,
//! so two captures line up, with every empty interval kept, because an empty
//! interval is exactly what an outage looks like.

use crate::output::ReportFormat;
use crate::sip::dialog::SipDialog;
pub use crate::sip::dialog_store::TimelineTooWide;

/// The width a histogram uses when the caller names none, in seconds: REST's
/// default `bucket_seconds`, the MCP tool's, and a bare `--timeline`'s.
pub const DEFAULT_BUCKET_SECONDS: u64 = 60;

/// Why a zero width is refused, worded to follow the name of the parameter
/// that carried it: `bucket_seconds` on REST and MCP, the width on the CLI.
pub const ZERO_WIDTH: &str = "must be greater than zero: a zero-width bucket \
                              describes no interval, and every dialog would fall \
                              into all of them";

/// The width to bucket by: `requested`, or [`DEFAULT_BUCKET_SECONDS`] when the
/// caller named none.
///
/// # Errors
///
/// [`ZERO_WIDTH`] for a width of zero, which every surface refuses rather
/// than divide by.
pub fn bucket_width(requested: Option<u64>) -> Result<u64, &'static str> {
    match requested.unwrap_or(DEFAULT_BUCKET_SECONDS) {
        0 => Err(ZERO_WIDTH),
        width => Ok(width),
    }
}

/// One interval of a call-volume histogram.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct TimelineBucket {
    /// Start of the interval, inclusive, RFC 3339. Aligned to the epoch, not
    /// to the first call, so two captures line up.
    pub start: String,
    /// Width of the interval in seconds, echoed so a row reads on its own.
    pub bucket_seconds: u64,
    /// Dialogs whose first message fell in this interval.
    pub dialogs: u64,
}

/// Call volume over time, in fixed-width buckets.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Timeline {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// One row per interval, oldest first, gaps included (an empty interval
    /// is the outage, so it is not dropped).
    pub buckets: Vec<TimelineBucket>,
    /// Rows in `buckets`.
    pub returned: usize,
    /// The bucket width actually used, echoed because the caller may have
    /// omitted it.
    pub bucket_seconds: u64,
    /// WHICH capture this answer came from, and which revision of its
    /// stores, stamped under the locks the answer was built with. A
    /// different `instance` from an earlier answer means a different
    /// capture. The same identity the MCP tool answering this question
    /// carries. `null` when nobody told this server what it is attached to.
    #[cfg_attr(
        feature = "api",
        schema(value_type = Option<crate::output::api::schema::CaptureIdentity>)
    )]
    pub capture_identity: Option<crate::provenance::CaptureEtag>,
}

/// Bucket `dialogs` by the instant of their first message.
///
/// # Arguments
///
/// * `dialogs` — the dialogs to count: the whole store on REST, the dialogs
///   the run's compiled filter admits on the CLI.
/// * `width` — the bucket width in seconds, from [`bucket_width`], so never
///   zero.
/// * `capture_identity` — which capture and store revision the dialogs came
///   from, stamped on the answer.
///
/// # Errors
///
/// [`TimelineTooWide`] when the dialogs span more intervals of `width` than
/// one histogram holds; it names a width that fits.
pub fn timeline<'a>(
    dialogs: impl IntoIterator<Item = &'a SipDialog>,
    width: u64,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Result<Timeline, TimelineTooWide> {
    let buckets: Vec<TimelineBucket> = crate::sip::dialog_store::bucket_by_start(
        dialogs.into_iter().map(|d| d.created_at),
        width,
    )?
    .into_iter()
    .map(|(start, dialogs)| TimelineBucket {
        start: start.to_rfc3339(),
        bucket_seconds: width,
        dialogs,
    })
    .collect();
    Ok(Timeline {
        schema_version: 1,
        returned: buckets.len(),
        bucket_seconds: width,
        buckets,
        capture_identity,
    })
}

/// The histogram as a table: a line naming the bucket count, the width and
/// the dialogs counted, then one row per interval, empty intervals included.
#[must_use]
pub fn render(answer: &Timeline, format: ReportFormat) -> String {
    let total: u64 = answer.buckets.iter().map(|b| b.dialogs).sum();
    let mut out = format!(
        "Call volume: {} of {} s, {}\n",
        plural(answer.returned as u64, "bucket"),
        answer.bucket_seconds,
        plural(total, "dialog"),
    );
    let rows: Vec<Vec<String>> = answer
        .buckets
        .iter()
        .map(|b| vec![b.start.clone(), b.dialogs.to_string()])
        .collect();
    out.push_str(&super::table(format, &["Start", "Dialogs"], &rows));
    out
}

/// `n` and `noun`, with an `s` unless `n` is one.
fn plural(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// The width rule, the builder and the table, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// The dialog a lone INVITE for `call_id` at `rfc3339` opens.
    fn dialog_at(call_id: &str, rfc3339: &str) -> Result<SipDialog, TestError> {
        let raw = crate::test_utils::build_sip_message(
            "INVITE sip:bob@example.com SIP/2.0",
            &[
                "From: <sip:alice@example.com>;tag=t1",
                "To: <sip:bob@example.com>",
                &format!("Call-ID: {call_id}"),
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let at = chrono::DateTime::parse_from_rfc3339(rfc3339)?.to_utc();
        let addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        let msg = crate::sip::parser::parse_sip(
            &raw,
            at,
            addr,
            addr,
            5060,
            5060,
            crate::net::TransportProto::Udp,
        )
        .map_err(|e| format!("INVITE parses: {e:?}"))?;
        Ok(SipDialog::new(&msg).ok_or("an INVITE opens a dialog")?)
    }

    /// No width is the default; zero is refused with the shared reason; any
    /// other width is used as given.
    #[test]
    fn the_width_defaults_refuses_zero_and_keeps_the_rest() {
        assert_eq!(bucket_width(None), Ok(DEFAULT_BUCKET_SECONDS));
        assert_eq!(bucket_width(Some(0)), Err(ZERO_WIDTH));
        assert_eq!(bucket_width(Some(7)), Ok(7));
    }

    /// Buckets align to the epoch, keep the empty interval between two
    /// occupied ones, and echo the width on every row and on the answer.
    #[test]
    fn buckets_align_to_the_epoch_and_keep_gaps() -> Result<(), TestError> {
        let a = dialog_at("a@example.com", "2024-06-15T12:00:05Z")?;
        let b = dialog_at("b@example.com", "2024-06-15T12:00:25Z")?;
        let answer = timeline([&a, &b], 10, None)?;
        let rows: Vec<(&str, u64, u64)> = answer
            .buckets
            .iter()
            .map(|r| (r.start.as_str(), r.bucket_seconds, r.dialogs))
            .collect();
        assert_eq!(
            rows,
            vec![
                ("2024-06-15T12:00:00+00:00", 10, 1),
                ("2024-06-15T12:00:10+00:00", 10, 0),
                ("2024-06-15T12:00:20+00:00", 10, 1),
            ]
        );
        assert_eq!(answer.returned, 3);
        assert_eq!(answer.bucket_seconds, 10);
        assert_eq!(answer.schema_version, 1);
        Ok(())
    }

    /// No dialogs is no buckets, never an error.
    #[test]
    fn no_dialogs_is_no_buckets() -> Result<(), TestError> {
        let answer = timeline(std::iter::empty::<&SipDialog>(), 60, None)?;
        assert!(answer.buckets.is_empty());
        assert_eq!(answer.returned, 0);
        Ok(())
    }

    /// A span wider than the store's bound is the store's refusal, passed
    /// through so each surface can word it: never a truncated answer.
    #[test]
    fn a_span_wider_than_the_bound_is_refused() -> Result<(), TestError> {
        let a = dialog_at("a@example.com", "1970-01-01T00:00:01Z")?;
        let b = dialog_at("b@example.com", "2023-11-14T22:13:20Z")?;
        let Err(e) = timeline([&a, &b], 60, None) else {
            return Err("28 million one-minute intervals must be refused".into());
        };
        assert_eq!(e.bucket_seconds, 60);
        assert!(timeline([&a, &b], e.fitting_seconds, None).is_ok());
        Ok(())
    }

    /// The table's first line counts in the singular when there is one.
    #[test]
    fn the_table_names_its_counts_in_the_singular_for_one() -> Result<(), TestError> {
        let a = dialog_at("a@example.com", "2024-06-15T12:00:05Z")?;
        let out = render(&timeline([&a], 60, None)?, ReportFormat::Text);
        assert!(
            out.starts_with("Call volume: 1 bucket of 60 s, 1 dialog\n"),
            "{out}"
        );
        assert!(out.contains("2024-06-15T12:00:00+00:00  1"), "{out}");
        Ok(())
    }
}
