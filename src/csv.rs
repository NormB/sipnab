// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! CSV output, escaped by one rule.
//!
//! Every CSV sipnab writes, the terminal UI's save and the WASM session's
//! export, goes through [`escape_field`] for each text column, so the two
//! cannot disagree about what a field may hold.

use crate::sip::dialog_store::DialogStore;

/// The first characters with which a spreadsheet starts a formula, or which
/// it strips before looking for one (the OWASP CSV-injection guidance).
const FORMULA_LEADS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Escape `field` for one CSV cell.
///
/// * A field that starts with one of `FORMULA_LEADS` (`=`, `+`, `-`, `@`,
///   TAB, CR) gets a leading `'`, so a spreadsheet shows it as text rather
///   than running it (CWE-1236), and is quoted. The SIP From and To users are
///   chosen by whoever places the call, so a cell such as a `HYPERLINK`
///   formula is a remote caller's text.
/// * A field holding a comma, a double quote, a line feed or a carriage
///   return is wrapped in double quotes, with each double quote doubled
///   (RFC 4180). A bare carriage return is a line break to an RFC 4180
///   reader, so it is quoted like a line feed.
///
/// Columns sipnab formats itself from numbers or timestamps hold no caller
/// text and are not passed through here: a negative `pdd_ms` is a number,
/// and prefixing it would turn it into text for every consumer.
#[must_use]
pub fn escape_field(field: &str) -> String {
    let formula = field.starts_with(FORMULA_LEADS);
    if !formula && !field.contains([',', '"', '\n', '\r']) {
        return field.to_string();
    }
    let prefix = if formula { "'" } else { "" };
    format!("\"{prefix}{}\"", field.replace('"', "\"\""))
}

/// The CSV the WASM session exports: a header and one row per dialog in
/// `store`.
///
/// Text columns go through [`escape_field`]; the message count, the PDD
/// (`-1` when there is none) and the RFC 3339 time are written as sipnab
/// formats them. It lives here, outside the `wasm32`-only module, so the host
/// test suite can drive it; `SipnabSession::export_csv` returns it unchanged.
#[must_use]
pub fn session_export(store: &DialogStore) -> String {
    let mut out =
        String::from("call_id,method,state,from,to,src_ip,dst_ip,messages,pdd_ms,created_at\n");
    for d in store.iter() {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{}\n",
            escape_field(&d.call_id),
            escape_field(d.method.as_str()),
            escape_field(&d.state().to_string()),
            // `-` marks an absent user: sipnab's placeholder, not caller
            // text, so it is written as it always was.
            d.from_user
                .as_deref()
                .map_or_else(|| "-".to_owned(), escape_field),
            d.to_user
                .as_deref()
                .map_or_else(|| "-".to_owned(), escape_field),
            escape_field(&d.src_addr.to_string()),
            escape_field(&d.dst_addr.to_string()),
            d.messages.len(),
            d.timing.pdd_ms().unwrap_or(-1),
            d.created_at.to_rfc3339(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::parse::TransportProto;
    use crate::sip::parser::parse_sip;
    use chrono::{TimeZone, Utc};
    use std::net::{IpAddr, Ipv4Addr};

    type TestError = Box<dyn std::error::Error>;

    /// A cell a spreadsheet would read as a formula starts with a single
    /// quote, so it is shown as text (CWE-1236, the OWASP CSV-injection
    /// guidance), and is quoted. A From user is set by whoever sends the
    /// INVITE, so `=1+1` here is a remote caller's choice.
    #[test]
    fn a_leading_equals_sign_is_neutralized() {
        assert_eq!(
            escape_field("=1+1"),
            "\"'=1+1\"",
            "a leading = is prefixed with ' and quoted"
        );
        assert_eq!(
            escape_field("=HYPERLINK(\"http://example.invalid\")"),
            "\"'=HYPERLINK(\"\"http://example.invalid\"\")\"",
            "a formula holding quotes is prefixed, quoted, and its quotes doubled"
        );
    }

    /// Every other character a spreadsheet treats as the start of a formula,
    /// or strips before looking for one: `+`, `-`, `@`, TAB, CR.
    #[test]
    fn every_formula_lead_is_neutralized() {
        for (field, want) in [
            ("+1+1", "\"'+1+1\""),
            ("-1+1", "\"'-1+1\""),
            ("@SUM(A1)", "\"'@SUM(A1)\""),
            ("\t=1+1", "\"'\t=1+1\""),
            ("\r=1+1", "\"'\r=1+1\""),
        ] {
            assert_eq!(escape_field(field), want, "for {field:?}");
        }
    }

    /// Negative control: the same characters anywhere but first leave the
    /// field as it was, and so do plain fields and an empty one.
    #[test]
    fn a_formula_character_not_in_first_place_is_left_alone() {
        for field in ["plain", "a=1", "1001", "1-2", "user@host", "", "x+y"] {
            assert_eq!(escape_field(field), field, "for {field:?}");
        }
    }

    /// A bare carriage return is a line break to an RFC 4180 reader, so a
    /// field holding one is quoted like a field holding `\n`. Unquoted, it
    /// split the row in two.
    #[test]
    fn a_bare_carriage_return_is_quoted() {
        assert_eq!(escape_field("a\rb"), "\"a\rb\"", "a bare CR is quoted");
        assert_eq!(escape_field("a\r\nb"), "\"a\r\nb\"", "a CRLF is quoted");
    }

    /// The RFC 4180 cases that already held still hold.
    #[test]
    fn commas_quotes_and_newlines_are_quoted() {
        for (field, want) in [
            ("a,b", "\"a,b\""),
            ("he said \"hi\"", "\"he said \"\"hi\"\"\""),
            ("line\nbreak", "\"line\nbreak\""),
        ] {
            assert_eq!(escape_field(field), want, "RFC 4180 quoting of {field:?}");
        }
    }

    /// A store holding one INVITE whose From user is `from`.
    fn store_with_from_user(from: &str) -> Result<DialogStore, TestError> {
        let raw = crate::test_utils::build_sip_message(
            "INVITE sip:1002@example.com SIP/2.0",
            &[
                &format!("From: <sip:{from}@example.com>;tag=t1"),
                "To: <sip:1002@example.com>",
                "Call-ID: csv-session@example.com",
                "CSeq: 1 INVITE",
                "Content-Length: 0",
            ],
            b"",
        );
        let ts = Utc
            .with_ymd_and_hms(2026, 1, 2, 3, 4, 5)
            .single()
            .ok_or("fixture timestamp")?;
        let msg = parse_sip(
            &raw,
            ts,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            5060,
            5060,
            TransportProto::Udp,
        )
        .map_err(|e| format!("parse INVITE: {e:?}"))?;
        let mut store = DialogStore::new(16, false);
        store.process_message(msg);
        let d = store.iter().next().ok_or("the INVITE made no dialog")?;
        assert_eq!(
            d.from_user.as_deref(),
            Some(from),
            "the fixture's From user did not parse as written, so the test would \
             not reach the guard"
        );
        Ok(store)
    }

    /// The fourth column of the one data row of `csv`.
    fn from_column(csv: &str) -> Result<String, TestError> {
        let row = csv.lines().nth(1).ok_or("no data row")?;
        let cols: Vec<&str> = row.split(',').collect();
        assert_eq!(
            cols.len(),
            10,
            "the row split into {} cells: {row:?}",
            cols.len()
        );
        Ok(cols[3].to_string())
    }

    /// The WASM session's export writes a caller's formula as text.
    ///
    /// `SipnabSession::export_csv` is built for `wasm32` only, so the host
    /// suite cannot call it; it returns [`session_export`] unchanged, which
    /// is what this drives.
    #[test]
    fn the_session_export_writes_a_formula_from_user_as_text() -> Result<(), TestError> {
        let store = store_with_from_user("=1+1")?;
        assert_eq!(
            from_column(&session_export(&store))?,
            "\"'=1+1\"",
            "the session export's from column"
        );
        Ok(())
    }

    /// Negative control: a plain From user is written as it arrived, and the
    /// numeric columns stay numbers (a missing PDD is still `-1`).
    #[test]
    fn the_session_export_leaves_a_plain_row_alone() -> Result<(), TestError> {
        let store = store_with_from_user("1001")?;
        let csv = session_export(&store);
        assert_eq!(
            from_column(&csv)?,
            "1001",
            "a plain From user is written as is"
        );
        let row = csv.lines().nth(1).ok_or("no data row")?;
        assert!(row.contains(",1,-1,"), "messages and pdd_ms: {row:?}");
        Ok(())
    }
}
