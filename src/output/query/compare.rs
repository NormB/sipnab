// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Two calls side by side, naming the fields that differ.
//!
//! One answer, [`Comparison`], built by [`comparison`]:
//! `GET /v1/dialogs/compare` serializes it and `--compare-dialogs` prints
//! it. The comparison itself is [`crate::sip::dialog::compare_dialogs`],
//! which the MCP `compare_dialogs` tool also reads.

use crate::output::ReportFormat;
use crate::sip::dialog::SipDialog;

/// One call summarized for a side-by-side comparison: the fields
/// `/v1/dialogs/compare` diffs, the same the MCP `compare_dialogs` tool
/// reports.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct ComparisonSide {
    /// The dialog's Call-ID.
    pub call_id: String,
    /// The dialog state (`InCall`, `Failed`, `Completed`, …).
    pub state: String,
    /// The final response code of the dialog's INVITE, or of the request
    /// that opened a dialog without one; null while it has none.
    pub final_status_code: Option<u16>,
    /// How many SIP messages the dialog holds.
    pub msg_count: usize,
    /// The distinct request methods seen, sorted.
    pub methods: Vec<String>,
    /// The signaling-diagnosis hints for the call.
    pub hints: Vec<String>,
}

/// Two calls side by side, naming which fields differ.
#[derive(Debug, Clone, serde::Serialize)]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Comparison {
    /// Version of this response's shape.
    #[cfg_attr(feature = "api", schema(example = 1))]
    pub schema_version: u32,
    /// The first call's summary.
    pub a: ComparisonSide,
    /// The second call's summary.
    pub b: ComparisonSide,
    /// The field names that differ — a subset of `state`,
    /// `final_status_code`, `msg_count`, `methods`, in that order. Empty
    /// when the two calls match on all four. `hints` is reported per side
    /// but not diffed.
    pub differences: Vec<String>,
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

/// `a` and `b` compared.
#[must_use]
pub fn comparison(
    a: &SipDialog,
    b: &SipDialog,
    capture_identity: Option<crate::provenance::CaptureEtag>,
) -> Comparison {
    let cmp = crate::sip::dialog::compare_dialogs(a, b);
    let side = |s: crate::sip::dialog::DialogSide| ComparisonSide {
        call_id: s.call_id,
        state: s.state,
        final_status_code: s.final_status_code,
        msg_count: s.msg_count,
        methods: s.methods,
        hints: s.hints,
    };
    Comparison {
        schema_version: 1,
        a: side(cmp.a),
        b: side(cmp.b),
        differences: cmp.differences,
        capture_identity,
    }
}

/// The comparison as a table: a line naming the two calls and how many
/// fields differ, one row per compared field with each call's value and
/// `differs` where they do, and each call's diagnosis hints below.
#[must_use]
pub fn render(answer: &Comparison, format: ReportFormat) -> String {
    let differing = answer.differences.len();
    let mut out = format!(
        "Comparing {} (A) with {} (B): {}\n",
        answer.a.call_id,
        answer.b.call_id,
        match differing {
            0 => "no field differs".to_string(),
            1 => "1 field differs".to_string(),
            n => format!("{n} fields differ"),
        },
    );
    let code = |c: Option<u16>| c.map_or_else(|| "-".to_string(), |c| c.to_string());
    let fields: [(&str, String, String); 4] = [
        ("state", answer.a.state.clone(), answer.b.state.clone()),
        (
            "final_status_code",
            code(answer.a.final_status_code),
            code(answer.b.final_status_code),
        ),
        (
            "msg_count",
            answer.a.msg_count.to_string(),
            answer.b.msg_count.to_string(),
        ),
        (
            "methods",
            answer.a.methods.join(","),
            answer.b.methods.join(","),
        ),
    ];
    let rows: Vec<Vec<String>> = fields
        .into_iter()
        .map(|(field, a, b)| {
            let differs = if answer.differences.iter().any(|d| d == field) {
                "differs"
            } else {
                ""
            };
            vec![field.to_string(), a, b, differs.to_string()]
        })
        .collect();
    out.push_str(&super::table(
        format,
        &["Field", "A", "B", "Differs"],
        &rows,
    ));
    for (label, side) in [("A", &answer.a), ("B", &answer.b)] {
        if side.hints.is_empty() {
            out.push_str(&format!("Hints for {label}: none\n"));
        } else {
            // Hints quote the wire (a reason phrase), so they are scrubbed as
            // a table cell is.
            out.push_str(&format!(
                "Hints for {label}: {}\n",
                super::clean(&side.hints.join(" "))
            ));
        }
    }
    out
}

/// The table, driven directly.
#[cfg(test)]
mod tests {
    use super::*;

    fn side(call_id: &str, hints: Vec<String>) -> ComparisonSide {
        ComparisonSide {
            call_id: call_id.into(),
            state: "Failed".into(),
            final_status_code: Some(486),
            msg_count: 4,
            methods: vec!["ACK".into(), "INVITE".into()],
            hints,
        }
    }

    /// A hint quoting a reason phrase with a terminal escape in it reaches
    /// the reader scrubbed, and no hint at all says so.
    #[test]
    fn hints_are_scrubbed_and_none_is_said() {
        let answer = Comparison {
            schema_version: 1,
            a: side(
                "a@example.com",
                vec!["Call failed: 486 \u{1b}[2JBusy.".into()],
            ),
            b: side("b@example.com", Vec::new()),
            differences: Vec::new(),
            capture_identity: None,
        };
        let out = render(&answer, ReportFormat::Text);
        assert!(!out.contains('\u{1b}'), "{out:?}");
        assert!(
            out.contains("Hints for A: Call failed: 486 \u{FFFD}[2JBusy."),
            "{out}"
        );
        assert!(out.contains("Hints for B: none"), "{out}");
        assert!(out.contains(": no field differs"), "{out}");
    }
}
