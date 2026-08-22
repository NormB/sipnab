// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tabular STUN and TURN report (`--stun`).
//!
//! Renders what NAT traversal actually achieved: which probes were answered,
//! how long they took, and what public address the server reported back. The
//! operationally load-bearing row is the unanswered one — a client whose
//! Binding Request drew no reply has no public address to advertise, so it
//! falls back to the private one in its SDP, and one-way audio follows.
//!
//! TURN ([RFC 5766](https://www.rfc-editor.org/rfc/rfc5766)) rides the same
//! transaction table, because a TURN message IS a STUN message. What it adds
//! is one section the transaction table cannot hold: the allocations a server
//! granted, with the lifetimes that decide when they lapse.
//!
//! # Which of the parser's fields earn a column
//!
//! [`crate::stun::StunMessage`] decodes more than this table shows, and the
//! difference is deliberate — a column that is a dash on every real capture is
//! how a table stops being read. Three earn their place, and each only when
//! the capture contains one:
//!
//! * **Relayed Address** — the TURN answer, absent on a pure-STUN capture.
//! * **Role** — `ICE-CONTROLLING` / `ICE-CONTROLLED`. Shown only on a capture
//!   holding ICE checks, and worth showing there because a capture where BOTH
//!   sides claim `Controlling` is a role conflict whose only other symptom is
//!   media that never starts.
//! * **FP** — `FINGERPRINT`, shown only when one FAILED. A valid fingerprint
//!   is the normal case and says nothing; a wrong one says the message was
//!   corrupted in flight, which is a different fault from every other row here.
//!
//! The auth challenge does not get a column: it is a property of the RESPONSE,
//! and the `Response` cell already has room to say `error 401 (auth)` — where a
//! reader is already looking when they want to know what came back.
//!
//! Nothing about `MESSAGE-INTEGRITY` is rendered anywhere. Deciding whether a
//! message is authentic needs credentials a passive observer does not have, and
//! a column about it would claim a verification that never happened.

use std::fmt::Write;

use crate::stun::{StunReport, StunTransaction, TurnAllocation};

/// Render a STUN/TURN report to a string.
///
/// # Returns
///
/// The formatted report, or an empty string when the run saw no STUN — the
/// same "a clean run stays quiet" rule the ICMP and retention summaries
/// follow, so a capture without STUN is byte-identical to one from before this
/// report existed.
#[must_use]
pub fn print_stun_report(report: &StunReport) -> String {
    print_stun_report_as(report, crate::output::ReportFormat::Text)
}

/// As [`print_stun_report`], in the requested format.
#[must_use]
pub fn print_stun_report_as(report: &StunReport, format: crate::output::ReportFormat) -> String {
    if report.is_empty() {
        return String::new();
    }
    let md = matches!(format, crate::output::ReportFormat::Markdown);
    let mut out = String::with_capacity(1024);

    if !report.transactions.is_empty() {
        transaction_table(report, md, &mut out);
    }
    if !report.allocations.is_empty() {
        allocation_table(report, md, &mut out);
    }
    // A run whose only STUN was indications has no table to show — an
    // indication is not a transaction (RFC 5766 §10) — but it is still not an
    // empty capture, and saying nothing about it would be the same defect this
    // report exists to fix.
    if out.is_empty() {
        let _ = writeln!(
            out,
            "STUN/TURN: {} packet(s), {} indication(s), {} relayed frame(s) — nothing that \
             correlates into a transaction or an allocation.",
            report.packets, report.indications, report.channel_data_frames
        );
    }

    ice_prose(report, &mut out);
    lapsed_allocation_prose(report, &mut out);
    unanswered_prose(report, &mut out);
    out
}

/// One row per STUN/TURN transaction.
fn transaction_table(report: &StunReport, md: bool, out: &mut String) {
    let _ = writeln!(
        out,
        "STUN Transactions ({} packet(s), {} transaction(s)):",
        report.packets,
        report.transactions.len()
    );

    // The three conditional columns. Each is carried only when the capture
    // actually holds one — see the module docs.
    let relayed = report
        .transactions
        .iter()
        .any(|t| t.relayed_address.is_some());
    let ice = report.transactions.iter().any(|t| t.ice_role.is_some());
    let bad_fingerprint = report
        .transactions
        .iter()
        .any(|t| t.fingerprint_valid == Some(false));

    let mut widths: Vec<usize> = vec![24, 16, 22, 22, 5, 14, 9, 22];
    let mut headers: Vec<String> = [
        "Transaction",
        "Method",
        "Client",
        "Server",
        "Reqs",
        "Response",
        "RTT",
        "Mapped Address",
    ]
    .iter()
    .map(|h| (*h).to_string())
    .collect();
    if relayed {
        widths.push(22);
        headers.push("Relayed Address".to_string());
    }
    if ice {
        widths.push(12);
        headers.push("Role".to_string());
    }
    if bad_fingerprint {
        widths.push(4);
        headers.push("FP".to_string());
    }

    out.push_str(&row(md, &widths, &headers));
    out.push_str(&rule(md, &widths));

    for tx in &report.transactions {
        let mut cells = vec![
            tx.transaction_id.clone(),
            tx.method_name.clone(),
            tx.client.to_string(),
            tx.server.to_string(),
            tx.request_count.to_string(),
            response_str(tx),
            tx.rtt_ms
                .map(|ms| format!("{ms:.1}ms"))
                .unwrap_or_else(|| "-".to_string()),
            addr_cell(tx.mapped_address),
        ];
        if relayed {
            cells.push(addr_cell(tx.relayed_address));
        }
        if ice {
            cells.push(match tx.ice_role {
                Some(crate::stun::IceRole::Controlling) => "controlling".to_string(),
                Some(crate::stun::IceRole::Controlled) => "controlled".to_string(),
                None => "-".to_string(),
            });
        }
        if bad_fingerprint {
            // Only the failure is named. `None` renders as a dash rather than
            // as "ok", because sipnab did not check a message that carried no
            // FINGERPRINT and must not imply it did.
            cells.push(match tx.fingerprint_valid {
                Some(false) => "BAD".to_string(),
                Some(true) => "ok".to_string(),
                None => "-".to_string(),
            });
        }
        out.push_str(&row(md, &widths, &cells));
    }

    // The cap is stated whenever it bit, for the reason the ICMP report states
    // its own: a silently truncated table understates the problem while
    // looking complete.
    if report.dropped > 0 {
        let _ = writeln!(
            out,
            "\n{} further transaction(s) were not retained (the capture held more than the \
             tracking cap); the packet count above stays exact.",
            report.dropped
        );
    }
}

/// One row per TURN allocation, with the lifetime that decides its fate.
fn allocation_table(report: &StunReport, md: bool, out: &mut String) {
    let _ = writeln!(out, "\nTURN Allocations ({}):", report.allocations.len());
    let widths: Vec<usize> = vec![22, 22, 22, 9, 10, 9];
    let headers: Vec<String> = [
        "Client",
        "Server",
        "Relayed Address",
        "Lifetime",
        "Refreshes",
        "Status",
    ]
    .iter()
    .map(|h| (*h).to_string())
    .collect();
    out.push_str(&row(md, &widths, &headers));
    out.push_str(&rule(md, &widths));

    for alloc in &report.allocations {
        out.push_str(&row(
            md,
            &widths,
            &[
                alloc.client.to_string(),
                alloc.server.to_string(),
                addr_cell(alloc.relayed_address),
                alloc
                    .lifetime_secs
                    .map(|s| format!("{s}s"))
                    .unwrap_or_else(|| "-".to_string()),
                alloc.refreshes.to_string(),
                allocation_status(alloc),
            ],
        ));
    }
    if report.allocations_dropped > 0 {
        let _ = writeln!(
            out,
            "\n{} further allocation(s) were not retained (the capture held more than the \
             tracking cap).",
            report.allocations_dropped
        );
    }
    if report.channel_data_frames > 0 {
        let _ = writeln!(
            out,
            "{} relayed ChannelData frame(s), {} byte(s) of application data, crossed these \
             allocations. Those bytes are also analyzed as ordinary media: the frame is \
             unwrapped and the RTP inside it reaches the stream store, so a relayed call \
             appears in the stream list rather than as a call with no media.",
            report.channel_data_frames, report.channel_data_bytes
        );
        relayed_media_prose(report, out);
    }
}

/// Say which media crossed which allocation, on which channel.
///
/// The line that closes the gap between the two halves of a relayed call. The
/// stream list already shows the media — that is what unwrapping ChannelData
/// achieved — but it shows it as packets between a phone and some socket, with
/// nothing saying that socket is a relay or which allocation was carrying
/// them. An SSRC is what both sides have in common, so naming it here is what
/// lets a reader move between the two tables.
fn relayed_media_prose(report: &StunReport, out: &mut String) {
    for alloc in &report.allocations {
        let Some(label) = alloc.relayed_media_label() else {
            continue;
        };
        let _ = writeln!(out, "  {} -> {}: {label}", alloc.client, alloc.server);
        for channel in &alloc.channels {
            if let Some(peer) = channel.peer {
                let _ = writeln!(
                    out,
                    "    channel 0x{:04x} is bound to peer {peer}",
                    channel.channel
                );
            } else if !channel.bound {
                // Not a fault, and said so: a capture that started after the
                // ChannelBind is the ordinary case, and leaving the line out
                // would make the missing peer look like missing data.
                let _ = writeln!(
                    out,
                    "    channel 0x{:04x}: no ChannelBind for it appears in this capture, so \
                     the peer behind the relay is not known",
                    channel.channel
                );
            }
        }
    }
}

/// Name the allocations that outlived the lifetime they were last granted.
fn lapsed_allocation_prose(report: &StunReport, out: &mut String) {
    let lapsed: Vec<&TurnAllocation> = report.lapsed_allocations().collect();
    if lapsed.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\n{} allocation(s) were still carrying traffic after the lifetime they were last \
         granted had run out, with no Refresh seen in between. A TURN server tears an \
         allocation down when its lifetime lapses, and the relayed media stops with it — \
         mid-call, with no SIP message to say why.",
        lapsed.len()
    );
    for alloc in lapsed.iter().take(5) {
        let _ = writeln!(
            out,
            "  {} -> {}: {} lifetime, {} refresh(es) seen, traffic continued {}s past expiry",
            alloc.client,
            alloc.server,
            alloc
                .lifetime_secs
                .map(|s| format!("{s}s"))
                .unwrap_or_else(|| "unknown".to_string()),
            alloc.refreshes,
            alloc.seconds_past_expiry().unwrap_or_default()
        );
        // What died with it. The finding is about a relay being torn down;
        // this is the audio that was on the relay when it happened, and
        // without it a reader has no route from the allocation to the call.
        if let Some(label) = alloc.relayed_media_label() {
            let _ = writeln!(out, "    media on it: {label}");
        }
    }
    if lapsed.len() > 5 {
        let _ = writeln!(out, "  ... and {} more.", lapsed.len() - 5);
    }
}

/// Say what ICE achieved: which pair won, and whether the agents agreed about
/// who was choosing.
///
/// Silent on a capture with no ICE in it, the same rule the rest of this
/// report follows. A capture holding plain STUN probes to a server has no
/// connectivity checks in it and gains no section.
fn ice_prose(report: &StunReport, out: &mut String) {
    let ice = report.ice_summary();
    if ice.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\nICE: {} connectivity check(s), {} answered.",
        ice.checks, ice.checks_answered
    );
    // The ICE reading of a silence every unanswered row below already lists
    // one by one. Stated as a CONSEQUENCE and not as a second finding: what
    // is new here is not that the checks went unanswered, it is that these
    // particular unanswered requests were checks, so ICE never completed and
    // the call has no media path at all.
    if ice.checks > 0 && ice.checks_answered == 0 {
        let _ = writeln!(
            out,
            "  Not one check was answered, so ICE never completed and no candidate pair was \
             ever validated — the call has no media path. The individual transactions are \
             listed under the unanswered transactions below."
        );
    }
    for pair in &ice.nominated {
        let mut line = format!("  nominated {} -> {}", pair.local, pair.remote);
        if let Some(role) = pair.role {
            line.push_str(&format!(" (nominated by the {} agent", role.label()));
            match pair.priority {
                Some(p) => line.push_str(&format!(", priority {p})")),
                None => line.push(')'),
            }
        }
        if let Some(rtt) = pair.rtt_ms {
            line.push_str(&format!(", {rtt:.1} ms"));
        }
        let _ = writeln!(out, "{line}");
    }
    if ice.nominated_dropped() > 0 {
        let _ = writeln!(
            out,
            "  ... and {} further nominated pair(s) not retained (the capture held more than \
             the tracking cap); the counts above stay exact.",
            ice.nominated_dropped()
        );
    }
    for conflict in &ice.role_conflicts {
        let mut line = format!("  ROLE CONFLICT {} <-> {}", conflict.a, conflict.b);
        if let Some(role) = conflict.role {
            line.push_str(&format!(": both claimed {}", role.label()));
        }
        if conflict.role_conflict_responses > 0 {
            line.push_str(&format!(
                ", {} x 487 Role Conflict",
                conflict.role_conflict_responses
            ));
        }
        line.push_str(if conflict.resolved {
            ". ICE resolved it and a pair between them was nominated anyway, so it cost a \
             round trip of repeated checks rather than the call."
        } else {
            ". No pair between them was ever nominated, so this is a candidate cause of media \
             that never started."
        });
        let _ = writeln!(out, "{line}");
    }
    if ice.role_conflicts_dropped() > 0 {
        let _ = writeln!(
            out,
            "  ... and {} further role conflict(s) not retained (the capture held more than \
             the tracking cap); the counts above stay exact.",
            ice.role_conflicts_dropped()
        );
    }
}

/// Name the probes nothing answered, and say what that costs.
fn unanswered_prose(report: &StunReport, out: &mut String) {
    let unanswered: Vec<&StunTransaction> = report.unanswered().collect();
    if unanswered.is_empty() {
        return;
    }
    let _ = writeln!(
        out,
        "\n{} transaction(s) drew no response. A client whose Binding Request goes \
         unanswered never learns its public address, so it advertises the private one \
         in its SDP — which is what a firewall silently dropping UDP to the STUN port \
         looks like from the inside.",
        unanswered.len()
    );
    for tx in unanswered.iter().take(5) {
        let _ = writeln!(
            out,
            "  {} -> {}: {} request(s), no reply{}",
            tx.client,
            tx.server,
            tx.request_count,
            if tx.was_retransmitted() {
                " (retransmitted, which by itself proves the first went unanswered)"
            } else {
                ""
            }
        );
    }
    if unanswered.len() > 5 {
        let _ = writeln!(out, "  ... and {} more.", unanswered.len() - 5);
    }
}

/// An address cell, or a dash where there is none.
fn addr_cell(addr: Option<std::net::SocketAddr>) -> String {
    addr.map(|a| a.to_string())
        .unwrap_or_else(|| "-".to_string())
}

/// The allocation `Status` cell.
fn allocation_status(alloc: &TurnAllocation) -> String {
    if alloc.released {
        "released".to_string()
    } else if alloc.expired_before_last_activity() {
        "LAPSED".to_string()
    } else {
        "active".to_string()
    }
}

/// The `Response` cell: what came back, or that nothing did.
///
/// An authentication challenge is marked here rather than in a column of its
/// own, because it is the most actionable answer of all and this is where a
/// reader is already looking: the path works and the credentials are the
/// problem, which sends the operator somewhere completely different from a
/// dropped-packet hunt.
fn response_str(tx: &StunTransaction) -> String {
    match (tx.error_code, tx.responded_at) {
        (Some(code), _) if tx.auth_challenge => format!("error {code} (auth)"),
        (Some(code), _) => format!("error {code}"),
        (None, Some(_)) => "success".to_string(),
        (None, None) => "NONE".to_string(),
    }
}

/// One table row, rendered for the requested format. Mirrors
/// [`crate::output::dialog_report`]: markdown carries values in full, text pads
/// to fixed columns.
fn row(md: bool, widths: &[usize], cells: &[String]) -> String {
    if md {
        format!("| {} |\n", cells.join(" | "))
    } else {
        let mut s = String::new();
        for (i, (c, w)) in cells.iter().zip(widths).enumerate() {
            if i > 0 {
                s.push(' ');
            }
            let _ = write!(s, "{c:<w$}");
        }
        s.push('\n');
        s
    }
}

/// The separator under a header row: markdown's `---|---`, or a dashed line as
/// wide as the fixed columns.
fn rule(md: bool, widths: &[usize]) -> String {
    if md {
        format!("|{}\n", "---|".repeat(widths.len()))
    } else {
        format!(
            "{}\n",
            "-".repeat(widths.iter().sum::<usize>() + widths.len() - 1)
        )
    }
}

/// One NDJSON line per transaction and per allocation (`--json-stun`).
///
/// One line per record rather than one object for the whole run: the records
/// are independent and a consumer streams them, which is the same shape
/// `--json-dialogs` uses. Each line carries a `record` field naming which of
/// the two it is, so a `jq` filter can select without guessing from the keys.
#[must_use]
pub fn stun_report_ndjson(report: &StunReport) -> String {
    let mut out = String::new();
    for tx in &report.transactions {
        if let Ok(mut v) = serde_json::to_value(tx) {
            if let Some(map) = v.as_object_mut() {
                map.insert("record".to_string(), "transaction".into());
            }
            let _ = writeln!(out, "{v}");
        }
    }
    for alloc in &report.allocations {
        if let Ok(mut v) = serde_json::to_value(alloc) {
            if let Some(map) = v.as_object_mut() {
                map.insert("record".to_string(), "turn_allocation".into());
                // Derived, not stored: a consumer should not have to
                // re-implement the lifetime arithmetic to learn the one thing
                // the allocation is tracked for.
                map.insert(
                    "lapsed".to_string(),
                    alloc.expired_before_last_activity().into(),
                );
            }
            let _ = writeln!(out, "{v}");
        }
    }
    // One `ice` record rather than one per pair: the counts and the lists are
    // one answer to one question, and splitting them would make a consumer
    // rebuild the denominator from the rows it happened to receive.
    let ice = report.ice_summary();
    if !ice.is_empty()
        && let Ok(mut v) = serde_json::to_value(&ice)
    {
        if let Some(map) = v.as_object_mut() {
            map.insert("record".to_string(), "ice".into());
        }
        let _ = writeln!(out, "{v}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    fn ts(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(ms).expect("valid timestamp")
    }

    fn tx(id: &str, answered: bool, requests: u32) -> StunTransaction {
        StunTransaction {
            transaction_id: id.to_string(),
            client: "192.0.2.223:5060".parse().expect("valid addr"),
            server: "198.51.100.39:3478".parse().expect("valid addr"),
            method: 0x001,
            method_name: "Binding".to_string(),
            first_request: ts(0),
            last_request: ts(0),
            request_count: requests,
            responded_at: answered.then(|| ts(7)),
            rtt_ms: answered.then_some(7.0),
            mapped_address: answered.then(|| "203.0.113.5:12262".parse().expect("valid addr")),
            relayed_address: None,
            peer_address: None,
            lifetime_secs: None,
            channel_number: None,
            error_code: None,
            auth_challenge: false,
            software: None,
            ice_role: None,
            use_candidate: false,
            priority: None,
            fingerprint_valid: None,
        }
    }

    fn report_of(transactions: Vec<StunTransaction>, packets: u64, dropped: u64) -> StunReport {
        StunReport {
            transactions,
            packets,
            dropped,
            ..StunReport::default()
        }
    }

    fn allocation(lifetime: u32, refreshed_ms: Option<i64>, last_ms: i64) -> TurnAllocation {
        TurnAllocation {
            client: "192.0.2.10:50000".parse().expect("valid addr"),
            server: "198.51.100.20:3478".parse().expect("valid addr"),
            relayed_address: Some("198.51.100.77:49160".parse().expect("valid addr")),
            lifetime_secs: Some(lifetime),
            allocated_at: ts(0),
            refreshed_at: refreshed_ms.map(ts),
            refreshes: u32::from(refreshed_ms.is_some()),
            last_activity: ts(last_ms),
            released: false,
            channels: Vec::new(),
            unattributed_frames: 0,
        }
    }

    /// No STUN means no section, not an empty header — a capture without STUN
    /// must render exactly as it did before this report existed.
    #[test]
    fn empty_report_renders_nothing() {
        assert_eq!(print_stun_report(&StunReport::default()), "");
    }

    #[test]
    fn answered_transaction_shows_mapped_address_and_rtt() {
        let report = report_of(vec![tx("aa", true, 1)], 2, 0);
        let out = print_stun_report(&report);
        assert!(out.contains("203.0.113.5:12262"), "{out}");
        assert!(out.contains("7.0ms"), "{out}");
        assert!(out.contains("success"), "{out}");
        assert!(
            !out.contains("drew no response"),
            "an answered probe must not be flagged: {out}"
        );
    }

    /// The motivating capture: a retransmitted request that never drew a
    /// reply. The table must say NONE and the prose must explain the SDP
    /// consequence, because that consequence is the whole finding.
    #[test]
    fn unanswered_retransmission_is_called_out() {
        let report = report_of(vec![tx("bb", false, 2)], 2, 0);
        let out = print_stun_report(&report);
        assert!(out.contains("NONE"), "{out}");
        assert!(out.contains("1 transaction(s) drew no response"), "{out}");
        assert!(out.contains("retransmitted"), "{out}");
        assert!(out.contains("advertises the private one"), "{out}");
    }

    /// A cap that bit must be stated. A truncated table that looks complete
    /// understates the problem.
    #[test]
    fn retention_cap_is_stated_when_it_bit() {
        let report = report_of(vec![tx("cc", true, 1)], 900, 41);
        let out = print_stun_report(&report);
        assert!(out.contains("41 further transaction(s)"), "{out}");
    }

    #[test]
    fn markdown_format_emits_a_pipe_table() {
        let report = report_of(vec![tx("dd", true, 1)], 2, 0);
        let out = print_stun_report_as(&report, crate::output::ReportFormat::Markdown);
        assert!(out.contains("| Transaction |"), "{out}");
        assert!(out.contains("|---|"), "{out}");
    }

    /// The method has to be on the row. A table of transactions that all look
    /// like Bindings cannot tell an Allocate from a connectivity check.
    #[test]
    fn transaction_row_names_the_method() {
        let mut allocate = tx("ee", true, 1);
        allocate.method = 0x003;
        allocate.method_name = "Allocate".to_string();
        let out = print_stun_report(&report_of(vec![allocate], 2, 0));
        assert!(out.contains("Method"), "{out}");
        assert!(out.contains("Allocate"), "{out}");
    }

    /// The relayed column appears only when a relay was in the capture. A
    /// column of dashes on a pure-STUN capture is noise.
    #[test]
    fn relayed_column_is_absent_until_a_relayed_address_exists() {
        let out = print_stun_report(&report_of(vec![tx("ff", true, 1)], 2, 0));
        assert!(!out.contains("Relayed Address"), "{out}");

        let mut allocate = tx("gg", true, 1);
        allocate.method_name = "Allocate".to_string();
        allocate.relayed_address = Some("198.51.100.77:49160".parse().expect("valid addr"));
        let out = print_stun_report(&report_of(vec![allocate], 2, 0));
        assert!(out.contains("Relayed Address"), "{out}");
        assert!(out.contains("198.51.100.77:49160"), "{out}");
    }

    /// The ICE role column is the same bargain: absent on a capture with no
    /// ICE in it, present when a capture holds a role conflict to find.
    #[test]
    fn ice_role_column_is_absent_until_a_role_is_claimed() {
        let out = print_stun_report(&report_of(vec![tx("hh", true, 1)], 2, 0));
        assert!(!out.contains("Role"), "{out}");

        let mut check = tx("ii", true, 1);
        check.ice_role = Some(crate::stun::IceRole::Controlling);
        let out = print_stun_report(&report_of(vec![check], 2, 0));
        assert!(out.contains("controlling"), "{out}");
    }

    /// A fingerprint that FAILED is a finding; one that passed is the normal
    /// case and gets no column. `None` must never render as a failure.
    #[test]
    fn only_a_failed_fingerprint_earns_a_column() {
        let mut good = tx("jj", true, 1);
        good.fingerprint_valid = Some(true);
        let out = print_stun_report(&report_of(vec![good], 2, 0));
        assert!(
            !out.contains("FP"),
            "a valid fingerprint says nothing: {out}"
        );

        let mut bad = tx("kk", true, 1);
        bad.fingerprint_valid = Some(false);
        let out = print_stun_report(&report_of(vec![bad], 2, 0));
        assert!(out.contains("BAD"), "{out}");
    }

    /// A 401 with a realm is a CHALLENGE, not a blocked path, and the response
    /// cell is where a reader is already looking for that.
    #[test]
    fn an_auth_challenge_is_marked_on_the_response_cell() {
        let mut challenged = tx("ll", true, 1);
        challenged.error_code = Some(401);
        challenged.auth_challenge = true;
        let out = print_stun_report(&report_of(vec![challenged], 2, 0));
        assert!(out.contains("error 401 (auth)"), "{out}");
    }

    #[test]
    fn allocation_table_states_the_lifetime_and_refreshes() {
        let report = StunReport {
            packets: 4,
            allocations: vec![allocation(600, Some(300_000), 400_000)],
            ..StunReport::default()
        };
        let out = print_stun_report(&report);
        assert!(out.contains("TURN Allocations (1)"), "{out}");
        assert!(out.contains("600s"), "{out}");
        assert!(out.contains("198.51.100.77:49160"), "{out}");
        assert!(out.contains("active"), "{out}");
        assert!(!out.contains("LAPSED"), "{out}");
    }

    /// The finding LIFETIME exists for: traffic still on the relay after the
    /// allocation could have survived. It has to be named in prose, not just
    /// implied by a status cell.
    #[test]
    fn a_lapsed_allocation_is_flagged_in_the_table_and_in_prose() {
        let report = StunReport {
            packets: 4,
            allocations: vec![allocation(600, None, 700_000)],
            ..StunReport::default()
        };
        let out = print_stun_report(&report);
        assert!(out.contains("LAPSED"), "{out}");
        assert!(
            out.contains("1 allocation(s) were still carrying traffic"),
            "{out}"
        );
        assert!(out.contains("100s past expiry"), "{out}");
        assert!(out.contains("the relayed media stops with it"), "{out}");
    }

    /// A capture whose only STUN was Send/Data indications has no transaction
    /// to table — they draw no response by design — but it is not an empty
    /// capture, and printing nothing for it would be the original defect.
    #[test]
    fn an_indication_only_capture_still_says_what_it_held() {
        let report = StunReport {
            packets: 40,
            indications: 40,
            ..StunReport::default()
        };
        let out = print_stun_report(&report);
        assert!(out.contains("40 packet(s)"), "{out}");
        assert!(out.contains("40 indication(s)"), "{out}");
    }

    /// NDJSON tags each record so a consumer never has to infer the kind from
    /// which keys happen to be present.
    #[test]
    fn ndjson_tags_every_record_with_its_kind() {
        let report = StunReport {
            packets: 4,
            transactions: vec![tx("mm", true, 1)],
            allocations: vec![allocation(600, None, 700_000)],
            ..StunReport::default()
        };
        let ndjson = stun_report_ndjson(&report);
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2, "one line per record");
        assert!(
            lines[0].contains("\"record\":\"transaction\""),
            "{}",
            lines[0]
        );
        assert!(
            lines[1].contains("\"record\":\"turn_allocation\""),
            "{}",
            lines[1]
        );
        assert!(
            lines[1].contains("\"lapsed\":true"),
            "the derived verdict must ride along: {}",
            lines[1]
        );
    }

    /// An ICE check, which is a Binding Request carrying the attributes RFC
    /// 8445 §7.2.1 requires. Built as a modification of `tx` so the two cannot
    /// drift apart in any field the ICE code does not care about.
    fn ice_check(id: &str, answered: bool, nominates: bool) -> StunTransaction {
        StunTransaction {
            priority: Some(2_130_706_431),
            ice_role: Some(crate::stun::IceRole::Controlling),
            use_candidate: nominates,
            ..tx(id, answered, 1)
        }
    }

    /// Every check going unanswered is ICE never completing, and the report
    /// says so as a CONSEQUENCE of the unanswered rows below rather than as a
    /// second finding over the same transactions.
    #[test]
    fn an_ice_exchange_where_nothing_answered_says_ice_never_completed() {
        let report = StunReport {
            packets: 3,
            transactions: vec![
                ice_check("a1", false, false),
                ice_check("a2", false, false),
                ice_check("a3", false, true),
            ],
            ..StunReport::default()
        };
        let out = print_stun_report(&report);
        assert!(
            out.contains("ICE: 3 connectivity check(s), 0 answered."),
            "{out}"
        );
        assert!(out.contains("Not one check was answered"), "{out}");
        assert!(
            out.contains("listed under the unanswered transactions below"),
            "the silence must be reported once, not twice: {out}"
        );
        assert!(
            !out.contains("nominated "),
            "an unanswered USE-CANDIDATE nominated nothing: {out}"
        );
    }

    /// A capture holding plain NAT probes has no ICE in it and must gain no
    /// ICE section — the quiet-run rule the whole report follows.
    #[test]
    fn a_capture_without_ice_gains_no_ice_section() {
        let report = report_of(vec![tx("nn", true, 1)], 2, 0);
        let out = print_stun_report(&report);
        assert!(!out.contains("ICE:"), "{out}");
    }

    /// The `ice` record rides the same NDJSON stream, tagged like the others,
    /// and appears exactly once.
    #[test]
    fn ndjson_carries_one_tagged_ice_record() {
        let report = StunReport {
            packets: 2,
            transactions: vec![ice_check("i1", true, true), ice_check("i2", true, false)],
            ..StunReport::default()
        };
        let ndjson = stun_report_ndjson(&report);
        let ice: Vec<&str> = ndjson
            .lines()
            .filter(|l| l.contains("\"record\":\"ice\""))
            .collect();
        assert_eq!(ice.len(), 1, "one ice record, not one per pair");
        assert!(ice[0].contains("\"checks\":2"), "{}", ice[0]);
        assert!(ice[0].contains("\"nominated_total\":1"), "{}", ice[0]);
    }
}
