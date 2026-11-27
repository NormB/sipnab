// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Finding a `Branch` tracking unit by its Call-ID.
//!
//! Under `--dialog-track branch` each transaction of a call is a unit keyed
//! `Call-ID` + newline + branch, and `get` / `find_dialog` of a Call-ID answer
//! the FIRST such unit in the store's order (or the unit keyed by the bare
//! Call-ID, which wins). That answer used to come from a scan of every key, so
//! a capture's cost grew with the square of its dialogs. These tests hold the
//! answer equal to that scan, written here as the oracle, after every step of
//! every scenario: messages, sorting, retaining, clearing, merging and
//! evicting. The cost tests hold that a lookup scans nothing.
//!
//! Every fixture is synthetic: RFC 5737 documentation addresses and
//! `example.com` names.

use super::{DialogAt, DialogStore, DialogTracking, prefix_scans_on_this_thread};
use crate::net::TransportProto;
use crate::sip::SipMessage;
use crate::sip::parser::parse_sip;
use crate::sip::sdp::SdpRead;
use crate::test_utils::build_sip_message as build_sip;
use chrono::{DateTime, TimeDelta, Utc};
use std::net::{IpAddr, Ipv4Addr};

type TestError = Box<dyn std::error::Error>;

/// The time of the first fixture message: 2024-06-15 12:00:00 UTC.
fn t0() -> Result<DateTime<Utc>, TestError> {
    Ok(
        chrono::TimeZone::with_ymd_and_hms(&Utc, 2024, 6, 15, 12, 0, 0)
            .single()
            .ok_or("a valid UTC time")?,
    )
}

/// Parse `raw` as sent `secs` after [`t0`] from 192.0.2.10 to 198.51.100.20.
fn parse(raw: &[u8], secs: i64) -> Result<SipMessage, TestError> {
    parse_sip(
        raw,
        t0()? + TimeDelta::seconds(secs),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
        5060,
        5060,
        TransportProto::Udp,
    )
    .map_err(|e| format!("the fixture should parse: {e:?}").into())
}

/// A request `method` of `call_id`, CSeq `seq`, top-Via `branch` (no
/// `;branch=` parameter at all when `branch` is `None`).
fn request(
    method: &str,
    call_id: &str,
    seq: u32,
    branch: Option<&str>,
) -> Result<SipMessage, TestError> {
    let via = match branch {
        Some(b) => format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch={b}"),
        None => "Via: SIP/2.0/UDP 192.0.2.10:5060".to_string(),
    };
    let raw = build_sip(
        &format!("{method} sip:bob@example.com SIP/2.0"),
        &[
            &via,
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} {method}"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, i64::from(seq))
}

/// A response `status` to `method` CSeq `seq` of `call_id` on `branch`.
fn response(
    status: u16,
    method: &str,
    call_id: &str,
    seq: u32,
    branch: &str,
) -> Result<SipMessage, TestError> {
    let raw = build_sip(
        &format!("SIP/2.0 {status} Status"),
        &[
            &format!("Via: SIP/2.0/UDP 192.0.2.10:5060;branch={branch}"),
            "From: <sip:alice@example.com>;tag=t1",
            "To: <sip:bob@example.com>;tag=t2",
            &format!("Call-ID: {call_id}"),
            &format!("CSeq: {seq} {method}"),
            "Content-Length: 0",
        ],
        b"",
    );
    parse(&raw, i64::from(seq) + 1)
}

/// The messages of a call with three transactions, each on its own branch:
/// INVITE and its 180 and 200, ACK, BYE and its 200.
fn call(call_id: &str) -> Result<Vec<SipMessage>, TestError> {
    Ok(vec![
        request("INVITE", call_id, 1, Some("z9hG4bK-i"))?,
        response(180, "INVITE", call_id, 1, "z9hG4bK-i")?,
        response(200, "INVITE", call_id, 1, "z9hG4bK-i")?,
        request("ACK", call_id, 1, Some("z9hG4bK-a"))?,
        request("BYE", call_id, 2, Some("z9hG4bK-b"))?,
        response(200, "BYE", call_id, 2, "z9hG4bK-b")?,
    ])
}

/// A store of `max` dialogs under Branch tracking.
fn branch_store(max: usize, rotate: bool) -> DialogStore {
    let mut store = DialogStore::new(max, rotate);
    store.set_tracking(DialogTracking::Branch);
    store
}

/// The answer the scan gave, written out: the unit under the exact key
/// `call_id`, else under `Branch` tracking the first key that starts with
/// `call_id` and a newline.
fn oracle(store: &DialogStore, call_id: &str) -> Option<DialogAt> {
    if let Some(index) = store.dialogs.get_index_of(call_id) {
        return Some(DialogAt { index, exact: true });
    }
    if store.tracking != DialogTracking::Branch {
        return None;
    }
    let prefix = format!("{call_id}\n");
    store
        .dialogs
        .keys()
        .position(|k| k.starts_with(&prefix))
        .map(|index| DialogAt {
            index,
            exact: false,
        })
}

/// `find_dialog` and `get` of each of `call_ids` agree with [`oracle`].
fn check(store: &DialogStore, call_ids: &[String], when: &str) {
    for call_id in call_ids {
        let want = oracle(store, call_id);
        assert_eq!(
            store.find_dialog(call_id),
            want,
            "{when}: find_dialog({call_id:?})"
        );
        if store.tracking == DialogTracking::Branch
            && store.dialogs.get_index_of(call_id.as_str()).is_none()
        {
            assert_eq!(
                store.first_unit_by_scan(call_id),
                want.map(|at| at.index),
                "{when}: the store's own scan for {call_id:?}"
            );
        }
        let got = store.get(call_id).map(std::ptr::from_ref);
        let expect = want
            .and_then(|at| store.dialogs.get_index(at.index))
            .map(|(_, d)| std::ptr::from_ref(d));
        assert_eq!(got, expect, "{when}: get({call_id:?})");
    }
}

/// One step of a scenario.
enum Step {
    /// Process a message on the read path.
    Read(SipMessage),
    /// Process a message as the batch runner does.
    Tracked(SipMessage),
    /// Sort the dialogs by their numbers, highest first.
    SortNewestFirst,
    /// Keep the dialogs whose method is not `method`.
    RetainNot(&'static str),
    /// Clear the store.
    Clear,
    /// Merge in a Branch store holding these messages.
    Merge(Vec<SipMessage>),
}

/// Run `steps` on `store`, checking every Call-ID in `call_ids` after each.
fn run(mut store: DialogStore, call_ids: &[&str], steps: Vec<Step>) -> DialogStore {
    let ids: Vec<String> = call_ids.iter().map(|s| (*s).to_string()).collect();
    check(&store, &ids, "before any step");
    for (n, step) in steps.into_iter().enumerate() {
        let when = match step {
            Step::Read(msg) => {
                store.process_message_read(msg, &SdpRead::Unread);
                "read"
            }
            Step::Tracked(msg) => {
                let _ = store.process_message_tracked_capped(msg, &SdpRead::Unread, 500);
                "tracked"
            }
            Step::SortNewestFirst => {
                store.sort_dialogs_by_key(|d| std::cmp::Reverse(d.number));
                "sort"
            }
            Step::RetainNot(method) => {
                store.retain(|d| d.method.as_str() != method);
                "retain"
            }
            Step::Clear => {
                store.clear();
                "clear"
            }
            Step::Merge(msgs) => {
                let mut other = branch_store(store.max_dialogs, false);
                for msg in msgs {
                    other.process_message_read(msg, &SdpRead::Unread);
                }
                store.merge([other], |_, at| at);
                "merge"
            }
        };
        check(&store, &ids, &format!("step {n} ({when})"));
    }
    store
}

/// `msgs` as read steps.
fn reads(msgs: Vec<SipMessage>) -> Vec<Step> {
    msgs.into_iter().map(Step::Read).collect()
}

/// The messages of `calls` interleaved, one message of each call in turn.
fn interleaved(calls: &[String]) -> Result<Vec<SipMessage>, TestError> {
    let mut per_call = calls
        .iter()
        .map(|id| call(id).map(Vec::into_iter))
        .collect::<Result<Vec<_>, _>>()?;
    let mut out = Vec::new();
    loop {
        let before = out.len();
        for msgs in &mut per_call {
            out.extend(msgs.next());
        }
        if out.len() == before {
            return Ok(out);
        }
    }
}

/// `n` Call-IDs `c0@example.com` ...
fn ids(n: usize) -> Vec<String> {
    (0..n).map(|i| format!("c{i}@example.com")).collect()
}

/// `ids` as string slices.
fn refs(ids: &[String]) -> Vec<&str> {
    ids.iter().map(String::as_str).collect()
}

// ── Success ──────────────────────────────────────────────────────────

/// One call, three units: each lookup finds the INVITE's unit.
#[test]
fn one_call_finds_its_first_unit() -> Result<(), TestError> {
    let store = run(
        branch_store(100, false),
        &["a@example.com"],
        reads(call("a@example.com")?),
    );
    assert_eq!(store.dialogs.len(), 3, "three units");
    assert_eq!(
        store.find_dialog("a@example.com"),
        Some(DialogAt {
            index: 0,
            exact: false
        }),
        "the INVITE's unit"
    );
    Ok(())
}

/// Ten calls one after the other.
#[test]
fn ten_calls_in_turn_each_find_their_first_unit() -> Result<(), TestError> {
    let calls = ids(10);
    let mut steps = Vec::new();
    for id in &calls {
        steps.extend(reads(call(id)?));
    }
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// Ten calls interleaved message by message.
#[test]
fn ten_interleaved_calls_each_find_their_first_unit() -> Result<(), TestError> {
    let calls = ids(10);
    run(
        branch_store(100, false),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// The batch runner's path agrees as the read path does.
#[test]
fn the_tracked_path_finds_each_first_unit() -> Result<(), TestError> {
    let calls = ids(5);
    let steps = interleaved(&calls)?
        .into_iter()
        .map(Step::Tracked)
        .collect();
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// A message without a branch keys the bare Call-ID, which wins over the
/// branch units.
#[test]
fn a_unit_under_the_bare_call_id_wins() -> Result<(), TestError> {
    let mut msgs = call("n@example.com")?;
    msgs.push(request("OPTIONS", "n@example.com", 9, None)?);
    let store = run(branch_store(100, false), &["n@example.com"], reads(msgs));
    assert_eq!(
        store.find_dialog("n@example.com").map(|at| at.exact),
        Some(true),
        "the exact key wins"
    );
    Ok(())
}

/// Retransmissions to a known unit change nothing.
#[test]
fn retransmissions_keep_the_first_unit() -> Result<(), TestError> {
    let mut msgs = call("r@example.com")?;
    msgs.extend(call("r@example.com")?);
    run(branch_store(100, false), &["r@example.com"], reads(msgs));
    Ok(())
}

/// Sorting newest first moves each call's first unit.
#[test]
fn sorting_moves_the_first_unit() -> Result<(), TestError> {
    let calls = ids(4);
    let mut steps = reads(interleaved(&calls)?);
    steps.push(Step::SortNewestFirst);
    let store = run(branch_store(100, false), &refs(&calls), steps);
    let first = store.find_dialog("c0@example.com").ok_or("found")?;
    let (key, _) = store.dialogs.get_index(first.index).ok_or("a unit")?;
    assert!(
        key.ends_with("z9hG4bK-b"),
        "after the sort the BYE's unit is first: {key:?}"
    );
    Ok(())
}

/// Removing the INVITE units makes the ACK units first.
#[test]
fn retaining_moves_the_first_unit_to_the_next() -> Result<(), TestError> {
    let calls = ids(4);
    let mut steps = reads(interleaved(&calls)?);
    steps.push(Step::RetainNot("INVITE"));
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// After a clear, new calls are found from scratch.
#[test]
fn a_cleared_store_finds_new_calls() -> Result<(), TestError> {
    let mut steps = reads(call("a@example.com")?);
    steps.push(Step::Clear);
    steps.extend(reads(call("b@example.com")?));
    run(
        branch_store(100, false),
        &["a@example.com", "b@example.com"],
        steps,
    );
    Ok(())
}

/// A merged store's calls are found.
#[test]
fn a_merged_stores_calls_are_found() -> Result<(), TestError> {
    let mut steps = reads(call("a@example.com")?);
    steps.push(Step::Merge(call("b@example.com")?));
    run(
        branch_store(100, false),
        &["a@example.com", "b@example.com"],
        steps,
    );
    Ok(())
}

/// Two stores that both saw a call merge into one set of units.
#[test]
fn a_call_seen_by_both_merged_stores_is_found() -> Result<(), TestError> {
    let msgs = call("s@example.com")?;
    let (first, second) = msgs.split_at(3);
    let mut steps = reads(second.to_vec());
    steps.push(Step::Merge(first.to_vec()));
    run(branch_store(100, false), &["s@example.com"], steps);
    Ok(())
}

/// Merging into an empty store.
#[test]
fn merging_into_an_empty_store_finds_the_calls() -> Result<(), TestError> {
    let calls = ids(3);
    run(
        branch_store(100, false),
        &refs(&calls),
        vec![Step::Merge(interleaved(&calls)?)],
    );
    Ok(())
}

/// A rotating store evicts the oldest units, the first units among them.
#[test]
fn eviction_moves_the_first_unit() -> Result<(), TestError> {
    let calls = ids(8);
    run(
        branch_store(10, true),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// A response to the INVITE after the BYE's unit exists goes to the INVITE's
/// unit, which stays first.
#[test]
fn a_late_response_keeps_the_first_unit() -> Result<(), TestError> {
    let msgs = vec![
        request("INVITE", "l@example.com", 1, Some("z9hG4bK-i"))?,
        request("BYE", "l@example.com", 2, Some("z9hG4bK-b"))?,
        response(200, "INVITE", "l@example.com", 1, "z9hG4bK-i")?,
    ];
    run(branch_store(100, false), &["l@example.com"], reads(msgs));
    Ok(())
}

/// Sorting, then more calls.
#[test]
fn calls_after_a_sort_are_found() -> Result<(), TestError> {
    let calls = ids(6);
    let (early, late) = calls.split_at(3);
    let mut steps = reads(interleaved(early)?);
    steps.push(Step::SortNewestFirst);
    steps.extend(reads(interleaved(late)?));
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// A retain that keeps everything.
#[test]
fn a_retain_that_keeps_everything_changes_nothing() -> Result<(), TestError> {
    let calls = ids(3);
    let mut steps = reads(interleaved(&calls)?);
    steps.push(Step::RetainNot("NOTIFY"));
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// Five hundred calls, 1,500 units.
#[test]
fn five_hundred_calls_each_find_their_first_unit() -> Result<(), TestError> {
    let calls = ids(500);
    run(
        branch_store(2_000, false),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// Every call is found, read and tracked messages mixed.
#[test]
fn read_and_tracked_messages_mixed_agree() -> Result<(), TestError> {
    let calls = ids(6);
    let steps = interleaved(&calls)?
        .into_iter()
        .enumerate()
        .map(|(n, m)| {
            if n % 2 == 0 {
                Step::Read(m)
            } else {
                Step::Tracked(m)
            }
        })
        .collect();
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

// ── Failure: nothing to find ─────────────────────────────────────────

/// An unknown Call-ID finds nothing.
#[test]
fn an_unknown_call_id_finds_nothing() -> Result<(), TestError> {
    let store = run(
        branch_store(100, false),
        &["a@example.com", "missing@example.com"],
        reads(call("a@example.com")?),
    );
    assert_eq!(store.find_dialog("missing@example.com"), None, "nothing");
    Ok(())
}

/// A Call-ID that is the start of another finds nothing of the other's.
#[test]
fn a_call_id_that_starts_another_finds_nothing() -> Result<(), TestError> {
    let store = run(
        branch_store(100, false),
        &["p@example.com", "p@example.com.x", "p@example"],
        reads(call("p@example.com.x")?),
    );
    assert_eq!(
        store.find_dialog("p@example.com"),
        None,
        "no unit of p@example.com"
    );
    Ok(())
}

/// A message without a Call-ID adds no unit.
#[test]
fn a_message_without_a_call_id_adds_nothing() -> Result<(), TestError> {
    let raw = build_sip(
        "OPTIONS sip:bob@example.com SIP/2.0",
        &[
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-x",
            "CSeq: 1 OPTIONS",
            "Content-Length: 0",
        ],
        b"",
    );
    let store = run(
        branch_store(100, false),
        &["a@example.com"],
        vec![Step::Read(parse(&raw, 0)?)],
    );
    assert!(store.dialogs.is_empty(), "no unit");
    Ok(())
}

/// A full store without rotation refuses a new call: nothing is found.
#[test]
fn a_call_refused_at_capacity_is_not_found() -> Result<(), TestError> {
    let mut msgs = call("a@example.com")?;
    msgs.extend(call("b@example.com")?);
    run(
        branch_store(3, false),
        &["a@example.com", "b@example.com"],
        reads(msgs),
    );
    Ok(())
}

/// A call the method filter refuses is not found.
#[test]
fn a_call_refused_by_method_is_not_found() -> Result<(), TestError> {
    let mut store = branch_store(100, false);
    store.set_drop_methods(vec!["INVITE".to_string()]);
    let store = run(store, &["a@example.com"], reads(call("a@example.com")?));
    assert_eq!(
        store.find_dialog("a@example.com").map(|at| at.exact),
        Some(false),
        "the ACK and BYE units open"
    );
    Ok(())
}

/// A call the admission matcher refuses is not found.
#[test]
fn a_call_refused_by_admission_is_not_found() -> Result<(), TestError> {
    let mut store = branch_store(100, false);
    let cli = crate::cli::Cli::parse_from_args(["sipnab", "-e", "^REGISTER"]);
    let matcher =
        crate::sip::matcher::SipMatcher::new(&cli, cli.matching_args.match_expr.as_deref())
            .map_err(|e| format!("matcher: {e:?}"))?;
    store.set_admission(Some(matcher));
    let store = run(store, &["a@example.com"], reads(call("a@example.com")?));
    assert!(store.dialogs.is_empty(), "no unit");
    Ok(())
}

/// A response with no CSeq cannot open a unit.
#[test]
fn a_message_that_cannot_open_a_unit_is_not_found() -> Result<(), TestError> {
    let raw = build_sip(
        "SIP/2.0 200 OK",
        &[
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-x",
            "Call-ID: nc@example.com",
            "Content-Length: 0",
        ],
        b"",
    );
    run(
        branch_store(100, false),
        &["nc@example.com"],
        vec![Step::Read(parse(&raw, 0)?)],
    );
    Ok(())
}

/// Removing every unit of a call leaves nothing to find.
#[test]
fn a_call_whose_units_are_all_removed_is_not_found() -> Result<(), TestError> {
    let mut steps = reads(call("a@example.com")?);
    steps.push(Step::RetainNot("INVITE"));
    steps.push(Step::RetainNot("ACK"));
    steps.push(Step::RetainNot("BYE"));
    let store = run(branch_store(100, false), &["a@example.com"], steps);
    assert!(store.dialogs.is_empty(), "every unit removed");
    Ok(())
}

/// After a clear nothing is found.
#[test]
fn nothing_is_found_after_a_clear() -> Result<(), TestError> {
    let calls = ids(3);
    let mut steps = reads(interleaved(&calls)?);
    steps.push(Step::Clear);
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// A call evicted whole is not found.
#[test]
fn an_evicted_call_is_not_found() -> Result<(), TestError> {
    let mut steps = Vec::new();
    for id in ids(5) {
        steps.extend(reads(call(&id)?));
    }
    let calls = ids(5);
    let store = run(branch_store(6, true), &refs(&calls), steps);
    assert_eq!(
        store.find_dialog("c0@example.com"),
        None,
        "the first call was evicted"
    );
    Ok(())
}

/// An empty Call-ID to look up.
#[test]
fn an_empty_call_id_finds_nothing() -> Result<(), TestError> {
    run(
        branch_store(100, false),
        &["", "a@example.com"],
        reads(call("a@example.com")?),
    );
    Ok(())
}

/// A Call-ID to look up that holds a newline.
#[test]
fn a_call_id_with_a_newline_agrees() -> Result<(), TestError> {
    run(
        branch_store(100, false),
        &[
            "a@example.com\n",
            "a@example.com\nz9hG4bK-i",
            "a@example.com\nz9hG4bK",
        ],
        reads(call("a@example.com")?),
    );
    Ok(())
}

/// Call-ID tracking finds no unit by prefix.
#[test]
fn call_id_tracking_finds_nothing_by_prefix() -> Result<(), TestError> {
    let store = run(
        DialogStore::new(100, false),
        &["a@example.com"],
        reads(call("a@example.com")?),
    );
    assert_eq!(store.dialogs.len(), 1, "one dialog under Call-ID tracking");
    Ok(())
}

/// A Call-ID that differs in case finds nothing.
#[test]
fn a_call_id_in_another_case_finds_nothing() -> Result<(), TestError> {
    let store = run(
        branch_store(100, false),
        &["Case@Example.com", "case@example.com"],
        reads(call("Case@Example.com")?),
    );
    assert_eq!(store.find_dialog("case@example.com"), None, "case matters");
    Ok(())
}

/// A capacity-refused call stays unfound while the kept call goes on.
#[test]
fn refused_calls_stay_unfound_while_the_kept_call_goes_on() -> Result<(), TestError> {
    let mut msgs = vec![request("INVITE", "k@example.com", 1, Some("z9hG4bK-i"))?];
    msgs.extend(call("x@example.com")?);
    msgs.push(request("BYE", "k@example.com", 2, Some("z9hG4bK-b"))?);
    run(
        branch_store(1, false),
        &["k@example.com", "x@example.com"],
        reads(msgs),
    );
    Ok(())
}

/// Merging an empty store adds nothing to find.
#[test]
fn merging_an_empty_store_adds_nothing() -> Result<(), TestError> {
    let mut steps = reads(call("a@example.com")?);
    steps.push(Step::Merge(Vec::new()));
    let store = run(
        branch_store(100, false),
        &["a@example.com", "b@example.com"],
        steps,
    );
    assert_eq!(store.dialogs.len(), 3, "the three units only");
    Ok(())
}

// ── Edge cases ───────────────────────────────────────────────────────

/// A rotating store of one unit.
#[test]
fn a_store_of_one_unit_rotates() -> Result<(), TestError> {
    let calls = ids(3);
    run(
        branch_store(1, true),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// Evictions in a row, one per new unit.
#[test]
fn evictions_in_a_row_keep_the_answers() -> Result<(), TestError> {
    let calls = ids(30);
    run(
        branch_store(20, true),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// A rotating store at a size where each eviction removes several units.
#[test]
fn batch_evictions_keep_the_answers() -> Result<(), TestError> {
    let calls = ids(150);
    run(
        branch_store(300, true),
        &refs(&calls),
        reads(interleaved(&calls)?),
    );
    Ok(())
}

/// Sort, retain, clear and refill in one run.
#[test]
fn sort_retain_clear_refill_keep_the_answers() -> Result<(), TestError> {
    let calls = ids(4);
    let mut steps = reads(interleaved(&calls)?);
    steps.push(Step::SortNewestFirst);
    steps.push(Step::RetainNot("ACK"));
    steps.push(Step::Clear);
    steps.extend(reads(interleaved(&calls)?));
    run(branch_store(100, false), &refs(&calls), steps);
    Ok(())
}

/// A merge, then evictions.
#[test]
fn a_merge_then_evictions_keep_the_answers() -> Result<(), TestError> {
    let calls = ids(10);
    let (a, b) = calls.split_at(5);
    let mut steps = reads(interleaved(a)?);
    steps.push(Step::Merge(interleaved(b)?));
    steps.extend(reads(interleaved(&ids(12)[10..])?));
    run(branch_store(32, true), &refs(&ids(12)), steps);
    Ok(())
}

/// A merge into a store with a method filter replays every message in read
/// order. Here the store holds a call's BYE unit and the merged store brings
/// the earlier INVITE unit, so after the replay the INVITE unit comes first.
#[test]
fn a_replayed_merge_finds_the_unit_read_first() -> Result<(), TestError> {
    let mut store = branch_store(100, false);
    store.set_drop_methods(vec!["NOTIFY".to_string()]);
    let steps = vec![
        Step::Read(request("BYE", "rp@example.com", 2, Some("z9hG4bK-b"))?),
        Step::Merge(vec![request(
            "INVITE",
            "rp@example.com",
            1,
            Some("z9hG4bK-i"),
        )?]),
    ];
    let store = run(store, &["rp@example.com"], steps);
    let first = store.find_dialog("rp@example.com").ok_or("found")?;
    let (key, _) = store.dialogs.get_index(first.index).ok_or("a unit")?;
    assert!(
        key.ends_with("z9hG4bK-i"),
        "the INVITE's unit, read first, is first: {key:?}"
    );
    Ok(())
}

/// The same branch value on two Call-IDs keys two units.
#[test]
fn the_same_branch_on_two_calls_keys_two_units() -> Result<(), TestError> {
    let mut msgs = call("a@example.com")?;
    msgs.extend(call("b@example.com")?);
    let store = run(
        branch_store(100, false),
        &["a@example.com", "b@example.com"],
        reads(msgs),
    );
    assert_eq!(store.dialogs.len(), 6, "three units each");
    Ok(())
}

/// An empty `branch=` keys the bare Call-ID.
#[test]
fn an_empty_branch_keys_the_bare_call_id() -> Result<(), TestError> {
    let msgs = vec![
        request("INVITE", "e@example.com", 1, Some(""))?,
        request("BYE", "e@example.com", 2, Some("z9hG4bK-b"))?,
    ];
    run(branch_store(100, false), &["e@example.com"], reads(msgs));
    Ok(())
}

/// A Call-ID with inner spaces.
#[test]
fn a_call_id_with_spaces_is_found() -> Result<(), TestError> {
    run(
        branch_store(100, false),
        &["sp ace@example.com"],
        reads(call("sp ace@example.com")?),
    );
    Ok(())
}

/// A Call-ID with non-ASCII characters.
#[test]
fn a_non_ascii_call_id_is_found() -> Result<(), TestError> {
    run(
        branch_store(100, false),
        &["çå-ü@example.com"],
        reads(call("çå-ü@example.com")?),
    );
    Ok(())
}

/// A Call-ID of 2,000 characters.
#[test]
fn a_very_long_call_id_is_found() -> Result<(), TestError> {
    let long = format!("{}@example.com", "x".repeat(2_000));
    run(
        branch_store(100, false),
        &[long.as_str()],
        reads(call(&long)?),
    );
    Ok(())
}

/// Two thousand calls, 6,000 units.
#[test]
fn two_thousand_calls_each_find_their_first_unit() -> Result<(), TestError> {
    let calls = ids(2_000);
    let mut store = branch_store(10_000, false);
    for msg in interleaved(&calls)? {
        store.process_message_read(msg, &SdpRead::Unread);
    }
    let all: Vec<String> = calls.clone();
    check(&store, &all, "after 12,000 messages");
    Ok(())
}

/// Messages that each open a unit with a branch never seen before.
#[test]
fn a_new_branch_per_message_keeps_the_first_unit() -> Result<(), TestError> {
    let msgs = (1..=20)
        .map(|n| request("OPTIONS", "o@example.com", n, Some(&format!("z9hG4bK-{n}"))))
        .collect::<Result<Vec<_>, _>>()?;
    let store = run(branch_store(100, false), &["o@example.com"], reads(msgs));
    assert_eq!(store.dialogs.len(), 20, "a unit per branch");
    Ok(())
}

// ── The cost: a lookup scans nothing ─────────────────────────────────

/// A Branch store of `calls` calls, three units each.
fn filled(calls: usize) -> Result<DialogStore, TestError> {
    let mut store = branch_store(calls * 3 + 10, false);
    for msg in interleaved(&ids(calls))? {
        store.process_message_read(msg, &SdpRead::Unread);
    }
    Ok(store)
}

/// How many prefix scans `f` makes on this thread.
fn scans_during<T>(f: impl FnOnce() -> T) -> (usize, T) {
    let before = prefix_scans_on_this_thread();
    let out = f();
    (prefix_scans_on_this_thread() - before, out)
}

/// `find_dialog` of a Branch call scans no key.
#[test]
fn find_dialog_under_branch_tracking_scans_nothing() -> Result<(), TestError> {
    let store = filled(300)?;
    let (scans, found) = scans_during(|| store.find_dialog("c299@example.com"));
    assert!(found.is_some(), "found");
    assert_eq!(scans, 0, "no scan of the store's keys");
    Ok(())
}

/// `get` of a Branch call scans no key.
#[test]
fn get_under_branch_tracking_scans_nothing() -> Result<(), TestError> {
    let store = filled(300)?;
    let (scans, found) = scans_during(|| store.get("c150@example.com").is_some());
    assert!(found, "found");
    assert_eq!(scans, 0, "no scan of the store's keys");
    Ok(())
}

/// A batch-runner message under Branch tracking scans no key.
#[test]
fn a_tracked_message_under_branch_tracking_scans_nothing() -> Result<(), TestError> {
    let mut store = filled(300)?;
    let msg = request("OPTIONS", "c7@example.com", 5, Some("z9hG4bK-o"))?;
    let (scans, _) =
        scans_during(|| store.process_message_tracked_capped(msg, &SdpRead::Unread, 500));
    assert_eq!(scans, 0, "no scan of the store's keys");
    Ok(())
}

/// A miss under Branch tracking scans no key either.
#[test]
fn a_miss_under_branch_tracking_scans_nothing() -> Result<(), TestError> {
    let store = filled(300)?;
    let (scans, found) = scans_during(|| store.find_dialog("none@example.com"));
    assert_eq!(found, None, "nothing");
    assert_eq!(scans, 0, "no scan of the store's keys");
    Ok(())
}
