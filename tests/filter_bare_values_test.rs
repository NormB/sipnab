// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A filter value may be written without quotes, on every surface.
//!
//! `method == INVITE`, `method == 'INVITE'` and `method == "INVITE"` are one
//! filter. Before this, the bare form was refused with "unexpected input at
//! position 10", and an MCP client that sent `list_dialogs` the filter
//! `method == INVITE` got an error instead of its rows. Every surface compiles
//! a filter through the one parser, so each is checked here to select the same
//! dialogs for the bare text as for the quoted text.
//!
//! The fixture, `tests/pcap-samples/b2bua-asterisk.pcapng`, holds 12 dialogs:
//! 2 INVITE, 3 PUBLISH, 5 SUBSCRIBE and 2 REGISTER. One INVITE is addressed to
//! the user `2302`, a value that looks like a number on a text field. The
//! expected Call-IDs below can be checked by hand with
//! `sipnab -N -I tests/pcap-samples/b2bua-asterisk.pcapng --json-dialogs`.

#![cfg(feature = "native")]

#[path = "support/run.rs"]
mod run;

/// Any error a test can return; `?` converts into it.
type TestError = Box<dyn std::error::Error>;

const FIXTURE: &str = "tests/pcap-samples/b2bua-asterisk.pcapng";

const CALLER: &str = "b2bua-caller-synth@203.0.113.1";
const LEG: &str = "b2bua-leg-synth@203.0.113.101:5060";
const PUB_1: &str = "b2bua-pub-1-synth@203.0.113.145";
const PUB_4: &str = "b2bua-pub-4-synth@203.0.113.145";
const PUB_6: &str = "b2bua-pub-6-synth@203.0.113.145";

/// Each case: the same filter written bare, single-quoted and double-quoted,
/// and the Call-IDs all three select.
const CASES: &[([&str; 3], &[&str])] = &[
    (
        [
            "method == INVITE",
            "method == 'INVITE'",
            "method == \"INVITE\"",
        ],
        &[CALLER, LEG],
    ),
    (
        [
            "to.user == 2302",
            "to.user == '2302'",
            "to.user == \"2302\"",
        ],
        &[CALLER],
    ),
    (
        [
            "method == INVITE AND (from.user == alice)",
            "method == 'INVITE' AND (from.user == 'alice')",
            "method == \"INVITE\" AND (from.user == \"alice\")",
        ],
        &[CALLER, LEG],
    ),
    (
        [
            "call_id == b2bua-leg-synth@203.0.113.101:5060",
            "call_id == 'b2bua-leg-synth@203.0.113.101:5060'",
            "call_id == \"b2bua-leg-synth@203.0.113.101:5060\"",
        ],
        &[LEG],
    ),
    (
        [
            "method =~ ^(PUBLISH|INVITE)$",
            "method =~ '^(PUBLISH|INVITE)$'",
            "method =~ \"^(PUBLISH|INVITE)$\"",
        ],
        &[CALLER, LEG, PUB_1, PUB_4, PUB_6],
    ),
];

/// The Call-IDs, sorted, in a set of JSON dialog rows.
fn call_ids(rows: &[serde_json::Value]) -> Result<Vec<String>, TestError> {
    let mut ids: Vec<String> = rows
        .iter()
        .map(|r| -> Result<_, TestError> {
            Ok(r["call_id"].as_str().ok_or("a call_id")?.to_string())
        })
        .collect::<Result<_, TestError>>()?;
    ids.sort();
    Ok(ids)
}

/// `expected` as a sorted owned list, for comparison with [`call_ids`].
fn sorted(expected: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    v.sort();
    v
}

/// `--filter` on the command line: the bare form exits 0 and its output is
/// byte-for-byte the quoted form's, and both select the expected dialogs.
#[test]
fn cli_bare_and_quoted_filters_print_identical_output() -> Result<(), TestError> {
    let run_filter = |expr: &str| -> Result<String, TestError> {
        let (stdout, stderr, code) = run::run(
            &[
                "-N",
                "-I",
                FIXTURE,
                "--json-dialogs",
                "--quiet",
                "--no-config",
                "--filter",
                expr,
            ],
            None,
        )?;
        assert_eq!(code, Some(0), "--filter {expr:?}: {stderr}");
        Ok(stdout)
    };
    for (forms, want) in CASES {
        let outputs = forms
            .iter()
            .map(|expr| run_filter(expr))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(outputs[0], outputs[1], "{:?} vs {:?}", forms[0], forms[1]);
        assert_eq!(outputs[0], outputs[2], "{:?} vs {:?}", forms[0], forms[2]);
        let rows: Vec<serde_json::Value> = outputs[0]
            .lines()
            .filter(|l| l.starts_with('{'))
            .map(serde_json::from_str)
            .collect::<Result<_, _>>()?;
        assert_eq!(call_ids(&rows)?, sorted(want), "--filter {:?}", forms[0]);
    }
    Ok(())
}

/// MCP `list_dialogs` with `filter: "method == INVITE"` returns the rows the
/// quoted filter returns: the request a production client sent and had refused.
#[cfg(feature = "mcp")]
#[test]
fn mcp_list_dialogs_takes_a_bare_value() -> Result<(), TestError> {
    #[path = "support/mcp.rs"]
    mod mcp;

    let mut session = mcp::McpSession::start(FIXTURE, &["--no-config"])?;
    for (forms, want) in CASES {
        for expr in forms {
            let listed = session.ok("list_dialogs", serde_json::json!({"filter": expr}))?;
            let rows = listed["dialogs"].as_array().ok_or("dialogs")?.clone();
            assert_eq!(call_ids(&rows)?, sorted(want), "MCP list_dialogs {expr:?}");
        }
    }
    Ok(())
}

/// The REST `filter` query parameter takes a bare value too.
#[cfg(feature = "api")]
#[test]
fn rest_filter_takes_a_bare_value() -> Result<(), TestError> {
    #[path = "support/server.rs"]
    mod server;

    /// Percent-encode everything but RFC 3986 unreserved characters.
    fn pct(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }

    let srv = server::ApiServer::spawn_with_pcap(FIXTURE, &["--no-config"])?;
    for (forms, want) in CASES {
        for expr in forms {
            let resp = srv.get(&format!("/v1/dialogs?filter={}", pct(expr)))?;
            assert_eq!(resp.status, 200, "{expr}: {}", resp.body);
            let body = resp.json()?;
            let rows = body["dialogs"].as_array().ok_or("dialogs")?.clone();
            assert_eq!(call_ids(&rows)?, sorted(want), "REST filter {expr:?}");
        }
    }
    Ok(())
}
