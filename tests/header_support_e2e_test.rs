// SPDX-License-Identifier: MIT OR Apache-2.0

//! `X-` and user-defined SIP headers are first-class, end to end (RFC 6648).
//!
//! RFC 6648 deprecates the `X-` convention and, in section 2, forbids an
//! implementation to "make any assumptions about the status of a parameter,
//! nor take automatic action regarding a parameter, based solely on the
//! presence or absence of 'X-' or a similar construct in the parameter's name".
//! For a capture tool that cuts two ways. Captures full of `X-` headers must
//! read exactly like captures full of registered ones, and a header nobody
//! registered — a vendor's `P-` header, an operator's `Foo-Bar` — must reach
//! every surface an operator reads it from.
//!
//! One SYNTHETIC capture, built here, carries an `X-` header, a `P-` header, a
//! custom header, repeated headers, compact forms and a header that only a
//! later message carries. The tests follow it through every surface that
//! projects or filters on headers: the per-message JSON's `extension_headers`,
//! the `header.<name>` filter field on the CLI, the REST API and MCP, and the
//! TUI's raw message view and filter dialog. The last test is RFC 6648 section
//! 2 itself: the same header content under `X-Foo` and `Foo` produces the same
//! analysis, lint findings and JSON, name aside.
//!
//! Nothing here reads a capture from disk that the test did not write: the
//! frames are built with `support/pcap_build.rs`.

#![cfg(feature = "native")]

#[path = "support/pcap_build.rs"]
mod pcap_build;
#[path = "support/run.rs"]
mod run;

use std::path::{Path, PathBuf};

use pcap_build::{udp_frame, write_pcap};

/// Call-ID of the call that carries the interesting headers.
const CALL_A: &str = "hdr-a@test";
/// Call-ID of the control call, which carries different values.
const CALL_B: &str = "hdr-b@test";

/// The headers call A's INVITE carries beyond the standard set, exactly as they
/// cross the wire — compact forms (`k` is `Supported`, `x` is
/// `Session-Expires`) and repeats included, in this order.
const A_INVITE_EXTRA: &[&str] = &[
    "X-Trunk: north-east",
    "P-Asserted-Identity: <sip:+15551230001@example.com>",
    "Foo-Bar: custom-1",
    "k: 100rel",
    "Foo-Bar: custom-2",
    "x: 1800",
    "X-Tag: one",
    "X-Tag: two",
];

/// The one header only call A's answer carries.
const A_OK_EXTRA: &[&str] = &["X-Answer-Node: media-7"];

/// Call B's headers: the same names as call A where it matters, with values
/// that must not be confused with A's.
const B_INVITE_EXTRA: &[&str] = &["X-Trunk: south", "Foo-Bar: other"];

/// One SIP message between `from_user` and 1002 on `call_id`, carrying the
/// standard headers plus `extra` in wire order.
fn sip(first_line: &str, call_id: &str, from_user: &str, cseq: &str, extra: &[&str]) -> Vec<u8> {
    let to = if first_line.starts_with("SIP/2.0") {
        "To: <sip:1002@10.2.0.1>;tag=answer"
    } else {
        "To: <sip:1002@10.2.0.1>"
    };
    let mut lines = vec![
        first_line.to_string(),
        "Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKhdr".to_string(),
        "Max-Forwards: 70".to_string(),
        format!("From: <sip:{from_user}@10.1.0.1>;tag=from-{from_user}"),
        to.to_string(),
        format!("Call-ID: {call_id}"),
        format!("CSeq: {cseq}"),
    ];
    lines.extend(extra.iter().map(|h| (*h).to_string()));
    lines.push("Content-Length: 0".to_string());
    format!("{}\r\n\r\n", lines.join("\r\n")).into_bytes()
}

/// The synthetic capture: call A answered, call B busy.
fn headers_capture(dir: &Path) -> PathBuf {
    let a = [10, 1, 0, 1];
    let b = [10, 2, 0, 1];
    let frames = vec![
        udp_frame(
            a,
            b,
            5060,
            5060,
            &sip(
                "INVITE sip:1002@10.2.0.1 SIP/2.0",
                CALL_A,
                "1001",
                "1 INVITE",
                A_INVITE_EXTRA,
            ),
        ),
        udp_frame(
            b,
            a,
            5060,
            5060,
            &sip("SIP/2.0 200 OK", CALL_A, "1001", "1 INVITE", A_OK_EXTRA),
        ),
        udp_frame(
            a,
            b,
            5060,
            5060,
            &sip(
                "INVITE sip:1002@10.2.0.1 SIP/2.0",
                CALL_B,
                "2001",
                "1 INVITE",
                B_INVITE_EXTRA,
            ),
        ),
        udp_frame(
            b,
            a,
            5060,
            5060,
            &sip("SIP/2.0 486 Busy Here", CALL_B, "2001", "1 INVITE", &[]),
        ),
    ];
    let path = dir.join("headers.pcap");
    write_pcap(&path, &frames);
    path
}

/// Every `header.` filter this suite asks, with the calls it must select.
///
/// One case per property: case-insensitive names, the quoted form, a repeated
/// header's second value, a compact form on the wire, a compact form in the
/// filter, a header only a later message carries, absence, and a name nobody
/// sent.
const FILTER_CASES: &[(&str, &[&str])] = &[
    ("header.X-Trunk == 'north-east'", &[CALL_A]),
    ("header.x-trunk =~ '^south$'", &[CALL_B]),
    ("header.\"P-Asserted-Identity\" =~ '5551230001'", &[CALL_A]),
    ("header.Foo-Bar == 'custom-2'", &[CALL_A]),
    ("header.foo-bar == 'other'", &[CALL_B]),
    ("header.Supported == '100rel'", &[CALL_A]),
    ("header.x == '1800'", &[CALL_A]),
    ("header.Session-Expires == '1800'", &[CALL_A]),
    ("header.X-Tag == 'two'", &[CALL_A]),
    ("header.X-Answer-Node == 'media-7'", &[CALL_A]),
    ("NOT header.X-Answer-Node =~ ''", &[CALL_B]),
    ("header.X-Nobody-Sent-This =~ ''", &[]),
];

/// The Call-IDs, sorted, in a set of JSON dialog rows.
fn call_ids(rows: &[serde_json::Value]) -> Vec<String> {
    let mut ids: Vec<String> = rows
        .iter()
        .map(|r| r["call_id"].as_str().expect("a call_id").to_string())
        .collect();
    ids.sort();
    ids
}

/// `expected` as a sorted owned list, for comparison with [`call_ids`].
fn sorted(expected: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    v.sort();
    v
}

/// The JSON objects among a run's stdout lines.
fn json_lines(stdout: &str) -> Vec<serde_json::Value> {
    stdout
        .lines()
        .filter(|l| l.starts_with('{'))
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad JSON line {l}: {e}")))
        .collect()
}

/// `--json` carries every header the message did, `X-`, vendor and custom
/// alike, in wire order with repeats kept and compact names expanded.
#[test]
fn per_message_json_carries_every_header_in_wire_order() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = headers_capture(dir.path());
    let (stdout, stderr, code) = run::run(
        &[
            "-N",
            "-I",
            pcap.to_str().expect("utf-8"),
            "--json",
            "--quiet",
            "--no-config",
        ],
        None,
    );
    assert_eq!(code, Some(0), "sipnab --json failed: {stderr}");
    let messages = json_lines(&stdout);
    let invite = messages
        .iter()
        .find(|m| m["call_id"] == CALL_A && m["method"] == "INVITE")
        .unwrap_or_else(|| panic!("no INVITE for {CALL_A} in:\n{stdout}"));
    let got: Vec<&str> = invite["extension_headers"]
        .as_array()
        .expect("extension_headers")
        .iter()
        .map(|v| v.as_str().expect("a string entry"))
        .collect();
    assert_eq!(
        got,
        vec![
            "Via: SIP/2.0/UDP 10.1.0.1:5060;branch=z9hG4bKhdr",
            "Max-Forwards: 70",
            "X-Trunk: north-east",
            "P-Asserted-Identity: <sip:+15551230001@example.com>",
            "Foo-Bar: custom-1",
            "Supported: 100rel",
            "Foo-Bar: custom-2",
            "Session-Expires: 1800",
            "X-Tag: one",
            "X-Tag: two",
            "Content-Length: 0",
        ],
        "every header, in wire order, repeats kept, compact forms expanded"
    );
    let ok = messages
        .iter()
        .find(|m| m["call_id"] == CALL_A && m["status_code"] == 200)
        .expect("the 200 OK");
    assert!(
        ok["extension_headers"]
            .as_array()
            .expect("extension_headers")
            .iter()
            .any(|v| v == "X-Answer-Node: media-7"),
        "the answer's own header: {ok}"
    );
}

/// `--filter` with `header.<name>` selects by any header on the CLI, through
/// the post-capture dialog output.
#[test]
fn cli_filter_selects_by_any_named_header() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = headers_capture(dir.path());
    let pcap = pcap.to_str().expect("utf-8");
    for (expr, want) in FILTER_CASES {
        let (stdout, stderr, code) = run::run(
            &[
                "-N",
                "-I",
                pcap,
                "--json-dialogs",
                "--quiet",
                "--no-config",
                "--filter",
                expr,
            ],
            None,
        );
        assert_eq!(code, Some(0), "{expr}: {stderr}");
        let rows: Vec<serde_json::Value> = json_lines(&stdout)
            .into_iter()
            .filter(|v| v.get("msg_count").is_some())
            .collect();
        assert_eq!(call_ids(&rows), sorted(want), "--filter {expr:?}");
    }
}

/// The REST API's `filter` parameter takes the same field, and so answers the
/// same question as the CLI.
#[cfg(feature = "api")]
#[test]
fn rest_filter_selects_by_any_named_header() {
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

    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = headers_capture(dir.path());
    let srv = server::ApiServer::spawn_with_pcap(pcap.to_str().expect("utf-8"), &["--no-config"]);
    for (expr, want) in FILTER_CASES {
        let resp = srv.get(&format!("/v1/dialogs?filter={}", pct(expr)));
        assert_eq!(resp.status, 200, "{expr}: {}", resp.body);
        let body = resp.json();
        let rows = body["dialogs"].as_array().expect("dialogs").clone();
        assert_eq!(call_ids(&rows), sorted(want), "REST filter {expr:?}");
    }
    let bad = srv.get(&format!(
        "/v1/dialogs?filter={}",
        pct("header.\"a b\" == 'x'")
    ));
    assert_eq!(
        bad.status, 400,
        "a malformed header name is the caller's error"
    );
    assert!(bad.body.contains("header name"), "{}", bad.body);
}

/// MCP: the per-message projection carries every header, and `list_dialogs`
/// and `validate_filter` take the `header.` field.
#[cfg(feature = "mcp")]
#[test]
fn mcp_projects_and_filters_every_header() {
    #[path = "support/mcp.rs"]
    mod mcp;

    let dir = tempfile::tempdir().expect("tempdir");
    let pcap = headers_capture(dir.path());
    let mut session = mcp::McpSession::start(pcap.to_str().expect("utf-8"), &["--no-config"]);

    let dialog = session.ok("get_dialog", serde_json::json!({"call_id": CALL_A}));
    let invite_headers: Vec<String> = dialog["messages"][0]["extension_headers"]
        .as_array()
        .unwrap_or_else(|| panic!("extension_headers on the INVITE: {dialog}"))
        .iter()
        .map(|v| v.as_str().expect("a string").to_string())
        .collect();
    // Each entry is fenced whole on this surface — the name is the sender's
    // choice too — so look for the wire text inside each entry, in order.
    let wanted = [
        "X-Trunk: north-east",
        "P-Asserted-Identity: <sip:+15551230001@example.com>",
        "Foo-Bar: custom-1",
        "Supported: 100rel",
        "Foo-Bar: custom-2",
        "Session-Expires: 1800",
        "X-Tag: one",
        "X-Tag: two",
    ];
    let positions: Vec<usize> = wanted
        .iter()
        .map(|w| {
            invite_headers
                .iter()
                .position(|h| h.contains(w))
                .unwrap_or_else(|| panic!("{w:?} missing from {invite_headers:?}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|p| p[0] < p[1]),
        "wire order kept: {positions:?} in {invite_headers:?}"
    );
    let answer = session.ok(
        "get_message",
        serde_json::json!({"call_id": CALL_A, "index": 1}),
    );
    assert!(
        answer["extension_headers"]
            .as_array()
            .expect("extension_headers")
            .iter()
            .any(|v| v
                .as_str()
                .is_some_and(|s| s.contains("X-Answer-Node: media-7"))),
        "{answer}"
    );

    for (expr, want) in FILTER_CASES {
        let listed = session.ok("list_dialogs", serde_json::json!({"filter": expr}));
        let rows = listed["dialogs"].as_array().expect("dialogs").clone();
        assert_eq!(call_ids(&rows), sorted(want), "MCP list_dialogs {expr:?}");
        let checked = session.ok("validate_filter", serde_json::json!({"expr": expr}));
        assert_eq!(checked["valid"], true, "{expr}: {checked}");
        assert_eq!(
            checked["total_matched"].as_u64(),
            Some(want.len() as u64),
            "MCP validate_filter {expr:?}: {checked}"
        );
    }
}

/// The TUI's raw message view shows every header exactly as captured, and its
/// filter dialog's Header field selects by any header.
#[cfg(feature = "tui")]
#[test]
fn tui_shows_and_filters_every_header() {
    use crossterm::event::KeyCode;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use sipnab::tui::{App, View};

    /// The screen as text, one row per line.
    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(200, 60)).expect("terminal");
        terminal.draw(|frame| app.render(frame)).expect("draw");
        let buf = terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf.cell((x, y)).expect("cell in bounds").symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Open the capture through the file browser, as a user would.
    fn open(dir: &Path) -> App {
        let mut app = App::new_test();
        app.set_open_dir_for_test(dir.to_path_buf());
        app.handle_key(KeyCode::Char('O'));
        assert_eq!(
            app.open_entry_names_for_test(),
            vec!["..".to_string(), "headers.pcap".to_string()]
        );
        app.handle_key(KeyCode::Down);
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.visible_dialog_count(), 2, "both calls load");
        app
    }

    let dir = tempfile::tempdir().expect("tempdir");
    headers_capture(dir.path());

    // Raw view: Enter on call A opens its flow, Enter again the INVITE raw.
    let mut app = open(dir.path());
    app.handle_key(KeyCode::Enter);
    assert!(
        matches!(app.current_view(), View::CallFlow(id) if id == CALL_A),
        "Enter opens call A's flow: {:?}",
        app.current_view()
    );
    app.handle_key(KeyCode::Enter);
    let text = screen(&mut app);
    for line in A_INVITE_EXTRA {
        assert!(
            text.contains(line),
            "the raw view shows {line:?} exactly as captured:\n{text}"
        );
    }

    // Filter dialog: the Header field is text field 6, after Payload.
    for (typed, from_user) in [
        ("X-Trunk: north-east", "1001"),
        ("foo-bar: other", "2001"),
        ("k: 100rel", "1001"),
        ("X-Answer-Node", "1001"),
    ] {
        let mut app = open(dir.path());
        app.handle_key(KeyCode::F(7));
        for _ in 0..5 {
            app.handle_key(KeyCode::Tab);
        }
        for c in typed.chars() {
            app.handle_key(KeyCode::Char(c));
        }
        app.handle_key(KeyCode::Enter);
        assert_eq!(app.active_popup(), None, "{typed:?} applies and closes");
        assert_eq!(app.visible_dialog_count(), 1, "{typed:?} selects one call");
        let text = screen(&mut app);
        assert!(
            text.contains(from_user),
            "{typed:?} keeps {from_user}:\n{text}"
        );
    }
}

/// RFC 6648 section 2: no analysis, lint rule or projection treats a header
/// differently because its name begins `X-`.
///
/// For each content in a battery chosen to trip rules — a control byte, an
/// empty value, a value past the header-line cap, values shaped like a URI and
/// a Via — two captures differ ONLY in the header's name, `X-Foo` against
/// `Foo`. Every output is then compared with the `X-` name written back as the
/// plain one and the frame digest (which hashes the differing bytes) masked.
/// Both captures sit under the same file name, in two directories, so the frame
/// pointers otherwise agree.
#[test]
fn an_x_prefix_changes_no_analysis() {
    fn capture(dir: &Path, name: &str, value: &str) -> PathBuf {
        let header = format!("{name}: {value}");
        let frames = vec![
            udp_frame(
                [10, 1, 0, 1],
                [10, 2, 0, 1],
                5060,
                5060,
                &sip(
                    "INVITE sip:1002@10.2.0.1 SIP/2.0",
                    "rfc6648@test",
                    "1001",
                    "1 INVITE",
                    &[header.as_str()],
                ),
            ),
            udp_frame(
                [10, 2, 0, 1],
                [10, 1, 0, 1],
                5060,
                5060,
                &sip(
                    "SIP/2.0 486 Busy Here",
                    "rfc6648@test",
                    "1001",
                    "1 INVITE",
                    &[header.as_str()],
                ),
            ),
        ];
        let path = dir.join("same-name.pcap");
        write_pcap(&path, &frames);
        path
    }
    let digest = regex::Regex::new(r"@[0-9a-f]{16}").expect("regex");
    let long = "v".repeat(9000);
    let battery: &[&str] = &[
        "plain-value",
        "",
        "a\u{1}b",
        &long,
        "<sip:attacker@example.com>;tag=spoof",
        "SIP/2.0/UDP 203.0.113.9:5060;branch=z9hG4bKfake",
    ];
    let modes: &[&[&str]] = &[
        &["--json"],
        &["--json-dialogs"],
        &["--lint"],
        &["--json-analyze"],
    ];
    let mut compared = 0usize;
    for (x_name, plain) in [("X-Foo", "Foo"), ("X-Trunk-Hint", "Trunk-Hint")] {
        for value in battery {
            let xdir = tempfile::tempdir().expect("tempdir");
            let pdir = tempfile::tempdir().expect("tempdir");
            let xcap = capture(xdir.path(), x_name, value);
            let pcap = capture(pdir.path(), plain, value);
            for mode in modes {
                let out = |cap: &Path| {
                    let mut args = vec![
                        "-N",
                        "-I",
                        cap.to_str().expect("utf-8"),
                        "--quiet",
                        "--no-config",
                    ];
                    args.extend_from_slice(mode);
                    let (stdout, stderr, code) = run::run(&args, None);
                    assert_eq!(code, Some(0), "{mode:?}: {stderr}");
                    let dir = cap.parent().and_then(Path::to_str).expect("a utf-8 dir");
                    digest.replace_all(&stdout, "@DIGEST").replace(dir, "<dir>")
                };
                let with_x = out(&xcap).replace(x_name, plain);
                let without = out(&pcap);
                assert_eq!(
                    with_x,
                    without,
                    "{mode:?} differs between {x_name:?} and {plain:?} for value {:?}",
                    value.chars().take(40).collect::<String>()
                );
                compared += 1;
                // Not vacuous: where the header survives the parser, the
                // per-message JSON names it, and the control byte is a lint
                // finding that names it.
                if *mode == ["--json"] && value.len() < 8000 {
                    assert!(
                        without.contains(&format!("\"{plain}: ")),
                        "--json must carry {plain}: {without}"
                    );
                }
                if *mode == ["--lint"] && value.contains('\u{1}') {
                    assert!(
                        without.contains("CONTROL-BYTE") && without.contains(plain),
                        "the control byte is a finding naming {plain}: {without}"
                    );
                }
            }
        }
    }
    assert_eq!(compared, 2 * battery.len() * modes.len());
}
