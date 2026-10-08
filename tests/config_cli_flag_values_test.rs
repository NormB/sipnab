// SPDX-License-Identifier: MIT OR Apache-2.0

//! Every command-line flag, with accepted, boundary and refused values.
//!
//! [`SPECS`] has one row per long flag clap defines, and
//! `every_flag_has_exactly_one_spec_row` fails when a flag is added, removed
//! or renamed without its row, or when a row's [`Kind`] no longer matches
//! the flag's clap shape. That is how a new flag is forced into coverage.
//!
//! Each row states the values the startup pipeline accepts and refuses
//! (`support/config_cli.rs` runs parse, `Cli::validate`,
//! `bootstrap::load_config` and `bootstrap::plan`, which are the steps that
//! decide whether a setting is usable before anything runs):
//!
//! - `Switch`: presence is accepted and sets the field; `--flag=value` is
//!   refused.
//! - `Choice`: every documented value is accepted; an unknown one and the
//!   empty string are refused.
//! - `Int { lo, hi }`: `lo` and `hi` are the edges of the accepted range.
//!   Both, and a value between them, are accepted and land in the field;
//!   `lo - 1`, `hi + 1`, a non-number, a fraction and the empty string are
//!   refused.
//! - `Real`: the listed values are accepted and land in the field; the
//!   listed refusals (non-finite, out of range, not a number) are refused.
//! - `Text`: the listed values are accepted and land in the field; each
//!   listed refusal exits with the listed code.
//!
//! Every refusal is checked for the exit code and for a message that names
//! the flag (or quotes the offending value, for the input-file refusals that
//! report the path), and no value may panic. The rows were first generated
//! from the parser's observed behavior and then reviewed against each flag's
//! help text; every disagreement found in that review is a defect with its
//! own test in `config_cli_defects_test.rs`.
//!
//! Context arguments (third column) satisfy a flag's declared requirements
//! (`requires`, a certificate's key, a detector the flag feeds), so the
//! value under test is what decides the outcome.
#![cfg(feature = "full")]

#[path = "support/config_cli.rs"]
mod config_cli;

use std::collections::BTreeSet;

use clap::CommandFactory;
use config_cli::{Outcome, Stage, TestError, argv, field_debug, run, run_exact};

/// A synthetic SIP capture in the repository.
const FIXTURE: &str = "tests/fixtures/sip_call.pcap";
/// A directory of synthetic captures.
const FIXTURE_DIR: &str = "tests/fixtures";

/// The shape of a flag's value and what the row asserts about it.
#[derive(Debug)]
enum Kind {
    /// `ArgAction::SetTrue`.
    Switch,
    /// A fixed set of possible values.
    Choice,
    /// An integer, accepted from `lo` to `hi` inclusive.
    Int { lo: i128, hi: i128 },
    /// A floating-point number.
    Real {
        accept: &'static [&'static str],
        reject: &'static [&'static str],
    },
    /// Free text, a path or a structured string.
    Text {
        accept: &'static [&'static str],
        reject: &'static [(&'static str, i32)],
    },
}

/// One row per long flag: the flag, what it takes, and the context it needs.
type Spec = (&'static str, Kind, &'static [&'static str]);

/// Every long flag the CLI defines.
static SPECS: &[Spec] = &[
    (
        "device",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "input",
        Kind::Text {
            accept: &[FIXTURE, FIXTURE_DIR],
            reject: &[
                ("x", 1),
                ("", 1),
                (" ", 1),
                ("0", 1),
                ("-1", 1),
                ("abc def", 1),
                ("5060-5061", 1),
                ("5061-5060", 1),
            ],
        },
        &[],
    ),
    ("recursive", Kind::Switch, &[]),
    (
        "input-name",
        Kind::Text {
            accept: &["*.pcap", "sip_call.pcap"],
            reject: &[
                ("x", 1),
                ("", 1),
                (" ", 1),
                ("0", 1),
                ("-1", 1),
                ("abc def", 1),
                ("5060-5061", 1),
                ("5061-5060", 1),
            ],
        },
        &["-I", FIXTURE_DIR],
    ),
    (
        "output",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "buffer",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "buffer-budget",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "snaplen",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    ("capture-profile", Kind::Choice, &[]),
    (
        "limitlen",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("no-reassembly", Kind::Switch, &[]),
    ("quiet-bad-parse", Kind::Switch, &[]),
    (
        "portrange",
        Kind::Text {
            accept: &["5060-5061", "8-18"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5061-5060", 2),
                ("0-65536", 2),
            ],
        },
        &[],
    ),
    (
        "ws-portrange",
        Kind::Text {
            accept: &["5060-5061", "8-18"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5061-5060", 2),
                ("0-65536", 2),
            ],
        },
        &[],
    ),
    ("multi-device", Kind::Switch, &[]),
    ("no-rtp", Kind::Switch, &[]),
    ("rtp", Kind::Switch, &[]),
    ("no-promisc", Kind::Switch, &[]),
    (
        "bpf-file",
        Kind::Text {
            accept: &["/dev/null"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "capture-tunnels",
        Kind::Text {
            accept: &["10"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "count",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "duration",
        Kind::Text {
            accept: &["10"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "autostop",
        Kind::Text {
            accept: &["duration:10", "filesize:5"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "split",
        Kind::Text {
            accept: &["duration:10", "filesize:5"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "split-keep",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    ("replay", Kind::Switch, &[]),
    ("pcapng", Kind::Switch, &[]),
    (
        "archive-password-file",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[],
    ),
    (
        "archive-password-command",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("archive-password-stdin", Kind::Switch, &[]),
    (
        "archive-password",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "archive-password-encoding",
        Kind::Text {
            accept: &["utf-8", "cp437", "cp850", "cp1252"],
            reject: &[
                ("latin1", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &[],
    ),
    ("no-password-prompt", Kind::Switch, &[]),
    ("no-tui", Kind::Switch, &[]),
    ("calls-only", Kind::Switch, &[]),
    ("telephone-event", Kind::Switch, &[]),
    ("dtmf-cleartext", Kind::Switch, &[]),
    ("quiet", Kind::Switch, &[]),
    ("resolve", Kind::Switch, &[]),
    ("no-resolve", Kind::Switch, &[]),
    ("reverse-dns", Kind::Switch, &[]),
    ("no-reverse-dns", Kind::Switch, &[]),
    (
        "dns-cache-entries",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "names",
        Kind::Text {
            accept: &["/dev/null", FIXTURE],
            reject: &[
                ("x", 1),
                ("", 1),
                (" ", 1),
                ("/nonexistent/sipnab-x", 1),
                ("/var/tmp", 1),
            ],
        },
        &[],
    ),
    ("from-to-mode", Kind::Choice, &[]),
    (
        "strip-secrets",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "show-frame",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "notes",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "write-annotated",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &["--notes", "/nonexistent/notes"],
    ),
    (
        "match",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("ignore-case", Kind::Switch, &[]),
    ("invert", Kind::Switch, &[]),
    ("word", Kind::Switch, &[]),
    ("single-line", Kind::Switch, &[]),
    (
        "from",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "to",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "contact",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "ua",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "filter",
        Kind::Text {
            accept: &["method == \"INVITE\"", "method == \"BYE\""],
            reject: &[
                ("method == INVITE", 2),
                ("mos < 3.5", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
            ],
        },
        &[],
    ),
    ("problems", Kind::Switch, &[]),
    ("slow-setup", Kind::Switch, &[]),
    ("short-calls", Kind::Switch, &[]),
    ("one-way", Kind::Switch, &[]),
    ("nat-issues", Kind::Switch, &[]),
    ("json", Kind::Switch, &[]),
    ("json-pretty", Kind::Switch, &[]),
    ("json-dialogs", Kind::Switch, &[]),
    (
        "plugin",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[],
    ),
    ("report", Kind::Switch, &[]),
    ("stun", Kind::Switch, &[]),
    ("json-stun", Kind::Switch, &[]),
    ("analyze", Kind::Switch, &[]),
    ("json-analyze", Kind::Switch, &[]),
    ("yang-analyze", Kind::Switch, &[]),
    ("print-yang-module", Kind::Switch, &[]),
    (
        "call-report",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "export-vcon",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "export-vcon-when",
        Kind::Text {
            accept: &["method == \"INVITE\""],
            reject: &[
                ("method == INVITE", 2),
                ("mos < 3.5", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
            ],
        },
        &["--export-vcon-dir", "/var/tmp"],
    ),
    (
        "export-vcon-dir",
        Kind::Text {
            accept: &["/var/tmp/sipnab-cfgcli-x", "x", " ", "0"],
            reject: &[("", 2)],
        },
        &["--export-vcon-when", "method == \"INVITE\""],
    ),
    (
        "vcon-max-inline-media",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "content-deny-header",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "content-deny-tombstone",
        Kind::Switch,
        &["--content-deny-header", "X-Test"],
    ),
    ("vcon-digest", Kind::Switch, &[]),
    (
        "vcon-out",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &["--export-vcon", "call-1"],
    ),
    (
        "redact",
        Kind::Switch,
        &["--export-vcon", "call-1", "-I", FIXTURE],
    ),
    (
        "redact-key-file",
        Kind::Text {
            accept: &["/var/tmp/sipnab-cfgcli-x", "x", " ", "0"],
            reject: &[("", 2)],
        },
        &["--redact", "--export-vcon", "call-1", "-I", FIXTURE],
    ),
    (
        "redact-keep-prefix",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &["--redact", "--export-vcon", "call-1", "-I", FIXTURE],
    ),
    (
        "redact-map",
        Kind::Text {
            accept: &["/var/tmp/sipnab-cfgcli-x", "x", " ", "0"],
            reject: &[("", 2)],
        },
        &["--redact", "--export-vcon", "call-1", "-I", FIXTURE],
    ),
    ("markdown", Kind::Switch, &[]),
    ("hexdump", Kind::Switch, &[]),
    ("delta-time", Kind::Switch, &[]),
    ("no-delta-time", Kind::Switch, &[]),
    (
        "after",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("show-empty", Kind::Switch, &[]),
    ("proto-number", Kind::Switch, &[]),
    ("line-buffer", Kind::Switch, &[]),
    ("color", Kind::Choice, &[]),
    (
        "payload-limit",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("text-dump", Kind::Switch, &[]),
    ("no-cli-print", Kind::Switch, &[]),
    ("wireshark", Kind::Switch, &[]),
    ("lint", Kind::Switch, &[]),
    (
        "lint-fail-on",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &["--lint"],
    ),
    (
        "lint-max-per-rule",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &["--lint"],
    ),
    (
        "lint-suppress-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &["--lint"],
    ),
    ("lint-no-suppress", Kind::Switch, &["--lint"]),
    (
        "tshark-filter",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("fail2ban", Kind::Switch, &[]),
    (
        "group-by",
        Kind::Text {
            accept: &["from", "to", "call-id", "method"],
            reject: &[
                ("caller", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &[],
    ),
    (
        "max-groups",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &["--group-by", "from"],
    ),
    (
        "max-grouped-messages",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &["--group-by", "from"],
    ),
    (
        "limit",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("rotate", Kind::Switch, &[]),
    ("no-rotate", Kind::Switch, &[]),
    (
        "dialog-track",
        Kind::Text {
            accept: &["call-id", "branch"],
            reject: &[
                ("INVITE", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &[],
    ),
    ("no-dialog", Kind::Switch, &[]),
    (
        "tag",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "rtpengine-control",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "rtpproxy-control",
        Kind::Text {
            accept: &["127.0.0.1:9999", "127.0.0.1:0", "[::1]:9999"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    ("relay-stats", Kind::Switch, &[]),
    (
        "relay-stats-call",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("relay-stats-list", Kind::Switch, &[]),
    (
        "relay-compare",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("relay-stats-interval", Kind::Int { lo: 1, hi: 3600 }, &[]),
    (
        "max-streams",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "max-lost-sequences",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("quality-interval", Kind::Int { lo: 1, hi: 300 }, &[]),
    (
        "quality-threshold",
        Kind::Real {
            accept: &["1", "5"],
            reject: &[
                "-1", "0", "0.001", "0.5", "100", "101", "1e308", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    ("kill-scanner", Kind::Switch, &[]),
    ("no-kill-scanner", Kind::Switch, &[]),
    ("sandbox", Kind::Choice, &[]),
    ("seccomp", Kind::Choice, &[]),
    (
        "kill-ua",
        Kind::Text {
            accept: &["friendly-scanner", "sipvicious", "x", "0"],
            reject: &[("", 2), (" ", 2)],
        },
        &["--kill-scanner"],
    ),
    ("kill-response", Kind::Int { lo: 100, hi: 699 }, &[]),
    (
        "kill-target",
        Kind::Text {
            accept: &["127.0.0.1:9999", "127.0.0.1:0", "[::1]:9999", "10.0.0.1"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    ("kill-spoof", Kind::Choice, &[]),
    ("hep-allow-kill", Kind::Switch, &[]),
    (
        "tfps-ctl",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[],
    ),
    (
        "journal-dir",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[],
    ),
    ("journal-show", Kind::Switch, &[]),
    (
        "revert-actions",
        Kind::Text {
            accept: &["x", "0", "-1", "abc def"],
            reject: &[("", 2), (" ", 2)],
        },
        &[],
    ),
    (
        "allow-action",
        Kind::Text {
            accept: &["tfps:rest", "tfps:mcp", "tfps:rest,mcp"],
            reject: &[
                ("tfps", 2),
                ("tfps:ban", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
            ],
        },
        &[],
    ),
    ("fraud-detect", Kind::Switch, &[]),
    ("no-fraud-detect", Kind::Switch, &[]),
    (
        "evidence-out",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "fraud-destination",
        Kind::Text {
            accept: &["CU", "DO,VG,MA", "", " "],
            reject: &[
                ("US", 2),
                ("x", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
                ("0-65536", 2),
            ],
        },
        &[],
    ),
    ("reg-flood", Kind::Switch, &[]),
    (
        "reg-flood-threshold",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    ("reg-flood-window", Kind::Int { lo: 1, hi: 3600 }, &[]),
    (
        "reg-flood-transaction-timeout",
        Kind::Int {
            lo: 1000,
            hi: 600000,
        },
        &[],
    ),
    (
        "kill-rate-limit",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "business-hours",
        Kind::Text {
            accept: &["8-18", "22-6", "0-23"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &[],
    ),
    (
        "fraud-short-call",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "fraud-wangiri-calls",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "fraud-sequential-calls",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "fraud-volume-multiplier",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "leg-correlation-window",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "active-idle-window",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "fraud-volume-min-calls",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "fraud-volume-window",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "fraud-wangiri-window",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "scanner-behavioral-probes",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "scanner-enumeration-targets",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "scanner-rejected-probes",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "scanner-unanswered-probes",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "scanner-window",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "scanner-established-factor",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "scanner-answer-grace",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "findings-history",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("digest-leak", Kind::Switch, &[]),
    (
        "alert",
        Kind::Text {
            accept: &["syslog", "json", "scanner:5/60s"],
            reject: &[
                ("jsno", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &[],
    ),
    (
        "alert-exec",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("stir-shaken", Kind::Switch, &[]),
    ("syslog", Kind::Switch, &[]),
    ("alert-json", Kind::Switch, &[]),
    (
        "run-provenance-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "tui-audit-file",
        Kind::Text {
            accept: &["/var/tmp/sipnab-cfgcli-x", "x", "", " "],
            reject: &[],
        },
        &[],
    ),
    ("recommend-block", Kind::Choice, &[]),
    (
        "on-dialog-exec",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "on-quality-exec",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "exec-rate-limit",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "exec-queue-depth",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "metrics",
        Kind::Text {
            accept: &["0", "10", "127.0.0.1:9999", "127.0.0.1:0"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
                ("0-65536", 2),
            ],
        },
        &[],
    ),
    (
        "metrics-auth",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "metrics-auth-file",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[],
    ),
    (
        "metrics-tls-cert",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--metrics-tls-key",
            "/nonexistent/sipnab-key",
            "--metrics",
            "127.0.0.1:0",
        ],
    ),
    (
        "metrics-tls-key",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--metrics-tls-cert",
            "/nonexistent/sipnab-cert",
            "--metrics",
            "127.0.0.1:0",
        ],
    ),
    (
        "api",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "api-key",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "api-signing-key",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "api-signing-key-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "api-revoked-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "api-token-ttl",
        Kind::Int {
            lo: i64::MIN as i128,
            hi: 9223372036854775807,
        },
        &[],
    ),
    (
        "api-tls-cert",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--api",
            "127.0.0.1:0",
            "--api-tls-key",
            "/nonexistent/sipnab-key",
        ],
    ),
    (
        "api-tls-key",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--api",
            "127.0.0.1:0",
            "--api-tls-cert",
            "/nonexistent/sipnab-cert",
        ],
    ),
    (
        "api-max-conn",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "api-allowed-host",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "metrics-max-conn",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "api-max-rows",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("api-allow-relay-query", Kind::Switch, &[]),
    (
        "api-file-root",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("api-accept-archive-passwords", Kind::Switch, &[]),
    (
        "api-rate-limit-per-peer",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    ("mcp", Kind::Switch, &[]),
    ("mcp-transport", Kind::Choice, &[]),
    (
        "mcp-bind",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-token",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-token-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-tls-cert",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-tls-key",
            "/nonexistent/sipnab-key",
        ],
    ),
    (
        "mcp-tls-key",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " "],
            reject: &[("", 2)],
        },
        &[
            "--mcp",
            "--mcp-transport",
            "http",
            "--mcp-tls-cert",
            "/nonexistent/sipnab-cert",
        ],
    ),
    (
        "mcp-signing-key",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-signing-key-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-revoked-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-token-ttl",
        Kind::Int {
            lo: i64::MIN as i128,
            hi: 9223372036854775807,
        },
        &[],
    ),
    (
        "mcp-audit-file",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-max-concurrent",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "mcp-tools",
        Kind::Text {
            accept: &["full", "tls", "core", "full,tls"],
            reject: &[
                ("nonexistent-bundle", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &[],
    ),
    ("mcp-output-schemas", Kind::Choice, &[]),
    (
        "one-way-delay",
        Kind::Real {
            accept: &["0", "0.001", "0.5", "1", "5", "100", "101", "1e308"],
            reject: &["-1", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "pdd-threshold",
        Kind::Real {
            accept: &["0.001", "0.5", "1", "5", "100", "101", "1e308"],
            reject: &["-1", "0", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "ack-timeout",
        Kind::Real {
            accept: &["0.001", "0.5", "1", "5", "100", "101", "1e308"],
            reject: &["-1", "0", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "no-final-response-timeout",
        Kind::Real {
            accept: &["0.001", "0.5", "1", "5", "100", "101", "1e308"],
            reject: &["-1", "0", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "duration-asymmetry-pct",
        Kind::Real {
            accept: &["0.001", "0.5", "1", "5", "100"],
            reject: &["-1", "0", "101", "1e308", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "duration-asymmetry-secs",
        Kind::Real {
            accept: &["0.001", "0.5", "1", "5", "100", "101", "1e308"],
            reject: &["-1", "0", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "late-media-ms",
        Kind::Int {
            lo: 1,
            hi: 9223372036854775807,
        },
        &[],
    ),
    (
        "cn-suppression-ratio",
        Kind::Real {
            accept: &["0.001", "0.5", "1"],
            reject: &[
                "-1", "0", "5", "100", "101", "1e308", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    (
        "jitter-warn-ms",
        Kind::Real {
            accept: &["0", "0.001", "0.5", "1", "5"],
            reject: &["-1", "100", "101", "1e308", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "jitter-bad-ms",
        Kind::Real {
            accept: &["100", "101", "1e308"],
            reject: &[
                "-1", "0", "0.001", "0.5", "1", "5", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    (
        "loss-warn-pct",
        Kind::Real {
            accept: &["0", "0.001", "0.5", "1", "5"],
            reject: &["-1", "100", "101", "1e308", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "loss-bad-pct",
        Kind::Real {
            accept: &["1", "5", "100"],
            reject: &[
                "-1", "0", "0.001", "0.5", "101", "1e308", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    (
        "mos-warn",
        Kind::Real {
            accept: &["5", "4.5", "3"],
            reject: &[
                "-1", "0", "0.001", "0.5", "1", "100", "101", "1e308", "NaN", "inf", "-inf", "abc",
                "",
            ],
        },
        &[],
    ),
    (
        "mos-bad",
        Kind::Real {
            accept: &["0", "0.001", "0.5", "1"],
            reject: &[
                "-1", "5", "100", "101", "1e308", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    (
        "rtt-warn-ms",
        Kind::Real {
            accept: &["0", "0.001", "0.5", "1", "5", "100", "101"],
            reject: &["-1", "1e308", "NaN", "inf", "-inf", "abc", ""],
        },
        &[],
    ),
    (
        "rtt-bad-ms",
        Kind::Real {
            accept: &["1e308", "500", "300"],
            reject: &[
                "-1", "0", "0.001", "0.5", "1", "5", "100", "101", "NaN", "inf", "-inf", "abc", "",
            ],
        },
        &[],
    ),
    (
        "mcp-max-rows",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "mcp-max-body-bytes",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "mcp-max-wait-seconds",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "mcp-max-findings",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "mcp-sweep-max-files",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "mcp-sweep-deadline-ms",
        Kind::Int {
            lo: 1,
            hi: 43200000,
        },
        &[],
    ),
    (
        "mcp-rate-limit-per-peer",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    (
        "mcp-allowed-host",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-resource-url",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-file-root",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "mcp-evidence-ring",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "mcp-sampling-budget",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &[],
    ),
    ("mcp-allow-shutdown", Kind::Switch, &[]),
    ("retain-audio", Kind::Switch, &[]),
    ("mcp-allow-open-capture", Kind::Switch, &[]),
    ("mcp-allow-relay-query", Kind::Switch, &[]),
    ("mcp-allow-tls-capture", Kind::Switch, &[]),
    (
        "node-name",
        Kind::Text {
            accept: &["x", "0", "", " "],
            reject: &[],
        },
        &[],
    ),
    ("mcp-allow-save-findings", Kind::Switch, &[]),
    (
        "hep-listen",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "hep-send",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "hep-send-transport",
        Kind::Text {
            accept: &["udp", "tcp", "tls"],
            reject: &[
                ("sctp", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
            ],
        },
        &["--hep-send", "127.0.0.1:9060"],
    ),
    (
        "hep-listen-transport",
        Kind::Text {
            accept: &["udp", "tcp"],
            reject: &[
                ("tls", 2),
                ("sctp", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
            ],
        },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "hep-tls-ca",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--hep-send",
            "127.0.0.1:9060",
            "--hep-send-transport",
            "tls",
        ],
    ),
    (
        "hep-tls-extra-ca",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--hep-send",
            "127.0.0.1:9060",
            "--hep-send-transport",
            "tls",
        ],
    ),
    (
        "hep-tls-cert",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " ", "0"],
            reject: &[("", 2)],
        },
        &[
            "--hep-tls-key",
            "/nonexistent/sipnab-key",
            "--hep-listen",
            "127.0.0.1:0",
            "--hep-listen-transport",
            "tls",
        ],
    ),
    (
        "hep-tls-key",
        Kind::Text {
            accept: &["/nonexistent/sipnab-pem", "x", " ", "0"],
            reject: &[("", 2)],
        },
        &[
            "--hep-tls-cert",
            "/nonexistent/sipnab-cert",
            "--hep-listen",
            "127.0.0.1:0",
            "--hep-listen-transport",
            "tls",
        ],
    ),
    (
        "hep-id",
        Kind::Int {
            lo: 0,
            hi: 4294967295,
        },
        &["--hep-send", "127.0.0.1:9"],
    ),
    (
        "hep-auth",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "hep-auth-file",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &["--hep-send", "127.0.0.1:9"],
    ),
    (
        "hep-auth-mode",
        Kind::Text {
            accept: &["plain", "hmac", "HMAC"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
            ],
        },
        &["--hep-send", "127.0.0.1:9"],
    ),
    (
        "hep-hmac-window",
        Kind::Int { lo: 1, hi: 300 },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "hep-silence-warn",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "hep-senders",
        Kind::Switch,
        &["--hep-listen", "127.0.0.1:0"],
    ),
    ("hep-parse", Kind::Switch, &[]),
    ("no-hep-parse", Kind::Switch, &[]),
    (
        "hep-allow",
        Kind::Text {
            accept: &["192.0.2.1", "192.0.2.0/24", "2001:db8::/32"],
            reject: &[("x", 2), ("", 2), (" ", 2), ("192.0.2.0/33", 2)],
        },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "hep-rate-limit",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "hep-rate-limit-per-peer",
        Kind::Text {
            accept: &["10", "auto", "off"],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("-1", 2),
                ("abc def", 2),
                ("5060-5061", 2),
                ("5061-5060", 2),
                ("0-65536", 2),
            ],
        },
        &["--hep-listen", "127.0.0.1:0"],
    ),
    (
        "tls-key",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "keylog",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "keylog-fd",
        Kind::Int {
            lo: 0,
            hi: 2147483647,
        },
        &[],
    ),
    ("keylog-watch", Kind::Switch, &[]),
    (
        "tls-lockon-window",
        Kind::Int {
            lo: 0,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "dtls-keylog",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    (
        "srtp-keys",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("pcap-export-mode", Kind::Choice, &[]),
    ("allow-coredump", Kind::Switch, &[]),
    ("uprobe-tls", Kind::Switch, &[]),
    (
        "uprobe-library",
        Kind::Text {
            accept: &["/usr/lib/libssl.so.3"],
            reject: &[
                ("/usr/lib/libgnutls.so.30", 2),
                ("libfoo.so", 2),
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("0", 2),
                ("-1", 2),
                ("abc def", 2),
            ],
        },
        &[],
    ),
    (
        "uprobe-symbol",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("uprobe-flavor", Kind::Choice, &[]),
    ("uprobe-backend", Kind::Choice, &[]),
    ("uprobe-list", Kind::Switch, &[]),
    (
        "user",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("no-priv-drop", Kind::Switch, &[]),
    ("priv-drop", Kind::Switch, &[]),
    (
        "chroot",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("setup-caps", Kind::Switch, &[]),
    (
        "max-capture-sources",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "max-reassembly",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "reassembly-ttl",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "max-tcp-buffer",
        Kind::Int {
            lo: 8192,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "max-metadata-file-bytes",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "max-gunzip-bytes",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    (
        "cores",
        Kind::Int {
            lo: 1,
            hi: 18446744073709551615,
        },
        &[],
    ),
    ("mint-token", Kind::Switch, &[]),
    (
        "token-id",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("token-scope", Kind::Choice, &[]),
    (
        "vcon-forward",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
        ],
    ),
    (
        "vcon-forward-url",
        Kind::Text {
            accept: &[
                "http://127.0.0.1:9/x",
                "https://store.example.com/v1/vcons?ingress_list=sipnab",
            ],
            reject: &[
                ("x", 2),
                ("", 2),
                (" ", 2),
                ("ftp://127.0.0.1/x", 2),
                ("https://user:pw@store.example.com/v1", 2),
                ("https://store.example.com/v1#part", 2),
            ],
        },
        &[
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-auth-file",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-done",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-failed",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-replace-url",
        Kind::Text {
            accept: &[
                "http://127.0.0.1:9/x/{uuid}",
                "https://store.example.com/v1/vcons/{uuid}",
            ],
            reject: &[
                ("x", 2),
                ("", 2),
                ("http://127.0.0.1:9/x", 2),
                ("x{uuid}", 2),
            ],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-once",
        Kind::Switch,
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-interval",
        Kind::Int { lo: 1, hi: 3600 },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-timeout",
        Kind::Int { lo: 1, hi: 600 },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-ca",
        Kind::Text {
            accept: &["x", " ", "0", "-1"],
            reject: &[("", 2)],
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-auth",
        Kind::Text {
            accept: &["x", "Authorization: Bearer x"],
            reject: &[("", 2), (" ", 2)],
        },
        &[],
    ),
    (
        "vcon-forward-backoff-first",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
            "--vcon-forward-backoff-cap=4294967295",
        ],
    ),
    (
        "vcon-forward-backoff-cap",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
            "--vcon-forward-backoff-first=1",
        ],
    ),
    (
        "vcon-forward-max-response-head",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-max-error-body",
        Kind::Int {
            lo: 1,
            hi: 4294967295,
        },
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-kind",
        Kind::Choice,
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "vcon-forward-compat",
        Kind::Choice,
        &[
            "--vcon-forward-url",
            "http://127.0.0.1:9/x",
            "--vcon-forward-auth-file",
            "/nonexistent/auth",
            "--vcon-forward",
            "/var/tmp",
        ],
    ),
    (
        "config",
        Kind::Text {
            accept: &["x", "", " ", "0"],
            reject: &[],
        },
        &[],
    ),
    ("no-config", Kind::Switch, &[]),
    ("dump-config", Kind::Switch, &[]),
    ("panic-selftest", Kind::Switch, &[]),
    ("completions", Kind::Choice, &[]),
];

/// The argv for one value of one flag: `-N` (unless the flag is `--no-tui`
/// or needs the terminal UI), the row's context, the flag, then `-F` (unless
/// the flag is `--no-config`) so no file on the test host is read.
fn flag_argv(long: &str, ctx: &[&str], flag_token: &str) -> Vec<String> {
    let mut a = vec!["sipnab".to_string()];
    if long != "no-tui" && long != "tui-audit-file" {
        a.push("-N".to_string());
    }
    a.extend(ctx.iter().map(|s| (*s).to_string()));
    a.push(flag_token.to_string());
    if long != "no-config" {
        a.push("-F".to_string());
    }
    a
}

/// Run one `--long=value` (or bare `--long` when `value` is `None`).
fn run_flag(long: &str, ctx: &[&str], value: Option<&str>) -> Outcome {
    let token = match value {
        Some(v) => format!("--{long}={v}"),
        None => format!("--{long}"),
    };
    run_exact(&flag_argv(long, ctx, &token))
}

/// The field id clap stores `long` under.
fn field_id(long: &str) -> Option<String> {
    sipnab::cli::Cli::command()
        .get_arguments()
        .find(|a| a.get_long() == Some(long))
        .map(|a| a.get_id().to_string())
}

/// The short form of `long`, when it has one.
fn short_of(long: &str) -> Option<char> {
    sipnab::cli::Cli::command()
        .get_arguments()
        .find(|a| a.get_long() == Some(long))
        .and_then(clap::Arg::get_short)
}

/// Whether `message` names the setting: the long flag, its short form, or
/// the offending value quoted.
fn names_setting(message: &str, long: &str, value: &str) -> bool {
    if message.contains(&format!("--{long}")) {
        return true;
    }
    if let Some(s) = short_of(long)
        && message.contains(&format!("-{s}"))
    {
        return true;
    }
    !value.trim().is_empty()
        && (message.contains(&format!("'{value}'")) || message.contains(&format!("{value:?}")))
}

/// A mismatch when `o` is not an accepted run with `needle` in the field.
/// Flags that ask for a facility this build does not have, and the words the
/// refusal must carry. Off Linux, or without the `native` feature, a uprobe
/// source is refused at planning, naming the flag that asked for it (macOS
/// CI, 2026-10-07: the rows expected acceptance everywhere).
fn platform_refusal(long: &str) -> Option<&'static str> {
    let uprobes = cfg!(all(target_os = "linux", feature = "native"));
    (!uprobes && matches!(long, "uprobe-tls" | "uprobe-library")).then_some("Linux kernel uprobes")
}

fn check_accepted(long: &str, value: &str, o: &Outcome, needle: Option<&str>) -> Option<String> {
    if let Some(p) = &o.panic {
        return Some(format!("--{long}={value}: panicked: {p}"));
    }
    if let Some(words) = platform_refusal(long) {
        let named = o.message.contains(&format!("--{long}")) && o.message.contains(words);
        return (o.accepted() || o.stage != Stage::Plan || !named).then(|| {
            format!(
                "--{long}={value}: want the platform refusal naming --{long} ({words}), got {:?}/{}: {}",
                o.stage, o.code, o.message
            )
        });
    }
    if !o.accepted() {
        return Some(format!(
            "--{long}={value}: want accepted, got {:?}/{}: {}",
            o.stage, o.code, o.message
        ));
    }
    let (Some(needle), Some(cli)) = (needle, o.cli.as_deref()) else {
        return None;
    };
    let id = field_id(long)?;
    match field_debug(cli, &id) {
        Some(text) if folded(&text).contains(&folded(needle)) => None,
        Some(text) => Some(format!(
            "--{long}={value}: field {id} does not hold {needle}: {text}"
        )),
        None => Some(format!("--{long}={value}: no field {id} in the parsed Cli")),
    }
}

/// `s` lowercased with everything but letters and digits removed, so a value
/// and the enum variant or address it parses into compare equal
/// (`call-id` and `CallId`, `"[::1]:9999"` and `[::1]:9999`).
fn folded(s: &str) -> String {
    s.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// A mismatch when `o` is not a refusal with exit `code` naming the flag.
fn check_refused(long: &str, value: &str, o: &Outcome, code: i32) -> Option<String> {
    if let Some(p) = &o.panic {
        return Some(format!("--{long}={value}: panicked: {p}"));
    }
    if o.accepted() || o.stage == Stage::Informational {
        return Some(format!("--{long}={value}: want refused, was accepted"));
    }
    if o.code != code {
        return Some(format!(
            "--{long}={value}: want exit {code}, got {:?}/{}: {}",
            o.stage, o.code, o.message
        ));
    }
    if !names_setting(&o.message, long, value) {
        return Some(format!(
            "--{long}={value}: refusal does not name the flag: {}",
            o.message
        ));
    }
    None
}

/// Turn collected mismatches into a test result.
fn verdict(failures: Vec<String>) -> Result<(), TestError> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!("{} failure(s):\n{}", failures.len(), failures.join("\n")).into())
    }
}

/// The kind a flag's clap definition implies.
fn kind_name_of(arg: &clap::Arg) -> &'static str {
    if matches!(arg.get_action(), clap::ArgAction::SetTrue) {
        return "Switch";
    }
    if !arg.get_possible_values().is_empty() {
        return "Choice";
    }
    let id = arg.get_value_parser().type_id();
    let ints = [
        std::any::TypeId::of::<u64>(),
        std::any::TypeId::of::<u32>(),
        std::any::TypeId::of::<u16>(),
        std::any::TypeId::of::<usize>(),
        std::any::TypeId::of::<i64>(),
        std::any::TypeId::of::<i32>(),
    ];
    if ints.iter().any(|t| id == *t) {
        return "Int";
    }
    if id == std::any::TypeId::of::<f64>() {
        return "Real";
    }
    "Text"
}

/// The name of a row's kind.
fn kind_name(kind: &Kind) -> &'static str {
    match kind {
        Kind::Switch => "Switch",
        Kind::Choice => "Choice",
        Kind::Int { .. } => "Int",
        Kind::Real { .. } => "Real",
        Kind::Text { .. } => "Text",
    }
}

/// The registry: one row per long flag, none for a flag that does not exist,
/// and each row's kind matching the flag's clap definition. A new flag
/// without a row fails here.
#[test]
fn every_flag_has_exactly_one_spec_row() -> Result<(), TestError> {
    let cmd = sipnab::cli::Cli::command();
    let mut failures = Vec::new();
    let mut seen = BTreeSet::new();
    for (long, kind, _) in SPECS {
        if !seen.insert(*long) {
            failures.push(format!("--{long}: more than one row"));
        }
        match cmd.get_arguments().find(|a| a.get_long() == Some(long)) {
            None => failures.push(format!("--{long}: row for a flag clap does not define")),
            Some(arg) if kind_name_of(arg) != kind_name(kind) => failures.push(format!(
                "--{long}: row says {}, clap says {}",
                kind_name(kind),
                kind_name_of(arg)
            )),
            Some(_) => {}
        }
    }
    for arg in cmd.get_arguments() {
        let Some(long) = arg.get_long() else {
            continue;
        };
        if long != "help" && long != "version" && !seen.contains(long) {
            failures.push(format!("--{long}: no row in SPECS; add one"));
        }
    }
    verdict(failures)
}

/// The registry check itself, on a synthetic flag set: a missing row and a
/// stale row are both reported.
#[test]
fn registry_check_reports_missing_and_stale_rows() -> Result<(), TestError> {
    let defined: BTreeSet<&str> = ["a", "b"].into_iter().collect();
    let rows: BTreeSet<&str> = ["b", "c"].into_iter().collect();
    let missing: Vec<&&str> = defined.difference(&rows).collect();
    let stale: Vec<&&str> = rows.difference(&defined).collect();
    if missing != [&"a"] || stale != [&"c"] {
        return Err(format!("missing {missing:?} stale {stale:?}").into());
    }
    // And the real table is not trivially empty.
    if SPECS.len() < 300 {
        return Err(format!("SPECS has only {} rows", SPECS.len()).into());
    }
    Ok(())
}

/// Switches: presence is accepted and sets the field; a value is refused.
#[test]
fn switches_accept_presence_and_refuse_a_value() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        if !matches!(kind, Kind::Switch) {
            continue;
        }
        let o = run_flag(long, ctx, None);
        failures.extend(check_accepted(long, "", &o, Some("true")));
        let o = run_flag(long, ctx, Some("maybe"));
        failures.extend(check_refused(long, "maybe", &o, 2));
    }
    verdict(failures)
}

/// Choices: every documented value is accepted; others are refused.
#[test]
fn choices_accept_every_possible_value_and_refuse_others() -> Result<(), TestError> {
    let cmd = sipnab::cli::Cli::command();
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        if !matches!(kind, Kind::Choice) {
            continue;
        }
        let Some(arg) = cmd.get_arguments().find(|a| a.get_long() == Some(long)) else {
            failures.push(format!("--{long}: not defined"));
            continue;
        };
        for pv in arg.get_possible_values() {
            let o = run_flag(long, ctx, Some(pv.get_name()));
            failures.extend(check_accepted(long, pv.get_name(), &o, None));
        }
        for bad in ["BOGUS", "", "-1"] {
            let o = run_flag(long, ctx, Some(bad));
            failures.extend(check_refused(long, bad, &o, 2));
        }
    }
    verdict(failures)
}

/// Integers: both edges and the middle are accepted and land in the field;
/// one past each edge, and every non-integer, is refused.
#[test]
fn integers_accept_their_range_and_refuse_its_neighbors() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        let Kind::Int { lo, hi } = kind else {
            continue;
        };
        let mid = lo + (hi - lo) / 2;
        for v in [*lo, mid, *hi] {
            let text = v.to_string();
            let o = run_flag(long, ctx, Some(&text));
            failures.extend(check_accepted(long, &text, &o, Some(&text)));
        }
        let below = (lo - 1).to_string();
        let above = (hi + 1).to_string();
        for bad in [
            below.as_str(),
            above.as_str(),
            "abc",
            "",
            "1.5",
            "0x10",
            "1e3",
        ] {
            let o = run_flag(long, ctx, Some(bad));
            failures.extend(check_refused(long, bad, &o, 2));
        }
    }
    verdict(failures)
}

/// Reals: each accepted value lands in the field as the number it spells;
/// each refused one is refused naming the flag.
#[test]
fn reals_accept_and_refuse_their_listed_values() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        let Kind::Real { accept, reject } = kind else {
            continue;
        };
        for v in *accept {
            let parsed: f64 = v.parse()?;
            let needle = format!("{parsed:?}");
            let o = run_flag(long, ctx, Some(v));
            failures.extend(check_accepted(long, v, &o, Some(&needle)));
        }
        for bad in *reject {
            let o = run_flag(long, ctx, Some(bad));
            failures.extend(check_refused(long, bad, &o, 2));
        }
        if reject.iter().all(|r| *r != "NaN") {
            failures.push(format!("--{long}: NaN is not among the refused values"));
        }
    }
    verdict(failures)
}

/// Text: each accepted value lands in the field verbatim; each refused value
/// exits with its listed code, naming the flag.
#[test]
fn texts_accept_and_refuse_their_listed_values() -> Result<(), TestError> {
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        let Kind::Text { accept, reject } = kind else {
            continue;
        };
        for v in *accept {
            let needle = format!("{v:?}");
            let o = run_flag(long, ctx, Some(v));
            failures.extend(check_accepted(long, v, &o, Some(&needle)));
        }
        for (bad, code) in *reject {
            let o = run_flag(long, ctx, Some(bad));
            failures.extend(check_refused(long, bad, &o, *code));
        }
    }
    verdict(failures)
}

/// Every flag that takes a value refuses to be given none, except a flag
/// clap gives a value when it is bare (`default_missing_value`), which must
/// then be accepted.
#[test]
fn value_flags_refuse_a_missing_value() -> Result<(), TestError> {
    let cmd = sipnab::cli::Cli::command();
    let mut failures = Vec::new();
    let mut bare_ok = 0usize;
    for (long, kind, ctx) in SPECS {
        if matches!(kind, Kind::Switch) {
            continue;
        }
        let has_missing_default = cmd
            .get_arguments()
            .find(|a| a.get_long() == Some(long))
            .and_then(clap::Arg::get_num_args)
            .is_some_and(|r| r.min_values() == 0);
        if has_missing_default {
            bare_ok += 1;
            let o = run_flag(long, ctx, None);
            failures.extend(check_accepted(long, "", &o, None));
            continue;
        }
        let mut a = flag_argv(long, ctx, &format!("--{long}"));
        // The flag must be last, so nothing after it can be read as its value.
        a.retain(|t| t != "-F");
        a.insert(1, "-F".to_string());
        if *long == "no-config" {
            a.retain(|t| t != "-F");
        }
        let o = run_exact(&a);
        if o.panic.is_some() || o.stage != Stage::Parse || o.code != 2 {
            failures.push(format!(
                "--{long} with no value: want Parse/2, got {:?}/{} {:?}",
                o.stage, o.code, o.panic
            ));
        }
    }
    if bare_ok > 4 {
        failures.push(format!("{bare_ok} flags accept a bare form; review each"));
    }
    verdict(failures)
}

/// Values no row lists cannot panic any step, and end in exit 0, 1 or 2.
#[test]
fn hostile_values_never_panic() -> Result<(), TestError> {
    let huge = "a".repeat(65_536);
    let hostile = [
        huge.as_str(),
        "-",
        "--",
        "=",
        "%s%n%x",
        "${HOME}",
        "\u{1F600}",
        "\t",
        "\u{202E}",
        "../../../../etc/passwd",
        "18446744073709551616000",
        "-0",
        "+1",
    ];
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        if matches!(kind, Kind::Switch) {
            continue;
        }
        for v in hostile {
            let o = run_flag(long, ctx, Some(v));
            if let Some(p) = &o.panic {
                failures.push(format!(
                    "--{long}={}: panicked: {p}",
                    v.chars().take(24).collect::<String>()
                ));
            } else if !(0..=2).contains(&o.code) {
                failures.push(format!("--{long}: exit {}", o.code));
            }
        }
    }
    verdict(failures)
}

/// A value that is not UTF-8 is refused by every text flag that needs text,
/// and panics none.
#[cfg(unix)]
#[test]
fn non_utf8_values_never_panic() -> Result<(), TestError> {
    use std::os::unix::ffi::OsStringExt;
    let mut failures = Vec::new();
    for (long, kind, ctx) in SPECS {
        if matches!(kind, Kind::Switch) {
            continue;
        }
        let mut token = format!("--{long}=").into_bytes();
        token.extend([0xff, 0xfe, b'x']);
        let mut args: Vec<std::ffi::OsString> = flag_argv(long, ctx, "-F")
            .into_iter()
            .map(std::ffi::OsString::from)
            .collect();
        args.push(std::ffi::OsString::from_vec(token));
        let parsed = std::panic::catch_unwind(|| sipnab::cli::Cli::try_parse_from_args(args));
        match parsed {
            Err(_) => failures.push(format!("--{long}: non-UTF-8 value panicked the parser")),
            Ok(Err(e)) if e.exit_code() != 2 => {
                failures.push(format!("--{long}: non-UTF-8 value exit {}", e.exit_code()));
            }
            Ok(_) => {}
        }
    }
    verdict(failures)
}

/// The in-process exit codes are the binary's. For every flag, one value
/// clap refuses is given to the real binary, which must exit 2 and name the
/// flag on stderr. Only parse refusals are run this way: the binary exits on
/// them before reading anything, while a value that parses would let
/// immediate commands (`--show-frame`, `--strip-secrets`, `--setup-caps`)
/// act before validation.
#[test]
fn binary_exits_2_naming_the_flag_for_a_parse_refusal() -> Result<(), TestError> {
    let mut failures = Vec::new();
    let mut ran = 0usize;
    for (long, kind, ctx) in SPECS {
        let candidates: Vec<&str> = match kind {
            Kind::Switch => vec!["maybe"],
            Kind::Choice => vec!["BOGUS"],
            Kind::Int { .. } | Kind::Real { .. } => vec!["abc"],
            Kind::Text { reject, .. } => reject.iter().map(|(v, _)| *v).collect(),
        };
        let Some(bad) = candidates
            .into_iter()
            .find(|v| run_flag(long, ctx, Some(v)).stage == Stage::Parse)
        else {
            continue;
        };
        let args = flag_argv(long, ctx, &format!("--{long}={bad}"));
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_sipnab"))
            .args(&args[1..])
            .env("NO_COLOR", "1")
            .env_remove("SIPNAB_CONFIG")
            .output()?;
        ran += 1;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.code() != Some(2) || !stderr.contains(&format!("--{long}")) {
            failures.push(format!(
                "--{long}={bad}: binary exit {:?}, stderr: {}",
                out.status.code(),
                stderr.lines().next().unwrap_or("")
            ));
        }
    }
    if ran < 220 {
        failures.push(format!("only {ran} flags reached the binary check"));
    }
    verdict(failures)
}

/// `--hep-rate-limit-per-peer 0` is documented as the same as `off`.
#[test]
fn hep_per_peer_rate_limit_zero_means_off() -> Result<(), TestError> {
    let listen = "--hep-listen=127.0.0.1:0";
    let zero = run(&argv(&[listen, "--hep-rate-limit-per-peer=0"]), None);
    let off = run(&argv(&[listen, "--hep-rate-limit-per-peer=off"]), None);
    let (Some(z), Some(o)) = (zero.cli.as_deref(), off.cli.as_deref()) else {
        return Err(format!("refused: {} / {}", zero.message, off.message).into());
    };
    let (zf, of) = (
        field_debug(z, "hep_rate_limit_per_peer"),
        field_debug(o, "hep_rate_limit_per_peer"),
    );
    if zf.is_none() || zf != of {
        return Err(format!("0 parsed as {zf:?}, off as {of:?}").into());
    }
    Ok(())
}

// ── Declared relations ─────────────────────────────────────────────────────

/// Every row with context, given an accepted value but none of its context,
/// is refused naming the flag or one of the context flags: the context is a
/// requirement, and the matrix rows above prove it is sufficient.
#[test]
fn context_requirements_are_refused_when_missing() -> Result<(), TestError> {
    let mut failures = Vec::new();
    let mut checked = 0usize;
    for (long, kind, ctx) in SPECS {
        if ctx.is_empty() {
            continue;
        }
        let value: Option<String> = match kind {
            Kind::Switch => None,
            Kind::Choice => continue,
            Kind::Int { lo, .. } => Some(lo.to_string()),
            Kind::Real { accept, .. } => accept.first().map(|s| (*s).to_string()),
            Kind::Text { accept, .. } => accept.first().map(|s| (*s).to_string()),
        };
        checked += 1;
        let o = run_flag(long, &[], value.as_deref());
        let named = o.message.contains(&format!("--{long}"))
            || ctx.iter().any(|c| {
                c.starts_with("--") && o.message.contains(c.split('=').next().unwrap_or(c))
            });
        if o.panic.is_some() || o.accepted() || o.code != 2 || !named {
            failures.push(format!(
                "--{long} without {ctx:?}: want refused naming a flag, got {:?}/{}: {}",
                o.stage, o.code, o.message
            ));
        }
    }
    if checked < 25 {
        failures.push(format!("only {checked} rows carry context"));
    }
    verdict(failures)
}

/// Every `conflicts_with` pair clap declares is refused in both orders,
/// naming both flags, while each side alone is accepted by its own row.
#[test]
fn declared_conflicts_are_refused_in_both_orders() -> Result<(), TestError> {
    let cmd = sipnab::cli::Cli::command();
    let mut failures = Vec::new();
    let mut pairs = 0usize;
    for a in cmd.get_arguments() {
        let Some(la) = a.get_long() else {
            continue;
        };
        for b in cmd.get_arg_conflicts_with(a) {
            let Some(lb) = b.get_long() else {
                continue;
            };
            pairs += 1;
            let (ta, tb) = (first_token(la), first_token(lb));
            for (x, y) in [(&ta, &tb), (&tb, &ta)] {
                let mut args = vec!["sipnab".to_string(), "-N".to_string(), "-F".to_string()];
                args.extend(x.iter().cloned());
                // Context the first flag already brought is not repeated.
                let shared = y.first().is_some_and(|t| args.contains(t)) && y.len() > 1;
                let rest = if shared { &y[y.len() - 1..] } else { &y[..] };
                args.extend(rest.iter().cloned());
                let o = run_exact(&args);
                if o.stage != Stage::Parse
                    || o.code != 2
                    || !o.message.contains(&format!("--{la}"))
                    || !o.message.contains(&format!("--{lb}"))
                {
                    failures.push(format!(
                        "{x:?} with {y:?}: want a conflict naming both, got {:?}/{}: {}",
                        o.stage, o.code, o.message
                    ));
                }
            }
        }
    }
    if pairs < 10 {
        failures.push(format!("only {pairs} declared conflicts found"));
    }
    verdict(failures)
}

/// The tokens that give `long` its first accepted value, after its context.
fn first_token(long: &str) -> Vec<String> {
    let Some((_, kind, ctx)) = SPECS.iter().find(|(l, _, _)| *l == long) else {
        return vec![format!("--{long}")];
    };
    let mut out: Vec<String> = ctx.iter().map(|s| (*s).to_string()).collect();
    let value: Option<String> = match kind {
        Kind::Switch => None,
        Kind::Choice => sipnab::cli::Cli::command()
            .get_arguments()
            .find(|a| a.get_long() == Some(long))
            .and_then(|a| {
                a.get_possible_values()
                    .first()
                    .map(|p| p.get_name().to_string())
            }),
        Kind::Int { lo, .. } => Some(lo.to_string()),
        Kind::Real { accept, .. } | Kind::Text { accept, .. } => {
            accept.first().map(|s| (*s).to_string())
        }
    };
    out.push(match value {
        Some(v) => format!("--{long}={v}"),
        None => format!("--{long}"),
    });
    out
}

// ── Flag and key precedence ────────────────────────────────────────────────

/// What the alert settings do: the syslog and JSON channels, the exec
/// command, and the rules. A channel named in `sources` is already in the
/// two switches, so `--syslog` and `[security] alert = ["syslog"]` render
/// alike.
fn alert_effect(a: &sipnab::cli::AlertSettings) -> String {
    let rules: Vec<&String> = a.sources.iter().filter(|s| s.contains(':')).collect();
    format!(
        "syslog={} json={} exec={:?} rules={rules:?}",
        a.syslog, a.json, a.exec
    )
}

/// Everything a run decides from its command line and config, as text: every
/// public resolver on `Cli` that reads the config, and the parts of
/// `bootstrap::plan`'s result that carry a setting. Two configurations with
/// the same fingerprint run the same way, as far as startup can show.
fn fingerprint(cli: &sipnab::cli::Cli, config: &sipnab::config::Config) -> String {
    let parts = [
        format!("{:?}", cli.dialog_limit(config)),
        format!("{:?}", cli.declared_one_way_delay_ms(config)),
        format!("{:?}", cli.mcp_output_schemas(config)),
        format!("{:?}", cli.mcp_row_cap(config)),
        format!("{:?}", cli.mcp_body_cap(config)),
        format!("{:?}", cli.mcp_wait_cap(config)),
        format!("{:?}", cli.mcp_sweep_limits(config)),
        format!("{:?}", cli.lost_sequence_log_cap(config)),
        format!("{:?}", cli.quality_interval_secs(config)),
        format!("{:?}", cli.group_caps(config)),
        format!("{:?}", cli.metadata_file_byte_cap(config)),
        format!("{:?}", cli.tcp_buffer_cap(config)),
        format!("{:?}", cli.no_rtp(config)),
        format!("{:?}", cli.delta_time(config)),
        format!("{:?}", cli.no_priv_drop(config)),
        format!("{:?}", cli.fraud_detect(config)),
        format!("{:?}", cli.kill_scanner(config)),
        format!("{:?}", cli.reverse_dns(config)),
        format!("{:?}", cli.resolve_names(config)),
        format!("{:?}", cli.hep_parse(config)),
        format!("{:?}", cli.gunzip_byte_cap(config)),
        format!("{:?}", cli.dns_cache_entries(config)),
        format!("{:?}", cli.hep_hmac_window_secs(config)),
        format!("{:?}", cli.mcp_findings_cap(config)),
        format!("{:?}", cli.metrics_conn_cap(config)),
        format!("{:?}", cli.api_row_cap(config)),
        format!("{:?}", cli.api_allowed_hosts(config)),
        format!("{:?}", cli.tls_settings_problem(config)),
        format!("{:?}", cli.api_peer_rate_limit(config)),
        format!("{:?}", cli.tracked_peer_capacity(config)),
        format!("{:?}", cli.color_mode(config)),
        format!("{:?}", cli.kill_response_code(config)),
        format!("{:?}", cli.max_streams_limit(config)),
        format!("{:?}", cli.max_reassembly_limit(config)),
        format!("{:?}", cli.reassembly_ttl_secs(config)),
        format!("{:?}", cli.max_capture_sources(config)),
        format!("{:?}", cli.hep_rate_limit_resolved(config)),
        format!("{:?}", cli.reg_flood_threshold(config)),
        format!("{:?}", cli.kill_rate_limit(config)),
        format!("{:?}", cli.journal_dir(config)),
        format!("{:?}", cli.security_sweep_max_age(config)),
        format!("{:?}", cli.findings_history(config)),
        format!("{:?}", cli.leg_correlation_window_ms(config)),
        format!("{:?}", cli.active_idle_window_secs(config)),
        format!("{:?}", cli.exec_queue_depth(config)),
        format!("{:?}", cli.lint_max_per_rule(config)),
        format!("{:?}", cli.quality_bands(config)),
        format!("{:?}", cli.mcp_tool_selection(config)),
        format!("{:?}", cli.ws_port_range(config)),
        format!("{:?}", cli.api_tls_files(config)),
        format!("{:?}", cli.mcp_tls_files(config)),
        format!("{:?}", cli.metrics_tls_files(config)),
        format!("{:?}", cli.hep_tls_trust(config)),
        format!("{:?}", cli.hep_tls_files(config)),
        format!("{:?}", cli.reg_flood_policy(config)),
        format!("{:?}", cli.business_hours(config)),
        format!("{:?}", cli.action_policy(config)),
        format!("{:?}", cli.action_limits(config)),
        format!("{:?}", cli.tfps_locator(config)),
        format!("{:?}", cli.fraud_thresholds(config)),
        format!("{:?}", cli.scanner_thresholds(config)),
        format!("{:?}", cli.signaling_thresholds(config)),
        format!("{:?}", cli.alias_thresholds(config)),
        format!("{:?}", cli.asymmetry_thresholds(config)),
        // Settings whose effect shows after startup, each through the
        // resolver its consumer reads: the alert channels app::batch builds,
        // the matcher's From/To patterns, the account and directory the
        // privilege drop uses, the fraud watch list, the TUI's From/To column
        // mode, the manual name files and the node name. Each is rendered as
        // its effect, without the name of the setting it came from, so a
        // flag and its key that mean the same thing render the same.
        alert_effect(&cli.alert_settings(config)),
        format!("{:?}", cli.filter_from(config).map(|(p, _)| p)),
        format!("{:?}", cli.filter_to(config).map(|(p, _)| p)),
        format!("{:?}", sipnab::app::bootstrap::effective_user(cli, config)),
        format!(
            "{:?}",
            sipnab::app::bootstrap::effective_chroot(cli, config)
        ),
        format!("{:?}", cli.fraud_watch(config)),
        format!(
            "{:?}",
            sipnab::app::tui_mode::resolve_from_to_mode(cli, config)
        ),
        format!("{:?}", cli.names_files(config)),
        format!("{:?}", cli.node_name(config)),
        // The forwarder's settings, resolved from its flags and
        // `[vcon_forward]`; the credential's value never shows in it.
        format!(
            "{:?}",
            sipnab::app::vcon_forward::ForwardPlan::resolve(
                &cli.vcon_forward_args,
                &config.vcon_forward
            )
        ),
    ];
    let mut text = parts.join("\n");
    match sipnab::app::bootstrap::plan(cli, config) {
        Ok(p) => {
            let items = [
                format!("{:?}", p.source),
                format!("{:?}", p.input_files),
                format!("{:?}", p.capture_config),
                format!("{:?}", p.portrange),
                format!("{:?}", p.policy.split_bytes),
                format!("{:?}", p.policy.split_duration),
                format!("{:?}", p.policy.split_keep),
                format!("{:?}", p.policy.autostop_duration),
                format!("{:?}", p.policy.autostop_filesize_bytes),
                format!("{:?}", p.filter_expr),
                format!("{:?}", p.output_opts),
                format!("{:?}", p.metrics_bind),
                format!("{:?}", p.max_capture_sources),
            ];
            text.push('\n');
            text.push_str(&items.join("\n"));
        }
        Err(e) => text.push_str(&format!("\nplan refused: {}", e.message)),
    }
    text
}

/// Settings rows whose effect `fingerprint` cannot see at startup, each with
/// where its precedence is tested instead. The list must match exactly: a
/// row that becomes observable, or a new row that is not, fails
/// `flag_and_key_combine_as_settings_declares`. Empty: every row's
/// resolver is in `fingerprint`, so a new row whose key startup cannot see
/// fails until its resolver is added there (or it is listed here with the
/// test that proves it).
const PRECEDENCE_ELSEWHERE: &[(&str, &str)] = &[];

/// Two distinct accepted values for a flag row, as flag-value text (`None`
/// for a switch's presence).
fn two_values(long: &str, kind: &Kind) -> Vec<Option<String>> {
    match kind {
        Kind::Switch => vec![None],
        Kind::Choice => sipnab::cli::Cli::command()
            .get_arguments()
            .find(|a| a.get_long() == Some(long))
            .map(|a| {
                a.get_possible_values()
                    .iter()
                    .take(2)
                    .map(|p| Some(p.get_name().to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        Kind::Int { lo, hi } => {
            let second = if lo < hi { lo + 1 } else { *hi };
            vec![Some(lo.to_string()), Some(second.to_string())]
        }
        Kind::Real { accept, .. } | Kind::Text { accept, .. } => accept
            .iter()
            .take(2)
            .map(|s| Some((*s).to_string()))
            .collect(),
    }
}

/// Key literals for flags whose value is not spelled the way its key is.
/// Each maps a flag value (`None` for a switch) to the key's literal.
fn mapped_key_literal(section: &str, key: &str, v: Option<&str>) -> Option<String> {
    match (section, key, v) {
        // `--alert-json` and `--syslog` each name one `[security] alert`
        // channel.
        ("security", "alert", None) => None,
        // `--allow-action tfps:rest,mcp` is `[actions] tfps = ["rest", "mcp"]`.
        ("actions", "tfps", Some(v)) => {
            let surfaces: Vec<String> = v
                .trim_start_matches("tfps:")
                .split(',')
                .map(|s| format!("{s:?}"))
                .collect();
            Some(format!("[{}]", surfaces.join(", ")))
        }
        // `--capture-profile` picks a snaplen by name.
        ("capture", "snaplen", Some(v)) if v.parse::<u32>().is_err() => Some("1500".to_string()),
        _ => None,
    }
}

/// The TOML literal that writes flag value `v` (or `true`, for a switch) as
/// `[section] key`, trying a mapped literal, a bare literal, a string, then a
/// one-item list.
fn key_literal(section: &str, key: &str, v: Option<&str>) -> Option<String> {
    if let Some(lit) = mapped_key_literal(section, key, v) {
        return Some(lit);
    }
    let v = v.unwrap_or("true");
    let quoted = format!("{v:?}");
    let candidates = [v.to_string(), quoted.clone(), format!("[{quoted}]")];
    // Through `toml::Value` first, as the loader reads a file: a TOML
    // integer is an i64, so a u64 above i64::MAX has no key spelling.
    candidates.into_iter().find(|lit| {
        toml::from_str::<toml::Value>(&format!("[{section}]\n{key} = {lit}\n"))
            .ok()
            .and_then(|v| v.try_into::<sipnab::config::Config>().ok())
            .is_some()
    })
}

/// A parsed command line and loaded config for one precedence probe.
fn probe(
    long: &str,
    ctx: &[&str],
    flag: Option<Option<&str>>,
    key: Option<(&str, &str, &str)>,
) -> Result<String, TestError> {
    let mut args = vec!["sipnab".to_string(), "-N".to_string()];
    args.extend(ctx.iter().map(|s| (*s).to_string()));
    let mut positional = None;
    if let Some(v) = flag {
        if long.starts_with('<') {
            positional = v.map(str::to_string);
        } else {
            args.push(match v {
                Some(v) => format!("--{long}={v}"),
                None => format!("--{long}"),
            });
        }
    }
    let dir = tempfile::tempdir()?;
    let config = match key {
        Some((section, key, literal)) => {
            let path = dir.path().join("sipnab.toml");
            std::fs::write(&path, format!("[{section}]\n{key} = {literal}\n"))?;
            sipnab::config::Config::load(Some(&path.display().to_string()), false)?.config
        }
        None => sipnab::config::Config::default(),
    };
    args.push("-F".to_string());
    args.extend(positional);
    let cli = sipnab::cli::Cli::try_parse_from_args(args)?;
    Ok(fingerprint(&cli, &config))
}

/// What one settings row's four probes say, or why it could not be probed.
enum Probed {
    /// The merge rule held.
    Holds,
    /// The key changed nothing startup can see.
    Unobservable,
    /// The merge rule did not hold.
    Broken(String),
}

/// The key literals a switch row is probed with.
fn switch_key_literals(long: &str) -> Vec<String> {
    match long {
        "alert-json" => vec!["[\"json\"]".to_string()],
        "syslog" => vec!["[\"syslog\"]".to_string()],
        _ => vec!["true".to_string()],
    }
}

/// Probe one `Link::Key` row in one value order.
fn probe_row(
    long: &str,
    ctx: &[&str],
    row: (&str, &str, sipnab::settings::Merge),
    flag_value: Option<&str>,
    key_value: Option<&str>,
) -> Result<Probed, TestError> {
    let Some(lit) = key_literal(row.0, row.1, key_value) else {
        return Ok(Probed::Broken(format!("no TOML literal for {key_value:?}")));
    };
    probe_row_literal(long, ctx, row, flag_value, &lit)
}

/// Probe one `Link::Key` row with the key written as `lit`.
fn probe_row_literal(
    long: &str,
    ctx: &[&str],
    (section, key, merge): (&str, &str, sipnab::settings::Merge),
    flag_value: Option<&str>,
    lit: &str,
) -> Result<Probed, TestError> {
    use sipnab::settings::Merge;
    let k = Some((section, key, lit));
    let o0 = probe(long, ctx, None, None)?;
    let ok = probe(long, ctx, None, k)?;
    let of = probe(long, ctx, Some(flag_value), None)?;
    let ofk = probe(long, ctx, Some(flag_value), k)?;
    let switch = flag_value.is_none();
    // `Off` forces a setting off over a key that turns it on, and that is
    // observable even when "on" is the default.
    if ok == o0 && !(switch && merge == Merge::Off) {
        return Ok(Probed::Unobservable);
    }
    let holds = match merge {
        // A switch has no "off" spelling, so overriding a key that turns
        // the same thing on is the `Either` rule.
        Merge::Override if switch => ofk == of && of == ok,
        // The flag wins: adding the key changes nothing, and the key alone
        // means something else.
        Merge::Override | Merge::Off => ofk == of && ofk != ok,
        // Either turns it on, to the same effect.
        Merge::Either => ofk == of && of == ok,
        // Both contribute.
        Merge::Union => ofk != of && ofk != ok,
    };
    Ok(if holds {
        Probed::Holds
    } else {
        Probed::Broken(format!(
            "{merge:?}: flag+key {} flag, {} key",
            if ofk == of { "==" } else { "!=" },
            if ofk == ok { "==" } else { "!=" }
        ))
    })
}

/// Every flag paired with a config key combines with it as
/// `sipnab::settings::FLAGS` declares: `Override` and `Off` (the flag wins),
/// `Either` (either one turns it on, to the same effect), `Union` (both
/// contribute). Each row is probed with two distinct values in both orders,
/// so a key value that happens to equal the default cannot hide a row.
#[test]
fn flag_and_key_combine_as_settings_declares() -> Result<(), TestError> {
    use sipnab::settings::{FLAGS, Link};
    let mut failures = Vec::new();
    let mut unobservable = BTreeSet::new();
    let mut held = 0usize;
    for (flag, link) in FLAGS {
        let Link::Key(section, key, merge) = link else {
            continue;
        };
        let positional: Spec = (
            "<BPF_FILTER>",
            Kind::Text {
                accept: &["udp port 5070", "udp port 5080"],
                reject: &[],
            },
            &[],
        );
        let row = SPECS
            .iter()
            .find(|(l, _, _)| l == flag)
            .or_else(|| (*flag == "<BPF_FILTER>").then_some(&positional));
        let Some((long, kind, ctx)) = row else {
            unobservable.insert(*flag);
            continue;
        };
        let values = two_values(long, kind);
        let mut verdicts = Vec::new();
        match values.as_slice() {
            // A switch: the key is probed on and off, since one of the two
            // is the default and shows nothing.
            [None] => {
                for lit in switch_key_literals(long) {
                    verdicts.push(probe_row_literal(
                        long,
                        ctx,
                        (section, key, *merge),
                        None,
                        &lit,
                    )?);
                }
            }
            [a] => verdicts.push(probe_row(
                long,
                ctx,
                (section, key, *merge),
                a.as_deref(),
                a.as_deref(),
            )?),
            [a, b, ..] => {
                for (fv, kv) in [(a, b), (b, a)] {
                    verdicts.push(probe_row(
                        long,
                        ctx,
                        (section, key, *merge),
                        fv.as_deref(),
                        kv.as_deref(),
                    )?);
                }
            }
            [] => {}
        }
        let listed = PRECEDENCE_ELSEWHERE.iter().any(|(f, _)| f == flag);
        if verdicts.iter().any(|v| matches!(v, Probed::Holds)) {
            held += 1;
            if listed {
                failures.push(format!(
                    "--{flag}: proved here; remove it from PRECEDENCE_ELSEWHERE"
                ));
            }
        } else if listed || verdicts.iter().all(|v| matches!(v, Probed::Unobservable)) {
            // A listed row is one whose combination startup cannot show,
            // whatever the probes report about part of it.
            unobservable.insert(*flag);
        } else {
            for v in verdicts {
                if let Probed::Broken(why) = v {
                    failures.push(format!("--{flag} / [{section}] {key}: {why}"));
                }
            }
        }
    }
    let exempt: BTreeSet<&str> = PRECEDENCE_ELSEWHERE.iter().map(|(f, _)| *f).collect();
    for f in unobservable.difference(&exempt) {
        failures.push(format!(
            "--{f}: its key changes nothing startup shows; test it and list it"
        ));
    }
    for f in exempt.difference(&unobservable) {
        failures.push(format!(
            "--{f}: listed in PRECEDENCE_ELSEWHERE but not a settings row"
        ));
    }
    if held < 60 {
        failures.push(format!("only {held} rows proved their merge rule"));
    }
    verdict(failures)
}

/// A flag and its key mean the same thing: for every `Override` row and
/// every accepted value, the flag alone and the key alone give the same
/// startup fingerprint. Rows `PRECEDENCE_ELSEWHERE` lists, and values that
/// have no key spelling, are skipped and counted.
#[test]
fn a_key_means_the_same_as_its_flag() -> Result<(), TestError> {
    use sipnab::settings::{FLAGS, Link, Merge};
    let mut failures = Vec::new();
    let mut compared = 0usize;
    for (flag, link) in FLAGS {
        let Link::Key(section, key, Merge::Override) = link else {
            continue;
        };
        if PRECEDENCE_ELSEWHERE.iter().any(|(f, _)| f == flag) {
            continue;
        }
        let Some((long, kind, ctx)) = SPECS.iter().find(|(l, _, _)| l == flag) else {
            continue;
        };
        let values: Vec<Option<String>> = match kind {
            Kind::Switch => vec![None],
            Kind::Int { lo, hi } => vec![Some(lo.to_string()), Some(hi.to_string())],
            Kind::Choice => two_values(long, kind),
            Kind::Real { accept, .. } | Kind::Text { accept, .. } => {
                accept.iter().map(|s| Some((*s).to_string())).collect()
            }
        };
        for v in values {
            let Some(lit) = key_literal(section, key, v.as_deref()) else {
                continue;
            };
            // A snaplen named by a profile is not the number 1500, and
            // `--bpf-file` names a file holding the expression the key holds
            // (`bpf_file_content_means_the_key` compares those).
            if mapped_key_literal(section, key, v.as_deref()).is_some() || *flag == "bpf-file" {
                continue;
            }
            let by_flag = probe(long, ctx, Some(v.as_deref()), None)?;
            let by_key = probe(long, ctx, None, Some((section, key, &lit)))?;
            compared += 1;
            if by_flag != by_key && !by_key.contains("plan refused") {
                failures.push(format!(
                    "--{flag}={} and [{section}] {key} = {lit} differ",
                    v.as_deref().unwrap_or("")
                ));
            }
        }
    }
    if compared < 150 {
        failures.push(format!("only {compared} flag/key values compared"));
    }
    verdict(failures)
}

// ── Combinations ───────────────────────────────────────────────────────────

/// One parameter of the pairwise array: a flag and the tokens of each of its
/// levels (`None` = the flag absent).
type Param = (&'static str, Vec<Option<Vec<String>>>);

/// The switch and choice flags the pairwise array covers: every one that is
/// not an immediate command (which acts instead of running) and needs no
/// context. Each level is the flag absent, or present with one value.
fn pairwise_params() -> Vec<Param> {
    use sipnab::settings::{FLAGS, Link};
    let cmd = sipnab::cli::Cli::command();
    let mut params = Vec::new();
    for (long, kind, ctx) in SPECS {
        let action = FLAGS
            .iter()
            .any(|(f, l)| f == long && matches!(l, Link::Action));
        if action || !ctx.is_empty() || matches!(*long, "no-tui" | "no-config") {
            continue;
        }
        let levels: Vec<Option<Vec<String>>> = match kind {
            Kind::Switch => vec![None, Some(vec![format!("--{long}")])],
            Kind::Choice => {
                let mut l = vec![None];
                if let Some(a) = cmd.get_arguments().find(|a| a.get_long() == Some(long)) {
                    for pv in a.get_possible_values() {
                        l.push(Some(vec![format!("--{long}={}", pv.get_name())]));
                    }
                }
                l
            }
            _ => continue,
        };
        params.push((*long, levels));
    }
    params
}

/// A deterministic pairwise covering array over `sizes` levels: every pair
/// of levels of every pair of parameters appears in at least one row.
/// Greedy: each row starts from the first uncovered pair and fills every
/// other parameter with the level that covers the most uncovered pairs
/// against the levels already chosen (lowest level on a tie).
fn pairwise_rows(sizes: &[usize]) -> Vec<Vec<usize>> {
    let n = sizes.len();
    let mut uncovered: BTreeSet<(usize, usize, usize, usize)> = BTreeSet::new();
    for i in 0..n {
        for j in i + 1..n {
            for a in 0..sizes[i] {
                for b in 0..sizes[j] {
                    uncovered.insert((i, a, j, b));
                }
            }
        }
    }
    let mut rows = Vec::new();
    while let Some(&(i, a, j, b)) = uncovered.iter().next() {
        let mut row: Vec<Option<usize>> = vec![None; n];
        row[i] = Some(a);
        row[j] = Some(b);
        for k in 0..n {
            if row[k].is_some() {
                continue;
            }
            let mut best = (0usize, 0usize);
            for level in 0..sizes[k] {
                let gain = (0..n)
                    .filter_map(|m| row[m].map(|lm| (m, lm)))
                    .filter(|&(m, lm)| {
                        let key = if m < k {
                            (m, lm, k, level)
                        } else {
                            (k, level, m, lm)
                        };
                        uncovered.contains(&key)
                    })
                    .count();
                if gain > best.0 {
                    best = (gain, level);
                }
            }
            row[k] = Some(best.1);
        }
        let row: Vec<usize> = row.into_iter().map(|l| l.unwrap_or(0)).collect();
        for p in 0..n {
            for q in p + 1..n {
                uncovered.remove(&(p, row[p], q, row[q]));
            }
        }
        rows.push(row);
    }
    rows
}

/// The generator itself: on a small synthetic space every pair is covered,
/// and the array is far smaller than the full product.
#[test]
fn pairwise_generator_covers_every_pair() -> Result<(), TestError> {
    let sizes = [2, 3, 2, 4, 2, 2];
    let rows = pairwise_rows(&sizes);
    for i in 0..sizes.len() {
        for j in i + 1..sizes.len() {
            for a in 0..sizes[i] {
                for b in 0..sizes[j] {
                    if !rows.iter().any(|r| r[i] == a && r[j] == b) {
                        return Err(format!("pair ({i}={a}, {j}={b}) not covered").into());
                    }
                }
            }
        }
    }
    let product: usize = sizes.iter().product();
    if rows.len() >= product / 4 {
        return Err(format!("{} rows for a product of {product}", rows.len()).into());
    }
    Ok(())
}

/// Whether a refusal names at least one of the flags on its command line.
fn names_one_of(message: &str, tokens: &[String]) -> bool {
    tokens.iter().any(|t| {
        let Some(rest) = t.strip_prefix("--") else {
            return false;
        };
        let (long, value) = rest.split_once('=').unwrap_or((rest, ""));
        names_setting(message, long, value)
    })
}

/// Every pair of levels of every switch and choice flag, run together: no
/// combination panics, each ends in exit 0, 1 or 2, and every refusal names
/// one of the flags it was given.
#[test]
fn pairwise_switch_and_choice_combinations() -> Result<(), TestError> {
    let params = pairwise_params();
    let sizes: Vec<usize> = params.iter().map(|(_, l)| l.len()).collect();
    let rows = pairwise_rows(&sizes);
    let mut failures = Vec::new();
    let mut accepted = 0usize;
    for row in &rows {
        let mut tokens = Vec::new();
        for (p, level) in row.iter().enumerate() {
            if let Some(Some(t)) = params[p].1.get(*level) {
                tokens.extend(t.iter().cloned());
            }
        }
        let mut args = vec!["sipnab".to_string(), "-N".to_string(), "-F".to_string()];
        args.extend(tokens.iter().cloned());
        let o = run_exact(&args);
        if let Some(p) = &o.panic {
            failures.push(format!("{tokens:?}: panicked: {p}"));
        } else if o.accepted() {
            accepted += 1;
        } else if !(1..=2).contains(&o.code) || !names_one_of(&o.message, &tokens) {
            failures.push(format!(
                "{tokens:?}: {:?}/{} does not name a given flag: {}",
                o.stage, o.code, o.message
            ));
        }
    }
    if params.len() < 90 || rows.len() < 10 {
        failures.push(format!("{} parameters, {} rows", params.len(), rows.len()));
    }
    let _ = accepted;
    verdict(failures)
}

/// `--bpf-file` names a file whose content is the filter `[capture]
/// bpf_filter` holds inline: the same expression by either route is the same
/// capture filter.
#[test]
fn bpf_file_content_means_the_key() -> Result<(), TestError> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("filter.bpf");
    std::fs::write(&file, "udp port 5070\n")?;
    let file_arg = file.display().to_string();
    let by_file = probe("bpf-file", &[], Some(Some(file_arg.as_str())), None)?;
    let by_key = probe(
        "bpf-file",
        &[],
        None,
        Some(("capture", "bpf_filter", "\"udp port 5070\"")),
    )?;
    if by_file != by_key {
        return Err("--bpf-file content and [capture] bpf_filter differ".into());
    }
    Ok(())
}

/// The tokens for one random draw from one row: an accepted or a refused
/// value (`accept`), picked by `pick`.
fn drawn_tokens(row: &Spec, accept: bool, pick: usize) -> Vec<String> {
    let (long, kind, ctx) = row;
    let mut out: Vec<String> = ctx.iter().map(|s| (*s).to_string()).collect();
    let value: Option<String> = match kind {
        Kind::Switch => {
            if accept {
                None
            } else {
                Some("maybe".to_string())
            }
        }
        Kind::Choice => {
            let pvs: Vec<String> = sipnab::cli::Cli::command()
                .get_arguments()
                .find(|a| a.get_long() == Some(long))
                .map(|a| {
                    a.get_possible_values()
                        .iter()
                        .map(|p| p.get_name().to_string())
                        .collect()
                })
                .unwrap_or_default();
            if accept && !pvs.is_empty() {
                Some(pvs[pick % pvs.len()].clone())
            } else {
                Some("BOGUS".to_string())
            }
        }
        Kind::Int { lo, hi } => {
            let mid = lo + (hi - lo) / 2;
            let choices = if accept {
                [*lo, mid, *hi]
            } else {
                [lo - 1, hi + 1, lo - 1]
            };
            Some(choices[pick % 3].to_string())
        }
        Kind::Real {
            accept: a,
            reject: r,
        } => {
            let list = if accept { *a } else { *r };
            list.get(pick % list.len().max(1)).map(|s| (*s).to_string())
        }
        Kind::Text {
            accept: a,
            reject: r,
        } => {
            if accept || r.is_empty() {
                a.get(pick % a.len().max(1)).map(|s| (*s).to_string())
            } else {
                r.get(pick % r.len()).map(|(s, _)| (*s).to_string())
            }
        }
    };
    out.push(match value {
        Some(v) => format!("--{long}={v}"),
        None => format!("--{long}"),
    });
    out
}

/// Random combinations of up to six flags, each with an accepted or a
/// refused value from its row, from a fixed seed so a failure reproduces:
/// nothing panics, every run ends in exit 0, 1 or 2, and every refusal names
/// one of the flags it was given.
#[test]
fn random_flag_combinations_hold_the_invariants() -> Result<(), TestError> {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
    let config = Config {
        cases: 400,
        failure_persistence: None,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::deterministic_rng(RngAlgorithm::ChaCha));
    let draws = prop::collection::vec((0..SPECS.len(), any::<bool>(), 0usize..64), 1..7);
    let outcome = runner.run(&draws, |picks| {
        let mut tokens = Vec::new();
        for (index, accept, pick) in picks {
            let Some(row) = SPECS.get(index) else {
                continue;
            };
            // Immediate commands act instead of running; keep the draw to
            // flags that only configure a run.
            let action = sipnab::settings::FLAGS
                .iter()
                .any(|(f, l)| *f == row.0 && matches!(l, sipnab::settings::Link::Action));
            if action || matches!(row.0, "no-tui" | "no-config" | "tui-audit-file") {
                continue;
            }
            tokens.extend(drawn_tokens(row, accept, pick));
        }
        let mut args = vec!["sipnab".to_string(), "-N".to_string(), "-F".to_string()];
        args.extend(tokens.iter().cloned());
        let o = run_exact(&args);
        if let Some(p) = &o.panic {
            return Err(TestCaseError::fail(format!("{tokens:?}: panicked: {p}")));
        }
        if !(0..=2).contains(&o.code) {
            return Err(TestCaseError::fail(format!("{tokens:?}: exit {}", o.code)));
        }
        if !o.accepted() && !names_one_of(&o.message, &tokens) {
            return Err(TestCaseError::fail(format!(
                "{tokens:?}: {:?}/{} names no given flag: {}",
                o.stage, o.code, o.message
            )));
        }
        Ok(())
    });
    outcome.map_err(|e| e.to_string().into())
}
