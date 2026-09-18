// SPDX-License-Identifier: MIT OR Apache-2.0

//! The TFPS contract, enforced on this side.
//!
//! Every fixture under `tests/fixtures/tfps-*` carries exactly the keys, in
//! order, that `tfps_ctl --json` emits at sippulse/tfps `master` `984577dc`,
//! the merge of sippulse/tfps#6 -- checked 2026-09-18 by running that binary.
//! Upstream ships no fixture files, so these are sipnab's own; the first test
//! pins each file's SHA-256 so an edit is deliberate, and
//! `upstreams_own_goldens_read_through_sipnabs_readers` holds them to the
//! JSON lines upstream's own unit tests assert. The two `sipnab-evidence-*`
//! fixtures are byte-identical to the copies on the fork's unmerged
//! `05-evidence-ingest` branch, the only TFPS code that reads them. The rest prove each fixture parses into the type sipnab reads it
//! through, and pin the argument shapes sipnab sends, in `tfps_ctl`'s own
//! grammar.
//!
//! # The executable is an input
//!
//! No test here needs TFPS. `tfps_ctl` is a shell script written into a
//! temporary directory: one that echoes a fixture, one that exits 3 with a
//! message, one that sleeps, one that records its arguments -- and, for the
//! ordinary case, a directory holding nothing. The locator is handed that
//! directory as its `PATH`, so a machine that does have TFPS installed sees
//! the same results as one that does not.
#![cfg(all(unix, feature = "native"))]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sipnab::security::tfps::{
    Invocation, NOT_INSTALLED_REASON, Reply, TfpsAction, TfpsActionAnswer, TfpsBanned, TfpsCommand,
    TfpsDropped, TfpsError, TfpsLabel, TfpsListAnswer, TfpsLocator, TfpsStatus, TfpsStatusAnswer,
};

const STATUS: &str = include_str!("fixtures/tfps-status-golden.json");
const BANNED: &str = include_str!("fixtures/tfps-banned-golden.jsonl");
const DROPPED: &str = include_str!("fixtures/tfps-dropped-golden.jsonl");
const BAN: &str = include_str!("fixtures/tfps-ban-golden.jsonl");
const UNBAN: &str = include_str!("fixtures/tfps-unban-golden.jsonl");
const LABELS: &str = include_str!("fixtures/tfps-labels-golden.jsonl");
const EVIDENCE: &str = include_str!("fixtures/sipnab-evidence-golden.jsonl");
const EVIDENCE_RESULT: &str = include_str!("fixtures/sipnab-evidence-result-golden.jsonl");

/// Every fixture, with the digest of the bytes verified against the peer. A
/// byte moved here fails until the fixture is re-derived and re-pinned.
const PINNED: &[(&str, &str, &str)] = &[
    (
        "tfps-status-golden.json",
        STATUS,
        "815424e6ee4a4b2668c145bba039650480f929224a16fa60b864b777de45b6ba",
    ),
    (
        "tfps-banned-golden.jsonl",
        BANNED,
        "4ad2cef31de83b0f7ceacee1471d32e9be9b4980957f21bb01590586a15f11da",
    ),
    (
        "tfps-dropped-golden.jsonl",
        DROPPED,
        "4f65e80c8aa56752f7acbf7c08ca1b9615e4ac671047c1829c027971a738e9a4",
    ),
    (
        "tfps-ban-golden.jsonl",
        BAN,
        "06fec15aa71a3a665b7c2e79276e7c9146e98f11f8ae066d9a4c274bc3e5139b",
    ),
    (
        "tfps-unban-golden.jsonl",
        UNBAN,
        "2511f25adb6d19fda7f7bf51495b61e7366345fcc695e68e7cae8285f2c0f5f9",
    ),
    (
        "tfps-labels-golden.jsonl",
        LABELS,
        "37b4cccc253e0e3230949a2356f72b533f391fc75f81bd18eb1a7702a821e10e",
    ),
    (
        "sipnab-evidence-golden.jsonl",
        EVIDENCE,
        "f970bef4633647733e03e466209e94dc2888d69636c832901707504221553167",
    ),
    (
        "sipnab-evidence-result-golden.jsonl",
        EVIDENCE_RESULT,
        "b31b2611670b369db616667bbd43bf25071a58b73dea2eb16b3553f8f9a47b3a",
    ),
];

/// The source most fixtures are about.
fn the_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20))
}

/// The first non-empty line of a JSON Lines fixture.
fn first_line(text: &str) -> &str {
    text.lines()
        .find(|l| !l.trim().is_empty())
        .expect("the fixture has a line")
}

/// Line `n` (1-based) of a JSON Lines fixture.
fn line(text: &str, n: usize) -> &str {
    text.lines().nth(n - 1).expect("the fixture has that line")
}

/// A directory holding one executable named `tfps_ctl`, or nothing.
struct FakeCtl {
    dir: tempfile::TempDir,
}

impl FakeCtl {
    /// A `tfps_ctl` that runs `body` under `/bin/sh`.
    fn with_body(body: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tfps_ctl");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("write the fake");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        Self { dir }
    }

    /// A `tfps_ctl` that prints `text` and exits 0, whatever it is asked.
    fn echoing(text: &str) -> Self {
        Self::with_body(&format!("cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE"))
    }

    /// A `tfps_ctl` that prints `text` and exits `code` -- TFPS's refusal
    /// convention: the structured result on stdout, the tally on stderr,
    /// exit 1.
    fn echoing_then_exiting(text: &str, code: i32, stderr: &str) -> Self {
        Self::with_body(&format!(
            "cat <<'SIPNAB_FIXTURE'\n{text}\nSIPNAB_FIXTURE\necho '{stderr}' >&2\nexit {code}"
        ))
    }

    /// A directory with no `tfps_ctl` in it at all.
    fn absent() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn path(&self) -> PathBuf {
        self.dir.path().join("tfps_ctl")
    }

    /// A locator that finds this fake on `PATH` and nowhere else.
    fn on_path(&self) -> TfpsLocator {
        TfpsLocator::new(None, None).with_search_path(self.dir.path().as_os_str())
    }

    /// A locator told where this fake is outright.
    fn explicit(&self) -> TfpsLocator {
        TfpsLocator::new(Some(self.path()), None)
    }
}

/// The keys of every JSON object in `text` (one per line), as one set.
fn keys_of_every_line(text: &str) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("fixture line is JSON");
        let o = v.as_object().expect("fixture line is an object");
        for k in o.keys() {
            all.insert(k.clone());
        }
    }
    all
}

/// `expected`, as a set.
fn set(expected: &[&str]) -> BTreeSet<String> {
    expected.iter().map(|s| (*s).to_string()).collect()
}

// ── The fixtures are what the emitter really prints ──────────────────

#[test]
fn every_fixture_is_pinned_to_its_verified_bytes() {
    use sha2::{Digest, Sha256};
    for (name, text, expected) in PINNED {
        let digest: String = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            &digest, expected,
            "tests/fixtures/{name} changed. These fixtures are what a released \
             `tfps_ctl --json` actually emits, verified by running it -- not a \
             shape anyone chose here. Change one only after the emitter \
             changes, re-derive it from real output, and re-pin the digest in \
             the same commit."
        );
    }
    assert_eq!(PINNED.len(), 8, "every shared fixture is pinned");
}

/// The `--json` lines upstream's own unit tests assert, copied verbatim from
/// `crates/tfps/src/bin/tfps_ctl.rs` at sippulse/tfps `984577dc` (line numbers
/// at that commit). Only the subcommands sipnab asks are here.
const UPSTREAM_STATUS_ACTIVE: &str = r#"{"enforcement":"active","mode":null,"interface":null,"map":"own map id 7","blocked_now":3,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/var/lib/tfps/tfps.db","version":"0.1.0"}"#; // :2102
const UPSTREAM_STATUS_INACTIVE: &str = r#"{"enforcement":"inactive","mode":null,"interface":null,"map":null,"blocked_now":0,"pairs":120,"peers":4,"last_checkpoint":1756800000,"db":"/x","version":"0.1.0"}"#; // :2122
const UPSTREAM_BANNED_ATTRIBUTED: &str = r#"{"ip":"198.51.100.10","reason":"user-agent","detail":"pplsip","first_seen":1756917600,"expires":1756921200,"enforced":true}"#; // :2221
const UPSTREAM_BANNED_UNATTRIBUTED: &str = r#"{"ip":"198.51.100.12","reason":null,"detail":null,"first_seen":null,"expires":null,"enforced":true}"#; // :2232
const UPSTREAM_LOG: &str = r#"{"ip":"198.51.100.10","reason":"scanner","detail":"sipvicious","first_seen":1756800000,"expires":1756803600,"unbanned_at":null,"enforced":true,"disposition":"block"}"#; // :2429
const UPSTREAM_BAN: &str = r#"{"ip":"198.51.100.20","action":"ban","applied":true,"refused":null,"expires":1756921210,"source":"operator"}"#; // :2678

/// Upstream's own goldens, through the code path sipnab reads a live peer
/// with, and read into the right fields: a renamed key on either side leaves
/// an `Option` field `None` and still parses, so the VALUES are asserted.
#[test]
fn upstreams_own_goldens_read_through_sipnabs_readers() {
    fn answered<T>(reply: Reply<T>) -> T {
        match reply {
            Reply::Answered { value, .. } => value,
            Reply::NotInstalled { reason } => panic!("an explicit fake is installed: {reason}"),
        }
    }

    let s = answered(
        FakeCtl::echoing(UPSTREAM_STATUS_ACTIVE)
            .explicit()
            .status()
            .expect("status"),
    );
    assert_eq!(
        (
            s.enforcement.as_str(),
            s.map.as_deref(),
            s.blocked_now,
            s.pairs,
            s.peers,
            s.last_checkpoint
        ),
        (
            "active",
            Some("own map id 7"),
            3,
            Some(120),
            Some(4),
            Some(1_756_800_000)
        )
    );
    assert_eq!(
        (s.mode, s.interface),
        (None, None),
        "upstream never fills these"
    );
    let s = answered(
        FakeCtl::echoing(UPSTREAM_STATUS_INACTIVE)
            .explicit()
            .status()
            .expect("status"),
    );
    assert_eq!(
        (s.enforcement.as_str(), s.map, s.blocked_now),
        ("inactive", None, 0)
    );

    let banned = answered(
        FakeCtl::echoing(&format!(
            "{UPSTREAM_BANNED_ATTRIBUTED}\n{UPSTREAM_BANNED_UNATTRIBUTED}"
        ))
        .explicit()
        .banned()
        .expect("banned"),
    );
    assert_eq!(banned.len(), 2);
    assert_eq!(
        (
            banned[0].reason.as_deref(),
            banned[0].detail.as_deref(),
            banned[0].first_seen,
            banned[0].expires
        ),
        (
            Some("user-agent"),
            Some("pplsip"),
            Some(1_756_917_600),
            Some(1_756_921_200)
        )
    );
    assert_eq!(
        (
            banned[1].reason.as_deref(),
            banned[1].first_seen,
            banned[1].expires,
            banned[1].enforced
        ),
        (None, None, None, true)
    );

    let log = answered(
        FakeCtl::echoing(UPSTREAM_LOG)
            .explicit()
            .labels(50)
            .expect("log"),
    );
    assert_eq!(
        (
            log[0].reason.as_str(),
            log[0].detail.as_str(),
            log[0].expires,
            log[0].disposition.as_str()
        ),
        ("scanner", "sipvicious", Some(1_756_803_600), "block")
    );

    let ban = answered(
        FakeCtl::echoing(UPSTREAM_BAN)
            .explicit()
            .ban(the_ip(), Some(3600))
            .expect("ban"),
    );
    assert_eq!(
        (
            ban.action.as_str(),
            ban.applied,
            ban.refused.as_deref(),
            ban.expires,
            ban.source.as_str()
        ),
        ("ban", true, None, Some(1_756_921_210), "operator")
    );
}

/// Where a fixture line and an upstream golden describe the same case they
/// are the same bytes, so the fixtures cannot drift from what upstream asserts.
#[test]
fn the_fixtures_repeat_upstreams_goldens_byte_for_byte() {
    for (fixture, name, golden) in [
        (
            BANNED,
            "tfps-banned-golden.jsonl",
            UPSTREAM_BANNED_ATTRIBUTED,
        ),
        (
            BANNED,
            "tfps-banned-golden.jsonl",
            UPSTREAM_BANNED_UNATTRIBUTED,
        ),
        (LABELS, "tfps-labels-golden.jsonl", UPSTREAM_LOG),
        (BAN, "tfps-ban-golden.jsonl", UPSTREAM_BAN),
    ] {
        assert!(
            fixture.lines().any(|l| l == golden),
            "tests/fixtures/{name} no longer carries upstream's golden {golden}"
        );
    }
}

// ── Each fixture parses into the type, and carries exactly the agreed keys ──

#[test]
fn the_status_fixture_parses_and_carries_every_agreed_field() {
    let s: TfpsStatus = serde_json::from_str(STATUS).expect("status parses");
    assert_eq!(s.enforcement, "active");
    // A released `tfps_ctl` opens the block map, not the XDP program, so it
    // cannot see either of these and always answers null. `map` is the one
    // enforcement fact it does have.
    assert_eq!(s.mode, None);
    assert_eq!(s.interface, None);
    assert_eq!(s.map.as_deref(), Some("own map id 7"));
    assert_eq!(s.blocked_now, 3);
    assert_eq!(s.pairs, Some(120));
    assert_eq!(s.peers, Some(4));
    assert_eq!(s.last_checkpoint, Some(1_756_800_500));
    assert_eq!(s.db, "/var/lib/tfps/tfps.db");
    assert_eq!(s.version, "0.2.1");
    assert_eq!(
        keys_of_every_line(STATUS),
        set(&[
            "enforcement",
            "mode",
            "interface",
            "map",
            "blocked_now",
            "pairs",
            "peers",
            "last_checkpoint",
            "db",
            "version"
        ])
    );
    // `null` where TFPS could not look, per its own contract.
    let inactive: TfpsStatus = serde_json::from_str(
        r#"{"enforcement":"inactive","mode":null,"interface":null,"map":null,"blocked_now":0,"pairs":null,"peers":null,"last_checkpoint":null,"db":"/x","version":"0.2.1"}"#,
    )
    .expect("an inactive status parses");
    assert_eq!(inactive.mode, None);
}

/// Every row of the ban table, including the one that is all `null` but the
/// address: a block that predates any audit row.
#[test]
fn the_banned_fixture_parses_and_carries_every_agreed_field() {
    let rows: Vec<TfpsBanned> = BANNED
        .lines()
        .map(|l| serde_json::from_str(l).expect("banned row parses"))
        .collect();
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].ip, "198.51.100.10");
    assert_eq!(rows[0].reason.as_deref(), Some("user-agent"));
    assert_eq!(rows[0].detail.as_deref(), Some("pplsip"));
    // Epoch seconds, not RFC 3339: a released TFPS renders every time this
    // way and leaves presentation to the reader.
    assert_eq!(rows[0].first_seen, Some(1_756_917_600));
    assert_eq!(rows[0].expires, Some(1_756_921_200));
    assert!(rows[0].enforced);
    assert_eq!(rows[1].reason.as_deref(), Some("apiban"));
    assert_eq!(rows[1].first_seen, None, "a feed entry has no first_seen");
    assert_eq!(
        (
            rows[2].reason.as_deref(),
            rows[2].detail.as_deref(),
            rows[2].expires
        ),
        (None, None, None),
        "a block with no audit row is all null but the address"
    );
    assert_eq!(
        keys_of_every_line(BANNED),
        set(&[
            "ip",
            "reason",
            "detail",
            "first_seen",
            "expires",
            "enforced"
        ])
    );
}

#[test]
fn the_dropped_fixture_parses_and_carries_every_agreed_field() {
    let rows: Vec<TfpsDropped> = DROPPED
        .lines()
        .map(|l| serde_json::from_str(l).expect("dropped row parses"))
        .collect();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].ip, "198.51.100.10");
    assert_eq!(rows[0].dropped, 30);
    assert_eq!(rows[0].events, 4);
    assert_eq!(rows[0].last_seen, "2026-09-03T16:41:00Z");
    assert_eq!(rows[0].rule.as_deref(), Some("user-agent"));
    assert_eq!(
        rows[0].last_request.as_deref(),
        Some("OPTIONS sip:100@198.51.100.1 SIP/2.0")
    );
    assert_eq!(rows[1].rule, None);
    assert_eq!(rows[1].last_request, None, "no request recorded is null");
    assert_eq!(
        keys_of_every_line(DROPPED),
        set(&[
            "ip",
            "dropped",
            "events",
            "last_seen",
            "rule",
            "last_request"
        ])
    );
}

/// Every outcome `ban` can answer with: applied with an expiry, applied
/// forever, refused as the host's own address, refused by `ignoreip`, and
/// refused as invalid with no address at all.
#[test]
fn the_ban_fixture_parses_every_outcome() {
    let rows: Vec<TfpsAction> = BAN
        .lines()
        .map(|l| serde_json::from_str(l).expect("ban row parses"))
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(
        rows.iter()
            .all(|r| r.action == "ban" && r.source == "operator")
    );
    assert_eq!(rows[0].ip.as_deref(), Some("198.51.100.20"));
    assert!(rows[0].applied && rows[0].refused.is_none());
    assert_eq!(rows[0].expires, Some(1_756_921_210));
    assert!(rows[1].applied && rows[1].expires.is_none(), "forever");
    let refusals: Vec<&str> = rows[2..]
        .iter()
        .filter_map(|r| r.refused.as_deref())
        .collect();
    // TFPS's own glossary: `local` is an address of the host, `declared` an
    // operator ignoreip entry, `kernel` a failed map write -- which is
    // enforcement broken, not policy, and must stay its own term.
    assert_eq!(refusals, ["local", "declared", "kernel"]);
    assert!(rows[2..].iter().all(|r| !r.applied));
    // There is no `invalid` row: a released `tfps_ctl ban` parses its
    // addresses with `?` before any per-address work, so an unparseable one
    // aborts the whole command instead of producing a line.
    assert!(rows.iter().all(|r| r.ip.is_some()));
    assert_eq!(
        keys_of_every_line(BAN),
        set(&["ip", "action", "applied", "refused", "expires", "source"])
    );
}

#[test]
fn the_unban_fixture_parses_every_outcome() {
    let rows: Vec<TfpsAction> = UNBAN
        .lines()
        .map(|l| serde_json::from_str(l).expect("unban row parses"))
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.action == "unban" && r.expires.is_none())
    );
    assert!(rows[0].applied);
    assert_eq!(rows[1].refused.as_deref(), Some("not-blocked"));
    // No `invalid` row: `unban` parses with `?` too, so an unparseable address
    // aborts the command rather than producing a line.
    assert_eq!(
        keys_of_every_line(UNBAN),
        set(&["ip", "action", "applied", "refused", "expires", "source"])
    );
}

/// The label export parses into the typed row too. `tfps_label_corpus_test`
/// reads it structurally for the harness; `tfps_labels` hands it to an agent
/// through this type, and both must accept the same bytes.
#[test]
fn the_labels_fixture_parses_into_the_typed_row() {
    let rows: Vec<TfpsLabel> = LABELS
        .lines()
        .map(|l| serde_json::from_str(l).expect("label row parses"))
        .collect();
    assert_eq!(rows.len(), 3);
    // A released TFPS writes only `block`: `block_log` has four columns and no
    // way to record the exempt or would-block classes. The vocabulary is
    // CONTEXT.md's, so this is the glossary term, not the past tense.
    let dispositions: BTreeSet<&str> = rows.iter().map(|r| r.disposition.as_str()).collect();
    assert_eq!(dispositions, ["block"].into());
    assert!(
        rows.iter().any(|r| r.expires == Some(0))
            && rows.iter().any(|r| r.expires.is_none())
            && rows.iter().any(|r| r.unbanned_at.is_some()),
        "all three meanings of expires and the operator lift must survive the typed read"
    );
}

/// What `tfps_ctl ingest` answers, per evidence line, is an action with
/// `source: "sipnab"` -- the same type `ban --json` prints. sipnab does not
/// read that stream back today; the fixture is pinned so that when it does,
/// the type is already the right one.
#[test]
fn the_evidence_result_fixture_is_an_action_per_line_from_sipnab() {
    let rows: Vec<TfpsAction> = EVIDENCE_RESULT
        .lines()
        .map(|l| serde_json::from_str(l).expect("result row parses"))
        .collect();
    assert_eq!(rows.len(), 5);
    assert!(
        rows.iter()
            .all(|r| r.source == "sipnab" && r.action == "ban")
    );
    assert_eq!(
        rows.iter().filter(|r| r.applied).count(),
        2,
        "two findings became bans; the host, the ignoreip entry and the torn line did not"
    );
}

// ── Locating the executable ──────────────────────────────────────────

#[test]
fn an_empty_search_path_finds_nothing() {
    let fake = FakeCtl::absent();
    assert_eq!(fake.on_path().locate(), None);
    assert_eq!(
        TfpsLocator::new(None, None).locate_in(None),
        None,
        "no PATH at all is the same answer"
    );
}

#[test]
fn an_executable_on_the_search_path_is_found() {
    let fake = FakeCtl::echoing(STATUS);
    assert_eq!(fake.on_path().locate(), Some(fake.path()));
}

/// A directory entry that is not a regular file is not the program.
#[test]
fn a_directory_named_tfps_ctl_is_not_the_program() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("tfps_ctl")).expect("mkdir");
    let locator = TfpsLocator::new(None, None).with_search_path(dir.path().as_os_str());
    assert_eq!(locator.locate(), None);
}

#[test]
fn an_explicit_path_wins_over_the_search_path() {
    let on_path = FakeCtl::echoing(STATUS);
    let named = PathBuf::from("/opt/tfps/bin/tfps_ctl");
    let locator = TfpsLocator::new(Some(named.clone()), None)
        .with_search_path(on_path.dir.path().as_os_str());
    assert_eq!(
        locator.locate(),
        Some(named),
        "the operator named a program; PATH is not consulted"
    );
}

#[test]
fn the_flag_wins_over_the_config_file() {
    let flag = Path::new("/from/flag");
    let cfg = Path::new("/from/config");
    let db = Path::new("/var/lib/tfps/tfps.db");
    let both = TfpsLocator::resolve(Some(flag), Some(cfg), Some(db));
    assert_eq!(both.ctl(), Some(flag));
    assert_eq!(both.db(), Some(db));
    let config_only = TfpsLocator::resolve(None, Some(cfg), None);
    assert_eq!(config_only.ctl(), Some(cfg));
    assert_eq!(config_only.db(), None);
    let neither = TfpsLocator::resolve(None, None, None);
    assert_eq!(
        neither,
        TfpsLocator::default(),
        "nothing configured is the default"
    );
}

// ── The argument shapes sipnab sends, in tfps_ctl's grammar ─────────

/// Every argv, exactly. `tfps_ctl` parses `--flag value` as two elements and
/// nothing else, and its export prints everything unless `--limit` is given.
/// A caller can never receive more than one page, so sipnab never asks TFPS
/// for more: the caller's `limit` when a page holds it, and otherwise the
/// page plus one row, which is how `truncated` knows rows were withheld.
/// Asking for the whole log to show a page cost `tfps_ctl` 179 MB and 12.7 s
/// on a million-row log (debug build, 2026-09-18). And there is no "every
/// row" value to send instead: TFPS reads `--limit 0` as zero rows.
#[test]
fn the_labels_request_never_asks_for_more_than_a_page() {
    use sipnab::security::tfps::labels_request;
    assert_eq!(
        labels_request(None, 1000),
        1001,
        "absent: a page and one row"
    );
    assert_eq!(
        labels_request(Some(0), 1000),
        1001,
        "0 is the default, as elsewhere"
    );
    assert_eq!(
        labels_request(Some(250), 1000),
        250,
        "a limit a page holds is sent as is"
    );
    assert_eq!(labels_request(Some(1000), 1000), 1000, "exactly a page");
    assert_eq!(
        labels_request(Some(5000), 1000),
        1001,
        "more than a page is a page"
    );
    assert_eq!(labels_request(None, 2), 3);
}

#[test]
fn every_command_has_the_agreed_argv() {
    let argv = |cmd: &TfpsCommand, db: Option<&Path>| -> Vec<String> {
        cmd.argv(db)
            .into_iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    };
    assert_eq!(argv(&TfpsCommand::Status, None), ["status", "--json"]);
    assert_eq!(argv(&TfpsCommand::Banned, None), ["banned", "--json"]);
    assert_eq!(argv(&TfpsCommand::Dropped, None), ["dropped", "--json"]);
    assert_eq!(
        argv(&TfpsCommand::Labels { limit: 250 }, None),
        ["log", "--json", "--limit", "250"]
    );
    assert_eq!(
        argv(
            &TfpsCommand::Ban {
                ip: the_ip(),
                ttl_secs: None
            },
            None
        ),
        ["ban", "--json", "198.51.100.20"]
    );
    assert_eq!(
        argv(
            &TfpsCommand::Ban {
                ip: the_ip(),
                ttl_secs: Some(86_400)
            },
            None
        ),
        ["ban", "--json", "198.51.100.20", "--ttl", "86400"]
    );
    assert_eq!(
        argv(&TfpsCommand::Unban { ip: the_ip() }, None),
        ["unban", "--json", "198.51.100.20"]
    );
    assert_eq!(
        argv(
            &TfpsCommand::Status,
            Some(Path::new("/var/lib/tfps/tfps.db"))
        ),
        ["status", "--json", "--db", "/var/lib/tfps/tfps.db"],
        "[tfps] db is passed through on every command"
    );
    assert!(
        TfpsCommand::Ban {
            ip: the_ip(),
            ttl_secs: None
        }
        .refusal_carries_a_result()
            && TfpsCommand::Unban { ip: the_ip() }.refusal_carries_a_result()
            && !TfpsCommand::Status.refusal_carries_a_result()
            && !TfpsCommand::Labels { limit: 50 }.refusal_carries_a_result(),
        "only the two actions answer a refusal with a result"
    );
}

/// The database path is one `argv` element after `--db`, whatever it holds.
/// Proved on the wire: the fake records what it received, one per line.
#[test]
fn the_database_path_arrives_as_its_own_argument() {
    let fake = FakeCtl::with_body(&format!(
        "for a in \"$@\"; do printf '%s\\n' \"$a\"; done > \"$(dirname \"$0\")/argv\"\n\
         cat <<'SIPNAB_FIXTURE'\n{STATUS}\nSIPNAB_FIXTURE"
    ));
    let db = PathBuf::from("/var/lib/tfps/space in name.db");
    let locator = TfpsLocator::new(Some(fake.path()), Some(db));
    assert!(matches!(
        locator.status().expect("answers"),
        Reply::Answered { .. }
    ));
    let recorded = std::fs::read_to_string(fake.dir.path().join("argv")).expect("argv recorded");
    assert_eq!(
        recorded.lines().collect::<Vec<_>>(),
        ["status", "--json", "--db", "/var/lib/tfps/space in name.db"],
        "the path reached the program as one argument and no shell saw it"
    );
}

// ── Invoking it ──────────────────────────────────────────────────────

/// The ordinary case on a bare machine: an answer, with the one agreed
/// reason, and no error.
#[test]
fn an_absent_peer_is_an_answer_not_an_error() {
    let fake = FakeCtl::absent();
    let got = fake
        .on_path()
        .invoke(&TfpsCommand::Status)
        .expect("absent is Ok");
    assert_eq!(
        got,
        Invocation::NotInstalled {
            reason: NOT_INSTALLED_REASON.to_string()
        }
    );
    assert_eq!(
        NOT_INSTALLED_REASON, "tfps_ctl not found on PATH; pass --tfps-ctl or [tfps] ctl",
        "the reason is part of the contract: both doors and the docs quote it"
    );
    let typed = fake.on_path().status().expect("absent is Ok");
    assert!(matches!(typed, Reply::NotInstalled { .. }));
}

/// An explicit path that does not run is a misconfiguration, reported as
/// one -- not folded into "not installed", which would tell the operator to
/// pass the flag they already passed.
#[test]
fn an_explicit_path_that_cannot_run_is_an_error_naming_it() {
    let missing = PathBuf::from("/nonexistent/sipnab-test/tfps_ctl");
    let err = TfpsLocator::new(Some(missing.clone()), None)
        .invoke(&TfpsCommand::Status)
        .expect_err("a path that does not exist cannot be spawned");
    assert!(
        matches!(&err, TfpsError::Spawn { ctl, .. } if *ctl == missing),
        "{err}"
    );
    assert!(err.to_string().contains(&missing.display().to_string()));
}

/// A freshly written executable can be open for writing at the moment sipnab
/// execs it -- by the installer that wrote it, or by a forked child of some
/// other thread that inherited the write descriptor and has not exec'd yet.
/// The kernel answers `ETXTBSY`. That is a moment, not a state, and sipnab
/// waits it out rather than reporting a peer that is there as one it cannot
/// run. Reproduced deterministically: the test holds the write handle open
/// itself and lets go after 50 ms.
///
/// Linux only, and the reason is the reproduction rather than the behavior.
/// `ETXTBSY` on `execve` while a writable descriptor is open is a Linux
/// guarantee; macOS does not enforce it, so the exec there succeeds at once,
/// nothing is retried, and the test measures a wait that never had to happen.
/// The retry path itself is not platform-specific -- only this way of
/// provoking it is.
#[cfg(target_os = "linux")]
#[test]
fn a_peer_busy_being_written_is_retried_not_refused() {
    let fake = FakeCtl::echoing(STATUS);
    let held = std::fs::OpenOptions::new()
        .append(true)
        .open(fake.path())
        .expect("hold the executable open for writing");
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(50));
        drop(held);
    });
    let started = std::time::Instant::now();
    let reply = fake
        .explicit()
        .status()
        .expect("ETXTBSY is a moment, not a missing peer");
    assert!(matches!(reply, Reply::Answered { .. }), "{reply:?}");
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "the answer arrived before the handle was released, so nothing was retried"
    );
    release.join().expect("release thread");
}

#[test]
fn a_zero_exit_is_answered_with_its_stdout() {
    let fake = FakeCtl::echoing(STATUS);
    match fake
        .explicit()
        .invoke(&TfpsCommand::Status)
        .expect("answered")
    {
        Invocation::Answered {
            ctl,
            status,
            stdout,
            ..
        } => {
            assert_eq!(ctl, fake.path());
            assert_eq!(status, Some(0));
            assert_eq!(stdout.trim(), STATUS.trim());
        }
        other => panic!("expected an answer, got {other:?}"),
    }
}

/// The peer's own diagnosis, verbatim. Paraphrasing it would lose the part
/// that says what to fix.
#[test]
fn a_non_zero_exit_is_an_error_carrying_stderr_verbatim() {
    let fake = FakeCtl::with_body("echo 'database is locked: /var/lib/tfps/tfps.db' >&2; exit 3");
    let err = fake.explicit().banned().expect_err("exit 3 is an error");
    match &err {
        TfpsError::Failed {
            status,
            stderr,
            subcommand,
            ..
        } => {
            assert_eq!(*status, Some(3));
            assert_eq!(stderr.trim(), "database is locked: /var/lib/tfps/tfps.db");
            assert_eq!(subcommand, "banned");
        }
        other => panic!("expected Failed, got {other:?}"),
    }
    assert!(
        err.to_string()
            .contains("database is locked: /var/lib/tfps/tfps.db"),
        "the rendered error carries stderr: {err}"
    );
}

/// TFPS's `ban` exits 1 when the request was refused and still prints the
/// structured line. That is the peer answering, and it is reported as an
/// answer: `applied: false`, `refused: "self"`.
/// A `tfps_ctl` from a tagged TFPS release rejects `--json` in its argument
/// parser: `error: unknown option: --json`, the usage text, exit 2. Read from
/// `crates/tfps/src/bin/tfps_ctl.rs` at v0.2.1, the newest tag on 2026-09-18.
/// JSON output reached sippulse/tfps `master` in #6 (merge commit `984577dc`)
/// and no tag carries it yet, so this is what an operator with a packaged
/// TFPS meets on every question sipnab asks. They get the peer's own words
/// AND what to install.
#[test]
fn a_released_peer_without_json_is_told_where_json_is() {
    let fake = FakeCtl::with_body(
        "printf 'error: unknown option: --json\\n\\nUSAGE: tfps_ctl <command> [options]\\n' >&2\nexit 2",
    );
    let msg = fake
        .explicit()
        .status()
        .expect_err("a tfps_ctl without --json cannot answer")
        .to_string();
    assert!(
        msg.contains("unknown option: --json"),
        "the peer's own words must survive: {msg}"
    );
    assert!(
        msg.contains("sippulse/tfps#6") && msg.contains("master") && msg.contains("v0.2.1"),
        "the operator must be told where --json is and that no release has it: {msg}"
    );
}

/// `dropped` is on no TFPS build: upstream `master` at `984577dc` answers
/// `error: unknown command: dropped` and exit 1 (run 2026-09-18), and v0.2.1
/// has no such arm either. An operator asking sipnab for kernel drops is told
/// that no TFPS can answer yet, not only that this one failed.
#[test]
fn a_peer_without_dropped_is_told_no_build_has_it() {
    let fake = FakeCtl::with_body("echo 'error: unknown command: dropped' >&2\nexit 1");
    let msg = fake
        .explicit()
        .dropped()
        .expect_err("no TFPS build has dropped")
        .to_string();
    assert!(
        msg.contains("unknown command: dropped"),
        "the peer's own words must survive: {msg}"
    );
    assert!(
        msg.contains("no TFPS build has"),
        "the operator must be told that no TFPS answers this yet: {msg}"
    );
}

/// The hints are for the two capability gaps and nothing else. A failure
/// that is the operator's to fix -- here the database path -- keeps the
/// peer's words alone, so a hint never points at the wrong cause.
#[test]
fn an_ordinary_peer_failure_carries_no_capability_hint() {
    let fake = FakeCtl::with_body(
        "echo 'error: opening /var/lib/tfps/tfps.db read-only: unable to open database file' >&2\nexit 1",
    );
    let msg = fake
        .explicit()
        .labels(50)
        .expect_err("an unreadable database is a failure")
        .to_string();
    assert!(msg.contains("unable to open database file"), "{msg}");
    assert!(
        !msg.contains("sippulse/tfps#6") && !msg.contains("no TFPS build has"),
        "a database error must not be dressed up as a missing capability: {msg}"
    );
}

/// The `dropped` hint names one missing subcommand, so it is given for that
/// one alone. A `tfps_ctl` that does not know some other subcommand has a
/// different gap, and telling its operator that no TFPS reports kernel drops
/// would send them after the wrong thing.
#[test]
fn another_missing_subcommand_is_not_reported_as_the_dropped_gap() {
    let fake = FakeCtl::with_body("echo 'error: unknown command: log' >&2\nexit 1");
    let msg = fake
        .explicit()
        .labels(50)
        .expect_err("a tfps_ctl without log cannot answer")
        .to_string();
    assert!(msg.contains("unknown command: log"), "{msg}");
    assert!(
        !msg.contains("no TFPS build has"),
        "a missing log subcommand is not the dropped gap: {msg}"
    );
}

#[test]
fn a_refused_ban_exits_one_and_is_still_an_answer() {
    let fake = FakeCtl::echoing_then_exiting(line(BAN, 3), 1, "error: 1 of 1 refused");
    let reply = fake
        .explicit()
        .ban(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), None)
        .expect("a refusal is a result, not an error");
    match reply {
        Reply::Answered { value, .. } => {
            assert!(!value.applied);
            assert_eq!(value.refused.as_deref(), Some("local"));
        }
        other => panic!("expected an answer, got {other:?}"),
    }
    let fake = FakeCtl::echoing_then_exiting(line(UNBAN, 2), 1, "error: 1 of 1 not lifted");
    let reply = fake
        .explicit()
        .unban(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 21)))
        .expect("a refusal is a result, not an error");
    assert!(
        matches!(reply, Reply::Answered { value, .. } if value.refused.as_deref() == Some("not-blocked"))
    );
}

/// Exit 1 with NOTHING readable on stdout is a failure, stderr and all --
/// the refusal convention does not turn every crash of `ban` into a result.
#[test]
fn a_ban_that_exits_one_without_a_result_is_a_failure() {
    let fake = FakeCtl::with_body("echo 'error: cannot open block map: CAP_BPF' >&2; exit 1");
    let err = fake
        .explicit()
        .ban(the_ip(), None)
        .expect_err("no result line means it failed");
    assert!(
        matches!(&err, TfpsError::Failed { status: Some(1), stderr, .. } if stderr.contains("CAP_BPF")),
        "{err}"
    );
    // And exit 1 on a command with no refusal convention is a failure even
    // with something parseable on stdout.
    let fake = FakeCtl::echoing_then_exiting(STATUS, 1, "error: whatever");
    let err = fake
        .explicit()
        .status()
        .expect_err("status has no refusal convention");
    assert!(
        matches!(
            err,
            TfpsError::Failed {
                status: Some(1),
                ..
            }
        ),
        "{err}"
    );
}

#[test]
fn output_that_is_not_the_contract_is_an_error() {
    let fake = FakeCtl::echoing("this is not json");
    let err = fake.explicit().status().expect_err("not JSON");
    assert!(matches!(err, TfpsError::Unparseable { .. }), "{err}");
    // A list with one bad line among good ones is refused whole, for the
    // reason the label harness gives: a quietly shortened list describes a
    // smaller world than the peer reported.
    let fake = FakeCtl::echoing(&format!("{BANNED}not json\n"));
    let err = fake.explicit().banned().expect_err("one bad line");
    match err {
        TfpsError::Unparseable { what, .. } => {
            assert!(what.contains("line 4"), "names the line: {what}");
        }
        other => panic!("expected Unparseable, got {other:?}"),
    }
    // One address asked, two results answered: reported, not resolved.
    let fake = FakeCtl::echoing(&format!("{}\n{}", line(BAN, 1), line(BAN, 2)));
    let err = fake.explicit().ban(the_ip(), None).expect_err("two lines");
    assert!(
        matches!(&err, TfpsError::Unparseable { what, .. } if what.contains("2 result lines")),
        "{err}"
    );
}

/// The whole tree is stopped, not just the peer. The fake is a shell whose
/// `sleep` is a grandchild holding the pipe: killing the shell alone left the
/// reader waiting the full thirty seconds, which is how this test first ran,
/// and returning without waiting would have hidden an orphan that kept
/// running. So the fake records the grandchild's pid and the test checks it
/// is dead, not merely that the call came back.
#[test]
fn a_peer_that_hangs_is_stopped_and_reported() {
    let fake = FakeCtl::with_body(
        "echo 'still opening the database' >&2\n\
         sleep 30 &\n\
         echo $! > \"$(dirname \"$0\")/sleep.pid\"\n\
         wait",
    );
    let started = std::time::Instant::now();
    let err = fake
        .explicit()
        .invoke_with(&TfpsCommand::Status, Duration::from_millis(300))
        .expect_err("a hang is an error");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the call took {:?}: the reader waited on a pipe the grandchild held",
        started.elapsed()
    );
    let pid: i32 = std::fs::read_to_string(fake.dir.path().join("sleep.pid"))
        .expect("the fake recorded its grandchild")
        .trim()
        .parse()
        .expect("a pid");
    // `kill(pid, 0)` asks whether the process exists without signaling it.
    // A moment's grace: the group kill is asynchronous with the wait.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut alive = true;
    while alive && std::time::Instant::now() < deadline {
        // SAFETY: signal 0 delivers nothing; it only reports existence.
        alive = unsafe { libc::kill(pid, 0) } == 0;
        if alive {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    if alive {
        // Do not leave it behind for the next test to trip over.
        // SAFETY: the pid is the grandchild this test's own fake started.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        panic!(
            "the grandchild sleep (pid {pid}) survived the timeout: the process group was not killed"
        );
    }
    match &err {
        TfpsError::TimedOut { after, stderr, .. } => {
            assert_eq!(*after, Duration::from_millis(300));
            assert!(stderr.contains("still opening"), "{stderr}");
        }
        other => panic!("expected TimedOut, got {other:?}"),
    }
}

#[test]
fn the_typed_readers_reach_every_shape() {
    let status = FakeCtl::echoing(STATUS)
        .explicit()
        .status()
        .expect("status");
    assert!(matches!(status, Reply::Answered { value, .. } if value.blocked_now == 3));

    let banned = FakeCtl::echoing(BANNED)
        .explicit()
        .banned()
        .expect("banned");
    assert!(matches!(banned, Reply::Answered { value, .. } if value.len() == 3));

    let dropped = FakeCtl::echoing(DROPPED)
        .explicit()
        .dropped()
        .expect("dropped");
    assert!(matches!(dropped, Reply::Answered { value, .. } if value[0].dropped == 30));

    let labels = FakeCtl::echoing(LABELS)
        .explicit()
        .labels(50)
        .expect("labels");
    assert!(matches!(labels, Reply::Answered { value, .. } if value.len() == 3));

    let ban = FakeCtl::echoing(first_line(BAN))
        .explicit()
        .ban(the_ip(), Some(3600))
        .expect("ban");
    assert!(matches!(ban, Reply::Answered { value, .. } if value.applied));

    let unban = FakeCtl::echoing(first_line(UNBAN))
        .explicit()
        .unban(the_ip())
        .expect("unban");
    assert!(matches!(unban, Reply::Answered { value, .. } if value.action == "unban"));
}

// ── What both doors answer with ──────────────────────────────────────

/// `installed: false` carries the reason and NOTHING else. A client keyed on
/// the presence of `status` must not find an empty one.
#[test]
fn the_absent_answer_is_exactly_installed_false_and_a_reason() {
    let answer = TfpsStatusAnswer::from(Reply::<TfpsStatus>::NotInstalled {
        reason: NOT_INSTALLED_REASON.to_string(),
    });
    let v = serde_json::to_value(&answer).expect("serializes");
    assert_eq!(
        v,
        serde_json::json!({"installed": false, "reason": NOT_INSTALLED_REASON})
    );

    let list = TfpsListAnswer::<TfpsBanned>::bounded(
        Reply::NotInstalled {
            reason: NOT_INSTALLED_REASON.to_string(),
        },
        50,
    );
    assert_eq!(
        serde_json::to_value(&list).expect("serializes"),
        serde_json::json!({"installed": false, "reason": NOT_INSTALLED_REASON})
    );

    let action = TfpsActionAnswer::from(Reply::<TfpsAction>::NotInstalled {
        reason: NOT_INSTALLED_REASON.to_string(),
    });
    assert_eq!(
        serde_json::to_value(&action).expect("serializes"),
        serde_json::json!({"installed": false, "reason": NOT_INSTALLED_REASON})
    );
}

#[test]
fn a_present_answer_names_the_executable_and_carries_the_value() {
    let s: TfpsStatus = serde_json::from_str(STATUS).expect("status");
    let answer = TfpsStatusAnswer::from(Reply::Answered {
        ctl: PathBuf::from("/usr/local/bin/tfps_ctl"),
        value: s.clone(),
    });
    let v = serde_json::to_value(&answer).expect("serializes");
    assert_eq!(v["installed"], true);
    assert_eq!(v["tfps_ctl"], "/usr/local/bin/tfps_ctl");
    assert_eq!(v["status"]["blocked_now"], 3);
    assert!(
        v.get("reason").is_none(),
        "no reason when there is an answer"
    );
}

/// The door's row cap bounds a list the same way every page on the MCP
/// surface is bounded, and says so.
#[test]
fn a_list_answer_is_bounded_by_the_row_cap_and_says_so() {
    let rows: Vec<TfpsLabel> = LABELS
        .lines()
        .map(|l| serde_json::from_str(l).expect("label row"))
        .collect();
    let reply = Reply::Answered {
        ctl: PathBuf::from("/x/tfps_ctl"),
        value: rows.clone(),
    };
    let bounded = TfpsListAnswer::bounded(reply, 2);
    assert_eq!(bounded.total, Some(3));
    assert_eq!(bounded.returned, Some(2));
    assert_eq!(bounded.truncated, Some(true));
    assert_eq!(bounded.rows.as_ref().map(Vec::len), Some(2));

    let reply = Reply::Answered {
        ctl: PathBuf::from("/x/tfps_ctl"),
        value: rows,
    };
    let whole = TfpsListAnswer::bounded(reply, 50);
    assert_eq!(whole.total, Some(3));
    assert_eq!(whole.returned, Some(3));
    assert_eq!(
        whole.truncated,
        Some(false),
        "a cap that withheld nothing says so rather than staying silent"
    );
}
