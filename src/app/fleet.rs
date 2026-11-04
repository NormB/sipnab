// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet inventory`: ask every sipnab instance in a hosts file for
//! its inventory, and report the fleet.
//!
//! # Pull, from a static list
//!
//! The controller asks; the instances never call in. Each instance already
//! serves an authenticated HTTP API, so pulling needs no listener here and no
//! new trust on the instances, and an instance that does not answer is
//! itself the finding. The list is a file the operator keeps, so an instance
//! is managed only when someone named it.
//!
//! # What is pure and what is not
//!
//! [`parse_hosts`] and [`merge`] take their inputs as arguments and are where
//! every rule lives: which answer is usable, which instances disagree, which
//! HEP sender nobody listed. [`fetch`] is the one function that opens a
//! connection, and it decides nothing.

use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Wire-format version of [`FleetReport`].
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// The highest inventory `schema_version` this build reads.
pub const INVENTORY_SCHEMA_VERSION: u64 = 1;

/// The most bytes of one inventory answer this command reads.
const MAX_ANSWER_BYTES: usize = 4 * 1024 * 1024;

/// The most bytes of one answer's status line and headers.
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The hosts file.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostsFile {
    /// One table per instance.
    #[serde(default)]
    host: Vec<HostEntry>,
}

/// One instance in the hosts file.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    /// The name the report shows; unique in the file.
    pub name: String,
    /// The instance's REST API base URL, `http://` or `https://`.
    pub url: String,
    /// A file holding the bearer token for the instance, readable by this
    /// user only.
    pub token_file: PathBuf,
    /// A PEM CA file to trust instead of the host's bundle, for `https://`.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

/// Parse a hosts file.
///
/// # Errors
///
/// Not TOML, an unknown key, no `[[host]]` table, an empty or repeated
/// name, or an empty URL. The message names the problem.
pub fn parse_hosts(text: &str) -> Result<Vec<HostEntry>, String> {
    let file: HostsFile = toml::from_str(text).map_err(|e| e.message().to_string())?;
    if file.host.is_empty() {
        return Err("the hosts file names no [[host]]".to_string());
    }
    let mut seen = std::collections::BTreeSet::new();
    for h in &file.host {
        if h.name.trim().is_empty() {
            return Err("a [[host]] has an empty name".to_string());
        }
        if h.url.trim().is_empty() {
            return Err(format!("host '{}' has an empty url", h.name));
        }
        if !seen.insert(h.name.as_str()) {
            return Err(format!("host '{}' is named twice", h.name));
        }
    }
    Ok(file.host)
}

/// What one instance answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// A 200 with a JSON body.
    Inventory(serde_json::Value),
    /// An HTTP status other than 200.
    Refused(u16),
    /// No answer: no connection, a timeout, or a body that is not JSON.
    Unreachable(String),
}

/// One instance's result.
#[derive(Debug, Clone, PartialEq)]
pub struct HostResult {
    /// Its name in the hosts file.
    pub name: String,
    /// Its URL.
    pub url: String,
    /// The addresses its URL's host resolved to, for matching HEP senders.
    pub addresses: Vec<IpAddr>,
    /// What it answered.
    pub answer: Answer,
}

/// The fleet report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct FleetReport {
    /// Wire-format version, [`REPORT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Whether every instance answered and there is no finding.
    pub ok: bool,
    /// One row per instance, in hosts-file order.
    pub hosts: Vec<HostRow>,
    /// What the fleet as a whole needs looked at.
    pub findings: Vec<Finding>,
}

/// One instance in the report.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct HostRow {
    /// Its name in the hosts file.
    pub name: String,
    /// Its URL.
    pub url: String,
    /// `ok`, `refused`, `unreachable` or `incompatible`.
    pub state: String,
    /// Why it is not `ok`.
    pub error: Option<String>,
    /// The inventory it returned, when `ok`.
    pub inventory: Option<serde_json::Value>,
}

/// One finding across the fleet.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Finding {
    /// `version_mismatch` or `unlisted_hep_sender`.
    pub kind: String,
    /// What was found, naming the instances.
    pub detail: String,
}

/// The report for `results`.
#[must_use]
pub fn merge(results: Vec<HostResult>) -> FleetReport {
    let listed: std::collections::BTreeSet<IpAddr> = results
        .iter()
        .flat_map(|r| r.addresses.iter().copied())
        .collect();
    let mut hosts = Vec::with_capacity(results.len());
    let mut versions: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut findings = Vec::new();
    for r in results {
        let (state, error, inventory) = match r.answer {
            Answer::Refused(code) => (
                "refused",
                Some(format!("the instance answered HTTP {code}")),
                None,
            ),
            Answer::Unreachable(why) => ("unreachable", Some(why), None),
            Answer::Inventory(v) => match v["schema_version"].as_u64() {
                Some(n) if (1..=INVENTORY_SCHEMA_VERSION).contains(&n) => ("ok", None, Some(v)),
                Some(n) => (
                    "incompatible",
                    Some(format!(
                        "the instance answered inventory schema_version {n}; this sipnab \
                         reads up to {INVENTORY_SCHEMA_VERSION}"
                    )),
                    None,
                ),
                None => (
                    "incompatible",
                    Some("the answer carries no inventory schema_version".to_string()),
                    None,
                ),
            },
        };
        if let Some(v) = &inventory {
            let line = v["build"]["version_line"].as_str().unwrap_or("unknown");
            versions
                .entry(line.to_string())
                .or_default()
                .push(r.name.clone());
            let senders = v["hep_listener"]["senders"].as_array().map(Vec::as_slice);
            for peer in senders.unwrap_or_default() {
                let Some(text) = peer["peer"].as_str() else {
                    continue;
                };
                let known = text.parse::<IpAddr>().is_ok_and(|ip| listed.contains(&ip));
                if !known {
                    findings.push(Finding {
                        kind: "unlisted_hep_sender".to_string(),
                        detail: format!(
                            "{} receives HEP from {text}, which is no instance in the \
                             hosts file",
                            r.name
                        ),
                    });
                }
            }
        }
        hosts.push(HostRow {
            name: r.name,
            url: r.url,
            state: state.to_string(),
            error,
            inventory,
        });
    }
    if versions.len() > 1 {
        let detail = versions
            .iter()
            .map(|(line, names)| format!("{} run {line}", names.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        findings.insert(
            0,
            Finding {
                kind: "version_mismatch".to_string(),
                detail,
            },
        );
    }
    let ok = findings.is_empty() && hosts.iter().all(|h| h.state == "ok");
    FleetReport {
        schema_version: REPORT_SCHEMA_VERSION,
        ok,
        hosts,
        findings,
    }
}

/// The report as a table, one line per instance, then the findings.
#[must_use]
pub fn render_table(report: &FleetReport) -> String {
    use std::fmt::Write as _;
    /// The first twelve characters of a digest, or `-`.
    fn short(v: &serde_json::Value) -> String {
        v.as_str()
            .map_or_else(|| "-".to_string(), |d| d.chars().take(12).collect())
    }
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{:<16} {:<12} {:<12} {:<12} {:<12} {:<12} {:>6} {:>10}",
        "NAME", "STATE", "VERSION", "COMMIT", "BINARY", "CONFIG", "UID", "UPTIME_S"
    );
    for h in &report.hosts {
        match &h.inventory {
            Some(v) => {
                let _ = writeln!(
                    out,
                    "{:<16} {:<12} {:<12} {:<12} {:<12} {:<12} {:>6} {:>10}",
                    h.name,
                    h.state,
                    v["build"]["version"].as_str().unwrap_or("-"),
                    short(&v["build"]["commit"]),
                    short(&v["binary"]["sha256"]),
                    short(&v["config"]["effective_sha256"]),
                    v["privilege"]["uid"]
                        .as_u64()
                        .map_or_else(|| "-".to_string(), |u| u.to_string()),
                    v["process"]["uptime_seconds"]
                        .as_u64()
                        .map_or_else(|| "-".to_string(), |u| u.to_string()),
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "{:<16} {:<12} {}",
                    h.name,
                    h.state,
                    h.error.as_deref().unwrap_or("")
                );
            }
        }
    }
    for f in &report.findings {
        let _ = writeln!(out, "finding {}: {}", f.kind, f.detail);
    }
    out
}

/// Ask `entry` for its inventory, waiting at most `timeout` for each step.
///
/// The token is read from `entry.token_file` and goes nowhere but the
/// `Authorization` header: no error this returns quotes it.
#[must_use]
pub fn fetch(entry: &HostEntry, timeout: std::time::Duration) -> HostResult {
    let mut addresses = Vec::new();
    let answer = ask(entry, timeout, &mut addresses).unwrap_or_else(Answer::Unreachable);
    HostResult {
        name: entry.name.clone(),
        url: entry.url.clone(),
        addresses,
        answer,
    }
}

/// [`fetch`]'s work, with every failure as the message for
/// [`Answer::Unreachable`]. `addresses` receives what the URL's host
/// resolved to, even when the request then fails.
fn ask(
    entry: &HostEntry,
    timeout: std::time::Duration,
    addresses: &mut Vec<IpAddr>,
) -> Result<Answer, String> {
    use super::https_client::{Endpoint, UrlUse};
    use std::io::Read as _;
    use std::net::ToSocketAddrs as _;

    let base = Endpoint::parse(&entry.url, UrlUse::FLEET)?;
    if let Ok(found) = (base.host.as_str(), base.port).to_socket_addrs() {
        addresses.extend(found.map(|a| a.ip()));
    }
    let mut token = String::new();
    crate::privilege::open_private_file(&entry.token_file, "token_file")?
        .read_to_string(&mut token)
        .map_err(|e| format!("token_file '{}': {e}", entry.token_file.display()))?;
    let token = token.trim();
    if token.is_empty() || token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "token_file '{}' does not hold one token on one line",
            entry.token_file.display()
        ));
    }
    let tls = if base.tls {
        Some(super::https_client::client_config(
            entry.ca_file.as_deref(),
            None,
            &crate::tls_files::TrustNames {
                ca: "ca_file",
                extra: "ca_file",
                issuer: "the instance's issuer",
            },
        )?)
    } else {
        None
    };
    let path = format!("{}/v1/inventory", base.target.trim_end_matches('/'));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\
         Accept: application/json\r\nConnection: close\r\n\r\n",
        base.host_header()
    );
    super::https_client::exchange(&base, timeout, tls.as_ref(), request.as_bytes(), |reader| {
        let head = super::https_client::read_head(reader, MAX_HEAD_BYTES, "the answer's headers")?;
        let status = super::https_client::status_of(&head)?;
        if status != 200 {
            return Ok(Answer::Refused(status));
        }
        let (body, more) = super::https_client::read_body(reader, &head, MAX_ANSWER_BYTES);
        if more {
            return Err(format!(
                "the answer is larger than {MAX_ANSWER_BYTES} bytes"
            ));
        }
        serde_json::from_slice(&body)
            .map(Answer::Inventory)
            .map_err(|e| format!("the answer is not JSON: {e}"))
    })
}

/// `sipnab fleet ...`, with `args` as its whole command line, the first
/// being the command's own name. Returns the exit code.
pub fn main(args: impl IntoIterator<Item = std::ffi::OsString>) -> i32 {
    use clap::Parser as _;
    use std::io::Write as _;
    let cli = match crate::cli::fleet_args::FleetCli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { 2 } else { 0 };
        }
    };
    let crate::cli::fleet_args::FleetCommand::Inventory {
        hosts,
        json,
        timeout,
    } = cli.command;
    let mut err = std::io::stderr();
    let entries = match std::fs::read_to_string(&hosts)
        .map_err(|e| e.to_string())
        .and_then(|t| parse_hosts(&t))
    {
        Ok(entries) => entries,
        Err(e) => {
            let _ = writeln!(err, "sipnab fleet: --hosts '{}': {e}", hosts.display());
            return 2;
        }
    };
    let timeout = std::time::Duration::from_secs(timeout);
    // One thread per instance, so one slow host costs one timeout, not one
    // per host after it. The order of the report is the file's order.
    let results: Vec<HostResult> = std::thread::scope(|scope| {
        let handles: Vec<_> = entries
            .iter()
            .map(|e| scope.spawn(move || fetch(e, timeout)))
            .collect();
        handles
            .into_iter()
            .zip(&entries)
            .map(|(h, e)| {
                h.join().unwrap_or_else(|_| HostResult {
                    name: e.name.clone(),
                    url: e.url.clone(),
                    addresses: Vec::new(),
                    answer: Answer::Unreachable("the request thread failed".to_string()),
                })
            })
            .collect()
    });
    let report = merge(results);
    let text = if json {
        match serde_json::to_string_pretty(&report) {
            Ok(t) => t + "\n",
            Err(e) => {
                let _ = writeln!(err, "sipnab fleet: the report did not serialize: {e}");
                return 1;
            }
        }
    } else {
        render_table(&report)
    };
    if std::io::stdout().write_all(text.as_bytes()).is_err() {
        return 1;
    }
    i32::from(!report.ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn inv(node: &str, version_line: &str, senders: &[&str]) -> serde_json::Value {
        let senders: Vec<serde_json::Value> = senders
            .iter()
            .map(|p| serde_json::json!({"peer": p, "capture_id": 7, "silent": false}))
            .collect();
        serde_json::json!({
            "schema_version": 1,
            "node_name": node,
            "build": {"version_line": version_line, "version": "0.0.0", "commit": "abc"},
            "binary": {"sha256": "00"},
            "config": {
                "parsed_sha256": "parsedparsedparsed",
                "file_sha256": "filefilefilefile",
                "effective_sha256": format!("eff0{node}0123456789"),
            },
            "privilege": {"uid": 1000, "root": false},
            "process": {"uptime_seconds": 5},
            "hep_listener": {"listening": !senders.is_empty(), "senders": senders},
        })
    }

    fn host(name: &str, ip: &str, answer: Answer) -> Result<HostResult, TestError> {
        Ok(HostResult {
            name: name.to_string(),
            url: format!("http://{ip}:8080"),
            addresses: vec![ip.parse()?],
            answer,
        })
    }

    /// One instance down: the report still lists the other, says which one
    /// failed and why, and is not ok.
    #[test]
    fn one_unreachable_host_is_reported_and_the_rest_listed() -> Result<(), TestError> {
        let r = merge(vec![
            host(
                "edge-a",
                "192.0.2.10",
                Answer::Inventory(inv("edge-a", "v1", &[])),
            )?,
            host(
                "edge-b",
                "192.0.2.11",
                Answer::Unreachable("connection refused".into()),
            )?,
            host("edge-c", "192.0.2.12", Answer::Refused(401))?,
        ]);
        assert!(!r.ok, "two of three hosts failed, so the fleet is not ok");
        let states: Vec<&str> = r.hosts.iter().map(|h| h.state.as_str()).collect();
        assert_eq!(
            states,
            ["ok", "unreachable", "refused"],
            "one row per host, in hosts-file order, each with its own state"
        );
        assert_eq!(
            r.hosts[1].error.as_deref(),
            Some("connection refused"),
            "the unreachable row carries the reason the request failed"
        );
        assert!(
            r.hosts[2]
                .error
                .as_deref()
                .is_some_and(|e| e.contains("401")),
            "the refused row names the HTTP status"
        );
        assert_eq!(
            r.hosts[0]
                .inventory
                .as_ref()
                .map(|v| v["node_name"].clone()),
            Some(serde_json::json!("edge-a")),
            "the answering host's inventory is kept"
        );
        assert_eq!(
            r.hosts[1].inventory, None,
            "no inventory for a host that did not answer"
        );
        Ok(())
    }

    /// All answering, same build, no stray sender: ok, no findings.
    #[test]
    fn a_healthy_fleet_is_ok() -> Result<(), TestError> {
        let r = merge(vec![
            host(
                "edge-a",
                "192.0.2.10",
                Answer::Inventory(inv("edge-a", "v1", &[])),
            )?,
            host(
                "hub",
                "192.0.2.1",
                Answer::Inventory(inv("hub", "v1", &["192.0.2.10"])),
            )?,
        ]);
        assert!(r.ok, "{r:?}");
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert_eq!(r.hosts.len(), 2, "both answering hosts are listed");
        Ok(())
    }

    /// A newer inventory schema, or none, is reported as incompatible and
    /// not read as zeros.
    #[test]
    fn an_unknown_schema_is_incompatible_not_misread() -> Result<(), TestError> {
        let mut newer = inv("edge-a", "v1", &[]);
        newer["schema_version"] = serde_json::json!(2);
        let r = merge(vec![
            host("edge-a", "192.0.2.10", Answer::Inventory(newer))?,
            host(
                "edge-b",
                "192.0.2.11",
                Answer::Inventory(serde_json::json!({"x": 1})),
            )?,
        ]);
        assert!(!r.ok, "an incompatible answer makes the fleet not ok");
        for row in &r.hosts {
            assert_eq!(row.state, "incompatible", "{row:?}");
            assert_eq!(
                row.inventory, None,
                "an unreadable record was passed on: {row:?}"
            );
        }
        assert!(
            r.hosts[0].error.as_deref().is_some_and(|e| e.contains('2')),
            "the error names the schema_version the host sent"
        );
        Ok(())
    }

    /// A HEP sender whose address is no listed instance's is a finding,
    /// naming the collector and the address; a listed one is not.
    #[test]
    fn an_unlisted_hep_sender_is_a_finding() -> Result<(), TestError> {
        let r = merge(vec![
            host(
                "edge-a",
                "192.0.2.10",
                Answer::Inventory(inv("edge-a", "v1", &[])),
            )?,
            host(
                "hub",
                "192.0.2.1",
                Answer::Inventory(inv("hub", "v1", &["192.0.2.10", "198.51.100.66"])),
            )?,
        ]);
        assert!(!r.ok, "an unlisted HEP sender makes the fleet not ok");
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(
            r.findings[0].kind, "unlisted_hep_sender",
            "the finding is the unlisted sender"
        );
        assert!(
            r.findings[0].detail.contains("198.51.100.66"),
            "{:?}",
            r.findings
        );
        assert!(r.findings[0].detail.contains("hub"), "{:?}", r.findings);
        Ok(())
    }

    /// Two builds in one fleet is a finding naming both.
    #[test]
    fn two_builds_in_one_fleet_is_a_finding() -> Result<(), TestError> {
        let r = merge(vec![
            host(
                "edge-a",
                "192.0.2.10",
                Answer::Inventory(inv("edge-a", "0.5.130", &[])),
            )?,
            host(
                "edge-b",
                "192.0.2.11",
                Answer::Inventory(inv("edge-b", "0.5.131", &[])),
            )?,
        ]);
        assert!(!r.ok, "two builds make the fleet not ok");
        assert_eq!(r.findings.len(), 1, "{:?}", r.findings);
        assert_eq!(
            r.findings[0].kind, "version_mismatch",
            "the finding is the build mismatch"
        );
        assert!(
            r.findings[0].detail.contains("0.5.130") && r.findings[0].detail.contains("0.5.131"),
            "the finding names both builds"
        );
        Ok(())
    }

    /// The hosts file: names, URLs and token files; unknown keys, repeated
    /// names and an empty list refused.
    #[test]
    fn the_hosts_file_is_parsed_and_checked() {
        let good = "[[host]]\nname = \"edge-a\"\nurl = \"https://edge-a.example.net:8443\"\n\
                    token_file = \"/etc/sipnab/fleet/edge-a.token\"\n\
                    [[host]]\nname = \"hub\"\nurl = \"http://192.0.2.1:8080\"\n\
                    token_file = \"hub.token\"\nca_file = \"ca.pem\"\n";
        let hosts = parse_hosts(good);
        assert_eq!(hosts.as_ref().map(Vec::len), Ok(2), "{hosts:?}");
        let refused = [
            ("", "no host"),
            (
                "[[host]]\nname = \"a\"\nurl = \"http://192.0.2.1\"\ntoken_file = \"t\"\nport = 1\n",
                "unknown",
            ),
            (
                "[[host]]\nname = \"a\"\nurl = \"http://192.0.2.1\"\ntoken_file = \"t\"\n\
              [[host]]\nname = \"a\"\nurl = \"http://192.0.2.2\"\ntoken_file = \"t\"\n",
                "twice",
            ),
            (
                "[[host]]\nname = \"\"\nurl = \"http://192.0.2.1\"\ntoken_file = \"t\"\n",
                "empty name",
            ),
        ];
        for (text, why) in refused {
            assert!(parse_hosts(text).is_err(), "accepted ({why}): {text:?}");
        }
    }

    /// The table names every instance and its state, and every finding.
    #[test]
    fn the_table_shows_every_host_and_finding() -> Result<(), TestError> {
        let r = merge(vec![
            host(
                "edge-a",
                "192.0.2.10",
                Answer::Inventory(inv("edge-a", "0.5.130", &[])),
            )?,
            host(
                "edge-b",
                "192.0.2.11",
                Answer::Inventory(inv("edge-b", "0.5.131", &[])),
            )?,
            host(
                "edge-c",
                "192.0.2.12",
                Answer::Unreachable("timed out".into()),
            )?,
        ]);
        let t = render_table(&r);
        for want in [
            "edge-a",
            "edge-b",
            "edge-c",
            "unreachable",
            "timed out",
            "version_mismatch",
        ] {
            assert!(t.contains(want), "{want} missing from:\n{t}");
        }
        // CONFIG is the effective digest, per instance: the one that also
        // moves when a flag does.
        let row = |name: &str| t.lines().find(|l| l.starts_with(name)).unwrap_or_default();
        assert!(row("edge-a").contains("eff0edge-a01"), "{t}");
        assert!(row("edge-b").contains("eff0edge-b01"), "{t}");
        assert!(
            !t.contains("parsedparsed"),
            "the parsed digest is not CONFIG:\n{t}"
        );
        Ok(())
    }
}
