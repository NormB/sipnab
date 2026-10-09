// SPDX-License-Identifier: MIT OR Apache-2.0

//! The public vCon datasets: their pins, their containers, and what sipnab's
//! schema validator says about each one.
//!
//! Shared by `vcon_dataset_corpus_test` (the full datasets, opt-in) and
//! `vcon_dataset_subset_test` (the committed subset, always run), so the two
//! judge a container by one rule.
//!
//! Every container is judged twice: by `sipnab::output::vcon_schema::validate`
//! and by `jsonschema`, the draft-07 engine the unit tests in
//! `src/output/vcon_schema.rs` already cross-check it against. Where the two
//! disagree, one of them is wrong about the schema, and the disagreement is
//! the finding — not the dataset's verdict.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;
use sipnab::output::vcon_schema::{SchemaFinding, validate};

/// Any error, boxed, so `?` works on every error type alike.
pub type TestError = Box<dyn std::error::Error>;

/// The committed subset's root, relative to the repository.
pub const SUBSET_DIR: &str = "tests/fixtures/vcon-datasets";

/// The repository root.
pub fn repo() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// One dataset, as `PINS.tsv` names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pin {
    /// The directory the dataset lives in, in the cache and in the subset.
    pub name: String,
    /// The repository it is fetched from.
    pub url: String,
    /// The full commit it is pinned to.
    pub commit: String,
    /// The SPDX identifier of its LICENSE file at that commit.
    pub license: String,
}

/// Parse a `PINS.tsv`: `name<TAB>url<TAB>commit<TAB>license` per line, blank
/// lines and `#` comments skipped. The same grammar
/// `scripts/fetch-vcon-datasets.py` reads.
pub fn parse_pins(text: &str) -> Result<Vec<Pin>, TestError> {
    let mut out = Vec::new();
    for (number, line) in text.lines().enumerate() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split('\t').map(str::trim).collect();
        let [name, url, commit, license] = fields[..] else {
            return Err(format!("PINS.tsv:{}: expected 4 fields", number + 1).into());
        };
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("PINS.tsv:{}: {commit:?} is not a full SHA-1", number + 1).into());
        }
        out.push(Pin {
            name: name.to_owned(),
            url: url.to_owned(),
            commit: commit.to_owned(),
            license: license.to_owned(),
        });
    }
    Ok(out)
}

/// The committed pins.
pub fn pins() -> Result<Vec<Pin>, TestError> {
    let path = repo().join(SUBSET_DIR).join("PINS.tsv");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_pins(&text)
}

/// Every `*.vcon.json` under `dir`, sorted, outside `.git`, symbolic links
/// not followed. The walk the opt-in corpus and the committed subset share.
///
/// The hook point for `-I <file>.vcon.json`: when vCon input lands on main, a
/// test that reads each of these through the binary belongs beside the
/// schema pass in `vcon_dataset_corpus_test.rs`, over this same list.
pub fn containers(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            match entry.file_type() {
                Ok(t) if t.is_dir() && entry.file_name() != ".git" => stack.push(path),
                Ok(t)
                    if t.is_file()
                        && path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .is_some_and(|n| n.ends_with(".vcon.json")) =>
                {
                    out.push(path);
                }
                _ => {}
            }
        }
    }
    out.sort();
    out
}

/// The reference engine, over the vendored schema, formats asserted as
/// sipnab asserts them.
pub fn reference() -> Result<jsonschema::Validator, TestError> {
    let path = repo().join(sipnab::output::vcon_schema::SCHEMA_PATH);
    let schema: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    Ok(jsonschema::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|e| format!("compile {}: {e}", path.display()))?)
}

/// A finding with its array indices replaced by `*`, so one shape of
/// problem repeated across a hundred Dialog Objects groups as one.
pub fn finding_key(f: &SchemaFinding) -> String {
    let path: Vec<&str> = f
        .instance_path
        .split('/')
        .map(|seg| {
            if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
                "*"
            } else {
                seg
            }
        })
        .collect();
    let path = if f.instance_path.is_empty() {
        "/".to_owned()
    } else {
        path.join("/")
    };
    format!("{path} ({}): {}", f.keyword, f.detail)
}

/// What sipnab and the reference say about one container.
#[derive(Debug)]
pub enum Judgment {
    /// Not JSON at all: neither validator was asked.
    NotJson(String),
    /// Both validators answered.
    Judged {
        /// sipnab's findings, empty when valid.
        findings: Vec<SchemaFinding>,
        /// The reference's verdict.
        reference_valid: bool,
        /// Where the reference found something: each error's instance path.
        reference_paths: BTreeSet<String>,
    },
}

/// Judge one container's bytes.
pub fn judge(bytes: &[u8], reference: &jsonschema::Validator) -> Judgment {
    match serde_json::from_slice::<Value>(bytes) {
        Err(e) => Judgment::NotJson(e.to_string()),
        Ok(doc) => Judgment::Judged {
            findings: validate(&doc).errors,
            reference_valid: reference.is_valid(&doc),
            reference_paths: reference
                .iter_errors(&doc)
                .map(|e| e.instance_path().as_str().to_owned())
                .collect(),
        },
    }
}

/// Is this pair of answers a disagreement?
///
/// Two questions, because a dataset in which every container is invalid
/// makes the verdict alone prove nothing: the two must agree on the verdict
/// AND on where in the container the problems are (the set of instance
/// paths). A validator that reports the right verdict for the wrong reason
/// fails the second.
///
/// One difference is known and pinned by
/// `the_uuid_format_is_enforced_here_and_annotated_by_the_reference` in
/// `src/output/vcon_schema.rs`: the reference does not check `format: uuid`
/// and sipnab does. Those findings are set aside before comparing; anything
/// else that splits the two is a disagreement.
pub fn disagrees(
    findings: &[SchemaFinding],
    reference_valid: bool,
    reference_paths: &BTreeSet<String>,
) -> bool {
    let compared: Vec<&SchemaFinding> = findings
        .iter()
        .filter(|f| !(f.keyword == "format" && f.detail.ends_with("is not a valid uuid")))
        .collect();
    let mine: BTreeSet<String> = compared.iter().map(|f| f.instance_path.clone()).collect();
    compared.is_empty() != reference_valid || mine != *reference_paths
}

/// The totals for one dataset.
#[derive(Debug, Default)]
pub struct Tally {
    /// Containers read.
    pub files: usize,
    /// Containers that are not JSON, with why.
    pub not_json: Vec<(String, String)>,
    /// Containers with no finding.
    pub valid: usize,
    /// Containers with at least one finding.
    pub invalid: usize,
    /// Each finding key, and how many containers carry it at least once.
    pub by_finding: BTreeMap<String, usize>,
    /// Containers where sipnab and the reference split, with sipnab's keys.
    pub disagreements: Vec<(String, Vec<String>)>,
}

/// Judge every container in `files`, naming each relative to `root`.
pub fn tally(
    root: &Path,
    files: &[PathBuf],
    reference: &jsonschema::Validator,
) -> Result<Tally, TestError> {
    let mut t = Tally::default();
    for path in files {
        let name = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let bytes = std::fs::read(path).map_err(|e| format!("read {name}: {e}"))?;
        t.files += 1;
        match judge(&bytes, reference) {
            Judgment::NotJson(why) => t.not_json.push((name, why)),
            Judgment::Judged {
                findings,
                reference_valid,
                reference_paths,
            } => {
                let mut keys: Vec<String> = findings.iter().map(finding_key).collect();
                keys.sort();
                keys.dedup();
                if findings.is_empty() {
                    t.valid += 1;
                } else {
                    t.invalid += 1;
                }
                for k in &keys {
                    *t.by_finding.entry(k.clone()).or_default() += 1;
                }
                if disagrees(&findings, reference_valid, &reference_paths) {
                    t.disagreements.push((name, keys));
                }
            }
        }
    }
    Ok(t)
}

/// The report for one dataset, as lines a reader can compare across runs.
pub fn render(name: &str, t: &Tally) -> String {
    let mut s = format!(
        "{name}: {} containers, {} valid, {} with findings, {} not JSON, {} disagreements with the reference\n",
        t.files,
        t.valid,
        t.invalid,
        t.not_json.len(),
        t.disagreements.len()
    );
    let mut rows: Vec<(&String, &usize)> = t.by_finding.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    for (key, count) in rows {
        let key: String = key.chars().take(220).collect();
        s.push_str(&format!("  {count:>6}  {key}\n"));
    }
    s
}

/// Write to the real stderr, past libtest's capture, so a passing run still
/// shows its numbers.
pub fn report(text: &str) {
    let _ = std::io::stderr().write_all(text.as_bytes());
}

// ---- A store that serves files, for the fetcher ----

/// An HTTP server on `127.0.0.1` that answers `GET /<uuid>` with the bytes
/// registered for that uuid, and `404` otherwise. Nothing else: the fetcher's
/// own tests cover every other answer.
pub struct FileStore {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    stop: Arc<AtomicBool>,
}

impl FileStore {
    /// Serve `files`, uuid to bytes.
    pub fn start(files: BTreeMap<String, Vec<u8>>) -> Result<Self, TestError> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let base = format!("http://{}", listener.local_addr()?);
        let stop = Arc::new(AtomicBool::new(false));
        let halt = stop.clone();
        std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_nonblocking(false);
                        let _ = sock.set_read_timeout(Some(Duration::from_secs(10)));
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            match sock.read(&mut byte) {
                                Ok(1) => head.push(byte[0]),
                                _ => break,
                            }
                        }
                        let text = String::from_utf8_lossy(&head);
                        let target = text.split(' ').nth(1).unwrap_or_default();
                        let uuid = target.trim_start_matches('/');
                        let (status, body) = match files.get(uuid) {
                            Some(b) => ("200 OK", b.clone()),
                            None => ("404 Not Found", b"{}".to_vec()),
                        };
                        let mut answer = format!(
                            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        answer.extend_from_slice(&body);
                        let _ = sock.write_all(&answer);
                        let _ = sock.flush();
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Ok(Self { base, stop })
    }
}

impl Drop for FileStore {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// The outcome of fetching one container back through `--vcon-fetch`'s
/// generic kind.
#[derive(Debug, PartialEq, Eq)]
pub struct RoundTrip {
    /// The file the fetcher wrote is the served bytes, unchanged.
    pub identical: bool,
    /// The fetcher's findings, as it formats them.
    pub fetcher_findings: Vec<String>,
}

/// Serve each `(uuid, bytes)` from a [`FileStore`] and fetch it with the
/// generic kind, `{uuid}` in the URL, into a temporary directory.
pub fn fetch_round_trip(
    items: &[(String, Vec<u8>)],
) -> Result<Vec<(String, RoundTrip)>, TestError> {
    use sipnab::app::vcon_fetch::{FetchLimits, FetchSettings, Fetched, Fetcher, read_url};
    use sipnab::app::vcon_forward::{AuthHeader, Endpoint, StoreKind};
    use std::os::unix::fs::PermissionsExt;

    let store = FileStore::start(items.iter().cloned().collect())?;
    let dir = tempfile::tempdir()?;
    let auth_file = dir.path().join("auth");
    // Synthetic: the file store checks no credential, but the fetcher needs one.
    std::fs::write(&auth_file, format!("x-test-auth: {}\n", "dataset_corpus"))?;
    std::fs::set_permissions(&auth_file, std::fs::Permissions::from_mode(0o600))?;
    let settings = FetchSettings {
        url: read_url(
            &Endpoint::parse(&format!("{}/{{uuid}}", store.base))?,
            StoreKind::Generic,
        )?,
        kind: StoreKind::Generic,
        auth: AuthHeader::read_file_for(&auth_file, "--vcon-fetch-auth-file", StoreKind::Generic)?,
        ca: None,
        timeout: Duration::from_secs(30),
        limits: FetchLimits {
            response_head: 64 * 1024,
            max_size: 64 * 1024 * 1024,
        },
        out_dir: dir.path().join("out"),
        overwrite: false,
    };
    let fetcher = Fetcher::new(settings)?;
    let mut out = Vec::new();
    for (uuid, bytes) in items {
        match fetcher.fetch_one(uuid) {
            Fetched::Saved { path, findings } => {
                let written = std::fs::read(&path)?;
                out.push((
                    uuid.clone(),
                    RoundTrip {
                        identical: written == *bytes,
                        fetcher_findings: findings,
                    },
                ));
            }
            other => return Err(format!("{uuid}: the fetcher did not save it: {other:?}").into()),
        }
    }
    Ok(out)
}

/// The fetcher's one-line form of sipnab's findings for `doc`, to compare a
/// round trip against.
pub fn fetcher_lines(doc: &Value) -> Vec<String> {
    validate(doc)
        .errors
        .iter()
        .map(|f| format!("{} ({}): {}", f.instance_path, f.keyword, f.detail))
        .collect()
}

// ---- The committed subset's manifest ----

/// One row of a subset README's file table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubsetRow {
    /// The committed file, relative to the dataset's subset directory.
    pub file: String,
    /// The file it copies, relative to the dataset repository's root.
    pub source: String,
    /// The SHA-256 of the committed bytes, lowercase hex.
    pub sha256: String,
}

/// The file table of a subset README: every row of the form
/// `` | `file` | `source` | `sha256` | `` after the header naming `SHA-256`.
pub fn parse_subset_rows(readme: &str) -> Vec<SubsetRow> {
    let mut out = Vec::new();
    let mut in_table = false;
    for line in readme.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            in_table = false;
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        if cells.iter().any(|c| c == "SHA-256") {
            in_table = true;
            continue;
        }
        if !in_table
            || cells
                .iter()
                .all(|c| c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }
        if let [file, source, sha256] = &cells[..] {
            out.push(SubsetRow {
                file: file.clone(),
                source: source.clone(),
                sha256: sha256.clone(),
            });
        }
    }
    out
}

/// The file table of `tests/fixtures/vcon-datasets/<name>/README.md`.
pub fn subset_rows(name: &str) -> Result<Vec<SubsetRow>, TestError> {
    let path = repo().join(SUBSET_DIR).join(name).join("README.md");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    Ok(parse_subset_rows(&text))
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

// ---- The recorded dataset issues, repaired ----

/// Repair, in place, the four schema violations the datasets were measured
/// to carry on 2026-10-09, and return which repairs were applied.
///
/// Each is a rule core-04 states, so the repair is the smallest change that
/// meets it, never a value the producer meant:
///
/// * `attachment-mediatype` -- an inline Attachment Object without
///   `mediatype` ([core-04 section 4.4.5](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.5)).
/// * `attachment-start` -- an Attachment Object without `start`
///   ([core-04 section 4.4.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.4.2)); the container's
///   `created_at` is used.
/// * `dialog-content-hash` -- a Dialog Object with `url` and no
///   `content_hash` ([core-04 section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.4)); a placeholder
///   token, since the content is not fetched.
/// * `dialog-encoding` -- a Dialog Object with a non-empty `body` and no
///   `encoding` ([core-04 section 2.3.2](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2)).
///
/// A repaired container that is still invalid carries something else, and
/// that is what the corpus test exists to surface.
pub fn repair_recorded_issues(doc: &mut Value) -> BTreeSet<&'static str> {
    let mut applied = BTreeSet::new();
    let created_at = doc.get("created_at").cloned();
    let inline = |o: &serde_json::Map<String, Value>| {
        o.get("body")
            .is_some_and(|b| b.as_str().is_none_or(|s| !s.is_empty()))
    };
    if let Some(list) = doc.get_mut("attachments").and_then(Value::as_array_mut) {
        for a in list.iter_mut().filter_map(Value::as_object_mut) {
            if inline(a) && !a.contains_key("mediatype") {
                let json = a.get("encoding").and_then(Value::as_str) == Some("json");
                let media = if json {
                    "application/json"
                } else {
                    "text/plain"
                };
                a.insert("mediatype".into(), Value::from(media));
                applied.insert("attachment-mediatype");
            }
            if !a.contains_key("start")
                && let Some(t) = &created_at
            {
                a.insert("start".into(), t.clone());
                applied.insert("attachment-start");
            }
        }
    }
    if let Some(list) = doc.get_mut("dialog").and_then(Value::as_array_mut) {
        for d in list.iter_mut().filter_map(Value::as_object_mut) {
            if d.contains_key("url") && !d.contains_key("content_hash") {
                d.insert(
                    "content_hash".into(),
                    Value::from(format!("sha512-{}", "A".repeat(86))),
                );
                applied.insert("dialog-content-hash");
            }
            if inline(d) && !d.contains_key("encoding") {
                d.insert("encoding".into(), Value::from("none"));
                applied.insert("dialog-encoding");
            }
        }
    }
    applied
}
