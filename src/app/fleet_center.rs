// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! `sipnab fleet serve`: a central sipnab that fleet members report to.
//!
//! Phase P1 of the fleet center (heartbeats). Each member pushes a heartbeat
//! to `POST /v1/fleet/ingest`; the center keeps the latest one per member,
//! says which members went silent, and serves them on
//! `GET /v1/fleet/members`.
//!
//! # Who a member is
//!
//! The member is the id of the bearer token it presented, a token of scope
//! `fleet-report` the center's own signing key minted. The signature is
//! what the center verified, so that id is the one identity in the record the
//! center vouches for. Everything in the heartbeat itself (node name, build,
//! configuration, counters) is the member's own claim, and the members answer
//! keeps it under `self_reported`. Revoking a member is revoking its token id
//! in the center's revocation file.
//!
//! # What is pure and what is not
//!
//! [`parse_batch`], [`admits`], [`is_silent`] and the [`Registry`] methods
//! take their inputs, the clock included, as arguments and hold every rule:
//! what a record must carry, when a record is a replay, when a member is
//! silent, what retention removes. [`Store`] is the one type that touches
//! the store file, and [`serve`] the one function that binds a socket.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Wire-format version of an ingest record this build reads.
pub const RECORD_SCHEMA_VERSION: u64 = 1;

/// Wire-format version of the members answer.
pub const MEMBERS_SCHEMA_VERSION: u32 = 1;

/// The one record kind P1 accepts.
pub const KIND_HEARTBEAT: &str = "heartbeat";

/// The shortest heartbeat interval a record may claim, in seconds.
pub const MIN_HEARTBEAT_SECS: u64 = 1;

/// The longest heartbeat interval a record may claim, in seconds.
pub const MAX_HEARTBEAT_SECS: u64 = 3600;

/// The most records one ingest request may carry.
///
/// Not a setting: a member sends what its spool holds, one request per spool
/// file, and one file holds one heartbeat. The bound is for a client that is
/// not a sipnab member.
pub const MAX_BATCH_RECORDS: usize = 1000;

/// The largest ingest body, in bytes; a larger one is answered `413`.
///
/// Not a setting: an inventory record is a few kilobytes, so this holds a
/// full batch of them with room to spare.
pub const MAX_INGEST_BYTES: usize = 4 * 1024 * 1024;

/// The longest member id (token id) and stream id.
pub const MAX_ID_LEN: usize = 64;

/// How often the center checks for silent members and logs a change.
const SILENCE_CHECK: std::time::Duration = std::time::Duration::from_secs(1);

/// How often the center applies retention and rewrites its store.
///
/// Not a setting: retention is in hours, so a minute's delay is inside it,
/// and a rewrite costs one file of the newest record per member.
const UPKEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// One heartbeat, as a member sent it.
#[derive(Debug, Clone, PartialEq)]
pub struct Heartbeat {
    /// The member's delivery stream: a random id its spool chose once.
    pub stream: String,
    /// Its position in that stream, from 1.
    pub seq: u64,
    /// When the member wrote it, on the member's clock.
    pub sent_at: DateTime<Utc>,
    /// How often the member says it sends one.
    pub heartbeat_secs: u64,
    /// The member's inventory record (`GET /v1/inventory`), as it sent it.
    pub inventory: serde_json::Value,
}

/// One ingest record on the wire.
#[derive(Debug, Deserialize)]
struct WireRecord {
    /// [`RECORD_SCHEMA_VERSION`].
    schema_version: u64,
    /// [`KIND_HEARTBEAT`].
    kind: String,
    /// See [`Heartbeat::stream`].
    stream: String,
    /// See [`Heartbeat::seq`].
    seq: u64,
    /// See [`Heartbeat::sent_at`], RFC 3339.
    sent_at: String,
    /// See [`Heartbeat::heartbeat_secs`].
    heartbeat_secs: u64,
    /// See [`Heartbeat::inventory`].
    inventory: serde_json::Value,
}

/// Parse an ingest body: one JSON record per line, blank lines ignored.
///
/// All or nothing: one bad record refuses the batch, so a member never has
/// half a batch accepted and has to find out which half.
///
/// # Errors
///
/// A body that is not UTF-8, holds no record or more than
/// [`MAX_BATCH_RECORDS`], or a record that is not JSON, names another
/// `schema_version` or `kind`, or carries a field out of its range. The
/// message names the line.
pub fn parse_batch(body: &[u8]) -> Result<Vec<Heartbeat>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the body is not UTF-8".to_string())?;
    let mut out = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let n = index + 1;
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if out.len() == MAX_BATCH_RECORDS {
            return Err(format!(
                "line {n}: more than {MAX_BATCH_RECORDS} records in one batch"
            ));
        }
        let record: WireRecord =
            serde_json::from_str(raw).map_err(|e| format!("line {n}: not a record: {e}"))?;
        out.push(heartbeat(record).map_err(|e| format!("line {n}: {e}"))?);
    }
    if out.is_empty() {
        return Err("the batch holds no record".to_string());
    }
    Ok(out)
}

/// `record` as a [`Heartbeat`], or why it is not one.
fn heartbeat(record: WireRecord) -> Result<Heartbeat, String> {
    if record.schema_version != RECORD_SCHEMA_VERSION {
        return Err(format!(
            "schema_version {}; this center reads {RECORD_SCHEMA_VERSION}",
            record.schema_version
        ));
    }
    if record.kind != KIND_HEARTBEAT {
        return Err(format!(
            "kind {:?}; this center accepts {KIND_HEARTBEAT:?}",
            cut(&record.kind)
        ));
    }
    if !is_valid_id(&record.stream) {
        return Err(format!(
            "stream must be 1 to {MAX_ID_LEN} letters, digits, '.', '_' or '-'"
        ));
    }
    if record.seq == 0 {
        return Err("seq must be 1 or more".to_string());
    }
    let sent_at = DateTime::parse_from_rfc3339(&record.sent_at)
        .map_err(|_| format!("sent_at {:?} is not an RFC 3339 time", cut(&record.sent_at)))?
        .with_timezone(&Utc);
    if !(MIN_HEARTBEAT_SECS..=MAX_HEARTBEAT_SECS).contains(&record.heartbeat_secs) {
        return Err(format!(
            "heartbeat_secs {} is outside {MIN_HEARTBEAT_SECS} to {MAX_HEARTBEAT_SECS}",
            record.heartbeat_secs
        ));
    }
    if !record.inventory.is_object() {
        return Err("inventory must be a JSON object".to_string());
    }
    Ok(Heartbeat {
        stream: record.stream,
        seq: record.seq,
        sent_at,
        heartbeat_secs: record.heartbeat_secs,
        inventory: record.inventory,
    })
}

/// At most the first 64 characters of a value a client sent, for an error.
fn cut(value: &str) -> String {
    value.chars().take(MAX_ID_LEN).collect()
}

/// Whether `id` may name a member or a stream: 1 to [`MAX_ID_LEN`] ASCII
/// letters, digits, `.`, `_` or `-`.
#[must_use]
pub fn is_valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Where a member's accepted records stand: the stream, position and send
/// time of the newest one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The stream of the newest accepted record.
    pub stream: String,
    /// Its position.
    pub seq: u64,
    /// Its send time, on the member's clock.
    pub sent_at: DateTime<Utc>,
}

/// Whether a record is new for a member whose newest accepted record is at
/// `prev`.
///
/// In the same stream, a record is new when its position is past `prev`'s.
/// In another stream, when it was sent after `prev`: a member whose spool
/// was recreated starts a new stream from 1, and a replayed record of an old
/// stream was sent before the newest one. The send time is the member's
/// own clock, which is the member's claim about itself, like the rest of
/// the record; it decides only which of that member's records count.
#[must_use]
pub fn admits(prev: Option<&Cursor>, hb: &Heartbeat) -> bool {
    match prev {
        None => true,
        Some(prev) if prev.stream == hb.stream => hb.seq > prev.seq,
        Some(prev) => hb.sent_at > prev.sent_at,
    }
}

/// Whether a member last heard at `last` is silent at `now`: more than
/// `missed` of its `heartbeat_secs` intervals have passed.
///
/// Measured on the center's clock at both ends, so a member's clock cannot
/// make it look alive. A `now` before `last` (the center's clock stepped
/// back) is not silence.
#[must_use]
pub fn is_silent(
    now: DateTime<Utc>,
    last: DateTime<Utc>,
    heartbeat_secs: u64,
    missed: u32,
) -> bool {
    let allowed = heartbeat_secs.saturating_mul(u64::from(missed));
    // Saturating, not panicking: a record read back from the store carries
    // whatever interval the file holds, and chrono refuses a span past its
    // range by panicking.
    let allowed = i64::try_from(allowed)
        .ok()
        .and_then(chrono::Duration::try_seconds)
        .unwrap_or(chrono::Duration::MAX);
    now.signed_duration_since(last) > allowed
}

/// One member's newest accepted heartbeat, as the store keeps it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberRecord {
    /// The member: its token's id.
    pub member: String,
    /// When the center received the heartbeat, on the center's clock.
    pub received_at: DateTime<Utc>,
    /// The address the request came from.
    pub peer: String,
    /// Heartbeats accepted from this member, this one included.
    pub heartbeats: u64,
    /// Where the member's records stand.
    pub cursor: Cursor,
    /// The interval the member claims.
    pub heartbeat_secs: u64,
    /// The member's inventory, as it sent it.
    pub inventory: serde_json::Value,
}

/// Every member's newest accepted heartbeat.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Registry {
    /// By member id.
    members: BTreeMap<String, MemberRecord>,
}

/// What one ingest request does to the registry, before it is written.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Records that are new.
    pub accepted: usize,
    /// Records already accepted, or older than the member's newest.
    pub duplicate: usize,
    /// The member's record after this request, when anything was accepted:
    /// what the store appends and the registry then holds.
    pub record: Option<MemberRecord>,
}

impl Registry {
    /// The registry the store's records describe: the last record per
    /// member, in file order.
    #[must_use]
    pub fn from_records(records: Vec<MemberRecord>) -> Self {
        let mut members = BTreeMap::new();
        for record in records {
            members.insert(record.member.clone(), record);
        }
        Self { members }
    }

    /// What `batch` from `member` at `peer`, received at `now`, would change.
    ///
    /// Each record is checked against the newest accepted before it, the
    /// batch's own earlier records included, so a batch that repeats a
    /// record counts it once.
    #[must_use]
    pub fn plan(&self, member: &str, peer: &str, now: DateTime<Utc>, batch: &[Heartbeat]) -> Plan {
        let mut current = self.members.get(member).cloned();
        let mut accepted = 0;
        let mut duplicate = 0;
        for hb in batch {
            if !admits(current.as_ref().map(|r| &r.cursor), hb) {
                duplicate += 1;
                continue;
            }
            accepted += 1;
            current = Some(MemberRecord {
                member: member.to_string(),
                received_at: now,
                peer: peer.to_string(),
                heartbeats: current
                    .as_ref()
                    .map_or(0, |r| r.heartbeats)
                    .saturating_add(1),
                cursor: Cursor {
                    stream: hb.stream.clone(),
                    seq: hb.seq,
                    sent_at: hb.sent_at,
                },
                heartbeat_secs: hb.heartbeat_secs,
                inventory: hb.inventory.clone(),
            });
        }
        Plan {
            accepted,
            duplicate,
            record: if accepted > 0 { current } else { None },
        }
    }

    /// Apply a plan once the store holds its record.
    pub fn commit(&mut self, plan: Plan) {
        if let Some(record) = plan.record {
            self.members.insert(record.member.clone(), record);
        }
    }

    /// Remove every member last heard before `now - retention`, and return
    /// their ids.
    pub fn expire(&mut self, now: DateTime<Utc>, retention: chrono::Duration) -> Vec<String> {
        let cutoff = now - retention;
        let gone: Vec<String> = self
            .members
            .values()
            .filter(|r| r.received_at < cutoff)
            .map(|r| r.member.clone())
            .collect();
        for member in &gone {
            self.members.remove(member);
        }
        gone
    }

    /// The members' records, by member id.
    #[must_use]
    pub fn records(&self) -> Vec<&MemberRecord> {
        self.members.values().collect()
    }

    /// The ids of the members silent at `now`.
    #[must_use]
    pub fn silent(&self, now: DateTime<Utc>, missed: u32) -> Vec<String> {
        self.members
            .values()
            .filter(|r| is_silent(now, r.received_at, r.heartbeat_secs, missed))
            .map(|r| r.member.clone())
            .collect()
    }

    /// The members answer at `now`.
    ///
    /// Each member's row keeps what the center verified (`member`, the token
    /// id; `verified`: when and from where the heartbeat arrived, and how
    /// many it accepted) apart from what the member says about itself
    /// (`self_reported`: its stream, position, send time, interval and
    /// inventory). `silent` and `seconds_since_heartbeat` are measured on the
    /// center's clock.
    #[must_use]
    pub fn report(
        &self,
        now: DateTime<Utc>,
        missed: u32,
        retention_hours: u64,
    ) -> serde_json::Value {
        let secs = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let members: Vec<serde_json::Value> = self
            .members
            .values()
            .map(|r| {
                serde_json::json!({
                    "member": r.member,
                    "silent": is_silent(now, r.received_at, r.heartbeat_secs, missed),
                    "seconds_since_heartbeat":
                        now.signed_duration_since(r.received_at).num_seconds().max(0),
                    "verified": {
                        "received_at": secs(r.received_at),
                        "peer": r.peer,
                        "heartbeats": r.heartbeats,
                    },
                    "self_reported": {
                        "stream": r.cursor.stream,
                        "seq": r.cursor.seq,
                        "sent_at": secs(r.cursor.sent_at),
                        "heartbeat_secs": r.heartbeat_secs,
                        "inventory": r.inventory,
                    },
                })
            })
            .collect();
        serde_json::json!({
            "schema_version": MEMBERS_SCHEMA_VERSION,
            "now": secs(now),
            "silent_after_missed": missed,
            "retention_hours": retention_hours,
            "members": members,
        })
    }
}

/// The store file: one [`MemberRecord`] per line, appended as heartbeats
/// arrive and rewritten to the newest per member by [`Store::compact`].
///
/// Created with mode 0600 and refused when other users can read it, because
/// it holds every member's inventory. Each append is synced before the
/// center answers, so a heartbeat the center acknowledged survives a crash,
/// and a replay of it is still recognized afterwards.
#[derive(Debug)]
pub struct Store {
    /// The file.
    path: PathBuf,
    /// Lines appended since the last rewrite.
    appended: usize,
}

impl Store {
    /// Open the store at `path`, creating it with mode 0600 when absent, and
    /// return the records it holds.
    ///
    /// A last line that does not parse is dropped: it is a write the center
    /// did not finish, and so never acknowledged.
    ///
    /// # Errors
    ///
    /// The file cannot be created or read, other users can read it, or a
    /// line before the last does not parse. The message names the path and
    /// the line.
    pub fn open(path: &Path) -> Result<(Self, Vec<MemberRecord>), String> {
        let shown = path.display();
        let text = match std::fs::read(path) {
            Ok(bytes) => {
                check_private(path)?;
                String::from_utf8_lossy(&bytes).into_owned()
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                create_private(path).map_err(|e| format!("--store '{shown}': {e}"))?;
                String::new()
            }
            Err(e) => return Err(format!("--store '{shown}': {e}")),
        };
        let lines: Vec<&str> = text.lines().collect();
        let mut records = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<MemberRecord>(line) {
                Ok(record) => records.push(record),
                Err(_) if index + 1 == lines.len() => {
                    tracing::warn!(
                        "--store '{shown}': line {} is incomplete, from a write the center \
                         did not finish; it is dropped",
                        index + 1
                    );
                }
                Err(e) => {
                    return Err(format!(
                        "--store '{shown}': line {} is not a member record: {e}",
                        index + 1
                    ));
                }
            }
        }
        Ok((
            Self {
                path: path.to_path_buf(),
                appended: 0,
            },
            records,
        ))
    }

    /// Append `record` and wait until it is on disk.
    ///
    /// # Errors
    ///
    /// The file cannot be opened, written or synced.
    pub fn append(&mut self, record: &MemberRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
        line.push(b'\n');
        let mut file = std::fs::OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(&line)?;
        file.sync_data()?;
        self.appended += 1;
        Ok(())
    }

    /// Rewrite the store to hold exactly `registry`'s records, mode 0600:
    /// staged beside it and renamed over it, so a reader sees the old file
    /// or the new one.
    ///
    /// # Errors
    ///
    /// The staged file cannot be written, synced or renamed.
    pub fn compact(&mut self, registry: &Registry) -> std::io::Result<()> {
        let name = self
            .path
            .file_name()
            .map_or_else(|| "store".into(), |n| n.to_string_lossy().into_owned());
        let staged = self.path.with_file_name(format!(".{name}.partial"));
        let _ = std::fs::remove_file(&staged);
        let result = (|| {
            let mut file = create_private(&staged)?;
            for record in registry.records() {
                let mut line = serde_json::to_vec(record).map_err(std::io::Error::other)?;
                line.push(b'\n');
                file.write_all(&line)?;
            }
            file.sync_all()?;
            std::fs::rename(&staged, &self.path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        result?;
        self.appended = 0;
        Ok(())
    }

    /// Lines appended since the last rewrite.
    #[must_use]
    pub fn appended(&self) -> usize {
        self.appended
    }
}

/// Create `path` new, readable and writable by this user only.
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

/// Refuse a store other users can read, by the rule every private file
/// sipnab reads follows ([`crate::privilege::permission_refusal`]).
fn check_private(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let meta =
            std::fs::metadata(path).map_err(|e| format!("--store '{}': {e}", path.display()))?;
        if let Some(why) = crate::privilege::permission_refusal(
            meta.uid(),
            crate::privilege::current_uid(),
            meta.mode(),
            meta.file_type().is_file(),
        ) {
            return Err(format!("--store '{}' {why}", path.display()));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// The refusal for serving plain HTTP on `addr`, or `None`.
///
/// Members send their inventory and their bearer token to the center, so
/// the center serves HTTPS, except on a loopback address, where nothing
/// crosses a network.
#[must_use]
pub fn plain_http_refusal(addr: std::net::SocketAddr, tls: bool) -> Option<String> {
    if tls || addr.ip().is_loopback() {
        return None;
    }
    Some(format!(
        "--listen {addr} without --tls-cert and --tls-key would take members' tokens and \
         inventories in plain HTTP; plain HTTP is refused except on loopback"
    ))
}

/// What the center's client-certificate refusals call its flags.
const FLEET_CLIENT_AUTH_LABELS: crate::cli::ClientAuthLabels<'static> =
    crate::cli::ClientAuthLabels {
        ca: "--tls-client-ca",
        mode: "--tls-client-auth",
        first: "--tls-cert",
        second: "--tls-key",
    };

/// What `sipnab fleet serve` was asked for.
#[derive(Debug, Clone)]
pub struct ServeArgs {
    /// `--listen`: the address to serve on.
    pub listen: String,
    /// `--store`: the store file.
    pub store: PathBuf,
    /// `--signing-key-file`: the key member and reader tokens are minted with.
    pub signing_key_file: PathBuf,
    /// `--revoked-file`: token ids no longer accepted, one per line.
    pub revoked_file: Option<PathBuf>,
    /// `--tls-cert`.
    pub tls_cert: Option<String>,
    /// `--tls-key`.
    pub tls_key: Option<String>,
    /// `--tls-client-ca` and `--tls-client-auth`: the member certificates
    /// the HTTPS handshake asks for.
    pub client_auth: crate::config::ClientCertAuth,
    /// `--retention-hours`: how long a member nobody heard from is kept.
    pub retention_hours: u64,
    /// `--silent-after-missed`: how many heartbeat intervals make a member
    /// silent.
    pub silent_after_missed: u32,
    /// `--allowed-host`: `Host` values served beyond loopback and the bound
    /// address.
    pub allowed_hosts: Vec<String>,
    /// `--rate-limit-per-peer`: requests per second per address; 0 is off.
    pub rate_limit_per_peer: u32,
}

/// The center a running `sipnab fleet serve` holds.
struct Center {
    /// The members.
    registry: Registry,
    /// The store file.
    store: Store,
}

/// What every request handler shares.
#[derive(Clone)]
struct CenterState {
    /// The members and the store, behind one lock: a heartbeat is written
    /// and applied as one step.
    center: Arc<parking_lot::Mutex<Center>>,
    /// Verifies member and reader tokens.
    verifier: Arc<crate::auth::TokenVerifier>,
    /// Requests per second per address.
    limiter: Arc<parking_lot::Mutex<crate::output::api::RateLimiter>>,
    /// `--silent-after-missed`.
    missed: u32,
    /// `--retention-hours`.
    retention_hours: u64,
}

/// The most peers the rate limiter tracks.
const MAX_TRACKED_PEERS: usize = 4096;

/// Run `sipnab fleet serve` until SIGINT or SIGTERM. Returns the exit code:
/// 0 when stopped, 2 when the arguments, the key, the store or the listener
/// are refused.
///
/// # Side effects
///
/// Reads the signing key, opens and rewrites the store, binds the listener,
/// serves until stopped, and logs.
pub fn serve(args: ServeArgs) -> i32 {
    match prepare(&args) {
        Ok((addr, state, server_config)) => {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    stderr_line!("sipnab fleet serve: the runtime did not start: {e}");
                    return 2;
                }
            };
            runtime.block_on(run(addr, state, server_config))
        }
        Err(e) => {
            stderr_line!("sipnab fleet serve: {e}");
            2
        }
    }
}

/// Check the arguments, read the key, open the store and apply retention.
fn prepare(
    args: &ServeArgs,
) -> Result<
    (
        std::net::SocketAddr,
        CenterState,
        crate::output::api::ApiServerConfig,
    ),
    String,
> {
    use std::io::Read as _;
    let addr = crate::output::api::parse_bind_addr(&args.listen)
        .map_err(|e| format!("--listen {}: {e}", args.listen))?;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(_), Some(_)) => true,
        (None, None) => false,
        _ => return Err("--tls-cert and --tls-key go together".to_string()),
    };
    if let Some(refusal) = plain_http_refusal(addr, tls) {
        return Err(refusal);
    }
    crate::cli::client_auth_problem(FLEET_CLIENT_AUTH_LABELS, &args.client_auth, tls)?;
    let mut key = String::new();
    crate::privilege::open_private_file(&args.signing_key_file, "--signing-key-file")?
        .read_to_string(&mut key)
        .map_err(|e| {
            format!(
                "--signing-key-file '{}': {e}",
                args.signing_key_file.display()
            )
        })?;
    let key = key.trim();
    if key.is_empty() {
        return Err(format!(
            "--signing-key-file '{}' is empty",
            args.signing_key_file.display()
        ));
    }
    let verifier = crate::auth::TokenVerifier::new(crate::auth::VerifierConfig {
        signing_keys: vec![key.as_bytes().to_vec()],
        static_keys: Vec::new(),
        revoked_file: args.revoked_file.clone(),
        audience: crate::auth::AUDIENCE_API.to_string(),
    });
    let (mut store, records) = Store::open(&args.store)?;
    let mut registry = Registry::from_records(records);
    let gone = registry.expire(Utc::now(), retention(args.retention_hours));
    store
        .compact(&registry)
        .map_err(|e| format!("--store '{}': {e}", args.store.display()))?;
    tracing::info!(
        "fleet center store '{}': {} member(s), {} past --retention-hours {} removed",
        args.store.display(),
        registry.records().len(),
        gone.len(),
        args.retention_hours
    );
    let state = CenterState {
        center: Arc::new(parking_lot::Mutex::new(Center { registry, store })),
        verifier: Arc::new(verifier),
        limiter: Arc::new(parking_lot::Mutex::new(
            crate::output::api::RateLimiter::new(args.rate_limit_per_peer, MAX_TRACKED_PEERS),
        )),
        missed: args.silent_after_missed,
        retention_hours: args.retention_hours,
    };
    let server_config = crate::output::api::ApiServerConfig {
        max_conn: 0,
        tls_cert: args.tls_cert.clone(),
        tls_key: args.tls_key.clone(),
        client_auth: args.client_auth.clone(),
        allowed_hosts: args.allowed_hosts.clone(),
        // The fleet center serves its own routes, not the capture API's.
        console: false,
    };
    Ok((addr, state, server_config))
}

/// `--retention-hours` as a duration.
fn retention(hours: u64) -> chrono::Duration {
    chrono::Duration::hours(i64::try_from(hours).unwrap_or(i64::MAX / 3600))
}

/// Bind, serve, keep the store, and stop on SIGINT or SIGTERM.
async fn run(
    addr: std::net::SocketAddr,
    state: CenterState,
    server_config: crate::output::api::ApiServerConfig,
) -> i32 {
    let (listener, router) = match bind(addr, &state, &server_config) {
        Ok(bound) => bound,
        Err(e) => {
            stderr_line!("sipnab fleet serve: {e}");
            return 2;
        }
    };
    tokio::spawn(upkeep(state.clone()));
    let code = serve_until_stopped(listener, router).await;
    rewrite_on_exit(&state);
    code
}

/// Bind the listener and build the router behind the `Host` allowlist.
fn bind(
    addr: std::net::SocketAddr,
    state: &CenterState,
    server_config: &crate::output::api::ApiServerConfig,
) -> Result<(crate::output::api::ApiListener, axum::Router), crate::Error> {
    let listener = crate::output::api::prepare_listener(addr, &state.verifier, server_config)?;
    let bound = listener.local_addr().unwrap_or(addr);
    let hosts = crate::host_allowlist::HostAllowlist::new(bound, &server_config.allowed_hosts);
    let router = crate::output::api::with_host_allowlist(router(state.clone()), hosts);
    tracing::info!(
        "fleet center serving {} on {bound}",
        if listener.is_tls() { "HTTPS" } else { "HTTP" }
    );
    Ok((listener, router))
}

/// Serve until the server fails (2) or a stop is asked for (0).
async fn serve_until_stopped(
    listener: crate::output::api::ApiListener,
    router: axum::Router,
) -> i32 {
    tokio::select! {
        served = crate::output::api::serve_router(listener, router) => match served {
            Ok(()) => 0,
            Err(e) => {
                stderr_line!("sipnab fleet serve: {e}");
                2
            }
        },
        () = stop_requested() => {
            tracing::info!("fleet center stopping: a stop was asked for");
            0
        }
    }
}

/// Resolves on SIGINT, or SIGTERM where there is one.
async fn stop_requested() {
    #[cfg(unix)]
    {
        let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        else {
            let _ = tokio::signal::ctrl_c().await;
            return;
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Rewrite the store once more as the center stops.
fn rewrite_on_exit(state: &CenterState) {
    let mut center = state.center.lock();
    let Center { registry, store } = &mut *center;
    if let Err(e) = store.compact(registry) {
        tracing::warn!("fleet center: the store was not rewritten on the way out: {e}");
    }
}

/// The center's routes.
fn router(state: CenterState) -> axum::Router {
    use axum::routing::{get, post};
    axum::Router::new()
        .route("/v1/fleet/ingest", post(ingest))
        .route("/v1/fleet/members", get(members))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_INGEST_BYTES))
        .with_state(state)
}

/// Charge `peer` to the rate limit: `503` when over it, before any
/// credential is looked at, as the REST API does.
fn limit(state: &CenterState, peer: std::net::IpAddr) -> Result<(), crate::output::api::Problem> {
    if state.limiter.lock().check(peer) {
        Ok(())
    } else {
        Err(crate::output::api::Problem::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ))
    }
}

/// `POST /v1/fleet/ingest`: a member's heartbeats.
///
/// `401` without a `fleet-report` token, `403` for one whose id cannot name
/// a member, `400` for a batch that does not parse, `413` past
/// [`MAX_INGEST_BYTES`], `503` over the rate limit or when the store cannot
/// be written; else `200` with how many records were new and how many were
/// replays.
async fn ingest(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    use crate::output::api::Problem;
    use axum::http::StatusCode;
    limit(&state, peer.ip())?;
    let token = crate::output::api::verify_bearer(
        &state.verifier,
        &headers,
        crate::auth::SCOPE_FLEET_REPORT,
    )?;
    let member = token.id.filter(|id| is_valid_id(id)).ok_or_else(|| {
        Problem::detailed(
            StatusCode::FORBIDDEN,
            format!(
                "the token's id names no member: mint it with --token-id of 1 to {MAX_ID_LEN} \
                 letters, digits, '.', '_' or '-'"
            ),
        )
    })?;
    let batch = parse_batch(&body).map_err(|e| Problem::detailed(StatusCode::BAD_REQUEST, e))?;
    let now = Utc::now();
    let peer = peer.ip().to_canonical().to_string();
    let center = Arc::clone(&state.center);
    let who = member.clone();
    let done = tokio::task::spawn_blocking(move || {
        let mut center = center.lock();
        let plan = center.registry.plan(&who, &peer, now, &batch);
        if let Some(record) = &plan.record {
            center.store.append(record)?;
        }
        let counts = (plan.accepted, plan.duplicate);
        center.registry.commit(plan);
        Ok::<_, std::io::Error>(counts)
    })
    .await
    .map_err(|_| Problem::new(StatusCode::INTERNAL_SERVER_ERROR))?;
    let (accepted, duplicate) = done.map_err(|e| {
        tracing::error!("fleet center: the store could not be written: {e}");
        Problem::detailed(
            StatusCode::SERVICE_UNAVAILABLE,
            "the center could not write its store; send the batch again",
        )
    })?;
    Ok(axum::Json(serde_json::json!({
        "member": member,
        "accepted": accepted,
        "duplicate": duplicate,
    })))
}

/// `GET /v1/fleet/members`: every member, its health and its heartbeat.
/// Needs scope `inventory` (or `full`, `actions`, `admin`).
async fn members(
    axum::extract::State(state): axum::extract::State<CenterState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: axum::http::HeaderMap,
) -> Result<axum::Json<serde_json::Value>, crate::output::api::Problem> {
    limit(&state, peer.ip())?;
    crate::output::api::verify_bearer(&state.verifier, &headers, crate::auth::SCOPE_INVENTORY)?;
    let center = state.center.lock();
    Ok(axum::Json(center.registry.report(
        Utc::now(),
        state.missed,
        state.retention_hours,
    )))
}

/// Log members going silent and coming back, every [`SILENCE_CHECK`]; apply
/// retention and rewrite the store every [`UPKEEP_EVERY`].
async fn upkeep(state: CenterState) {
    let mut silent: BTreeSet<String> = BTreeSet::new();
    let mut tick = tokio::time::interval(SILENCE_CHECK);
    let mut last_upkeep = tokio::time::Instant::now();
    loop {
        tick.tick().await;
        let now = Utc::now();
        let mut center = state.center.lock();
        silent = log_silence_changes(&center.registry, now, state.missed, &silent);
        if last_upkeep.elapsed() >= UPKEEP_EVERY {
            last_upkeep = tokio::time::Instant::now();
            for member in apply_retention(&mut center, now, state.retention_hours) {
                silent.remove(&member);
            }
        }
    }
}

/// Log each member that went silent or came back since `before`, the set
/// silent at the last check, and return the set silent at `now`.
fn log_silence_changes(
    registry: &Registry,
    now: DateTime<Utc>,
    missed: u32,
    before: &BTreeSet<String>,
) -> BTreeSet<String> {
    let silent_now: BTreeSet<String> = registry.silent(now, missed).into_iter().collect();
    for r in registry.records() {
        if silent_now.contains(&r.member) && !before.contains(&r.member) {
            tracing::warn!(
                "fleet member '{}' is silent: no heartbeat for {} s, more than {missed} of \
                 its {} s intervals",
                r.member,
                now.signed_duration_since(r.received_at).num_seconds(),
                r.heartbeat_secs
            );
        }
    }
    for member in before.difference(&silent_now) {
        tracing::info!("fleet member '{member}' is heard again");
    }
    silent_now
}

/// Remove the members past retention, rewrite the store when anything
/// changed, and return the members removed.
fn apply_retention(center: &mut Center, now: DateTime<Utc>, retention_hours: u64) -> Vec<String> {
    let Center { registry, store } = center;
    let gone = registry.expire(now, retention(retention_hours));
    for member in &gone {
        tracing::info!(
            "fleet member '{member}' removed: not heard for --retention-hours {retention_hours}"
        );
    }
    if (store.appended() > 0 || !gone.is_empty())
        && let Err(e) = store.compact(registry)
    {
        tracing::warn!("fleet center: the store was not rewritten: {e}");
    }
    gone
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    fn t(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    fn line(stream: &str, seq: u64, sent_at: &str, secs: u64) -> String {
        serde_json::json!({
            "schema_version": 1,
            "kind": "heartbeat",
            "stream": stream,
            "seq": seq,
            "sent_at": sent_at,
            "heartbeat_secs": secs,
            "inventory": {"schema_version": 1, "node_name": "edge-a"},
        })
        .to_string()
    }

    fn hb(stream: &str, seq: u64, sent_at: &str) -> Result<Heartbeat, TestError> {
        Ok(Heartbeat {
            stream: stream.to_string(),
            seq,
            sent_at: t(sent_at)?,
            heartbeat_secs: 30,
            inventory: serde_json::json!({"node_name": "edge-a"}),
        })
    }

    /// A body of heartbeat lines parses, blank lines and a final newline
    /// included, each record with its fields.
    #[test]
    fn a_batch_of_heartbeats_parses() -> Result<(), TestError> {
        let body = format!(
            "{}\n\n{}\n",
            line("s-1", 1, "2026-11-07T12:00:00Z", 30),
            line("s-1", 2, "2026-11-07T12:00:30Z", 30)
        );
        let got = parse_batch(body.as_bytes())?;
        assert_eq!(got.len(), 2, "two records: {got:?}");
        assert_eq!(got[1].seq, 2, "{got:?}");
        assert_eq!(got[1].stream, "s-1", "{got:?}");
        assert_eq!(got[1].sent_at, t("2026-11-07T12:00:30Z")?, "{got:?}");
        assert_eq!(got[0].heartbeat_secs, 30, "{got:?}");
        assert_eq!(
            got[0].inventory["node_name"], "edge-a",
            "the inventory is kept as sent"
        );
        Ok(())
    }

    /// Every malformed record refuses the whole batch, and the reason names
    /// the line, so nothing is half accepted.
    #[test]
    fn a_malformed_record_refuses_the_batch_and_names_the_line() -> Result<(), TestError> {
        let good = line("s-1", 1, "2026-11-07T12:00:00Z", 30);
        let with = |key: &str, value: serde_json::Value| -> Result<String, TestError> {
            let mut v: serde_json::Value = serde_json::from_str(&good)?;
            v[key] = value;
            Ok(v.to_string())
        };
        let cases: Vec<(String, &str)> = vec![
            ("not json".to_string(), "line 2"),
            (with("kind", serde_json::json!("rollup"))?, "kind"),
            (
                with("schema_version", serde_json::json!(2))?,
                "schema_version",
            ),
            (with("stream", serde_json::json!("bad stream!"))?, "stream"),
            (with("seq", serde_json::json!(0))?, "seq"),
            (with("sent_at", serde_json::json!("yesterday"))?, "sent_at"),
            (
                with("heartbeat_secs", serde_json::json!(0))?,
                "heartbeat_secs",
            ),
            (
                with("heartbeat_secs", serde_json::json!(3601))?,
                "heartbeat_secs",
            ),
            (with("inventory", serde_json::json!([1]))?, "inventory"),
        ];
        for (bad, want) in cases {
            assert_ne!(bad, good, "the case must differ from the good record");
            let body = format!("{good}\n{bad}\n");
            let why = parse_batch(body.as_bytes())
                .err()
                .ok_or_else(|| format!("accepted a batch with {bad}"))?;
            assert!(why.contains(want), "{why} does not name {want} for {bad}");
            assert!(why.contains("line 2"), "{why} does not name the line");
        }
        assert!(parse_batch(b"").is_err(), "an empty batch is refused");
        assert!(parse_batch(b"\n\n").is_err(), "a blank batch is refused");
        let many: String = (1..=(MAX_BATCH_RECORDS as u64 + 1))
            .map(|n| line("s-1", n, "2026-11-07T12:00:00Z", 30) + "\n")
            .collect();
        assert!(
            parse_batch(many.as_bytes()).is_err_and(|e| e.contains("records")),
            "more than {MAX_BATCH_RECORDS} records are refused"
        );
        Ok(())
    }

    /// Member and stream ids: letters, digits, `.`, `_` and `-`, at most 64.
    #[test]
    fn ids_are_short_and_plain() {
        for good in ["edge-a", "E.1_x", &"a".repeat(MAX_ID_LEN)] {
            assert!(is_valid_id(good), "{good} refused");
        }
        for bad in ["", "a b", "a/b", "é", &"a".repeat(MAX_ID_LEN + 1), "a\n"] {
            assert!(!is_valid_id(bad), "{bad:?} accepted");
        }
    }

    /// The replay rule. In one stream a record is new when its position is
    /// past the newest accepted one. A record of another stream is new when
    /// it was sent after the newest accepted one: a member whose spool was
    /// recreated starts a new stream, and a replay of an old stream is older.
    #[test]
    fn a_record_is_new_once_and_a_replay_is_not() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 5,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            admits(None, &hb("s-1", 1, "2026-11-07T11:00:00Z")?),
            "first"
        );
        assert!(
            admits(Some(&at), &hb("s-1", 6, "2026-11-07T12:00:30Z")?),
            "next"
        );
        assert!(
            !admits(Some(&at), &hb("s-1", 5, "2026-11-07T12:00:00Z")?),
            "replay"
        );
        assert!(
            !admits(Some(&at), &hb("s-1", 4, "2026-11-07T12:00:30Z")?),
            "older"
        );
        assert!(
            admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:01Z")?),
            "a new stream, sent later"
        );
        assert!(
            !admits(Some(&at), &hb("s-0", 9, "2026-11-07T12:00:00Z")?),
            "another stream, sent no later: a replay of an old stream"
        );
        Ok(())
    }

    /// Silent once more than `missed` intervals passed since the last
    /// heartbeat; not at exactly that many.
    #[test]
    fn a_member_is_silent_after_the_missed_heartbeats() -> Result<(), TestError> {
        let last = t("2026-11-07T12:00:00Z")?;
        let at = |s: &str| t(s);
        assert!(
            !is_silent(at("2026-11-07T12:01:30Z")?, last, 30, 3),
            "3 x 30 s"
        );
        assert!(
            is_silent(at("2026-11-07T12:01:31Z")?, last, 30, 3),
            "past 3 x 30 s"
        );
        assert!(
            !is_silent(at("2026-11-07T12:00:05Z")?, last, 1, 5),
            "5 x 1 s"
        );
        assert!(
            is_silent(at("2026-11-07T12:00:06Z")?, last, 1, 5),
            "past 5 x 1 s"
        );
        assert!(
            !is_silent(at("2026-11-07T11:59:00Z")?, last, 1, 3),
            "a clock that went back is not silence"
        );
        Ok(())
    }

    /// One request: new records counted once, replays counted as
    /// duplicates, and the member's record is the newest accepted one with
    /// the center's receive time and the peer.
    #[test]
    fn a_plan_counts_new_records_once() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let now = t("2026-11-07T12:00:40Z")?;
        let batch = vec![
            hb("s-1", 1, "2026-11-07T12:00:00Z")?,
            hb("s-1", 2, "2026-11-07T12:00:30Z")?,
        ];
        let plan = reg.plan("edge-a", "192.0.2.11", now, &batch);
        assert_eq!((plan.accepted, plan.duplicate), (2, 0), "{plan:?}");
        let rec = plan.record.clone().ok_or("a record")?;
        assert_eq!(rec.member, "edge-a", "{rec:?}");
        assert_eq!(rec.heartbeats, 2, "{rec:?}");
        assert_eq!(rec.cursor.seq, 2, "{rec:?}");
        assert_eq!(rec.received_at, now, "{rec:?}");
        assert_eq!(rec.peer, "192.0.2.11", "{rec:?}");
        reg.commit(plan);
        // The same batch again, then once more with one new record.
        let again = reg.plan("edge-a", "192.0.2.11", now, &batch);
        assert_eq!((again.accepted, again.duplicate), (0, 2), "{again:?}");
        assert_eq!(again.record, None, "nothing new, nothing to write");
        let mut more = batch.clone();
        more.push(hb("s-1", 3, "2026-11-07T12:01:00Z")?);
        let plan = reg.plan("edge-a", "192.0.2.11", now, &more);
        assert_eq!((plan.accepted, plan.duplicate), (1, 2), "{plan:?}");
        assert_eq!(
            plan.record.as_ref().map(|r| r.heartbeats),
            Some(3),
            "the third record makes three"
        );
        reg.commit(plan);
        assert_eq!(reg.records().len(), 1, "one member");
        assert_eq!(reg.records()[0].heartbeats, 3, "counted once each");
        Ok(())
    }

    /// Retention removes the members last heard before it, and only them.
    #[test]
    fn retention_removes_what_it_should_and_nothing_else() -> Result<(), TestError> {
        let mut reg = Registry::default();
        for (member, at) in [
            ("old", "2026-11-04T11:59:59Z"),
            ("edge", "2026-11-04T12:00:00Z"),
            ("new", "2026-11-07T11:00:00Z"),
        ] {
            let plan = reg.plan(member, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            reg.commit(plan);
        }
        let gone = reg.expire(t("2026-11-07T12:00:00Z")?, chrono::Duration::hours(72));
        assert_eq!(
            gone,
            vec!["old".to_string()],
            "only the member past retention"
        );
        let left: Vec<&str> = reg.records().iter().map(|r| r.member.as_str()).collect();
        assert_eq!(left, ["edge", "new"], "the rest stay");
        Ok(())
    }

    /// The members answer keeps what the center verified apart from what the
    /// member says about itself, and says which members are silent.
    #[test]
    fn the_members_answer_labels_self_reported_fields() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let plan = reg.plan(
            "edge-a",
            "192.0.2.11",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s-1", 1, "2026-11-07T11:59:59Z")?],
        );
        reg.commit(plan);
        let plan = reg.plan(
            "edge-b",
            "192.0.2.12",
            t("2026-11-07T12:01:00Z")?,
            &[hb("s-2", 1, "2026-11-07T12:01:00Z")?],
        );
        reg.commit(plan);
        let v = reg.report(t("2026-11-07T12:01:31Z")?, 3, 72);
        assert_eq!(v["schema_version"], 1, "{v}");
        assert_eq!(v["silent_after_missed"], 3, "{v}");
        assert_eq!(v["retention_hours"], 72, "{v}");
        let rows = v["members"].as_array().ok_or("members")?;
        assert_eq!(rows.len(), 2, "{v}");
        let a = &rows[0];
        assert_eq!(a["member"], "edge-a", "{v}");
        assert_eq!(a["silent"], true, "91 s past a 30 s interval: {v}");
        assert_eq!(rows[1]["silent"], false, "{v}");
        assert_eq!(a["seconds_since_heartbeat"], 91, "{v}");
        assert_eq!(a["verified"]["peer"], "192.0.2.11", "{v}");
        assert_eq!(a["verified"]["received_at"], "2026-11-07T12:00:00Z", "{v}");
        assert_eq!(a["verified"]["heartbeats"], 1, "{v}");
        assert_eq!(
            a["self_reported"]["inventory"]["node_name"], "edge-a",
            "{v}"
        );
        assert_eq!(a["self_reported"]["heartbeat_secs"], 30, "{v}");
        assert_eq!(a["self_reported"]["stream"], "s-1", "{v}");
        assert_eq!(a["self_reported"]["seq"], 1, "{v}");
        assert_eq!(a["self_reported"]["sent_at"], "2026-11-07T11:59:59Z", "{v}");
        assert!(
            a["verified"]["inventory"].is_null(),
            "no claim among the verified: {v}"
        );
        assert_eq!(
            reg.silent(t("2026-11-07T12:01:31Z")?, 3),
            vec!["edge-a".to_string()],
            "the silent list agrees with the answer"
        );
        Ok(())
    }

    /// The store is created 0600, holds what was appended across a reopen,
    /// keeps only the newest record per member after a rewrite, and refuses
    /// a file other users can read.
    #[cfg(unix)]
    #[test]
    fn the_store_is_private_durable_and_compacts() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, loaded) = Store::open(&path)?;
        assert!(loaded.is_empty(), "a new store is empty");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "created private"
        );
        let mut reg = Registry::default();
        for seq in 1..=3 {
            let at = format!("2026-11-07T12:00:0{seq}Z");
            let plan = reg.plan("edge-a", "192.0.2.11", t(&at)?, &[hb("s-1", seq, &at)?]);
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            reg.commit(plan);
        }
        assert_eq!(store.appended(), 3, "three lines");
        drop(store);
        let (mut store, loaded) = Store::open(&path)?;
        assert_eq!(loaded.len(), 3, "every appended line is there");
        let reopened = Registry::from_records(loaded);
        assert_eq!(reopened, reg, "the reopened registry is the one written");
        store.compact(&reopened)?;
        let text = std::fs::read_to_string(&path)?;
        assert_eq!(
            text.lines().count(),
            1,
            "the newest record per member: {text}"
        );
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "rewritten private"
        );
        assert_eq!(store.appended(), 0, "a rewrite resets the count");
        drop(store);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let refused = Store::open(&path);
        assert!(
            refused
                .as_ref()
                .is_err_and(|e| e.contains("0644") && e.contains("chmod 600")),
            "{refused:?}"
        );
        Ok(())
    }

    /// A store whose last line is cut short (the center stopped mid-write)
    /// opens with that line dropped; a bad line before the last is refused,
    /// because it is not a torn write.
    #[test]
    fn a_torn_last_line_is_dropped_and_a_bad_middle_line_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path)?;
        let reg = Registry::default();
        let plan = reg.plan(
            "edge-a",
            "192.0.2.11",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s-1", 1, "2026-11-07T12:00:00Z")?],
        );
        store.append(plan.record.as_ref().ok_or("a record")?)?;
        drop(store);
        let whole = std::fs::read_to_string(&path)?;
        std::fs::write(&path, format!("{whole}{{\"member\":\"edge-b\",\"recei"))?;
        let (_, loaded) = Store::open(&path)?;
        assert_eq!(loaded.len(), 1, "the torn line is dropped");
        std::fs::write(&path, format!("{whole}garbage\n{whole}"))?;
        assert!(
            Store::open(&path).is_err_and(|e| e.contains("line 2")),
            "a bad line before the last is refused, by line"
        );
        Ok(())
    }

    /// The minute's upkeep removes a member past retention from the
    /// registry and from the store file, and leaves the others in both.
    #[test]
    fn the_upkeep_applies_retention_to_the_registry_and_the_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("center.store");
        let (mut store, _) = Store::open(&path)?;
        let mut registry = Registry::default();
        for (member, at) in [
            ("old", "2026-11-01T00:00:00Z"),
            ("new", "2026-11-07T11:00:00Z"),
        ] {
            let plan = registry.plan(member, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            store.append(plan.record.as_ref().ok_or("a record")?)?;
            registry.commit(plan);
        }
        let mut center = Center { registry, store };
        let gone = apply_retention(&mut center, t("2026-11-07T12:00:00Z")?, 72);
        assert_eq!(gone, vec!["old".to_string()], "only the old member");
        assert_eq!(center.registry.records().len(), 1, "one member left");
        let text = std::fs::read_to_string(&path)?;
        assert!(!text.contains("\"old\""), "removed from the file: {text}");
        assert!(
            text.contains("\"new\""),
            "the other stays in the file: {text}"
        );
        Ok(())
    }

    /// The silence check returns the members silent now, so the next check
    /// logs only what changed.
    #[test]
    fn the_silence_check_returns_who_is_silent_now() -> Result<(), TestError> {
        let mut registry = Registry::default();
        for (member, at) in [
            ("quiet", "2026-11-07T12:00:00Z"),
            ("loud", "2026-11-07T12:01:00Z"),
        ] {
            let plan = registry.plan(member, "192.0.2.1", t(at)?, &[hb("s", 1, at)?]);
            registry.commit(plan);
        }
        let now = t("2026-11-07T12:01:31Z")?;
        let first = log_silence_changes(&registry, now, 3, &BTreeSet::new());
        assert_eq!(first, BTreeSet::from(["quiet".to_string()]), "{first:?}");
        let again = log_silence_changes(&registry, t("2026-11-07T11:00:00Z")?, 3, &first);
        assert!(
            again.is_empty(),
            "nobody silent before they were heard: {again:?}"
        );
        Ok(())
    }

    /// Plain HTTP is refused on any address but loopback; HTTPS anywhere.
    #[test]
    fn plain_http_is_refused_except_on_loopback() -> Result<(), TestError> {
        for (addr, tls, refused) in [
            ("127.0.0.1:8443", false, false),
            ("[::1]:8443", false, false),
            ("192.0.2.10:8443", false, true),
            ("0.0.0.0:8443", false, true),
            ("192.0.2.10:8443", true, false),
            ("0.0.0.0:8443", true, false),
        ] {
            let got = plain_http_refusal(addr.parse()?, tls);
            assert_eq!(got.is_some(), refused, "{addr} tls={tls}: {got:?}");
            if let Some(why) = got {
                assert!(why.contains("--tls-cert"), "{why}");
            }
        }
        Ok(())
    }
}

/// One behavior each, by category, for the center's rules (SUCCESS, FAILURE,
/// EDGE). The routes are driven in process through the router the center
/// serves, with no socket; the rules through their functions.
#[cfg(test)]
mod behavior_tests {
    use super::*;
    use tower::ServiceExt as _;

    type TestError = Box<dyn std::error::Error>;

    /// The key tokens are minted with in these tests, derived at run time
    /// (a literal here is a hard-coded cryptographic value to CodeQL).
    fn key() -> &'static [u8] {
        crate::test_material::key_bytes("fleet-center-behavior")
    }

    fn t(s: &str) -> Result<DateTime<Utc>, TestError> {
        Ok(DateTime::parse_from_rfc3339(s)?.with_timezone(&Utc))
    }

    fn hb(stream: &str, seq: u64, sent_at: &str) -> Result<Heartbeat, TestError> {
        Ok(Heartbeat {
            stream: stream.to_string(),
            seq,
            sent_at: t(sent_at)?,
            heartbeat_secs: 30,
            inventory: serde_json::json!({"node_name": "edge-a"}),
        })
    }

    fn record(v: serde_json::Value) -> String {
        let mut base = serde_json::json!({
            "schema_version": 1,
            "kind": "heartbeat",
            "stream": "s-1",
            "seq": 1,
            "sent_at": "2026-11-07T12:00:00Z",
            "heartbeat_secs": 30,
            "inventory": {"node_name": "edge-a"},
        });
        if let (Some(b), Some(o)) = (base.as_object_mut(), v.as_object()) {
            for (k, val) in o {
                b.insert(k.clone(), val.clone());
            }
        }
        base.to_string()
    }

    fn without(key: &str) -> String {
        let mut v: serde_json::Value =
            serde_json::from_str(&record(serde_json::json!({}))).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.remove(key);
        }
        v.to_string()
    }

    fn token(id: &str, scope: &str, exp_offset: i64, audience: &str) -> String {
        crate::auth::mint(
            key(),
            id,
            Utc::now().timestamp() + exp_offset,
            audience,
            scope,
        )
    }

    fn member(id: &str) -> String {
        token(
            id,
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_API,
        )
    }

    /// A center state over a store in `dir`, `rate` requests per second.
    fn state(dir: &Path, rate: u32) -> Result<CenterState, TestError> {
        let (store, records) = Store::open(&dir.join("center.store"))?;
        Ok(CenterState {
            center: Arc::new(parking_lot::Mutex::new(Center {
                registry: Registry::from_records(records),
                store,
            })),
            verifier: Arc::new(crate::auth::TokenVerifier::new(
                crate::auth::VerifierConfig {
                    signing_keys: vec![key().to_vec()],
                    static_keys: Vec::new(),
                    revoked_file: None,
                    audience: crate::auth::AUDIENCE_API.to_string(),
                },
            )),
            limiter: Arc::new(parking_lot::Mutex::new(
                crate::output::api::RateLimiter::new(rate, 64),
            )),
            missed: 3,
            retention_hours: 72,
        })
    }

    /// One request through the center's router: status and body.
    async fn call(
        st: &CenterState,
        method: &str,
        path: &str,
        auth: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(u16, String), TestError> {
        let mut req = axum::http::Request::builder().method(method).uri(path);
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        let mut req = req.body(axum::body::Body::from(body))?;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(std::net::SocketAddr::from((
                [127, 0, 0, 1],
                40000,
            ))));
        let resp = router(st.clone()).oneshot(req).await?;
        let status = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await?;
        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
    }

    fn bearer(tok: &str) -> String {
        format!("Bearer {tok}")
    }

    fn line() -> Vec<u8> {
        (record(serde_json::json!({"sent_at": Utc::now().to_rfc3339()})) + "\n").into_bytes()
    }

    // ── SUCCESS ─────────────────────────────────────────────────────────

    /// A batch of exactly the most records parses.
    #[test]
    fn success_a_batch_at_the_record_limit_parses() -> Result<(), TestError> {
        let body: String = (1..=MAX_BATCH_RECORDS as u64)
            .map(|n| record(serde_json::json!({"seq": n})) + "\n")
            .collect();
        assert_eq!(
            parse_batch(body.as_bytes())?.len(),
            MAX_BATCH_RECORDS,
            "exactly the limit is accepted"
        );
        Ok(())
    }

    /// A gap in a stream's positions (heartbeats the member's cap dropped)
    /// is still new.
    #[test]
    fn success_a_gap_in_positions_is_new() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s".into(),
            seq: 5,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            admits(Some(&at), &hb("s", 9, "2026-11-07T12:02:00Z")?),
            "seq 9 after 5 is new"
        );
        Ok(())
    }

    /// Reopened, the registry holds the last record of each member in file
    /// order.
    #[test]
    fn success_the_last_record_per_member_wins() -> Result<(), TestError> {
        let reg = Registry::default();
        let a1 = reg
            .plan(
                "a",
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            )
            .record
            .ok_or("a record")?;
        let a2 = reg
            .plan(
                "a",
                "192.0.2.2",
                t("2026-11-07T12:01:00Z")?,
                &[hb("s", 2, "2026-11-07T12:01:00Z")?],
            )
            .record
            .ok_or("a record")?;
        let reg = Registry::from_records(vec![a1, a2]);
        assert_eq!(reg.records()[0].peer, "192.0.2.2", "the later record");
        Ok(())
    }

    /// The members answer lists members by id.
    #[test]
    fn success_members_are_listed_by_id() -> Result<(), TestError> {
        let mut reg = Registry::default();
        for m in ["edge-c", "edge-a", "edge-b"] {
            let p = reg.plan(
                m,
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            );
            reg.commit(p);
        }
        let v = reg.report(t("2026-11-07T12:00:01Z")?, 3, 72);
        let ids: Vec<&str> = v["members"]
            .as_array()
            .ok_or("members")?
            .iter()
            .filter_map(|r| r["member"].as_str())
            .collect();
        assert_eq!(ids, ["edge-a", "edge-b", "edge-c"], "sorted by member id");
        Ok(())
    }

    /// Two members' plans are independent: one's cursor does not touch the
    /// other's.
    #[test]
    fn success_members_have_their_own_cursors() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 5, "2026-11-07T12:00:00Z")?],
        );
        reg.commit(p);
        let p = reg.plan(
            "b",
            "192.0.2.2",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 1, "2026-11-07T11:00:00Z")?],
        );
        assert_eq!(p.accepted, 1, "b's first record is new whatever a holds");
        Ok(())
    }

    /// A rewritten store reopens to the same registry.
    #[test]
    fn success_a_compacted_store_reopens_the_same() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path)?;
        let mut reg = Registry::default();
        for m in ["a", "b"] {
            let p = reg.plan(
                m,
                "192.0.2.1",
                t("2026-11-07T12:00:00Z")?,
                &[hb("s", 1, "2026-11-07T12:00:00Z")?],
            );
            store.append(p.record.as_ref().ok_or("r")?)?;
            reg.commit(p);
        }
        store.compact(&reg)?;
        drop(store);
        let (_, loaded) = Store::open(&path)?;
        assert_eq!(Registry::from_records(loaded), reg, "same registry");
        Ok(())
    }

    /// The ingest answers `200` with the member, and counts.
    #[tokio::test]
    async fn success_the_ingest_answers_the_counts() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let (status, body) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        assert_eq!(status, 200, "{body}");
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(
            (
                v["member"].clone(),
                v["accepted"].clone(),
                v["duplicate"].clone()
            ),
            ("edge-a".into(), 1.into(), 0.into()),
            "{v}"
        );
        Ok(())
    }

    /// The `Bearer` scheme is matched without regard to case.
    #[tokio::test]
    async fn success_a_lowercase_bearer_scheme_is_accepted() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let auth = format!("bearer {}", member("edge-a"));
        let (status, body) = call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line()).await?;
        assert_eq!(status, 200, "{body}");
        Ok(())
    }

    /// An `admin` token reads the members list.
    #[tokio::test]
    async fn success_an_admin_token_reads_the_members() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "op",
            crate::auth::SCOPE_ADMIN,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (status, _) = call(
            &st,
            "GET",
            "/v1/fleet/members",
            Some(&bearer(&tok)),
            Vec::new(),
        )
        .await?;
        assert_eq!(status, 200, "admin reads the members");
        Ok(())
    }

    /// A heartbeat taken through the route is in the store file at once.
    #[tokio::test]
    async fn success_an_accepted_heartbeat_is_on_disk() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        let text = std::fs::read_to_string(dir.path().join("center.store"))?;
        assert!(
            text.contains("\"member\":\"edge-a\""),
            "appended before the answer: {text}"
        );
        Ok(())
    }

    /// The members answer carries the center's settings.
    #[test]
    fn success_the_answer_carries_the_settings() -> Result<(), TestError> {
        let v = Registry::default().report(t("2026-11-07T12:00:00Z")?, 5, 24);
        assert_eq!(
            (
                v["silent_after_missed"].clone(),
                v["retention_hours"].clone(),
                v["now"].clone()
            ),
            (5.into(), 24.into(), "2026-11-07T12:00:00Z".into()),
            "{v}"
        );
        Ok(())
    }

    // ── FAILURE ─────────────────────────────────────────────────────────

    /// A body that is not UTF-8 is refused.
    #[test]
    fn failure_a_body_that_is_not_utf8_is_refused() {
        assert!(
            parse_batch(&[0xff, 0xfe, b'\n']).is_err_and(|e| e.contains("UTF-8")),
            "not UTF-8"
        );
    }

    /// A record without its `inventory` is refused, by line.
    #[test]
    fn failure_a_record_without_an_inventory_is_refused() {
        let body = without("inventory") + "\n";
        assert!(
            parse_batch(body.as_bytes()).is_err_and(|e| e.starts_with("line 1: not a record")),
            "a missing field"
        );
    }

    /// An inventory of `null` is refused.
    #[test]
    fn failure_a_null_inventory_is_refused() {
        let body = record(serde_json::json!({"inventory": null}));
        assert!(
            parse_batch(body.as_bytes()).is_err_and(|e| e.contains("inventory")),
            "null inventory"
        );
    }

    /// No `Authorization` header: `401`.
    #[tokio::test]
    async fn failure_no_credential_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", None, line()).await?.0,
            401,
            "no header"
        );
        Ok(())
    }

    /// A `Basic` credential: `401`.
    #[tokio::test]
    async fn failure_a_basic_credential_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let auth = format!("Basic {}", member("edge-a"));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line())
                .await?
                .0,
            401,
            "Basic"
        );
        Ok(())
    }

    /// An expired member token: `401`.
    #[tokio::test]
    async fn failure_an_expired_token_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            -10,
            crate::auth::AUDIENCE_API,
        );
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            401,
            "expired"
        );
        Ok(())
    }

    /// A member token minted for the MCP audience: `401`.
    #[tokio::test]
    async fn failure_an_mcp_audience_token_is_401() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "edge-a",
            crate::auth::SCOPE_FLEET_REPORT,
            3600,
            crate::auth::AUDIENCE_MCP,
        );
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            401,
            "mcp audience"
        );
        Ok(())
    }

    /// A token id longer than a member name: `403`.
    #[tokio::test]
    async fn failure_a_token_id_too_long_is_403() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = member(&"a".repeat(MAX_ID_LEN + 1));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            403,
            "65 characters"
        );
        Ok(())
    }

    /// A body past the limit: `413`, and nothing counted.
    #[tokio::test]
    async fn failure_an_oversized_body_is_413() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let body = vec![b'x'; MAX_INGEST_BYTES + 1];
        let (status, _) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            body,
        )
        .await?;
        assert_eq!(status, 413, "past MAX_INGEST_BYTES");
        Ok(())
    }

    /// Past the rate limit: `503`, before the credential is looked at.
    #[tokio::test]
    async fn failure_past_the_rate_limit_is_503() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 1)?;
        let auth = bearer(&member("edge-a"));
        call(&st, "POST", "/v1/fleet/ingest", Some(&auth), line()).await?;
        let (status, _) = call(&st, "POST", "/v1/fleet/ingest", None, line()).await?;
        assert_eq!(status, 503, "the second request in the second");
        Ok(())
    }

    /// The ingest takes `POST` only.
    #[tokio::test]
    async fn failure_get_on_the_ingest_is_405() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let (status, _) = call(
            &st,
            "GET",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            Vec::new(),
        )
        .await?;
        assert_eq!(status, 405, "GET");
        Ok(())
    }

    /// A store that cannot be written: `503`, and the heartbeat is not
    /// counted, so the member sends it again.
    #[tokio::test]
    async fn failure_an_unwritable_store_is_503_and_counts_nothing() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        std::fs::remove_file(dir.path().join("center.store"))?;
        std::fs::create_dir(dir.path().join("center.store"))?;
        let (status, _) = call(
            &st,
            "POST",
            "/v1/fleet/ingest",
            Some(&bearer(&member("edge-a"))),
            line(),
        )
        .await?;
        assert_eq!(status, 503, "the append failed");
        assert!(
            st.center.lock().registry.records().is_empty(),
            "nothing counted"
        );
        Ok(())
    }

    /// A store path that is a directory is refused.
    #[test]
    fn failure_a_store_that_is_a_directory_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert!(Store::open(dir.path()).is_err(), "a directory");
        Ok(())
    }

    /// A route the center does not serve: `404`.
    #[tokio::test]
    async fn failure_an_unknown_route_is_404() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "op",
            crate::auth::SCOPE_FULL,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (status, _) = call(&st, "GET", "/v1/dialogs", Some(&bearer(&tok)), Vec::new()).await?;
        assert_eq!(status, 404, "the center serves no dialogs");
        Ok(())
    }

    // ── EDGE ────────────────────────────────────────────────────────────

    /// Zero members: an empty list.
    #[tokio::test]
    async fn edge_zero_members_is_an_empty_list() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = token(
            "r",
            crate::auth::SCOPE_INVENTORY,
            3600,
            crate::auth::AUDIENCE_API,
        );
        let (_, body) = call(
            &st,
            "GET",
            "/v1/fleet/members",
            Some(&bearer(&tok)),
            Vec::new(),
        )
        .await?;
        let v: serde_json::Value = serde_json::from_str(&body)?;
        assert_eq!(v["members"], serde_json::json!([]), "{v}");
        Ok(())
    }

    /// A member clock far ahead holds the cursor there: another stream's
    /// record sent "earlier" is not new until the clock passes it.
    #[test]
    fn edge_a_clock_far_ahead_holds_the_cursor() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 1,
            sent_at: t("2030-01-01T00:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:00Z")?),
            "behind a future send time"
        );
        Ok(())
    }

    /// A new stream sent at exactly the newest send time is not new.
    #[test]
    fn edge_a_new_stream_at_the_same_instant_is_not_new() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s-1".into(),
            seq: 1,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s-2", 1, "2026-11-07T12:00:00Z")?),
            "a tie"
        );
        Ok(())
    }

    /// The largest interval and count do not overflow the silence check.
    #[test]
    fn edge_the_silence_check_does_not_overflow() -> Result<(), TestError> {
        let last = t("2026-11-07T12:00:00Z")?;
        assert!(
            !is_silent(t("2026-11-08T12:00:00Z")?, last, u64::MAX, u32::MAX),
            "saturates rather than wraps"
        );
        Ok(())
    }

    /// Retention on an empty registry removes nothing.
    #[test]
    fn edge_retention_on_no_members_removes_nothing() -> Result<(), TestError> {
        let mut reg = Registry::default();
        assert!(
            reg.expire(t("2026-11-07T12:00:00Z")?, chrono::Duration::hours(1))
                .is_empty(),
            "none"
        );
        Ok(())
    }

    /// A member id of exactly 64 characters reports.
    #[tokio::test]
    async fn edge_a_64_character_member_reports() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let tok = member(&"m".repeat(MAX_ID_LEN));
        assert_eq!(
            call(&st, "POST", "/v1/fleet/ingest", Some(&bearer(&tok)), line())
                .await?
                .0,
            200,
            "64"
        );
        Ok(())
    }

    /// Unicode in an inventory reaches the members answer unchanged.
    #[test]
    fn edge_unicode_in_the_inventory_is_kept() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let mut h = hb("s", 1, "2026-11-07T12:00:00Z")?;
        h.inventory = serde_json::json!({"node_name": "edge-zürich-東京"});
        let p = reg.plan("a", "192.0.2.1", t("2026-11-07T12:00:00Z")?, &[h]);
        reg.commit(p);
        let v = reg.report(t("2026-11-07T12:00:01Z")?, 3, 72);
        assert_eq!(
            v["members"][0]["self_reported"]["inventory"]["node_name"], "edge-zürich-東京",
            "{v}"
        );
        Ok(())
    }

    /// A record repeated inside one batch is counted once.
    #[test]
    fn edge_a_record_repeated_in_one_batch_counts_once() -> Result<(), TestError> {
        let reg = Registry::default();
        let h = hb("s", 1, "2026-11-07T12:00:00Z")?;
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[h.clone(), h],
        );
        assert_eq!((p.accepted, p.duplicate), (1, 1), "{p:?}");
        Ok(())
    }

    /// The largest position is accepted, and nothing in that stream follows.
    #[test]
    fn edge_the_largest_position_ends_the_stream() -> Result<(), TestError> {
        let at = Cursor {
            stream: "s".into(),
            seq: u64::MAX,
            sent_at: t("2026-11-07T12:00:00Z")?,
        };
        assert!(
            !admits(Some(&at), &hb("s", u64::MAX, "2026-11-07T12:01:00Z")?),
            "no seq past MAX"
        );
        Ok(())
    }

    /// An empty store file opens with no members.
    #[test]
    fn edge_an_empty_store_opens_empty() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        Store::open(&path)?;
        assert!(Store::open(&path)?.1.is_empty(), "no records");
        Ok(())
    }

    /// Blank lines between records are passed over.
    #[test]
    fn edge_blank_lines_in_the_store_are_passed_over() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path)?;
        let reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:00:00Z")?,
            &[hb("s", 1, "2026-11-07T12:00:00Z")?],
        );
        store.append(p.record.as_ref().ok_or("r")?)?;
        let text = std::fs::read_to_string(&path)?;
        std::fs::write(&path, format!("\n{text}\n\n{text}"))?;
        assert_eq!(
            Store::open(&path)?.1.len(),
            2,
            "two records, blank lines skipped"
        );
        Ok(())
    }

    /// Rewriting an empty registry leaves an empty store.
    #[test]
    fn edge_compacting_no_members_leaves_an_empty_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("s");
        let (mut store, _) = Store::open(&path)?;
        store.compact(&Registry::default())?;
        assert_eq!(std::fs::read_to_string(&path)?, "", "empty");
        Ok(())
    }

    /// A receive time after `now` (the clock stepped back) reports zero
    /// seconds, never a negative age.
    #[test]
    fn edge_a_receive_time_in_the_future_reports_zero_seconds() -> Result<(), TestError> {
        let mut reg = Registry::default();
        let p = reg.plan(
            "a",
            "192.0.2.1",
            t("2026-11-07T12:10:00Z")?,
            &[hb("s", 1, "2026-11-07T12:10:00Z")?],
        );
        reg.commit(p);
        let v = reg.report(t("2026-11-07T12:00:00Z")?, 3, 72);
        assert_eq!(v["members"][0]["seconds_since_heartbeat"], 0, "{v}");
        Ok(())
    }

    /// Plain HTTP on a routable IPv6 address is refused.
    #[test]
    fn edge_plain_http_on_routable_ipv6_is_refused() -> Result<(), TestError> {
        assert!(
            plain_http_refusal("[2001:db8::1]:8444".parse()?, false).is_some(),
            "routable IPv6"
        );
        Ok(())
    }

    /// An IPv4-mapped IPv6 peer is reported as its IPv4 address.
    #[tokio::test]
    async fn edge_an_ipv4_mapped_peer_is_reported_as_ipv4() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let st = state(dir.path(), 0)?;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/fleet/ingest")
            .header("authorization", bearer(&member("edge-a")))
            .body(axum::body::Body::from(line()))?;
        req.extensions_mut().insert(axum::extract::ConnectInfo(
            "[::ffff:192.0.2.7]:40000".parse::<std::net::SocketAddr>()?,
        ));
        router(st.clone()).oneshot(req).await?;
        assert_eq!(
            st.center.lock().registry.records()[0].peer,
            "192.0.2.7",
            "canonical"
        );
        Ok(())
    }
}
