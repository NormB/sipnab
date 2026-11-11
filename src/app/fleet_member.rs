// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! A fleet member: this run reports its heartbeat to a fleet center
//! (`sipnab fleet serve`, [`super::fleet_center`]).
//!
//! Every `[fleet] heartbeat_secs` the member writes its inventory
//! (`GET /v1/inventory`, built by [`crate::output::inventory::current`]) as
//! one heartbeat file in its spool, and a delivery pass sends the spool to
//! the center's `POST /v1/fleet/ingest`, oldest first. The spool is the vCon
//! forwarder's ([`super::spool`]): the same naming, staging, ordering,
//! status classification and retry spacing, so a center that is away for a
//! while costs the member nothing but files, and the spool drains when it
//! returns.
//!
//! # Capture first
//!
//! The member runs on a thread of its own and touches nothing the capture
//! uses. A center that is down, slow or refusing makes the member wait and
//! retry; the capture never waits on it. A spool past
//! `[fleet] spool_max_files` drops its oldest heartbeats, which a newer one
//! supersedes anyway.
//!
//! # Replays
//!
//! The spool chooses a stream id once and numbers its heartbeats in it, and
//! keeps both in two dot-files beside them, so a restarted member continues
//! its stream. A heartbeat the center took but whose answer was lost is sent
//! again, and the center counts it once
//! ([`super::fleet_center::admits`]).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};

/// The default seconds between heartbeats.
pub const DEFAULT_HEARTBEAT_SECS: u64 = 30;

/// The default most heartbeats the spool keeps: a day at the default
/// interval.
pub const DEFAULT_SPOOL_MAX_FILES: u64 = 2880;

/// The spool's stream id file.
const STREAM_FILE: &str = ".stream";

/// The spool's next-position file.
const SEQ_FILE: &str = ".next-seq";

/// Where heartbeats the center refused for good go.
const FAILED_DIR: &str = "failed";

/// How long one delivery may take to connect, send and be answered.
///
/// Not a setting: a center answers a heartbeat at once or not at all, and
/// the delivery retries on its own spacing either way.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of the center's answer the member reads, head and body each.
const MAX_ANSWER_BYTES: usize = 16 * 1024;

/// What a member run reports, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberPlan {
    /// The center.
    pub url: super::https_client::Endpoint,
    /// The member's token file.
    pub token_file: PathBuf,
    /// The CA to trust for the center, if not the host's bundle.
    pub ca_file: Option<PathBuf>,
    /// Where heartbeats wait.
    pub spool: PathBuf,
    /// Seconds between heartbeats.
    pub heartbeat_secs: u64,
    /// The most heartbeats the spool keeps.
    pub spool_max_files: u64,
    /// How the member pushes its ended calls; `None` when it pushes none.
    pub calls: Option<CallPlan>,
}

/// How a member pushes its ended calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallPlan {
    /// `[fleet] call_push`: `exceptions` or `all`.
    pub rule: super::fleet_calls::CallPush,
    /// `[fleet] exception_max_per_sec`.
    pub max_per_sec: u32,
    /// `[fleet] spool_key_file`.
    pub key_file: PathBuf,
}

/// The call push `[fleet]` asks for; `None` when the member pushes no call.
///
/// With no `call_push`, a member that has a `spool_key_file` pushes
/// `exceptions` and one without pushes none, so a member set up before call
/// records existed runs as it did.
///
/// # Errors
///
/// `call_push` is not one of its three values, `exception_max_per_sec` is
/// out of range, or `call_push` asks for records with no `spool_key_file`
/// to seal them under. The message names the key.
pub fn call_plan(keys: &crate::config::FleetConfig) -> Result<Option<CallPlan>, String> {
    use super::fleet_calls::{CallPush, DEFAULT_EXCEPTION_MAX_PER_SEC, MAX_EXCEPTION_MAX_PER_SEC};
    let written = keys.call_push.as_deref().map(CallPush::parse).transpose()?;
    let max_per_sec = keys
        .exception_max_per_sec
        .unwrap_or(DEFAULT_EXCEPTION_MAX_PER_SEC);
    if !(1..=MAX_EXCEPTION_MAX_PER_SEC).contains(&max_per_sec) {
        return Err(format!(
            "[fleet] exception_max_per_sec {max_per_sec} is outside 1 to {MAX_EXCEPTION_MAX_PER_SEC}"
        ));
    }
    let rule = match (written, &keys.spool_key_file) {
        (Some(CallPush::None), _) | (None, None) => return Ok(None),
        (Some(rule), Some(_)) => rule,
        (None, Some(_)) => CallPush::Exceptions,
        (Some(rule), None) => {
            return Err(format!(
                "[fleet] call_push {:?} needs [fleet] spool_key_file: call records wait on disk \
                 only in sealed files. Create a key with `sipnab fleet keygen --out FILE`",
                rule.name()
            ));
        }
    };
    Ok(keys.spool_key_file.clone().map(|key_file| CallPlan {
        rule,
        max_per_sec,
        key_file,
    }))
}

impl MemberPlan {
    /// The member this run is, from its flags and `[fleet]` keys, a flag
    /// overriding its key; `None` when no report URL is set.
    ///
    /// # Errors
    ///
    /// A URL that does not parse or is plain HTTP to another machine, no
    /// token file or spool directory named, a CA file that does not load, or
    /// an interval or cap out of range. The message names the setting. The
    /// token file itself is read and checked where the member starts
    /// (`prepare`), through `secret_files`, which read it before the
    /// privilege drop.
    pub fn resolve(
        cli: &crate::cli::Cli,
        config: &crate::config::Config,
    ) -> Result<Option<Self>, String> {
        use super::https_client::{Endpoint, UrlUse};
        let args = &cli.listener_args;
        let keys = &config.fleet;
        // Checked whether or not a URL is set, so a setting that cannot work
        // is refused when it is written, not when a URL is added later. An
        // empty flag value never gets here: the command line refuses it.
        let written = [
            ("report_token_file", &keys.report_token_file),
            ("report_ca_file", &keys.report_ca_file),
            ("spool_dir", &keys.spool_dir),
            ("spool_key_file", &keys.spool_key_file),
        ];
        for (key, path) in written {
            if path.as_ref().is_some_and(|p| p.as_os_str().is_empty()) {
                return Err(format!("[fleet] {key} is empty; give a path"));
            }
        }
        let heartbeat_secs = keys.heartbeat_secs.unwrap_or(DEFAULT_HEARTBEAT_SECS);
        let range =
            super::fleet_center::MIN_HEARTBEAT_SECS..=super::fleet_center::MAX_HEARTBEAT_SECS;
        if !range.contains(&heartbeat_secs) {
            return Err(format!(
                "[fleet] heartbeat_secs {heartbeat_secs} is outside {} to {}",
                range.start(),
                range.end()
            ));
        }
        let spool_max_files = keys.spool_max_files.unwrap_or(DEFAULT_SPOOL_MAX_FILES);
        if spool_max_files == 0 {
            return Err("[fleet] spool_max_files must be 1 or more".to_string());
        }
        let calls = call_plan(keys)?;
        let (url, url_from) = match (&args.fleet_report_url, &keys.report_url) {
            (Some(url), _) => (url.clone(), "--fleet-report-url"),
            (None, Some(url)) => (url.clone(), "[fleet] report_url"),
            (None, None) => return Ok(None),
        };
        let endpoint =
            Endpoint::parse(&url, UrlUse::FLEET_REPORT).map_err(|e| format!("{url_from} {e}"))?;
        if !endpoint.tls && !endpoint.is_loopback() {
            return Err(format!(
                "{url_from} {url}: plain HTTP is refused except to loopback, because the \
                 member's token and inventory would cross the network unencrypted; use \
                 https://"
            ));
        }
        let token_file = args
            .fleet_report_token_file
            .clone()
            .or(keys.report_token_file.clone())
            .ok_or_else(|| {
                "--fleet-report-url needs --fleet-report-token-file ([fleet] \
                 report_token_file): the member's fleet-report token"
                    .to_string()
            })?;
        let spool = args
            .fleet_spool_dir
            .clone()
            .or(keys.spool_dir.clone())
            .ok_or_else(|| {
                "--fleet-report-url needs --fleet-spool-dir ([fleet] spool_dir): where \
                 heartbeats wait for the center"
                    .to_string()
            })?;
        let ca_file = args
            .fleet_report_ca_file
            .clone()
            .or(keys.report_ca_file.clone());
        if endpoint.tls {
            trust(ca_file.as_deref())?;
        }
        Ok(Some(Self {
            url: endpoint,
            token_file,
            ca_file,
            spool,
            heartbeat_secs,
            spool_max_files,
            calls,
        }))
    }
}

/// The TLS client configuration for the center.
fn trust(ca_file: Option<&Path>) -> Result<std::sync::Arc<rustls::ClientConfig>, String> {
    super::https_client::client_config(
        ca_file,
        None,
        &crate::tls_files::TrustNames {
            ca: "--fleet-report-ca-file",
            extra: "--fleet-report-ca-file",
            issuer: "the fleet center's issuer",
        },
    )
}

/// The spool's own record of its stream: the id and the next position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolStream {
    /// The stream id.
    pub stream: String,
    /// The position the next heartbeat takes.
    pub next_seq: u64,
}

impl SpoolStream {
    /// The stream of the spool at `spool`: the one its dot-files record, or
    /// a new one, recorded now. Creates the directory when absent.
    ///
    /// # Errors
    ///
    /// The directory or the files cannot be created, read or written, or
    /// hold something other than what this function writes.
    pub fn open(spool: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(spool)?;
        let stream_path = spool.join(STREAM_FILE);
        let stream = match std::fs::read_to_string(&stream_path) {
            Ok(text) => text.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let id = new_stream_id()?;
                super::spool::write_atomically(&stream_path, id.as_bytes())?;
                id
            }
            Err(e) => return Err(e),
        };
        if !super::fleet_center::is_valid_id(&stream) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} does not hold a stream id", stream_path.display()),
            ));
        }
        let next_seq = match std::fs::read_to_string(spool.join(SEQ_FILE)) {
            Ok(text) => text.trim().parse::<u64>().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{} does not hold a position",
                        spool.join(SEQ_FILE).display()
                    ),
                )
            })?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e),
        };
        Ok(Self { stream, next_seq })
    }

    /// The next position, recorded as taken before it is returned, so a
    /// member that stops at any point never hands one out twice.
    ///
    /// # Errors
    ///
    /// The position file cannot be written.
    pub fn take(&mut self, spool: &Path) -> std::io::Result<u64> {
        let seq = self.next_seq;
        let next = seq.saturating_add(1);
        super::spool::write_atomically(&spool.join(SEQ_FILE), next.to_string().as_bytes())?;
        self.next_seq = next;
        Ok(seq)
    }

    /// The next `n` positions, recorded as taken before the first is
    /// returned.
    ///
    /// # Errors
    ///
    /// The position file cannot be written.
    pub fn take_n(&mut self, spool: &Path, n: u64) -> std::io::Result<u64> {
        let first = self.next_seq;
        if n == 0 {
            return Ok(first);
        }
        let next = first.saturating_add(n);
        super::spool::write_atomically(&spool.join(SEQ_FILE), next.to_string().as_bytes())?;
        self.next_seq = next;
        Ok(first)
    }
}

/// A new stream id: 32 random hex digits.
fn new_stream_id() -> std::io::Result<String> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| std::io::Error::other("no random bytes for a stream id"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// One heartbeat as the line the center reads
/// ([`super::fleet_center::parse_batch`]), newline included.
#[must_use]
pub fn heartbeat_line(
    stream: &str,
    seq: u64,
    sent_at: DateTime<Utc>,
    heartbeat_secs: u64,
    inventory: &serde_json::Value,
) -> String {
    heartbeat_line_with(stream, seq, sent_at, heartbeat_secs, inventory, None)
}

/// [`heartbeat_line`] for a member that pushes call records: the line
/// carries `calls`, what the member did with its ended calls so far.
#[must_use]
pub fn heartbeat_line_with(
    stream: &str,
    seq: u64,
    sent_at: DateTime<Utc>,
    heartbeat_secs: u64,
    inventory: &serde_json::Value,
    calls: Option<super::fleet_calls::CallCounts>,
) -> String {
    let mut record = serde_json::json!({
        "schema_version": super::fleet_center::RECORD_SCHEMA_VERSION,
        "kind": super::fleet_center::KIND_HEARTBEAT,
        "stream": stream,
        "seq": seq,
        "sent_at": sent_at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
        "heartbeat_secs": heartbeat_secs,
        "inventory": inventory,
    });
    if let Some(calls) = calls {
        record["calls"] = serde_json::json!(calls);
    }
    let mut line = record.to_string();
    line.push('\n');
    line
}

/// The spool file of the heartbeat at `seq`: zero-padded, so name order is
/// position order, and ending `.json`, as the spool's rule reads.
#[must_use]
pub fn file_name(seq: u64) -> String {
    format!("{seq:020}.json")
}

/// Remove the oldest heartbeats past `max`, and return how many.
///
/// # Errors
///
/// The spool cannot be listed, or a file cannot be removed.
pub fn enforce_cap(spool: &Path, max: u64) -> std::io::Result<usize> {
    let names = waiting(spool)?;
    let keep = usize::try_from(max).unwrap_or(usize::MAX);
    let over = names.len().saturating_sub(keep);
    for name in &names[..over] {
        std::fs::remove_file(spool.join(name))?;
    }
    Ok(over)
}

/// The files waiting in `spool`, heartbeats and sealed deliveries of call
/// records, in position order.
///
/// # Errors
///
/// The directory cannot be read.
pub fn waiting(spool: &Path) -> std::io::Result<Vec<String>> {
    super::spool::pending_with(spool, |name| {
        name.ends_with(".json") || super::fleet_calls::is_batch_file(name)
    })
}

/// Seal `selected` into `spool` as the next records of `stream`, sent at
/// `now`: one sealed file per delivery ([`super::fleet_calls::batches`]),
/// under `key`, with `source` for each file's random values. Returns how
/// many calls were written and how many were left out.
///
/// # Errors
///
/// The positions or a file cannot be written, or a delivery cannot be
/// sealed. Nothing in clear is written at any point.
pub fn spool_calls(
    spool: &Path,
    stream: &mut SpoolStream,
    selected: &[super::fleet_calls::Selected],
    now: DateTime<Utc>,
    key: &super::fleet_seal::MasterKey,
    source: super::fleet_seal::Draw<'_>,
) -> Result<(u64, u64), String> {
    use super::fleet_calls::{MAX_DELIVERY_BYTES, MAX_DELIVERY_RECORDS};
    if selected.is_empty() {
        return Ok((0, 0));
    }
    let first = stream
        .take_n(spool, selected.len() as u64)
        .map_err(|e| e.to_string())?;
    let lines: Vec<String> = selected
        .iter()
        .zip(first..)
        .map(|(call, seq)| {
            super::fleet_calls::call_line(&stream.stream, seq, now, call.selected_by, &call.call)
        })
        .collect();
    let (batches, left_out) =
        super::fleet_calls::batches(lines, MAX_DELIVERY_RECORDS, MAX_DELIVERY_BYTES);
    let mut spooled = 0u64;
    let mut seq = first;
    for batch in batches {
        // Named by a position of its own: the records inside carry theirs.
        let sealed = super::fleet_calls::seal_batch(key, &batch, source)?;
        let name = super::fleet_calls::batch_file_name(seq);
        super::spool::write_atomically(&spool.join(name), &sealed).map_err(|e| e.to_string())?;
        spooled += batch.len() as u64;
        seq += batch.len() as u64;
    }
    Ok((spooled, left_out as u64))
}

/// What a delivery's answer means for the heartbeat that drew it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The center took it: remove it from the spool.
    Delivered,
    /// The center refused this file for good: move it to `failed/`.
    Refused,
    /// The center refused the member's token: keep it, wait, try again.
    Unauthorized,
    /// The center could not take it now: keep it, wait, try again.
    Retry,
}

/// The step for `status`, by the spool's one classification
/// ([`super::spool::classify`]), with `2xx` delivered.
///
/// A refused token is waited out rather than ending the member as the
/// forwarder ends: the member is part of a capture run that goes on, and a
/// center that is given the token back takes the spool then.
#[must_use]
pub fn step(status: u16) -> Step {
    use super::spool::Verdict;
    match super::spool::classify(status, false, (200, 299)) {
        Verdict::Delivered => Step::Delivered,
        Verdict::Halt => Step::Unauthorized,
        Verdict::Refused | Verdict::Replace => Step::Refused,
        Verdict::Retry => Step::Retry,
    }
}

/// What the inventory of this run is built from.
#[derive(Clone)]
pub struct Sources {
    /// The capture meter, for the queue, exporter and HEP roster.
    pub meter: Option<crate::capture::channel::CaptureMeter>,
    /// The interfaces this run captures on.
    pub interfaces: Vec<String>,
    /// When the run started, for the uptime.
    pub started: Instant,
    /// The dialogs this run holds, which the call push reads.
    pub dialogs: std::sync::Arc<parking_lot::RwLock<crate::sip::dialog_store::DialogStore>>,
    /// The RTP streams this run holds, which the call push reads.
    pub streams: std::sync::Arc<parking_lot::RwLock<crate::rtp::stream_store::StreamStore>>,
}

/// Start the member on a thread of its own.
///
/// # Errors
///
/// The thread cannot be started.
pub fn spawn(plan: MemberPlan, sources: Sources) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("fleet-member".to_string())
        .spawn(move || run(&plan, &sources))
}

/// How a delivery pass ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pass {
    /// Nothing is left to send.
    Drained,
    /// Something is left; wait before the next pass. The text says why.
    Wait(String),
}

/// How often a member that pushes call records looks at its dialogs.
const CALL_LOOK: Duration = Duration::from_secs(5);

/// How long an ended call must be quiet before it is pushed, so the answer
/// it is pushed with is the one the call settles on.
const CALL_SETTLE: chrono::TimeDelta = chrono::TimeDelta::seconds(5);

/// A member's push of call records while it runs.
struct CallState {
    /// The rule, the cap and the calls pushed.
    pusher: super::fleet_calls::CallPusher,
    /// The spool key, which seals and opens the deliveries.
    keys: super::fleet_seal::Keys,
    /// When the member next looks at its dialogs.
    next_look: Instant,
}

/// The member's loop: a heartbeat every interval, a look at the ended calls
/// every [`CALL_LOOK`] when the member pushes them, and a delivery pass
/// when one is due. Returns only when the spool cannot be used at all.
fn run(plan: &MemberPlan, sources: &Sources) {
    let Some(ready) = start(plan) else {
        return;
    };
    let Ready {
        mut stream,
        tls,
        token,
        spool_key,
    } = ready;
    let mut calls = plan
        .calls
        .as_ref()
        .zip(spool_key)
        .map(|(call, key)| CallState {
            pusher: super::fleet_calls::CallPusher::new(call.rule, call.max_per_sec),
            keys: super::fleet_seal::Keys::new(key, Vec::new()),
            next_look: Instant::now(),
        });
    let interval = Duration::from_secs(plan.heartbeat_secs);
    let mut next_beat = Instant::now();
    let mut delivery = Delivery::new(plan.heartbeat_secs);
    loop {
        let now = Instant::now();
        if let Some(state) = calls.as_mut()
            && now >= state.next_look
        {
            state.next_look = now + CALL_LOOK;
            match push_calls(plan, sources, &mut stream, state) {
                // New records go out now, unless the center is being waited for.
                Ok(spooled) if spooled > 0 && delivery.waiting.is_none() => {
                    delivery.next_try = now;
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("fleet member: call records were not written to the spool: {e}");
                }
            }
        }
        if now >= next_beat {
            next_beat = now + interval;
            let counts = calls.as_ref().map(|state| state.pusher.counts());
            if let Err(e) = write_heartbeat(plan, sources, &mut stream, counts) {
                tracing::warn!("fleet member: a heartbeat was not written to the spool: {e}");
            }
        }
        if now >= delivery.next_try {
            let keys = calls.as_ref().map(|state| &state.keys);
            let pass = deliver(plan, tls.as_ref(), &token, keys);
            delivery.after(pass, now, next_beat);
        }
        let look = calls.as_ref().map_or(next_beat, |state| state.next_look);
        let until = next_beat.min(delivery.next_try).min(look);
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
    }
}

/// One look at the run's dialogs: the ended calls the rule selects are
/// sealed into the spool. Returns how many were written.
fn push_calls(
    plan: &MemberPlan,
    sources: &Sources,
    stream: &mut SpoolStream,
    state: &mut CallState,
) -> Result<u64, String> {
    let selected = {
        // Dialogs, then streams: the order the REST API takes them in.
        let dialogs = sources.dialogs.read();
        let streams = sources.streams.read();
        state.pusher.look(
            &dialogs,
            &streams,
            Utc::now(),
            sources.started.elapsed(),
            CALL_SETTLE,
        )
    };
    if selected.is_empty() {
        return Ok(0);
    }
    let (spooled, left_out) = spool_calls(
        &plan.spool,
        stream,
        &selected,
        Utc::now(),
        state.keys.current(),
        &super::fleet_seal::system_draw,
    )?;
    state.pusher.spooled(spooled, left_out);
    let dropped = enforce_cap(&plan.spool, plan.spool_max_files).map_err(|e| e.to_string())?;
    warn_capped(plan, dropped);
    Ok(spooled)
}

/// Log that the spool's cap removed `dropped` files, when it removed any.
fn warn_capped(plan: &MemberPlan, dropped: usize) {
    if dropped > 0 {
        tracing::warn!(
            "fleet member: the spool holds [fleet] spool_max_files {}; the oldest {dropped} \
             file(s) were dropped",
            plan.spool_max_files
        );
    }
}

/// What a member needs to run, read once at its start.
struct Ready {
    /// The spool's stream.
    stream: SpoolStream,
    /// The TLS configuration for the center, when its URL is `https://`.
    tls: Option<std::sync::Arc<rustls::ClientConfig>>,
    /// The member's token.
    token: String,
    /// The spool key, when the member pushes call records.
    spool_key: Option<super::fleet_seal::MasterKey>,
}

/// [`prepare`], logging where the member reports, or why it does not.
fn start(plan: &MemberPlan) -> Option<Ready> {
    match prepare(plan) {
        Ok(ready) => {
            tracing::info!(
                "fleet member reporting to {} every {} s, spool '{}', call records: {}",
                plan.url,
                plan.heartbeat_secs,
                plan.spool.display(),
                plan.calls.as_ref().map_or("none", |call| call.rule.name())
            );
            Some(ready)
        }
        Err(e) => {
            tracing::error!("fleet member: not reporting: {e}");
            None
        }
    }
}

/// When the next delivery pass runs, and why the last one left heartbeats
/// waiting.
struct Delivery {
    /// When the next pass runs.
    next_try: Instant,
    /// Failed passes in a row, for the retry spacing.
    attempts: u32,
    /// Why heartbeats wait, while they do: logged once per reason.
    waiting: Option<String>,
    /// The longest wait between passes: one heartbeat interval.
    cap_secs: u64,
}

impl Delivery {
    /// A schedule that tries at once.
    fn new(cap_secs: u64) -> Self {
        Self {
            next_try: Instant::now(),
            attempts: 0,
            waiting: None,
            cap_secs,
        }
    }

    /// Set the next try after `pass`, ended at `now`, and log what changed:
    /// a new reason heartbeats wait, or their delivery coming back. A drained
    /// spool waits for the next heartbeat, `next_beat`. Returns the line it
    /// logged, if any.
    fn after(&mut self, pass: Pass, now: Instant, next_beat: Instant) -> Option<String> {
        match pass {
            Pass::Drained => {
                self.attempts = 0;
                self.next_try = next_beat;
                let why = self.waiting.take()?;
                let line = format!("the center takes heartbeats again (was: {why})");
                tracing::info!("fleet member: {line}");
                Some(line)
            }
            Pass::Wait(why) => {
                self.attempts = self.attempts.saturating_add(1);
                self.next_try = now + super::spool::backoff_delay(self.attempts, 1, self.cap_secs);
                if self.waiting.as_deref() == Some(why.as_str()) {
                    return None;
                }
                tracing::warn!("fleet member: heartbeats wait in the spool: {why}");
                let line = format!("heartbeats wait in the spool: {why}");
                self.waiting = Some(why);
                Some(line)
            }
        }
    }
}

/// The spool's stream, the TLS configuration and the token.
fn prepare(plan: &MemberPlan) -> Result<Ready, String> {
    let stream = SpoolStream::open(&plan.spool)
        .map_err(|e| format!("--fleet-spool-dir '{}': {e}", plan.spool.display()))?;
    std::fs::create_dir_all(plan.spool.join(FAILED_DIR))
        .map_err(|e| format!("--fleet-spool-dir '{}': {e}", plan.spool.display()))?;
    let tls = if plan.url.tls {
        Some(trust(plan.ca_file.as_deref())?)
    } else {
        None
    };
    let token = read_token(&plan.token_file)?;
    let spool_key = plan
        .calls
        .as_ref()
        .map(|call| read_spool_key(&call.key_file))
        .transpose()?;
    Ok(Ready {
        stream,
        tls,
        token,
        spool_key,
    })
}

/// The spool key from `path`, a file other users cannot read.
///
/// Through `secret_files`, as the token is: a run that drops privileges
/// read the file before the drop.
fn read_spool_key(path: &Path) -> Result<super::fleet_seal::MasterKey, String> {
    let shown = path.display();
    let label = "[fleet] spool_key_file";
    let hint = "create a key with `sipnab fleet keygen --out FILE`";
    #[cfg(unix)]
    {
        let mode = crate::secret_files::mode(path)
            .map_err(|e| format!("{label} '{shown}': {e}; {hint}"))?;
        if mode & 0o077 != 0 {
            return Err(format!(
                "{label} '{shown}' can be read or written by other users (mode {:04o}); chmod \
                 600 it",
                mode & 0o7777
            ));
        }
    }
    let text = zeroize::Zeroizing::new(
        crate::secret_files::read_to_string(path)
            .map_err(|e| format!("{label} '{shown}': {e}; {hint}"))?,
    );
    super::fleet_seal::MasterKey::parse(&text)
        .map_err(|why| format!("{label} '{shown}' {why}; {hint}"))
}

/// The member's token from `path`: one token on one line, in a file other
/// users cannot read.
///
/// Through `secret_files`: a run that drops privileges read the token before
/// the drop, and a root-only token is not readable after it. The mode is the
/// one the file had when it was read, by the rule every private file sipnab
/// reads follows.
fn read_token(path: &Path) -> Result<String, String> {
    let shown = path.display();
    #[cfg(unix)]
    {
        let mode = crate::secret_files::mode(path)
            .map_err(|e| format!("--fleet-report-token-file '{shown}': {e}"))?;
        if mode & 0o077 != 0 {
            return Err(format!(
                "--fleet-report-token-file '{shown}' can be read or written by other users \
                 (mode {:04o}); chmod 600 it",
                mode & 0o7777
            ));
        }
    }
    let token = crate::secret_files::read_to_string(path)
        .map_err(|e| format!("--fleet-report-token-file '{shown}': {e}"))?;
    let token = token.trim().to_string();
    if token.is_empty() || token.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!(
            "--fleet-report-token-file '{shown}' does not hold one token on one line"
        ));
    }
    Ok(token)
}

/// Write one heartbeat into the spool and apply the cap.
fn write_heartbeat(
    plan: &MemberPlan,
    sources: &Sources,
    stream: &mut SpoolStream,
    calls: Option<super::fleet_calls::CallCounts>,
) -> Result<(), String> {
    let inventory = crate::output::inventory::current(
        sources.meter.as_ref(),
        &sources.interfaces,
        sources.started.elapsed().as_secs(),
    );
    let inventory = serde_json::to_value(&inventory).map_err(|e| e.to_string())?;
    let dropped = spool_heartbeat(
        &plan.spool,
        stream,
        &inventory,
        Utc::now(),
        plan.heartbeat_secs,
        plan.spool_max_files,
        calls,
    )?;
    warn_capped(plan, dropped);
    Ok(())
}

/// Write `inventory` as the next heartbeat of `stream` into `spool`, sent at
/// `now`, then hold the spool to `max` files. Returns how many old ones the
/// cap removed.
///
/// # Errors
///
/// The position, the file or the cap cannot be written.
fn spool_heartbeat(
    spool: &Path,
    stream: &mut SpoolStream,
    inventory: &serde_json::Value,
    now: DateTime<Utc>,
    heartbeat_secs: u64,
    max: u64,
    calls: Option<super::fleet_calls::CallCounts>,
) -> Result<usize, String> {
    let seq = stream.take(spool).map_err(|e| e.to_string())?;
    let line = heartbeat_line_with(&stream.stream, seq, now, heartbeat_secs, inventory, calls);
    super::spool::write_atomically(&spool.join(file_name(seq)), line.as_bytes())
        .map_err(|e| e.to_string())?;
    enforce_cap(spool, max).map_err(|e| e.to_string())
}

/// Send the spool, oldest first, until it is empty or the center cannot
/// take more now.
fn deliver(
    plan: &MemberPlan,
    tls: Option<&std::sync::Arc<rustls::ClientConfig>>,
    token: &str,
    keys: Option<&super::fleet_seal::Keys>,
) -> Pass {
    deliver_spool(&plan.spool, keys, |body| post(&plan.url, tls, token, body))
}

/// [`deliver`]'s rules, with `send` as the one step that reaches the
/// center: the status and the start of the answer, or why there was none.
fn deliver_spool(
    spool: &Path,
    keys: Option<&super::fleet_seal::Keys>,
    mut send: impl FnMut(&[u8]) -> Result<(u16, String), String>,
) -> Pass {
    let names = match waiting(spool) {
        Ok(names) => names,
        Err(e) => return Pass::Wait(format!("the spool cannot be read: {e}")),
    };
    for name in names {
        let path = spool.join(&name);
        let Ok(body) = std::fs::read(&path) else {
            // Gone since the listing: the cap removed it.
            continue;
        };
        let body = if super::fleet_calls::is_batch_file(&name) {
            match opened(&body, keys) {
                Ok(lines) => lines,
                Err(why) => {
                    tracing::warn!(
                        "fleet member: sealed layer: {name}: {why}; it is moved to {FAILED_DIR}/ \
                         and not sent"
                    );
                    let _ = std::fs::rename(&path, spool.join(FAILED_DIR).join(&name));
                    continue;
                }
            }
        } else {
            body
        };
        let (status, text) = match send(&body) {
            Ok(got) => got,
            Err(e) => return Pass::Wait(format!("the center did not answer: {e}")),
        };
        match step(status) {
            Step::Delivered => {
                let _ = std::fs::remove_file(&path);
            }
            Step::Refused => {
                tracing::warn!(
                    "fleet member: the center refused heartbeat {name} for good (HTTP \
                     {status}): {text}; it is moved to {FAILED_DIR}/"
                );
                let _ = std::fs::rename(&path, spool.join(FAILED_DIR).join(&name));
            }
            Step::Unauthorized => {
                return Pass::Wait(format!(
                    "the center refused this member's token (HTTP {status}); mint a \
                     fleet-report token with the center's key and restart the member"
                ));
            }
            Step::Retry => {
                return Pass::Wait(format!("the center answered HTTP {status}"));
            }
        }
    }
    Pass::Drained
}

/// The body a sealed delivery holds, opened under `keys`, or why it does
/// not open.
fn opened(sealed: &[u8], keys: Option<&super::fleet_seal::Keys>) -> Result<Vec<u8>, String> {
    let keys = keys.ok_or("no [fleet] spool_key_file is loaded")?;
    super::fleet_calls::open_batch(sealed, keys).map_err(|e| format!("the file {e}"))
}

/// The request target for the ingest under `target`, the URL's own path.
fn ingest_path(target: &str) -> String {
    format!("{}/v1/fleet/ingest", target.trim_end_matches('/'))
}

/// `POST /v1/fleet/ingest` with `body`: the status and the start of the
/// answer's body.
fn post(
    url: &super::https_client::Endpoint,
    tls: Option<&std::sync::Arc<rustls::ClientConfig>>,
    token: &str,
    body: &[u8],
) -> Result<(u16, String), String> {
    let path = ingest_path(&url.target);
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {token}\r\n\
         User-Agent: {}\r\nContent-Type: application/x-ndjson\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        url.host_header(),
        super::https_client::USER_AGENT,
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    super::https_client::exchange(url, DELIVERY_TIMEOUT, tls, &request, |reader| {
        let head = super::https_client::read_head(reader, MAX_ANSWER_BYTES, "the center's answer")?;
        let status = super::https_client::status_of(&head)?;
        let (bytes, _) = super::https_client::read_body(reader, &head, MAX_ANSWER_BYTES);
        let text: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
        Ok((status, text))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A heartbeat line is exactly what the center reads: the center's own
    /// parser takes it back field for field, so the two ends cannot drift.
    #[test]
    fn a_heartbeat_line_is_what_the_center_reads() -> Result<(), TestError> {
        let at = DateTime::parse_from_rfc3339("2026-11-07T12:00:00.5Z")?.with_timezone(&Utc);
        let inventory = serde_json::json!({"schema_version": 1, "node_name": "edge-a"});
        let line = heartbeat_line("s-0123", 7, at, 30, &inventory);
        assert!(line.ends_with('\n'), "one line: {line:?}");
        assert_eq!(line.matches('\n').count(), 1, "one line: {line:?}");
        let got = crate::app::fleet_center::parse_heartbeats(line.as_bytes())?;
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0].stream, "s-0123", "{got:?}");
        assert_eq!(got[0].seq, 7, "{got:?}");
        assert_eq!(got[0].sent_at, at, "{got:?}");
        assert_eq!(got[0].heartbeat_secs, 30, "{got:?}");
        assert_eq!(got[0].inventory, inventory, "{got:?}");
        Ok(())
    }

    /// File names sort in position order, so the spool sends in order.
    #[test]
    fn file_names_sort_in_position_order() {
        let mut names: Vec<String> = [10, 9, 100, 1].iter().map(|n| file_name(*n)).collect();
        names.sort();
        assert_eq!(
            names,
            [file_name(1), file_name(9), file_name(10), file_name(100)],
            "name order is position order"
        );
        assert!(file_name(1).ends_with(".json"), "{}", file_name(1));
        assert!(
            !file_name(1).starts_with('.'),
            "a staged name is never sent"
        );
    }

    /// The stream id is chosen once per spool and kept; positions go up by
    /// one and survive a reopen, so a restarted member never reuses one.
    #[test]
    fn the_spool_keeps_its_stream_and_positions() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut first = SpoolStream::open(dir.path())?;
        assert!(
            crate::app::fleet_center::is_valid_id(&first.stream),
            "{first:?}"
        );
        assert_eq!(first.take(dir.path())?, 1, "the first position");
        assert_eq!(first.take(dir.path())?, 2, "the next");
        let mut again = SpoolStream::open(dir.path())?;
        assert_eq!(again.stream, first.stream, "the same stream after a reopen");
        assert_eq!(again.take(dir.path())?, 3, "positions survive a reopen");
        let other = tempfile::tempdir()?;
        assert_ne!(
            SpoolStream::open(other.path())?.stream,
            first.stream,
            "another spool, another stream"
        );
        Ok(())
    }

    /// Past the cap the oldest heartbeats go, and the count says how many.
    #[test]
    fn the_cap_drops_the_oldest() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        for n in 1..=5 {
            std::fs::write(dir.path().join(file_name(n)), "x\n")?;
        }
        std::fs::write(dir.path().join(".stream"), "kept")?;
        assert_eq!(enforce_cap(dir.path(), 3)?, 2, "two over the cap");
        let left = crate::app::spool::pending(dir.path())?;
        assert_eq!(
            left,
            [file_name(3), file_name(4), file_name(5)],
            "the newest stay"
        );
        assert!(
            dir.path().join(".stream").exists(),
            "the spool's own files stay"
        );
        assert_eq!(enforce_cap(dir.path(), 3)?, 0, "at the cap, nothing goes");
        Ok(())
    }

    /// The center's answers: taken, refused for good, a token refused, or
    /// try later; by the spool's one classification.
    #[test]
    fn each_answer_has_its_step() {
        for (status, want) in [
            (200, Step::Delivered),
            (204, Step::Delivered),
            (400, Step::Refused),
            (413, Step::Refused),
            (401, Step::Unauthorized),
            (403, Step::Unauthorized),
            (500, Step::Retry),
            (503, Step::Retry),
        ] {
            assert_eq!(step(status), want, "{status}");
        }
    }

    /// The flags and keys a member run is planned from, and the refusals.
    #[test]
    fn a_member_plan_is_resolved_and_checked() -> Result<(), TestError> {
        use clap::Parser as _;
        let dir = tempfile::tempdir()?;
        let token = dir.path().join("member.token");
        std::fs::write(&token, "s2.x.y\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600))?;
        }
        let spool = dir.path().join("spool");
        let cli = |extra: &[&str]| -> Result<crate::cli::Cli, TestError> {
            Ok(crate::cli::Cli::try_parse_from(
                ["sipnab", "-N"]
                    .iter()
                    .copied()
                    .chain(extra.iter().copied()),
            )?)
        };
        let config = crate::config::Config::default();
        assert_eq!(
            MemberPlan::resolve(&cli(&[])?, &config)?,
            None,
            "no URL, no member"
        );
        let t = token.to_str().ok_or("utf-8")?;
        let sp = spool.to_str().ok_or("utf-8")?;
        let plan = MemberPlan::resolve(
            &cli(&[
                "--fleet-report-url",
                "https://center.example.net:8444",
                "--fleet-report-token-file",
                t,
                "--fleet-spool-dir",
                sp,
            ])?,
            &config,
        )?
        .ok_or("a plan")?;
        assert_eq!(plan.url.host, "center.example.net", "{plan:?}");
        assert_eq!(plan.heartbeat_secs, DEFAULT_HEARTBEAT_SECS, "{plan:?}");
        assert_eq!(plan.spool_max_files, DEFAULT_SPOOL_MAX_FILES, "{plan:?}");
        assert_eq!(plan.spool, spool, "{plan:?}");

        // The keys alone plan the same, and a flag overrides its key.
        let mut keyed = crate::config::Config::default();
        keyed.fleet.report_url = Some("http://127.0.0.1:8444".into());
        keyed.fleet.report_token_file = Some(token.clone());
        keyed.fleet.spool_dir = Some(spool.clone());
        keyed.fleet.heartbeat_secs = Some(5);
        keyed.fleet.spool_max_files = Some(10);
        let plan = MemberPlan::resolve(&cli(&[])?, &keyed)?.ok_or("a plan")?;
        assert_eq!(
            (plan.heartbeat_secs, plan.spool_max_files),
            (5, 10),
            "{plan:?}"
        );
        assert_eq!(
            plan.url.host, "127.0.0.1",
            "plain HTTP to loopback: {plan:?}"
        );
        let plan = MemberPlan::resolve(
            &cli(&["--fleet-report-url", "https://center.example.net:8444"])?,
            &keyed,
        )?
        .ok_or("a plan")?;
        assert!(plan.url.tls, "the flag overrides the key: {plan:?}");

        let refused =
            |args: &[&str], config: &crate::config::Config, want: &str| -> Result<(), TestError> {
                let got = MemberPlan::resolve(&cli(args)?, config);
                let why = got.err().ok_or_else(|| format!("accepted {args:?}"))?;
                assert!(why.contains(want), "{args:?}: {why} does not say {want}");
                Ok(())
            };
        // Every flag overrides its key.
        keyed.fleet.report_ca_file = Some(dir.path().join("key-ca.pem"));
        let flag_token = dir.path().join("flag.token");
        let flag_spool = dir.path().join("flag.spool");
        let flag_ca = dir.path().join("flag-ca.pem");
        let plan = MemberPlan::resolve(
            &cli(&[
                "--fleet-report-token-file",
                flag_token.to_str().ok_or("utf-8")?,
                "--fleet-spool-dir",
                flag_spool.to_str().ok_or("utf-8")?,
                "--fleet-report-ca-file",
                flag_ca.to_str().ok_or("utf-8")?,
            ])?,
            &keyed,
        )?
        .ok_or("a plan")?;
        assert_eq!(plan.token_file, flag_token, "{plan:?}");
        assert_eq!(plan.spool, flag_spool, "{plan:?}");
        assert_eq!(plan.ca_file, Some(flag_ca), "{plan:?}");
        let plan = MemberPlan::resolve(&cli(&[])?, &keyed)?.ok_or("a plan")?;
        assert_eq!(plan.token_file, token, "the keys alone: {plan:?}");
        assert_eq!(
            plan.ca_file,
            Some(dir.path().join("key-ca.pem")),
            "the keys alone: {plan:?}"
        );

        let base = ["--fleet-report-token-file", t, "--fleet-spool-dir", sp];
        let with = |url: &'static str| -> Vec<&str> {
            let mut v = vec!["--fleet-report-url", url];
            v.extend(base);
            v
        };
        refused(&with("http://192.0.2.10:8444"), &config, "plain HTTP")?;
        refused(&with("ftp://192.0.2.10"), &config, "--fleet-report-url")?;
        refused(
            &[
                "--fleet-report-url",
                "https://192.0.2.10:8444",
                "--fleet-spool-dir",
                sp,
            ],
            &config,
            "--fleet-report-token-file",
        )?;
        refused(
            &[
                "--fleet-report-url",
                "https://192.0.2.10:8444",
                "--fleet-report-token-file",
                t,
            ],
            &config,
            "--fleet-spool-dir",
        )?;
        let mut bad = crate::config::Config::default();
        bad.fleet.heartbeat_secs = Some(0);
        refused(&with("https://192.0.2.10:8444"), &bad, "heartbeat_secs")?;
        bad.fleet.heartbeat_secs = Some(3601);
        refused(&with("https://192.0.2.10:8444"), &bad, "heartbeat_secs")?;
        // An empty path, or a bad interval, is refused with no URL set too.
        let mut empty = crate::config::Config::default();
        empty.fleet.report_token_file = Some(PathBuf::new());
        refused(&[], &empty, "[fleet] report_token_file is empty")?;
        let mut bad = crate::config::Config::default();
        bad.fleet.heartbeat_secs = Some(0);
        refused(&[], &bad, "heartbeat_secs")?;
        let mut bad = crate::config::Config::default();
        bad.fleet.spool_max_files = Some(0);
        refused(&with("https://192.0.2.10:8444"), &bad, "spool_max_files")?;
        Ok(())
    }
}

/// One behavior each, by category: what a working member does (SUCCESS),
/// how it meets every way the center, the files or the settings can fail
/// (FAILURE), and the boundaries (EDGE). The delivery rules are driven
/// through [`deliver_spool`] with a scripted center, and the wire through
/// [`post`] against a one-shot local listener.
#[cfg(test)]
mod behavior_tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// A spool in a fresh directory, holding heartbeats 1..=`n`.
    fn spool_with(n: u64) -> Result<tempfile::TempDir, TestError> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join(FAILED_DIR))?;
        for seq in 1..=n {
            std::fs::write(dir.path().join(file_name(seq)), format!("hb {seq}\n"))?;
        }
        Ok(dir)
    }

    /// The bodies a scripted center received, in order.
    type Seen = std::rc::Rc<std::cell::RefCell<Vec<String>>>;

    /// What a center answers: a status and body, or why there was none.
    type Answer = Result<(u16, String), String>;

    /// A scripted center: answers `script` in order and records each body.
    fn scripted(script: Vec<Answer>) -> (impl FnMut(&[u8]) -> Answer, Seen) {
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let log = std::rc::Rc::clone(&seen);
        let mut answers = script.into_iter();
        let send = move |body: &[u8]| {
            log.borrow_mut()
                .push(String::from_utf8_lossy(body).trim().to_string());
            answers
                .next()
                .unwrap_or_else(|| Err("the script ran out".to_string()))
        };
        (send, seen)
    }

    fn ok(status: u16) -> Result<(u16, String), String> {
        Ok((status, String::new()))
    }

    fn left(dir: &Path) -> Result<Vec<String>, TestError> {
        Ok(crate::app::spool::pending(dir)?)
    }

    fn failed(dir: &Path) -> Result<Vec<String>, TestError> {
        Ok(crate::app::spool::pending(&dir.join(FAILED_DIR))?)
    }

    fn cli(args: &[&str]) -> Result<crate::cli::Cli, TestError> {
        use clap::Parser as _;
        Ok(crate::cli::Cli::try_parse_from(
            ["sipnab", "-N"].iter().copied().chain(args.iter().copied()),
        )?)
    }

    /// A config whose `[fleet]` names `url`, a token file and a spool.
    fn fleet_config(url: &str) -> crate::config::Config {
        let mut c = crate::config::Config::default();
        c.fleet.report_url = Some(url.to_string());
        c.fleet.report_token_file = Some(PathBuf::from("/run/example/member.token"));
        c.fleet.spool_dir = Some(PathBuf::from("/run/example/spool"));
        c
    }

    fn private(dir: &Path, name: &str, text: &str, mode: u32) -> Result<PathBuf, TestError> {
        let path = dir.join(name);
        std::fs::write(&path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        }
        #[cfg(not(unix))]
        let _ = mode;
        Ok(path)
    }

    /// A one-shot center on loopback that reads a request and answers
    /// `reply` raw, then closes.
    fn one_shot(
        reply: Vec<u8>,
    ) -> Result<
        (
            super::super::https_client::Endpoint,
            std::thread::JoinHandle<()>,
        ),
        TestError,
    > {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let handle = std::thread::spawn(move || {
            if let Ok((mut sock, _)) = listener.accept() {
                let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                let mut buf = [0u8; 4096];
                let _ = sock.read(&mut buf);
                let _ = sock.write_all(&reply);
            }
        });
        let url = super::super::https_client::Endpoint::parse(
            &format!("http://127.0.0.1:{port}"),
            super::super::https_client::UrlUse::FLEET_REPORT,
        )?;
        Ok((url, handle))
    }

    // ── SUCCESS ─────────────────────────────────────────────────────────

    /// Every waiting heartbeat goes to the center, oldest first.
    #[test]
    fn success_the_spool_is_sent_oldest_first() -> Result<(), TestError> {
        let dir = spool_with(3)?;
        let (send, seen) = scripted(vec![ok(200), ok(200), ok(200)]);
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Drained,
            "success the spool is sent oldest first"
        );
        assert_eq!(
            *seen.borrow(),
            ["hb 1", "hb 2", "hb 3"],
            "in position order"
        );
        Ok(())
    }

    /// A heartbeat the center took leaves the spool.
    #[test]
    fn success_a_delivered_heartbeat_leaves_the_spool() -> Result<(), TestError> {
        let dir = spool_with(2)?;
        let (send, _) = scripted(vec![ok(200), ok(204)]);
        deliver_spool(dir.path(), None, send);
        assert!(left(dir.path())?.is_empty(), "{:?}", left(dir.path())?);
        Ok(())
    }

    /// The defaults: a 30 s interval, a 2880-file spool, no CA of its own.
    #[test]
    fn success_a_plan_takes_the_defaults() -> Result<(), TestError> {
        let plan = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://127.0.0.1:8444"))?
            .ok_or("a plan")?;
        assert_eq!(
            (
                plan.heartbeat_secs,
                plan.spool_max_files,
                plan.ca_file.clone()
            ),
            (30, 2880, None),
            "{plan:?}"
        );
        Ok(())
    }

    /// An `https://` center with no CA of its own plans against the host's
    /// bundle.
    #[test]
    fn success_https_without_a_ca_file_plans() -> Result<(), TestError> {
        let plan = MemberPlan::resolve(&cli(&[])?, &fleet_config("https://192.0.2.10:8444"))?
            .ok_or("a plan")?;
        assert!(plan.url.tls, "{plan:?}");
        Ok(())
    }

    /// `localhost` counts as loopback for plain HTTP.
    #[test]
    fn success_plain_http_to_localhost_plans() -> Result<(), TestError> {
        let plan = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://localhost:8444"))?;
        assert!(plan.is_some_and(|p| !p.url.tls), "plain HTTP to localhost");
        Ok(())
    }

    /// A heartbeat written to the spool is one file, named by its position,
    /// holding the line the center reads.
    #[test]
    fn success_a_heartbeat_is_written_as_one_file() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        let inv = serde_json::json!({"node_name": "edge-a"});
        let now = Utc::now();
        spool_heartbeat(dir.path(), &mut stream, &inv, now, 30, 10, None)?;
        assert_eq!(left(dir.path())?, [file_name(1)], "one file, position 1");
        let text = std::fs::read_to_string(dir.path().join(file_name(1)))?;
        assert_eq!(
            text,
            heartbeat_line(&stream.stream, 1, now, 30, &inv),
            "the line"
        );
        Ok(())
    }

    /// Each heartbeat takes the next position.
    #[test]
    fn success_heartbeats_take_successive_positions() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        let inv = serde_json::json!({});
        for _ in 0..3 {
            spool_heartbeat(dir.path(), &mut stream, &inv, Utc::now(), 30, 10, None)?;
        }
        assert_eq!(
            left(dir.path())?,
            [file_name(1), file_name(2), file_name(3)],
            "success heartbeats take successive positions"
        );
        Ok(())
    }

    /// After a drained pass, the next one waits for the next heartbeat.
    #[test]
    fn success_a_drained_pass_waits_for_the_next_heartbeat() {
        let mut d = Delivery::new(30);
        let now = Instant::now();
        let beat = now + Duration::from_secs(30);
        d.after(Pass::Drained, now, beat);
        assert_eq!(d.next_try, beat, "the next try is the next heartbeat");
    }

    /// Delivery coming back after a wait is logged once, with the reason.
    #[test]
    fn success_delivery_coming_back_is_logged_with_the_reason() {
        let mut d = Delivery::new(30);
        let now = Instant::now();
        d.after(Pass::Wait("the center answered HTTP 503".into()), now, now);
        let line = d.after(Pass::Drained, now, now);
        assert_eq!(
            line.as_deref(),
            Some("the center takes heartbeats again (was: the center answered HTTP 503)"),
            "success delivery coming back is logged with the reason"
        );
    }

    /// The ingest path goes under the URL's own path.
    #[test]
    fn success_the_ingest_path_sits_under_the_urls_path() {
        assert_eq!(
            ingest_path("/sipnab"),
            "/sipnab/v1/fleet/ingest",
            "success the ingest path sits under the urls path"
        );
    }

    /// A one-shot center's `200` and body come back through the wire.
    #[test]
    fn success_the_wire_returns_the_status_and_body() -> Result<(), TestError> {
        let (url, h) = one_shot(
            b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n{\"accepted\":1"
                .to_vec(),
        )?;
        let got = post(&url, None, "s2.x.y", b"hb\n")?;
        let _ = h.join();
        assert_eq!(
            got,
            (200, "{\"accepted\":1".to_string()),
            "success the wire returns the status and body"
        );
        Ok(())
    }

    /// A token file holding one token is read, trimmed.
    #[test]
    fn success_a_private_token_file_is_read() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "t", "s2.abc.def\n", 0o600)?;
        assert_eq!(
            read_token(&path)?,
            "s2.abc.def",
            "success a private token file is read"
        );
        Ok(())
    }

    // ── FAILURE ─────────────────────────────────────────────────────────

    /// A `5xx` keeps the heartbeat and stops the pass.
    #[test]
    fn failure_a_5xx_keeps_the_heartbeat_and_stops() -> Result<(), TestError> {
        let dir = spool_with(2)?;
        let (send, seen) = scripted(vec![ok(503)]);
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Wait("the center answered HTTP 503".into()),
            "failure a 5xx keeps the heartbeat and stops"
        );
        assert_eq!(left(dir.path())?.len(), 2, "both kept");
        assert_eq!(seen.borrow().len(), 1, "nothing sent after the 503");
        Ok(())
    }

    /// No answer at all (down, timeout) keeps the heartbeat and says why.
    #[test]
    fn failure_no_answer_keeps_the_heartbeat() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        let (send, _) = scripted(vec![Err("connection timed out".into())]);
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Wait("the center did not answer: connection timed out".into()),
            "failure no answer keeps the heartbeat"
        );
        assert_eq!(
            left(dir.path())?.len(),
            1,
            "failure no answer keeps the heartbeat"
        );
        Ok(())
    }

    /// A `401` keeps every heartbeat and names the token.
    #[test]
    fn failure_a_401_waits_and_names_the_token() -> Result<(), TestError> {
        let dir = spool_with(2)?;
        let (send, seen) = scripted(vec![ok(401)]);
        let Pass::Wait(why) = deliver_spool(dir.path(), None, send) else {
            return Err("a 401 must wait".into());
        };
        assert!(
            why.contains("refused this member's token (HTTP 401)"),
            "{why}"
        );
        assert_eq!(
            (left(dir.path())?.len(), seen.borrow().len()),
            (2, 1),
            "failure a 401 waits and names the token"
        );
        Ok(())
    }

    /// A `403` is a refused token too, not a refused heartbeat.
    #[test]
    fn failure_a_403_is_a_refused_token() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        let (send, _) = scripted(vec![ok(403)]);
        let Pass::Wait(why) = deliver_spool(dir.path(), None, send) else {
            return Err("a 403 must wait".into());
        };
        assert!(why.contains("HTTP 403"), "{why}");
        assert!(failed(dir.path())?.is_empty(), "nothing moved to failed/");
        Ok(())
    }

    /// A `400` moves that heartbeat to `failed/` and the pass goes on.
    #[test]
    fn failure_a_400_moves_the_heartbeat_to_failed() -> Result<(), TestError> {
        let dir = spool_with(2)?;
        let (send, _) = scripted(vec![ok(400), ok(200)]);
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Drained,
            "failure a 400 moves the heartbeat to failed"
        );
        assert_eq!(
            failed(dir.path())?,
            [file_name(1)],
            "failure a 400 moves the heartbeat to failed"
        );
        assert!(left(dir.path())?.is_empty(), "the next one was delivered");
        Ok(())
    }

    /// A `413` (too large) is a refusal for good as well.
    #[test]
    fn failure_a_413_moves_the_heartbeat_to_failed() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        let (send, _) = scripted(vec![ok(413)]);
        deliver_spool(dir.path(), None, send);
        assert_eq!(
            failed(dir.path())?,
            [file_name(1)],
            "failure a 413 moves the heartbeat to failed"
        );
        Ok(())
    }

    /// Plain HTTP to a host name that is not this machine is refused.
    #[test]
    fn failure_plain_http_to_a_host_name_is_refused() -> Result<(), TestError> {
        let got = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://center.example.net:8444"));
        assert!(
            got.is_err_and(|e| e.contains("plain HTTP")),
            "failure plain http to a host name is refused"
        );
        Ok(())
    }

    /// Plain HTTP to an IPv6 address that is not loopback is refused.
    #[test]
    fn failure_plain_http_to_a_routable_ipv6_is_refused() -> Result<(), TestError> {
        let got = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://[2001:db8::10]:8444"));
        assert!(
            got.is_err_and(|e| e.contains("plain HTTP")),
            "failure plain http to a routable ipv6 is refused"
        );
        Ok(())
    }

    /// A CA file that does not exist is refused at plan time, by its flag.
    #[test]
    fn failure_a_missing_ca_file_is_refused() -> Result<(), TestError> {
        let got = MemberPlan::resolve(
            &cli(&["--fleet-report-ca-file", "/nonexistent/fleet-ca.pem"])?,
            &fleet_config("https://192.0.2.10:8444"),
        );
        assert!(
            got.as_ref()
                .is_err_and(|e| e.contains("--fleet-report-ca-file")),
            "{got:?}"
        );
        Ok(())
    }

    /// A CA file that holds no certificate is refused.
    #[test]
    fn failure_a_ca_file_with_no_certificate_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let ca = private(dir.path(), "ca.pem", "not a certificate\n", 0o644)?;
        let got = MemberPlan::resolve(
            &cli(&["--fleet-report-ca-file", ca.to_str().ok_or("utf-8")?])?,
            &fleet_config("https://192.0.2.10:8444"),
        );
        assert!(got.is_err(), "a CA file with no certificate");
        Ok(())
    }

    /// An empty token file is refused, naming the file and not a token.
    #[test]
    fn failure_an_empty_token_file_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "t", "\n", 0o600)?;
        assert!(
            read_token(&path).is_err_and(|e| e.contains("does not hold one token")),
            "failure an empty token file is refused"
        );
        Ok(())
    }

    /// Two tokens in one file are refused.
    #[test]
    fn failure_two_tokens_in_one_file_are_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "t", "s2.a.b\ns2.c.d\n", 0o600)?;
        assert!(
            read_token(&path).is_err_and(|e| !e.contains("s2.a.b")),
            "failure two tokens in one file are refused"
        );
        Ok(())
    }

    /// A token file other users can read is refused, naming its mode.
    #[cfg(unix)]
    #[test]
    fn failure_a_token_file_others_can_read_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "t", "s2.a.b\n", 0o640)?;
        assert!(
            read_token(&path).is_err_and(|e| e.contains("mode 0640")),
            "failure a token file others can read is refused"
        );
        Ok(())
    }

    /// A token file that is not there is refused, by its flag.
    #[test]
    fn failure_a_missing_token_file_is_refused() {
        let got = read_token(Path::new("/nonexistent/sipnab-member.token"));
        assert!(
            got.is_err_and(|e| e.starts_with("--fleet-report-token-file")),
            "failure a missing token file is refused"
        );
    }

    /// A spool path that is a file, not a directory, cannot be opened.
    #[test]
    fn failure_a_spool_that_is_a_file_cannot_be_opened() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("spool");
        std::fs::write(&path, "not a directory")?;
        assert!(
            SpoolStream::open(&path).is_err(),
            "failure a spool that is a file cannot be opened"
        );
        Ok(())
    }

    /// A spool whose stream file holds no stream id is refused, not reused.
    #[test]
    fn failure_a_corrupt_stream_file_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(STREAM_FILE), "not a stream id!")?;
        let got = SpoolStream::open(dir.path());
        assert!(
            got.is_err_and(|e| e.kind() == std::io::ErrorKind::InvalidData),
            "failure a corrupt stream file is refused"
        );
        Ok(())
    }

    /// A spool whose position file holds no number is refused.
    #[test]
    fn failure_a_corrupt_position_file_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        std::fs::write(dir.path().join(SEQ_FILE), "seven")?;
        assert!(
            SpoolStream::open(dir.path()).is_err(),
            "failure a corrupt position file is refused"
        );
        Ok(())
    }

    /// A heartbeat cannot be written into a spool that has gone.
    #[test]
    fn failure_a_heartbeat_into_a_removed_spool_is_an_error() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let spool = dir.path().join("spool");
        let mut stream = SpoolStream::open(&spool)?;
        std::fs::remove_dir_all(&spool)?;
        let got = spool_heartbeat(
            &spool,
            &mut stream,
            &serde_json::json!({}),
            Utc::now(),
            30,
            10,
            None,
        );
        assert!(
            got.is_err(),
            "failure a heartbeat into a removed spool is an error"
        );
        Ok(())
    }

    /// A reply that is not HTTP is no answer.
    #[test]
    fn failure_a_reply_that_is_not_http_is_no_answer() -> Result<(), TestError> {
        let (url, h) = one_shot(b"SSH-2.0-OpenSSH_9.6\r\n\r\n".to_vec())?;
        let got = post(&url, None, "s2.x.y", b"hb\n");
        let _ = h.join();
        assert!(
            got.is_err_and(|e| e.contains("not HTTP")),
            "failure a reply that is not http is no answer"
        );
        Ok(())
    }

    /// A center that closes without a word is no answer.
    #[test]
    fn failure_a_closed_connection_is_no_answer() -> Result<(), TestError> {
        let (url, h) = one_shot(Vec::new())?;
        let got = post(&url, None, "s2.x.y", b"hb\n");
        let _ = h.join();
        assert!(got.is_err(), "failure a closed connection is no answer");
        Ok(())
    }

    /// A port where nothing listens is no answer.
    #[test]
    fn failure_a_refused_connection_is_no_answer() -> Result<(), TestError> {
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let url = super::super::https_client::Endpoint::parse(
            &format!("http://127.0.0.1:{port}"),
            super::super::https_client::UrlUse::FLEET_REPORT,
        )?;
        assert!(
            post(&url, None, "s2.x.y", b"hb\n").is_err(),
            "failure a refused connection is no answer"
        );
        Ok(())
    }

    // ── EDGE ────────────────────────────────────────────────────────────

    /// An empty spool asks the center nothing.
    #[test]
    fn edge_an_empty_spool_sends_nothing() -> Result<(), TestError> {
        let dir = spool_with(0)?;
        let (send, seen) = scripted(Vec::new());
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Drained,
            "edge an empty spool sends nothing"
        );
        assert!(
            seen.borrow().is_empty(),
            "edge an empty spool sends nothing"
        );
        Ok(())
    }

    /// A spool exactly at its cap keeps every heartbeat.
    #[test]
    fn edge_a_spool_at_its_cap_keeps_all() -> Result<(), TestError> {
        let dir = spool_with(3)?;
        assert_eq!(
            enforce_cap(dir.path(), 3)?,
            0,
            "edge a spool at its cap keeps all"
        );
        Ok(())
    }

    /// A cap of one keeps only the newest heartbeat.
    #[test]
    fn edge_a_cap_of_one_keeps_the_newest() -> Result<(), TestError> {
        let dir = spool_with(4)?;
        enforce_cap(dir.path(), 1)?;
        assert_eq!(
            left(dir.path())?,
            [file_name(4)],
            "edge a cap of one keeps the newest"
        );
        Ok(())
    }

    /// The position saturates at the largest number rather than wrapping
    /// to an old one.
    #[test]
    fn edge_the_position_saturates() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        stream.next_seq = u64::MAX;
        assert_eq!(
            stream.take(dir.path())?,
            u64::MAX,
            "edge the position saturates"
        );
        assert_eq!(stream.next_seq, u64::MAX, "no wrap to 0");
        Ok(())
    }

    /// A file that goes between the listing and the read (the cap removed
    /// it) is passed over, and the pass goes on to the next one.
    #[test]
    fn edge_a_vanished_heartbeat_is_passed_over() -> Result<(), TestError> {
        let dir = spool_with(3)?;
        let second = dir.path().join(file_name(2));
        let mut seen = Vec::new();
        let send = |body: &[u8]| {
            seen.push(String::from_utf8_lossy(body).trim().to_string());
            // Removed after the pass listed it, before the pass reads it.
            let _ = std::fs::remove_file(&second);
            ok(200)
        };
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Drained,
            "edge a vanished heartbeat is passed over"
        );
        assert_eq!(seen, ["hb 1", "hb 3"], "the vanished one is passed over");
        Ok(())
    }

    /// The spool's own dot-files and other names are never sent.
    #[test]
    fn edge_dot_files_and_other_names_are_not_sent() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        std::fs::write(dir.path().join(STREAM_FILE), "abc")?;
        std::fs::write(dir.path().join("notes.txt"), "x")?;
        let (send, seen) = scripted(vec![ok(200)]);
        deliver_spool(dir.path(), None, send);
        assert_eq!(
            *seen.borrow(),
            ["hb 1"],
            "edge dot files and other names are not sent"
        );
        Ok(())
    }

    /// A heartbeat moved to `failed/` is not sent again.
    #[test]
    fn edge_a_failed_heartbeat_is_not_sent_again() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        let (send, _) = scripted(vec![ok(400)]);
        deliver_spool(dir.path(), None, send);
        let (send, seen) = scripted(Vec::new());
        assert_eq!(
            deliver_spool(dir.path(), None, send),
            Pass::Drained,
            "edge a failed heartbeat is not sent again"
        );
        assert!(
            seen.borrow().is_empty(),
            "edge a failed heartbeat is not sent again"
        );
        Ok(())
    }

    /// The interval's bounds, 1 and 3600 seconds, are accepted.
    #[test]
    fn edge_the_interval_bounds_are_accepted() -> Result<(), TestError> {
        for secs in [1, 3600] {
            let mut c = fleet_config("http://127.0.0.1:8444");
            c.fleet.heartbeat_secs = Some(secs);
            let plan = MemberPlan::resolve(&cli(&[])?, &c)?.ok_or("a plan")?;
            assert_eq!(
                plan.heartbeat_secs, secs,
                "edge the interval bounds are accepted"
            );
        }
        Ok(())
    }

    /// Unicode in the inventory reaches the center unchanged.
    #[test]
    fn edge_unicode_in_the_inventory_round_trips() -> Result<(), TestError> {
        let inv = serde_json::json!({"node_name": "edge-zürich-東京"});
        let line = heartbeat_line("s", 1, Utc::now(), 30, &inv);
        let got = crate::app::fleet_center::parse_heartbeats(line.as_bytes())?;
        assert_eq!(
            got[0].inventory, inv,
            "edge unicode in the inventory round trips"
        );
        Ok(())
    }

    /// An empty inventory object is still a heartbeat the center reads.
    #[test]
    fn edge_an_empty_inventory_is_a_heartbeat() -> Result<(), TestError> {
        let line = heartbeat_line("s", 1, Utc::now(), 30, &serde_json::json!({}));
        assert_eq!(
            crate::app::fleet_center::parse_heartbeats(line.as_bytes())?.len(),
            1,
            "edge an empty inventory is a heartbeat"
        );
        Ok(())
    }

    /// The send time keeps its nanoseconds.
    #[test]
    fn edge_the_send_time_keeps_nanoseconds() -> Result<(), TestError> {
        let at =
            DateTime::parse_from_rfc3339("2026-11-07T12:00:00.123456789Z")?.with_timezone(&Utc);
        let line = heartbeat_line("s", 1, at, 30, &serde_json::json!({}));
        assert_eq!(
            crate::app::fleet_center::parse_heartbeats(line.as_bytes())?[0].sent_at,
            at,
            "edge the send time keeps nanoseconds"
        );
        Ok(())
    }

    /// Plain HTTP to the IPv6 loopback address plans.
    #[test]
    fn edge_plain_http_to_ipv6_loopback_plans() -> Result<(), TestError> {
        let plan = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://[::1]:8444"))?;
        assert!(
            plan.is_some_and(|p| p.url.host == "::1"),
            "edge plain http to ipv6 loopback plans"
        );
        Ok(())
    }

    /// A URL ending in `/` gets no double slash before the ingest path.
    #[test]
    fn edge_a_trailing_slash_gives_no_double_slash() {
        assert_eq!(
            ingest_path("/"),
            "/v1/fleet/ingest",
            "edge a trailing slash gives no double slash"
        );
    }

    /// The first retry after a failure comes one second later.
    #[test]
    fn edge_the_first_retry_is_one_second_later() {
        let mut d = Delivery::new(30);
        let now = Instant::now();
        d.after(Pass::Wait("x".into()), now, now);
        assert_eq!(
            d.next_try,
            now + Duration::from_secs(1),
            "edge the first retry is one second later"
        );
    }

    /// Retries double, and never wait longer than one interval.
    #[test]
    fn edge_retries_never_wait_past_one_interval() {
        let mut d = Delivery::new(5);
        let now = Instant::now();
        for _ in 0..20 {
            d.after(Pass::Wait("x".into()), now, now);
        }
        assert_eq!(
            d.next_try,
            now + Duration::from_secs(5),
            "edge retries never wait past one interval"
        );
    }

    /// One reason heartbeats wait is logged once, however many passes.
    #[test]
    fn edge_the_same_reason_is_logged_once() {
        let mut d = Delivery::new(30);
        let now = Instant::now();
        assert!(
            d.after(Pass::Wait("down".into()), now, now).is_some(),
            "edge the same reason is logged once"
        );
        assert_eq!(
            d.after(Pass::Wait("down".into()), now, now),
            None,
            "edge the same reason is logged once"
        );
    }

    /// A new reason is logged again.
    #[test]
    fn edge_a_new_reason_is_logged_again() {
        let mut d = Delivery::new(30);
        let now = Instant::now();
        d.after(Pass::Wait("down".into()), now, now);
        let line = d.after(Pass::Wait("HTTP 401".into()), now, now);
        assert_eq!(
            line.as_deref(),
            Some("heartbeats wait in the spool: HTTP 401"),
            "edge a new reason is logged again"
        );
    }

    /// A member restarted mid-batch continues after the last position it
    /// took, delivered or not.
    #[test]
    fn edge_a_restart_mid_batch_continues_the_positions() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        for _ in 0..3 {
            spool_heartbeat(
                dir.path(),
                &mut stream,
                &serde_json::json!({}),
                Utc::now(),
                30,
                10,
                None,
            )?;
        }
        let (send, _) = scripted(vec![ok(200), ok(200), Err("stopped".into())]);
        deliver_spool(dir.path(), None, send);
        let mut again = SpoolStream::open(dir.path())?;
        assert_eq!(
            again.take(dir.path())?,
            4,
            "edge a restart mid batch continues the positions"
        );
        Ok(())
    }

    /// A long answer is kept to its first 200 characters.
    #[test]
    fn edge_a_long_answer_is_cut_to_200_characters() -> Result<(), TestError> {
        let body = "x".repeat(5000);
        let reply = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let (url, h) = one_shot(reply.into_bytes())?;
        let (status, text) = post(&url, None, "s2.x.y", b"hb\n")?;
        let _ = h.join();
        assert_eq!(
            (status, text.chars().count()),
            (400, 200),
            "edge a long answer is cut to 200 characters"
        );
        Ok(())
    }

    // ── CALL RECORDS ────────────────────────────────────────────────────

    use crate::app::fleet_calls::{CallCounts, CallPush, Selected};
    use crate::app::fleet_seal::{Keys, MasterKey};

    /// `[fleet]` with `set` applied.
    fn fleet_keys(set: impl Fn(&mut crate::config::FleetConfig)) -> crate::config::FleetConfig {
        let mut keys = crate::config::FleetConfig::default();
        set(&mut keys);
        keys
    }

    /// A spool key path, for a plan that is not started.
    fn key_path() -> PathBuf {
        PathBuf::from("/run/example/spool.key")
    }

    #[test]
    fn success_a_member_with_no_call_settings_pushes_no_calls() -> Result<(), TestError> {
        assert_eq!(
            call_plan(&fleet_keys(|_| {}))?,
            None,
            "success a member with no call settings pushes no calls"
        );
        let plan = MemberPlan::resolve(&cli(&[])?, &fleet_config("http://127.0.0.1:8444"))?
            .ok_or("a plan")?;
        assert_eq!(
            plan.calls, None,
            "a member set up before call records runs as it did"
        );
        Ok(())
    }

    #[test]
    fn success_a_spool_key_alone_pushes_exceptions_at_the_default_cap() -> Result<(), TestError> {
        let got = call_plan(&fleet_keys(|k| k.spool_key_file = Some(key_path())))?;
        let want = CallPlan {
            rule: CallPush::Exceptions,
            max_per_sec: 10,
            key_file: key_path(),
        };
        assert_eq!(
            got,
            Some(want),
            "success a spool key alone pushes exceptions at the default cap"
        );
        Ok(())
    }

    #[test]
    fn success_call_push_all_with_a_key_and_a_cap_is_planned_as_written() -> Result<(), TestError> {
        let mut c = fleet_config("http://127.0.0.1:8444");
        c.fleet.spool_key_file = Some(key_path());
        c.fleet.call_push = Some("all".to_string());
        c.fleet.exception_max_per_sec = Some(250);
        let plan = MemberPlan::resolve(&cli(&[])?, &c)?.ok_or("a plan")?;
        let want = CallPlan {
            rule: CallPush::All,
            max_per_sec: 250,
            key_file: key_path(),
        };
        assert_eq!(
            plan.calls,
            Some(want),
            "success call push all with a key and a cap is planned as written"
        );
        Ok(())
    }

    #[test]
    fn failure_call_push_without_a_spool_key_is_refused_with_the_fix() {
        for rule in ["exceptions", "all"] {
            let e = call_plan(&fleet_keys(|k| k.call_push = Some(rule.to_string())))
                .err()
                .unwrap_or_default();
            assert_eq!(
                e,
                format!(
                    "[fleet] call_push \"{rule}\" needs [fleet] spool_key_file: call records wait \
                     on disk only in sealed files. Create a key with `sipnab fleet keygen --out FILE`"
                ),
                "failure call push without a spool key is refused with the fix"
            );
        }
    }

    #[test]
    fn failure_an_unknown_call_push_is_refused_even_with_no_center_named() -> Result<(), TestError>
    {
        let mut c = crate::config::Config::default();
        c.fleet.call_push = Some("some".to_string());
        let e = MemberPlan::resolve(&cli(&[])?, &c)
            .err()
            .unwrap_or_default();
        assert!(
            e.starts_with("[fleet] call_push \"some\" is not one of"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn failure_an_exception_cap_out_of_range_is_refused() {
        for cap in [0, 10_001, u32::MAX] {
            let e = call_plan(&fleet_keys(|k| {
                k.spool_key_file = Some(key_path());
                k.exception_max_per_sec = Some(cap);
            }))
            .err()
            .unwrap_or_default();
            assert_eq!(
                e,
                format!("[fleet] exception_max_per_sec {cap} is outside 1 to 10000"),
                "failure an exception cap out of range is refused"
            );
        }
        let unused = call_plan(&fleet_keys(|k| k.exception_max_per_sec = Some(0))).err();
        assert!(
            unused.is_some(),
            "refused when it is written, key or no key"
        );
    }

    #[test]
    fn failure_an_empty_spool_key_path_is_refused() -> Result<(), TestError> {
        let mut c = crate::config::Config::default();
        c.fleet.spool_key_file = Some(PathBuf::new());
        let e = MemberPlan::resolve(&cli(&[])?, &c)
            .err()
            .unwrap_or_default();
        assert_eq!(
            e, "[fleet] spool_key_file is empty; give a path",
            "failure an empty spool key path is refused"
        );
        Ok(())
    }

    #[test]
    fn edge_call_push_none_with_a_key_pushes_no_calls() -> Result<(), TestError> {
        let got = call_plan(&fleet_keys(|k| {
            k.spool_key_file = Some(key_path());
            k.call_push = Some("none".to_string());
        }))?;
        assert_eq!(got, None, "edge call push none with a key pushes no calls");
        Ok(())
    }

    #[test]
    fn edge_the_exception_cap_bounds_are_accepted() -> Result<(), TestError> {
        for cap in [1, 10_000] {
            let got = call_plan(&fleet_keys(|k| {
                k.spool_key_file = Some(key_path());
                k.exception_max_per_sec = Some(cap);
            }))?;
            assert_eq!(
                got.map(|plan| plan.max_per_sec),
                Some(cap),
                "edge the exception cap bounds are accepted"
            );
        }
        Ok(())
    }

    #[test]
    fn success_positions_taken_together_are_successive_and_recorded() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        assert_eq!(
            stream.take_n(dir.path(), 3)?,
            1,
            "success positions taken together are successive and recorded"
        );
        assert_eq!(
            stream.take(dir.path())?,
            4,
            "the next position is past the three"
        );
        assert_eq!(
            SpoolStream::open(dir.path())?.next_seq,
            5,
            "and a restart continues"
        );
        Ok(())
    }

    #[test]
    fn edge_taking_no_position_takes_none() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        stream.take_n(dir.path(), 0)?;
        assert_eq!(
            stream.take(dir.path())?,
            1,
            "edge taking no position takes none"
        );
        Ok(())
    }

    /// Every file name in the spool's failed directory.
    fn failed_names(dir: &Path) -> Result<Vec<String>, TestError> {
        let mut names = Vec::new();
        for entry in std::fs::read_dir(dir.join(FAILED_DIR))? {
            names.push(entry?.file_name().to_string_lossy().into_owned());
        }
        names.sort();
        Ok(names)
    }

    /// The spool key the tests seal under, alone.
    fn spool_keys() -> Keys {
        Keys::new(MasterKey::from_bytes([7; 32]), Vec::new())
    }

    /// `n` selected calls that name a number and a host.
    fn selected(n: usize) -> Vec<Selected> {
        (0..n)
            .map(|i| Selected {
                selected_by: "failed",
                call: serde_json::json!({
                    "call_id": format!("call-{i}@example.com"),
                    "from": "sip:+12025550101@example.com",
                }),
            })
            .collect()
    }

    /// `n` calls sealed into the spool at `dir` as the stream's next records.
    fn spool_n(dir: &Path, n: usize) -> Result<(u64, u64), TestError> {
        let mut stream = SpoolStream::open(dir)?;
        let now = DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z")?.with_timezone(&Utc);
        Ok(spool_calls(
            dir,
            &mut stream,
            &selected(n),
            now,
            spool_keys().current(),
            &crate::app::fleet_seal::system_draw,
        )?)
    }

    #[test]
    fn success_calls_are_sealed_as_one_delivery_named_by_its_first_position()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        SpoolStream::open(dir.path())?.take(dir.path())?;
        assert_eq!(
            spool_n(dir.path(), 3)?,
            (3, 0),
            "success calls are sealed as one delivery named by its first position"
        );
        assert_eq!(
            waiting(dir.path())?,
            vec!["00000000000000000002.sealed"],
            "success calls are sealed as one delivery named by its first position"
        );
        let bytes = std::fs::read(dir.path().join("00000000000000000002.sealed"))?;
        let body = crate::app::fleet_calls::open_batch(&bytes, &spool_keys())
            .map_err(|e| e.to_string())?;
        let records = crate::app::fleet_center::parse_batch(&body)?;
        let seqs: Vec<u64> = records
            .iter()
            .filter_map(|r| r.call().map(|c| c.seq))
            .collect();
        assert_eq!(seqs, vec![2, 3, 4], "each call has its own position");
        assert_eq!(
            SpoolStream::open(dir.path())?.next_seq,
            5,
            "success calls are sealed as one delivery named by its first position"
        );
        Ok(())
    }

    #[test]
    fn success_no_file_of_the_spool_holds_a_call_in_clear() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        spool_n(dir.path(), 3)?;
        let mut files = 0;
        for entry in std::fs::read_dir(dir.path())? {
            let path = entry?.path();
            if !path.is_file() {
                continue;
            }
            files += 1;
            let bytes = std::fs::read(&path)?;
            for clear in ["2025550101", "example.com", "call_id"] {
                assert!(
                    !bytes.windows(clear.len()).any(|w| w == clear.as_bytes()),
                    "{clear} is in {}",
                    path.display()
                );
            }
        }
        assert_eq!(files, 3, "the delivery, the stream id and the position");
        Ok(())
    }

    #[test]
    fn edge_no_calls_write_no_file_and_take_no_position() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert_eq!(
            spool_n(dir.path(), 0)?,
            (0, 0),
            "edge no calls write no file and take no position"
        );
        assert_eq!(
            waiting(dir.path())?,
            Vec::<String>::new(),
            "edge no calls write no file and take no position"
        );
        assert_eq!(
            SpoolStream::open(dir.path())?.next_seq,
            1,
            "edge no calls write no file and take no position"
        );
        Ok(())
    }

    #[test]
    fn edge_a_call_over_the_size_of_a_delivery_is_left_out_and_the_rest_written()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut calls = selected(2);
        calls[0].call["note"] =
            serde_json::json!("x".repeat(crate::app::fleet_calls::MAX_DELIVERY_BYTES));
        let mut stream = SpoolStream::open(dir.path())?;
        let got = spool_calls(
            dir.path(),
            &mut stream,
            &calls,
            Utc::now(),
            spool_keys().current(),
            &crate::app::fleet_seal::system_draw,
        )?;
        assert_eq!(
            got,
            (1, 1),
            "edge a call over the size of a delivery is left out and the rest written"
        );
        assert_eq!(
            waiting(dir.path())?.len(),
            1,
            "edge a call over the size of a delivery is left out and the rest written"
        );
        Ok(())
    }

    #[test]
    fn failure_a_random_source_that_fails_leaves_no_delivery() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let mut stream = SpoolStream::open(dir.path())?;
        let failing = |_: usize| Err("no entropy".to_string());
        let e = spool_calls(
            dir.path(),
            &mut stream,
            &selected(1),
            Utc::now(),
            spool_keys().current(),
            &failing,
        )
        .err()
        .unwrap_or_default();
        assert_eq!(
            e, "no entropy",
            "failure a random source that fails leaves no delivery"
        );
        assert_eq!(
            waiting(dir.path())?,
            Vec::<String>::new(),
            "failure a random source that fails leaves no delivery"
        );
        Ok(())
    }

    #[test]
    fn success_a_sealed_delivery_is_sent_as_its_lines_and_removed_when_taken()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join(FAILED_DIR))?;
        spool_n(dir.path(), 2)?;
        let (send, seen) = scripted(vec![ok(200)]);
        assert_eq!(
            deliver_spool(dir.path(), Some(&spool_keys()), send),
            Pass::Drained,
            "success a sealed delivery is sent as its lines and removed when taken"
        );
        let bodies = seen.borrow();
        assert_eq!(
            bodies.len(),
            1,
            "success a sealed delivery is sent as its lines and removed when taken"
        );
        let records = crate::app::fleet_center::parse_batch(bodies[0].as_bytes())?;
        assert_eq!(
            records.len(),
            2,
            "the center reads what was sent: {}",
            bodies[0]
        );
        assert_eq!(
            waiting(dir.path())?,
            Vec::<String>::new(),
            "deleted on acknowledgment"
        );
        Ok(())
    }

    #[test]
    fn failure_no_answer_keeps_the_sealed_delivery_sealed() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        spool_n(dir.path(), 2)?;
        let before = std::fs::read(dir.path().join("00000000000000000001.sealed"))?;
        let (send, _) = scripted(vec![Err("refused".to_string())]);
        let pass = deliver_spool(dir.path(), Some(&spool_keys()), send);
        assert_eq!(
            pass,
            Pass::Wait("the center did not answer: refused".to_string()),
            "failure no answer keeps the sealed delivery sealed"
        );
        assert_eq!(
            std::fs::read(dir.path().join("00000000000000000001.sealed"))?,
            before,
            "failure no answer keeps the sealed delivery sealed"
        );
        Ok(())
    }

    #[test]
    fn failure_a_delivery_that_does_not_open_goes_to_failed_and_is_never_sent()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        std::fs::create_dir_all(dir.path().join(FAILED_DIR))?;
        spool_n(dir.path(), 1)?;
        let path = dir.path().join("00000000000000000001.sealed");
        let mut bytes = std::fs::read(&path)?;
        let last = bytes.len() - 30;
        bytes[last] ^= 1;
        std::fs::write(&path, &bytes)?;
        let (send, seen) = scripted(Vec::new());
        assert_eq!(
            deliver_spool(dir.path(), Some(&spool_keys()), send),
            Pass::Drained,
            "failure a delivery that does not open goes to failed and is never sent"
        );
        assert!(seen.borrow().is_empty(), "nothing of it reaches the center");
        assert_eq!(
            failed_names(dir.path())?,
            vec!["00000000000000000001.sealed"],
            "failure a delivery that does not open goes to failed and is never sent"
        );
        Ok(())
    }

    #[test]
    fn failure_a_delivery_under_another_key_or_with_no_key_goes_to_failed() -> Result<(), TestError>
    {
        let other = Keys::new(MasterKey::from_bytes([8; 32]), Vec::new());
        for keys in [Some(&other), None] {
            let dir = tempfile::tempdir()?;
            std::fs::create_dir_all(dir.path().join(FAILED_DIR))?;
            spool_n(dir.path(), 1)?;
            let (send, seen) = scripted(Vec::new());
            assert_eq!(
                deliver_spool(dir.path(), keys, send),
                Pass::Drained,
                "failure a delivery under another key or with no key goes to failed"
            );
            assert!(
                seen.borrow().is_empty(),
                "failure a delivery under another key or with no key goes to failed"
            );
            assert_eq!(
                failed_names(dir.path())?.len(),
                1,
                "failure a delivery under another key or with no key goes to failed"
            );
        }
        Ok(())
    }

    #[test]
    fn edge_heartbeats_and_deliveries_are_sent_in_position_order() -> Result<(), TestError> {
        let dir = spool_with(1)?;
        SpoolStream::open(dir.path())?.take_n(dir.path(), 1)?;
        spool_n(dir.path(), 2)?;
        let mut stream = SpoolStream::open(dir.path())?;
        let inventory = serde_json::json!({});
        spool_heartbeat(
            dir.path(),
            &mut stream,
            &inventory,
            Utc::now(),
            30,
            100,
            None,
        )?;
        let (send, seen) = scripted(vec![ok(200), ok(200), ok(200)]);
        assert_eq!(
            deliver_spool(dir.path(), Some(&spool_keys()), send),
            Pass::Drained,
            "edge heartbeats and deliveries are sent in position order"
        );
        let kinds: Vec<&str> = seen
            .borrow()
            .iter()
            .map(|body| {
                if body.contains("\"kind\":\"call\"") {
                    "calls"
                } else {
                    "heartbeat"
                }
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["heartbeat", "calls", "heartbeat"],
            "edge heartbeats and deliveries are sent in position order"
        );
        Ok(())
    }

    #[test]
    fn edge_the_spool_cap_counts_deliveries_with_heartbeats() -> Result<(), TestError> {
        let dir = spool_with(2)?;
        SpoolStream::open(dir.path())?.take_n(dir.path(), 2)?;
        spool_n(dir.path(), 1)?;
        assert_eq!(
            enforce_cap(dir.path(), 2)?,
            1,
            "edge the spool cap counts deliveries with heartbeats"
        );
        let left = waiting(dir.path())?;
        assert_eq!(left.len(), 2, "{left:?}");
        assert!(
            left[1].ends_with(".sealed"),
            "the oldest heartbeat went: {left:?}"
        );
        Ok(())
    }

    #[test]
    fn success_a_heartbeat_carries_the_call_counts_the_center_reads() -> Result<(), TestError> {
        let at = DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z")?.with_timezone(&Utc);
        let counts = CallCounts {
            selected: 5,
            dropped_by_cap: 2,
            left_out: 1,
            spooled: 4,
        };
        let line = heartbeat_line_with("s-1", 7, at, 30, &serde_json::json!({}), Some(counts));
        let got = crate::app::fleet_center::parse_heartbeats(line.as_bytes())?;
        assert_eq!(
            got[0].calls,
            Some(counts),
            "success a heartbeat carries the call counts the center reads"
        );
        Ok(())
    }

    #[test]
    fn edge_a_heartbeat_of_a_member_that_pushes_no_calls_has_no_calls_field()
    -> Result<(), TestError> {
        let at = DateTime::parse_from_rfc3339("2026-11-07T12:00:00Z")?.with_timezone(&Utc);
        let line = heartbeat_line("s-1", 7, at, 30, &serde_json::json!({}));
        assert!(!line.contains("calls"), "{line}");
        Ok(())
    }

    /// A key file's text for the key whose every byte is 7.
    fn key_text() -> String {
        MasterKey::from_bytes([7; 32]).encode().to_string()
    }

    #[test]
    fn success_a_private_spool_key_file_is_read() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "spool.key", &key_text(), 0o600)?;
        assert_eq!(
            read_spool_key(&path)?.id(),
            spool_keys().current().id(),
            "success a private spool key file is read"
        );
        Ok(())
    }

    #[test]
    fn failure_a_spool_key_file_others_can_read_is_refused() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "spool.key", &key_text(), 0o640)?;
        let e = read_spool_key(&path).err().unwrap_or_default();
        assert!(e.starts_with("[fleet] spool_key_file '"), "{e}");
        assert!(
            e.ends_with("can be read or written by other users (mode 0640); chmod 600 it"),
            "{e}"
        );
        Ok(())
    }

    #[test]
    fn failure_a_spool_key_file_that_is_not_a_key_is_refused_without_its_contents()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = private(dir.path(), "spool.key", "hunter2-not-a-key", 0o600)?;
        let e = read_spool_key(&path).err().unwrap_or_default();
        assert!(e.contains("is not a key"), "{e}");
        assert!(!e.contains("hunter2"), "the contents are not shown: {e}");
        Ok(())
    }

    #[test]
    fn failure_a_missing_spool_key_file_names_the_key_and_the_fix() {
        let e = read_spool_key(Path::new("/nonexistent/example/spool.key"))
            .err()
            .unwrap_or_default();
        assert!(
            e.starts_with("[fleet] spool_key_file '/nonexistent/example/spool.key'"),
            "{e}"
        );
        assert!(
            e.ends_with("create a key with `sipnab fleet keygen --out FILE`"),
            "{e}"
        );
    }

    #[test]
    fn edge_more_calls_than_one_delivery_holds_make_files_named_by_their_first_positions()
    -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let n = crate::app::fleet_calls::MAX_DELIVERY_RECORDS + 1;
        assert_eq!(
            spool_n(dir.path(), n)?,
            (n as u64, 0),
            "every call is written"
        );
        assert_eq!(
            waiting(dir.path())?,
            vec!["00000000000000000001.sealed", "00000000000000000501.sealed"],
            "the second delivery starts where the first ended"
        );
        let last = std::fs::read(dir.path().join("00000000000000000501.sealed"))?;
        let body =
            crate::app::fleet_calls::open_batch(&last, &spool_keys()).map_err(|e| e.to_string())?;
        let records = crate::app::fleet_center::parse_batch(&body)?;
        let seqs: Vec<u64> = records
            .iter()
            .filter_map(|r| r.call().map(|c| c.seq))
            .collect();
        assert_eq!(
            seqs,
            vec![501],
            "and holds the one record past the first 500"
        );
        Ok(())
    }
}
