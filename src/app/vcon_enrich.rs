// SPDX-License-Identifier: MIT OR Apache-2.0

//! Post-call enrichment: `[[vcon.enrich]]`.
//!
//! Before a rule's container is written, each enrichment service the rule is
//! named in is sent the call's container (without sipnab's own analysis) and
//! its audio, and answers with core-04 Analysis Objects, which are appended.
//! The service is the operator's: a URL or a program they name. sipnab chooses
//! no model and bundles none.
//!
//! A service that fails, times out or answers with something that is not an
//! analysis never loses the call. The container is written without that
//! service's analysis, and its `sipnab-enrichment` attachment records every
//! service's outcome: which service, where the request went, what was sent
//! (so a reader knows the audio left the host, and to whom), and how it ended.
//!
//! # The request
//!
//! One JSON document, POSTed to a URL or written to a program's stdin:
//!
//! ```json
//! {"schema": "sipnab-enrichment-request/1", "service": "stt",
//!  "vcon": { ...the container, analysis holding only earlier services' answers... },
//!  "audio": [{"dialog": 0, "sip_call_id": "...", "mediatype": "audio/wav",
//!             "encoding": "base64url", "body": "..."}]}
//! ```
//!
//! `vcon` is present when the service is sent signaling, `audio` when it is
//! sent audio and the call has some: one entry per leg, `dialog` naming the
//! leg's signaling Dialog Object.
//!
//! # The answer
//!
//! `{"analysis": [ {"type": "...", "vendor": "...", "body": "...",
//! "encoding": "none" | "json" | "base64url", "product"?, "schema"?,
//! "mediatype"?, "dialog"?} ]}`. A missing `dialog` is the first leg's
//! signaling object. An answer with any entry that is not that shape is
//! refused whole, and recorded as `malformed`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::output::vcon::{Analysis, Attachment, Vcon};

/// What an enrichment service's trust refusals name: the service has no CA
/// setting, so each names its URL key.
const ENRICH_TRUST: crate::tls_files::TrustNames<'static> = crate::tls_files::TrustNames {
    ca: "[[vcon.enrich]] url",
    extra: "[[vcon.enrich]] url",
    issuer: "the service's CA",
};

/// The `purpose` of the attachment recording every service's outcome.
pub const ENRICHMENT_PURPOSE: &str = "sipnab-enrichment";

/// The request's `schema` value.
pub const REQUEST_SCHEMA: &str = "sipnab-enrichment-request/1";

/// How long a service is waited for when `timeout_secs` is not set.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// The longest `timeout_secs` accepted: an hour.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// The most bytes of an answer read. A transcript of a long call is large;
/// anything past this is not an analysis sipnab will carry.
pub const MAX_ANSWER_BYTES: usize = 16 * 1024 * 1024;

/// Where a service is.
#[derive(Debug)]
enum Target {
    /// A URL, POSTed to.
    Url(crate::app::vcon_forward::Endpoint),
    /// A program, run per call.
    Command(PathBuf),
}

/// One `[[vcon.enrich]]`, resolved.
#[derive(Debug)]
pub struct Service {
    /// The service's name.
    pub name: String,
    /// The rules whose calls it enriches.
    pub rules: Vec<String>,
    /// Where it is.
    target: Target,
    /// The URL or program, as the container records it.
    shown: String,
    /// The header that authenticates to a URL service.
    auth: Option<crate::app::vcon_forward::AuthHeader>,
    /// The TLS configuration for an `https://` URL.
    tls: Option<Arc<rustls::ClientConfig>>,
    /// How long the answer is waited for.
    timeout: Duration,
    /// Whether the call's audio is sent.
    send_audio: bool,
    /// Whether the container is sent.
    send_signaling: bool,
}

impl Service {
    /// Whether this service sends a call's audio, which turns retention on.
    #[must_use]
    pub fn sends_audio(&self) -> bool {
        self.send_audio
    }
}

/// Every `[[vcon.enrich]]`, resolved against the run's rule names.
///
/// # Errors
///
/// A message naming the enrichment: an unusable or repeated name, no rules or
/// a rule no `[[vcon.rule]]` defines, both or neither of `url` and `command`,
/// an `http://` URL to anything but a loopback address, a `send` other than
/// `audio` and `signaling`, a `timeout_secs` of 0 or above an hour, or an
/// auth file that does not load.
pub fn services(
    config: &[crate::config::VconEnrichConfig],
    rule_names: &[&str],
) -> Result<Vec<Arc<Service>>, String> {
    let mut out: Vec<Arc<Service>> = Vec::new();
    for entry in config {
        let name = &entry.name;
        let say = |why: String| format!("[[vcon.enrich]] '{name}': {why}");
        if !crate::sip::named_filters::valid_name(name) {
            return Err(format!(
                "[[vcon.enrich]] name '{name}' is not usable: a name is 1 to {} ASCII \
                 letters, digits, '-' or '_', starting with a letter or digit",
                crate::sip::named_filters::MAX_FILTER_NAME_LEN
            ));
        }
        if out.iter().any(|s| &s.name == name) {
            return Err(format!(
                "[[vcon.enrich]] name '{name}' is used by two enrichments; each needs its own"
            ));
        }
        if entry.rules.is_empty() {
            return Err(say(
                "names no rules; list the [[vcon.rule]] names whose calls it enriches".into(),
            ));
        }
        if let Some(missing) = entry
            .rules
            .iter()
            .find(|r| !rule_names.contains(&r.as_str()))
        {
            return Err(say(format!("there is no [[vcon.rule]] named '{missing}'")));
        }
        let (target, shown) = match (&entry.url, &entry.command) {
            (Some(url), None) => {
                let endpoint = crate::app::vcon_forward::Endpoint::parse(url).map_err(say)?;
                if !endpoint.tls && !is_loopback_host(&endpoint.host) {
                    return Err(say(format!(
                        "'{url}' sends call content in the clear to another host; use https:// \
                         (plain http:// is for a service on this host, 127.0.0.1 or ::1)"
                    )));
                }
                (Target::Url(endpoint), url.clone())
            }
            (None, Some(command)) => (
                Target::Command(command.clone()),
                command.display().to_string(),
            ),
            _ => {
                return Err(say("set one of url or command: where the service is".into()));
            }
        };
        let (mut send_audio, mut send_signaling) = (true, true);
        if let Some(send) = &entry.send {
            send_audio = false;
            send_signaling = false;
            for what in send {
                match what.as_str() {
                    "audio" => send_audio = true,
                    "signaling" => send_signaling = true,
                    other => {
                        return Err(say(format!(
                            "send = '{other}'; use 'audio' and 'signaling'"
                        )));
                    }
                }
            }
            if !send_audio && !send_signaling {
                return Err(say(
                    "send is empty; send 'audio', 'signaling' or both".into()
                ));
            }
        }
        let secs = entry.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS);
        if secs == 0 || secs > MAX_TIMEOUT_SECS {
            return Err(say(format!(
                "timeout_secs = {secs}; use 1 to {MAX_TIMEOUT_SECS}"
            )));
        }
        let auth = entry
            .auth_file
            .as_deref()
            .map(|path| {
                crate::app::vcon_forward::AuthHeader::read_file_for(
                    path,
                    "[[vcon.enrich]] auth_file",
                    crate::app::vcon_forward::StoreKind::Generic,
                )
            })
            .transpose()
            .map_err(say)?;
        let tls = match &target {
            Target::Url(endpoint) if endpoint.tls => Some(
                crate::app::vcon_forward::client_config(None, None, &ENRICH_TRUST).map_err(say)?,
            ),
            _ => None,
        };
        out.push(Arc::new(Service {
            name: name.clone(),
            rules: entry.rules.clone(),
            target,
            shown,
            auth,
            tls,
            timeout: Duration::from_secs(secs),
            send_audio,
            send_signaling,
        }));
    }
    Ok(out)
}

/// Whether `host` is a loopback address or `localhost`.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// One leg's audio for the request.
#[derive(Debug, Clone, Copy)]
pub struct LegAudio<'a> {
    /// The leg's signaling Dialog Object in the container.
    pub dialog: usize,
    /// The leg's Call-ID.
    pub sip_call_id: &'a str,
    /// The leg's WAV.
    pub wav: &'a [u8],
}

/// How one service's request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Answered with analysis, which was appended.
    Ok,
    /// Could not be reached, refused, or exited non-zero.
    Failed,
    /// Did not answer within `timeout_secs`.
    Timeout,
    /// Answered with something that is not an analysis list.
    Malformed,
    /// The queue of calls waiting for enrichment was full; nothing was sent.
    QueueFull,
}

impl Outcome {
    /// The name the attachment records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
            Self::Timeout => "timeout",
            Self::Malformed => "malformed",
            Self::QueueFull => "queue-full",
        }
    }
}

/// One service's line in the enrichment attachment.
#[derive(Debug, Clone)]
pub struct Record {
    /// The service.
    pub service: String,
    /// Its URL or program.
    pub target: String,
    /// What was sent: `audio`, `signaling`.
    pub sent: Vec<&'static str>,
    /// How it ended.
    pub outcome: Outcome,
    /// What happened, in words; empty on success.
    pub detail: String,
    /// The indices in `analysis` of what it added.
    pub analysis: Vec<usize>,
}

/// Run `services` in order on `container`, appending each answer's analysis,
/// then append the attachment recording every outcome.
///
/// Returns the records, for the run's report.
pub fn enrich(
    container: &mut Vcon,
    audio: &[LegAudio<'_>],
    services: &[Arc<Service>],
) -> Vec<Record> {
    let own = container.analysis.len();
    let first_leg = audio.first().map_or(0, |a| a.dialog);
    let mut records = Vec::with_capacity(services.len());
    for service in services {
        let mut sent = Vec::new();
        if service.send_audio && !audio.is_empty() {
            sent.push("audio");
        }
        if service.send_signaling {
            sent.push("signaling");
        }
        let request = request_body(container, own, audio, service);
        let (outcome, detail, added) = match ask(service, &request) {
            Err((outcome, detail)) => (outcome, detail, Vec::new()),
            Ok(answer) => match parse_answer(&answer, container.dialog.len(), first_leg) {
                Ok(found) => {
                    let start = container.analysis.len();
                    if found.iter().any(|a| a.kind == WTF_TYPE) {
                        declare(container, WTF_TYPE);
                    }
                    container.analysis.extend(found);
                    (
                        Outcome::Ok,
                        String::new(),
                        (start..container.analysis.len()).collect(),
                    )
                }
                Err(why) => (Outcome::Malformed, why, Vec::new()),
            },
        };
        records.push(Record {
            service: service.name.clone(),
            target: service.shown.clone(),
            sent,
            outcome,
            detail,
            analysis: added,
        });
    }
    attach(container, &records);
    records
}

/// List `extension` in the container's `extensions`, once.
///
/// [Section 4.1.3 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.3):
/// `extensions` "SHOULD contain the list of names of all vCon extensions for
/// any parameters used that are not defined in this core vCon schema
/// document". Never `critical`: every extension an enrichment brings in is
/// Compatible by its own draft.
fn declare(container: &mut Vcon, extension: &'static str) {
    if !container.extensions.contains(&extension) {
        container.extensions.push(extension);
    }
}

/// Append the attachment recording `records`.
pub fn attach(container: &mut Vcon, records: &[Record]) {
    if records.is_empty() {
        return;
    }
    let observer = container.observer_index();
    let start = container
        .dialog
        .first()
        .and_then(|d| d.start.clone())
        .unwrap_or_else(|| container.created_at.clone());
    let services: Vec<serde_json::Value> = records
        .iter()
        .map(|r| {
            serde_json::json!({
                "service": r.service,
                "target": r.target,
                "sent": r.sent,
                "outcome": r.outcome.as_str(),
                "detail": r.detail,
                "analysis": r.analysis,
            })
        })
        .collect();
    container.attachments.push(Attachment {
        purpose: ENRICHMENT_PURPOSE,
        party: observer,
        dialog: 0,
        start,
        mediatype: "application/json",
        encoding: "json",
        body: serde_json::json!({ "services": services }),
    });
}

/// The request for `service`: the container with only the analysis earlier
/// services added (those past index `own`), and the audio.
fn request_body(
    container: &Vcon,
    own: usize,
    audio: &[LegAudio<'_>],
    service: &Service,
) -> Vec<u8> {
    use base64::Engine as _;
    let mut doc = serde_json::json!({
        "schema": REQUEST_SCHEMA,
        "service": service.name,
    });
    if service.send_signaling
        && let Ok(mut vcon) = serde_json::to_value(container)
    {
        if let Some(list) = vcon.get_mut("analysis").and_then(|a| a.as_array_mut()) {
            let earlier: Vec<serde_json::Value> = list.split_off(own.min(list.len()));
            *list = earlier;
        }
        doc["vcon"] = vcon;
    }
    if service.send_audio && !audio.is_empty() {
        doc["audio"] = audio
            .iter()
            .map(|a| {
                serde_json::json!({
                    "dialog": a.dialog,
                    "sip_call_id": a.sip_call_id,
                    "mediatype": "audio/wav",
                    "encoding": "base64url",
                    "body": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(a.wav),
                })
            })
            .collect();
    }
    doc.to_string().into_bytes()
}

/// Send `request` to `service` and return the answer's body.
fn ask(service: &Service, request: &[u8]) -> Result<Vec<u8>, (Outcome, String)> {
    let started = Instant::now();
    let result = match &service.target {
        Target::Url(endpoint) => post(service, endpoint, request),
        Target::Command(path) => run_command(path, request, service.timeout),
    };
    result.map_err(|(outcome, detail)| {
        // A read that waited the whole timeout timed out, whatever the
        // operating system called it.
        if outcome == Outcome::Failed && started.elapsed() >= service.timeout {
            (
                Outcome::Timeout,
                format!("no answer within {} s", service.timeout.as_secs()),
            )
        } else {
            (outcome, detail)
        }
    })
}

/// POST `request` to `endpoint`.
fn post(
    service: &Service,
    endpoint: &crate::app::vcon_forward::Endpoint,
    request: &[u8],
) -> Result<Vec<u8>, (Outcome, String)> {
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sipnab/{}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        endpoint.target,
        endpoint.host_header(),
        env!("CARGO_PKG_VERSION"),
        request.len()
    );
    if let Some(auth) = &service.auth {
        head.push_str(&auth.line());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(request);
    let scrub = |text: String| match &service.auth {
        Some(auth) => auth.scrub(&text),
        None => text,
    };
    crate::app::vcon_forward::exchange(
        endpoint,
        service.timeout,
        service.tls.as_ref(),
        &bytes,
        |reader| {
            let head = crate::app::vcon_forward::read_head(reader, 64 * 1024, "[[vcon.enrich]]")?;
            let status = crate::app::vcon_forward::status_of(&head)?;
            let (body, truncated) =
                crate::app::vcon_forward::read_body(reader, &head, MAX_ANSWER_BYTES);
            if !(200..300).contains(&status) {
                let text = String::from_utf8_lossy(&body);
                let excerpt: String = text.chars().take(200).collect();
                return Err(format!("answered HTTP {status}: {excerpt}"));
            }
            if truncated {
                return Err(format!("answered with more than {MAX_ANSWER_BYTES} bytes"));
            }
            Ok(body)
        },
    )
    .map_err(|e| (Outcome::Failed, scrub(e)))
}

/// Run `path`, write `request` to its stdin, and return its stdout.
fn run_command(
    path: &std::path::Path,
    request: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>, (Outcome, String)> {
    let mut child = std::process::Command::new(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| (Outcome::Failed, format!("could not run: {e}")))?;
    let mut stdin = child.stdin.take();
    let request = request.to_vec();
    let writer = std::thread::spawn(move || {
        if let Some(pipe) = stdin.as_mut() {
            let _ = pipe.write_all(&request);
        }
    });
    let mut stdout = child.stdout.take();
    let reader = std::thread::spawn(move || {
        let mut out = Vec::new();
        if let Some(pipe) = stdout.as_mut() {
            let _ = pipe.take(MAX_ANSWER_BYTES as u64 + 1).read_to_end(&mut out);
        }
        out
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err((
                    Outcome::Timeout,
                    format!("no answer within {} s", timeout.as_secs()),
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err((Outcome::Failed, e.to_string())),
        }
    };
    let _ = writer.join();
    let out = reader.join().unwrap_or_default();
    if !status.success() {
        return Err((Outcome::Failed, format!("exited with {status}")));
    }
    if out.len() > MAX_ANSWER_BYTES {
        return Err((
            Outcome::Failed,
            format!("answered with more than {MAX_ANSWER_BYTES} bytes"),
        ));
    }
    Ok(out)
}

/// How many calls may wait for enrichment on a live capture. A call that
/// finds the queue full is written unenriched at once, saying so, rather
/// than holding its audio without limit.
pub const QUEUE_CAPACITY: usize = 64;

/// One leg's audio, owned, for a call that waits in the queue.
#[derive(Debug, Clone)]
pub struct OwnedLegAudio {
    /// The leg's signaling Dialog Object in the container.
    pub dialog: usize,
    /// The leg's Call-ID.
    pub sip_call_id: String,
    /// The leg's WAV.
    pub wav: Vec<u8>,
}

/// What finishes a queued call: writes the enriched container, given the
/// records of what each service did.
pub type Finish = Box<dyn FnOnce(Vcon, Vec<Record>) + Send>;

/// One call waiting for enrichment on a live capture.
pub struct Job {
    /// The container, built and not yet sealed.
    pub container: Vcon,
    /// Each leg's audio.
    pub audio: Vec<OwnedLegAudio>,
    /// The services, in order.
    pub services: Vec<Arc<Service>>,
    /// Writes the container once it is enriched.
    pub finish: Finish,
}

impl Job {
    /// Enrich the container and hand it to `finish`.
    pub fn run(self) {
        let Self {
            mut container,
            audio,
            services,
            finish,
        } = self;
        let legs: Vec<LegAudio<'_>> = audio
            .iter()
            .map(|a| LegAudio {
                dialog: a.dialog,
                sip_call_id: &a.sip_call_id,
                wav: &a.wav,
            })
            .collect();
        let records = enrich(&mut container, &legs, &services);
        finish(container, records);
    }
}

/// A bounded queue of calls waiting for enrichment, and the one worker that
/// runs them in arrival order, so a slow service holds up enrichment and
/// never the capture.
pub struct Queue {
    /// Where jobs are handed to the worker.
    tx: std::sync::mpsc::SyncSender<Job>,
    /// Jobs submitted and not yet finished, and the signal when it falls.
    pending: Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>,
    /// Jobs submitted and not yet taken by the worker.
    queued: Arc<std::sync::atomic::AtomicUsize>,
}

impl Queue {
    /// Start the worker, with room for `capacity` waiting jobs.
    #[must_use]
    pub fn start(capacity: usize) -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Job>(capacity);
        let pending = Arc::new((std::sync::Mutex::new(0usize), std::sync::Condvar::new()));
        let queued = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (worker_pending, worker_queued) = (Arc::clone(&pending), Arc::clone(&queued));
        std::thread::Builder::new()
            .name("vcon-enrich".into())
            .spawn(move || {
                for job in rx {
                    worker_queued.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    job.run();
                    let (count, signal) = &*worker_pending;
                    if let Ok(mut n) = count.lock() {
                        *n = n.saturating_sub(1);
                        signal.notify_all();
                    }
                }
            })
            .ok();
        Self {
            tx,
            pending,
            queued,
        }
    }

    /// Hand `job` to the worker, or hand it back when the queue is full.
    ///
    /// # Errors
    ///
    /// The job, when there is no room for it.
    pub fn submit(&self, job: Job) -> Result<(), Box<Job>> {
        if let Ok(mut n) = self.pending.0.lock() {
            *n += 1;
        }
        self.queued
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.tx.try_send(job).map_err(|e| {
            self.queued
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            if let Ok(mut n) = self.pending.0.lock() {
                *n = n.saturating_sub(1);
            }
            match e {
                std::sync::mpsc::TrySendError::Full(job)
                | std::sync::mpsc::TrySendError::Disconnected(job) => Box::new(job),
            }
        })
    }

    /// Jobs submitted and not yet taken by the worker.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.queued.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Wait until every submitted job has finished, or `deadline`. `true`
    /// when they all finished.
    #[must_use]
    pub fn drain(&self, deadline: Instant) -> bool {
        let (count, signal) = &*self.pending;
        let Ok(mut n) = count.lock() else {
            return false;
        };
        while *n > 0 {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            match signal.wait_timeout(n, left) {
                Ok((guard, _)) => n = guard,
                Err(_) => return false,
            }
        }
        true
    }
}

/// The run's queue, started on first use.
pub fn queue() -> &'static Queue {
    static QUEUE: std::sync::OnceLock<Queue> = std::sync::OnceLock::new();
    QUEUE.get_or_init(|| Queue::start(QUEUE_CAPACITY))
}

/// The records for a call the queue had no room for: every service
/// `queue-full`, nothing sent.
#[must_use]
pub fn queue_full_records(services: &[Arc<Service>]) -> Vec<Record> {
    services
        .iter()
        .map(|s| Record {
            service: s.name.clone(),
            target: s.shown.clone(),
            sent: Vec::new(),
            outcome: Outcome::QueueFull,
            detail: format!(
                "{QUEUE_CAPACITY} calls were already waiting for enrichment; this one was \
                 written without it"
            ),
            analysis: Vec::new(),
        })
        .collect()
}

/// The Analysis Objects in an answer, each checked.
///
/// # Errors
///
/// What is wrong with the answer, naming the entry.
fn parse_answer(
    body: &[u8],
    dialogs: usize,
    default_dialog: usize,
) -> Result<Vec<Analysis>, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| format!("the answer is not JSON: {e}"))?;
    let list = doc
        .get("analysis")
        .and_then(serde_json::Value::as_array)
        .ok_or("the answer has no analysis list")?;
    let mut out = Vec::with_capacity(list.len());
    for (i, entry) in list.iter().enumerate() {
        let text = |key: &str| entry.get(key).and_then(serde_json::Value::as_str);
        let required = |key: &str| {
            text(key)
                .filter(|v| !v.is_empty())
                .map(|v| std::borrow::Cow::<'static, str>::Owned(v.to_owned()))
                .ok_or(format!("analysis {i} has no {key}"))
        };
        let kind = required("type")?;
        let vendor = required("vendor")?;
        let encoding = required("encoding")?;
        if !matches!(encoding.as_ref(), "none" | "json" | "base64url") {
            return Err(format!(
                "analysis {i} has encoding '{encoding}'; core-04 allows none, json and base64url"
            ));
        }
        let body = answer_body(entry, &encoding).ok_or(match encoding.as_ref() {
            "json" => format!("analysis {i} has no body"),
            _ => format!("analysis {i} has no body string"),
        })?;
        let dialog = match entry.get("dialog") {
            None => default_dialog,
            Some(v) => v
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n < dialogs)
                .ok_or(format!("analysis {i} names no dialog this container holds"))?,
        };
        if kind == WTF_TYPE {
            check_wtf(&encoding, &body).map_err(|why| format!("analysis {i} {why}"))?;
        }
        let optional =
            |key: &str| text(key).map(|v| std::borrow::Cow::<'static, str>::Owned(v.to_owned()));
        out.push(Analysis {
            kind,
            dialog,
            vendor,
            product: optional("product"),
            schema: optional("schema"),
            mediatype: optional("mediatype"),
            encoding,
            body,
        });
    }
    Ok(out)
}

/// The analysis `type`, and the extension name, of a WTF transcription.
///
/// [Section 5.2 of draft-howe-vcon-wtf-extension-02](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-5.2)
/// registers the extension token, and
/// [section 6.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-6.1)
/// says the analysis `type` "MUST be set to \"wtf_transcription\"".
pub const WTF_TYPE: &str = "wtf_transcription";

/// Whether `value` is a JSON number from 0 to 1, the range
/// [section 8.1 of draft-howe-vcon-wtf-extension-02](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-8.1)
/// requires of every confidence score.
fn is_unit(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(serde_json::Value::as_f64)
        .is_some_and(|n| (0.0..=1.0).contains(&n))
}

/// Check a WTF transcription's `encoding` and `body` against what
/// draft-howe-vcon-wtf-extension-02 requires.
///
/// - [Section 6.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-6.1):
///   `encoding` "MUST be set to \"json\"", and the body is a JSON object.
/// - [Section 4.2](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-4.2):
///   "three required sections", `transcript`, `segments` and `metadata`.
/// - [Section 6.2.1](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-6.2.1):
///   the members of each. `transcript` has `text`, `language`, `duration`
///   (at least 0) and `confidence`. Each segment has a unique integer `id`,
///   `start` and `end` with `end` after `start`, `text` and `confidence`;
///   `speaker`, when present, is an integer or a string, and `words` an
///   array of integers. `metadata` has `created_at`, `processed_at`,
///   `provider` and `model`. The draft's own examples in
///   [section 12.2](https://datatracker.ietf.org/doc/html/draft-howe-vcon-wtf-extension-02#section-12.2)
///   omit `metadata.audio` and `metadata.options`, so neither is required.
///
/// # Errors
///
/// What is missing or out of range, naming the section and member.
fn check_wtf(encoding: &str, body: &serde_json::Value) -> Result<(), String> {
    if encoding != "json" {
        return Err(format!(
            "is a {WTF_TYPE} with encoding '{encoding}'; the WTF draft requires json"
        ));
    }
    let body = body
        .as_object()
        .ok_or(format!("is a {WTF_TYPE} whose body is not a JSON object"))?;
    let section = |name: &str| {
        body.get(name).ok_or(format!(
            "is a {WTF_TYPE} without its required {name} section"
        ))
    };
    let transcript = section("transcript")?
        .as_object()
        .ok_or(format!("is a {WTF_TYPE} whose transcript is not an object"))?;
    let segments = section("segments")?
        .as_array()
        .ok_or(format!("is a {WTF_TYPE} whose segments is not an array"))?;
    let metadata = section("metadata")?
        .as_object()
        .ok_or(format!("is a {WTF_TYPE} whose metadata is not an object"))?;
    let bad = |what: String| Err(format!("is a {WTF_TYPE} whose {what}"));
    for key in ["text", "language"] {
        if !transcript
            .get(key)
            .is_some_and(serde_json::Value::is_string)
        {
            return bad(format!("transcript has no {key} string"));
        }
    }
    if !transcript
        .get("duration")
        .and_then(serde_json::Value::as_f64)
        .is_some_and(|d| d >= 0.0)
    {
        return bad("transcript has no duration of 0 or more seconds".into());
    }
    if !is_unit(transcript.get("confidence")) {
        return bad("transcript has no confidence from 0 to 1".into());
    }
    let mut ids = std::collections::HashSet::new();
    for (n, segment) in segments.iter().enumerate() {
        let Some(segment) = segment.as_object() else {
            return bad(format!("segments[{n}] is not an object"));
        };
        match segment.get("id").and_then(serde_json::Value::as_i64) {
            None => return bad(format!("segments[{n}] has no integer id")),
            Some(id) if !ids.insert(id) => {
                return bad(format!("segments[{n}] repeats the id {id}"));
            }
            Some(_) => {}
        }
        let time = |key: &str| segment.get(key).and_then(serde_json::Value::as_f64);
        let (Some(start), Some(end)) = (time("start"), time("end")) else {
            return bad(format!("segments[{n}] has no start and end in seconds"));
        };
        if end <= start {
            return bad(format!(
                "segments[{n}] ends at {end}, not after its start {start}"
            ));
        }
        if !segment
            .get("text")
            .is_some_and(serde_json::Value::is_string)
        {
            return bad(format!("segments[{n}] has no text string"));
        }
        if !is_unit(segment.get("confidence")) {
            return bad(format!("segments[{n}] has no confidence from 0 to 1"));
        }
        if segment
            .get("speaker")
            .is_some_and(|s| !(s.is_i64() || s.is_u64() || s.is_string()))
        {
            return bad(format!(
                "segments[{n}] has a speaker that is neither an integer nor a string"
            ));
        }
        if segment.get("words").is_some_and(|w| {
            !w.as_array()
                .is_some_and(|list| list.iter().all(|i| i.is_u64() || i.is_i64()))
        }) {
            return bad(format!(
                "segments[{n}] has words that are not an array of integers"
            ));
        }
    }
    for key in ["created_at", "processed_at", "provider", "model"] {
        if !metadata.get(key).is_some_and(serde_json::Value::is_string) {
            return bad(format!("metadata has no {key} string"));
        }
    }
    Ok(())
}

/// An analysis entry's body, in the shape its encoding allows.
///
/// [Section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2):
/// "\"json\": The value of the body parameter is a JSON value (object,
/// array, number, string, or one of the literals true, false, or null)", while
/// `base64url` and `none` describe a string value. A `json` body is therefore
/// kept as whatever JSON value it is, a string included, which is how a
/// service written against earlier sipnab releases sends it; the other two
/// must be strings. An absent `body` is `None` for every encoding.
fn answer_body(entry: &serde_json::Value, encoding: &str) -> Option<serde_json::Value> {
    let body = entry.get("body")?;
    match encoding {
        "json" => Some(body.clone()),
        _ => body
            .as_str()
            .map(|text| serde_json::Value::String(text.to_owned())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// An answer holding `entry` alone.
    fn one(entry: &serde_json::Value) -> Vec<u8> {
        serde_json::json!({ "analysis": [entry] })
            .to_string()
            .into_bytes()
    }

    fn transcript() -> serde_json::Value {
        serde_json::json!({"type": "transcript", "vendor": "v", "encoding": "none", "body": "b"})
    }

    /// A well-formed entry is kept with what it said, and a missing `dialog`
    /// is the first leg's signaling object.
    #[test]
    fn a_good_entry_is_kept() -> Result<(), TestError> {
        let mut entry = transcript();
        entry["product"] = "p".into();
        entry["mediatype"] = "text/plain".into();
        let found = parse_answer(&one(&entry), 3, 2)?;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].kind, "transcript");
        assert_eq!(found[0].dialog, 2, "the default dialog");
        assert_eq!(found[0].product.as_deref(), Some("p"));
        assert_eq!(found[0].mediatype.as_deref(), Some("text/plain"));
        assert_eq!(found[0].schema, None);
        entry["dialog"] = 1.into();
        assert_eq!(parse_answer(&one(&entry), 3, 2)?[0].dialog, 1);
        Ok(())
    }

    /// With `encoding: "json"` the body is any JSON value, and it is kept as
    /// that value.
    ///
    /// [Section 2.3.2 of the core draft](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-2.3.2):
    /// "\"json\": The value of the body parameter is a JSON value (object,
    /// array, number, string, or one of the literals true, false, or null)".
    #[test]
    fn a_json_encoded_body_may_be_any_json_value() -> Result<(), TestError> {
        for body in [
            serde_json::json!({"summary": "s"}),
            serde_json::json!([1, 2]),
            serde_json::json!(7),
            serde_json::json!(true),
            serde_json::Value::Null,
            serde_json::json!("{\"summary\":\"s\"}"),
        ] {
            let mut entry = transcript();
            entry["encoding"] = "json".into();
            entry["body"] = body.clone();
            let found = parse_answer(&one(&entry), 3, 0)?;
            assert_eq!(found[0].body, body, "the body is kept as it was sent");
        }
        Ok(())
    }

    /// With `none` or `base64url` the body is a string, as section 2.3.2
    /// defines both, and anything else is refused.
    #[test]
    fn a_text_encoded_body_must_be_a_string() -> Result<(), TestError> {
        for encoding in ["none", "base64url"] {
            let mut entry = transcript();
            entry["encoding"] = encoding.into();
            entry["body"] = serde_json::json!({"summary": "s"});
            match parse_answer(&one(&entry), 3, 0) {
                Ok(_) => return Err(format!("{encoding}: accepted an object body").into()),
                Err(why) => assert!(why.contains("no body string"), "{encoding}: {why}"),
            }
        }
        Ok(())
    }

    /// Every shape that is not an analysis is refused, saying what is wrong.
    #[test]
    fn a_malformed_answer_is_refused_saying_why() -> Result<(), TestError> {
        let with = |key: &str, value: serde_json::Value| {
            let mut e = transcript();
            e[key] = value;
            one(&e)
        };
        let without = |key: &str| {
            let mut e = transcript();
            e.as_object_mut().map(|m| m.remove(key));
            one(&e)
        };
        let cases: [(Vec<u8>, &str); 9] = [
            (b"not json".to_vec(), "not JSON"),
            (b"{}".to_vec(), "no analysis list"),
            (without("type"), "no type"),
            (without("vendor"), "no vendor"),
            (without("encoding"), "no encoding"),
            (with("encoding", "gzip".into()), "core-04 allows"),
            (without("body"), "no body"),
            (with("dialog", 3.into()), "names no dialog"),
            (with("type", "".into()), "no type"),
        ];
        for (answer, needle) in cases {
            match parse_answer(&answer, 3, 0) {
                Ok(_) => {
                    return Err(format!("accepted an answer that should say '{needle}'").into());
                }
                Err(why) => assert!(why.contains(needle), "{needle}: {why}"),
            }
        }
        Ok(())
    }

    /// The WTF transcription of section 12.2 of
    /// draft-howe-vcon-wtf-extension-02, as an answer entry.
    fn wtf() -> serde_json::Value {
        serde_json::json!({
            "type": "wtf_transcription", "vendor": "openai", "encoding": "json",
            "body": {
                "transcript": {"text": "t", "language": "en-US", "duration": 3.5,
                               "confidence": 0.96},
                "segments": [{"id": 0, "start": 0.0, "end": 3.5, "text": "t",
                              "confidence": 0.96, "speaker": 0, "words": [0, 1]}],
                "metadata": {"created_at": "2025-01-02T12:00:00Z",
                             "processed_at": "2025-01-02T12:00:15Z",
                             "provider": "whisper", "model": "whisper-large-v3"}
            }
        })
    }

    /// A WTF transcription with every required section is kept, body and
    /// all, and one with any of them wrong is refused, naming what is wrong.
    #[test]
    fn a_wtf_transcription_is_checked_against_the_draft() -> Result<(), TestError> {
        let found = parse_answer(&one(&wtf()), 1, 0)?;
        assert_eq!(found[0].kind, "wtf_transcription");
        assert_eq!(found[0].body["segments"][0]["end"], 3.5);
        let broken = |path: &[&str], value: Option<serde_json::Value>| {
            let mut entry = wtf();
            let mut at = &mut entry;
            for key in &path[..path.len() - 1] {
                at = match key.parse::<usize>() {
                    Ok(n) => &mut at[n],
                    Err(_) => &mut at[*key],
                };
            }
            let last = path[path.len() - 1];
            match (value, at.as_object_mut()) {
                (Some(v), Some(map)) => {
                    map.insert(last.to_owned(), v);
                }
                (None, Some(map)) => {
                    map.remove(last);
                }
                _ => {}
            }
            one(&entry)
        };
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                one(
                    &serde_json::json!({"type": "wtf_transcription", "vendor": "v",
                                        "encoding": "none", "body": "t"}),
                ),
                "requires json",
            ),
            (broken(&["body"], Some("{}".into())), "not a JSON object"),
            (broken(&["body", "transcript"], None), "transcript section"),
            (broken(&["body", "segments"], None), "segments section"),
            (broken(&["body", "metadata"], None), "metadata section"),
            (
                broken(&["body", "transcript", "language"], None),
                "language",
            ),
            (
                broken(&["body", "transcript", "duration"], Some((-1).into())),
                "duration",
            ),
            (
                broken(&["body", "transcript", "confidence"], Some(96.into())),
                "confidence",
            ),
            (broken(&["body", "segments", "0", "id"], None), "integer id"),
            (
                broken(&["body", "segments", "0", "end"], Some(0.0.into())),
                "not after",
            ),
            (broken(&["body", "segments", "0", "text"], None), "text"),
            (
                broken(&["body", "segments", "0", "confidence"], Some(1.5.into())),
                "confidence",
            ),
            (
                broken(&["body", "segments", "0", "speaker"], Some(true.into())),
                "speaker",
            ),
            (
                broken(&["body", "segments", "0", "words"], Some("w".into())),
                "words",
            ),
            (
                broken(&["body", "metadata", "processed_at"], None),
                "processed_at",
            ),
            (broken(&["body", "metadata", "model"], None), "model"),
        ];
        for (answer, needle) in cases {
            match parse_answer(&answer, 1, 0) {
                Ok(_) => return Err(format!("accepted a WTF that should say '{needle}'").into()),
                Err(why) => assert!(why.contains(needle), "{needle}: {why}"),
            }
        }
        // Two segments with one id.
        let mut entry = wtf();
        let segment = entry["body"]["segments"][0].clone();
        entry["body"]["segments"] = serde_json::json!([segment.clone(), segment]);
        match parse_answer(&one(&entry), 1, 0) {
            Ok(_) => return Err("accepted a repeated segment id".into()),
            Err(why) => assert!(why.contains("repeats the id"), "{why}"),
        }
        Ok(())
    }

    /// A job that changes nothing and tells `done` when it has run, after
    /// waiting for `gate` to open.
    fn job(
        gate: std::sync::mpsc::Receiver<()>,
        done: std::sync::mpsc::Sender<usize>,
        n: usize,
    ) -> Job {
        Job {
            container: Vcon {
                vcon: "0.4.0",
                uuid: String::new(),
                created_at: String::new(),
                updated_at: None,
                subject: String::new(),
                redacted: None,
                amended: None,
                extensions: Vec::new(),
                parties: Vec::new(),
                dialog: Vec::new(),
                attachments: Vec::new(),
                analysis: Vec::new(),
            },
            audio: Vec::new(),
            services: Vec::new(),
            finish: Box::new(move |_, _| {
                let _ = gate.recv();
                let _ = done.send(n);
            }),
        }
    }

    /// One job running and one waiting fill a queue of one: the next is handed
    /// back, so the caller can write it unenriched. Every accepted job runs,
    /// and `drain` returns once they have.
    #[test]
    fn a_full_queue_hands_the_job_back() -> Result<(), TestError> {
        let queue = Queue::start(1);
        let (done_tx, done) = std::sync::mpsc::channel();
        let mut gates = Vec::new();
        let mut submit = |n| {
            let (open, gate) = std::sync::mpsc::channel();
            gates.push(open);
            queue.submit(job(gate, done_tx.clone(), n))
        };
        assert!(submit(1).is_ok(), "the worker takes the first");
        // The worker is holding job 1; wait until it has left the channel.
        let deadline = Instant::now() + Duration::from_secs(5);
        while queue.waiting() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(submit(2).is_ok(), "the channel holds one more");
        assert!(submit(3).is_err(), "a third is handed back");
        for open in &gates {
            let _ = open.send(());
        }
        assert!(
            queue.drain(Instant::now() + Duration::from_secs(5)),
            "drained"
        );
        let mut ran: Vec<usize> = done.try_iter().collect();
        ran.sort_unstable();
        assert_eq!(ran, [1, 2]);
        Ok(())
    }

    /// `http://` is for a service on this host only.
    #[test]
    fn plain_http_is_for_this_host_only() {
        for host in ["127.0.0.1", "::1", "localhost", "LocalHost", "127.9.9.9"] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in ["192.0.2.7", "example.com", "10.0.0.1"] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }
}
