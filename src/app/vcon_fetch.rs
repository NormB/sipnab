// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vCon fetcher: `sipnab --vcon-fetch <UUID>...`.
//!
//! The counterpart of the forwarder ([`crate::app::vcon_forward`]): a
//! separate process that reads containers back from a vCon store by uuid
//! and writes each to `<uuid>.vcon.json`. The capture process still makes no
//! outbound connection; this mode reads no packet.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::app::vcon_forward::{
    AuthHeader, Endpoint, Envelope, MAX_AUTH_FILE, Members, StoreKind, client_config, exchange,
    header_value, is_path_uuid, plaintext_warning, read_body, read_head, request_head, status_of,
};

/// What one fetched container's file is named after its uuid.
pub const OUT_SUFFIX: &str = ".vcon.json";

/// How much of a store's answer the fetcher reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchLimits {
    /// The most bytes of the status line and headers read.
    pub response_head: usize,
    /// The largest body read.
    pub max_size: usize,
}

/// Everything one fetcher needs.
#[derive(Debug, Clone)]
pub struct FetchSettings {
    /// The read URL, its target holding `{uuid}`.
    pub url: Endpoint,
    /// The kind of store.
    pub kind: StoreKind,
    /// The one authentication header.
    pub auth: AuthHeader,
    /// The only CA file trusted for HTTPS; the host's bundle when `None`.
    pub ca: Option<PathBuf>,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// How much of an answer is read.
    pub limits: FetchLimits,
    /// Where each container is written.
    pub out_dir: PathBuf,
    /// Replace a file that exists.
    pub overwrite: bool,
}

/// What became of one uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// Written to this file. `findings`: what the schema check found, empty
    /// for a valid container.
    Saved {
        /// The file written.
        path: PathBuf,
        /// The schema findings, one line each.
        findings: Vec<String>,
    },
    /// The file exists and `--vcon-fetch-overwrite` was not given: not
    /// fetched.
    Exists(PathBuf),
    /// The store holds no container with this uuid (`404`).
    NotFound,
    /// Anything else that left no file, and why.
    Failed(String),
    /// The store refused the credential or the client (`401`, `403`):
    /// nothing more is fetched.
    Halt(String),
}

/// The file that holds the credential, and the setting that named it.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthSource {
    /// The file.
    pub path: PathBuf,
    /// `--vcon-fetch-auth-file` or `[vcon_fetch] auth_file`.
    pub from: &'static str,
    /// Where `from` was given, which sets the exit code when the file is
    /// refused.
    pub origin: crate::settings::Origin,
}

impl std::fmt::Debug for AuthSource {
    /// The file's path alone: a flag and its key that name the same file are
    /// the same credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "File({:?})", self.path)
    }
}

/// Every fetcher setting, resolved from the flags and the `[vcon_fetch]`
/// keys, before any file is read.
#[derive(Debug, Clone)]
pub struct FetchPlan {
    /// The uuids given on the command line, `-` left out.
    pub uuids: Vec<String>,
    /// `-` was given: the uuids on standard input follow these.
    pub from_stdin: bool,
    /// The kind of store.
    pub kind: StoreKind,
    /// The read URL, its target holding `{uuid}`.
    pub url: Endpoint,
    /// The file holding the credential.
    pub auth: AuthSource,
    /// The only CA file trusted for HTTPS.
    pub ca: Option<PathBuf>,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// How much of an answer is read.
    pub limits: FetchLimits,
    /// Where each container is written.
    pub out_dir: PathBuf,
    /// Replace a file that exists.
    pub overwrite: bool,
}

/// The flag that names the uuids, quoted in their refusals.
const MODE_FLAG: &str = "--vcon-fetch";

/// The flag that names the auth file, quoted in its errors.
const AUTH_FLAG: &str = "--vcon-fetch-auth-file";

/// The key that names the auth file, quoted in its errors.
const AUTH_KEY: &str = "[vcon_fetch] auth_file";

/// The value of `--vcon-fetch` that asks for the uuids on standard input.
const STDIN: &str = "-";

/// The value in force of a text setting, and the name of where it came from:
/// the flag, else the key.
fn pick_text<'a>(
    flag: Option<&'a str>,
    flag_name: &'static str,
    key: Option<&'a str>,
    key_name: &'static str,
) -> Option<(&'a str, &'static str)> {
    flag.map(|v| (v, flag_name))
        .or_else(|| key.map(|v| (v, key_name)))
}

/// A whole-number setting's value in force, checked by its one rule.
fn pick_number(
    number: crate::config::ForwardNumber,
    flag: Option<u64>,
    key: Option<u64>,
) -> Result<u64, String> {
    let (value, from) = number.pick(flag, key);
    number.check(value).map_err(|e| format!("{from}: {e}"))
}

impl FetchPlan {
    /// Resolve every setting: the flag, else the `[vcon_fetch]` key, else
    /// the store kind's value, else the declared default. Reads no file.
    ///
    /// # Errors
    ///
    /// No URL or no credential from any source; a uuid a URL path may not
    /// carry; a URL or number its flag's rule refuses; an unknown kind. Each
    /// message names the flag or key the value came from.
    pub fn resolve(
        args: &crate::cli::VconFetchArgs,
        keys: &crate::config::VconFetchConfig,
    ) -> Result<Self, String> {
        Self::resolve_refusal(args, keys).map_err(|(_, m)| m)
    }

    /// [`Self::resolve`], with where a refused value came from: the URL can
    /// be refused from the config file alone (exit 1); a `[vcon_fetch]`
    /// number or kind was refused when the file loaded, and every other
    /// refusal involves a flag (exit 2).
    ///
    /// # Errors
    ///
    /// As [`Self::resolve`], each message with its
    /// [`crate::settings::Origin`].
    pub fn resolve_refusal(
        args: &crate::cli::VconFetchArgs,
        keys: &crate::config::VconFetchConfig,
    ) -> Result<Self, (crate::settings::Origin, String)> {
        use crate::config::{FETCH_MAX_RESPONSE_HEAD, FETCH_MAX_SIZE, FETCH_TIMEOUT};
        use crate::settings::Origin;
        let flag = |message: String| (Origin::CommandLine, message);
        let mut uuids: Vec<String> = Vec::new();
        let mut from_stdin = false;
        for value in &args.vcon_fetch {
            if value == STDIN {
                from_stdin = true;
            } else if !is_path_uuid(value) {
                return Err(flag(format!(
                    "{MODE_FLAG}: {value:?} is not a uuid (1 to 64 characters, each a letter, \
                     a digit or '-')"
                )));
            } else if !uuids.contains(value) {
                uuids.push(value.clone());
            }
        }
        let kind = match pick_text(
            args.vcon_fetch_kind.as_deref(),
            "--vcon-fetch-kind",
            keys.kind.as_deref(),
            "[vcon_fetch] kind",
        ) {
            Some((name, from)) => StoreKind::from_name(name)
                .ok_or_else(|| flag(format!("{from}: {name:?} is not a store kind")))?,
            None => StoreKind::Generic,
        };
        let (url_text, url_from) = pick_text(
            args.vcon_fetch_url.as_deref(),
            "--vcon-fetch-url",
            keys.url.as_deref(),
            "[vcon_fetch] url",
        )
        .ok_or_else(|| {
            flag(
                "--vcon-fetch needs the store's URL: give --vcon-fetch-url, or \
                 [vcon_fetch] url in the config file"
                    .to_string(),
            )
        })?;
        let url_origin = Origin::of(args.vcon_fetch_url.is_some());
        let url = Endpoint::parse(url_text)
            .and_then(|url| read_url(&url, kind))
            .map_err(|e| (url_origin, format!("{url_from} {e}")))?;
        let auth = match (&args.vcon_fetch_auth_file, &keys.auth_file) {
            (Some(path), _) => AuthSource {
                path: path.clone(),
                from: AUTH_FLAG,
                origin: Origin::CommandLine,
            },
            (None, Some(path)) => AuthSource {
                path: path.clone(),
                from: AUTH_KEY,
                origin: Origin::ConfigFile,
            },
            (None, None) => {
                return Err(flag(format!(
                    "--vcon-fetch needs a credential: give {AUTH_FLAG}, or {AUTH_KEY} in the \
                     config file"
                )));
            }
        };
        let timeout =
            pick_number(FETCH_TIMEOUT, args.vcon_fetch_timeout, keys.timeout).map_err(flag)?;
        let head = pick_number(
            FETCH_MAX_RESPONSE_HEAD,
            args.vcon_fetch_max_response_head,
            keys.max_response_head,
        )
        .map_err(flag)?;
        let size =
            pick_number(FETCH_MAX_SIZE, args.vcon_fetch_max_size, keys.max_size).map_err(flag)?;
        Ok(Self {
            uuids,
            from_stdin,
            kind,
            url,
            auth,
            ca: args.vcon_fetch_ca.clone().or_else(|| keys.ca.clone()),
            timeout: Duration::from_secs(timeout),
            limits: FetchLimits {
                response_head: usize::try_from(head).unwrap_or(usize::MAX),
                max_size: usize::try_from(size).unwrap_or(usize::MAX),
            },
            out_dir: args
                .vcon_fetch_out
                .clone()
                .unwrap_or_else(|| PathBuf::from(".")),
            overwrite: args.vcon_fetch_overwrite,
        })
    }

    /// Every uuid to fetch: the ones on the command line, then, when `-` was
    /// given, the ones in `listed` (standard input's text), each once.
    ///
    /// # Errors
    ///
    /// `-` was given and `listed` is not a uuid list
    /// ([`uuids_from_text`]).
    pub fn all_uuids(&self, listed: Option<&str>) -> Result<Vec<String>, String> {
        let mut uuids = self.uuids.clone();
        if !self.from_stdin {
            return Ok(uuids);
        }
        let text = listed.unwrap_or_default();
        for uuid in uuids_from_text(text).map_err(|e| format!("{MODE_FLAG} -: {e}"))? {
            if !uuids.contains(&uuid) {
                uuids.push(uuid);
            }
        }
        Ok(uuids)
    }

    /// The settings to run with, the credential read.
    ///
    /// # Errors
    ///
    /// The credential's file is refused or holds no credential, with the
    /// [`crate::settings::Origin`] of the setting that named it.
    pub fn into_settings(self) -> Result<FetchSettings, (crate::settings::Origin, String)> {
        let auth = AuthHeader::read_file_for(&self.auth.path, self.auth.from, self.kind)
            .map_err(|e| (self.auth.origin, e))?;
        Ok(FetchSettings {
            url: self.url,
            kind: self.kind,
            auth,
            ca: self.ca,
            timeout: self.timeout,
            limits: self.limits,
            out_dir: self.out_dir,
            overwrite: self.overwrite,
        })
    }
}

/// The read URL for `url` and a store of `kind`: its target holds `{uuid}`.
///
/// A URL whose target holds `{uuid}` is used as written. Otherwise the
/// kind's read path ([`crate::app::vcon_forward::KindFacts::read_path`])
/// follows the URL's own path, so a store served under a prefix
/// (`https://host/api`) is read at `https://host/api/vcon/{uuid}`.
///
/// # Errors
///
/// No `{uuid}` and a kind with no read path (`generic`), or a base URL with
/// a query, which a path cannot follow.
pub fn read_url(url: &Endpoint, kind: StoreKind) -> Result<Endpoint, String> {
    if url.target.contains("{uuid}") {
        return Ok(url.clone());
    }
    let Some(path) = kind.facts().read_path else {
        return Err(format!(
            "'{url}': the {} kind reads at a URL template; write {{uuid}} where the uuid goes",
            kind.facts().name
        ));
    };
    if url.target.contains('?') {
        return Err(format!(
            "'{url}': a base URL with a query cannot take the read path; give a template \
             holding {{uuid}}"
        ));
    }
    let mut read = url.clone();
    read.target = format!("{}{path}", url.target.trim_end_matches('/'));
    Ok(read)
}

/// The container inside the answer a store of `kind` gave: the answer
/// itself for a bare kind, without the added member for vcon.store, the
/// wrapped member for vcon-mcp ([`Envelope`]). Every byte of the container
/// is kept as the store sent it, and its members' order.
///
/// # Errors
///
/// The answer is not a JSON object, or, for a wrapping kind, holds no
/// object in the wrapping member.
pub fn unwrap_container(kind: StoreKind, body: &[u8]) -> Result<Vec<u8>, String> {
    let Members(members) = serde_json::from_slice(body).map_err(|e| {
        if e.is_data() {
            "the answer is not a JSON object".to_string()
        } else {
            format!("the answer is not JSON: {e}")
        }
    })?;
    match kind.facts().envelope {
        Envelope::Bare => Ok(body.to_vec()),
        Envelope::AddedMember(name) => {
            if members.iter().all(|(n, _)| n != name) {
                return Ok(body.to_vec());
            }
            let mut out = String::from("{");
            for (member, value) in members.iter().filter(|(n, _)| n != name) {
                if out.len() > 1 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(member).map_err(|e| e.to_string())?);
                out.push(':');
                out.push_str(value.get());
            }
            out.push('}');
            Ok(out.into_bytes())
        }
        Envelope::Wrapped(name) => members
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.get())
            .filter(|v| v.starts_with('{'))
            .map(|v| v.as_bytes().to_vec())
            .ok_or_else(|| {
                format!(
                    "the answer holds no `{name}` object; a {} store answers \
                     {{\"success\": true, \"{name}\": {{...}}}}",
                    kind.facts().name
                )
            }),
    }
}

/// The uuids in `text`, one per line: spaces around each, blank lines and
/// lines starting with `#` passed over, a uuid listed twice kept once.
///
/// # Errors
///
/// A line that is not a uuid, named by its number, or no uuid at all.
pub fn uuids_from_text(text: &str) -> Result<Vec<String>, String> {
    let mut uuids: Vec<String> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !is_path_uuid(line) {
            return Err(format!(
                "line {}: {line:?} is not a uuid (1 to 64 characters, each a letter, a digit \
                 or '-')",
                n + 1
            ));
        }
        if !uuids.iter().any(|u| u == line) {
            uuids.push(line.to_string());
        }
    }
    if uuids.is_empty() {
        return Err("no uuid; give one per line".into());
    }
    Ok(uuids)
}

/// The most of a refusal's body a message quotes, in bytes.
///
/// Not a setting: the quote goes into one log line, and its only purpose is
/// to make the answer recognizable there. Nothing is kept from a refusal.
const MAX_QUOTED_BODY: usize = 200;

/// The fetcher: settings, and the HTTPS configuration.
#[derive(Debug)]
pub struct Fetcher {
    /// What it was started with.
    settings: FetchSettings,
    /// The TLS client configuration, when the URL is `https://`.
    tls: Option<Arc<rustls::ClientConfig>>,
}

impl Fetcher {
    /// Check the settings, load the CA when the URL is `https://`, and
    /// create the output directory, mode 0700, when it does not exist.
    ///
    /// # Errors
    ///
    /// The URL holds no `{uuid}`, HTTPS is needed and no CA loads, or the
    /// output directory is not one or cannot be created.
    pub fn new(settings: FetchSettings) -> Result<Self, String> {
        if !settings.url.target.contains("{uuid}") {
            return Err(format!(
                "'{}': the read URL holds no {{uuid}}",
                settings.url
            ));
        }
        let tls = if settings.url.tls {
            Some(client_config(settings.ca.as_deref(), "--vcon-fetch-ca")?)
        } else {
            None
        };
        prepare_out_dir(&settings.out_dir)?;
        Ok(Self { settings, tls })
    }

    /// The file `uuid`'s container is written to.
    #[must_use]
    pub fn path_for(&self, uuid: &str) -> PathBuf {
        self.settings.out_dir.join(format!("{uuid}{OUT_SUFFIX}"))
    }

    /// Fetch the container with `uuid` and write it to its file.
    ///
    /// Nothing is written unless the store answered `2xx` with a JSON object
    /// whose `uuid` is the one asked for, within the size limit. A container
    /// the schema refuses is written all the same, as the store holds it,
    /// with the findings returned: it is the store's record, and the person
    /// who asked for it needs it to see what is wrong.
    #[must_use]
    pub fn fetch_one(&self, uuid: &str) -> Fetched {
        if !is_path_uuid(uuid) {
            return Fetched::Failed(format!("{uuid:?} is not a uuid"));
        }
        let path = self.path_for(uuid);
        if !self.settings.overwrite && std::fs::symlink_metadata(&path).is_ok() {
            return Fetched::Exists(path);
        }
        let mut url = self.settings.url.clone();
        url.target = url.target.replace("{uuid}", uuid);
        let request = request_head(&url, "GET", &self.settings.auth, None);
        let limits = self.settings.limits;
        let answer = match exchange(
            &url,
            self.settings.timeout,
            self.tls.as_ref(),
            &request,
            |r| read_answer(r, limits),
        ) {
            Ok(answer) => answer,
            Err(e) => return Fetched::Failed(format!("{url}: {e}")),
        };
        let quoted = || {
            let text = String::from_utf8_lossy(&answer.body);
            let text = self.settings.auth.scrub(&text);
            let mut end = text.len().min(MAX_QUOTED_BODY);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text[..end].trim().to_string()
        };
        match answer.status {
            401 | 403 => {
                return Fetched::Halt(format!(
                    "{url} answered {}: the store refused the credential or this client \
                     ({}); nothing more is fetched",
                    answer.status,
                    quoted()
                ));
            }
            404 => return Fetched::NotFound,
            200..=299 => {}
            status => {
                return Fetched::Failed(format!("{url} answered {status} ({})", quoted()));
            }
        }
        if answer.oversized {
            return Fetched::Failed(format!(
                "the answer is larger than {} bytes (--vcon-fetch-max-size); nothing was written",
                limits.max_size
            ));
        }
        if let Some(problem) = &answer.short {
            return Fetched::Failed(format!("{url}: {problem}; nothing was written"));
        }
        let container = match unwrap_container(self.settings.kind, &answer.body) {
            Ok(c) => c,
            Err(e) => return Fetched::Failed(format!("{url}: {e}; nothing was written")),
        };
        let doc: serde_json::Value = match serde_json::from_slice(&container) {
            Ok(doc) => doc,
            Err(e) => return Fetched::Failed(format!("{url}: the container is not JSON: {e}")),
        };
        let held = doc.get("uuid").and_then(serde_json::Value::as_str);
        if !held.is_some_and(|h| h.eq_ignore_ascii_case(uuid)) {
            return Fetched::Failed(format!(
                "{url}: the container's uuid is {}, not the one asked for; nothing was written",
                held.map_or_else(|| "missing".to_string(), |h| format!("{h:?}"))
            ));
        }
        let report = crate::output::vcon_schema::validate(&doc);
        let findings: Vec<String> = report
            .errors
            .iter()
            .map(|f| format!("{} ({}): {}", f.instance_path, f.keyword, f.detail))
            .collect();
        if let Err(e) = write_private(&path, &container, self.settings.overwrite) {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                return Fetched::Exists(path);
            }
            return Fetched::Failed(format!("{}: {e}", path.display()));
        }
        Fetched::Saved { path, findings }
    }
}

/// One answer to a GET: the status, and the body of a `2xx` or the start of
/// any other's.
struct Answer {
    /// The status code.
    status: u16,
    /// The body, at most the size limit.
    body: Vec<u8>,
    /// The body was larger than the size limit.
    oversized: bool,
    /// The body ended before its declared length, and how.
    short: Option<String>,
}

/// Read the answer: the head, at most `limits.response_head` bytes; for a
/// `2xx`, the body, at most `limits.max_size` bytes; for any other, the start
/// of the body, for the message.
fn read_answer(reader: &mut dyn BufRead, limits: FetchLimits) -> Result<Answer, String> {
    loop {
        let head = read_head(
            reader,
            limits.response_head,
            "--vcon-fetch-max-response-head",
        )?;
        let status = status_of(&head)?;
        if (100..200).contains(&status) {
            continue;
        }
        if !(200..300).contains(&status) {
            let (body, _) = read_body(reader, &head, MAX_QUOTED_BODY.saturating_add(MAX_AUTH_FILE));
            return Ok(Answer {
                status,
                body,
                oversized: false,
                short: None,
            });
        }
        let declared = header_value(&head, "content-length").and_then(|v| v.parse::<u64>().ok());
        let chunked = header_value(&head, "transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if !chunked && declared.is_some_and(|n| n > limits.max_size as u64) {
            return Ok(Answer {
                status,
                body: Vec::new(),
                oversized: true,
                short: None,
            });
        }
        let (body, more) = read_body(reader, &head, limits.max_size);
        let short = match declared {
            Some(n) if !chunked && (body.len() as u64) < n => Some(format!(
                "the answer ended after {} of its {n} bytes",
                body.len()
            )),
            _ => None,
        };
        return Ok(Answer {
            status,
            body,
            oversized: more,
            short,
        });
    }
}

/// Write `bytes` to `path`, mode 0600, by staging a dot-prefixed sibling
/// and moving it into place, so a reader never sees half a container.
///
/// Without `overwrite` the move is a hard link, which fails when `path`
/// exists, whatever is there; with it, a rename, which replaces a symbolic
/// link rather than following it. Neither writes through a link.
fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path
        .file_name()
        .map_or_else(|| "vcon".into(), |n| n.to_string_lossy().into_owned());
    let staged = path.with_file_name(format!(".{name}.partial"));
    let _ = std::fs::remove_file(&staged);
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staged)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| {
            if overwrite {
                std::fs::rename(&staged, path)
            } else {
                std::fs::hard_link(&staged, path)
            }
        });
    let _ = std::fs::remove_file(&staged);
    result
}

/// Create `dir`, mode 0700, when it does not exist.
fn prepare_out_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(format!(
            "--vcon-fetch-out '{}': not a directory",
            dir.display()
        )),
        Err(_) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("--vcon-fetch-out '{}': {e}", dir.display())),
    }
}

/// The exit code for what became of each uuid: 3 when the store refused
/// the credential, else 0 when every container was written and valid, else
/// 1.
///
/// These are the forwarder's codes: 0 all done, 1 any not done, 2 settings
/// refused (which [`run`] returns before any fetch), 3 credential refused.
#[must_use]
pub fn exit_code(outcomes: &[Fetched]) -> i32 {
    if outcomes.iter().any(|o| matches!(o, Fetched::Halt(_))) {
        return 3;
    }
    let clean = outcomes
        .iter()
        .all(|o| matches!(o, Fetched::Saved { findings, .. } if findings.is_empty()));
    i32::from(!clean)
}

/// What to log for `uuid`'s outcome, and at which level: info for a clean
/// write, a warning for a container the schema refuses, an error for
/// anything not written.
#[must_use]
pub fn describe(uuid: &str, outcome: &Fetched) -> (tracing::Level, String) {
    match outcome {
        Fetched::Saved { path, findings } if findings.is_empty() => (
            tracing::Level::INFO,
            format!("{uuid}: written to {}", path.display()),
        ),
        Fetched::Saved { path, findings } => (
            tracing::Level::WARN,
            format!(
                "{uuid}: written to {}, but the schema refuses it ({} finding(s)): {}",
                path.display(),
                findings.len(),
                findings.join("; ")
            ),
        ),
        Fetched::Exists(path) => (
            tracing::Level::ERROR,
            format!(
                "{uuid}: {} exists; not fetched. --vcon-fetch-overwrite replaces it",
                path.display()
            ),
        ),
        Fetched::NotFound => (
            tracing::Level::ERROR,
            format!("{uuid}: the store holds no such vCon (404)"),
        ),
        Fetched::Failed(why) | Fetched::Halt(why) => {
            (tracing::Level::ERROR, format!("{uuid}: {why}"))
        }
    }
}

/// Log one line at `level`.
fn log_at(level: tracing::Level, line: &str) {
    if level == tracing::Level::INFO {
        tracing::info!("{line}");
    } else if level == tracing::Level::WARN {
        tracing::warn!("{line}");
    } else {
        tracing::error!("{line}");
    }
}

/// The settings and the uuids for a `--vcon-fetch` run, from the flags, the
/// `[vcon_fetch]` keys and, when `-` was given, `stdin`'s text. `stdin` is
/// called only then.
///
/// # Errors
///
/// The exit code and the message: a refused setting by its
/// [`crate::settings::Origin`] (2 for a flag, 1 for a key), 2 for standard
/// input that cannot be read or is not a uuid list.
pub fn prepare(
    args: &crate::cli::VconFetchArgs,
    keys: &crate::config::VconFetchConfig,
    stdin: impl FnOnce() -> std::io::Result<String>,
) -> Result<(FetchSettings, Vec<String>), (i32, String)> {
    let plan = FetchPlan::resolve_refusal(args, keys).map_err(|(o, m)| (o.exit_code(), m))?;
    let listed = if plan.from_stdin {
        Some(stdin().map_err(|e| (2, format!("{MODE_FLAG} -: standard input: {e}")))?)
    } else {
        None
    };
    let uuids = plan.all_uuids(listed.as_deref()).map_err(|e| (2, e))?;
    let settings = plan.into_settings().map_err(|(o, m)| (o.exit_code(), m))?;
    Ok((settings, uuids))
}

/// Run the fetcher over `uuids`, in order, logging what became of each.
///
/// # Returns
///
/// The exit code: 2 when the settings are refused (the output directory
/// cannot be made, or no CA loads); otherwise as [`exit_code`]. A `401` or
/// `403` stops the run at that uuid.
///
/// # Side effects
///
/// Creates the output directory, connects to the store, and writes one file
/// per container.
pub fn run(settings: FetchSettings, uuids: &[String]) -> i32 {
    if let Some(warning) = plaintext_warning(&settings.url) {
        tracing::warn!("{warning}");
    }
    let fetcher = match Fetcher::new(settings) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!("{e}");
            return 2;
        }
    };
    let mut outcomes = Vec::new();
    for uuid in uuids {
        let outcome = fetcher.fetch_one(uuid);
        let (level, line) = describe(uuid, &outcome);
        log_at(level, &line);
        let halt = matches!(outcome, Fetched::Halt(_));
        outcomes.push(outcome);
        if halt {
            break;
        }
    }
    exit_code(&outcomes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// The fetcher flags after `--vcon-fetch <uuid>`, parsed.
    fn flags(extra: &[&str]) -> Result<crate::cli::VconFetchArgs, Box<dyn std::error::Error>> {
        use clap::Parser as _;
        let mut argv = vec![
            "sipnab",
            "--vcon-fetch",
            "018bcfe5-6800-8a6b-a667-78f1c5213800",
        ];
        argv.extend_from_slice(extra);
        Ok(crate::cli::Cli::try_parse_from(argv)?.vcon_fetch_args)
    }

    /// A `[vcon_fetch]` section holding `body`.
    fn keys(body: &str) -> Result<crate::config::VconFetchConfig, Box<dyn std::error::Error>> {
        let config: crate::config::Config = toml::from_str(&format!("[vcon_fetch]\n{body}\n"))?;
        Ok(config.vcon_fetch)
    }

    /// Every `[vcon_fetch]` key, each with a value no default has.
    const ALL_KEYS: &str = "kind = \"conserver\"\n\
        url = \"https://keys.example.com/base\"\n\
        auth_file = \"/etc/keys/auth\"\nca = \"/etc/keys/ca.pem\"\n\
        timeout = 12\nmax_response_head = 15000\nmax_size = 16000";

    /// Each `[vcon_fetch]` key supplies its setting when its flag is not
    /// given.
    #[test]
    fn every_key_supplies_its_setting() -> TestResult {
        let plan = FetchPlan::resolve(&flags(&[])?, &keys(ALL_KEYS)?)?;
        assert_eq!(plan.kind, StoreKind::Conserver);
        assert_eq!(
            plan.url.to_string(),
            "https://keys.example.com/base/vcon/{uuid}"
        );
        assert_eq!(plan.auth.path, Path::new("/etc/keys/auth"));
        assert_eq!(plan.auth.from, "[vcon_fetch] auth_file");
        assert_eq!(plan.auth.origin, crate::settings::Origin::ConfigFile);
        assert_eq!(plan.ca.as_deref(), Some(Path::new("/etc/keys/ca.pem")));
        assert_eq!(plan.timeout, Duration::from_secs(12));
        assert_eq!(
            plan.limits,
            FetchLimits {
                response_head: 15000,
                max_size: 16000
            }
        );
        Ok(())
    }

    /// Each flag overrides its `[vcon_fetch]` key.
    #[test]
    fn every_flag_overrides_its_key() -> TestResult {
        let args = flags(&[
            "--vcon-fetch-kind=vcon-mcp",
            "--vcon-fetch-url=https://flags.example.com",
            "--vcon-fetch-auth-file=/etc/flags/auth",
            "--vcon-fetch-ca=/etc/flags/ca.pem",
            "--vcon-fetch-timeout=22",
            "--vcon-fetch-max-response-head=25000",
            "--vcon-fetch-max-size=26000",
            "--vcon-fetch-out=/srv/flags-out",
            "--vcon-fetch-overwrite",
        ])?;
        let plan = FetchPlan::resolve(&args, &keys(ALL_KEYS)?)?;
        assert_eq!(plan.kind, StoreKind::VconMcp);
        assert_eq!(
            plan.url.to_string(),
            "https://flags.example.com/api/v1/vcons/{uuid}"
        );
        assert_eq!(plan.auth.path, Path::new("/etc/flags/auth"));
        assert_eq!(plan.auth.from, "--vcon-fetch-auth-file");
        assert_eq!(plan.auth.origin, crate::settings::Origin::CommandLine);
        assert_eq!(plan.ca.as_deref(), Some(Path::new("/etc/flags/ca.pem")));
        assert_eq!(plan.timeout, Duration::from_secs(22));
        assert_eq!(
            plan.limits,
            FetchLimits {
                response_head: 25000,
                max_size: 26000
            }
        );
        assert_eq!(plan.out_dir, Path::new("/srv/flags-out"));
        assert!(plan.overwrite);
        Ok(())
    }

    /// With neither a flag nor a key, each setting takes its declared
    /// default.
    #[test]
    fn without_a_flag_or_key_each_setting_has_its_default() -> TestResult {
        use crate::config::{FETCH_MAX_RESPONSE_HEAD, FETCH_MAX_SIZE, FETCH_TIMEOUT};
        let args = flags(&[
            "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}",
            "--vcon-fetch-auth-file=/etc/a",
        ])?;
        let plan = FetchPlan::resolve(&args, &keys("")?)?;
        assert_eq!(plan.kind, StoreKind::Generic);
        assert_eq!(plan.ca, None);
        assert_eq!(plan.timeout, Duration::from_secs(FETCH_TIMEOUT.default));
        assert_eq!(
            (
                plan.limits.response_head as u64,
                plan.limits.max_size as u64
            ),
            (FETCH_MAX_RESPONSE_HEAD.default, FETCH_MAX_SIZE.default)
        );
        assert_eq!(plan.out_dir, Path::new("."));
        assert!(!plan.overwrite);
        assert_eq!(plan.uuids, ["018bcfe5-6800-8a6b-a667-78f1c5213800"]);
        assert!(!plan.from_stdin);
        Ok(())
    }

    /// No URL and no credential from any source are refused naming both
    /// sources; a uuid a URL path may not carry is refused quoting it.
    #[test]
    fn the_url_the_credential_and_each_uuid_are_required() -> TestResult {
        let no_url = FetchPlan::resolve(&flags(&["--vcon-fetch-auth-file=/a"])?, &keys("")?);
        let e = no_url.err().ok_or("no URL was accepted")?;
        assert!(
            e.contains("--vcon-fetch-url") && e.contains("[vcon_fetch] url"),
            "{e}"
        );
        let no_auth = FetchPlan::resolve(
            &flags(&["--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}"])?,
            &keys("")?,
        );
        let e = no_auth.err().ok_or("no credential was accepted")?;
        assert!(
            e.contains("--vcon-fetch-auth-file") && e.contains("[vcon_fetch] auth_file"),
            "{e}"
        );
        use clap::Parser as _;
        let args = crate::cli::Cli::try_parse_from([
            "sipnab",
            "--vcon-fetch",
            "../etc/passwd",
            "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}",
            "--vcon-fetch-auth-file=/a",
        ])?
        .vcon_fetch_args;
        let e = FetchPlan::resolve(&args, &keys("")?)
            .err()
            .ok_or("a path was accepted as a uuid")?;
        assert!(
            e.contains("../etc/passwd") && e.contains("--vcon-fetch"),
            "{e}"
        );
        Ok(())
    }

    /// `-` among the uuids asks for standard input and is not a uuid itself;
    /// a uuid given twice is fetched once.
    #[test]
    fn a_dash_reads_standard_input_and_repeats_are_dropped() -> TestResult {
        use clap::Parser as _;
        let args = crate::cli::Cli::try_parse_from([
            "sipnab",
            "--vcon-fetch",
            "aaaa-1",
            "-",
            "aaaa-1",
            "bbbb-2",
            "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}",
            "--vcon-fetch-auth-file=/a",
        ])?
        .vcon_fetch_args;
        let plan = FetchPlan::resolve(&args, &keys("")?)?;
        assert!(plan.from_stdin);
        assert_eq!(plan.uuids, ["aaaa-1", "bbbb-2"]);
        Ok(())
    }

    /// A uuid list: one per line, blank lines and `#` comments passed over,
    /// repeats dropped, a line that is not a uuid refused naming its line.
    #[test]
    fn a_uuid_list_is_read_line_by_line() -> TestResult {
        let text = "# fetched for case 12\n\naaaa-1\n  bbbb-2  \naaaa-1\n";
        assert_eq!(uuids_from_text(text)?, ["aaaa-1", "bbbb-2"]);
        let e = uuids_from_text("aaaa-1\nnot a uuid\n")
            .err()
            .ok_or("a bad line was accepted")?;
        assert!(e.contains("line 2"), "{e}");
        let e = uuids_from_text("# nothing\n")
            .err()
            .ok_or("an empty list was accepted")?;
        assert!(e.contains("no uuid"), "{e}");
        Ok(())
    }

    /// Each kind's read path follows the base URL's own path; a URL holding
    /// `{uuid}` is used as written; the generic kind needs `{uuid}`; a base
    /// URL with a query cannot take a path after it.
    #[test]
    fn each_kind_supplies_its_read_path() -> TestResult {
        let at = |url: &str, kind: StoreKind| -> Result<String, String> {
            read_url(&Endpoint::parse(url)?, kind).map(|e| e.to_string())
        };
        assert_eq!(
            at("https://api.vcon.store", StoreKind::VconStore)?,
            "https://api.vcon.store/v1/vcons/{uuid}"
        );
        assert_eq!(
            at("http://127.0.0.1:8000/", StoreKind::Conserver)?,
            "http://127.0.0.1:8000/vcon/{uuid}"
        );
        assert_eq!(
            at("http://127.0.0.1:8000/api/", StoreKind::Conserver)?,
            "http://127.0.0.1:8000/api/vcon/{uuid}"
        );
        assert_eq!(
            at("http://127.0.0.1:3000", StoreKind::VconMcp)?,
            "http://127.0.0.1:3000/api/v1/vcons/{uuid}"
        );
        assert_eq!(
            at("http://127.0.0.1:3000/x/{uuid}?full=1", StoreKind::VconMcp)?,
            "http://127.0.0.1:3000/x/{uuid}?full=1"
        );
        assert_eq!(
            at("http://127.0.0.1:9/v/{uuid}", StoreKind::Generic)?,
            "http://127.0.0.1:9/v/{uuid}"
        );
        let e = at("http://127.0.0.1:9/v", StoreKind::Generic)
            .err()
            .ok_or("generic without {uuid} was accepted")?;
        assert!(e.contains("{uuid}"), "{e}");
        let e = at("http://127.0.0.1:9/v?x=1", StoreKind::Conserver)
            .err()
            .ok_or("a base URL with a query was accepted")?;
        assert!(e.contains("{uuid}"), "{e}");
        Ok(())
    }

    /// vcon.store's `_meta` member is removed, every other member kept byte
    /// for byte and in order; vcon-mcp's `vcon` member is the container; the
    /// bare kinds keep the answer as it came.
    #[test]
    fn each_kind_s_envelope_is_removed() -> TestResult {
        let store = br#"{"vcon":"0.4.0","uuid":"u-1","_meta":{"owner":"o"},"parties":[ 1 ]}"#;
        assert_eq!(
            unwrap_container(StoreKind::VconStore, store)?,
            br#"{"vcon":"0.4.0","uuid":"u-1","parties":[ 1 ]}"#
        );
        let plain = br#"{"vcon":"0.4.0","uuid":"u-1"}"#;
        assert_eq!(unwrap_container(StoreKind::VconStore, plain)?, plain);
        let mcp = br#"{"success":true,"vcon":{"vcon":"0.4.0","uuid":"u-1"}}"#;
        assert_eq!(unwrap_container(StoreKind::VconMcp, mcp)?, plain);
        let e = unwrap_container(StoreKind::VconMcp, plain)
            .err()
            .ok_or("a vcon-mcp answer without its envelope was accepted")?;
        assert!(e.contains("vcon"), "{e}");
        for kind in [StoreKind::Generic, StoreKind::Conserver] {
            assert_eq!(unwrap_container(kind, store)?, store);
        }
        let e = unwrap_container(StoreKind::Conserver, b"not json")
            .err()
            .ok_or("an answer that is not JSON was accepted")?;
        assert!(e.contains("JSON"), "{e}");
        let e = unwrap_container(StoreKind::Generic, b"[1]")
            .err()
            .ok_or("an answer that is not an object was accepted")?;
        assert!(e.contains("object"), "{e}");
        Ok(())
    }

    /// The exit code: 3 for a halt whatever else happened, 0 only when every
    /// uuid was written clean, else 1.
    #[test]
    fn the_exit_code_follows_the_forwarder_s() {
        let clean = Fetched::Saved {
            path: PathBuf::from("a"),
            findings: Vec::new(),
        };
        let invalid = Fetched::Saved {
            path: PathBuf::from("b"),
            findings: vec!["/uuid (format): x".into()],
        };
        assert_eq!(exit_code(std::slice::from_ref(&clean)), 0);
        assert_eq!(exit_code(&[]), 0);
        assert_eq!(exit_code(&[clean.clone(), invalid]), 1);
        assert_eq!(exit_code(&[clean.clone(), Fetched::NotFound]), 1);
        assert_eq!(exit_code(&[Fetched::Exists(PathBuf::from("c"))]), 1);
        assert_eq!(exit_code(&[clean, Fetched::Halt("401".into())]), 3);
    }

    /// Standard input is read only for `-`; its uuids follow the command
    /// line's, each once; a list that is not one is refused with exit 2.
    #[test]
    fn standard_input_is_read_only_for_a_dash() -> TestResult {
        let read = std::cell::Cell::new(false);
        // The auth file does not exist, so this ends refused; what matters is
        // that standard input was not read on the way.
        let _ = prepare(
            &flags(&[
                "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}",
                "--vcon-fetch-auth-file=/nonexistent/auth",
            ])?,
            &keys("")?,
            || {
                read.set(true);
                Ok(String::new())
            },
        );
        assert!(!read.get(), "standard input was read without `-`");
        use clap::Parser as _;
        let args = crate::cli::Cli::try_parse_from([
            "sipnab",
            "--vcon-fetch",
            "aaaa-1",
            "-",
            "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}",
            "--vcon-fetch-auth-file=/a",
        ])?
        .vcon_fetch_args;
        let plan = FetchPlan::resolve(&args, &keys("")?)?;
        assert_eq!(
            plan.all_uuids(Some("bbbb-2\naaaa-1\n"))?,
            ["aaaa-1", "bbbb-2"]
        );
        let e = prepare(&args, &keys("")?, || Ok("not a uuid\n".into()))
            .err()
            .ok_or("a bad list was accepted")?;
        assert_eq!(e.0, 2);
        assert!(
            e.1.contains("--vcon-fetch -") && e.1.contains("line 1"),
            "{}",
            e.1
        );
        Ok(())
    }

    /// A kind name the fetcher accepts maps to a kind, `vcon-mcp` among
    /// them, and the forwarder's names are the first of them.
    #[test]
    fn every_fetch_kind_name_maps() {
        for name in crate::config::FETCH_KINDS {
            assert_eq!(
                StoreKind::from_name(name).map(|k| k.facts().name),
                Some(*name)
            );
        }
        assert_eq!(
            &crate::config::FETCH_KINDS[..crate::config::FORWARD_KINDS.len()],
            crate::config::FORWARD_KINDS
        );
    }
}
