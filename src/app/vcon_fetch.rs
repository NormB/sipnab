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
    /// A CA file trusted for HTTPS in addition to the host's bundle.
    pub extra_ca: Option<PathBuf>,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// How much of an answer is read.
    pub limits: FetchLimits,
    /// Where each container is written.
    pub out_dir: PathBuf,
    /// Replace a file that exists.
    pub overwrite: bool,
    /// Opens an encrypted container; `None` writes it as the store holds it.
    pub decrypt: Option<Arc<crate::output::vcon_jose::Opener>>,
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
    /// An encrypted container, decrypted with `--vcon-fetch-decrypt-key`,
    /// its signature verified, and the unsigned container inside written to
    /// this file. `findings`: what the schema check found in it. `signer`:
    /// the SHA-256 fingerprint of the certificate the signature verified
    /// against.
    Decrypted {
        /// The file written.
        path: PathBuf,
        /// The schema findings, one line each.
        findings: Vec<String>,
        /// The signer certificate's SHA-256 fingerprint.
        signer: String,
    },
    /// A signed container that is not encrypted, its signature verified and
    /// its signer checked, written to this file as the store holds it.
    /// `findings`: what the schema check found in the vCon it signs.
    /// `signer`: the SHA-256 fingerprint of the certificate the signature
    /// verified against.
    Signed {
        /// The file written.
        path: PathBuf,
        /// The schema findings, one line each.
        findings: Vec<String>,
        /// The signer certificate's SHA-256 fingerprint.
        signer: String,
    },
    /// An encrypted container, written to this file as the store holds it:
    /// no decryption key was given.
    Encrypted(PathBuf),
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
    /// A CA file trusted for HTTPS in addition to the host's bundle.
    pub extra_ca: Option<PathBuf>,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// How much of an answer is read.
    pub limits: FetchLimits,
    /// Where each container is written.
    pub out_dir: PathBuf,
    /// Replace a file that exists.
    pub overwrite: bool,
    /// The file holding the key that decrypts an encrypted container.
    pub decrypt_key: Option<AuthSource>,
    /// The CA a decrypted container's signer must chain to.
    pub signer_ca: Option<SignerCa>,
    /// The SHA-256 fingerprint a decrypted container's signer must have.
    pub signer_sha256: Option<[u8; 32]>,
}

/// Where the CA a signer must chain to comes from.
#[derive(Clone, PartialEq, Eq)]
pub enum SignerCa {
    /// The host's CA bundle: the value `system`, and the setting that gave
    /// it.
    System(&'static str, crate::settings::Origin),
    /// A PEM file, and the setting that named it.
    File(AuthSource),
}

impl std::fmt::Debug for SignerCa {
    /// The value alone: a flag and its key that name the same CA are the
    /// same setting.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::System(..) => write!(f, "System"),
            Self::File(source) => write!(f, "{source:?}"),
        }
    }
}

/// The value of `--vcon-fetch-signer-ca` that names the host's CA bundle.
pub const SIGNER_CA_SYSTEM: &str = "system";

/// The flag that names the uuids, quoted in their refusals.
const MODE_FLAG: &str = "--vcon-fetch";

/// The flag that names the auth file, quoted in its errors.
const AUTH_FLAG: &str = "--vcon-fetch-auth-file";

/// The key that names the auth file, quoted in its errors.
const AUTH_KEY: &str = "[vcon_fetch] auth_file";

/// The flag that names the decrypt key, quoted in its refusals.
const DECRYPT_FLAG: &str = "--vcon-fetch-decrypt-key";

/// The key that names the decrypt key, quoted in its refusals.
const DECRYPT_KEY: &str = "[vcon_fetch] decrypt_key";

/// The flag that names the signer's CA, quoted in its refusals.
const SIGNER_CA_FLAG: &str = "--vcon-fetch-signer-ca";

/// The key that names the signer's CA, quoted in its refusals.
const SIGNER_CA_KEY: &str = "[vcon_fetch] signer_ca";

/// The flag that pins the signer's fingerprint, quoted in its refusals.
const SIGNER_SHA256_FLAG: &str = "--vcon-fetch-signer-sha256";

/// The key that pins the signer's fingerprint, quoted in its refusals.
const SIGNER_SHA256_KEY: &str = "[vcon_fetch] signer_sha256";

/// The [`SignerCa`] `path` names: the host's bundle for `system`, else the
/// file.
pub fn signer_ca(path: &Path, from: &'static str, origin: crate::settings::Origin) -> SignerCa {
    if path.as_os_str() == SIGNER_CA_SYSTEM {
        SignerCa::System(from, origin)
    } else {
        SignerCa::File(AuthSource {
            path: path.to_path_buf(),
            from,
            origin,
        })
    }
}

/// What the fetcher's trust refusals call its settings and its peer.
const FETCH_TRUST: crate::tls_files::TrustNames<'static> = crate::tls_files::TrustNames {
    ca: "--vcon-fetch-ca",
    extra: "--vcon-fetch-extra-ca",
    issuer: "the store's CA",
};

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
        let url = Endpoint::parse(url_text, crate::app::https_client::UrlUse::FETCHER)
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
        let (ca, extra_ca) = crate::config::trust_pair(
            (
                args.vcon_fetch_ca.as_ref(),
                args.vcon_fetch_extra_ca.as_ref(),
            ),
            (keys.ca.as_ref(), keys.extra_ca.as_ref()),
        );
        if ca.is_some() && extra_ca.is_some() {
            return Err((
                Origin::ConfigFile,
                crate::config::trust_keys_conflict("vcon_fetch", "ca", "extra_ca"),
            ));
        }
        let plan = Self {
            uuids,
            from_stdin,
            kind,
            url,
            auth,
            ca,
            extra_ca,
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
            signer_ca: match (&args.vcon_fetch_signer_ca, &keys.signer_ca) {
                (Some(path), _) => Some(signer_ca(path, SIGNER_CA_FLAG, Origin::CommandLine)),
                (None, Some(path)) => Some(signer_ca(path, SIGNER_CA_KEY, Origin::ConfigFile)),
                (None, None) => None,
            },
            signer_sha256: match (&args.vcon_fetch_signer_sha256, &keys.signer_sha256) {
                (Some(text), _) => Some(
                    crate::config::parse_sha256_fingerprint(text)
                        .map_err(|e| flag(format!("{SIGNER_SHA256_FLAG}: {e}")))?,
                ),
                (None, Some(text)) => Some(
                    crate::config::parse_sha256_fingerprint(text)
                        .map_err(|e| (Origin::ConfigFile, format!("{SIGNER_SHA256_KEY}: {e}")))?,
                ),
                (None, None) => None,
            },
            decrypt_key: match (&args.vcon_fetch_decrypt_key, &keys.decrypt_key) {
                (Some(path), _) => Some(AuthSource {
                    path: path.clone(),
                    from: DECRYPT_FLAG,
                    origin: Origin::CommandLine,
                }),
                (None, Some(path)) => Some(AuthSource {
                    path: path.clone(),
                    from: DECRYPT_KEY,
                    origin: Origin::ConfigFile,
                }),
                (None, None) => None,
            },
        };
        Ok(plan)
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
            extra_ca: self.extra_ca,
            timeout: self.timeout,
            limits: self.limits,
            out_dir: self.out_dir,
            overwrite: self.overwrite,
            // A signer check needs no key: it applies to a signed container
            // as it is, and to the signed form inside an encrypted one.
            decrypt: match (
                self.decrypt_key,
                self.signer_ca.is_some() || self.signer_sha256.is_some(),
            ) {
                (Some(key), _) => Some(Arc::new(
                    crate::output::vcon_jose::Opener::load(&key.path)
                        .map_err(|e| (key.origin, format!("{}: {e}", key.from)))?
                        .trusting(signer_trust(self.signer_ca.as_ref(), self.signer_sha256)?),
                )),
                (None, true) => Some(Arc::new(
                    crate::output::vcon_jose::Opener::without_key()
                        .trusting(signer_trust(self.signer_ca.as_ref(), self.signer_sha256)?),
                )),
                (None, false) => None,
            },
        })
    }
}

/// The signer checks `ca` and `sha256` ask for, the CA read.
///
/// # Errors
///
/// The CA file cannot be read or holds no usable CA certificate, or, for
/// `system`, the host has no CA bundle; with the
/// [`crate::settings::Origin`] of the setting.
pub fn signer_trust(
    ca: Option<&SignerCa>,
    sha256: Option<[u8; 32]>,
) -> Result<crate::output::vcon_jose::SignerTrust, (crate::settings::Origin, String)> {
    use crate::output::vcon_jose::SignerTrust;
    let trust = match ca {
        None => SignerTrust::default(),
        Some(SignerCa::System(from, origin)) => {
            let bundle = crate::tls_files::host_ca_bundle().ok_or_else(|| {
                (
                    *origin,
                    format!(
                        "{from} system: no CA bundle found on this host; name a CA file instead"
                    ),
                )
            })?;
            let pem = std::fs::read_to_string(&bundle).map_err(|e| {
                (
                    *origin,
                    format!("{from} system: '{}': {e}", bundle.display()),
                )
            })?;
            SignerTrust::from_ca_pem(&pem, false).map_err(|e| {
                (
                    *origin,
                    format!("{from} system: '{}': {e}", bundle.display()),
                )
            })?
        }
        Some(SignerCa::File(source)) => {
            let refuse = |e: String| {
                (
                    source.origin,
                    format!("{} '{}': {e}", source.from, source.path.display()),
                )
            };
            let pem = std::fs::read_to_string(&source.path).map_err(|e| refuse(e.to_string()))?;
            SignerTrust::from_ca_pem(&pem, true).map_err(refuse)?
        }
    };
    Ok(match sha256 {
        Some(pin) => trust.pinned(pin),
        None => trust,
    })
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
        let fetcher = Self::reader(settings)?;
        prepare_out_dir(&fetcher.settings.out_dir, "--vcon-fetch-out")?;
        Ok(fetcher)
    }

    /// [`Self::new`] for a fetcher that writes no file: the MCP `fetch_vcon`
    /// tool and `GET /v1/vcon/fetch/{uuid}`, which return the container
    /// inline. The output directory is neither checked nor created.
    ///
    /// # Errors
    ///
    /// The URL holds no `{uuid}`, or HTTPS is needed and no CA loads.
    pub fn reader(settings: FetchSettings) -> Result<Self, String> {
        if !settings.url.target.contains("{uuid}") {
            return Err(format!(
                "'{}': the read URL holds no {{uuid}}",
                settings.url
            ));
        }
        let tls = if settings.url.tls {
            Some(client_config(
                settings.ca.as_deref(),
                settings.extra_ca.as_deref(),
                &FETCH_TRUST,
            )?)
        } else {
            None
        };
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
        let held = match self.retrieve(uuid) {
            Retrieved::Container(held) => held,
            Retrieved::NotFound => return Fetched::NotFound,
            Retrieved::Failed(why) => return Fetched::Failed(why),
            Retrieved::Halt(why) => return Fetched::Halt(why),
        };
        if let Err(outcome) = self.write(&path, &held.bytes) {
            return outcome;
        }
        match (held.stored_form, held.signer) {
            (crate::output::vcon_jose::Form::Encrypted, Some(signer)) => Fetched::Decrypted {
                path,
                findings: held.findings,
                signer,
            },
            (crate::output::vcon_jose::Form::Encrypted, None) => Fetched::Encrypted(path),
            (_, Some(signer)) => Fetched::Signed {
                path,
                findings: held.findings,
                signer,
            },
            (_, None) => Fetched::Saved {
                path,
                findings: held.findings,
            },
        }
    }

    /// Read the container with `uuid` from the store into memory, with every
    /// check [`Self::fetch_one`] makes before it writes: the status, the size
    /// limit, the kind's envelope, the uuid inside, and for a signed
    /// container, or an encrypted one with a key, the readers' rule
    /// ([`crate::output::vcon_jose::Opener::unwrap`]): the decryption, every
    /// signature and the signer checks. Writes nothing.
    ///
    /// The one rule for both the fetcher and the server doors that return a
    /// container inline ([`fetch_inline`]).
    #[must_use]
    pub fn retrieve(&self, uuid: &str) -> Retrieved {
        if !is_path_uuid(uuid) {
            return Retrieved::Failed(format!("{uuid:?} is not a uuid"));
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
            |r| read_answer(r, limits, "--vcon-fetch-max-response-head"),
        ) {
            Ok(answer) => answer,
            Err(e) => return Retrieved::Failed(format!("{url}: {e}")),
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
                return Retrieved::Halt(format!(
                    "{url} answered {}: the store refused the credential or this client \
                     ({}); nothing more is fetched",
                    answer.status,
                    quoted()
                ));
            }
            404 => return Retrieved::NotFound,
            200..=299 => {}
            status => {
                return Retrieved::Failed(format!("{url} answered {status} ({})", quoted()));
            }
        }
        if answer.oversized {
            return Retrieved::Failed(format!(
                "the answer is larger than {} bytes (--vcon-fetch-max-size); nothing was written",
                limits.max_size
            ));
        }
        if let Some(problem) = &answer.short {
            return Retrieved::Failed(format!("{url}: {problem}; nothing was written"));
        }
        let container = match unwrap_container(self.settings.kind, &answer.body) {
            Ok(c) => c,
            Err(e) => return Retrieved::Failed(format!("{url}: {e}; nothing was written")),
        };
        let doc: serde_json::Value = match serde_json::from_slice(&container) {
            Ok(doc) => doc,
            Err(e) => return Retrieved::Failed(format!("{url}: the container is not JSON: {e}")),
        };
        // The uuid by the rule the forwarder files a container under: the
        // top-level member, or the header a signed or encrypted container
        // carries it in.
        let held = crate::app::vcon_forward::container_uuid(&container).ok();
        if !held
            .as_deref()
            .is_some_and(|h| h.eq_ignore_ascii_case(uuid))
        {
            return Retrieved::Failed(format!(
                "{url}: the container's uuid is {}, not the one asked for; nothing was written",
                held.map_or_else(|| "missing".to_string(), |h| format!("{h:?}"))
            ));
        }
        let stored_form = crate::output::vcon_jose::form_of(&doc);
        let signed_or_encrypted = matches!(
            stored_form,
            crate::output::vcon_jose::Form::Signed | crate::output::vcon_jose::Form::Encrypted
        );
        if !signed_or_encrypted
            && let Some(opener) = &self.settings.decrypt
            && opener.checks_signer()
        {
            return Retrieved::Failed(format!(
                "{url}: the container is not signed, so it has no signer for \
                 {SIGNER_CA_FLAG} or {SIGNER_SHA256_FLAG} to check; nothing was written"
            ));
        }
        if !signed_or_encrypted {
            return Retrieved::Container(Held {
                findings: schema_findings(&doc),
                bytes: container,
                stored_form,
                signer: None,
            });
        }
        let encrypted = stored_form == crate::output::vcon_jose::Form::Encrypted;
        // An encrypted container with no key is kept as the store holds it.
        let keyless;
        let opener: &crate::output::vcon_jose::Opener = match &self.settings.decrypt {
            // A signer check without a key: the signer of an encrypted
            // container is inside the encryption, so it cannot be checked,
            // and writing the container as stored would skip the check.
            Some(opener) if encrypted && !opener.has_key() => {
                return Retrieved::Failed(format!(
                    "{url}: the container is encrypted, so {SIGNER_CA_FLAG} or \
                     {SIGNER_SHA256_FLAG} cannot check its signer without the key: give \
                     {DECRYPT_FLAG}, or {DECRYPT_KEY} in the config file; nothing was written"
                ));
            }
            Some(opener) => opener,
            None if encrypted => {
                return Retrieved::Container(Held {
                    bytes: container,
                    stored_form,
                    signer: None,
                    findings: Vec::new(),
                });
            }
            None => {
                keyless = crate::output::vcon_jose::Opener::without_key();
                &keyless
            }
        };
        // The readers' rule (`-I`, `analyze_vcon`, `validate_vcon`): decrypt
        // the encrypted form, verify every signed layer, and check the
        // outermost signer against the configured trust.
        let unwrapped = match opener.unwrap(&container, self.settings.limits.max_size) {
            Ok(u) => u,
            Err(e) if encrypted => {
                return Retrieved::Failed(format!(
                    "{url}: the container is encrypted and did not decrypt with \
                     --vcon-fetch-decrypt-key ({e}); nothing was written"
                ));
            }
            Err(e) => {
                return Retrieved::Failed(format!(
                    "{url}: the container is signed and did not verify ({e}); nothing was \
                     written"
                ));
            }
        };
        let signer = unwrapped.layers.iter().find_map(|layer| match layer {
            crate::output::vcon_jose::Layer::Signed(fingerprint) => Some(fingerprint.clone()),
            _ => None,
        });
        let inner: serde_json::Value = match serde_json::from_slice(&unwrapped.unsigned) {
            Ok(v) => v,
            Err(e) => {
                return Retrieved::Failed(format!(
                    "{url}: the vCon inside the container is not JSON: {e}; nothing was written"
                ));
            }
        };
        let inner_uuid = inner.get("uuid").and_then(serde_json::Value::as_str);
        if !inner_uuid.is_some_and(|h| h.eq_ignore_ascii_case(uuid)) {
            return Retrieved::Failed(format!(
                "{url}: the {} container's uuid is {}, not the one asked for; nothing was \
                 written",
                if encrypted { "decrypted" } else { "signed" },
                inner_uuid.map_or_else(|| "missing".to_string(), |h| format!("{h:?}"))
            ));
        }
        Retrieved::Container(Held {
            findings: schema_findings(&inner),
            // A decrypted container is kept as the vCon inside; a signed one
            // as the store holds it, its signature with it.
            bytes: if encrypted {
                unwrapped.unsigned
            } else {
                container
            },
            stored_form,
            signer,
        })
    }

    /// Write `bytes` to `path`, private, or the outcome that says why not.
    fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), Fetched> {
        write_private(path, bytes, self.settings.overwrite).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                Fetched::Exists(path.to_path_buf())
            } else {
                Fetched::Failed(format!("{}: {e}", path.display()))
            }
        })
    }
}

/// One container read from the store and held in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The unsigned container when an encrypted one was decrypted, else the
    /// container as the store holds it, the kind's envelope removed.
    pub bytes: Vec<u8>,
    /// The form the store held it in.
    pub stored_form: crate::output::vcon_jose::Form,
    /// The SHA-256 fingerprint of the certificate the outermost signature
    /// verified against: present when a signed container verified, or an
    /// encrypted one was decrypted and its signature verified.
    pub signer: Option<String>,
    /// What the core-04 schema found in the vCon, one line each: in
    /// [`Self::bytes`], or for a signed container in the vCon it signs.
    /// Empty for a container left encrypted, which the schema cannot read.
    pub findings: Vec<String>,
}

/// What [`Fetcher::retrieve`] got for one uuid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retrieved {
    /// The container, every check passed.
    Container(Held),
    /// The store holds no container with this uuid (`404`).
    NotFound,
    /// Anything else, and why.
    Failed(String),
    /// The store refused the credential or the client (`401`, `403`).
    Halt(String),
}

/// Whether a server door may fetch a container, and from which store.
///
/// Built once, when the server starts, from the door's opt-in flag and the
/// operator's `[vcon_fetch]` keys. Nothing a caller sends picks the store,
/// the kind or the credential.
#[derive(Debug, Clone, Default)]
pub enum Access {
    /// The door's opt-in flag was not given.
    #[default]
    Off,
    /// The flag was given and no `[vcon_fetch] url` is configured.
    NotConfigured,
    /// The operator's store.
    Ready(Arc<Fetcher>),
}

impl Access {
    /// Whether a fetch can reach a store: the door's flag was given and a
    /// `[vcon_fetch]` store is configured. What the capabilities answers
    /// report as the door's opt-in.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(_))
    }

    /// The access a door opted in with `flag` (`allowed`) has to the store
    /// `keys` configure. Reads the credential and the decryption key, and
    /// loads the CA, as `sipnab --vcon-fetch` does.
    ///
    /// # Errors
    ///
    /// A store that the fetcher's own resolver refuses, or whose files do
    /// not read, with the message prefixed by `flag`.
    pub fn resolve(
        flag: &str,
        allowed: bool,
        keys: &crate::config::VconFetchConfig,
    ) -> Result<Self, String> {
        if !allowed {
            return Ok(Self::Off);
        }
        if keys.url.is_none() {
            return Ok(Self::NotConfigured);
        }
        let refuse = |e: String| format!("{flag}: {e}");
        let plan =
            FetchPlan::resolve(&crate::cli::VconFetchArgs::default(), keys).map_err(refuse)?;
        let settings = plan.into_settings().map_err(|(_, e)| refuse(e))?;
        Ok(Self::Ready(Arc::new(
            Fetcher::reader(settings).map_err(refuse)?,
        )))
    }
}

/// Why an inline fetch returned no container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InlineRefusal {
    /// The door's opt-in flag was not given.
    Off,
    /// No `[vcon_fetch]` store is configured.
    NotConfigured,
    /// The uuid is not one a URL path may carry.
    NotAUuid,
    /// The store holds no container with this uuid (`404`).
    NotFound,
    /// Anything else, and why. The store's answer is quoted with the
    /// credential removed.
    Store(String),
}

impl InlineRefusal {
    /// The sentence a door answers with, naming `flag`, the door's opt-in.
    #[must_use]
    pub fn message(&self, flag: &str) -> String {
        match self {
            Self::Off => format!(
                "fetching a vCon from the store is off on this server: start sipnab with \
                 {flag}, and configure the store in [vcon_fetch]"
            ),
            Self::NotConfigured => format!(
                "{flag} is set, but no vCon store is configured: set [vcon_fetch] url and \
                 [vcon_fetch] auth_file in the config file"
            ),
            Self::NotAUuid => "the uuid is not one (1 to 64 characters, each a letter, a \
                               digit or '-')"
                .to_string(),
            Self::NotFound => "the store holds no such vCon (404)".to_string(),
            Self::Store(why) => why.clone(),
        }
    }
}

/// The name of `form` in an answer.
fn form_name(form: crate::output::vcon_jose::Form) -> &'static str {
    use crate::output::vcon_jose::Form;
    match form {
        Form::Unsigned => "unsigned",
        Form::Signed => "signed",
        Form::Encrypted => "encrypted",
        Form::Unknown => "unknown",
    }
}

/// Fetch the container with `uuid` from the operator's store and return it
/// inline, with what was checked: the MCP `fetch_vcon` tool and
/// `GET /v1/vcon/fetch/{uuid}`. Writes no file.
///
/// The checks are [`Fetcher::retrieve`]'s, the fetcher's own. The answer
/// carries `stored_form` (`unsigned`, `signed`, `encrypted`), `decrypted`,
/// `signature_verified` and `signer_sha256`, which are set only when an
/// encrypted container was decrypted with `[vcon_fetch] decrypt_key` and its
/// signature verified, the schema findings, and `container`. It carries no
/// key and no credential.
///
/// # Errors
///
/// [`InlineRefusal`]: the door is off or has no store, the uuid is not one,
/// the store holds no such container, or anything else the fetcher refuses.
pub fn fetch_inline(access: &Access, uuid: &str) -> Result<InlineVcon, InlineRefusal> {
    let fetcher = match access {
        Access::Off => return Err(InlineRefusal::Off),
        Access::NotConfigured => return Err(InlineRefusal::NotConfigured),
        Access::Ready(fetcher) => fetcher,
    };
    if !is_path_uuid(uuid) {
        return Err(InlineRefusal::NotAUuid);
    }
    let held = match fetcher.retrieve(uuid) {
        Retrieved::Container(held) => held,
        Retrieved::NotFound => return Err(InlineRefusal::NotFound),
        Retrieved::Failed(why) | Retrieved::Halt(why) => return Err(InlineRefusal::Store(why)),
    };
    let container: serde_json::Value = serde_json::from_slice(&held.bytes)
        .map_err(|e| InlineRefusal::Store(format!("the container is not JSON: {e}")))?;
    let verified = held.signer.is_some();
    Ok(InlineVcon {
        container,
        decrypted: verified && held.stored_form == crate::output::vcon_jose::Form::Encrypted,
        schema_findings: held.findings,
        schema_version: 1,
        signature_verified: verified,
        signer_sha256: held.signer,
        stored_form: form_name(held.stored_form).to_string(),
        uuid: uuid.to_string(),
    })
}

/// One container read from the operator's store, and what was checked:
/// the answer of the MCP `fetch_vcon` tool and `GET /v1/vcon/fetch/{uuid}`.
///
/// It carries no key and no credential. The members are in name order.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct InlineVcon {
    /// The vCon: the unsigned container when sipnab decrypted it, else the
    /// container as the store holds it, without the store kind's envelope.
    #[cfg_attr(feature = "api", schema(value_type = Object))]
    pub container: serde_json::Value,
    /// Whether sipnab decrypted an encrypted container with
    /// `[vcon_fetch] decrypt_key`.
    pub decrypted: bool,
    /// Where the container fails the draft-ietf-vcon-vcon-core-04 schema,
    /// one line each. Empty for a valid container and for one left
    /// encrypted.
    pub schema_findings: Vec<String>,
    /// The version of this answer's shape.
    pub schema_version: u32,
    /// Whether the container's signature verified and passed
    /// `[vcon_fetch] signer_ca` and `signer_sha256` when the operator sets
    /// them: the signed form inside a decrypted container, or a signed
    /// container that is not encrypted. `false` for an unsigned container
    /// and for one left encrypted.
    pub signature_verified: bool,
    /// The SHA-256 fingerprint of the certificate the signature verified
    /// against, as `openssl x509 -noout -fingerprint -sha256` prints it.
    pub signer_sha256: Option<String>,
    /// The form the store held the container in: `unsigned`, `signed`,
    /// `encrypted` or `unknown`.
    pub stored_form: String,
    /// The uuid asked for.
    pub uuid: String,
}

/// What the core-04 schema finds in `doc`, one line each.
fn schema_findings(doc: &serde_json::Value) -> Vec<String> {
    crate::output::vcon_schema::validate(doc)
        .errors
        .iter()
        .map(|f| format!("{} ({}): {}", f.instance_path, f.keyword, f.detail))
        .collect()
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
/// of the body, for the message. `head_setting` names the setting a head
/// over its limit is refused by.
fn read_answer(
    reader: &mut dyn BufRead,
    limits: FetchLimits,
    head_setting: &str,
) -> Result<Answer, String> {
    loop {
        let head = read_head(reader, limits.response_head, head_setting)?;
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
pub(crate) fn write_private(path: &Path, bytes: &[u8], overwrite: bool) -> std::io::Result<()> {
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

/// Create `dir`, mode 0700, when it does not exist. `flag` names the
/// setting that named it, for the refusal.
pub(crate) fn prepare_out_dir(dir: &Path, flag: &str) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::metadata(dir) {
        Ok(meta) if meta.is_dir() => Ok(()),
        Ok(_) => Err(format!("{flag} '{}': not a directory", dir.display())),
        Err(_) => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{flag} '{}': {e}", dir.display())),
    }
}

/// One `GET` of `url` with no credential, read within `limits` by the
/// fetcher's own answer reader: the body of a `2xx` answer. What
/// `--vcon-audio-fetch` reads a recording's `url` with. `max_size_setting`
/// names the setting an answer over `limits.max_size` is refused by.
///
/// # Errors
///
/// No connection, a TLS refusal, a status other than `2xx`, an answer over
/// the size limit, or one that ended before its declared length.
pub(crate) fn get_body(
    url: &Endpoint,
    timeout: Duration,
    tls: &Arc<rustls::ClientConfig>,
    limits: FetchLimits,
    max_size_setting: &str,
) -> Result<Vec<u8>, String> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.target,
        url.host_header(),
        crate::app::vcon_forward::USER_AGENT
    );
    let answer = exchange(url, timeout, Some(tls), request.as_bytes(), |r| {
        read_answer(r, limits, "the response head limit")
    })
    .map_err(|e| format!("{url}: {e}"))?;
    if !(200..300).contains(&answer.status) {
        return Err(format!("{url} answered {}", answer.status));
    }
    if answer.oversized {
        return Err(format!(
            "{url}: the answer is larger than {} bytes ({max_size_setting})",
            limits.max_size
        ));
    }
    if let Some(problem) = answer.short {
        return Err(format!("{url}: {problem}, so the file is not whole"));
    }
    Ok(answer.body)
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
    let clean = outcomes.iter().all(|o| match o {
        Fetched::Saved { findings, .. }
        | Fetched::Decrypted { findings, .. }
        | Fetched::Signed { findings, .. } => findings.is_empty(),
        Fetched::Encrypted(_) => true,
        _ => false,
    });
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
        Fetched::Decrypted {
            path,
            findings,
            signer,
        } if findings.is_empty() => (
            tracing::Level::INFO,
            format!(
                "{uuid}: decrypted and written to {}; the signature verifies against the \
                 certificate with SHA-256 fingerprint {signer}",
                path.display()
            ),
        ),
        Fetched::Decrypted {
            path,
            findings,
            signer,
        } => (
            tracing::Level::WARN,
            format!(
                "{uuid}: decrypted and written to {} (signed by the certificate with SHA-256 \
                 fingerprint {signer}), but the schema refuses it ({} finding(s)): {}",
                path.display(),
                findings.len(),
                findings.join("; ")
            ),
        ),
        Fetched::Signed {
            path,
            findings,
            signer,
        } if findings.is_empty() => (
            tracing::Level::INFO,
            format!(
                "{uuid}: written to {} as the store holds it; the signature verifies against \
                 the certificate with SHA-256 fingerprint {signer}",
                path.display()
            ),
        ),
        Fetched::Signed {
            path,
            findings,
            signer,
        } => (
            tracing::Level::WARN,
            format!(
                "{uuid}: written to {} (signed by the certificate with SHA-256 fingerprint \
                 {signer}), but the schema refuses the vCon it signs ({} finding(s)): {}",
                path.display(),
                findings.len(),
                findings.join("; ")
            ),
        ),
        Fetched::Encrypted(path) => (
            tracing::Level::INFO,
            format!(
                "{uuid}: written to {} as the store holds it: the container is encrypted \
                 (draft-ietf-vcon-vcon-core-04 section 5.3). --vcon-fetch-decrypt-key decrypts it",
                path.display()
            ),
        ),
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

    /// Which way an inline fetch came out, for a test's error: never the
    /// container or the refusal text, which hold the stored uuid.
    fn other_outcome<T, E>(outcome: &Result<T, E>) -> &'static str {
        if outcome.is_ok() {
            "the fetch returned a container where the test expected a refusal"
        } else {
            "the fetch refused for a reason the test did not expect"
        }
    }

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

    /// A fetch URL the URL parser refuses is refused in the fetcher's terms.
    /// On 0.5.224 a credential in `--vcon-fetch-url` was refused with "put
    /// credentials in --vcon-forward-auth-file", the forwarder's flag, and an
    /// `ftp://` URL with "the forwarder speaks http:// and https:// only".
    #[test]
    fn a_refused_fetch_url_names_the_fetcher_and_its_credential_flag() -> TestResult {
        let from_flag: &[&str] = &[
            "--vcon-fetch-url=https://user:pw@store.example/{uuid}",
            "--vcon-fetch-auth-file=/a",
        ];
        for (extra, key) in [
            (from_flag, ""),
            (
                &["--vcon-fetch-auth-file=/a"][..],
                "url = \"https://user:pw@store.example/{uuid}\"",
            ),
        ] {
            let e = FetchPlan::resolve(&flags(extra)?, &keys(key)?)
                .err()
                .ok_or("a URL holding credentials was accepted")?;
            assert!(
                e.contains("--vcon-fetch-auth-file") && !e.contains("--vcon-forward"),
                "the fetcher's credential flag, not the forwarder's: {e}"
            );
            assert!(!e.contains("pw@"), "the password must not be quoted: {e}");
        }
        let e = FetchPlan::resolve(
            &flags(&[
                "--vcon-fetch-url=ftp://store.example/{uuid}",
                "--vcon-fetch-auth-file=/a",
            ])?,
            &keys("")?,
        )
        .err()
        .ok_or("an ftp:// URL was accepted")?;
        assert!(
            e.contains("fetcher") && !e.contains("forwarder"),
            "the scheme refusal names the fetcher: {e}"
        );
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
            read_url(
                &Endpoint::parse(url, crate::app::https_client::UrlUse::FETCHER)?,
                kind,
            )
            .map(|e| e.to_string())
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
    /// The decrypt key prints by its path alone, so a flag and a key that
    /// name the same file are the same setting; a key that is refused names
    /// the setting that named it, with that setting's exit-code origin.
    #[test]
    fn the_decrypt_key_is_named_by_the_setting_that_gave_it() -> TestResult {
        let dir = tempfile::tempdir()?;
        let auth = dir.path().join("auth");
        std::fs::write(&auth, "Authorization: Bearer token\n")?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600))?;
        }
        let missing = dir.path().join("missing.key");
        let auth_flag = format!("--vcon-fetch-auth-file={}", auth.display());
        let url = "--vcon-fetch-url=http://127.0.0.1:9/v/{uuid}";
        let by_flag = FetchPlan::resolve(
            &flags(&[
                url,
                &auth_flag,
                &format!("--vcon-fetch-decrypt-key={}", missing.display()),
            ])?,
            &keys("")?,
        )?;
        let by_key = FetchPlan::resolve(
            &flags(&[url, &auth_flag])?,
            &keys(&format!(
                "decrypt_key = {:?}",
                missing.display().to_string()
            ))?,
        )?;
        assert_eq!(format!("{by_flag:?}"), format!("{by_key:?}"));
        for (plan, origin, from) in [
            (
                by_flag,
                crate::settings::Origin::CommandLine,
                "--vcon-fetch-decrypt-key",
            ),
            (
                by_key,
                crate::settings::Origin::ConfigFile,
                "[vcon_fetch] decrypt_key",
            ),
        ] {
            let Err((got, message)) = plan.into_settings() else {
                return Err("a missing decrypt key was accepted".into());
            };
            assert_eq!(got, origin);
            assert!(message.starts_with(&format!("{from}: ")), "{message}");
        }
        Ok(())
    }

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

    // ── Fetching for a server door: fetch_inline ─────────────────────────

    use super::stub_store::{self, ready};

    /// The uuid the inline tests fetch. Synthetic.
    const INLINE_UUID: &str = stub_store::UUID;

    /// Without the opt-in, nothing is fetched, and the refusal names the
    /// flag the door was given.
    #[test]
    fn an_inline_fetch_is_refused_without_the_opt_in() -> TestResult {
        let stub = stub_store::start(200, stub_store::container(INLINE_UUID))?;
        let refused = fetch_inline(&Access::Off, INLINE_UUID);
        assert_eq!(refused, Err(InlineRefusal::Off));
        let message = InlineRefusal::Off.message("--mcp-allow-vcon-fetch");
        assert!(message.contains("--mcp-allow-vcon-fetch"), "{message}");
        let unset = InlineRefusal::NotConfigured.message("--api-allow-vcon-fetch");
        assert!(
            unset.contains("[vcon_fetch] url") && unset.contains("--api-allow-vcon-fetch"),
            "{unset}"
        );
        assert_eq!(
            fetch_inline(&Access::NotConfigured, INLINE_UUID),
            Err(InlineRefusal::NotConfigured)
        );
        assert_eq!(stub.hits(), 0, "a refused fetch sends nothing");
        Ok(())
    }

    /// The opt-in alone is not a store: off stays off whatever the keys say,
    /// the opt-in without `[vcon_fetch] url` is "not configured", a store
    /// with no credential is refused naming the opt-in, and a full store is
    /// ready.
    #[test]
    fn the_door_s_access_follows_the_opt_in_and_the_keys() -> TestResult {
        let dir = tempfile::tempdir()?;
        let auth = stub_store::private_file(dir.path(), "auth", &stub_store::secret())?;
        let store = keys(&format!(
            "kind = \"conserver\"\nurl = \"http://127.0.0.1:9\"\nauth_file = {:?}",
            auth.display().to_string()
        ))?;
        let flag = "--mcp-allow-vcon-fetch";
        assert!(matches!(Access::resolve(flag, false, &store)?, Access::Off));
        assert!(matches!(
            Access::resolve(flag, true, &keys("")?)?,
            Access::NotConfigured
        ));
        let e = Access::resolve(flag, true, &keys("url = \"http://127.0.0.1:9/v/{uuid}\"")?)
            .err()
            .ok_or("a store with no credential was accepted")?;
        assert!(
            e.contains(flag) && e.contains("[vcon_fetch] auth_file"),
            "{e}"
        );
        assert!(matches!(
            Access::resolve(flag, true, &store)?,
            Access::Ready(_)
        ));
        Ok(())
    }

    /// An unsigned container comes back inline, as the store holds it, with
    /// nothing verified, and no file is written.
    #[test]
    fn an_unsigned_container_comes_back_inline() -> TestResult {
        let stored = stub_store::container(INLINE_UUID);
        let stub = stub_store::start(200, stored.clone())?;
        let (dir, access) = ready(&stub, false)?;
        let v = serde_json::to_value(
            fetch_inline(&access, INLINE_UUID).map_err(|e| e.message("--x"))?,
        )?;
        assert_eq!(v["uuid"], INLINE_UUID, "{v}");
        assert_eq!(v["stored_form"], "unsigned", "{v}");
        assert_eq!(v["decrypted"], false, "{v}");
        assert_eq!(v["signature_verified"], false, "{v}");
        assert!(v["signer_sha256"].is_null(), "{v}");
        assert_eq!(v["schema_findings"], serde_json::json!([]), "{v}");
        let want: serde_json::Value = serde_json::from_str(&stored)?;
        assert_eq!(v["container"], want, "{v}");
        assert_eq!(stub.hits(), 1);
        assert!(
            !dir.path().join("out").exists(),
            "an inline fetch writes no file"
        );
        Ok(())
    }

    /// An encrypted container is decrypted with the configured key, its
    /// signature verified, and the unsigned container inside comes back
    /// with the signer's fingerprint. Neither the key nor the credential
    /// appears in the answer.
    #[test]
    fn an_encrypted_container_comes_back_decrypted() -> TestResult {
        let stub = stub_store::start(200, stub_store::sealed(INLINE_UUID)?)?;
        let (_dir, access) = ready(&stub, true)?;
        let v = serde_json::to_value(
            fetch_inline(&access, INLINE_UUID).map_err(|e| e.message("--x"))?,
        )?;
        assert_eq!(v["stored_form"], "encrypted", "{v}");
        assert_eq!(v["decrypted"], true, "{v}");
        assert_eq!(v["signature_verified"], true, "{v}");
        assert_eq!(
            v["signer_sha256"],
            stub_store::fixture_fingerprint()?,
            "{v}"
        );
        let want: serde_json::Value = serde_json::from_str(&stub_store::container(INLINE_UUID))?;
        assert_eq!(v["container"], want, "{v}");
        let text = v.to_string();
        assert!(!text.contains("PRIVATE KEY"), "{text}");
        assert!(!text.contains(&stub_store::secret()), "{text}");
        Ok(())
    }

    /// Without a key, an encrypted container comes back as the store holds
    /// it, and the answer says it was not decrypted.
    #[test]
    fn an_encrypted_container_without_a_key_comes_back_as_stored() -> TestResult {
        let sealed = stub_store::sealed(INLINE_UUID)?;
        let stub = stub_store::start(200, sealed.clone())?;
        let (_dir, access) = ready(&stub, false)?;
        let v = serde_json::to_value(
            fetch_inline(&access, INLINE_UUID).map_err(|e| e.message("--x"))?,
        )?;
        assert_eq!(v["stored_form"], "encrypted", "{v}");
        assert_eq!(v["decrypted"], false, "{v}");
        assert!(v["signer_sha256"].is_null(), "{v}");
        let want: serde_json::Value = serde_json::from_str(&sealed)?;
        assert_eq!(v["container"], want, "{v}");
        Ok(())
    }

    /// A `404` is "the store holds no such vCon", not a failure.
    #[test]
    fn a_missing_container_is_not_found_inline() -> TestResult {
        let stub = stub_store::start(404, "{}".to_string())?;
        let (_dir, access) = ready(&stub, false)?;
        assert_eq!(
            fetch_inline(&access, INLINE_UUID),
            Err(InlineRefusal::NotFound)
        );
        Ok(())
    }

    /// A uuid a URL path may not carry is refused before anything is sent.
    #[test]
    fn a_uuid_that_is_not_one_is_refused_unsent() -> TestResult {
        let stub = stub_store::start(200, stub_store::container(INLINE_UUID))?;
        let (_dir, access) = ready(&stub, false)?;
        for bad in ["../etc/passwd", "", "a b", "x?y=1"] {
            assert_eq!(
                fetch_inline(&access, bad),
                Err(InlineRefusal::NotAUuid),
                "{bad:?}"
            );
        }
        assert_eq!(stub.hits(), 0, "nothing was sent");
        Ok(())
    }

    /// A signed container that is not encrypted is verified, as the readers
    /// verify it, and comes back as the store holds it with its signer. No
    /// key is needed; the schema is checked on the vCon it signs.
    #[test]
    fn a_signed_container_comes_back_verified() -> TestResult {
        let signed = stub_store::signed(INLINE_UUID, false)?;
        let stub = stub_store::start(200, signed.clone())?;
        let (_dir, access) = ready(&stub, false)?;
        let v = serde_json::to_value(
            fetch_inline(&access, INLINE_UUID).map_err(|e| e.message("--x"))?,
        )?;
        assert_eq!(v["stored_form"], "signed", "{v}");
        assert_eq!(v["decrypted"], false, "{v}");
        assert_eq!(v["signature_verified"], true, "{v}");
        assert_eq!(
            v["signer_sha256"],
            stub_store::fixture_fingerprint()?,
            "{v}"
        );
        assert_eq!(v["schema_findings"], serde_json::json!([]), "{v}");
        let want: serde_json::Value = serde_json::from_str(&signed)?;
        assert_eq!(v["container"], want, "{v}");
        Ok(())
    }

    /// A server door takes `[vcon_fetch] signer_sha256` without a
    /// decryption key, and applies it to a signed container: the pinned
    /// signer comes back verified, another is refused naming the
    /// fingerprint.
    #[test]
    fn a_door_checks_the_signer_of_a_signed_container_without_a_key() -> TestResult {
        let dir = tempfile::tempdir()?;
        let auth = stub_store::private_file(dir.path(), "auth", &stub_store::secret())?;
        let stub = stub_store::start(200, stub_store::signed(INLINE_UUID, false)?)?;
        let pin = stub_store::fixture_fingerprint()?;
        for (pinned, verified) in [(pin.as_str(), true), (&"ab".repeat(32)[..], false)] {
            let store = keys(&format!(
                "kind = \"conserver\"\nurl = \"{}\"\nauth_file = {:?}\nsigner_sha256 = \"{pinned}\"",
                stub.url,
                auth.display().to_string()
            ))?;
            let access = Access::resolve("--mcp-allow-vcon-fetch", true, &store)?;
            match (fetch_inline(&access, INLINE_UUID), verified) {
                (Ok(inline), true) => assert!(inline.signature_verified),
                (Err(InlineRefusal::Store(why)), false) => {
                    assert!(
                        why.contains("fingerprint"),
                        "the refusal names the fingerprint"
                    );
                }
                (other, _) => return Err(other_outcome(&other).into()),
            }
        }
        Ok(())
    }

    /// A signed container whose signature does not verify is refused, as
    /// the readers refuse it.
    #[test]
    fn a_signed_container_whose_signature_fails_is_refused() -> TestResult {
        let stub = stub_store::start(200, stub_store::signed(INLINE_UUID, true)?)?;
        let (_dir, access) = ready(&stub, false)?;
        match fetch_inline(&access, INLINE_UUID) {
            Err(InlineRefusal::Store(why)) => {
                assert!(why.contains("signature"), "the refusal names the signature");
            }
            other => return Err(other_outcome(&other).into()),
        }
        Ok(())
    }
}

/// A vCon store on `127.0.0.1` for the in-crate tests of every door that
/// fetches: it answers each request with one scripted status and body, and
/// counts the requests. The same pattern `tests/vcon_fetch_test.rs` uses; no
/// test contacts the internet.
#[cfg(test)]
pub(crate) mod stub_store {
    use std::io::{Read, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    /// The fixtures the encryption tests use.
    const JOSE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vcon-jose");

    /// The uuid the stub tests fetch. Synthetic.
    pub(crate) const UUID: &str = "018bcfe5-6800-8a6b-a667-78f1c5213800";

    /// A `[vcon_fetch]` store at `stub`, read as a conserver, opening
    /// encrypted containers with the fixture key when `decrypting`. The
    /// directory holds the auth file and the key, and is where a file would
    /// land if anything wrote one.
    pub(crate) fn ready(
        stub: &Stub,
        decrypting: bool,
    ) -> Result<(tempfile::TempDir, super::Access), Box<dyn std::error::Error>> {
        use crate::app::vcon_forward::{AuthHeader, Endpoint, StoreKind};
        let dir = tempfile::tempdir()?;
        let auth = private_file(dir.path(), "auth", &secret())?;
        let decrypt = if decrypting {
            let key = private_copy(dir.path(), "fake_grp.key")?;
            Some(Arc::new(crate::output::vcon_jose::Opener::load(&key)?))
        } else {
            None
        };
        let settings = super::FetchSettings {
            url: super::read_url(
                &Endpoint::parse(&stub.url, crate::app::https_client::UrlUse::FETCHER)?,
                StoreKind::Conserver,
            )?,
            kind: StoreKind::Conserver,
            auth: AuthHeader::read_file_for(&auth, super::AUTH_KEY, StoreKind::Conserver)?,
            ca: None,
            extra_ca: None,
            timeout: Duration::from_secs(5),
            limits: super::FetchLimits {
                response_head: 64 * 1024,
                max_size: 1024 * 1024,
            },
            out_dir: dir.path().join("out"),
            overwrite: false,
            decrypt,
        };
        Ok((
            dir,
            super::Access::Ready(Arc::new(super::Fetcher::reader(settings)?)),
        ))
    }

    /// A running store. It stops when dropped.
    pub(crate) struct Stub {
        /// `http://127.0.0.1:<port>`.
        pub(crate) url: String,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
    }

    impl Stub {
        /// Requests received so far.
        pub(crate) fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for Stub {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// Start a store that answers every request with `status` and `body`.
    pub(crate) fn start(status: u16, body: String) -> std::io::Result<Stub> {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let url = format!("http://{}", listener.local_addr()?);
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (count, halt) = (Arc::clone(&hits), Arc::clone(&stop));
        std::thread::spawn(move || {
            while !halt.load(Ordering::SeqCst) {
                let Ok((mut sock, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let _ = sock.set_nonblocking(false);
                let _ = sock.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match sock.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                count.fetch_add(1, Ordering::SeqCst);
                let answer = format!(
                    "HTTP/1.1 {status} Scripted\r\nContent-Length: {}\r\n\
                     Content-Type: application/json\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = sock.write_all(answer.as_bytes());
                let _ = sock.flush();
            }
        });
        Ok(Stub { url, hits, stop })
    }

    /// The credential every stub's auth file carries. Built at run time so
    /// no scanner reads a literal credential here.
    pub(crate) fn secret() -> String {
        format!("vcf_test_{}", "5d0a8e17c3b2")
    }

    /// Write `text` to `dir/name`, mode 0600.
    pub(crate) fn private_file(
        dir: &std::path::Path,
        name: &str,
        text: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("{text}\n"))?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }

    /// The encryption fixture `name`, copied to `dir` with mode 0600: a
    /// private key other users can read is refused, and git checks the
    /// fixtures out 0644.
    pub(crate) fn private_copy(
        dir: &std::path::Path,
        name: &str,
    ) -> std::io::Result<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::copy(format!("{JOSE}/{name}"), &path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }

    /// A synthetic unsigned container with `uuid`. Not anyone's call.
    pub(crate) fn container(uuid: &str) -> String {
        format!(
            r#"{{"vcon":"0.4.0","uuid":"{uuid}","created_at":"2026-10-07T12:00:00+00:00","parties":[{{"tel":"+15550100001"}},{{"tel":"+15550100002"}}],"dialog":[],"attachments":[],"analysis":[]}}"#
        )
    }

    /// [`container`], signed and encrypted to the fixture certificate, as an
    /// encrypting `[[vcon.rule]]` writes it.
    pub(crate) fn sealed(uuid: &str) -> Result<String, Box<dyn std::error::Error>> {
        use crate::output::vcon_jose::{Recipient, Signer, seal};
        let key = std::fs::read_to_string(format!("{JOSE}/fake_grp.key"))?;
        let cert = std::fs::read_to_string(format!("{JOSE}/fake_grp.crt"))?;
        let bytes = seal(
            container(uuid).as_bytes(),
            uuid,
            &Signer::from_pem(&key, &cert)?,
            &Recipient::from_cert_pem(&cert)?,
        )?;
        Ok(String::from_utf8(bytes)?)
    }

    /// [`container`] signed with the fixture key and certificate, not
    /// encrypted. With `tamper`, the signature's first character is changed,
    /// so it does not verify.
    pub(crate) fn signed(uuid: &str, tamper: bool) -> Result<String, Box<dyn std::error::Error>> {
        use crate::output::vcon_jose::{Signer, sign};
        let key = std::fs::read_to_string(format!("{JOSE}/fake_grp.key"))?;
        let cert = std::fs::read_to_string(format!("{JOSE}/fake_grp.crt"))?;
        let bytes = sign(
            container(uuid).as_bytes(),
            uuid,
            &Signer::from_pem(&key, &cert)?,
        )?;
        if !tamper {
            return Ok(String::from_utf8(bytes)?);
        }
        let mut jws: serde_json::Value = serde_json::from_slice(&bytes)?;
        let sig = jws["signatures"][0]["signature"]
            .as_str()
            .ok_or("signature")?
            .to_string();
        let flipped = if sig.starts_with('A') { "B" } else { "A" };
        jws["signatures"][0]["signature"] = format!("{flipped}{}", &sig[1..]).into();
        Ok(jws.to_string())
    }

    /// The fixture certificate's SHA-256 fingerprint, as openssl prints it.
    pub(crate) fn fixture_fingerprint() -> Result<String, Box<dyn std::error::Error>> {
        use base64::Engine as _;
        use sha2::Digest as _;
        let pem = std::fs::read_to_string(format!("{JOSE}/fake_grp.crt"))?;
        let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der = base64::engine::general_purpose::STANDARD.decode(b64)?;
        Ok(sha2::Sha256::digest(&der)
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"))
    }
}
