// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! SCITT lifecycle statements for the vCon forwarder.
//!
//! When the forwarder delivers a container, it registers the lifecycle
//! events of
//! [draft-howe-vcon-lifecycle-01 section 5](https://datatracker.ietf.org/doc/html/draft-howe-vcon-lifecycle-01#section-5)
//! with a SCITT transparency service:
//!
//! - `vcon_created` for a container sipnab wrote once (no `updated_at`, or
//!   one equal to `created_at`). The capture process makes no outbound
//!   connection, so the forwarder registers the creation when it first
//!   handles the container.
//! - `vcon_sent` for every delivery: "recording what was sent, to whom, and
//!   when".
//!
//! The lifecycle draft names the events and defines no statement format, so
//! the statement follows the drafts that do define one:
//!
//! - [draft-ietf-scitt-architecture-22 section 6](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22#section-6):
//!   a COSE_Sign1 whose protected header carries the CWT Claims (label 15)
//!   with `iss` and `sub`, and, with X.509, `x5chain` (33). `iss` is a URI.
//! - [draft-ietf-scitt-scrapi-11 section 2.3](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.3):
//!   POSTed to `/entries` as `application/cose`, answered by `201` with the
//!   receipt or `202` with a `Location` to poll.
//! - [draft-ietf-scitt-scrapi-11 section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.4):
//!   a GET on that `Location` answers `200` with the receipt, `204` while
//!   the registration is running, or `404` when it failed. The forwarder
//!   polls it within its timeout, and only on the service's own origin.
//!
//! What sipnab chose where the drafts leave it open:
//!
//! - `alg` follows the key, as it does for an encrypting `[[vcon.rule]]`'s
//!   signing key: ES256 (`-7`, [RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1))
//!   for an EC P-256 key, RS256 (`-257`, [RFC 8812 section 2](https://www.rfc-editor.org/rfc/rfc8812.html#section-2))
//!   for an RSA key. A transparency service whose registration policy
//!   admits other algorithms only refuses it, and the record says so.
//! - `sub` is `urn:uuid:<uuid>` ([RFC 9562 section 4](https://www.rfc-editor.org/rfc/rfc9562.html#section-4)),
//!   so every statement about one vCon shares a subject.
//! - The payload is a JSON object naming the event, the vCon's `uuid`, the
//!   `sha512-` hash of the bytes delivered, the time, and, for `vcon_sent`,
//!   the store's URL. It carries no party data.
//!
//! The forwarder writes what each registration returned to `<name>.scitt`
//! beside the delivered container. A registration that fails is recorded
//! there and not retried: the store already holds the container. A receipt
//! still running when the timeout ran out is recorded as `pending`, with
//! its `Location`.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::app::vcon_forward::{AuthHeader, Endpoint};
use crate::output::vcon_jose::Signer;

/// The suffix of the record the forwarder writes beside a delivered
/// container. Not `.json`: the delivered directory counts `*.json` files as
/// containers.
pub const RECORD_SUFFIX: &str = ".scitt";

/// The most bytes of a receipt kept.
///
/// Not a setting: a receipt is a signature and an inclusion proof, a few
/// hundred bytes for a log of billions of entries; a longer answer is not
/// one.
const MAX_RECEIPT: usize = 64 * 1024;

/// The COSE algorithm of RS256, RSASSA-PKCS1-v1_5 with SHA-256,
/// [RFC 8812 section 2](https://www.rfc-editor.org/rfc/rfc8812.html#section-2).
const RS256: i64 = -257;

/// The COSE algorithm of ES256, ECDSA with SHA-256,
/// [RFC 9053 section 2.1](https://www.rfc-editor.org/rfc/rfc9053.html#section-2.1).
const ES256: i64 = -7;

/// The wait before the first poll of a `202`'s `Location` that names no
/// `Retry-After`; it doubles after each poll.
const FIRST_POLL_WAIT: Duration = Duration::from_millis(250);

/// The most GETs on one `Location`:
/// [SCRAPI section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-5.1)
/// has a client "cap the total number of retries". The forwarder timeout
/// bounds the polling first unless the service answers with `Retry-After: 0`.
const MAX_POLLS: u32 = 16;

/// The COSE `alg` of a statement signed by a signer whose JWS `alg` is
/// `jws_alg`: [`ES256`] for an EC P-256 key, [`RS256`] for an RSA key.
fn cose_alg(jws_alg: &str) -> i64 {
    if jws_alg == crate::output::vcon_jose::JWS_ALG_ES256 {
        ES256
    } else {
        RS256
    }
}

/// The longest `iss`,
/// [draft-ietf-scitt-architecture-22 section 6](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-22#section-6):
/// "The iss value's length MUST be between 1 and 8192 characters".
pub const MAX_ISSUER_LEN: usize = 8192;

/// A lifecycle event,
/// [draft-howe-vcon-lifecycle-01 section 5](https://datatracker.ietf.org/doc/html/draft-howe-vcon-lifecycle-01#section-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// `vcon_created`: "The initial vCon document as first recorded."
    Created,
    /// `vcon_sent`: "The vCon was sent to an external party."
    Sent,
}

impl Event {
    /// The event's name in the draft.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "vcon_created",
            Self::Sent => "vcon_sent",
        }
    }
}

/// The key the statements are signed with, and its certificate chain.
pub struct ScittSigner {
    /// The RSA or EC P-256 key, as an encrypting `[[vcon.rule]]` loads it.
    signer: Signer,
    /// The chain as `x5chain` carries it: DER, leaf first.
    chain: Vec<Vec<u8>>,
}

impl ScittSigner {
    /// A signer from a PEM private key, RSA (RS256) or EC P-256 (ES256),
    /// and its PEM certificate chain, leaf first. [`Signer::from_pem`]
    /// checks that the leaf is the key's.
    ///
    /// # Errors
    ///
    /// The key or the chain does not load, or the leaf is another key's.
    pub fn from_pem(key_pem: &str, chain_pem: &str) -> Result<Self, String> {
        use base64::Engine as _;
        let signer = Signer::from_pem(key_pem, chain_pem)?;
        let mut chain = Vec::new();
        for block in chain_pem.split("-----BEGIN CERTIFICATE-----").skip(1) {
            let text: String = block
                .split("-----END CERTIFICATE-----")
                .next()
                .unwrap_or_default()
                .split_whitespace()
                .collect();
            chain.push(
                base64::engine::general_purpose::STANDARD
                    .decode(text)
                    .map_err(|e| format!("a certificate in the chain is not base64: {e}"))?,
            );
        }
        if chain.is_empty() {
            return Err("the chain holds no certificate".into());
        }
        Ok(Self { signer, chain })
    }
}

/// Where lifecycle statements are registered, and what signs them.
#[derive(Clone)]
pub struct ScittSettings {
    /// The transparency service's base URL; statements go to `<url>/entries`.
    pub url: Endpoint,
    /// The header that authenticates to it.
    pub auth: Option<AuthHeader>,
    /// The only CA file trusted for an `https://` service; the host's bundle
    /// when `None`.
    pub ca: Option<PathBuf>,
    /// The key and chain the statements are signed with.
    pub signer: Arc<ScittSigner>,
    /// The statements' `iss`, a URI.
    pub issuer: String,
}

/// Names no key material and no credential.
impl std::fmt::Debug for ScittSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScittSettings")
            .field("url", &self.url)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

/// Whether `issuer` is a URI an `iss` may hold: a scheme, `:`, and more,
/// with no whitespace, from 1 to [`MAX_ISSUER_LEN`] characters.
///
/// The scheme is [RFC 3986 section 3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1)'s
/// `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
#[must_use]
pub fn is_uri(issuer: &str) -> bool {
    let Some((scheme, rest)) = issuer.split_once(':') else {
        return false;
    };
    let mut chars = scheme.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && !rest.is_empty()
        && !issuer.chars().any(char::is_whitespace)
        && issuer.chars().count() <= MAX_ISSUER_LEN
}

/// `urn:uuid:<uuid>` when `uuid` is a UUID's text form, 8-4-4-4-12
/// hexadecimal digits.
#[must_use]
pub fn subject(uuid: &str) -> Option<String> {
    let groups: Vec<&str> = uuid.split('-').collect();
    let shaped = groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, n)| g.len() == n && g.chars().all(|c| c.is_ascii_hexdigit()));
    shaped.then(|| format!("urn:uuid:{}", uuid.to_ascii_lowercase()))
}

/// One CBOR data item ([RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html)),
/// the kinds a COSE_Sign1 needs.
enum Cbor {
    /// An integer, major type 0 or 1.
    Int(i64),
    /// A byte string, major type 2.
    Bytes(Vec<u8>),
    /// A text string, major type 3.
    Text(String),
    /// An array, major type 4.
    Array(Vec<Cbor>),
    /// A map, major type 5, written in the order given.
    Map(Vec<(Cbor, Cbor)>),
    /// A tagged item, major type 6.
    Tag(u64, Box<Cbor>),
}

impl Cbor {
    /// The item's encoding, every length in its shortest form, as
    /// [RFC 8949 section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)
    /// requires of deterministic encoding.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write(&mut out);
        out
    }

    /// Append the item's encoding to `out`.
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Int(n) if *n >= 0 => head(out, 0, n.unsigned_abs()),
            // -1 - n, for a negative n, is |n| - 1.
            Self::Int(n) => head(out, 1, n.unsigned_abs() - 1),
            Self::Bytes(b) => {
                head(out, 2, b.len() as u64);
                out.extend_from_slice(b);
            }
            Self::Text(t) => {
                head(out, 3, t.len() as u64);
                out.extend_from_slice(t.as_bytes());
            }
            Self::Array(items) => {
                head(out, 4, items.len() as u64);
                for item in items {
                    item.write(out);
                }
            }
            Self::Map(pairs) => {
                head(out, 5, pairs.len() as u64);
                for (k, v) in pairs {
                    k.write(out);
                    v.write(out);
                }
            }
            Self::Tag(tag, item) => {
                head(out, 6, *tag);
                item.write(out);
            }
        }
    }
}

/// A data item's initial byte and argument,
/// [RFC 8949 section 3](https://www.rfc-editor.org/rfc/rfc8949.html#section-3).
fn head(out: &mut Vec<u8>, major: u8, n: u64) {
    let major = major << 5;
    match n {
        0..=23 => out.push(major | n as u8),
        24..=0xff => out.extend_from_slice(&[major | 24, n as u8]),
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
}

/// The facts one statement records.
#[derive(Debug, Clone, Copy)]
pub struct Facts<'a> {
    /// Which event.
    pub event: Event,
    /// The container's `uuid`.
    pub uuid: &'a str,
    /// The container's bytes, as delivered.
    pub container: &'a [u8],
    /// When: the container's `created_at` for `vcon_created`, the delivery
    /// time for `vcon_sent`. RFC 3339.
    pub at: &'a str,
    /// The store's URL, for `vcon_sent`.
    pub to: Option<&'a str>,
    /// The statement's `iat`, seconds since the epoch.
    pub issued_at: i64,
}

/// The Signed Statement for `facts`: a tagged COSE_Sign1,
/// [RFC 9052 section 4.2](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2),
/// signed over the Sig_structure of
/// [RFC 9052 section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
///
/// # Errors
///
/// The `uuid` is not a UUID, or the signature fails.
pub fn statement(facts: &Facts<'_>, settings: &ScittSettings) -> Result<Vec<u8>, String> {
    let sub = subject(facts.uuid)
        .ok_or_else(|| format!("the container's uuid {:?} is not a UUID", facts.uuid))?;
    let mut payload = serde_json::json!({
        "event": facts.event.as_str(),
        "vcon_uuid": facts.uuid,
        "vcon_hash": crate::app::vcon_hash::token(facts.container),
        "at": facts.at,
    });
    if let Some(to) = facts.to {
        payload["to"] = to.into();
    }
    let payload = crate::app::vcon_hash::jcs(&payload).into_bytes();
    let chain = &settings.signer.chain;
    let x5chain = match chain.as_slice() {
        [one] => Cbor::Bytes(one.clone()),
        many => Cbor::Array(many.iter().cloned().map(Cbor::Bytes).collect()),
    };
    // Labels in ascending order, the order RFC 8949 section 4.2.1 gives
    // their encodings: 1, 3, 15 (one byte each), then 33.
    let protected = Cbor::Map(vec![
        (
            Cbor::Int(1),
            Cbor::Int(cose_alg(settings.signer.signer.alg())),
        ),
        (Cbor::Int(3), Cbor::Text("application/json".into())),
        (
            Cbor::Int(15),
            Cbor::Map(vec![
                (Cbor::Int(1), Cbor::Text(settings.issuer.clone())),
                (Cbor::Int(2), Cbor::Text(sub)),
                (Cbor::Int(6), Cbor::Int(facts.issued_at)),
            ]),
        ),
        (Cbor::Int(33), x5chain),
    ])
    .encode();
    let to_be_signed = Cbor::Array(vec![
        Cbor::Text("Signature1".into()),
        Cbor::Bytes(protected.clone()),
        Cbor::Bytes(Vec::new()),
        Cbor::Bytes(payload.clone()),
    ])
    .encode();
    let signature = settings.signer.signer.sign_input(&to_be_signed)?;
    Ok(Cbor::Tag(
        18,
        Box::new(Cbor::Array(vec![
            Cbor::Bytes(protected),
            Cbor::Map(Vec::new()),
            Cbor::Bytes(payload),
            Cbor::Bytes(signature),
        ])),
    )
    .encode())
}

/// What one registration returned, as the record holds it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Registration {
    /// The event.
    pub event: &'static str,
    /// The HTTP status; absent when no answer came.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// The `Location` of the receipt resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The receipt, base64url: of a `201`, or of the `200` a GET on a
    /// `202`'s `Location` answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Why it did not register: the POST's refusal, or a `4xx` a GET on
    /// the `Location` answered (a registration that failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The HTTP status of the last GET on a `202`'s `Location`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_status: Option<u16>,
    /// The receipt had not come when the forwarder timeout ran out or a
    /// stop was asked for: the registration is running, and the receipt
    /// can be fetched from `location` later.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
    /// Why the `Location` was not polled (another origin than the service
    /// URL, or no `Location`), or the last answer that was not a receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub poll_error: Option<String>,
}

impl Registration {
    /// A registration of `event` with nothing recorded yet.
    fn of(event: Event) -> Self {
        Self {
            event: event.as_str(),
            status: None,
            location: None,
            receipt: None,
            error: None,
            poll_status: None,
            pending: false,
            poll_error: None,
        }
    }

    /// A registration of `event` that did not happen, and why.
    fn failed(event: Event, why: String) -> Self {
        Self {
            error: Some(why),
            ..Self::of(event)
        }
    }
}

/// The events to register for the delivered `container`: `vcon_created`
/// when it has no `updated_at` or one equal to `created_at`, then
/// `vcon_sent`. With the container's `uuid` and `created_at`.
///
/// # Errors
///
/// The container is not JSON or has no `uuid`.
fn events(container: &[u8]) -> Result<(Vec<Event>, String, String), String> {
    let doc: serde_json::Value =
        serde_json::from_slice(container).map_err(|e| format!("the container is not JSON: {e}"))?;
    let uuid = doc["uuid"]
        .as_str()
        .ok_or("the container has no uuid")?
        .to_owned();
    let created = doc["created_at"].as_str().unwrap_or_default().to_owned();
    let first = match doc.get("updated_at") {
        None | Some(serde_json::Value::Null) => true,
        Some(updated) => updated.as_str() == Some(created.as_str()),
    };
    let mut out = Vec::new();
    if first {
        out.push(Event::Created);
    }
    out.push(Event::Sent);
    Ok((out, uuid, created))
}

/// Register the lifecycle statements for one delivered container. Returns
/// the record's text, and whether every statement registered (`201` or
/// `202`).
///
/// A `202`'s `Location` is polled for the receipt until the registration's
/// `timeout` runs out, and only on the service's origin
/// ([`receipt_endpoint`]). Once `stop` says so, polling ends and
/// no further statement is sent.
///
/// # Arguments
///
/// * `container` — the bytes the store accepted.
/// * `store` — the store's URL, the `to` of `vcon_sent`.
/// * `timeout` — the connect, read and write timeout, and the most time
///   one registration, its POST and its polling, takes.
/// * `tls` — the client configuration for an `https://` service.
/// * `stop` — whether a stop was asked for.
#[must_use]
pub fn register_delivery(
    settings: &ScittSettings,
    tls: Option<&Arc<rustls::ClientConfig>>,
    timeout: Duration,
    container: &[u8],
    store: &str,
    stop: &dyn Fn() -> bool,
) -> (String, bool) {
    let now = chrono::Utc::now();
    let sent_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let statements: Vec<Registration> = match events(container) {
        Err(why) => vec![Registration::failed(Event::Sent, why)],
        Ok((events, uuid, created)) => events
            .into_iter()
            .map(|event| {
                if stop() {
                    return Registration::failed(
                        event,
                        "not sent: a stop was asked for".to_owned(),
                    );
                }
                let facts = Facts {
                    event,
                    uuid: &uuid,
                    container,
                    at: if event == Event::Created {
                        &created
                    } else {
                        &sent_at
                    },
                    to: (event == Event::Sent).then_some(store),
                    issued_at: now.timestamp(),
                };
                match statement(&facts, settings) {
                    Ok(bytes) => {
                        let link = Link {
                            settings,
                            tls,
                            timeout,
                            deadline: Instant::now() + timeout,
                            stop,
                        };
                        register(&link, event, &bytes)
                    }
                    Err(why) => Registration::failed(event, why),
                }
            })
            .collect(),
    };
    let all = statements.iter().all(|s| s.error.is_none());
    let record = serde_json::json!({ "statements": statements });
    (
        serde_json::to_string_pretty(&record).unwrap_or_else(|_| record.to_string()),
        all,
    )
}

/// `url` with `/entries` appended to its path, the resource of
/// [SCRAPI section 2.3](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.3).
#[must_use]
pub fn entries(url: &Endpoint) -> Endpoint {
    let mut out = url.clone();
    let (path, query) = match url.target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (url.target.as_str(), None),
    };
    let mut target = format!("{}/entries", path.trim_end_matches('/'));
    if let Some(q) = query {
        target.push('?');
        target.push_str(q);
    }
    out.target = target;
    out
}

/// What one registration talks to the transparency service with.
struct Link<'a> {
    /// The service.
    settings: &'a ScittSettings,
    /// The client configuration for an `https://` service.
    tls: Option<&'a Arc<rustls::ClientConfig>>,
    /// The connect, read and write timeout.
    timeout: Duration,
    /// When the registration's time runs out: no poll starts after it.
    deadline: Instant,
    /// Whether a stop was asked for.
    stop: &'a dyn Fn() -> bool,
}

/// One answer of the transparency service.
struct Answer {
    /// The HTTP status.
    status: u16,
    /// The `Location` header.
    location: Option<String>,
    /// The wait the `Retry-After` header asks for.
    retry_after: Option<Duration>,
    /// At most [`MAX_RECEIPT`] bytes of the body; none for a `202` or a
    /// `204`, which carry none.
    body: Vec<u8>,
    /// The body was longer.
    truncated: bool,
}

impl Link<'_> {
    /// `text` with the service's credential removed.
    fn scrub(&self, text: String) -> String {
        match &self.settings.auth {
            Some(auth) => auth.scrub(&text),
            None => text,
        }
    }

    /// Send `method` to `endpoint`, with `body` as `application/cose` when
    /// given, and read the answer, `io` the connect, read and write timeout.
    fn send(
        &self,
        endpoint: &Endpoint,
        method: &str,
        body: Option<&[u8]>,
        io: Duration,
    ) -> Result<Answer, String> {
        use std::fmt::Write as _;
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\n",
            endpoint.target,
            endpoint.host_header(),
            crate::app::vcon_forward::USER_AGENT,
        );
        if let Some(body) = body {
            let _ = write!(
                head,
                "Content-Type: application/cose\r\nContent-Length: {}\r\n",
                body.len()
            );
        }
        head.push_str("Accept: application/cose\r\nConnection: close\r\n");
        if let Some(auth) = &self.settings.auth {
            head.push_str(&auth.line());
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        let mut request = head.into_bytes();
        if let Some(body) = body {
            request.extend_from_slice(body);
        }
        crate::app::vcon_forward::exchange(
            endpoint,
            io,
            self.tls,
            &request,
            |reader: &mut dyn BufRead| {
                use crate::app::vcon_forward::header_value;
                let head = crate::app::vcon_forward::read_head(
                    reader,
                    64 * 1024,
                    "--vcon-forward-scitt-url",
                )?;
                let status = crate::app::vcon_forward::status_of(&head)?;
                let (body, truncated) = if matches!(status, 202 | 204) {
                    (Vec::new(), false)
                } else {
                    crate::app::vcon_forward::read_body(reader, &head, MAX_RECEIPT)
                };
                Ok(Answer {
                    status,
                    location: header_value(&head, "location").map(str::to_owned),
                    retry_after: header_value(&head, "retry-after")
                        .and_then(|v| retry_after(v, chrono::Utc::now())),
                    body,
                    truncated,
                })
            },
        )
        .map_err(|e| self.scrub(e))
    }
}

/// POST `statement` to the service and read what it answered; for a `202`,
/// [`poll`] its `Location` for the receipt.
fn register(link: &Link<'_>, event: Event, statement: &[u8]) -> Registration {
    let mut out = Registration::of(event);
    let answer = match link.send(
        &entries(&link.settings.url),
        "POST",
        Some(statement),
        link.timeout,
    ) {
        Ok(answer) => answer,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    out.status = Some(answer.status);
    out.location.clone_from(&answer.location);
    match answer.status {
        201 => keep_receipt(&mut out, &answer),
        202 => match &answer.location {
            None => {
                out.poll_error = Some(
                    "not polled: the 202 names no Location (SCRAPI section 2.3.2 requires one)"
                        .into(),
                );
            }
            Some(location) => match receipt_endpoint(&link.settings.url, location) {
                Err(why) => out.poll_error = Some(link.scrub(why)),
                Ok(at) => poll(link, &at, answer.retry_after, &mut out),
            },
        },
        _ => out.error = Some(link.scrub(problem(&answer.body))),
    }
    out
}

/// Keep `answer`'s body as the receipt, unless it was cut short.
fn keep_receipt(out: &mut Registration, answer: &Answer) {
    use base64::Engine as _;
    if answer.truncated {
        out.error = Some(format!("the receipt is longer than {MAX_RECEIPT} bytes"));
    } else {
        out.receipt = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&answer.body));
    }
}

/// Poll `at`, a `202`'s `Location`, for the receipt,
/// [SCRAPI section 2.4](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2.4):
/// a GET with `Accept: application/cose`, answered `200` with the receipt,
/// `204` while the registration is running, or `404` when it failed.
///
/// - `200`: the body is the receipt; polling ends.
/// - `204`, or `202`: still running (RFC 9110's `202` is "not yet
///   completed"); poll again.
/// - `429` or a `5xx`: poll again; the record keeps the answer as
///   `poll_error` until a later one replaces it.
/// - Any other `4xx`: the registration failed; its problem is the error.
/// - Anything else ends polling, recorded as `poll_error`.
///
/// Each poll waits first: the `Retry-After` of the last answer, a minimum
/// ([SCRAPI section 5.1](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-5.1)),
/// else [`poll_wait`]'s jittered doubling. A wait that would reach the
/// deadline, [`MAX_POLLS`] polls, or a stop ends polling with the receipt
/// `pending`.
fn poll(link: &Link<'_>, at: &Endpoint, first: Option<Duration>, out: &mut Registration) {
    let mut retry = first;
    for attempt in 0..MAX_POLLS {
        let wait = poll_wait(retry, attempt, jitter());
        if wait >= link.deadline.saturating_duration_since(Instant::now()) {
            out.pending = true;
            return;
        }
        if !crate::app::vcon_forward::sleep_unless_stopped(wait, link.stop) {
            out.pending = true;
            out.poll_error = Some("polling ended: a stop was asked for".into());
            return;
        }
        let left = link.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            out.pending = true;
            return;
        }
        let answer = match link.send(at, "GET", None, link.timeout.min(left)) {
            Ok(answer) => answer,
            Err(e) => {
                out.poll_error = Some(e);
                retry = None;
                continue;
            }
        };
        out.poll_status = Some(answer.status);
        retry = answer.retry_after;
        match answer.status {
            200 => {
                out.poll_error = None;
                keep_receipt(out, &answer);
                return;
            }
            202 | 204 => out.poll_error = None,
            429 | 500..=599 => {
                out.poll_error =
                    Some(link.scrub(format!("{}: {}", answer.status, problem(&answer.body))));
            }
            400..=499 => {
                out.error = Some(link.scrub(problem(&answer.body)));
                return;
            }
            other => {
                out.poll_error = Some(format!(
                    "polling ended: the Location answered {other}, not a receipt"
                ));
                return;
            }
        }
    }
    out.pending = true;
}

/// A random byte, the jitter of [`poll_wait`]; 255 (no jitter) when the
/// system has none to give.
fn jitter() -> u8 {
    use ring::rand::SecureRandom as _;
    let mut byte = [u8::MAX];
    let _ = ring::rand::SystemRandom::new().fill(&mut byte);
    byte[0]
}

/// The wait before poll number `attempt` (0 for the first): `retry_after`
/// when the last answer named one; else [`FIRST_POLL_WAIT`] doubled per
/// attempt, scaled by `jitter` to between half (0) and all (255) of it,
/// which SCRAPI section 5.1 asks of a client without a `Retry-After`:
/// "exponential backoff with jitter".
fn poll_wait(retry_after: Option<Duration>, attempt: u32, jitter: u8) -> Duration {
    if let Some(wait) = retry_after {
        return wait;
    }
    let full = FIRST_POLL_WAIT.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
    full / 2 + full.saturating_mul(u32::from(jitter)) / 510
}

/// The wait a `Retry-After` value asks for, at `now`:
/// [RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3)'s
/// delay-seconds, or an HTTP-date in any of the three forms
/// [section 5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7)
/// has a recipient accept. A date in the past is no wait; anything else is
/// no value.
#[must_use]
pub fn retry_after(value: &str, now: chrono::DateTime<chrono::Utc>) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return Some(
            value
                .parse::<u64>()
                .map_or(Duration::MAX, Duration::from_secs),
        );
    }
    let at = chrono::DateTime::parse_from_rfc2822(value)
        .map(|d| d.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            // rfc850-date, then asctime-date.
            ["%A, %d-%b-%y %H:%M:%S GMT", "%a %b %e %H:%M:%S %Y"]
                .iter()
                .find_map(|form| chrono::NaiveDateTime::parse_from_str(value, form).ok())
                .map(|naive| naive.and_utc())
        })?;
    Some((at - now).to_std().unwrap_or(Duration::ZERO))
}

/// The endpoint a `202`'s `location` names, which must be on the service's
/// origin: the scheme, host and port of `service`. A path alone
/// (`/entries/1`) is on it.
///
/// # Errors
///
/// `location` is not an `http://` or `https://` URL or an absolute path, or
/// it is on another origin. The forwarder does not poll it: the service's
/// credential goes only to the service.
pub fn receipt_endpoint(service: &Endpoint, location: &str) -> Result<Endpoint, String> {
    let scheme = if service.tls { "https" } else { "http" };
    let origin = format!("{scheme}://{}", service.host_header());
    let absolute = if location.starts_with('/') && !location.starts_with("//") {
        format!("{origin}{location}")
    } else {
        location.to_owned()
    };
    let refuse = |why: &str| {
        format!(
            "not polled: the Location {location:?} is not on the transparency service's origin \
             {origin}{why}"
        )
    };
    let at = Endpoint::parse(&absolute, crate::app::https_client::UrlUse::DOWNLOAD)
        .map_err(|e| refuse(&format!(" ({e})")))?;
    if at.tls != service.tls
        || !at.host.eq_ignore_ascii_case(&service.host)
        || at.port != service.port
    {
        return Err(refuse(""));
    }
    Ok(at)
}

/// A refusal's body in words: the `title` and `detail` of an RFC 9290
/// Concise Problem Details object, which
/// [SCRAPI section 2](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11#section-2)
/// requires of every error, else the start of the body as text.
fn problem(body: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Some(pairs) = read_map(body) {
        for label in [-1, -2] {
            if let Some((_, text)) = pairs.iter().find(|(k, _)| *k == label) {
                parts.push(text.clone());
            }
        }
    }
    if parts.is_empty() {
        let text = String::from_utf8_lossy(body);
        return text.chars().take(200).collect();
    }
    parts.join(": ")
}

/// A CBOR map of integer keys to text, the shape of a Concise Problem
/// Details object; members of any other shape end the read. `None` when the
/// body is not a map.
fn read_map(body: &[u8]) -> Option<Vec<(i64, String)>> {
    let mut at = 0usize;
    let (major, count) = argument(body, &mut at)?;
    if major != 5 {
        return None;
    }
    let mut out = Vec::new();
    for _ in 0..count {
        let (kmajor, karg) = argument(body, &mut at)?;
        let key = match kmajor {
            0 => i64::try_from(karg).ok()?,
            1 => -1 - i64::try_from(karg).ok()?,
            _ => break,
        };
        let (vmajor, len) = argument(body, &mut at)?;
        if vmajor != 3 {
            break;
        }
        let len = usize::try_from(len).ok()?;
        let text = body.get(at..at.checked_add(len)?)?;
        at += len;
        out.push((key, String::from_utf8_lossy(text).into_owned()));
    }
    Some(out)
}

/// The major type and argument of the data item at `*at`, advancing past
/// the head.
fn argument(body: &[u8], at: &mut usize) -> Option<(u8, u64)> {
    let first = *body.get(*at)?;
    *at += 1;
    let (major, info) = (first >> 5, first & 0x1f);
    let width = match info {
        0..=23 => return Some((major, u64::from(info))),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return None,
    };
    let bytes = body.get(*at..*at + width)?;
    *at += width;
    Some((
        major,
        bytes.iter().fold(0u64, |n, b| (n << 8) | u64::from(*b)),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shortest-form heads, at each width boundary, and negative integers,
    /// as RFC 8949 Appendix A lists them.
    #[test]
    fn cbor_encodes_as_rfc_8949_appendix_a_lists() {
        for (item, hex) in [
            (Cbor::Int(0), "00"),
            (Cbor::Int(23), "17"),
            (Cbor::Int(24), "1818"),
            (Cbor::Int(1000), "1903e8"),
            (Cbor::Int(1_000_000), "1a000f4240"),
            (Cbor::Int(1_000_000_000_000), "1b000000e8d4a51000"),
            (Cbor::Int(-1), "20"),
            (Cbor::Int(-100), "3863"),
            (Cbor::Int(-1000), "3903e7"),
            (Cbor::Text("IETF".into()), "6449455446"),
            (Cbor::Bytes(vec![1, 2, 3, 4]), "4401020304"),
            (
                Cbor::Array(vec![Cbor::Int(1), Cbor::Int(2), Cbor::Int(3)]),
                "83010203",
            ),
            (
                Cbor::Map(vec![
                    (Cbor::Int(1), Cbor::Int(2)),
                    (Cbor::Int(3), Cbor::Int(4)),
                ]),
                "a201020304",
            ),
            (
                Cbor::Tag(1, Box::new(Cbor::Int(1_363_896_240))),
                "c11a514b67b0",
            ),
        ] {
            let got: String = item.encode().iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, hex);
        }
    }

    /// An `iss` is a URI: a scheme and more, no whitespace.
    #[test]
    fn an_issuer_is_a_uri() {
        for good in [
            "https://pbx.example.com/sipnab",
            "urn:example:sipnab",
            "a+b.c-d:x",
        ] {
            assert!(is_uri(good), "{good}");
        }
        for bad in [
            "",
            "sipnab",
            ":x",
            "1http://x",
            "https:",
            "https://a b",
            "ht_tp://x",
        ] {
            assert!(!is_uri(bad), "{bad}");
        }
        assert!(!is_uri(&format!("urn:{}", "x".repeat(MAX_ISSUER_LEN))));
    }

    /// A subject is a UUID's URN; anything else is not one.
    #[test]
    fn a_subject_is_a_uuid_urn() {
        assert_eq!(
            subject("018BCFE5-6800-8F87-BED9-9FAC32562404").as_deref(),
            Some("urn:uuid:018bcfe5-6800-8f87-bed9-9fac32562404")
        );
        for bad in [
            "",
            "018bcfe5-6800-8f87-bed9",
            "018bcfe5-6800-8f87-bed9-9fac3256240g",
        ] {
            assert_eq!(subject(bad), None, "{bad}");
        }
    }

    /// `vcon_created` only for a container written once.
    #[test]
    fn created_is_registered_for_the_first_version_only() -> Result<(), String> {
        let once = br#"{"uuid":"u","created_at":"t1"}"#;
        let same = br#"{"uuid":"u","created_at":"t1","updated_at":"t1"}"#;
        let later = br#"{"uuid":"u","created_at":"t1","updated_at":"t2"}"#;
        assert_eq!(events(once)?.0, [Event::Created, Event::Sent]);
        assert_eq!(events(same)?.0, [Event::Created, Event::Sent]);
        assert_eq!(events(later)?.0, [Event::Sent]);
        Ok(())
    }

    /// The entries resource is the base path and `/entries`, the query
    /// kept.
    #[test]
    fn the_entries_resource_follows_the_base_path() -> Result<(), String> {
        for (base, target) in [
            ("http://127.0.0.1:1/", "/entries"),
            ("http://127.0.0.1:1/scitt", "/scitt/entries"),
            ("http://127.0.0.1:1/scitt/", "/scitt/entries"),
            ("http://127.0.0.1:1/s?tenant=a", "/s/entries?tenant=a"),
        ] {
            assert_eq!(
                entries(&Endpoint::parse(
                    base,
                    crate::app::https_client::UrlUse::FORWARDER_SCITT
                )?)
                .target,
                target,
                "{base}"
            );
        }
        Ok(())
    }

    /// A Concise Problem Details object reads as its title and detail;
    /// anything else as its start.
    #[test]
    fn a_problem_reads_as_its_title_and_detail() {
        // {-1: "Bad", -2: "why"}
        let cbor = [
            0xa2, 0x20, 0x63, b'B', b'a', b'd', 0x21, 0x63, b'w', b'h', b'y',
        ];
        assert_eq!(problem(&cbor), "Bad: why");
        assert_eq!(problem(b"plain refusal"), "plain refusal");
    }

    /// An EC P-256 signer's statements carry ES256 (-7, RFC 9053 section
    /// 2.1); an RSA signer's RS256 (-257, [RFC 8812 section 2](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)).
    #[test]
    fn the_cose_alg_follows_the_key() {
        assert_eq!(cose_alg(crate::output::vcon_jose::JWS_ALG_ES256), -7);
        assert_eq!(cose_alg(crate::output::vcon_jose::JWS_ALG), -257);
    }

    /// `Retry-After` is delay-seconds or an HTTP-date in any of the three
    /// forms [RFC 9110 section 5.6.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.7) has a recipient accept; anything else
    /// is no value.
    #[test]
    fn retry_after_reads_seconds_and_each_http_date_form() -> Result<(), String> {
        let now = chrono::DateTime::parse_from_rfc3339("1994-11-06T08:49:30Z")
            .map_err(|e| e.to_string())?
            .with_timezone(&chrono::Utc);
        let seven = Some(Duration::from_secs(7));
        assert_eq!(retry_after("0", now), Some(Duration::ZERO));
        assert_eq!(retry_after(" 120 ", now), Some(Duration::from_secs(120)));
        assert_eq!(
            retry_after("99999999999999999999999", now),
            Some(Duration::MAX),
            "too many seconds to count is still a wait"
        );
        assert_eq!(retry_after("Sun, 06 Nov 1994 08:49:37 GMT", now), seven);
        assert_eq!(retry_after("Sunday, 06-Nov-94 08:49:37 GMT", now), seven);
        assert_eq!(retry_after("Sun Nov  6 08:49:37 1994", now), seven);
        assert_eq!(
            retry_after("Sun, 06 Nov 1994 08:00:00 GMT", now),
            Some(Duration::ZERO),
            "a date in the past is no wait"
        );
        for bad in ["", "-1", "1.5", "soon", "5 s"] {
            assert_eq!(retry_after(bad, now), None, "{bad:?}");
        }
        Ok(())
    }

    /// Without `Retry-After` the wait starts at [`FIRST_POLL_WAIT`] and
    /// doubles each poll, scaled by the jitter to between half and all of
    /// it; with one, it is that value.
    #[test]
    fn a_poll_waits_for_retry_after_else_a_jittered_doubling() {
        let ms = Duration::from_millis;
        assert_eq!(poll_wait(None, 0, 255), FIRST_POLL_WAIT);
        assert_eq!(poll_wait(None, 0, 0), FIRST_POLL_WAIT / 2);
        assert_eq!(poll_wait(None, 1, 255), FIRST_POLL_WAIT * 2);
        assert_eq!(poll_wait(None, 3, 255), FIRST_POLL_WAIT * 8);
        for attempt in 0..MAX_POLLS {
            for jitter in [0, 128, 255] {
                let wait = poll_wait(None, attempt, jitter);
                let full = poll_wait(None, attempt, 255);
                assert!(wait >= full / 2 && wait <= full, "{attempt} {jitter}");
            }
        }
        assert_eq!(
            poll_wait(None, 200, 255),
            poll_wait(None, 63, 255),
            "no overflow"
        );
        assert_eq!(poll_wait(Some(ms(1500)), 4, 0), ms(1500));
        assert_eq!(poll_wait(Some(Duration::ZERO), 0, 255), Duration::ZERO);
    }

    /// A `Location` is polled only on the service's origin: its scheme,
    /// host and port. A path alone is on it.
    #[test]
    fn a_location_is_polled_only_on_the_services_origin() -> Result<(), String> {
        let service = Endpoint::parse(
            "https://ts.example:8443/scitt",
            crate::app::https_client::UrlUse::FORWARDER_SCITT,
        )?;
        for good in [
            "https://ts.example:8443/scitt/entries/1",
            "https://TS.example:8443/entries/1?x=1",
            "/scitt/entries/1",
        ] {
            let got = receipt_endpoint(&service, good)?;
            assert!(got.tls && got.port == 8443, "{good}");
            assert!(got.target.ends_with("entries/1") || got.target.ends_with("x=1"));
        }
        let plain = Endpoint::parse(
            "http://ts.example/scitt",
            crate::app::https_client::UrlUse::FORWARDER_SCITT,
        )?;
        assert_eq!(
            receipt_endpoint(&plain, "http://ts.example:80/e/1")?.target,
            "/e/1"
        );
        for bad in [
            "http://ts.example:8443/entries/1",
            "https://ts.example/entries/1",
            "https://other.example:8443/entries/1",
            "//other.example:8443/entries/1",
            "entries/1",
            "ftp://ts.example:8443/entries/1",
        ] {
            let why = receipt_endpoint(&service, bad).err().ok_or(bad)?;
            assert!(why.contains("origin"), "{bad}: {why}");
        }
        Ok(())
    }
}
