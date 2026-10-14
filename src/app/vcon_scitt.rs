// SPDX-License-Identifier: MIT OR Apache-2.0

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
//!
//! What sipnab chose where the drafts leave it open:
//!
//! - `alg` is RS256 (`-257`, [RFC 8812 section 2](https://www.rfc-editor.org/rfc/rfc8812.html#section-2)),
//!   so the key is the same kind of PEM RSA key an encrypting
//!   `[[vcon.rule]]` signs with. A transparency service whose registration
//!   policy admits other algorithms only refuses it, and the record says so.
//! - `sub` is `urn:uuid:<uuid>` ([RFC 9562 section 4](https://www.rfc-editor.org/rfc/rfc9562.html#section-4)),
//!   so every statement about one vCon shares a subject.
//! - The payload is a JSON object naming the event, the vCon's `uuid`, the
//!   `sha512-` hash of the bytes delivered, the time, and, for `vcon_sent`,
//!   the store's URL. It carries no party data.
//!
//! The forwarder writes what each registration returned to `<name>.scitt`
//! beside the delivered container. A registration that fails is recorded
//! there and not retried: the store already holds the container.

use std::io::BufRead;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
    /// The RSA key, as an encrypting `[[vcon.rule]]` loads it.
    signer: Signer,
    /// The chain as `x5chain` carries it: DER, leaf first.
    chain: Vec<Vec<u8>>,
}

impl ScittSigner {
    /// A signer from a PEM RSA private key and its PEM certificate chain,
    /// leaf first. [`Signer::from_pem`] checks that the leaf is the key's.
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
        (Cbor::Int(1), Cbor::Int(RS256)),
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
    let signature = settings.signer.signer.rs256(&to_be_signed)?;
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
    /// The receipt of a `201`, base64url.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Why it did not register.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
/// # Arguments
///
/// * `container` — the bytes the store accepted.
/// * `store` — the store's URL, the `to` of `vcon_sent`.
/// * `timeout` — the connect, read and write timeout.
/// * `tls` — the client configuration for an `https://` service.
#[must_use]
pub fn register_delivery(
    settings: &ScittSettings,
    tls: Option<&Arc<rustls::ClientConfig>>,
    timeout: Duration,
    container: &[u8],
    store: &str,
) -> (String, bool) {
    let now = chrono::Utc::now();
    let sent_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let statements: Vec<Registration> = match events(container) {
        Err(why) => vec![Registration {
            event: Event::Sent.as_str(),
            status: None,
            location: None,
            receipt: None,
            error: Some(why),
        }],
        Ok((events, uuid, created)) => events
            .into_iter()
            .map(|event| {
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
                    Ok(bytes) => register(settings, tls, timeout, event, &bytes),
                    Err(why) => Registration {
                        event: event.as_str(),
                        status: None,
                        location: None,
                        receipt: None,
                        error: Some(why),
                    },
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

/// POST `statement` to the service and read what it answered.
fn register(
    settings: &ScittSettings,
    tls: Option<&Arc<rustls::ClientConfig>>,
    timeout: Duration,
    event: Event,
    statement: &[u8],
) -> Registration {
    use base64::Engine as _;
    let endpoint = entries(&settings.url);
    let mut head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nContent-Type: application/cose\r\n\
         Accept: application/cose\r\nContent-Length: {}\r\nConnection: close\r\n",
        endpoint.target,
        endpoint.host_header(),
        crate::app::vcon_forward::USER_AGENT,
        statement.len()
    );
    if let Some(auth) = &settings.auth {
        head.push_str(&auth.line());
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    let mut request = head.into_bytes();
    request.extend_from_slice(statement);
    let scrub = |text: String| match &settings.auth {
        Some(auth) => auth.scrub(&text),
        None => text,
    };
    let answered = crate::app::vcon_forward::exchange(
        &endpoint,
        timeout,
        tls,
        &request,
        |reader: &mut dyn BufRead| {
            let head =
                crate::app::vcon_forward::read_head(reader, 64 * 1024, "--vcon-forward-scitt-url")?;
            let status = crate::app::vcon_forward::status_of(&head)?;
            let location =
                crate::app::vcon_forward::header_value(&head, "location").map(str::to_owned);
            let (body, truncated) = crate::app::vcon_forward::read_body(reader, &head, MAX_RECEIPT);
            Ok((status, location, body, truncated))
        },
    );
    let mut out = Registration {
        event: event.as_str(),
        status: None,
        location: None,
        receipt: None,
        error: None,
    };
    match answered {
        Err(e) => out.error = Some(scrub(e)),
        Ok((status, location, body, truncated)) => {
            out.status = Some(status);
            out.location = location;
            match status {
                201 if truncated => {
                    out.error = Some(format!("the receipt is longer than {MAX_RECEIPT} bytes"));
                }
                201 => {
                    out.receipt =
                        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&body));
                }
                202 => {}
                _ => out.error = Some(scrub(problem(&body))),
            }
        }
    }
    out
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
            assert_eq!(entries(&Endpoint::parse(base)?).target, target, "{base}");
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
}
