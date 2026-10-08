// SPDX-License-Identifier: MIT OR Apache-2.0

//! The vCon forwarder: `sipnab --vcon-forward <SPOOL_DIR>`.
//!
//! sipnab's capture process writes containers into an `--export-vcon-dir`
//! spool and makes no outbound connection for them. This mode is the separate
//! process that delivers that spool to a vCon store: it POSTs each container,
//! byte for byte, with one authentication header, and moves it out of the
//! spool by what the store answers.
//!
//! | The store answers | The forwarder |
//! |---|---|
//! | `2xx` | moves the container to the delivered directory |
//! | `401` or `403` | stops: sends nothing more, moves nothing, logs the status and the start of the answer, and exits 3 |
//! | `409`, with `--vcon-forward-replace-url` | PUTs it to that URL, uuid filled in, and acts on that answer |
//! | any other `4xx` | moves it to the failed directory beside `<name>.error.json` |
//! | `5xx`, a timeout, or no connection | leaves it, and retries with a doubling delay |
//!
//! Every number it works by is a setting with a flag and a `[vcon_forward]`
//! key (see [`ForwardPlan::resolve`]), except the constants below, each of
//! which says why it is not one. A store kind ([`STORE_KINDS`]) supplies the
//! values a store of that kind needs, and an explicit setting overrides each.
//!
//! A `2xx` means the store ACCEPTED the container. It does not mean the store
//! kept it: the self-hosted conserver once answered `204` for a container it
//! then failed to store. So the forwarder reports "delivered", never "stored".
//!
//! The contract it reads the spool by is the one `docs/vcon.md` states: a
//! container appears whole, by rename, under a stable name, and a dot-prefixed
//! name is sipnab's staging file. A container sipnab rewrites under the same
//! name (the call changed) is a new container to the forwarder, and goes out
//! again.

use std::collections::HashMap;
use std::io::{BufRead, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The most of a store's answer the stop reason quotes, in bytes.
///
/// Not a setting: the quote goes into one log line, and its only purpose is
/// to make the answer recognizable there (a CDN's `error code: 1010`). Nothing
/// is kept from a halted answer, so no deployment loses data by its length.
const MAX_HALT_BODY: usize = 200;

/// The largest credential the forwarder reads from a file, in bytes.
///
/// Not a setting: the file holds one header line, and common HTTP servers
/// refuse a longer one (Apache httpd's `LimitRequestFieldSize` defaults to
/// 8190 bytes, nginx's `large_client_header_buffers` to 8 KiB per line). The
/// same figure bounds how far past the kept part of an answer the forwarder
/// reads, so the credential is removed before the cut.
pub const MAX_AUTH_FILE: usize = 8 * 1024;

/// How often the wait between passes asks whether a stop was requested.
///
/// Not a setting: it changes nothing that is sent or when, only how soon
/// after SIGTERM or SIGINT the forwarder returns, which is at most this long.
const STOP_POLL_STEP: Duration = Duration::from_millis(100);

/// The longest container `uuid` the forwarder puts into a replace URL's path.
///
/// Not a setting: it describes the value, not the store. A vCon `uuid` is a
/// UUID, 36 characters in its text form; the limit refuses a value long
/// enough to be something else before it reaches a URL.
const MAX_UUID_LEN: usize = 64;

/// The shortest last word of the credential that [`AuthHeader::scrub`] also
/// removes on its own (the token of `Bearer <token>`).
///
/// Not a setting: a shorter word would remove ordinary words from a store's
/// answer, and a token shorter than this is not one a store issues.
const MIN_SCRUBBED_WORD: usize = 8;

/// What replaces the auth value in any text the forwarder keeps.
const REMOVED: &str = "[auth value removed]";

/// The `User-Agent` every request carries. A Cloudflare front refuses some
/// client libraries' default agents with `403 error code: 1010`; an explicit,
/// honest one names the software that sent the request.
///
/// Not a setting: the header names the software that sent the request, and a
/// setting would let the request name other software.
const USER_AGENT: &str = concat!("sipnab/", env!("CARGO_PKG_VERSION"));

/// The flag that names the auth file, quoted in its errors.
const AUTH_FLAG: &str = "--vcon-forward-auth-file";

/// The key that names the auth file, quoted in its errors.
const AUTH_KEY: &str = "[vcon_forward] auth_file";

/// The flag and the environment variable that carry the credential itself,
/// quoted in their errors.
const AUTH_INLINE: &str = "--vcon-forward-auth (or SIPNAB_VCON_FORWARD_AUTH)";

/// Headers the forwarder writes itself, so the auth file may not name them.
///
/// Not a setting: they frame the HTTP request and are computed from it.
const RESERVED_HEADERS: &[&str] = &[
    "host",
    "content-type",
    "content-length",
    "transfer-encoding",
    "connection",
    "user-agent",
    "expect",
];

/// Where the forwarder sends a container: scheme, host, port and the path
/// with its query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// `https://` rather than `http://`.
    pub tls: bool,
    /// The host as written, without brackets around an IPv6 literal.
    pub host: String,
    /// The port, 80 or 443 when the URL names none.
    pub port: u16,
    /// The path and query, `/` when the URL names none.
    pub target: String,
}

impl Endpoint {
    /// Parse an `http://` or `https://` URL.
    ///
    /// # Errors
    ///
    /// Any other scheme, whitespace, an empty host, a bad port, credentials
    /// in the URL (they would reach the log) or a fragment.
    pub fn parse(url: &str) -> Result<Self, String> {
        // Every refusal below quotes the URL; none may quote its userinfo.
        let shown = crate::app::run_provenance::redact_url_userinfo(url);
        let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(format!(
                "'{shown}': the forwarder speaks http:// and https:// only"
            ));
        };
        if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(format!("'{shown}': a URL cannot hold whitespace"));
        }
        if url.contains('#') {
            return Err(format!("'{shown}': a URL sent to a store has no fragment"));
        }
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) => rest.split_at(i),
            None => (rest, "/"),
        };
        // Userinfo by the redaction rule, not by `authority`: a password
        // typed with an unescaped `?` ends `authority` early, and its tail
        // would otherwise be read, and quoted, as the port.
        if shown != url {
            return Err(format!(
                "'{shown}': put credentials in --vcon-forward-auth-file, not in the URL"
            ));
        }
        let (host, port) = split_authority(authority).map_err(|e| format!("'{shown}': {e}"))?;
        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(|| format!("'{shown}': '{p}' is not a port"))?,
            None if tls => 443,
            None => 80,
        };
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_string()
        };
        Ok(Self {
            tls,
            host: host.to_string(),
            port,
            target,
        })
    }

    /// The port this scheme uses when the URL names none.
    fn default_port(&self) -> u16 {
        if self.tls { 443 } else { 80 }
    }

    /// The `Host` header's value: the host, bracketed when it is an IPv6
    /// literal, and the port when it is not the scheme's default.
    #[must_use]
    pub fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let scheme = if self.tls { "https" } else { "http" };
        write!(f, "{scheme}://{}{}", self.host_header(), self.target)
    }
}

/// `host[:port]` or `[v6][:port]`, split. The port is `None` when absent.
fn split_authority(authority: &str) -> Result<(&str, Option<&str>), String> {
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (host, tail) = after
            .split_once(']')
            .ok_or("an IPv6 address needs its closing ']'")?;
        match tail {
            "" => (host, None),
            _ => (
                host,
                Some(
                    tail.strip_prefix(':')
                        .ok_or("only a port may follow an IPv6 address")?,
                ),
            ),
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("the URL names no host".to_string());
    }
    Ok((host, port))
}

/// The one header that authenticates the forwarder to the store.
///
/// The value is a credential. Nothing prints it: `Debug` shows the name
/// alone, no error quotes it, and [`AuthHeader::scrub`] removes it from the
/// store's answers before the forwarder keeps them.
#[derive(Clone)]
pub struct AuthHeader {
    /// The header's name, as the file wrote it.
    name: String,
    /// The credential. Written to the request and nowhere else.
    value: String,
}

impl AuthHeader {
    /// Parse `Header-Name: value`, one header on one line.
    ///
    /// Spaces around the name and the value, and the line ending, are not
    /// part of either. Blank lines are passed over.
    ///
    /// # Errors
    ///
    /// No header, more than one, a name that is not an HTTP field name or is
    /// one the forwarder writes itself, an empty value, or a control
    /// character in the value. No message quotes the line: a file holding
    /// only a token is the commonest mistake, and the token is the secret.
    pub fn parse(text: &str) -> Result<Self, String> {
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let line = match lines.as_slice() {
            [one] => *one,
            [] => return Err("holds no header; write one line, `Header-Name: value`".into()),
            _ => {
                return Err(
                    "holds more than one line; the forwarder sends one header, `Header-Name: value`"
                        .into(),
                );
            }
        };
        let (name, value) = line
            .split_once(':')
            .ok_or("is not `Header-Name: value` (no colon on the line)")?;
        let (name, value) = (name.trim(), value.trim());
        if name.is_empty() || !name.bytes().all(is_field_name_byte) {
            return Err("names no valid HTTP header before the colon".into());
        }
        if RESERVED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(format!(
                "names `{name}`, which the forwarder writes itself; name the header that authenticates"
            ));
        }
        if value.is_empty() {
            return Err(format!("gives `{name}` no value"));
        }
        if value.chars().any(char::is_control) {
            return Err(format!(
                "gives `{name}` a value holding a control character"
            ));
        }
        Ok(Self {
            name: name.to_string(),
            value: value.to_string(),
        })
    }

    /// The header a credential stands for, for a store of `kind`: a
    /// `Header-Name: value` line is that header, whatever the kind. A kind
    /// with an auth header ([`KindFacts::auth_header`]) also takes the bare
    /// key, one line, and sends it in that header after the kind's prefix;
    /// the generic kind takes only the full line.
    ///
    /// # Errors
    ///
    /// As [`AuthHeader::parse`] for the generic kind; for another, no key,
    /// more than one line, or a control character. No message quotes the
    /// credential.
    pub fn from_credential(text: &str, kind: StoreKind) -> Result<Self, String> {
        let parsed = Self::parse(text);
        let Some((name, prefix)) = kind.facts().auth_header else {
            return parsed;
        };
        if parsed.is_ok() {
            return parsed;
        }
        let lines: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        let key = match lines.as_slice() {
            [one] => *one,
            [] => return Err("holds no key".into()),
            _ => return Err("holds more than one line; give the key, or one header line".into()),
        };
        if key.chars().any(char::is_control) {
            return Err("holds a key with a control character in it".into());
        }
        Ok(Self {
            name: name.to_string(),
            value: format!("{prefix}{key}"),
        })
    }

    /// Read the header from a secret file, refused when other users can read
    /// it ([`crate::privilege::open_private_file`], the rule every secret file
    /// sipnab reads follows). The generic kind's rule, with the flag named.
    ///
    /// # Errors
    ///
    /// As [`AuthHeader::read_file_for`].
    pub fn read_file(path: &Path) -> Result<Self, String> {
        Self::read_file_for(path, AUTH_FLAG, StoreKind::Generic)
    }

    /// Read the credential for a store of `kind` from a secret file, by
    /// [`AuthHeader::from_credential`]. `from` names the setting that named
    /// the file, for the messages.
    ///
    /// # Errors
    ///
    /// The file is refused, unreadable, larger than [`MAX_AUTH_FILE`], not
    /// UTF-8, or not a credential. Every message names `from` and the path,
    /// never the contents.
    pub fn read_file_for(path: &Path, from: &str, kind: StoreKind) -> Result<Self, String> {
        let shown = path.display();
        let file = crate::privilege::open_private_file(path, from)?;
        let mut buf = Vec::new();
        file.take(MAX_AUTH_FILE as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| format!("{from} '{shown}': {e}"))?;
        if buf.len() > MAX_AUTH_FILE {
            return Err(format!(
                "{from} '{shown}': larger than {MAX_AUTH_FILE} bytes; it holds one line"
            ));
        }
        let text =
            String::from_utf8(buf).map_err(|_| format!("{from} '{shown}': not UTF-8 text"))?;
        Self::from_credential(&text, kind).map_err(|e| format!("{from} '{shown}' {e}"))
    }

    /// The header's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `text` with every occurrence of the value replaced, and of its last
    /// word too: an `Authorization: Bearer <token>` value's token may be
    /// echoed without the scheme in front of it.
    #[must_use]
    pub fn scrub(&self, text: &str) -> String {
        let mut out = text.replace(&self.value, REMOVED);
        if let Some(word) = self.value.split_whitespace().last()
            && word != self.value
            && word.len() >= MIN_SCRUBBED_WORD
        {
            out = out.replace(word, REMOVED);
        }
        out
    }
}

impl std::fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {REMOVED}", self.name)
    }
}

/// A `tchar` of [RFC 9110 section 5.6.2](https://www.rfc-editor.org/rfc/rfc9110#section-5.6.2): what an HTTP field name is made of.
fn is_field_name_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// A store's known deviation from the vCon drafts that the forwarder corrects
/// for in the copy it SENDS. The container on disk never changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compat {
    /// Send every container byte for byte (`none`). The default.
    Off,
    /// vcon.store (`vcon-store`): `extensions` as an object, and no Dialog
    /// Object without `type` and `parties`. See [`vcon_store_copy`].
    VconStore,
}

impl Compat {
    /// The mode one of [`crate::config::FORWARD_COMPAT`] names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "none" => Some(Self::Off),
            "vcon-store" => Some(Self::VconStore),
            _ => None,
        }
    }
}

/// The kind of store a forwarder delivers to: what it supplies for a setting
/// that is not given. One store per forwarder process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// Nothing supplied: every setting is explicit. The default.
    Generic,
    /// vcon.store, the hosted store.
    VconStore,
    /// A self-hosted vCon server (conserver), through its external ingress.
    Conserver,
}

impl StoreKind {
    /// The kind one of [`crate::config::FORWARD_KINDS`] names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::Generic, Self::VconStore, Self::Conserver]
            .into_iter()
            .find(|k| k.facts().name == name)
    }

    /// This kind's row of [`STORE_KINDS`].
    #[must_use]
    pub fn facts(self) -> &'static KindFacts {
        match self {
            Self::Generic => &STORE_KINDS[0],
            Self::VconStore => &STORE_KINDS[1],
            Self::Conserver => &STORE_KINDS[2],
        }
    }
}

/// What a store of one kind needs, as measured. An explicit setting
/// overrides each value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindFacts {
    /// The kind's name in `--vcon-forward-kind` and `[vcon_forward] kind`.
    pub name: &'static str,
    /// The path and query the kind appends to a URL that names no path.
    /// `None`: the URL is the endpoint as written.
    pub ingest_path: Option<&'static str>,
    /// The header a bare key is sent in, and the text before the key in its
    /// value. `None`: the credential is a full `Header-Name: value` line.
    pub auth_header: Option<(&'static str, &'static str)>,
    /// What the store answers for a uuid it already holds: `Some(status)`
    /// when it refuses the duplicate with that status (a replace URL then
    /// applies), `None` when the duplicate replaces the held container or
    /// nothing was measured.
    pub duplicate_status: Option<u16>,
    /// The adaptation of the copy sent.
    pub compat: Compat,
    /// The statuses, inclusive, that count as delivered.
    pub delivered: (u16, u16),
}

/// One row per store kind, in the order of
/// [`crate::config::FORWARD_KINDS`]. The one place each kind's facts live.
///
/// vcon.store, measured by the maintainer against `https://api.vcon.store`
/// on 2026-10-07: `POST /v1/vcons` with `Authorization: Bearer <key>`
/// answered `201` on create, `400` for `extensions` as an array of strings
/// and for a Dialog Object without `type` and `parties`, and `409` for a uuid
/// it held. A `PUT` to `/v1/vcons/{uuid}` was not measured, so the kind sets
/// no replace URL.
///
/// conserver, measured against the self-hosted vCon server in the development lab on
/// 2026-10-07: `POST /vcon/external-ingress?ingress_list=sipnab` with
/// `x-conserver-api-token: <key>` answered `204` for a new container, and
/// `GET /vcon/{uuid}` then returned it with an `amended` member added; `204`
/// for the same uuid again, and the read-back then showed the second copy;
/// `422` for a body that is not JSON and for one without `uuid`; `403` with
/// no key or a wrong one. `ingress_list=sipnab` names the ingress list the
/// sipnab setup in `docs/vcon-sipnab.md` creates.
pub const STORE_KINDS: [KindFacts; 3] = [
    KindFacts {
        name: "generic",
        ingest_path: None,
        auth_header: None,
        duplicate_status: None,
        compat: Compat::Off,
        delivered: (200, 299),
    },
    KindFacts {
        name: "vcon-store",
        ingest_path: Some("/v1/vcons"),
        auth_header: Some(("Authorization", "Bearer ")),
        duplicate_status: Some(409),
        compat: Compat::VconStore,
        delivered: (200, 299),
    },
    KindFacts {
        name: "conserver",
        ingest_path: Some("/vcon/external-ingress?ingress_list=sipnab"),
        auth_header: Some(("x-conserver-api-token", "")),
        duplicate_status: None,
        compat: Compat::Off,
        delivered: (200, 299),
    },
];

/// The copy of a container the forwarder sends in a compat mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatCopy {
    /// The bytes to send.
    pub bytes: Vec<u8>,
    /// One phrase per change made, for the log. Empty when nothing changed.
    pub transforms: Vec<String>,
}

/// The copy of `container` to send to vcon.store.
///
/// vcon.store's validator rejects `extensions` in the form both
/// draft-ietf-vcon-vcon-core-02 and -03 define in section 4.1.3, an array of
/// strings, with `400 extensions: Expected object, received array`, and
/// accepts an object. So the copy carries `extensions` as an object mapping
/// each name, in its original order, to `true`. Every other member keeps its
/// bytes.
///
/// The store also requires `type` and `parties` on every Dialog Object.
/// sipnab writes a Dialog Object with neither when the run kept no audio,
/// which section 4.3 of core-03 allows, and the forwarder does not invent a
/// `type` sipnab did not observe or drop the object and leave dangling
/// indexes. Such a container is refused here instead, with the reason.
///
/// # Errors
///
/// The reason the container cannot be sent there: it is not a JSON object,
/// or a Dialog Object lacks `type` or `parties`.
pub fn vcon_store_copy(container: &[u8]) -> Result<CompatCopy, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(container).map_err(|e| format!("the container is not JSON: {e}"))?;
    let object = doc
        .as_object()
        .ok_or("the container is not a JSON object")?;
    if let Some(serde_json::Value::Array(dialogs)) = object.get("dialog") {
        for (i, d) in dialogs.iter().enumerate() {
            dialog_refusal(i, d)?;
        }
    }
    let names: Vec<&str> = match object.get("extensions") {
        Some(serde_json::Value::Array(items)) => {
            match items.iter().map(serde_json::Value::as_str).collect() {
                Some(names) => names,
                None => return Ok(unchanged(container)),
            }
        }
        _ => return Ok(unchanged(container)),
    };
    let bytes = with_member_replaced(container, "extensions", &names_as_object(&names)?)?;
    Ok(CompatCopy {
        bytes,
        transforms: vec![format!(
            "sent `extensions` as an object of {} name(s) mapped to true, because vcon.store \
             refuses the String[] form that draft-ietf-vcon-vcon-core-02 and -03 define in \
             section 4.1.3",
            names.len()
        )],
    })
}

/// A copy that changes nothing.
fn unchanged(container: &[u8]) -> CompatCopy {
    CompatCopy {
        bytes: container.to_vec(),
        transforms: Vec::new(),
    }
}

/// Why vcon.store would refuse Dialog Object `index`, or `Ok` when it would
/// not.
fn dialog_refusal(index: usize, dialog: &serde_json::Value) -> Result<(), String> {
    let has = |key: &str| dialog.get(key).is_some();
    let missing = match (has("type"), has("parties")) {
        (true, true) => return Ok(()),
        (false, false) => "`type` or `parties`",
        (false, true) => "`type`",
        (true, false) => "`parties`",
    };
    Err(format!(
        "vcon.store requires `type` and `parties` on every Dialog Object \
         (draft-ietf-vcon-vcon-core-02), and dialog[{index}] has no {missing}. sipnab writes \
         a Dialog Object without them when the container carries no audio, which section 4.3 \
         of draft-ietf-vcon-vcon-core-03 allows, and the forwarder does not invent what sipnab \
         did not observe. A container carries audio only when the export ran with \
         --retain-audio and without --redact, which withholds it; such a container has a \
         `recording` Dialog Object, which the store accepts. The container was not sent and was \
         not changed."
    ))
}

/// `{"a":true,"b":true}` for `["a","b"]`, in order.
fn names_as_object(names: &[&str]) -> Result<String, String> {
    let mut out = String::from("{");
    for (i, name) in names.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(name).map_err(|e| e.to_string())?);
        out.push_str(":true");
    }
    out.push('}');
    Ok(out)
}

/// The top-level members of a JSON object, in their order, each value's
/// bytes as written.
struct Members(Vec<(String, Box<serde_json::value::RawValue>)>);

impl<'de> serde::Deserialize<'de> for Members {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        /// Collects the members of one map.
        struct Collect;
        impl<'de> serde::de::Visitor<'de> for Collect {
            type Value = Members;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Members, A::Error> {
                let mut out = Vec::new();
                while let Some(member) = map.next_entry()? {
                    out.push(member);
                }
                Ok(Members(out))
            }
        }
        de.deserialize_map(Collect)
    }
}

/// `container` with member `key`'s value replaced by `json`, every other
/// member's bytes and the members' order kept.
fn with_member_replaced(container: &[u8], key: &str, json: &str) -> Result<Vec<u8>, String> {
    let Members(members) =
        serde_json::from_slice(container).map_err(|e| format!("the container is not JSON: {e}"))?;
    let mut out = String::from("{");
    for (i, (name, value)) in members.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&serde_json::to_string(name).map_err(|e| e.to_string())?);
        out.push(':');
        out.push_str(if name == key { json } else { value.get() });
    }
    out.push('}');
    Ok(out.into_bytes())
}

/// The `uuid` a container carries, checked for use in a URL path.
///
/// # Errors
///
/// Not JSON, no `uuid`, or a `uuid` that is empty, longer than 64 characters
/// or holds a character outside `[0-9A-Za-z-]`.
pub fn container_uuid(container: &[u8]) -> Result<String, String> {
    let doc: serde_json::Value =
        serde_json::from_slice(container).map_err(|e| format!("the container is not JSON: {e}"))?;
    let uuid = doc
        .get("uuid")
        .and_then(serde_json::Value::as_str)
        .ok_or("the container carries no `uuid` to replace by")?;
    if uuid.is_empty()
        || uuid.len() > MAX_UUID_LEN
        || !uuid.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("the container's `uuid` is not one a URL path may carry".into());
    }
    Ok(uuid.to_string())
}

/// The containers waiting in `spool`, by name, sorted.
///
/// A container is a regular file whose name ends in `.json` and does not
/// start with a dot. sipnab stages every write as `.<name>.partial` and
/// renames it into place, so neither rule ever selects a half-written file.
/// Directories (the delivered and failed ones among them), symbolic links and
/// names that are not UTF-8 are passed over.
///
/// # Errors
///
/// The directory cannot be read.
pub fn pending(spool: &Path) -> std::io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(spool)? {
        let entry = entry?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.starts_with('.') || !name.ends_with(".json") {
            continue;
        }
        if entry.file_type()?.is_file() {
            names.push(name);
        }
    }
    names.sort();
    Ok(names)
}

/// How long a container waits after its `attempts`-th failed try:
/// `first_secs`, then doubling, never more than `cap_secs`.
#[must_use]
pub fn backoff_delay(attempts: u32, first_secs: u64, cap_secs: u64) -> Duration {
    let doublings = attempts.saturating_sub(1).min(u64::BITS - 1);
    let secs = first_secs.saturating_mul(1u64 << doublings);
    Duration::from_secs(secs.min(cap_secs))
}

/// What an HTTP status means for the container that drew it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// `2xx`: the store accepted it.
    Delivered,
    /// A `4xx` that a retry will not change.
    Refused,
    /// `5xx`, or a status this client does not act on: try later.
    Retry,
    /// `409` with a replace URL: PUT it there.
    Replace,
    /// `401` or `403`: the store refuses the credentials or the client, for
    /// every container alike. Stop.
    Halt,
}

/// Classify a status. `can_replace` is whether a replace URL is set;
/// `delivered` is the inclusive range of statuses that count as delivered
/// ([`KindFacts::delivered`]). Any other `2xx` is retried.
#[must_use]
pub fn classify(status: u16, can_replace: bool, delivered: (u16, u16)) -> Verdict {
    match status {
        s if (delivered.0..=delivered.1).contains(&s) => Verdict::Delivered,
        401 | 403 => Verdict::Halt,
        409 if can_replace => Verdict::Replace,
        400..=499 => Verdict::Refused,
        _ => Verdict::Retry,
    }
}

/// A warning when the auth header would cross a network in clear text:
/// `http://` to a host that is not this machine. `None` for HTTPS and for
/// loopback.
#[must_use]
pub fn plaintext_warning(endpoint: &Endpoint) -> Option<String> {
    let loopback = endpoint.host.eq_ignore_ascii_case("localhost")
        || endpoint
            .host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if endpoint.tls || loopback {
        return None;
    }
    Some(format!(
        "{endpoint} is plain http to another machine: the auth header and every container \
         cross the network unencrypted. Use https:// for anything but loopback"
    ))
}

/// How a container's retries are spaced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Seconds before the first retry. See
    /// [`crate::config::FORWARD_BACKOFF_FIRST`].
    pub first_secs: u64,
    /// The longest wait between retries, in seconds. See
    /// [`crate::config::FORWARD_BACKOFF_CAP`].
    pub cap_secs: u64,
}

impl Default for BackoffPolicy {
    /// The declared defaults.
    fn default() -> Self {
        Self {
            first_secs: crate::config::FORWARD_BACKOFF_FIRST.default,
            cap_secs: crate::config::FORWARD_BACKOFF_CAP.default,
        }
    }
}

/// How much of a store's answer the forwarder reads and keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadLimits {
    /// The most bytes of the status line and headers read. See
    /// [`crate::config::FORWARD_MAX_RESPONSE_HEAD`].
    pub response_head: usize,
    /// The most bytes of a refusal's body a failure record keeps. See
    /// [`crate::config::FORWARD_MAX_ERROR_BODY`].
    pub error_body: usize,
}

impl ReadLimits {
    /// The limits from two byte counts. Both settings accept at most
    /// `u32::MAX`, which every target's `usize` holds; a larger count reads
    /// as `usize::MAX`.
    #[must_use]
    pub fn from_bytes(response_head: u64, error_body: u64) -> Self {
        Self {
            response_head: usize::try_from(response_head).unwrap_or(usize::MAX),
            error_body: usize::try_from(error_body).unwrap_or(usize::MAX),
        }
    }
}

impl Default for ReadLimits {
    /// The declared defaults.
    fn default() -> Self {
        Self::from_bytes(
            crate::config::FORWARD_MAX_RESPONSE_HEAD.default,
            crate::config::FORWARD_MAX_ERROR_BODY.default,
        )
    }
}

/// Everything one forwarder needs.
#[derive(Debug, Clone)]
pub struct ForwardSettings {
    /// The `--export-vcon-dir` spool it drains.
    pub spool: PathBuf,
    /// Where it POSTs each container.
    pub url: Endpoint,
    /// The URL template a `409` is PUT to, `{uuid}` filled in.
    pub replace_url: Option<String>,
    /// The one authentication header.
    pub auth: AuthHeader,
    /// Where a delivered container goes.
    pub done_dir: PathBuf,
    /// Where a refused container goes, beside its `.error.json` record.
    pub failed_dir: PathBuf,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// The store deviation to correct for in the copy sent.
    pub compat: Compat,
    /// The only CA file trusted for HTTPS; the host's bundle when `None`.
    pub ca: Option<PathBuf>,
    /// The kind of store: which statuses count as delivered.
    pub kind: StoreKind,
    /// How retries are spaced.
    pub backoff: BackoffPolicy,
    /// How much of an answer is read and kept.
    pub limits: ReadLimits,
}

/// Where the credential comes from, resolved but not yet read.
#[derive(Clone)]
pub enum Credential {
    /// The header itself, from `--vcon-forward-auth` or
    /// `SIPNAB_VCON_FORWARD_AUTH`.
    Header(AuthHeader),
    /// A file that holds it, and the setting that named the file.
    File {
        /// The file.
        path: PathBuf,
        /// `--vcon-forward-auth-file` or `[vcon_forward] auth_file`, for
        /// the messages.
        from: &'static str,
        /// Where `from` was given, which sets the exit code when the file
        /// is refused.
        origin: crate::settings::Origin,
    },
}

impl std::fmt::Debug for Credential {
    /// The header's name, or the file's path. Never the value, and not the
    /// setting that named the file: a flag and its key that name the same
    /// file are the same credential.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Header(h) => write!(f, "Header({h:?})"),
            Self::File { path, .. } => write!(f, "File({path:?})"),
        }
    }
}

/// Every forwarder setting, resolved from the flags and the `[vcon_forward]`
/// keys, before any file is read.
#[derive(Debug, Clone)]
pub struct ForwardPlan {
    /// The spool.
    pub spool: PathBuf,
    /// The kind of store.
    pub kind: StoreKind,
    /// Where each container is POSTed.
    pub url: Endpoint,
    /// The URL template a `409` is PUT to.
    pub replace_url: Option<String>,
    /// Where the credential comes from.
    pub credential: Credential,
    /// Where a delivered container goes.
    pub done_dir: PathBuf,
    /// Where a refused container goes.
    pub failed_dir: PathBuf,
    /// The connect, read and write timeout.
    pub timeout: Duration,
    /// The wait between passes.
    pub interval: Duration,
    /// The adaptation of the copy sent.
    pub compat: Compat,
    /// The only CA file trusted for HTTPS.
    pub ca: Option<PathBuf>,
    /// How retries are spaced.
    pub backoff: BackoffPolicy,
    /// How much of an answer is read and kept.
    pub limits: ReadLimits,
}

/// Which step of [`ForwardPlan::resolve_refusal`] refused a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveStep {
    /// The store's URL did not parse.
    Url,
    /// The replace URL did not parse.
    ReplaceUrl,
    /// Anything else, each of which involves a flag.
    Other,
}

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

/// A whole-number setting's value in force, checked by its one rule, with
/// where it came from.
fn pick_number(
    number: crate::config::ForwardNumber,
    flag: Option<u64>,
    key: Option<u64>,
) -> Result<(u64, String), String> {
    let (value, from) = number.pick(flag, key);
    number.check(value).map_err(|e| format!("{from}: {e}"))?;
    Ok((value, from))
}

impl ForwardPlan {
    /// Resolve every setting: the flag, else the `[vcon_forward]` key, else
    /// the store kind's value, else the declared default. Reads no file.
    ///
    /// # Errors
    ///
    /// No URL or no credential from any source; the credential from more
    /// than one; a URL, replace URL or number its flag's rule refuses; a
    /// first back-off longer than the cap; an unknown kind or compat name.
    /// Each message names the flag or key the value came from, and none
    /// quotes the credential.
    pub fn resolve(
        args: &crate::cli::VconForwardArgs,
        keys: &crate::config::VconForwardConfig,
    ) -> Result<Self, String> {
        Self::resolve_refusal(args, keys).map_err(|(_, message)| message)
    }

    /// [`Self::resolve`], with where a refused value came from.
    ///
    /// Only the URL and the replace URL can be refused here from the config
    /// file alone: a `[vcon_forward]` number, kind or compat name was refused
    /// when the file loaded, and every other refusal involves a flag or is a
    /// setting `--vcon-forward` needs and nothing gave.
    ///
    /// # Errors
    ///
    /// As [`Self::resolve`], each message with its
    /// [`crate::settings::Origin`].
    pub fn resolve_refusal(
        args: &crate::cli::VconForwardArgs,
        keys: &crate::config::VconForwardConfig,
    ) -> Result<Self, (crate::settings::Origin, String)> {
        use crate::settings::Origin;
        let flag = |message: String| (Origin::CommandLine, message);
        let url_origin = Origin::of(args.vcon_forward_url.is_some());
        let replace_origin = Origin::of(args.vcon_forward_replace_url.is_some());
        Self::resolve_inner(args, keys).map_err(|(step, message)| match step {
            ResolveStep::Url => (url_origin, message),
            ResolveStep::ReplaceUrl => (replace_origin, message),
            ResolveStep::Other => flag(message),
        })
    }

    /// The body of [`Self::resolve_refusal`]: each refusal with the step that
    /// made it.
    fn resolve_inner(
        args: &crate::cli::VconForwardArgs,
        keys: &crate::config::VconForwardConfig,
    ) -> Result<Self, (ResolveStep, String)> {
        let other = |message: String| (ResolveStep::Other, message);
        use crate::config::{
            FORWARD_BACKOFF_CAP, FORWARD_BACKOFF_FIRST, FORWARD_INTERVAL, FORWARD_MAX_ERROR_BODY,
            FORWARD_MAX_RESPONSE_HEAD, FORWARD_TIMEOUT,
        };
        let spool = args
            .vcon_forward
            .clone()
            .ok_or_else(|| other("--vcon-forward names no spool".to_string()))?;
        let kind = match pick_text(
            args.vcon_forward_kind.as_deref(),
            "--vcon-forward-kind",
            keys.kind.as_deref(),
            "[vcon_forward] kind",
        ) {
            Some((name, from)) => StoreKind::from_name(name)
                .ok_or_else(|| other(format!("{from}: {name:?} is not a store kind")))?,
            None => StoreKind::Generic,
        };
        let facts = kind.facts();
        let (url_text, url_from) = pick_text(
            args.vcon_forward_url.as_deref(),
            "--vcon-forward-url",
            keys.url.as_deref(),
            "[vcon_forward] url",
        )
        .ok_or_else(|| {
            other(
                "--vcon-forward needs the store's URL: give --vcon-forward-url, or \
                 [vcon_forward] url in the config file"
                    .to_string(),
            )
        })?;
        let mut url =
            Endpoint::parse(url_text).map_err(|e| (ResolveStep::Url, format!("{url_from} {e}")))?;
        if let Some(path) = facts.ingest_path
            && url.target == "/"
        {
            path.clone_into(&mut url.target);
        }
        let replace = pick_text(
            args.vcon_forward_replace_url.as_deref(),
            "--vcon-forward-replace-url",
            keys.replace_url.as_deref(),
            "[vcon_forward] replace_url",
        );
        if let Some((template, from)) = replace {
            replace_endpoint(template, "0")
                .map_err(|e| (ResolveStep::ReplaceUrl, format!("{from} {e}")))?;
        }
        let credential = credential(args, keys, kind).map_err(other)?;
        let compat = match pick_text(
            args.vcon_forward_compat.as_deref(),
            "--vcon-forward-compat",
            keys.compat.as_deref(),
            "[vcon_forward] compat",
        ) {
            Some((name, from)) => Compat::from_name(name)
                .ok_or_else(|| other(format!("{from}: {name:?} is not a compat mode")))?,
            None => facts.compat,
        };
        let interval = pick_number(FORWARD_INTERVAL, args.vcon_forward_interval, keys.interval)
            .map_err(other)?;
        let timeout =
            pick_number(FORWARD_TIMEOUT, args.vcon_forward_timeout, keys.timeout).map_err(other)?;
        let first = pick_number(
            FORWARD_BACKOFF_FIRST,
            args.vcon_forward_backoff_first,
            keys.backoff_first,
        )
        .map_err(other)?;
        let cap = pick_number(
            FORWARD_BACKOFF_CAP,
            args.vcon_forward_backoff_cap,
            keys.backoff_cap,
        )
        .map_err(other)?;
        if let Some(problem) =
            crate::config::forward_backoff_problem((first.0, &first.1), (cap.0, &cap.1))
        {
            return Err(other(problem));
        }
        let head = pick_number(
            FORWARD_MAX_RESPONSE_HEAD,
            args.vcon_forward_max_response_head,
            keys.max_response_head,
        )
        .map_err(other)?;
        let body = pick_number(
            FORWARD_MAX_ERROR_BODY,
            args.vcon_forward_max_error_body,
            keys.max_error_body,
        )
        .map_err(other)?;
        Ok(Self {
            done_dir: args
                .vcon_forward_done
                .clone()
                .or_else(|| keys.done.clone())
                .unwrap_or_else(|| spool.join("delivered")),
            failed_dir: args
                .vcon_forward_failed
                .clone()
                .or_else(|| keys.failed.clone())
                .unwrap_or_else(|| spool.join("failed")),
            ca: args.vcon_forward_ca.clone().or_else(|| keys.ca.clone()),
            replace_url: replace.map(|(t, _)| t.to_string()),
            spool,
            kind,
            url,
            credential,
            timeout: Duration::from_secs(timeout.0),
            interval: Duration::from_secs(interval.0),
            compat,
            backoff: BackoffPolicy {
                first_secs: first.0,
                cap_secs: cap.0,
            },
            limits: ReadLimits::from_bytes(head.0, body.0),
        })
    }

    /// The settings to run with, the credential read, and the wait between
    /// passes.
    ///
    /// # Errors
    ///
    /// The credential's file is refused or holds no credential, with the
    /// [`crate::settings::Origin`] of the setting that named the file:
    /// `--vcon-forward-auth-file` or `[vcon_forward] auth_file`.
    pub fn into_settings(
        self,
    ) -> Result<(ForwardSettings, Duration), (crate::settings::Origin, String)> {
        let auth = match self.credential {
            Credential::Header(h) => h,
            Credential::File { path, from, origin } => {
                AuthHeader::read_file_for(&path, from, self.kind).map_err(|e| (origin, e))?
            }
        };
        Ok((
            ForwardSettings {
                spool: self.spool,
                url: self.url,
                replace_url: self.replace_url,
                auth,
                done_dir: self.done_dir,
                failed_dir: self.failed_dir,
                timeout: self.timeout,
                compat: self.compat,
                ca: self.ca,
                kind: self.kind,
                backoff: self.backoff,
                limits: self.limits,
            },
            self.interval,
        ))
    }
}

/// Where the credential comes from: exactly one of `--vcon-forward-auth`
/// (or its environment variable), `--vcon-forward-auth-file`, and
/// `[vcon_forward] auth_file`, except that the file flag replaces the key.
///
/// # Errors
///
/// None given, the inline one beside a file, or an inline one that is not a
/// credential for `kind`. No message quotes the value.
fn credential(
    args: &crate::cli::VconForwardArgs,
    keys: &crate::config::VconForwardConfig,
    kind: StoreKind,
) -> Result<Credential, String> {
    match (
        args.vcon_forward_auth.as_deref(),
        args.vcon_forward_auth_file.as_ref(),
        keys.auth_file.as_ref(),
    ) {
        (Some(_), Some(_), _) => Err(format!(
            "{AUTH_INLINE} and {AUTH_FLAG} both name the credential; give one"
        )),
        (Some(_), None, Some(_)) => Err(format!(
            "{AUTH_INLINE} and {AUTH_KEY} both name the credential; give one, or name another \
             file with {AUTH_FLAG}, which replaces the key"
        )),
        (Some(text), None, None) => AuthHeader::from_credential(text, kind)
            .map(Credential::Header)
            .map_err(|e| format!("{AUTH_INLINE} {e}")),
        (None, Some(path), _) => Ok(Credential::File {
            path: path.clone(),
            from: AUTH_FLAG,
            origin: crate::settings::Origin::CommandLine,
        }),
        (None, None, Some(path)) => Ok(Credential::File {
            path: path.clone(),
            from: AUTH_KEY,
            origin: crate::settings::Origin::ConfigFile,
        }),
        (None, None, None) => Err(format!(
            "--vcon-forward needs a credential: give {AUTH_FLAG}, {AUTH_KEY} in the config file, \
             or the SIPNAB_VCON_FORWARD_AUTH environment variable"
        )),
    }
}

/// What one pass over the spool did, by container name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Accepted with a `2xx`, and moved to the delivered directory.
    pub delivered: Vec<String>,
    /// Refused, and moved to the failed directory.
    pub refused: Vec<String>,
    /// Still in the spool: retrying, backing off, rewritten during the send,
    /// or not reached before a stop.
    pub waiting: Vec<String>,
    /// The pass ended early because a stop was asked for.
    pub stopped: bool,
    /// The store refused the credentials or the client (`401`, `403`), so
    /// the pass stopped. The reason, with the status and the start of the
    /// answer, the auth value removed.
    pub halted: Option<String>,
}

/// What became of one container.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Accepted, and moved to the delivered directory.
    Delivered,
    /// Refused, and moved to the failed directory.
    Refused,
    /// Try again after the back-off.
    Retry,
    /// Rewritten during the send: try again next pass, no back-off.
    Changed,
    /// Gone before it could be read.
    Gone,
    /// The store refused the credentials or the client: stop the pass and
    /// leave this container and every one after it where they are. The
    /// reason, for the one log line.
    Halted(String),
}

/// A container's retry state.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    /// Failed tries so far.
    attempts: u32,
    /// The earliest time of the next try.
    next: Instant,
}

/// A file's identity: a rewrite by rename changes the inode, and a rewrite in
/// place changes the size or the modification time.
type Identity = (u64, u64, u64, i64, i64);

/// The identity of `meta`.
fn identity(meta: &std::fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    (
        meta.dev(),
        meta.ino(),
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec(),
    )
}

/// One HTTP answer: the status, and the start of the body.
struct Answer {
    /// The status code.
    status: u16,
    /// The start of the body; empty for a `2xx`, which is not read.
    body: Vec<u8>,
    /// The body was longer than what was kept.
    truncated: bool,
}

/// Why a container went to the failed directory.
enum Refusal<'a> {
    /// The store answered this.
    Answered(&'a Answer, &'a str, &'a Endpoint),
    /// The forwarder refused it before sending.
    Before(&'a str),
}

/// The forwarder: settings, the HTTPS configuration, and each waiting
/// container's back-off.
#[derive(Debug)]
pub struct Forwarder {
    /// What it was started with.
    settings: ForwardSettings,
    /// The TLS client configuration, when a URL is `https://`.
    tls: Option<Arc<rustls::ClientConfig>>,
    /// The back-off of each container that failed a try, by name.
    waiting: HashMap<String, Backoff>,
}

impl Forwarder {
    /// Check the settings and prepare the directories.
    ///
    /// Creates the delivered and failed directories (mode 0700) when they do
    /// not exist. Both must be on the spool's filesystem, so that moving a
    /// container is a rename: a copy across filesystems is a window in which
    /// a container exists twice or half.
    ///
    /// # Errors
    ///
    /// The spool is not a directory; a destination is the spool itself, cannot
    /// be created, or is on another filesystem; the replace URL has no
    /// `{uuid}` or does not parse; or HTTPS is needed and no CA loads.
    pub fn new(settings: ForwardSettings) -> Result<Self, String> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let spool_meta = std::fs::metadata(&settings.spool)
            .map_err(|e| format!("--vcon-forward '{}': {e}", settings.spool.display()))?;
        if !spool_meta.is_dir() {
            return Err(format!(
                "--vcon-forward '{}' is not a directory",
                settings.spool.display()
            ));
        }
        for (flag, dir) in [
            (
                "--vcon-forward-done ([vcon_forward] done)",
                &settings.done_dir,
            ),
            (
                "--vcon-forward-failed ([vcon_forward] failed)",
                &settings.failed_dir,
            ),
        ] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("{flag} '{}': {e}", dir.display()))?;
            let meta =
                std::fs::metadata(dir).map_err(|e| format!("{flag} '{}': {e}", dir.display()))?;
            if meta.dev() == spool_meta.dev() && meta.ino() == spool_meta.ino() {
                return Err(format!("{flag} '{}' is the spool itself", dir.display()));
            }
            if meta.dev() != spool_meta.dev() {
                return Err(format!(
                    "{flag} '{}' is on another filesystem from the spool; a move must be a rename",
                    dir.display()
                ));
            }
        }
        let mut needs_tls = settings.url.tls;
        if let Some(template) = &settings.replace_url {
            needs_tls |= replace_endpoint(template, "0")
                .map_err(|e| format!("the replace URL {e}"))?
                .tls;
        }
        let tls = if needs_tls {
            Some(client_config(settings.ca.as_deref())?)
        } else {
            None
        };
        Ok(Self {
            settings,
            tls,
            waiting: HashMap::new(),
        })
    }

    /// One pass over the spool: every container not backing off is sent
    /// once, and moved by the answer.
    ///
    /// A container that draws a `5xx`, a timeout or no connection waits for
    /// its back-off and the pass carries on to the next one, so one bad
    /// container never holds up the rest. `stop` is asked before each send;
    /// once it says yes nothing more is sent and the pass returns.
    ///
    /// # Arguments
    ///
    /// * `now` — the time to judge back-offs by.
    /// * `stop` — whether a stop was asked for.
    pub fn pass(&mut self, now: Instant, stop: &dyn Fn() -> bool) -> PassReport {
        let mut report = PassReport::default();
        let names = match pending(&self.settings.spool) {
            Ok(names) => names,
            Err(e) => {
                tracing::warn!(
                    "cannot read the spool '{}': {e}",
                    self.settings.spool.display()
                );
                return report;
            }
        };
        self.waiting.retain(|name, _| names.contains(name));
        let mut rest = names.into_iter();
        while let Some(name) = rest.next() {
            if stop() {
                report.stopped = true;
            } else if self.waiting.get(&name).is_none_or(|b| b.next <= now) {
                let outcome = self.forward_one(&name);
                if let Outcome::Halted(why) = outcome {
                    report.halted = Some(why);
                } else {
                    self.record(name, outcome, now, &mut report);
                    continue;
                }
            }
            // Stopped, halted, or backing off: this container stays. After
            // a stop or a halt, so does every one not reached.
            report.waiting.push(name);
            if report.stopped || report.halted.is_some() {
                report.waiting.extend(rest.by_ref());
            }
        }
        report
    }

    /// Account for one container's outcome in the back-offs and the report.
    fn record(&mut self, name: String, outcome: Outcome, now: Instant, report: &mut PassReport) {
        match outcome {
            Outcome::Delivered => {
                self.waiting.remove(&name);
                report.delivered.push(name);
            }
            Outcome::Refused => {
                self.waiting.remove(&name);
                report.refused.push(name);
            }
            Outcome::Retry => {
                let attempts = self.waiting.get(&name).map_or(0, |b| b.attempts) + 1;
                let policy = self.settings.backoff;
                let next = now + backoff_delay(attempts, policy.first_secs, policy.cap_secs);
                self.waiting
                    .insert(name.clone(), Backoff { attempts, next });
                report.waiting.push(name);
            }
            Outcome::Changed | Outcome::Halted(_) => report.waiting.push(name),
            Outcome::Gone => {}
        }
    }

    /// Send one container and move it by the answer.
    fn forward_one(&self, name: &str) -> Outcome {
        let path = self.settings.spool.join(name);
        let (bytes, before) = match read_container(&path) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Outcome::Gone,
            Err(e) => {
                tracing::warn!("{name}: cannot read it: {e}; will retry");
                return Outcome::Retry;
            }
        };
        let body = match self.copy_to_send(name, &bytes) {
            Ok(body) => body,
            Err(reason) => return self.refuse(name, &before, &Refusal::Before(&reason)),
        };
        let url = &self.settings.url;
        let answer = match self.send(url, "POST", &body) {
            Ok(answer) => answer,
            Err(e) => {
                tracing::warn!("{name}: {url} not reached: {e}; will retry");
                return Outcome::Retry;
            }
        };
        let delivered = self.settings.kind.facts().delivered;
        match classify(
            answer.status,
            self.settings.replace_url.is_some(),
            delivered,
        ) {
            Verdict::Replace => self.replace(name, &before, &body),
            verdict => self.act_on(name, &before, verdict, &answer, "POST", url),
        }
    }

    /// The bytes to send for `bytes`: the container itself, or its compat
    /// copy with each change logged.
    fn copy_to_send(&self, name: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
        match self.settings.compat {
            Compat::Off => Ok(bytes.to_vec()),
            Compat::VconStore => {
                let copy = vcon_store_copy(bytes)?;
                for change in &copy.transforms {
                    tracing::info!(
                        "{name}: --vcon-forward-compat vcon-store {change}; the file on disk is unchanged"
                    );
                }
                Ok(copy.bytes)
            }
        }
    }

    /// The store already holds this uuid: PUT the container to the replace
    /// URL, and act on that answer.
    fn replace(&self, name: &str, before: &Identity, body: &[u8]) -> Outcome {
        let target = container_uuid(body).and_then(|uuid| match &self.settings.replace_url {
            Some(template) => {
                replace_endpoint(template, &uuid).map_err(|e| format!("the replace URL {e}"))
            }
            None => Err("no replace URL".to_string()),
        });
        let endpoint = match target {
            Ok(endpoint) => endpoint,
            Err(reason) => return self.refuse(name, before, &Refusal::Before(&reason)),
        };
        match self.send(&endpoint, "PUT", body) {
            Ok(answer) => {
                let verdict = classify(answer.status, false, self.settings.kind.facts().delivered);
                self.act_on(name, before, verdict, &answer, "PUT", &endpoint)
            }
            Err(e) => {
                tracing::warn!("{name}: {endpoint} not reached: {e}; will retry");
                Outcome::Retry
            }
        }
    }

    /// Move the container by `verdict`.
    fn act_on(
        &self,
        name: &str,
        before: &Identity,
        verdict: Verdict,
        answer: &Answer,
        method: &str,
        url: &Endpoint,
    ) -> Outcome {
        let status = answer.status;
        match verdict {
            Verdict::Delivered => {
                if !self.settle(name, before, &self.settings.done_dir) {
                    return Outcome::Changed;
                }
                tracing::info!(
                    "delivered {name}: {method} {url} answered {status}; moved to '{}'",
                    self.settings.done_dir.display()
                );
                Outcome::Delivered
            }
            Verdict::Retry => {
                tracing::warn!("{name}: {method} {url} answered {status}; will retry");
                Outcome::Retry
            }
            Verdict::Halt => Outcome::Halted(self.halt_reason(name, answer, method, url)),
            Verdict::Refused | Verdict::Replace => {
                self.refuse(name, before, &Refusal::Answered(answer, method, url))
            }
        }
    }

    /// Move a refused container to the failed directory and write its
    /// record beside it.
    fn refuse(&self, name: &str, before: &Identity, why: &Refusal<'_>) -> Outcome {
        let failed = &self.settings.failed_dir;
        if !self.settle(name, before, failed) {
            return Outcome::Changed;
        }
        let record = self.failure_record(name, why);
        let record_name = format!("{name}.error.json");
        if let Err(e) = write_atomically(&failed.join(&record_name), record.as_bytes()) {
            tracing::error!("{name}: could not write {record_name}: {e}");
        }
        match why {
            Refusal::Answered(answer, method, url) => tracing::warn!(
                "refused {name}: {method} {url} answered {}; moved to '{}' beside {record_name}",
                answer.status,
                failed.display()
            ),
            Refusal::Before(reason) => tracing::warn!(
                "refused {name}: not sent: {reason} Moved to '{}' beside {record_name}",
                failed.display()
            ),
        }
        Outcome::Refused
    }

    /// Why the forwarder stopped: the request, the status, and the start of
    /// the store's answer with the auth value removed, so a CDN's
    /// `error code: 1010` is recognizable from the log line alone.
    fn halt_reason(&self, name: &str, answer: &Answer, method: &str, url: &Endpoint) -> String {
        let text = self
            .settings
            .auth
            .scrub(&String::from_utf8_lossy(&answer.body));
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let (start, cut) = cut_to(&flat, MAX_HALT_BODY);
        let more = if cut { "…" } else { "" };
        format!(
            "{method} {url} answered {} for {name}: \"{start}{more}\". A {} refuses the \
             credentials or the client for every container alike, so nothing more is sent and \
             every container stays in the spool. Check the credential, and that nothing replaces \
             the User-Agent: a Cloudflare front refuses some clients with a 403 whose body \
             names error code 1010",
            answer.status, answer.status
        )
    }

    /// The `<name>.error.json` text: the status and the store's answer, or
    /// the forwarder's own reason. The auth value is scrubbed from the answer
    /// before it is cut to [`ReadLimits::error_body`], so a cut cannot leave
    /// part of it behind.
    fn failure_record(&self, name: &str, why: &Refusal<'_>) -> String {
        let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let record = match why {
            Refusal::Answered(answer, method, url) => {
                let text = self
                    .settings
                    .auth
                    .scrub(&String::from_utf8_lossy(&answer.body));
                let (body, cut) = cut_to(&text, self.settings.limits.error_body);
                serde_json::json!({
                    "file": name,
                    "method": method,
                    "url": url.to_string(),
                    "status": answer.status,
                    "body": body,
                    "body_truncated": cut || answer.truncated,
                    "reason": serde_json::Value::Null,
                    "at": at,
                })
            }
            Refusal::Before(reason) => serde_json::json!({
                "file": name,
                "method": serde_json::Value::Null,
                "url": serde_json::Value::Null,
                "status": serde_json::Value::Null,
                "body": serde_json::Value::Null,
                "body_truncated": false,
                "reason": reason,
                "at": at,
            }),
        };
        serde_json::to_string_pretty(&record).unwrap_or_else(|_| record.to_string())
    }

    /// Move `name` from the spool into `dir`, if it is still the file that
    /// was read. Returns whether it was.
    ///
    /// The move comes first and the check after it, on the moved file: a
    /// rewrite that lands between a check and a move would otherwise carry a
    /// container the store never saw out of the queue. When the moved file is
    /// not the one sent, it goes back to the spool (by a link that refuses to
    /// replace a still newer one) and the next pass sends it.
    fn settle(&self, name: &str, before: &Identity, dir: &Path) -> bool {
        let from = self.settings.spool.join(name);
        let to = dir.join(name);
        if let Err(e) = std::fs::rename(&from, &to) {
            tracing::error!("{name}: could not move it to '{}': {e}", dir.display());
            return false;
        }
        let moved = std::fs::symlink_metadata(&to).map(|m| identity(&m));
        if moved.as_ref().is_ok_and(|id| id == before) {
            return true;
        }
        if let Err(e) = std::fs::hard_link(&to, &from)
            && e.kind() != std::io::ErrorKind::AlreadyExists
        {
            tracing::error!("{name}: could not return the rewritten container to the spool: {e}");
            return false;
        }
        let _ = std::fs::remove_file(&to);
        tracing::info!("{name}: rewritten during the send; it goes again on the next pass");
        false
    }

    /// One request to `endpoint`, over TLS when it is `https://`.
    fn send(&self, endpoint: &Endpoint, method: &str, body: &[u8]) -> Result<Answer, String> {
        let mut head = format!(
            "{method} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            endpoint.target,
            endpoint.host_header(),
            body.len()
        );
        head.push_str(&self.settings.auth.name);
        head.push_str(": ");
        head.push_str(&self.settings.auth.value);
        head.push_str("\r\n\r\n");
        let sock = connect(endpoint, self.settings.timeout)?;
        // Read past the kept part by the most a credential can be, so the
        // credential is removed from the answer before the cut.
        let limits = self.settings.limits;
        let read = ReadLimits {
            error_body: limits.error_body.saturating_add(MAX_AUTH_FILE),
            ..limits
        };
        if !endpoint.tls {
            return talk(sock, head.as_bytes(), body, read);
        }
        let config = self.tls.clone().ok_or("no TLS configuration")?;
        let name = rustls::pki_types::ServerName::try_from(endpoint.host.clone())
            .map_err(|e| format!("'{}' is not a certificate name: {e}", endpoint.host))?;
        let conn = rustls::ClientConnection::new(config, name).map_err(|e| e.to_string())?;
        talk(
            rustls::StreamOwned::new(conn, sock),
            head.as_bytes(),
            body,
            read,
        )
    }
}

/// The endpoint `template` names for `uuid`.
///
/// # Errors
///
/// The template has no `{uuid}`, or does not parse. The caller names the
/// setting the template came from.
fn replace_endpoint(template: &str, uuid: &str) -> Result<Endpoint, String> {
    if !template.contains("{uuid}") {
        return Err(format!(
            "'{}' has no {{uuid}} to fill in",
            crate::app::run_provenance::redact_url_userinfo(template)
        ));
    }
    Endpoint::parse(&template.replace("{uuid}", uuid))
}

/// The rustls client configuration: trusting only `ca` when named, else the
/// host's CA bundle.
fn client_config(ca: Option<&Path>) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    let (path, strict) = match ca {
        Some(path) => (path.to_path_buf(), true),
        None => (
            crate::tls_files::host_ca_bundle().ok_or(
                "no CA bundle found on this host; name the store's CA with --vcon-forward-ca",
            )?,
            false,
        ),
    };
    for cert in crate::tls_files::pem_certificates(&path).map_err(|e| format!("{e:#}"))? {
        if let Err(e) = roots.add(cert)
            && strict
        {
            return Err(format!(
                "{}: rustls rejected a certificate: {e}",
                path.display()
            ));
        }
    }
    if roots.is_empty() {
        return Err(format!("{}: no usable CA certificate", path.display()));
    }
    let config = rustls::ClientConfig::builder_with_provider(crate::tls_files::provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Read a container without following a symbolic link, with the identity of
/// the file that was read.
fn read_container(path: &Path) -> std::io::Result<(Vec<u8>, Identity)> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let id = identity(&file.metadata()?);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok((bytes, id))
}

/// Connect to `endpoint`, trying each address it resolves to, and set the
/// read and write timeouts.
fn connect(endpoint: &Endpoint, timeout: Duration) -> Result<std::net::TcpStream, String> {
    use std::net::ToSocketAddrs;
    let addrs = (endpoint.host.as_str(), endpoint.port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve '{}': {e}", endpoint.host))?;
    let mut last = format!("'{}' resolved to no address", endpoint.host);
    for addr in addrs {
        match std::net::TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => {
                sock.set_read_timeout(Some(timeout))
                    .and_then(|()| sock.set_write_timeout(Some(timeout)))
                    .map_err(|e| e.to_string())?;
                return Ok(sock);
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    Err(last)
}

/// Write the request and read the answer: at most `limits.response_head`
/// bytes of status line and headers, and, for an answer other than a `2xx`
/// (whose body is not read), at most `limits.error_body` bytes of its body.
fn talk(
    stream: impl Read + Write,
    head: &[u8],
    body: &[u8],
    limits: ReadLimits,
) -> Result<Answer, String> {
    let mut reader = std::io::BufReader::new(stream);
    let out = reader.get_mut();
    out.write_all(head)
        .and_then(|()| out.write_all(body))
        .and_then(|()| out.flush())
        .map_err(|e| format!("sending: {e}"))?;
    loop {
        let headers = read_head(&mut reader, limits.response_head)?;
        let status = status_of(&headers)?;
        if (100..200).contains(&status) {
            continue;
        }
        if (200..300).contains(&status) || status == 304 {
            return Ok(Answer {
                status,
                body: Vec::new(),
                truncated: false,
            });
        }
        let (body, truncated) = read_body(&mut reader, &headers, limits.error_body);
        return Ok(Answer {
            status,
            body,
            truncated,
        });
    }
}

/// The status line and headers, as lines, refused past `max` bytes.
fn read_head(reader: &mut impl BufRead, max: usize) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let mut total = 0usize;
    loop {
        let mut line = Vec::new();
        let n = reader
            .read_until(b'\n', &mut line)
            .map_err(|e| format!("reading the answer: {e}"))?;
        if n == 0 {
            return Err("the store closed the connection without an answer".into());
        }
        total += n;
        if total > max {
            return Err(format!(
                "the answer's status line and headers are larger than {max} bytes \
                 (--vcon-forward-max-response-head)"
            ));
        }
        let text = String::from_utf8_lossy(&line).trim_end().to_string();
        if text.is_empty() {
            return Ok(lines);
        }
        lines.push(text);
    }
}

/// The status code in a status line.
fn status_of(head: &[String]) -> Result<u16, String> {
    let line = head.first().map(String::as_str).unwrap_or_default();
    let mut words = line.split_whitespace();
    match (
        words.next(),
        words.next().and_then(|c| c.parse::<u16>().ok()),
    ) {
        (Some(v), Some(code)) if v.starts_with("HTTP/") => Ok(code),
        _ => Err("the answer is not HTTP".into()),
    }
}

/// The value of header `name` in `head`, case-insensitively.
fn header_value<'a>(head: &'a [String], name: &str) -> Option<&'a str> {
    head.iter().skip(1).find_map(|line| {
        let (n, v) = line.split_once(':')?;
        n.trim().eq_ignore_ascii_case(name).then_some(v.trim())
    })
}

/// At most `keep` bytes of the body, and whether there was more. A body
/// that ends early or fails to read ends where it ended: it is evidence for
/// a person, not data the forwarder acts on.
fn read_body(reader: &mut impl BufRead, head: &[String], keep: usize) -> (Vec<u8>, bool) {
    let chunked = header_value(head, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return read_chunked(reader, keep);
    }
    let length = header_value(head, "content-length").and_then(|v| v.parse::<u64>().ok());
    let limit = length.map_or(keep as u64 + 1, |n| n.min(keep as u64 + 1));
    let mut body = Vec::new();
    let _ = reader.take(limit).read_to_end(&mut body);
    let more = body.len() > keep || length.is_some_and(|n| n > keep as u64);
    body.truncate(keep);
    (body, more)
}

/// [`read_body`] for `Transfer-Encoding: chunked`.
fn read_chunked(reader: &mut impl BufRead, keep: usize) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).unwrap_or(0) == 0 {
            return (body, false);
        }
        let hex = size_line.split(';').next().unwrap_or_default().trim();
        let Ok(size) = usize::from_str_radix(hex, 16) else {
            return (body, false);
        };
        if size == 0 {
            return (body, false);
        }
        let room = keep.saturating_sub(body.len());
        let mut chunk = Vec::new();
        let _ = reader.take(size.min(room) as u64).read_to_end(&mut chunk);
        body.extend_from_slice(&chunk);
        if size > room {
            return (body, true);
        }
        let mut crlf = String::new();
        let _ = reader.read_line(&mut crlf);
    }
}

/// `text` cut to at most `max` bytes on a character boundary, and whether it
/// was cut.
fn cut_to(text: &str, max: usize) -> (&str, bool) {
    if text.len() <= max {
        return (text, false);
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Write `bytes` to `path` by staging a dot-prefixed sibling and renaming it,
/// so a reader never sees half a record.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .map_or_else(|| "record".into(), |n| n.to_string_lossy().into_owned());
    let staged = path.with_file_name(format!(".{name}.partial"));
    let result = std::fs::File::create(&staged)
        .and_then(|mut f| f.write_all(bytes).and_then(|()| f.sync_all()))
        .and_then(|()| std::fs::rename(&staged, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    result
}

/// Run the forwarder: one pass with `once`, else a pass every `interval`
/// until `stop` says so.
///
/// # Returns
///
/// The exit code: 2 when the settings are refused; 3 when the store refused
/// the credentials or the client (`401`, `403`), in either mode; with `once`,
/// 0 when every container was delivered (or there was none) and 1 when any was
/// refused or is still waiting; without it, 0 once stopped.
///
/// # Side effects
///
/// Creates the delivered and failed directories, connects to the store, and
/// moves files out of the spool.
pub fn run(
    settings: ForwardSettings,
    once: bool,
    interval: Duration,
    stop: &dyn Fn() -> bool,
) -> i32 {
    let Some(mut forwarder) = start(settings) else {
        return 2;
    };
    loop {
        let report = forwarder.pass(Instant::now(), stop);
        if let Some(why) = &report.halted {
            tracing::error!("vCon forwarder stopped: {why}");
        }
        if let Some(code) = pass_outcome(&report, once) {
            return code;
        }
        if !sleep_unless_stopped(interval, stop) || report.stopped {
            tracing::info!("vCon forwarder stopping: a stop was asked for; nothing more is sent");
            return 0;
        }
    }
}

/// Build the forwarder from `settings`, logging what it will do, or the
/// reason the settings are refused (`None`).
fn start(settings: ForwardSettings) -> Option<Forwarder> {
    if let Some(warning) = plaintext_warning(&settings.url) {
        tracing::warn!("{warning}");
    }
    let spool = settings.spool.display().to_string();
    let url = settings.url.to_string();
    match Forwarder::new(settings) {
        Ok(forwarder) => {
            tracing::info!("vCon forwarder watching '{spool}', delivering to {url}");
            Some(forwarder)
        }
        Err(e) => {
            tracing::error!("{e}");
            None
        }
    }
}

/// What one pass means for the run: an exit code, or `None` to keep polling.
///
/// A halt (the store refused the credentials or the client) is 3 in either
/// mode. With `once` the run ends after the pass: 0 when nothing was refused
/// or left waiting, else 1.
fn pass_outcome(report: &PassReport, once: bool) -> Option<i32> {
    if report.halted.is_some() {
        return Some(3);
    }
    once.then(|| i32::from(!(report.refused.is_empty() && report.waiting.is_empty())))
}

/// Sleep for `interval` in short steps. Returns `false` as soon as `stop`
/// says so.
fn sleep_unless_stopped(interval: Duration, stop: &dyn Fn() -> bool) -> bool {
    let until = Instant::now() + interval;
    while Instant::now() < until {
        if stop() {
            return false;
        }
        std::thread::sleep(STOP_POLL_STEP.min(until.saturating_duration_since(Instant::now())));
    }
    !stop()
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// What one pass means for the run: a halt is exit 3 in either mode; with
    /// `once` the run ends, 0 only when nothing was refused or left waiting;
    /// without it the run keeps polling.
    #[test]
    fn a_pass_decides_the_exit_code() {
        let clean = PassReport::default();
        let refused = PassReport {
            refused: vec!["a.json".into()],
            ..PassReport::default()
        };
        let waiting = PassReport {
            waiting: vec!["b.json".into()],
            ..PassReport::default()
        };
        let halted = PassReport {
            halted: Some("401".into()),
            ..PassReport::default()
        };
        assert_eq!(pass_outcome(&clean, true), Some(0));
        assert_eq!(pass_outcome(&refused, true), Some(1));
        assert_eq!(pass_outcome(&waiting, true), Some(1));
        assert_eq!(pass_outcome(&halted, true), Some(3));
        assert_eq!(pass_outcome(&halted, false), Some(3));
        assert_eq!(pass_outcome(&refused, false), None);
        assert_eq!(pass_outcome(&clean, false), None);
    }

    /// `http://` and `https://` parse with their default ports, an explicit
    /// port, an IPv6 literal, and the path with its query intact.
    #[test]
    fn endpoints_parse_scheme_host_port_and_target() -> TestResult {
        let e = Endpoint::parse("http://127.0.0.1:8000/vcon/external-ingress?ingress_list=sipnab")?;
        assert_eq!(
            e,
            Endpoint {
                tls: false,
                host: "127.0.0.1".into(),
                port: 8000,
                target: "/vcon/external-ingress?ingress_list=sipnab".into(),
            }
        );
        let e = Endpoint::parse("https://api.vcon.store/v1/vcons")?;
        assert_eq!((e.tls, e.port, e.target.as_str()), (true, 443, "/v1/vcons"));
        let e = Endpoint::parse("https://store.example.com/v1?mail=a@b")?;
        assert_eq!(e.target, "/v1?mail=a@b");
        let e = Endpoint::parse("http://store.example.com")?;
        assert_eq!((e.port, e.target.as_str()), (80, "/"));
        let e = Endpoint::parse("https://[2001:db8::1]:8443/x")?;
        assert_eq!((e.host.as_str(), e.port), ("2001:db8::1", 8443));
        assert_eq!(e.to_string(), "https://[2001:db8::1]:8443/x");
        Ok(())
    }

    /// A URL the forwarder cannot use is refused up front: another scheme,
    /// no host, a bad port, credentials in the URL (they would be logged), or
    /// a fragment.
    #[test]
    fn endpoints_refuse_what_the_forwarder_cannot_use() {
        for bad in [
            "ftp://store.example.com/",
            "store.example.com/v1",
            "https:///v1",
            "https://store.example.com:99999/",
            "https://store.example.com:x/",
            "https://user:pw@store.example.com/",
            "https://vcs_live_token@store.example.com/v1",
            "https://store.example.com/v1#frag",
            "https://store.example.com /v1",
        ] {
            assert!(Endpoint::parse(bad).is_err(), "{bad} accepted");
        }
    }

    /// A refused URL is quoted in the message with its userinfo replaced by
    /// `[redacted]`, whichever check refuses it: the message reaches the
    /// terminal and the log. Before 2026-10-07 the userinfo refusal itself
    /// printed the password it was refusing.
    #[test]
    fn a_refused_url_never_echoes_its_userinfo() {
        for bad in [
            "https://user:planted-pw@store.example.com/v1",
            "ftp://user:planted-pw@store.example.com/",
            "user:planted-pw@store.example.com/v1",
            "https://user:planted-pw@store.example.com /v1",
            "https://user:planted-pw@store.example.com/v1#frag",
            "https://user:planted-pw@store.example.com:99999/",
            "https://user:planted-pw#x@store.example.com/v1",
            "https://user:planted-pw?x@store.example.com/v1",
        ] {
            let message = Endpoint::parse(bad).err().unwrap_or_default();
            assert!(!message.is_empty(), "{bad} accepted");
            assert!(!message.contains("planted-pw"), "{bad}: {message}");
            assert!(!message.contains("user:"), "{bad}: {message}");
            assert!(message.contains("[redacted]@"), "{bad}: {message}");
        }
        let message = replace_endpoint("https://user:planted-pw@store.example.com/v1", "0")
            .err()
            .unwrap_or_default();
        assert!(!message.contains("planted-pw"), "{message}");
        assert!(message.contains("[redacted]@"), "{message}");
    }

    /// Both header forms the stores use parse, surrounding spaces and the
    /// newline go, and `Debug` never shows the value.
    #[test]
    fn auth_headers_parse_both_forms_and_debug_hides_the_value() -> TestResult {
        let h = AuthHeader::parse("Authorization: Bearer vcs_live_abc123\n")?;
        assert_eq!(h.name(), "Authorization");
        assert_eq!(h.value, "Bearer vcs_live_abc123");
        let h = AuthHeader::parse("  x-conserver-api-token:   k3y  \r\n\n")?;
        assert_eq!(
            (h.name(), h.value.as_str()),
            ("x-conserver-api-token", "k3y")
        );
        let shown = format!("{h:?}");
        assert!(!shown.contains("k3y"), "{shown}");
        assert!(shown.contains("x-conserver-api-token"), "{shown}");
        Ok(())
    }

    /// A malformed auth file is refused, and the error never quotes the line,
    /// which may be the secret itself.
    #[test]
    fn malformed_auth_headers_are_refused_without_quoting_them() -> TestResult {
        for bad in [
            "",
            "\n\n",
            "s3cr3t-only",
            ": s3cr3t-only",
            "Bad Name: s3cr3t-only",
            "Authorization:",
            "Authorization: s3cr3t-only\nx-other: s3cr3t-only",
            "Authorization: s3cr3t\u{7}-only",
            "Content-Length: s3cr3t-only",
            "Host: s3cr3t-only",
        ] {
            match AuthHeader::parse(bad) {
                Ok(_) => return Err(format!("{bad:?} accepted").into()),
                Err(e) => assert!(!e.contains("s3cr3t"), "{e}"),
            }
        }
        Ok(())
    }

    /// The auth value is removed from text the forwarder keeps, such as a
    /// store's answer that echoes the request.
    #[test]
    fn the_auth_value_is_scrubbed_from_kept_text() -> TestResult {
        let h = AuthHeader::parse("Authorization: Bearer vcs_live_abc123")?;
        let kept = h.scrub("echo: Authorization: Bearer vcs_live_abc123; again vcs_live_abc123");
        assert!(!kept.contains("vcs_live_abc123"), "{kept}");
        assert!(kept.contains("[auth value removed]"), "{kept}");
        Ok(())
    }

    /// 2xx delivers; 409 replaces only when a replace URL is set; every other
    /// 4xx refuses; 5xx and anything else retries.
    #[test]
    fn statuses_classify_by_class() {
        const ALL_2XX: (u16, u16) = (200, 299);
        for s in [200, 201, 202, 204, 299] {
            assert_eq!(classify(s, false, ALL_2XX), Verdict::Delivered, "{s}");
        }
        assert_eq!(classify(409, true, ALL_2XX), Verdict::Replace);
        assert_eq!(classify(409, false, ALL_2XX), Verdict::Refused);
        for s in [400, 404, 413, 422, 499] {
            assert_eq!(classify(s, true, ALL_2XX), Verdict::Refused, "{s}");
        }
        for s in [401, 403] {
            assert_eq!(classify(s, true, ALL_2XX), Verdict::Halt, "{s}");
            assert_eq!(classify(s, false, ALL_2XX), Verdict::Halt, "{s}");
        }
        for s in [500, 502, 503, 504, 599, 100, 301, 304] {
            assert_eq!(classify(s, false, ALL_2XX), Verdict::Retry, "{s}");
        }
    }

    /// With the defaults the delay doubles from 2 s and stops at 5 minutes,
    /// and a huge attempt count does not overflow.
    #[test]
    fn backoff_doubles_from_two_seconds_and_caps_at_five_minutes() {
        let delay = |n| {
            backoff_delay(
                n,
                crate::config::FORWARD_BACKOFF_FIRST.default,
                crate::config::FORWARD_BACKOFF_CAP.default,
            )
        };
        assert_eq!(delay(1), Duration::from_secs(2));
        assert_eq!(delay(2), Duration::from_secs(4));
        assert_eq!(delay(3), Duration::from_secs(8));
        assert_eq!(delay(8), Duration::from_secs(256));
        assert_eq!(delay(9), Duration::from_secs(300));
        assert_eq!(delay(u32::MAX), Duration::from_secs(300));
        assert_eq!(delay(0), Duration::from_secs(2));
    }

    /// The delay starts at the configured first delay, doubles, and stops at
    /// the configured cap, whatever the two are.
    #[test]
    fn backoff_follows_the_configured_first_delay_and_cap() {
        assert_eq!(backoff_delay(1, 10, 25), Duration::from_secs(10));
        assert_eq!(backoff_delay(2, 10, 25), Duration::from_secs(20));
        assert_eq!(backoff_delay(3, 10, 25), Duration::from_secs(25));
        assert_eq!(backoff_delay(u32::MAX, 10, 25), Duration::from_secs(25));
        assert_eq!(backoff_delay(1, 7, 7), Duration::from_secs(7));
        assert_eq!(backoff_delay(5, 1, 1000), Duration::from_secs(16));
        let most = u64::from(u32::MAX);
        assert_eq!(backoff_delay(40, most, most), Duration::from_secs(most));
    }

    /// The forwarder flags after `--vcon-forward /srv/spool`, parsed.
    fn flags(extra: &[&str]) -> Result<crate::cli::VconForwardArgs, Box<dyn std::error::Error>> {
        use clap::Parser as _;
        let mut argv = vec!["sipnab", "--vcon-forward", "/srv/spool"];
        argv.extend_from_slice(extra);
        Ok(crate::cli::Cli::try_parse_from(argv)?.vcon_forward_args)
    }

    /// A `[vcon_forward]` section holding `body`.
    fn keys(body: &str) -> Result<crate::config::VconForwardConfig, Box<dyn std::error::Error>> {
        let config: crate::config::Config = toml::from_str(&format!("[vcon_forward]\n{body}\n"))?;
        Ok(config.vcon_forward)
    }

    /// Every `[vcon_forward]` key, each with a value no default has.
    const ALL_KEYS: &str = "kind = \"generic\"\n\
        url = \"https://keys.example.com/v1/vcons\"\n\
        replace_url = \"https://keys.example.com/v1/vcons/{uuid}\"\n\
        auth_file = \"/etc/keys/auth\"\nca = \"/etc/keys/ca.pem\"\n\
        done = \"/srv/keys-done\"\nfailed = \"/srv/keys-failed\"\n\
        interval = 11\ntimeout = 12\ncompat = \"vcon-store\"\n\
        backoff_first = 13\nbackoff_cap = 140\n\
        max_response_head = 15000\nmax_error_body = 1600";

    /// Each `[vcon_forward]` key supplies its setting when its flag is not
    /// given.
    #[test]
    fn every_key_supplies_its_setting() -> TestResult {
        let plan = ForwardPlan::resolve(&flags(&[])?, &keys(ALL_KEYS)?)?;
        assert_eq!(plan.kind, StoreKind::Generic);
        assert_eq!(plan.url.to_string(), "https://keys.example.com/v1/vcons");
        assert_eq!(
            plan.replace_url.as_deref(),
            Some("https://keys.example.com/v1/vcons/{uuid}")
        );
        match &plan.credential {
            Credential::File { path, .. } => assert_eq!(path, Path::new("/etc/keys/auth")),
            Credential::Header(h) => return Err(format!("inline credential {h:?}").into()),
        }
        assert_eq!(plan.ca.as_deref(), Some(Path::new("/etc/keys/ca.pem")));
        assert_eq!(plan.done_dir, Path::new("/srv/keys-done"));
        assert_eq!(plan.failed_dir, Path::new("/srv/keys-failed"));
        assert_eq!(plan.interval, Duration::from_secs(11));
        assert_eq!(plan.timeout, Duration::from_secs(12));
        assert_eq!(plan.compat, Compat::VconStore);
        assert_eq!(
            plan.backoff,
            BackoffPolicy {
                first_secs: 13,
                cap_secs: 140
            }
        );
        assert_eq!(
            plan.limits,
            ReadLimits {
                response_head: 15000,
                error_body: 1600
            }
        );
        Ok(())
    }

    /// Each flag overrides its `[vcon_forward]` key.
    #[test]
    fn every_flag_overrides_its_key() -> TestResult {
        let args = flags(&[
            "--vcon-forward-kind=conserver",
            "--vcon-forward-url=https://flags.example.com/v2/in",
            "--vcon-forward-replace-url=https://flags.example.com/v2/in/{uuid}",
            "--vcon-forward-auth-file=/etc/flags/auth",
            "--vcon-forward-ca=/etc/flags/ca.pem",
            "--vcon-forward-done=/srv/flags-done",
            "--vcon-forward-failed=/srv/flags-failed",
            "--vcon-forward-interval=21",
            "--vcon-forward-timeout=22",
            "--vcon-forward-compat=none",
            "--vcon-forward-backoff-first=23",
            "--vcon-forward-backoff-cap=240",
            "--vcon-forward-max-response-head=25000",
            "--vcon-forward-max-error-body=2600",
        ])?;
        let plan = ForwardPlan::resolve(&args, &keys(ALL_KEYS)?)?;
        assert_eq!(plan.kind, StoreKind::Conserver);
        assert_eq!(plan.url.to_string(), "https://flags.example.com/v2/in");
        assert_eq!(
            plan.replace_url.as_deref(),
            Some("https://flags.example.com/v2/in/{uuid}")
        );
        match &plan.credential {
            Credential::File { path, .. } => assert_eq!(path, Path::new("/etc/flags/auth")),
            Credential::Header(h) => return Err(format!("inline credential {h:?}").into()),
        }
        assert_eq!(plan.ca.as_deref(), Some(Path::new("/etc/flags/ca.pem")));
        assert_eq!(plan.done_dir, Path::new("/srv/flags-done"));
        assert_eq!(plan.failed_dir, Path::new("/srv/flags-failed"));
        assert_eq!(plan.interval, Duration::from_secs(21));
        assert_eq!(plan.timeout, Duration::from_secs(22));
        assert_eq!(plan.compat, Compat::Off);
        assert_eq!(
            plan.backoff,
            BackoffPolicy {
                first_secs: 23,
                cap_secs: 240
            }
        );
        assert_eq!(
            plan.limits,
            ReadLimits {
                response_head: 25000,
                error_body: 2600
            }
        );
        Ok(())
    }

    /// With neither a flag nor a key, each setting takes its declared
    /// default.
    #[test]
    fn without_a_flag_or_key_each_setting_has_its_default() -> TestResult {
        use crate::config::{
            FORWARD_BACKOFF_CAP, FORWARD_BACKOFF_FIRST, FORWARD_INTERVAL, FORWARD_MAX_ERROR_BODY,
            FORWARD_MAX_RESPONSE_HEAD, FORWARD_TIMEOUT,
        };
        let args = flags(&[
            "--vcon-forward-url=http://127.0.0.1:9/x",
            "--vcon-forward-auth-file=/etc/a",
        ])?;
        let plan = ForwardPlan::resolve(&args, &keys("")?)?;
        assert_eq!(plan.kind, StoreKind::Generic);
        assert_eq!(plan.replace_url, None);
        assert_eq!(plan.ca, None);
        assert_eq!(plan.done_dir, Path::new("/srv/spool/delivered"));
        assert_eq!(plan.failed_dir, Path::new("/srv/spool/failed"));
        assert_eq!(plan.interval, Duration::from_secs(FORWARD_INTERVAL.default));
        assert_eq!(plan.timeout, Duration::from_secs(FORWARD_TIMEOUT.default));
        assert_eq!(plan.compat, Compat::Off);
        assert_eq!(
            (plan.backoff.first_secs, plan.backoff.cap_secs),
            (FORWARD_BACKOFF_FIRST.default, FORWARD_BACKOFF_CAP.default)
        );
        assert_eq!(
            (
                plan.limits.response_head as u64,
                plan.limits.error_body as u64
            ),
            (
                FORWARD_MAX_RESPONSE_HEAD.default,
                FORWARD_MAX_ERROR_BODY.default
            )
        );
        Ok(())
    }

    /// The credential has exactly one source. `--vcon-forward-auth` beside
    /// `[vcon_forward] auth_file` is refused naming both; no source at all is
    /// refused naming every one; neither refusal quotes the value.
    #[test]
    fn the_credential_has_one_source() -> TestResult {
        let inline = "--vcon-forward-auth=Authorization: Bearer s3cr3t-value";
        let url = "--vcon-forward-url=http://127.0.0.1:9/x";
        let both = ForwardPlan::resolve(&flags(&[url, inline])?, &keys("auth_file = \"/etc/a\"")?);
        let e = both.err().ok_or("inline beside the key was accepted")?;
        assert!(
            e.contains("--vcon-forward-auth") && e.contains("[vcon_forward] auth_file"),
            "{e}"
        );
        assert!(!e.contains("s3cr3t"), "{e}");
        let none = ForwardPlan::resolve(&flags(&[url])?, &keys("")?);
        let e = none.err().ok_or("no credential was accepted")?;
        for name in [
            "--vcon-forward-auth-file",
            "[vcon_forward] auth_file",
            "SIPNAB_VCON_FORWARD_AUTH",
        ] {
            assert!(e.contains(name), "{name} not in {e}");
        }
        let plan = ForwardPlan::resolve(&flags(&[url, inline])?, &keys("")?)?;
        match &plan.credential {
            Credential::Header(h) => assert_eq!(h.name(), "Authorization"),
            Credential::File { .. } => return Err("the inline credential was not used".into()),
        }
        assert!(!format!("{plan:?}").contains("s3cr3t"), "{plan:?}");
        Ok(())
    }

    /// A URL is checked by one rule, and the refusal names where it came
    /// from: the flag or the key.
    #[test]
    fn a_url_refusal_names_its_source() -> TestResult {
        let auth = "--vcon-forward-auth-file=/etc/a";
        let e = ForwardPlan::resolve(&flags(&[auth, "--vcon-forward-url=x"])?, &keys("")?)
            .err()
            .ok_or("x accepted")?;
        assert!(e.contains("--vcon-forward-url"), "{e}");
        let e = ForwardPlan::resolve(&flags(&[auth])?, &keys("url = \"x\"")?)
            .err()
            .ok_or("x accepted")?;
        assert!(e.contains("[vcon_forward] url"), "{e}");
        let e = ForwardPlan::resolve(&flags(&[auth])?, &keys("")?)
            .err()
            .ok_or("no URL accepted")?;
        assert!(
            e.contains("--vcon-forward-url") && e.contains("[vcon_forward] url"),
            "{e}"
        );
        Ok(())
    }

    /// A back-off pair whose first delay is longer than its cap is refused,
    /// however the two are given, naming both sources.
    #[test]
    fn a_first_delay_longer_than_the_cap_is_refused() -> TestResult {
        let base = [
            "--vcon-forward-url=http://127.0.0.1:9/x",
            "--vcon-forward-auth-file=/etc/a",
        ];
        let mut args = base.to_vec();
        args.push("--vcon-forward-backoff-cap=5");
        let e = ForwardPlan::resolve(&flags(&args)?, &keys("backoff_first = 10")?)
            .err()
            .ok_or("10 > 5 accepted")?;
        assert!(
            e.contains("--vcon-forward-backoff-cap") && e.contains("[vcon_forward] backoff_first"),
            "{e}"
        );
        let mut args = base.to_vec();
        args.push("--vcon-forward-backoff-first=301");
        let e = ForwardPlan::resolve(&flags(&args)?, &keys("")?)
            .err()
            .ok_or("301 > the default 300 accepted")?;
        assert!(
            e.contains("--vcon-forward-backoff-first") && e.contains("the default"),
            "{e}"
        );
        let mut args = base.to_vec();
        args.push("--vcon-forward-backoff-first=300");
        ForwardPlan::resolve(&flags(&args)?, &keys("")?)?;
        Ok(())
    }

    // ── Store kinds ─────────────────────────────────────────────────────

    /// Every kind and compat name the flag and key accept is one the
    /// forwarder knows, and the kind table holds one row per kind name.
    #[test]
    fn every_kind_and_compat_name_maps() {
        for name in crate::config::FORWARD_KINDS {
            let kind = StoreKind::from_name(name);
            assert!(kind.is_some(), "{name}");
            assert_eq!(kind.map(|k| k.facts().name), Some(*name));
        }
        let names: Vec<&str> = STORE_KINDS.iter().map(|f| f.name).collect();
        assert_eq!(names, crate::config::FORWARD_KINDS);
        for name in crate::config::FORWARD_COMPAT {
            assert!(Compat::from_name(name).is_some(), "{name}");
        }
        assert_eq!(StoreKind::from_name("other"), None);
        assert_eq!(Compat::from_name("other"), None);
    }

    /// The vcon-store kind, given the store's base URL and the bare key,
    /// posts to `/v1/vcons` with `Authorization: Bearer <key>` and adapts the
    /// payload as `--vcon-forward-compat vcon-store` does.
    #[test]
    fn the_vcon_store_kind_supplies_its_path_header_and_adaptation() -> TestResult {
        let plan = ForwardPlan::resolve(
            &flags(&[
                "--vcon-forward-kind=vcon-store",
                "--vcon-forward-url=https://api.vcon.store",
                "--vcon-forward-auth=vcs_live_0123456789",
            ])?,
            &keys("")?,
        )?;
        assert_eq!(plan.url.to_string(), "https://api.vcon.store/v1/vcons");
        assert_eq!(plan.compat, Compat::VconStore);
        let generic = ForwardPlan::resolve(
            &flags(&[
                "--vcon-forward-url=https://api.vcon.store/v1/vcons",
                "--vcon-forward-auth=Authorization: Bearer vcs_live_0123456789",
                "--vcon-forward-compat=vcon-store",
            ])?,
            &keys("")?,
        )?;
        assert_eq!(
            plan.compat, generic.compat,
            "the compat flag means the kind's adaptation"
        );
        assert_eq!(plan.url, generic.url);
        let (Credential::Header(by_kind), Credential::Header(by_line)) =
            (&plan.credential, &generic.credential)
        else {
            return Err("inline credentials expected".into());
        };
        assert_eq!(by_kind.name(), "Authorization");
        assert_eq!(by_kind.value, "Bearer vcs_live_0123456789");
        assert_eq!(by_kind.value, by_line.value);
        Ok(())
    }

    /// The conserver kind, given the server's base URL and the bare key,
    /// posts to the `sipnab` external ingress list with
    /// `x-conserver-api-token: <key>` and leaves the payload alone.
    #[test]
    fn the_conserver_kind_supplies_its_path_and_header() -> TestResult {
        let plan = ForwardPlan::resolve(
            &flags(&["--vcon-forward-auth=k3y-0123456789"])?,
            &keys("kind = \"conserver\"\nurl = \"http://127.0.0.1:8000\"")?,
        )?;
        assert_eq!(
            plan.url.to_string(),
            "http://127.0.0.1:8000/vcon/external-ingress?ingress_list=sipnab"
        );
        assert_eq!(plan.compat, Compat::Off);
        let Credential::Header(h) = &plan.credential else {
            return Err("inline credential expected".into());
        };
        assert_eq!(
            (h.name(), h.value.as_str()),
            ("x-conserver-api-token", "k3y-0123456789")
        );
        Ok(())
    }

    /// Every value a kind supplies gives way to an explicit one: a URL with a
    /// path is the endpoint as written, a full header line is sent as
    /// written, and the compat flag or key replaces the kind's adaptation.
    #[test]
    fn an_explicit_setting_overrides_the_kind_default() -> TestResult {
        let plan = ForwardPlan::resolve(
            &flags(&[
                "--vcon-forward-kind=vcon-store",
                "--vcon-forward-url=https://proxy.example.com/other/path",
                "--vcon-forward-auth=X-Api-Key: k3y-0123456789",
                "--vcon-forward-compat=none",
                "--vcon-forward-replace-url=https://proxy.example.com/other/path/{uuid}",
            ])?,
            &keys("")?,
        )?;
        assert_eq!(plan.url.to_string(), "https://proxy.example.com/other/path");
        assert_eq!(plan.compat, Compat::Off);
        assert_eq!(
            plan.replace_url.as_deref(),
            Some("https://proxy.example.com/other/path/{uuid}")
        );
        let Credential::Header(h) = &plan.credential else {
            return Err("inline credential expected".into());
        };
        assert_eq!(
            (h.name(), h.value.as_str()),
            ("X-Api-Key", "k3y-0123456789")
        );
        let keyed = ForwardPlan::resolve(
            &flags(&["--vcon-forward-kind=vcon-store", "--vcon-forward-auth=k"])?,
            &keys("url = \"https://api.vcon.store\"\ncompat = \"none\"")?,
        )?;
        assert_eq!(
            keyed.compat,
            Compat::Off,
            "the compat key replaces the kind's"
        );
        Ok(())
    }

    /// The generic kind keeps today's rule: the credential is a full
    /// `Header-Name: value` line, and a bare key is refused without being
    /// quoted.
    #[test]
    fn the_generic_kind_needs_a_full_header_line() -> TestResult {
        let e = ForwardPlan::resolve(
            &flags(&[
                "--vcon-forward-url=http://127.0.0.1:9/x",
                "--vcon-forward-auth=s3cr3t-bare-key",
            ])?,
            &keys("")?,
        )
        .err()
        .ok_or("a bare key was accepted by the generic kind")?;
        assert!(e.contains("--vcon-forward-auth"), "{e}");
        assert!(!e.contains("s3cr3t"), "{e}");
        let h = AuthHeader::from_credential("s3cr3t-bare-key", StoreKind::Conserver)?;
        assert_eq!(h.name(), "x-conserver-api-token");
        assert!(AuthHeader::from_credential("s3cr3t-bare-key", StoreKind::Generic).is_err());
        Ok(())
    }

    /// The kind key supplies the kind, and the flag overrides it.
    #[test]
    fn the_kind_flag_overrides_the_kind_key() -> TestResult {
        let k = keys("kind = \"conserver\"\nurl = \"http://127.0.0.1:8000\"")?;
        let by_key = ForwardPlan::resolve(&flags(&["--vcon-forward-auth=A: b"])?, &k)?;
        assert_eq!(by_key.kind, StoreKind::Conserver);
        let by_flag = ForwardPlan::resolve(
            &flags(&["--vcon-forward-auth=A: b", "--vcon-forward-kind=generic"])?,
            &k,
        )?;
        assert_eq!(by_flag.kind, StoreKind::Generic);
        assert_eq!(by_flag.url.to_string(), "http://127.0.0.1:8000/");
        Ok(())
    }

    /// A store kind's delivered statuses decide what a 2xx means: a status
    /// outside them is retried, never moved as delivered.
    #[test]
    fn delivered_statuses_come_from_the_kind() {
        assert_eq!(classify(201, false, (201, 201)), Verdict::Delivered);
        assert_eq!(classify(204, false, (201, 201)), Verdict::Retry);
        for facts in &STORE_KINDS {
            assert_eq!(
                classify(201, false, facts.delivered),
                Verdict::Delivered,
                "{}",
                facts.name
            );
            assert_eq!(
                classify(204, false, facts.delivered),
                Verdict::Delivered,
                "{}",
                facts.name
            );
        }
    }

    /// A credential over plain HTTP to anything but loopback draws a
    /// warning; HTTPS, and plain HTTP on loopback, do not.
    #[test]
    fn plain_http_off_loopback_is_warned_about() -> TestResult {
        assert!(plaintext_warning(&Endpoint::parse("http://192.0.2.10:8000/x")?).is_some());
        assert!(plaintext_warning(&Endpoint::parse("http://store.example.com/x")?).is_some());
        assert!(plaintext_warning(&Endpoint::parse("http://127.0.0.1:8000/x")?).is_none());
        assert!(plaintext_warning(&Endpoint::parse("http://localhost:8000/x")?).is_none());
        assert!(plaintext_warning(&Endpoint::parse("http://[::1]:8000/x")?).is_none());
        assert!(plaintext_warning(&Endpoint::parse("https://192.0.2.10/x")?).is_none());
        Ok(())
    }

    /// `extensions` becomes an object, names in their order mapped to `true`,
    /// and every other byte of the container is kept.
    #[test]
    fn the_vcon_store_copy_maps_extensions_in_order() -> TestResult {
        let src = br#"{"vcon":"0.4.0","uuid":"u","extensions":["sip-signaling","CC","a"],"parties":[{"tel":"+15550100001","b":1,"a":2}],"dialog":[{"type":"recording","parties":[0]}]}"#;
        let copy = vcon_store_copy(src)?;
        assert_eq!(
            String::from_utf8_lossy(&copy.bytes),
            r#"{"vcon":"0.4.0","uuid":"u","extensions":{"sip-signaling":true,"CC":true,"a":true},"parties":[{"tel":"+15550100001","b":1,"a":2}],"dialog":[{"type":"recording","parties":[0]}]}"#
        );
        assert_eq!(copy.transforms.len(), 1);
        assert!(
            copy.transforms[0].contains("extensions"),
            "{:?}",
            copy.transforms
        );
        Ok(())
    }

    /// A container with no `extensions`, or one already an object, is sent
    /// as it is, with no transform reported.
    #[test]
    fn the_vcon_store_copy_leaves_other_containers_alone() -> TestResult {
        for src in [
            &br#"{"uuid":"u","dialog":[{"type":"recording","parties":[0]}]}"#[..],
            br#"{"uuid":"u","extensions":{"CC":true},"dialog":[]}"#,
        ] {
            let copy = vcon_store_copy(src)?;
            assert_eq!(copy.bytes, src);
            assert!(copy.transforms.is_empty());
        }
        Ok(())
    }

    /// A Dialog Object missing `type` or `parties` is refused, naming the
    /// index and what is missing; a container that is not a JSON object is
    /// refused too.
    #[test]
    fn the_vcon_store_copy_refuses_dialogs_the_store_rejects() -> TestResult {
        let cases = [
            (&br#"{"dialog":[{"sip_call_id":"c"}]}"#[..], "dialog[0]"),
            (br#"{"dialog":[{"type":"recording","parties":[0]},{"type":"incomplete","disposition":"failed"}]}"#, "dialog[1]"),
            (br#"{"dialog":[{"parties":[0]}]}"#, "`type`"),
            (br#"["not","an","object"]"#, "JSON object"),
        ];
        for (src, needle) in cases {
            match vcon_store_copy(src) {
                Ok(c) => return Err(format!("accepted: {:?}", c.transforms).into()),
                Err(e) => assert!(e.contains(needle), "{needle} not in: {e}"),
            }
        }
        Ok(())
    }

    /// The uuid comes from the container, and only a uuid's characters may go
    /// into a URL path.
    #[test]
    fn the_replace_uuid_is_read_and_checked() {
        assert_eq!(
            container_uuid(br#"{"uuid":"018bcfe5-6800-8a6b-a667-78f1c5213800"}"#).as_deref(),
            Ok("018bcfe5-6800-8a6b-a667-78f1c5213800")
        );
        assert!(container_uuid(br#"{"uuid":"../../admin"}"#).is_err());
        assert!(container_uuid(br#"{"uuid":""}"#).is_err());
        assert!(container_uuid(br#"{"vcon":"0.4.0"}"#).is_err());
        assert!(container_uuid(b"not json").is_err());
    }
}
