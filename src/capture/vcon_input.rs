// SPDX-License-Identifier: MIT OR Apache-2.0

//! Stored vCon containers as an input: `-I` reading a `*.vcon.json`.
//!
//! sipnab writes vCons (`--export-vcon`, the REST and MCP exports). This reads
//! them back, so every surface that analyzes a capture — the dialog list, the
//! ladder, `--report`, `--json`, `--analyze`, the TUI, REST and MCP — can
//! analyze a stored conversation too, through the code that analyzes packets.
//!
//! # How a container becomes input
//!
//! Each stored SIP message is rebuilt as wire text and handed to the packet
//! path as a pre-parsed packet, the way a HEP listener hands over a message it
//! did not capture itself: addressing, transport and time from the container,
//! payload from the rebuilt text. The parser, the dialog store and every
//! analysis then run unchanged, and a rebuilt message carries
//! [`InputOrigin::Vcon`](crate::capture::parse::InputOrigin::Vcon) so every
//! surface that prints an origin says where it came from.
//!
//! Two stored forms are read:
//!
//! - the `sip-message-trace` attachment sipnab writes, and the trace form of
//!   draft-howe-vcon-sip-signaling-00 that it extends: a JSON body whose
//!   `messages` list holds one object per message;
//! - `message/sip` attachments, draft-howe-vcon-sip-signaling-00's other
//!   form: one whole message per attachment, timed by the attachment's
//!   `start`. That form stores no addressing at all.
//!
//! # What a rebuilt message cannot have
//!
//! A vCon is a summary of a capture, not the capture, and the rebuild says so
//! rather than filling the gaps. Every container read is recorded as a
//! [`VconProvenance`], and the capture analysis raises one
//! `rebuilt_from_vcon` finding per container naming what is missing:
//!
//! - **Media.** No RTP is stored, so no stream, MOS, jitter or loss is
//!   computed. A producer's own `media_quality` numbers are reported as its
//!   numbers by the MCP tool and the REST route, never fed back in as if
//!   measured.
//! - **The request-URI.** The trace stores the method, not the request line,
//!   so a rebuilt request carries [`REQUEST_URI_NOT_STORED`], a name in the
//!   reserved `.invalid` domain that can never be mistaken for a real target.
//! - **Header order across names.** The trace keys its header map by name.
//!   Values of one header (a `Via` stack) keep their order.
//! - **Bodies other than SDP**, and headers the producer chose not to store
//!   (sipnab removes credential headers). `Content-Length` is set to the body
//!   the container holds, because the stored value describes bytes that are
//!   not there.
//! - **Frame pointers.** A rebuilt message was never a frame anybody can
//!   re-read, so it has none.
//!
//! # Detection
//!
//! One rule, [`sniffs_as_container`]: a file whose first byte other than
//! whitespace (after an optional UTF-8 byte order mark) is `{` is read as a
//! vCon container, and the vendored schema then decides whether it is one. No
//! capture format sipnab reads begins with that byte, the extension is not
//! consulted — the input set identifies captures by opening them, not by name
//! — and a JSON file that is not a valid container is reported with the
//! schema's reasons instead of libpcap's "unknown file format".

use std::sync::LazyLock;

/// The request-URI a rebuilt request carries when its container did not store
/// one.
///
/// `.invalid` is reserved by [RFC 2606 section 2](https://www.rfc-editor.org/rfc/rfc2606#section-2) for names that must never
/// resolve, so this cannot be confused with a real target and nothing can be
/// sent to it.
pub const REQUEST_URI_NOT_STORED: &str = "sip:request-uri-not-stored.invalid";

/// The largest container file `-I` reads, in bytes.
///
/// A container is read whole to be validated. The cap keeps a stray
/// multi-gigabyte JSON file in a capture directory from being read into
/// memory; a container carrying inline audio over sipnab's 5 MiB default
/// budget is still far below it.
pub const MAX_CONTAINER_BYTES: u64 = 64 * 1024 * 1024;

/// Whether bytes at the start of a file make it a vCon container to read.
///
/// The one detection rule; see the module docs.
#[must_use]
pub fn sniffs_as_container(prefix: &[u8]) -> bool {
    let rest = prefix.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(prefix);
    rest.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{')
}

/// Whether a file NAME is one sipnab writes containers under: `*.vcon.json`,
/// any case.
///
/// A listing hint for a file browser, which cannot open every file it shows
/// to decide. It is not the detection rule: a container under any name is
/// read, and [`sniffs_as_container`] is what decides.
#[must_use]
pub fn is_container_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.len() > ".vcon.json".len() && lower.ends_with(".vcon.json")
}

/// Whether the file at `path` is read as a vCon container.
///
/// Reads at most 64 bytes. A file that cannot be opened is not one: the
/// capture path then reports why it cannot be opened, as it always has.
#[cfg(feature = "native")]
#[must_use]
pub fn is_container_file(path: &std::path::Path) -> bool {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return false;
    };
    let mut prefix = Vec::with_capacity(64);
    if file.take(64).read_to_end(&mut prefix).is_err() {
        return false;
    }
    sniffs_as_container(&prefix)
}

/// What one stored container contributed to a run, and what it could not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VconProvenance {
    /// The file the container was read from, or `inline` for one handed to
    /// the MCP tool or the REST route.
    pub source: String,
    /// The container's `uuid`, when it has one.
    pub uuid: Option<String>,
    /// SIP messages rebuilt from it.
    pub messages: u64,
    /// What is not recomputed or not stored, one sentence each.
    pub not_recomputed: Vec<String>,
    /// The producer's own caveat, verbatim, when the container carries one
    /// (sipnab's `sipnab-capture-completeness` attachment).
    pub producer_note: Option<String>,
    /// Where the container disagrees with the vendored
    /// draft-ietf-vcon-vcon-core-04 schema, one line per finding. Reported,
    /// never a reason to skip a container whose SIP is readable: vcon.store,
    /// for one, hands a container back with `extensions` as an object.
    pub schema_findings: Vec<String>,
}

impl VconProvenance {
    /// The evidence note the `rebuilt_from_vcon` finding carries.
    #[must_use]
    pub fn note(&self) -> String {
        let mut note = format!(
            "{} SIP message(s) rebuilt from this container. Not recomputed or not stored: {}.",
            self.messages,
            self.not_recomputed.join("; ")
        );
        if !self.schema_findings.is_empty() {
            note.push_str(" The container fails the draft-ietf-vcon-vcon-core-04 schema: ");
            note.push_str(&self.schema_findings.join("; "));
            note.push_str(". Its SIP was read regardless.");
        }
        if let Some(producer) = &self.producer_note {
            note.push_str(" The producer's caveat: ");
            note.push_str(producer);
        }
        note
    }
}

/// The top-level members a vCon container has: any one of them makes a JSON
/// object a container to read, and none of them makes it something else.
pub const CONTAINER_MEMBERS: &[&str] = &[
    "vcon",
    "uuid",
    "created_at",
    "parties",
    "dialog",
    "analysis",
    "attachments",
];

/// The extensions a container declares, in either form it arrives in.
///
/// core-04 makes `extensions` an array of names. vcon.store hands a container
/// back with an object instead, `{"sip-signaling": true, "CC": true}`, and
/// sipnab's `--vcon-forward-compat vcon-store` sends that form, so both are
/// read: an array contributes its strings in order, an object the names whose
/// value is `true`, sorted.
#[must_use]
pub fn declared_extensions(container: &serde_json::Value) -> Vec<String> {
    match &container["extensions"] {
        serde_json::Value::Array(names) => names
            .iter()
            .filter_map(serde_json::Value::as_str)
            .map(str::to_string)
            .collect(),
        serde_json::Value::Object(map) => map
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(true))
            .map(|(k, _)| k.clone())
            .collect(),
        _ => Vec::new(),
    }
}

/// Containers this process has read into its stores, in read order.
static READ: LazyLock<parking_lot::Mutex<Vec<VconProvenance>>> =
    LazyLock::new(|| parking_lot::Mutex::new(Vec::new()));

/// Record a container read into this process's stores.
pub fn record_read(provenance: VconProvenance) {
    READ.lock().push(provenance);
}

/// Every container recorded so far.
#[must_use]
pub fn read_report() -> Vec<VconProvenance> {
    READ.lock().clone()
}

/// Forget every recorded container: the stores they filled were replaced.
pub fn reset_read_report() {
    READ.lock().clear();
}

#[cfg(feature = "vcon")]
pub use reader::{
    ContainerError, Rebuilt, RebuiltMessage, into_stores, packets, read_file, rebuild,
};

#[cfg(all(feature = "native", not(feature = "vcon")))]
pub use unbuilt::{NoVconReader, Rebuilt, packets, read_file};

/// The reader's shape in a build without the `vcon` feature: every container
/// is refused with the reason, so `-I` names the missing feature instead of
/// handing the file to libpcap and reporting an unknown file format.
#[cfg(all(feature = "native", not(feature = "vcon")))]
mod unbuilt {
    use super::VconProvenance;

    /// Why this build reads no container.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct NoVconReader;

    impl std::fmt::Display for NoVconReader {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(
                "this is a vCon container, and this build of sipnab was compiled without \
                 the `vcon` feature that reads them",
            )
        }
    }

    impl std::error::Error for NoVconReader {}

    /// A rebuilt container. Never produced by this build.
    #[derive(Debug, Clone)]
    pub struct Rebuilt {
        /// What it contributed.
        pub provenance: VconProvenance,
    }

    /// Refuse: this build has no reader.
    ///
    /// # Errors
    ///
    /// Always.
    pub fn read_file(_path: &std::path::Path) -> Result<Rebuilt, NoVconReader> {
        Err(NoVconReader)
    }

    /// No packets: nothing is ever rebuilt in this build.
    #[must_use]
    pub fn packets(_rebuilt: &Rebuilt) -> Vec<crate::capture::packet::Packet> {
        Vec::new()
    }
}

/// Reading and rebuilding. Needs the schema validator, which lives behind the
/// `vcon` feature with the exporter.
#[cfg(feature = "vcon")]
mod reader {
    use super::{MAX_CONTAINER_BYTES, REQUEST_URI_NOT_STORED, VconProvenance};
    use crate::capture::packet::{Packet, PreParsed, VconOrigin};
    use crate::net::TransportProto;
    use chrono::{DateTime, Utc};
    use serde_json::Value;
    use std::net::{IpAddr, Ipv4Addr};

    /// Why a container could not be read.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ContainerError {
        /// The file could not be read, or is over [`MAX_CONTAINER_BYTES`].
        Unreadable(String),
        /// The bytes are not JSON.
        NotJson(String),
        /// The JSON is not an object.
        NotObject,
        /// The object carries none of [`super::CONTAINER_MEMBERS`].
        NotAVcon,
        /// The container stores no SIP message that could be rebuilt; the
        /// detail says why.
        NoSignaling(String),
    }

    impl std::fmt::Display for ContainerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Unreadable(e) => write!(f, "cannot read the vCon container: {e}"),
                Self::NotJson(e) => write!(f, "not a vCon container: not JSON ({e})"),
                Self::NotObject => f.write_str("not a vCon container: the JSON is not an object"),
                Self::NotAVcon => write!(
                    f,
                    "not a vCon container: a JSON object with none of the members a vCon has \
                     ({})",
                    super::CONTAINER_MEMBERS.join(", ")
                ),
                Self::NoSignaling(why) => {
                    write!(
                        f,
                        "a vCon container with no SIP signaling sipnab can read: {why}"
                    )
                }
            }
        }
    }

    impl std::error::Error for ContainerError {}

    /// One stored SIP message, rebuilt.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct RebuiltMessage {
        /// When the container says it was sent or seen.
        pub timestamp: DateTime<Utc>,
        /// Source address, `0.0.0.0` when the container stored none.
        pub src_addr: IpAddr,
        /// Source port, `0` when the container stored none.
        pub src_port: u16,
        /// Destination address, `0.0.0.0` when the container stored none.
        pub dst_addr: IpAddr,
        /// Destination port, `0` when the container stored none.
        pub dst_port: u16,
        /// Transport as the container stated it, or as the top `Via` names it.
        pub transport: TransportProto,
        /// The message as wire text.
        pub text: Vec<u8>,
    }

    /// Everything one container yields.
    #[derive(Debug, Clone)]
    pub struct Rebuilt {
        /// Its messages, in time order.
        pub messages: Vec<RebuiltMessage>,
        /// What it contributed, and what it could not.
        pub provenance: VconProvenance,
        /// The producer's `media_quality` rows, verbatim, from every sipnab
        /// `report` analysis entry. The producer's numbers, never recomputed.
        pub stored_media_quality: Vec<Value>,
        /// Earliest message time, for ordering a set of inputs.
        pub first_message: Option<DateTime<Utc>>,
    }

    /// Read, validate and rebuild the container in the file at `path`.
    ///
    /// # Errors
    ///
    /// A [`ContainerError`] naming why the file holds no SIP sipnab can read.
    pub fn read_file(path: &std::path::Path) -> Result<Rebuilt, ContainerError> {
        let len = std::fs::metadata(path)
            .map_err(|e| ContainerError::Unreadable(e.to_string()))?
            .len();
        if len > MAX_CONTAINER_BYTES {
            return Err(ContainerError::Unreadable(format!(
                "{len} bytes is over the {MAX_CONTAINER_BYTES}-byte limit for one container"
            )));
        }
        let bytes = std::fs::read(path).map_err(|e| ContainerError::Unreadable(e.to_string()))?;
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|e| ContainerError::NotJson(e.to_string()))?;
        rebuild(&value, &crate::capture::archive::source_name(path))
    }

    /// Validate `container` and rebuild every SIP message it stores.
    ///
    /// # Errors
    ///
    /// [`ContainerError::NotObject`], [`ContainerError::NotAVcon`], or
    /// [`ContainerError::NoSignaling`] when not one stored SIP message could
    /// be rebuilt. A schema finding is NOT an error: it is carried in the
    /// provenance, because the SIP is what is analyzed and a container a
    /// store reshaped is still a record of the call. A message that cannot be
    /// rebuilt beside others that can is skipped and named in the
    /// provenance.
    pub fn rebuild(container: &Value, source: &str) -> Result<Rebuilt, ContainerError> {
        let Some(members) = container.as_object() else {
            return Err(ContainerError::NotObject);
        };
        if !super::CONTAINER_MEMBERS
            .iter()
            .any(|m| members.contains_key(*m))
        {
            return Err(ContainerError::NotAVcon);
        }
        let schema_findings = schema_finding_lines(container);

        let mut gaps = Gaps::default();
        let mut messages: Vec<RebuiltMessage> = Vec::new();
        let attachments = container["attachments"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        for attachment in attachments {
            if attachment["purpose"] == "sip-message-trace" {
                gaps.signaling = true;
                match attachment_body_json(attachment) {
                    Ok(trace) => read_trace(&trace, &mut messages, &mut gaps),
                    Err(e) => gaps.unreadable(format!("a sip-message-trace body: {e}")),
                }
            } else if attachment["mediatype"]
                .as_str()
                .is_some_and(|m| m.eq_ignore_ascii_case("message/sip"))
            {
                gaps.signaling = true;
                match read_message_sip(attachment) {
                    Ok(m) => {
                        gaps.no_addresses += 1;
                        messages.push(m);
                    }
                    Err(e) => gaps.unreadable(format!("a message/sip attachment: {e}")),
                }
            }
        }
        if messages.is_empty() {
            return Err(ContainerError::NoSignaling(no_signaling_reason(
                container, &gaps,
            )));
        }
        // Stable: equal times keep the order the container stored them in.
        messages.sort_by_key(|m| m.timestamp);

        let stored_media_quality = stored_media_quality(container);
        let provenance = VconProvenance {
            source: source.to_string(),
            uuid: container["uuid"].as_str().map(str::to_string),
            messages: messages.len() as u64,
            not_recomputed: gaps.sentences(stored_media_quality.len()),
            producer_note: producer_note(container),
            schema_findings,
        };
        Ok(Rebuilt {
            first_message: messages.first().map(|m| m.timestamp),
            messages,
            provenance,
            stored_media_quality,
        })
    }

    /// Every schema finding against `container`, one line each:
    /// `pointer (keyword): detail`.
    fn schema_finding_lines(container: &Value) -> Vec<String> {
        crate::output::vcon_schema::validate(container)
            .errors
            .iter()
            .map(|e| {
                let at = if e.instance_path.is_empty() {
                    "/"
                } else {
                    e.instance_path.as_str()
                };
                format!("{at} ({}): {}", e.keyword, e.detail)
            })
            .collect()
    }

    /// Why a container yielded no message, in one sentence.
    fn no_signaling_reason(container: &Value, gaps: &Gaps) -> String {
        if gaps.signaling {
            return format!(
                "its signaling attachments held no message that could be rebuilt, the first \
                 because of {}",
                gaps.first_skip.as_deref().unwrap_or("an unrecorded reason")
            );
        }
        let declared = super::declared_extensions(container);
        let declares = if declared.iter().any(|e| e == "sip-signaling") {
            ", although it declares the sip-signaling extension"
        } else {
            ""
        };
        format!("it has no sip-message-trace or message/sip attachment{declares}")
    }

    /// What the rebuild could not reproduce, tallied while it runs.
    #[derive(Debug, Default)]
    struct Gaps {
        /// Whether the container stored any SIP signaling at all.
        signaling: bool,
        /// Requests whose request-URI the container did not store.
        no_request_uri: u64,
        /// Messages read from a header map keyed by name.
        header_map: u64,
        /// Messages whose stored `Content-Length` promised a body the
        /// container does not hold.
        body_absent: u64,
        /// Messages with no stored addressing.
        no_addresses: u64,
        /// Messages with no stored transport and no `Via` naming one.
        no_transport: u64,
        /// Stored messages that could not be rebuilt.
        skipped: u64,
        /// The first reason one could not.
        first_skip: Option<String>,
    }

    impl Gaps {
        /// Count one stored message or body that could not be rebuilt.
        fn unreadable(&mut self, why: String) {
            self.skipped += 1;
            if self.first_skip.is_none() {
                self.first_skip = Some(why);
            }
        }

        /// One sentence per gap, media first because it always applies.
        fn sentences(&self, stored_media_rows: usize) -> Vec<String> {
            let mut out = vec![
                "media: a vCon carries no RTP, so no stream, MOS, jitter or loss was computed \
                 from it"
                    .to_string(),
            ];
            if stored_media_rows > 0 {
                out.push(format!(
                    "the producer's analysis holds {stored_media_rows} media_quality row(s), \
                     its own numbers, not recomputed"
                ));
            }
            if !self.signaling {
                out.push(
                    "the container carries no SIP signaling (no sip-message-trace or \
                     message/sip attachment), so it adds no dialog"
                        .to_string(),
                );
            }
            if self.no_request_uri > 0 {
                out.push(format!(
                    "request-URI: not stored for {} request(s), which carry \
                     {REQUEST_URI_NOT_STORED}",
                    self.no_request_uri
                ));
            }
            if self.header_map > 0 {
                out.push(
                    "header order: the trace keys headers by name, so their order across \
                     names is the container's, not the wire's, and headers the producer did \
                     not store (credential headers, when sipnab produced it) are absent"
                        .to_string(),
                );
            }
            if self.body_absent > 0 {
                out.push(format!(
                    "bodies: {} message(s) had a body other than SDP that the container does \
                     not store",
                    self.body_absent
                ));
            }
            if self.no_addresses > 0 {
                out.push(format!(
                    "addresses: {} message(s) stored no source or destination and carry \
                     0.0.0.0:0",
                    self.no_addresses
                ));
            }
            if self.no_transport > 0 {
                out.push(format!(
                    "transport: {} message(s) stored none and no Via named one; UDP stands in",
                    self.no_transport
                ));
            }
            if self.skipped > 0 {
                out.push(format!(
                    "{} stored message(s) or bodies could not be rebuilt, the first because \
                     of {}",
                    self.skipped,
                    self.first_skip.as_deref().unwrap_or("an unrecorded reason")
                ));
            }
            out
        }
    }

    /// An attachment's body as JSON, whatever encoding carried it.
    fn attachment_body_json(attachment: &Value) -> Result<Value, String> {
        let body = &attachment["body"];
        match attachment["encoding"].as_str() {
            // core-04: any JSON type for `json`. sipnab writes a string
            // holding the JSON text; another producer may inline the object.
            Some("json") | Some("none") | None => match body {
                Value::String(text) => serde_json::from_str(text).map_err(|e| e.to_string()),
                Value::Null => Err("no body".to_string()),
                other => Ok(other.clone()),
            },
            Some("base64url") => {
                let bytes = decode_base64url(body.as_str().ok_or("body is not a string")?)?;
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())
            }
            Some(other) => Err(format!("unknown encoding '{other}'")),
        }
    }

    /// Decode base64url, with or without padding.
    fn decode_base64url(text: &str) -> Result<Vec<u8>, String> {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text.trim_end_matches('='))
            .map_err(|e| format!("not base64url: {e}"))
    }

    /// Every message of one trace body, rebuilt into `out`.
    fn read_trace(trace: &Value, out: &mut Vec<RebuiltMessage>, gaps: &mut Gaps) {
        let Some(list) = trace["messages"].as_array() else {
            gaps.unreadable("a trace with no messages list".to_string());
            return;
        };
        for (i, m) in list.iter().enumerate() {
            match rebuild_trace_message(m, gaps) {
                Ok(message) => out.push(message),
                Err(e) => gaps.unreadable(format!("trace message {i}: {e}")),
            }
        }
    }

    /// The transport a stored name spells, in the one spelling sipnab uses.
    fn transport_named(name: &str) -> Option<TransportProto> {
        [
            TransportProto::Udp,
            TransportProto::Tcp,
            TransportProto::Sctp,
            TransportProto::Tls,
            TransportProto::Ws,
            TransportProto::Wss,
        ]
        .into_iter()
        .find(|t| t.as_str().eq_ignore_ascii_case(name.trim()))
    }

    /// An address and port from a trace message, `0.0.0.0:0` when absent.
    fn endpoint(m: &Value, addr: &str, port: &str) -> Option<(IpAddr, u16)> {
        let ip: IpAddr = m[addr].as_str()?.parse().ok()?;
        let port = u16::try_from(m[port].as_u64()?).ok()?;
        Some((ip, port))
    }

    /// The body a trace message stores: sipnab's `sdp`, or the `body` of the
    /// draft's trace form.
    fn trace_body(m: &Value) -> Result<Vec<u8>, String> {
        if let Some(sdp) = m["sdp"].as_str() {
            return Ok(sdp.as_bytes().to_vec());
        }
        match (m["body"].as_str(), m["body_encoding"].as_str()) {
            (Some(b), Some("base64url")) => decode_base64url(b),
            (Some(b), _) => Ok(b.as_bytes().to_vec()),
            (None, _) => Ok(Vec::new()),
        }
    }

    /// One trace message, rebuilt as wire text.
    fn rebuild_trace_message(m: &Value, gaps: &mut Gaps) -> Result<RebuiltMessage, String> {
        let timestamp = m["timestamp"]
            .as_str()
            .ok_or("no timestamp")
            .and_then(|t| DateTime::parse_from_rfc3339(t).map_err(|_| "a malformed timestamp"))?
            .with_timezone(&Utc);
        let method = m["method"].as_str();
        let status = m["status_code"].as_u64();
        let is_request = m["is_request"].as_bool().unwrap_or(method.is_some());

        let start_line = if is_request {
            let method = method.ok_or("a request with no method")?;
            let uri = match m["request_uri"].as_str() {
                Some(uri) => uri,
                None => {
                    gaps.no_request_uri += 1;
                    REQUEST_URI_NOT_STORED
                }
            };
            format!("{method} {uri} SIP/2.0")
        } else {
            let code = status.ok_or("a response with no status_code")?;
            let reason = m["reason"]
                .as_str()
                .or_else(|| m["status_text"].as_str())
                .unwrap_or_default();
            format!("SIP/2.0 {code} {reason}")
        };

        let body = trace_body(m)?;
        let mut lines: Vec<(String, String)> = Vec::new();
        let mut stored_length: Option<usize> = None;
        if let Some(map) = m["headers"].as_object() {
            gaps.header_map += 1;
            // `Via` first: it is the one header whose position RFC 3261
            // gives meaning to, and the parser reads the top one.
            let mut names: Vec<&String> = map.keys().collect();
            names.sort_by_key(|n| !n.eq_ignore_ascii_case("via"));
            for name in names {
                let values: Vec<&str> = match &map[name] {
                    Value::Array(list) => list.iter().filter_map(Value::as_str).collect(),
                    Value::String(one) => vec![one.as_str()],
                    _ => Vec::new(),
                };
                if name.eq_ignore_ascii_case("content-length") || name == "l" {
                    stored_length = values.first().and_then(|v| v.trim().parse().ok());
                    continue;
                }
                for value in values {
                    lines.push((name.clone(), value.to_string()));
                }
            }
        } else {
            synthesized_headers(m, &body, &mut lines);
        }
        if !lines
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case("call-id") || n == "i")
            && let Some(call_id) = m["call_id"].as_str()
        {
            lines.push(("Call-ID".to_string(), call_id.to_string()));
        }
        if stored_length.is_some_and(|n| n > 0) && body.is_empty() {
            gaps.body_absent += 1;
        }

        let mut text = start_line;
        text.push_str("\r\n");
        for (name, value) in &lines {
            text.push_str(name);
            text.push_str(": ");
            text.push_str(value);
            text.push_str("\r\n");
        }
        text.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        let mut bytes = text.into_bytes();
        bytes.extend_from_slice(&body);

        let unspecified = (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let src = endpoint(m, "src", "src_port");
        let dst = endpoint(m, "dst", "dst_port");
        if src.is_none() || dst.is_none() {
            gaps.no_addresses += 1;
        }
        let (src_addr, src_port) = src.unwrap_or(unspecified);
        let (dst_addr, dst_port) = dst.unwrap_or(unspecified);
        let transport = m["transport"]
            .as_str()
            .and_then(transport_named)
            .or_else(|| crate::capture::parse::top_via_transport(&bytes))
            .unwrap_or_else(|| {
                gaps.no_transport += 1;
                TransportProto::Udp
            });
        Ok(RebuiltMessage {
            timestamp,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            transport,
            text: bytes,
        })
    }

    /// Headers for a trace message that stored only the projected fields.
    fn synthesized_headers(m: &Value, body: &[u8], lines: &mut Vec<(String, String)>) {
        for (key, name) in [
            ("from", "From"),
            ("to", "To"),
            ("call_id", "Call-ID"),
            ("contact", "Contact"),
            ("ua", "User-Agent"),
        ] {
            if let Some(v) = m[key].as_str() {
                lines.push((name.to_string(), v.to_string()));
            }
        }
        if let (Some(n), Some(method)) =
            (m["cseq"]["number"].as_u64(), m["cseq"]["method"].as_str())
        {
            lines.push(("CSeq".to_string(), format!("{n} {method}")));
        }
        if m["sdp"].is_string() && !body.is_empty() {
            lines.push(("Content-Type".to_string(), "application/sdp".to_string()));
        }
    }

    /// One `message/sip` attachment, rebuilt.
    fn read_message_sip(attachment: &Value) -> Result<RebuiltMessage, String> {
        let timestamp = attachment["start"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .ok_or("no usable start time")?
            .with_timezone(&Utc);
        let body = attachment["body"].as_str().ok_or("no inline body")?;
        let text = match attachment["encoding"].as_str() {
            Some("base64url") => decode_base64url(body)?,
            _ => body.as_bytes().to_vec(),
        };
        let unspecified = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        Ok(RebuiltMessage {
            timestamp,
            src_addr: unspecified,
            src_port: 0,
            dst_addr: unspecified,
            dst_port: 0,
            transport: crate::capture::parse::top_via_transport(&text)
                .unwrap_or(TransportProto::Udp),
            text,
        })
    }

    /// The producer's prose caveat from sipnab's completeness attachment.
    fn producer_note(container: &Value) -> Option<String> {
        container["attachments"]
            .as_array()?
            .iter()
            .filter(|a| a["purpose"] == "sipnab-capture-completeness")
            .find_map(|a| {
                attachment_body_json(a).ok()?["note"]
                    .as_str()
                    .map(str::to_string)
            })
    }

    /// The producer's `media_quality` rows from sipnab's analysis entries.
    fn stored_media_quality(container: &Value) -> Vec<Value> {
        let Some(entries) = container["analysis"].as_array() else {
            return Vec::new();
        };
        entries
            .iter()
            .filter(|a| a["vendor"] == "sipnab")
            .filter_map(|a| attachment_body_json(a).ok())
            .filter_map(|body| body["media_quality"].as_array().cloned())
            .flatten()
            .collect()
    }

    /// The packets one rebuilt container feeds the packet path.
    ///
    /// Pre-parsed, like a HEP message: the payload is the rebuilt message and
    /// the addressing is the container's. The source name carries no ordinal,
    /// so no frame pointer is minted for a message that was never a frame.
    #[must_use]
    pub fn packets(rebuilt: &Rebuilt) -> Vec<Packet> {
        let source = format!("vcon:{}", rebuilt.provenance.source);
        rebuilt
            .messages
            .iter()
            .map(|m| {
                Packet::with_pre_parsed(
                    m.timestamp,
                    m.text.clone(),
                    Some(source.clone()),
                    PreParsed {
                        src_addr: m.src_addr,
                        dst_addr: m.dst_addr,
                        src_port: m.src_port,
                        dst_port: m.dst_port,
                        ip_protocol: m.transport.ip_proto_number(),
                        hep: None,
                        vcon: Some(VconOrigin {
                            transport: m.transport,
                        }),
                    },
                )
            })
            .collect()
    }

    /// Route one rebuilt container's packets into a pair of stores through
    /// the shared packet applier, and return how many it routed.
    ///
    /// The store-direct path: the MCP and REST readers and the analysis of an
    /// inline container. The `-I` reader sends the same packets down its
    /// channel instead.
    pub fn into_stores(
        rebuilt: &Rebuilt,
        opts: &crate::pipeline::PipelineOptions,
        dialog_store: &std::sync::Arc<parking_lot::RwLock<crate::sip::dialog_store::DialogStore>>,
        stream_store: &std::sync::Arc<parking_lot::RwLock<crate::rtp::stream_store::StreamStore>>,
    ) -> u64 {
        let mut rtp_heuristic = crate::rtp::heuristic::RtpHeuristic::new();
        let mut routed = 0u64;
        for packet in packets(rebuilt) {
            let Ok(parsed) = crate::capture::parse::parse_packet(&packet) else {
                continue;
            };
            let mut decrypt = crate::pipeline::MediaDecrypt::default();
            crate::pipeline::process_packet(
                &parsed,
                dialog_store,
                stream_store,
                &mut rtp_heuristic,
                opts,
                &mut decrypt,
                None,
            );
            routed += 1;
        }
        routed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    #[test]
    fn the_detection_rule_reads_json_objects_and_nothing_else() {
        assert!(sniffs_as_container(b"{\"vcon\":\"0.4.0\"}"));
        assert!(sniffs_as_container(b"\n\t  {"));
        assert!(sniffs_as_container(b"\xEF\xBB\xBF{"));
        // The capture formats sipnab reads: pcap both byte orders, pcapng,
        // gzip.
        for magic in [
            &[0xd4, 0xc3, 0xb2, 0xa1][..],
            &[0xa1, 0xb2, 0xc3, 0xd4],
            &[0x0a, 0x0d, 0x0d, 0x0a],
            &[0x1f, 0x8b],
        ] {
            assert!(!sniffs_as_container(magic), "{magic:?}");
        }
        assert!(!sniffs_as_container(b"[{}]"), "an array is not a container");
        assert!(!sniffs_as_container(b""));
    }

    #[test]
    fn the_note_names_every_gap_and_the_producer() -> Result<(), TestError> {
        let p = VconProvenance {
            source: "a.vcon.json".to_string(),
            uuid: None,
            messages: 3,
            not_recomputed: vec!["media: none".to_string(), "bodies: 1".to_string()],
            producer_note: Some("Produced by sipnab.".to_string()),
            schema_findings: vec!["/extensions (type): expected an array".to_string()],
        };
        let note = p.note();
        assert!(note.starts_with("3 SIP message(s)"), "{note}");
        assert!(note.contains("media: none; bodies: 1"), "{note}");
        assert!(
            note.contains(
                "fails the draft-ietf-vcon-vcon-core-04 schema: /extensions (type): \
                 expected an array. Its SIP was read regardless."
            ),
            "{note}"
        );
        assert!(
            note.ends_with("The producer's caveat: Produced by sipnab."),
            "{note}"
        );
        Ok(())
    }

    #[cfg(feature = "vcon")]
    mod rebuilding {
        use super::super::{
            ContainerError, REQUEST_URI_NOT_STORED, declared_extensions, packets, rebuild,
        };
        use serde_json::json;

        type TestError = Box<dyn std::error::Error>;

        /// A minimal valid container around one attachment list.
        fn container(attachments: serde_json::Value) -> serde_json::Value {
            json!({
                "vcon": "0.4.0",
                "uuid": "01928e10-193e-8231-b9a2-279e0d16bc46",
                "created_at": "2026-10-09T12:00:00Z",
                "parties": [{"name": "observer"}],
                "attachments": attachments,
            })
        }

        /// A sipnab-shaped trace attachment holding `messages`.
        fn trace(messages: serde_json::Value) -> serde_json::Value {
            json!([{
                "purpose": "sip-message-trace",
                "start": "2026-10-09T12:00:00Z",
                "party": 0,
                "dialog": 0,
                "mediatype": "application/json",
                "encoding": "json",
                "body": json!({"version": 1, "call_id": "c1", "messages": messages}).to_string(),
            }])
        }

        fn invite() -> serde_json::Value {
            json!({
                "timestamp": "2026-10-09T12:00:01.250+00:00",
                "src": "192.0.2.1", "src_port": 5060,
                "dst": "192.0.2.2", "dst_port": 5070,
                "transport": "TLS",
                "is_request": true,
                "method": "INVITE",
                "call_id": "c1",
                "headers": {
                    "Via": ["SIP/2.0/TLS 192.0.2.1:5060;branch=z9hG4bK1",
                            "SIP/2.0/TLS 192.0.2.9:5060;branch=z9hG4bK0"],
                    "From": ["<sip:a@example.com>;tag=1"],
                    "To": ["<sip:b@example.com>"],
                    "Call-ID": ["c1"],
                    "CSeq": ["1 INVITE"],
                    "Content-Type": ["application/dtmf-relay"],
                    "Content-Length": ["24"]
                }
            })
        }

        #[test]
        fn a_trace_message_keeps_its_time_addressing_and_transport() -> Result<(), TestError> {
            let rebuilt = rebuild(&container(trace(json!([invite()]))), "t")?;
            let m = rebuilt.messages.first().ok_or("one message")?;
            assert_eq!(m.timestamp.to_rfc3339(), "2026-10-09T12:00:01.250+00:00");
            assert_eq!(m.src_addr.to_string(), "192.0.2.1");
            assert_eq!((m.src_port, m.dst_port), (5060, 5070));
            assert_eq!(m.transport, crate::net::TransportProto::Tls);
            let text = String::from_utf8(m.text.clone())?;
            assert!(
                text.starts_with(&format!("INVITE {REQUEST_URI_NOT_STORED} SIP/2.0\r\nVia: ")),
                "{text}"
            );
            // The Via stack keeps its order, top first.
            let first = text.find("z9hG4bK1").ok_or("top via")?;
            let second = text.find("z9hG4bK0").ok_or("second via")?;
            assert!(first < second, "{text}");
            // The stored Content-Length described a body that is not here.
            assert!(text.ends_with("Content-Length: 0\r\n\r\n"), "{text}");
            let gaps = rebuilt.provenance.not_recomputed.join("|");
            assert!(gaps.contains("request-URI"), "{gaps}");
            assert!(gaps.contains("bodies: 1"), "{gaps}");
            assert!(gaps.contains("header order"), "{gaps}");
            Ok(())
        }

        #[test]
        fn a_rebuilt_message_parses_as_the_message_it_was() -> Result<(), TestError> {
            let rebuilt = rebuild(&container(trace(json!([invite()]))), "t")?;
            let packets = packets(&rebuilt);
            let parsed = crate::capture::parse::parse_packet(packets.first().ok_or("packet")?)?;
            assert_eq!(
                parsed.input_origin,
                crate::capture::parse::InputOrigin::Vcon
            );
            assert_eq!(parsed.transport, crate::net::TransportProto::Tls);
            assert_eq!(parsed.dst_port, 5070);
            assert!(parsed.frame.is_none(), "a rebuilt message is not a frame");
            let msg = crate::sip::parser::parse_sip_bytes(
                &parsed.payload,
                parsed.timestamp,
                parsed.src_addr,
                parsed.dst_addr,
                parsed.src_port,
                parsed.dst_port,
                parsed.transport,
            )?;
            assert_eq!(msg.call_id(), Some("c1"));
            assert!(msg.malformations().is_empty(), "{:?}", msg.malformations());
            Ok(())
        }

        /// The schema is reported, never a reason to drop readable SIP: the
        /// shape vcon.store hands back has `extensions` as an object.
        #[test]
        fn a_schema_finding_travels_and_does_not_refuse_readable_sip() -> Result<(), TestError> {
            let mut c = container(trace(json!([invite()])));
            c["extensions"] = json!({"sip-signaling": true, "CC": true});
            let rebuilt = rebuild(&c, "t")?;
            assert_eq!(rebuilt.messages.len(), 1);
            let findings = rebuilt.provenance.schema_findings.join("|");
            assert!(findings.contains("/extensions"), "{findings}");
            assert!(rebuilt.provenance.note().contains("/extensions"));
            // A clean container carries none.
            let clean = rebuild(&container(trace(json!([invite()]))), "t")?;
            assert!(clean.provenance.schema_findings.is_empty());
            Ok(())
        }

        /// What is refused is a container whose SIP cannot be read, and a
        /// document that is not a vCon at all.
        #[test]
        fn only_unreadable_sip_or_a_non_vcon_is_refused() {
            assert!(matches!(
                rebuild(&json!({"vcon": "0.4.0"}), "t"),
                Err(ContainerError::NoSignaling(_))
            ));
            assert!(matches!(
                rebuild(&json!({"name": "a config file"}), "t"),
                Err(ContainerError::NotAVcon)
            ));
            assert!(matches!(
                rebuild(&json!([1]), "t"),
                Err(ContainerError::NotObject)
            ));
        }

        /// `extensions` is read in either form a container comes in.
        #[test]
        fn declared_extensions_accepts_the_array_and_the_object_form() {
            assert_eq!(
                declared_extensions(&json!({"extensions": ["sip-signaling", "CC"]})),
                vec!["sip-signaling", "CC"]
            );
            assert_eq!(
                declared_extensions(
                    &json!({"extensions": {"sip-signaling": true, "CC": true, "x": false}})
                ),
                vec!["CC", "sip-signaling"]
            );
            assert!(declared_extensions(&json!({})).is_empty());
        }

        #[test]
        fn a_message_that_cannot_be_rebuilt_is_named_not_dropped() -> Result<(), TestError> {
            let mut broken = invite();
            broken["timestamp"] = json!("yesterday");
            let rebuilt = rebuild(&container(trace(json!([invite(), broken]))), "t")?;
            assert_eq!(rebuilt.messages.len(), 1);
            let gaps = rebuilt.provenance.not_recomputed.join("|");
            assert!(
                gaps.contains("trace message 1: a malformed timestamp"),
                "{gaps}"
            );
            Ok(())
        }

        #[test]
        fn a_container_without_signaling_is_refused_and_says_so() -> Result<(), TestError> {
            let err = rebuild(&container(json!([])), "t")
                .err()
                .ok_or("a container with no SIP must be refused")?;
            assert!(matches!(err, ContainerError::NoSignaling(_)), "{err:?}");
            assert!(err.to_string().contains("no SIP signaling"), "{err}");
            Ok(())
        }
    }
}
