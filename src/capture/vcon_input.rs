// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

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
/// `.invalid` is reserved by [RFC 2606 section 2](https://www.rfc-editor.org/rfc/rfc2606.html#section-2) for names that must never
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

/// Whether a file NAME is one a stored container goes under: `*.vcon.json`,
/// which sipnab writes the unsigned, signed and encrypted forms under, or
/// `*.vcon.json.gz`, the name `gzip` gives the gzip format of one. Any case.
///
/// A listing hint for a file browser, which cannot open every file it shows
/// to decide. It is not the detection rule: a container under any name is
/// read, and [`sniffs_as_container`] is what decides.
#[must_use]
pub fn is_container_file_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".gz").unwrap_or(lower.as_str());
    stem.len() > ".vcon.json".len() && stem.ends_with(".vcon.json")
}

/// The first two bytes of every gzip member, ID1 and ID2
/// ([RFC 1952 section 2.3.1](https://www.rfc-editor.org/rfc/rfc1952.html#section-2.3.1)).
pub const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Whether the file at `path` is read as a vCon container.
///
/// Reads at most 64 bytes. A file that starts with the gzip magic is a gzip
/// format vCon
/// ([draft-ietf-vcon-vcon-core-04 section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4))
/// when the first 64 bytes it inflates to pass [`sniffs_as_container`];
/// a gzip-compressed capture inflates to its capture magic and stays a
/// capture. A file that cannot be opened is not one: the capture path then
/// reports why it cannot be opened, as it always has.
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
    if prefix.starts_with(&GZIP_MAGIC) {
        let Ok(file) = std::fs::File::open(path) else {
            return false;
        };
        let mut inflated = Vec::with_capacity(64);
        // A short or damaged member keeps what inflated before the error,
        // and the reader then reports the damage.
        let _ = flate2::read::GzDecoder::new(file)
            .take(64)
            .read_to_end(&mut inflated);
        return sniffs_as_container(&inflated);
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
    /// The layers taken off the container to reach the unsigned vCon,
    /// outermost first: the gzip format, the encrypted form, the signed form
    /// and its signer. Empty for an unsigned container.
    pub opened: Vec<String>,
    /// The form the file arrived in, outermost first: what the vCon
    /// container report's `form` column prints.
    pub form: ContainerForm,
    /// The Call-IDs of the messages rebuilt from it, sorted, each once: which
    /// of the run's calls this container contributed.
    pub call_ids: Vec<String>,
}

/// The form a container file arrived in, by its outermost layer
/// ([draft-ietf-vcon-vcon-core-04 section 5.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-5.4)):
/// the gzip format wraps any of the other three, so a gzip file is `gzip`
/// whatever is inside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContainerForm {
    /// The unsigned form: the vCon itself.
    #[default]
    Unsigned,
    /// The signed form (section 5.2).
    Signed,
    /// The encrypted form (section 5.3).
    Encrypted,
    /// The gzip format (section 6.2).
    Gzip,
    /// Not a form sipnab can name: the bytes are not JSON, or the JSON is not
    /// an object.
    Unknown,
}

impl ContainerForm {
    /// The word the report prints.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::Signed => "signed",
            Self::Encrypted => "encrypted",
            Self::Gzip => "gzip",
            Self::Unknown => "unknown",
        }
    }
}

/// A container file a directory or glob held that the run did not read, and
/// why: the skipped rows of the vCon container report.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VconSkip {
    /// The file, named as [`VconProvenance::source`] names a read one.
    pub source: String,
    /// The container's `uuid`, when the file opened far enough to have one.
    pub uuid: Option<String>,
    /// The form the file arrived in.
    pub form: ContainerForm,
    /// Why, as one stable word: see `ContainerError::kind`.
    pub reason: String,
    /// Why, in full: the sentence the `Skipping` warning prints.
    pub detail: String,
    /// Schema findings against the unsigned vCon, when the file opened to
    /// one and the schema check ran; `None` when it did not get that far.
    pub validation_findings: Option<usize>,
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
        if !self.opened.is_empty() {
            note.push_str(" Opened from: ");
            note.push_str(&self.opened.join("; "));
            note.push('.');
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

/// The extensions `container` lists in `critical` that sipnab does not
/// support, in the order listed. Empty when it lists none, or only ones in
/// [`crate::output::vcon::DECLARED_EXTENSIONS`].
///
/// [Section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4):
/// "An implementation that does not recognize or support the extensions
/// listed in the critical parameter MUST NOT attempt to process or operate on
/// the vCon, except to reject it or report unsupported content." Every reader
/// (`-I`, `analyze_vcon`, `validate_vcon`, `POST /v1/vcon/analyze` and
/// `POST /v1/vcon/validate`) refuses through [`critical_refusal`], so the
/// rule is this one function.
///
/// `critical` is an array of names in core-04. A single string is read as one
/// name, and an object (the form vcon.store gives `extensions`) contributes
/// the names whose value is `true`. An array entry that is not a string is
/// reported as its JSON text, since no supported name matches it.
#[cfg(feature = "vcon")]
#[must_use]
pub fn unsupported_critical(container: &serde_json::Value) -> Vec<String> {
    let listed: Vec<String> = match &container["critical"] {
        serde_json::Value::Array(names) => names
            .iter()
            .map(|n| n.as_str().map_or_else(|| n.to_string(), str::to_string))
            .collect(),
        serde_json::Value::String(name) => vec![name.clone()],
        serde_json::Value::Object(map) => map
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(true))
            .map(|(k, _)| k.clone())
            .collect(),
        _ => Vec::new(),
    };
    listed
        .into_iter()
        .filter(|name| !crate::output::vcon::DECLARED_EXTENSIONS.contains(&name.as_str()))
        .collect()
}

/// Why sipnab must not read `container`, when its `critical` lists an
/// extension sipnab does not support; `None` otherwise. See
/// [`unsupported_critical`].
#[cfg(feature = "vcon")]
#[must_use]
pub fn critical_refusal(container: &serde_json::Value) -> Option<String> {
    let unsupported = unsupported_critical(container);
    if unsupported.is_empty() {
        return None;
    }
    Some(format!(
        "its critical parameter lists {}, which sipnab does not support, and \
         draft-ietf-vcon-vcon-core-04 section 4.1.4 forbids processing a vCon that \
         lists an unsupported critical extension. sipnab supports {}",
        unsupported.join(", "),
        crate::output::vcon::DECLARED_EXTENSIONS.join(" and ")
    ))
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

/// Container files this process found in a directory or glob and skipped,
/// in the order they were found.
static SKIPPED: LazyLock<parking_lot::Mutex<Vec<VconSkip>>> =
    LazyLock::new(|| parking_lot::Mutex::new(Vec::new()));

/// Record a container file the run skipped.
pub fn record_skipped(skip: VconSkip) {
    SKIPPED.lock().push(skip);
}

/// Every skipped container recorded so far.
#[must_use]
pub fn skipped_report() -> Vec<VconSkip> {
    SKIPPED.lock().clone()
}

/// Forget every recorded container, read or skipped: the stores they filled
/// were replaced.
pub fn reset_read_report() {
    READ.lock().clear();
    SKIPPED.lock().clear();
}

#[cfg(feature = "vcon")]
pub use reader::{
    ContainerError, ReaderKeys, Rebuilt, RebuiltMessage, Refused, form_of_bytes, into_stores,
    open_bytes, opener, packets, read_file, read_file_reporting, rebuild, set_reader_keys,
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
        /// The container's `critical` lists an extension sipnab does not
        /// support; the detail names it. See [`super::critical_refusal`].
        UnsupportedCritical(String),
        /// The container is signed, encrypted or in the gzip format, and
        /// did not open: no key, a signature that does not verify, a signer
        /// the checks refuse. The detail says which.
        Unopened(String),
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
                Self::UnsupportedCritical(why) => {
                    write!(f, "a vCon container sipnab must not read: {why}")
                }
                Self::Unopened(why) => write!(f, "cannot open the vCon container: {why}"),
            }
        }
    }

    impl std::error::Error for ContainerError {}

    impl ContainerError {
        /// Why the container was not read, as one stable word: the
        /// `skip_reason` of the vCon container report, which totals skipped
        /// containers by it.
        ///
        /// An encrypted container refused for want of a key is `no_key`, apart
        /// from every other layer that did not open (`not_opened`), because the
        /// operator's remedy is a flag, `--vcon-key`, and not a different file.
        #[must_use]
        pub fn kind(&self) -> &'static str {
            match self {
                Self::Unreadable(_) => "unreadable",
                Self::NotJson(_) => "not_json",
                Self::NotObject | Self::NotAVcon => "not_a_vcon",
                Self::NoSignaling(_) => "no_sip_signaling",
                Self::UnsupportedCritical(_) => "unsupported_critical",
                Self::Unopened(why) if why == crate::output::vcon_jose::NO_KEY => "no_key",
                Self::Unopened(_) => "not_opened",
            }
        }
    }

    /// The form the file whose bytes are `bytes` arrived in, by its outermost
    /// layer: the gzip magic, else the top-level members of the JSON object
    /// as [`crate::output::vcon_jose::form_of_members`] reads them.
    ///
    /// Reads the member names only, so it costs one scan of the bytes and
    /// keeps no value. A JSON object with none of the members a form has is
    /// `unsigned`: the reader judges it as an unsigned vCon.
    #[must_use]
    pub fn form_of_bytes(bytes: &[u8]) -> super::ContainerForm {
        use super::ContainerForm;
        use crate::output::vcon_jose::Form;
        if bytes.starts_with(&super::GZIP_MAGIC) {
            return ContainerForm::Gzip;
        }
        let Ok(members) = serde_json::from_slice::<
            std::collections::BTreeMap<String, serde::de::IgnoredAny>,
        >(bytes) else {
            return ContainerForm::Unknown;
        };
        match crate::output::vcon_jose::form_of_members(|k| members.contains_key(k)) {
            Form::Encrypted => ContainerForm::Encrypted,
            Form::Signed => ContainerForm::Signed,
            Form::Unsigned | Form::Unknown => ContainerForm::Unsigned,
        }
    }

    /// A container file the reader refused: why, and the skipped row of the
    /// vCon container report, both from the one read of the file.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Refused {
        /// Why the reader refused it.
        pub error: ContainerError,
        /// The skipped row: the form, and, when the file opened to a JSON
        /// object, its `uuid` and its schema finding count.
        pub skip: super::VconSkip,
    }

    impl std::fmt::Display for Refused {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.error.fmt(f)
        }
    }

    impl std::error::Error for Refused {}

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
        read_file_reporting(path).map_err(|refused| refused.error)
    }

    /// [`read_file`], and on a refusal the skipped row of the vCon container
    /// report, taken from the same read: the file is read, opened and
    /// schema-checked once whichever way it goes.
    ///
    /// The schema check does not run on a container whose `critical` lists
    /// an unsupported extension (core-04 section 4.1.4), so that row has no
    /// finding count; nor on a file that did not open to a JSON object.
    ///
    /// # Errors
    ///
    /// A [`Refused`] naming why the file holds no SIP sipnab can read, boxed:
    /// it carries the whole skipped row, and the read path returns it rarely.
    pub fn read_file_reporting(path: &std::path::Path) -> Result<Rebuilt, Box<Refused>> {
        let source = crate::capture::archive::source_name(path);
        let refuse = |error: ContainerError,
                      form: super::ContainerForm,
                      uuid: Option<String>,
                      validation_findings: Option<usize>| {
            Box::new(Refused {
                skip: super::VconSkip {
                    source: source.clone(),
                    uuid,
                    form,
                    reason: error.kind().to_string(),
                    detail: error.to_string(),
                    validation_findings,
                },
                error,
            })
        };
        let unknown = super::ContainerForm::Unknown;
        let len = std::fs::metadata(path)
            .map_err(|e| {
                refuse(
                    ContainerError::Unreadable(e.to_string()),
                    unknown,
                    None,
                    None,
                )
            })?
            .len();
        if len > MAX_CONTAINER_BYTES {
            let why = format!(
                "{len} bytes is over the {MAX_CONTAINER_BYTES}-byte limit for one container"
            );
            return Err(refuse(ContainerError::Unreadable(why), unknown, None, None));
        }
        let bytes = std::fs::read(path).map_err(|e| {
            refuse(
                ContainerError::Unreadable(e.to_string()),
                unknown,
                None,
                None,
            )
        })?;
        let form = form_of_bytes(&bytes);
        let (value, opened) = open_bytes(&bytes).map_err(|e| refuse(e, form, None, None))?;
        match rebuild_counted(&value, &source) {
            Ok(mut rebuilt) => {
                rebuilt.provenance.opened = opened;
                rebuilt.provenance.form = form;
                Ok(rebuilt)
            }
            Err((error, findings)) => {
                let uuid = value["uuid"].as_str().map(str::to_string);
                Err(refuse(error, form, uuid, findings))
            }
        }
    }

    /// How the readers open a signed or encrypted container: the decryption
    /// key and the signer checks `--vcon-key`, `--vcon-signer-ca` and
    /// `--vcon-signer-sha256` (or `[vcon_input]`) name. Each names the
    /// setting it came from, which its refusals quote.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ReaderKeys {
        /// The PEM RSA private key that decrypts an encrypted container.
        pub key: Option<crate::app::vcon_fetch::AuthSource>,
        /// The CA a signed container's signer must chain to.
        pub signer_ca: Option<crate::app::vcon_fetch::SignerCa>,
        /// The SHA-256 fingerprint a signed container's signer must have.
        pub signer_sha256: Option<[u8; 32]>,
        /// The CA an `x5u` URL's server must chain to, which allows fetching
        /// a chain named only by `x5u`; `None` fetches none.
        pub x5u_ca: Option<crate::app::vcon_fetch::SignerCa>,
    }

    /// The opener built from the keys on first use, or why it was not.
    type Built = Option<Result<std::sync::Arc<Opener>, String>>;

    /// The keys this process reads with, and the opener built from them on
    /// first use: the files are read once, when the first container is.
    static KEYS: std::sync::LazyLock<parking_lot::Mutex<(ReaderKeys, Built)>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new((ReaderKeys::default(), None)));

    use crate::output::vcon_jose::Opener;

    /// Set the keys every reader in this process opens containers with.
    pub fn set_reader_keys(keys: ReaderKeys) {
        let mut held = KEYS.lock();
        if held.0 != keys {
            *held = (keys, None);
        }
    }

    /// The opener the keys make, read on first use and kept: what every
    /// reader, and `--vcon-resign`, checks a signer with.
    ///
    /// # Errors
    ///
    /// A key or CA file the keys name does not read.
    pub fn opener() -> Result<std::sync::Arc<Opener>, String> {
        let mut held = KEYS.lock();
        if held.1.is_none() {
            held.1 = Some(build_opener(&held.0).map(std::sync::Arc::new));
        }
        held.1.clone().unwrap_or_else(|| Err("no opener".into()))
    }

    /// Read the key and the signer CA `keys` name.
    fn build_opener(keys: &ReaderKeys) -> Result<Opener, String> {
        let opener = match &keys.key {
            Some(source) => {
                Opener::load(&source.path).map_err(|e| format!("{}: {e}", source.from))?
            }
            None => Opener::without_key(),
        };
        let trust =
            crate::app::vcon_fetch::signer_trust(keys.signer_ca.as_ref(), keys.signer_sha256)
                .map_err(|(_, e)| e)?;
        let opener = opener.trusting(trust);
        Ok(match &keys.x5u_ca {
            Some(ca) => opener.fetching_x5u(x5u_fetcher(ca)?),
            None => opener,
        })
    }

    /// The most bytes of an `x5u` answer read: a certificate chain is a few
    /// kilobytes, so a larger answer is not one.
    pub const X5U_MAX_BYTES: usize = 256 * 1024;

    /// The connect, read and write timeout of an `x5u` fetch.
    pub const X5U_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    /// What the `x5u` fetch's trust refusals call its setting and its peer.
    const X5U_TRUST: crate::tls_files::TrustNames<'static> = crate::tls_files::TrustNames {
        ca: "--vcon-x5u-ca",
        extra: "--vcon-x5u-ca",
        issuer: "the x5u server's CA",
    };

    /// The `x5u` fetch: an HTTPS `GET` through the fetcher's client
    /// (`vcon_forward::client_config` and `exchange`), trusting `ca` (a file,
    /// or the host's bundle for `system`), within [`X5U_TIMEOUT`] and
    /// [`X5U_MAX_BYTES`]. Only a `2xx` answer is a chain. A chain fetched
    /// once is kept for the process, so a directory of containers that name
    /// one URL fetches it once.
    fn x5u_fetcher(
        ca: &crate::app::vcon_fetch::SignerCa,
    ) -> Result<std::sync::Arc<crate::output::vcon_jose::X5uFetch>, String> {
        use crate::app::vcon_fetch::SignerCa;
        use crate::app::vcon_forward::{
            Endpoint, client_config, exchange, read_body, read_head, status_of,
        };
        let file = match ca {
            SignerCa::System(..) => None,
            SignerCa::File(source) => Some(source.path.clone()),
        };
        let config = client_config(file.as_deref(), None, &X5U_TRUST)?;
        let fetched: parking_lot::Mutex<std::collections::HashMap<String, Vec<u8>>> =
            parking_lot::Mutex::default();
        Ok(std::sync::Arc::new(move |url: &str| {
            if let Some(chain) = fetched.lock().get(url) {
                return Ok(chain.clone());
            }
            // The https rule is vcon_jose's, checked before any fetch.
            let endpoint = Endpoint::parse(url, crate::app::https_client::UrlUse::DOWNLOAD)
                .map_err(|e| format!("x5u {url:?}: {e}"))?;
            let request = format!(
                "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sipnab/{}\r\nAccept: application/pem-certificate-chain\r\nConnection: close\r\n\r\n",
                endpoint.target,
                endpoint.host_header(),
                env!("CARGO_PKG_VERSION")
            );
            exchange(
                &endpoint,
                X5U_TIMEOUT,
                Some(&config),
                request.as_bytes(),
                |reader| {
                    let head = read_head(reader, 64 * 1024, "the x5u fetch limit")?;
                    let status = status_of(&head)?;
                    if !(200..300).contains(&status) {
                        return Err(format!("x5u {url:?} answered {status}"));
                    }
                    let (body, more) = read_body(reader, &head, X5U_MAX_BYTES);
                    if more {
                        return Err(format!(
                            "x5u {url:?} answered more than {X5U_MAX_BYTES} bytes, more than a \
                             certificate chain"
                        ));
                    }
                    Ok(body)
                },
            )
            .map_err(|e| format!("x5u {url:?}: {e}"))
            .inspect(|chain| {
                fetched.lock().insert(url.to_owned(), chain.clone());
            })
        }))
    }

    /// The unsigned container `bytes` hold, in whatever form they arrive:
    /// the one unwrap step every reader runs (`-I`, the MCP `analyze_vcon`
    /// and `validate_vcon` tools, `POST /v1/vcon/analyze` and
    /// `POST /v1/vcon/validate`). The gzip format is inflated, the encrypted
    /// form decrypted with the reader's key, the signed form verified and
    /// its signer checked ([`Opener::unwrap`]), all within
    /// [`MAX_CONTAINER_BYTES`]. Returns the container and a description of
    /// each layer taken off, outermost first.
    ///
    /// # Errors
    ///
    /// [`ContainerError::Unopened`] when a layer does not open, and
    /// [`ContainerError::NotJson`] when what is inside is not JSON.
    pub fn open_bytes(bytes: &[u8]) -> Result<(Value, Vec<String>), ContainerError> {
        let cap = usize::try_from(MAX_CONTAINER_BYTES).unwrap_or(usize::MAX);
        let unwrapped = opener()
            .and_then(|opener| opener.unwrap(bytes, cap))
            .map_err(ContainerError::Unopened)?;
        let value = serde_json::from_slice(&unwrapped.unsigned)
            .map_err(|e| ContainerError::NotJson(e.to_string()))?;
        Ok((
            value,
            unwrapped.layers.iter().map(ToString::to_string).collect(),
        ))
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
        rebuild_counted(container, source).map_err(|(error, _)| error)
    }

    /// [`rebuild`], and on a refusal the schema finding count when the
    /// schema check ran: the count the vCon container report gives a
    /// skipped container, from the one check `rebuild` makes.
    fn rebuild_counted(
        container: &Value,
        source: &str,
    ) -> Result<Rebuilt, (ContainerError, Option<usize>)> {
        let Some(members) = container.as_object() else {
            return Err((ContainerError::NotObject, None));
        };
        if !super::CONTAINER_MEMBERS
            .iter()
            .any(|m| members.contains_key(*m))
        {
            return Err((ContainerError::NotAVcon, None));
        }
        if let Some(why) = super::critical_refusal(container) {
            return Err((ContainerError::UnsupportedCritical(why), None));
        }
        let schema_findings = schema_finding_lines(container);

        let mut gaps = Gaps::default();
        let mut messages: Vec<RebuiltMessage> = Vec::new();
        let attachments = container["attachments"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default();
        // A trace holds every message of the dialog, and the `message/sip`
        // attachments beside it (draft-howe-vcon-sip-signaling-00 section
        // 6.1, such as sipnab's `sip-invite` and `sip-response`) are copies of
        // some of them. Reading both would put each copied message in the
        // ladder twice, so `message/sip` is read only from a container that
        // carries no trace.
        let has_trace = attachments
            .iter()
            .any(|a| a["purpose"] == "sip-message-trace");
        for attachment in attachments {
            if attachment["purpose"] == "sip-message-trace" {
                gaps.signaling = true;
                match attachment_body_json(attachment) {
                    Ok(trace) => read_trace(&trace, &mut messages, &mut gaps),
                    Err(e) => gaps.unreadable(format!("a sip-message-trace body: {e}")),
                }
            } else if !has_trace
                && attachment["mediatype"]
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
            return Err((
                ContainerError::NoSignaling(no_signaling_reason(container, &gaps)),
                Some(schema_findings.len()),
            ));
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
            opened: Vec::new(),
            form: super::ContainerForm::Unsigned,
            call_ids: call_ids_of(&messages),
        };
        Ok(Rebuilt {
            first_message: messages.first().map(|m| m.timestamp),
            messages,
            provenance,
            stored_media_quality,
        })
    }

    /// The Call-IDs of `messages`, sorted, each once, as the parser that
    /// fills the dialog store reads them: so each names a dialog the run's
    /// store holds under that key.
    fn call_ids_of(messages: &[RebuiltMessage]) -> Vec<String> {
        let ids: std::collections::BTreeSet<String> = messages
            .iter()
            .filter_map(|m| {
                crate::sip::parser::parse_sip(
                    &m.text,
                    m.timestamp,
                    m.src_addr,
                    m.dst_addr,
                    m.src_port,
                    m.dst_port,
                    m.transport,
                )
                .ok()
                .and_then(|parsed| parsed.call_id().map(str::to_string))
            })
            .collect();
        ids.into_iter().collect()
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

    /// A missing key is `no_key`, apart from every other layer that did not
    /// open, because its remedy is the `--vcon-key` flag.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_missing_key_is_its_own_skip_reason() {
        let no_key = ContainerError::Unopened(crate::output::vcon_jose::NO_KEY.to_string());
        assert_eq!(no_key.kind(), "no_key");
        assert_eq!(
            ContainerError::Unopened("the signature does not verify".into()).kind(),
            "not_opened"
        );
        assert_eq!(
            ContainerError::NoSignaling(String::new()).kind(),
            "no_sip_signaling"
        );
        assert_eq!(ContainerError::NotJson(String::new()).kind(), "not_json");
        assert_eq!(ContainerError::NotAVcon.kind(), "not_a_vcon");
    }

    /// The form is the outermost layer: gzip by its magic, else the members.
    #[cfg(feature = "vcon")]
    #[test]
    fn the_form_is_read_off_the_outermost_layer() {
        assert_eq!(form_of_bytes(&[0x1f, 0x8b, 8, 0]), ContainerForm::Gzip);
        assert_eq!(
            form_of_bytes(br#"{"ciphertext":"x","recipients":[]}"#),
            ContainerForm::Encrypted
        );
        assert_eq!(
            form_of_bytes(br#"{"payload":"x","signatures":[]}"#),
            ContainerForm::Signed
        );
        assert_eq!(
            form_of_bytes(br#"{"vcon":"0.4.0"}"#),
            ContainerForm::Unsigned
        );
        assert_eq!(form_of_bytes(br#"{"vcon": "#), ContainerForm::Unknown);
    }

    /// A file over `MAX_CONTAINER_BYTES` is refused by its size, before any
    /// of it is read, and the reason names the size and the limit. The file
    /// is sparse, so the test writes almost nothing to disk.
    #[cfg(feature = "vcon")]
    #[test]
    fn a_container_over_the_size_limit_is_refused_unread() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("huge.vcon.json");
        let file = std::fs::File::create(&path)?;
        file.set_len(MAX_CONTAINER_BYTES + 1)?;
        drop(file);
        let err = match read_file(&path) {
            Ok(_) => return Err("a file over the limit must be refused".into()),
            Err(e) => e,
        };
        assert!(
            matches!(err, ContainerError::Unreadable(_)),
            "refused by size, not by parsing: {err:?}"
        );
        let text = err.to_string();
        assert!(
            text.contains(&(MAX_CONTAINER_BYTES + 1).to_string())
                && text.contains(&MAX_CONTAINER_BYTES.to_string()),
            "the reason names the size and the limit: {text}"
        );
        Ok(())
    }

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
            opened: Vec::new(),
            ..VconProvenance::default()
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

        /// A container whose `critical` lists an extension sipnab does not
        /// support is refused, naming each such extension and no other.
        ///
        /// [Section 4.1.4 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.4):
        /// "An implementation that does not recognize or support the
        /// extensions listed in the critical parameter MUST NOT attempt to
        /// process or operate on the vCon, except to reject it or report
        /// unsupported content."
        #[test]
        fn an_unsupported_critical_extension_is_refused_naming_it() -> Result<(), TestError> {
            let mut c = container(trace(json!([invite()])));
            c["critical"] = json!(["sip-signaling", "x-redaction", "x-other"]);
            let err = rebuild(&c, "t")
                .err()
                .ok_or("a container sipnab cannot interpret must be refused")?
                .to_string();
            for needle in ["x-redaction", "x-other", "critical", "section 4.1.4"] {
                assert!(err.contains(needle), "{needle}: {err}");
            }
            assert_eq!(
                crate::capture::vcon_input::unsupported_critical(&c),
                ["x-redaction", "x-other"],
                "a supported one is not named"
            );
            Ok(())
        }

        /// `critical` is read in each form it can arrive in: the core-04
        /// array, a single string, and the object form vcon.store gives
        /// `extensions`; an entry that is not a string is reported as its
        /// JSON text.
        #[test]
        fn critical_is_read_in_every_form() {
            use crate::capture::vcon_input::unsupported_critical;
            assert!(unsupported_critical(&json!({})).is_empty());
            assert_eq!(unsupported_critical(&json!({"critical": "x"})), ["x"]);
            assert_eq!(
                unsupported_critical(&json!({"critical": {"x": true, "CC": true, "y": false}})),
                ["x"]
            );
            assert_eq!(unsupported_critical(&json!({"critical": [5, "CC"]})), ["5"]);
        }

        /// A `critical` listing only what sipnab supports, or nothing, does
        /// not stop the read.
        #[test]
        fn a_supported_or_empty_critical_list_is_read() -> Result<(), TestError> {
            for critical in [json!([]), json!(["CC"]), json!(["sip-signaling", "CC"])] {
                let mut c = container(trace(json!([invite()])));
                c["critical"] = critical.clone();
                let rebuilt = rebuild(&c, "t").map_err(|e| format!("{critical}: {e}"))?;
                assert_eq!(rebuilt.messages.len(), 1, "{critical}");
            }
            Ok(())
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
