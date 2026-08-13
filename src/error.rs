// SPDX-License-Identifier: MIT OR Apache-2.0

//! Structured library errors.
//!
//! The library surface used to return `Result<_, String>` in several
//! places, which forced callers to pattern-match on message text. These
//! variants are matchable; `Display` carries the actionable message.

/// Errors returned by sipnab's library surface (config loading,
/// validation, and address/rule parsing).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An explicitly requested config file does not exist.
    #[error("config file not found: {path}")]
    ConfigNotFound {
        /// The path that was requested.
        path: String,
    },

    /// A config file exists but could not be read.
    #[error("cannot read config file {path}: {source}")]
    ConfigRead {
        /// The file that failed to read.
        path: String,
        /// The underlying I/O error (also reachable via `source()`).
        #[source]
        source: std::io::Error,
    },

    /// A config file is not valid TOML (or has invalid key types).
    #[error("invalid config {path}: {source}")]
    ConfigParse {
        /// The file that failed to parse (`"<inline>"` for string input).
        path: String,
        /// The TOML error (also reachable via `source()`).
        #[source]
        source: toml::de::Error,
    },

    /// Config values parsed but failed semantic validation.
    #[error("invalid config value: {0}")]
    ConfigInvalid(String),

    /// Config serialization (`--dump-config`) failed.
    #[error("cannot serialize config: {0}")]
    ConfigSerialize(String),

    /// A CIDR range (HEP allowlist) could not be parsed.
    #[error("invalid CIDR '{input}': {reason}")]
    InvalidCidr {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// A bind address (API / metrics / MCP HTTP) could not be parsed.
    #[error("invalid bind address '{input}': {reason}")]
    InvalidBindAddr {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// An alert rule (`--alert`) could not be parsed.
    #[error("invalid alert rule '{input}': {reason}")]
    InvalidAlertRule {
        /// The offending input.
        input: String,
        /// Why it failed.
        reason: String,
    },

    /// CLI flag combination failed validation.
    #[error("{0}")]
    CliValidation(String),

    /// A server (API / metrics) failed to start or run.
    #[error("server error: {0}")]
    Server(String),
}

/// Errors from the protocol parsers re-exported at the crate root:
/// `parse_sip`,
/// `parse_sip_bytes`,
/// `parse_rtp_header` and
/// `parse_sdp`.
///
/// Variants are matchable (the point of the type); `Display` carries the
/// human-readable message. The `what` fields say which structure the
/// generic variants refer to (e.g. `"RTP header"`, `"SDP body"`).
///
/// # Examples
///
/// ```
/// use sipnab::ParseError;
///
/// match sipnab::rtp::parser::parse_rtp_header(&[0x80]) {
///     Err(ParseError::TooShort { need, got, .. }) => assert!(got < need),
///     other => panic!("expected TooShort, got {other:?}"),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ParseError {
    /// Input is empty where a message or body is required.
    #[error("empty {what}")]
    Empty {
        /// What was expected (e.g. `"SIP message"`, `"SDP body"`).
        what: &'static str,
    },

    /// Input is shorter than a declared or required length.
    #[error("{what} too short: {got} bytes (need {need})")]
    TooShort {
        /// The structure that did not fit.
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },

    /// Bytes that must be text are not valid UTF-8.
    #[error("{what} contains invalid UTF-8")]
    InvalidUtf8 {
        /// The structure that must be text (e.g. `"SIP first line"`).
        what: &'static str,
    },

    /// No CRLF found — SIP messages are line-structured.
    #[error("no CRLF found — not a SIP message")]
    MissingCrlf,

    /// The first line is neither a SIP request line nor a status line.
    #[error("not a SIP message: first line is '{line}'")]
    NotSip {
        /// The offending first line.
        line: String,
    },

    /// A structurally-SIP first line with a malformed element.
    #[error("invalid SIP first line '{line}': {reason}")]
    InvalidFirstLine {
        /// The offending first line.
        line: String,
        /// What is malformed about it.
        reason: &'static str,
    },

    /// A SIP status line whose status code is not a number.
    #[error("invalid SIP status code: '{code}'")]
    InvalidStatusCode {
        /// The text found where the status code belongs.
        code: String,
    },

    /// The RTP version field is not 2.
    #[error("RTP version {version}, expected 2")]
    BadRtpVersion {
        /// The version the packet declared.
        version: u8,
    },

    /// The SDP body does not start with a `v=` line.
    #[error("SDP must start with a v= line")]
    SdpMissingVersion,

    /// The SDP `v=` line declares a version other than 0.
    #[error("unsupported SDP version: '{version}'")]
    BadSdpVersion {
        /// The declared version text.
        version: String,
    },
}

/// Errors from the capture-file and packet-decoding surface re-exported
/// at the crate root: `PcapReader` and
/// `parse_packet`.
///
/// # Examples
///
/// ```
/// use sipnab::{CaptureError, PcapReader};
///
/// let not_a_capture = [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0];
/// match PcapReader::new(&not_a_capture) {
///     Err(CaptureError::UnknownFormat { magic }) => assert_eq!(magic, 0xefbeadde),
///     other => panic!("expected UnknownFormat, got {other:?}"),
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    /// Input is shorter than the structure requires.
    #[error("{what} too short: {got} bytes (need {need})")]
    TooShort {
        /// The structure that did not fit (e.g. `"capture file"`).
        what: &'static str,
        /// Bytes required.
        need: usize,
        /// Bytes available.
        got: usize,
    },

    /// The pcap link-layer header type is not one sipnab decodes.
    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(i32),

    /// A link/network layer failed to decode.
    #[error("failed to decode {what}")]
    PacketDecode {
        /// The layer being decoded (e.g. `"Ethernet packet"`).
        what: &'static str,
        /// The decoder's error.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The packet carries no IP layer (e.g. ARP).
    #[error("{what} has no IP layer")]
    NotIp {
        /// Which packet (`"packet"`, `"inner packet"`, `"ARP packet"`).
        what: &'static str,
    },

    /// An IP layer with no payload to walk into.
    #[error("no IP payload in {what}")]
    NoIpPayload {
        /// Which packet the payload is missing from.
        what: &'static str,
    },

    /// No UDP/TCP transport header.
    #[error("no transport header (not UDP/TCP)")]
    NoTransport,

    /// ICMP traffic, which sipnab does not process.
    #[error("ICMP packets are not processed by sipnab")]
    Icmp,

    /// Nested encapsulation deeper than the safety limit.
    #[error("{kind} encapsulation depth exceeds limit ({limit})")]
    EncapTooDeep {
        /// The encapsulation kind (`"IP-in-IP"`, `"GRE"`).
        kind: &'static str,
        /// The depth limit that was exceeded.
        limit: u8,
    },

    /// A GRE header names an inner protocol sipnab cannot decode.
    #[error("unsupported GRE inner protocol: 0x{0:04X}")]
    UnsupportedGreProtocol(u16),

    /// A pre-parsed (e.g. HEP) packet asserts an IP protocol number that is
    /// not a SIP transport (UDP/TCP/SCTP), so no transport can be labeled
    /// without guessing. The packet is rejected rather than mislabeled.
    #[error("unsupported IP protocol number: {0}")]
    UnsupportedIpProtocol(u8),

    /// Microsoft Network Monitor capture format (convertible, not readable).
    #[error(
        "Microsoft Network Monitor (.cap) format is not supported. \
         Convert to pcap with: editcap -F pcap input.cap output.pcap"
    )]
    NetMonFormat,

    /// The file magic matches no supported capture format.
    #[error(
        "not a pcap/pcapng file (magic: 0x{magic:08x}). \
         Supported formats: .pcap, .pcapng, .cap (pcap format), and their \
         gzip-compressed variants (.pcap.gz, .pcapng.gz)"
    )]
    UnknownFormat {
        /// The unrecognized magic number.
        magic: u32,
    },

    /// The bytes are a gzip stream, not a raw capture; decompress first.
    ///
    /// `crate::capture::pcap_reader::decompress_capture` (and sipnab's file
    /// loaders, which call it) handle this transparently — this error is only
    /// seen by callers that hand a still-compressed buffer straight to
    /// `crate::PcapReader::new`.
    #[error(
        "gzip-compressed capture; decompress it first \
         (sipnab's file loaders and decompress_capture do this automatically)"
    )]
    GzipData,

    /// A gzip-compressed capture failed to decompress.
    #[error("gzip stream is corrupt or truncated: {source}")]
    GzipDecode {
        /// The underlying decompression error.
        #[source]
        source: std::io::Error,
    },

    /// Decompressing a gzip capture would exceed the in-memory safety cap.
    #[error(
        "gzip-compressed capture inflates past the {limit}-byte safety cap; \
         raise --max-gunzip-bytes (or [limits] max_gunzip_bytes) for a capture \
         you trust, or decompress it manually (e.g. gunzip) and open the raw file"
    )]
    GzipTooLarge {
        /// The inflation cap, in bytes.
        limit: u64,
    },
}
