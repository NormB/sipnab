//! TLS record layer parser and SSLKEYLOGFILE support.
//!
//! Provides parsing of TLS records from TCP payloads, heuristic TLS detection,
//! and NSS-format SSLKEYLOGFILE parsing for TLS session key extraction. The
//! actual decryption operations require a [`CryptoBackend`](crate::crypto::CryptoBackend)
//! implementation, which is stubbed in this phase.

use std::path::Path;

use anyhow::{Context, Result};

/// Maximum TLS record payload length (16384 + 2048 for expansion).
const MAX_TLS_RECORD_LENGTH: u16 = 18432;

/// Minimum TLS record header size: 1 (type) + 2 (version) + 2 (length).
const TLS_RECORD_HEADER_LEN: usize = 5;

/// A parsed TLS record from the record layer.
#[derive(Debug, Clone)]
pub struct TlsRecord {
    /// The content type of this record.
    pub content_type: TlsContentType,
    /// The protocol version declared in the record header.
    pub version: TlsVersion,
    /// The payload length in bytes.
    pub length: u16,
    /// The raw record payload (may be encrypted).
    pub payload: Vec<u8>,
}

/// TLS record content types (RFC 8446 Section 5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsContentType {
    /// Change Cipher Spec (20).
    ChangeCipherSpec,
    /// Alert (21).
    Alert,
    /// Handshake (22).
    Handshake,
    /// Application Data (23).
    ApplicationData,
    /// Unrecognized content type.
    Unknown(u8),
}

impl TlsContentType {
    /// Parse a content type byte into the enum variant.
    fn from_byte(b: u8) -> Self {
        match b {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            _ => Self::Unknown(b),
        }
    }

    /// Returns `true` if this is a recognized TLS content type.
    fn is_valid(b: u8) -> bool {
        matches!(b, 20..=23)
    }
}

/// TLS protocol versions as declared in the record layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.0 (0x0301).
    Tls10,
    /// TLS 1.1 (0x0302).
    Tls11,
    /// TLS 1.2 (0x0303). Note: TLS 1.3 records also use 0x0303 in the record layer.
    Tls12,
    /// TLS 1.3 (0x0304). Only appears in the ClientHello supported_versions extension.
    Tls13,
    /// Unrecognized version.
    Unknown(u16),
}

impl TlsVersion {
    /// Parse a two-byte big-endian version into the enum variant.
    fn from_u16(v: u16) -> Self {
        match v {
            0x0301 => Self::Tls10,
            0x0302 => Self::Tls11,
            0x0303 => Self::Tls12,
            0x0304 => Self::Tls13,
            _ => Self::Unknown(v),
        }
    }

    /// Returns `true` if this looks like a plausible TLS version for the record layer.
    fn is_plausible(v: u16) -> bool {
        matches!(v, 0x0300..=0x0304)
    }
}

/// Parse TLS records from a TCP payload.
///
/// Returns a vec because one TCP segment may contain multiple TLS records
/// (record layer pipelining). Parsing stops when the remaining data is too
/// short for a record header or the declared length exceeds available data.
///
/// This parser is lenient: it stops on malformed data rather than returning
/// errors, because partial TLS data is common in packet captures.
pub fn parse_tls_records(data: &[u8]) -> Vec<TlsRecord> {
    let mut records = Vec::new();
    let mut offset = 0;

    while offset + TLS_RECORD_HEADER_LEN <= data.len() {
        let content_type_byte = data[offset];
        if !TlsContentType::is_valid(content_type_byte) {
            break;
        }

        let version = u16::from_be_bytes([data[offset + 1], data[offset + 2]]);
        if !TlsVersion::is_plausible(version) {
            break;
        }

        let length = u16::from_be_bytes([data[offset + 3], data[offset + 4]]);
        if length > MAX_TLS_RECORD_LENGTH {
            break;
        }

        let payload_start = offset + TLS_RECORD_HEADER_LEN;
        let payload_end = payload_start + length as usize;

        if payload_end > data.len() {
            // Truncated record — the segment doesn't contain the full payload.
            break;
        }

        records.push(TlsRecord {
            content_type: TlsContentType::from_byte(content_type_byte),
            version: TlsVersion::from_u16(version),
            length,
            payload: data[payload_start..payload_end].to_vec(),
        });

        offset = payload_end;
    }

    records
}

/// Check if data looks like a TLS record.
///
/// Validates that the first bytes contain a valid content type and a plausible
/// TLS version. This is a fast heuristic, not a full parse.
pub fn is_tls(data: &[u8]) -> bool {
    if data.len() < TLS_RECORD_HEADER_LEN {
        return false;
    }

    let content_type = data[0];
    if !TlsContentType::is_valid(content_type) {
        return false;
    }

    let version = u16::from_be_bytes([data[1], data[2]]);
    if !TlsVersion::is_plausible(version) {
        return false;
    }

    let length = u16::from_be_bytes([data[3], data[4]]);
    length <= MAX_TLS_RECORD_LENGTH
}

// ---------------------------------------------------------------------------
// SSLKEYLOGFILE support
// ---------------------------------------------------------------------------

/// A parsed entry from an NSS SSLKEYLOGFILE.
///
/// The file format is documented at:
/// <https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format>
#[derive(Debug, Clone)]
pub struct KeyLogEntry {
    /// The key label (e.g., `CLIENT_RANDOM`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`).
    pub label: String,
    /// The client random value (32 bytes for TLS 1.2, variable for 1.3 labels).
    pub client_random: Vec<u8>,
    /// The secret value (master secret for TLS 1.2, traffic secret for TLS 1.3).
    pub secret: Vec<u8>,
}

/// Parse an SSLKEYLOGFILE into key log entries.
///
/// Reads the file at `path`, skipping comment lines (starting with `#`) and
/// blank lines. Returns an error if the file cannot be read.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or if individual lines
/// contain invalid hex values.
pub fn parse_keylog_file(path: &Path) -> Result<Vec<KeyLogEntry>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read keylog file: {}", path.display()))?;

    let mut entries = Vec::new();
    for (line_num, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let entry = parse_keylog_line(line).with_context(|| {
            format!(
                "Invalid keylog entry at {}:{}: {line}",
                path.display(),
                line_num + 1
            )
        })?;
        entries.push(entry);
    }

    Ok(entries)
}

/// Parse a single SSLKEYLOGFILE line.
///
/// Format: `LABEL <hex_client_random> <hex_secret>`
///
/// Returns `Ok(entry)` on success or an error if the line format is invalid
/// or contains non-hex characters.
pub fn parse_keylog_line(line: &str) -> Result<KeyLogEntry> {
    let line = line.trim();

    let parts: Vec<&str> = line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        anyhow::bail!("Expected 'LABEL hex_random hex_secret', got: {line}");
    }

    let label = parts[0].to_string();
    let client_random =
        decode_hex(parts[1]).with_context(|| format!("Invalid client_random hex: {}", parts[1]))?;
    let secret =
        decode_hex(parts[2]).with_context(|| format!("Invalid secret hex: {}", parts[2]))?;

    Ok(KeyLogEntry {
        label,
        client_random,
        secret,
    })
}

/// Decode a hex string into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        anyhow::bail!("Odd-length hex string: {hex}");
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("Invalid hex byte at position {i}: {}", &hex[i..i + 2]))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    // -----------------------------------------------------------------------
    // TLS record parsing
    // -----------------------------------------------------------------------

    /// Build a minimal TLS record byte sequence.
    fn make_tls_record(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(content_type);
        buf.extend_from_slice(&version.to_be_bytes());
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn parse_valid_handshake_record() {
        let payload = vec![0x01, 0x00, 0x00, 0x05, 0x03, 0x03, 0x00, 0x00, 0x00];
        let data = make_tls_record(22, 0x0303, &payload);

        let records = parse_tls_records(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsContentType::Handshake);
        assert_eq!(records[0].version, TlsVersion::Tls12);
        assert_eq!(records[0].length, payload.len() as u16);
        assert_eq!(records[0].payload, payload);
    }

    #[test]
    fn parse_application_data_record() {
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let data = make_tls_record(23, 0x0303, &payload);

        let records = parse_tls_records(&data);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content_type, TlsContentType::ApplicationData);
    }

    #[test]
    fn parse_multiple_records_in_segment() {
        let handshake_payload = vec![0x01, 0x00];
        let appdata_payload = vec![0xCA, 0xFE];

        let mut data = make_tls_record(22, 0x0303, &handshake_payload);
        data.extend_from_slice(&make_tls_record(23, 0x0303, &appdata_payload));

        let records = parse_tls_records(&data);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].content_type, TlsContentType::Handshake);
        assert_eq!(records[1].content_type, TlsContentType::ApplicationData);
    }

    #[test]
    fn is_tls_on_tls_data() {
        let data = make_tls_record(22, 0x0303, &[0x01, 0x00]);
        assert!(is_tls(&data));
    }

    #[test]
    fn is_tls_on_non_tls_data() {
        // SIP message start
        assert!(!is_tls(b"SIP/2.0 200 OK\r\n"));
        // Too short
        assert!(!is_tls(&[0x16, 0x03]));
        // Invalid content type
        assert!(!is_tls(&[0xFF, 0x03, 0x03, 0x00, 0x05]));
        // Implausible version
        assert!(!is_tls(&[0x16, 0x05, 0x00, 0x00, 0x05]));
    }

    #[test]
    fn truncated_record_stops_cleanly() {
        // Valid header but payload is cut short
        let mut data = vec![22, 0x03, 0x03, 0x00, 0x10]; // claims 16 bytes
        data.extend_from_slice(&[0u8; 8]); // only 8 bytes of payload

        let records = parse_tls_records(&data);
        assert!(records.is_empty(), "Truncated record should not be emitted");
    }

    // -----------------------------------------------------------------------
    // SSLKEYLOGFILE parsing
    // -----------------------------------------------------------------------

    #[test]
    fn parse_keylog_client_random_entry() {
        let line = "CLIENT_RANDOM \
            aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd \
            00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

        let entry = parse_keylog_line(line).expect("should parse CLIENT_RANDOM line");
        assert_eq!(entry.label, "CLIENT_RANDOM");
        assert_eq!(entry.client_random.len(), 32);
        assert_eq!(entry.client_random[0], 0xaa);
        assert_eq!(entry.secret.len(), 48);
        assert_eq!(entry.secret[0], 0x00);
    }

    #[test]
    fn parse_keylog_tls13_labels() {
        let line = "CLIENT_HANDSHAKE_TRAFFIC_SECRET \
            aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd \
            ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

        let entry = parse_keylog_line(line).expect("should parse TLS 1.3 label");
        assert_eq!(entry.label, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        assert_eq!(entry.client_random.len(), 32);
        assert_eq!(entry.secret.len(), 32);
    }

    #[test]
    fn parse_keylog_file_with_comments_and_blanks() {
        let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        writeln!(tmp, "# TLS 1.2 key log").expect("write");
        writeln!(tmp).expect("write");
        writeln!(
            tmp,
            "CLIENT_RANDOM \
            aabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccddaabbccdd \
            00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        )
        .expect("write");
        writeln!(tmp, "# another comment").expect("write");
        writeln!(
            tmp,
            "SERVER_HANDSHAKE_TRAFFIC_SECRET \
            11223344556677881122334455667788112233445566778811223344556677aa \
            ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
        )
        .expect("write");
        tmp.flush().expect("flush");

        let entries = parse_keylog_file(tmp.path()).expect("should parse keylog file");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].label, "CLIENT_RANDOM");
        assert_eq!(entries[1].label, "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    }

    #[test]
    fn parse_keylog_invalid_hex() {
        let line = "CLIENT_RANDOM ZZZZ 0011";
        assert!(parse_keylog_line(line).is_err());
    }
}
