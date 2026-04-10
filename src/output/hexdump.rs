//! Raw hex+ASCII packet dump.
//!
//! Provides a `hexdump` function that formats binary data in the classic
//! `xxd`/`tcpdump` hex dump style: offset, hex bytes (16 per line with a
//! space every 8 bytes), and printable ASCII characters.

use std::fmt::Write;

/// Format binary data as a hex+ASCII dump.
///
/// Output format (16 bytes per line):
/// ```text
/// 00000000  80 00 00 64 00 00 00 00  00 00 00 00 12 34 56 78  |...d.........4Vx|
/// 00000010  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  |................|
/// ```
///
/// Non-printable bytes are shown as `.` in the ASCII column. Returns an
/// empty string for empty input.
pub fn hexdump(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(data.len() * 5);

    for (i, chunk) in data.chunks(16).enumerate() {
        let offset = i * 16;
        let _ = write!(out, "{offset:08x}  ");

        // Hex bytes with a space gap at byte 8
        for (j, byte) in chunk.iter().enumerate() {
            if j == 8 {
                out.push(' ');
            }
            let _ = write!(out, "{byte:02x} ");
        }

        // Pad remaining hex positions if the line is short
        let remaining = 16 - chunk.len();
        for j in 0..remaining {
            if chunk.len() + j == 8 {
                out.push(' ');
            }
            out.push_str("   ");
        }

        // ASCII column
        out.push(' ');
        out.push('|');
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                out.push(*byte as char);
            } else {
                out.push('.');
            }
        }
        out.push('|');
        out.push('\n');
    }

    out
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_bytes_correct_output() {
        let data: Vec<u8> = (0..32).collect();
        let result = hexdump(&data);

        // First line: offset 00000000, bytes 00-0f
        assert!(result.contains("00000000"), "should start with offset 0");
        assert!(
            result.contains("00 01 02 03 04 05 06 07"),
            "first 8 hex bytes"
        );
        assert!(
            result.contains("08 09 0a 0b 0c 0d 0e 0f"),
            "second 8 hex bytes"
        );

        // Second line: offset 00000010, bytes 10-1f
        assert!(result.contains("00000010"), "should have offset 16");
        assert!(result.contains("10 11 12 13"), "second line hex");

        // ASCII column should have pipe delimiters
        assert!(result.contains('|'), "should have ASCII column delimiters");
    }

    #[test]
    fn empty_input_empty_output() {
        assert_eq!(hexdump(&[]), "");
    }

    #[test]
    fn partial_line() {
        let data = b"Hello";
        let result = hexdump(data);

        assert!(
            result.contains("48 65 6c 6c 6f"),
            "should contain 'Hello' in hex"
        );
        assert!(
            result.contains("|Hello|"),
            "should contain 'Hello' in ASCII"
        );
        // Should be padded to align ASCII column
        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1, "short data should be one line");
    }

    #[test]
    fn non_printable_shown_as_dot() {
        let data = [0x00, 0x01, 0x41, 0x42, 0xFF, 0x7F];
        let result = hexdump(&data);

        // 0x41='A', 0x42='B' are printable; rest should be '.'
        assert!(
            result.contains("|..AB..|"),
            "non-printable as dot, printable as-is: got {result}"
        );
    }

    #[test]
    fn exactly_16_bytes() {
        let data: Vec<u8> = (0x30..0x40).collect();
        let result = hexdump(&data);

        let lines: Vec<&str> = result.lines().collect();
        assert_eq!(lines.len(), 1, "exactly 16 bytes should be one line");
        assert!(result.contains("00000000"), "starts at offset 0");
    }

    #[test]
    fn gap_at_byte_8() {
        let data: Vec<u8> = (0..16).collect();
        let result = hexdump(&data);

        // There should be a double-space gap between byte 7 and byte 8 hex
        // Format: "07 " then " " then "08 "
        assert!(
            result.contains("07  08"),
            "should have extra space gap at byte 8 boundary: got {result}"
        );
    }
}
