// SPDX-License-Identifier: MIT OR Apache-2.0

//! Wireshark display filter translation and tshark command generation.
//!
//! Converts sipnab's filter DSL field names to Wireshark display filter
//! syntax, and generates tshark CLI commands from capture configuration.

use anyhow::Result;

/// Field name mappings from sipnab DSL to Wireshark display filters.
/// Ordered longest-first to prevent partial replacement.
const FIELD_MAPPINGS: &[(&str, &str)] = &[
    ("from.user", "sip.from.user"),
    ("from.host", "sip.from.host"),
    ("to.user", "sip.to.user"),
    ("to.host", "sip.to.host"),
    ("src_port", "udp.srcport"),
    ("dst_port", "udp.dstport"),
    ("src_ip", "ip.src"),
    ("dst_ip", "ip.dst"),
    ("call_id", "sip.Call-ID"),
    ("method", "sip.Method"),
    ("status", "sip.Status-Code"),
    ("from", "sip.From"),
    ("to", "sip.To"),
    ("ua", "sip.User-Agent"),
    ("contact", "sip.Contact"),
    ("ruri", "sip.r-uri"),
];

/// Check whether the character at a boundary position is a field-name character
/// (alphanumeric, underscore, or dot). Used for word-boundary detection.
fn is_field_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_' || c == '.'
}

/// Translate a sipnab DSL filter expression to a Wireshark display filter.
///
/// Performs field name substitution and operator translation. The result
/// is a best-effort translation -- complex DSL expressions may need manual
/// adjustment. Field names are only replaced at word boundaries to avoid
/// corrupting longer identifiers.
///
/// # Arguments
///
/// * `filter` — The sipnab DSL expression.
///
/// # Returns
///
/// The translated display filter (`=~` becomes `matches`; `==`, `!=`,
/// `AND`, `OR`, `NOT` pass through). Unmapped identifiers are left
/// untouched.
///
/// # Errors
///
/// Currently never fails; the `Result` is kept for future strict
/// validation.
pub fn dsl_to_wireshark(filter: &str) -> Result<String> {
    let mut result = filter.to_string();

    // Replace field names (longest first to avoid partial matches).
    // Only replace at word boundaries to prevent "custom_field" from being
    // corrupted by the "to" -> "sip.To" mapping.
    for &(sipnab_field, ws_field) in FIELD_MAPPINGS {
        let mut new_result = String::with_capacity(result.len());
        let mut search_from = 0;

        while let Some(pos) = result[search_from..].find(sipnab_field) {
            let abs_pos = search_from + pos;
            let end_pos = abs_pos + sipnab_field.len();

            // Check word boundary: character before must not be a field char
            let before_ok = abs_pos == 0 || !is_field_char(result.as_bytes()[abs_pos - 1] as char);
            // Character after must not be a field char
            let after_ok =
                end_pos >= result.len() || !is_field_char(result.as_bytes()[end_pos] as char);

            if before_ok && after_ok {
                new_result.push_str(&result[search_from..abs_pos]);
                new_result.push_str(ws_field);
                search_from = end_pos;
            } else {
                new_result.push_str(&result[search_from..end_pos]);
                search_from = end_pos;
            }
        }

        new_result.push_str(&result[search_from..]);
        result = new_result;
    }

    // Translate operators
    result = result.replace("=~", "matches");
    // ==, !=, AND, OR, NOT are the same in Wireshark syntax

    Ok(result)
}

/// Generate a tshark command line from capture configuration.
///
/// # Arguments
///
/// * `device` — Capture interface (`-i`), used only when `input_file` is
///   `None`.
/// * `input_file` — Pcap file to read (`-r`); takes precedence over
///   `device`.
/// * `bpf_filter` — Capture filter (`-f`), if any.
/// * `display_filter` — Display filter (`-Y`), if any.
///
/// # Returns
///
/// The assembled single-line command ending in `-V` (verbose decode).
/// File and filter values are single-quoted for the shell; nothing is
/// executed here.
pub fn generate_tshark_command(
    device: Option<&str>,
    input_file: Option<&str>,
    bpf_filter: Option<&str>,
    display_filter: Option<&str>,
) -> String {
    let mut parts = vec!["tshark".to_string()];

    if let Some(file) = input_file {
        parts.push(format!("-r {}", shell_single_quote(file)));
    } else if let Some(dev) = device {
        parts.push(format!("-i {}", shell_single_quote(dev)));
    }

    if let Some(bpf) = bpf_filter {
        parts.push(format!("-f {}", shell_single_quote(bpf)));
    }

    if let Some(df) = display_filter {
        parts.push(format!("-Y {}", shell_single_quote(df)));
    }

    parts.push("-V".to_string());
    parts.join(" ")
}

/// POSIX-quote an arbitrary string for safe inclusion in a `/bin/sh` command
/// line. Wraps the value in single quotes and renders any embedded single
/// quote as the `'\''` idiom (close quote, escaped literal quote, reopen), so
/// the value is always exactly one shell word and cannot inject additional
/// commands. A crafted filename or filter (e.g. `evil'; rm -rf ~; '`) is
/// neutralized to inert data.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Tests for DSL→Wireshark field/operator translation and tshark command
/// assembly.
#[cfg(test)]
mod tests {
    use super::*;

    /// `method` maps to `sip.Method` with the value untouched.
    #[test]
    fn translate_simple_field() {
        let result = dsl_to_wireshark("method == 'INVITE'").unwrap();
        assert_eq!(result, "sip.Method == 'INVITE'");
    }

    /// Multiple fields in one AND expression each translate.
    #[test]
    fn translate_compound_filter() {
        let result = dsl_to_wireshark("from.user == '1001' AND src_ip == '10.0.0.1'").unwrap();
        assert_eq!(result, "sip.from.user == '1001' AND ip.src == '10.0.0.1'");
    }

    /// The `=~` operator becomes Wireshark's `matches`.
    #[test]
    fn translate_regex_operator() {
        let result = dsl_to_wireshark("ua =~ 'friendly-scanner'").unwrap();
        assert_eq!(result, "sip.User-Agent matches 'friendly-scanner'");
    }

    /// An unmapped identifier (`custom_field`) passes through unmangled —
    /// the word-boundary guard keeps `to` from corrupting it.
    #[test]
    fn no_field_passthrough() {
        let result = dsl_to_wireshark("custom_field == 'value'").unwrap();
        assert_eq!(result, "custom_field == 'value'");
    }

    /// File input yields `-r` plus the display filter and `-V`.
    #[test]
    fn tshark_from_file() {
        let cmd =
            generate_tshark_command(None, Some("test.pcap"), None, Some("sip.Method == INVITE"));
        assert_eq!(cmd, "tshark -r 'test.pcap' -Y 'sip.Method == INVITE' -V");
    }

    /// Device capture yields `-i` plus the BPF filter and `-V`.
    #[test]
    fn tshark_from_device() {
        let cmd = generate_tshark_command(Some("eth0"), None, Some("port 5060"), None);
        assert_eq!(cmd, "tshark -i 'eth0' -f 'port 5060' -V");
    }

    /// With no configuration the command is the bare `tshark -V`.
    #[test]
    fn tshark_no_args() {
        let cmd = generate_tshark_command(None, None, None, None);
        assert_eq!(cmd, "tshark -V");
    }

    /// The POSIX single-quote escaper wraps in quotes and renders embedded
    /// quotes via the `'\''` idiom.
    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(shell_single_quote("abc"), "'abc'");
        assert_eq!(shell_single_quote(""), "''");
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    /// A filename containing a single quote cannot break out of the quoting
    /// to inject additional shell words.
    #[test]
    fn tshark_command_escapes_single_quote_in_filename() {
        let cmd = generate_tshark_command(None, Some("evil'.pcap"), None, None);
        // The embedded quote is rendered as the escaped idiom, so the shell
        // sees one argument, not a quote-break followed by injected text.
        assert_eq!(cmd, "tshark -r 'evil'\\''.pcap' -V");
    }
}
