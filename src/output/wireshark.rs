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
pub fn generate_tshark_command(
    device: Option<&str>,
    input_file: Option<&str>,
    bpf_filter: Option<&str>,
    display_filter: Option<&str>,
) -> String {
    let mut parts = vec!["tshark".to_string()];

    if let Some(file) = input_file {
        parts.push(format!("-r '{}'", file));
    } else if let Some(dev) = device {
        parts.push(format!("-i {}", dev));
    }

    if let Some(bpf) = bpf_filter {
        parts.push(format!("-f '{}'", bpf));
    }

    if let Some(df) = display_filter {
        parts.push(format!("-Y '{}'", df));
    }

    parts.push("-V".to_string());
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_simple_field() {
        let result = dsl_to_wireshark("method == 'INVITE'").unwrap();
        assert_eq!(result, "sip.Method == 'INVITE'");
    }

    #[test]
    fn translate_compound_filter() {
        let result = dsl_to_wireshark("from.user == '1001' AND src_ip == '10.0.0.1'").unwrap();
        assert_eq!(result, "sip.from.user == '1001' AND ip.src == '10.0.0.1'");
    }

    #[test]
    fn translate_regex_operator() {
        let result = dsl_to_wireshark("ua =~ 'friendly-scanner'").unwrap();
        assert_eq!(result, "sip.User-Agent matches 'friendly-scanner'");
    }

    #[test]
    fn no_field_passthrough() {
        let result = dsl_to_wireshark("custom_field == 'value'").unwrap();
        assert_eq!(result, "custom_field == 'value'");
    }

    #[test]
    fn tshark_from_file() {
        let cmd =
            generate_tshark_command(None, Some("test.pcap"), None, Some("sip.Method == INVITE"));
        assert_eq!(cmd, "tshark -r 'test.pcap' -Y 'sip.Method == INVITE' -V");
    }

    #[test]
    fn tshark_from_device() {
        let cmd = generate_tshark_command(Some("eth0"), None, Some("port 5060"), None);
        assert_eq!(cmd, "tshark -i eth0 -f 'port 5060' -V");
    }

    #[test]
    fn tshark_no_args() {
        let cmd = generate_tshark_command(None, None, None, None);
        assert_eq!(cmd, "tshark -V");
    }
}
