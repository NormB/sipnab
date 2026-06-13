//! Test utilities shared across modules. Only compiled in test builds.

/// Build raw SIP bytes from a request/status line, header lines, and an optional body.
///
/// Each header line gets `\r\n` appended; the blank line separator between
/// headers and body is added automatically.
pub fn build_sip_message(first_line: &str, headers: &[&str], body: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(first_line.as_bytes());
    msg.extend_from_slice(b"\r\n");
    for h in headers {
        msg.extend_from_slice(h.as_bytes());
        msg.extend_from_slice(b"\r\n");
    }
    msg.extend_from_slice(b"\r\n");
    msg.extend_from_slice(body);
    msg
}
