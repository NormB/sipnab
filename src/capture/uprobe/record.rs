//! Reading one binary tracepoint record.
//!
//! The kernel publishes the layout of its own records at
//! `events/uprobes/<name>/format`, and that layout is **read rather than
//! computed**. It is not derivable from the probe definition: the header is
//! followed by padding the kernel chooses, so `common_pid` sits at offset 4 but
//! `__probe_ip` at 8 rather than 8-after-the-header, and the payload begins
//! wherever those leave it. Hard-coding offsets that happen to be right on one
//! kernel is how a reader starts decoding a different field on the next one and
//! reports the result as a SIP message.

use std::collections::BTreeMap;

/// Where one field sits inside a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldSpan {
    /// Byte offset from the start of the record.
    pub offset: usize,
    /// Field width in bytes.
    pub size: usize,
}

/// The parts of a record sipnab reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLayout {
    /// `common_pid` — which process wrote, for the frame pointer's identity.
    pub pid: FieldSpan,
    /// The `b<n>` payload fetches, in ascending buffer order.
    ///
    /// Ordered, because a band is several 64-byte fetches side by side and
    /// reassembling them out of order yields plausible-looking nonsense rather
    /// than an obvious failure.
    pub payload: Vec<FieldSpan>,
    /// `len` — the length the application passed, which bounds everything.
    pub len: FieldSpan,
}

impl RecordLayout {
    /// Total payload bytes this record can carry.
    #[must_use]
    pub fn payload_capacity(&self) -> usize {
        self.payload.iter().map(|f| f.size).sum()
    }
}

/// Parse one `field:` line into a name and span.
fn parse_field(line: &str) -> Option<(String, FieldSpan)> {
    let line = line.trim();
    let decl = line.strip_prefix("field:")?;
    let (decl, rest) = decl.split_once(';')?;
    // `unsigned char b0[]` — the name is the last identifier, minus any `[]`.
    let name = decl
        .trim()
        .rsplit(|c: char| c.is_whitespace() || c == '*')
        .next()?
        .trim_end_matches("[]")
        .to_string();
    let mut offset = None;
    let mut size = None;
    for part in rest.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("offset:") {
            offset = v.trim().parse::<usize>().ok();
        } else if let Some(v) = part.strip_prefix("size:") {
            size = v.trim().parse::<usize>().ok();
        }
    }
    Some((
        name,
        FieldSpan {
            offset: offset?,
            size: size?,
        },
    ))
}

/// Read the layout the kernel published for a probe.
///
/// Returns `None` when a field sipnab depends on is missing, rather than
/// filling in a plausible offset: decoding the wrong bytes is worse than not
/// decoding at all, because the result still looks like a message.
#[must_use]
pub fn parse_layout(format_text: &str) -> Option<RecordLayout> {
    let mut pid = None;
    let mut len = None;
    // Keyed by the numeric suffix of `b<n>`, so ordering is by buffer position
    // rather than by the order the kernel happened to print them.
    let mut payload: BTreeMap<usize, FieldSpan> = BTreeMap::new();

    for line in format_text.lines() {
        let Some((name, span)) = parse_field(line) else {
            continue;
        };
        match name.as_str() {
            "common_pid" => pid = Some(span),
            "len" => len = Some(span),
            other => {
                if let Some(n) = other.strip_prefix('b')
                    && let Ok(at) = n.parse::<usize>()
                {
                    payload.insert(at, span);
                }
            }
        }
    }

    let layout = RecordLayout {
        pid: pid?,
        len: len?,
        payload: payload.into_values().collect(),
    };
    // A layout with no payload would decode every event to an empty message,
    // which reads as "that traffic carried nothing".
    if layout.payload.is_empty() {
        return None;
    }
    Some(layout)
}

/// What one record said, before any acceptance rules are applied.
#[derive(Debug, PartialEq, Eq)]
pub struct RawRecord {
    /// The process that made the write.
    pub pid: u32,
    /// The payload fetches, concatenated in buffer order. Still includes
    /// whatever padding the fetch read past the write.
    pub bytes: Vec<u8>,
    /// The length the application passed. May exceed `bytes.len()`.
    pub len: i32,
}

/// Decode one record using a layout the kernel published.
///
/// Returns `None` if the record is shorter than the layout describes, rather
/// than decoding a truncated buffer into a shorter message.
#[must_use]
pub fn decode(record: &[u8], layout: &RecordLayout) -> Option<RawRecord> {
    let pid_bytes = record.get(layout.pid.offset..layout.pid.offset + 4)?;
    let pid = i32::from_le_bytes(pid_bytes.try_into().ok()?);
    let len_bytes = record.get(layout.len.offset..layout.len.offset + 4)?;
    let len = i32::from_le_bytes(len_bytes.try_into().ok()?);

    let mut bytes = Vec::with_capacity(layout.payload_capacity());
    for f in &layout.payload {
        bytes.extend_from_slice(record.get(f.offset..f.offset + f.size)?);
    }

    Some(RawRecord {
        // A negative pid is not one; the kernel writes it as a signed int.
        pid: u32::try_from(pid).ok()?,
        bytes,
        len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `events/uprobes/<name>/format` on a 6.8 kernel, for a
    /// single-band probe. Real kernel output rather than a guess at its shape.
    const REAL_FORMAT: &str = "name: sipnab_fmt\nID: 1815\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:unsigned long __probe_ip;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:u8 b0[];\toffset:16;\tsize:64;\tsigned:0;\n\tfield:s32 len;\toffset:80;\tsize:4;\tsigned:1;\n";

    #[test]
    fn the_layout_comes_from_what_the_kernel_published() {
        let l = parse_layout(REAL_FORMAT).expect("real kernel output must parse");
        assert_eq!(l.pid, FieldSpan { offset: 4, size: 4 });
        assert_eq!(
            l.len,
            FieldSpan {
                offset: 80,
                size: 4
            }
        );
        assert_eq!(
            l.payload,
            vec![FieldSpan {
                offset: 16,
                size: 64
            }]
        );
        assert_eq!(l.payload_capacity(), 64);
    }

    /// A multi-band probe's fetches must reassemble in buffer order, not in
    /// whatever order they were listed.
    #[test]
    fn payload_fetches_are_ordered_by_buffer_position() {
        let fmt = "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
                   \tfield:u8 b128[];\toffset:144;\tsize:64;\tsigned:0;\n\
                   \tfield:u8 b0[];\toffset:16;\tsize:64;\tsigned:0;\n\
                   \tfield:u8 b64[];\toffset:80;\tsize:64;\tsigned:0;\n\
                   \tfield:s32 len;\toffset:208;\tsize:4;\tsigned:1;\n";
        let l = parse_layout(fmt).expect("parses");
        assert_eq!(
            l.payload.iter().map(|f| f.offset).collect::<Vec<_>>(),
            vec![16, 80, 144],
            "b0, b64, b128 — reassembling these out of order yields plausible \
             nonsense rather than an obvious failure"
        );
        assert_eq!(l.payload_capacity(), 192);
    }

    #[test]
    fn a_layout_missing_a_field_sipnab_needs_is_refused() {
        let no_len = "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
                      \tfield:u8 b0[];\toffset:16;\tsize:64;\tsigned:0;\n";
        assert!(
            parse_layout(no_len).is_none(),
            "without len nothing bounds the read"
        );

        let no_payload = "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
                          \tfield:s32 len;\toffset:80;\tsize:4;\tsigned:1;\n";
        assert!(
            parse_layout(no_payload).is_none(),
            "no payload would decode every event to an empty message"
        );
    }

    #[test]
    fn a_record_decodes_at_the_published_offsets() {
        let l = parse_layout(REAL_FORMAT).unwrap();
        let mut rec = vec![0u8; 84];
        rec[4..8].copy_from_slice(&1234i32.to_le_bytes());
        rec[16..16 + 6].copy_from_slice(b"INVITE");
        rec[80..84].copy_from_slice(&6i32.to_le_bytes());

        let got = decode(&rec, &l).expect("a full record decodes");
        assert_eq!(got.pid, 1234);
        assert_eq!(got.len, 6);
        assert_eq!(&got.bytes[..6], b"INVITE");
        assert_eq!(got.bytes.len(), 64, "the whole fetch, padding included");
    }

    /// The acceptance rules then cut it down. This is the join between the two.
    #[test]
    fn a_decoded_record_reduces_to_only_what_was_written() {
        let l = parse_layout(REAL_FORMAT).unwrap();
        let mut rec = vec![0xAAu8; 84];
        rec[4..8].copy_from_slice(&1234i32.to_le_bytes());
        rec[16..16 + 6].copy_from_slice(b"INVITE");
        rec[80..84].copy_from_slice(&6i32.to_le_bytes());

        let mut raw = decode(&rec, &l).unwrap();
        let accepted = super::super::accept(&mut raw.bytes, raw.len).expect("usable");
        assert_eq!(accepted.bytes, b"INVITE", "never the 64-byte fetch");
        assert!(!accepted.truncated);
    }

    #[test]
    fn a_short_record_is_refused_rather_than_decoded_partially() {
        let l = parse_layout(REAL_FORMAT).unwrap();
        let rec = vec![0u8; 40];
        assert!(
            decode(&rec, &l).is_none(),
            "a truncated buffer must not become a shorter message"
        );
    }
}
