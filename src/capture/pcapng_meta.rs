// SPDX-License-Identifier: MIT OR Apache-2.0

//! Read metadata blocks from a pcapng file so embedded names and TLS keys
//! travel with the capture.
//!
//! - **Name Resolution Block (NRB):** IP → name records, fed back into the
//!   resolver as a low-priority `file` source.
//! - **Decryption Secrets Block (DSB):** TLS Key Log secrets, fed to the TLS
//!   decryptor so a self-contained capture "just decrypts" (like Wireshark).
//!
//! Reading is defensive: a non-pcapng file (e.g. legacy pcap) or one with no
//! such blocks yields empty metadata, and unknown/garbage blocks are skipped
//! rather than fatal.

use std::net::IpAddr;
use std::path::Path;

/// Shipped cap on a file sipnab slurps entirely into memory for metadata
/// extraction or secret stripping. Generous enough for real captures while
/// preventing a hostile multi-GB "pcapng" from OOMing the process
/// (`strip_secrets` holds roughly 2× the input). Streaming would lift this;
/// until then, fail loudly.
///
/// `tcpdump -C` and `dumpcap -b` rings do exceed it on a host with the RAM to
/// spare, so it is a setting: `--max-metadata-file-bytes` or
/// `[limits] max_metadata_file_bytes`. **What raising it exposes:** this is a
/// memory-exhaustion guard on untrusted input, and the file is read whole
/// before anything in it is parsed. Raising it to N lets one capture claim N
/// bytes of this host's RAM — roughly 2N while `--strip-secrets` writes its
/// copy — on nothing but a file size, from a file that need not be a valid
/// pcapng at all. Raise it for captures you produced; leave it where it is for
/// captures someone sent you.
pub const DEFAULT_MAX_METADATA_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// The ceiling this process declared, in bytes.
///
/// Process-global and written once at startup, like
/// [`crate::sip::parser::set_parser_limits`] and for the same reason: the
/// readers are free functions reached from the TUI's file-open controller, the
/// decryptor and `--strip-secrets`, none of which is handed a config.
static MAX_METADATA_FILE_BYTES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(DEFAULT_MAX_METADATA_FILE_BYTES);

/// Bytes of pcapng this process will read into memory at once.
#[must_use]
pub fn max_metadata_file_bytes() -> u64 {
    MAX_METADATA_FILE_BYTES.load(std::sync::atomic::Ordering::Relaxed)
}

/// Declare the in-memory pcapng ceiling for this process. Call once, at
/// startup.
///
/// # Arguments
///
/// * `bytes` — the ceiling. `0` is treated as the shipped default; the
///   operator-facing `0` is refused earlier, by
///   `crate::config::LimitsConfig::validate`.
///
/// # Side effects
///
/// Stores `bytes` into a process-wide atomic (relaxed ordering), raising or
/// lowering the guard for every later read in this process.
pub fn set_max_metadata_file_bytes(bytes: u64) {
    MAX_METADATA_FILE_BYTES.store(
        if bytes == 0 {
            DEFAULT_MAX_METADATA_FILE_BYTES
        } else {
            bytes
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

/// Reject a file larger than `max` before we read it into memory.
fn ensure_within_size_cap(len: u64, max: u64) -> std::io::Result<()> {
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "pcapng too large to process in memory: {len} bytes (cap {max}); \
                 raise --max-metadata-file-bytes or [limits] \
                 max_metadata_file_bytes for a capture you trust"
            ),
        ));
    }
    Ok(())
}

/// Metadata extracted from a pcapng file's non-packet blocks.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PcapngMetadata {
    /// IP → name pairs from Name Resolution Blocks.
    pub names: Vec<(IpAddr, String)>,
    /// TLS Key Log lines from Decryption Secrets Blocks.
    pub tls_secrets: Vec<String>,
    /// Name-resolution or secrets blocks whose frame was sound but whose
    /// contents could not be decoded, and were skipped.
    pub malformed_blocks: usize,
    /// Byte offset of a block whose length could not be trusted, where reading
    /// had to stop: nothing after it was read.
    pub stopped_at: Option<usize>,
}

/// Read NRB names and DSB TLS secrets from the pcapng file at `path`.
///
/// # Arguments
///
/// * `path` - the capture file (plain or gzip-compressed pcapng).
///
/// # Returns
///
/// The extracted metadata. Non-pcapng input, a corrupt gzip stream, or a
/// capture with no NRB/DSB blocks all yield empty metadata, not an error. A
/// name or secrets block whose contents are malformed is skipped and counted in
/// [`PcapngMetadata::malformed_blocks`]; a block whose length cannot be trusted
/// ends the walk, recorded in [`PcapngMetadata::stopped_at`]. Both are logged.
///
/// # Errors
///
/// Only filesystem failures (missing file, unreadable metadata) and a file
/// exceeding the in-memory size cap are errors.
///
/// # Side effects
///
/// Reads the whole file into memory (bounded by [`max_metadata_file_bytes`]).
pub fn read_pcapng_metadata(path: &Path) -> std::io::Result<PcapngMetadata> {
    use pcap_file::pcapng::Block;
    use pcap_file::pcapng::blocks::name_resolution::Record;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut meta = PcapngMetadata::default();
    ensure_within_size_cap(std::fs::metadata(path)?.len(), max_metadata_file_bytes())?;
    let bytes = std::fs::read(path)?;
    // The file-open path hands us the ORIGINAL file, which may be
    // gzip-compressed (the packet loader gunzips separately); inflate so
    // embedded names/secrets survive compression. A corrupt gzip stream is
    // not fatal here — it simply carries no readable metadata.
    let bytes = match crate::capture::pcap_reader::decompress_capture(&bytes) {
        Ok(inflated) => inflated,
        Err(_) => return Ok(meta),
    };
    // A non-pcapng file (e.g. legacy pcap) simply carries no metadata blocks.
    let Ok(frames) = BlockFrames::new(&bytes) else {
        return Ok(meta);
    };

    // Blocks are framed by their lengths and only the two kinds this reads are
    // decoded, each on its own. It used to decode every block through one
    // `pcap-file` reader and stop at the first it could not decode -- under a
    // comment saying malformed blocks were skipped -- so one bad block, of any
    // kind, silently cost every name and TLS secret after it. A block whose
    // contents are bad is now skipped and counted; only a length that cannot
    // be trusted stops the walk, because nothing after it can be found.
    let mut section: &[u8] = &[];
    for frame in frames {
        let frame = match frame {
            Ok(frame) => frame,
            Err(offset) => {
                meta.stopped_at = Some(offset);
                break;
            }
        };
        match frame.kind {
            SHB_TYPE => section = frame.bytes,
            NRB_TYPE | DSB_TYPE => match decode_in_section(section, frame.bytes) {
                Some(Block::NameResolution(nrb)) => {
                    for rec in &nrb.records {
                        match rec {
                            Record::Ipv4(r) if r.ip_addr.len() == 4 => {
                                let o = r.ip_addr.as_ref();
                                let ip = IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]));
                                for n in &r.names {
                                    meta.names.push((ip, n.to_string()));
                                }
                            }
                            Record::Ipv6(r) if r.ip_addr.len() == 16 => {
                                let mut a = [0u8; 16];
                                a.copy_from_slice(r.ip_addr.as_ref());
                                let ip = IpAddr::V6(Ipv6Addr::from(a));
                                for n in &r.names {
                                    meta.names.push((ip, n.to_string()));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                // Decryption Secrets Block -- not a typed pcap-file block.
                Some(Block::Unknown(u)) if u.type_ == DSB_TYPE => {
                    if let Some(secret) = parse_dsb_tls_secret(u.value.as_ref()) {
                        meta.tls_secrets.push(secret);
                    }
                }
                _ => meta.malformed_blocks += 1,
            },
            _ => {}
        }
    }
    if meta.malformed_blocks > 0 {
        tracing::warn!(
            "{}: skipped {} malformed name-resolution or decryption-secrets block(s); \
             any names or TLS secrets in them were not read",
            path.display(),
            meta.malformed_blocks
        );
    }
    if let Some(offset) = meta.stopped_at {
        tracing::warn!(
            "{}: stopped reading pcapng metadata at byte {offset}: that block's length \
             cannot be trusted, so names and TLS secrets after it were not read",
            path.display()
        );
    }
    Ok(meta)
}

/// Parse the TLS Key Log text from a Decryption Secrets Block body
/// (`Secrets Type | Secrets Length | data | pad`). Returns the secret only for
/// the TLS Key Log secret type (`"TLSK"`); other types or malformed bodies
/// yield `None`. Accepts either byte order for the header fields.
fn parse_dsb_tls_secret(value: &[u8]) -> Option<String> {
    const TLS_KEYLOG: u32 = 0x544c_534b; // "TLSK"
    if value.len() < 8 {
        return None;
    }
    let head: [u8; 4] = value[0..4].try_into().ok()?;
    let big_endian = if u32::from_le_bytes(head) == TLS_KEYLOG {
        false
    } else if u32::from_be_bytes(head) == TLS_KEYLOG {
        true
    } else {
        return None; // not a TLS Key Log DSB
    };
    let len_bytes: [u8; 4] = value[4..8].try_into().ok()?;
    let len = if big_endian {
        u32::from_be_bytes(len_bytes)
    } else {
        u32::from_le_bytes(len_bytes)
    } as usize;
    let data = value.get(8..8usize.checked_add(len)?)?;
    let s = String::from_utf8_lossy(data).into_owned();
    (!s.is_empty()).then_some(s)
}

/// Write a copy of the pcapng at `src` to `dst` with every Decryption Secrets
/// Block removed (the `editcap --discard-all-secrets` analog). All other blocks
/// are copied byte-for-byte. Written atomically (temp+rename) so a failure never
/// corrupts `dst`, and `src` is never modified. Returns the number of DSBs
/// stripped. Gzip-compressed input (`.pcapng.gz`) is inflated first, like every
/// other read path; the sanitized output is always written uncompressed.
///
/// # Arguments
///
/// * `src` - the pcapng (or `.pcapng.gz`) file to sanitize; never modified.
/// * `dst` - where the DSB-free copy is written (atomic temp+rename).
///
/// # Errors
///
/// Fails when `src` cannot be read, exceeds the size cap (on disk or after
/// inflation), is not pcapng (missing/invalid SHB), contains a truncated or
/// invalid block length, or when writing `dst` fails.
pub fn strip_secrets(src: &Path, dst: &Path) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    ensure_within_size_cap(std::fs::metadata(src)?.len(), max_metadata_file_bytes())?;
    let raw = std::fs::read(src)?;
    let bytes = crate::capture::pcap_reader::decompress_capture(&raw)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    // The on-disk cap above saw the compressed size; re-check what it inflated
    // to before block-walking it.
    ensure_within_size_cap(bytes.len() as u64, max_metadata_file_bytes())?;
    let frames = BlockFrames::new(&bytes).map_err(|why| Error::new(ErrorKind::InvalidData, why))?;

    let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut stripped = 0usize;
    for frame in frames {
        let frame = frame.map_err(|_| {
            Error::new(
                ErrorKind::InvalidData,
                "truncated or invalid pcapng block length",
            )
        })?;
        if frame.kind == DSB_TYPE {
            stripped += 1; // drop this Decryption Secrets Block
        } else {
            kept.extend_from_slice(frame.bytes);
        }
    }

    crate::capture::atomic::write_atomic(dst, |w| w.write_all(&kept))?;
    Ok(stripped)
}

/// The Section Header Block's first four bytes. Byte-symmetric, so they read
/// the same in either byte order.
const SHB_BYTES: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
/// Section Header Block type.
const SHB_TYPE: u32 = 0x0A0D_0D0A;
/// Name Resolution Block type.
const NRB_TYPE: u32 = 0x0000_0004;
/// Decryption Secrets Block type.
const DSB_TYPE: u32 = 0x0000_000A;

/// One pcapng block, framed by its length and nothing else.
struct BlockFrame<'a> {
    /// Block type code.
    kind: u32,
    /// The whole block, header and trailer included.
    bytes: &'a [u8],
}

/// The blocks of a pcapng, framed by their lengths, following each section's
/// byte order. The one framing rule for this module: [`strip_secrets`] copies
/// frames and [`read_pcapng_metadata`] decodes the two kinds it reads.
///
/// Yields `Err(offset)` once, for a block whose length cannot be trusted (under
/// the 12-byte minimum or past the end of the data), and then stops: nothing
/// after an untrusted length can be found. Fewer than 8 trailing bytes are not
/// a block and end the walk quietly.
struct BlockFrames<'a> {
    /// The whole (inflated) pcapng.
    bytes: &'a [u8],
    /// Where the next block starts.
    offset: usize,
    /// The current section's byte order; another SHB resets it.
    big_endian: bool,
    /// Set after an untrusted length, so the walk yields nothing more.
    done: bool,
}

impl<'a> BlockFrames<'a> {
    /// Start at the first Section Header Block.
    ///
    /// # Errors
    ///
    /// `bytes` does not begin with a Section Header Block, or its byte-order
    /// magic is neither order.
    fn new(bytes: &'a [u8]) -> Result<Self, &'static str> {
        if bytes.len() < 12 || bytes[0..4] != SHB_BYTES {
            return Err("not a pcapng (missing Section Header Block)");
        }
        let big_endian =
            byte_order_from_shb(&bytes[8..12]).ok_or("invalid SHB byte-order magic")?;
        Ok(Self {
            bytes,
            offset: 0,
            big_endian,
            done: false,
        })
    }
}

impl<'a> Iterator for BlockFrames<'a> {
    type Item = Result<BlockFrame<'a>, usize>;

    fn next(&mut self) -> Option<Self::Item> {
        let (b, off) = (self.bytes, self.offset);
        if self.done || off + 8 > b.len() {
            return None;
        }
        // A new section (another SHB) resets the byte order.
        if b[off..off + 4] == SHB_BYTES
            && let Some(order) = b.get(off + 8..off + 12).and_then(byte_order_from_shb)
        {
            self.big_endian = order;
        }
        let kind = rd_u32(&b[off..off + 4], self.big_endian);
        let len = rd_u32(&b[off + 4..off + 8], self.big_endian) as usize;
        if len < 12 || off + len > b.len() {
            self.done = true;
            return Some(Err(off));
        }
        self.offset = off + len;
        Some(Ok(BlockFrame {
            kind,
            bytes: &b[off..off + len],
        }))
    }
}

/// Decode one block in the section whose header is `section`, so it is read
/// with that section's byte order. `None` when `pcap-file` cannot decode it.
fn decode_in_section(section: &[u8], block: &[u8]) -> Option<pcap_file::pcapng::Block<'static>> {
    let mut buf = Vec::with_capacity(section.len() + block.len());
    buf.extend_from_slice(section);
    buf.extend_from_slice(block);
    let mut reader = pcap_file::pcapng::PcapNgReader::new(&buf[..]).ok()?;
    reader
        .next_block()?
        .ok()
        .map(pcap_file::pcapng::Block::into_owned)
}

/// Read a u32 from a 4-byte slice in the given byte order.
fn rd_u32(b: &[u8], be: bool) -> u32 {
    let a: [u8; 4] = b.try_into().unwrap_or([0; 4]);
    if be {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

/// Section byte order from an SHB byte-order magic field: `Some(true)` for
/// big-endian (`1A2B3C4D`), `Some(false)` for little-endian (`4D3C2B1A`).
fn byte_order_from_shb(magic: &[u8]) -> Option<bool> {
    match magic {
        [0x1A, 0x2B, 0x3C, 0x4D] => Some(true),
        [0x4D, 0x3C, 0x2B, 0x1A] => Some(false),
        _ => None,
    }
}

/// Tests for pcapng metadata extraction (NRB/DSB) and secret stripping,
/// including the gzip-compressed input paths.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{PcapExportMode, PcapWriter};

    /// Sizes at/under the cap pass; one byte over is `InvalidData`.
    #[test]
    fn size_cap_rejects_oversized_and_allows_normal() {
        // At/under the cap is fine; over it is rejected as invalid data so a
        // multi-GB "pcapng" can't OOM the metadata reader / stripper.
        assert!(ensure_within_size_cap(100, 1024).is_ok());
        assert!(ensure_within_size_cap(1024, 1024).is_ok());
        let err = ensure_within_size_cap(1025, 1024).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    /// Helper: write a pcapng carrying an NRB for the given entries.
    fn write_pcapng_with_nrb(path: &Path, entries: &[(IpAddr, Vec<String>)]) {
        let mut w =
            PcapWriter::with_format(path, 1, None, None, true, PcapExportMode::Raw).unwrap();
        w.write_name_resolution_block(entries).unwrap();
        w.finish().unwrap();
    }

    /// NRB names embedded in a gzip-compressed pcapng still read back (the
    /// file-open path hands over the original compressed file).
    #[test]
    fn reads_nrb_names_from_gzip_compressed_pcapng() {
        // The TUI file-open path hands this reader the ORIGINAL (possibly
        // gzip-compressed) file; embedded names must survive compression.
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("named.pcapng");
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        write_pcapng_with_nrb(&plain, &[(ip, vec!["sbc-edge".to_string()])]);

        let gz_path = dir.path().join("named.pcapng.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz_path).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(&std::fs::read(&plain).unwrap()).unwrap();
        enc.finish().unwrap();

        let meta = read_pcapng_metadata(&gz_path).unwrap();
        assert!(
            meta.names.contains(&(ip, "sbc-edge".to_string())),
            "gzipped pcapng must still yield NRB names, got: {:?}",
            meta.names
        );
    }

    /// IPv4 and IPv6 NRB records (with multiple names) read back from a
    /// written pcapng.
    #[test]
    fn reads_nrb_names() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("named.pcapng");
        let v4: IpAddr = "10.0.0.2".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        write_pcapng_with_nrb(
            &path,
            &[
                (v4, vec!["sbc-edge".to_string()]),
                (v6, vec!["v6".to_string(), "v6.example.com".to_string()]),
            ],
        );

        let meta = read_pcapng_metadata(&path).unwrap();
        assert!(
            meta.names.contains(&(v4, "sbc-edge".to_string())),
            "names: {:?}",
            meta.names
        );
        assert!(meta.names.contains(&(v6, "v6".to_string())));
        assert!(meta.names.contains(&(v6, "v6.example.com".to_string())));
    }

    /// A DSB written from a keylog surfaces its TLS Key Log lines.
    #[test]
    fn reads_dsb_tls_secret() {
        // A pcapng carrying a Decryption Secrets Block (TLS Key Log) should
        // surface its secret lines so the decryptor can use embedded keys.
        let dir = tempfile::tempdir().unwrap();
        let keylog = dir.path().join("keys.txt");
        std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();
        let path = dir.path().join("withsecret.pcapng");
        {
            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true,
                PcapExportMode::EncryptedWithDsb,
            )
            .unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();
            w.finish().unwrap();
        }

        let meta = read_pcapng_metadata(&path).unwrap();
        assert_eq!(meta.tls_secrets.len(), 1, "secrets: {:?}", meta.tls_secrets);
        assert!(
            meta.tls_secrets[0].contains("CLIENT_RANDOM aabbccdd 00112233"),
            "secret content: {:?}",
            meta.tls_secrets[0]
        );
    }

    /// A non-pcapng file yields empty metadata, not an error.
    #[test]
    fn non_pcapng_yields_empty_metadata() {
        // Failure/negative case: a file that isn't pcapng must not error.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notpcapng.bin");
        std::fs::write(&path, b"this is not a capture file").unwrap();
        let meta = read_pcapng_metadata(&path).unwrap();
        assert_eq!(meta, PcapngMetadata::default());
    }

    /// A nonexistent path is a filesystem error.
    #[test]
    fn missing_file_errors() {
        let meta = read_pcapng_metadata(Path::new("/no/such/file.pcapng"));
        assert!(meta.is_err());
    }

    /// Write a pcapng carrying an NRB and (optionally) a DSB.
    fn write_pcapng_with(dir: &Path, name: &str, with_dsb: bool) -> std::path::PathBuf {
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        let path = dir.join(name);
        let mut w =
            PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::EncryptedWithDsb)
                .unwrap();
        w.write_name_resolution_block(&[(ip, vec!["sbc-edge".to_string()])])
            .unwrap();
        if with_dsb {
            let keylog = dir.join("k.txt");
            std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();
        }
        w.finish().unwrap();
        path
    }

    /// Stripping removes the DSB from the copy, keeps NRB names, and leaves
    /// the source file intact.
    #[test]
    fn strip_secrets_removes_dsb_keeps_names_and_source() {
        let dir = tempfile::tempdir().unwrap();
        let src = write_pcapng_with(dir.path(), "withsecret.pcapng", true);
        let dst = dir.path().join("clean.pcapng");

        let n = strip_secrets(&src, &dst).unwrap();
        assert_eq!(n, 1, "one DSB stripped");

        // Output: no secrets, names preserved.
        let after = read_pcapng_metadata(&dst).unwrap();
        assert!(after.tls_secrets.is_empty(), "secrets must be gone");
        assert!(
            after.names.iter().any(|(_, name)| name == "sbc-edge"),
            "names preserved: {:?}",
            after.names
        );
        // Source untouched.
        let src_meta = read_pcapng_metadata(&src).unwrap();
        assert_eq!(
            src_meta.tls_secrets.len(),
            1,
            "source DSB must remain intact"
        );
    }

    /// A DSB-free input strips zero blocks and produces a faithful copy.
    #[test]
    fn strip_secrets_no_dsb_returns_zero_and_copies() {
        let dir = tempfile::tempdir().unwrap();
        let src = write_pcapng_with(dir.path(), "nodsb.pcapng", false);
        let dst = dir.path().join("copy.pcapng");
        assert_eq!(strip_secrets(&src, &dst).unwrap(), 0);
        // Faithful copy: names still present.
        let after = read_pcapng_metadata(&dst).unwrap();
        assert!(after.names.iter().any(|(_, name)| name == "sbc-edge"));
    }

    /// Stripping a non-pcapng file is an error (unlike metadata reading).
    #[test]
    fn strip_secrets_non_pcapng_errors() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("notpcapng.bin");
        std::fs::write(&src, b"definitely not a pcapng file").unwrap();
        let dst = dir.path().join("out.pcapng");
        assert!(strip_secrets(&src, &dst).is_err());
    }

    /// gzip-compress the file at `src` into `<src>.gz` and return that path.
    fn gzip_file(src: &Path) -> std::path::PathBuf {
        use std::io::Write;
        let gz = src.with_extension("pcapng.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&gz).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(&std::fs::read(src).unwrap()).unwrap();
        enc.finish().unwrap();
        gz
    }

    /// A `.pcapng.gz` strips transparently; the sanitized output is plain
    /// (uncompressed) pcapng.
    #[test]
    fn strip_secrets_reads_gzip_compressed_input() {
        // Every other read path gunzips transparently; the sanitizer must
        // too, or a .pcapng.gz can't be stripped without a manual gunzip.
        let dir = tempfile::tempdir().unwrap();
        let plain = write_pcapng_with(dir.path(), "withsecret.pcapng", true);
        let gz = gzip_file(&plain);
        let dst = dir.path().join("clean.pcapng");

        let n = strip_secrets(&gz, &dst).unwrap();
        assert_eq!(n, 1, "one DSB stripped from gzip input");

        // Output is a plain (uncompressed) sanitized pcapng.
        let after = read_pcapng_metadata(&dst).unwrap();
        assert!(after.tls_secrets.is_empty(), "secrets must be gone");
        assert!(
            after.names.iter().any(|(_, name)| name == "sbc-edge"),
            "names preserved: {:?}",
            after.names
        );
    }

    /// Gzip wrapping non-pcapng bytes still errors after inflation.
    #[test]
    fn strip_secrets_gzip_wrapping_non_pcapng_errors() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("garbage.pcapng.gz");
        let mut enc = flate2::write::GzEncoder::new(
            std::fs::File::create(&src).unwrap(),
            flate2::Compression::default(),
        );
        enc.write_all(b"definitely not a pcapng file").unwrap();
        enc.finish().unwrap();
        let dst = dir.path().join("out.pcapng");
        assert!(strip_secrets(&src, &dst).is_err());
    }

    /// A truncated gzip stream errors cleanly, never panics.
    #[test]
    fn strip_secrets_truncated_gzip_errors_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let plain = write_pcapng_with(dir.path(), "withsecret.pcapng", true);
        let gz = gzip_file(&plain);
        let whole = std::fs::read(&gz).unwrap();
        let cut = dir.path().join("truncated.pcapng.gz");
        std::fs::write(&cut, &whole[..whole.len() / 2]).unwrap();
        let dst = dir.path().join("out.pcapng");
        assert!(strip_secrets(&cut, &dst).is_err(), "no panic, clean error");
    }
}

#[cfg(test)]
mod malformed_block_tests {
    //! One bad block must not cost the metadata that follows it.
    //!
    //! The reader used to stop at the first block `pcap-file` could not
    //! decode, under a comment saying it skipped them, so a single malformed
    //! block silently dropped every name and TLS secret after it and TLS
    //! decryption then failed with nothing said.
    use super::*;
    use crate::capture::{PcapExportMode, PcapWriter};
    /// Name-resolution block type.
    const NRB: u32 = 0x0000_0004;
    /// Enhanced packet block type.
    const EPB: u32 = 0x0000_0006;

    /// A pcapng with an NRB naming `early`, one naming `late`, and a DSB.
    fn fixture(dir: &Path) -> Vec<u8> {
        let path = dir.join("fixture.pcapng");
        let mut w =
            PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::EncryptedWithDsb)
                .unwrap();
        let early: IpAddr = "10.0.0.1".parse().unwrap();
        let late: IpAddr = "10.0.0.2".parse().unwrap();
        w.write_name_resolution_block(&[(early, vec!["early".to_string()])])
            .unwrap();
        w.write_name_resolution_block(&[(late, vec!["late".to_string()])])
            .unwrap();
        let keylog = dir.join("keys.txt");
        std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();
        w.maybe_write_keylog_dsb(&keylog).unwrap();
        w.finish().unwrap();
        std::fs::read(&path).unwrap()
    }

    /// Byte order of the first section, and the offset just past the first
    /// NRB, where a crafted block is spliced in.
    fn after_first_nrb(bytes: &[u8]) -> (bool, usize) {
        let be = byte_order_from_shb(&bytes[8..12]).expect("fixture has an SHB");
        let mut off = 0;
        while off + 8 <= bytes.len() {
            let kind = rd_u32(&bytes[off..off + 4], be);
            let len = rd_u32(&bytes[off + 4..off + 8], be) as usize;
            if kind == NRB {
                return (be, off + len);
            }
            off += len;
        }
        panic!("fixture has no NRB");
    }

    /// A block of `kind` framed correctly around `body` (padded to 32 bits).
    fn framed(kind: u32, body: &[u8], be: bool) -> Vec<u8> {
        let mut body = body.to_vec();
        while !body.len().is_multiple_of(4) {
            body.push(0);
        }
        let total = (12 + body.len()) as u32;
        let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut out = Vec::new();
        out.extend_from_slice(&w32(kind));
        out.extend_from_slice(&w32(total));
        out.extend_from_slice(&body);
        out.extend_from_slice(&w32(total));
        out
    }

    /// Whether `pcap-file` refuses to decode `block` in the fixture's section --
    /// the fixture guard, so a test cannot pass because the "malformed" block
    /// was in fact fine. Independent of the code under test.
    fn pcap_file_refuses(bytes: &[u8], block: &[u8], be: bool) -> bool {
        let shb_len = rd_u32(&bytes[4..8], be) as usize;
        let mut buf = bytes[..shb_len].to_vec();
        buf.extend_from_slice(block);
        let Ok(mut reader) = pcap_file::pcapng::PcapNgReader::new(&buf[..]) else {
            return true;
        };
        !matches!(reader.next_block(), Some(Ok(_)))
    }

    fn splice(bytes: &[u8], at: usize, block: &[u8], dir: &Path) -> std::path::PathBuf {
        let mut out = bytes[..at].to_vec();
        out.extend_from_slice(block);
        out.extend_from_slice(&bytes[at..]);
        let path = dir.join("spliced.pcapng");
        std::fs::write(&path, out).unwrap();
        path
    }

    fn named(meta: &PcapngMetadata, name: &str) -> bool {
        meta.names.iter().any(|(_, n)| n == name)
    }

    /// An NRB whose frame is sound and whose one IPv4 record claims 200 bytes
    /// the block does not hold is skipped, counted, and the NRB and DSB after
    /// it are still read.
    #[test]
    fn a_malformed_name_block_is_skipped_and_what_follows_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = fixture(dir.path());
        let (be, at) = after_first_nrb(&bytes);
        let w16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut body = Vec::new();
        body.extend_from_slice(&w16(1)); // record type: IPv4
        body.extend_from_slice(&w16(200)); // claimed length: far past the block
        body.extend_from_slice(&[10, 0, 0, 9, b'x', 0, 0, 0]);
        let bad = framed(NRB, &body, be);
        assert!(
            pcap_file_refuses(&bytes, &bad, be),
            "fixture: the crafted NRB must not decode"
        );

        let meta = read_pcapng_metadata(&splice(&bytes, at, &bad, dir.path())).unwrap();
        assert!(named(&meta, "early"), "{meta:?}");
        assert!(
            named(&meta, "late"),
            "the NRB after the bad one was lost: {meta:?}"
        );
        assert_eq!(
            meta.tls_secrets.len(),
            1,
            "the DSB after the bad block was lost"
        );
        assert_eq!(meta.malformed_blocks, 1);
        assert_eq!(meta.stopped_at, None);
    }

    /// A packet block with garbage in it is none of the metadata's business:
    /// it is not decoded, so it costs nothing and is not counted.
    #[test]
    fn a_garbled_packet_block_costs_the_metadata_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = fixture(dir.path());
        let (be, at) = after_first_nrb(&bytes);
        let bad = framed(EPB, &[0xFF; 9], be);
        assert!(
            pcap_file_refuses(&bytes, &bad, be),
            "fixture: the crafted EPB must not decode"
        );

        let meta = read_pcapng_metadata(&splice(&bytes, at, &bad, dir.path())).unwrap();
        assert!(named(&meta, "late"), "{meta:?}");
        assert_eq!(meta.tls_secrets.len(), 1);
        assert_eq!(
            meta.malformed_blocks, 0,
            "a packet block is never decoded here"
        );
    }

    /// A block whose length cannot be trusted leaves nothing after it
    /// findable, so reading stops there and says where.
    #[test]
    fn an_untrustworthy_block_length_stops_reading_and_says_where() {
        let dir = tempfile::tempdir().unwrap();
        let bytes = fixture(dir.path());
        let (be, at) = after_first_nrb(&bytes);
        let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let mut bad = Vec::new();
        bad.extend_from_slice(&w32(NRB));
        bad.extend_from_slice(&w32(0x7FFF_FFF0)); // past the end of any file here
        bad.extend_from_slice(&[0; 8]);

        let meta = read_pcapng_metadata(&splice(&bytes, at, &bad, dir.path())).unwrap();
        assert!(named(&meta, "early"), "what came before is kept: {meta:?}");
        assert!(
            !named(&meta, "late"),
            "nothing past an untrusted length can be found"
        );
        assert_eq!(meta.stopped_at, Some(at));
    }
}
