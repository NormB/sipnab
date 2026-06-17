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

/// Cap on a file we slurp entirely into memory for metadata extraction or
/// secret stripping. Generous enough for real captures while preventing a
/// hostile multi-GB "pcapng" from OOMing the process (`strip_secrets` holds
/// roughly 2× the input). Streaming would lift this; until then, fail loudly.
const MAX_METADATA_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Reject a file larger than `max` before we read it into memory.
fn ensure_within_size_cap(len: u64, max: u64) -> std::io::Result<()> {
    if len > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("pcapng too large to process in memory: {len} bytes (cap {max})"),
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
}

/// Read NRB names and DSB TLS secrets from the pcapng file at `path`.
pub fn read_pcapng_metadata(path: &Path) -> std::io::Result<PcapngMetadata> {
    use pcap_file::pcapng::Block;
    use pcap_file::pcapng::blocks::name_resolution::Record;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut meta = PcapngMetadata::default();
    ensure_within_size_cap(std::fs::metadata(path)?.len(), MAX_METADATA_FILE_BYTES)?;
    let bytes = std::fs::read(path)?;
    // A non-pcapng file (e.g. legacy pcap) simply carries no metadata blocks.
    let mut reader = match pcap_file::pcapng::PcapNgReader::new(&bytes[..]) {
        Ok(r) => r,
        Err(_) => return Ok(meta),
    };

    // Skip malformed blocks rather than aborting (untrusted-input hardening).
    while let Some(Ok(block)) = reader.next_block() {
        match block {
            Block::NameResolution(nrb) => {
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
            // Decryption Secrets Block (type 0x0A) — not a typed pcap-file block.
            Block::Unknown(u) if u.type_ == 0x0000_000A => {
                if let Some(secret) = parse_dsb_tls_secret(u.value.as_ref()) {
                    meta.tls_secrets.push(secret);
                }
            }
            _ => {}
        }
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
/// stripped.
pub fn strip_secrets(src: &Path, dst: &Path) -> std::io::Result<usize> {
    use std::io::{Error, ErrorKind};
    const DSB_TYPE: u32 = 0x0000_000A;
    // The Section Header Block type 0x0A0D0D0A is byte-symmetric, so it reads
    // the same regardless of section byte order.
    const SHB_BYTES: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];

    ensure_within_size_cap(std::fs::metadata(src)?.len(), MAX_METADATA_FILE_BYTES)?;
    let bytes = std::fs::read(src)?;
    if bytes.len() < 12 || bytes[0..4] != SHB_BYTES {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "not a pcapng (missing Section Header Block)",
        ));
    }
    let mut be = byte_order_from_shb(&bytes[8..12])
        .ok_or_else(|| Error::new(ErrorKind::InvalidData, "invalid SHB byte-order magic"))?;

    let mut kept: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut stripped = 0usize;
    let mut off = 0usize;
    while off + 8 <= bytes.len() {
        // A new section (another SHB) resets the byte order.
        if bytes[off..off + 4] == SHB_BYTES
            && let Some(b) = bytes.get(off + 8..off + 12).and_then(byte_order_from_shb)
        {
            be = b;
        }
        let btype = rd_u32(&bytes[off..off + 4], be);
        let total_len = rd_u32(&bytes[off + 4..off + 8], be) as usize;
        if total_len < 12 || off + total_len > bytes.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "truncated or invalid pcapng block length",
            ));
        }
        if btype == DSB_TYPE {
            stripped += 1; // drop this Decryption Secrets Block
        } else {
            kept.extend_from_slice(&bytes[off..off + total_len]);
        }
        off += total_len;
    }

    crate::capture::atomic::write_atomic(dst, |w| w.write_all(&kept))?;
    Ok(stripped)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{PcapExportMode, PcapWriter};

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

    #[test]
    fn non_pcapng_yields_empty_metadata() {
        // Failure/negative case: a file that isn't pcapng must not error.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notpcapng.bin");
        std::fs::write(&path, b"this is not a capture file").unwrap();
        let meta = read_pcapng_metadata(&path).unwrap();
        assert_eq!(meta, PcapngMetadata::default());
    }

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

    #[test]
    fn strip_secrets_non_pcapng_errors() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("notpcapng.bin");
        std::fs::write(&src, b"definitely not a pcapng file").unwrap();
        let dst = dir.path().join("out.pcapng");
        assert!(strip_secrets(&src, &dst).is_err());
    }
}
