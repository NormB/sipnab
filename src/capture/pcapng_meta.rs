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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{PcapExportMode, PcapWriter};

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
}
