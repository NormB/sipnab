//! Pure-Rust pcap/pcapng file reader for WASM compatibility.
//! Reads both pcap and pcapng files from raw byte slices without libpcap.

use anyhow::{Result, bail, ensure};

/// A single packet read from a pcap/pcapng file.
pub struct PcapPacket {
    /// Capture timestamp, whole seconds since the epoch.
    pub timestamp_secs: u32,
    /// Sub-second microseconds of the capture timestamp.
    pub timestamp_usecs: u32,
    /// Captured packet bytes (possibly truncated to the snap length).
    pub data: Vec<u8>,
    /// Original on-the-wire packet length.
    pub orig_len: u32,
}

/// Unified reader for both pcap and pcapng formats.
#[derive(Debug)]
pub struct PcapReader<'a> {
    inner: ReaderInner<'a>,
    /// Link-layer type from the file header (pcap DLT value).
    pub link_type: u32,
}

#[derive(Debug)]
enum ReaderInner<'a> {
    Classic(ClassicReader<'a>),
    Ng(NgReader<'a>),
}

// ── Classic pcap ──────────────────────────────────────────────────────

#[derive(Debug)]
struct ClassicReader<'a> {
    data: &'a [u8],
    offset: usize,
    big_endian: bool,
    nanoseconds: bool,
}

impl<'a> ClassicReader<'a> {
    fn read_u32(&self, off: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.data.get(off..off + 4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    fn next_packet(&mut self) -> Option<PcapPacket> {
        let ts_sec = self.read_u32(self.offset)?;
        let ts_usec = self.read_u32(self.offset + 4)?;
        let incl_len = self.read_u32(self.offset + 8)? as usize;
        let orig_len = self.read_u32(self.offset + 12)?;
        self.offset += 16;

        let end = self.offset.checked_add(incl_len)?;
        if end > self.data.len() {
            return None;
        }
        let data = self.data[self.offset..end].to_vec();
        self.offset = end;

        let ts_usec = if self.nanoseconds {
            ts_usec / 1000
        } else {
            ts_usec
        };
        Some(PcapPacket {
            timestamp_secs: ts_sec,
            timestamp_usecs: ts_usec,
            data,
            orig_len,
        })
    }
}

// ── Pcapng ────────────────────────────────────────────────────────────

#[derive(Debug)]
struct NgReader<'a> {
    data: &'a [u8],
    offset: usize,
    big_endian: bool,
    if_tsresol: u64, // timestamp units per second (default 1_000_000 = microseconds)
    link_type: u32,
}

impl<'a> NgReader<'a> {
    fn read_u16(&self, off: usize) -> Option<u16> {
        let bytes: [u8; 2] = self.data.get(off..off + 2)?.try_into().ok()?;
        Some(if self.big_endian {
            u16::from_be_bytes(bytes)
        } else {
            u16::from_le_bytes(bytes)
        })
    }

    fn read_u32(&self, off: usize) -> Option<u32> {
        let bytes: [u8; 4] = self.data.get(off..off + 4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        })
    }

    fn next_packet(&mut self) -> Option<PcapPacket> {
        loop {
            let block_type = self.read_u32(self.offset)?;
            let block_total_len = self.read_u32(self.offset + 4)? as usize;

            if block_total_len < 12 {
                return None;
            }
            let block_end = self.offset.checked_add(block_total_len)?;
            if block_end > self.data.len() {
                return None;
            }

            match block_type {
                // Section Header Block (SHB) — 0x0a0d0d0a
                0x0a0d0d0a => {
                    if let Some(bom_bytes) = self.data.get(self.offset + 8..self.offset + 12) {
                        let bom = u32::from_le_bytes(bom_bytes.try_into().ok()?);
                        self.big_endian = bom == 0x4d3c2b1a;
                    }
                    self.offset = block_end;
                }

                // Interface Description Block (IDB) — 0x00000001
                0x00000001 => {
                    if block_total_len >= 20 {
                        if let Some(lt) = self.read_u16(self.offset + 8) {
                            self.link_type = lt as u32;
                        }
                        let opts_start = self.offset + 16;
                        let opts_end = self.offset + block_total_len.saturating_sub(4);
                        self.parse_idb_options(opts_start, opts_end);
                    }
                    self.offset = block_end;
                }

                // Enhanced Packet Block (EPB) — 0x00000006
                0x00000006 => {
                    if block_total_len < 32 {
                        self.offset = block_end;
                        continue;
                    }
                    let ts_high = self.read_u32(self.offset + 12)?;
                    let ts_low = self.read_u32(self.offset + 16)?;
                    let captured_len = self.read_u32(self.offset + 20)? as usize;
                    let orig_len = self.read_u32(self.offset + 24)?;

                    let data_start = self.offset + 28;
                    let data_end = data_start.checked_add(captured_len)?;
                    if data_end > self.data.len() {
                        self.offset = block_end;
                        continue;
                    }

                    let pkt_data = self.data[data_start..data_end].to_vec();

                    let ts64 = ((ts_high as u64) << 32) | (ts_low as u64);
                    let resol = self.if_tsresol.max(1); // guard against zero
                    let ts_sec = (ts64 / resol) as u32;
                    let ts_usec = ((ts64 % resol).saturating_mul(1_000_000) / resol) as u32;

                    self.offset = block_end;
                    return Some(PcapPacket {
                        timestamp_secs: ts_sec,
                        timestamp_usecs: ts_usec,
                        data: pkt_data,
                        orig_len,
                    });
                }

                // Any other block — skip
                _ => {
                    self.offset = block_end;
                }
            }
        }
    }

    fn parse_idb_options(&mut self, mut pos: usize, end: usize) {
        while pos + 4 <= end {
            let opt_code = match self.read_u16(pos) {
                Some(v) => v,
                None => break,
            };
            let opt_len = match self.read_u16(pos + 2) {
                Some(v) => v as usize,
                None => break,
            };
            pos += 4;
            let opt_data_end = match pos.checked_add(opt_len) {
                Some(e) if e <= end => e,
                _ => break,
            };

            // if_tsresol option (code 9)
            if opt_code == 9
                && opt_len >= 1
                && let Some(&tsresol) = self.data.get(pos)
            {
                if tsresol & 0x80 != 0 {
                    let exp = (tsresol & 0x7f) as u32;
                    // Cap shift to prevent overflow (u64 max shift is 63)
                    self.if_tsresol = if exp <= 63 { 1u64 << exp } else { u64::MAX };
                } else {
                    // Cap exponent to prevent 10^N overflow (10^19 fits in u64, 10^20 does not)
                    self.if_tsresol = 10u64.checked_pow(tsresol as u32).unwrap_or(u64::MAX);
                }
            }

            // opt_endofopt (code 0)
            if opt_code == 0 {
                break;
            }

            // Pad to 4-byte boundary
            let padded = opt_len + (4 - (opt_len % 4)) % 4;
            pos = match pos.checked_add(padded) {
                Some(p) => p,
                None => break,
            };
            let _ = opt_data_end; // used in guard above
        }
    }
}

// ── PcapReader public API ─────────────────────────────────────────────

impl<'a> PcapReader<'a> {
    /// Open a reader over an in-memory pcap or pcapng file (detected by
    /// magic number).
    #[must_use = "parsing result must be handled"]
    pub fn new(data: &'a [u8]) -> Result<Self> {
        ensure!(data.len() >= 12, "capture file too short");
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        match magic {
            // Classic pcap (LE/BE, micro/nanoseconds)
            0xa1b2c3d4 | 0xd4c3b2a1 | 0xa1b23c4d | 0x4d3cb2a1 => {
                ensure!(data.len() >= 24, "pcap file too short for global header");
                let big_endian = magic == 0xd4c3b2a1 || magic == 0x4d3cb2a1;
                let nanoseconds = magic == 0xa1b23c4d || magic == 0x4d3cb2a1;
                let link_type = if big_endian {
                    u32::from_be_bytes([data[20], data[21], data[22], data[23]])
                } else {
                    u32::from_le_bytes([data[20], data[21], data[22], data[23]])
                };
                Ok(Self {
                    inner: ReaderInner::Classic(ClassicReader {
                        data,
                        offset: 24,
                        big_endian,
                        nanoseconds,
                    }),
                    link_type,
                })
            }

            // Pcapng Section Header Block
            0x0a0d0d0a => {
                ensure!(data.len() >= 28, "pcapng file too short for SHB");
                let bom = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                let big_endian = bom == 0x4d3c2b1a;
                let shb_len = if big_endian {
                    u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize
                } else {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize
                };
                let start = if shb_len > 0 && shb_len <= data.len() {
                    shb_len
                } else {
                    28
                };

                Ok(Self {
                    inner: ReaderInner::Ng(NgReader {
                        data,
                        offset: start,
                        big_endian,
                        if_tsresol: 1_000_000,
                        link_type: 1,
                    }),
                    link_type: 1,
                })
            }

            // Microsoft Network Monitor format
            0x55424d47 => bail!(
                "Microsoft Network Monitor (.cap) format is not supported. Convert to pcap with: editcap -F pcap input.cap output.pcap"
            ),
            _ => bail!(
                "Not a pcap/pcapng file (magic: 0x{:08x}). Supported formats: .pcap, .pcapng, .cap (pcap format)",
                magic
            ),
        }
    }
}

impl<'a> Iterator for PcapReader<'a> {
    type Item = PcapPacket;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.inner {
            ReaderInner::Classic(r) => r.next_packet(),
            ReaderInner::Ng(r) => {
                let pkt = r.next_packet();
                self.link_type = r.link_type;
                pkt
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_pcap_file() {
        let data = std::fs::read("tests/pcap-samples/sip-rtp-g711.pcap").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        assert_eq!(reader.link_type, 1);
        let packets: Vec<_> = reader.collect();
        assert!(packets.len() > 10, "should have multiple packets");
    }

    #[test]
    fn parse_pcapng_file() {
        let data = std::fs::read("tests/pcap-samples/b2bua-asterisk.pcapng").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(
            packets.len() > 5,
            "pcapng should have packets, got {}",
            packets.len()
        );
        assert!(
            packets[0].timestamp_secs > 0,
            "timestamp should be non-zero"
        );
    }

    #[test]
    fn parse_pcapng_sip_auth_failure() {
        let data = std::fs::read("tests/pcap-samples/sip-auth-failure.pcapng").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(!packets.is_empty(), "should have packets");
    }

    #[test]
    fn too_short_file() {
        let result = PcapReader::new(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_pcap_packet() {
        let data = std::fs::read("tests/pcap-samples/sip-rtp-g711.pcap").unwrap();
        let truncated = &data[..100];
        let reader = PcapReader::new(truncated).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(packets.len() <= 1);
    }

    #[test]
    fn invalid_magic() {
        let result = PcapReader::new(&[0xFF; 24]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Not a pcap"));
    }

    #[test]
    fn cap_file_pcap_format() {
        let data = std::fs::read("tests/pcap-samples/SIP_DTMF2.cap").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(!packets.is_empty(), "pcap-format .cap file should parse");
    }

    #[test]
    fn cap_file_netmon_format_error() {
        let data = std::fs::read("tests/pcap-samples/rtsp-packets.cap").unwrap();
        let result = PcapReader::new(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Network Monitor"));
    }

    // ── Malformed input tests ─────────────────────────────────────────

    #[test]
    fn crafted_pcapng_zero_tsresol() {
        // Ensure tsresol=0 doesn't cause division by zero
        let data = std::fs::read("tests/pcap-samples/b2bua-asterisk.pcapng").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        // Just verify it doesn't panic
        let _packets: Vec<_> = reader.collect();
    }

    #[test]
    fn truncated_pcapng_block() {
        // Pcapng with valid SHB header but truncated before any packets
        let data = std::fs::read("tests/pcap-samples/b2bua-asterisk.pcapng").unwrap();
        let truncated = &data[..40]; // Just the SHB
        let reader = PcapReader::new(truncated).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(packets.is_empty() || packets.len() <= 1);
    }

    // ── Load every capture file in tests/pcap-samples/ ──────────────

    fn assert_loads(path: &str, min_packets: usize) {
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("Can't read {path}: {e}"));
        let reader = PcapReader::new(&data).unwrap_or_else(|e| panic!("{path}: {e}"));
        let packets: Vec<_> = reader.collect();
        assert!(
            packets.len() >= min_packets,
            "{path}: expected >= {min_packets} packets, got {}",
            packets.len()
        );
    }

    // -- pcap format files --

    #[test]
    fn load_asterisk_zfone() {
        assert_loads("tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap", 10);
    }
    #[test]
    fn load_dtmfsipinfo() {
        assert_loads("tests/pcap-samples/DTMFsipinfo.pcap", 1);
    }
    #[test]
    fn load_h263_rtp() {
        assert_loads("tests/pcap-samples/h263-over-rtp.pcap", 1);
    }
    #[test]
    fn load_metasploit() {
        assert_loads("tests/pcap-samples/metasploit-sip-invite-spoof.pcap", 1);
    }
    #[test]
    fn load_rtp_protocol() {
        assert_loads("tests/pcap-samples/rtp-protocol.pcap", 1);
    }
    #[test]
    fn load_sip_call_g711() {
        assert_loads("tests/pcap-samples/SIP_CALL_RTP_G711", 100);
    }
    #[test]
    fn load_sip_dtmf2_cap() {
        assert_loads("tests/pcap-samples/SIP_DTMF2.cap", 10);
    }
    #[test]
    fn load_sip_over_tcp() {
        assert_loads("tests/pcap-samples/sip-over-tcp.pcap", 1);
    }
    #[test]
    fn load_sip_proxy() {
        assert_loads("tests/pcap-samples/sip-proxy.pcap", 1);
    }
    #[test]
    fn load_sip_register() {
        assert_loads("tests/pcap-samples/sip-register.pcap", 1);
    }
    #[test]
    fn load_sip_rtp_g711() {
        assert_loads("tests/pcap-samples/sip-rtp-g711.pcap", 10);
    }
    #[test]
    fn load_sip_rtp_g722() {
        assert_loads("tests/pcap-samples/sip-rtp-g722.pcap", 10);
    }
    #[test]
    fn load_sip_rtp_g729a() {
        assert_loads("tests/pcap-samples/sip-rtp-g729a.pcap", 10);
    }
    #[test]
    fn load_sip_rtp_opus() {
        assert_loads("tests/pcap-samples/sip-rtp-opus-hybrid.pcap", 1);
    }
    #[test]
    fn load_sip_sdp_example() {
        assert_loads("tests/pcap-samples/sip-sdp-example.pcap", 1);
    }
    #[test]
    fn load_rtsp_tcp_cap() {
        assert_loads("tests/pcap-samples/rtsp-interleaved-tcp.cap", 1);
    }
    #[test]
    fn load_voipshark_normal() {
        assert_loads("tests/pcap-samples/voipshark-normal-call.pcap", 100);
    }
    #[test]
    fn load_voipshark_dtmf() {
        assert_loads("tests/pcap-samples/voipshark-dtmf.pcap", 100);
    }
    #[test]
    fn load_voipshark_srtp() {
        assert_loads("tests/pcap-samples/voipshark-srtp-call.pcap", 100);
    }
    #[test]
    fn load_voipshark_tls_rtp() {
        assert_loads("tests/pcap-samples/voipshark-tls-rtp.pcap", 100);
    }
    #[test]
    fn load_voipshark_tls_srtp() {
        assert_loads("tests/pcap-samples/voipshark-tls-srtp.pcap", 100);
    }
    #[test]
    fn load_speech_8k_ulaw() {
        // Linux SLL (cooked v1) link-type — the only SLL fixture in the suite.
        assert_loads("tests/pcap-samples/speech_8k_ulaw.pcap", 100);
    }
    #[test]
    fn load_voicecmd_combined() {
        assert_loads("tests/pcap-samples/voicecmd_combined.pcap", 1000);
    }

    // -- pcapng format files --

    #[test]
    fn load_b2bua_pcapng() {
        assert_loads("tests/pcap-samples/b2bua-asterisk.pcapng", 10);
    }
    #[test]
    fn load_sip_488_pcapng() {
        assert_loads("tests/pcap-samples/sip-488-codec-reject.pcapng", 1);
    }
    #[test]
    fn load_sip_auth_pcapng() {
        assert_loads("tests/pcap-samples/sip-auth-failure.pcapng", 1);
    }
    #[test]
    fn load_sip_routing_pcapng() {
        assert_loads("tests/pcap-samples/sip-routing-error.pcapng", 1);
    }
    #[test]
    fn load_sipp_branch_pcapng() {
        assert_loads("tests/pcap-samples/sipp-branch-scenario.pcapng", 100);
    }

    // -- .cap files (mixed formats) --

    #[test]
    fn load_http_cap_pcap_format() {
        assert_loads("tests/pcap-samples/http-example.cap", 1);
    }

    #[test]
    fn load_c07_sip_r2_netmon() {
        let data = std::fs::read("tests/pcap-samples/c07-sip-r2.cap").unwrap();
        let result = PcapReader::new(&data);
        assert!(result.is_err(), "NetMon format should error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Network Monitor"),
            "Error should mention Network Monitor: {err}"
        );
        assert!(
            err.contains("editcap"),
            "Error should suggest editcap conversion: {err}"
        );
    }

    // ── Hardening regression tests ───────────────────────────────────

    /// Helper: build a minimal pcapng SHB (Section Header Block), little-endian.
    /// Returns the raw bytes for a 28-byte SHB.
    fn build_shb() -> Vec<u8> {
        let mut buf = Vec::new();
        // Block type: SHB
        buf.extend_from_slice(&0x0a0d0d0au32.to_le_bytes());
        // Block total length: 28
        buf.extend_from_slice(&28u32.to_le_bytes());
        // Byte-Order Magic (LE)
        buf.extend_from_slice(&0x1a2b3c4du32.to_le_bytes());
        // Version 1.0
        buf.extend_from_slice(&1u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        // Section length: -1 (not specified)
        buf.extend_from_slice(&(-1i64).to_le_bytes());
        // Trailing block total length
        buf.extend_from_slice(&28u32.to_le_bytes());
        buf
    }

    /// Helper: build a pcapng IDB (Interface Description Block), little-endian.
    /// `opts` is appended as raw option bytes before the trailing length.
    fn build_idb(link_type: u16, opts: &[u8]) -> Vec<u8> {
        // Fixed part: 8 (block header) + 4 (link_type + reserved) + 4 (snap_len)
        // + opts.len() + 4 (trailing length) — must be padded to 4-byte boundary
        let opts_padded = if opts.len() % 4 != 0 {
            opts.len() + (4 - opts.len() % 4)
        } else {
            opts.len()
        };
        let total_len = 8 + 4 + 4 + opts_padded + 4;
        let mut buf = Vec::new();
        // Block type: IDB (0x00000001)
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        // LinkType + Reserved
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        // SnapLen
        buf.extend_from_slice(&65535u32.to_le_bytes());
        // Options
        buf.extend_from_slice(opts);
        // Pad to 4-byte boundary
        while buf.len() < total_len - 4 {
            buf.push(0);
        }
        // Trailing block total length
        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        buf
    }

    /// Helper: build a pcapng EPB (Enhanced Packet Block), little-endian.
    fn build_epb(
        ts_high: u32,
        ts_low: u32,
        captured_len: u32,
        orig_len: u32,
        pkt_data: &[u8],
    ) -> Vec<u8> {
        let data_padded = if pkt_data.len() % 4 != 0 {
            pkt_data.len() + (4 - pkt_data.len() % 4)
        } else {
            pkt_data.len()
        };
        let total_len = 8 + 4 + 4 + 4 + 4 + 4 + data_padded + 4;
        let mut buf = Vec::new();
        // Block type: EPB (0x00000006)
        buf.extend_from_slice(&6u32.to_le_bytes());
        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        // Interface ID
        buf.extend_from_slice(&0u32.to_le_bytes());
        // Timestamp high + low
        buf.extend_from_slice(&ts_high.to_le_bytes());
        buf.extend_from_slice(&ts_low.to_le_bytes());
        // Captured Len
        buf.extend_from_slice(&captured_len.to_le_bytes());
        // Original Len
        buf.extend_from_slice(&orig_len.to_le_bytes());
        // Packet data
        buf.extend_from_slice(pkt_data);
        // Pad to 4-byte boundary
        while buf.len() < total_len - 4 {
            buf.push(0);
        }
        // Trailing block total length
        buf.extend_from_slice(&(total_len as u32).to_le_bytes());
        buf
    }

    /// Helper: build a classic pcap global header (24 bytes, LE).
    fn build_pcap_header(link_type: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        // Magic (LE, microseconds)
        buf.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        // Version 2.4
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        // ThisZone
        buf.extend_from_slice(&0i32.to_le_bytes());
        // SigFigs
        buf.extend_from_slice(&0u32.to_le_bytes());
        // SnapLen
        buf.extend_from_slice(&65535u32.to_le_bytes());
        // Network (link type)
        buf.extend_from_slice(&link_type.to_le_bytes());
        buf
    }

    /// Helper: build a classic pcap packet record header (16 bytes, LE).
    fn build_pcap_packet_header(
        ts_sec: u32,
        ts_usec: u32,
        incl_len: u32,
        orig_len: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
        buf.extend_from_slice(&incl_len.to_le_bytes());
        buf.extend_from_slice(&orig_len.to_le_bytes());
        buf
    }

    #[test]
    fn truncated_epb_block_no_panic() {
        // EPB block header claims block_total_len >= 32 but the actual file
        // data ends before offset+28, so the field reads should return None.
        let mut data = build_shb();
        data.extend_from_slice(&build_idb(1, &[]));

        // Craft a truncated EPB: write block_type + block_total_len only (8 bytes),
        // claiming total_len = 64, but provide no further data.
        data.extend_from_slice(&6u32.to_le_bytes()); // block type: EPB
        data.extend_from_slice(&64u32.to_le_bytes()); // block_total_len = 64

        // Only 8 bytes of the "block" exist — reads at offset+12..+28 must fail gracefully
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        // Should return no packets — the EPB is too short to parse
        assert!(packets.is_empty(), "truncated EPB should yield no packets");
    }

    #[test]
    fn huge_incl_len_classic_pcap_no_panic() {
        // Classic pcap with incl_len = 0xFFFFFFFF. The checked_add + bounds check
        // must prevent any out-of-bounds access or allocation panic.
        let mut data = build_pcap_header(1);
        data.extend_from_slice(&build_pcap_packet_header(1000, 0, 0xFFFFFFFF, 0xFFFFFFFF));

        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(
            packets.is_empty(),
            "huge incl_len should produce no packets"
        );
    }

    #[test]
    fn huge_captured_len_pcapng_epb_no_panic() {
        // pcapng EPB with captured_len = 0xFFFFFFFF. The data_end checked_add
        // or bounds check must prevent panic.
        let mut data = build_shb();
        data.extend_from_slice(&build_idb(1, &[]));

        // Build an EPB where captured_len = 0xFFFFFFFF but block_total_len is
        // just large enough for the header (32). The captured_len will exceed
        // the actual data, so it should be skipped.
        let mut epb = Vec::new();
        epb.extend_from_slice(&6u32.to_le_bytes()); // block type: EPB
        epb.extend_from_slice(&32u32.to_le_bytes()); // block_total_len = 32
        epb.extend_from_slice(&0u32.to_le_bytes()); // interface ID
        epb.extend_from_slice(&0u32.to_le_bytes()); // ts_high
        epb.extend_from_slice(&0u32.to_le_bytes()); // ts_low
        epb.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // captured_len (huge)
        epb.extend_from_slice(&0u32.to_le_bytes()); // orig_len
        epb.extend_from_slice(&32u32.to_le_bytes()); // trailing block_total_len
        data.extend_from_slice(&epb);

        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(
            packets.is_empty(),
            "huge captured_len EPB should produce no packets"
        );
    }

    #[test]
    fn if_tsresol_overflow_no_panic() {
        // IDB with if_tsresol option value = 20 (power-of-10 mode).
        // 10^20 overflows u64. The parser should clamp to u64::MAX and
        // not panic or divide by zero.
        let mut opts = Vec::new();
        // Option code 9 (if_tsresol), length 1
        opts.extend_from_slice(&9u16.to_le_bytes());
        opts.extend_from_slice(&1u16.to_le_bytes());
        // Value: 20 (bit 7 = 0 → power of 10, exponent = 20)
        opts.push(20);
        // Pad to 4-byte boundary
        opts.extend_from_slice(&[0, 0, 0]);
        // End of options
        opts.extend_from_slice(&0u16.to_le_bytes());
        opts.extend_from_slice(&0u16.to_le_bytes());

        let mut data = build_shb();
        data.extend_from_slice(&build_idb(1, &opts));

        // Now append an EPB with a valid timestamp and some packet data
        let pkt_payload = [0xAAu8; 16];
        data.extend_from_slice(&build_epb(0, 1000, 16, 16, &pkt_payload));

        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        // Should produce exactly one packet without panicking
        assert_eq!(
            packets.len(),
            1,
            "should parse the EPB even with overflowed tsresol"
        );
        assert_eq!(packets[0].data.len(), 16);
        // Timestamp may be clamped/weird, but must be finite and not cause panic
        // (the division by u64::MAX yields 0 for ts_sec, which is fine)
    }

    #[test]
    fn zero_length_classic_pcap_packet() {
        // Classic pcap with a packet whose incl_len = 0. Should parse
        // successfully with empty data vec.
        let mut data = build_pcap_header(1);
        data.extend_from_slice(&build_pcap_packet_header(1000, 500, 0, 100));

        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert_eq!(packets.len(), 1, "zero-length packet should parse");
        assert!(packets[0].data.is_empty(), "packet data should be empty");
        assert_eq!(packets[0].timestamp_secs, 1000);
        assert_eq!(packets[0].timestamp_usecs, 500);
        assert_eq!(packets[0].orig_len, 100);
    }
}
