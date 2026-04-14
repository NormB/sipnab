//! Pure-Rust pcap/pcapng file reader for WASM compatibility.
//! Reads both pcap and pcapng files from raw byte slices without libpcap.

use anyhow::{Result, bail, ensure};

pub struct PcapPacket {
    pub timestamp_secs: u32,
    pub timestamp_usecs: u32,
    pub data: Vec<u8>,
    pub orig_len: u32,
}

/// Unified reader for both pcap and pcapng formats.
#[derive(Debug)]
pub struct PcapReader<'a> {
    inner: ReaderInner<'a>,
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
    fn read_u32(&self, off: usize) -> u32 {
        if self.big_endian {
            u32::from_be_bytes([self.data[off], self.data[off+1], self.data[off+2], self.data[off+3]])
        } else {
            u32::from_le_bytes([self.data[off], self.data[off+1], self.data[off+2], self.data[off+3]])
        }
    }

    fn next_packet(&mut self) -> Option<PcapPacket> {
        if self.offset + 16 > self.data.len() { return None; }
        let ts_sec = self.read_u32(self.offset);
        let ts_usec = self.read_u32(self.offset + 4);
        let incl_len = self.read_u32(self.offset + 8) as usize;
        let orig_len = self.read_u32(self.offset + 12);
        self.offset += 16;
        if self.offset + incl_len > self.data.len() { return None; }
        let data = self.data[self.offset..self.offset + incl_len].to_vec();
        self.offset += incl_len;
        let ts_usec = if self.nanoseconds { ts_usec / 1000 } else { ts_usec };
        Some(PcapPacket { timestamp_secs: ts_sec, timestamp_usecs: ts_usec, data, orig_len })
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
    fn read_u16(&self, off: usize) -> u16 {
        if self.big_endian {
            u16::from_be_bytes([self.data[off], self.data[off+1]])
        } else {
            u16::from_le_bytes([self.data[off], self.data[off+1]])
        }
    }

    fn read_u32(&self, off: usize) -> u32 {
        if self.big_endian {
            u32::from_be_bytes([self.data[off], self.data[off+1], self.data[off+2], self.data[off+3]])
        } else {
            u32::from_le_bytes([self.data[off], self.data[off+1], self.data[off+2], self.data[off+3]])
        }
    }

    fn next_packet(&mut self) -> Option<PcapPacket> {
        // Walk blocks until we find an Enhanced Packet Block (EPB) or Simple Packet Block
        loop {
            if self.offset + 12 > self.data.len() { return None; }

            let block_type = self.read_u32(self.offset);
            let block_total_len = self.read_u32(self.offset + 4) as usize;

            if block_total_len < 12 || self.offset + block_total_len > self.data.len() {
                return None; // Truncated or corrupt
            }

            match block_type {
                // Section Header Block (SHB) — 0x0a0d0d0a
                0x0a0d0d0a => {
                    // Re-detect endianness from byte order magic at offset+8
                    if self.offset + 16 <= self.data.len() {
                        let bom = u32::from_le_bytes([
                            self.data[self.offset+8], self.data[self.offset+9],
                            self.data[self.offset+10], self.data[self.offset+11],
                        ]);
                        self.big_endian = bom == 0x4d3c2b1a;
                    }
                    self.offset += block_total_len;
                }

                // Interface Description Block (IDB) — 0x00000001
                0x00000001 => {
                    if block_total_len >= 20 {
                        self.link_type = self.read_u16(self.offset + 8) as u32;
                        // Parse options for if_tsresol
                        let opts_start = self.offset + 16;
                        let opts_end = self.offset + block_total_len - 4;
                        self.parse_idb_options(opts_start, opts_end);
                    }
                    self.offset += block_total_len;
                }

                // Enhanced Packet Block (EPB) — 0x00000006
                0x00000006 => {
                    if block_total_len < 32 {
                        self.offset += block_total_len;
                        continue;
                    }
                    // EPB layout: block_type(4) + block_len(4) + interface_id(4) +
                    //   ts_high(4) + ts_low(4) + captured_len(4) + orig_len(4) + data(...)
                    let ts_high = self.read_u32(self.offset + 12);
                    let ts_low = self.read_u32(self.offset + 16);
                    let captured_len = self.read_u32(self.offset + 20) as usize;
                    let orig_len = self.read_u32(self.offset + 24);

                    let data_start = self.offset + 28;
                    if data_start + captured_len > self.data.len() {
                        self.offset += block_total_len;
                        continue;
                    }

                    let pkt_data = self.data[data_start..data_start + captured_len].to_vec();

                    // Convert 64-bit timestamp to seconds + microseconds
                    let ts64 = ((ts_high as u64) << 32) | (ts_low as u64);
                    let ts_sec = (ts64 / self.if_tsresol) as u32;
                    let ts_usec = ((ts64 % self.if_tsresol) * 1_000_000 / self.if_tsresol) as u32;

                    self.offset += block_total_len;
                    return Some(PcapPacket {
                        timestamp_secs: ts_sec,
                        timestamp_usecs: ts_usec,
                        data: pkt_data,
                        orig_len,
                    });
                }

                // Any other block — skip
                _ => {
                    self.offset += block_total_len;
                }
            }
        }
    }

    fn parse_idb_options(&mut self, mut pos: usize, end: usize) {
        while pos + 4 <= end {
            let opt_code = self.read_u16(pos);
            let opt_len = self.read_u16(pos + 2) as usize;
            pos += 4;
            if pos + opt_len > end { break; }

            // if_tsresol option (code 9)
            if opt_code == 9 && opt_len >= 1 {
                let tsresol = self.data[pos];
                if tsresol & 0x80 != 0 {
                    // Power of 2
                    let exp = (tsresol & 0x7f) as u32;
                    self.if_tsresol = 1u64 << exp;
                } else {
                    // Power of 10
                    self.if_tsresol = 10u64.pow(tsresol as u32);
                }
            }

            // opt_endofopt (code 0)
            if opt_code == 0 { break; }

            // Pad to 4-byte boundary
            pos += opt_len + (4 - (opt_len % 4)) % 4;
        }
    }
}

// ── PcapReader public API ─────────────────────────────────────────────

impl<'a> PcapReader<'a> {
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
                        data, offset: 24, big_endian, nanoseconds,
                    }),
                    link_type,
                })
            }

            // Pcapng Section Header Block
            0x0a0d0d0a => {
                ensure!(data.len() >= 28, "pcapng file too short for SHB");
                // Byte-order magic at offset 8
                let bom = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
                let big_endian = bom == 0x4d3c2b1a;
                let shb_len = if big_endian {
                    u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize
                } else {
                    u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize
                };
                let start = if shb_len > 0 && shb_len <= data.len() { shb_len } else { 28 };

                Ok(Self {
                    inner: ReaderInner::Ng(NgReader {
                        data,
                        offset: start,
                        big_endian,
                        if_tsresol: 1_000_000, // default: microseconds
                        link_type: 1, // default: Ethernet (updated by IDB)
                    }),
                    link_type: 1,
                })
            }

            // Microsoft Network Monitor format
            0x55424d47 => bail!("Microsoft Network Monitor (.cap) format is not supported. Convert to pcap with: editcap -F pcap input.cap output.pcap"),
            _ => bail!("Not a pcap/pcapng file (magic: 0x{:08x}). Supported formats: .pcap, .pcapng, .cap (pcap format)", magic),
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
                // Update the public link_type from the ng reader (set by IDB)
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
        assert!(packets.len() > 5, "pcapng should have packets, got {}", packets.len());
        // Verify timestamps are reasonable (non-zero)
        assert!(packets[0].timestamp_secs > 0, "timestamp should be non-zero");
    }

    #[test]
    fn parse_pcapng_sip_auth_failure() {
        let data = std::fs::read("tests/pcap-samples/sip-auth-failure.pcapng").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(packets.len() > 0, "should have packets");
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
        // .cap files that are pcap format should work
        let data = std::fs::read("tests/pcap-samples/SIP_DTMF2.cap").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        let packets: Vec<_> = reader.collect();
        assert!(packets.len() > 0, "pcap-format .cap file should parse");
    }

    #[test]
    fn cap_file_netmon_format_error() {
        let data = std::fs::read("tests/pcap-samples/rtsp-packets.cap").unwrap();
        let result = PcapReader::new(&data);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Network Monitor"));
    }

    // ── Load every capture file in tests/pcap-samples/ ──────────────

    /// Helper: load a file and assert it parses with at least `min_packets` packets.
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

    #[test] fn load_asterisk_zfone() { assert_loads("tests/pcap-samples/Asterisk_ZFONE_XLITE.pcap", 10); }
    #[test] fn load_dtmfsipinfo() { assert_loads("tests/pcap-samples/DTMFsipinfo.pcap", 1); }
    #[test] fn load_h263_rtp() { assert_loads("tests/pcap-samples/h263-over-rtp.pcap", 1); }
    #[test] fn load_metasploit() { assert_loads("tests/pcap-samples/metasploit-sip-invite-spoof.pcap", 1); }
    #[test] fn load_rtp_protocol() { assert_loads("tests/pcap-samples/rtp-protocol.pcap", 1); }
    #[test] fn load_sip_call_g711() { assert_loads("tests/pcap-samples/SIP_CALL_RTP_G711", 100); }
    #[test] fn load_sip_dtmf2_cap() { assert_loads("tests/pcap-samples/SIP_DTMF2.cap", 10); }
    #[test] fn load_sip_over_tcp() { assert_loads("tests/pcap-samples/sip-over-tcp.pcap", 1); }
    #[test] fn load_sip_proxy() { assert_loads("tests/pcap-samples/sip-proxy.pcap", 1); }
    #[test] fn load_sip_register() { assert_loads("tests/pcap-samples/sip-register.pcap", 1); }
    #[test] fn load_sip_rtp_g711() { assert_loads("tests/pcap-samples/sip-rtp-g711.pcap", 10); }
    #[test] fn load_sip_rtp_g722() { assert_loads("tests/pcap-samples/sip-rtp-g722.pcap", 10); }
    #[test] fn load_sip_rtp_g729a() { assert_loads("tests/pcap-samples/sip-rtp-g729a.pcap", 10); }
    #[test] fn load_sip_rtp_opus() { assert_loads("tests/pcap-samples/sip-rtp-opus-hybrid.pcap", 1); }
    #[test] fn load_sip_sdp_example() { assert_loads("tests/pcap-samples/sip-sdp-example.pcap", 1); }
    #[test] fn load_rtsp_tcp_cap() { assert_loads("tests/pcap-samples/rtsp-interleaved-tcp.cap", 1); }
    #[test] fn load_voipshark_normal() { assert_loads("tests/pcap-samples/voipshark-normal-call.pcap", 100); }
    #[test] fn load_voipshark_dtmf() { assert_loads("tests/pcap-samples/voipshark-dtmf.pcap", 100); }
    #[test] fn load_voipshark_srtp() { assert_loads("tests/pcap-samples/voipshark-srtp-call.pcap", 100); }
    #[test] fn load_voipshark_tls_rtp() { assert_loads("tests/pcap-samples/voipshark-tls-rtp.pcap", 100); }
    #[test] fn load_voipshark_tls_srtp() { assert_loads("tests/pcap-samples/voipshark-tls-srtp.pcap", 100); }

    // -- pcapng format files --

    #[test] fn load_b2bua_pcapng() { assert_loads("tests/pcap-samples/b2bua-asterisk.pcapng", 10); }
    #[test] fn load_sip_488_pcapng() { assert_loads("tests/pcap-samples/sip-488-codec-reject.pcapng", 1); }
    #[test] fn load_sip_auth_pcapng() { assert_loads("tests/pcap-samples/sip-auth-failure.pcapng", 1); }
    #[test] fn load_sip_routing_pcapng() { assert_loads("tests/pcap-samples/sip-routing-error.pcapng", 1); }
    #[test] fn load_sipp_branch_pcapng() { assert_loads("tests/pcap-samples/sipp-branch-scenario.pcapng", 100); }

    // -- .cap files (mixed formats) --

    #[test] fn load_http_cap_pcap_format() { assert_loads("tests/pcap-samples/http-example.cap", 1); }

    #[test]
    fn load_c07_sip_r2_netmon() {
        let data = std::fs::read("tests/pcap-samples/c07-sip-r2.cap").unwrap();
        let result = PcapReader::new(&data);
        assert!(result.is_err(), "NetMon format should error");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Network Monitor"), "Error should mention Network Monitor: {err}");
        assert!(err.contains("editcap"), "Error should suggest editcap conversion: {err}");
    }
}
