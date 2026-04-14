//! Pure-Rust pcap file reader for WASM compatibility.
//! Reads pcap files from raw byte slices without the libpcap C library.

use anyhow::{Result, bail, ensure};

pub struct PcapPacket {
    pub timestamp_secs: u32,
    pub timestamp_usecs: u32,
    pub data: Vec<u8>,
    pub orig_len: u32,
}

pub struct PcapReader<'a> {
    data: &'a [u8],
    offset: usize,
    big_endian: bool,
    nanoseconds: bool,
    pub link_type: u32,
}

impl<'a> PcapReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        ensure!(data.len() >= 24, "pcap file too short for global header");
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);

        let (big_endian, nanoseconds) = match magic {
            0xa1b2c3d4 => (false, false), // LE, microseconds
            0xd4c3b2a1 => (true, false),  // BE, microseconds
            0xa1b23c4d => (false, true),  // LE, nanoseconds
            0x4d3cb2a1 => (true, true),   // BE, nanoseconds
            _ => bail!("Not a pcap file (magic: 0x{:08x})", magic),
        };

        let read_u32 = |off: usize| -> u32 {
            if big_endian {
                u32::from_be_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            } else {
                u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
            }
        };

        let link_type = read_u32(20);

        Ok(Self {
            data,
            offset: 24,
            big_endian,
            nanoseconds,
            link_type,
        })
    }

    fn read_u32(&self, off: usize) -> u32 {
        if self.big_endian {
            u32::from_be_bytes([
                self.data[off],
                self.data[off + 1],
                self.data[off + 2],
                self.data[off + 3],
            ])
        } else {
            u32::from_le_bytes([
                self.data[off],
                self.data[off + 1],
                self.data[off + 2],
                self.data[off + 3],
            ])
        }
    }
}

impl<'a> Iterator for PcapReader<'a> {
    type Item = PcapPacket;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset + 16 > self.data.len() {
            return None;
        }

        let ts_sec = self.read_u32(self.offset);
        let ts_usec = self.read_u32(self.offset + 4);
        let incl_len = self.read_u32(self.offset + 8) as usize;
        let orig_len = self.read_u32(self.offset + 12);

        self.offset += 16;

        if self.offset + incl_len > self.data.len() {
            return None; // Truncated
        }

        let data = self.data[self.offset..self.offset + incl_len].to_vec();
        self.offset += incl_len;

        // Convert nanoseconds to microseconds if needed
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_real_pcap_file() {
        let data = std::fs::read("tests/pcap-samples/sip-rtp-g711.pcap").unwrap();
        let reader = PcapReader::new(&data).unwrap();
        assert_eq!(reader.link_type, 1); // Ethernet
        let packets: Vec<_> = reader.collect();
        assert!(packets.len() > 10, "should have multiple packets");
    }

    #[test]
    fn parse_pcapng_not_supported() {
        let data = std::fs::read("tests/pcap-samples/b2bua-asterisk.pcapng").unwrap();
        let result = PcapReader::new(&data);
        assert!(result.is_err(), "pcapng should fail with clear error");
    }

    #[test]
    fn too_short_file() {
        let result = PcapReader::new(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn truncated_packet() {
        let data = std::fs::read("tests/pcap-samples/sip-rtp-g711.pcap").unwrap();
        // Truncate mid-packet
        let truncated = &data[..100];
        let reader = PcapReader::new(truncated).unwrap();
        let packets: Vec<_> = reader.collect();
        // Should parse what it can, not panic
        assert!(packets.len() <= 1);
    }
}
