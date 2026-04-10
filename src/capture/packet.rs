//! Core packet type for sipnab.
//!
//! [`Packet`] represents a single captured network packet with metadata
//! including timestamp, raw bytes, capture/original lengths, source interface,
//! and link-layer type.

use chrono::{DateTime, Utc};

/// A captured network packet with metadata.
///
/// Carries the raw bytes from the link layer along with timing and source
/// information needed for downstream parsing and output.
#[derive(Debug, Clone)]
pub struct Packet {
    /// When the packet was captured (UTC).
    pub timestamp: DateTime<Utc>,
    /// Raw packet bytes starting from the link layer.
    pub data: Vec<u8>,
    /// Number of bytes actually captured (may be less than `origlen`).
    pub caplen: usize,
    /// Original length of the packet on the wire.
    pub origlen: usize,
    /// Name of the capture interface, if from a live source.
    pub interface: Option<String>,
    /// Pcap link-layer header type (e.g., `1` for `DLT_EN10MB`).
    pub link_type: i32,
}

impl Packet {
    /// Create a new packet from raw capture data.
    ///
    /// This is the primary constructor used by both live and file capture paths.
    pub fn new(
        timestamp: DateTime<Utc>,
        data: Vec<u8>,
        caplen: usize,
        origlen: usize,
        interface: Option<String>,
        link_type: i32,
    ) -> Self {
        Self {
            timestamp,
            data,
            caplen,
            origlen,
            interface,
            link_type,
        }
    }
}
