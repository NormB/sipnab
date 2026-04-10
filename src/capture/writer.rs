//! Pcap output writer with rotation support.
//!
//! [`PcapWriter`] wraps `pcap::Savefile` and adds support for:
//! - Writing captured packets to pcap files
//! - File rotation by size (`--split filesize:N`)
//! - File rotation by duration (`--split duration:N`)
//! - On-demand rotation via SIGUSR1 (checked via [`crate::signals::rotation_requested`])

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::packet::Packet;
use crate::signals;

/// Pcap output writer with optional file rotation.
///
/// Wraps a pcap `Savefile` and tracks state for rotation decisions.
pub struct PcapWriter {
    /// The underlying pcap savefile handle.
    savefile: pcap::Savefile,
    /// Base path for output files (used for rotation naming).
    base_path: PathBuf,
    /// Link-layer type for the pcap header.
    link_type: pcap::Linktype,
    /// Current file sequence number (0 for the first file).
    sequence: u32,
    /// Bytes written to the current file.
    bytes_written: u64,
    /// When the current file was opened.
    file_opened_at: std::time::Instant,
    /// Rotate when file exceeds this size in bytes (from `--split filesize:N`).
    max_file_bytes: Option<u64>,
    /// Rotate when file has been open for this duration (from `--split duration:N`).
    max_file_duration: Option<std::time::Duration>,
}

impl PcapWriter {
    /// Create a new pcap writer at the given path.
    ///
    /// The file is created immediately with the specified link-layer type.
    /// Rotation parameters are optional; pass `None` to disable automatic rotation.
    pub fn new(
        path: &Path,
        link_type: i32,
        max_file_bytes: Option<u64>,
        max_file_duration: Option<std::time::Duration>,
    ) -> Result<Self> {
        let linktype = pcap::Linktype(link_type);
        let savefile = create_savefile(path, linktype)?;

        log::info!("Writing packets to '{}'", path.display());

        Ok(Self {
            savefile,
            base_path: path.to_path_buf(),
            link_type: linktype,
            sequence: 0,
            bytes_written: 0,
            file_opened_at: std::time::Instant::now(),
            max_file_bytes,
            max_file_duration,
        })
    }

    /// Write a packet to the output file.
    ///
    /// Checks rotation conditions (size, duration, SIGUSR1) before writing.
    /// If rotation is needed, the current file is closed and a new one opened
    /// with an incremented sequence number.
    pub fn write(&mut self, packet: &Packet) -> Result<()> {
        // Check if rotation is needed before writing
        if self.should_rotate() {
            self.rotate()?;
        }

        let ts = packet.timestamp;
        let secs = ts.timestamp();
        let usecs = ts.timestamp_subsec_micros();

        let header = pcap::PacketHeader {
            ts: libc::timeval {
                tv_sec: secs as libc::time_t,
                tv_usec: usecs as libc::suseconds_t,
            },
            caplen: packet.caplen as u32,
            len: packet.origlen as u32,
        };

        self.savefile.write(&pcap::Packet {
            header: &header,
            data: &packet.data,
        });

        self.bytes_written += packet.caplen as u64;
        Ok(())
    }

    /// Force rotation to a new output file.
    ///
    /// Closes the current file and opens a new one with an incremented
    /// sequence number appended to the base filename.
    pub fn rotate(&mut self) -> Result<()> {
        self.sequence += 1;
        let new_path = rotated_path(&self.base_path, self.sequence);

        log::info!(
            "Rotating output to '{}' (seq={}, wrote {} bytes in {:?})",
            new_path.display(),
            self.sequence,
            self.bytes_written,
            self.file_opened_at.elapsed(),
        );

        // Drop the old savefile (flushes and closes) by replacing it
        self.savefile = create_savefile(&new_path, self.link_type)?;
        self.bytes_written = 0;
        self.file_opened_at = std::time::Instant::now();

        Ok(())
    }

    /// Check whether any rotation condition is met.
    fn should_rotate(&self) -> bool {
        // SIGUSR1-triggered rotation
        if signals::rotation_requested() {
            log::debug!("Rotation triggered by SIGUSR1");
            return true;
        }

        // Size-based rotation
        if let Some(max_bytes) = self.max_file_bytes
            && self.bytes_written >= max_bytes
        {
            log::debug!(
                "Rotation triggered by size ({} >= {max_bytes})",
                self.bytes_written,
            );
            return true;
        }

        // Duration-based rotation
        if let Some(max_dur) = self.max_file_duration
            && self.file_opened_at.elapsed() >= max_dur
        {
            log::debug!("Rotation triggered by duration ({:?})", max_dur);
            return true;
        }

        false
    }
}

/// Create a pcap `Savefile` at the given path using a dead capture handle.
fn create_savefile(path: &Path, linktype: pcap::Linktype) -> Result<pcap::Savefile> {
    let dead =
        pcap::Capture::dead(linktype).context("Failed to create dead capture for savefile")?;
    dead.savefile(path)
        .with_context(|| format!("Failed to create output file '{}'", path.display()))
}

/// Generate a rotated filename from a base path and sequence number.
///
/// `output.pcap` with sequence 1 becomes `output_00001.pcap`.
/// If there is no extension, the sequence is appended directly.
fn rotated_path(base: &Path, sequence: u32) -> PathBuf {
    let stem = base
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("capture");
    let ext = base.extension().and_then(|s| s.to_str()).unwrap_or("pcap");
    let parent = base.parent().unwrap_or_else(|| Path::new("."));

    parent.join(format!("{stem}_{sequence:05}.{ext}"))
}

/// Parse a `--split` value into rotation parameters.
///
/// Supported formats:
/// - `filesize:N` — rotate after N megabytes
/// - `duration:N` — rotate after N seconds
///
/// Returns `(max_file_bytes, max_file_duration)`.
pub fn parse_split(split: &str) -> Result<(Option<u64>, Option<std::time::Duration>)> {
    let parts: Vec<&str> = split.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid --split format: '{split}'. Expected 'filesize:N' or 'duration:N'");
    }

    let key = parts[0];
    let value: u64 = parts[1]
        .parse()
        .with_context(|| format!("Invalid --split value: '{}'", parts[1]))?;

    match key {
        "filesize" => Ok((Some(value * 1_000_000), None)), // N megabytes
        "duration" => Ok((None, Some(std::time::Duration::from_secs(value)))),
        _ => anyhow::bail!("Unknown --split condition: '{key}'. Expected 'filesize' or 'duration'"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotated_path_with_extension() {
        let base = PathBuf::from("/tmp/output.pcap");
        assert_eq!(
            rotated_path(&base, 1),
            PathBuf::from("/tmp/output_00001.pcap")
        );
        assert_eq!(
            rotated_path(&base, 42),
            PathBuf::from("/tmp/output_00042.pcap")
        );
    }

    #[test]
    fn rotated_path_no_extension() {
        let base = PathBuf::from("/tmp/capture");
        // When there's no extension, file_stem is "capture" and extension defaults to "pcap"
        assert_eq!(
            rotated_path(&base, 3),
            PathBuf::from("/tmp/capture_00003.pcap")
        );
    }

    #[test]
    fn parse_split_filesize() {
        let (bytes, dur) = parse_split("filesize:50").unwrap();
        assert_eq!(bytes, Some(50_000_000));
        assert!(dur.is_none());
    }

    #[test]
    fn parse_split_duration() {
        let (bytes, dur) = parse_split("duration:300").unwrap();
        assert!(bytes.is_none());
        assert_eq!(dur, Some(std::time::Duration::from_secs(300)));
    }

    #[test]
    fn parse_split_invalid() {
        assert!(parse_split("bogus:5").is_err());
        assert!(parse_split("filesize").is_err());
        assert!(parse_split("filesize:abc").is_err());
    }
}
