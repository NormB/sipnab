//! Pcap output writer with rotation support.
//!
//! [`PcapWriter`] wraps `pcap::Savefile` and adds support for:
//! - Writing captured packets to pcap files (standard pcap or PCAP-NG)
//! - File rotation by size (`--split filesize:N`)
//! - File rotation by duration (`--split duration:N`)
//! - On-demand rotation via SIGUSR1 (checked via [`crate::signals::rotation_requested`])
//! - Export mode control via `--pcap-export-mode` for TLS traffic

use std::borrow::Cow;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use pcap_file::DataLink;
use pcap_file::Endianness;
use pcap_file::pcapng::PcapNgWriter as PcapFileNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};
use pcap_file::pcapng::blocks::section_header::{SectionHeaderBlock, SectionHeaderOption};

use super::packet::Packet;
use crate::signals;

/// Controls how encrypted traffic is written to output pcap files.
///
/// - `Decrypted`: Include DSB (Decryption Secrets Block) so Wireshark can
///   decrypt inline. In a future version this may write synthetic decrypted
///   frames; today it behaves identically to `EncryptedWithDsb`.
/// - `EncryptedWithDsb`: Write original (encrypted) frames and include DSBs
///   containing the TLS key material so Wireshark can decrypt on load.
/// - `Raw`: Write original (encrypted) frames with no DSBs. The output file
///   contains only the packets as captured on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PcapExportMode {
    /// Default. Include DSBs; future: may write decrypted frames.
    Decrypted,
    /// Write encrypted frames + DSBs for Wireshark decryption.
    EncryptedWithDsb,
    /// Write original frames only, no key material embedded.
    Raw,
}

impl PcapExportMode {
    /// Parse from the CLI string value.
    ///
    /// Returns `None` for unrecognized values (caller should reject at
    /// validation time, so this is a fallback).
    pub fn parse_mode(s: &str) -> Option<Self> {
        match s {
            "decrypted" => Some(Self::Decrypted),
            "encrypted+dsb" => Some(Self::EncryptedWithDsb),
            "raw" => Some(Self::Raw),
            _ => None,
        }
    }

    /// Whether this mode should include DSB blocks in the output.
    pub fn include_dsb(self) -> bool {
        matches!(self, Self::Decrypted | Self::EncryptedWithDsb)
    }
}

/// Internal writer backend: either standard pcap or PCAP-NG.
enum WriterBackend {
    /// Standard pcap via the `pcap` crate.
    Pcap(pcap::Savefile),
    /// PCAP-NG via the `pcap-file` crate.
    PcapNg(PcapFileNgWriter<BufWriter<std::fs::File>>),
}

/// Pcap output writer with optional file rotation.
///
/// Wraps a pcap `Savefile` or a PCAP-NG writer and tracks state for rotation decisions.
pub struct PcapWriter {
    /// The underlying writer backend.
    backend: WriterBackend,
    /// Base path for output files (used for rotation naming).
    base_path: PathBuf,
    /// Link-layer type (pcap integer value).
    link_type_raw: i32,
    /// Whether to use PCAP-NG format.
    use_pcapng: bool,
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
    /// How encrypted traffic should be exported (controls DSB inclusion).
    export_mode: PcapExportMode,
    /// Whether a DSB has already been written to the current file.
    dsb_written: bool,
    /// Capture interface name embedded in pcapng IDBs (carried across rotation).
    interface_name: Option<String>,
}

impl PcapWriter {
    /// Create a new pcap writer at the given path.
    ///
    /// The file is created immediately with the specified link-layer type.
    /// Rotation parameters are optional; pass `None` to disable automatic rotation.
    /// Uses standard pcap format and `Decrypted` export mode.
    ///
    /// Warns if the path contains `..` components, which may indicate path
    /// traversal. The file is still opened (user may have legitimate reasons).
    pub fn new(
        path: &Path,
        link_type: i32,
        max_file_bytes: Option<u64>,
        max_file_duration: Option<std::time::Duration>,
    ) -> Result<Self> {
        Self::with_format(
            path,
            link_type,
            max_file_bytes,
            max_file_duration,
            false,
            PcapExportMode::Decrypted,
        )
    }

    /// Create a new writer with explicit format and export mode selection.
    ///
    /// When `pcapng` is `true`, the output uses PCAP-NG format; otherwise
    /// standard pcap. The `export_mode` controls whether DSB blocks are
    /// written for TLS key material. The capture interface is left unrecorded;
    /// use [`with_interface`](Self::with_interface) to embed it.
    pub fn with_format(
        path: &Path,
        link_type: i32,
        max_file_bytes: Option<u64>,
        max_file_duration: Option<std::time::Duration>,
        pcapng: bool,
        export_mode: PcapExportMode,
    ) -> Result<Self> {
        Self::with_interface(
            path,
            link_type,
            max_file_bytes,
            max_file_duration,
            pcapng,
            export_mode,
            None,
        )
    }

    /// As [`with_format`](Self::with_format), but records the capture
    /// `interface` name in the pcapng Interface Description Block so the export
    /// is self-describing (SNB-0001). Pass the capture device for live capture
    /// or the input source for replay; `None` (or empty) records no name.
    #[allow(clippy::too_many_arguments)]
    pub fn with_interface(
        path: &Path,
        link_type: i32,
        max_file_bytes: Option<u64>,
        max_file_duration: Option<std::time::Duration>,
        pcapng: bool,
        export_mode: PcapExportMode,
        interface: Option<&str>,
    ) -> Result<Self> {
        // M5: Warn on path traversal components
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            tracing::warn!(
                "Output path '{}' contains '..' components — verify this is intentional",
                path.display()
            );
        }

        let interface_name = interface.filter(|n| !n.is_empty()).map(|n| n.to_string());

        let backend = if pcapng {
            create_pcapng_backend(path, link_type, interface_name.as_deref())?
        } else {
            let linktype = pcap::Linktype(link_type);
            WriterBackend::Pcap(create_savefile(path, linktype)?)
        };

        tracing::info!(
            "Writing packets to '{}' ({}, mode={})",
            path.display(),
            if pcapng { "pcapng" } else { "pcap" },
            match export_mode {
                PcapExportMode::Decrypted => "decrypted",
                PcapExportMode::EncryptedWithDsb => "encrypted+dsb",
                PcapExportMode::Raw => "raw",
            },
        );

        Ok(Self {
            backend,
            base_path: path.to_path_buf(),
            link_type_raw: link_type,
            use_pcapng: pcapng,
            sequence: 0,
            bytes_written: 0,
            file_opened_at: std::time::Instant::now(),
            max_file_bytes,
            max_file_duration,
            export_mode,
            dsb_written: false,
            interface_name,
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

        match &mut self.backend {
            WriterBackend::Pcap(savefile) => {
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

                savefile.write(&pcap::Packet {
                    header: &header,
                    data: &packet.data,
                });
            }
            WriterBackend::PcapNg(writer) => {
                let ts = packet.timestamp;
                // PCAP-NG timestamps are in nanoseconds since epoch
                let nanos: u64 = ts
                    .timestamp_nanos_opt()
                    .and_then(|n| u64::try_from(n).ok())
                    .unwrap_or(0);
                let timestamp = Duration::from_nanos(nanos);

                let epb = EnhancedPacketBlock {
                    interface_id: 0,
                    timestamp,
                    original_len: packet.origlen as u32,
                    data: Cow::Borrowed(&packet.data),
                    options: vec![],
                };

                writer
                    .write_pcapng_block(epb)
                    .map_err(|e| anyhow::anyhow!("PCAP-NG write error: {e}"))?;
            }
        }

        self.bytes_written += packet.caplen as u64;
        Ok(())
    }

    /// Return the current export mode.
    pub fn export_mode(&self) -> PcapExportMode {
        self.export_mode
    }

    /// Write a Name Resolution Block (pcapng only) mapping IP addresses to
    /// host/FQDN names.
    ///
    /// `entries` are `(ip, names)` pairs (e.g. from
    /// [`crate::names::NameResolver::nrb_entries`]); names should already be
    /// validated. A no-op for empty input or the plain-pcap backend. An
    /// `opt_comment` records sipnab as the producer.
    pub fn write_name_resolution_block(
        &mut self,
        entries: &[(std::net::IpAddr, Vec<String>)],
    ) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        match &mut self.backend {
            WriterBackend::PcapNg(writer) => {
                use pcap_file::pcapng::blocks::name_resolution::{
                    Ipv4Record, Ipv6Record, NameResolutionBlock, NameResolutionOption, Record,
                };
                let mut records: Vec<Record> = Vec::with_capacity(entries.len());
                for (ip, names) in entries {
                    let names: Vec<Cow<str>> =
                        names.iter().map(|n| Cow::Owned(n.clone())).collect();
                    match ip {
                        std::net::IpAddr::V4(v4) => records.push(Record::Ipv4(Ipv4Record {
                            ip_addr: Cow::Owned(v4.octets().to_vec()),
                            names,
                        })),
                        std::net::IpAddr::V6(v6) => records.push(Record::Ipv6(Ipv6Record {
                            ip_addr: Cow::Owned(v6.octets().to_vec()),
                            names,
                        })),
                    }
                }
                let block = NameResolutionBlock {
                    records,
                    options: vec![NameResolutionOption::Comment(Cow::Borrowed(
                        "name resolution added by sipnab",
                    ))],
                };
                writer
                    .write_pcapng_block(block)
                    .map_err(|e| anyhow::anyhow!("NRB write error: {e}"))?;
                Ok(())
            }
            WriterBackend::Pcap(_) => {
                tracing::warn!("Name Resolution Blocks require PCAP-NG format; skipping");
                Ok(())
            }
        }
    }

    /// Write a DSB from a keylog file, if the export mode requires it.
    ///
    /// Reads the SSLKEYLOGFILE at `keylog_path` and embeds its content as a
    /// Decryption Secrets Block. No-ops if:
    /// - The export mode is `Raw` (no key material should be embedded)
    /// - A DSB has already been written to the current file
    /// - The keylog file cannot be read (logs a warning)
    /// - The backend is standard pcap (DSBs require PCAP-NG)
    pub fn maybe_write_keylog_dsb(&mut self, keylog_path: &Path) -> Result<()> {
        if !self.export_mode.include_dsb() {
            return Ok(());
        }
        if self.dsb_written {
            return Ok(());
        }
        match std::fs::read(keylog_path) {
            Ok(data) if !data.is_empty() => {
                self.write_dsb(&data)?;
                self.dsb_written = true;
                tracing::info!(
                    "Wrote DSB ({} bytes of key material) to '{}'",
                    data.len(),
                    self.base_path.display(),
                );
            }
            Ok(_) => {
                tracing::debug!(
                    "Keylog file '{}' is empty; skipping DSB",
                    keylog_path.display()
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Cannot read keylog '{}' for DSB: {e}",
                    keylog_path.display()
                );
            }
        }
        Ok(())
    }

    /// Write a Decryption Secrets Block (DSB) containing TLS key material.
    ///
    /// The `secrets_data` should be SSLKEYLOGFILE-format content.
    /// Call after IDB, before first EPB. Only works with PCAP-NG backend;
    /// silently skips if using standard pcap format.
    ///
    /// Prefer [`maybe_write_keylog_dsb`](Self::maybe_write_keylog_dsb) which
    /// checks the export mode automatically.
    pub fn write_dsb(&mut self, secrets_data: &[u8]) -> Result<()> {
        match &mut self.backend {
            WriterBackend::PcapNg(writer) => {
                // DSB body: secrets_type (4 LE) + secrets_length (4 LE) + data + padding
                let mut body = Vec::with_capacity(8 + secrets_data.len());
                // TLS Key Log type = 0x544c534b ("TLSK")
                body.extend_from_slice(&0x544c534bu32.to_le_bytes());
                body.extend_from_slice(&(secrets_data.len() as u32).to_le_bytes());
                body.extend_from_slice(secrets_data);
                // Pad to 4-byte boundary
                let pad = (4 - (secrets_data.len() % 4)) % 4;
                body.resize(body.len() + pad, 0);

                use pcap_file::pcapng::blocks::unknown::UnknownBlock;
                let block = UnknownBlock {
                    type_: 0x0000000A, // DSB block type
                    length: (12 + body.len()) as u32,
                    value: Cow::Owned(body),
                };
                writer
                    .write_pcapng_block(block)
                    .map_err(|e| anyhow::anyhow!("DSB write error: {e}"))?;
                Ok(())
            }
            WriterBackend::Pcap(_) => {
                tracing::warn!("DSB blocks require PCAP-NG format; skipping");
                Ok(())
            }
        }
    }

    /// Return the number of bytes written to the current output file.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Flush buffered output to disk, surfacing any deferred write error.
    ///
    /// The PCAP-NG backend buffers through a `BufWriter`, whose `Drop`
    /// flushes but silently DISCARDS errors — without an explicit
    /// `finish()` at end of capture, the tail of the file can be lost
    /// (ENOSPC, revoked permissions, dead NFS mount) with exit code 0
    /// and no operator signal. Call this when capture ends and report
    /// the error.
    pub fn finish(&mut self) -> Result<()> {
        match &mut self.backend {
            WriterBackend::Pcap(savefile) => savefile
                .flush()
                .context("flushing pcap output at end of capture"),
            WriterBackend::PcapNg(writer) => {
                use std::io::Write;
                writer
                    .get_mut()
                    .flush()
                    .context("flushing pcapng output at end of capture")
            }
        }
    }

    /// Force rotation to a new output file.
    ///
    /// Closes the current file and opens a new one with an incremented
    /// sequence number appended to the base filename.
    pub fn rotate(&mut self) -> Result<()> {
        self.sequence += 1;
        let new_path = rotated_path(&self.base_path, self.sequence);

        tracing::info!(
            "Rotating output to '{}' (seq={}, wrote {} bytes in {:?})",
            new_path.display(),
            self.sequence,
            self.bytes_written,
            self.file_opened_at.elapsed(),
        );

        // Drop the old backend (flushes and closes) by replacing it
        self.backend = if self.use_pcapng {
            create_pcapng_backend(
                &new_path,
                self.link_type_raw,
                self.interface_name.as_deref(),
            )?
        } else {
            let linktype = pcap::Linktype(self.link_type_raw);
            WriterBackend::Pcap(create_savefile(&new_path, linktype)?)
        };
        self.bytes_written = 0;
        self.dsb_written = false;
        self.file_opened_at = std::time::Instant::now();

        Ok(())
    }

    /// Check whether any rotation condition is met.
    fn should_rotate(&self) -> bool {
        // SIGUSR1-triggered rotation
        if signals::rotation_requested() {
            tracing::debug!("Rotation triggered by SIGUSR1");
            return true;
        }

        // Size-based rotation
        if let Some(max_bytes) = self.max_file_bytes
            && self.bytes_written >= max_bytes
        {
            tracing::debug!(
                "Rotation triggered by size ({} >= {max_bytes})",
                self.bytes_written,
            );
            return true;
        }

        // Duration-based rotation
        if let Some(max_dur) = self.max_file_duration
            && self.file_opened_at.elapsed() >= max_dur
        {
            tracing::debug!("Rotation triggered by duration ({:?})", max_dur);
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

/// Create a PCAP-NG writer backend at the given path.
/// Producer string embedded in exported pcapng metadata (SHB UserApplication,
/// IDB description), e.g. `"sipnab 0.4.4"`.
fn app_version() -> String {
    format!("sipnab {}", env!("CARGO_PKG_VERSION"))
}

/// Create a PCAP-NG backend whose Section Header and Interface Description
/// blocks carry self-describing metadata (SNB-0001): the producing application
/// and OS in the SHB, and the OS, a human description, and — when known — the
/// capture interface name in the IDB. Without this, `tshark` shows
/// `Interface name: unknown` and `capinfos` reports no application/OS.
fn create_pcapng_backend(
    path: &Path,
    link_type: i32,
    interface: Option<&str>,
) -> Result<WriterBackend> {
    let file = std::fs::File::create(path)
        .with_context(|| format!("Failed to create output file '{}'", path.display()))?;
    let buf_writer = BufWriter::new(file);

    // Section Header Block with producer + OS, so the file is self-describing.
    let section = SectionHeaderBlock {
        endianness: Endianness::native(),
        options: vec![
            SectionHeaderOption::UserApplication(Cow::Owned(app_version())),
            SectionHeaderOption::OS(Cow::Borrowed(std::env::consts::OS)),
        ],
        ..Default::default()
    };
    let mut writer = PcapFileNgWriter::with_section_header(buf_writer, section)
        .map_err(|e| anyhow::anyhow!("Failed to create PCAP-NG writer: {e}"))?;

    // Interface Description Block: OS + description always, interface name when
    // the caller knows it (capture device for live, input source for replay).
    let mut options = vec![
        InterfaceDescriptionOption::IfDescription(Cow::Owned(format!("{} capture", app_version()))),
        InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::env::consts::OS)),
    ];
    if let Some(name) = interface.filter(|n| !n.is_empty()) {
        options.push(InterfaceDescriptionOption::IfName(Cow::Owned(
            name.to_string(),
        )));
    }
    let idb = InterfaceDescriptionBlock {
        linktype: DataLink::from(link_type as u32),
        snaplen: 0xFFFF,
        options,
    };
    writer
        .write_pcapng_block(idb)
        .map_err(|e| anyhow::anyhow!("Failed to write PCAP-NG interface block: {e}"))?;

    Ok(WriterBackend::PcapNg(writer))
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

    /// A Name Resolution Block written into a PCAP-NG capture must survive a
    /// round trip: reading the file back recovers the IP → name mappings. This
    /// is the write half of the name-resolution feature (the read half powers
    /// loading names from a capture on open).
    #[test]
    fn pcapng_name_resolution_block_round_trips() {
        use std::collections::HashMap;
        use std::net::IpAddr;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("names.pcapng");
        let entries: Vec<(IpAddr, Vec<String>)> = vec![
            ("10.0.0.1".parse().unwrap(), vec!["sbc-edge".to_string()]),
            ("2001:db8::1".parse().unwrap(), vec!["core6".to_string()]),
        ];
        {
            let mut w = PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw)
                .expect("create pcapng writer");
            w.write_name_resolution_block(&entries).expect("write NRB");
            w.finish().expect("finish");
        }

        let meta = crate::capture::pcapng_meta::read_pcapng_metadata(&path).expect("read metadata");
        let names: HashMap<IpAddr, String> = meta.names.into_iter().collect();
        assert_eq!(
            names
                .get(&"10.0.0.1".parse::<IpAddr>().unwrap())
                .map(String::as_str),
            Some("sbc-edge")
        );
        assert_eq!(
            names
                .get(&"2001:db8::1".parse::<IpAddr>().unwrap())
                .map(String::as_str),
            Some("core6")
        );
    }

    /// Writing a Name Resolution Block to a plain (non-PCAP-NG) capture is a
    /// no-op, not an error — NRBs only exist in the -ng format.
    #[test]
    fn name_resolution_block_skipped_for_plain_pcap() {
        use std::net::IpAddr;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.pcap");
        let mut w = PcapWriter::with_format(&path, 1, None, None, false, PcapExportMode::Raw)
            .expect("create pcap writer");
        let entries: Vec<(IpAddr, Vec<String>)> =
            vec![("10.0.0.1".parse().unwrap(), vec!["x".to_string()])];
        assert!(w.write_name_resolution_block(&entries).is_ok());
        w.finish().expect("finish");
    }

    /// ENOSPC regression tests using /dev/full, which fails every write
    /// with "No space left on device" without filling a real disk.
    #[cfg(target_os = "linux")]
    mod write_failure {
        use super::*;
        use crate::capture::packet::Packet;

        fn small_packet() -> Packet {
            Packet::new(
                chrono::Utc::now(),
                vec![0u8; 64],
                64,
                64,
                Some("test0".to_string()),
                1, // LINKTYPE_ETHERNET
            )
        }

        /// Sustained writes to a full disk must surface as an Err from
        /// write(), never a panic or silent success forever.
        #[test]
        fn sustained_writes_to_full_disk_error_out() {
            let mut w = PcapWriter::with_format(
                Path::new("/dev/full"),
                1,
                None,
                None,
                true, // pcapng (buffered) — the interesting backend
                PcapExportMode::Raw,
            )
            .expect("open /dev/full (writes are buffered)");

            let pkt = small_packet();
            // BufWriter defaults to 8 KiB; well under 4096 × 64B writes
            // the buffer must spill to the device and hit ENOSPC.
            let failed = (0..4096).any(|_| w.write(&pkt).is_err());
            assert!(failed, "writing 256 KiB to /dev/full must surface an error");
        }

        /// A small tail of packets can sit in the BufWriter when capture
        /// ends; Drop discards flush errors silently. finish() must
        /// surface the deferred failure so the operator learns the file
        /// is incomplete.
        #[test]
        fn finish_surfaces_deferred_flush_error() {
            let mut w = PcapWriter::with_format(
                Path::new("/dev/full"),
                1,
                None,
                None,
                true,
                PcapExportMode::Raw,
            )
            .expect("open /dev/full");

            // One small packet: stays buffered, write() reports Ok.
            let _ = w.write(&small_packet());

            let result = w.finish();
            assert!(
                result.is_err(),
                "finish() must report the deferred ENOSPC, got Ok"
            );
        }
    }

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

    #[test]
    fn dsb_body_format() {
        let keylog = b"CLIENT_RANDOM abcd1234 deadbeef\n";
        let mut body = Vec::new();
        body.extend_from_slice(&0x544c534bu32.to_le_bytes());
        body.extend_from_slice(&(keylog.len() as u32).to_le_bytes());
        body.extend_from_slice(keylog);
        let pad = (4 - (keylog.len() % 4)) % 4;
        body.resize(body.len() + pad, 0);

        // Verify TLS Key Log type
        assert_eq!(&body[0..4], &0x544c534bu32.to_le_bytes());
        // Verify length
        assert_eq!(&body[4..8], &(keylog.len() as u32).to_le_bytes());
        // Verify data
        assert_eq!(&body[8..8 + keylog.len()], keylog);
    }

    #[test]
    fn pcapng_timestamp_nanos_overflow_no_panic() {
        // Verify the nanos conversion used in PcapNg write path handles
        // timestamps where timestamp_nanos_opt() returns None (i64 overflow)
        // or values that don't fit in u64 (negative). The fix uses
        // .and_then(|n| u64::try_from(n).ok()).unwrap_or(0).
        use chrono::DateTime;

        // Year 2554+: timestamp_nanos_opt() returns None because nanoseconds
        // exceed i64::MAX (~292 years from epoch = ~year 2262).
        let far_future = DateTime::from_timestamp(20_000_000_000, 999_999_999)
            .expect("valid far-future timestamp");

        // Replicate the exact conversion from PcapWriter::write
        let nanos: u64 = far_future
            .timestamp_nanos_opt()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0);

        // timestamp_nanos_opt returns None for dates past ~2262, so fallback to 0
        assert_eq!(nanos, 0, "far-future timestamp should fall back to 0 nanos");

        // Also verify a normal timestamp works correctly
        let normal =
            DateTime::from_timestamp(1_700_000_000, 500_000_000).expect("valid normal timestamp");
        let normal_nanos: u64 = normal
            .timestamp_nanos_opt()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0);
        assert_eq!(
            normal_nanos, 1_700_000_000_500_000_000u64,
            "normal timestamp nanos should be exact"
        );

        // Pre-epoch timestamp: nanos would be negative (fails u64::try_from)
        let pre_epoch = DateTime::from_timestamp(-1, 0).expect("valid pre-epoch timestamp");
        let pre_nanos: u64 = pre_epoch
            .timestamp_nanos_opt()
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0);
        assert_eq!(
            pre_nanos, 0,
            "pre-epoch timestamp should fall back to 0 nanos"
        );
    }

    #[test]
    fn pcap_export_mode_parse() {
        assert_eq!(
            PcapExportMode::parse_mode("decrypted"),
            Some(PcapExportMode::Decrypted)
        );
        assert_eq!(PcapExportMode::parse_mode("raw"), Some(PcapExportMode::Raw));
        assert_eq!(
            PcapExportMode::parse_mode("encrypted+dsb"),
            Some(PcapExportMode::EncryptedWithDsb)
        );
        assert_eq!(
            PcapExportMode::parse_mode("bogus"),
            None,
            "Unrecognized mode should return None"
        );
        assert_eq!(
            PcapExportMode::parse_mode(""),
            None,
            "Empty string should return None"
        );
    }

    #[test]
    fn pcap_export_mode_include_dsb() {
        assert!(
            PcapExportMode::Decrypted.include_dsb(),
            "Decrypted mode should include DSB"
        );
        assert!(
            PcapExportMode::EncryptedWithDsb.include_dsb(),
            "EncryptedWithDsb mode should include DSB"
        );
        assert!(
            !PcapExportMode::Raw.include_dsb(),
            "Raw mode should NOT include DSB"
        );
    }

    // ── End-to-end write / read-back / rotate / DSB ─────────────────────
    mod roundtrip {
        use super::*;
        use crate::capture::packet::Packet;

        fn pkt(byte: u8, len: usize) -> Packet {
            Packet::new(chrono::Utc::now(), vec![byte; len], len, len, None, 1)
        }

        #[test]
        fn pcap_write_and_read_back() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.pcap");

            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            assert_eq!(w.export_mode(), PcapExportMode::Decrypted);
            for i in 0..3u8 {
                w.write(&pkt(i, 50)).unwrap();
            }
            assert_eq!(w.bytes_written(), 150);
            w.finish().unwrap();

            // Re-open with libpcap and count the packets back.
            let mut cap = pcap::Capture::from_file(&path).expect("reopen pcap");
            let mut count = 0;
            while cap.next_packet().is_ok() {
                count += 1;
                if count > 10 {
                    break;
                }
            }
            assert_eq!(count, 3, "all three packets should round-trip");
        }

        #[test]
        fn pcapng_write_with_dsb_produces_valid_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.pcapng");
            let keylog = dir.path().join("keys.txt");
            std::fs::write(&keylog, b"CLIENT_RANDOM aabbccdd 00112233\n").unwrap();

            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true, // pcapng
                PcapExportMode::EncryptedWithDsb,
            )
            .unwrap();

            // First call writes the DSB; the second is a no-op (already written).
            w.maybe_write_keylog_dsb(&keylog).unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();

            for i in 0..2u8 {
                w.write(&pkt(i, 40)).unwrap();
            }
            w.finish().unwrap();

            // The PCAP-NG Section Header Block opens with block type 0x0A0D0D0A.
            let bytes = std::fs::read(&path).unwrap();
            assert!(bytes.len() > 28, "file should have content");
            assert_eq!(&bytes[0..4], &0x0A0D0D0Au32.to_le_bytes());
        }

        #[test]
        fn name_resolution_block_round_trips() {
            use pcap_file::pcapng::PcapNgReader;
            use pcap_file::pcapng::blocks::name_resolution::Record;
            use std::net::IpAddr;

            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("names.pcapng");
            let v6: IpAddr = "2001:db8::1".parse().unwrap();
            {
                let mut w =
                    PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw)
                        .unwrap();
                let entries = vec![
                    (IpAddr::from([10, 0, 0, 2]), vec!["sbc-edge".to_string()]),
                    (v6, vec!["v6".to_string(), "v6.example.com".to_string()]),
                ];
                w.write_name_resolution_block(&entries).unwrap();
                w.write(&pkt(0, 40)).unwrap();
                w.finish().unwrap();
            }

            // Read the NRB back and confirm both records survive with names.
            let bytes = std::fs::read(&path).unwrap();
            let mut reader = PcapNgReader::new(&bytes[..]).unwrap();
            let mut v4_names: Vec<String> = Vec::new();
            let mut v6_count = 0;
            while let Some(Ok(block)) = reader.next_block() {
                if let Some(nrb) = block.into_name_resolution() {
                    for rec in &nrb.records {
                        match rec {
                            Record::Ipv4(r) if r.ip_addr.as_ref() == [10, 0, 0, 2] => {
                                v4_names = r.names.iter().map(|n| n.to_string()).collect();
                            }
                            Record::Ipv6(r) => v6_count = r.names.len(),
                            _ => {}
                        }
                    }
                }
            }
            assert_eq!(v4_names, vec!["sbc-edge".to_string()]);
            assert_eq!(v6_count, 2, "IPv6 record should carry both names");
        }

        /// Read back the SHB UserApplication/OS and the first IDB's
        /// IfName/IfDescription/IfOs options (owned), for metadata assertions.
        #[allow(clippy::type_complexity)]
        fn read_export_metadata(
            path: &Path,
        ) -> (
            (Option<String>, Option<String>), // (shb_user_app, shb_os)
            (Option<String>, Option<String>, Option<String>), // (if_name, if_desc, if_os)
        ) {
            use pcap_file::pcapng::PcapNgReader;
            use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;
            use pcap_file::pcapng::blocks::section_header::SectionHeaderOption;

            let bytes = std::fs::read(path).unwrap();
            let mut reader = PcapNgReader::new(&bytes[..]).unwrap();
            let (mut app, mut os) = (None, None);
            // The Section Header Block is parsed in `new()` and exposed here;
            // `next_block()` yields only the blocks that follow it.
            for opt in &reader.section().options {
                match opt {
                    SectionHeaderOption::UserApplication(s) => app = Some(s.to_string()),
                    SectionHeaderOption::OS(s) => os = Some(s.to_string()),
                    _ => {}
                }
            }
            let (mut if_name, mut if_desc, mut if_os) = (None, None, None);
            while let Some(Ok(block)) = reader.next_block() {
                if let Some(idb) = block.into_interface_description() {
                    for opt in &idb.options {
                        match opt {
                            InterfaceDescriptionOption::IfName(s) => if_name = Some(s.to_string()),
                            InterfaceDescriptionOption::IfDescription(s) => {
                                if_desc = Some(s.to_string())
                            }
                            InterfaceDescriptionOption::IfOs(s) => if_os = Some(s.to_string()),
                            _ => {}
                        }
                    }
                }
            }
            ((app, os), (if_name, if_desc, if_os))
        }

        #[test]
        fn pcapng_export_embeds_app_and_os_metadata() {
            // SNB-0001: a headless pcapng export must be self-describing — the SHB
            // carries the producing application + OS, and the IDB an OS + a
            // human description (so capinfos/tshark show real metadata).
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("meta.pcapng");
            {
                let mut w =
                    PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw)
                        .unwrap();
                w.write(&pkt(0, 40)).unwrap();
                w.finish().unwrap();
            }
            let ((app, os), (_if_name, if_desc, if_os)) = read_export_metadata(&path);
            let app = app.expect("SHB UserApplication must be set");
            assert!(app.contains("sipnab"), "app = {app:?}");
            assert!(
                app.contains(env!("CARGO_PKG_VERSION")),
                "app has version: {app:?}"
            );
            assert_eq!(os.as_deref(), Some(std::env::consts::OS), "SHB OS");
            assert_eq!(if_os.as_deref(), Some(std::env::consts::OS), "IDB IfOs");
            let desc = if_desc.expect("IDB IfDescription must be set");
            assert!(desc.contains("sipnab"), "desc = {desc:?}");
        }

        #[test]
        fn pcapng_export_records_interface_name() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("iface.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("eth0"),
                )
                .unwrap();
                w.write(&pkt(0, 40)).unwrap();
                w.finish().unwrap();
            }
            let (_, (if_name, _, _)) = read_export_metadata(&path);
            assert_eq!(if_name.as_deref(), Some("eth0"), "IDB IfName");
        }

        #[test]
        fn pcapng_export_interface_name_special_chars_round_trip() {
            // Adversarial: a device/source name with unicode, spaces, a
            // backslash, and a tab must round-trip verbatim, never truncate.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("weird.pcapng");
            let weird = "réseau 0\\1\tπ";
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some(weird),
                )
                .unwrap();
                w.write(&pkt(0, 40)).unwrap();
                w.finish().unwrap();
            }
            let (_, (if_name, _, _)) = read_export_metadata(&path);
            assert_eq!(if_name.as_deref(), Some(weird));
        }

        #[test]
        fn pcapng_export_empty_interface_records_no_name() {
            // Boundary: an empty interface name records no IfName (avoids an
            // empty, misleading option) but still carries the description/OS.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("emptyiface.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some(""),
                )
                .unwrap();
                w.write(&pkt(0, 40)).unwrap();
                w.finish().unwrap();
            }
            let (_, (if_name, if_desc, _)) = read_export_metadata(&path);
            assert!(
                if_name.is_none(),
                "empty interface → no IfName, got {if_name:?}"
            );
            assert!(if_desc.is_some(), "description still present");
        }

        #[test]
        fn name_resolution_block_empty_is_noop() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("empty.pcapng");
            let mut w =
                PcapWriter::with_format(&path, 1, None, None, true, PcapExportMode::Raw).unwrap();
            // Empty entries must not error and must not write a block.
            w.write_name_resolution_block(&[]).unwrap();
            w.finish().unwrap();
            assert!(path.exists());
        }

        #[test]
        fn size_based_rotation_creates_sequenced_file() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("rot.pcap");

            // Tiny size cap so the third write triggers rotation.
            let mut w = PcapWriter::new(&path, 1, Some(80), None).unwrap();
            for i in 0..5u8 {
                w.write(&pkt(i, 50)).unwrap();
            }
            w.finish().unwrap();

            assert!(
                dir.path().join("rot_00001.pcap").exists(),
                "rotation should create a sequenced file"
            );
        }

        #[test]
        fn explicit_rotate_resets_counters() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("man.pcap");
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            w.write(&pkt(0, 50)).unwrap();
            assert_eq!(w.bytes_written(), 50);
            w.rotate().unwrap();
            assert_eq!(w.bytes_written(), 0, "rotate resets the byte counter");
            assert!(dir.path().join("man_00001.pcap").exists());
        }

        #[test]
        fn write_dsb_on_plain_pcap_is_skipped() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("plain.pcap");
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            // Plain pcap backend can't hold a DSB — must be a benign no-op.
            assert!(w.write_dsb(b"CLIENT_RANDOM a b\n").is_ok());
        }

        #[test]
        fn maybe_write_dsb_handles_raw_empty_and_missing() {
            let dir = tempfile::tempdir().unwrap();

            // Raw mode never embeds key material -> early return.
            let raw_path = dir.path().join("raw.pcapng");
            let mut w =
                PcapWriter::with_format(&raw_path, 1, None, None, true, PcapExportMode::Raw)
                    .unwrap();
            let keylog = dir.path().join("k.txt");
            std::fs::write(&keylog, b"CLIENT_RANDOM a b\n").unwrap();
            w.maybe_write_keylog_dsb(&keylog).unwrap();

            // EncryptedWithDsb but an empty keylog -> the "Ok(empty)" arm.
            let p2 = dir.path().join("e.pcapng");
            let mut w2 =
                PcapWriter::with_format(&p2, 1, None, None, true, PcapExportMode::EncryptedWithDsb)
                    .unwrap();
            let empty = dir.path().join("empty.txt");
            std::fs::write(&empty, b"").unwrap();
            w2.maybe_write_keylog_dsb(&empty).unwrap();

            // ...and a missing keylog path -> the Err arm (logged, still Ok).
            w2.maybe_write_keylog_dsb(dir.path().join("nope.txt").as_path())
                .unwrap();
        }
    }
}
