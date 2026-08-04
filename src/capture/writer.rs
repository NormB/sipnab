// SPDX-License-Identifier: MIT OR Apache-2.0

//! Pcap output writer with rotation support.
//!
//! [`PcapWriter`] writes classic pcap directly (buffered) or PCAP-NG via
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
    /// Standard pcap via the hand-rolled buffered writer.
    Pcap(RawPcapWriter),
    /// PCAP-NG via the `pcap-file` crate.
    PcapNg(PcapFileNgWriter<BufWriter<std::fs::File>>),
}

/// Buffer for the raw classic-pcap writer: large enough that an offline
/// re-emit spills to the kernel thousands of packets at a time.
const RAW_PCAP_BUF_BYTES: usize = 512 * 1024;
/// Snap length recorded in the classic-pcap global header (matches the
/// pcapng backend's IDB snaplen).
const RAW_PCAP_SNAPLEN: u32 = 0xFFFF;

/// Hand-rolled buffered classic-pcap writer.
///
/// Replaces libpcap's `Savefile` on the plain-pcap output path: `Savefile`
/// costs an FFI call plus a locked stdio `fwrite` per packet and silently
/// discards write errors. Classic pcap is a 24-byte global header followed
/// by 16-byte little-endian record headers, so writing it directly through
/// a large `BufWriter` turns the per-packet cost into a bounds-checked
/// memcpy — and write failures surface as errors.
struct RawPcapWriter {
    /// Buffered handle to the destination capture file.
    out: BufWriter<std::fs::File>,
}

impl RawPcapWriter {
    /// Create the file and write the canonical little-endian global header
    /// (magic `d4c3b2a1`, version 2.4, microsecond timestamps).
    fn create(path: &Path, link_type: i32) -> Result<Self> {
        use std::io::Write;
        let file = std::fs::File::create(path)
            .with_context(|| format!("Failed to create output file '{}'", path.display()))?;
        let mut out = BufWriter::with_capacity(RAW_PCAP_BUF_BYTES, file);
        let mut header = [0u8; 24];
        header[0..4].copy_from_slice(&0xA1B2_C3D4u32.to_le_bytes());
        header[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
        header[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
        // thiszone + sigfigs stay zero
        header[16..20].copy_from_slice(&RAW_PCAP_SNAPLEN.to_le_bytes());
        header[20..24].copy_from_slice(&(link_type as u32).to_le_bytes());
        out.write_all(&header)
            .with_context(|| format!("Failed to write pcap header to '{}'", path.display()))?;
        Ok(Self { out })
    }

    /// Append one record: 16-byte LE header (seconds, microseconds,
    /// captured length, original length) followed by the captured bytes.
    /// `incl_len` is always `data.len()` — the record must describe exactly
    /// the bytes that follow it.
    fn write_record(
        &mut self,
        ts_sec: i64,
        ts_usec: u32,
        origlen: usize,
        data: &[u8],
    ) -> Result<()> {
        use std::io::Write;
        let mut rec = [0u8; 16];
        // Classic pcap carries 32-bit timestamps; saturate rather than wrap
        // (matches the format's own 2038 horizon).
        let secs = u32::try_from(ts_sec).unwrap_or(if ts_sec < 0 { 0 } else { u32::MAX });
        rec[0..4].copy_from_slice(&secs.to_le_bytes());
        rec[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        rec[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        let orig = u32::try_from(origlen.max(data.len())).unwrap_or(u32::MAX);
        rec[12..16].copy_from_slice(&orig.to_le_bytes());
        self.out
            .write_all(&rec)
            .context("pcap record header write")?;
        self.out.write_all(data).context("pcap record data write")?;
        Ok(())
    }

    /// Flush buffered records to the file, surfacing any deferred error.
    fn flush(&mut self) -> Result<()> {
        use std::io::Write;
        self.out.flush().context("pcap output flush")
    }
}

/// Pcap output writer with optional file rotation.
///
/// Wraps the raw classic-pcap writer or a PCAP-NG writer and tracks state for rotation decisions.
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
    /// pcapng interface table: index = the `interface_id` stamped on EPBs.
    /// An entry is appended (with an IDB written just before the packet's
    /// own block) the first time a packet arrives from a not-yet-seen
    /// (source name, link type) pair. Carried across rotation so every split
    /// file re-emits the full set of IDBs.
    ///
    /// Starts EMPTY, even when the constructor was told a capture source:
    /// see [`default_source`](Self::default_source).
    interfaces: Vec<InterfaceEntry>,
    /// The capture source the constructor was told about (`--interface`, or
    /// the `-I` argument), used to name the FIRST interface when the first
    /// packet carries no source of its own.
    ///
    /// It is only a fallback because the constructor's idea of the source can
    /// be coarser than the packets': `-I /captures` names a directory, and no
    /// frame was ever captured from a directory. Writing its IDB eagerly made
    /// that guess interface 0 of every export — either a phantom interface
    /// with no packets on it, or (when the guess happened to be one member of
    /// a multi-file set) the name every frame of every OTHER member was
    /// attributed to. Deferring it lets the first packet's own source win.
    default_source: Option<String>,
}

/// One entry of the writer's pcapng interface table (index = interface_id):
/// the source name recorded as the IDB `if_name` option (`None` when the
/// source had no identity to record) and the link type its IDB declares. Devices
/// can report different link types (e.g. `eth0` = Ethernet, `any` = Linux
/// SLL), and so can the members of a multi-file input set, so an entry is
/// identified by BOTH — one IDB declares exactly one link type.
struct InterfaceEntry {
    /// Interface name recorded in the IDB `if_name` option, if known.
    name: Option<String>,
    /// Pcap link-layer type declared by this interface's IDB.
    link_type: i32,
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

        // No IDB yet: the first packet decides what interface 0 is called,
        // falling back to `default_source` only if it carries no source of
        // its own. See the field's documentation.
        let interfaces: Vec<InterfaceEntry> = Vec::new();
        let default_source = interface.filter(|n| !n.is_empty()).map(str::to_string);

        // Classic pcap keeps header bytes out of the `--split` accounting
        // (its 24-byte global header has always been uncounted); pcapng
        // counts the SHB + IDB header bytes so rotation fires at the real
        // file size.
        let (backend, header_bytes) = if pcapng {
            create_pcapng_backend(path, &interfaces)?
        } else {
            (
                WriterBackend::Pcap(RawPcapWriter::create(path, link_type)?),
                0,
            )
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
            bytes_written: header_bytes,
            file_opened_at: std::time::Instant::now(),
            max_file_bytes,
            max_file_duration,
            export_mode,
            dsb_written: false,
            interfaces,
            default_source,
        })
    }

    /// Write a packet to the output file.
    ///
    /// Checks rotation conditions (size, duration, SIGUSR1) before writing.
    /// If rotation is needed, the current file is closed and a new one opened
    /// with an incremented sequence number.
    ///
    /// # Arguments
    ///
    /// * `packet` - the captured packet; its timestamp, captured bytes, and
    ///   original length become the pcap record / EPB.
    ///
    /// # Errors
    ///
    /// Fails when rotation cannot open the new file, the backend write fails
    /// (e.g. disk full), or — on the classic-pcap backend only — the packet's
    /// link type is not the one the file's global header declares. Classic
    /// pcap has a single link type per file, so such a frame cannot be
    /// recorded truthfully; the error names both link types and `--pcapng`,
    /// which can carry them together.
    ///
    /// # Side effects
    ///
    /// Appends to the (buffered) output file, may rotate to a new file, and
    /// advances the `bytes_written` counter by the on-disk record size
    /// (framing + payload, so `--split filesize:N` rotates at the real file
    /// size). On the pcapng backend, the first packet from a not-yet-seen
    /// (interface, link type) pair also appends that interface's IDB (and
    /// counts its bytes) before the packet's EPB.
    pub fn write(&mut self, packet: &Packet) -> Result<()> {
        // Check if rotation is needed before writing
        if self.should_rotate() {
            self.rotate()?;
        }

        match &mut self.backend {
            WriterBackend::Pcap(w) => {
                // A classic pcap file states ONE link type, in its global
                // header, and every reader decodes every record with it.
                // A packet captured on a different link layer cannot be
                // written here truthfully: it would arrive at a carrier, a
                // regulator or a court as bytes that decode cleanly into
                // packets nobody sent. Refuse. `--pcapng` carries the same
                // set faithfully, one interface per link type, so the
                // remedy is named in the error rather than left to be
                // guessed.
                if packet.link_type != self.link_type_raw {
                    anyhow::bail!(
                        "link type mismatch: this frame is {}, but '{}' declares {} in its \
                         header. Classic pcap records one link-layer type for the whole \
                         file, so writing it would present these frames as {}. Re-run with \
                         --pcapng, which records a link type per interface.",
                        describe_link_type(packet.link_type),
                        self.base_path.display(),
                        describe_link_type(self.link_type_raw),
                        describe_link_type(self.link_type_raw),
                    );
                }
                let ts = packet.timestamp;
                w.write_record(
                    ts.timestamp(),
                    ts.timestamp_subsec_micros(),
                    packet.origlen,
                    &packet.data,
                )?;
                // Classic pcap: 16-byte record header + captured bytes.
                self.bytes_written += 16 + packet.data.len() as u64;
            }
            WriterBackend::PcapNg(writer) => {
                // Resolve the packet to its pcapng interface_id, appending an
                // IDB the first time an unseen interface appears (the format
                // allows IDBs interleaved with packet blocks).
                //
                // Interface identity is (name, LINK TYPE), not name alone. An
                // IDB declares exactly one link type and every EPB is decoded
                // with its interface's, so a packet whose link layer differs
                // from an entry's needs an entry of its own — matching on the
                // name alone silently decoded it as the other link type.
                //
                // A packet's source is its OWN name when it has one — the
                // capture device for live, the capture FILE for replay. Two
                // inputs at the same link type are otherwise indistinguishable
                // here, and every frame of the second one was attributed to
                // the first: an export that names the wrong origin with no
                // hint that it is guessing.
                //
                // Packets with no source identity at all (synthetic) belong
                // to any entry whose link type agrees. The table stays tiny
                // (one entry per source/link-type pair), so a linear scan per
                // packet is cheap — the common single-source case matches
                // entry 0.
                let name = packet.interface.as_deref().filter(|n| !n.is_empty());
                let existing = self.interfaces.iter().position(|e| {
                    e.link_type == packet.link_type && (name.is_none() || e.name.as_deref() == name)
                });
                let interface_id = match existing {
                    Some(id) => id as u32,
                    None => {
                        // The constructor-supplied source names the FIRST
                        // interface only, and only when the packet brought no
                        // name of its own. A later entry exists because this
                        // packet's source or link type is genuinely different,
                        // so borrowing the constructor's name for it would
                        // assert an origin nothing established.
                        let idb_name = name.or_else(|| {
                            self.interfaces
                                .is_empty()
                                .then_some(self.default_source.as_deref())
                                .flatten()
                        });
                        let idb = build_idb(packet.link_type, idb_name);
                        let idb_bytes = writer
                            .write_pcapng_block(idb)
                            .map_err(|e| anyhow::anyhow!("PCAP-NG IDB write error: {e}"))?;
                        self.bytes_written += idb_bytes as u64;
                        self.interfaces.push(InterfaceEntry {
                            name: idb_name.map(str::to_string),
                            link_type: packet.link_type,
                        });
                        (self.interfaces.len() - 1) as u32
                    }
                };

                let ts = packet.timestamp;
                // PCAP-NG timestamps are in nanoseconds since epoch
                let nanos: u64 = ts
                    .timestamp_nanos_opt()
                    .and_then(|n| u64::try_from(n).ok())
                    .unwrap_or(0);
                let timestamp = Duration::from_nanos(nanos);

                let epb = EnhancedPacketBlock {
                    interface_id,
                    timestamp,
                    original_len: packet.origlen as u32,
                    data: Cow::Borrowed(&packet.data),
                    options: vec![],
                };

                let epb_bytes = writer
                    .write_pcapng_block(epb)
                    .map_err(|e| anyhow::anyhow!("PCAP-NG write error: {e}"))?;
                self.bytes_written += epb_bytes as u64;
            }
        }

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
    ///
    /// # Side effects
    ///
    /// Reads `keylog_path` from disk, appends a DSB to the output on success,
    /// sets the per-file `dsb_written` latch, and logs the outcome.
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
        // A capture that yielded no packets still has to say what it was a
        // capture OF. Interface 0's IDB is normally written by the first
        // packet (which knows its own source); with no packets at all, the
        // constructor's source is the only thing known, and a section with no
        // IDB would leave the export saying nothing about where it came from.
        self.ensure_pcapng_interface()?;
        match &mut self.backend {
            WriterBackend::Pcap(w) => w.flush().context("flushing pcap output at end of capture"),
            WriterBackend::PcapNg(writer) => {
                use std::io::Write;
                writer
                    .get_mut()
                    .flush()
                    .context("flushing pcapng output at end of capture")
            }
        }
    }

    /// Write interface 0's IDB from the constructor-supplied source if no
    /// packet has established one yet. No-op for classic pcap and for a
    /// pcapng file that already has an interface.
    ///
    /// The IDB is written even when no source name is known, because a
    /// pcapng section with no Interface Description Block at all is not
    /// merely uninformative: libpcap refuses to open it ("the capture file
    /// has no Interface Description Blocks"), so an export that happened to
    /// contain no packets would be unreadable by sipnab itself, by tcpdump,
    /// and by every other libpcap consumer.
    fn ensure_pcapng_interface(&mut self) -> Result<()> {
        let WriterBackend::PcapNg(writer) = &mut self.backend else {
            return Ok(());
        };
        if !self.interfaces.is_empty() {
            return Ok(());
        }
        let name = self.default_source.as_deref();
        let idb_bytes = writer
            .write_pcapng_block(build_idb(self.link_type_raw, name))
            .map_err(|e| anyhow::anyhow!("PCAP-NG IDB write error: {e}"))?;
        self.bytes_written += idb_bytes as u64;
        self.interfaces.push(InterfaceEntry {
            name: name.map(str::to_string),
            link_type: self.link_type_raw,
        });
        Ok(())
    }

    /// Force rotation to a new output file.
    ///
    /// Closes the current file and opens a new one with an incremented
    /// sequence number appended to the base filename. A pcapng rotation
    /// re-emits the SHB plus IDBs for every interface seen so far (in the
    /// same id order), so each split file is self-contained.
    ///
    /// # Errors
    ///
    /// Fails when the new sequenced file cannot be created.
    ///
    /// # Side effects
    ///
    /// Drops the old backend (flushing and closing its file), creates the new
    /// file, resets `bytes_written` (to the new file's SHB+IDB header size for
    /// pcapng, 0 for classic pcap), resets `dsb_written`/`file_opened_at`, and
    /// logs the rotation at info level.
    pub fn rotate(&mut self) -> Result<()> {
        // The file about to be closed must be readable on its own, and a
        // pcapng section with no IDB is not — see
        // [`ensure_pcapng_interface`](Self::ensure_pcapng_interface). Only
        // reachable when rotation fires before the first packet (a duration
        // split, or SIGUSR1 on an idle capture).
        self.ensure_pcapng_interface()?;

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
        let (backend, header_bytes) = if self.use_pcapng {
            create_pcapng_backend(&new_path, &self.interfaces)?
        } else {
            (
                WriterBackend::Pcap(RawPcapWriter::create(&new_path, self.link_type_raw)?),
                0,
            )
        };
        self.backend = backend;
        self.bytes_written = header_bytes;
        self.dsb_written = false;
        self.file_opened_at = std::time::Instant::now();

        Ok(())
    }

    /// Check whether any rotation condition is met: a pending SIGUSR1
    /// request, the size cap, or the duration cap. Returns `true` if the next
    /// write should go to a fresh file.
    ///
    /// # Side effects
    ///
    /// Reading the SIGUSR1 flag consumes the pending rotation request (the
    /// signal module's check-and-clear); logs the trigger at debug level.
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

/// Producer string embedded in exported pcapng metadata (SHB UserApplication,
/// IDB description), e.g. `"sipnab 0.4.4"`.
fn app_version() -> String {
    format!("sipnab {}", env!("CARGO_PKG_VERSION"))
}

/// Create a PCAP-NG backend whose Section Header and Interface Description
/// blocks carry self-describing metadata (SNB-0001): the producing application
/// and OS in the SHB, and the OS, a human description, and — when known — the
/// capture interface name in each IDB. Without this, `tshark` shows
/// `Interface name: unknown` and `capinfos` reports no application/OS.
///
/// Writes one IDB per entry of `interfaces` in table order, so the block
/// order matches the `interface_id`s the writer stamps on EPBs (a rotated
/// file re-emits every interface seen so far and stays self-contained).
/// Returns the backend plus the on-disk SHB+IDB header size, which counts
/// toward `--split filesize:N` accounting.
fn create_pcapng_backend(
    path: &Path,
    interfaces: &[InterfaceEntry],
) -> Result<(WriterBackend, u64)> {
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

    // Measure the SHB's serialized size by writing the same section into a
    // throwaway Vec (the crate's constructor doesn't report it, and flushing
    // the real BufWriter to seek would defeat its buffering).
    let shb_bytes = PcapFileNgWriter::with_section_header(Vec::new(), section.clone())
        .map_err(|e| anyhow::anyhow!("Failed to measure PCAP-NG section header: {e}"))?
        .into_inner()
        .len() as u64;

    let mut writer = PcapFileNgWriter::with_section_header(buf_writer, section)
        .map_err(|e| anyhow::anyhow!("Failed to create PCAP-NG writer: {e}"))?;

    let mut header_bytes = shb_bytes;
    for entry in interfaces {
        let idb = build_idb(entry.link_type, entry.name.as_deref());
        let idb_bytes = writer
            .write_pcapng_block(idb)
            .map_err(|e| anyhow::anyhow!("Failed to write PCAP-NG interface block: {e}"))?;
        header_bytes += idb_bytes as u64;
    }

    Ok((WriterBackend::PcapNg(writer), header_bytes))
}

/// Build an Interface Description Block carrying self-describing metadata:
/// a human description and the OS always, nanosecond timestamp resolution,
/// and the interface name when known (capture device for live, input source
/// for replay).
fn build_idb(link_type: i32, name: Option<&str>) -> InterfaceDescriptionBlock<'static> {
    let mut options = vec![
        InterfaceDescriptionOption::IfDescription(Cow::Owned(format!("{} capture", app_version()))),
        InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::env::consts::OS)),
        // pcap-file always encodes EPB timestamps as NANOSECOND ticks
        // (Duration::as_nanos), so the interface must declare 10^-9 —
        // without this, readers assume the pcapng default of microseconds
        // and every timestamp is inflated ×1000 (the "year 58484" files).
        InterfaceDescriptionOption::IfTsResol(9),
    ];
    if let Some(name) = name.filter(|n| !n.is_empty()) {
        options.push(InterfaceDescriptionOption::IfName(Cow::Owned(
            name.to_string(),
        )));
    }
    InterfaceDescriptionBlock {
        linktype: DataLink::from(link_type as u32),
        snaplen: 0xFFFF,
        options,
    }
}

/// Name a pcap link-layer type for an error an operator has to act on.
///
/// The number alone ("1" vs "113") says nothing to someone holding two
/// captures and wondering which one disagrees, so every link type sipnab
/// decodes is named; anything else is reported as its bare DLT value, which
/// is still what `capinfos` and Wireshark will show.
///
/// DLT 0 and DLT 108 are named separately rather than sharing a "loopback"
/// label: they differ in exactly one way that matters when two captures
/// disagree — DLT 0's address family is in host byte order and DLT 108's is
/// always big-endian — so collapsing them would hide the one detail an
/// operator comparing a Linux capture against a BSD one needs to see.
fn describe_link_type(link_type: i32) -> String {
    match link_type {
        0 => "NULL/loopback (DLT 0)".to_string(),
        1 => "Ethernet (DLT 1)".to_string(),
        12 => "raw IP (DLT 12)".to_string(),
        108 => "OpenBSD loopback (DLT 108)".to_string(),
        113 => "Linux SLL (DLT 113)".to_string(),
        276 => "Linux SLL2 (DLT 276)".to_string(),
        other => format!("DLT {other}"),
    }
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

/// Tests for the pcap/pcapng writer: NRB/DSB blocks, rotation, split parsing,
/// timestamp fidelity, and write-failure surfacing.
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

        /// Build a 64-byte zero-filled Ethernet packet stamped "now".
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

    /// Field-capture regression: pcapng files written by sipnab carried
    /// NANOSECOND timestamp ticks while the IDB declared (by omission)
    /// MICROSECOND resolution — every reader (sipnab, capinfos, wireshark)
    /// saw all times ×1000: a real 42 ms PDD displayed as 41972 ms and a
    /// ~3-minute capture spanned "46 hours" (year 58484). A write→read
    /// round trip through sipnab's own reader must preserve timestamps.
    #[test]
    fn pcapng_roundtrip_preserves_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roundtrip.pcapng");
        // The real capture's first packet time: 2026-07-07 12:42:46.117182 UTC
        let ts0 = chrono::DateTime::from_timestamp(1_783_428_166, 117_182_000).unwrap();
        let ts1 = ts0 + chrono::TimeDelta::milliseconds(1_500); // +1.5 s
        {
            let mut w = PcapWriter::with_format(
                &path,
                1,
                None,
                None,
                true, // pcapng
                PcapExportMode::Raw,
            )
            .unwrap();
            for ts in [ts0, ts1] {
                w.write(&Packet::new(ts, vec![0u8; 64], 64, 64, None, 1))
                    .unwrap();
            }
            w.finish().unwrap();
        }

        let data = std::fs::read(&path).unwrap();
        let reader = crate::capture::pcap_reader::PcapReader::new(&data).unwrap();
        let pkts: Vec<_> = reader.collect();
        assert_eq!(pkts.len(), 2);
        for (pkt, want) in pkts.iter().zip([ts0, ts1]) {
            let got = chrono::DateTime::from_timestamp(
                pkt.timestamp_secs as i64,
                pkt.timestamp_usecs * 1000,
            )
            .unwrap();
            assert_eq!(
                got, want,
                "round-tripped timestamp must equal the written one \
                 (ns ticks require if_tsresol=9 in the IDB)"
            );
        }
    }

    /// `output.pcap` + sequence N yields `output_0000N.pcap`.
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

    /// A base path without an extension gets the default `.pcap` appended.
    #[test]
    fn rotated_path_no_extension() {
        let base = PathBuf::from("/tmp/capture");
        // When there's no extension, file_stem is "capture" and extension defaults to "pcap"
        assert_eq!(
            rotated_path(&base, 3),
            PathBuf::from("/tmp/capture_00003.pcap")
        );
    }

    /// `filesize:50` parses as a 50 MB size cap and no duration cap.
    #[test]
    fn parse_split_filesize() {
        let (bytes, dur) = parse_split("filesize:50").unwrap();
        assert_eq!(bytes, Some(50_000_000));
        assert!(dur.is_none());
    }

    /// `duration:300` parses as a 300-second cap and no size cap.
    #[test]
    fn parse_split_duration() {
        let (bytes, dur) = parse_split("duration:300").unwrap();
        assert!(bytes.is_none());
        assert_eq!(dur, Some(std::time::Duration::from_secs(300)));
    }

    /// Unknown keys, missing values, and non-numeric values are errors.
    #[test]
    fn parse_split_invalid() {
        assert!(parse_split("bogus:5").is_err());
        assert!(parse_split("filesize").is_err());
        assert!(parse_split("filesize:abc").is_err());
    }

    /// The DSB body layout is `TLSK` type, LE length, data, zero padding.
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

    /// The nanosecond conversion in the pcapng write path falls back to 0
    /// for far-future (i64 overflow) and pre-epoch timestamps, no panic.
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

    /// `parse_mode` maps the three CLI strings; anything else yields `None`.
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

    /// Only `Raw` mode excludes DSB blocks from the output.
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
    /// End-to-end tests: write files, read them back, rotate, and embed
    /// metadata/DSB blocks.
    mod roundtrip {
        use super::*;
        use crate::capture::packet::Packet;

        /// Build a `len`-byte packet filled with `byte`, stamped "now".
        fn pkt(byte: u8, len: usize) -> Packet {
            Packet::new(chrono::Utc::now(), vec![byte; len], len, len, None, 1)
        }

        /// Three packets written as plain pcap read back via libpcap, and the
        /// byte counter matches.
        #[test]
        fn pcap_write_and_read_back() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("out.pcap");

            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            assert_eq!(w.export_mode(), PcapExportMode::Decrypted);
            for i in 0..3u8 {
                w.write(&pkt(i, 50)).unwrap();
            }
            // Each classic-pcap record is a 16-byte header plus the 50-byte
            // payload, so --split accounting must see 3 * 66 = 198, not the
            // payload-only 150.
            assert_eq!(w.bytes_written(), 198);
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

        /// Writing a DSB (once — the second call is a no-op) plus packets
        /// produces a file opening with the pcapng SHB magic.
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

        /// IPv4 and IPv6 NRB records (with multiple names) survive a write
        /// and read back through the `pcap-file` reader.
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
        #[expect(clippy::type_complexity)]
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

        /// SNB-0001: the SHB carries app+OS and the IDB carries OS plus a
        /// description, so a headless export is self-describing.
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

        /// `with_interface(..., Some("eth0"))` records IfName in the IDB.
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

        /// An interface name with unicode, spaces, backslash, and tab
        /// round-trips verbatim through the IDB IfName option.
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

        /// An empty interface name records no IfName option while keeping the
        /// description and OS options.
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

        /// An empty NRB entry list writes nothing and returns `Ok`.
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

        /// Exceeding a tiny size cap mid-run creates the `_00001` sequenced
        /// rotation file.
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

        /// A manual `rotate()` zeroes the byte counter and opens the
        /// sequenced file.
        #[test]
        fn explicit_rotate_resets_counters() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("man.pcap");
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            w.write(&pkt(0, 50)).unwrap();
            // 16-byte pcap record header + 50-byte payload.
            assert_eq!(w.bytes_written(), 66);
            w.rotate().unwrap();
            assert_eq!(w.bytes_written(), 0, "rotate resets the byte counter");
            assert!(dir.path().join("man_00001.pcap").exists());
        }

        /// `write_dsb` on a plain-pcap backend is a benign no-op.
        #[test]
        fn write_dsb_on_plain_pcap_is_skipped() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("plain.pcap");
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            // Plain pcap backend can't hold a DSB — must be a benign no-op.
            assert!(w.write_dsb(b"CLIENT_RANDOM a b\n").is_ok());
        }

        /// `maybe_write_keylog_dsb` no-ops cleanly for Raw mode, an empty
        /// keylog, and a missing keylog path.
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

        // ── Multi-interface pcapng (one IDB per source interface) ───────

        /// A parsed pcapng block reduced to what the multi-interface tests
        /// assert on: IDBs (name + link type) and EPBs (interface_id).
        #[derive(Debug, PartialEq, Eq)]
        enum NgBlock {
            /// Interface Description Block: `if_name` option and link type.
            Idb {
                /// The `if_name` option, if present.
                name: Option<String>,
                /// The declared link-layer type.
                linktype: u32,
            },
            /// Enhanced Packet Block: the interface it references.
            Epb {
                /// The `interface_id` field.
                interface_id: u32,
            },
        }

        /// Parse a written pcapng file into the ordered IDB/EPB sequence
        /// (other block types are skipped).
        fn read_ng_blocks(path: &Path) -> Vec<NgBlock> {
            use pcap_file::pcapng::PcapNgReader;
            use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;

            let bytes = std::fs::read(path).unwrap();
            let mut reader = PcapNgReader::new(&bytes[..]).unwrap();
            let mut blocks = Vec::new();
            while let Some(block) = reader.next_block() {
                let block = block.expect("valid pcapng block");
                if let Some(idb) = block.clone().into_interface_description() {
                    let name = idb.options.iter().find_map(|o| match o {
                        InterfaceDescriptionOption::IfName(s) => Some(s.to_string()),
                        _ => None,
                    });
                    blocks.push(NgBlock::Idb {
                        name,
                        linktype: u32::from(idb.linktype),
                    });
                } else if let Some(epb) = block.into_enhanced_packet() {
                    blocks.push(NgBlock::Epb {
                        interface_id: epb.interface_id,
                    });
                }
            }
            blocks
        }

        /// Build a `len`-byte packet tagged with a source `interface` name
        /// and link type, stamped "now".
        fn pkt_on(interface: &str, link_type: i32, len: usize) -> Packet {
            Packet::new(
                chrono::Utc::now(),
                vec![0u8; len],
                len,
                len,
                Some(interface.to_string()),
                link_type,
            )
        }

        /// Interleaved packets from two capture interfaces must produce two
        /// IDBs (in first-appearance order, each carrying its own if_name
        /// and link type) and EPBs that reference the correct interface_id —
        /// not a single IDB with every EPB stamped 0.
        #[test]
        fn pcapng_multi_interface_writes_idb_per_interface_with_correct_epb_ids() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("multi.pcapng");
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
                // eth1 uses LINKTYPE_LINUX_SLL (113) to prove the mid-stream
                // IDB records the tagging packet's link type, not the
                // writer-global one.
                w.write(&pkt_on("eth0", 1, 40)).unwrap();
                w.write(&pkt_on("eth1", 113, 40)).unwrap();
                w.write(&pkt_on("eth0", 1, 40)).unwrap();
                w.write(&pkt_on("eth1", 113, 40)).unwrap();
                w.finish().unwrap();
            }

            let blocks = read_ng_blocks(&path);
            let idbs: Vec<_> = blocks
                .iter()
                .filter_map(|b| match b {
                    NgBlock::Idb { name, linktype } => Some((name.clone(), *linktype)),
                    _ => None,
                })
                .collect();
            assert_eq!(
                idbs,
                vec![
                    (Some("eth0".to_string()), 1),
                    (Some("eth1".to_string()), 113),
                ],
                "one IDB per interface, in first-appearance order"
            );
            let epb_ids: Vec<_> = blocks
                .iter()
                .filter_map(|b| match b {
                    NgBlock::Epb { interface_id } => Some(*interface_id),
                    _ => None,
                })
                .collect();
            assert_eq!(
                epb_ids,
                vec![0, 1, 0, 1],
                "each EPB references its own interface's id"
            );
        }

        /// pcapng allows IDBs interleaved with packet blocks: when a new
        /// interface first appears mid-stream, its IDB must be written
        /// before that packet's EPB — and the EPBs already written stay
        /// untouched on interface 0.
        #[test]
        fn pcapng_new_interface_idb_written_before_its_first_epb() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("midstream.pcapng");
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
                w.write(&pkt_on("eth0", 1, 40)).unwrap();
                w.write(&pkt_on("eth0", 1, 40)).unwrap();
                w.write(&pkt_on("eth1", 1, 40)).unwrap();
                w.finish().unwrap();
            }

            assert_eq!(
                read_ng_blocks(&path),
                vec![
                    NgBlock::Idb {
                        name: Some("eth0".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 0 },
                    NgBlock::Epb { interface_id: 0 },
                    NgBlock::Idb {
                        name: Some("eth1".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 1 },
                ],
                "eth1's IDB appears mid-stream, before its first EPB"
            );
        }

        /// Build a `len`-byte packet with NO source interface name (file
        /// replay, synthetic) on the given link type, stamped "now".
        fn pkt_unnamed(link_type: i32, len: usize) -> Packet {
            Packet::new(
                chrono::Utc::now(),
                vec![0u8; len],
                len,
                len,
                None,
                link_type,
            )
        }

        /// Classic pcap states ONE link type for the whole file, so a frame
        /// captured on a different link layer must be refused, not written.
        ///
        /// Writing it produces a file that opens cleanly and decodes every
        /// such frame with the wrong link layer — the failure mode is a
        /// plausible-looking capture of packets nobody sent, which is worse
        /// than no capture at all. The error has to name both link types and
        /// the format that can carry them.
        #[test]
        fn plain_pcap_refuses_a_foreign_link_type() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("mixed.pcap");
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();

            // The declared link type is written without complaint.
            w.write(&pkt_unnamed(1, 60)).unwrap();
            let after_first = w.bytes_written();

            // A Linux SLL2 frame is not an Ethernet frame.
            let err = w
                .write(&pkt_unnamed(276, 60))
                .expect_err("a foreign link type must be refused");
            let msg = err.to_string();
            assert!(
                msg.contains("276") && msg.contains("Ethernet"),
                "the error must name both link types: {msg}"
            );
            assert!(
                msg.contains("--pcapng"),
                "the error must name the format that can carry both: {msg}"
            );
            assert_eq!(
                w.bytes_written(),
                after_first,
                "the refused frame must not reach the file"
            );
        }

        /// A pcapng interface is identified by (name, link type), not name
        /// alone: sources with no name at all — a multi-file input set, whose
        /// packets carry a per-file link type and no interface — still get one
        /// IDB per link type, and each EPB references the interface whose link
        /// type decodes it.
        ///
        /// Keyed on name alone, every unnamed packet landed on interface 0 and
        /// was decoded as the FIRST file's link layer.
        #[test]
        fn pcapng_unnamed_sources_get_an_interface_per_link_type() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("unnamed.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    113,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("first.pcap"),
                )
                .unwrap();
                w.write(&pkt_unnamed(113, 40)).unwrap();
                w.write(&pkt_unnamed(1, 40)).unwrap();
                w.write(&pkt_unnamed(113, 40)).unwrap();
                w.write(&pkt_unnamed(1, 40)).unwrap();
                w.finish().unwrap();
            }

            let blocks = read_ng_blocks(&path);
            let linktypes: Vec<_> = blocks
                .iter()
                .filter_map(|b| match b {
                    NgBlock::Idb { linktype, .. } => Some(*linktype),
                    _ => None,
                })
                .collect();
            assert_eq!(
                linktypes,
                vec![113, 1],
                "one IDB per link type, in first-appearance order"
            );
            let epb_ids: Vec<_> = blocks
                .iter()
                .filter_map(|b| match b {
                    NgBlock::Epb { interface_id } => Some(*interface_id),
                    _ => None,
                })
                .collect();
            assert_eq!(
                epb_ids,
                vec![0, 1, 0, 1],
                "each frame references the interface whose link type decodes it"
            );
        }

        /// One named interface that changes link type mid-capture (a device
        /// re-opened as `any`, a bonded link) gets a second IDB under the same
        /// name rather than having its frames decoded as the old link layer.
        #[test]
        fn pcapng_same_interface_new_link_type_gets_its_own_idb() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("relink.pcapng");
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
                w.write(&pkt_on("eth0", 1, 40)).unwrap();
                w.write(&pkt_on("eth0", 113, 40)).unwrap();
                w.finish().unwrap();
            }

            assert_eq!(
                read_ng_blocks(&path),
                vec![
                    NgBlock::Idb {
                        name: Some("eth0".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 0 },
                    NgBlock::Idb {
                        name: Some("eth0".to_string()),
                        linktype: 113,
                    },
                    NgBlock::Epb { interface_id: 1 },
                ],
                "same name, new link type => its own interface"
            );
        }

        /// Two sources at the SAME link type get one IDB each, and every EPB
        /// references the source it actually came from.
        ///
        /// The link-type rule alone separates inputs captured on different
        /// link layers. Two ordinary Ethernet captures collapsed onto the
        /// constructor's interface 0, so the export named `a.pcap` as the
        /// origin of every frame read out of `b.pcap` — a claim the file
        /// makes with no hint that it is a guess.
        #[test]
        fn pcapng_two_sources_same_link_type_get_their_own_idbs() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("twofiles.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("a.pcap"),
                )
                .unwrap();
                w.write(&pkt_on("a.pcap", 1, 40)).unwrap();
                w.write(&pkt_on("b.pcap", 1, 40)).unwrap();
                w.write(&pkt_on("a.pcap", 1, 40)).unwrap();
                w.write(&pkt_on("b.pcap", 1, 40)).unwrap();
                w.finish().unwrap();
            }

            assert_eq!(
                read_ng_blocks(&path),
                vec![
                    NgBlock::Idb {
                        name: Some("a.pcap".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 0 },
                    NgBlock::Idb {
                        name: Some("b.pcap".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 1 },
                    NgBlock::Epb { interface_id: 0 },
                    NgBlock::Epb { interface_id: 1 },
                ],
                "same link type, different source file => its own interface"
            );
        }

        /// The first packet's own source names interface 0, even when the
        /// constructor was told something else.
        ///
        /// `-I /captures` hands the writer a DIRECTORY as its capture source,
        /// and no frame was ever captured from a directory. Writing that guess
        /// as interface 0 up front left a phantom interface with no packets on
        /// it in every directory export.
        #[test]
        fn pcapng_first_packet_source_names_interface_zero() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("dirsource.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("/captures"),
                )
                .unwrap();
                w.write(&pkt_on("/captures/a.pcap", 1, 40)).unwrap();
                w.finish().unwrap();
            }

            assert_eq!(
                read_ng_blocks(&path),
                vec![
                    NgBlock::Idb {
                        name: Some("/captures/a.pcap".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Epb { interface_id: 0 },
                ],
                "the file the frame came from names interface 0, not the -I directory"
            );
        }

        /// The constructor's source names interface 0 only. A second entry
        /// exists because that packet's source or link type is genuinely
        /// different, so it must not borrow the constructor's name.
        #[test]
        fn pcapng_later_interface_does_not_borrow_the_constructor_source() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("noborrow.pcapng");
            {
                let mut w = PcapWriter::with_interface(
                    &path,
                    113,
                    None,
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("first.pcap"),
                )
                .unwrap();
                // Unnamed sources: the first takes the constructor's name,
                // the second (a different link layer) has no established
                // origin and must be recorded as having none.
                w.write(&pkt_unnamed(113, 40)).unwrap();
                w.write(&pkt_unnamed(1, 40)).unwrap();
                w.finish().unwrap();
            }

            let names: Vec<_> = read_ng_blocks(&path)
                .into_iter()
                .filter_map(|b| match b {
                    NgBlock::Idb { name, .. } => Some(name),
                    NgBlock::Epb { .. } => None,
                })
                .collect();
            assert_eq!(
                names,
                vec![Some("first.pcap".to_string()), None],
                "only interface 0 may be named by the constructor's source"
            );
        }

        /// A capture that yielded no packets still records what it was a
        /// capture OF: `finish()` writes interface 0's IDB from the
        /// constructor's source rather than leaving a section that says
        /// nothing about its origin.
        #[test]
        fn pcapng_empty_capture_still_declares_its_source() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("nopackets.pcapng");
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
                w.finish().unwrap();
            }

            assert_eq!(
                read_ng_blocks(&path),
                vec![NgBlock::Idb {
                    name: Some("eth0".to_string()),
                    linktype: 1,
                }],
                "an empty export still names its capture source"
            );
        }

        /// `--split filesize:N` with two interfaces: every rotated file must
        /// be self-contained — it re-opens with an SHB plus IDBs for ALL
        /// interfaces seen so far (same id order), and its EPBs reference
        /// the correct ids.
        #[test]
        fn split_rotation_reemits_shb_and_all_interface_idbs() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("rot.pcapng");
            {
                // ~800-byte cap: headers + first eth0 EPB stay well under it,
                // so both interfaces are registered before the first rotation.
                let mut w = PcapWriter::with_interface(
                    &path,
                    1,
                    Some(800),
                    None,
                    true,
                    PcapExportMode::Raw,
                    Some("eth0"),
                )
                .unwrap();
                for _ in 0..20 {
                    w.write(&pkt_on("eth0", 1, 200)).unwrap();
                    w.write(&pkt_on("eth1", 1, 200)).unwrap();
                }
                w.finish().unwrap();
            }

            let rot = dir.path().join("rot_00001.pcapng");
            assert!(rot.exists(), "size cap must trigger rotation");
            let blocks = read_ng_blocks(&rot);
            assert_eq!(
                &blocks[..2],
                &[
                    NgBlock::Idb {
                        name: Some("eth0".to_string()),
                        linktype: 1,
                    },
                    NgBlock::Idb {
                        name: Some("eth1".to_string()),
                        linktype: 1,
                    },
                ],
                "rotated file re-emits IDBs for all seen interfaces before any EPB"
            );
            let epb_ids: Vec<_> = blocks
                .iter()
                .filter_map(|b| match b {
                    NgBlock::Epb { interface_id } => Some(*interface_id),
                    _ => None,
                })
                .collect();
            assert!(!epb_ids.is_empty(), "rotated file carries packets");
            assert!(
                epb_ids.contains(&1),
                "rotated file's eth1 EPBs reference id 1: {epb_ids:?}"
            );
            assert!(
                epb_ids.iter().all(|&id| id <= 1),
                "no EPB references an unknown interface: {epb_ids:?}"
            );
        }

        /// pcapng size accounting must count the SHB + IDB header bytes
        /// (extending the record-framing fix): `bytes_written` equals the
        /// real on-disk file size both before and after rotation.
        #[test]
        fn pcapng_size_accounting_includes_shb_and_idb_bytes() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("acct.pcapng");
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
            // Registers eth1 → a second IDB in the first file.
            w.write(&pkt_on("eth1", 1, 40)).unwrap();
            let first_file_bytes = w.bytes_written();

            // rotate() drops (flushes) the first backend, so its on-disk
            // size is final and must equal the accounted bytes.
            w.rotate().unwrap();
            assert_eq!(
                first_file_bytes,
                std::fs::metadata(&path).unwrap().len(),
                "first file: bytes_written == on-disk size (SHB+IDBs+EPB)"
            );
            assert!(
                w.bytes_written() > 0,
                "after rotation the re-emitted SHB+IDB bytes count toward the cap"
            );

            w.write(&pkt_on("eth1", 1, 40)).unwrap();
            let rot_bytes = w.bytes_written();
            w.finish().unwrap();
            let rot = dir.path().join("acct_00001.pcapng");
            assert_eq!(
                rot_bytes,
                std::fs::metadata(&rot).unwrap().len(),
                "rotated file: bytes_written == on-disk size"
            );
        }
    }
}

/// Tests for the hand-rolled `RawPcapWriter`: canonical header bytes,
/// round-trip fidelity, and non-silent write errors.
#[cfg(test)]
mod raw_pcap_writer_tests {
    use super::*;
    use crate::capture::packet::Packet;
    use crate::capture::pcap_reader::PcapReader;

    /// Build an Ethernet packet with the given timestamp (`secs`/`usecs`),
    /// payload `data`, and original length `origlen`.
    fn pkt_at(secs: i64, usecs: u32, data: Vec<u8>, origlen: usize) -> Packet {
        let caplen = data.len();
        let ts = chrono::DateTime::from_timestamp(secs, usecs * 1000).unwrap();
        Packet::new(ts, data, caplen, origlen, None, 1)
    }

    /// The hand-rolled writer must emit the canonical little-endian classic
    /// pcap global header: magic d4c3b2a1, version 2.4, zone/sigfigs 0,
    /// snaplen 0xFFFF (matching the pcapng backend's convention), then the
    /// link type.
    #[test]
    fn raw_pcap_header_is_canonical_le() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hdr.pcap");
        {
            let mut w = RawPcapWriter::create(&path, 1).unwrap();
            w.flush().unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes.len(), 24, "header only");
        assert_eq!(&bytes[0..4], &[0xd4, 0xc3, 0xb2, 0xa1], "LE usec magic");
        assert_eq!(&bytes[4..8], &[2, 0, 4, 0], "version 2.4");
        assert_eq!(&bytes[8..16], &[0u8; 8], "thiszone + sigfigs zero");
        assert_eq!(
            u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            0xFFFF,
            "snaplen"
        );
        assert_eq!(
            u32::from_le_bytes(bytes[20..24].try_into().unwrap()),
            1,
            "linktype ethernet"
        );
    }

    /// Everything written through the plain-pcap PcapWriter (which the raw
    /// writer now backs) must round-trip byte-for-byte through PcapReader —
    /// including the adversarial shapes: an empty-payload packet, a
    /// truncated packet (origlen > caplen), and sub-second timestamps.
    #[test]
    fn plain_pcap_round_trips_edge_shapes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.pcap");

        let packets = vec![
            pkt_at(1_700_000_000, 0, vec![0xAA; 60], 60),
            pkt_at(1_700_000_001, 999_999, vec![], 0),
            pkt_at(1_700_000_002, 123_456, vec![0x55; 40], 1500), // truncated
            pkt_at(0, 1, vec![0x01], 1),                          // epoch + 1µs
        ];

        {
            let mut w = PcapWriter::new(&path, 1, None, None).unwrap();
            for p in &packets {
                w.write(p).unwrap();
            }
            w.finish().unwrap();
        }

        let bytes = std::fs::read(&path).unwrap();
        let rd: Vec<_> = PcapReader::new(&bytes).unwrap().collect();
        assert_eq!(rd.len(), packets.len());
        for (got, want) in rd.iter().zip(&packets) {
            assert_eq!(&got.data[..], &want.data[..], "payload bytes");
            assert_eq!(got.orig_len as usize, want.origlen, "original length");
            assert_eq!(i64::from(got.timestamp_secs), want.timestamp.timestamp());
            assert_eq!(
                got.timestamp_usecs,
                want.timestamp.timestamp_subsec_micros(),
                "microsecond timestamp fidelity"
            );
        }
    }

    /// Writes to a full device must surface an Err from the raw writer
    /// (libpcap's Savefile::write silently returned unit). Buffered records
    /// may succeed until the buffer spills; at the latest, flush must fail.
    #[cfg(target_os = "linux")]
    #[test]
    fn raw_writer_write_errors_are_not_silent() {
        let mut w = RawPcapWriter::create(Path::new("/dev/full"), 1).unwrap();
        let mut result = Ok(());
        for _ in 0..10_000 {
            if let Err(e) = w.write_record(1, 0, 0xFFFF_usize, &[0u8; 4096][..]) {
                result = Err(e);
                break;
            }
        }
        if result.is_ok() {
            result = w.flush();
        }
        assert!(result.is_err(), "write/flush to a full device must error");
    }
}
