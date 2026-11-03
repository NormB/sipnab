// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! What this sipnab process is: its build, its binary, its configuration,
//! its privilege and its health, as one record a fleet controller reads.
//!
//! # Why this module exists
//!
//! An estate of sipnab instances had no way to say which build each one runs
//! or which configuration it loaded. The upgrade note for HEP HMAC version 2
//! (`docs/config-reference.md`, "Upgrade a fleet that uses HMAC
//! authentication") could only tell the operator to run `sipnab --version`
//! on every host by hand. `GET /v1/inventory`, the MCP `fleet_inventory` tool
//! and `sipnab fleet inventory` read this one record, so the three cannot
//! describe one process differently.
//!
//! # What it never carries
//!
//! No configuration value and no command-line argument. Each is reported as a
//! SHA-256 digest only, so a secret in either changes the digest and never
//! appears in the answer. That is also why the record needs only the
//! `inventory` token scope ([`crate::auth::SCOPE_INVENTORY`]) and no scope
//! that reads call content.
//!
//! # What it cannot prove
//!
//! Every field is the process's own claim. A compromised host can report
//! anything, and nothing here detects that. In particular the record never
//! says its binary is a verified release: [`SIGNATURE_STATE`] is always
//! `unverified`, and the controller compares [`BinaryInfo::sha256`] with the
//! release's attested `SHA256SUMS.txt`.

use std::sync::OnceLock;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Wire-format version of [`Inventory`].
pub const SCHEMA_VERSION: u32 = 1;

/// The only signature state an instance reports about itself.
///
/// A process cannot verify the binary it is running against a release
/// attestation without the attestation's trust root, and a process that
/// could be tampered with would report "verified" as easily as anything
/// else. The check belongs to whoever holds the release's `SHA256SUMS.txt`.
pub const SIGNATURE_STATE: &str = "unverified";

/// The most HEP senders one inventory lists.
pub const MAX_HEP_PEERS: usize = 256;

/// The lowercase hexadecimal SHA-256 digest of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// The digest of a parsed configuration.
///
/// Taken over the configuration as sipnab parsed it, after `${NAME}`
/// expansion, so two files that differ only in key order, comments or
/// whitespace give one digest, and a changed value always gives another. The
/// serialization is canonical: `serde_json::Value` objects are sorted maps,
/// so struct field order and map insertion order cannot reach the digest.
///
/// # Errors
///
/// When the configuration does not serialize, which a configuration that
/// deserialized cannot do; the message is returned rather than a digest of
/// nothing.
pub fn parsed_config_digest(config: &crate::config::Config) -> Result<String, String> {
    let value = serde_json::to_value(config).map_err(|e| e.to_string())?;
    let canonical = canonical_json(&value);
    Ok(sha256_hex(canonical.as_bytes()))
}

/// `value` serialized with every object's keys sorted, whatever map type
/// `serde_json` was built with.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body: Vec<String> = keys
                .into_iter()
                .map(|k| {
                    let key = serde_json::Value::String(k.clone()).to_string();
                    format!("{key}:{}", canonical_json(&map[k]))
                })
                .collect();
            format!("{{{}}}", body.join(","))
        }
        serde_json::Value::Array(items) => {
            let body: Vec<String> = items.iter().map(canonical_json).collect();
            format!("[{}]", body.join(","))
        }
        other => other.to_string(),
    }
}

/// The digest of a command line.
///
/// Each argument is length-prefixed, so `["ab", "c"]` and `["a", "bc"]`
/// differ. The first argument, the program path, is left out: the same build
/// installed at two paths runs the same command.
#[must_use]
pub fn argv_digest(argv: &[std::ffi::OsString]) -> String {
    let mut hasher = Sha256::new();
    for arg in argv.iter().skip(1) {
        let bytes = arg.as_encoded_bytes();
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    hex(&hasher.finalize())
}

/// The digest of everything that decides this run's effective
/// configuration: the parsed configuration and the command line.
///
/// A command-line flag overrides the file, so two instances with one file
/// and different flags run differently; this digest tells them apart, where
/// [`parsed_config_digest`] alone would not. Each part is length-prefixed and
/// labeled. `None` when the parsed configuration has no digest.
#[must_use]
pub fn effective_digest(parsed_sha256: Option<&str>, argv_sha256: &str) -> Option<String> {
    let parsed = parsed_sha256?;
    let mut hasher = Sha256::new();
    for (label, part) in [("parsed", parsed), ("argv", argv_sha256)] {
        hasher.update(label.as_bytes());
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    Some(hex(&hasher.finalize()))
}

/// `bytes` as lowercase hexadecimal.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// What this run recorded about its configuration when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRecord {
    /// The file the configuration was read from, if any.
    pub source: Option<String>,
    /// Default-location files present but not read.
    pub shadowed: Vec<String>,
    /// SHA-256 of the bytes of `source`, as read.
    pub file_sha256: Option<String>,
    /// [`parsed_config_digest`] of the configuration, or `None` when it did
    /// not serialize.
    pub parsed_sha256: Option<String>,
    /// [`argv_digest`] of the command line.
    pub argv_sha256: String,
    /// [`effective_digest`] of the two above.
    pub effective_sha256: Option<String>,
    /// When the record was taken, RFC 3339.
    pub started: String,
}

impl RunRecord {
    /// The record for `loaded`, run with `argv`, at `started`.
    #[must_use]
    pub fn of(
        loaded: &crate::config::LoadedConfig,
        argv: &[std::ffi::OsString],
        started: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let parsed_sha256 = parsed_config_digest(&loaded.config).ok();
        let argv_sha256 = argv_digest(argv);
        Self {
            source: loaded.source.as_ref().map(|p| p.display().to_string()),
            shadowed: loaded
                .shadowed
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            file_sha256: loaded
                .file_text
                .as_deref()
                .map(|t| sha256_hex(t.as_bytes())),
            effective_sha256: effective_digest(parsed_sha256.as_deref(), &argv_sha256),
            parsed_sha256,
            argv_sha256,
            started: started.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        }
    }
}

/// This process's record, set once by [`record_run`].
static RUN: OnceLock<RunRecord> = OnceLock::new();

/// Record this run's configuration, once. A second call changes nothing, so
/// the answer is stable for the life of the process.
pub fn record_run(record: RunRecord) {
    let _ = RUN.set(record);
}

/// The record [`record_run`] set, if it ran.
#[must_use]
pub fn recorded() -> Option<&'static RunRecord> {
    RUN.get()
}

/// SHA-256 of the file at `path`, read in blocks.
///
/// # Errors
///
/// When the file cannot be opened or read; the message names the path.
pub fn file_sha256(path: &std::path::Path) -> Result<String, String> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path).map_err(|e| format!("'{}': {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("'{}': {e}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex(&hasher.finalize()))
}

/// The file this process is running from.
///
/// `/proc/self/exe` on Linux, which opens the image the process runs even
/// after an upgrade replaced or removed the file at its path, so the digest
/// describes what runs rather than what is installed. Elsewhere, the path
/// the operating system reports.
fn running_image() -> Result<std::path::PathBuf, String> {
    if cfg!(target_os = "linux") {
        return Ok(std::path::PathBuf::from("/proc/self/exe"));
    }
    std::env::current_exe().map_err(|e| e.to_string())
}

/// SHA-256 of the running binary, computed on first use and kept.
fn binary_digest() -> &'static Result<String, String> {
    static DIGEST: OnceLock<Result<String, String>> = OnceLock::new();
    DIGEST.get_or_init(|| running_image().and_then(|p| file_sha256(&p)))
}

/// One inventory record.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Inventory {
    /// Wire-format version of this envelope, [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The node name this process reports (`--node-name`,
    /// `[capture] node_name`, else the host name).
    pub node_name: String,
    /// The build.
    pub build: BuildInfo,
    /// The running binary.
    pub binary: BinaryInfo,
    /// What this process can say about its release signature.
    pub signature: SignatureInfo,
    /// The configuration this run loaded, as digests.
    pub config: ConfigInfo,
    /// The privilege the process holds.
    pub privilege: PrivilegeInfo,
    /// The process.
    pub process: ProcessInfo,
    /// The capture interfaces and their error and drop counters.
    pub interfaces: Vec<InterfaceCounters>,
    /// Capture-path and HEP export counters.
    pub counters: Counters,
    /// The HEP listener, when this run has one.
    pub hep_listener: HepListenerInfo,
}

/// The build, as `sipnab --version` reports it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct BuildInfo {
    /// The crate version.
    pub version: String,
    /// The git commit the build recorded; empty when it recorded none.
    pub commit: String,
    /// The git tag at that commit; empty when there was none.
    pub tag: String,
    /// Whether the working tree had uncommitted changes.
    pub dirty: bool,
    /// The target triple.
    pub target: String,
    /// The compiled feature set, sorted.
    pub features: Vec<String>,
    /// The whole `--version` line.
    pub version_line: String,
}

/// The running binary.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct BinaryInfo {
    /// SHA-256 of the running image, lowercase hex; absent when it could
    /// not be read.
    pub sha256: Option<String>,
    /// Why it could not be read.
    pub error: Option<String>,
}

/// The release signature, as far as the process can speak to it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct SignatureInfo {
    /// Always [`SIGNATURE_STATE`].
    pub state: String,
    /// How to verify the binary.
    pub note: String,
}

/// The configuration, as digests only.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct ConfigInfo {
    /// Whether this run recorded its configuration. `false` means every
    /// digest below is unknown, not empty.
    pub recorded: bool,
    /// The file read, if any.
    pub source: Option<String>,
    /// Default-location files present but not read.
    pub shadowed: Vec<String>,
    /// SHA-256 of the file's bytes.
    pub file_sha256: Option<String>,
    /// SHA-256 of the parsed configuration, canonically serialized.
    pub parsed_sha256: Option<String>,
    /// SHA-256 of the command line, without the program path.
    pub argv_sha256: Option<String>,
    /// SHA-256 over `parsed_sha256` and `argv_sha256`: what decides the
    /// effective configuration. The one configuration digest to compare
    /// across instances.
    pub effective_sha256: Option<String>,
}

/// The privilege the process holds.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct PrivilegeInfo {
    /// The user id the process runs as.
    pub uid: Option<u32>,
    /// Whether that is root.
    pub root: bool,
    /// The user a privilege drop switched to; absent when none happened.
    pub dropped_to: Option<String>,
}

/// The process.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct ProcessInfo {
    /// The process id.
    pub pid: u32,
    /// When the configuration was recorded, RFC 3339; absent when it was
    /// not.
    pub started: Option<String>,
    /// Seconds this process has been serving.
    pub uptime_seconds: u64,
}

/// One capture interface's error and drop counters, read from the interface.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct InterfaceCounters {
    /// The interface name.
    pub name: String,
    /// Link state; absent when not readable on this platform.
    pub operstate: Option<String>,
    /// Receive errors.
    pub rx_errors: Option<u64>,
    /// Packets the kernel dropped on receive.
    pub rx_dropped: Option<u64>,
    /// Packets the NIC missed for lack of ring space.
    pub rx_missed_errors: Option<u64>,
}

/// Capture-path and HEP export counters, cumulative.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct Counters {
    /// Packets the capture path received.
    pub capture_packets_total: u64,
    /// Capture sources refused past the source-table cap.
    pub capture_sources_refused_total: u64,
    /// Times the capture path blocked on a full queue; absent with no queue.
    pub capture_backpressure_blocks_total: Option<u64>,
    /// HEP export failures of every kind; absent with no exporter.
    pub hep_export_failures_total: Option<u64>,
    /// HEP export packets dropped of every kind; absent with no exporter.
    pub hep_export_dropped_total: Option<u64>,
    /// HEP export packets queued now; absent with no exporter.
    pub hep_export_queue_depth: Option<u64>,
}

/// The HEP listener's senders, by address only.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct HepListenerInfo {
    /// Whether this run has a HEP listener.
    pub listening: bool,
    /// Packets the listener refused, for any reason.
    pub packets_refused: u64,
    /// The senders it tracks, at most [`MAX_HEP_PEERS`].
    pub senders: Vec<HepPeer>,
}

/// One HEP sender.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "mcp", derive(rmcp::schemars::JsonSchema))]
#[cfg_attr(feature = "mcp", schemars(crate = "rmcp::schemars"))]
#[cfg_attr(feature = "api", derive(utoipa::ToSchema))]
pub struct HepPeer {
    /// The address its packets came from.
    pub peer: String,
    /// The capture id it claims; never proven.
    pub capture_id: Option<u32>,
    /// Whether it has been silent past the warning threshold.
    pub silent: bool,
}

/// The build half of the record, from the one `--version` source.
#[must_use]
pub fn build_info() -> BuildInfo {
    let mut features: Vec<String> = crate::cli::compiled_features()
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    features.sort();
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: env!("SIPNAB_GIT_COMMIT").to_string(),
        tag: env!("SIPNAB_GIT_TAG").to_string(),
        dirty: !env!("SIPNAB_GIT_DIRTY").is_empty(),
        target: env!("SIPNAB_TARGET").to_string(),
        features,
        version_line: crate::cli::build_version(),
    }
}

/// The configuration half of the record, from `record`.
#[must_use]
pub fn config_info(record: Option<&RunRecord>) -> ConfigInfo {
    match record {
        Some(r) => ConfigInfo {
            recorded: true,
            source: r.source.clone(),
            shadowed: r.shadowed.clone(),
            file_sha256: r.file_sha256.clone(),
            parsed_sha256: r.parsed_sha256.clone(),
            argv_sha256: Some(r.argv_sha256.clone()),
            effective_sha256: r.effective_sha256.clone(),
        },
        None => ConfigInfo {
            recorded: false,
            source: None,
            shadowed: Vec::new(),
            file_sha256: None,
            parsed_sha256: None,
            argv_sha256: None,
            effective_sha256: None,
        },
    }
}

/// The signature half of the record. Never anything but
/// [`SIGNATURE_STATE`].
#[must_use]
pub fn signature_info() -> SignatureInfo {
    SignatureInfo {
        state: SIGNATURE_STATE.to_string(),
        note: "sipnab does not verify its own binary. Compare binary.sha256 \
               with SHA256SUMS.txt of the release, after `gh attestation \
               verify SHA256SUMS.txt --repo NormB/sipnab`."
            .to_string(),
    }
}

/// The HEP half of the record, from the listener's roster when there is one.
#[must_use]
pub fn hep_listener_info(meter: Option<&crate::capture::channel::CaptureMeter>) -> HepListenerInfo {
    #[cfg(feature = "hep")]
    {
        let report = crate::capture::hep_roster::senders_report(
            meter.and_then(crate::capture::channel::CaptureMeter::hep_roster),
            MAX_HEP_PEERS,
        );
        HepListenerInfo {
            listening: report.listening,
            packets_refused: report.packets_refused,
            senders: report
                .senders
                .into_iter()
                .map(|row| HepPeer {
                    peer: row.peer,
                    capture_id: row.capture_id,
                    silent: row.silent,
                })
                .collect(),
        }
    }
    #[cfg(not(feature = "hep"))]
    {
        let _ = meter;
        HepListenerInfo::default()
    }
}

/// The counters half of the record.
#[must_use]
pub fn counters(meter: Option<&crate::capture::channel::CaptureMeter>) -> Counters {
    let exporter = meter
        .and_then(crate::capture::channel::CaptureMeter::hep_export)
        .map(crate::output::runtime::HepExportStats::of);
    Counters {
        capture_packets_total: crate::capture::captured_packets(),
        capture_sources_refused_total: crate::capture::packet::capture_source_counts().refused,
        capture_backpressure_blocks_total: meter
            .map(crate::capture::channel::CaptureMeter::backpressure_blocks),
        hep_export_failures_total: exporter.as_ref().map(|e| e.failures.values().sum()),
        hep_export_dropped_total: exporter.as_ref().map(|e| e.dropped.values().sum()),
        hep_export_queue_depth: exporter.as_ref().map(|e| e.queue_depth),
    }
}

/// This process's inventory record, now.
///
/// The one builder `GET /v1/inventory` and the MCP `fleet_inventory` tool
/// call.
///
/// # Arguments
///
/// * `meter` — the capture meter, for the queue, exporter and roster.
/// * `interfaces` — the interfaces sipnab was asked to capture on.
/// * `uptime_seconds` — how long this process has been serving.
#[must_use]
pub fn current(
    meter: Option<&crate::capture::channel::CaptureMeter>,
    interfaces: &[String],
    uptime_seconds: u64,
) -> Inventory {
    let record = recorded();
    let binary = match binary_digest() {
        Ok(d) => BinaryInfo {
            sha256: Some(d.clone()),
            error: None,
        },
        Err(e) => BinaryInfo {
            sha256: None,
            error: Some(e.clone()),
        },
    };
    #[cfg(unix)]
    let uid = Some(crate::privilege::current_uid());
    #[cfg(not(unix))]
    let uid = None;
    Inventory {
        schema_version: SCHEMA_VERSION,
        node_name: crate::provenance::node_name().to_string(),
        build: build_info(),
        binary,
        signature: signature_info(),
        config: config_info(record),
        privilege: PrivilegeInfo {
            uid,
            root: uid == Some(0),
            dropped_to: crate::privilege::dropped_to().map(str::to_string),
        },
        process: ProcessInfo {
            pid: std::process::id(),
            started: record.map(|r| r.started.clone()),
            uptime_seconds,
        },
        interfaces: interfaces
            .iter()
            .map(|n| {
                let s = crate::output::runtime::interface_stats(n);
                InterfaceCounters {
                    name: s.name,
                    operstate: s.operstate,
                    rx_errors: s.rx_errors,
                    rx_dropped: s.rx_dropped,
                    rx_missed_errors: s.rx_missed_errors,
                }
            })
            .collect(),
        counters: counters(meter),
        hep_listener: hep_listener_info(meter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestError = Box<dyn std::error::Error>;

    /// An independent SHA-256, so a test never checks the module's digest
    /// against the module's own digest.
    fn reference_hex(bytes: &[u8]) -> String {
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn parse(text: &str) -> Result<crate::config::Config, TestError> {
        Ok(toml::from_str(text)?)
    }

    /// FIPS 180-2's "abc" vector, so the hex encoding is checked against a
    /// published value and not only against itself.
    #[test]
    fn sha256_hex_matches_the_published_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "\"abc\" must hash to the FIPS 180-2 vector"
        );
    }

    /// The parsed digest ignores key order, whitespace and comments, and
    /// changes when one value changes.
    #[test]
    fn parsed_digest_follows_values_not_layout() -> Result<(), TestError> {
        let a = parse("[capture]\nnode_name = \"edge-a\"\nsnaplen = 1500\n")?;
        let b = parse("# a comment\n[capture]\n  snaplen   = 1500\nnode_name=\"edge-a\"\n")?;
        let c = parse("[capture]\nnode_name = \"edge-a\"\nsnaplen = 1501\n")?;
        let da = parsed_config_digest(&a)?;
        assert_eq!(da.len(), 64, "a SHA-256 in hex: {da:?}");
        assert_eq!(da, parsed_config_digest(&b)?, "layout reached the digest");
        assert_ne!(
            da,
            parsed_config_digest(&c)?,
            "a changed value kept the digest"
        );
        assert_eq!(
            da,
            reference_hex(canonical_json(&serde_json::to_value(&a)?).as_bytes()),
            "the digest is SHA-256 of the canonical serialization"
        );
        Ok(())
    }

    /// What a run records follows values, not layout: two files that differ
    /// only in key order, whitespace and comments give one parsed and one
    /// effective digest, and two file digests.
    #[test]
    fn the_run_record_digests_values_not_layout() -> Result<(), TestError> {
        let record = |text: &str| -> Result<RunRecord, TestError> {
            let loaded = crate::config::LoadedConfig {
                config: parse(text)?,
                source: None,
                shadowed: Vec::new(),
                file_text: Some(text.to_string()),
            };
            let argv: Vec<std::ffi::OsString> = vec!["sipnab".into(), "-N".into()];
            let at = chrono::DateTime::from_timestamp(1_790_000_000, 0).ok_or("a time")?;
            Ok(RunRecord::of(&loaded, &argv, at))
        };
        let a = record("[capture]\nnode_name = \"edge-a\"\nsnaplen = 1500\n")?;
        let b = record("# a comment\n[capture]\n  snaplen   = 1500\nnode_name=\"edge-a\"\n")?;
        assert_ne!(
            a.file_sha256, b.file_sha256,
            "the files differ byte for byte"
        );
        assert_eq!(
            a.parsed_sha256, b.parsed_sha256,
            "layout reached the parsed digest"
        );
        assert_eq!(
            a.effective_sha256, b.effective_sha256,
            "layout reached the effective digest"
        );
        assert!(
            a.effective_sha256.is_some(),
            "a parsed configuration has an effective digest"
        );
        Ok(())
    }

    /// A secret a configuration takes from the environment with `${NAME}`
    /// changes the parsed digest, though the file's bytes are the same: the
    /// digest is over the configuration after expansion.
    #[test]
    fn an_expanded_secret_changes_the_parsed_digest() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("sipnab.toml");
        std::fs::write(
            &path,
            "[vcon_forward]\nauth_file = \"/run/example/${FLEET_TEST_SECRET}\"\n",
        )?;
        let digest = |value: &'static str| -> Result<String, TestError> {
            let config = crate::config::Config::load_file_with_env(&path, &move |name| {
                (name == "FLEET_TEST_SECRET").then(|| value.to_string())
            })?;
            Ok(parsed_config_digest(&config)?)
        };
        assert_ne!(
            digest("first-value")?,
            digest("second-value")?,
            "the expanded value must reach the parsed digest"
        );
        Ok(())
    }

    /// Canonical JSON sorts every object's keys, at every depth.
    #[test]
    fn canonical_json_sorts_keys_at_every_depth() -> Result<(), TestError> {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"b":{"y":1,"x":[{"d":2,"c":3}]},"a":0}"#)?;
        assert_eq!(
            canonical_json(&v),
            r#"{"a":0,"b":{"x":[{"c":3,"d":2}],"y":1}}"#,
            "the digest is SHA-256 of the canonical serialization"
        );
        Ok(())
    }

    /// A secret in the configuration or on the command line changes the
    /// digests, and its value is in no field of the record.
    #[test]
    fn a_secret_changes_the_digest_and_never_appears() -> Result<(), TestError> {
        const SECRET: &str = "s3cr3t-marker-0b1f0e2d";
        let text = |v: &str| format!("[vcon_forward]\nauth_file = \"/run/example/{v}\"\n");
        let loaded = |v: &str| -> Result<crate::config::LoadedConfig, TestError> {
            Ok(crate::config::LoadedConfig {
                config: parse(&text(v))?,
                source: Some(std::path::PathBuf::from("/etc/sipnab/sipnab.toml")),
                shadowed: Vec::new(),
                file_text: Some(text(v)),
            })
        };
        let argv = |v: &str| -> Vec<std::ffi::OsString> {
            ["sipnab", "--api-key", v].iter().map(Into::into).collect()
        };
        let at = chrono::DateTime::from_timestamp(1_790_000_000, 0).ok_or("a time")?;
        let with = RunRecord::of(&loaded(SECRET)?, &argv(SECRET), at);
        let other = RunRecord::of(&loaded("other-value")?, &argv("other-value"), at);
        assert_ne!(with.file_sha256, other.file_sha256, "file digest");
        assert_ne!(with.parsed_sha256, other.parsed_sha256, "parsed digest");
        assert_ne!(with.argv_sha256, other.argv_sha256, "argv digest");
        assert_ne!(
            with.effective_sha256, other.effective_sha256,
            "effective digest"
        );
        assert!(with.effective_sha256.is_some(), "an effective digest");
        assert!(
            with.file_sha256.is_some() && with.parsed_sha256.is_some(),
            "a loaded file has a file digest and a parsed digest"
        );
        let json = serde_json::to_string(&config_info(Some(&with)))?;
        assert!(
            !json.contains(SECRET),
            "the secret reached the record: {json}"
        );
        Ok(())
    }

    /// The effective digest is SHA-256 of the two labeled, length-prefixed
    /// parts; it follows each part, cannot be forged by moving bytes from one
    /// part to the other, and is absent without a parsed digest.
    #[test]
    fn the_effective_digest_covers_the_file_and_the_command_line() -> Result<(), TestError> {
        let (p, a) = ("1".repeat(64), "2".repeat(64));
        let got = effective_digest(Some(&p), &a).ok_or("a digest")?;
        let mut want = Vec::new();
        for (label, part) in [("parsed", &p), ("argv", &a)] {
            want.extend_from_slice(label.as_bytes());
            want.extend_from_slice(&(part.len() as u64).to_be_bytes());
            want.extend_from_slice(part.as_bytes());
        }
        assert_eq!(
            got,
            reference_hex(&want),
            "the effective digest is SHA-256 of the labeled, length-prefixed parts"
        );
        assert_ne!(
            Some(got.clone()),
            effective_digest(Some(&"3".repeat(64)), &a),
            "parsed"
        );
        assert_ne!(
            Some(got.clone()),
            effective_digest(Some(&p), &"3".repeat(64)),
            "argv"
        );
        assert_ne!(
            effective_digest(Some("ab"), "c"),
            effective_digest(Some("a"), "bc"),
            "a byte moved between the parts"
        );
        assert_eq!(
            effective_digest(None, &a),
            None,
            "no parsed digest, no effective digest"
        );
        Ok(())
    }

    /// Arguments are length-prefixed and the program path is left out.
    #[test]
    fn argv_digest_separates_arguments_and_skips_the_program() {
        let v =
            |args: &[&str]| -> Vec<std::ffi::OsString> { args.iter().map(Into::into).collect() };
        let ab_c = argv_digest(&v(&["sipnab", "ab", "c"]));
        assert_eq!(ab_c.len(), 64, "{ab_c:?}");
        assert_ne!(
            ab_c,
            argv_digest(&v(&["sipnab", "a", "bc"])),
            "moving a byte between arguments must change the digest"
        );
        assert_eq!(
            ab_c,
            argv_digest(&v(&["/usr/local/bin/sipnab", "ab", "c"])),
            "the program path is left out of the digest"
        );
    }

    /// The file digest is SHA-256 of the file's bytes.
    #[test]
    fn file_sha256_is_the_digest_of_the_bytes() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("blob");
        let bytes: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&path, &bytes)?;
        assert_eq!(
            file_sha256(&path)?,
            reference_hex(&bytes),
            "the file digest is SHA-256 of the file's bytes"
        );
        assert!(
            file_sha256(&dir.path().join("absent")).is_err(),
            "a missing file is an error, not a digest"
        );
        Ok(())
    }

    /// The binary digest is SHA-256 of the image this process runs.
    #[test]
    fn the_binary_digest_is_the_running_image() -> Result<(), TestError> {
        let exe = std::env::current_exe()?;
        let inv = current(None, &[], 0);
        assert_eq!(inv.binary.error, None, "the running image must be readable");
        assert_eq!(
            inv.binary.sha256,
            Some(reference_hex(&std::fs::read(exe)?)),
            "the binary digest is SHA-256 of the running image"
        );
        Ok(())
    }

    /// The process never claims its own signature is verified.
    #[test]
    fn an_instance_reports_its_signature_unverified() {
        assert_eq!(
            signature_info().state,
            "unverified",
            "an instance never reports its signature verified"
        );
        assert_eq!(
            current(None, &[], 0).signature.state,
            "unverified",
            "the record carries the unverified state"
        );
    }

    /// The build fields come from the one `--version` source.
    #[test]
    fn build_info_is_the_version_line_split() {
        let b = build_info();
        assert_eq!(
            b.version_line,
            crate::cli::build_version(),
            "the version line is the one --version prints"
        );
        assert_eq!(
            b.version,
            env!("CARGO_PKG_VERSION"),
            "the version is the crate version"
        );
        assert_eq!(
            b.commit,
            env!("SIPNAB_GIT_COMMIT"),
            "the commit is the one the build recorded"
        );
        assert_eq!(
            b.target,
            env!("SIPNAB_TARGET"),
            "the target is the one the build recorded"
        );
        assert_eq!(
            b.dirty,
            !env!("SIPNAB_GIT_DIRTY").is_empty(),
            "the dirty flag is the one the build recorded"
        );
        let mut want: Vec<String> = crate::cli::compiled_features()
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        want.sort();
        assert!(!want.is_empty(), "this build compiles some feature");
        assert_eq!(
            b.features, want,
            "the features are the compiled set, sorted"
        );
    }

    /// No record means unknown, said as `recorded: false`, never as digests
    /// of nothing.
    #[test]
    fn an_unrecorded_run_says_so() {
        let c = config_info(None);
        assert!(!c.recorded, "no record means not recorded");
        assert_eq!(c.parsed_sha256, None, "no record has no parsed digest");
        assert_eq!(c.argv_sha256, None, "no record has no command-line digest");
        assert_eq!(
            c.effective_sha256, None,
            "no record has no effective digest"
        );
    }
}
