//! Running the uprobe capture source: install, drain, convert, send.
//!
//! This is the piece that makes the rest of the module reachable. It installs
//! the banded probes, opens one perf ring per CPU, and turns each accepted read
//! into a [`Packet`](crate::capture::packet::Packet) on the same channel a live
//! device or a HEP listener feeds — so filtering, the dialog store, the
//! detectors and every output format work on uprobe input without knowing where
//! it came from.
//!
//! **What it does not do is invent a peer.** These bytes were handed to a TLS
//! library by a process; sipnab never saw a socket, so the addresses are
//! unspecified and the ports zero. The packet carries a `uprobe:<comm>/<pid>`
//! source name instead, which is what makes its frame pointer refuse to resolve
//! and its [`InputOrigin`](crate::capture::parse::InputOrigin) `Uprobe` rather
//! than `Hep` — the latter being what decides that no `--hep-allow-kill` can
//! ever make this input transmit-eligible.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{BANDS, InstalledProbes, accept, is_interesting, perf, probe_name, record};
use crate::capture::channel::PacketTx;
use crate::capture::packet::{FrameOrigin, Packet, PreParsed};

/// TLS runs over TCP, and that is what the transport is reported as.
///
/// Not a guess: `SSL_write` on a stream BIO is a TCP connection. sipnab did not
/// observe the header, which is why the ADDRESSES are left unspecified — but
/// the protocol is not in doubt, and `PreParsed` requires one.
const IP_PROTO_TCP: u8 = 6;

/// One CPU's ring paired with the layout its probe publishes.
struct Band {
    /// The ring to drain.
    ring: perf::PerfRing,
    /// How to read the records it yields.
    layout: Arc<record::RecordLayout>,
}

/// Everything the reader owns, in the order it must be released.
///
/// **Field order is the drop order and it is load-bearing.** The kernel refuses
/// to remove a tracepoint that still has an open perf consumer, so the rings
/// must close before the probes are removed. Declared the other way round, a
/// clean shutdown would leave every probe attached to a production library —
/// measured, not theorised: the first end-to-end run leaked four probes exactly
/// that way.
pub struct UprobeReader {
    /// Dropped FIRST.
    bands: Vec<Band>,
    /// Dropped SECOND, once nothing is consuming the tracepoints.
    ///
    /// One entry per library. A host running OpenSSL and wolfSSL together is
    /// the ordinary case rather than the exotic one, and each needs its own
    /// symbol, its own file offset and its own probe set.
    probes: Vec<InstalledProbes>,
}

/// One library to probe, and the symbol to probe in it.
#[derive(Debug, Clone)]
pub struct Target {
    /// Path that names the library **from sipnab's own mount namespace**.
    ///
    /// For a containerised process this is a `/proc/<pid>/root/…` path, not the
    /// path the process itself sees. See
    /// [`TlsLibrary::probe_path`](super::discover::TlsLibrary::probe_path).
    pub library: std::path::PathBuf,
    /// The write symbol: `SSL_write`, `wolfSSL_write`, or one an operator named.
    pub symbol: String,
}

impl UprobeReader {
    /// Install probes on `library` at `symbol` and open a ring per CPU.
    ///
    /// # Errors
    ///
    /// Any failure to read the library, resolve the symbol, install a probe, or
    /// open a ring. Every one is reported rather than downgraded: a capture
    /// that silently attached to nothing reads exactly like quiet traffic.
    pub fn attach(tracefs: &Path, library: &str, symbol: &str) -> io::Result<Self> {
        Self::attach_many(
            tracefs,
            &[Target {
                library: std::path::PathBuf::from(library),
                symbol: symbol.to_string(),
            }],
        )
    }

    /// Install probes on every target and open a ring per CPU per band.
    ///
    /// **A target that cannot be attached is reported, not skipped.** Quietly
    /// dropping one would mean an operator on a mixed OpenSSL/wolfSSL host is
    /// told the capture is running while half of it is not, and missing traffic
    /// is indistinguishable from a quiet trunk.
    ///
    /// # Errors
    ///
    /// The first target that fails, after everything already installed has been
    /// released by the guard.
    pub fn attach_many(tracefs: &Path, targets: &[Target]) -> io::Result<Self> {
        if targets.is_empty() {
            return Err(io::Error::other(
                "no TLS library to probe. Nothing on this host maps one, or \
                 sipnab cannot read /proc — a capture attached to nothing reads \
                 exactly like a quiet trunk, so this is refused rather than \
                 started",
            ));
        }
        let pid = std::process::id();
        let cpus = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        let mut this = Self {
            bands: Vec::new(),
            probes: Vec::new(),
        };

        for (slot, target) in targets.iter().enumerate() {
            let library = target.library.display().to_string();
            let elf = std::fs::read(&target.library)
                .map_err(|e| io::Error::other(format!("{library}: {e}")))?;
            let offset = super::elf::function_file_offset(&elf, &target.symbol)
                .map_err(|e| io::Error::other(format!("{library}: {e}")))?;

            // Pushed before the rings are opened, so a failure below still
            // releases what this iteration installed.
            this.probes.push(InstalledProbes::install(
                tracefs, pid, slot, &library, offset,
            )?);

            for band in BANDS {
                let name = probe_name(pid, slot, band);
                let text =
                    std::fs::read_to_string(tracefs.join(format!("events/uprobes/{name}/format")))?;
                let layout = Arc::new(record::parse_layout(&text).ok_or_else(|| {
                    io::Error::other(format!(
                        "the kernel published a format for {name} without the fields \
                         sipnab reads; refusing rather than decoding at guessed offsets"
                    ))
                })?);
                for cpu in 0..i32::try_from(cpus).unwrap_or(1) {
                    match perf::PerfRing::open(perf::event_id(tracefs, &name)?, cpu, 8) {
                        Ok(ring) => this.bands.push(Band {
                            ring,
                            layout: Arc::clone(&layout),
                        }),
                        // One CPU refusing is survivable; every CPU refusing is
                        // not, and the emptiness check below catches that.
                        Err(e) => tracing::debug!("uprobe: cpu {cpu} ring for {name}: {e}"),
                    }
                }
            }
        }

        if this.bands.is_empty() {
            return Err(io::Error::other(
                "no perf ring could be opened for any band, so nothing would ever \
                 be read. Note the kernel refuses a tracepoint already enabled \
                 through tracefs",
            ));
        }
        Ok(this)
    }

    /// Probes currently installed, across every library.
    #[must_use]
    pub fn probe_names(&self) -> Vec<&str> {
        self.probes
            .iter()
            .flat_map(|p| p.names().iter().map(String::as_str))
            .collect()
    }

    /// Records the kernel dropped because this reader fell behind.
    #[must_use]
    pub fn lost(&self) -> u64 {
        self.bands.iter().map(|b| b.ring.lost()).sum()
    }

    /// Drain every ring once, sending what survives the acceptance rules.
    ///
    /// Returns how many packets were sent.
    pub fn drain_once(&mut self, tx: &PacketTx) -> usize {
        let mut sent = 0;
        for band in &mut self.bands {
            let layout = Arc::clone(&band.layout);
            band.ring.drain(|raw| {
                let Some(mut rec) = record::decode(raw, &layout) else {
                    return;
                };
                // accept() truncates to the length the application wrote and
                // wipes the rest, so nothing past it can leave this call.
                let Some(acc) = accept(&mut rec.bytes, rec.len) else {
                    return;
                };
                if !is_interesting(&acc.bytes) {
                    return;
                }
                if tx.send(to_packet(&acc.bytes, rec.pid, sent as u64)).is_ok() {
                    sent += 1;
                }
            });
        }
        sent
    }

    /// Drain until `stop` is set, sleeping briefly when a sweep finds nothing.
    pub fn run(&mut self, tx: &PacketTx, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            if self.drain_once(tx) == 0 {
                // A probe fires only when the application writes, which on a
                // quiet trunk is rarely. Sleeping beats spinning fourteen rings.
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        let lost = self.lost();
        if lost > 0 {
            tracing::warn!(
                "uprobe capture: the kernel dropped {lost} record(s) because this \
                 reader fell behind. Those messages are missing from the capture"
            );
        }
    }
}

/// Build the packet for one accepted read.
///
/// The addresses are unspecified and the ports zero **on purpose**: a uprobe
/// sees the bytes an application handed its TLS library and nothing about the
/// socket beneath. Filling in a plausible peer would make every dialog a small
/// lie. The source name carries the attribution instead.
fn to_packet(bytes: &[u8], pid: u32, ordinal: u64) -> Packet {
    let comm = comm_of(pid);
    let mut pkt = Packet::with_pre_parsed(
        chrono::Utc::now(),
        bytes.to_vec(),
        Some(format!("uprobe:{comm}/{pid}")),
        PreParsed {
            src_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            dst_addr: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_port: 0,
            ip_protocol: IP_PROTO_TCP,
            // A uprobe read has no wrapper to assert anything.
            hep: None,
        },
    );
    // Both halves or no pointer: `frame_locator` needs a source AND an origin.
    // No digest, and none is possible -- a digest exists so a resolver can
    // prove it found the same bytes again, and these cannot be read twice.
    pkt.origin = Some(FrameOrigin {
        ordinal,
        digest: None,
        // Read out of a process, never a frame on a wire. There is
        // nothing to re-read, so there is nothing a digest could check.
        verifiable: false,
    });
    pkt
}

/// The kernel's command name for a pid, or `unknown` when it cannot be read.
///
/// `unknown` rather than a fabricated name: the pid is the identifying half and
/// is always present, so a missing comm degrades the label without inventing
/// one.
fn comm_of(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().replace('/', "_"))
        .unwrap_or_else(|_| "unknown".to_string())
}

/// Run the uprobe capture source to completion.
///
/// Mirrors the contract every other capture function follows: attach the
/// resource, signal readiness once it is actually attached, then loop until
/// shutdown is requested.
///
/// **Readiness is signaled after the probes and rings exist, not before.** The
/// launch sequence waits on that signal before dropping privileges, and probes
/// need root — reporting ready early would drop privileges out from under the
/// attach.
///
/// # Errors
///
/// Propagates an attach failure after reporting it on `ready_tx`, so the caller
/// exits with a named reason rather than capturing nothing in silence.
pub fn capture_uprobe(
    targets: &[crate::capture::UprobeTarget],
    tx: PacketTx,
    ready_tx: Option<crossbeam_channel::Sender<Result<(), String>>>,
) -> anyhow::Result<()> {
    let tracefs = Path::new(super::TRACEFS);
    let attach: Vec<Target> = targets
        .iter()
        .map(|t| Target {
            library: std::path::PathBuf::from(&t.library),
            symbol: t.symbol.clone(),
        })
        .collect();
    let described = attach
        .iter()
        .map(|t| format!("{}:{}", t.library.display(), t.symbol))
        .collect::<Vec<_>>()
        .join(", ");

    let mut reader = match UprobeReader::attach_many(tracefs, &attach) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("uprobe capture on [{described}] failed: {e}");
            if let Some(tx) = ready_tx {
                let _ = tx.send(Err(msg.clone()));
            }
            anyhow::bail!(msg);
        }
    };
    tracing::info!(
        "uprobe capture attached to {} librar{} [{described}] with {} probes. \
         Addresses are not observable from a uprobe, so dialogs from this source \
         name the process rather than a peer.",
        attach.len(),
        if attach.len() == 1 { "y" } else { "ies" },
        reader.probe_names().len()
    );
    if let Some(tx) = ready_tx {
        let _ = tx.send(Ok(()));
    }

    while !crate::signals::shutdown_requested() {
        if reader.drain_once(&tx) == 0 {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let lost = reader.lost();
    if lost > 0 {
        tracing::warn!(
            "uprobe capture: the kernel dropped {lost} record(s) because this \
             reader fell behind; those messages are missing from the capture"
        );
    }
    // `reader` drops here: rings first, then probes, which is the only order
    // the kernel accepts.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_uprobe_packet_names_its_process_and_claims_no_peer() {
        let pkt = to_packet(b"INVITE sip:b@x SIP/2.0\r\n\r\n", 4321, 7);

        let iface = pkt.interface.as_deref().expect("a source name");
        assert!(iface.starts_with("uprobe:"), "source name is {iface}");
        assert!(iface.ends_with("/4321"), "names the pid: {iface}");

        let meta = pkt.pre_parsed.as_ref().expect("pre-parsed");
        assert!(meta.src_addr.is_unspecified(), "no socket was observed");
        assert!(meta.dst_addr.is_unspecified());
        assert_eq!(meta.src_port, 0);
        assert_eq!(meta.dst_port, 0);
    }

    /// The pointer must survive into the parsed packet, or the provenance work
    /// stops at the capture boundary.
    #[test]
    fn a_uprobe_packet_carries_a_resolvable_pointer_shape() {
        let pkt = to_packet(b"INVITE sip:b@x SIP/2.0\r\n\r\n", 4321, 7);
        let loc = pkt.frame_locator().expect("both halves present");
        assert_eq!(loc.origin.ordinal, 7);
        assert!(
            loc.origin.digest.is_none(),
            "these bytes cannot be read twice, so a digest would be unverifiable"
        );
        let r = pkt.frame_ref().expect("owned pointer");
        assert!(matches!(
            r.source_kind(),
            crate::capture::packet::FrameSource::Uprobe { pid: 4321, .. }
        ));
    }

    /// A pid whose comm cannot be read still yields a usable label.
    #[test]
    fn an_unreadable_comm_degrades_rather_than_fabricates() {
        assert_eq!(comm_of(u32::MAX), "unknown");
    }
}
