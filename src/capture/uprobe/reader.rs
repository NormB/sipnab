//! Running the uprobe capture source: install, drain, convert, send.
//!
//! Needs `libc`, which it reaches through `perf`.
//!
//! This is the piece that makes the rest of the module reachable. It installs
//! the banded probes, opens one perf ring per CPU, and turns each accepted read
//! into a [`Packet`] on the same channel a live device or a HEP listener
//! feeds — so filtering, the dialog store, the detectors and every output
//! format work on uprobe input without knowing where it came from.
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
/// measured, not theorized: the first end-to-end run leaked four probes exactly
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
    /// The ordinal the next packet sent will carry.
    ///
    /// The reader's, not one sweep's: [`Self::drain_once`] used to number from
    /// zero on every call, so the first packet of every sweep was `#0` again
    /// and a process's messages named one another's frames. Advanced only for
    /// a packet actually sent, as the BPF backend does.
    next_ordinal: u64,
}

/// One library to probe, and the symbol to probe in it.
#[derive(Debug, Clone)]
pub struct Target {
    /// Path that names the library **from sipnab's own mount namespace**.
    ///
    /// For a containerized process this is a `/proc/<pid>/root/…` path, not the
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
            next_ordinal: 0,
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
        let next_ordinal = &mut self.next_ordinal;
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
                if tx
                    .send(to_packet(&acc.bytes, rec.pid, *next_ordinal))
                    .is_ok()
                {
                    // Saturating, as `FrameCounter` is: wrapping would mint a
                    // second `#0` for the same source.
                    *next_ordinal = next_ordinal.saturating_add(1);
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

    // ── Draining: record -> acceptance -> packet, over a stand-in ring ───
    //
    // A real ring needs a perf descriptor, which needs privileges this suite
    // does not have. `perf::fake` maps an ordinary file with the same layout,
    // so everything from the ring walk onward is the production path.

    use super::super::perf::fake;
    use crate::capture::channel::packet_channel;

    /// Verbatim `events/uprobes/<name>/format` from a 6.8 kernel for a
    /// 64-byte band -- the same text `record`'s tests pin.
    const FORMAT: &str = "name: sipnab_fmt\nID: 1815\nformat:\n\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\n\tfield:unsigned long __probe_ip;\toffset:8;\tsize:8;\tsigned:0;\n\tfield:u8 b0[];\toffset:16;\tsize:64;\tsigned:0;\n\tfield:s32 len;\toffset:80;\tsize:4;\tsigned:1;\n";

    /// A pid no process on the host can hold (above every `pid_max`), so the
    /// comm lookup is deterministic: `unknown`.
    const NO_SUCH_PID: i32 = 2_000_000_000;

    const INVITE: &[u8] = b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: u@x\r\n\r\n";

    /// One tracepoint record at `FORMAT`'s offsets: `written` in the fetch,
    /// `len` as the length the application passed, and the rest of the
    /// 64-byte fetch filled with 0xAA standing in for adjacent heap.
    fn tracepoint(pid: i32, written: &[u8], len: i32) -> Vec<u8> {
        let mut rec = vec![0xAA; 84];
        rec[4..8].copy_from_slice(&pid.to_le_bytes());
        rec[16..16 + written.len()].copy_from_slice(written);
        rec[80..84].copy_from_slice(&len.to_le_bytes());
        rec
    }

    fn layout() -> Arc<record::RecordLayout> {
        Arc::new(record::parse_layout(FORMAT).expect("real kernel output parses"))
    }

    /// A reader over one stand-in ring holding `records`, with no probes.
    fn reader_over(records: &[u8]) -> (UprobeReader, std::fs::File) {
        let (ring, file) = fake::ring(1, 0, records);
        let reader = UprobeReader {
            bands: vec![Band {
                ring,
                layout: layout(),
            }],
            probes: Vec::new(),
            next_ordinal: 0,
        };
        (reader, file)
    }

    /// Only an accepted SIP write becomes a packet, and only the bytes the
    /// application wrote travel in it -- never the fetch padding.
    #[test]
    fn a_drain_sends_only_accepted_sip_and_only_what_was_written() {
        let mut records = fake::sample(&tracepoint(NO_SUCH_PID, INVITE, INVITE.len() as i32));
        // Not SIP: the probes see every process that maps the library.
        records.extend(fake::sample(&tracepoint(
            NO_SUCH_PID,
            b"GET / HTTP/1.1\r\n",
            16,
        )));
        // A zero-length write: padding only.
        records.extend(fake::sample(&tracepoint(NO_SUCH_PID, INVITE, 0)));
        // Shorter than the layout: refused rather than decoded partially.
        records.extend(fake::sample(&[0u8; 40]));
        let (mut reader, _file) = reader_over(&records);
        let (tx, rx) = packet_channel(16);

        assert_eq!(reader.drain_once(&tx), 1, "exactly one record survives");

        let pkts: Vec<_> = rx.try_iter().collect();
        assert_eq!(pkts.len(), 1);
        assert_eq!(
            &pkts[0].data[..],
            INVITE,
            "the write, cut at its own length -- none of the 0xAA padding"
        );
        assert_eq!(
            pkts[0].interface.as_deref(),
            Some(format!("uprobe:unknown/{NO_SUCH_PID}").as_str()),
            "attributed to the process that wrote it"
        );
    }

    /// A frame pointer is `<source>#<ordinal>`, and two different reads must
    /// never share one. The ordinal therefore belongs to the READER, not to a
    /// single sweep: restarting it per `drain_once` minted `#0` again on the
    /// first packet of every sweep, so a busy process's messages all claimed
    /// to be each other. The BPF backend already threads its ordinal across
    /// sweeps; this pins the tracefs one to the same rule.
    #[test]
    fn frame_ordinals_keep_counting_across_sweeps() {
        let first = fake::sample(&tracepoint(NO_SUCH_PID, INVITE, INVITE.len() as i32));
        let (mut reader, file) = reader_over(&first);
        let (tx, rx) = packet_channel(16);

        assert_eq!(reader.drain_once(&tx), 1);
        fake::append(
            &file,
            1,
            &fake::sample(&tracepoint(NO_SUCH_PID, INVITE, INVITE.len() as i32)),
        );
        assert_eq!(reader.drain_once(&tx), 1);

        let refs: Vec<String> = rx
            .try_iter()
            .map(|p| p.frame_ref().expect("both halves").to_string())
            .collect();
        assert_eq!(refs.len(), 2);
        assert_ne!(
            refs[0], refs[1],
            "two different reads from one process named the same frame"
        );
        assert_eq!(
            refs,
            vec![
                format!("uprobe:unknown/{NO_SUCH_PID}#0"),
                format!("uprobe:unknown/{NO_SUCH_PID}#1"),
            ]
        );
    }

    /// A read that could not be handed on is not numbered: the ordinal counts
    /// packets that exist, so the next one delivered is still `#0`.
    #[test]
    fn a_closed_channel_sends_nothing_and_counts_nothing() {
        let rec = fake::sample(&tracepoint(NO_SUCH_PID, INVITE, INVITE.len() as i32));
        let (mut reader, file) = reader_over(&rec);
        let (closed_tx, closed_rx) = packet_channel(16);
        drop(closed_rx);
        assert_eq!(reader.drain_once(&closed_tx), 0, "nothing reached anyone");

        fake::append(&file, 1, &rec);
        let (tx, rx) = packet_channel(16);
        assert_eq!(reader.drain_once(&tx), 1);
        let origin = rx
            .try_iter()
            .next()
            .and_then(|p| p.origin)
            .expect("a numbered packet");
        assert_eq!(
            origin.ordinal, 0,
            "the undelivered read must not have consumed an ordinal"
        );
    }

    /// Every band's losses are the reader's losses. Reporting one ring's would
    /// understate the hole in the capture.
    #[test]
    fn records_lost_on_every_ring_are_summed() {
        let (ring_a, _fa) = fake::ring(1, 0, &fake::lost(1, 3));
        let (ring_b, _fb) = fake::ring(1, 0, &fake::lost(2, 4));
        let mut reader = UprobeReader {
            bands: vec![
                Band {
                    ring: ring_a,
                    layout: layout(),
                },
                Band {
                    ring: ring_b,
                    layout: layout(),
                },
            ],
            probes: Vec::new(),
            next_ordinal: 0,
        };
        let (tx, _rx) = packet_channel(16);
        assert_eq!(reader.lost(), 0);
        assert_eq!(reader.drain_once(&tx), 0);
        assert_eq!(reader.lost(), 7, "3 on one ring and 4 on the other");
    }

    /// `run` drains until told to stop, and on the way out says how much the
    /// kernel threw away -- a capture with a hole in it must be able to say so.
    #[test]
    fn run_drains_until_stopped_and_reports_what_the_kernel_dropped() {
        let mut records = fake::sample(&tracepoint(NO_SUCH_PID, INVITE, INVITE.len() as i32));
        records.extend(fake::lost(9, 5));
        let (mut reader, _file) = reader_over(&records);
        let (tx, rx) = packet_channel(16);
        let stop = Arc::new(AtomicBool::new(false));

        // The stopper waits for the packet, so `run` must have drained at
        // least once before it is asked to return.
        let stopper = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                let got = rx.recv_timeout(std::time::Duration::from_secs(10));
                stop.store(true, Ordering::Relaxed);
                got.map(|p| p.data.to_vec())
            })
        };
        let logs = capture_logs(|| reader.run(&tx, &stop));

        assert_eq!(
            stopper.join().expect("stopper thread").expect("a packet"),
            INVITE
        );
        assert_eq!(reader.lost(), 5);
        assert!(
            logs.contains("dropped 5 record(s)") && logs.contains("missing from the capture"),
            "the loss is reported, with its size: {logs}"
        );
    }

    /// Nothing lost, nothing said: the warning is evidence, not decoration.
    #[test]
    fn a_clean_run_reports_no_loss() {
        let (mut reader, _file) = reader_over(&[]);
        let (tx, _rx) = packet_channel(16);
        let stop = AtomicBool::new(true);
        let logs = capture_logs(|| reader.run(&tx, &stop));
        assert!(!logs.contains("dropped"), "{logs}");
    }

    /// Run `f` under a thread-local subscriber and return what it logged.
    fn capture_logs(f: impl FnOnce()) -> String {
        crate::test_utils::capture_logs(tracing::Level::DEBUG, f)
    }

    // ── Attaching, against a stand-in tracefs ────────────────────────────
    //
    // `attach_many` takes the tracefs root as an argument, so every step up to
    // opening the perf rings runs against a temp directory. The rings are
    // where it stops: `perf_event_open` refuses an unprivileged caller, and
    // the ids written below name no tracepoint even for a privileged one. So
    // these tests reach the refusal that a ringless attach must produce, and
    // the SUCCESSFUL attach stays out of reach of an unprivileged suite.

    /// The smallest ELF64 that exports `SSL_write` as a defined function in
    /// `.dynsym`, at virtual address 0x500 in a segment mapped 1:1 from the
    /// file -- so its probe offset is 0x500.
    fn elf_exporting_ssl_write() -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little endian
        b[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes()); // e_phoff
        b[0x28..0x30].copy_from_slice(&0x100u64.to_le_bytes()); // e_shoff
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
        b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
        // PT_LOAD, offset 0 at vaddr 0, 0x1000 bytes.
        b[0x40..0x44].copy_from_slice(&1u32.to_le_bytes());
        b[0x60..0x68].copy_from_slice(&0x1000u64.to_le_bytes());
        // Section 0: the string table at 0x300.
        b[0x104..0x108].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        b[0x118..0x120].copy_from_slice(&0x300u64.to_le_bytes());
        // Section 1: .dynsym at 0x200, two entries, linked to section 0.
        b[0x144..0x148].copy_from_slice(&11u32.to_le_bytes()); // SHT_DYNSYM
        b[0x158..0x160].copy_from_slice(&0x200u64.to_le_bytes());
        b[0x160..0x168].copy_from_slice(&48u64.to_le_bytes());
        b[0x178..0x180].copy_from_slice(&24u64.to_le_bytes());
        // Symbol 1: name at strtab+1, STT_FUNC, value 0x500.
        b[0x218..0x21c].copy_from_slice(&1u32.to_le_bytes());
        b[0x21c] = 2; // STT_FUNC
        b[0x220..0x228].copy_from_slice(&0x500u64.to_le_bytes());
        b[0x301..0x30a].copy_from_slice(b"SSL_write");
        b
    }

    /// A tracefs root with `uprobe_events` and, for every band of `slot`, a
    /// directory holding `format` (when given) and an `id`.
    fn fake_tracefs(root: &Path, slot: usize, format: Option<&str>, id: &str) {
        std::fs::write(root.join("uprobe_events"), "").expect("uprobe_events");
        for band in BANDS {
            let d = root.join(format!(
                "events/uprobes/{}",
                probe_name(std::process::id(), slot, band)
            ));
            std::fs::create_dir_all(&d).expect("event dir");
            if let Some(f) = format {
                std::fs::write(d.join("format"), f).expect("format");
            }
            std::fs::write(d.join("id"), id).expect("id");
        }
    }

    /// Every probe `attach_many` installed for `slot` was also removed, with
    /// the `-:name` append that leaves other tracers' probes standing.
    fn assert_installed_then_removed(root: &Path, slot: usize) {
        let events = std::fs::read_to_string(root.join("uprobe_events")).expect("uprobe_events");
        for band in BANDS {
            let name = probe_name(std::process::id(), slot, band);
            assert!(
                events.contains(&format!("p:{name} ")),
                "{name} was installed: {events}"
            );
            assert!(
                events.contains(&format!("-:{name}")),
                "{name} must be removed when the attach fails, or it stays on \
                 the library costing every process that maps it: {events}"
            );
        }
    }

    /// An empty target list is refused by name. A capture attached to nothing
    /// reads exactly like a quiet trunk.
    #[test]
    fn attaching_to_no_library_is_refused_rather_than_started() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = UprobeReader::attach_many(dir.path(), &[])
            .err()
            .expect("nothing to attach to")
            .to_string();
        assert!(err.contains("no TLS library to probe"), "{err}");
    }

    /// `attach` is `attach_many` for one library, and a library that cannot
    /// be read is named in the refusal.
    #[test]
    fn an_unreadable_library_is_named_in_the_refusal() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libabsent.so.3");
        let err = UprobeReader::attach(dir.path(), &lib.display().to_string(), "SSL_write")
            .err()
            .expect("an absent library cannot be probed")
            .to_string();
        assert!(
            err.starts_with(&lib.display().to_string()),
            "the operator must be told WHICH library: {err}"
        );
    }

    /// A file that is not an ELF shared object is refused with the library
    /// named, before anything is written to tracefs.
    #[test]
    fn a_library_that_is_not_elf_is_refused_before_tracefs_is_touched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libssl.so.3");
        std::fs::write(&lib, b"#!/bin/sh\necho not a library\n").expect("write");
        std::fs::write(dir.path().join("uprobe_events"), "").expect("uprobe_events");
        let err = UprobeReader::attach_many(
            dir.path(),
            &[Target {
                library: lib.clone(),
                symbol: "SSL_write".to_string(),
            }],
        )
        .err()
        .expect("not an ELF")
        .to_string();
        assert!(err.starts_with(&lib.display().to_string()), "{err}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("uprobe_events")).expect("read"),
            "",
            "no probe may be installed for a library that could not be resolved"
        );
    }

    /// A format the kernel published without the fields sipnab reads is
    /// refused rather than decoded at guessed offsets -- and the probes already
    /// installed are removed on the way out.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn a_format_without_the_fields_sipnab_reads_is_refused_and_the_probes_removed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libssl.so.3");
        std::fs::write(&lib, elf_exporting_ssl_write()).expect("write");
        let no_len = "format:\n\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
                      \tfield:u8 b0[];\toffset:16;\tsize:64;\tsigned:0;\n";
        fake_tracefs(dir.path(), 0, Some(no_len), "1\n");

        let err = UprobeReader::attach_many(
            dir.path(),
            &[Target {
                library: lib,
                symbol: "SSL_write".to_string(),
            }],
        )
        .err()
        .expect("a layout without len bounds nothing")
        .to_string();

        assert!(err.contains("without the fields sipnab reads"), "{err}");
        assert_installed_then_removed(dir.path(), 0);
        let events = std::fs::read_to_string(dir.path().join("uprobe_events")).expect("read");
        assert!(
            events.contains(":0x500 "),
            "the probe sits at the symbol's FILE offset: {events}"
        );
    }

    /// A band whose format file is missing fails the attach with the I/O
    /// error, and again nothing is left installed.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn a_missing_format_fails_the_attach_and_leaves_nothing_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libssl.so.3");
        std::fs::write(&lib, elf_exporting_ssl_write()).expect("write");
        fake_tracefs(dir.path(), 0, None, "1\n");

        let err = UprobeReader::attach_many(
            dir.path(),
            &[Target {
                library: lib,
                symbol: "SSL_write".to_string(),
            }],
        )
        .err()
        .expect("no format, no layout");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
        assert_installed_then_removed(dir.path(), 0);
    }

    /// When no CPU will open a ring for any band, nothing would ever be read,
    /// so the attach is refused -- and every probe it installed is removed.
    ///
    /// The ids name no tracepoint (`u64::MAX`), so the opens are refused at
    /// every privilege level; see `perf`'s test of the same refusal.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn with_no_ring_open_on_any_cpu_the_attach_is_refused_and_nothing_left_installed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libssl.so.3");
        std::fs::write(&lib, elf_exporting_ssl_write()).expect("write");
        fake_tracefs(dir.path(), 0, Some(FORMAT), &format!("{}\n", u64::MAX));

        let err = UprobeReader::attach_many(
            dir.path(),
            &[Target {
                library: lib,
                symbol: "SSL_write".to_string(),
            }],
        )
        .err()
        .expect("a reader with no ring reads nothing")
        .to_string();

        assert!(err.contains("no perf ring could be opened"), "{err}");
        assert_installed_then_removed(dir.path(), 0);
    }

    /// On a host running two TLS libraries, the second failing is reported
    /// by name, and the first library's probes -- already installed -- are
    /// released rather than left behind.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn a_later_library_failing_releases_the_probes_on_the_earlier_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let good = dir.path().join("libssl.so.3");
        std::fs::write(&good, elf_exporting_ssl_write()).expect("write");
        fake_tracefs(dir.path(), 0, Some(FORMAT), &format!("{}\n", u64::MAX));
        let absent = dir.path().join("libwolfssl.so.42");

        let err = UprobeReader::attach_many(
            dir.path(),
            &[
                Target {
                    library: good,
                    symbol: "SSL_write".to_string(),
                },
                Target {
                    library: absent.clone(),
                    symbol: "wolfSSL_write".to_string(),
                },
            ],
        )
        .err()
        .expect("the second library cannot be read")
        .to_string();

        assert!(err.starts_with(&absent.display().to_string()), "{err}");
        assert_installed_then_removed(dir.path(), 0);
    }

    /// A tracefs whose `uprobe_events` cannot be written refuses the install,
    /// and that refusal is the attach's error -- not a reader holding fewer
    /// probes than it was asked for.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn a_probe_that_cannot_be_installed_fails_the_attach() {
        let dir = tempfile::tempdir().expect("tempdir");
        let lib = dir.path().join("libssl.so.3");
        std::fs::write(&lib, elf_exporting_ssl_write()).expect("write");
        fake_tracefs(dir.path(), 0, Some(FORMAT), &format!("{}\n", u64::MAX));
        std::fs::remove_file(dir.path().join("uprobe_events")).expect("remove");

        let err = UprobeReader::attach_many(
            dir.path(),
            &[Target {
                library: lib,
                symbol: "SSL_write".to_string(),
            }],
        )
        .err()
        .expect("nowhere to install a probe");
        assert_eq!(err.kind(), io::ErrorKind::NotFound, "{err}");
    }

    /// Every probe the reader holds, across every library, is listed in
    /// installation order -- and dropping the reader removes all of them.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn probe_names_lists_every_probe_across_every_library() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::write(root.join("uprobe_events"), "").expect("uprobe_events");
        let want: Vec<String> = (0..2)
            .flat_map(|slot| BANDS.map(|band| probe_name(77, slot, band)))
            .collect();
        for name in &want {
            std::fs::create_dir_all(root.join(format!("events/uprobes/{name}"))).expect("dir");
        }
        let reader = UprobeReader {
            bands: Vec::new(),
            probes: vec![
                InstalledProbes::install(root, 77, 0, "/lib/libssl.so.3", 0x1000).expect("openssl"),
                InstalledProbes::install(root, 77, 1, "/lib/libwolfssl.so.42", 0x2000)
                    .expect("wolfssl"),
            ],
            next_ordinal: 0,
        };

        assert_eq!(
            reader.probe_names(),
            want.iter().map(String::as_str).collect::<Vec<_>>()
        );

        drop(reader);
        let events = std::fs::read_to_string(root.join("uprobe_events")).expect("read");
        for name in &want {
            assert!(
                events.contains(&format!("-:{name}")),
                "{name} removed: {events}"
            );
        }
    }

    // ── The capture entry point's failure contract ───────────────────────

    /// An attach failure is reported on the readiness channel BEFORE the
    /// function returns it, with every target named -- the launch sequence is
    /// waiting on that channel to decide whether to drop privileges.
    ///
    /// The library does not exist, so the attach fails reading it, before
    /// the real tracefs is touched at all.
    #[test]
    fn a_failed_attach_is_reported_on_the_ready_channel_with_every_target_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("libssl.so.3").display().to_string();
        let targets = [crate::capture::UprobeTarget {
            library: a.clone(),
            symbol: "SSL_write".to_string(),
        }];
        let (tx, _rx) = packet_channel(16);
        let (ready_tx, ready_rx) = crossbeam_channel::bounded(1);

        let err = capture_uprobe(&targets, tx, Some(ready_tx))
            .expect_err("an absent library cannot be captured from")
            .to_string();

        let reported = ready_rx
            .try_recv()
            .expect("readiness must be answered")
            .expect_err("and the answer is a failure");
        assert_eq!(reported, err, "one message, both places");
        assert!(
            err.starts_with(&format!("uprobe capture on [{a}:SSL_write] failed:")),
            "{err}"
        );
    }

    /// With nobody waiting on readiness, the failure is still returned.
    #[test]
    fn a_failed_attach_without_a_ready_channel_still_fails() {
        let (tx, _rx) = packet_channel(16);
        let err = capture_uprobe(&[], tx, None)
            .expect_err("no target, no capture")
            .to_string();
        assert!(
            err.starts_with("uprobe capture on [] failed:") && err.contains("no TLS library"),
            "{err}"
        );
    }
}
