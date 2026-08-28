//! Deciding what a kernel uprobe delivered may be used for.
//!
//! A kernel uprobe fetch argument is a **fixed** size chosen when the probe is
//! installed, but the write it observes is whatever length the application
//! passed. Those two disagree constantly, and the disagreement is not benign:
//! measured on a live OpenSIPS, a 512-byte fetch against a 128-byte SIP message
//! returned the message followed by 384 bytes of adjacent process heap —
//! pointers, not zeros. On a SIP proxy that heap can hold other calls'
//! plaintext.
//!
//! So the rule this module exists to enforce is: **only the bytes the
//! application actually wrote may ever leave here**, and everything past that
//! is wiped rather than merely ignored.
//!
//! Sizing is banded rather than maximal for the same reason. Several probes sit
//! on one symbol, each fetching one band and filtered to it, so what the kernel
//! delivers overshoots the true length by at most one band instead of by the
//! largest message sipnab supports. The band is a bound, not a guarantee, which
//! is why the truncation below still happens.

#[cfg(all(feature = "bpf", target_os = "linux"))]
pub mod bpf;
pub mod bpf_record;
pub mod btf;
pub mod discover;
pub mod elf;
#[cfg(feature = "native")]
pub mod perf;
#[cfg(feature = "native")]
pub mod reader;
pub mod record;

/// Fetch sizes, in bytes, for the banded probe set.
///
/// 64 is the kernel's hard ceiling for a single fetch argument — `x8[65]` is
/// refused — so every band above it is several arguments side by side. 2048 is
/// where that stops being accepted, and it covers an ordinary `INVITE` with SDP.
pub const BANDS: [usize; 4] = [64, 256, 1024, 2048];

/// The largest write the banded set can carry.
#[must_use]
pub fn max_fetch() -> usize {
    BANDS[BANDS.len() - 1]
}

/// The band that will carry a write of `len` bytes: the smallest that fits.
///
/// `None` when the write is larger than every band, which is not an error — it
/// is a message sipnab can only partially read, and the caller must say so
/// rather than presenting the fragment as whole.
#[must_use]
pub fn band_for(len: usize) -> Option<usize> {
    BANDS.iter().copied().find(|&b| len <= b)
}

/// The tracefs filter that confines a probe to its band.
///
/// The kernel evaluates this **before** recording the event — verified: a
/// 64-byte probe filtered to `len <= 64` delivered nothing at all for a
/// 128-byte write — which is what keeps an oversized fetch from reaching
/// userspace in the first place.
#[must_use]
pub fn filter_for(band: usize) -> String {
    let lower = BANDS.iter().copied().take_while(|&b| b < band).last();
    match lower {
        Some(prev) => format!("len > {prev} && len <= {band}"),
        None => format!("len > 0 && len <= {band}"),
    }
}

/// SIP start-line tokens the kernel filter matches, so non-SIP writes never
/// reach userspace.
///
/// Requests begin with a method token; responses begin with `SIP/2.0`. Fourteen
/// methods plus the response form is what a filter needs to pass SIP and drop
/// everything else.
pub const SIP_START_TOKENS: [&str; 15] = [
    "INVITE",
    "ACK",
    "BYE",
    "CANCEL",
    "OPTIONS",
    "REGISTER",
    "PRACK",
    "SUBSCRIBE",
    "NOTIFY",
    "PUBLISH",
    "INFO",
    "REFER",
    "MESSAGE",
    "UPDATE",
    "SIP/2.0",
];

/// The tracefs filter for one band: in-kernel length AND content matching.
///
/// **This is the filter doing the work sngrep needs a BPF program for.** These
/// probes sit on every process that maps the library, so a filter is what makes
/// the feature affordable rather than an optimization — and the kernel
/// evaluates it BEFORE recording the event, so a non-SIP write costs a glob
/// comparison and never a ring slot or a wakeup.
///
/// Measured on a 6.8 kernel: a probe filtered to `s ~ "INVITE*"` delivered the
/// `INVITE` written through `SSL_write` and **suppressed** a non-SIP write on
/// the same connection entirely — one event, not two. The 15-token chain below
/// is accepted by the same filter parser.
///
/// The string argument exists only to be matched on. Payload still arrives
/// through the banded byte fetches, because `:string` stops at the first NUL
/// and a SIP message is not NUL-terminated.
#[must_use]
pub fn kernel_filter_for(band: usize) -> String {
    let content = SIP_START_TOKENS
        .iter()
        .map(|t| format!("s ~ \"{t}*\""))
        .collect::<Vec<_>>()
        .join(" || ");
    format!("({}) && ({content})", filter_for(band))
}

/// Plaintext a probe delivered, reduced to what may be used.
#[derive(Debug, PartialEq, Eq)]
pub struct Delivered {
    /// Exactly the bytes the application wrote, never the fetch padding.
    pub bytes: Vec<u8>,
    /// The write was longer than the largest band, so `bytes` is a prefix.
    ///
    /// Carried so a caller can refuse to treat a fragment as a whole message.
    /// A SIP message sipnab only half-read must never look like a complete one.
    pub truncated: bool,
}

/// Overwrite a buffer's tail so the fetch padding cannot outlive this call.
///
/// `write_volatile` rather than a plain loop or `fill`: the compiler is
/// entitled to delete stores to memory it can prove is never read again, which
/// is exactly this memory, and a wipe the optimiser removed is a wipe that
/// never happened.
fn wipe(buf: &mut [u8]) {
    for b in buf {
        // SAFETY: `b` is a valid, uniquely borrowed, writable byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
}

/// Reduce one delivered event to the bytes that may be used, or reject it.
///
/// `raw` is the whole fetch, padding included. `len` is what the application
/// passed, straight from the probe. Returns `None` for anything that carries no
/// usable payload, so a caller cannot accidentally act on padding alone.
#[must_use]
pub fn accept(raw: &mut [u8], len: i32) -> Option<Delivered> {
    // A zero or negative length is an ordinary event, not a fault: TLS
    // libraries call the write path with nothing to send. It was the majority
    // of what the first traces returned, so filtering it is required rather
    // than tidy — the payload for these is entirely padding.
    let len = usize::try_from(len).ok().filter(|&n| n > 0)?;

    let usable = len.min(raw.len());
    let (keep, pad) = raw.split_at_mut(usable);
    wipe(pad);

    Some(Delivered {
        bytes: keep.to_vec(),
        // Truncated when the application wrote more than reached us, whether
        // because the write exceeded every band or because the fetch was short.
        truncated: len > usable,
    })
}

/// Whether delivered plaintext is worth carrying further.
///
/// These probes sit on every process mapping the library, so a filter is what
/// makes the feature affordable at all rather than an optimization.
#[must_use]
pub fn is_interesting(bytes: &[u8]) -> bool {
    crate::sip::is_sip_message(bytes)
}

/// The tracefs directory every probe operation goes through.
pub const TRACEFS: &str = "/sys/kernel/tracing";

/// Registers holding `SSL_write(SSL *ssl, const void *buf, int num)`'s second
/// and third arguments, named the way tracefs wants them.
///
/// Arch-specific because the kernel gave no choice: `$arg2`/`$arg3`, which
/// would have been portable, are rejected outright on a 6.12 kernel — measured,
/// not assumed. So the calling convention is written down per architecture and
/// an unknown one refuses rather than guessing at a register that would read
/// whatever happens to be there.
#[must_use]
pub fn arg_registers() -> Option<(&'static str, &'static str)> {
    #[cfg(target_arch = "x86_64")]
    {
        // SysV AMD64: rdi, rsi, rdx.
        Some(("%si", "%dx"))
    }
    #[cfg(target_arch = "aarch64")]
    {
        // AAPCS64: x0, x1, x2.
        Some(("%x1", "%x2"))
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        None
    }
}

/// The probe name sipnab uses for one band of one library.
///
/// Carries the pid because `uprobe_events` is a **system-wide** namespace: two
/// sipnabs on one host, or a sipnab beside another tracer, must not collide.
///
/// Carries `slot` because one sipnab probes **several libraries at once** — a
/// host commonly runs OpenSSL and wolfSSL together, and may run several builds
/// of one flavor. Without it the second install would reuse the first's names
/// and only one library would ever be captured.
#[must_use]
pub fn probe_name(pid: u32, slot: usize, band: usize) -> String {
    format!("sipnab_{pid}_l{slot}_b{band}")
}

/// The line that installs one banded probe.
///
/// Returns `None` on an architecture whose argument registers are unknown,
/// because a probe built from guessed registers would read arbitrary memory and
/// report it as a SIP message.
#[must_use]
pub fn install_line(name: &str, library: &str, offset: u64, band: usize) -> Option<String> {
    let (buf_reg, len_reg) = arg_registers()?;
    // `s` exists to be filtered on in-kernel, not to be read: `:string` stops
    // at the first NUL and a SIP message is not NUL-terminated, so the payload
    // still comes from the banded byte fetches below.
    let mut line = format!("p:{name} {library}:0x{offset:x} s=+0({buf_reg}):string");
    // 64 bytes is the ceiling for ONE fetch argument, so a band above it is
    // several side by side rather than one larger read.
    let mut at = 0usize;
    while at < band {
        let chunk = BANDS[0].min(band - at);
        line.push_str(&format!(" b{at}=+{at}({buf_reg}):x8[{chunk}]"));
        at += chunk;
    }
    line.push_str(&format!(" len={len_reg}:s32"));
    Some(line)
}

/// The line that removes one probe, and only that probe.
///
/// `-:<name>`, appended. Never a truncation of `uprobe_events`: that file is
/// shared, and emptying it removes every other tracer's probes on the host.
/// Verified both halves on a live box — removing `-:mine` left a second probe
/// standing.
#[must_use]
pub fn remove_line(name: &str) -> String {
    format!("-:{name}")
}

/// Probes sipnab installed, removed when this drops.
///
/// The guard is the point. `uprobe_events` is kernel state that outlives the
/// process that wrote it: a sipnab that exits without removing its probes
/// leaves them attached to a production `libssl`, costing every process on the
/// host that maps it, with nothing left running to explain why.
///
/// **Close every perf ring on these probes before dropping this.** The kernel
/// refuses to remove a tracepoint that still has an open consumer, so dropping
/// the guard first leaves all of it installed. Measured: an end-to-end run that
/// dropped the guard while its rings were still open left four probes behind.
/// Rust drops struct fields in declaration order, so a type owning both must
/// declare the rings first.
pub struct InstalledProbes {
    /// Probe names, in installation order.
    names: Vec<String>,
    /// Where tracefs is mounted, so tests can point somewhere writable.
    root: std::path::PathBuf,
}

impl InstalledProbes {
    /// Install one banded probe per band over `library` at `offset`.
    ///
    /// # Errors
    ///
    /// Returns the first failure, after removing anything already installed —
    /// a half-installed set would capture some lengths and silently miss
    /// others, which reads as "that traffic did not happen".
    pub fn install(
        root: &std::path::Path,
        pid: u32,
        slot: usize,
        library: &str,
        offset: u64,
    ) -> std::io::Result<Self> {
        let mut held = Self {
            names: Vec::new(),
            root: root.to_path_buf(),
        };
        for band in BANDS {
            let name = probe_name(pid, slot, band);
            let Some(line) = install_line(&name, library, offset, band) else {
                return Err(std::io::Error::other(
                    "no known argument registers for this architecture, so a \
                     probe here would read whatever happens to be in them",
                ));
            };
            held.append("uprobe_events", &line)?;
            held.names.push(name.clone());
            held.write(
                &format!("events/uprobes/{name}/filter"),
                &kernel_filter_for(band),
            )?;
            // Deliberately NOT written: events/uprobes/<name>/enable.
            //
            // That file switches the event on for tracefs's own text readers,
            // and doing so makes the tracepoint UNOPENABLE by perf. Measured on
            // a 6.8 kernel with an identical C program: against a disabled
            // probe perf_event_open returns a descriptor, and against the same
            // probe after `echo 1 > enable` it fails with EINTR — which reads
            // as a spurious interruption and is really the two readers
            // conflicting. perf enables the event itself when it opens it, so
            // the only correct action here is to leave this alone.
        }
        Ok(held)
    }

    /// Names of the probes currently held, for tests and diagnostics.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Append a line to a tracefs control file.
    fn append(&self, rel: &str, line: &str) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(self.root.join(rel))?;
        writeln!(f, "{line}")
    }

    /// Overwrite a tracefs control file.
    fn write(&self, rel: &str, value: &str) -> std::io::Result<()> {
        std::fs::write(self.root.join(rel), value)
    }
}

impl InstalledProbes {
    /// Remove every probe this installed.
    ///
    /// # Errors
    ///
    /// The first removal failure, with the names that remain left in place so a
    /// caller can retry or report them. The common cause is a perf ring still
    /// open on the tracepoint: the kernel refuses to remove a tracepoint that
    /// still has a consumer.
    pub fn remove(&mut self) -> std::io::Result<()> {
        // Take the list first: draining in place holds a mutable borrow while
        // the writes below need an immutable one.
        let names = std::mem::take(&mut self.names);
        let mut failed = Vec::new();
        let mut first_err = None;
        for name in names.into_iter().rev() {
            // Disable first: removing an enabled probe is refused, and the
            // failure would leave it attached. install() never enables, so
            // this is a no-op for sipnab's own probes and a repair for one
            // something else switched on.
            let _ = self.write(&format!("events/uprobes/{name}/enable"), "0");
            // `-:name`, never a truncation of the shared file.
            if let Err(e) = self.append("uprobe_events", &remove_line(&name)) {
                if first_err.is_none() {
                    first_err = Some(e);
                }
                failed.push(name);
            }
        }
        self.names = failed;
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}

impl Drop for InstalledProbes {
    fn drop(&mut self) {
        if let Err(e) = self.remove() {
            // Loud, because the alternative is kernel state left on a
            // production library with nothing running to explain it. A silent
            // `let _ =` here is what let an end-to-end run leak four probes
            // without a word.
            tracing::error!(
                "failed to remove uprobe(s) {:?}: {e}. They are still attached \
                 to the target library and cost every process that maps it. \
                 Remove by hand: for each, append '-:<name>' to \
                 {}/uprobe_events — never truncate that file, it is shared",
                self.names,
                self.root.display()
            );
        }
    }
}

/// Why accepted plaintext did not become a message.
#[derive(Debug)]
pub enum IngestError {
    /// The write was longer than the largest band, so only a prefix arrived.
    ///
    /// Refused rather than parsed: a half-read `INVITE` that parses is worse
    /// than one that does not, because the result looks like a whole message
    /// with headers missing.
    Truncated {
        /// What the application actually wrote.
        wrote: usize,
        /// What reached sipnab.
        got: usize,
    },
    /// The bytes did not parse as SIP.
    NotSip(crate::error::ParseError),
}

impl std::fmt::Display for IngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { wrote, got } => write!(
                f,
                "the process wrote {wrote} bytes and only {got} reached the \
                 probe, so this is a fragment. Parsing it would produce a \
                 message that looks whole and is missing headers"
            ),
            Self::NotSip(e) => write!(f, "not a SIP message: {e}"),
        }
    }
}

/// Turn accepted plaintext into a SIP message attributed to its process.
///
/// **The peer addresses are not known and are not invented.** A uprobe sees the
/// bytes an application handed its TLS library and nothing about the socket
/// underneath, so the 5-tuple that a captured packet carries simply is not
/// available here. The addresses are left unspecified and the ports zero, and
/// the message carries a
/// [`FrameSource::Uprobe`](crate::capture::packet::FrameSource::Uprobe) pointer
/// naming the process instead — which is the honest attribution, and which a
/// resolver refuses to follow rather than pretending there are bytes behind it.
///
/// # Errors
///
/// [`IngestError::Truncated`] for a fragment, and [`IngestError::NotSip`] when
/// the plaintext is something else — these probes see every process on the host
/// that maps the library.
pub fn to_message(
    accepted: &Delivered,
    pid: u32,
    comm: &str,
    ordinal: u64,
    timestamp: chrono::DateTime<chrono::Utc>,
) -> Result<crate::sip::SipMessage, IngestError> {
    if accepted.truncated {
        return Err(IngestError::Truncated {
            wrote: accepted.bytes.len(),
            got: accepted.bytes.len(),
        });
    }
    let data = bytes::Bytes::copy_from_slice(&accepted.bytes);
    let mut msg = crate::sip::parser::parse_sip_bytes(
        &data,
        timestamp,
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        0,
        0,
        crate::net::TransportProto::Tls,
    )
    .map_err(IngestError::NotSip)?;
    msg.frame = Some(crate::capture::packet::FrameRef::uprobe(comm, pid, ordinal));
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The filter must bound BOTH length and content, or one of the two jobs is
    /// not being done in the kernel.
    #[test]
    fn the_kernel_filter_bounds_length_and_content_together() {
        let f = kernel_filter_for(64);
        assert!(f.contains("len > 0 && len <= 64"), "length band: {f}");
        assert!(f.contains("s ~ \"INVITE*\""), "SIP requests: {f}");
        assert!(f.contains("s ~ \"SIP/2.0*\""), "SIP responses: {f}");
        assert!(
            f.starts_with('(') && f.contains(") && ("),
            "the two halves must both apply, not either: {f}"
        );
    }

    /// Every method sipnab claims to capture must be in the kernel filter, or
    /// it is dropped before userspace ever sees it -- which reads as "that
    /// traffic did not happen".
    #[test]
    fn every_sip_start_token_reaches_the_filter() {
        let f = kernel_filter_for(2048);
        for t in SIP_START_TOKENS {
            assert!(f.contains(&format!("s ~ \"{t}*\"")), "{t} missing from {f}");
        }
        assert_eq!(
            SIP_START_TOKENS.len(),
            15,
            "14 methods plus the response form"
        );
    }

    /// The probe must fetch the string the filter matches on, or the filter
    /// references a field that does not exist and the kernel refuses the write.
    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn the_probe_fetches_the_string_its_filter_matches_on() {
        let line = install_line("t", "/lib/libssl.so.3", 0x1000, 64).expect("known arch");
        assert!(line.contains("s=+0("), "string arg for the filter: {line}");
        assert!(line.contains(":string"), "typed as string: {line}");
        assert!(
            line.contains(":x8[64]"),
            "payload still comes from bytes: {line}"
        );
    }

    fn delivered(bytes: &[u8]) -> Delivered {
        Delivered {
            bytes: bytes.to_vec(),
            truncated: false,
        }
    }

    /// The join: plaintext from a probe becomes a message whose provenance
    /// says where it came from and refuses to claim a frame.
    #[test]
    fn accepted_plaintext_becomes_a_message_attributed_to_its_process() {
        let d = delivered(
            b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: u@x\r\nCSeq: 1 INVITE\r\n\r\n",
        );
        let msg = to_message(&d, 4321, "opensips", 9, chrono::Utc::now()).expect("parses");

        let frame = msg
            .frame
            .as_ref()
            .expect("a uprobe message still carries provenance");
        assert!(
            matches!(
                frame.source_kind(),
                crate::capture::packet::FrameSource::Uprobe { pid: 4321, .. }
            ),
            "the pointer names the process it was read from"
        );
        // Gated on the item, not the file: `capture::resolve` needs `native`,
        // and the rest of this test is true without it.
        #[cfg(feature = "native")]
        {
            let err = crate::capture::resolve::resolve(frame)
                .expect_err("there is no frame behind uprobe bytes");
            assert!(err.to_string().contains("opensips"), "and says so: {err}");
        }
    }

    /// Addresses are absent, not zero-as-a-value. A uprobe sees no socket.
    #[test]
    fn peer_addresses_are_left_unspecified_rather_than_invented() {
        let d = delivered(
            b"INVITE sip:b@example.net SIP/2.0\r\nCall-ID: u@x\r\nCSeq: 1 INVITE\r\n\r\n",
        );
        let msg = to_message(&d, 1, "p", 0, chrono::Utc::now()).unwrap();
        assert!(msg.src_addr.is_unspecified(), "no socket was observed");
        assert_eq!(msg.src_port, 0);
        assert_eq!(msg.transport, crate::net::TransportProto::Tls);
    }

    /// A fragment must not parse into something that looks whole.
    #[test]
    fn a_truncated_read_is_refused_rather_than_parsed() {
        let d = Delivered {
            bytes: b"INVITE sip:b@x SIP/2.0\r\n".to_vec(),
            truncated: true,
        };
        let err =
            to_message(&d, 1, "p", 0, chrono::Utc::now()).expect_err("a fragment is not a message");
        assert!(matches!(err, IngestError::Truncated { .. }), "{err}");
    }

    /// These probes see every process mapping the library.
    #[test]
    fn non_sip_plaintext_does_not_become_a_message() {
        let d = delivered(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(matches!(
            to_message(&d, 1, "curl", 0, chrono::Utc::now()),
            Err(IngestError::NotSip(_))
        ));
    }

    #[test]
    fn a_probe_name_is_unique_per_process_library_and_band() {
        assert_eq!(probe_name(42, 0, 64), "sipnab_42_l0_b64");
        assert_ne!(
            probe_name(42, 0, 64),
            probe_name(43, 0, 64),
            "two sipnabs must not collide"
        );
        assert_ne!(
            probe_name(42, 0, 64),
            probe_name(42, 0, 256),
            "nor two bands"
        );
        // A host running OpenSSL and wolfSSL is probed on both at once, and a
        // host running three builds of one flavor on all three. Same pid,
        // same band, different library: the name must still differ or the
        // second install overwrites the first and captures only one of them.
        assert_ne!(
            probe_name(42, 0, 64),
            probe_name(42, 1, 64),
            "nor two libraries probed by one sipnab"
        );
    }

    /// Removal must name the probe. Truncating `uprobe_events` would remove
    /// every other tracer's probes on the host.
    #[test]
    fn removal_names_one_probe_and_is_an_append() {
        let line = remove_line("sipnab_42_b64");
        assert_eq!(line, "-:sipnab_42_b64");
        assert!(
            !line.is_empty(),
            "an empty write would truncate the shared file"
        );
    }

    #[test]
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn a_band_is_built_from_64_byte_fetches_because_that_is_the_ceiling() {
        let line = install_line("t", "/lib/libssl.so.3", 0x3e110, 256).expect("known arch");
        assert_eq!(
            line.matches(":x8[64]").count(),
            4,
            "256 = four 64-byte fetches"
        );
        assert!(line.contains("p:t /lib/libssl.so.3:0x3e110"));
        assert!(line.ends_with(":s32"), "the length argument comes last");
        assert!(
            line.contains("b0=+0(") && line.contains("b64=+64("),
            "each fetch reads its own offset: {line}"
        );
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn x86_64_uses_the_sysv_argument_registers() {
        let line = install_line("t", "/l", 0, 64).expect("x86_64 is known");
        assert!(line.contains("(%si)"), "second argument is rsi: {line}");
        assert!(line.contains("len=%dx"), "third argument is rdx: {line}");
    }

    #[test]
    #[cfg(target_arch = "aarch64")]
    fn aarch64_uses_the_aapcs64_argument_registers() {
        let line = install_line("t", "/l", 0, 64).expect("aarch64 is known");
        assert!(line.contains("(%x1)"), "second argument is x1: {line}");
        assert!(line.contains("len=%x2"), "third argument is x2: {line}");
    }

    /// A removal that fails must leave the names behind, not pretend success.
    /// The kernel refuses to remove a tracepoint with an open perf consumer,
    /// and an end-to-end run really did leak four probes that way.
    #[test]
    fn a_failed_removal_is_reported_and_keeps_the_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("uprobe_events"), "").unwrap();
        for band in BANDS {
            let d = root.join(format!("events/uprobes/{}", probe_name(8, 0, band)));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("filter"), "").unwrap();
            std::fs::write(d.join("enable"), "").unwrap();
        }
        let mut held = InstalledProbes::install(root, 8, 0, "/lib/libssl.so.3", 0x1000).unwrap();

        // Stand in for the kernel refusing while a consumer is open.
        let ev = root.join("uprobe_events");
        let mut perms = std::fs::metadata(&ev).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o444);
        }
        std::fs::set_permissions(&ev, perms).unwrap();

        let err = held
            .remove()
            .expect_err("an unwritable control file must fail");
        let _ = err;
        assert_eq!(
            held.names().len(),
            BANDS.len(),
            "the names of probes still installed must survive, so the failure \
             can be reported and retried rather than forgotten"
        );

        // Let the guard clean up for real.
        let mut perms = std::fs::metadata(&ev).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o644);
        }
        std::fs::set_permissions(&ev, perms).unwrap();
    }

    /// The guard is the safety property: probes are kernel state that outlives
    /// the process, so dropping must remove every one it installed.
    #[test]
    fn dropping_the_guard_removes_every_probe_it_installed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("uprobe_events"), "").unwrap();
        for band in BANDS {
            let d = root.join(format!("events/uprobes/{}", probe_name(7, 0, band)));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("filter"), "").unwrap();
            std::fs::write(d.join("enable"), "").unwrap();
        }

        let held = InstalledProbes::install(root, 7, 0, "/lib/libssl.so.3", 0x1000)
            .expect("install into the fake tracefs");
        for band in BANDS {
            let enable = root.join(format!("events/uprobes/{}/enable", probe_name(7, 0, band)));
            assert_eq!(
                std::fs::read_to_string(&enable).unwrap(),
                "",
                "install must NOT write enable: a tracepoint switched on through \
                 tracefs cannot then be opened by perf, which fails with a \
                 misleading EINTR"
            );
        }
        assert_eq!(held.names().len(), BANDS.len(), "one probe per band");
        let installed = std::fs::read_to_string(root.join("uprobe_events")).unwrap();
        assert_eq!(
            installed.lines().filter(|l| l.starts_with("p:")).count(),
            BANDS.len()
        );

        drop(held);

        let after = std::fs::read_to_string(root.join("uprobe_events")).unwrap();
        for band in BANDS {
            let name = probe_name(7, 0, band);
            assert!(
                after.contains(&format!("-:{name}")),
                "drop must remove {name}: {after}"
            );
        }
        assert!(
            !after.trim().is_empty(),
            "removal is an APPEND of -:name; an empty file would mean sipnab \
             truncated shared kernel state and took other tracers with it"
        );
    }

    /// A host running OpenSSL and wolfSSL together is the ordinary case. Both
    /// probe sets must exist at once, and both must be removed.
    #[test]
    fn two_libraries_probed_at_once_do_not_collide_and_both_are_released() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("uprobe_events"), "").unwrap();
        for slot in 0..2 {
            for band in BANDS {
                let d = root.join(format!("events/uprobes/{}", probe_name(9, slot, band)));
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join("filter"), "").unwrap();
                std::fs::write(d.join("enable"), "").unwrap();
            }
        }

        let openssl =
            InstalledProbes::install(root, 9, 0, "/lib/libssl.so.3", 0x1000).expect("openssl");
        let wolfssl =
            InstalledProbes::install(root, 9, 1, "/lib/libwolfssl.so.42", 0x2000).expect("wolfssl");

        let installed = std::fs::read_to_string(root.join("uprobe_events")).unwrap();
        assert_eq!(
            installed.lines().filter(|l| l.starts_with("p:")).count(),
            BANDS.len() * 2,
            "one probe set per library, not one set overwritten by the other"
        );
        let names: std::collections::BTreeSet<String> = openssl
            .names()
            .iter()
            .chain(wolfssl.names().iter())
            .cloned()
            .collect();
        assert_eq!(
            names.len(),
            BANDS.len() * 2,
            "every probe name distinct, or the second install silently replaces \
             the first and only one library is ever captured"
        );
        assert!(
            installed.contains("/lib/libssl.so.3:0x1000")
                && installed.contains("/lib/libwolfssl.so.42:0x2000"),
            "each set points at its own library and offset: {installed}"
        );

        drop(openssl);
        drop(wolfssl);

        let after = std::fs::read_to_string(root.join("uprobe_events")).unwrap();
        for name in &names {
            assert!(
                after.contains(&format!("-:{name}")),
                "drop must remove {name}"
            );
        }
    }

    /// THE rule. A short write inside a long fetch must yield the message and
    /// nothing else — the padding measured on a live proxy was adjacent heap.
    #[test]
    fn only_the_bytes_the_application_wrote_come_back() {
        let mut raw = vec![0xAA; 512];
        raw[..12].copy_from_slice(b"INVITE sip:x");

        let got = accept(&mut raw, 12).expect("a 12-byte write is usable");
        assert_eq!(got.bytes, b"INVITE sip:x");
        assert!(!got.truncated);
        assert_eq!(got.bytes.len(), 12, "never the 512-byte fetch");
    }

    /// Ignoring the padding is not enough: it must not survive in the buffer.
    #[test]
    fn the_padding_is_wiped_not_merely_skipped() {
        let mut raw = vec![0xAA; 128];
        raw[..4].copy_from_slice(b"SIP/");

        accept(&mut raw, 4).expect("usable");

        assert!(
            raw[4..].iter().all(|&b| b == 0),
            "adjacent process memory must not outlive the call that read it"
        );
        assert_eq!(&raw[..4], b"SIP/", "and the payload is left alone");
    }

    /// The zero-length writes were most of the first trace. They carry only
    /// padding, so acting on them would be acting on adjacent memory.
    #[test]
    fn a_zero_or_negative_length_write_is_rejected() {
        let mut raw = vec![0xAA; 64];
        assert_eq!(accept(&mut raw, 0), None, "zero-length carries no payload");
        assert_eq!(accept(&mut raw, -1), None, "a negative length is not one");
    }

    /// A message bigger than every band is a fragment, and must announce it.
    #[test]
    fn a_write_larger_than_the_fetch_is_reported_truncated() {
        let mut raw = vec![b'x'; max_fetch()];
        let got = accept(&mut raw, 9000).expect("still usable, just partial");

        assert_eq!(got.bytes.len(), max_fetch());
        assert!(
            got.truncated,
            "a half-read SIP message must never look like a complete one"
        );
    }

    /// Bands are chosen to overshoot as little as possible.
    #[test]
    fn the_smallest_band_that_fits_is_chosen() {
        assert_eq!(band_for(1), Some(64));
        assert_eq!(band_for(64), Some(64), "a band includes its own size");
        assert_eq!(
            band_for(65),
            Some(256),
            "one past a band moves up exactly one"
        );
        assert_eq!(band_for(2048), Some(2048));
        assert_eq!(band_for(2049), None, "larger than every band");
    }

    /// The filters must partition, or a write lands in two probes or none.
    #[test]
    fn the_band_filters_cover_every_length_exactly_once() {
        for len in 1..=max_fetch() {
            let matching: Vec<usize> = BANDS
                .iter()
                .copied()
                .filter(|&b| {
                    let lower = BANDS.iter().copied().take_while(|&x| x < b).last();
                    len > lower.unwrap_or(0) && len <= b
                })
                .collect();
            assert_eq!(
                matching.len(),
                1,
                "length {len} matched {matching:?}; bands must partition"
            );
        }
    }

    #[test]
    fn filter_text_matches_the_band_it_guards() {
        assert_eq!(filter_for(64), "len > 0 && len <= 64");
        assert_eq!(filter_for(256), "len > 64 && len <= 256");
        assert_eq!(filter_for(2048), "len > 1024 && len <= 2048");
    }

    /// These probes see every process on the box mapping the library.
    #[test]
    fn non_sip_plaintext_is_filtered_out() {
        assert!(is_interesting(b"INVITE sip:b@example.net SIP/2.0\r\n\r\n"));
        assert!(!is_interesting(b"GET /index.html HTTP/1.1\r\n\r\n"));
        assert!(!is_interesting(&[0u8; 32]));
    }
}
