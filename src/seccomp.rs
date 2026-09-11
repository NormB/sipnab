// SPDX-License-Identifier: MIT OR Apache-2.0

//! Seccomp, in the one mode that cannot end a capture: logging.
//!
//! # Why only logging, and why that is the useful half
//!
//! [`docs/design/syscall-sandbox.md`](../../docs/design/syscall-sandbox.md)
//! §8 sequences the syscall sandbox in four steps and puts the *enforcing*
//! filter last, for one reason: an allowlist has to be derived from a real
//! run, and a mis-derived list kills the process on a capture box during the
//! incident the capture was started for. §3 sets out the derivation and §9
//! left one question open — whether the kernel's own logging route is usable
//! on an ordinary host, or whether it needs an audit daemon nobody has
//! installed.
//!
//! It is usable, and this module is that answer made reproducible. A filter
//! whose only action is `SECCOMP_RET_LOG` records every syscall the process
//! makes, **allows all of them**, and can no more kill the process than a
//! comment can. Run it over the corpus, read the records back, and the
//! allowlist writes itself from evidence rather than from a guess.
//!
//! Verified rather than assumed, on Debian 13 (kernel 6.12, x86_64) with **no
//! `auditd` and no `audit=1` on the kernel command line**: the records land in
//! the kernel ring buffer and `dmesg` prints them, one line per call, each
//! carrying `arch=`, `syscall=<nr>` and `code=0x7ffc0000`. That last field is
//! `SECCOMP_RET_LOG` itself, which is how a reader tells these records from an
//! enforcing filter's.
//!
//! # Where the records go depends on the host, and an operator has to be told
//!
//! The ring buffer is the *fallback*. When an audit daemon is connected the
//! kernel hands records to it instead, and `dmesg` shows nothing at all — so
//! guidance naming only `dmesg` sends half its readers to an empty buffer to
//! conclude the filter never installed. This development host is that case:
//! `auditctl -s` reports a connected daemon, `dmesg` carries not one seccomp
//! record, and the filter is demonstrably loaded. `ausearch -m SECCOMP` is the
//! other route, and `auditctl -s` is how a reader tells which one they are on
//! — it prints the daemon's pid, or `0` when there is none.
//!
//! # The ring buffer drops records, and a short list is the dangerous one
//!
//! Without a daemon the records fall back to `printk`, which is rate limited.
//! The kernel says so — `kauditd_printk_skb: N callbacks suppressed` — and
//! nothing else does. Measured on the lab VM while deriving sipnab's own set
//! from a twenty-second capture: 50 records arrived and roughly 1,700 were
//! dropped, and the surviving set was a short one.
//!
//! Short is the direction that kills. The artifact being derived is an
//! allowlist, and a filter missing a call ends the process making it.
//!
//! The buffer also WRAPS, and that one announces nothing. Reading the log after
//! a run keeps only the last few hundred records: on the lab VM it holds about
//! 454 audit lines, and three different run shapes each came back with 453 to
//! 455 — a number that describes the buffer rather than any run. Reading the
//! buffer after a twenty-second capture returned 12 distinct syscalls; streaming
//! the same shape with `dmesg --follow` returned 21. Nine missing entries is
//! nine ways to kill the process the list was built for.
//!
//! So a derivation streams, and it unions a corpus of run shapes rather than
//! trusting one — `docs/design/syscall-sandbox.md` §3.1 asks for exactly that,
//! and two runs of the same shape here produced different sets.
//!
//! # The cost, stated rather than hidden
//!
//! There is no allowlist here, so **every** syscall is recorded. That is what
//! makes it a derivation tool and it is also what makes it unfit to leave on:
//! a live capture doing a hundred thousand receives a second will emit a
//! hundred thousand audit records a second, and the ring buffer — or a
//! persistent journal — is where they go. Point it at a bounded offline run,
//! read the records, turn it off. The startup line says so on every run.
//!
//! # It has to reach the capture thread, and does not by default
//!
//! A seccomp filter behaves the way Landlock does unless told otherwise: it
//! covers the calling thread and threads created after it, and a sibling that
//! already exists goes on unfiltered. sipnab installs at the end of
//! `bootstrap`, after the capture thread — the one running libpcap — is
//! already spawned, so without [`SECCOMP_FILTER_FLAG_TSYNC`] this would record
//! everything except the thread it exists to characterize.
//!
//! Probed rather than read: with the flag a sibling thread's `getpriority`
//! comes back `EPERM`; without it the same call returns 20. `install` passes
//! the flag and a test fails if it stops.
//!
//! # What it is not
//!
//! It is not a control. Nothing is denied, so nothing is protected; the
//! posture a run reports must not claim otherwise, which is why
//! [`SeccompStatus`] has no "enforcing" variant to be mistaken for one. The
//! filesystem control that *does* deny is [`crate::sandbox`], and the two are
//! reported separately for exactly that reason.

/// One classic-BPF instruction, laid out as the kernel's `struct sock_filter`
/// (`linux/filter.h`).
///
/// `#[repr(C)]` because a `Vec<SockFilter>` is handed to the kernel by
/// pointer. The field order and widths are the ABI, not a choice.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    /// Opcode: class, size and addressing mode, OR-ed together.
    pub code: u16,
    /// Instructions to skip when a comparison is true.
    pub jt: u8,
    /// Instructions to skip when a comparison is false.
    pub jf: u8,
    /// Immediate operand: an offset for a load, a value for a compare, a
    /// return action for a return.
    pub k: u32,
}

// ── The opcodes, read out of the headers rather than remembered ─────────────

/// `BPF_LD | BPF_W | BPF_ABS` — load a 32-bit word at a fixed offset.
///
/// `linux/bpf_common.h`: `BPF_LD` is `0x00`, `BPF_W` is `0x00`, `BPF_ABS` is
/// `0x20`.
pub const BPF_LD_W_ABS: u16 = 0x20;

/// `BPF_JMP | BPF_JEQ | BPF_K` — compare the accumulator against `k`.
///
/// `BPF_JMP` is `0x05`, `BPF_JEQ` is `0x10`, `BPF_K` is `0x00`.
pub const BPF_JEQ_K: u16 = 0x15;

/// `BPF_RET | BPF_K` — return the constant in `k` as the seccomp action.
///
/// `BPF_RET` is `0x06`, `BPF_K` is `0x00`.
pub const BPF_RET_K: u16 = 0x06;

// ── The seccomp ABI ─────────────────────────────────────────────────────────

/// Byte offset of `seccomp_data.nr`, the system call number.
pub const OFFSET_NR: u32 = 0;

/// Byte offset of `seccomp_data.arch`.
///
/// `struct seccomp_data` opens `int nr; __u32 arch;`, so `arch` sits at 4.
/// Checking it is not optional: on a multi-ABI kernel a 32-bit entry point
/// renumbers every call, and a filter that matched numbers without pinning
/// the architecture would be matching a different set of syscalls entirely.
pub const OFFSET_ARCH: u32 = 4;

/// `SECCOMP_RET_LOG`: allow the call, and record it.
pub const SECCOMP_RET_LOG: u32 = 0x7ffc_0000;

/// `SECCOMP_RET_ALLOW`: allow the call, silently.
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// `SECCOMP_RET_ERRNO`: refuse the call, returning `k & 0xffff` as `errno`.
///
/// Present so a test can prove a filter is genuinely loaded — a program that
/// only ever allows is indistinguishable from no program at all. Nothing in
/// the shipped path builds one.
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// `SECCOMP_FILTER_FLAG_TSYNC`: apply the filter to every thread, not just
/// this one.
///
/// Not optional here, and the reason is measured rather than assumed. A filter
/// installed without it reaches the calling thread and threads created after
/// it — a sibling that already exists goes on making the calls the filter
/// covers. Probed on this host: with the flag a sibling's `getpriority` comes
/// back `EPERM`; without it the same call returns 20.
///
/// sipnab installs at the end of `bootstrap`, after the capture thread — the
/// one running libpcap — is already spawned. Without this flag the instrument
/// would record everything except the thread it exists to characterize.
pub const SECCOMP_FILTER_FLAG_TSYNC: libc::c_uint = 1;

/// `SECCOMP_RET_KILL_PROCESS`: end the whole process, with the syscall number
/// recorded by the kernel.
///
/// The only action here that can end a run, reached only by `--seccomp
/// enforce`. `docs/design/syscall-sandbox.md` §3.2 chose it over `ERRNO`
/// because an `EPERM` from `openat` on the output path produces a run that
/// captures happily and writes nothing, and a confident wrong answer is worse
/// than a loud death.
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// `SECCOMP_SET_MODE_FILTER`, the `seccomp(2)` operation.
pub const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;

/// `AUDIT_ARCH_AARCH64` — `EM_AARCH64| __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_AARCH64: u32 = 0xc000_00b7;

/// `AUDIT_ARCH_X86_64` — `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

/// The most syscall numbers [`build_program`] can encode.
///
/// A classic-BPF jump offset is a `u8`. The first compare has to be able to
/// reach the final `RET`, which is `n` instructions further on for a list of
/// `n`, and the architecture check has to reach one past that. So 254 entries
/// is the ceiling, and one more would silently emit a jump to the wrong
/// instruction rather than fail — the shape of defect this constant exists to
/// turn into a refusal.
pub const MAX_ALLOWLIST: usize = 254;

/// Why a filter could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// More syscall numbers than a `u8` jump offset can reach past.
    TooManyEntries {
        /// How many were asked for.
        asked: usize,
        /// The most that can be encoded.
        limit: usize,
    },
    /// A syscall number outside the 32-bit space `seccomp_data.nr` holds.
    ///
    /// `nr` is a signed 32-bit field and the compare operand is unsigned, so
    /// anything outside `0..=i32::MAX` could never match and asking for it is
    /// a mistake worth reporting rather than encoding.
    UnrepresentableSyscall(i64),
}

impl std::fmt::Display for ProgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyEntries { asked, limit } => write!(
                f,
                "{asked} syscalls asked for and a classic-BPF jump reaches {limit}; \
                 a longer list needs a different program shape, not a wider jump"
            ),
            Self::UnrepresentableSyscall(nr) => write!(
                f,
                "syscall number {nr} is outside the 0..=2147483647 that \
                 seccomp_data.nr can hold, so no call could ever match it"
            ),
        }
    }
}

/// Build the filter program: allow `allow`, take `fallback` for everything
/// else, and take `fallback` for any other architecture.
///
/// Pure, and takes the architecture token as an argument rather than reading
/// it, so the aarch64 program can be built and asserted on an x86_64 host and
/// the other way round. Every number the kernel will act on is decided here.
///
/// # The program
///
/// ```text
///   0  LD  W ABS  [arch]
///   1  JEQ arch_token          jt=0  jf=(n+1)   -> fall through, or fallback
///   2  LD  W ABS  [nr]
///   3  JEQ allow[0]            jt=n  jf=0
///   ..
/// 3+i  JEQ allow[i]            jt=n-i  jf=0
/// 3+n  RET fallback
/// 4+n  RET ALLOW
/// ```
///
/// A jump lands at `pc + 1 + offset`, which is why the last compare carries
/// `jt = 1` rather than `0`: zero would fall onto the fallback it is trying
/// to skip.
///
/// # Errors
///
/// [`ProgramError::TooManyEntries`] when `allow` is longer than
/// [`MAX_ALLOWLIST`], and [`ProgramError::UnrepresentableSyscall`] for a
/// number `seccomp_data.nr` could never carry.
pub fn build_program(
    arch: u32,
    allow: &[i64],
    fallback: u32,
) -> Result<Vec<SockFilter>, ProgramError> {
    if allow.len() > MAX_ALLOWLIST {
        return Err(ProgramError::TooManyEntries {
            asked: allow.len(),
            limit: MAX_ALLOWLIST,
        });
    }
    for &nr in allow {
        if !(0..=i64::from(i32::MAX)).contains(&nr) {
            return Err(ProgramError::UnrepresentableSyscall(nr));
        }
    }

    let n = allow.len();
    let mut prog = Vec::with_capacity(n + 5);

    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_ARCH,
    });
    // A wrong architecture skips every compare and the `RET ALLOW` with them.
    let jf_to_fallback = u8::try_from(n + 1).map_err(|_| ProgramError::TooManyEntries {
        asked: n,
        limit: MAX_ALLOWLIST,
    })?;
    prog.push(SockFilter {
        code: BPF_JEQ_K,
        jt: 0,
        jf: jf_to_fallback,
        k: arch,
    });
    prog.push(SockFilter {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: OFFSET_NR,
    });
    for (i, &nr) in allow.iter().enumerate() {
        // Distance from this compare to the trailing `RET ALLOW`.
        let jt = u8::try_from(n - i).map_err(|_| ProgramError::TooManyEntries {
            asked: n,
            limit: MAX_ALLOWLIST,
        })?;
        prog.push(SockFilter {
            code: BPF_JEQ_K,
            jt,
            jf: 0,
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            k: nr as u32,
        });
    }
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: fallback,
    });
    prog.push(SockFilter {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });
    Ok(prog)
}

/// The `AUDIT_ARCH_*` token for the architecture this binary was built for, or
/// `None` where the value has not been established.
///
/// `None` rather than a guess. A filter installed with the wrong token matches
/// nothing, which for a logging filter means silence — and silence reads
/// exactly like a clean run.
#[must_use]
pub fn audit_arch() -> Option<u32> {
    #[cfg(target_arch = "aarch64")]
    {
        Some(AUDIT_ARCH_AARCH64)
    }
    #[cfg(target_arch = "x86_64")]
    {
        Some(AUDIT_ARCH_X86_64)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        None
    }
}

// ── The derived allowlist ───────────────────────────────────────────────────

/// The feature set the allowlists below were derived against.
///
/// A build with more features makes more syscalls, and an allowlist is only
/// true for the build it was derived from. `--seccomp enforce` refuses on a
/// binary whose features differ rather than enforcing a list that was never
/// about it, because the failure mode of guessing here is a dead capture.
pub const DERIVED_FEATURES: &str =
    "native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,bpf,vcon";

/// The environment variable naming a locally derived allowlist.
///
/// Enforcement reads its list from here and from nowhere else, because a list
/// baked into a binary is a list derived somewhere its operator has never been.
/// See [`DERIVED_ALLOWLIST`] for the run that proved it.
pub const ALLOWLIST_ENV: &str = "SIPNAB_SECCOMP_ALLOWLIST";

/// Syscalls an x86_64 sipnab makes after the filter installs.
///
/// # Provenance, because a list with none is a guess
///
/// Derived 2026-09-11 by `scripts/derive-seccomp-allowlist.sh` against the
/// published 0.5.165 `x86_64-unknown-linux-gnu` artifact, on Debian 13 (kernel
/// 6.12, no `auditd`, `printk_ratelimit=0`). Sixteen shapes, 29,048 records,
/// nothing suppressed, verdict `SETTLED` with three shapes in a row adding
/// nothing.
///
/// # What each shape contributed, because the shape list is the real artifact
///
/// Seven offline shapes found 16 syscalls between them and the last six of
/// those added nothing at all. The first LIVE shape added six more. `--api`
/// added EIGHTEEN — socket, bind, listen, accept and the async runtime they
/// pull in — and `--metrics` and the HEP listener one each. A list derived
/// before the server shapes ran would have killed every run that turns a
/// server on, which is why the script refuses a union that is still growing.
///
/// # It is a REFERENCE. Enforcement does not use it.
///
/// This list killed a process. It settled on the lab VM across sixteen shapes
/// and 29,048 records, and on a GitHub runner — same architecture, same
/// program, different glibc and different environment — the first run under it
/// died by signal. `the_derived_list_survives_the_work_it_was_derived_for`
/// caught that in CI, which is why the gate asserts SURVIVAL rather than a
/// denial: a filter that kills is easy to demonstrate and worthless to.
///
/// So an allowlist is per-HOST, not merely per-architecture and per-build.
/// `--seccomp enforce` reads its list from [`ALLOWLIST_ENV`] and refuses
/// without one. This constant remains the worked example the tests drive and
/// the documentation cites, and nothing enforces it.
#[cfg(target_arch = "x86_64")]
pub const DERIVED_ALLOWLIST: &[i64] = &[
    0,   // read
    1,   // write
    3,   // close
    5,   // fstat
    7,   // poll
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    16,  // ioctl
    24,  // sched_yield
    28,  // madvise
    39,  // getpid
    41,  // socket
    45,  // recvfrom
    49,  // bind
    50,  // listen
    51,  // getsockname
    53,  // socketpair
    54,  // setsockopt
    55,  // getsockopt
    60,  // exit
    72,  // fcntl
    131, // sigaltstack
    157, // prctl
    186, // gettid
    202, // futex
    204, // sched_getaffinity
    217, // getdents64
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    257, // openat
    273, // set_robust_list
    288, // accept4
    290, // eventfd2
    291, // epoll_create1
    318, // getrandom
    332, // statx
    334, // rseq
    435, // clone3
];

/// No allowlist has been derived for this architecture.
///
/// Empty rather than borrowed from x86_64. The numbers are per-ABI and a list
/// from the wrong one names a different set of calls entirely — `enforce`
/// refuses here, and the refusal names the script that would fix it.
#[cfg(not(target_arch = "x86_64"))]
pub const DERIVED_ALLOWLIST: &[i64] = &[];

/// The seccomp action a mode installs, or `None` for a mode that installs none.
///
/// One place, because a status that disagrees with the action a filter carries
/// is a status that lies. `install` built a logging filter and returned
/// `Enforcing` while the two were decided separately.
#[must_use]
pub fn intended_action(mode: SeccompMode) -> Option<u32> {
    match mode {
        SeccompMode::Off => None,
        SeccompMode::Log => Some(SECCOMP_RET_LOG),
        SeccompMode::Enforce => Some(SECCOMP_RET_KILL_PROCESS),
    }
}

/// Parse an allowlist file: one syscall number per line, `#` comments allowed.
///
/// Strict on purpose. A list is the input to something that kills, so a line
/// that is not a number is a refusal rather than a skip — a typo that silently
/// dropped an entry would shorten the list, and short is the direction that
/// ends a capture.
///
/// # Errors
///
/// The offending line and why, as a sentence.
pub fn parse_allowlist(text: &str) -> Result<Vec<i64>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        for field in line.split_whitespace() {
            let nr: i64 = field.parse().map_err(|_| {
                format!(
                    "line {}: {field:?} is not a syscall number. A list feeding a \
                     filter that kills is parsed strictly: a dropped entry shortens \
                     it, and short is what ends a capture",
                    i + 1
                )
            })?;
            if !(0..=i64::from(i32::MAX)).contains(&nr) {
                return Err(format!(
                    "line {}: {nr} is outside the range seccomp_data.nr can hold",
                    i + 1
                ));
            }
            out.push(nr);
        }
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Why enforcement must not install here, or `None` when it may.
///
/// Pure, and taking every input as an argument, for a reason a mutation
/// taught. Both refusals lived inline inside `install`; deleting the
/// architecture check SURVIVED, because on a host where the features also
/// differ the second refusal fired and the test could not tell which one had.
/// A predicate that can only be driven in one state is a predicate that is
/// mostly untested.
///
/// `derived` is how many syscalls this build carries a list for — zero means
/// none was derived for this architecture, and the numbers are per-ABI, so a
/// list from elsewhere names different calls. `features` is what this binary
/// actually carries, which has to equal what the list was derived against: a
/// build with more features makes more calls, and enforcing a list about
/// another program ends a capture.
#[must_use]
pub fn enforcement_refusal(derived: usize, arch: &str, features: &str) -> Option<String> {
    if derived == 0 {
        return Some(format!(
            "no syscall allowlist has been derived for {arch}. Derive one with \
             scripts/derive-seccomp-allowlist.sh and land it before enforcing; a list \
             borrowed from another architecture names different calls"
        ));
    }
    if features != DERIVED_FEATURES {
        return Some(format!(
            "the allowlist was derived against a build with features \
             {DERIVED_FEATURES}, and this binary carries {features}. A build with \
             different features makes different calls, so enforcing this list would be \
             enforcing a list about another program"
        ));
    }
    None
}

// ── What a run asked for, and what it got ───────────────────────────────────

/// What `--seccomp` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// No filter. The default, and the only mode fit for a live capture.
    #[default]
    Off,
    /// Record every syscall and allow every syscall.
    Log,
    /// Refuse every syscall outside the derived allowlist, fatally.
    ///
    /// The only mode that is a control, and the only one that can end a run.
    /// `SECCOMP_RET_KILL_PROCESS` is what `docs/design/syscall-sandbox.md` §3.2
    /// chose over `ERRNO`, and the reason is that an `EPERM` from `openat` on
    /// the output path produces a run that captures happily and writes nothing
    /// — a confident wrong answer, which is the failure this codebase has
    /// already had to fix once at the capture layer. A death carries the
    /// syscall number and is diagnosable.
    Enforce,
}

/// What actually happened.
///
/// A value rather than a bool, for the reason [`crate::sandbox`] gives: a
/// control that quietly did not install looks exactly like one that did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeccompStatus {
    /// Not asked for.
    Disabled,
    /// A logging filter is loaded. Nothing is denied.
    Logging,
    /// An enforcing filter is loaded, carrying `count` allowed syscalls.
    ///
    /// The one variant that means a control is in force, added when one
    /// existed. `no_status_claims_to_deny_anything` was rewritten in the same
    /// commit, and reading why is the point of having made it structural.
    Enforcing {
        /// How many syscalls the filter admits.
        count: usize,
    },
    /// This build cannot install one, and why.
    Unsupported(String),
    /// The kernel refused, and why.
    Failed(String),
}

/// The startup line for `status`, which always says what is NOT protected.
///
/// The line an operator reads has to carry the same warning the module doc
/// does, because the operator will not be reading the module doc.
#[must_use]
pub fn startup_line(status: &SeccompStatus) -> String {
    match status {
        SeccompStatus::Disabled => "Syscall logging off.".to_string(),
        SeccompStatus::Logging => "Syscall logging on: every system call is recorded and \
             every system call is allowed. This denies nothing and protects nothing — it \
             exists to derive an allowlist from a bounded run. Where the records go \
             depends on this host: `auditctl -s` prints a connected daemon's pid, and \
             then they are in `ausearch -m SECCOMP`; a pid of 0 means no daemon and the \
             records are in `dmesg`. WITHOUT A DAEMON THE KERNEL DROPS RECORDS, two \
             ways, and a derivation that misses a call produces an allowlist that \
             kills the process it was built for. It rate limits, saying so as \
             `callbacks suppressed`; set `kernel.printk_ratelimit=0` for the run. And \
             the ring buffer WRAPS, saying nothing at all — reading it afterwards \
             keeps only the last few hundred records. STREAM them instead: run \
             `dmesg --follow > run.log` for the duration and read that. \
             Turn it off afterwards — a live capture emits one record per packet and \
             will flood the log."
            .to_string(),
        SeccompStatus::Enforcing { count } => format!(
            "Syscall filter ENFORCING: {count} system calls are permitted and any other \
             ends this process immediately, with the number in the kernel log. The list \
             came from {ALLOWLIST_ENV}, which is the only place it can come from — a \
             list that settled on one machine killed the process on another of the same \
             architecture, so a list that ships in a binary is a list derived somewhere \
             you have never been. If yours was not produced by \
             scripts/derive-seccomp-allowlist.sh on THIS host, against THIS build, \
             running the features this capture uses, turn this off."
        ),
        // Mode-neutral, because these two are reached from `log` AND from
        // `enforce`. They read "Syscall logging unavailable ... Nothing is
        // recorded" until enforcement shipped, which told an operator who asked
        // for a CONTROL that a recorder was missing — a true sentence about
        // the wrong thing, and the class of defect this module has already had
        // to fix twice.
        SeccompStatus::Unsupported(why) => {
            format!("Syscall filter unavailable: {why}. No filter is in force.")
        }
        SeccompStatus::Failed(why) => {
            format!("Syscall filter could not be installed: {why}. No filter is in force.")
        }
    }
}

// ── Installing it ───────────────────────────────────────────────────────────

/// Install the logging filter across every thread of this process.
///
/// [`SECCOMP_FILTER_FLAG_TSYNC`] carries the whole claim. A seccomp filter
/// installed without it behaves the way Landlock does — the calling thread and
/// its future children — which would leave the capture thread, spawned earlier
/// in `bootstrap`, outside the filter and its syscalls unrecorded.
///
/// Requires `PR_SET_NO_NEW_PRIVS`, which the privilege drop already sets on a
/// root start; this sets it too, because an unprivileged run never reaches
/// that code and would otherwise get `EACCES` from a kernel that is working
/// perfectly.
#[cfg(target_os = "linux")]
#[must_use]
pub fn install(mode: SeccompMode) -> SeccompStatus {
    if mode == SeccompMode::Off {
        return SeccompStatus::Disabled;
    }
    let Some(arch) = audit_arch() else {
        return SeccompStatus::Unsupported(format!(
            "no AUDIT_ARCH token is established for {}",
            std::env::consts::ARCH
        ));
    };
    // Enforcing needs a list derived for THIS architecture and THIS build, and
    // both refusals are hard. A list from another ABI names a different set of
    // calls; a list from another feature set was never about this binary.
    // Enforcing either is enforcing a list about a different program, and
    // being wrong ends a capture.
    let supplied: Vec<i64>;
    let (allow, action) = if mode == SeccompMode::Enforce {
        let Some(path) = std::env::var_os(ALLOWLIST_ENV) else {
            return SeccompStatus::Unsupported(format!(
                "enforcement needs an allowlist derived ON THIS HOST, named by \
                 {ALLOWLIST_ENV}. The list that ships in this binary settled across \
                 sixteen shapes on one machine and killed the process on another of \
                 the same architecture, so it is a worked example rather than a list \
                 to enforce. Produce yours with scripts/derive-seccomp-allowlist.sh"
            ));
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                return SeccompStatus::Failed(format!(
                    "{ALLOWLIST_ENV} names {}, which could not be read: {e}",
                    path.to_string_lossy()
                ));
            }
        };
        supplied = match parse_allowlist(&text) {
            Ok(list) => list,
            Err(e) => return SeccompStatus::Failed(e),
        };
        if let Some(why) = enforcement_refusal(
            supplied.len(),
            std::env::consts::ARCH,
            &crate::cli::compiled_features().join(","),
        ) {
            return SeccompStatus::Unsupported(why);
        }
        (
            supplied.as_slice(),
            intended_action(mode).unwrap_or(SECCOMP_RET_KILL_PROCESS),
        )
    } else {
        // Logging takes no allowlist: the point is to record everything.
        (
            [].as_slice(),
            intended_action(mode).unwrap_or(SECCOMP_RET_LOG),
        )
    };
    let allow_len = allow.len();
    let prog = match build_program(arch, allow, action) {
        Ok(p) => p,
        Err(e) => return SeccompStatus::Failed(e.to_string()),
    };
    if let Err(e) = load(&prog, SECCOMP_FILTER_FLAG_TSYNC) {
        return SeccompStatus::Failed(e);
    }
    // Read it back. `load` returning `Ok` says the syscall did not report an
    // error; it does not say a filter is in force, and the difference is the
    // whole failure mode this module's status enum exists for. A mutation
    // that made `install` report success without calling the kernel at all
    // SURVIVED every behavioral gate in `seccomp_child_test` until this
    // check existed — an allowing filter and no filter look identical from
    // the outside, which is exactly what makes the readback load-bearing here
    // and merely reassuring for a filter that denies.
    if !in_filter_mode() {
        return SeccompStatus::Failed(
            "the kernel accepted the filter and then reported no filter mode;              nothing is being recorded"
                .to_string(),
        );
    }
    if mode == SeccompMode::Enforce {
        return SeccompStatus::Enforcing { count: allow_len };
    }
    SeccompStatus::Logging
}

/// Whether this process is running under a seccomp *filter* right now.
///
/// `prctl(PR_GET_SECCOMP)` answers 0 for none, 1 for strict mode and 2 for a
/// filter. Necessary and not sufficient, as
/// [`docs/design/syscall-sandbox.md`](../../docs/design/syscall-sandbox.md)
/// §7.1 puts it: it proves a filter exists, never that the filter is the one
/// that was asked for.
#[cfg(target_os = "linux")]
#[must_use]
pub fn in_filter_mode() -> bool {
    // SAFETY: `PR_GET_SECCOMP` takes no pointers and returns the mode.
    let mode = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
    mode >= 0 && libc::c_uint::try_from(mode).is_ok_and(|m| m == libc::SECCOMP_MODE_FILTER)
}

/// Install the logging filter — not on this platform.
#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn install(mode: SeccompMode) -> SeccompStatus {
    if mode == SeccompMode::Off {
        return SeccompStatus::Disabled;
    }
    SeccompStatus::Unsupported("seccomp is a Linux facility".to_string())
}

/// Hand `prog` to the kernel with `flags`, setting `PR_SET_NO_NEW_PRIVS` first.
///
/// `flags` is a parameter rather than a constant inside so a test can install
/// the same program with and without [`SECCOMP_FILTER_FLAG_TSYNC`] and observe
/// the difference on a sibling thread. That difference is the only reason the
/// flag is in the shipped path, and a rule nothing can drive is a rule nobody
/// can check.
///
/// # Errors
///
/// The failing call and its `errno`, as a sentence — except under thread sync,
/// where the kernel reports the thread that could not be synchronized as a
/// POSITIVE return value rather than `-1`. Reading that as success is the
/// obvious mistake, and reading it as an `errno` is the next one.
#[cfg(target_os = "linux")]
pub fn load(prog: &[SockFilter], flags: libc::c_uint) -> Result<(), String> {
    // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes an int and touches no
    // memory this process owns.
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(format!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let len = u16::try_from(prog.len())
        .map_err(|_| format!("{} instructions is more than a filter may hold", prog.len()))?;
    let fprog = libc::sock_fprog {
        len,
        filter: prog.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };
    // SAFETY: `fprog` points at `prog`, which outlives the call, and `len` is
    // its length. The kernel copies the program before returning.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            flags,
            std::ptr::from_ref(&fprog),
        )
    };
    if rc > 0 {
        // Measured, because the obvious sentence here is wrong. A failed
        // thread sync returns a POSITIVE thread id rather than -1, leaves
        // `errno` at 0, and installs NOTHING — a probe with a sibling holding
        // a different filter returned 545951 and left the caller's
        // `PR_GET_SECCOMP` at 0. Saying the process ended up "partly covered"
        // would send an operator hunting for a filter that is not there.
        return Err(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER) could not synchronize thread {rc} to the \
             filter and installed nothing; the process is entirely unfiltered"
        ));
    }
    if rc != 0 {
        return Err(format!(
            "seccomp(SECCOMP_SET_MODE_FILTER) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program a run with no allowlist installs, instruction by
    /// instruction.
    ///
    /// Every field is pinned, not just the ones that look interesting: a
    /// layout test that checks some fields passes while the rest drift.
    #[test]
    fn an_empty_allowlist_logs_everything_on_the_right_architecture() {
        let prog = build_program(AUDIT_ARCH_X86_64, &[], SECCOMP_RET_LOG).expect("builds");
        assert_eq!(
            prog,
            vec![
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: OFFSET_ARCH
                },
                SockFilter {
                    code: BPF_JEQ_K,
                    jt: 0,
                    jf: 1,
                    k: AUDIT_ARCH_X86_64
                },
                SockFilter {
                    code: BPF_LD_W_ABS,
                    jt: 0,
                    jf: 0,
                    k: OFFSET_NR
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_LOG
                },
                SockFilter {
                    code: BPF_RET_K,
                    jt: 0,
                    jf: 0,
                    k: SECCOMP_RET_ALLOW
                },
            ]
        );
    }

    /// Every compare reaches the trailing `RET ALLOW`, and only it.
    ///
    /// The arithmetic that is easy to write down wrong and impossible to see
    /// wrong: a jump lands at `pc + 1 + offset`, so an off-by-one puts an
    /// allowed syscall on the fallback action. Walked rather than asserted as
    /// a constant, because a constant would encode the same mistake twice.
    #[test]
    fn every_compare_jumps_to_the_allow_and_falls_through_to_the_next() {
        let allow: Vec<i64> = (100..140).collect();
        let prog = build_program(AUDIT_ARCH_AARCH64, &allow, SECCOMP_RET_LOG).expect("builds");
        let n = allow.len();
        let ret_fallback = 3 + n;
        let ret_allow = 4 + n;
        assert_eq!(prog.len(), ret_allow + 1);

        for (i, _) in allow.iter().enumerate() {
            let pc = 3 + i;
            let taken = pc + 1 + usize::from(prog[pc].jt);
            assert_eq!(
                taken, ret_allow,
                "compare {i} jumps to instruction {taken}, not the RET ALLOW at {ret_allow}"
            );
            let fallen = pc + 1 + usize::from(prog[pc].jf);
            let expected = if i + 1 < n { pc + 1 } else { ret_fallback };
            assert_eq!(
                fallen, expected,
                "compare {i} falls through to {fallen}, not {expected}"
            );
        }
        assert_eq!(prog[ret_fallback].k, SECCOMP_RET_LOG);
        assert_eq!(prog[ret_allow].k, SECCOMP_RET_ALLOW);
    }

    /// A wrong architecture reaches the fallback, never the allow.
    ///
    /// The branch a same-architecture test can never exercise, and the one
    /// that matters most: on a multi-ABI kernel the numbers mean something
    /// else entirely, so an allowlist matched without the architecture check
    /// is an allowlist for the wrong syscalls.
    #[test]
    fn a_foreign_architecture_lands_on_the_fallback() {
        for n in [0usize, 1, 7, 254] {
            let allow: Vec<i64> = (0..n as i64).collect();
            let prog = build_program(AUDIT_ARCH_X86_64, &allow, SECCOMP_RET_LOG).expect("builds");
            let taken = 1 + 1 + usize::from(prog[1].jf);
            assert_eq!(
                taken,
                3 + n,
                "with {n} entries the architecture mismatch lands on {taken}, not the \
                 fallback at {}",
                3 + n
            );
            assert_eq!(prog[taken].code, BPF_RET_K);
            assert_eq!(prog[taken].k, SECCOMP_RET_LOG);
        }
    }

    /// The longest list that fits still encodes reachable jumps.
    #[test]
    fn the_largest_allowlist_still_encodes() {
        let allow: Vec<i64> = (0..MAX_ALLOWLIST as i64).collect();
        let prog = build_program(AUDIT_ARCH_AARCH64, &allow, SECCOMP_RET_LOG).expect("builds");
        assert_eq!(
            prog[3].jt, 254,
            "the first compare must reach the RET ALLOW"
        );
        assert_eq!(prog[1].jf, 255, "the arch check must reach the fallback");
        assert_eq!(prog.len(), MAX_ALLOWLIST + 5);
    }

    /// One more than fits is refused, not silently mis-encoded.
    ///
    /// The failure this refuses is invisible: `u8` truncation would emit a
    /// jump to a real instruction, just the wrong one, and the filter would
    /// load and run and allow the wrong calls.
    #[test]
    fn a_list_too_long_for_a_jump_offset_is_refused() {
        let allow: Vec<i64> = (0..=MAX_ALLOWLIST as i64).collect();
        assert_eq!(
            build_program(AUDIT_ARCH_AARCH64, &allow, SECCOMP_RET_LOG),
            Err(ProgramError::TooManyEntries {
                asked: MAX_ALLOWLIST + 1,
                limit: MAX_ALLOWLIST
            })
        );
    }

    /// A number `seccomp_data.nr` cannot hold is refused.
    #[test]
    fn a_syscall_number_outside_the_field_is_refused() {
        for nr in [-1i64, i64::from(i32::MAX) + 1, i64::MAX] {
            assert_eq!(
                build_program(AUDIT_ARCH_X86_64, &[nr], SECCOMP_RET_LOG),
                Err(ProgramError::UnrepresentableSyscall(nr)),
                "syscall {nr} was encoded rather than refused"
            );
        }
        assert!(build_program(AUDIT_ARCH_X86_64, &[i64::from(i32::MAX)], SECCOMP_RET_LOG).is_ok());
    }

    /// The two architectures produce different programs.
    ///
    /// Guards the token, which is one hex constant away from matching nothing
    /// — and a logging filter that matches nothing is silent, which reads
    /// exactly like a clean run.
    #[test]
    fn the_architecture_token_reaches_the_program() {
        let a = build_program(AUDIT_ARCH_AARCH64, &[1, 2], SECCOMP_RET_LOG).expect("builds");
        let x = build_program(AUDIT_ARCH_X86_64, &[1, 2], SECCOMP_RET_LOG).expect("builds");
        assert_eq!(a[1].k, AUDIT_ARCH_AARCH64);
        assert_eq!(x[1].k, AUDIT_ARCH_X86_64);
        assert_ne!(a, x);
        assert_eq!(AUDIT_ARCH_AARCH64, 0xc000_00b7);
        assert_eq!(AUDIT_ARCH_X86_64, 0xc000_003e);
    }

    /// `SockFilter` is the kernel's `sock_filter`, field for field.
    ///
    /// Linux-gated because `libc::sock_filter` does not exist off Linux, and
    /// an ungated reference broke the macOS build after this shipped. The
    /// module's own types are portable; the comparison is not, and the
    /// comparison is the point.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_instruction_matches_the_kernels_layout() {
        assert_eq!(
            std::mem::size_of::<SockFilter>(),
            std::mem::size_of::<libc::sock_filter>()
        );
        assert_eq!(
            std::mem::align_of::<SockFilter>(),
            std::mem::align_of::<libc::sock_filter>()
        );
        assert_eq!(std::mem::offset_of!(SockFilter, code), 0);
        assert_eq!(std::mem::offset_of!(SockFilter, jt), 2);
        assert_eq!(std::mem::offset_of!(SockFilter, jf), 3);
        assert_eq!(std::mem::offset_of!(SockFilter, k), 4);
    }

    /// The fallback action reaches the program unchanged.
    ///
    /// A test can build a denying program even though nothing shipped does,
    /// and `seccomp_child_test` uses one to prove a filter is really loaded.
    #[test]
    fn the_fallback_action_is_whatever_the_caller_asked_for() {
        for action in [
            SECCOMP_RET_LOG,
            SECCOMP_RET_ALLOW,
            SECCOMP_RET_ERRNO | u32::from(libc::EPERM as u16),
        ] {
            let prog = build_program(AUDIT_ARCH_X86_64, &[1], action).expect("builds");
            assert_eq!(prog[prog.len() - 2].k, action);
        }
    }

    /// Off installs nothing, on every platform.
    #[test]
    fn off_installs_nothing() {
        assert_eq!(install(SeccompMode::Off), SeccompStatus::Disabled);
        assert_eq!(SeccompMode::default(), SeccompMode::Off);
    }

    /// Every startup line says what is not protected.
    ///
    /// The sentence is the product here. A line reading "seccomp active" would
    /// be true and would leave an operator believing a control is in force
    /// when nothing is denied.
    #[test]
    fn the_startup_line_never_implies_protection() {
        let logging = startup_line(&SeccompStatus::Logging);
        assert!(
            logging.contains("allowed") && logging.contains("protects nothing"),
            "the logging line must say every call is allowed: {logging}"
        );
        assert!(
            logging.contains("dmesg") && logging.contains("ausearch"),
            "an operator has to be told BOTH places the records can be: a host with an \
             audit daemon shows nothing in dmesg, and guidance naming only dmesg sends \
             that reader to an empty buffer to conclude the filter never loaded: {logging}"
        );
        assert!(
            logging.contains("auditctl -s"),
            "the line has to say how to tell which of the two applies: {logging}"
        );
        assert!(
            logging.contains("flood"),
            "the line must carry the cost of leaving it on: {logging}"
        );
        for status in [
            SeccompStatus::Unsupported("no kernel support".to_string()),
            SeccompStatus::Failed("EACCES".to_string()),
        ] {
            let line = startup_line(&status);
            assert!(
                line.contains("No filter is in force"),
                "a control that did not install must say so, without naming a \
                 mode nobody asked for: {line}"
            );
            assert!(
                !line.contains("logging"),
                "a refusal reached from `enforce` calls itself a logging \
                 failure: {line}"
            );
        }
        assert_eq!(
            startup_line(&SeccompStatus::Disabled),
            "Syscall logging off."
        );
    }

    /// A failed thread sync says nothing was installed, not "partly".
    ///
    /// The sentence is the product. A failed sync leaves the process entirely
    /// unfiltered — probed, with a sibling holding a different filter: the call
    /// returned a positive thread id and the caller's `PR_GET_SECCOMP` stayed
    /// at 0. A message reading "partly covered" would send an operator looking
    /// for a filter that does not exist.
    #[test]
    fn a_failed_thread_sync_does_not_claim_partial_coverage() {
        let src = include_str!("seccomp.rs");
        let start = src
            .find("could not synchronize thread")
            .expect("the thread-sync failure message is still here");
        // To the end of the string literal, not a fixed count of characters.
        // This read `start + 200` until `no_structural_gate_here_slices_a_window_chosen_by_eye`
        // found it — the same expiring window that broke the readback gate one
        // commit earlier, sitting three tests away and unnoticed.
        let msg = &src[start..start + src[start..].find("\"\n").unwrap_or(0).max(1)];
        assert!(
            msg.contains("installed nothing"),
            "the thread-sync failure message must say nothing was installed: {msg}"
        );
        assert!(
            !msg.contains("partly"),
            "the message claims partial coverage, which the kernel does not \
             produce: {msg}"
        );
    }

    /// Every failure this module can report says nothing is in force.
    ///
    /// Owed for the thread-sync message, which read "partly covered and partly
    /// not" — a state the kernel does not produce. One wrong sentence is a
    /// mistake; the class is a module where SOME failure path leaves an
    /// operator believing a control is half on. So this walks every failure
    /// string in the file rather than the one that was wrong.
    #[test]
    fn no_failure_path_leaves_an_operator_thinking_a_filter_is_partly_on() {
        // Logical lines, not physical ones. A Rust string continuation ends
        // in a backslash, and the first version of this test looked only at
        // the line carrying the `Failed(` marker — so the mutation that put
        // "partly covered" back on the SECOND line of the same literal
        // survived it. A gate that reads half a sentence judges half a
        // sentence.
        let src = include_str!("seccomp.rs");
        let mut logical: Vec<(usize, String)> = Vec::new();
        let mut pending: Option<(usize, String)> = None;
        for (i, line) in src.lines().enumerate() {
            let joined = match pending.take() {
                Some((start, mut acc)) => {
                    acc.push_str(line.trim_start());
                    (start, acc)
                }
                None => (i + 1, line.to_string()),
            };
            if joined.1.trim_end().ends_with('\\') {
                pending = Some((
                    joined.0,
                    joined.1.trim_end().trim_end_matches('\\').to_string(),
                ));
            } else {
                logical.push(joined);
            }
        }
        let mut hedged = Vec::new();
        for (line_no, line) in &logical {
            if !line.contains("SeccompStatus::Failed(") && !line.contains("could not") {
                continue;
            }
            for weasel in ["partly", "partially", "some of", "may still"] {
                if line.contains(weasel) {
                    hedged.push(format!("line {line_no}: {weasel}"));
                }
            }
        }
        assert!(
            hedged.is_empty(),
            "a failure path hedges about what is in force: {hedged:?}. A seccomp \
             install either takes or does not; saying otherwise sends an \
             operator looking for a filter that is not there"
        );
    }

    /// A failure's operator line and its status agree.
    ///
    /// The second of the two owed. `startup_line` is what an operator reads and
    /// the status is what the code branches on, and the sentence was wrong while
    /// the status was right — so this drives every failure variant through the
    /// line and requires the two to say the same thing.
    #[test]
    fn a_failure_status_and_its_operator_line_say_the_same_thing() {
        for status in [
            SeccompStatus::Unsupported("no kernel support".to_string()),
            SeccompStatus::Failed("EACCES".to_string()),
            SeccompStatus::Failed(
                "could not synchronize thread 7 to the filter and installed nothing".to_string(),
            ),
        ] {
            let line = startup_line(&status);
            assert!(
                line.contains("No filter is in force"),
                "{status:?} renders as {line:?}, which does not tell an operator \
                 that nothing is in force"
            );
            assert!(
                !line.contains("Syscall logging on"),
                "a failure renders with the success sentence: {line}"
            );
        }
        // And the success variant is the only one that reads as success, so the
        // pair above cannot pass by the line being uniformly negative.
        assert!(startup_line(&SeccompStatus::Logging).contains("Syscall logging on"));
    }

    /// `install` reads the filter back before reporting success.
    ///
    /// Owed for the mutation that SURVIVED: making `install` return `Logging`
    /// without calling the kernel passed every behavioral gate, because an
    /// allowing filter and no filter are indistinguishable by their effects.
    /// Structural on purpose — the behavioral half cannot see this, which is
    /// the whole finding.
    #[test]
    fn install_reads_the_filter_back_before_reporting_success() {
        let src = include_str!("seccomp.rs");
        let start = src
            .find("pub fn install(mode: SeccompMode) -> SeccompStatus {")
            .expect("the Linux install is in this file");
        // The real body, by brace depth. A fixed-size window was here and the
        // function outgrew it the moment enforcement landed — the readback
        // moved past character 2000 and the gate reported it missing. A window
        // chosen by eye is a window that expires.
        let open = start + src[start..].find('{').expect("the function has a body");
        let mut depth = 0i32;
        let mut end = open;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &src[open..=end];
        let load = body.find("load(&prog").expect("install loads a program");
        let readback = body
            .find("in_filter_mode()")
            .expect("install reads the mode back");
        let success = body
            .find("SeccompStatus::Logging")
            .expect("install reports success somewhere");
        assert!(
            load < readback && readback < success,
            "install reports success without reading the filter back first \
             (load at {load}, readback at {readback}, success at {success}). An \
             allowing filter and no filter look identical from outside, so this \
             ordering is the only thing between them"
        );
    }

    /// The readback answers about THIS thread, not about the process.
    ///
    /// The second owed for that mutation, and it matters because the value is
    /// per-thread: `install` uses it to judge its own success, and the sibling
    /// gates use it to judge coverage. A readback that asked a process-wide
    /// question would answer both incorrectly.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_readback_is_false_in_a_process_that_installed_nothing() {
        assert!(
            !in_filter_mode(),
            "this test process reports a seccomp filter without installing one, \
             so the readback cannot distinguish a working install from a \
             missing one"
        );
        assert_eq!(install(SeccompMode::Off), SeccompStatus::Disabled);
        assert!(!in_filter_mode(), "asking for no filter left one in force");
    }

    /// The operator guidance names both places a record can land.
    ///
    /// Owed for the first draft, which named only `dmesg`. On a host with an
    /// audit daemon connected that buffer stays empty and the records go to the
    /// daemon, so half of all readers would find nothing and conclude the
    /// filter never installed. Both routes and the way to tell them apart are
    /// required in every surface an operator reads.
    #[test]
    fn every_operator_surface_names_both_record_routes() {
        let surfaces: [(&str, String); 2] = [
            ("the startup line", startup_line(&SeccompStatus::Logging)),
            (
                "the module documentation",
                // Every `//!` line, not a `take_while` from the top: the
                // first line of the file is the SPDX comment, which is `//`,
                // and a `take_while` stopped there and compared against an
                // EMPTY string. That version failed for the right reason by
                // luck; it would have passed just as happily on a module with
                // no documentation at all.
                include_str!("seccomp.rs")
                    .lines()
                    .filter(|l| l.trim_start().starts_with("//!"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        ];
        for (what, text) in surfaces {
            for route in ["dmesg", "ausearch", "auditctl"] {
                assert!(
                    text.contains(route),
                    "{what} never mentions {route}, so a reader on the other \
                     kind of host is sent to an empty buffer"
                );
            }
        }
    }

    /// Neither route is described as the only one.
    ///
    /// The second owed. Naming both and then saying "the records are in dmesg"
    /// is the same defect with more words, so the phrasing has to make the fork
    /// explicit — it says where they go DEPENDS on the host.
    #[test]
    fn the_guidance_presents_the_routes_as_a_fork_not_a_default() {
        let line = startup_line(&SeccompStatus::Logging);
        assert!(
            line.contains("depends on this host"),
            "the startup line names two routes without saying the choice \
             depends on the host, which reads as one route with an aside: {line}"
        );
        let dmesg = line.find("dmesg").expect("dmesg is named");
        let ausearch = line.find("ausearch").expect("ausearch is named");
        let auditctl = line.find("auditctl").expect("auditctl is named");
        assert!(
            auditctl < ausearch && auditctl < dmesg,
            "the line names a route before telling the reader how to find out \
             which one applies: {line}"
        );
    }

    /// The guidance says the ring-buffer route drops records.
    ///
    /// Owed for a defect this instrument shipped with. Deriving on a host with
    /// no audit daemon, the kernel rate limits the fallback and says so as
    /// `kauditd_printk_skb: N callbacks suppressed`. Measured on the lab VM
    /// while deriving sipnab's own set: 50 records arrived and about 1,700 were
    /// dropped, and the surviving set was a short one.
    ///
    /// A SHORT list is the dangerous direction. It is the input to an enforcing
    /// filter, and a filter missing a call kills the process making it — on a
    /// capture box, during the incident the capture was started for. Guidance
    /// that sends an operator to a log which silently drops is not a smaller
    /// version of the right guidance; it is the mechanism of that failure.
    #[test]
    fn the_guidance_warns_that_the_ring_buffer_route_drops_records() {
        let line = startup_line(&SeccompStatus::Logging);
        assert!(
            line.contains("DROPS RECORDS"),
            "the startup line does not tell an operator the no-daemon route \
             loses records: {line}"
        );
        assert!(
            line.contains("callbacks suppressed"),
            "the line never names the string the kernel prints when it drops \
             them, so a reader cannot check whether their own run was complete: \
             {line}"
        );
        assert!(
            line.contains("printk_ratelimit"),
            "the line names no way to stop the dropping: {line}"
        );
    }

    /// It says WHY a short list is the dangerous direction.
    ///
    /// The second owed, and the one that makes the warning act. "Some records
    /// may be missing" reads as a completeness nicety. What it actually means
    /// is that the artifact being derived kills processes when it is short, and
    /// an operator who does not know that has no reason to re-run.
    #[test]
    fn the_guidance_says_what_a_missing_record_costs() {
        let line = startup_line(&SeccompStatus::Logging);
        assert!(
            line.contains("kills the process"),
            "the line warns about dropped records without saying what a \
             derivation built from them does: {line}"
        );
        let drops = line.find("DROPS RECORDS").expect("the warning is present");
        let cost = line.find("kills the process").expect("the cost is present");
        assert!(
            drops < cost,
            "the line states the consequence before the cause, which reads as \
             two unrelated cautions: {line}"
        );
    }

    /// Every surface an operator reads carries the warning, not just one.
    ///
    /// The third owed. The flag's help and the startup line are read by
    /// different people at different times — one before the run and one during
    /// it — and a warning on only one of them is a warning half the readers
    /// never see. This is the same pairing the record-route guidance already
    /// needed, and it went wrong there first.
    #[test]
    fn both_operator_surfaces_carry_the_dropped_record_warning() {
        let cli = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli.rs"),
        )
        .expect("src/cli.rs is in the tree");
        let start = cli
            .find("pub seccomp: Option<SeccompModeArg>")
            .expect("the flag is declared");
        // Rendered, not raw. A doc comment wraps, so "kills the process" is
        // split by a newline and three slashes in the source and matches
        // nothing — the same physical-versus-logical-line mistake that let a
        // mutation survive the failure-sentence gate. Strip the markers and
        // collapse the whitespace, which is what clap shows a reader anyway.
        let help: String = cli[start.saturating_sub(2500)..start]
            .lines()
            .map(|l| l.trim_start().trim_start_matches("///").trim())
            .collect::<Vec<_>>()
            .join(" ");
        for phrase in ["DROPS RECORDS", "callbacks suppressed", "printk_ratelimit"] {
            assert!(
                help.contains(phrase),
                "the --seccomp help never says {phrase:?}, so a reader who \
                 checks the flag before running learns nothing about it"
            );
        }
        assert!(
            help.contains("kills the process"),
            "the flag's help warns about dropped records without saying what \
             they cost"
        );
    }

    /// The guidance names BOTH ways the ring buffer loses records.
    ///
    /// Owed for the second one, which is the quieter and therefore worse of
    /// the two. Rate limiting announces itself; the buffer WRAPPING announces
    /// nothing, and reading the log after a run silently keeps only the last
    /// few hundred records. On the lab VM that buffer holds about 454 audit
    /// lines, and three different run shapes each came back with 453 to 455 —
    /// a number that is the buffer's size rather than any run's behavior.
    #[test]
    fn the_guidance_names_both_ways_the_ring_buffer_loses_records() {
        let line = startup_line(&SeccompStatus::Logging);
        assert!(
            line.contains("callbacks suppressed"),
            "the rate-limit route is unnamed: {line}"
        );
        assert!(
            line.to_uppercase().contains("WRAPS"),
            "the line warns about rate limiting and not about the buffer \
             wrapping, which is the loss that announces nothing: {line}"
        );
        assert!(
            line.contains("saying nothing"),
            "the line does not tell a reader that the second loss is silent, \
             so they will look for a warning that never comes: {line}"
        );
    }

    /// And it says to stream rather than to read afterwards.
    ///
    /// The second owed. Naming a hazard without naming the way out leaves an
    /// operator with a log they now distrust and no alternative — so they use
    /// it anyway. `dmesg --follow` defeats both losses at once, which is the
    /// only instruction here that actually produces a complete list.
    #[test]
    fn the_guidance_says_to_stream_the_records_not_to_read_them_after() {
        let line = startup_line(&SeccompStatus::Logging);
        assert!(
            line.contains("dmesg --follow"),
            "the line names no way to collect a complete set: {line}"
        );
        let wraps = line.to_uppercase().find("WRAPS").expect("the hazard");
        let fix = line.find("dmesg --follow").expect("the remedy");
        assert!(
            wraps < fix,
            "the remedy is offered before the hazard it answers, which reads as \
             an unexplained preference: {line}"
        );
    }

    /// The flag's help carries the measurement, not just the warning.
    ///
    /// The third owed, and the reason is that "some records may be lost" does
    /// not move anyone. A number does: reading the buffer after a twenty-second
    /// capture returned 12 distinct syscalls where streaming returned 21. Nine
    /// missing entries in an allowlist is nine ways to kill the process it was
    /// built for.
    #[test]
    fn the_flag_help_carries_what_reading_after_the_run_actually_lost() {
        let cli = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli.rs"),
        )
        .expect("src/cli.rs is in the tree");
        let start = cli
            .find("pub seccomp: Option<SeccompModeArg>")
            .expect("the flag is declared");
        let help: String = cli[start.saturating_sub(3000)..start]
            .lines()
            .map(|l| l.trim_start().trim_start_matches("///").trim())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            help.contains("dmesg --follow"),
            "the help names no way to collect a complete set: {help}"
        );
        assert!(
            help.contains("12 distinct syscalls") && help.contains("21"),
            "the help warns without saying what the loss measured, and a \
             warning with no number reads as a caution rather than a defect: \
             {help}"
        );
    }

    /// The action a mode installs, named once so a status cannot contradict it.
    ///
    /// Owed for a defect that shipped for about a minute: `install` built a
    /// LOGGING filter and returned `Enforcing`. Every behavioral gate passed,
    /// because an allowing filter and an enforcing one are told apart only by a
    /// call that gets refused — and nothing in the runner made one.
    #[test]
    fn each_mode_names_exactly_one_action() {
        assert_eq!(intended_action(SeccompMode::Log), Some(SECCOMP_RET_LOG));
        assert_eq!(
            intended_action(SeccompMode::Enforce),
            Some(SECCOMP_RET_KILL_PROCESS)
        );
        assert_eq!(intended_action(SeccompMode::Off), None);
        assert_ne!(
            SECCOMP_RET_LOG, SECCOMP_RET_KILL_PROCESS,
            "the two actions are equal, so no test anywhere can tell a recorder \
             from a control"
        );
    }

    /// The program a mode builds carries that mode's action.
    ///
    /// The second owed, and the one that would have caught it. It checks the
    /// artifact rather than the report: build what each mode builds, and read
    /// the fallback out of the instruction the kernel will actually run.
    #[test]
    fn the_program_each_mode_builds_carries_that_modes_action() {
        for mode in [SeccompMode::Log, SeccompMode::Enforce] {
            let Some(action) = intended_action(mode) else {
                panic!("{mode:?} names no action");
            };
            let allow: &[i64] = if mode == SeccompMode::Enforce {
                &[1, 2, 3]
            } else {
                &[]
            };
            let prog = build_program(AUDIT_ARCH_X86_64, allow, action).expect("builds");
            assert_eq!(
                prog[prog.len() - 2].k,
                action,
                "{mode:?} built a program whose fallback is not its own action"
            );
        }
    }

    /// A status claiming enforcement is only reachable from the enforcing mode.
    ///
    /// The third owed, structural because the wrong pairing compiled fine and
    /// ran fine. `Enforcing` must be returned under a test of the mode, not
    /// unconditionally at the end of a shared path.
    #[test]
    fn the_enforcing_status_is_returned_only_under_a_test_of_the_mode() {
        let src = include_str!("seccomp.rs");
        let at = src
            .find("return SeccompStatus::Enforcing")
            .expect("install returns the enforcing status somewhere");
        let before = &src[at.saturating_sub(200)..at];
        assert!(
            before.contains("mode == SeccompMode::Enforce"),
            "the enforcing status is returned without testing the mode first, \
             which is how a logging install came to report enforcement: {before}"
        );
    }

    /// Enforcement refuses when no list was supplied for this host.
    ///
    /// Owed for shipping a list that killed. It settled on the lab VM across
    /// sixteen shapes and 29,048 records, and the first run under it on a
    /// GitHub runner — same architecture, same program — died by signal. An
    /// allowlist is per-HOST, so a list compiled into a binary is a list
    /// derived somewhere its operator has never been, and enforcement must not
    /// be reachable without one the operator made.
    #[cfg(target_os = "linux")]
    #[test]
    fn enforcement_refuses_when_no_list_was_supplied_for_this_host() {
        // SAFETY: reading the variable here and nothing else; the test process
        // installs no filter either way.
        let had = std::env::var_os(ALLOWLIST_ENV);
        assert!(
            had.is_none(),
            "{ALLOWLIST_ENV} is set in this test process, so this gate is \
             measuring somebody else's configuration"
        );
        let status = install(SeccompMode::Enforce);
        match status {
            SeccompStatus::Unsupported(why) => {
                assert!(
                    why.contains(ALLOWLIST_ENV),
                    "the refusal does not name the variable that would supply a \
                     list: {why}"
                );
                assert!(
                    why.contains("killed the process"),
                    "the refusal does not say WHY a shipped list is not used, so \
                     it reads as a missing-configuration nag: {why}"
                );
            }
            other => panic!(
                "enforcement installed without a supplied list: {other:?}. The \
                 list in this binary killed a process on a host it was not \
                 derived on"
            ),
        }
    }

    /// The shipped list is documented as a reference and enforced by nothing.
    ///
    /// The second owed, structural because the constant still exists and still
    /// looks authoritative. Nothing on the install path may read it, and its
    /// documentation has to say why in the place someone will look.
    #[test]
    fn the_shipped_list_is_a_reference_that_nothing_enforces() {
        let src = include_str!("seccomp.rs");
        let start = src
            .find("pub fn install(mode: SeccompMode) -> SeccompStatus {")
            .expect("the Linux install is in this file");
        let open = start + src[start..].find('{').expect("body");
        let mut depth = 0i32;
        let mut end = open;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(
            !src[open..=end].contains("DERIVED_ALLOWLIST"),
            "the install path reads the list that ships in the binary. That list \
             settled on one machine and killed the process on another of the \
             same architecture"
        );
        let doc_at = src
            .find("pub const DERIVED_ALLOWLIST")
            .expect("the reference list is in this file");
        let doc = &src[doc_at.saturating_sub(3000)..doc_at];
        assert!(
            doc.contains("killed a process") && doc.contains("REFERENCE"),
            "the reference list does not say that it killed a process or that \
             nothing enforces it, so the next reader will enforce it"
        );
    }

    /// A supplied list is parsed strictly: a bad line refuses, never skips.
    ///
    /// The third owed. The list feeds a filter that kills, so a line that
    /// silently failed to parse would SHORTEN it — and short is precisely the
    /// direction that ends a capture. Comments and blanks are fine; anything
    /// that is not a number is a refusal naming the line.
    #[test]
    fn a_supplied_list_is_parsed_strictly_rather_than_skipping_a_bad_line() {
        let good = parse_allowlist("# comment\n1\n 2 \n\n3 4\n").expect("parses");
        assert_eq!(good, vec![1, 2, 3, 4], "sorted, deduped, comments dropped");
        assert_eq!(
            parse_allowlist("1\n1\n2\n").expect("parses"),
            vec![1, 2],
            "a duplicate entry must not change the list"
        );
        let err = parse_allowlist("1\nopenat\n3\n").expect_err("a name is not a number");
        assert!(
            err.contains("line 2") && err.contains("openat"),
            "the refusal does not name the offending line: {err}"
        );
        let out_of_range = parse_allowlist("1\n-5\n").expect_err("negative is refused");
        assert!(out_of_range.contains("line 2"), "{out_of_range}");
    }

    /// An architecture with no derived list is refused, and says which.
    ///
    /// Drivable on any host because the predicate takes its inputs. Inline,
    /// this branch could not be reached on a machine whose features also
    /// differ — and deleting it survived a mutation for exactly that reason.
    #[test]
    fn enforcement_refuses_an_architecture_with_no_derived_list() {
        let why = enforcement_refusal(0, "riscv64", DERIVED_FEATURES)
            .expect("an empty list must be refused");
        assert!(
            why.contains("riscv64"),
            "the refusal does not name the architecture it is about: {why}"
        );
        assert!(
            why.contains("derive-seccomp-allowlist.sh"),
            "the refusal names no way to obtain a list that would work: {why}"
        );
    }

    /// A build whose features differ is refused, and says which differ.
    ///
    /// The second branch, driven independently of the first. A list is only
    /// true for the build it came from: more features, more calls, and a call
    /// the list does not carry ends the process.
    #[test]
    fn enforcement_refuses_a_build_the_list_was_not_derived_against() {
        let why = enforcement_refusal(42, "x86_64", "native,tui")
            .expect("a different feature set must be refused");
        assert!(
            why.contains("native,tui"),
            "the refusal does not say what this binary carries: {why}"
        );
        assert!(
            why.contains(DERIVED_FEATURES),
            "the refusal does not say what the list was derived against: {why}"
        );
    }

    /// The matching case is permitted, so the refusals are not blanket.
    ///
    /// The positive control. Without it both gates above would pass on a
    /// predicate that refuses everything, which would make `--seccomp enforce`
    /// a flag that never works and nobody would notice for months.
    #[test]
    fn enforcement_is_permitted_where_the_list_was_derived() {
        assert_eq!(
            enforcement_refusal(42, "x86_64", DERIVED_FEATURES),
            None,
            "a build the list WAS derived for was refused"
        );
    }

    /// The refusals are ordered so the more fundamental one answers first.
    ///
    /// With no list at all, the features are beside the point: there is nothing
    /// to enforce whatever they are. Reporting the feature mismatch there would
    /// send someone to rebuild with different features when what they need is a
    /// derivation.
    #[test]
    fn the_architecture_refusal_answers_before_the_feature_one() {
        let why = enforcement_refusal(0, "aarch64", "native,tui")
            .expect("both conditions hold, so it must refuse");
        assert!(
            why.contains("aarch64") && !why.contains("native,tui"),
            "with no derived list at all, the refusal talks about features: {why}"
        );
    }

    /// The shipped list is the one that was derived, not a copy of it.
    ///
    /// Pins the artifact: 42 syscalls for x86_64, sorted and without
    /// duplicates, and none outside what `seccomp_data.nr` can hold. A list
    /// that grew a duplicate or lost its order is a list somebody edited by
    /// hand, which is the one way it is not allowed to change.
    ///
    /// Gated on Linux as well as on the architecture: `libc::SYS_*` does not
    /// exist off Linux, and an x86_64 macOS build would fail to compile it.
    /// That is the same split that broke the build once already, and the
    /// scanner caught it here before it could again.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn the_derived_list_is_the_one_the_derivation_returned() {
        assert_eq!(
            DERIVED_ALLOWLIST.len(),
            42,
            "the derived list changed size without the derivation being re-run"
        );
        let mut sorted = DERIVED_ALLOWLIST.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.as_slice(),
            DERIVED_ALLOWLIST,
            "the list is unsorted or carries a duplicate, which no derivation \
             produces and a hand edit does"
        );
        assert!(
            build_program(
                AUDIT_ARCH_X86_64,
                DERIVED_ALLOWLIST,
                SECCOMP_RET_KILL_PROCESS
            )
            .is_ok(),
            "the shipped list cannot be encoded as a filter at all"
        );
        for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_exit_group] {
            assert!(
                DERIVED_ALLOWLIST.contains(&nr),
                "the list omits syscall {nr}, which every run makes — a list this \
                 short kills on the first call"
            );
        }
    }

    /// The variant scan sees a variant appended after the ones it knows.
    ///
    /// The one still owed for a gate that passed untouched when `Enforcing`
    /// appeared. Its predecessor compared against a typed-out list, so a new
    /// variant changed nothing it could observe. This drives the parser over an
    /// enum carrying a variant the real one does not have, which is the only
    /// way to know it would see the next one.
    #[test]
    fn the_variant_scan_would_see_the_next_variant_too() {
        let src = "pub enum SeccompStatus {\n    Disabled,\n    Logging,\n    \
                   Enforcing {\n        count: usize,\n    },\n    \
                   Quarantining,\n    Failed(String),\n}\n";
        let start = src.find("pub enum SeccompStatus {").expect("present");
        let body = &src[start..start + src[start..].find("\n}").expect("ends")];
        let variants: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| {
                l.chars().next().is_some_and(char::is_uppercase)
                    && (l.ends_with(',') || l.ends_with('{') || l.ends_with('}'))
            })
            .map(|l| l.trim_end_matches([',', ' ', '{', '}']))
            .collect();
        assert!(
            variants.iter().any(|v| v.contains("Quarantining")),
            "a variant the parser has never seen was not found, so the scan is \
             recognizing names rather than enumerating the type: {variants:?}"
        );
        assert_eq!(
            variants.len(),
            5,
            "the parser miscounted a five-variant enum: {variants:?}"
        );
    }

    /// No structural gate here slices a fixed-size window out of the source.
    ///
    /// Owed for one that did. `install_reads_the_filter_back_before_reporting_success`
    /// read `&src[start..start + 2000]`, and the function outgrew it the moment
    /// enforcement landed — the readback moved past character 2000 and the gate
    /// reported it missing. A window chosen by eye expires, silently, and the
    /// failure looks like the code being wrong rather than the test.
    #[test]
    fn no_structural_gate_here_slices_a_window_chosen_by_eye() {
        // CODE, not commentary. A comment describing this pattern is not an
        // instance of it, and the doc comment above this very function is
        // written in terms of it — which is how the first two versions
        // reported themselves. Excluding a window around the function was the
        // obvious fix and the wrong one: it missed the doc comment, because a
        // window drawn by hand is the thing being outlawed here.
        let src = include_str!("seccomp.rs");
        let re = regex::Regex::new(r"start \+ [0-9]{2,}\]").expect("pattern");
        let hits: Vec<String> = src
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                !t.starts_with("//") && !t.starts_with("///")
            })
            .flat_map(|l| re.find_iter(l).map(|m| m.as_str().to_string()))
            .collect();
        assert!(
            hits.is_empty(),
            "these slice a fixed number of characters out of the source, which \
             expires the moment the thing they read grows: {hits:?}. Walk the \
             braces instead"
        );
    }

    /// The brace walk returns a whole function, not a prefix of one.
    ///
    /// The replacement, driven on synthetic source so its edges are testable.
    /// Nested braces are the case a naive scan gets wrong, and a function whose
    /// body contains a block is every function here.
    #[test]
    fn the_brace_walk_returns_the_whole_function() {
        let src = "fn a() {\n    if x {\n        y();\n    }\n    z();\n}\nfn b() {}\n";
        let start = src.find("fn a()").expect("present");
        let open = start + src[start..].find('{').expect("body");
        let mut depth = 0i32;
        let mut end = open;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &src[open..=end];
        assert!(body.contains("z();"), "the walk stopped early: {body}");
        assert!(
            !body.contains("fn b"),
            "the walk ran past the function it was reading: {body}"
        );
    }

    /// And it stops at the function's own close, not the file's.
    ///
    /// The other edge. A walk that never decrements returns everything to the
    /// end of the file and every `contains` check on it passes — a gate that
    /// agrees with any source.
    #[test]
    fn the_brace_walk_stops_at_the_functions_own_close() {
        let src = "fn a() {\n    let s = 1;\n}\nfn poison() { unreachable!() }\n";
        let start = src.find("fn a()").expect("present");
        let open = start + src[start..].find('{').expect("body");
        let mut depth = 0i32;
        let mut end = open;
        for (offset, ch) in src[open..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(
            !src[open..=end].contains("poison"),
            "the walk swallowed the next function, so any gate using it would \
             pass on text from somewhere else"
        );
    }

    /// A status two modes can reach names neither of them.
    ///
    /// Owed for `Unsupported` and `Failed`, which read "Syscall LOGGING
    /// unavailable" for months and then, the moment enforcement shipped, told
    /// an operator who had asked for a control that a recorder was missing. A
    /// true sentence about the wrong thing.
    ///
    /// The rule is structural because the wrong sentence compiles: a variant
    /// both modes reach must render without naming either.
    #[test]
    fn a_status_both_modes_reach_names_neither_mode() {
        for status in [
            SeccompStatus::Unsupported("a reason".to_string()),
            SeccompStatus::Failed("a reason".to_string()),
        ] {
            let line = startup_line(&status).to_lowercase();
            for mode_word in ["logging", "enforc", "recorded"] {
                assert!(
                    !line.contains(mode_word),
                    "{status:?} renders as {line:?}, which names {mode_word:?} — a \
                     mode the operator may not have asked for"
                );
            }
        }
    }

    /// A refusal reached from enforce reads as a filter failure.
    ///
    /// The second owed, from the other side: the line must still say something
    /// useful once the mode words are gone. "No filter is in force" is true for
    /// both modes and is the fact an operator needs.
    #[test]
    fn a_refusal_says_no_filter_is_in_force_whichever_mode_asked() {
        for status in [
            SeccompStatus::Unsupported("no derived list".to_string()),
            SeccompStatus::Failed("EACCES".to_string()),
        ] {
            let line = startup_line(&status);
            assert!(
                line.contains("No filter is in force"),
                "{status:?} renders as {line:?} and never says that nothing is \
                 protecting or recording anything"
            );
            assert!(
                line.contains("a reason")
                    || line.contains("no derived list")
                    || line.contains("EACCES"),
                "the line drops the reason it was given: {line}"
            );
        }
    }

    /// Only the two mode-specific statuses name a mode.
    ///
    /// The third owed, and the pairing that makes the rule above safe. Strip
    /// mode words from everything and the success lines stop saying what is
    /// running; this pins which statuses are allowed to name one.
    #[test]
    fn the_mode_specific_statuses_are_the_only_ones_naming_a_mode() {
        let logging = startup_line(&SeccompStatus::Logging).to_lowercase();
        assert!(
            logging.contains("logging"),
            "the logging line stopped saying which mode is running: {logging}"
        );
        let enforcing = startup_line(&SeccompStatus::Enforcing { count: 42 }).to_lowercase();
        assert!(
            enforcing.contains("enforcing"),
            "the enforcing line stopped saying which mode is running: {enforcing}"
        );
        assert!(
            !enforcing.contains("logging") && !logging.contains("enforcing"),
            "the two mode lines name each other's mode"
        );
        let off = startup_line(&SeccompStatus::Disabled).to_lowercase();
        assert!(
            !off.contains("enforc"),
            "the off line mentions enforcement: {off}"
        );
    }

    /// Exactly one status reads as enforcement, and it is the one that does.
    ///
    /// This began as "no status claims to deny anything", with a comment saying
    /// that whoever added an enforcing mode would have to change it and would
    /// therefore read why it existed. They did not: the variant list was
    /// written out by hand, so `Enforcing` slipped past a gate built to catch
    /// exactly that. A hand-written list of variants is not an enumeration of
    /// the type.
    ///
    /// It reads the enum from source now. A variant whose name sounds like a
    /// control has to BE one, and the check that decides is the action the
    /// installer uses — `SECCOMP_RET_KILL_PROCESS` appears once in the file,
    /// on the enforcing path.
    #[test]
    fn only_the_enforcing_status_reads_as_enforcement() {
        let src = include_str!("seccomp.rs");
        let start = src
            .find("pub enum SeccompStatus {")
            .expect("the status enum is in this file");
        let body = &src[start..start + src[start..].find("\n}").expect("it ends")];
        let variants: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| {
                l.chars().next().is_some_and(char::is_uppercase)
                    && (l.ends_with(',') || l.ends_with('{') || l.ends_with('}'))
            })
            .map(|l| l.trim_end_matches([',', ' ', '{', '}']))
            .collect();
        assert!(
            variants.len() >= 4,
            "only {} variant(s) parsed out of SeccompStatus; the scan has stopped \
             matching and would let the next one past too: {variants:?}",
            variants.len()
        );
        let enforcing: Vec<&&str> = variants
            .iter()
            .filter(|v| v.to_lowercase().contains("enforc"))
            .collect();
        assert_eq!(
            enforcing.len(),
            1,
            "SeccompStatus has {} variant(s) reading as enforcement: {enforcing:?}. \
             One mode denies calls; every other name that sounds like it would \
             mislead a reader of a run's posture",
            enforcing.len()
        );
        assert!(
            src.contains("SECCOMP_RET_KILL_PROCESS"),
            "a status claims enforcement and no denying action exists in the file"
        );
    }

    /// The variant scan sees a variant added by hand, which the old one did not.
    ///
    /// The fixture guard for the gate above, and the reason it exists: the
    /// version this replaced compared against a list somebody typed, so adding
    /// `Enforcing` to the enum changed nothing it could observe. This drives
    /// the parser over a synthetic enum instead of the real one.
    #[test]
    fn the_variant_scan_reads_the_type_rather_than_a_typed_out_list() {
        let src = "pub enum SeccompStatus {\n    Disabled,\n    Logging,\n    \
                   Enforcing {\n        count: usize,\n    },\n    Failed(String),\n}\n";
        let start = src.find("pub enum SeccompStatus {").expect("present");
        let body = &src[start..start + src[start..].find("\n}").expect("ends")];
        let variants: Vec<&str> = body
            .lines()
            .map(str::trim)
            .filter(|l| {
                l.chars().next().is_some_and(char::is_uppercase)
                    && (l.ends_with(',') || l.ends_with('{') || l.ends_with('}'))
            })
            .map(|l| l.trim_end_matches([',', ' ', '{', '}']))
            .collect();
        assert!(
            variants.iter().any(|v| v.contains("Enforcing")),
            "the parser cannot see a struct variant, which is the shape the real \
             one has: {variants:?}"
        );
        assert!(
            variants.iter().any(|v| v.contains("Disabled")),
            "the parser cannot see a unit variant: {variants:?}"
        );
    }
}
