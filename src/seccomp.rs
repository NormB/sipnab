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

// ── What a run asked for, and what it got ───────────────────────────────────

/// What `--seccomp` asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeccompMode {
    /// No filter. The default, and the only mode fit for a live capture.
    #[default]
    Off,
    /// Record every syscall and allow every syscall.
    Log,
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
             records are in `dmesg | grep 'type=1326'`. Turn it off afterwards — a live \
             capture emits one record per packet and will flood the log."
            .to_string(),
        SeccompStatus::Unsupported(why) => {
            format!("Syscall logging unavailable: {why}. Nothing is recorded.")
        }
        SeccompStatus::Failed(why) => {
            format!("Syscall logging could not be installed: {why}. Nothing is recorded.")
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
    // No allowlist: the point is to record everything.
    let prog = match build_program(arch, &[], SECCOMP_RET_LOG) {
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
                line.contains("Nothing is recorded"),
                "a control that did not install must say so: {line}"
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
        let msg = &src[start..start + 200];
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

    /// The status enum has no variant that could be read as enforcement.
    ///
    /// Structural, deliberately: the day someone adds an enforcing mode they
    /// have to change this test, and changing it means reading why it is here.
    #[test]
    fn no_status_claims_to_deny_anything() {
        let all = [
            SeccompStatus::Disabled,
            SeccompStatus::Logging,
            SeccompStatus::Unsupported(String::new()),
            SeccompStatus::Failed(String::new()),
        ];
        for s in &all {
            let name = format!("{s:?}");
            assert!(
                !name.to_lowercase().contains("enforc"),
                "{name} reads as enforcement, and nothing here denies a call"
            );
        }
    }
}
