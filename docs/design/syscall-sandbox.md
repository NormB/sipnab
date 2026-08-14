# seccomp and Landlock

**Status:** DESIGN. seccomp and Landlock are **not implemented**, which is G5's
own opening evidence and is still true. What sipnab *does* have is weaker and is
not nothing — §0 tabulates it. A reader who stops at this line will re-implement
hardening that already ships.
**Check:** `grep -rniE 'seccomp|landlock|\bunshare\(' src/` exits 1 — no syscall filter and no path sandbox.
**Check:** `grep -c 'libc::prctl\|libc::setrlimit\|libc::chroot\|libc::setuid\|libc::setgroups' src/privilege.rs` returns 6 — the calls §0 tabulates; the gate running this line proves the set is non-empty, and the 6 was counted by hand.
The first check's original wording was `grep -rn 'seccomp\|landlock\|unshare'`,
which matched one hit — the prose "(unshared)" in the TUI, added months before
this document. The verdict was right and the evidence was too broad, so the
command narrowed and the conclusion stands. The second check exists because a
page carrying only the first reads as "sipnab has no hardening", which is a
different and false statement.
**Verified against:** `4651932`, working tree.
**Backlog:** [`backlog.md`](backlog.md) **G5** (`:1719`).
**Upstream argument:**
[`process-isolation-and-hot-path-cost.md`](process-isolation-and-hot-path-cost.md)
§2b, which is where the threat is established and where forking was declined in
favour of this.

Most of this page is about **how to derive an allowlist**, not what the
allowlist is. That is deliberate: G5 is ranked P5 *"only because it needs a
carefully-derived allowlist and a per-platform fallback"*, and a page that
guessed the list would have skipped the only hard part. A wrong allowlist kills
the process on a path nobody exercised — on a production capture box, during the
incident the capture was started for.

## 0. What is in place today

"Not implemented" is accurate about seccomp and Landlock and misleading about
sipnab. The process already hardens itself four ways, and a fifth sandbox — a
real one, for a different threat — ships in the plugin host. None of the five is
a syscall filter, and knowing which is which is the difference between adding
the missing control and re-implementing one that exists.

Every row below was read at the SHA in the header.

| In place | Where | Stops | Does not stop |
|---|---|---|---|
| Privilege drop: `setgroups(0, NULL)` → `setgid` → `setuid`, then a `getuid`/`getgid` readback | [`src/privilege.rs:66-70`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L66-L70), verified by `verify_dropped` ([`src/privilege.rs:480`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L480)) | Reaching other users' files, signalling their processes, opening a new privileged socket | Anything this process does as itself — its own memory, its own descriptors, `execve` |
| `PR_SET_NO_NEW_PRIVS` | `set_no_new_privs` ([`src/privilege.rs:426`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L426)), called from [`src/privilege.rs:74`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L74) | Regaining privilege through a setuid or setgid binary | `execve` itself, of anything already runnable |
| Core dumps off: `prctl(PR_SET_DUMPABLE, 0)`, or `setrlimit(RLIMIT_CORE, 0)` on macOS | `disable_core_dumps` ([`src/privilege.rs:198`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L198)), called from [`src/app/bootstrap.rs:942`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L942) | Key material landing in a core file after a crash | Any live read of that key material |
| `chroot` + `chdir("/")`, opt-in via `--chroot` | `do_chroot` ([`src/privilege.rs:450`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L450)), called from [`src/app/bootstrap.rs:775`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L775) | Naming a path outside the new root | Everything inside the new root, and every already-open descriptor |
| WASM plugin host: no imports registered at all, plus fuel, memory and output caps | [`src/plugin/mod.rs:238`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L238), caps at [`:57`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L57), [`:61`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L61), [`:81`](https://github.com/NormB/sipnab/blob/main/src/plugin/mod.rs#L81) | A third-party plugin doing anything but returning findings | Anything in the host process, libpcap included |

The plugin row is the one most likely to be mistaken for this page's subject.
It is a genuine sandbox and it is airtight in its own scope — a module that
imports anything at all fails to instantiate, and `wasmi` interprets rather than
JITs, so the host maps no writable-executable page. It governs **plugin** code.
It has no bearing on libpcap, which is the code §1 is about, and which runs in
the host with the host's full authority. [`wasm-plugin-api.md`](wasm-plugin-api.md)
owns that argument and states its own limits.

### 0.1 Four caveats, because the table above is the optimistic reading

**The privilege drop and `PR_SET_NO_NEW_PRIVS` both require starting as root.**
`drop_privileges` returns early when `getuid()` is not 0
([`src/privilege.rs:37-40`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L37-L40)), and `set_no_new_privs` is
called from inside it, past that return. The install path this project
recommends is `sipnab --setup-caps`, which writes
`cap_net_raw,cap_net_admin+ep` onto the binary
(`CAPTURE_CAPS`, [`src/privilege.rs:93`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L93)) so capture needs no
root at all.
**On that path there is no drop, no no-new-privs, and both capabilities stay in
the effective set for the life of the run** — so a compromised libpcap can open
further raw sockets, not merely keep the one it was handed. The recommended
install is therefore the *least* hardened of the two, which is worth stating
plainly rather than leaving a reader to infer it from a `getuid` check.

Note what does the capability clearing on the root path: `setuid(2)` away from
root empties the permitted and effective sets as a kernel side effect. sipnab
never drops a capability itself — `grep -rn 'capset\|PR_CAPBSET_DROP' src/`
exits 1 — and `verify_dropped` reads back uid and gid only, not the capability
sets. So "capabilities are gone after the drop" is true, inherited from
`setuid` semantics rather than asserted by this code, and it is one more thing
the readback in §4 could cover and does not.

**`--no-priv-drop` turns off rows one and two by request**
([`src/privilege.rs:32-35`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L32-L35)), and on macOS a root run without
`--user` skips them too, deliberately
([`src/privilege.rs:49-57`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L49-L57)).

**Core dumps stay on unless decryption keys are loaded.**
`disable_core_dumps` runs only when one of `--tls-key`, `--keylog`,
`--srtp-keys` or `--dtls-keylog` is set and `--allow-coredump` is absent
([`src/app/bootstrap.rs:936-942`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L936-L942)). An ordinary capture
dumps core, and that core carries packet payloads.

**Two of the four report success they did not achieve.** `set_no_new_privs`
warns and returns `Ok` when the `prctl` fails
([`src/privilege.rs:430-437`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L430-L437)), and `disable_core_dumps`
does the same, then logs `"Core dumps disabled (decryption active)"`
unconditionally on the way out
([`src/privilege.rs:231-232`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L231-L232)). A failed
`PR_SET_DUMPABLE` therefore produces a warning line *and* a confident success
line, and the caller's `exit(1)` on error is unreachable. This is the same
silence-as-failure-mode §6 is built to avoid, already present in the controls
that exist — so §6's reporting surface is a fix for shipped behaviour, not only
a requirement on new behaviour.

### 0.2 What a syscall filter adds that none of this does

Every control above governs **identity** — which uid the process carries,
whether it can regain root, which directory tree it can name — or **artefacts on
disk**. Not one of them constrains what the sipnab process may ask the kernel
for while running as itself.

So a libpcap compromise that never tries to become another user, never execs a
setuid binary and never leaves the chroot keeps everything §1 lists with all
four controls in force: it reads the TLS keys out of this process's memory,
opens the keylog through this process's own credentials, sends on the
`CAP_NET_RAW` socket the drop deliberately preserved, `connect`s outward,
`execve`s whatever the unprivileged user can already run, and `mmap`s executable
pages. `setuid` answers "as whom?". seccomp answers "may it at all?", and
Landlock answers "pointing where?". Nothing shipped today asks the second
question or the third.

That is the gap, stated so it can be argued with. The rest of this page is how
to close it without killing a production capture in the process.

## 1. The threat, and why it is not the usual one

sipnab's own parsers are 100% safe Rust; `process-isolation-and-hot-path-cost.md`
§2b establishes that *"none in `sip/`, `rtp/parser.rs`, `capture/parse.rs` or
`sdp.rs`"* carry an `unsafe` block. **libpcap is the exception, and it is the
first thing to touch every untrusted byte**, on both the live and the offline
path. §2b enumerates what shares its address space:

- TLS key material (`--tls-key`, keylog secrets),
- MCP and REST bearer tokens ([`auth.rs`](../../src/auth.rs)),
- the raw `CAP_NET_RAW` socket opened *before* the privilege drop and held for
  the whole run ([`src/process_isolation.rs:107-136`](https://github.com/NormB/sipnab/blob/main/src/process_isolation.rs#L107-L136)),
- the dialog and stream stores.

That last bullet is the one the existing privilege drop does not touch. `setuid`
to `nobody` stops the process reaching *other users'* files. It does not stop
code executing inside this process from reading this process's own memory,
opening this process's own keylog, or sending on the `CAP_NET_RAW` socket that
survived the drop by design.

§2b's own conclusion is worth carrying forward, because it names the shape of
the fix: *"it argues for isolating **the libpcap reader**, not for forking N
analysis workers. And §5 has a cheaper answer that closes more of the same
path."* This page is that cheaper answer.

## 2. Why the allowlist cannot be written by hand

The usual seccomp story is a daemon with a small, stable syscall set. sipnab's
post-drop set is neither small nor fixed — it is a **function of the effective
configuration**. Enumerated from the code, everything below runs after
`drop_privileges` returns:

| Post-drop activity | Where | What it needs |
|---|---|---|
| Ring drain | `cap.next_packet()`, [`src/capture/live.rs:599`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L599) | libpcap ring reads |
| Idle wait | `libc::poll`, [`src/capture/live.rs:102-113`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L102-L113) | `poll`/`ppoll` |
| Drop stats | `cap.stats()`, [`src/capture/live.rs:552`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L552); *"a `getsockopt` on Linux"*, [`:769`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L769) | `getsockopt` |
| Fanout join | [`src/capture/live.rs:515`](https://github.com/NormB/sipnab/blob/main/src/capture/live.rs#L515) | `setsockopt` |
| Output pcap, created **lazily on the first packet** | [`src/app/batch.rs:2233-2242`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2233-L2242) → [`src/capture/writer.rs:103`](https://github.com/NormB/sipnab/blob/main/src/capture/writer.rs#L103) | file create + write |
| `--split` rotation, mid-run | [`src/capture/writer.rs:837`](https://github.com/NormB/sipnab/blob/main/src/capture/writer.rs#L837) | more file creates |
| REST API listener bind | [`src/app/servers.rs:277`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L277) | socket/bind/listen/accept |
| Metrics listener, raw TCP + threads | [`src/app/servers.rs:227`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L227) | the same, plus thread creation |
| MCP over stdio | [`src/mcp/transport.rs:59-60`](https://github.com/NormB/sipnab/blob/main/src/mcp/transport.rs#L59-L60) | read/write on fds 0 and 1 |
| MCP over HTTP, `mcp-http` | [`src/app/servers.rs:370-375`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L370-L375) | tokio reactor: epoll, eventfd, timerfd |
| Syslog, eight lines after the drop | [`src/app/bootstrap.rs:838`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L838) → [`src/security/alerting.rs:960`](https://github.com/NormB/sipnab/blob/main/src/security/alerting.rs#L960) | `AF_UNIX` connect to `/dev/log` |
| Signing keys read from files | [`src/app/servers.rs:442`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L442) | file open, after the drop *and* after any chroot |
| `--keylog-watch` re-reads the keylog repeatedly | [`src/capture/decrypt.rs:592`](https://github.com/NormB/sipnab/blob/main/src/capture/decrypt.rs#L592) | file open + stat, for the life of the run |
| Reverse DNS | [`src/names.rs:520`](https://github.com/NormB/sipnab/blob/main/src/names.rs#L520) | resolver sockets, `/etc/resolv.conf`, glibc NSS `dlopen` |
| Audio playback plugin | `Library::new`, [`src/rtp/playback.rs:475`](https://github.com/NormB/sipnab/blob/main/src/rtp/playback.rs#L475) | `dlopen` of `libsipnab_audio.so`: openat, mmap, **mprotect with PROT_EXEC** |
| Event exec hooks | `Command::new("sh").spawn()`, [`src/output/event_exec.rs:565-571`](https://github.com/NormB/sipnab/blob/main/src/output/event_exec.rs#L565-L571) | **clone + execve + wait4** |
| Crash report write | [`src/crash.rs:125`](https://github.com/NormB/sipnab/blob/main/src/crash.rs#L125) | file create with `O_EXCL` |
| HEP listener / sender | [`src/capture/hep.rs:1372`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1372) | UDP bind |

Two rows deserve to be read twice.

**`dlopen` and `execve` are the two features that gut the filter.** A filter that
permits `execve` cannot stop a libpcap RCE from running a shell; a filter that
permits `mprotect(PROT_EXEC)` cannot stop it mapping code. Both are real
features (`--alert-exec`, `--on-*-exec`, and TUI audio playback), and both are
optional.

**Therefore the allowlist should be computed from the effective configuration,
not fixed at build time.** A run with no exec hooks and no audio gets a strictly
narrower filter than a run with both, and the startup log says which of the two
widened it. This is the single most valuable structural decision on this page:
it makes the sandbox's strength visible and configuration-dependent, instead of
publishing one lowest-common-denominator list that is as weak as the most
permissive feature anyone might enable.

**The privilege module's own doc is stale about this, and it matters.**
[`src/privilege.rs:3-14`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L3-L14) lists the call sequence as
*"2. Open key files, bind API/metrics ports; 3. Call `drop_privileges()`"*. The
code does the opposite: `drop_privileges` is at
[`src/app/bootstrap.rs:830`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L830) and `start_servers` is reached
only after `launch` returns, from
[`src/app/batch.rs:1951`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1951) or
[`src/app/tui_mode.rs:428`](https://github.com/NormB/sipnab/blob/main/src/app/tui_mode.rs#L428). Anyone deriving an allowlist from
that comment would omit `socket`, `bind`, `listen` and `accept4` and ship a
filter that kills every `--api` run. Correcting the comment is part of this work.

## 3. Deriving the allowlist

### What is not available on this host

Verified by running it: `which strace ltrace bpftrace` returns nothing —
**neither strace nor ltrace is installed**, so a `ptrace`-based empirical trace
is not currently possible here. `auditctl` is present at `/usr/sbin/auditctl`,
and `perf` at `/usr/bin/perf`. `grep Seccomp /proc/self/status` returns both
`Seccomp:` and `Seccomp_filters:` fields, so `CONFIG_SECCOMP` is compiled in and
the kernel exposes the readback surface §6 needs. Kernel is `6.8.12-rt-tegra`
(aarch64).

### Route A — `SECCOMP_RET_LOG`, the recommended one

Install the real filter with its default action set to `SECCOMP_RET_LOG` instead
of a denial. Every syscall not on the candidate allowlist is written to the audit
subsystem and **the process continues**. Run the whole exercise corpus under it,
harvest the logged set, union it into the allowlist, then switch the default
action to a denial and re-run.

`auditctl` being present makes this the cheapest route here. The filter code is
the same code either way, which is the property that makes this better than an
external tracer: the thing being derived and the thing being shipped are one
program, so a filter that was never installed produces an empty log rather than
a false clean bill.

Two rules keep it from becoming the defect it is meant to prevent:

- **LOG mode is opt-in and never a fallback.** A kernel that cannot install a
  filter must not silently get LOG mode. A filter that logs is not a filter, and
  a run that believes it is sandboxed and is not is worse than one that knows it
  is not.
- **LOG mode ships permanently, as `--seccomp=log`.** The derivation has to be
  repeatable by someone on a platform the maintainer does not have — musl,
  a different glibc, a distro kernel. Making it a one-off developer script
  guarantees the musl list is guessed.

**Unverified:** whether the audit subsystem is actually enabled on this kernel
(`auditctl` being installed is not the same as `audit=1` and a running
`auditd`), and whether `SECCOMP_RET_LOG` records reach it without an explicit
rule. Probe before committing to this route.

### Route B — `perf trace`

`perf` is present, and `perf trace` reads `raw_syscalls:sys_enter` tracepoints,
which is a strace-shaped tool without `ptrace`. Worth probing as a
cross-check on Route A's output.

**Unverified:** whether this `perf` build includes `trace`, and whether it works
under this kernel's `perf_event_paranoid` without additional capability. Both are
one command to check and neither has been checked.

### Route C — static derivation from the dependency tree — **rejected**

Reading the crate graph and writing down the syscalls it "should" make is
precisely the guessed list G5 warns about. The set is decided by things not
visible in sipnab's source:

- **libc.** glibc reaches for `clone3` on newer versions and falls back to
  `clone`; musl does not. The release matrix builds four Linux triples —
  `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`,
  `aarch64-unknown-linux-gnu`, `aarch64-unknown-linux-musl`
  ([`.github/workflows/release.yml`](https://github.com/NormB/sipnab/blob/main/.github/workflows/release.yml)), and both musl targets are cross-built in
  Docker.
- **Architecture.** aarch64 has no `open`, only `openat`; no `fork`, only
  `clone`. A list derived on x86_64 is wrong on aarch64 in both directions.
- **libpcap's ring choice.** TPACKET_V3 versus V2 is decided at runtime by the
  library and the kernel, not by sipnab.

So the allowlist is per `(libc, architecture)`, derived, and pinned per target —
not one list.

### The procedure

1. **Write the candidate set from §2's table**, from the code surface, not from
   a guess about libc.
2. **Build with `--seccomp=log`** and run the exercise corpus (§3.1).
3. **Union the logged set in**, per target triple, with each addition carrying a
   one-line note saying which run produced it. A syscall in the list that nobody
   can attribute is a syscall nobody can later remove.
4. **Re-run in enforce mode** and require **byte-identical output** to the
   unfiltered run over the same fixtures. That is the regression gate a
   too-strict list trips.
5. **Only then tighten**, one syscall at a time, each removal re-running step 4.

### 3.1 The corpus that has to be exercised

The derived list is only as good as the runs that produced it, and the risk is
asymmetric: a list derived on a **narrow** build and shipped on a **wide** one
kills the wide build. So the corpus must be the widest configuration each target
actually ships, plus the paths CI never reaches:

- The CI feature matrix, not `--all-features` — the two are not the same set of
  builds, and the matrix combinations are the ones users get.
- Live capture on a real interface (CI reads files).
- `-O` writing, including a `--split` rotation, because the second file is
  created mid-run at [`src/capture/writer.rs:837`](https://github.com/NormB/sipnab/blob/main/src/capture/writer.rs#L837).
- `--api`, `--mcp` over stdio, and `--mcp-http`.
- Audio playback, which is the only `dlopen` sipnab performs deliberately.
- `--keylog-watch`, which re-opens a file every sweep.
- An event exec hook firing.
- The crash handler writing a report.

Anything on that list that is not exercised must be either excluded from the
build being sandboxed or excluded from the sandbox, explicitly and in the log —
never assumed harmless.

### 3.2 The default action: KILL, not ERRNO

`SECCOMP_RET_ERRNO(EPERM)` looks kinder and is the wrong choice here.

An `EPERM` from `openat` on the output path produces a run that captures happily
and writes nothing. An `EPERM` from the resolver produces a report with no names
in it. Those are **confident wrong answers** — the exact failure this codebase
has already had to fix once at the capture layer, where an unreadable
encapsulation produced *"49 packets captured, 0 SIP messages … exit 0 — output
textually IDENTICAL to a capture that was read perfectly"*
([`src/capture/mod.rs:107-112`](https://github.com/NormB/sipnab/blob/main/src/capture/mod.rs#L107-L112)).

`SECCOMP_RET_KILL_PROCESS` produces a death with a syscall number attached. That
is diagnosable, it is loud, and it is the only action that makes §6's proof
possible: a filter whose denial is observable is a filter a test can prove is
active.

The cost is real and must be stated in the docs rather than hidden: **an
under-derived allowlist kills a production capture.** That cost is why §3's
procedure is a derivation and not a guess, why LOG mode ships, and why §5's
degradation rule exists.

## 4. Where the filter installs

Verified ordering today:

| Step | Site |
|---|---|
| `do_chroot` (needs root) | [`src/app/bootstrap.rs:775`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L775) |
| `drop_privileges` → setgroups, setgid, setuid, `PR_SET_NO_NEW_PRIVS` | [`src/app/bootstrap.rs:830`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L830), [`src/privilege.rs:66-74`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L66-L74) |
| `init_syslog` | [`src/app/bootstrap.rs:838`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L838) |
| `disable_core_dumps` (conditional on key material) | [`src/app/bootstrap.rs:942`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L942) |
| `start_servers` — binds API, MCP, metrics | [`src/app/batch.rs:1951`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L1951) |
| receive loop; writer created on first packet | [`src/app/batch.rs:2146`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2146), [`:2242`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2242) |

The first two rows run **only on a root start**, and the fourth only when
decryption keys are loaded, per §0.1. The install point below is chosen against
the ordering, which holds either way; what changes without root is how much is
already in force by the time the filter goes in, which is why §6 reports the
whole posture rather than the filter alone.

**Install point: immediately after `start_servers` returns, before the receive
loop.** Two reasons. Installing at the drop is too early — the listeners are not
bound yet, so the filter would have to permit `bind`/`listen` for the whole run
to cover a few milliseconds of startup. Installing later is not possible — the
receive loop is where the untrusted bytes arrive, and the filter has to be up
before the first one does.

The TUI path needs the same install after
[`src/app/tui_mode.rs:428`](https://github.com/NormB/sipnab/blob/main/src/app/tui_mode.rs#L428). Two call sites, one function.

**`PR_SET_NO_NEW_PRIVS` must be verified, not assumed.** `seccomp(2)` without
`CAP_SYS_ADMIN` requires it, and today `set_no_new_privs`
([`src/privilege.rs:426`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L426)) is deliberately non-fatal — it
warns and continues ([`:431-436`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L431-L436)). So the install path
must read the flag back with `PR_GET_NO_NEW_PRIVS` and report "no filter,
because no-new-privs is not set" rather than silently failing to install one.
This is exactly the readback discipline `verify_dropped`
([`src/privilege.rs:480`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L480)) already applies to the uid and gid.

The stronger case is the one §0.1 names: on a `--setup-caps` install the flag is
never attempted, because `set_no_new_privs` sits past the `getuid()` check inside
`drop_privileges`. So the readback is not a guard against a rare `prctl` failure
— on the recommended install path it reads back 0 every time, and a filter that
assumed otherwise would fail to install on the configuration most users run.

**The writer stays lazy.** Making it eager would let the filter drop the file
syscalls, but the writer needs `link_type`, which comes from the first packet
([`src/app/batch.rs:2242`](https://github.com/NormB/sipnab/blob/main/src/app/batch.rs#L2242)). Re-architecting that to tighten a
syscall list is the wrong trade. Instead: seccomp permits the file syscalls,
and **Landlock bounds where they may point** (§5). That division of labour is
what G5 means by Landlock being *"additionally"* useful, and it is why the two
are one piece of work rather than two.

## 5. Landlock: weaker, cheaper, and the one to ship first

Landlock bounds **paths**, not syscalls. It needs no syscall enumeration, so it
carries none of §3's derivation risk, and it closes the largest single hole:
after it is installed, a libpcap RCE cannot open the keylog of another run,
cannot read `/etc/shadow`, and cannot write outside the output directory.

Proposed ruleset, derived from what actually runs post-drop:

| Access | Paths |
|---|---|
| Read | the `-I` input set; the keylog, which `--keylog-watch` re-reads for the life of the run ([`src/capture/decrypt.rs:592`](https://github.com/NormB/sipnab/blob/main/src/capture/decrypt.rs#L592)); the signing-key files ([`src/app/servers.rs:442`](https://github.com/NormB/sipnab/blob/main/src/app/servers.rs#L442)) |
| Read + execute | the audio plugin path, only when `audio` is compiled and playback is reachable ([`src/rtp/playback.rs:475`](https://github.com/NormB/sipnab/blob/main/src/rtp/playback.rs#L475)) |
| Read, write, create | the `-O` output directory, including `--split` siblings; the crash-report directory ([`src/crash.rs:125`](https://github.com/NormB/sipnab/blob/main/src/crash.rs#L125)) |
| Read, only when reverse DNS is on | `/etc/resolv.conf`, `/etc/nsswitch.conf` and the NSS modules glibc `dlopen`s ([`src/names.rs:520`](https://github.com/NormB/sipnab/blob/main/src/names.rs#L520)) |

**Landlock does not bound the network in the way an operator might assume.**
Network rules arrived at ABI 4 and cover TCP bind/connect only. They do not cover
the HEP UDP listener ([`src/capture/hep.rs:1372`](https://github.com/NormB/sipnab/blob/main/src/capture/hep.rs#L1372)) and they do not
cover the pre-drop `CAP_NET_RAW` socket, which is not a Landlock-governed object
at all. Saying so plainly is better than letting "sandboxed" imply a guarantee it
does not make — the same rule
[`wasm-plugin-api.md`](wasm-plugin-api.md) applies to its own trust section.

**ABI negotiation is mandatory, not optional.** Landlock ABI levels track kernel
versions (5.13 → 1, 5.19 → 2, 6.2 → 3, 6.7 → 4). This host is 6.8. Debian 12
ships 6.1. So the code must request best-effort compatibility and accept a weaker
ruleset on an older kernel, never fail. That is also why Landlock is the right
thing to ship *first*: its degradation mode is "fewer rules", whereas a
mis-derived seccomp list's degradation mode is a dead process.

**Landlock and `--chroot` compose; neither replaces the other.** `do_chroot`
runs before the drop because it needs root
([`src/app/bootstrap.rs:771-775`](https://github.com/NormB/sipnab/blob/main/src/app/bootstrap.rs#L771-L775)) and, once inside, the
process can still reach everything in the new root. Landlock works after the
drop, needs no privilege, and can be finer than a directory. G5's framing —
Landlock for runs *without* `--chroot` — is right about the motivation and should
not become an exclusion in the code: a run with both should get both.

## 6. Degradation, and saying so

**Rule: never refuse to capture because a hardening feature was unavailable.**
The precedent is in this repo and should be cited rather than re-argued —
`join_fanout_group` ([`src/capture/fanout.rs:71-74`](https://github.com/NormB/sipnab/blob/main/src/capture/fanout.rs#L71-L74)):

> The caller must treat every error as advisory. Capture works without fanout;
> refusing to capture because an optimisation was unavailable would trade a
> throughput problem for a total outage.

The same reasoning applies with one addition: **silence is the failure mode of
every security control in this project's history.** The wasm memory cap
*"reliably reports a problem after causing it"*
([`wasm-plugin-api.md`](wasm-plugin-api.md)); the capture path returned a
confident zero on undecodable frames. A sandbox that quietly did not install
looks exactly like one that did.

So degradation is paired with reporting:

| Platform | seccomp | Landlock |
|---|---|---|
| Linux, kernel with both | derived filter, enforce | ruleset at the best available ABI |
| Linux, no `CONFIG_SECCOMP` | none, reported | as above |
| Linux, kernel below 5.13 | derived filter, enforce | none, reported |
| macOS | none — see below | none |
| `wasm32` | not compiled | not compiled |

Reporting means three things:

1. A startup log line naming what is active and what is not, and *why not* —
   covering **the §0 controls as well as the two new ones**. A run under
   `--setup-caps` today logs nothing about having skipped the privilege drop and
   `PR_SET_NO_NEW_PRIVS` beyond one `debug!` line, so an operator reading `info`
   cannot tell that posture from a root run apart. Reporting the two new
   controls and staying silent about the four that were already there would
   leave the same gap this page opened by being read as "nothing is
   implemented".
2. A field in the batch summary and in `capture_health` — the same structural
   discipline the rest of that response follows: a code, not a free string
   ([`src/mcp/server.rs:1809-1819`](https://github.com/NormB/sipnab/blob/main/src/mcp/server.rs#L1809-L1819)).
3. **`--require-sandbox`**, which turns degradation into a refusal. Opt-in,
   never the default, for the operator who would rather not capture than capture
   unsandboxed. Without this flag there is no way to express that preference; with
   it as a default, §6's rule is violated.

**macOS: declined, and not guessed at.** There is no seccomp. `sandbox_init(3)`
is deprecated and its profile language is not a documented interface.
**Unverified** whether any supported mechanism reaches the same result from
inside the process. Rather than ship something whose guarantee nobody can state,
macOS reports "no filter" and the docs say so.

**Docker.** Both musl targets are cross-built in containers, and Docker installs
its own default seccomp profile. Filters compose — the most restrictive wins — so
adding one inside is not a conflict. **Unverified:** whether Docker's default
profile permits the `seccomp(2)`/`prctl(PR_SET_SECCOMP)` call itself under the
configurations sipnab is run in. If it does not, the install fails and §6's
degradation path handles it — which is the point of having one.

## 7. Testing, and proving the filter is actually there

The central problem: **a filter that failed to install and a filter that
installed and permits everything are indistinguishable from outside.** Every gate
below exists because of that sentence.

### 7.1 Readback, which is necessary and not sufficient

`/proc/self/status` exposes `Seccomp:` and `Seccomp_filters:` — verified present
on this host. `Seccomp: 2` means filter mode; `Seccomp_filters: N` counts
installed filters. That proves *a* filter exists. It says nothing about whether
it is the right one, so it is the cheap first assertion and never the only one.

There is no `/proc` field for Landlock. Its ABI level can be read with
`landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`, which
reports what the kernel supports and not what this process installed. Landlock
therefore has **only** a behavioural proof.

### 7.2 The behavioural proof, which is the one that matters

Assert the **effect**, not the predicate:

- **seccomp.** After install, a child attempts a syscall that must be denied and
  the parent requires it to die by `SIGSYS`. Under `KILL_PROCESS` that is the
  observable, which is a second reason §3.2 chose it over `ERRNO`.
- **Landlock.** A child opens a path outside the ruleset and must get `EACCES`;
  the same child opens a path inside the ruleset and must succeed. Both halves,
  because a child that cannot open anything would pass the first assertion for
  the wrong reason.

**Reuse the existing child-role machinery rather than inventing a second one.**
[`tests/privilege_drop_test.rs`](../../tests/privilege_drop_test.rs) already
solves this problem for the privilege drop, and its module doc explains why the
work has to happen in a child: *"a test runner that has dropped to `nobody`,
chrooted into a temp directory or turned off its own dumpability would poison
every test after it"* ([`:20-34`](https://github.com/NormB/sipnab/blob/main/tests/privilege_drop_test.rs#L20-L34)). A process
that installed a seccomp filter poisons the runner in exactly the same way, and
more permanently — a filter cannot be removed.

Two pieces of that harness carry over unchanged and must not be reimplemented:

- `CHILD_COMPLETE` on stdout ([`:58`](https://github.com/NormB/sipnab/blob/main/tests/privilege_drop_test.rs#L58)),
  because *"without it a child that took an early return would still exit 0, and
  the parent would read that silence as proof — a gate that cannot fail."*
- `announce_skip` writing to the **real** stderr
  ([`:66`](https://github.com/NormB/sipnab/blob/main/tests/privilege_drop_test.rs#L66)), because libtest swallows
  `eprintln!` on pass and *"exactly that left nine binaries reporting `ok` while
  proving nothing."*

The existing chroot child role
([`:632-660`](https://github.com/NormB/sipnab/blob/main/tests/privilege_drop_test.rs#L632-L660)) is the closest model: it
proves confinement by checking a marker file's visibility rather than by trusting
a return value.

### 7.3 Mutation, so the gate cannot be vacuous

Every gate above must be run **twice**: once with the sandbox installed,
requiring the denial, and once with `--no-sandbox`, requiring the same operation
to **succeed**. A denial test that passes with the filter removed is testing
something other than the filter — which is the standing rule in this repo, and
the reason the wasm memory-cap test was rewritten after it *"caught it by passing
— in 25 seconds."*

### 7.4 Coverage, so the list is not narrower than the shipped build

A gate that runs the enforce-mode binary over §3.1's corpus and requires
byte-identical output to the unfiltered run. This is the assertion that would
have caught an allowlist derived on a build that had no `--api`, or on x86_64 and
shipped for aarch64. It runs per target triple, because the list is per target
triple.

## 8. Recommendation

1. **Landlock first**, best-effort ABI, with the ruleset in §5. It carries no
   derivation risk, its failure mode is a weaker ruleset, and it closes the
   largest hole on its own.
2. **The reporting surface second** — startup log line, summary field,
   `capture_health` code, and `--require-sandbox`. Without it neither control can
   be shown to be present, and §7's gates have nothing to read.
3. **`--seccomp=log` third**, shipped, so the derivation is reproducible by
   someone on a platform the maintainer does not have.
4. **The derived filter last**, per target triple, enforce mode, with §7's four
   gates.

Steps 1 and 2 are independently valuable and the sequence stops cleanly after
either.

## 9. Open questions

- **Which crate?** `libseccomp` is LGPL-2.1 and would **fail
  [`deny.toml`](../../deny.toml)**, whose allowed list is
  `MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0,
  Unicode-DFS-2016, Zlib, GPL-3.0, GPL-3.0-only, OpenSSL`. `seccompiler`
  (Apache-2.0) and `landlock` (Apache-2.0 / BSD-3) pass that list.
  **Unverified:** their MSRV against `rust-version = "1.97"`, their transitive
  crate count, and their binary-size cost — all three are the kind of number
  [`wasm-plugin-api.md`](wasm-plugin-api.md) measured rather than argued, and
  none of them has been measured here.
- **Is the audit subsystem usable on the derivation host?** `auditctl` is
  installed; whether `audit=1` is set, `auditd` is running, and
  `SECCOMP_RET_LOG` records land somewhere readable is unverified.
- **Does `perf trace` work here?** Unverified — the binary exists; the subcommand
  and `perf_event_paranoid` have not been checked.
- **Does Docker's default profile permit installing a nested filter?**
  Unverified, and it decides whether the musl builds can be sandbox-tested in the
  same containers that build them.
- **Does the glibc NSS `dlopen` happen after the filter installs?**
  `drop_privileges` pre-loads NSS during `getpwnam_r`
  ([`src/privilege.rs:274`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L274), and the `.init_array`
  pre-load at [`:587`](https://github.com/NormB/sipnab/blob/main/src/privilege.rs#L587) exists because of a related
  deadlock), so the *drop* is covered. Reverse DNS runs on a background thread
  ([`src/names.rs:179`](https://github.com/NormB/sipnab/blob/main/src/names.rs#L179)) and may `dlopen` a different module
  later. Unverified which modules, and whether the first `getnameinfo` after the
  filter installs needs `mprotect(PROT_EXEC)`.
- **Should `--require-sandbox` also require Landlock, or only seccomp?** Landlock
  degrades by ABI level rather than by presence, so "required" needs a minimum
  ABI to mean anything, and no minimum has been argued for.
- **What is the right behaviour for `--cores N` offline?** The parallel engine
  spawns workers after the drop
  ([`parallel.rs`](../../src/parallel.rs)); whether the filter installs before or
  after the pool exists has not been examined, and thread creation is a syscall
  the filter must permit either way.
