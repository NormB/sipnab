# Uprobe TLS capture

This page explains how sipnab reads SIP that never appears in plaintext on any wire.
It also explains why each part of it refuses rather than guesses.

A uprobe is a kernel breakpoint on a userspace function.

- sipnab puts one on the write entry point of a TLS library.
- It reads the buffer the application passed: plaintext, before encryption.
- It needs no certificate, no private key, no keylog file, and no restart of
  the process it observes.

Everything here is `tracefs` and `perf_event_open`.

- There is no BPF program and no `bpf-linker`.
- That is what makes it build on stable Rust.
- It also makes it run on a kernel without BTF.
  - BTF is the **BPF Type Format**: the kernel's description of its
    own structs and where each member sits.
- See the section
  ["What tracefs cannot do"](#what-tracefs-cannot-do) for the one thing that costs.

---

## The shape of the problem

`SSL_write(SSL *ssl, const void *buf, int num)` gets a pointer and a length.

- A uprobe fetch argument reads a **fixed** number of bytes, chosen at install
  time.
- The write is whatever length the application passed.
- Those two disagree constantly.

The disagreement is not benign. Measured on a live OpenSIPS:

- A 512-byte fetch ran against a 128-byte SIP message.
- It returned the message followed by **384 bytes of
  adjacent process heap**.
- Those bytes were pointers, not zeros.
- On a SIP proxy that heap holds other calls' plaintext.

So the module exists to enforce one rule: *only the bytes the application
actually wrote may ever leave*.

- The module wipes everything past that.
- It does not merely ignore it.

```
SSL_write(ssl, buf, num)
        │
        ├─ kernel uprobe fires, fetches a FIXED band from buf
        │  and the value of num
        │
        ├─ in-kernel filter: len in band AND buf starts with a SIP token
        │  (evaluated BEFORE the event is recorded — a non-SIP write
        │   never costs a ring slot)
        │
        ├─ perf ring → userspace
        │
        ├─ accept(): truncate to num, volatile-wipe the tail
        │
        └─ Packet with source "uprobe:<comm>/<pid>", no addresses
```

## Banded probes

64 bytes is the kernel's hard ceiling for **one** fetch argument.

- It refuses `x8[65]`.
- So a larger band is several arguments side by side.
- 2048 is where it stops accepting more.
- That covers an ordinary `INVITE` with SDP.

`BANDS = [64, 256, 1024, 2048]`.

- There is one probe each on the same symbol.
- A filter limits each to its own length range.
- The band bounds the overshoot.
  - What the kernel delivers exceeds the true length by at most one band.
  - It does not exceed it by the largest message sipnab supports.
- It is a bound, not a guarantee.
  - That is why [`accept`](../../src/capture/uprobe/mod.rs) still truncates.

The wipe uses `write_volatile`.

- A plain loop or `fill` is a store to memory the
  compiler can prove nothing reads again.
- The compiler may delete that store.
- A wipe the optimiser removed is a wipe that never happened.

## Which library, and whose

`discover` reads `/proc/<pid>/maps`, not the filesystem.

- A library present on disk and a library in use are different facts.
- Only the second can produce traffic.

**Identity is device and inode, never the path.**

- One file is reachable through several paths, all at once:
  - a `libssl.so.3` symlink;
  - its versioned real name;
  - a container mount.
- Two *builds* of one flavor are genuinely two targets.
  - Their symbol offsets differ.
  - An offset computed from one is wrong for the other.

The container case is the one that captures nothing while looking healthy.
Measured on the development host, three distinct files share the path
`/usr/lib/aarch64-linux-gnu/libssl.so.3`:

| inode | mapped by |
|-------|-----------|
| 21143 | the host |
| 14166752 | one container |
| 146539451 | another container |

sipnab installs a uprobe with a path that resolves in **its own** mount
namespace.

- But that path came from the **mapping process's** mount namespace.
- Probing the bare string attaches to the host copy and misses both containers.
- `TlsLibrary::probe_path` reaches through `/proc/<pid>/root/`, followed by the library's path in the process's namespace.
  - It accepts a candidate only when the inode matches.
  - Otherwise it returns `None`.
  - It does not probe a file that merely has the right name.

### Flavors

| Flavor | Write symbol | Notes |
|---------|--------------|-------|
| OpenSSL | `SSL_write` | and the ABI-compatible forks that keep the name |
| wolfSSL | `wolfSSL_write` | same `(ssl, buf, len)` positions, so one probe shape serves both |

Ordinary hosts map GnuTLS. sipnab deliberately does **not** classify it.

- `gnutls_record_send` has a different signature.
- Probing it with the OpenSSL shape would read whatever the second argument
  register happens to hold.

Classification matches a basename **prefix**. That is what keeps the two apart.

- `libwolfssl.so.42` does not *begin* with `libssl`.
- A `contains` rule would claim it.
- It would then resolve `SSL_write` in a library that exports `wolfSSL_write`.

## Probe naming

```
sipnab_<pid>_l<slot>_b<band>
```

`uprobe_events` is a **system-wide** namespace.

- The pid keeps two sipnabs, or a sipnab beside another tracer, from colliding.
- The slot keeps one sipnab's own libraries apart.
  - Without it the second install reuses the first's names.
  - Then a mixed-flavor host captures exactly one of them.

## Two orders that are load-bearing

**Drop order.**

- The kernel refuses to remove a tracepoint that still has an open perf consumer.
- `UprobeReader` declares `bands` before `probes`.
  - Rust drops fields in declaration order.
  - So rings close first.
- Declared the other way round, a clean shutdown leaves every probe attached to
  a production library.
  - A measurement showed this; it is not a theory.
  - The first end-to-end run leaked four probes exactly that way.

**Never enable through tracefs.**

- `install` writes the probe and its filter.
- It does *not* write `enable`.
- `perf_event_open` cannot open a tracepoint that tracefs already switched on.
  - It fails with a misleading `EINTR`.
- An equivalent C program proved that before the explanation seemed credible.

Removal is always `-:<name>` **appended** to `uprobe_events`.

- Truncating that file removes every other tracer's probes on the host.

## Provenance, and why this input can never transmit

A uprobe sees bytes handed to a TLS library. It sees no socket, so:

- Addresses are `0.0.0.0`, and ports are `0`.
  - Filling in a plausible peer would make every dialog a small lie.
- The source name is `uprobe:<comm>/<pid>`.
  - That name carries the attribution.
- The frame pointer has **no digest**.
  - A digest exists so a resolver can prove it found the same bytes again.
  - Nothing can read these twice.
- [`resolve`](../../src/capture/resolve.rs) refuses such a pointer with
  `NeverOnTheWire` *before* touching the filesystem.

And the rule that follows from all of it:

```rust
pub fn kill_response_eligible(origin: InputOrigin, hep_allow_kill: bool) -> bool {
    match origin {
        InputOrigin::Wire => true,
        InputOrigin::Hep => hep_allow_kill,
        InputOrigin::Uprobe => false,  // no opt-in exists
    }
}
```

`--hep-allow-kill` can make HEP input transmit-eligible.

- Uprobe input **cannot**.
- There is deliberately no flag for it.
- sipnab never observed the peer.
  - So it has no address to answer to.
  - It would be guessing about where to send a response.

## What tracefs cannot do

These limits come from measurement, so the boundary is not a matter of opinion.
tracefs does these things in kernel space before recording an event:

- It fetches fixed byte ranges.
- It dereferences nested pointers.
- It glob-matches strings.

That covers the plaintext, the secrets, and the non-SIP prefilter.

What it cannot do is **carry state between two probes**. There is no map.

- That gap is exactly the 5-tuple.
- `SSL_write` knows nothing about the socket beneath.
- Recovering the peer means three steps:
  - hooking `tcp_sendmsg`;
  - reading `struct sock`;
  - matching per thread across two hooks.

That is what the **BPF backend** does: `--uprobe-backend bpf`.

- The section
  ["The BPF backend, and what it costs"](#the-bpf-backend-and-what-it-costs) describes it.
- [The backlog](../design/backlog.md) records the live verification.
- It also records the three silent failures that turned up producing it.

## The BPF backend, and what it costs

The backend is two programs and one rule, in `bpf/`.

- It is a separate package with its own empty `[workspace]` table.
- sipnab's workspace excludes it.
- So a stock `cargo build` never demands the nightly toolchain it needs.

The two programs:

- A **uprobe** on the TLS write symbol parks the plaintext under its thread id.
- A kernel probe on `tcp_sendmsg` claims it, stamps the socket's addresses on
  it, and submits it.

They pair **by thread, and only by thread**.

- A TLS library encrypts and sends on the calling thread, back to back.
- Sometimes that pairing does not hold: a write the library buffered rather than sent.
  - Then the record goes out with **no addresses** rather than a guessed peer.
  - The host builds it exactly as a tracefs packet.
- Filling in a plausible peer for that case would make the honest case worthless.
  - Nothing downstream could tell them apart.

### The offsets come from the running kernel

`aya-ebpf` at this version has no CO-RE read helpers.

- So offsets compiled into the program would be right on one kernel.
- They would be silently wrong on the next.
- The host reads them from `/sys/kernel/btf/vmlinux` itself
  ([`btf.rs`](../../src/capture/uprobe/btf.rs)).
- It writes them into a map before either program attaches.
- Until then `valid` is zero and the program does not read a socket at all.
  - The reason: **zero is a legal offset**.

`aya` cannot do this lookup.

- It parses BTF.
- But `Struct::members` is `pub(crate)`.

### Two traps this cost a day to find

**`include_bytes!` yields alignment 1.**

- The ELF parser under `aya` casts the header out of the buffer rather than copying it.
- It rejects a byte-aligned buffer with `error parsing ELF data`.
  - That reads as a corrupt object and sends you to the build.
- The same bytes load from an aligned buffer.
  - They fail from one offset by a single byte.
- sipnab copies the program into a `Vec<u64>` before loading it.

**Hand-counted field offsets were wrong, and the tests were wrong the same
way.**

- So they agreed with each other and not with the kernel.
- `sport` sat at 48 while the reader looked at 64.
- Every captured message reported `0.0.0.0:0` while the suite stayed green.
- The host now reads the record **by field** through the shared `#[repr(C)]` type.
- [`sipnab-bpf-types`](../../crates/sipnab-bpf-types/src/lib.rs) pins every
  offset rather than only the total size.

### It is not the default

It needs BTF, and the development host has none.

- A backend unavailable on the box its authors use is a backend nobody tests.
- So tracefs stays the default.
- An operator chooses this one by name.
- sipnab refuses it in a build or on a kernel that cannot run it.
  - It does not quietly downgrade.

## Testing it

The unit tests run everywhere. These parts are ordinary byte and string handling:

- record decoding;
- band selection;
- filter construction;
- classification;
- the planning rules.

`InstalledProbes` takes a tracefs **root**.

- So the install and drop-guard tests run against a temporary directory.
- They do not run against the kernel.

Nothing can fake the kernel's own record layout.

- So `record::parse_layout` runs against verbatim `format` output from a 6.8 kernel.

### The half the suite cannot reach

Everything above runs without privilege. Loading an eBPF program does not.

That asymmetry is not a detail. Through four releases:

- the object built on every run;
- the suite stayed green;
- the verifier rejected the program on every kernel that had it.

Building had cover. Loading, attaching and reading had none.
Those are where the failures live.

Read any coverage figure over
[`bpf.rs`](../../src/capture/uprobe/bpf.rs) with that in mind.

- The lines the suite executes are record decoding and planning.
- The load is unreachable from a process that must never acquire the privilege to try.

A manual, out-of-band run against a PUBLISHED artifact covers it instead.

- It is not a local build.
- A local build is not what anyone installs.

Whatever the site currently advertises:

```sh
sudo scripts/verify-bpf-load.sh
```

Or a specific release:

```sh
sudo scripts/verify-bpf-load.sh 0.5.166
```

The script does four things:

- It downloads the tarball.
- It checks it against the checksum published beside it.
- It runs it.
- It judges the output.

The judging half is a separate mode (`--classify`), so a test can drive it.

- [`tests/bpf_load_verification_test.rs`](../../tests/bpf_load_verification_test.rs) does.
- It uses the real message from a real attach.
- It uses the real refusal from the release that failed.
- A run that prints neither counts as no verdict rather than as a pass.
  - The four broken releases turned on that distinction.

Each successful run gets a row here.

- `the_load_verification_record_names_the_published_release`
  requires one for whatever `published_version` names.
- So advertising a release nobody has loaded fails the suite:

| Version | Artifact | Host | Kernel | Date (UTC) | Result |
|---|---|---|---|---|---|
| 0.5.162 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-10 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.163 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-10 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.164 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-10 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.165 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-11 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.166 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-11 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.167 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-11 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.168 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-12 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.169 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-13 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.170 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-14 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.171 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-14 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.172 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-14 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.173 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-15 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.174 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-15 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.175 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-15 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.176 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-16 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.177 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 7.0.14-3-pve | 2026-09-17 | attached, 1 library plus `tcp_sendmsg` |
| 0.5.178 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-17 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.179 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-18 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.180 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-18 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.181 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-19 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.182 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-21 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.183 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-21 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.184 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-22 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.185 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-22 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.186 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-23 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.187 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-23 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.188 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-23 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.189 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-24 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.190 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-25 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.191 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-26 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.192 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-26 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.193 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-27 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.194 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-28 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.195 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-28 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.196 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-29 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.197 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-09-30 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.198 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-01 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.199 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-01 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.200 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-01 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.201 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-02 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.202 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-03 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.203 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-06 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.204 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-06 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.205 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-07 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.206 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-07 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.207 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-08 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.208 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-09 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.209 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-09 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.210 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-11 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.211 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-11 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.212 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-12 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.213 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-12 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.214 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-12 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.215 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.105+deb13-amd64 | 2026-10-13 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.216 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-13 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.217 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-13 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.218 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-14 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.219 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-14 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.220 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-14 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.221 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-15 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.222 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-16 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.223 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-16 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.224 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-16 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.225 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-17 | attached, 2 libraries plus `tcp_sendmsg` |
| 0.5.226 | x86_64-unknown-linux-gnu | Debian 13, x86_64 | 6.12.111+deb13-amd64 | 2026-10-18 | attached, 2 libraries plus `tcp_sendmsg` |

That requirement makes this file part of every phase-two release commit.

- The classifier deciding what a phase-two commit looks like has to agree with that.
- It did not, on 0.5.164:
  - the verification had run;
  - the row sat in the commit;
  - the delivery gates refused the push, because they read the record as ordinary work.
- Both sides now read `LOAD_VERIFICATION_RECORD` in
  [`tests/support/release_logic.rs`](../../tests/support/release_logic.rs).
  - So nobody can hand one side a new obligation without the other hearing about it.

Mutation-test any gate you add here.

- One of these tests began life believing the flavor list's *order* prevented
  misclassification.
- Reversing the order did not fail it.
  - `strip_prefix` already separates the two.
- The comment was wrong, not the code. See
  [`discover.rs`](../../src/capture/uprobe/discover.rs).

## Running it by hand

What sipnab would probe, without installing anything:

```sh
sudo sipnab --uprobe-list
```

Capture, probing every TLS library discovered. This is the default.

- An ordinary host runs more than one.
- Probing only the one you had in mind misses the rest silently.

```sh
sudo sipnab -N --uprobe-tls
```

One flavor only, when the other stack is not yours to read.

- The flag is repeatable.
- So naming both is the same as naming neither.

```sh
sudo sipnab -N --uprobe-tls --uprobe-flavor openssl
```

```sh
sudo sipnab -N --uprobe-tls --uprobe-flavor wolfssl
```

One specific library.

- This is also how to reach a daemon that has not started yet.
- Discovery can only see what something has already mapped.

```sh
sudo sipnab -N --uprobe-tls --uprobe-library /usr/lib/x86_64-linux-gnu/libssl.so.3
```

Inspect the kernel state sipnab created. It should be empty after exit:

```sh
sudo grep sipnab_ /sys/kernel/tracing/uprobe_events
```

That last command may print something after sipnab has exited. Then probes leaked.

- Remove each by appending `-:<name>` to `uprobe_events`.
- **Never truncate the file.**
  - Every other tracer on the host shares it.
