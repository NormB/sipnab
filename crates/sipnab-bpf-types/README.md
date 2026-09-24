# The `sipnab-bpf-types` crate

The record layout behind [sipnab](https://crates.io/crates/sipnab)'s eBPF TLS
capture: the one backend that reads SIP over TLS with no keys **and** reports
the real peer address of every message.

## For operators: what this powers

sipnab can read SIP out of a TLS library's memory as the library writes it, so
it needs no certificate, no private key and no restart of the process you
watch. Two backends do this. `tracefs` works on any Linux with tracefs mounted,
but it sees no socket, so each message names a process and no peer. `bpf` pairs
each write with the `tcp_sendmsg` call that sent it and so recovers the real
addresses and ports. This crate defines the record that the `bpf` backend's
kernel program hands to sipnab, one record per write.

Use the `bpf` backend when you cannot get the TLS keys, you have root on the
host that runs the SIP process, and you need to know who each message went to.
It needs a Linux kernel built with `CONFIG_DEBUG_INFO_BTF=y` and a sipnab built
with its kernel programs. First see which TLS libraries sipnab would probe.
This installs nothing:

```sh
sudo sipnab --uprobe-list
```

Then capture, with the real peer addresses:

```sh
sudo sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535
```

Widen `--portrange`, because the port a uprobe reports is whatever the socket
used, often an ephemeral one. A sipnab built without the kernel programs, or a
kernel without BTF, refuses `--uprobe-backend bpf` by name rather than falling
back to a capture with no peers. Build one that carries the programs with
`SIPNAB_BPF_REQUIRED=1 cargo build --release --features bpf` on a host with a
nightly toolchain and `bpf-linker`.

Read on in the operator guides:

- [Reading SIP over TLS without keys](https://github.com/NormB/sipnab/blob/main/docs/uprobe-walkthrough.md#walkthrough-the-ebpf-backend),
  the eBPF walkthrough, with its requirements, build, output and troubleshooting.
- [Capture SIP over TLS](https://github.com/NormB/sipnab/blob/main/docs/tls-capture.md#4-plaintext-and-the-peer-address),
  which compares every TLS method sipnab offers.
- [Security implications](https://github.com/NormB/sipnab/blob/main/docs/uprobe-walkthrough.md#security-implications-stated-plainly).
  Anyone who can run this can read every SIP session on the host, credentials
  included.

You never add this crate to a project to use the capture. Install
[`sipnab`](https://crates.io/crates/sipnab), which depends on it.

## For developers: why it is a crate

The kernel half is a `no_std` program built for `bpfel-unknown-none` with a
nightly toolchain. The host half is ordinary sipnab. They exchange bytes
through a perf ring buffer, so both must agree on the layout exactly. When they
disagree, the build still succeeds and the host decodes a plausible SIP message
out of misaligned fields. So this crate defines the layout once, and both sides
compile against it.

| Item | What it is |
|---|---|
| `TlsRecord` | One plaintext write captured from a TLS library: process and thread IDs, length, flags, both socket addresses and ports, address family, the command name, and up to `MAX_PAYLOAD` bytes of data |
| `TlsRecord::read` | The host's reader: turns one perf sample into a record and the payload bytes that are safe to use |
| `SockOffsets` | Where the fields of the kernel's `struct sock` sit. sipnab reads them from the running kernel's BTF and hands them to the program before it attaches, so the program carries no compiled-in offset |
| `MAX_PAYLOAD` | The largest plaintext one record carries: 2,048 bytes |
| `FAMILY_IPV4`, `FAMILY_IPV6` | The address families a record can carry |
| `FLAG_HAS_TUPLE` | The program observed the record's addresses rather than leaving them unknown |
| `FLAG_TRUNCATED` | The application wrote more than `MAX_PAYLOAD`, so `data` is a prefix |

### Read one record

A sample is shorter than a `TlsRecord`. The program submits only
`TlsRecord::used_len(payload)` bytes, the header and the bytes written, so a
sample cannot be viewed in place as a `&TlsRecord`. `TlsRecord::read` copies
the header out and hands back the payload. The example builds the sample the
program would submit for one `INVITE`. A real one comes off the perf ring.

```rust
use core::net::SocketAddr;
use sipnab_bpf_types::{FAMILY_IPV4, FLAG_HAS_TUPLE, TlsRecord};

let invite = b"INVITE sip:bob@example.net SIP/2.0\r\nCall-ID: a84b4c76e66710\r\n\r\n";

// What the kernel program writes: an INVITE from 192.0.2.10:5061 to
// 198.51.100.7:5060, sent by an `opensips` process.
let mut sent = TlsRecord {
    pid: 4242,
    tid: 4243,
    len: invite.len() as u32,
    flags: FLAG_HAS_TUPLE,
    sport: 5061,
    dport: 5060,
    family: FAMILY_IPV4,
    ..TlsRecord::ZEROED
};
sent.saddr[..4].copy_from_slice(&[192, 0, 2, 10]);
sent.daddr[..4].copy_from_slice(&[198, 51, 100, 7]);
sent.comm[..8].copy_from_slice(b"opensips");
let mut sample = sent.header_bytes().to_vec();
sample.extend_from_slice(invite);
assert_eq!(sample.len(), TlsRecord::used_len(invite.len()));

// What the host does with it.
let (record, payload) = TlsRecord::read(&sample).expect("a whole header arrived");
assert_eq!(payload, invite);
assert_eq!(record.command(), b"opensips");
assert_eq!((record.pid, record.tid), (4242, 4243));

let (from, to) = record.socket_addrs().expect("the program saw the socket");
assert_eq!(from, "192.0.2.10:5061".parse::<SocketAddr>().unwrap());
assert_eq!(to, "198.51.100.7:5060".parse::<SocketAddr>().unwrap());
```

### What the reader refuses

A sample shorter than the header is refused, never decoded from a partial
header. The payload runs to the smallest of `len`, `MAX_PAYLOAD` and the bytes
that arrived, so neither a bad length nor the padding perf adds to a sample can
widen it.

```rust
use sipnab_bpf_types::{FLAG_TRUNCATED, MAX_PAYLOAD, TlsRecord};

// Too short to hold a header.
assert!(TlsRecord::read(&[0u8; TlsRecord::HEADER_LEN - 1]).is_none());

// A 5,000-byte write: the program kept the first MAX_PAYLOAD bytes and said so.
let sent = TlsRecord {
    len: 5000,
    flags: FLAG_TRUNCATED,
    ..TlsRecord::ZEROED
};
let mut sample = sent.header_bytes().to_vec();
sample.extend_from_slice(&[b'x'; MAX_PAYLOAD]);
sample.extend_from_slice(&[0; 7]); // perf pads a sample to a multiple of eight bytes
let (record, payload) = TlsRecord::read(&sample).unwrap();
assert_eq!(payload.len(), MAX_PAYLOAD);
assert_eq!(record.len, 5000);
assert_ne!(record.flags & FLAG_TRUNCATED, 0, "the message is a prefix");

// A length that claims more than arrived reads only what arrived.
let sent = TlsRecord { len: 2048, ..TlsRecord::ZEROED };
let mut sample = sent.header_bytes().to_vec();
sample.extend_from_slice(b"BYE");
assert_eq!(TlsRecord::read(&sample).unwrap().1, b"BYE");
```

### Peers: only what the program observed

The addresses mean something only when `FLAG_HAS_TUPLE` is set. A write the
library buffered rather than sent has no socket to pair with, and its record
still carries whatever sat in the buffer. `socket_addrs` returns `None` for
it, and for a family other than `FAMILY_IPV4` or `FAMILY_IPV6`. An IPv4
address sits in the first four bytes of `saddr` and `daddr`, and an IPv6 one
fills all sixteen.

```rust
use core::net::{Ipv6Addr, SocketAddr};
use sipnab_bpf_types::{FAMILY_IPV4, FAMILY_IPV6, FLAG_HAS_TUPLE, TlsRecord};

let mut rec = TlsRecord {
    flags: FLAG_HAS_TUPLE,
    family: FAMILY_IPV6,
    sport: 5061,
    dport: 5061,
    ..TlsRecord::ZEROED
};
rec.saddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
rec.daddr = "2001:db8::2".parse::<Ipv6Addr>().unwrap().octets();
let (from, to) = rec.socket_addrs().unwrap();
assert_eq!(from, "[2001:db8::1]:5061".parse::<SocketAddr>().unwrap());
assert_eq!(to, "[2001:db8::2]:5061".parse::<SocketAddr>().unwrap());

// The same bytes read as IPv4 give the first four of them.
rec.family = FAMILY_IPV4;
assert_eq!(rec.socket_addrs().unwrap().0.ip().to_string(), "32.1.13.184");

// No FLAG_HAS_TUPLE: the addresses are left over, not observed.
rec.flags = 0;
assert_eq!(rec.socket_addrs(), None);
```

### Socket offsets come from the running kernel

`SockOffsets` tells the program where `struct sock` keeps the family,
addresses and ports. sipnab reads them from the running kernel's BTF, sets
`valid`, and writes them into the program's map before it attaches. A zero
offset is a real offset, so the program reads no socket while `valid` is clear.

```rust
use sipnab_bpf_types::SockOffsets;

// What the program sees before the host has written anything.
let unset = SockOffsets::default();
assert_eq!(unset.valid, 0, "the program refuses to read a socket");

// What the host writes once every offset has resolved. The numbers are
// illustrative. Real ones depend on the kernel build.
let resolved = SockOffsets {
    family: 16,
    saddr4: 4,
    daddr4: 0,
    saddr6: 72,
    daddr6: 56,
    sport: 14,
    dport: 12,
    valid: 1,
};
assert_ne!(resolved.valid, 0);
assert_ne!(resolved, unset);
```

## Properties

- `#![no_std]` with no dependencies by default. Everything here has to compile
  for a target with no allocator and a verifier that rejects anything it
  cannot prove. The reading helpers compile for the host only. `read`
  returns a 2 KiB record by value, four times the 512-byte stack the BPF
  verifier allows, so the kernel half keeps its records in a map instead.
- `#[repr(C)]`, fixed-size arrays, and padding that has a name. Rust's default
  representation guarantees no field order, and a hole the compiler chooses is
  a hole the two halves can disagree about.
- The `pod` feature (Linux only) implements `aya::Pod` for `TlsRecord` and
  `SockOffsets`, so `aya` can read and write them through its maps. It pulls
  in `aya`, and the kernel build never enables it.

## Stability

sipnab versions this crate for its own use, and changes the layout whenever
its BPF program needs it to. It makes no promise to any other consumer.

## License

Licensed under either of
[Apache License, Version 2.0](https://github.com/NormB/sipnab/blob/main/crates/sipnab-bpf-types/LICENSE-APACHE)
or [MIT license](https://github.com/NormB/sipnab/blob/main/crates/sipnab-bpf-types/LICENSE-MIT),
at your option.
