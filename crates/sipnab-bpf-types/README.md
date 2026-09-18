# The `sipnab-bpf-types` crate

The record layout shared between [sipnab](https://crates.io/crates/sipnab) and
the eBPF program behind its uprobe TLS-capture backend.

**You probably want [`sipnab`](https://crates.io/crates/sipnab), not this
crate.** It exists on crates.io only because `sipnab` depends on it. sipnab
builds its kernel-side program for `bpfel-unknown-none`, with no `std`, and
that program writes records into a perf ring buffer. sipnab's userspace reads those records
back. If the two sides disagree about the layout, the build still succeeds and
the host decodes a plausible-looking but wrong SIP message. So this crate
defines the layout once, and both sides compile against it.

## What it contains

| Item | What it is |
|---|---|
| `TlsRecord` | One plaintext write captured from a TLS library: process and thread IDs, length, flags, both socket addresses and ports, address family, the command name, and up to `MAX_PAYLOAD` bytes of data |
| `SockOffsets` | Where the fields of the kernel's `struct sock` sit. sipnab reads them from the running kernel's BTF and hands them to the program before it attaches, so the program carries no compiled-in offset |
| `MAX_PAYLOAD` | The largest plaintext one record carries: 2,048 bytes |
| `FAMILY_IPV4`, `FAMILY_IPV6` | The address families a record can carry |
| `FLAG_HAS_TUPLE` | The program observed the record's addresses rather than leaving them unknown |
| `FLAG_TRUNCATED` | The application wrote more than `MAX_PAYLOAD`, so `data` is a prefix |

## Properties

- `#![no_std]` with no dependencies by default. Everything here has to compile
  for a target with no allocator and a verifier that rejects anything it
  cannot prove.
- `#[repr(C)]` with the padding named, so the two compilers cannot choose
  different layouts.
- The `pod` feature (Linux only) implements `aya::Pod` for `TlsRecord` and
  `SockOffsets`, so `aya` can read and write them through its maps. It pulls
  in `aya`, and the kernel build never enables it.

## Stability

sipnab versions this crate for its own use, and changes the layout whenever
its BPF program needs it to. It makes no promise to any other consumer.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.
