+++
title = "Read SIP over TLS on a server you cannot restart, using eBPF uprobes"
date = 2026-09-01
updated = 2026-10-16
description = "Steps to read the unencrypted SIP inside a running TLS server process with sipnab's uprobe capture, with no key, no certificate and no restart, and what each backend can and cannot show."

[extra]
kind = "howto"
+++

## In short

A phone system may encrypt its call signaling with TLS. Then a network
recording shows only scrambled bytes.

You may have administrator (root) access to the server but be unable to
restart it or obtain its keys. Then sipnab can read the signaling inside the
running server program, just before the program encrypts it.

This how-to walks through:

- checking that the server is readable,
- running the capture,
- getting the network addresses of the other side when you need them.

## Who this is for

Engineers with root on a Linux host running a SIP server over TLS. They cannot
restart it.

Read
[Decrypting SIP over TLS from session key logs](@/notes/reading-tls-without-a-certificate.md)
instead in either of these cases:

- You can restart an endpoint with `SSLKEYLOGFILE` set.
- You want keys that decrypt a recording later.

## What this method does and does not do

A uprobe is a Linux kernel hook on a function in a program or shared library.

- `--uprobe-tls` places one on the TLS library's write function:
  - `SSL_write` for OpenSSL,
  - `wolfSSL_write` for wolfSSL.
- It reads the bytes the server hands to that function, before the library
  encrypts them.
- It recovers no key and decrypts no recording.
- The plaintext exists only in the sipnab run that read it.
- To keep a recording that others can decrypt later, use the key log method in
  the note linked above.

It reads process memory. So anyone who can run it can read every SIP session on
that host, credentials included. Read the security section of the uprobe
walkthrough before using it on a production host.

## Steps

Most commands below need root and a running TLS server. The example output of
those commands comes from the
[uprobe walkthrough](@/docs/uprobe-walkthrough.md), recorded on other hosts.
Your library paths, process IDs and addresses differ from these.

- Confirm that the host is Linux with tracefs (the kernel's tracing file
  system) mounted:

```bash
ls -d /sys/kernel/tracing
```

```text
/sys/kernel/tracing
```

   If the directory is missing, the uprobe walkthrough shows how to mount it.

- List the TLS libraries sipnab would probe. This installs nothing:

```bash
sudo sipnab --uprobe-list
```

   Example output from one host:

```text
FLAVOR        INODE  PIDS  LIBRARY
OpenSSL        21143    12  /proc/954/root/usr/lib/x86_64-linux-gnu/libssl.so.3
wolfSSL     17433084     1  /proc/982702/root/usr/lib/libwolfssl.so.42.2.0
```

   Each row is one library file. It shows:

   - the number of processes (PIDS) that map it,
   - its path as seen through one of those processes (`/proc/<pid>/root`).
     This also works for a server running in a container.

   Two rows with the same path and different inodes are two different copies of
   the library.

   The list may not show your SIP server's library. Then the capture cannot
   read it. For example, a server statically linked with its TLS library maps no
   `libssl` file. `--uprobe-library <PATH>` names a library directly instead.

   When sipnab finds nothing, it prints this and exits with code 1:

```text
No TLS library is mapped by any process sipnab can see.
Either nothing here uses OpenSSL or wolfSSL, or sipnab cannot read
/proc/<pid>/maps — try again as root.
```

   A run without root sees only its own processes. So run this as root before
   concluding the host uses no TLS.

- Start the capture with the default `tracefs` backend:

```bash
sudo sipnab -N --uprobe-tls
```

   Example line from such a run:

```text
12:57:47.360 0.0.0.0:0 -> 0.0.0.0:0 REGISTER TCP origin=uprobe
```

   This backend sees no network connection. So:

   - messages carry no addresses (`0.0.0.0:0`),
   - dialogs carry the label `uprobe:<process>/<pid>`,
   - `origin=uprobe` marks the line as uprobe input.

   sipnab probes every TLS library it found. `--uprobe-flavor openssl` or
   `--uprobe-flavor wolfssl` narrows that.

- The capture may attach but report no messages. Then the server may call a
  different write function.
  - Some OpenSSL 3 programs call `SSL_write_ex` instead of `SSL_write`.
  - List the write functions the server binary imports. Replace
    `/usr/sbin/opensips` with your server's binary:

```bash
nm -D --undefined-only /usr/sbin/opensips | grep -i ssl_write
```

  - Then probe the function it names, for example `SSL_write_ex`:

```bash
sudo sipnab -N --uprobe-tls --uprobe-symbol SSL_write_ex
```

- To get the other side's address and port, use the `bpf` backend.
  - It pairs each write with the kernel's `tcp_sendmsg` call on the same
    thread.
  - It recovers the connection's addresses.
  - It needs three things:
    - a sipnab built with the `bpf` feature,
    - a build that also produced the kernel programs. This needs `bpf-linker`
      and a nightly Rust toolchain on the build host.
    - a kernel with BTF (`CONFIG_DEBUG_INFO_BTF`), which provides
      `/sys/kernel/btf/vmlinux`.
  - Check the build first:

```bash
sipnab --version
```

   Example output from a build that carries the `bpf` feature:

```text
sipnab 0.5.222 (16f7b0ea) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,wasm,plugins,bpf,vcon,opus,archive,g729
libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
```

   Look for `bpf` in the `features:` list.

   - When `bpf` is missing, `--uprobe-backend bpf` logs this error and exits
     with code 1:

```text
--uprobe-backend bpf needs a sipnab built with the `bpf` feature; this binary does not carry it
```

   - When the list includes `bpf` but the build host had no `bpf-linker`, sipnab
     refuses with an error that says the binary carries "no kernel programs".
     Rebuild where `cargo install bpf-linker` has run, or use the `tracefs`
     backend.
   - sipnab never falls back to `tracefs` on its own.

   With all three in place, widen `--portrange`. The ports a uprobe reports are
   the connection's actual ports, often not 5061:

```bash
sudo sipnab -N --uprobe-tls --uprobe-backend bpf --portrange 0-65535
```

   Example output:

```text
200 OK     127.0.0.1:15061 -> 127.0.0.1:36160  TCP  uprobe:python3/349147#0
REGISTER   127.0.0.1:36160 -> 127.0.0.1:15061  TCP  uprobe:python3/349147#1
```

   The library may buffer a write instead of sending it at once. That write does
   not pair with a send. sipnab reports that message with no addresses rather
   than guessing one.

- After the capture, confirm that sipnab removed its probes.
  - This is for the tracefs backend only. The kernel frees the programs of the
    `bpf` backend on exit.
  - This prints nothing when no sipnab probe remains:

```bash
sudo grep sipnab_ /sys/kernel/tracing/uprobe_events
```

## Choosing between this and a key log

| You need | Use |
|---|---|
| The SIP text now, with no keys and no restart | `--uprobe-tls` (the `tracefs` steps above) |
| The same, plus the other side's address and port | `--uprobe-tls --uprobe-backend bpf` (the `bpf` backend step above) |
| A recording that you or others can decrypt later | Keys from the endpoint or from eCapture, read with `--keylog` or `--keylog-fd`; see [Decrypting SIP over TLS from session key logs](@/notes/reading-tls-without-a-certificate.md) |

The server's private key (`--tls-key`) decrypts only TLS 1.2 sessions that used
RSA key exchange. Sessions using ECDHE, DHE or TLS 1.3 have forward secrecy.
The private key does not decrypt them.

## Terms used here

- **SIP**: the protocol that sets up, changes and ends phone calls over IP.
- **TLS**: the protocol that encrypts a network connection.
- **Plaintext**: the unencrypted content.
- **Root**: the Linux administrator account.
- **uprobe**: a Linux kernel hook placed on a function in a user program or
  library.
- **tracefs**: the kernel file system under `/sys/kernel/tracing`. Programs
  manage tracing hooks through it.
- **eBPF / `bpf` backend**: a Linux facility that runs small verified programs
  in the kernel. sipnab's `bpf` backend uses it to read the connection
  addresses.
- **BTF**: BPF Type Format, the kernel's description of its own data
  structures, at `/sys/kernel/btf/vmlinux`.
- **Inode**: the file system's number for one file. Two paths with the same
  inode are the same file.
- **Shared library / statically linked**: code loaded from a separate file at
  run time, compared with code built into the program itself.
- **Dialog**: one SIP conversation, such as one call.
- **Forward secrecy**: a key-exchange property. Under it, the server's private
  key cannot decrypt recorded sessions.
- **eCapture**: an open-source eBPF tool that extracts TLS keys from running
  programs.

## Related guides

- [Read TLS without keys (eBPF): can your system run this at all?](@/docs/uprobe-walkthrough.md#can-your-system-run-this-at-all)
- [The quickest answer to all three](@/docs/uprobe-walkthrough.md#the-quickest-answer-to-all-three)
- [Security implications, stated plainly](@/docs/uprobe-walkthrough.md#security-implications-stated-plainly)
- [Walkthrough: the tracefs backend](@/docs/uprobe-walkthrough.md#walkthrough-the-tracefs-backend)
- [Walkthrough: the eBPF backend](@/docs/uprobe-walkthrough.md#walkthrough-the-ebpf-backend)
- [Cleaning up](@/docs/uprobe-walkthrough.md#cleaning-up)
- [Capture SIP over TLS: which method can you use?](@/docs/tls-capture.md#which-method-can-you-use)
- [No keys at all](@/docs/tls-capture.md#no-keys-at-all-read-the-plaintext-in-the-process)
  and [Plaintext and the peer address](@/docs/tls-capture.md#plaintext-and-the-peer-address)
- Cookbook [7g](@/docs/cookbook.md#read-tls-with-no-keys-at-all) and
  [7h](@/docs/cookbook.md#read-tls-and-who-the-peer-was)
- [CLI reference: TLS / decryption](@/docs/cli.md#tls-decryption)
