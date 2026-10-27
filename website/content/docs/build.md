+++
title = "Build sipnab from source"
weight = 30
description = "Build sipnab from source: cargo, the feature-flag matrix, release profile, and cross-compilation."
+++

Most users should [install a binary](@/docs/install.md). Build from source when you need a custom feature set or target.

## Install from crates.io with cargo

```bash
cargo install sipnab --features full
```

## Building from source

### Build prerequisites

- **Rust 1.99+**
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)
- **cmake and a C compiler**, for `full` or `opus`: the `opus` feature compiles libopus from source and links it into the binary

### Install from a checkout, with capabilities

`cargo install` has no post-install hook. So a source install leaves you to run
`--setup-caps` yourself. [`scripts/install-from-source.sh`](https://github.com/NormB/sipnab/blob/main/scripts/install-from-source.sh) does both:

- Clone the repository:

   ```bash
   git clone https://github.com/NormB/sipnab.git
   ```

- Change into the checkout:

   ```bash
   cd sipnab
   ```

- Run the install script:

   ```bash
   ./scripts/install-from-source.sh --features full
   ```

The script does this:

- It runs `cargo install --path . --bin sipnab`, forwarding any arguments.
- Then on Linux it invokes the binary's own `--setup-caps`. So live capture
  works without `sudo`.
- Non-Linux platforms skip the capability step and point you at `sudo`.

This is a *source* install. It is distinct from the one-line installer at
<https://sipnab.com/install.sh>.

- That installer downloads a prebuilt release binary.
- It compiles nothing.

### Basic build (TUI only, default features)

- Clone the repository:

   ```bash
   git clone https://github.com/NormB/sipnab.git
   ```

- Change into the checkout:

   ```bash
   cd sipnab
   ```

- Build the release binary:

   ```bash
   cargo build --release
   ```

- Copy it onto your `PATH`:

   ```bash
   sudo cp target/release/sipnab /usr/local/bin/
   ```

### Full-features build

```bash
cargo build --release --features full
```

### Debug build with logging

```bash
SIPNAB_LOG=trace cargo run -- -N -I test.pcap
```

## Feature flags

sipnab uses Cargo feature flags to control optional capability. The default build includes `native`, `tui`, `audio`, and `metrics`.

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required (directly or transitively) by `tui`, `hep`, `metrics`, `api`, `mcp`, `mcp-http`, `plugins`, `bpf`, `vcon`, `archive` and `g729`. Not required by `tls`, `audio`, or `wasm`.** Included by default. | `pcap`, `clap`, `clap_complete`, `env_logger`, `crossbeam-channel`, `libc`, `pcap-file`, `memmap2`, `tracing-subscriber`, `tracing-log`, `tempfile` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width`, `base64` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Builds the separate `sipnab-audio` plugin (`libsipnab_audio.so`) that the binary `dlopen`s lazily; the binary itself does **not** link `libasound.so.2`. | `libloading`, `libc` (plugin: `rodio`) |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `rsa`, `aes`, `cbc`, `zeroize`, `base64`, `libc` |
| `hep` | HEP v3 send + v1/v2/v3 receive (Homer Encapsulation Protocol) | `native`, `hmac`, `sha2`, `rustls`, `base64` |
| `api` | REST API + Prometheus metrics endpoint, over HTTP or HTTPS. Runs on a background thread in the sipnab process, sharing its address space — not a separate OS process, so treat the bind address and API key accordingly. | `native`, `axum`, `tokio`, `base64`, `hmac`, `sha2`, `utoipa`, `rustls`, `tokio-rustls`, `ring`, `hyper`, `hyper-util`, `futures-core` |
| `mcp` | Model Context Protocol server, stdio transport. Lets an AI agent, such as Claude Code or Claude Desktop, drive sipnab. | `native`, `tokio`, `rmcp`, `base64`, `hmac`, `sha2` |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Adds the `--mcp-transport http` option. | `mcp`, `api`, `rmcp/transport-streamable-http-server` |
| `metrics` | Standalone Prometheus `/metrics` server on a plain TCP listener and threads. Needs neither the `api` feature nor an async runtime. Included by default. | `native`, `base64`, `rustls` |
| `plugins` | WASM plugin host (`--plugin`): runs third-party dialog detections in a sandbox that has no access to the sipnab process. | `native`, `wasmi` |
| `bpf` | eBPF TLS capture (`--uprobe-backend bpf`): reads SIP plaintext **and the peer addresses** with no key material. Needs a nightly toolchain and `bpf-linker` to build, and a kernel with `CONFIG_DEBUG_INFO_BTF` to run — without the linker the binary still builds, and `--uprobe-backend bpf` refuses at run time. | `native`, `aya`, `sipnab-bpf-types/pod` |
| `vcon` | vCon export: one observed dialog as an IETF conversation container, with the audio inline when the run retained it, or signed and encrypted when a `[[vcon.rule]]` sets `encrypt_to`. Not in the default build. Adds `--export-vcon`/`--vcon-out`, the `export_vcon` MCP tool and `GET /v1/dialogs/{call_id}/vcon`. | `native`, `sha2`, `hmac`, `base64`, `rustls`, `rsa`, `ring`, `aes`, `cbc`, `sha1_oaep`, `sha1`, `webpki`, `p256` |
| `opus` | Ogg Opus recordings in vCon containers (`audio_format = "opus"` on a `[[vcon.rule]]`). Compiles libopus from the source `opusic-sys` vendors and links it statically, so building it needs `cmake` and a C compiler; the binary needs no system libopus. In `full`; not in the static musl builds, which have no vCon export. | `vcon`, `opus` |
| `archive` | Password-protected ZIP and 7z input: `-I evidence.zip` reads the captures inside, stored, deflated, WinZip AES or ZipCrypto, and `-I evidence.7z` reads LZMA or LZMA2, AES-256 or not, without leaving a decrypted copy on disk. Adds `--archive-password-file`, `--archive-password-command`, `--archive-password-stdin`, `--archive-password` and `--archive-password-encoding`, and reads `SIPNAB_ARCHIVE_PASSWORD` and the systemd credential `archive-password`. | `native`, `zip`, `sevenz-rust2`, `zeroize`, `unicode-normalization` |
| `g729` | G.729 Annex A decoding, with Annex B comfort noise, for WAV export, vCon recordings, the live audio route and the dead-air measurement. Adds `--g729-tables`, `[g729]`, and the `sipnab g729 install` and `sipnab g729 status` commands. sipnab ships no ITU-T table values: each host installs them with `sipnab g729 install`, described on the G.729 decoding page. Pure Rust, so in `full` and in the static musl builds. | `native`, `g729` (crates/g729), `sha2`, `rustls`, `base64` |
| `full` | Everything: `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` + `metrics` + `plugins` + `vcon` + `opus` + `archive` + `g729` | all |
| `wasm` | WebAssembly target for in-browser pcap analysis | `wasm-bindgen`, `js-sys`, `web-sys`, `console_error_panic_hook` |

Build with specific features. This example builds the TUI and TLS decryption
only. It compiles in no audio plugin, HEP, REST API or MCP:

```bash
cargo build --release --features tui,tls
```

A headless capture host has a HEP listener, REST API and MCP over HTTP. It leaves
out the TUI and audio, because a server has no use for either:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

Everything. This is the feature set the official macOS releases ship:

```bash
cargo build --release --features full
```

The published `*-linux-gnu` binaries add one more feature, `bpf`.

- `bpf` is outside `full`, because its kernel half needs a nightly toolchain
  and `bpf-linker`.
- The Linux glibc tarballs, `.deb` and `.rpm` all ship it, so
  `--uprobe-tls --uprobe-backend bpf` works on them with no extra build.

To build `bpf` yourself, install two things a stock toolchain does not have:

- a nightly toolchain carrying the `rust-src` component, installed with
  `rustup`,
- and `bpf-linker` on `PATH`. Get it with either `cargo install bpf-linker` or
  the prebuilt static tarball the release workflow uses.
- Pick the `bpf-linker` release that matches your LLVM:
  - 0.9.13 pairs with LLVM 19,
  - 0.11 pairs with LLVM 23.1.

Then build with the feature:

```bash
cargo build --release --features full,bpf
```

Without either tool, the build still succeeds and prints a warning.

- The resulting binary refuses `--uprobe-backend bpf` at run time.
- Set `SIPNAB_BPF_REQUIRED=1` to turn that warning into a build failure. The
  release workflow sets it.

The musl tarballs and the macOS builds do **not** carry `bpf`. On macOS the
feature cannot work: `aya`, the eBPF library it uses, is a Linux-only
dependency.

`sipnab --version` lists every compiled feature. So it is how you tell which
build you are holding.

### What features do you need?

- **Most users (interactive analysis):** `cargo build --release`.
  - Default features (`native` + `tui` + `audio` + `metrics`) give you:
    - interactive TUI,
    - CLI mode,
    - audio playback of captured RTP,
    - and the standalone Prometheus endpoint.
- **CI/scripting only (no TUI):** `cargo build --release --no-default-features --features native`.
  - This is a headless binary for automation pipelines.
- **MCP / AI-agent server:** add `mcp` (stdio) or `mcp,mcp-http` (HTTP).
  - See [MCP Server](@/docs/mcp.md) for the runtime configuration.
- **Headless capture host with HEP + Prometheus + MCP:** `cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http`.
  - This is the typical "fleet capture server" feature set.
  - It leaves out the TUI and audio playback you don't need on a server.
- **Full installation:** `cargo build --release --features full`.
  - This is everything except `wasm` and `bpf`.
- **Peer addresses from a TLS uprobe:** add `bpf` (`cargo build --release --features full,bpf`).
  - It needs a nightly toolchain and `bpf-linker` at build time.
  - It needs a kernel with `CONFIG_DEBUG_INFO_BTF` at run time.
  - It is already compiled into every published `*-linux-gnu` binary.
- **WASM/browser analysis:** `cargo build --release --features wasm`.
  - This is the WebAssembly target for in-browser pcap analysis (see Analyze page).

### Runtime dependencies

`libasound.so.2` is an **optional** runtime dependency.

- The `audio` feature builds a separate plugin, `libsipnab_audio.so`.
  - The `.deb` installs it to `/usr/lib/sipnab/`.
  - Dev builds place it next to the binary.
- The `sipnab` binary `dlopen`s this plugin only when you actually play a
  stream.
- So an audio-enabled binary starts fine on a host without libasound.

If libasound (or the plugin) is missing:

- playback returns a clear error,
- and you can still export the stream to a WAV file (F2).

Only `libpcap0.8` is a hard dependency:

```bash
apt-get install -y libpcap0.8
```

libasound is optional and only affects live playback. Skip it on a server:

- the binary still starts,
- and WAV export (F2) still works without it.

```bash
apt-get install -y libasound2
```

You may not need TUI audio playback on the host. That is typical for a `--hep-listen` / `--api` / `--mcp` server. Then do one of these:

- install the `-noaudio` `.deb`,
- or build without the `audio` feature, so the plugin is not built at all:

```bash
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

### Audio on musl and Alpine

**A statically linked musl build can never play audio, whatever features you compile in.**

- The plugin arrives through `dlopen`.
- Static musl has no dynamic loader at all. `dlopen` returns `NULL` with *"Dynamic loading not supported"*.
- This is why the release builds the `-unknown-linux-musl` tarballs without `audio`.

This matters because it fails quietly. `cargo build --release --features full` on Alpine succeeds. The binary then reports:

```text
sipnab <version> features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,opus,archive,g729
```

It advertises `audio` it cannot deliver. Nothing errors until you try to play a stream.

There are two supported ways to build on Alpine, depending on what you want.
Pick one. The two produce incompatible binaries.

Portable, no audio. This is what the release ships:

- static,
- zero runtime deps,
- runs on any Linux distro regardless of libc.

- Install the build dependencies:

   ```bash
   apk add --no-cache musl-dev libpcap-dev pkgconf
   ```

- Build the static binary:

   ```bash
   cargo build --release --no-default-features \
       --features native,tui,tls,hep,api,mcp,mcp-http
   ```

Alpine-only, with audio.

- Dynamically linked. So `dlopen` works and the plugin loads.
- Needs alsa-lib at runtime.
- Does NOT run on glibc hosts.

- Install the build dependencies, including ALSA:

   ```bash
   apk add --no-cache musl-dev libpcap-dev pkgconf alsa-lib alsa-lib-dev
   ```

- Build sipnab, dynamically linked:

   ```bash
   RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --features full
   ```

- Build the audio plugin the same way:

   ```bash
   RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -p sipnab-audio
   ```

- The `sipnab` binary itself still links only libpcap, libgcc and libc.

### Cross-glibc compatibility

The release `-gnu` builds require **glibc >= 2.36**.

- That is the floor the release workflow enforces on every gnu binary.
- On older hosts they refuse to start with `version 'GLIBC_2.36' not found`.
- The [installer script](@/docs/install.md#install-in-one-command) handles this
  automatically. Below the 2.36 floor it falls back to the static musl build.

The same applies to your own builds.

- You may build on a newer Debian/Ubuntu (e.g. Debian 13 / glibc 2.41).
- And you may deploy to an older one (Debian 12 / glibc 2.36).
- Then do one of these:
  - build inside a container matching the target's glibc. For example,
    `rust:1-bookworm` for Debian 12 deploys.
  - or use musl. These are the static `--target x86_64-unknown-linux-musl`
    builds the release CI publishes.

## Rust and `unsafe`

sipnab is a Rust program. Its `unsafe` blocks are mostly two kinds:

- calls into the kernel and C libraries such as libc and libpcap,
- and reads of memory the kernel shares with it.

Every block carries a `// SAFETY:` comment that states its soundness argument.

- `Cargo.toml` turns on clippy's `undocumented_unsafe_blocks` lint.
- CI runs clippy with `-D warnings`.
- So a block without one fails the build.

The release workflow also enforces a size ceiling on the static musl binary.
See [Release profile](#release-profile).

## Release profile

The release build uses LTO, a single codegen unit and symbol stripping for a small binary, unwinds on panic so sipnab can contain a panic in a parser of untrusted input, and keeps line tables for crash reports:

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
panic = "unwind"
debug = "line-tables-only"
```

Target binary size (musl, stripped): <= 23 MB. The release workflow measures
each published musl binary and refuses to publish one larger than the
`binary_size_ceiling_mb` value in
[`website/config.toml`](https://github.com/NormB/sipnab/blob/main/website/config.toml).

## Cross-compilation

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation.

- It runs each build in a container that already carries the target's toolchain.
- So the host needs no cross-linker of its own.

Install it once:

```bash
cargo install cross
```

Build for aarch64 Linux:

```bash
cross build --release --features full --target aarch64-unknown-linux-gnu
```

Build for x86_64 Linux:

```bash
cross build --release --features full --target x86_64-unknown-linux-gnu
```
