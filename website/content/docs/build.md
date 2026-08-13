+++
title = "Build from Source"
weight = 16
description = "Build sipnab from source: cargo, the feature-flag matrix, release profile, and cross-compilation."
+++

Most users should [install a binary](@/docs/install.md). Build from source when you need a custom feature set or target.

## Cargo (from source)

```bash
cargo install sipnab --features full
```

## Building from source

### Build prerequisites

- **Rust 1.97+**
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)

### Install from a checkout, with capabilities

`cargo install` has no post-install hook, so a source install leaves you to run
`--setup-caps` yourself. [`scripts/install-from-source.sh`](https://github.com/NormB/sipnab/blob/main/scripts/install-from-source.sh) does both:

```bash
# Run all of these, in order.
git clone https://github.com/NormB/sipnab.git
cd sipnab
./scripts/install-from-source.sh --features full
```

It runs `cargo install --path . --bin sipnab` (forwarding any arguments), then
on Linux invokes the binary's own `--setup-caps` so live capture works without
`sudo`. Non-Linux platforms skip the capability step and point you at `sudo`.

This is a *source* install and is distinct from the one-line installer at
<https://sipnab.com/install.sh>, which downloads a prebuilt release binary
and compiles nothing.

### Basic build (TUI only, default features)

```bash
# Run all of these, in order.
git clone https://github.com/NormB/sipnab.git
cd sipnab
cargo build --release
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
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required (directly or transitively) by `tui`, `hep`, `metrics`, `api`, `mcp`, `mcp-http`, and `plugins`; not required by `tls`, `audio`, or `wasm`.** Included by default. | `pcap`, `clap`, `crossbeam-channel`, `libc`, `pcap-file`, `tracing-subscriber` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Builds the separate `sipnab-audio` plugin (`libsipnab_audio.so`) that the binary `dlopen`s lazily; the binary itself does **not** link `libasound.so.2`. | `libloading`, `libc` (plugin: `rodio`) |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `aes`, `cbc`, `zeroize` |
| `hep` | HEP v3 send + v2/v3 receive (Homer Encapsulation Protocol) | `native` |
| `api` | REST API + Prometheus metrics endpoint. Runs on a background thread in the sipnab process, sharing its address space — not a separate OS process, so treat the bind address and API key accordingly. | `native`, `axum`, `tokio` |
| `mcp` | Model Context Protocol server, stdio transport. Lets an AI agent (Claude Code, Claude Desktop, …) drive sipnab. | `native`, `tokio`, `rmcp` |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Adds the `--mcp-transport http` option. | `mcp`, `api`, `rmcp/transport-streamable-http-server` |
| `metrics` | Standalone Prometheus `/metrics` server: a raw TCP listener and plain threads, no axum/tokio, so scraping does not drag in the `api` feature or its async runtime. Included by default. | `native`, `base64` |
| `plugins` | WASM plugin host (`--plugin`): sandboxed third-party dialog detections | `native`, `wasmi` |
| `full` | Everything: `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` + `metrics` + `plugins` | all |
| `wasm` | WebAssembly target for in-browser pcap analysis | wasm-bindgen toolchain |

Build with specific features. The TUI and TLS decryption only — no audio plugin,
HEP, REST API or MCP compiled in:

```bash
cargo build --release --features tui,tls
```

A headless capture host — HEP listener, REST API and MCP over HTTP, with the TUI
and audio left out because a server has no use for either:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

Everything — the feature set the official glibc and macOS releases ship:

```bash
cargo build --release --features full
```

### What features do you need?

- **Most users (interactive analysis):** `cargo build --release` -- default features (`native` + `tui` + `audio` + `metrics`) give you interactive TUI, CLI mode, audio playback of captured RTP, and the standalone Prometheus endpoint.
- **CI/scripting only (no TUI):** `cargo build --release --no-default-features --features native` -- headless binary for automation pipelines.
- **MCP / AI-agent server:** add `mcp` (stdio) or `mcp,mcp-http` (HTTP). See [MCP Server](@/docs/mcp.md) for the runtime configuration.
- **Headless capture host with HEP + Prometheus + MCP:** `cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http` -- the typical "fleet capture server" feature set, leaves out the TUI and audio playback you don't need on a server.
- **Full installation:** `cargo build --release --features full` -- everything.
- **WASM/browser analysis:** `cargo build --release --features wasm` -- WebAssembly target for in-browser pcap analysis (see Analyze page).

### Runtime dependencies

`libasound.so.2` is an **optional** runtime dependency. The `audio` feature builds a separate plugin, `libsipnab_audio.so`, installed to `/usr/lib/sipnab/` by the `.deb` (or placed next to the binary in dev builds). The `sipnab` binary `dlopen`s this plugin only when you actually play a stream, so an audio-enabled binary starts fine on a host without libasound. If libasound (or the plugin) is missing, playback returns a clear error and you can still export the stream to a WAV file (F2). Only `libpcap0.8` is a hard dependency:

```bash
apt-get install -y libpcap0.8
```

libasound is optional and only affects live playback. Skip it on a server: the
binary still starts, and WAV export (F2) still works without it.

```bash
apt-get install -y libasound2
```

If you don't need TUI audio playback on the host (typical for a `--hep-listen` / `--api` / `--mcp` server), install the `-noaudio` `.deb`, or build without the `audio` feature so the plugin is not built at all:

```bash
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

### Audio on musl and Alpine

**A statically linked musl build can never play audio, whatever features you compile in.** The plugin arrives through `dlopen`, and static musl has no dynamic loader at all — `dlopen` returns `NULL` with *"Dynamic loading not supported"*. This is why the release builds the `…-linux-musl` tarballs without `audio`.

This matters because it fails quietly. `cargo build --release --features full` on Alpine succeeds, and the binary then reports:

```text
sipnab <version> features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics
```

It advertises `audio` it cannot deliver. Nothing errors until you try to play a stream.

Two supported ways to build on Alpine, depending on what you want. Pick one — the
two produce incompatible binaries.

Portable, no audio. This is what the release ships: static, zero runtime deps,
runs on any Linux distro regardless of libc.

```bash
# Run all of these, in order.
apk add --no-cache musl-dev libpcap-dev pkgconf
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

Alpine-only, with audio. Dynamically linked, so `dlopen` works and the plugin
loads. Needs alsa-lib at runtime and does NOT run on glibc hosts.

```bash
# Run all of these, in order.
apk add --no-cache musl-dev libpcap-dev pkgconf alsa-lib alsa-lib-dev
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --features full
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release -p sipnab-audio
```

A CI job checks both paths on `rust:1.97-alpine`: the full test suite passes on Alpine with zero failures and the same test count as the glibc host, and in the dynamic build the plugin links `libasound.so.2` and `dlopen`s successfully while the `sipnab` binary itself still links only libpcap, libgcc and libc.

### Cross-glibc compatibility

The release `-gnu` builds require **glibc >= 2.36** (the floor the release workflow enforces on every gnu binary). On older hosts they refuse to start with `version 'GLIBC_2.36' not found`. The [installer script](@/docs/install.md#install-in-one-command) handles this automatically — below the 2.36 floor it falls back to the static musl build.

The same applies to your own builds: if you build on a newer Debian/Ubuntu (e.g. Debian 13 / glibc 2.41) and deploy to an older one (Debian 12 / glibc 2.36), build inside a container matching the target's glibc -- for example, `rust:1-bookworm` for Debian 12 deploys, or use musl (the static `--target x86_64-unknown-linux-musl` builds the release CI publishes).

## Release profile

The release build uses LTO, single codegen unit, and symbol stripping for a small binary:

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
```

Target binary size (musl, stripped): <= 12 MB. Enforced against the real artifact by the "Enforce published binary size" step in release.yml.

## Cross-compilation

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation. It
runs each build in a container that already carries the target's toolchain, so
the host needs no cross-linker of its own. Install it once:

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
