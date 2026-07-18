+++
title = "Build from Source"
weight = 15
description = "Build sipnab from source: cargo, the feature-flag matrix, release profile, and cross-compilation."
+++

Most users should [install a binary](@/docs/install.md); build from source when you need a custom feature set or target.

## Cargo (from source)

```bash
cargo install sipnab --features full
```

## Building from Source

### Build prerequisites

- **Rust 1.94+**
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)

### Basic build (TUI only, default features)

```bash
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

## Feature Flags

sipnab uses Cargo feature flags to control optional functionality. The default build includes `native`, `tui`, and `audio`.

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required by every other feature except `wasm`.** Included by default. | `pcap`, `clap`, `crossbeam-channel`, `libc`, `pcap-file`, `tracing-subscriber` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Builds the separate `sipnab-audio` plugin (`libsipnab_audio.so`) that the binary `dlopen`s lazily; the binary itself does **not** link `libasound.so.2`. | `libloading`, `libc` (plugin: `rodio`) |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `aes`, `cbc`, `zeroize` |
| `hep` | HEP v2/v3 send + receive (Homer Encapsulation Protocol) | `native` |
| `api` | REST API + Prometheus metrics endpoint (runs in isolated child process) | `native`, `axum`, `tokio` |
| `mcp` | Model Context Protocol server, stdio transport. Lets an AI agent (Claude Code, Claude Desktop, …) drive sipnab. | `native`, `tokio`, `rmcp` |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Adds the `--mcp-transport http` option. | `mcp`, `api`, `rmcp/transport-streamable-http-server` |
| `full` | Everything: `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` | all |
| `wasm` | WebAssembly target for in-browser pcap analysis | wasm-bindgen toolchain |

Build with specific features:

```bash
# TUI + TLS only
cargo build --release --features tui,tls

# Headless capture host with HEP listener + REST API + MCP HTTP
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http

# Everything
cargo build --release --features full
```

### What Features Do You Need?

- **Most users (interactive analysis):** `cargo build --release` -- default features (`native` + `tui` + `audio`) give you interactive TUI, CLI mode, and audio playback of captured RTP.
- **CI/scripting only (no TUI):** `cargo build --release --no-default-features --features native` -- headless binary for automation pipelines.
- **MCP / AI-agent server:** add `mcp` (stdio) or `mcp,mcp-http` (HTTP). See [MCP Server](@/docs/mcp.md) for the runtime configuration.
- **Headless capture host with HEP + Prometheus + MCP:** `cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http` -- the typical "fleet capture server" feature set, leaves out the TUI and audio playback you don't need on a server.
- **Full installation:** `cargo build --release --features full` -- everything.
- **WASM/browser analysis:** `cargo build --release --features wasm` -- WebAssembly target for in-browser pcap analysis (see Analyze page).

### Runtime dependencies

`libasound.so.2` is an **optional** runtime dependency. The `audio` feature builds a separate plugin, `libsipnab_audio.so`, installed to `/usr/lib/sipnab/` by the `.deb` (or placed next to the binary in dev builds). The `sipnab` binary `dlopen`s this plugin only when you actually play a stream, so an audio-enabled binary starts fine on a host without libasound. If libasound (or the plugin) is missing, playback returns a clear error and you can still export the stream to a WAV file (F2). Only `libpcap0.8` is a hard dependency:

```bash
apt-get install -y libpcap0.8            # required
apt-get install -y libasound2           # optional, for live playback
```

If you don't need TUI audio playback on the host (typical for a `--hep-listen` / `--api` / `--mcp` server), install the `-noaudio` `.deb`, or build without the `audio` feature so the plugin is not built at all:

```bash
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

### Cross-glibc compatibility

The release `-gnu` builds require **glibc >= 2.39** (the installer's floor); on older hosts they refuse to start with `version 'GLIBC_2.39' not found`. The [installer script](@/docs/install.md#installer-recommended) handles this automatically — below the 2.39 floor it falls back to the static musl build.

The same applies to your own builds: if you build on a newer Debian/Ubuntu (e.g. Debian 13 / glibc 2.41) and deploy to an older one (Debian 12 / glibc 2.36), build inside a container matching the target's glibc -- for example, `rust:1-bookworm` for Debian 12 deploys, or use musl (the static `--target x86_64-unknown-linux-musl` builds the release CI publishes).

## Release Profile

The release build uses LTO, single codegen unit, and symbol stripping for a small binary:

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
```

Target binary size (musl, stripped): <= 5 MB.

## Cross-Compilation

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation:

```bash
# Install cross
cargo install cross

# Build for aarch64 Linux
cross build --release --features full --target aarch64-unknown-linux-gnu

# Build for x86_64 Linux
cross build --release --features full --target x86_64-unknown-linux-gnu
```
