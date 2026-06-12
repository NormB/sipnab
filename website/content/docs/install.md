+++
title = "Installation"
weight = 1
description = "Install sipnab from pre-built binaries, cargo, package managers, or source."
+++

## Prerequisites

- **Rust 1.92+** (for building from source)
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)

## Pre-built Binaries

Download from [GitHub Releases](https://github.com/NormB/sipnab/releases):

```bash
# Linux x86_64 (static musl)
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab-x86_64-unknown-linux-musl
chmod +x sipnab-x86_64-unknown-linux-musl
sudo mv sipnab-x86_64-unknown-linux-musl /usr/local/bin/sipnab

# Linux aarch64 (static musl)
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab-aarch64-unknown-linux-musl
chmod +x sipnab-aarch64-unknown-linux-musl
sudo mv sipnab-aarch64-unknown-linux-musl /usr/local/bin/sipnab
```

## Docker

### Run from pre-built image

```bash
docker run --rm --net=host ghcr.io/normb/sipnab:latest -N -d eth0
```

`--net=host` is required for live capture. For reading pcap files, mount the file into the container:

```bash
docker run --rm -v /path/to/capture.pcap:/data/capture.pcap \
  ghcr.io/normb/sipnab:latest -N -I /data/capture.pcap
```

### Build the Docker image locally

```bash
docker build -t sipnab .
```

The multi-stage Dockerfile uses `rust:1.92-slim-bookworm` for the build stage and `debian:bookworm-slim` for the runtime image. The runtime image includes only `libpcap0.8` and runs as a non-root `sipnab` user.

## Cargo (from source)

```bash
cargo install sipnab --features full
```

## Package Managers

### Debian/Ubuntu (.deb)

```bash
sudo dpkg -i sipnab_0.4.1_amd64.deb  # replace 0.4.1 with latest version from releases page
```

### RHEL/Fedora (.rpm)

```bash
sudo rpm -i sipnab-0.4.1-1.x86_64.rpm  # replace 0.4.1 with latest version from releases page
```

### Homebrew (macOS)

```bash
brew install sipnab
```

## Building from Source

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
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Adds a runtime dependency on `libasound.so.2`. | `rodio`, `libc` |
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

When you build with `--features full` (or `--features audio`), the resulting binary dynamically links `libasound.so.2` and refuses to start if it's missing -- even on a headless server where audio playback is never invoked. On Debian/Ubuntu hosts that means installing the runtime library alongside `libpcap0.8`:

```bash
apt-get install -y libpcap0.8 libasound2
```

If you don't need TUI audio playback on the host (typical for a `--hep-listen` / `--api` / `--mcp` server), build without the `audio` feature to drop the libasound dependency entirely:

```bash
cargo build --release --no-default-features \
    --features native,tui,tls,hep,api,mcp,mcp-http
```

### Cross-glibc compatibility

If you build on a newer Debian/Ubuntu (e.g. Debian 13 / glibc 2.41) and deploy to an older one (Debian 12 / glibc 2.36), the binary will refuse to start with `version 'GLIBC_2.39' not found`. Build inside a container matching the target's glibc -- for example, `rust:1-bookworm` for Debian 12 deploys, or use musl (the static `--target x86_64-unknown-linux-musl` builds the release CI publishes).

## Enabling MCP

The Model Context Protocol server lets an AI agent (Claude Code, Claude Desktop, any MCP-capable client) drive sipnab. Two transports:

- **stdio** (default, requires `mcp` feature) -- the agent launches sipnab as a subprocess and communicates over stdin/stdout. Best for local agents.
- **HTTP** (requires `mcp-http` feature) -- sipnab listens on a TCP port for JSON-RPC requests. Best for remote agents.

### Quick start (stdio, local agent)

```bash
# Build with mcp support
cargo build --release --features full

# Or, if you only want MCP without TUI/audio:
cargo build --release --no-default-features --features native,api,mcp

# Run sipnab in MCP stdio mode against a pcap file
sipnab --mcp -I capture.pcap --quiet
```

For Claude Desktop, add to your MCP servers config:

```json
{
  "mcpServers": {
    "sipnab": {
      "command": "sipnab",
      "args": ["--mcp", "-I", "/path/to/capture.pcap", "--quiet"]
    }
  }
}
```

`--quiet` is recommended in stdio mode so log output doesn't interfere with the JSON-RPC wire on stdout.

### Quick start (HTTP, remote agent)

```bash
# Build with mcp-http support
cargo build --release --no-default-features --features native,api,mcp,mcp-http

# Generate a token (any random secret)
echo "$(openssl rand -hex 32)" > /etc/sipnab/mcp-token
chmod 0600 /etc/sipnab/mcp-token

# Run with HTTP transport bound to all interfaces
sipnab --mcp --mcp-transport http \
       --mcp-bind 0.0.0.0:8731 \
       --mcp-token-file /etc/sipnab/mcp-token \
       --mcp-allowed-host capture.example.com \
       -I capture.pcap --quiet
```

The agent then connects to `http://capture.example.com:8731/mcp` with header `Authorization: Bearer <token>`. See [MCP Server](@/docs/mcp.md) for the full protocol/security model, the list of available tools, and the systemd unit pattern for running MCP alongside an HEP listener.

> **Security note:** The HTTP transport refuses to start on a non-loopback bind without a token. The default Host-header allowlist is `localhost`, `127.0.0.1`, `::1` only -- add your real hostname / IP via `--mcp-allowed-host` (repeatable). For TLS, terminate it in nginx in front of sipnab; sipnab itself doesn't serve HTTPS for MCP.

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

## Platform Notes

### Linux

Full functionality. Live capture requires `CAP_NET_RAW` capability or root. Privilege dropping (`--user`) uses `setuid`/`setgid` after opening capture devices.

### macOS

TUI and pcap file analysis work fully. Live capture requires root or BPF device access. Install libpcap headers via Xcode Command Line Tools (included by default) or Homebrew.

### FreeBSD / Other

Should build and run. Live capture support depends on platform pcap implementation. Not regularly tested.

## Verify Installation

After installing, confirm sipnab is working:

```bash
# Check version
sipnab --version

# Display full help
sipnab --help

# Quick test with a pcap file
sipnab -I /path/to/capture.pcap

# CLI mode test (non-interactive, first 5 dialogs)
sipnab -N -I /path/to/capture.pcap | head -5

# Dump effective config to confirm feature flags
sipnab -D
```

<div class="terminal">
<div class="terminal-bar">
<span class="terminal-dot red"></span><span class="terminal-dot yellow"></span><span class="terminal-dot green"></span>
<span class="terminal-title">Verify Installation</span>
</div>
<pre class="terminal-body"><span class="t-muted">$</span> sipnab --version
sipnab 0.4.1 (c9620a5f) features: native,tui,audio,tls,hep,api,mcp,mcp-http

<span class="t-muted">$</span> sipnab -N -I demo.pcap | head -3
<span class="t-accent">INVITE</span> alice -> bob  10.0.0.1:5060 -> 10.0.0.2:5060  <span class="t-good">InCall</span>  PDD=847ms
<span class="t-accent">REGISTER</span> admin -> --  10.0.0.5:5060 -> 10.0.0.1:5060  <span class="t-good">Registered</span>
<span class="t-accent">INVITE</span> +15551234 -> +15559876  10.0.0.6:5060 -> 10.0.0.7:5060  <span class="t-bad">Failed</span>  408 Request Timeout</pre>
</div>

> **Tip:** sipnab requires libpcap for live capture. For pcap file analysis, no special permissions are needed. For live capture, run with `sudo` or set capabilities:
> ```bash
> sudo setcap cap_net_raw,cap_net_admin=eip $(which sipnab)
> ```
