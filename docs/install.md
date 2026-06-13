# Installing sipnab

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

## Cargo (from source)

```bash
cargo install sipnab --features full
```

## Package Managers

### Debian/Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/NormB/sipnab/releases/latest) and install with `apt` (it resolves the `libpcap0.8` runtime dependency):

```bash
# amd64 (x86_64) -- replace <version> with the latest, e.g. 0.4.1
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64.deb
sudo apt install ./sipnab_<version>_amd64.deb

# arm64 (aarch64)
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64.deb
sudo apt install ./sipnab_<version>_arm64.deb
```

On Ubuntu 24.04+ the dependency is satisfied by `libpcap0.8t64`.

### RHEL/Fedora (.rpm)

```bash
sudo rpm -i sipnab-0.3.1-1.x86_64.rpm
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
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required by every other feature except `wasm`.** Included by default. | `pcap`, `clap`, `crossbeam-channel`, `libc`, `pcap-file`, `tracing-subscriber`, `tracing-log` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Adds a runtime dependency on `libasound.so.2`. | `rodio`, `libc` |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `aes`, `cbc`, `zeroize` |
| `hep` | HEP v2/v3 send + receive (Homer Encapsulation Protocol) | `native` |
| `api` | REST API + Prometheus metrics endpoint | `native`, `axum`, `tokio` |
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

A `--features full` (or any build with `audio`) dynamically links `libasound.so.2` and refuses to start without it — install `libasound2` alongside `libpcap0.8` on Debian/Ubuntu, or drop the `audio` feature for headless servers.

See the website install guide ([www.sipnab.com/docs/install](https://www.sipnab.com/docs/install/)) for the full MCP enablement walkthrough including token-file generation and the systemd unit pattern.

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

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation. Supported targets are configured in `Cross.toml`:

```bash
# Install cross
cargo install cross

# Build for aarch64 Linux
cross build --release --features full --target aarch64-unknown-linux-gnu

# Build for x86_64 Linux
cross build --release --features full --target x86_64-unknown-linux-gnu
```

The cross images automatically install the required `libpcap-dev` headers for the target architecture.

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

## Platform Notes

### Linux

Full functionality. Live capture requires `CAP_NET_RAW` capability or root. Privilege dropping (`--user`) uses `setuid`/`setgid` after opening capture devices.

### macOS

TUI and pcap file analysis work fully. Live capture requires root or BPF device access. Install libpcap headers via Xcode Command Line Tools (included by default) or Homebrew.

### FreeBSD / Other

Should build and run. Live capture support depends on platform pcap implementation. Not regularly tested.

## Verify Installation

```bash
sipnab --version
sipnab --help
```

`--version` lists the Cargo features compiled into the binary, e.g.

```
sipnab 0.3.1 (a7cf953d) features: native,tui,audio,tls,hep,api,mcp,mcp-http
```

This is the fastest way to confirm a build was produced with the feature set
you expected (e.g. that `mcp-http` is present on a server build).
