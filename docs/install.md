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

```bash
sudo dpkg -i sipnab_0.3.1_amd64.deb
```

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

sipnab uses Cargo feature flags to control optional functionality. The `default` feature includes `tui` only.

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `tui` | Interactive terminal UI (ratatui + crossterm). **Included by default.** | `ratatui`, `crossterm`, `unicode-width` |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `aes`, `cbc`, `zeroize` |
| `hep` | HEP v2/v3 support (Homer Encapsulation Protocol) | -- (no extra deps) |
| `api` | REST API + Prometheus metrics endpoint (runs in isolated child process) | `axum`, `tokio` |
| `full` | All of the above: `tui` + `tls` + `hep` + `api` | all |

Build with specific features:

```bash
# TUI + TLS only
cargo build --release --features tui,tls

# Headless with HEP (no TUI)
cargo build --release --no-default-features --features hep

# Everything
cargo build --release --features full
```

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
