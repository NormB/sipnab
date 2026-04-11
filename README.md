# sipnab

SIP & RTP capture, analysis, and security tool.

sipnab unifies [sngrep](https://github.com/irontec/sngrep) (TUI) and
[sipgrep](https://github.com/sipcapture/sipgrep) (CLI) into a single Rust
binary with first-class RTP quality monitoring, VoIP diagnostic aliases, and
security analysis.

> **Status:** Under active development. Not yet ready for production use.

## Features

- **Three output modes** -- interactive TUI, non-interactive CLI, JSON
- **SIP header matching** -- From, To, Contact, User-Agent, filter DSL
- **RTP quality monitoring** -- jitter, loss, MOS scoring, one-way audio detection
- **Diagnostic aliases** -- `--problems`, `--slow-setup`, `--short-calls`, `--one-way`, `--nat-issues`
- **Security analysis** -- scanner detection, registration flood, digest leak, STIR/SHAKEN, fraud heuristics
- **Event execution** -- run commands on dialog state changes or quality drops
- **HEP v3** -- send/receive Homer Encapsulation Protocol
- **TLS/SRTP decryption** -- private key, keylog file, DTLS support
- **Privilege separation** -- drop to unprivileged user after capture device open
- **pcap I/O** -- read/write pcap and pcapng, file rotation and splitting

## Prerequisites

- **Rust 1.92+** (edition 2024)
- **libpcap headers**
  - macOS: included with Xcode Command Line Tools (`xcode-select --install`)
  - Debian/Ubuntu: `apt install libpcap-dev`
  - Fedora/RHEL: `dnf install libpcap-devel`

## Build

```bash
cargo build --release
```

The binary is at `target/release/sipnab`. Live capture requires root or
`CAP_NET_RAW` (Linux) / BPF access (macOS).

## Quick Start

```bash
# TUI mode -- interactive call list
sudo sipnab -d eth0

# CLI mode -- filter by From header
sudo sipnab -N -d eth0 --from 1001

# Diagnose a specific call from a pcap
sipnab -N -I capture.pcap --call-report <call-id>

# Show only problematic calls
sudo sipnab -N -d eth0 --problems

# JSON output piped to jq
sudo sipnab -N -d eth0 --json | jq .

# Security -- detect SIP scanners
sudo sipnab -N -d eth0 --kill-scanner --alert syslog
```

## TUI

The default interactive mode provides an sngrep-compatible terminal interface
with additional features:

- **Call list** with sortable columns, multi-select, inline search, filter DSL
- **Call flow ladder** with color-coded arrows, SDP codec display, PDD annotation
- **Three timestamp modes** -- absolute (`HH:MM:SS.mmm`), delta from previous
  message (color-coded by latency), delta from first message
- **Split view** -- raw SIP detail panel alongside the ladder diagram, resizable
  with `9`/`0` or `+`/`-`
- **Message diff** -- select two messages with Space to compare side-by-side
- **Extended flow** -- merge correlated dialog legs into a single ladder (`F4`/`x`)
- **RTP stream list** -- jitter, loss, MOS scores (Tab to switch)

All sngrep keybindings are supported. Press `F1` for the full shortcut reference.

## Feature Flags

| Flag | Description | Default |
|------|-------------|---------|
| `tui` | Interactive terminal UI (ratatui) | yes |
| `tls` | TLS/SRTP decryption (ring, zeroize) | no |
| `tls-wolfssl` | TLS via wolfSSL backend | no |
| `tls-openssl` | TLS via OpenSSL backend | no |
| `hep` | Homer Encapsulation Protocol support | no |
| `grpc` | gRPC streaming interface (tonic) | no |
| `api` | REST API and Prometheus metrics (axum) | no |
| `full` | All of the above | no |

Build with specific features:

```bash
cargo build --release --features tls,hep
cargo build --release --features full
```

## Documentation

- [CLI Reference](docs/cli-reference.md) -- all flags, organized by group
- [Keybindings](docs/keybindings.md) -- TUI keyboard shortcuts
- [Config Reference](docs/config-reference.md) -- TOML config file format
- [Implementation Plan](implementation-plan-v6.md) -- architecture and roadmap

## License

[GPL-3.0-only](https://www.gnu.org/licenses/gpl-3.0.html)

Copyright 2024-2026 Norm Brandinger
