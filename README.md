# sipnab

SIP & RTP capture, analysis, and security tool.

sipnab unifies [sngrep](https://github.com/irontec/sngrep) (TUI) and
[sipgrep](https://github.com/sipcapture/sipgrep) (CLI) into a single Rust
binary with first-class RTP quality monitoring, VoIP diagnostic aliases, and
security analysis.

> **Status:** Under active development. Not yet ready for production use.

## Features

- **Four output modes** -- interactive TUI, non-interactive CLI, JSON, MCP server (drive sipnab from an AI agent)
- **SIP header matching** -- From, To, Contact, User-Agent, filter DSL
- **RTP quality monitoring** -- jitter, loss, MOS scoring, one-way audio detection
- **Per-call asymmetry signals** -- codec, ptime, payload-type, duration, late-media (Phase 8.7)
- **Diagnostic aliases** -- `--problems`, `--slow-setup`, `--short-calls`, `--one-way`, `--nat-issues` as flags; `codec-asym`, `ptime-asym`, `payload-asym`, `duration-asym`, `late-media` via `--filter` (e.g. `sipnab -N -I capture.pcap --filter codec-asym`)
- **Security analysis** -- scanner detection, registration flood, digest leak, STIR/SHAKEN, fraud heuristics
- **Event execution** -- run commands on dialog state changes or quality drops
- **HEP v3** -- send/receive Homer Encapsulation Protocol
- **TLS/SRTP decryption** -- private key, keylog file, DTLS support
- **Privilege separation** -- drop to unprivileged user after capture device open
- **pcap I/O** -- read/write pcap and pcapng, file rotation and splitting
- **MCP server mode** -- expose read-only analysis (dialogs, streams, RTP, security findings) as Model Context Protocol tools an AI agent can call. Stdio + HTTP transports. See [`docs/mcp-overview.md`](./docs/mcp-overview.md).

## Prerequisites

### Build Dependencies

- **Rust 1.92+** (edition 2024)
- **libpcap headers**
  - macOS: included with Xcode Command Line Tools (`xcode-select --install`)
  - Debian/Ubuntu: `apt install libpcap-dev`
  - Fedora/RHEL: `dnf install libpcap-devel`

### Runtime Dependencies

sipnab dynamically links to system libraries. These must be present on the
target system:

| Library            | Package (Debian/Ubuntu) | Package (Fedora/RHEL)   | When required                                  |
|--------------------|-------------------------|-------------------------|------------------------------------------------|
| `libpcap.so.1`     | `libpcap0.8`            | `libpcap`               | Any build that includes the `native` feature   |
| `libasound.so.2`   | `libasound2`            | `alsa-lib`              | Any build that includes the `audio` feature (in default) |

`tls`, `hep`, `api`, `mcp`, `mcp-http`, and `wasm` are pure-Rust and need no
additional system libraries. To drop the libasound runtime dependency on a
headless capture/MCP host, build without the `audio` feature — see the
`--no-default-features --features native,hep,api,mcp,mcp-http` recipe in the
Feature Flags section below.

## Build

```bash
cargo build --release
```

The binary is at `target/release/sipnab`. Live capture requires root or
`CAP_NET_RAW` (Linux) / BPF access (macOS).

### Cross-Compilation

Pre-built binaries for x86_64 and aarch64 Linux can be built from macOS using
[cross](https://github.com/cross-rs/cross):

```bash
# x86_64 Linux (dynamically linked, requires libpcap on target)
cross build --release --target x86_64-unknown-linux-gnu

# aarch64 Linux
cross build --release --target aarch64-unknown-linux-gnu
```

Cross-compilation requires Docker (via [Colima](https://github.com/abiosoft/colima),
Docker Desktop, or similar) and `cross` (`cargo install cross`).

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

| Flag       | Description                                                          | Default |
|------------|----------------------------------------------------------------------|---------|
| `native`   | Live capture, file capture, output writers, signal handling, CLI     | yes     |
| `tui`      | Interactive terminal UI (ratatui + crossterm)                        | yes     |
| `audio`    | RTP audio playback in TUI + WAV export (rodio)                       | yes     |
| `tls`      | TLS/DTLS decryption + SRTP key extraction (ring, zeroize, rustls)    | no      |
| `hep`      | HEP v2/v3 send + receive (Homer Encapsulation Protocol)              | no      |
| `api`      | REST API + Prometheus metrics endpoint (axum, tokio)                 | no      |
| `mcp`      | Model Context Protocol server, stdio transport (rmcp)                | no      |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Implies `mcp` + `api`.       | no      |
| `wasm`     | WebAssembly target for in-browser pcap analysis                      | no      |
| `full`     | `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` | no      |

Build with specific features:

```bash
cargo build --release --features tls,hep
cargo build --release --features full

# Headless capture host with HEP listener + REST API + MCP HTTP
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

Note: `audio` is in the default feature set, so the `libasound2` runtime dependency applies to plain `cargo build --release` too — not just `--features full`. Drop `audio` (e.g. `--no-default-features --features native,tui` or the headless recipe above) if your deploy host won't have libasound.

## Documentation

- [CLI Reference](docs/cli-reference.md) -- all flags, organized by group
- [Keybindings](docs/keybindings.md) -- TUI keyboard shortcuts
- [Config Reference](docs/config-reference.md) -- TOML config file format
  (starter file: [contrib/sipnabrc.example](contrib/sipnabrc.example))
- [MCP Setup](docs/mcp-setup.md) -- token bootstrap, systemd unit, troubleshooting
- [Implementation Plan](implementation-plan-v6.md) -- architecture and roadmap

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Copyright 2024-2026 Norm Brandinger
