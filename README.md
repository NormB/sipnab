# sipnab

[![CI](https://github.com/NormB/sipnab/actions/workflows/ci.yml/badge.svg)](https://github.com/NormB/sipnab/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/NormB/sipnab/graph/badge.svg)](https://codecov.io/gh/NormB/sipnab)
[![Patreon](https://img.shields.io/badge/Patreon-support-f96854?logo=patreon&logoColor=white)](https://www.patreon.com/c/NormB975)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%9D%A4-db61a2?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/NormB)

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
- **TLS/SRTP decryption** -- SSLKEYLOGFILE (TLS 1.2/1.3), RSA private key (`--tls-key`, TLS 1.2 RSA-kx only — not ECDHE/PFS), SRTP media (`--srtp-keys` + SDES `a=crypto`, AES-CM), and DTLS-SRTP key extraction (`--dtls-keylog`, RFC 5764)
- **Privilege separation** -- drop to unprivileged user after capture device open
- **pcap I/O** -- read/write pcap and pcapng, file rotation and splitting
- **MCP server mode** -- expose read-only analysis (dialogs, streams, RTP, security findings) as Model Context Protocol tools an AI agent can call. Stdio + HTTP transports. See [`docs/mcp.md`](./docs/mcp.md).

## Prerequisites

### Build dependencies

- **Rust 1.97+** (edition 2024)
- **libpcap headers**
  - macOS: included with Xcode Command Line Tools (`xcode-select --install`)
  - Debian/Ubuntu: `apt install libpcap-dev`
  - Fedora/RHEL: `dnf install libpcap-devel`

### Runtime dependencies

sipnab dynamically links to system libraries. These must be present on the
target system:

| Library            | Package (Debian/Ubuntu) | Package (Fedora/RHEL)   | When required                                  |
|--------------------|-------------------------|-------------------------|------------------------------------------------|
| `libpcap.so.1`     | `libpcap0.8`            | `libpcap`               | Mandatory — any build that includes the `native` feature (the binary always links it) |
| `libasound.so.2`   | `libasound2`            | `alsa-lib`              | **Optional** — only for live audio playback in the TUI (loaded lazily via the audio plugin) |

`tls`, `hep`, `api`, `mcp`, `mcp-http`, and `wasm` are pure-Rust and need no
additional system libraries.

The `audio` feature **no longer links libasound into the `sipnab` binary**.
Device output lives in a separate plugin, `libsipnab_audio.so`
(`/usr/lib/sipnab/` from the `.deb`, or next to the binary in dev builds),
which sipnab `dlopen`s only the moment you press play. So an audio-enabled
binary starts fine on a host without libasound. If libasound (or the plugin)
is missing, playback returns a clear error and WAV export (F2) still works.
Install `libasound2` for live playback — it is a Debian `Recommends`, not a
hard dependency. For headless servers, each release also ships a `-noaudio`
`.deb` with no plugin and no ALSA Recommends at all (see
[docs/install.md](docs/install.md)).

## Build

```bash
cargo build --release
```

The binary is at `target/release/sipnab`. Live capture requires root or
`CAP_NET_RAW` (Linux) / BPF access (macOS).

### Cross-compilation

You can produce pre-built binaries for x86_64 and aarch64 Linux from macOS using
[cross](https://github.com/cross-rs/cross):

Build for x86_64 Linux. The result is dynamically linked, so the target host
needs libpcap present:

```bash
cross build --release --target x86_64-unknown-linux-gnu
```

Build for aarch64 Linux:

```bash
cross build --release --target aarch64-unknown-linux-gnu
```

Cross-compilation requires Docker (via [Colima](https://github.com/abiosoft/colima),
Docker Desktop, or similar) and `cross` (`cargo install cross`).

## Quick start

The default mode is the TUI -- an interactive call list. It puts the terminal in
raw mode, so anything pasted after it arrives as keystrokes rather than as a
second command (`i` clears non-matching dialogs, `q` quits). Run it on its own:

```bash
sudo sipnab -d eth0
```

CLI mode instead of the TUI, filtering on the From header:

```bash
sudo sipnab -N -d eth0 --from 1001
```

Diagnose a specific call from a pcap:

```bash
sipnab -N -I capture.pcap --call-report <call-id>
```

Show only the calls sipnab considers problematic:

```bash
sudo sipnab -N -d eth0 --problems
```

Emit JSON and pipe it to jq:

```bash
sudo sipnab -N -d eth0 --json | jq .
```

Detect SIP scanners and report them to syslog:

```bash
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

sipnab honours every sngrep keybinding. Press `F1` for the full shortcut reference.

## Feature flags

| Flag       | Description                                                          | Default |
|------------|----------------------------------------------------------------------|---------|
| `native`   | Live capture, file capture, output writers, signal handling, CLI. Required (directly or transitively) by `tui`, `hep`, `metrics`, `api`, `mcp`, and `mcp-http`; NOT required by `tls`, `audio`, or `wasm` | yes     |
| `tui`      | Interactive terminal UI (ratatui + crossterm)                        | yes     |
| `audio`    | RTP audio playback in TUI via the lazily loaded `sipnab-audio` plugin + WAV export | yes     |
| `tls`      | TLS/DTLS decryption + SRTP key extraction (ring, zeroize, rustls)    | no      |
| `hep`      | HEP v3 send + HEP v2/v3 receive (Homer Encapsulation Protocol)              | no      |
| `api`      | REST API + Prometheus metrics endpoint (axum, tokio)                 | no      |
| `mcp`      | Model Context Protocol server, stdio transport (rmcp)                | no      |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Implies `mcp` + `api`.       | no      |
| `metrics`  | Standalone Prometheus metrics server (raw TCP, no tokio)             | yes     |
| `wasm`     | WebAssembly target for in-browser pcap analysis                      | no      |
| `full`     | `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` + `metrics` | no      |

Build with specific features. Adding TLS decryption and HEP to the default set:

```bash
cargo build --release --features tls,hep
```

Everything the crate can do:

```bash
cargo build --release --features full
```

A headless capture host -- HEP listener, REST API, and MCP over HTTP, with no
TUI and no audio:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

Note: `audio` is in the default feature set, but it does **not** add a load-time `libasound2` dependency to the `sipnab` binary. The rodio/ALSA code lives in the separate `sipnab-audio` cdylib plugin (`libsipnab_audio.so`), which the binary `dlopen`s lazily only when you actually play a stream. So the binary starts fine without libasound. Install `libasound2` only if you want live playback (otherwise WAV export still works). For a fully audio-free build, drop `audio` (e.g. `--no-default-features --features native,tui` or the headless recipe above) and the plugin is simply not built.

## Documentation

- [CLI Reference](docs/cli-reference.md) -- all flags, organized by group
- [Library API](docs/library.md) -- using sipnab as a Rust crate; typed `ParseError`/`CaptureError`
- [Cookbook](docs/examples.md) -- copy-paste recipes for common workflows
- [Output Formats](docs/output-formats.md) -- NDJSON schema, jq recipes, pcap export
- [Keybindings](docs/keybindings.md) -- TUI keyboard shortcuts
- [Config Reference](docs/config-reference.md) -- TOML config file format
  (starter file: [contrib/sipnabrc.example](contrib/sipnabrc.example))
- [MCP Server](docs/mcp.md) -- tools, transports, token bootstrap, systemd unit, troubleshooting
- [Architecture](docs/architecture.md) -- module map, data flow, threading model
- [Implementation Plan](docs/design/implementation-plan-v6.md) -- historical design decisions and roadmap

## Contributing

Contributions are welcome -- see [CONTRIBUTING.md](CONTRIBUTING.md) for the
build/test workflow and pull request checklist. This project follows the
[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Found a vulnerability? **Do not open a public issue.** See
[SECURITY.md](SECURITY.md) for the private disclosure address, the response
timeline, and what is in scope -- parser crashes, key-material leakage,
privilege-drop and chroot escapes, API/MCP authentication bypass, and command
injection through the `--alert-exec` family.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.

Copyright 2024-2026 Norm Brandinger
