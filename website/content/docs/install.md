+++
title = "Installation"
weight = 1
description = "Install sipnab from pre-built binaries, cargo, or package managers."
+++

> Just want the binary? The [Download page](@/download.md) auto-detects your OS, CPU, and glibc and highlights the right file. This page is the full reference — every method, package manager, and platform note.
>
> Want a custom feature set or a cross-compiled target? See [Build from Source](@/docs/build.md).

## Installer (recommended)

One command on Linux (x86_64/aarch64) or macOS:

```bash
curl -fsSL https://www.sipnab.com/install.sh | sh
```

The [installer script](/install.sh) detects your OS, CPU architecture, and glibc version, downloads the matching versioned release tarball (`sipnab-<version>-<target-triple>.tar.gz`) together with its `.sha256` file, **verifies the checksum**, and installs the binary to `/usr/local/bin` (using `sudo` only if that directory isn't writable).

Two environment variables tune it:

```bash
# Pin a specific version instead of the latest release
curl -fsSL https://www.sipnab.com/install.sh | SIPNAB_VERSION=<version> sh

# Install somewhere else (e.g. no root)
curl -fsSL https://www.sipnab.com/install.sh | SIPNAB_INSTALL_DIR="$HOME/.local/bin" sh
```

On Linux the installer chooses between two build variants: the dynamically linked **`-gnu`** build (requires glibc >= 2.36 — Debian 12+, Ubuntu 23.04+ — and libpcap installed via your package manager) and the static **musl** build (no glibc/libpcap requirement; TUI audio playback unavailable, everything else identical). The 2.36 figure is the floor the release workflow actually enforces on every gnu binary, and the installer now uses that same cutover — it serves musl only to hosts below **glibc 2.36**, or with no glibc at all. It previously cut over at 2.39, so hosts between 2.36 and 2.39 (Debian 12 among them) received the static build and lost TUI audio even though the gnu build ran there fine.

## Pre-built Binaries

Every [GitHub release](https://github.com/NormB/sipnab/releases) ships versioned tarballs per target triple, each with a matching `.sha256` checksum file:

- `sipnab-<version>-x86_64-unknown-linux-gnu.tar.gz` — dynamic, needs glibc >= 2.36 + libpcap
- `sipnab-<version>-aarch64-unknown-linux-gnu.tar.gz` — same, for arm64
- `sipnab-<version>-x86_64-unknown-linux-musl.tar.gz` — static, runs on any glibc (no TUI audio)
- `sipnab-<version>-aarch64-unknown-linux-musl.tar.gz` — same, for arm64
- `sipnab-<version>-x86_64-apple-darwin.tar.gz` / `sipnab-<version>-aarch64-apple-darwin.tar.gz` — macOS

Manual download with checksum verification (replace `<version>` with the latest, e.g. 0.5.50):

```bash
V=<version> T=x86_64-unknown-linux-gnu
curl -LO "https://github.com/NormB/sipnab/releases/download/v$V/sipnab-$V-$T.tar.gz"
curl -LO "https://github.com/NormB/sipnab/releases/download/v$V/sipnab-$V-$T.tar.gz.sha256"
sha256sum -c "sipnab-$V-$T.tar.gz.sha256"
tar -xzf "sipnab-$V-$T.tar.gz"   # unpacks into ./sipnab-$V-$T/
sudo install -m 755 "sipnab-$V-$T/sipnab" /usr/local/bin/sipnab
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

The multi-stage Dockerfile uses `rust:1.97-slim-trixie` for the build stage and `debian:trixie-slim` for the runtime image. The runtime image includes only `libpcap0.8t64` and runs as a non-root `sipnab` user.

## Cargo

```bash
cargo install sipnab --features full
```

For build prerequisites, the full feature-flag matrix, release profile, and cross-compilation, see [Build from Source](@/docs/build.md).

## Package Managers

### Debian/Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/NormB/sipnab/releases/latest) and install it with `apt`, which resolves the `libpcap0.8` runtime dependency automatically:

```bash
# amd64 (x86_64) -- replace <version> with the latest, e.g. 0.5.50
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64.deb
sudo apt install ./sipnab_<version>_amd64.deb

# arm64 (aarch64)
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64.deb
sudo apt install ./sipnab_<version>_arm64.deb
```

The package installs `/usr/bin/sipnab`, the man page, and a systemd unit, and creates a `sipnab` system user for privilege dropping. On Ubuntu 24.04+ the dependency is satisfied by `libpcap0.8t64`.

The standard package ships the audio playback plugin and therefore *Recommends* `libasound2`, which apt installs by default — pulling the ALSA stack (~500 kB) onto the system. For headless servers, each release also publishes a **`-noaudio`** package with no plugin and no ALSA dependency (everything else — WAV export included — works the same; only live playback in the TUI is unavailable):

```bash
# amd64 (x86_64), headless / no ALSA
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64-noaudio.deb
sudo apt install ./sipnab_<version>_amd64-noaudio.deb

# arm64 (aarch64), headless / no ALSA
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64-noaudio.deb
sudo apt install ./sipnab_<version>_arm64-noaudio.deb
```

Alternatively, install the standard package with `sudo apt install --no-install-recommends ./sipnab_<version>_amd64.deb` to skip the ALSA packages while keeping the plugin on disk (playback then works as soon as `libasound2` is installed).

### RHEL/Fedora (.rpm)

`.rpm` packages ship per release for `x86_64` and `aarch64`, each in a
standard and a `-noaudio` variant (no audio plugin, no `alsa-lib` weak
dependency — for headless servers, mirroring the `.deb` variants):

```bash
sudo rpm -i sipnab-<version>-1.x86_64.rpm  # replace <version> with the latest, e.g. 0.5.50
# headless / no-ALSA variant:
sudo rpm -i sipnab-<version>-1.x86_64-noaudio.rpm
# arm64 hosts:
sudo rpm -i sipnab-<version>-1.aarch64.rpm
```

### Homebrew (macOS)

```bash
brew install sipnab
```

## Enabling MCP

To run sipnab as a Model Context Protocol server for an AI agent (Claude Code, Claude Desktop, …), see the [MCP Server](@/docs/mcp.md) page, which documents building with the `mcp`/`mcp-http` features and the runtime configuration.

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
sipnab 0.5.50 (<hash>) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics

<span class="t-muted">$</span> sipnab -N -I demo.pcap | head -3
<span class="t-accent">INVITE</span> alice -> bob  192.0.2.1:5060 -> 192.0.2.2:5060 <span class="t-good">InCall</span> PDD=847ms
<span class="t-accent">REGISTER</span> admin -> --  192.0.2.5:5060 -> 192.0.2.1:5060 <span class="t-good">Registered</span>
<span class="t-accent">INVITE</span> +15551234 -> +15559876  192.0.2.6:5060 -> 192.0.2.7:5060 <span class="t-bad">Failed</span> 408 Request Timeout</pre>
</div>

> **Tip:** sipnab requires libpcap for live capture. For pcap file analysis, no special permissions are needed. For live capture, run with `sudo` or set capabilities:
> ```bash
> sudo setcap cap_net_raw,cap_net_admin+ep $(which sipnab)
> ```
