# Installing sipnab

## Prerequisites

- **Rust 1.97+** (for building from source)
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)

## Installer (recommended)

The install script detects your OS, CPU, and glibc version, picks the right
build, verifies its sha256, and installs to `/usr/local/bin`:

```bash
curl -fsSL https://www.sipnab.com/install.sh | sh
```

Prefer to read it first: <https://www.sipnab.com/install.sh>. Pin a version
with `SIPNAB_VERSION=0.5.55`, change the destination with `SIPNAB_INSTALL_DIR`.

## Pre-built Binaries

Download from [GitHub Releases](https://github.com/NormB/sipnab/releases).
Architecture naming: `x86_64` = `amd64` (Intel/AMD), `aarch64` = `arm64`
(ARM); tarballs use the former, `.deb` packages the latter. `uname -m` tells
you which one you are.

```bash
# Linux x86_64 (static musl -- runs on any distro, any glibc, Alpine included)
# Replace <version> with the latest, e.g. 0.5.55
curl -LO https://github.com/NormB/sipnab/releases/download/v<version>/sipnab-<version>-x86_64-unknown-linux-musl.tar.gz
tar xzf sipnab-<version>-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 sipnab-<version>-x86_64-unknown-linux-musl/sipnab /usr/local/bin/sipnab

# Linux aarch64 (static musl)
curl -LO https://github.com/NormB/sipnab/releases/download/v<version>/sipnab-<version>-aarch64-unknown-linux-musl.tar.gz
tar xzf sipnab-<version>-aarch64-unknown-linux-musl.tar.gz
sudo install -m 755 sipnab-<version>-aarch64-unknown-linux-musl/sipnab /usr/local/bin/sipnab
```

The dynamic `…-unknown-linux-gnu.tar.gz` builds add TUI audio playback but
require glibc >= 2.36 (Debian 12+, Ubuntu 23.04+) and libpcap. That floor is
enforced, not estimated: the gnu targets build inside a Debian bookworm
container and a release-workflow gate rejects any binary linking a newer
`GLIBC_` symbol. On an older distro they fail with `` version `GLIBC_2.36' not
found `` -- use the static musl build. The install script uses that same 2.36
cutover: it served musl below 2.39 for eleven releases, which cost every
Debian 12 host its TUI audio for a floor the release gate had already lowered.

## Cargo (from source)

```bash
cargo install sipnab --features full
```

> **On Alpine or any musl target, `--features full` will not give you audio.**
> The playback plugin is loaded with `dlopen`, and static musl has no dynamic
> loader — it returns "Dynamic loading not supported". The build succeeds and
> the binary reports `audio` in `--version`, but playback can never work. Build
> without the `audio` feature, or build dynamically linked
> (`RUSTFLAGS="-C target-feature=-crt-static"` plus `apk add alsa-lib
> alsa-lib-dev`), which is Alpine-only. See the site's
> [Build from Source](https://www.sipnab.com/docs/build/#audio-on-musl-and-alpine)
> page for both recipes.

## Package Managers

### Debian/Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/NormB/sipnab/releases/latest) and install with `apt` (it resolves the `libpcap0.8` runtime dependency). The `.deb` needs glibc >= 2.36, i.e. Debian 12+ / Ubuntu 23.04+ -- on older releases use the static musl tarball above:

```bash
# amd64 (x86_64) -- replace <version> with the latest, e.g. 0.5.55
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64.deb
sudo apt install ./sipnab_<version>_amd64.deb

# arm64 (aarch64)
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64.deb
sudo apt install ./sipnab_<version>_arm64.deb
```

On Ubuntu 24.04+ the dependency is satisfied by `libpcap0.8t64`.

The standard package ships the audio playback plugin and therefore
*Recommends* `libasound2`, which apt installs by default — pulling the ALSA
stack (~500 kB) onto the system. For headless servers, each release also
publishes a **`-noaudio`** package with no plugin and no ALSA dependency
(everything else — WAV export included — works the same; only live playback
in the TUI is unavailable):

```bash
# amd64 (x86_64), headless / no ALSA
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64-noaudio.deb
sudo apt install ./sipnab_<version>_amd64-noaudio.deb

# arm64 (aarch64), headless / no ALSA
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64-noaudio.deb
sudo apt install ./sipnab_<version>_arm64-noaudio.deb
```

Alternatively, install the standard package with
`sudo apt install --no-install-recommends ./sipnab_<version>_amd64.deb` to
skip the ALSA packages while keeping the plugin on disk (playback then works
as soon as `libasound2` is installed).

### RHEL/Fedora (.rpm)

`.rpm` packages ship per release for `x86_64` and `aarch64`, each in a
standard and a `-noaudio` variant (no audio plugin, no `alsa-lib` weak
dependency — for headless servers, mirroring the `.deb` variants):

```bash
sudo rpm -i sipnab-0.5.55-1.x86_64.rpm
# headless / no-ALSA variant:
sudo rpm -i sipnab-0.5.55-1.x86_64-noaudio.rpm
# arm64 hosts:
sudo rpm -i sipnab-0.5.55-1.aarch64.rpm
```

### Homebrew (macOS)

```bash
brew install sipnab
```

## Building from Source

### Install from a checkout, with capabilities

`cargo install` has no post-install hook, so a source install leaves you to run
`--setup-caps` yourself. [`scripts/install-from-source.sh`](https://github.com/NormB/sipnab/blob/main/scripts/install-from-source.sh) does both:

```bash
git clone https://github.com/NormB/sipnab.git
cd sipnab
./scripts/install-from-source.sh --features full
```

It runs `cargo install --path . --bin sipnab` (forwarding any arguments), then
on Linux invokes the binary's own `--setup-caps` so live capture works without
`sudo`. Non-Linux platforms skip the capability step and are told to use `sudo`.

This is a *source* install and is distinct from the one-line installer at
<https://www.sipnab.com/install.sh>, which downloads a prebuilt release binary
and compiles nothing.

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

## Verifying a Download

Every release artifact is checksummed, signed with sigstore build provenance,
and accompanied by a CycloneDX SBOM. The installer script verifies the sha256
for you; these steps are for manual downloads, mirrors, and anything that
reached you by a route you did not choose.

**Checksum.** `SHA256SUMS.txt` covers every tarball, `.deb`, `.rpm`, and SBOM
in the release:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

**Provenance.** A checksum only proves the file matches the list; it says
nothing about who produced the list. The attestation is cryptographic proof the
artifact was built by sipnab's own release workflow, from a specific commit:

```bash
gh attestation verify sipnab-<version>-x86_64-unknown-linux-gnu.tar.gz \
    --repo NormB/sipnab
```

This is what detects a rehosted or tampered copy, including one served with a
matching checksum file.

**Dependencies.** Two CycloneDX SBOMs ship with each release:

| File | Covers |
|------|--------|
| `sipnab-<version>.cdx.json` | the `sipnab` binary |
| `sipnab-audio-<version>.cdx.json` | `libsipnab_audio.so`, the playback plugin |

There are two because the plugin is a separate crate loaded at runtime with
`dlopen`, and it brings in dependencies — `alsa`, `cpal`, `rodio` among them —
that appear nowhere in the binary's own graph. Scanning only the first would
quietly miss them. Feed either to any CycloneDX-aware scanner:

```bash
grype sbom:sipnab-<version>.cdx.json      # or trivy sbom, osv-scanner, ...
```

The binary SBOM is generated with all features enabled, so it is a superset of
what any single published binary contains — it will never under-report.

## Live Capture Permissions

Live capture (`sipnab -d <iface>` or the default `any` device) needs raw-socket
access. Rather than running the whole TUI as root, grant the binary the Linux
capabilities once and then run it as your normal user:

```bash
sudo sipnab --setup-caps
# equivalent to: sudo setcap cap_net_raw,cap_net_admin+ep $(command -v sipnab)
```

`--setup-caps` runs `setcap` on the sipnab binary (re-invoking through `sudo`
itself when not already root) and exits. After that, **run sipnab without
`sudo`**:

```bash
sipnab            # live capture works; no sudo needed
```

Prefer this to `sudo sipnab`. When started as root, sipnab opens the capture
device and then drops privileges to an unprivileged user (`nobody` by default,
or `--user <name>`). That dropped user usually **cannot read your home
directory**, so the in-TUI file browser (`O`) comes up empty — it will show a
"run without sudo" message explaining why. Running unprivileged with
capabilities avoids this entirely. (Re-running `--setup-caps` is needed after
each reinstall, since replacing the file clears its capabilities.)

> macOS and other non-Linux platforms have no file capabilities; run live
> capture under `sudo` there.

## Feature Flags

sipnab uses Cargo feature flags to control optional functionality. The default build includes `native`, `tui`, `audio`, and `metrics`.

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required (directly or transitively) by `tui`, `hep`, `metrics`, `api`, `mcp`, and `mcp-http`; not required by `tls`, `audio`, or `wasm`.** Included by default. | `pcap`, `clap`, `crossbeam-channel`, `libc`, `pcap-file`, `tracing-subscriber`, `tracing-log` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Builds the separate `sipnab-audio` plugin (`libsipnab_audio.so`) that the binary `dlopen`s lazily; the binary itself does **not** link `libasound.so.2`. | `libloading`, `libc` (plugin: `rodio`) |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `aes`, `cbc`, `zeroize` |
| `hep` | HEP v3 send + v2/v3 receive (Homer Encapsulation Protocol) | `native` |
| `api` | REST API + Prometheus metrics endpoint | `native`, `axum`, `tokio` |
| `mcp` | Model Context Protocol server, stdio transport. Lets an AI agent (Claude Code, Claude Desktop, …) drive sipnab. | `native`, `tokio`, `rmcp` |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Adds the `--mcp-transport http` option. | `mcp`, `api`, `rmcp/transport-streamable-http-server` |
| `metrics` | Standalone Prometheus `/metrics` server: a raw TCP listener and plain threads, no axum/tokio, so scraping does not drag in the `api` feature or its async runtime. Included by default. | `native`, `base64` |
| `full` | Everything: `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` + `metrics` | all |
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

`libasound.so.2` is now an **optional** runtime dependency. The `audio` feature
builds a separate plugin, `libsipnab_audio.so`, installed to `/usr/lib/sipnab/`
by the `.deb` (or placed next to the binary in dev builds). The `sipnab` binary
`dlopen`s this plugin only when you actually play a stream, so an audio-enabled
binary starts fine on a host without libasound. If libasound (or the plugin) is
missing, playback returns a clear error and you can still export the stream to a
WAV file (F2). On Debian/Ubuntu `libasound2` is shipped as a `Recommends` of the
package; install it for live playback. Only `libpcap0.8` is a hard dependency.
For a fully audio-free build, drop the `audio` feature and the plugin is not
built.

See [mcp.md](mcp.md) (or the website install guide, [www.sipnab.com/docs/install](https://www.sipnab.com/docs/install/)) for the full MCP enablement walkthrough including token-file generation and the systemd unit pattern.

## Release Profile

The release build uses LTO, single codegen unit, and symbol stripping for a small binary:

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
```

Target binary size (musl, stripped): <= 10 MB. Enforced against the real artifact by the "Enforce published binary size" step in release.yml.

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

The multi-stage Dockerfile uses `rust:1.97-slim-trixie` for the build stage and `debian:trixie-slim` for the runtime image. The runtime image includes only `libpcap0.8t64` and runs as a non-root `sipnab` user.

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
sipnab 0.5.55 (<hash>) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics
```

This is the fastest way to confirm a build was produced with the feature set
you expected (e.g. that `mcp-http` is present on a server build).

## Next steps

- [examples.md](examples.md) — copy-paste recipes for the most common tasks
- [keybindings.md](keybindings.md) — driving the interactive TUI
- [cli-reference.md](cli-reference.md) — every flag, for headless use
