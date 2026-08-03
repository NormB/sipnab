# Installing sipnab

## Prerequisites

- **Rust 1.97+** (for building from source)
- **libpcap headers** (`libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on RHEL/Fedora)
- **pkg-config** (for libpcap detection during build)

## Installer (recommended)

One command on Linux (x86_64/aarch64) or macOS:

```bash
curl -fsSL https://www.sipnab.com/install.sh | sh
```

The install script detects your OS, CPU architecture, and glibc version,
downloads the matching versioned release tarball
(`sipnab-<version>-<target-triple>.tar.gz`) together with its `.sha256` file,
**verifies the checksum**, and installs the binary to `/usr/local/bin` (using
`sudo` only if that directory isn't writable). Prefer to read it first:
<https://www.sipnab.com/install.sh>.

Two environment variables tune it. To pin a specific version instead of taking
whatever the latest release is:

```bash
curl -fsSL https://www.sipnab.com/install.sh | SIPNAB_VERSION=0.5.73 sh
```

To install somewhere other than `/usr/local/bin` — a directory you already own,
so root never enters into it:

```bash
curl -fsSL https://www.sipnab.com/install.sh | SIPNAB_INSTALL_DIR="$HOME/.local/bin" sh
```

On Linux the installer chooses between two build variants: the dynamically
linked **`-gnu`** build (requires glibc >= 2.36 — Debian 12+, Ubuntu 23.04+ —
and libpcap installed via your package manager) and the static **musl** build
(no glibc or libpcap requirement, and no TUI audio playback — everything else
identical). The 2.36 figure is the floor the release workflow actually
enforces on every gnu binary, and the installer now uses that same cutover —
it serves musl only to hosts below **glibc 2.36**, or with no glibc at all. It
previously cut over at 2.39 for eleven releases, so hosts between 2.36 and
2.39 (Debian 12 among them) received the static build and lost TUI audio even
though the gnu build ran there fine.

## Pre-built binaries

Every [GitHub release](https://github.com/NormB/sipnab/releases) ships the
artifacts below. This table is the reference. The
[download page](https://www.sipnab.com/download) carries the same files as
ready-made links for the current release.

### Release artifacts

Substitute the release version for `<version>` throughout. `SHA256SUMS.txt`
covers every file, and the tarballs additionally ship an individual
`.sha256` sidecar.

| File | CPU | Runs on | Notes |
|---|---|---|---|
| `sipnab_<version>_amd64.deb` | x86_64 / amd64 | Debian 12+, Ubuntu 23.04+ | apt-managed, full features |
| `sipnab_<version>_arm64.deb` | aarch64 / arm64 | Debian 12+, Ubuntu 23.04+ | apt-managed, full features |
| `sipnab_<version>_amd64-noaudio.deb` | x86_64 / amd64 | Debian 12+, Ubuntu 23.04+ | no ALSA dependency — headless servers |
| `sipnab_<version>_arm64-noaudio.deb` | aarch64 / arm64 | Debian 12+, Ubuntu 23.04+ | no ALSA dependency — headless servers |
| `sipnab-<version>-1.x86_64.rpm` | x86_64 / amd64 | RHEL/Fedora, glibc >= 2.36 | dnf/rpm-managed, full features |
| `sipnab-<version>-1.aarch64.rpm` | aarch64 / arm64 | RHEL/Fedora, glibc >= 2.36 | dnf/rpm-managed, full features |
| `sipnab-<version>-1.x86_64-noaudio.rpm` | x86_64 / amd64 | RHEL/Fedora, glibc >= 2.36 | no ALSA weak dependency |
| `sipnab-<version>-1.aarch64-noaudio.rpm` | aarch64 / arm64 | RHEL/Fedora, glibc >= 2.36 | no ALSA weak dependency |
| `sipnab-<version>-x86_64-unknown-linux-musl.tar.gz` | x86_64 / amd64 | any Linux, any glibc, Alpine | static — no TUI audio playback |
| `sipnab-<version>-aarch64-unknown-linux-musl.tar.gz` | aarch64 / arm64 | any Linux, any glibc, Alpine | static — no TUI audio playback |
| `sipnab-<version>-x86_64-unknown-linux-gnu.tar.gz` | x86_64 / amd64 | glibc >= 2.36 + libpcap | full features including audio |
| `sipnab-<version>-aarch64-unknown-linux-gnu.tar.gz` | aarch64 / arm64 | glibc >= 2.36 + libpcap | full features including audio |
| `sipnab-<version>-x86_64-apple-darwin.tar.gz` | Intel | macOS 10.12+ | Intel Macs |
| `sipnab-<version>-aarch64-apple-darwin.tar.gz` | Apple Silicon | macOS 11.0+ | M-series Macs |
| `SHA256SUMS.txt` | — | — | checksums for every package, tarball, and SBOM |
| `sipnab-<version>.cdx.json` | — | — | CycloneDX SBOM — full dependency tree |
| `sipnab-audio-<version>.cdx.json` | — | — | CycloneDX SBOM — audio feature subtree |
| `v<version>.tar.gz`, `v<version>.zip` | — | anywhere Rust 1.97+ builds | tagged source tree |

The two macOS floors differ because they are the pinned compiler's own defaults,
one per target. `release.yml` now pins `MACOSX_DEPLOYMENT_TARGET` to exactly
those two values, so a toolchain bump cannot move a published floor without
someone deciding to, and `published_macos_floors_match_the_toolchain` holds
`website/config.toml` to what the workflow pins — refusing a floor below the
compiler's own default, which would agree on paper and still name an OS the
binary cannot run on. Read them from the toolchain rather than trusting a copy:

```bash
rustc --print deployment-target --target x86_64-apple-darwin
```

```bash
rustc --print deployment-target --target aarch64-apple-darwin
```

### Architecture naming

`x86_64` = `amd64` (Intel/AMD) and `aarch64` = `arm64` (ARM) are the same chips
under two spellings. Tarballs and `.rpm` packages use `x86_64`/`aarch64`, and `.deb`
packages use `amd64`/`arm64`. `uname -m` reports which one you have.

The `unknown` in `x86_64-unknown-linux-gnu` is the **vendor** field of the Rust
target triple (`arch-vendor-os-abi`) — the canonical value meaning "no specific
vendor", which is why the macOS files say `apple` in that position. It is part
of the platform name, not a failed detection or a broken build. The names stay
canonical triples deliberately: they match `rustc -vV`, they are what
`SHA256SUMS.txt` and the build-provenance attestation cover, and the install
script constructs them.

On Linux x86_64, the static musl tarball runs on any distro and any glibc,
Alpine included. Replace `<version>` with the latest, e.g. 0.5.73:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/download/v<version>/sipnab-<version>-x86_64-unknown-linux-musl.tar.gz
tar xzf sipnab-<version>-x86_64-unknown-linux-musl.tar.gz
sudo install -m 755 sipnab-<version>-x86_64-unknown-linux-musl/sipnab /usr/local/bin/sipnab
```

The same three steps on Linux aarch64, against the aarch64 musl tarball:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/download/v<version>/sipnab-<version>-aarch64-unknown-linux-musl.tar.gz
tar xzf sipnab-<version>-aarch64-unknown-linux-musl.tar.gz
sudo install -m 755 sipnab-<version>-aarch64-unknown-linux-musl/sipnab /usr/local/bin/sipnab
```

Manual download with checksum verification (replace `<version>` with the
latest, e.g. 0.5.73):

```bash
# Run all of these, in order.
V=<version> T=x86_64-unknown-linux-gnu
curl -LO "https://github.com/NormB/sipnab/releases/download/v$V/sipnab-$V-$T.tar.gz"
curl -LO "https://github.com/NormB/sipnab/releases/download/v$V/sipnab-$V-$T.tar.gz.sha256"
sha256sum -c "sipnab-$V-$T.tar.gz.sha256"
tar -xzf "sipnab-$V-$T.tar.gz"   # unpacks into ./sipnab-$V-$T/
sudo install -m 755 "sipnab-$V-$T/sipnab" /usr/local/bin/sipnab
```

The dynamic `…-unknown-linux-gnu.tar.gz` builds add TUI audio playback but
require glibc >= 2.36 (Debian 12+, Ubuntu 23.04+) and libpcap. A gate holds that
floor rather than estimating it: the gnu targets build inside a Debian bookworm
container and a release-workflow gate rejects any binary linking a newer
`GLIBC_` symbol. On an older distro they fail with `` version `GLIBC_2.36' not
found `` -- use the static musl build.

## Cargo (from source)

```bash
cargo install sipnab --features full
```

> **On Alpine or any musl target, `--features full` does not give you audio.**
> The playback plugin arrives through `dlopen`, and static musl has no dynamic
> loader — it returns "Dynamic loading not supported". The build succeeds and
> the binary reports `audio` in `--version`, but playback can never work. Build
> without the `audio` feature, or build dynamically linked
> (`RUSTFLAGS="-C target-feature=-crt-static"` plus `apk add alsa-lib
> alsa-lib-dev`), which is Alpine-only. See the site's
> [Build from Source](https://www.sipnab.com/docs/build/#audio-on-musl-and-alpine)
> page for both recipes.

## Package managers

### Debian/Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/NormB/sipnab/releases/latest) and install with `apt` (it resolves the `libpcap0.8` runtime dependency). The `.deb` needs glibc >= 2.36, i.e. Debian 12+ / Ubuntu 23.04+ -- on older releases use the static musl tarball above.

Download and install the amd64 (x86_64) package — replace `<version>` with the
latest, e.g. 0.5.73:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64.deb
sudo apt install ./sipnab_<version>_amd64.deb
```

On an arm64 (aarch64) host, take the arm64 package instead — installing the
wrong-architecture `.deb` over the right one leaves you with a binary that does
not run:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64.deb
sudo apt install ./sipnab_<version>_arm64.deb
```

The package installs `/usr/bin/sipnab`, the man page, and a systemd unit, and
creates a `sipnab` system user for privilege dropping. On Ubuntu 24.04+ the
dependency resolves to `libpcap0.8t64`.

The standard package ships the audio playback plugin and therefore
*Recommends* `libasound2`, which apt installs by default — pulling the ALSA
stack (~500 kB) onto the system. For headless servers, each release also
publishes a **`-noaudio`** package with no plugin and no ALSA dependency
(everything else — WAV export included — works the same, and only live playback
in the TUI is unavailable).

The headless amd64 (x86_64) package:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_amd64-noaudio.deb
sudo apt install ./sipnab_<version>_amd64-noaudio.deb
```

The headless arm64 (aarch64) package, for arm64 hosts:

```bash
# Run all of these, in order.
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab_<version>_arm64-noaudio.deb
sudo apt install ./sipnab_<version>_arm64-noaudio.deb
```

Alternatively, install the standard package with
`sudo apt install --no-install-recommends ./sipnab_<version>_amd64.deb` to
skip the ALSA packages while keeping the plugin on disk (playback then works
as soon as `libasound2` lands).

### RHEL/Fedora (.rpm)

`.rpm` packages ship per release for `x86_64` and `aarch64`, each in a
standard and a `-noaudio` variant (no audio plugin, no `alsa-lib` weak
dependency — for headless servers, mirroring the `.deb` variants).

The standard package on an x86_64 host:

```bash
sudo rpm -i sipnab-0.5.73-1.x86_64.rpm
```

The headless / no-ALSA variant on the same architecture:

```bash
sudo rpm -i sipnab-0.5.73-1.x86_64-noaudio.rpm
```

The standard package on an aarch64 (arm64) host — pick the variant matching
`uname -m`:

```bash
sudo rpm -i sipnab-0.5.73-1.aarch64.rpm
```

The headless / no-ALSA variant on aarch64:

```bash
sudo rpm -i sipnab-0.5.73-1.aarch64-noaudio.rpm
```

### Homebrew (macOS)

```bash
brew install sipnab
```

## Building from source

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
<https://www.sipnab.com/install.sh>, which downloads a prebuilt release binary
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

## Verifying a download

Every release artifact is checksummed, signed with sigstore build provenance,
and accompanied by a CycloneDX SBOM. The installer script verifies the sha256
for you. These steps are for manual downloads, mirrors, and anything that
reached you by a route you did not choose.

**Checksum.** `SHA256SUMS.txt` covers every tarball, `.deb`, `.rpm`, and SBOM
in the release:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

**Provenance.** A checksum only proves the file matches the list. It says
nothing about who produced the list. The attestation is cryptographic proof the
artifact came from sipnab's own release workflow, at a specific commit:

```bash
gh attestation verify sipnab-<version>-x86_64-unknown-linux-gnu.tar.gz \
    --repo NormB/sipnab
```

This is what detects a rehosted or tampered copy, including one served with a
matching checksum file.

**This needs `gh` 2.49 or newer** — check with `gh --version`. The subcommand
did not exist before then, and distributions lag: Ubuntu 24.04 ships 2.45, where
the command prints `unknown command "attestation"` followed by the general help
text **and still exits 0**. Piped or scripted, that reads as success while
verifying nothing. Install a current `gh` from
<https://github.com/cli/cli/releases> rather than trusting a silent pass.

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

The binary SBOM covers all features, so it is a superset of
what any single published binary contains — it never under-reports.

## Live Capture Permissions

Reading a pcap file needs no special permissions at all. Live capture
(`sipnab -d <iface>` or the default `any` device) needs libpcap and raw-socket
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
directory**, so the in-TUI file browser (`O`) comes up empty — it shows a
"run without sudo" message explaining why. Running unprivileged with
capabilities avoids this entirely. (Re-run `--setup-caps` after
each reinstall, since replacing the file clears its capabilities.)

> macOS and other non-Linux platforms have no file capabilities; run live
> capture under `sudo` there.

## Feature flags

sipnab uses Cargo feature flags to control optional capability. The default build includes `native`, `tui`, `audio`, and `metrics`.

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

Build with specific features. For the TUI plus TLS decryption and nothing else:

```bash
cargo build --release --features tui,tls
```

For a headless capture host — HEP listener, REST API, and MCP over HTTP, with
no TUI and no audio:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

For everything:

```bash
cargo build --release --features full
```

`libasound.so.2` is now an **optional** runtime dependency. The `audio` feature
builds a separate plugin, `libsipnab_audio.so`, installed to `/usr/lib/sipnab/`
by the `.deb` (or placed next to the binary in dev builds). The `sipnab` binary
`dlopen`s this plugin only when you actually play a stream, so an audio-enabled
binary starts fine on a host without libasound. If libasound (or the plugin) is
missing, playback returns a clear error and you can still export the stream to a
WAV file (F2). On Debian/Ubuntu the package carries `libasound2` as a `Recommends`. Install it for live playback. Only `libpcap0.8` is a hard dependency.
For a fully audio-free build, drop the `audio` feature and the plugin is not
built.

## Enabling MCP

To run sipnab as a Model Context Protocol server for an AI agent (Claude Code,
Claude Desktop, …), see [mcp.md](mcp.md), which documents building with the
`mcp`/`mcp-http` features and the runtime configuration, including token-file
generation and the systemd unit pattern.

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

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation. `Cross.toml` lists the supported targets.

`cross` is a separate binary, so install it first:

```bash
cargo install cross
```

With that in place, build for aarch64 Linux:

```bash
cross build --release --features full --target aarch64-unknown-linux-gnu
```

Or for x86_64 Linux:

```bash
cross build --release --features full --target x86_64-unknown-linux-gnu
```

The cross images automatically install the required `libpcap-dev` headers for the target architecture.

## Docker

### Run from pre-built image

```bash
docker run --rm --net=host ghcr.io/normb/sipnab:latest -N -d eth0
```

Live capture needs `--net=host`. For reading pcap files, mount the file into the container:

```bash
docker run --rm -v /path/to/capture.pcap:/data/capture.pcap \
  ghcr.io/normb/sipnab:latest -N -I /data/capture.pcap
```

### Build the Docker image locally

```bash
docker build -t sipnab .
```

The multi-stage Dockerfile uses `rust:1.97-slim-trixie` for the build stage and `debian:trixie-slim` for the runtime image. The runtime image includes only `libpcap0.8t64` and runs as a non-root `sipnab` user.

## Platform notes

### Linux

Full capability. Live capture requires `CAP_NET_RAW` capability or root. Privilege dropping (`--user`) uses `setuid`/`setgid` after opening capture devices.

### macOS

TUI and pcap file analysis work fully. Live capture requires root or BPF device access. Install libpcap headers via Xcode Command Line Tools (included by default) or Homebrew.

### FreeBSD / other

Should build and run. Live capture support depends on platform pcap implementation. Not regularly tested.

## Verify Installation

After installing, confirm sipnab is working. Print the version, which also
names the features in the binary:

```bash
sipnab --version
```

Print the full help, which lists every flag this build accepts:

```bash
sipnab --help
```

Open a capture file in the TUI, which is the quickest end-to-end test:

```bash
sipnab -I /path/to/capture.pcap
```

Or read the same file in CLI mode — non-interactive, the first few SIP
messages. `-N` streams one line per **message**, not per call:

```bash
sipnab -N -I /path/to/capture.pcap | head -5
```

For one line per **call** instead, ask for the report and suppress the message
stream:

```bash
sipnab -N -I /path/to/capture.pcap --report --no-cli-print | head -5
```

Print the version banner and the config sipnab loaded, which is what a bug
report wants:

```bash
sipnab -D
```

`--version` lists the Cargo features compiled into the binary, e.g.

```text
sipnab 0.5.75 (<hash>) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics
```

This is the fastest way to confirm a build carries the feature set
you expected (e.g. that `mcp-http` is present on a server build).

A first non-interactive run against a capture looks like this — timestamp,
source, destination, method or status line, transport, one line per SIP
message:

```text
$ sipnab -N -I demo.pcap | head -4
09:14:22.881 192.0.2.5:44285 -> 192.0.2.1:5060 REGISTER UDP
09:14:22.883 192.0.2.1:5060 -> 192.0.2.5:44285 401 Unauthorized UDP
09:14:22.901 192.0.2.5:44285 -> 192.0.2.1:5060 REGISTER UDP
09:14:22.904 192.0.2.1:5060 -> 192.0.2.5:44285 200 OK UDP
```

`--report --no-cli-print` gives the per-call view of the same file instead:

```text
$ sipnab -N -I demo.pcap --report --no-cli-print | head -4
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
a84b4c76e66710@192.0.2.5         alice          alice          Registered   -      0s         4      -        -
3848276298220188511@192.0.2.6    alice          bob            Completed    200    14s        15     0.7s     -
```

Two things surprise people here. The `Code` column reads INVITE transactions
only, so a `REGISTER` row shows `-` whatever the registrar answered. And
`Duration` is the span from the dialog's first message to its last, not talk
time.

## Next steps

- [examples.md](examples.md) — copy-paste recipes for the most common tasks
- [keybindings.md](keybindings.md) — driving the interactive TUI
- [cli-reference.md](cli-reference.md) — every flag, for headless use
