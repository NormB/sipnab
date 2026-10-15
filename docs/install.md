# Installing sipnab

sipnab is a single binary.

- The static Linux musl build needs nothing else.
- The other builds load the system's libpcap. macOS always has it, and a Linux
  package manager installs it.
- You do not need Rust, a compiler, or a toolchain to run it. Those are only
  for the build-it-yourself path near the end of this page.

Most people should run the one-line installer and be reading a capture inside a
minute.

## I want to

| Your goal | Go to |
|---|---|
| Install it and get working | [Install in one command](#install-in-one-command) |
| Confirm the install actually worked | [Check it worked](#check-it-worked) |
| Avoid piping a script from the internet into a shell | [Download a release binary yourself](#download-a-release-binary-yourself) |
| Use `apt`, `dnf`, or Homebrew | [Install with your package manager](#install-with-your-package-manager) |
| Compile it myself | [Build it from source](#build-it-from-source) |
| Capture live traffic without running as root | [Capture live traffic without root](#capture-live-traffic-without-root) |
| Prove a download is genuine before trusting it | [Verify a download is genuine](#verify-a-download-is-genuine) |
| Run it in a container | [Run it in Docker](#run-it-in-docker) |
| Drive it from an AI agent | [Turn on the MCP server](#turn-on-the-mcp-server) |
| Move to a newer release | [Upgrade sipnab](#upgrade-sipnab) |
| Take it off this machine | [Uninstall it](#uninstall-it) |

## Install in one command

One command on Linux (x86_64/aarch64) or macOS:

```bash
curl -fsSL https://sipnab.com/install.sh | sh
```

The install script:

- detects your OS, CPU architecture, and glibc version,
- downloads the matching versioned release tarball
  (`sipnab-<version>-<target-triple>.tar.gz`) together with its `.sha256` file,
- **verifies the checksum**,
- installs the binary to `/usr/local/bin` (using `sudo` only if that directory
  isn't writable).

Prefer to read it first: <https://sipnab.com/install.sh>.

Two environment variables tune it. To pin a specific version instead of taking
whatever the latest release is:

```bash
curl -fsSL https://sipnab.com/install.sh | SIPNAB_VERSION=0.5.221 sh
```

To install somewhere other than `/usr/local/bin`, use a directory you already
own. Then root never enters into it:

```bash
curl -fsSL https://sipnab.com/install.sh | SIPNAB_INSTALL_DIR="$HOME/.local/bin" sh
```

Then confirm it landed. It is one command, and the answer is the version plus
the features compiled in:

```bash
sipnab --version
```

If that prints a version, the install worked.

- Go to [Check it worked](#check-it-worked) for the fuller checks, or
  [Next steps](#next-steps) to start reading captures.
- If the shell cannot find `sipnab`, the install directory is not on your
  `PATH`. See [Check it worked](#check-it-worked).

On Linux the installer chooses between two builds.
- Hosts with glibc 2.36 or newer (Debian 12+, Ubuntu 23.04+) get the
  dynamically linked **`-gnu`** build. That build needs libpcap from your
  package manager.
- Older hosts, and hosts with no glibc, get the static **musl** build. It
  needs nothing else.
  - It lacks TUI audio playback, WASM plugins, vCon export and the eBPF uprobe
    backend.
  - It reads password-protected ZIP and 7z archives like every other release
    build.

## Download a release binary yourself

Every [GitHub release](https://github.com/NormB/sipnab/releases) ships the
artifacts below. This table is the reference. The
[download page](https://sipnab.com/download) carries the same files as
ready-made links for the current release.

### Release artifacts

Substitute the release version for `<version>` throughout.

- `SHA256SUMS.txt` covers every file.
- The tarballs additionally ship an individual `.sha256` sidecar.

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
| `sipnab-<version>-x86_64-unknown-linux-musl.tar.gz` | x86_64 / amd64 | any Linux, any glibc, Alpine | static — no TUI audio playback, WASM plugins, vCon export or eBPF uprobe backend |
| `sipnab-<version>-aarch64-unknown-linux-musl.tar.gz` | aarch64 / arm64 | any Linux, any glibc, Alpine | static — no TUI audio playback, WASM plugins, vCon export or eBPF uprobe backend |
| `sipnab-<version>-x86_64-unknown-linux-gnu.tar.gz` | x86_64 / amd64 | glibc >= 2.36 + libpcap | full features including audio |
| `sipnab-<version>-aarch64-unknown-linux-gnu.tar.gz` | aarch64 / arm64 | glibc >= 2.36 + libpcap | full features including audio |
| `sipnab-<version>-x86_64-apple-darwin.tar.gz` | Intel | macOS 10.12+ | Intel Macs |
| `sipnab-<version>-aarch64-apple-darwin.tar.gz` | Apple Silicon | macOS 11.0+ | M-series Macs |
| `sipnab-<version>-<target>.debug` | per target | — | Linux symbol file for the binary of the same name, for reading a [crash report](troubleshooting.md#send-us-a-crash-report) or a core dump. One per tarball, plus `-noaudio` ones for the `-noaudio` packages |
| `sipnab-<version>-<target>.dSYM.zip` | per target | — | macOS symbol bundle, the same for the two macOS tarballs |
| `SHA256SUMS.txt` | — | — | checksums for every package, tarball, symbol file, and SBOM |
| `sipnab-<version>.cdx.json` | — | — | CycloneDX SBOM — full dependency tree |
| `sipnab-audio-<version>.cdx.json` | — | — | CycloneDX SBOM — audio feature subtree |
| `v<version>.tar.gz`, `v<version>.zip` | — | anywhere Rust 1.99+ builds | tagged source tree |

### Which capture backends an artifact can reach

libpcap selects a capture backend from the device name. sipnab passes the
name through.

- `--device netmap:eth0` reaches libpcap's netmap module when the libpcap
  behind that binary carries one.
- **Which artifact you installed decides whether it was**. The three families
  differ:

| Artifact family | libpcap | netmap | DPDK | AF_XDP |
|---|---|---|---|---|
| `*-linux-musl.tar.gz` | statically linked, 1.10.6 | compiled in: netmap API 14 from 0.5.184, API 13 on 0.5.183 and earlier (see below) | no | no |
| `*-linux-gnu.tar.gz`, `.deb`, `.rpm`, Docker image, Homebrew on Linux | the host's, at runtime | whatever your distribution built | almost never | no |
| `*-apple-darwin.tar.gz`, Homebrew on macOS | the one macOS ships, `/usr/lib/libpcap.A.dylib`, at runtime | no | no | no |

> **Warning:** capture on a `netmap:` device only on an interface dedicated to
> capture, such as a SPAN or mirror port, never on one the host needs.
> libpcap's netmap module takes the interface's rings away from the kernel, so
> the host stops receiving that interface's traffic for as long as the capture
> runs.
>
> Measured on a veth pair: a UDP socket on the host received 0 of 5
> datagrams during a `netmap:` capture, and 5 of 5 during an ordinary capture
> on the same interface. Point it at the interface carrying your SIP service
> and the service goes dark until sipnab exits.

Debian and Ubuntu build libpcap without netmap.

- So the `.deb`, the `.rpm` and the Docker image answer
  `No such device exists` for a `netmap:` name.
- The static musl tarballs answer `netmap open: cannot access netmap:eth0`
  instead. This is a different error, and the difference is the whole point:
  - the first says the module is absent,
  - the second says the module tried and your kernel has no netmap device.

**On 0.5.183 and earlier, the musl tarballs' netmap module does not work
with a current netmap kernel module.**

- Those builds compiled libpcap against netmap's `v13.0` headers, which speak
  netmap API 13.
- A netmap module built from current netmap sources accepts API 14 and later.
- On Debian 13 (kernel 6.12) the open fails with
  `nm_open [948] NIOCREGIF failed: Invalid argument netmap:<iface>`.
- The kernel log says `Minimum supported API is 14 (requested 13)`.

netmap `v13.0`
itself no longer compiles against that kernel, so there is no older module to
pair it with.

The same libpcap 1.10.6 built against current netmap headers
captures through `netmap:` on that host. The 0.5.184 build uses them.
Its published x86_64-musl binary captured 5 of 5 SIP messages through
`netmap:` there. On 0.5.183 and earlier, treat the musl netmap column as not
usable.

**On 0.5.188 and earlier, a `netmap:` capture crashes on the first frame its
filter drops after it has captured a packet.**

- libpcap's netmap module reports a frame its BPF filter rejects as a
  successful read that delivers no data.
- Those builds then copied the previous packet's length from address 0.
- The kernel log names the capture thread:
  `capture-netmap:[...]: segfault at 0`.
- It looked like a crash at shutdown. The dropped frame is usually link
  chatter, such as an IPv6 router solicitation, that arrives while the
  capture sits idle.
- An idle capture survived only because no packet had yet set a length to
  copy.
- Later builds check that a read delivered a packet before they copy it.

A `netmap:` capture on a link that carries no traffic at all used not to stop
on SIGTERM until a frame arrived. `--duration` could not end it either.

- libpcap's netmap module waits for a frame inside its own read. It never
  hands control back while the link is silent.
- Later builds break that read with `pcap_breakloop` when a stop is due.
- Measured on the same host, on a veth pair with IPv6 turned off:
  - the older build was still running 15 seconds after SIGTERM in 10 runs
    of 10,
  - the fixed build exited in 30 to 71 ms, and at 3.0 seconds under
    `--duration 3s`.

macOS builds libpcap on BPF alone, with netmap and DPDK both left out.
Homebrew on macOS installs the same darwin tarball rather than bringing a
libpcap of its own. A `netmap:` or `dpdk:` name on a Mac reaches nothing.

No artifact sipnab publishes carries DPDK. No libpcap has an AF_XDP backend at
all. So an `xdp:` name is never a capture path.

Ask sipnab what its own binary runs. The second line of `--version` is the
libpcap it loaded. sipnab asks the library at runtime rather than recording it
at build time. So on a gnu build it names your host's library:

```bash
sipnab --version
```

On a musl tarball that line reads:

```text
libpcap version 1.10.6 (64-bit time_t, with TPACKET_V3 and netmap); alternate capture backends named: netmap
```

and on Debian 13's libpcap:

```text
libpcap version 1.10.5 (with TPACKET_V3); alternate capture backends named: none
```

A backend the banner does not name remains unconfirmed rather than absent.

- libpcap puts netmap in its banner only from 1.10.6.
- libpcap names DPDK only in a build that captures from DPDK alone.
- The same report is the `libpcap` block of the MCP
  [`server_capabilities`](mcp-tools-server.md#server_capabilities) tool and of
  the REST [`GET /v1/capabilities`](rest-api.md#get-v1capabilities) route.
- It also sits under the version in the TUI help view (F1).

A sipnab that predates the report prints only the first line. For one of
those, look for the banner yourself:

```bash
strings "$(command -v sipnab)" | grep 'libpcap version'
```

An empty result means the binary links your system's libpcap rather than
embedding one. Ask that library instead:

```bash
strings /usr/lib/*/libpcap.so.* | grep 'libpcap version'
```

### Architecture naming

`x86_64` = `amd64` (Intel/AMD) and `aarch64` = `arm64` (ARM) are the same chips
under two spellings.

- Tarballs and `.rpm` packages use `x86_64`/`aarch64`.
- `.deb` packages use `amd64`/`arm64`.
- `uname -m` reports which one you have.

The `unknown` in `x86_64-unknown-linux-gnu` is the **vendor** field of the Rust
target triple (`arch-vendor-os-abi`).

- It is the canonical value meaning "no specific vendor". That is why the
  macOS files say `apple` in that position.
- It is part of the platform name, not a failed detection or a broken build.
- The names stay canonical triples deliberately:
  - they match `rustc -vV`,
  - they are what `SHA256SUMS.txt` and the build-provenance attestation cover,
  - the install script constructs them.

Every command below reads the release number from a `VERSION` variable. Set
it first, in the same shell, to the release you want, e.g. 0.5.221 for the
latest:

```bash
VERSION=0.5.221
```

On Linux x86_64, the static musl tarball runs on any distro and any glibc,
Alpine included:

- Download the tarball:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab-$VERSION-x86_64-unknown-linux-musl.tar.gz"
   ```

- Unpack it:

   ```bash
   tar xzf "sipnab-$VERSION-x86_64-unknown-linux-musl.tar.gz"
   ```

- Install the binary:

   ```bash
   sudo install -m 755 "sipnab-$VERSION-x86_64-unknown-linux-musl/sipnab" /usr/local/bin/sipnab
   ```

The same three steps on Linux aarch64, against the aarch64 musl tarball:

- Download the tarball:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab-$VERSION-aarch64-unknown-linux-musl.tar.gz"
   ```

- Unpack it:

   ```bash
   tar xzf "sipnab-$VERSION-aarch64-unknown-linux-musl.tar.gz"
   ```

- Install the binary:

   ```bash
   sudo install -m 755 "sipnab-$VERSION-aarch64-unknown-linux-musl/sipnab" /usr/local/bin/sipnab
   ```

A manual download of the gnu build that checks the checksum before installing.
`TARGET` names the build. The tarball unpacks into `./sipnab-$VERSION-$TARGET/`:

- Set the target:

   ```bash
   TARGET=x86_64-unknown-linux-gnu
   ```

- Download the tarball:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab-$VERSION-$TARGET.tar.gz"
   ```

- Download its checksum file:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab-$VERSION-$TARGET.tar.gz.sha256"
   ```

- Check the checksum:

   ```bash
   sha256sum -c "sipnab-$VERSION-$TARGET.tar.gz.sha256"
   ```

- Unpack the tarball:

   ```bash
   tar -xzf "sipnab-$VERSION-$TARGET.tar.gz"
   ```

- Install the binary:

   ```bash
   sudo install -m 755 "sipnab-$VERSION-$TARGET/sipnab" /usr/local/bin/sipnab
   ```

The dynamic `…-unknown-linux-gnu.tar.gz` builds add TUI audio playback.

- They require glibc >= 2.36 (Debian 12+, Ubuntu 23.04+) and libpcap.
- On an older distribution they fail with
  `` version `GLIBC_2.36' not found ``. Use the static musl build there.

## Install with cargo

```bash
cargo install sipnab --features full
```

> **On Alpine or any musl target, `--features full` does not give you audio.**
>
> - The playback plugin arrives through `dlopen`.
> - Static musl has no dynamic loader. It returns "Dynamic loading not
>   supported".
> - The build succeeds and the binary reports `audio` in `--version`. But
>   playback can never work.
> - Build without the `audio` feature. Or build dynamically linked
>   (`RUSTFLAGS="-C target-feature=-crt-static"` plus `apk add alsa-lib
>   alsa-lib-dev`), which is Alpine-only.
> - See the site's
>   [Build from Source](https://sipnab.com/docs/build/#audio-on-musl-and-alpine)
>   page for both recipes.

## Install with your package manager

### Debian/Ubuntu (.deb)

Download the `.deb` for your architecture from the [latest release](https://github.com/NormB/sipnab/releases/latest).

- Install it with `apt`. It resolves the `libpcap0.8` runtime dependency.
- The `.deb` needs glibc >= 2.36, i.e. Debian 12+ / Ubuntu 23.04+.
- On older releases use the static musl tarball above.

Download and install the amd64 (x86_64) package. Set `VERSION` to the release
you want, e.g. 0.5.221, as in
[Download a release binary yourself](#download-a-release-binary-yourself):

- Set the version:

   ```bash
   VERSION=0.5.221
   ```

- Download the package:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab_${VERSION}_amd64.deb"
   ```

- Install it:

   ```bash
   sudo apt install "./sipnab_${VERSION}_amd64.deb"
   ```

On an arm64 (aarch64) host, take the arm64 package instead, with `VERSION` set
as above. Installing the wrong-architecture `.deb` over the right one leaves
you with a binary that does not run:

- Download the package:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab_${VERSION}_arm64.deb"
   ```

- Install it:

   ```bash
   sudo apt install "./sipnab_${VERSION}_arm64.deb"
   ```

The package installs `/usr/bin/sipnab`, the man page, and a systemd unit.

- It creates a `sipnab` system user for privilege dropping.
- On Ubuntu 24.04+ the dependency resolves to `libpcap0.8t64`.

The unit is not started for you. `sudo systemctl enable --now sipnab` starts a
capture on every interface as the `sipnab` user. The unit:

- uses only the two capabilities live capture needs,
- logs to syslog,
- keeps the per-message stream out of the journal,
- serves metrics on `127.0.0.1:9090`.

The REST API stays off. Change any of that with a drop-in
(`sudo systemctl edit sipnab`). A package upgrade leaves the drop-in alone.

The standard package ships the audio playback plugin. It therefore
*Recommends* `libasound2`.

- apt installs it by default. That pulls the ALSA stack (~500 kB)
  onto the system.
- For headless servers, each release also publishes a **`-noaudio`** package.
  It has no plugin and no ALSA dependency.
  - Everything else, WAV export included, works the same.
  - Only live playback in the TUI is unavailable.

The headless amd64 (x86_64) package:

- Download the package:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab_${VERSION}_amd64-noaudio.deb"
   ```

- Install it:

   ```bash
   sudo apt install "./sipnab_${VERSION}_amd64-noaudio.deb"
   ```

The headless arm64 (aarch64) package, for arm64 hosts:

- Download the package:

   ```bash
   curl -LO "https://github.com/NormB/sipnab/releases/download/v$VERSION/sipnab_${VERSION}_arm64-noaudio.deb"
   ```

- Install it:

   ```bash
   sudo apt install "./sipnab_${VERSION}_arm64-noaudio.deb"
   ```

Alternatively, install the standard package with
`sudo apt install --no-install-recommends "./sipnab_${VERSION}_amd64.deb"`.

- This skips the ALSA packages while keeping the plugin on disk.
- Playback then works as soon as `libasound2` lands.

### RHEL/Fedora (.rpm)

`.rpm` packages ship per release for `x86_64` and `aarch64`. Each comes in a
standard and a `-noaudio` variant.

- The no-audio variant has no audio plugin and no `alsa-lib` weak
  dependency.
- It is for headless servers, mirroring the `.deb` variants.

The standard package on an x86_64 host:

```bash
sudo rpm -i sipnab-0.5.221-1.x86_64.rpm
```

The headless / no-ALSA variant on the same architecture:

```bash
sudo rpm -i sipnab-0.5.221-1.x86_64-noaudio.rpm
```

The standard package on an aarch64 (arm64) host. Pick the variant matching
`uname -m`:

```bash
sudo rpm -i sipnab-0.5.221-1.aarch64.rpm
```

The headless / no-ALSA variant on aarch64:

```bash
sudo rpm -i sipnab-0.5.221-1.aarch64-noaudio.rpm
```

### Homebrew (macOS)

```bash
brew install NormB/tap/sipnab
```

## Build it from source

Only this section needs a toolchain. The installer, the release tarballs and the
packages all ship a finished binary.

**Before you build, you need:**

- **Rust 1.99+** — the toolchain the project builds and tests against.
- **libpcap headers** — `libpcap-dev` on Debian/Ubuntu, `libpcap-devel` on
  RHEL/Fedora. This is the one library sipnab links against.
- **pkg-config** — how the build finds libpcap.
- **cmake and a C compiler** — for `--features full`, whose `opus` feature
  compiles libopus from source and links it into the binary.

### Install from a checkout, with capabilities

`cargo install` has no post-install hook. So a source install leaves you to
run `--setup-caps` yourself. [`scripts/install-from-source.sh`](https://github.com/NormB/sipnab/blob/main/scripts/install-from-source.sh) does both:

- Clone the repository:

   ```bash
   git clone https://github.com/NormB/sipnab.git
   ```

- Change into it:

   ```bash
   cd sipnab
   ```

- Run the install script:

   ```bash
   ./scripts/install-from-source.sh --features full
   ```

The script does this:

- It runs `cargo install --path . --bin sipnab` (forwarding any arguments).
- Then on Linux it invokes the binary's own `--setup-caps`. So live capture
  works without `sudo`.
- Non-Linux platforms skip the capability step and point you at `sudo`.

This is a *source* install. It is distinct from the one-line installer at
<https://sipnab.com/install.sh>. That installer downloads a prebuilt release
binary and compiles nothing.

### Basic build (TUI only, default features)

- Clone the repository:

   ```bash
   git clone https://github.com/NormB/sipnab.git
   ```

- Change into it:

   ```bash
   cd sipnab
   ```

- Build the release binary:

   ```bash
   cargo build --release
   ```

- Copy it onto your `PATH`:

   ```bash
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

## Verify a download is genuine

Every release artifact is checksummed, signed with sigstore build provenance,
and accompanied by a CycloneDX SBOM.

- The installer script verifies the sha256 for you.
- These steps are for manual downloads, mirrors, and anything that reached you
  by a route you did not choose.

**Checksum.** `SHA256SUMS.txt` covers every tarball, `.deb`, `.rpm`, symbol
file, and SBOM in the release:

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

**Provenance.** A checksum only proves the file matches the list. It says
nothing about who produced the list. The attestation is cryptographic proof
the artifact came from sipnab's own release workflow, at a specific commit:

```bash
gh attestation verify "sipnab-$VERSION-x86_64-unknown-linux-gnu.tar.gz" \
    --repo NormB/sipnab
```

This is what detects a rehosted or tampered copy, including one served with a
matching checksum file.

**This needs `gh` 2.49 or newer.** Check with `gh --version`.

- The subcommand did not exist before then, and distributions lag.
- Ubuntu 24.04 ships 2.45. There the command prints
  `unknown command "attestation"` followed by the general help text **and
  still exits 0**.
- Piped or scripted, that reads as success while verifying nothing.
- Install a current `gh` from <https://github.com/cli/cli/releases> rather
  than trusting a silent pass.

**Dependencies.** Two CycloneDX SBOMs ship with each release:

| File | Covers |
|------|--------|
| `sipnab-<version>.cdx.json` | the `sipnab` binary |
| `sipnab-audio-<version>.cdx.json` | `libsipnab_audio.so`, the playback plugin |

There are two because the plugin is a separate crate loaded at runtime with
`dlopen`.

- It brings in dependencies, `alsa`, `cpal`, `rodio` among them.
- Those appear nowhere in the binary's own graph.
- Scanning only the first would quietly miss them.

Feed either to any CycloneDX-aware scanner:

```bash
grype "sbom:sipnab-$VERSION.cdx.json"      # or trivy sbom, osv-scanner, ...
```

The binary SBOM covers all features. So it is a superset of what any single
published binary contains. It never under-reports.

### Rebuild a release and compare it

A checksum and an attestation say where a binary came from. A rebuild says
what it contains.

- The `sipnab` binary in each Linux gnu tarball is reproducible. Building the
  release's tag yourself gives the same bytes.
- Compare the binary, not the tarball or a package. Those carry file times.
- The audio plugin beside the binary is not covered yet.
- This applies to releases built after reproducible builds landed.
  [`CHANGELOG.md`](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md)
  names the first one.

You need a git checkout of the tag, not a source tarball. The binary embeds
the commit hash and the tag, and a tarball has neither.

You also need the same toolchain the release used. For the gnu targets, that
is:

- the `rust:1-bookworm` image `release.yml` pins by digest,
- Rust 1.99.0,
- the eBPF nightly [`bpf/rust-toolchain.toml`](https://github.com/NormB/sipnab/blob/main/bpf/rust-toolchain.toml) names,
- and bpf-linker 0.11.0.

The release job's log shows each version it used.

- Check out the tag and install the pinned eBPF nightly:

   ```bash
   # Run all of these, in order.
   git clone https://github.com/NormB/sipnab && cd sipnab
   git checkout "v$VERSION"
   (cd bpf && rustup toolchain install)
   ```

- Build the way the release does, with the feature set the release gives
   that target (`full,bpf` for the gnu tarballs):

   ```bash
   SIPNAB_BPF_REQUIRED=1 bash scripts/reproducible-build.sh build x86_64-unknown-linux-gnu full,bpf
   ```

- Strip it the way the release does. The binary carries the symbol file's
   name, so use the release's name for it:

   ```bash
   bash scripts/split-debuginfo.sh target/x86_64-unknown-linux-gnu/release/sipnab \
       "sipnab-$VERSION-x86_64-unknown-linux-gnu"
   ```

- Compare it with the binary from the release tarball:

   ```bash
   bash scripts/reproducible-build.sh compare \
       target/x86_64-unknown-linux-gnu/release/sipnab "sipnab-$VERSION-x86_64-unknown-linux-gnu/sipnab"
   ```

   `identical` and a sha256 means the bytes match. Otherwise the script prints
   both hashes, where the files first differ, and the strings that differ.
   The usual cause is a different toolchain rather than a different source.

To check that the project's own build repeats, without a published binary to
compare against, use `check`. It builds a commit or tag twice in two
directories and compares the two:

```bash
SIPNAB_BPF_REQUIRED=1 bash scripts/reproducible-build.sh check \
    x86_64-unknown-linux-gnu full,bpf /tmp/sipnab-repro "v$VERSION"
```

The project runs that check weekly.
[Reproducible builds](internals/build-ci-release.md#reproducible-builds) says
what it covers and what a rebuild must hold fixed.

## Capture live traffic without root

Reading a pcap file needs no special permissions at all.

- Live capture (`sipnab -d <iface>` or the default `any` device) needs libpcap
  and raw-socket access.
- Rather than running the whole TUI as root, grant the binary the Linux
  capabilities once. Then run it as your normal user:

```bash
sudo sipnab --setup-caps
# equivalent to: sudo setcap cap_net_raw,cap_net_admin+ep $(command -v sipnab)
```

`--setup-caps` runs `setcap` on the sipnab binary and exits. It re-invokes
itself through `sudo` when not already root. After that, **run sipnab without
`sudo`**:

```bash
sipnab            # live capture works; no sudo needed
```

Prefer this to `sudo sipnab`.

- When started as root, sipnab opens the capture device. Then it drops
  privileges to an unprivileged user (`nobody` by default, or
  `--user <name>`).
- That dropped user usually **cannot read your home directory**.
- So the in-TUI file browser (`O`) comes up empty. It shows a
  "run without sudo" message explaining why.
- Running unprivileged with capabilities avoids this entirely.
- Re-run `--setup-caps` after each reinstall. Replacing the file clears its
  capabilities.

> macOS and other non-Linux platforms have no file capabilities. Run live
> capture under `sudo` there.

## Feature flags

sipnab uses Cargo feature flags to control optional capability. The default build includes `native`, `tui`, `audio`, and `metrics`.

| Feature | Description | Dependencies |
|---------|-------------|--------------|
| `native` | Live capture, file capture, output writers, signal handling, CLI parser. **Required (directly or transitively) by `tui`, `hep`, `metrics`, `api`, `mcp`, `mcp-http`, `plugins`, `bpf`, `vcon` and `archive`. Not required by `tls`, `audio`, or `wasm`.** Included by default. | `pcap`, `clap`, `clap_complete`, `env_logger`, `crossbeam-channel`, `libc`, `pcap-file`, `memmap2`, `tracing-subscriber`, `tracing-log`, `tempfile` |
| `tui` | Interactive terminal UI (ratatui + crossterm). Included by default. | `native`, `ratatui`, `crossterm`, `unicode-width`, `base64` |
| `audio` | RTP audio playback in the TUI + WAV export. Included by default. Builds the separate `sipnab-audio` plugin (`libsipnab_audio.so`) that the binary `dlopen`s lazily; the binary itself does **not** link `libasound.so.2`. | `libloading`, `libc` (plugin: `rodio`) |
| `tls` | TLS/DTLS decryption and SRTP key extraction (pure Rust) | `ring`, `rustls`, `rsa`, `aes`, `cbc`, `zeroize`, `base64`, `libc` |
| `hep` | HEP v3 send + v1/v2/v3 receive (Homer Encapsulation Protocol) | `native`, `hmac`, `sha2`, `rustls`, `base64` |
| `api` | REST API + Prometheus metrics endpoint, over HTTP or HTTPS. Runs on a background thread in the sipnab process, sharing its address space — not a separate OS process, so treat the bind address and API key accordingly. | `native`, `axum`, `tokio`, `base64`, `hmac`, `sha2`, `utoipa`, `rustls`, `tokio-rustls`, `ring`, `hyper`, `hyper-util`, `futures-core` |
| `mcp` | Model Context Protocol server, stdio transport. Lets an AI agent (Claude Code, Claude Desktop, …) drive sipnab. | `native`, `tokio`, `rmcp`, `base64`, `hmac`, `sha2` |
| `mcp-http` | MCP server over HTTP (Streamable-HTTP). Adds the `--mcp-transport http` option. | `mcp`, `api`, `rmcp/transport-streamable-http-server` |
| `metrics` | Standalone Prometheus `/metrics` server: a raw TCP listener and plain threads, no axum/tokio, so scraping does not drag in the `api` feature or its async runtime. Included by default. | `native`, `base64`, `rustls` |
| `plugins` | WASM plugin host (`--plugin`): runs sandboxed third-party dialog detections, so a detection nobody here wrote cannot reach the process it inspects. | `native`, `wasmi` |
| `bpf` | eBPF TLS capture (`--uprobe-backend bpf`): reads SIP plaintext **and the peer addresses** with no key material. Needs a nightly toolchain and `bpf-linker` to build, and a kernel with `CONFIG_DEBUG_INFO_BTF` to run — without the linker the binary still builds and the backend refuses at runtime rather than capturing nothing silently. | `native`, `aya`, `sipnab-bpf-types/pod` |
| `vcon` | vCon export: one observed dialog as an IETF conversation container, with the audio inline when the run retained it, or signed and encrypted when a `[[vcon.rule]]` sets `encrypt_to`. Non-default, because a container that leaves the machine is a publication surface and a capture tool should not grow one unless an operator asks. Adds `--export-vcon`/`--vcon-out`, the `export_vcon` MCP tool and `GET /v1/dialogs/{call_id}/vcon`. | `native`, `sha2`, `hmac`, `base64`, `rustls`, `rsa`, `ring`, `aes`, `cbc`, `sha1_oaep`, `webpki`, `p256` |
| `opus` | Ogg Opus recordings in vCon containers (`audio_format = "opus"` on a `[[vcon.rule]]`). Compiles libopus from the source `opusic-sys` vendors and links it statically, so building it needs `cmake` and a C compiler; the binary needs no system libopus. In `full`; not in the static musl builds, which have no vCon export. | `vcon`, `opus` |
| `archive` | Password-protected ZIP and 7z input: `-I evidence.zip` reads the captures inside, stored, deflated, WinZip AES or ZipCrypto, and `-I evidence.7z` reads LZMA or LZMA2, AES-256 or not, without leaving a decrypted copy on disk. Adds `--archive-password-file`, `--archive-password-command`, `--archive-password-stdin`, `--archive-password` and `--archive-password-encoding`, and reads `SIPNAB_ARCHIVE_PASSWORD` and the systemd credential `archive-password`. | `native`, `zip`, `sevenz-rust2`, `zeroize`, `unicode-normalization` |
| `full` | Everything: `native` + `tui` + `audio` + `tls` + `hep` + `api` + `mcp` + `mcp-http` + `metrics` + `plugins` + `vcon` + `opus` + `archive` | all |
| `wasm` | WebAssembly target for in-browser pcap analysis | `wasm-bindgen`, `js-sys`, `web-sys`, `console_error_panic_hook` |

Build with specific features. For the TUI plus TLS decryption and nothing else:

```bash
cargo build --release --features tui,tls
```

For a headless capture host, with HEP listener, REST API, and MCP over HTTP,
and with no TUI and no audio:

```bash
cargo build --release --no-default-features --features native,hep,api,mcp,mcp-http
```

For everything:

```bash
cargo build --release --features full
```

`libasound.so.2` is an **optional** runtime dependency.

- The `audio` feature builds a separate plugin, `libsipnab_audio.so`.
  - The `.deb` installs it to `/usr/lib/sipnab/`.
  - Dev builds place it next to the binary.
- The `sipnab` binary `dlopen`s this plugin only when you actually play a
  stream.
- So an audio-enabled binary starts fine on a host without libasound.

If libasound (or the plugin) is missing, playback returns a clear error. You
can still export the stream to a WAV file (F2).

On Debian/Ubuntu the package carries `libasound2` as a `Recommends`. Install it for live playback. Only `libpcap0.8` is a hard dependency.
For a fully audio-free build, drop the `audio` feature. Then the plugin is not
built.

## Turn on the MCP server

To run sipnab as a Model Context Protocol server for an AI agent (Claude Code,
Claude Desktop, …), start with [MCP server](mcp.md).

- It covers the `mcp` and `mcp-http` features and a first working example.
- [Connect an AI agent to sipnab](mcp-deploy.md) covers running it on a
  server, including token-file generation and the systemd unit.

## Release profile

The release build uses LTO, a single codegen unit, and symbol stripping for a
small binary. It also aborts on panic rather than unwinding. It compiles
line-table debug info:

```toml
[profile.release]
lto = true
codegen-units = 1
strip = true
panic = "abort"
debug = "line-tables-only"
```

Target binary size (musl, stripped): <= 19 MB.

A local `cargo build --release` strips at link time. So the line tables never
reach the binary.

- The release workflow appends `-C strip=none` to `RUSTFLAGS` for the same
  profile instead.
- [`scripts/split-debuginfo.sh`](https://github.com/NormB/sipnab/blob/main/scripts/split-debuginfo.sh)
  moves the symbols into the `.debug` file each release publishes. It does
  this before it strips the binary.
- The published binary carries the same code either way. It is within 100
  bytes of the same size (the split drops `.comment` and adds a
  `.gnu_debuglink`).
- The symbol file resolves the addresses in a
  [crash report](troubleshooting.md#send-us-a-crash-report) or a core dump.

## Cross-compilation

sipnab uses [cross](https://github.com/cross-rs/cross) for cross-compilation. [`Cross.toml`](https://github.com/NormB/sipnab/blob/main/Cross.toml) lists the supported targets.

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

## Run it in Docker

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

The multi-stage Dockerfile uses `rust:1.99-slim-trixie` for the build stage and `debian:trixie-slim` for the runtime image.

- The runtime image includes only `libpcap0.8t64`.
- It runs as a non-root `sipnab` user.

## Platform notes

### Linux

Full capability.

- Live capture requires `CAP_NET_RAW` capability or root.
- Privilege dropping (`--user`) uses `setuid`/`setgid` after opening capture devices.

### macOS

TUI and pcap file analysis work fully.

- Live capture requires root or BPF device access.
- Install libpcap headers via Xcode Command Line Tools (included by default) or Homebrew.

### FreeBSD / other

Should build and run. Live capture support depends on platform pcap implementation. Not regularly tested.

## Check it worked

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

Or read the same file in CLI mode. It is non-interactive and shows the first
few SIP messages. `-N` streams one line per **message**, not per call:

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

`--version` lists the Cargo features compiled into the binary. On a second
line it shows the libpcap it is running, e.g.

```text
sipnab 0.5.221 (<hash>) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,bpf,vcon,archive
libpcap version 1.10.5 (with TPACKET_V3); alternate capture backends named: none
```

This is the fastest way to confirm a build carries the feature set
you expected (e.g. that `mcp-http` is present on a server build).

- The second line names the libpcap that decides whether a `netmap:` device
  can work. See
  [which capture backends an artifact can
  reach](#which-capture-backends-an-artifact-can-reach).
- `-V` prints only the first line.

The list differs by artifact, and deliberately. The example above is a
`*-linux-gnu` release binary on a Debian 13 host. That host's libpcap names no
alternate backend.

Those binaries carry `bpf`, the uprobe backend that can report the peer
address a TLS session went out to.

- The static musl tarballs and the macOS builds do not carry it:
  - musl has no room under the published size ceiling,
  - `aya` is Linux-only.
- So on those, `--uprobe-tls` falls back to the `tracefs` backend. Its dialogs
  name a process rather than a peer.
- `--uprobe-backend bpf` refuses rather than pretending.

The musl tarballs also
omit `audio` (static musl has no `dlopen`).

A first non-interactive run against a capture looks like this. Each SIP
message gets one line: timestamp, source, destination, method or status line,
transport:

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
a84b4c76e66710@192.0.2.5         alice          alice          Registered   200    0s         4      -        -
3848276298220188511@192.0.2.6    alice          bob            Completed    200    14s        15     0.7s     -
```

Two things surprise people here.

- The `Code` column is the final answer to the dialog's INVITE, or to the
  request that opened a dialog without one.
  - It skips an answered challenge.
  - So the `REGISTER` row shows the registrar's 200 and not its 401.
- `Duration` is the span from the dialog's first message to its last, not
  talk time.

## Upgrade sipnab

Upgrade the same way you installed. Each route below replaces the binary with
the newer release. It keeps your configuration.

**Before you upgrade, read the changelog.** sipnab is pre-1.0 and makes no
Semantic Versioning promise. Any release may change a flag, a config key or an
output format.

- [CHANGELOG.md](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md)
  calls out each breaking change in the entry that carries it.
- It marks them **Breaking:** (entries up to 0.5.100 spell it `BREAKING:`).
- Search the entries between your version and the new one for that word.

**Only the latest release gets fixes**, security fixes included.

- There are no long-term support branches (see
  [SECURITY.md](https://github.com/NormB/sipnab/blob/main/SECURITY.md#supported-versions)).
- Upgrading is how you get a fix.

Check the version you run now, and again after the upgrade:

```bash
sipnab --version
```

### With the one-line installer

Run the installer again. It fetches the latest release and overwrites the
binary in place:

```bash
curl -fsSL https://sipnab.com/install.sh | sh
```

If you installed with `SIPNAB_INSTALL_DIR`, set it again. Otherwise the new
binary lands in `/usr/local/bin` beside the old one:

```bash
curl -fsSL https://sipnab.com/install.sh | SIPNAB_INSTALL_DIR="$HOME/.local/bin" sh
```

### From a release tarball

Repeat the download steps in
[Download a release binary yourself](#download-a-release-binary-yourself) with
`VERSION` set to the new release. The last step,
`sudo install -m 755`, replaces the old binary.

### With a .deb package

Download the new `.deb` as in
[Install with your package manager](#install-with-your-package-manager).
Install it over the old one.
apt treats a newer version of an installed package as an upgrade:

```bash
sudo apt install "./sipnab_${VERSION}_amd64.deb"
```

`sudo dpkg -i` with the same file also upgrades. But it does not fetch a
missing dependency, which `apt` does.

### With an .rpm package

Use `rpm -U`, not `rpm -i`. `rpm -i` refuses a package that is already
installed. `-U` replaces the installed version:

```bash
sudo rpm -U "sipnab-${VERSION}-1.x86_64.rpm"
```

`dnf` does the same, and fetches a missing dependency too:

```bash
sudo dnf upgrade "./sipnab-${VERSION}-1.x86_64.rpm"
```

On aarch64, or for the `-noaudio` package, use that file's name, as listed in
[Install with your package manager](#install-with-your-package-manager).

### With Homebrew

```bash
brew upgrade NormB/tap/sipnab
```

### With cargo

Install the new version over the old one.

- `--force` replaces the installed binary.
- `--locked` builds with the exact dependency versions the release's own
  tests ran against:

```bash
cargo install sipnab --features full --locked --force
```

### From a source checkout

Fetch the latest code, then run the install script again, from the checkout:

```bash
git pull
```

```bash
./scripts/install-from-source.sh --features full
```

### In Docker

Pull the new image. The next `docker run` uses it:

```bash
docker pull ghcr.io/normb/sipnab:latest
```

### What an upgrade keeps, and what to redo

**Your configuration survives every route.** No package ships a configuration
file.

- The `.deb` creates an empty `/etc/sipnab` directory. The `.rpm` creates
  nothing there.
- An upgrade replaces only the files the package ships. So
  `/etc/sipnab/sipnab.toml` and `~/.config/sipnab/` stay as you left them.
- The installer, the tarball, Homebrew and cargo never touch either location.

**Capabilities do not survive a replaced binary.** If you granted live capture
without root, grant it again after the upgrade. Replacing the file clears its
capabilities (see
[Capture live traffic without root](#capture-live-traffic-without-root)):

```bash
sudo sipnab --setup-caps
```

The `.deb` and `.rpm` service unit needs no such step: it grants the
capabilities itself each time it starts.

**A running service keeps the old binary until it restarts.** Neither package
restarts it for you. If you enabled the systemd unit, restart it after the
upgrade:

```bash
sudo systemctl restart sipnab
```

The package upgrade replaces the unit file too. Put your changes to the unit
in a drop-in (`sudo systemctl edit sipnab`). The upgrade leaves the drop-in
alone.

## Uninstall it

Remove sipnab the way you installed it. Every method below removes the binary
itself. The last part covers the files sipnab may have read but never created.

If you used the one-line installer, it copied a single binary and nothing
else. So deleting that file is the whole uninstall:

```bash
sudo rm -f /usr/local/bin/sipnab
```

If you set `SIPNAB_INSTALL_DIR`, remove the copy there instead. `command -v`
answers where it actually is, which beats guessing:

```bash
command -v sipnab
```

On Debian or Ubuntu, remove the package:

```bash
sudo apt remove sipnab
```

On RHEL or Fedora:

```bash
sudo dnf remove sipnab
```

On macOS with Homebrew:

```bash
brew uninstall sipnab
```

If you installed with cargo:

```bash
cargo uninstall sipnab
```

**No run creates a configuration file on its own, so there is usually nothing
to clean up.**

- sipnab reads the first configuration file it finds:
  - the one named by `--config`,
  - then `$SIPNAB_CONFIG`,
  - `$XDG_CONFIG_HOME/sipnab/sipnab.toml` (by default
    `~/.config/sipnab/sipnab.toml`),
  - `~/.sipnabrc`,
  - and `/etc/sipnab/sipnab.toml`.
- It reads the credential files named by `--hep-auth-file`,
  `--mcp-token-file` and `--mcp-signing-key-file`.
- It writes none of those on its own. You do, if you want them.

Two TUI actions are the exception. Both need you to ask for them:

- `s` in the F10 column selector saves the layout to
  `[display] visible_columns`.
- With `[names] persist_to_config = true`, the `N` naming dialog saves
  mappings to `[names.manual]`.

Where they write:

- Either writes into the config file the run loaded, whichever of the five it
  was. It leaves the rest of the file, comments included, intact.
- With no file loaded, it creates the user config file and its directory
  (`$XDG_CONFIG_HOME/sipnab/sipnab.toml`, by default
  `~/.config/sipnab/sipnab.toml`).
- When the settings came from `/etc/sipnab/sipnab.toml`, sipnab refuses the
  save and says so on the status line.
  - A file of your own would hide every setting in it.
  - Copy that file to `~/.config/sipnab/sipnab.toml` first.
- The `N` dialog also keeps a mapping file at `~/.config/sipnab/hosts`
  whatever the config says.

Remove what you find there:

```bash
rm -rf ~/.config/sipnab
```

No package removes a system-wide config file, because none ships one.

- The `.deb` creates an empty `/etc/sipnab` directory. The `.rpm` creates
  nothing there.
- So a `sipnab.toml` you put in `/etc/sipnab` survives `apt remove`,
  `apt purge` and `dnf remove` alike.

Remove it yourself:

```bash
sudo rm -rf /etc/sipnab
```

## Next steps

- [examples.md](examples.md) — copy-paste recipes for the most common tasks
- [keybindings.md](keybindings.md) — driving the interactive TUI
- [cli-reference.md](cli-reference.md) — every flag, for headless use

<details>
<summary>Why / how we know</summary>

**The glibc cutover.** 2.36 is the floor the release workflow enforces on
every gnu binary.

- The installer uses the same cutover. It serves musl only to hosts below
  glibc 2.36 or with no glibc at all.
- One number in both places stops a host the gnu build runs on from taking
  the static build. That host would lose TUI audio for nothing.

**The two macOS floors.** They differ because they are the pinned compiler's
own defaults, one per target.

- `release.yml` pins `MACOSX_DEPLOYMENT_TARGET` to exactly those two values.
  So a toolchain bump cannot move a published floor without someone deciding
  to.
- `published_macos_floors_match_the_toolchain` holds
  [`website/config.toml`](https://github.com/NormB/sipnab/blob/main/website/config.toml)
  to what the workflow pins.
  - It refuses a floor below the compiler's own default.
  - Such a floor would agree on paper and still name an OS the binary cannot
    run on.

Read them from the toolchain rather than trusting a copy:

```bash
rustc --print deployment-target --target x86_64-apple-darwin
```

```bash
rustc --print deployment-target --target aarch64-apple-darwin
```

**How the release keeps the glibc floor.** The gnu targets build inside a
Debian bookworm container. A release-workflow gate rejects any binary linking
a `GLIBC_` symbol newer than 2.36. A gate enforces the floor rather than
estimating it.

**The size ceiling.** The "Enforce published binary size" step in
`release.yml` checks the 19 MB ceiling against the real musl artifact on every
release.

</details>
