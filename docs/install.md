# Installing sipnab

## Pre-built Binaries

Download from [GitHub Releases](https://github.com/NormB/sipnab/releases):

```bash
# Linux x86_64
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab-x86_64-unknown-linux-musl
chmod +x sipnab-x86_64-unknown-linux-musl
sudo mv sipnab-x86_64-unknown-linux-musl /usr/local/bin/sipnab

# Linux aarch64
curl -LO https://github.com/NormB/sipnab/releases/latest/download/sipnab-aarch64-unknown-linux-musl
chmod +x sipnab-aarch64-unknown-linux-musl
sudo mv sipnab-aarch64-unknown-linux-musl /usr/local/bin/sipnab
```

## Cargo (from source)

```bash
cargo install sipnab --features full
```

Requires: Rust 1.92+, libpcap headers (`libpcap-dev` on Debian, `libpcap-devel` on RHEL).

## Debian/Ubuntu (.deb)

```bash
sudo dpkg -i sipnab_0.3.0_amd64.deb
```

## RHEL/Fedora (.rpm)

```bash
sudo rpm -i sipnab-0.3.0-1.x86_64.rpm
```

## Homebrew (macOS)

```bash
brew install sipnab
```

## Docker

```bash
docker run --rm --net=host ghcr.io/normb/sipnab:latest -N -d eth0
```

Note: `--net=host` is required for live capture.

## Building from Source

```bash
git clone https://github.com/NormB/sipnab.git
cd sipnab
cargo build --release --features full
sudo cp target/release/sipnab /usr/local/bin/
```

## Verify Installation

```bash
sipnab --version
sipnab --help
```
