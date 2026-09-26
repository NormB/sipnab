# Add TFPS to an OpenSIPS voice stack

[TFPS](https://github.com/sippulse/tfps) watches the SIP traffic arriving at a
machine and blocks the sources that are attacking it: scanners such as
SIPVicious, password guessers, and callers trying to run up international fraud.
It blocks them in the kernel with an XDP program, before the packets reach your
SIP server. It does not sit in the call path and needs nothing from OpenSIPS. It
reads a copy of the traffic, the way a capture tool does.

Install it on the machine that receives SIP from the Internet, which is usually
the machine running OpenSIPS. This guide does not use sipnab. When TFPS is working,
[Let sipnab see and control TFPS](tfps-sipnab.md) adds sipnab.

Two terms used below:

- **XDP** (eXpress Data Path) is a hook in the Linux network driver where a small
  program can drop a packet before the rest of the kernel sees it. TFPS's program
  drops packets to or from your SIP ports whose source it has blocked, and passes
  everything else, so a blocked address can still reach SSH.
- **BTF** (BPF Type Format) is a description of the running kernel's data
  structures, at `/sys/kernel/btf/vmlinux`. TFPS compiles its XDP program against
  it during the install, so the kernel needs BTF built in.

## Tested on

Every command on this page ran as written, in order, on 2026-09-25 on a
clean Ubuntu 24.04.5 virtual machine (kernel `6.8.0-139-generic`), and step by
step on a clean Debian 13 one (kernel `6.12.63+deb13-amd64`). Both were x86_64
with 2 cores and 2 GB of memory, and used the
[TFPS v0.2.1](https://github.com/sippulse/tfps/releases/tag/v0.2.1) release.
TFPS's prebuilt binaries are x86_64 only.

The examples use `192.0.2.20` for the TFPS machine and `198.51.100.60` for a second
machine that plays the attacker. Replace both with yours.

## 1. Check the kernel

TFPS needs Linux 5.15 or newer, built with BTF:

```bash
# Run all of these, in order.
uname -r
ls -l /sys/kernel/btf/vmlinux
```

The file must exist. Debian 11, Ubuntu 22.04 and later distribution kernels have
it.

## 2. Install TFPS

Download the release and check it against the checksum published beside it:

```bash
# Run all of these, in order.
mkdir -p ~/tfps && cd ~/tfps
curl -fsSLO https://github.com/sippulse/tfps/releases/download/v0.2.1/tfps-x86_64-linux-musl.tar.gz
curl -fsSLO https://github.com/sippulse/tfps/releases/download/v0.2.1/tfps-x86_64-linux-musl.tar.gz.sha256
sha256sum -c tfps-x86_64-linux-musl.tar.gz.sha256
tar xzf tfps-x86_64-linux-musl.tar.gz
```

`sha256sum` prints `tfps-x86_64-linux-musl.tar.gz: OK`.

The installer compiles the XDP program on this machine. It installs `clang` and
`bpftool` for that, but not the BPF headers the program includes, so install
them first:

```bash
sudo apt-get install -y libbpf-dev
```

Without `libbpf-dev` the install stops at `fatal error: 'bpf/bpf_helpers.h' file
not found`.

Run the installer from the tarball you checked. Pointing it at the file with
`TFPS_TARBALL` makes it install exactly those bytes. The one-line
`curl ... | sh` form on TFPS's site fetches master's installer script instead:

```bash
# Run all of these, in order.
cd ~/tfps
sudo TFPS_TARBALL="$PWD/tfps-x86_64-linux-musl.tar.gz" sh tfps-x86_64-linux-musl/packaging/install.sh
```

It ends with `tfps is running`. What it installed:

| Path | What |
|---|---|
| `/usr/local/bin/tfps` | the daemon |
| `/usr/local/bin/tfps_ctl` | the command you use to ask it questions and lift blocks |
| `/usr/local/lib/tfps/tfps_xdp.o` | the XDP program, compiled for this kernel |
| `/etc/systemd/system/tfps.service` | the unit; the installer replaces it on upgrade |
| `/etc/tfps/config.json` | settings, written once and never overwritten |
| `/var/lib/tfps/tfps.db` | what TFPS has learned, and its audit log |

## 3. Check that it is enforcing

```bash
# Run all of these, in order.
systemctl is-active tfps
sudo journalctl -u tfps -n 30
sudo tfps_ctl status
```

The journal's startup report names the interface TFPS chose (the one carrying
the default route), the mode, `PREVENTION`, and where the XDP program went, for
example `XDP native (DRV) on eth0`. It also lists the addresses it never
blocks. Out of the box that is only this machine's own addresses.

## 4. Tell it which sources to trust

A carrier that delivers calls to you, a monitoring system, and your own
management network should never lose access. List them in `ignoreip` in
`/etc/tfps/config.json`, as single addresses or ranges. This adds a management
range and one carrier to the settings the installer wrote:

```bash
# Run all of these, in order.
sudo tee /etc/tfps/config.json >/dev/null <<'EOF'
{
  "ports": [5060],
  "intl_prefixes": ["+", "00", "011", "9011"],
  "learn_days": 30,
  "block_ttl": 3600,
  "stats_every": 60,
  "ignoreip": ["192.168.10.0/24", "203.0.113.7"]
}
EOF
sudo systemctl restart tfps
sleep 2
sudo journalctl -u tfps -n 30 | grep -A4 ignoreip | tail -5
```

`ports` are the SIP ports TFPS watches and blocks on. List `5061` as well if
you take SIP over TLS. TFPS detects attacks only in SIP it can read, which means
UDP: it cannot read encrypted SIP, and it does not reassemble SIP over TCP. A
source it has blocked, though, loses every listed port, TCP and TLS
included. TFPS's README lists these limits under "What it does not do".
`block_ttl` is how long a block lasts, in seconds.

Do not list the address of a firewall that forwards SIP to this machine unless
it rewrites the source address, in which case fix the forward instead. With a
plain port forward TFPS sees each attacker's own address. If the firewall
replaces it with its own, every attacker looks like the firewall, and trusting
the firewall trusts them all.

## 5. Watch it block an attacker

From a second machine, send one SIP request the way a scanner does, with
SIPVicious's `friendly-scanner` user agent, then a second one. This uses only
Python's standard library:

```bash
python3 - <<'EOF'
import socket, time, uuid
TARGET = ("192.0.2.20", 5060)
def options(n):
    cid = uuid.uuid4().hex
    return (f"OPTIONS sip:100@{TARGET[0]} SIP/2.0\r\n"
            f"Via: SIP/2.0/UDP 198.51.100.60:5098;branch=z9hG4bK{cid}\r\n"
            "Max-Forwards: 70\r\n"
            f"From: <sip:100@198.51.100.60>;tag={n}\r\n"
            f"To: <sip:100@{TARGET[0]}>\r\n"
            f"Call-ID: {cid}\r\nCSeq: 1 OPTIONS\r\n"
            "User-Agent: friendly-scanner\r\nContent-Length: 0\r\n\r\n").encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(options(1), TARGET)
time.sleep(2)
s.sendto(options(2), TARGET)
EOF
```

Then, on the TFPS machine:

```bash
# Run all of these, in order.
sudo tfps_ctl banned --why
sudo tfps_ctl stats | head -6
sudo journalctl -u tfps -n 5 | grep BLOCKED
```

The first request got the sender blocked for an hour, and the kernel dropped the
second before anything else saw it:

```text
SOURCE           EXPIRES IN  REASON
198.51.100.60               59m  user-agent (friendly)
```

```text
  seen on SIP ports : 2
  dropped by XDP    : 1 (50.0% — gone before sngrep)
```

The test has to come from a second machine: TFPS never blocks the machine it
runs on.

## 6. Operate it

`tfps_ctl` reads and changes what the running daemon holds. Reading or changing
blocks needs root.

| Command | What it does |
|---|---|
| `sudo tfps_ctl status` | what is running, what TFPS blocks, how fresh the learned state is |
| `sudo tfps_ctl stats` | every counter: kernel drops, the traffic mix, what got blocked |
| `sudo tfps_ctl banned --why` | every blocked source, the time left and the reason |
| `sudo tfps_ctl unban 198.51.100.60` | lift a block; `--all` lifts every one |
| `sudo tfps_ctl ban 192.0.2.10 --ttl 600` | block a source by hand for 600 seconds; `--ttl 0` is forever |
| `sudo tfps_ctl log --limit 20` | the audit log of blocks, newest first |

Blocks live in the kernel. They last while `tfps` runs, and `tfps_ctl ban` and
`unban` work only while it is running.

**Observe before you enforce.** For the first days on a busy machine, you can
have TFPS decide without blocking. The journal records every decision as `WOULD BLOCK`
instead. Add a drop-in rather than editing the unit, because an upgrade replaces
the unit:

```bash
sudo systemctl edit tfps
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tfps --no-enforce
```

In this mode TFPS attaches no XDP program, so `tfps_ctl banned` answers `no loaded
eBPF map called 'blocked'`: there is nothing to list. The journal holds the
decisions, as `WOULD BLOCK peer=... (observe only)`.

To start blocking, remove the drop-in and restart:

```bash
# Run all of these, in order.
sudo systemctl revert tfps
sudo systemctl restart tfps
```

**Upgrade** by running the installer again with the newer tarball. It replaces
the binaries, the XDP program and the unit, and keeps `/etc/tfps/config.json`
and `/var/lib/tfps`.

**Uninstall.** Stopping the service removes the XDP program, so no block
outlives it:

```bash
# Run all of these, in order.
sudo systemctl disable --now tfps
sudo rm -f /etc/systemd/system/tfps.service /usr/local/bin/tfps /usr/local/bin/tfps_ctl
sudo rm -rf /usr/local/lib/tfps
sudo systemctl daemon-reload
```

`/var/lib/tfps` and `/etc/tfps` stay behind, so that a reinstall keeps what TFPS
learned. Remove them too if you no longer want it:

```bash
sudo rm -rf /var/lib/tfps /etc/tfps
```

## When something does not work

- **`fatal error: 'bpf/bpf_helpers.h' file not found`.** Install `libbpf-dev`
  and run the installer again.
- **`no /sys/kernel/btf/vmlinux`.** The kernel has no BTF or is older than 5.15.
  Use a distribution kernel.
- **Nothing is ever blocked.** Check the startup report's `ignoreip` list and
  where your SIP arrives from. If a firewall forwards SIP with its own address as
  the source, TFPS sees one source, and `ignoreip` may already trust it.
- **You blocked yourself.** A block covers only the SIP ports, so SSH still
  works: `sudo tfps_ctl unban <your address>`.
