# Capture with the least privilege

A live capture needs raw-socket rights for one moment: opening the interface.
Everything after that, the parsing of untrusted packets included, needs none.
This page takes the rights away as early as sipnab allows, and narrows what the
process can reach after that.

| Step | What it takes away | Needs |
|---|---|---|
| [Grant capture rights to the binary](#grant-capture-rights-to-the-binary) | Running as root at all | Linux, `setcap` |
| [Let sipnab drop root](#let-sipnab-drop-root-after-opening-the-interface) | Root after the interface opens | Started as root |
| [Read capture files only root can read](#read-capture-files-only-root-can-read) | Root while it reads the files | Started as root, one open file per input |
| [Confine it to a directory](#confine-it-to-a-directory) | The rest of the file system | Started as root |
| [Bound the files it can open](#bound-the-files-it-can-open-landlock) | Files outside the paths the run names | A kernel with Landlock |
| [Bound the system calls it makes](#bound-the-system-calls-it-makes-seccomp) | System calls outside a derived list | A kernel with seccomp, a list derived on that host |

Reading a capture file needs none of this: it is reading a file.

What ran: every command and output on this page ran on 2026-11-03 with sipnab
0.5.232 built from source, on Ubuntu 24.04 with Linux 6.8 (aarch64). That
kernel has seccomp and no Landlock, so [Bound the files it can
open](#bound-the-files-it-can-open-landlock) shows the refusal and not a
confined run.

## Before you start

- **Linux.** File capabilities, Landlock and seccomp are Linux features.
  Every command on this page ran on Linux only.
- **sipnab on the capture host,** as [Installing sipnab](install.md) says.
- **Root, or `sudo`, for the step you take.** The table above names the steps
  that start as root.
- **`setcap` and `getcap`,** for the first step. On Debian and Ubuntu the
  `libcap2-bin` package has them.
- **An interface that carries the traffic.** `ip -brief link` lists the
  interfaces. The examples use `eth0`.
- **Nothing on any other system.** Every step changes the capture host only:
  the capabilities of one binary, the user and root directory of one process,
  and the paths and system calls that process may use. No SIP server, relay
  or network device changes.

## Grant capture rights to the binary

```bash
sipnab --setup-caps
```

It sets `cap_net_raw,cap_net_admin+ep` on the binary with `setcap`,
re-running itself through `sudo` when it is not root, and exits. It prints
nothing. Check the result:

```bash
getcap "$(command -v sipnab)"
```

It prints the binary's path followed by `cap_net_admin,cap_net_raw=ep`.

Then capture as your own user:

```bash
sipnab -N -d eth0 --duration 3 --no-cli-print
```

On a lab bridge, `hepx`, that printed:

```text
INFO sipnab::capture::live: Capturing on 'hepx' (link_type=1, snaplen=65535)
INFO sipnab::capture::live: Live capture on 'hepx' finished: 0 packets, no drops
```

- Replacing the binary clears its capabilities: an upgrade, a rebuild, a
  package update. Run `--setup-caps` again after each.
- A file system mounted `nosuid` ignores file capabilities.
- macOS and other systems without file capabilities run live capture under
  `sudo`.
- Under systemd, `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` grants the
  same to a unit that runs as an ordinary user ([Run sipnab as a
  service](examples.md#run-sipnab-as-a-service)).

## Let sipnab drop root after opening the interface

Started as root, sipnab opens the interface, then switches to an unprivileged
user: `nobody` unless you name another with `--user` or `[privilege] user`.

```bash
sudo sipnab -N -d eth0 --duration 3 --no-cli-print
```

The log says which user it became. On the lab bridge:

```text
INFO sipnab::privilege: Dropped privileges to user 'nobody' (uid=65534, gid=65534)
```

- sipnab opens what the run reads by path before the drop: the capture
  device, a keylog file or FIFO, the config. A file the dropped user cannot
  reach is unreachable after that.
- It creates `-O` and `--split` files after the drop, as the dropped user, so
  that user must be able to write their directory ([An output file sipnab
  cannot create](troubleshooting.md#an-output-file-sipnab-cannot-create)).
- The dropped user usually cannot read your home directory, so the TUI's file
  browser (`O`) shows nothing there. Capture with capabilities instead.
- `--no-priv-drop` (or `[privilege] no_priv_drop = true`) keeps root for the
  whole run, and the log says `Privilege drop disabled (--no-priv-drop)`.
  `--priv-drop` turns the drop back on for one run when the file turns it off.
  The scanner-kill worker does not need either: sipnab opens its raw socket
  before the drop.

## Read capture files only root can read

Purpose: read a set of captures, or an archive of them, that only root may
open (mode `0600`, owner root), while the run still drops to `nobody` or
chroots before it parses a packet.

Prerequisites: started as root, as in the previous section. The open-file
limit must hold one descriptor per input file plus 64 for the run itself.

Steps: name the files, a directory or an archive with `-I`, as an ordinary run
does.

```bash
sudo sipnab -N -I /var/lib/captures/ring/ --user nobody
```

A root run that drops privileges or chroots opens every file of the set
before it does either, and reads each one through the descriptor it opened
then. A run that keeps its credentials (not root, or `--no-priv-drop` without
`--chroot`) opens each file when it reaches it, as before.

- The run raises its open-file soft limit as far as the hard limit when the
  set needs it. Above the hard limit the run stops before it reads anything, with
  exit `2`.
- The run unpacks an archive (`.tar.gz`, `.zip`, a `.pcap.gz`) before the
  drop, as root, into a directory only its owner may enter (`0700`) holding
  files only its owner may read (`0600`). Before the drop it gives that
  directory to the user the run drops to, so the run can remove it when it
  ends. A `--chroot` run removes it before the chroot instead, because no
  path reaches it afterwards. So does a run whose drop user could not reach
  it to remove it: a `TMPDIR` inside a directory only another user may
  enter, such as root's per-user temporary folder on macOS
  (under `/var/folders`, mode `0700`). Every member is open by then.
- The run reads the TLS secrets a pcapng carries in a Decryption Secrets
  Block before the drop too, so a root-only capture still decrypts.

Verify: with `SIPNAB_LOG=info`, the closing line counts every file as read in
full, and no line says `Skipping`. On 2026-11-08 with sipnab built from source after
0.5.237, three root-only copies of one capture under a soft limit of 66:

```text
INFO sipnab::app::bootstrap: Raised the open-file limit from 66 to 67: the 3 input file(s) are opened before the run confines itself
INFO sipnab::privilege: Dropped privileges to user 'nobody' (uid=65534, gid=65534)
INFO sipnab::capture::file: Read 21 packets: 3 of 3 file(s) read in full
```

Troubleshooting: under a hard limit of 66 the same run stopped with exit `2`:

```text
sipnab opens all 3 input file(s) before it drops root privileges or chroots, beside 64 descriptors of its own, and this process may hold at most 66 open files. Raise the limit (ulimit -n), read fewer files per run, or run as an ordinary user, which opens each file when it is read.
```

Raise the hard limit (`ulimit -Hn`, or `LimitNOFILE=` in a systemd unit), or
split the set across runs. 0.5.239 and earlier opened every file after the
first by path after the drop, and skipped a root-only one with
`Permission denied` (`No such file or directory` under `--chroot`), the run
ending with exit `1` and a line such as `Read 2 packets: 1 of 2 file(s) read in
full, 1 skipped`.

## Confine it to a directory

`--chroot DIR` (or `[privilege] chroot`) changes the root directory to `DIR`
after the interface opens and before the drop.

sipnab looks the user up before it changes root, so `DIR` needs no
`etc/passwd`: an empty directory works. 0.5.233 and earlier looked the user
up inside `DIR` and stopped with `Failed to drop privileges: User 'nobody' not
found` unless `DIR` held an `etc/passwd` naming the user.

A TLS client that names no CA file of its own (a `--hep-send-transport tls`
sender without `--hep-tls-ca`, an HTTPS `[vcon_fetch]` store without `ca`)
trusts the host's CA bundle. A run with `--chroot` finds and reads that bundle
before it changes root, so `DIR` needs no copy of it. 0.5.238 and earlier
looked for it inside `DIR` and stopped with exit `2`: `Failed to create HEP
sender: no system CA bundle found; name the collector's issuer with
--hep-tls-ca`. If no bundle exists outside `DIR`, sipnab still looks inside it.

A directory that does not exist stops the run with exit `1`: `Failed to
chroot: chroot(/var/empty) failed: No such file or directory (os error 2)`.
Debian and Ubuntu have no `/var/empty`. Make an empty directory for it:

```bash
sudo mkdir -p /var/lib/sipnab/jail
```

```bash
sudo sipnab -N -d eth0 --user nobody --chroot /var/lib/sipnab/jail --duration 3 --no-cli-print
```

```text
INFO sipnab::privilege: Chrooted to /var/lib/sipnab/jail
INFO sipnab::privilege: Dropped privileges to user 'nobody' (uid=65534, gid=65534)
```

Any file the run writes after this, `-O` included, is a path inside `DIR`.

## Bound the files it can open (Landlock)

`--sandbox` uses Linux's Landlock to limit which paths the process can open
once startup is over, to the ones the run names: its inputs, outputs, key
files and configuration.

- `--sandbox best-effort` confines the run where the kernel has Landlock, and
  warns and runs unconfined where it does not.
- `--sandbox required` refuses to capture without it, with exit `1`.

On a kernel built without Landlock:

```bash
sipnab -N -I sample-call.pcap --sandbox required --report --no-cli-print
```

```text
WARN sipnab::app::bootstrap: path sandbox NOT active: this kernel (6.8.12-rt-tegra) has no Landlock: it was built without Landlock support (CONFIG_SECURITY_LANDLOCK). The capture is running unsandboxed; `--sandbox required` refuses instead of continuing.
`--sandbox required` was given and no path sandbox is in force: this kernel (6.8.12-rt-tegra) has no Landlock: it was built without Landlock support (CONFIG_SECURITY_LANDLOCK). Refusing to capture. Use `--sandbox best-effort` to capture without one.
```

Rerun on 2026-11-08 on the same host (Linux 6.8.12-rt-tegra). The reason
depends on the running kernel's release, from `uname`:

| The version query returns | Release | The reason says |
|---|---|---|
| `ENOSYS` | older than 5.13 | `this kernel (<release>) has no Landlock (needs 5.13 or newer)` |
| `ENOSYS` | 5.13 or newer | `this kernel (<release>) has no Landlock: it was built without Landlock support (CONFIG_SECURITY_LANDLOCK)`: a kernel upgrade does not help; a kernel built with that option does |
| `ENOSYS` | unreadable | both causes, and that sipnab could not read the release |
| `EOPNOTSUPP` | any | `Landlock is compiled in but disabled; add it to the kernel's lsm= list to enable it` |

Before that change the text said `needs 5.13 or newer` for every `ENOSYS`,
which on this 6.8 kernel was wrong. Check yours:

```bash
cat /sys/kernel/security/lsm
```

`landlock` must be in the list. Not run for this page: a run with Landlock in
force.

## Bound the system calls it makes (seccomp)

`--seccomp` installs a seccomp filter. Its two modes are two steps:

1. **`--seccomp log`** allows every system call and records each one. It
   protects nothing. It exists to find out which calls your runs make.
2. **`--seccomp enforce`** kills the process on a call outside an allowlist,
   which you derive on the host that runs the capture and name with
   `SIPNAB_SECCOMP_ALLOWLIST`: a file of syscall numbers, one per line, `#`
   comments allowed.

Without a list, `enforce` refuses to start, with exit `1`:

```text
`--seccomp enforce` was given and no syscall filter is in force: enforcement needs an allowlist derived ON THIS HOST, named by SIPNAB_SECCOMP_ALLOWLIST. The list that ships in this binary settled across sixteen shapes on one machine and killed the process on another of the same architecture, so it is a worked example rather than a list to enforce. Produce yours with scripts/derive-seccomp-allowlist.sh. Refusing to capture. Use `--seccomp off` to capture without one.
```

`scripts/derive-seccomp-allowlist.sh <sipnab> <interface>`, run as root, runs
sipnab in sixteen shapes under `--seccomp log`, streams the log the records go
to, and says whether the set of calls stopped growing.

Where the records go depends on the host, and the script finds out the same way
you would:

```bash
sudo auditctl -s
```

- A non-zero `pid` means an audit daemon holds the audit socket. The kernel hands it the
  records, and they land in its log (`log_file` in `/etc/audit/auditd.conf`,
  `/var/log/audit/audit.log` by default) as `type=SECCOMP` lines. The script
  follows that file with `tail -F` and prints
  `Records go to the audit daemon; following /var/log/audit/audit.log.`
- A `pid` of 0, or no `auditctl`, means no daemon. The records are in the
  kernel log as `audit: type=1326` lines, and the script follows
  `dmesg --follow`, with `kernel.printk_ratelimit` set to 0 for the run and
  restored after it.

Set `SIPNAB_DERIVE_AUDIT_LOG` to read another file on the audit path.

To look at the records yourself on a host with a daemon:

```bash
sudo ausearch -m SECCOMP -ts recent
```

A single `--report` run over the sample capture on 2026-11-03 left 5,896
records there, naming 13 distinct system calls. Not run for this page: the
collector as root on this host after the change on 2026-11-08 that made it
read the audit log, nor an enforcing filter. `seccomp_derivation_test` drives
the source choice and the parsing of audit-log records with synthetic input.

The script refuses a run that lost records. On the kernel log that is a
`callbacks suppressed` line. On the audit path it is a rise in the `lost`
counter of `auditctl -s`, which the script reads before and after each shape:

```text
LOST: the audit subsystem lost 12 record(s) during the run.
  A derivation that misses a call yields an allowlist that kills
  the process it was built for. Raise the backlog (auditctl -b
  65536), check that auditctl -r is 0, and run it again.
```

## Check that it worked

The kernel reports the user, the group and the capabilities a running
process holds. While a capture runs, read them:

```bash
grep -E '^(Uid|Gid|CapEff):' "/proc/$(pidof sipnab)/status"
```

A run that started as root and dropped to `nobody` printed:

```text
Uid:	65534	65534	65534	65534
Gid:	65534	65534	65534	65534
CapEff:	0000000000000000
```

`CapEff` of all zeros means the process holds no capability. The same run
with `--no-priv-drop` printed `Uid:	0	0	0	0` and a `CapEff` that is not zero:
it kept root.

The log states each step as sipnab takes it:

| Step | Log line |
|---|---|
| The drop | `Dropped privileges to user 'nobody' (uid=65534, gid=65534)` |
| `--chroot` | `Chrooted to /var/lib/sipnab/jail`, before the line of the drop |
| `--no-priv-drop` | `Privilege drop disabled (--no-priv-drop)` |

What ran: on 2026-11-11, sipnab 0.5.245 built from source ran as root on the
loopback interface inside an Ubuntu 24.04 container with no network, three
times: with no option, with `--user nobody --chroot /var/lib/sipnab/jail`,
and with `--no-priv-drop`. The output and the log lines above are from those
runs. Not run for this check: a run that got its rights from
`--setup-caps`.

## When something does not work

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied on 'eth0'. Grant capture capabilities once`, exit 1 | The binary has no capabilities, or something replaced it since | `sipnab --setup-caps` again |
| `Permission denied on 'eth0'. This process runs with NoNewPrivs set`, exit 1 | `NoNewPrivileges=yes` or `no-new-privileges` makes file capabilities ineffective | `AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` in the unit, or start as root |
| `Permission denied on 'eth0'. CAP_NET_RAW is not in this process's capability bounding set`, exit 1 | The container or unit dropped the capability | `--cap-add=NET_RAW`, or `CapabilityBoundingSet=` naming it |
| `Failed to drop privileges: User 'nobody' not found. Create it with 'useradd -r -s /usr/sbin/nologin nobody' or use --user <name>` | The user does not exist on this host. With `--chroot`, 0.5.233 and earlier also printed this when the directory held no `etc/passwd` naming the user | Create the user, or name another with `--user`. On 0.5.233 or earlier, upgrade, or add the user's entries to the directory |
| `Failed to chroot: chroot(/var/empty) failed: No such file or directory (os error 2)` | The `--chroot` directory does not exist | Create it |
| A root run reading files stops before it reads any with exit `2`, and the message names the hard open-file limit ([quoted in full](#read-capture-files-only-root-can-read)) | The set needs one descriptor per file plus 64, more than the hard open-file limit allows | Raise `ulimit -Hn` or `LimitNOFILE=`, or read fewer files per run |
| `--sandbox required` refuses, `needs 5.13 or newer` | The kernel predates Landlock | `best-effort`, or a 5.13 or newer kernel with Landlock |
| `--sandbox required` refuses, `built without Landlock support (CONFIG_SECURITY_LANDLOCK)` | The kernel is new enough, and its build left Landlock out | `best-effort`, or a kernel built with `CONFIG_SECURITY_LANDLOCK=y` and `landlock` in `lsm=` |
| `--seccomp enforce` refuses | No `SIPNAB_SECCOMP_ALLOWLIST`, or one it cannot read | Derive a list on this host |
| `derive-seccomp-allowlist.sh` prints `NO RECORDS` | The filter never installed, or the records went to a log the script did not follow | Check `sudo auditctl -s`: with a non-zero `pid`, the records are in the audit log, which the script follows; name another file with `SIPNAB_DERIVE_AUDIT_LOG` |
| `derive-seccomp-allowlist.sh` exits 66, `cannot be read` | An audit daemon holds the audit socket and its log is not at the path auditd.conf names | Set `SIPNAB_DERIVE_AUDIT_LOG` to the log's path |

[Privilege](cli-reference.md#privilege) and [`[privilege]`](config-reference.md#privilege)
list every flag and key. The [threat model](threat-model.md) says what each
step defends against.
