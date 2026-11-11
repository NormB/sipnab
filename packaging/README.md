# Packaging

First-party packaging for sipnab releases. Everything here is maintained by
the project, exercised by CI, and run by `.github/workflows/release.yml` when a
tag is cut — it is not optional or community-contributed material. For that,
see [`contrib/`](../contrib/README.md).

| Path | What it does | What runs it |
|------|--------------|--------------|
| `deb/build-deb.sh` | Builds the `.deb` (full and `-noaudio` variants) | `release.yml`, on a tag |
| `deb/test-build-deb.sh` | 54 assertions over control metadata, payload and what each maintainer script does per dpkg action | CI, every push |
| `rpm/build-rpm.sh` | Builds the `.rpm` from a spec it generates inline | `release.yml`, on a tag |
| `rpm/test-build-rpm.sh` | 49 assertions over rpm metadata, payload, the packaged binary's `DT_NEEDED` and what each scriptlet does on erase and upgrade | CI, every push |
| `homebrew/update-formula.sh` | Generates `sipnab.rb` from `SHA256SUMS.txt` | `scripts/post-release.py`, after a release |
| `homebrew/test-update-formula.sh` | 25 assertions over formula generation, against a fixture whose shape is checked by `test-real-sums.sh` | CI, every push |
| `homebrew/test-real-sums.sh` | Runs the real generator against the **real** `SHA256SUMS.txt` of the latest published release | CI, every push |
| `sipnab.service` | systemd unit, installed by both the `.deb` and the `.rpm` | — |

There is deliberately no checked-in `.spec` file. `build-rpm.sh` writes its
own spec into the rpmbuild tree at build time, so a second copy in the repo is
read by nothing — and the one that used to sit here had drifted into declaring
`License: GPL-3.0-only`, which is not sipnab's license.

## Running the builders

Both builders resolve their inputs (`man/sipnab.1`, `packaging/sipnab.service`,
the binary) **relative to the working directory**, so run them from the repo
root, not from this directory.

The full `.deb`, with the audio plugin:

```bash
bash packaging/deb/build-deb.sh 1.2.3 amd64
```

The `-noaudio` `.deb`, for hosts that have no `libasound2` and never play audio:

```bash
bash packaging/deb/build-deb.sh 1.2.3 amd64 noaudio
```

The `.rpm`, which takes the rpm spelling of the architecture — `x86_64`, not the
`amd64` the `.deb` builder expects:

```bash
bash packaging/rpm/build-rpm.sh 1.2.3 x86_64
```

Set `SIPNAB_BIN` (and optionally `SIPNAB_AUDIO_PLUGIN`) to package a pre-built
binary instead of invoking `cargo build` — this is how the release workflow
packages cross-compiled artifacts.

## Why the paths are tested

Those bare relative literals are the fragile part: nothing type-checks a path
inside a shell script, so moving a file leaves the string pointing at nothing.
For `build-deb.sh` that surfaces in CI, but `update-formula.sh` only ever runs
on a release tag — the worst place to learn a path is stale, since the tag is
cut and the workflow is already publishing.

`packaging_scripts_reference_existing_paths` (in `tests/site_journey_test.rs`)
asserts every repo-relative path these scripts name actually exists, so that
failure lands on the push that causes it.

## What the packages do to the service

Neither package enables or starts `sipnab.service` on a fresh install. Both
stop and disable it when the package is removed, and restart it on an upgrade
only when it is running, so it never keeps running a replaced or deleted
binary:

| Operation | `.deb` script | `.rpm` scriptlet | Effect |
|---|---|---|---|
| Fresh install | `postinst configure` | — | Creates the `sipnab` user; nothing else |
| Upgrade | `postinst configure <old>` | `%postun` with `$1` = 1 | `systemctl daemon-reload`, then `try-restart` |
| Remove | `prerm remove`, `postrm remove` | `%preun` with `$1` = 0, `%postun` with `$1` = 0 | Stop (when systemd is running), `disable`, `daemon-reload` |

The rules are the ones `dh_installsystemd` and the `%systemd_preun` /
`%systemd_postun_with_restart` macros apply, written out by hand: the `.deb`
is not built with debhelper, and the `.rpm` is built on Debian, where the
macros are not defined. The `.deb` disables in `prerm`, not `postrm`, because
`systemctl disable` reads the unit file's `[Install]` section to find the links,
and the file is gone by `postrm`. Both test harnesses run each script per
action against stub commands.

## Why the rpm names a different libpcap than the deb

The two builders disagree about one string on purpose. Debian patched
libpcap's SONAME to `libpcap.so.0.8` and never bumped it; upstream, and so
every RPM distribution, ships `libpcap.so.1`. The release workflow builds the
gnu binaries — and both packages — inside a Debian container, so the binary it
hands over records `libpcap.so.0.8`, and rpmbuild's automatic dependency
generator wrote that straight into the `.rpm`. Nothing on Fedora or RHEL
provides that name, so `dnf install` refused a package whose library was
already present.

`build-rpm.sh` therefore rewrites its **own copy** of the binary's `DT_NEEDED`
to `libpcap.so.1` with `patchelf` before rpmbuild sees it, and fails the build
rather than proceeding if it cannot. Rewriting only the generated `Requires:`
would have been worse than the bug: the loader reads the same `DT_NEEDED` the
generator does, so the package would have installed and then failed to start.
The `.deb` keeps Debian's name, because on Debian that name is correct.
