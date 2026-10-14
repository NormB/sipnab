# Let sipnab see and control TFPS

[TFPS](tfps.md) blocks attacking SIP sources in the kernel.

- sipnab can ask it what it is blocking and why. It does this through its REST
  API and its MCP tools.
- It can also block or unblock an address on your behalf, once you turn that
  on. Out of the box, sipnab changes nothing outside itself.
- sipnab never blocks anything on its own.
  - Every ban through sipnab is one you ask for.
  - sipnab records it, so you can see it and undo it later.

This guide starts where [Add TFPS to your voice stack](tfps.md) ends, with TFPS
installed and enforcing.

- It covers sipnab on the same machine as TFPS.
- It covers sipnab on a different machine.
- Neither TFPS nor sipnab needs anything from the SIP server. So every step is
  the same beside OpenSIPS or Kamailio.

## What sipnab asks TFPS

sipnab runs `tfps_ctl`, TFPS's own command, and reads its answers:

| sipnab route | MCP tool | Runs | Needs |
|---|---|---|---|
| `GET /v1/tfps/status` | `tfps_status` | `tfps_ctl status` | the block map, to report enforcement |
| `GET /v1/tfps/banned` | `tfps_banned` | `tfps_ctl banned` | the block map |
| `GET /v1/tfps/labels` | `tfps_labels` | `tfps_ctl log` | the database |
| `POST /v1/tfps/ban` | `tfps_ban` | `tfps_ctl ban` | the block map and `/etc/tfps/config.json`, once `--allow-action` turns it on |
| `POST /v1/tfps/unban` | `tfps_unban` | `tfps_ctl unban` | the block map, once `--allow-action` turns it on |
| `POST /v1/actions/revert` | `actions_revert` | `tfps_ctl unban` | the block map, once `--allow-action` turns it on |
| `GET /v1/tfps/dropped` | `tfps_dropped` | nothing yet | a TFPS release that reports its kernel drops; none does yet, so this answers `502` |

The [REST API reference](rest-api.md) gives every request and response.

## Tested on

Every block on this page ran as written, in order, on 2026-09-28. The exception
is the blocks in
[sipnab on the same machine as TFPS](#sipnab-on-the-same-machine-as-tfps).

- sipnab was 0.5.194, from its release package.
- The machines were clean x86_64 virtual machines with 2 cores and 3 GB of
  memory:
  - Debian 13 (kernel 6.12.63),
  - Ubuntu 24.04.5 (kernel 6.8.0).
- sipnab ran beside TFPS, and on a second machine reaching it over SSH.
- TFPS came from a build of master.
- On Debian 13, causing each fault under
  [When something does not work](#when-something-does-not-work) produced what
  it describes.

## Check that TFPS answers in JSON

sipnab reads `tfps_ctl`'s answers as JSON. It asks with `--json`.

- That option is on TFPS's master branch, merged 2026-09-18 as
  [`984577dc`](https://github.com/sippulse/tfps/commit/984577dc).
- It is in no release yet. v0.2.1 answers `unknown option: --json`.
- [Add TFPS to your voice stack](tfps.md) builds that commit.
- If your TFPS is a release, run its
  [Install TFPS](tfps.md#install-tfps) step.
  - The installer builds from the checkout and upgrades the release in place.
  - It keeps `/etc/tfps/config.json` and what TFPS has learned.

Then check:

```bash
sudo tfps_ctl status --json
```

It prints one line of JSON, starting `{"enforcement":"active",...`. This build
still calls itself `0.2.1` in that line. That is because master has not changed
its version number since the release.

## Install sipnab

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_amd64.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_amd64.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_amd64.deb
```

The package runs sipnab as the `sipnab` user, capturing on every interface.

## sipnab on the same machine as TFPS

This section ran as written on 2026-09-29. It did not run with the release in
[Tested on](#tested-on).

- It ran on the same Debian 13 and Ubuntu 24.04 machines.
- It used a package built from source that day, before the 0.5.196 release.
- The test installed that package over the release package that the "Install
  sipnab" step installs.
- `--allow-action`, `--journal-show` and `--revert-actions` first shipped in
  0.5.196.

**Turn on the REST API, and let it ban.** The API key reads everything and
changes nothing.

- To ban and unban, sipnab also needs a signing key. From it you make a separate
  credential that may act.
- Keep both keys out of the command line, where every user on the machine could
  read them.
- Put them in a file only root can read. systemd reads it before it starts
  sipnab:

```bash
# Run all of these, in order.
sudo sh -c 'umask 077; { printf "SIPNAB_API_KEY=%s\n" "$(openssl rand -hex 32)"; printf "SIPNAB_API_SIGNING_KEY=%s\n" "$(openssl rand -hex 32)"; } > /etc/sipnab/api.env'
sudo mkdir -p /etc/systemd/system/sipnab.service.d
sudo tee /etc/systemd/system/sipnab.service.d/tfps.conf >/dev/null <<'EOF'
[Service]
EnvironmentFile=/etc/sipnab/api.env
ExecStart=
ExecStart=/usr/bin/sipnab -N -d any --no-cli-print --syslog --metrics 127.0.0.1:9090 \
  --api 127.0.0.1:8080 --tfps-ctl /usr/local/bin/tfps_ctl --allow-action tfps:rest
EOF
```

`--allow-action tfps:rest` is what lets a REST caller ban and unban.

- Without it, those two routes answer `403` and `tfps_ctl` never runs.
- Leave it out if you only want to read what TFPS decided.
- With it, sipnab records every ban and unban in `/var/lib/sipnab/journal`.
  systemd creates that directory for the packaged service.
- With it, sipnab also limits how often it acts:
  - at most 10 actions a minute,
  - 5 from one caller,
  - one per address a minute.
- Every ban it asks for expires. That is after an hour, unless you ask for
  another time.

The API listens on `127.0.0.1` only. Put a TLS proxy in front of it before you
open it to the network.

Following [Send sipnab's vCons to a vCon server](vcon-sipnab.md) as well?

- Both guides replace sipnab's `ExecStart` in a drop-in.
- systemd uses the last `ExecStart=` it reads, taking drop-ins in file-name
  order.
- So one silently replaces the other.
- Put the flags from both into one drop-in instead.

**Give sipnab what `tfps_ctl` needs.** sipnab runs without root. The `tfps_ctl`
it starts inherits sipnab's privileges. TFPS's commands need more than a capture
does:

- **To read or change blocks,** `tfps_ctl` has to find TFPS's block map in the
  kernel by name.
  - That takes `CAP_BPF` and `CAP_SYS_ADMIN`.
  - With `CAP_BPF` alone it fails with ``no loaded eBPF map called `blocked` ``.
- **To ban,** `tfps_ctl` reads `/etc/tfps/config.json`. It does this to refuse
  addresses you told TFPS to trust. The file is readable by root only.

```bash
# Run all of these, in order.
sudo tee /etc/systemd/system/sipnab.service.d/tfps-caps.conf >/dev/null <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF CAP_SYS_ADMIN
EOF
sudo chgrp sipnab /etc/tfps/config.json
sudo chmod 640 /etc/tfps/config.json
sudo systemctl daemon-reload
sudo systemctl restart sipnab
```

Know what you are granting.

- `CAP_SYS_ADMIN` is a broad capability, and sipnab parses traffic from the
  Internet.
- If you only want to *read* what TFPS decided, skip the capabilities.
  - `labels` works without them.
  - `status` still answers. It reports enforcement as `inactive`, because it
    cannot see the map.
- The [different-machine setup](#sipnab-on-a-different-machine) below grants
  sipnab nothing. It works on one machine too.

The installer never rewrites `/etc/tfps/config.json`. So the group you gave it
survives TFPS upgrades. Anything secret in that file, such as an APIBAN key, is
now readable by sipnab.

**Try it.** Make a credential that may act: a token with scope `actions`,
signed with the key sipnab now holds. Then read, ban, look, and unban:

```bash
# Run all of these, in order.
KEY=$(sudo sed -n 's/^SIPNAB_API_KEY=//p' /etc/sipnab/api.env)
ACT=$(sudo sh -c 'set -a; . /etc/sipnab/api.env; sipnab --mint-token --token-scope actions --token-id ops-console')
curl -s -w '\n' -H "Authorization: Bearer $KEY" 127.0.0.1:8080/v1/tfps/status
curl -s -w '\n' -X POST -H "Authorization: Bearer $ACT" -H 'Content-Type: application/json' \
  -d '{"ip":"198.51.100.20","ttl_secs":600}' 127.0.0.1:8080/v1/tfps/ban
curl -s -w '\n' -H "Authorization: Bearer $KEY" 127.0.0.1:8080/v1/tfps/banned
sudo sipnab --journal-show
sleep 60
curl -s -w '\n' -X POST -H "Authorization: Bearer $ACT" -H 'Content-Type: application/json' \
  -d '{"ip":"198.51.100.20"}' 127.0.0.1:8080/v1/tfps/unban
```

What you see:

- The status reports `"enforcement":"active"`.
- The ban answers `"applied":true` with the `id` sipnab recorded it under.
- `banned` lists `198.51.100.20` with its expiry.
- `sipnab --journal-show` lists the same ban, its id, and `token:ops-console` as
  the caller.
- The `sleep` is there because sipnab rests an address for a minute between
  actions.
- After it, the unban answers `"applied":true`.
- TFPS refuses to ban its own machine. The answer is `"applied":false` with
  `"refused":"local"`.

The API key alone cannot ban. Try the ban with `$KEY` and it answers `401`.

**Undo everything sipnab did.** Someone may misuse a credential that may act.
Then:

- take the permission away first,
- then lift every ban sipnab placed.

sipnab only lifts its own bans, never one TFPS placed:

```bash
# Run all of these, in order.
sudo sed -i 's/ --allow-action tfps:rest//' /etc/systemd/system/sipnab.service.d/tfps.conf
sudo systemctl daemon-reload
sudo systemctl stop sipnab
sudo sipnab --revert-actions all --tfps-ctl /usr/local/bin/tfps_ctl
sudo systemctl start sipnab
```

## sipnab on a different machine

sipnab starts `tfps_ctl` as a local program. It does not care whether that
program is TFPS's or a script.

- On the sipnab machine, a two-line script takes its place. The script runs
  `tfps_ctl` on the TFPS machine over SSH.
- On the TFPS machine, a dedicated account's key can run `tfps_ctl` and nothing
  else.

This way sipnab needs no extra privileges at all. The one privileged thing, a
`sudo` rule for `tfps_ctl`, stays on the TFPS machine.

**On the sipnab machine,** make a key for the connection:

```bash
# Run all of these, in order.
sudo install -d -o sipnab -g sipnab -m 0700 /etc/sipnab/tfps
sudo -u sipnab ssh-keygen -q -t ed25519 -N '' -C sipnab-tfps -f /etc/sipnab/tfps/key
sudo cat /etc/sipnab/tfps/key.pub
```

**On the TFPS machine,** create these:

- the account,
- a forced command that passes the arguments to `tfps_ctl` and nothing else,
- a `sudo` rule for `tfps_ctl` alone.

Paste the public key from the last step where it says `PUBLIC-KEY`:

```bash
# Run all of these, in order.
sudo useradd --system --create-home --home-dir /var/lib/sipnabctl --shell /bin/sh sipnabctl
sudo install -d -m 0755 /usr/local/lib/tfps-remote
sudo tee /usr/local/lib/tfps-remote/serve >/dev/null <<'EOF'
#!/bin/sh
# Forced command for sipnab's key: run tfps_ctl with the arguments sipnab
# sent, and nothing else. set -f stops the shell expanding * or ? in them;
# the arguments are split on spaces and never evaluated.
set -f
exec sudo -n /usr/local/bin/tfps_ctl $SSH_ORIGINAL_COMMAND
EOF
sudo chmod 0755 /usr/local/lib/tfps-remote/serve
echo 'sipnabctl ALL=(root) NOPASSWD: /usr/local/bin/tfps_ctl' | sudo tee /etc/sudoers.d/sipnabctl >/dev/null
sudo chmod 0440 /etc/sudoers.d/sipnabctl
sudo visudo -cf /etc/sudoers.d/sipnabctl
sudo install -d -o sipnabctl -g sipnabctl -m 0700 /var/lib/sipnabctl/.ssh
echo 'restrict,command="/usr/local/lib/tfps-remote/serve" PUBLIC-KEY' \
  | sudo tee /var/lib/sipnabctl/.ssh/authorized_keys >/dev/null
sudo chown sipnabctl: /var/lib/sipnabctl/.ssh/authorized_keys
sudo chmod 0600 /var/lib/sipnabctl/.ssh/authorized_keys
```

- `restrict` turns off port forwarding, agent forwarding and terminals for the
  key.
- `command=` means the key runs `serve` whatever the other side asks for.
- An attempt to slip in a second command, such as `status;id`, reaches
  `tfps_ctl` as one unknown argument. `tfps_ctl` refuses it.

**Back on the sipnab machine,** do these things:

- write the script that stands in for `tfps_ctl`,
- record the TFPS machine's host key,
- try it.

Replace `192.0.2.20` with the TFPS machine's address:

```bash
# Run all of these, in order.
sudo tee /etc/sipnab/tfps/tfps_ctl >/dev/null <<'EOF'
#!/bin/sh
exec ssh -o BatchMode=yes -o UserKnownHostsFile=/etc/sipnab/tfps/known_hosts \
  -i /etc/sipnab/tfps/key sipnabctl@192.0.2.20 -- "$@"
EOF
sudo chmod 0755 /etc/sipnab/tfps/tfps_ctl
ssh-keyscan -t ed25519 192.0.2.20 | sudo -u sipnab tee /etc/sipnab/tfps/known_hosts >/dev/null
sudo -u sipnab /etc/sipnab/tfps/tfps_ctl status --json
```

The last line prints TFPS's status as JSON. Check the host key that
`ssh-keyscan` recorded against the TFPS machine's own
(`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` there). Do this before you
rely on it.

Then point sipnab at the script.

- Use the API key file from
  [the same-machine section](#sipnab-on-the-same-machine-as-tfps).
- Do not use the capability drop-in.

```bash
# Run all of these, in order.
sudo sh -c 'umask 077; printf "SIPNAB_API_KEY=%s\n" "$(openssl rand -hex 32)" > /etc/sipnab/api.env'
sudo mkdir -p /etc/systemd/system/sipnab.service.d
sudo tee /etc/systemd/system/sipnab.service.d/tfps.conf >/dev/null <<'EOF'
[Service]
EnvironmentFile=/etc/sipnab/api.env
ReadWritePaths=/etc/sipnab/tfps
ExecStart=
ExecStart=/usr/bin/sipnab -N -d any --no-cli-print --syslog --metrics 127.0.0.1:9090 \
  --api 127.0.0.1:8080 --tfps-ctl /etc/sipnab/tfps/tfps_ctl
EOF
sudo systemctl daemon-reload
sudo systemctl restart sipnab
```

The `curl` commands from the same-machine section work unchanged.

## When something does not work

- **`unknown option: --json`.** The TFPS in use is a release. Build master, as
  in the "Check that TFPS answers in JSON" step.
- **``no loaded eBPF map called `blocked` — is tfps running, and are you root?``**
  Either TFPS is not running, or sipnab lacks `CAP_BPF` and `CAP_SYS_ADMIN`.
- **`reading /etc/tfps/config.json: Permission denied`.** Give the file to the
  `sipnab` group, as in the same-machine section.
- **`/v1/tfps/dropped` answers `502`.** Expected: no TFPS build has `dropped`
  yet.
- **`installed: false`, and the reason says `tfps_ctl` was not found on
  `PATH`.**
  - The service runs without `--tfps-ctl`, and its `PATH` has no `tfps_ctl`.
  - Name it with `--tfps-ctl`.
- **`502` with `cannot run ...: No such file or directory`.** The path given to
  `--tfps-ctl` does not exist. Check it.
