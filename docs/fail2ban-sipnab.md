# Feed fail2ban from sipnab

[fail2ban](fail2ban.md) bans the addresses that a log names. sipnab can write
that log. Its scanner detector and its registration-flood detector each find
attackers in the SIP traffic sipnab captures, and with `--fail2ban` sipnab
writes one line for each detection. The filter and jail in sipnab's
[`contrib/fail2ban`](https://github.com/NormB/sipnab/tree/main/contrib/fail2ban)
turn those lines into bans. sipnab writes the lines, and fail2ban decides and
bans.

sipnab's lines come from the traffic it captures, not from your SIP server's
log.

This guide starts where [Ban SIP scanners with fail2ban](fail2ban.md) ends,
before its uninstall: OpenSIPS, fail2ban and the two test addresses in place.

## What sipnab writes

Two kinds of line, one per detection:

```text
2026-10-01 03:49:45 sipnab[17157]: scanner_detected src=198.51.100.60 ua="friendly-scanner" method="OPTIONS"
2026-10-01 03:51:13 sipnab[17540]: reg_flood src=198.51.100.60 count=51
```

- `scanner_detected` comes from the scanner detector, `--kill-scanner`. sipnab
  quotes `ua` and `method`.
- `reg_flood` comes from the registration-flood detector, `--reg-flood`.
  `count` is how many REGISTERs with credentials the registrar refused from
  that address within one second. Out of the box the threshold is 50, and
  sipnab writes a line for each refusal past it, so 80 refusals in a burst
  write 30 lines, `count=51` to `count=80`.

`--fail2ban` itself detects nothing: it only chooses the format. Without a
detector beside it, sipnab warns when it starts that `no detector is running,
so this run will emit nothing`.

**Know what `--kill-scanner` sends.** On a live capture, the scanner detector
also answers the scanner requests it detects, from a separate process. The
answer is a `200 OK`, sent with your SIP server's address and port as its
source. Watching the scanner's side, the request OpenSIPS ignored on purpose
got an answer within milliseconds:

```text
03:50:04.370537 IP 198.51.100.60.54184 > 192.0.2.10.5060: SIP: OPTIONS sip:192.0.2.10 SIP/2.0
03:50:04.383978 IP 192.0.2.10.5060 > 198.51.100.60.54184: SIP: SIP/2.0 200 OK
```

So with sipnab running this way, a scanner learns that something answers on
your SIP port, even when your SIP server answers nothing.

## Tested on

Every block on this page, and every command in step 6's table, ran as written,
in order, on 2026-10-01, with sipnab 0.5.198 from its release package, on the
machines [the fail2ban guide](fail2ban.md#tested-on) ran on: clean x86_64
virtual machines with 2 cores and 3 GB of memory, Debian 13 (kernel 6.12.111)
and Ubuntu 24.04 (kernel 6.8.0), right after that guide's step 8. On each
system the shipped jail failed in step 3 as described, and a capture on both
showed the answer `--kill-scanner` sends.

## 1. Install sipnab

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_amd64.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_amd64.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_amd64.deb
```

The package installs a service that runs sipnab as the `sipnab` user,
capturing on every interface. It does not start it.

## 2. Run sipnab with its detectors, writing the log

A drop-in adds the two detectors and `--fail2ban` to the packaged command, and
sends sipnab's standard output, where the lines go, to `/var/log/sipnab.log`,
the file the contrib jail reads. sipnab's own messages, on standard error, stay
in the journal:

```bash
# Run all of these, in order.
sudo mkdir -p /etc/systemd/system/sipnab.service.d
sudo tee /etc/systemd/system/sipnab.service.d/fail2ban.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/sipnab -N -d any --no-cli-print --syslog --metrics 127.0.0.1:9090 \
  --kill-scanner --reg-flood --fail2ban
StandardOutput=append:/var/log/sipnab.log
StandardError=journal
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now sipnab
sleep 3
systemctl is-active sipnab
sudo ls -l /var/log/sipnab.log
```

`--no-cli-print` keeps every SIP message out of the log, but does not hold back
the detection lines. systemd creates the log file when the service starts.
Start sipnab before the jail: fail2ban refuses to start a jail whose log file
does not exist, and stops every other jail with it.

## 3. Install sipnab's filter and jail

Fetch both files at the tag of the sipnab you installed:

```bash
# Run all of these, in order.
V=$(sipnab --version | awk 'NR==1 {print $2}')
sudo curl -fsSL "https://raw.githubusercontent.com/NormB/sipnab/v$V/contrib/fail2ban/sipnab-scanner.conf" \
  -o /etc/fail2ban/filter.d/sipnab-scanner.conf
sudo curl -fsSL "https://raw.githubusercontent.com/NormB/sipnab/v$V/contrib/fail2ban/sipnab-jail.conf" \
  -o /etc/fail2ban/jail.d/sipnab.conf
cat /etc/fail2ban/jail.d/sipnab.conf
```

The jail, `sipnab-scanner`, bans after one line (`maxretry = 1`), for an hour,
on every port. As shipped, it does not ban on either system this guide ran
on:

- **On Debian 13** it reads `/var/log/sipnab.log`, but its ban action,
  `iptables-allports`, needs the `iptables` command, which installing fail2ban
  and nftables as [the fail2ban guide](fail2ban.md#2-install-fail2ban) does
  leaves out. The jail lists the address as banned, `/var/log/fail2ban.log`
  reports `returned 127` and `Command not found` for `iptables`, and the
  scanner's traffic still gets through.
- **On Ubuntu 24.04** it never reads `/var/log/sipnab.log`: its status shows
  `Journal matches:` with nothing after it, where Debian's shows `File list:`.
  The jail reads the systemd journal instead of the file it names, and bans
  nobody.

A `.local` file overrides the jail without editing it. It makes the jail read
its log file, and ban with nftables, as the OpenSIPS jail does:

```bash
# Run all of these, in order.
sudo tee /etc/fail2ban/jail.d/sipnab.local >/dev/null <<'EOF'
[sipnab-scanner]
backend = auto
action = nftables[type=allports, name=sipnab, protocol="udp,tcp"]
EOF
sudo systemctl restart fail2ban
sleep 3
sudo fail2ban-client status sipnab-scanner
```

The status shows `File list: /var/log/sipnab.log`.

One line is enough for a ban here. Before you leave this running on real
traffic, measure who the detectors would name on a capture of your own, as
[Detect SIP scanners and auto-block via fail2ban](examples.md#10-detect-sip-scanners-and-auto-block-via-fail2ban)
shows, and set the jail's `maxretry` and `ignoreip` in `sipnab.local` to suit.

## 4. Watch sipnab's line become a ban

Start with the scanner unbanned in every jail, in case the fail2ban guide's
tests left a ban behind. Then the scanner sends one `OPTIONS` as
`friendly-scanner`, and one more:

```bash
# Run all of these, in order.
sudo fail2ban-client unban 198.51.100.60
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 OPTIONS 1 friendly-scanner
sleep 3
sudo tail -n 1 /var/log/sipnab.log
sudo fail2ban-client status sipnab-scanner
sudo nft list set inet f2b-table addr-set-sipnab
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 OPTIONS 1
```

The first `OPTIONS` prints `SIP/2.0 200 OK`: sipnab's answer, not OpenSIPS's.
The log holds its `scanner_detected src=198.51.100.60` line, the jail lists the
address, nftables holds it in `addr-set-sipnab`, and the second `OPTIONS`
prints `refused`.

The phone is not affected, and sipnab wrote nothing about it:

```bash
# Run all of these, in order.
sudo ip netns exec phone python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 1 MicroSIP 1001 correct-horse-1001
sudo grep -c 203.0.113.70 /var/log/sipnab.log || true
```

It prints `REGISTER 1001: SIP/2.0 200 OK`, then `0`.

## 5. Watch a registration flood become a ban

Lift the scanner's ban first. The OpenSIPS jail would also ban this guesser,
after its third wrong password, so have that jail ignore the address while you
watch, and stop ignoring it afterwards:

```bash
# Run all of these, in order.
sudo fail2ban-client set sipnab-scanner unbanip 198.51.100.60
sudo fail2ban-client set opensips addignoreip 198.51.100.60
sudo ip netns exec scanner python3 ~/f2b-test/sipreq.py 192.0.2.10 REGISTER 80 MicroSIP 1001 wrong-password | sort | uniq -c
sleep 3
sudo grep -c 'reg_flood src=198.51.100.60' /var/log/sipnab.log
sudo fail2ban-client status sipnab-scanner
sudo fail2ban-client set opensips delignoreip 198.51.100.60
```

All 80 guesses print `REGISTER 1001: SIP/2.0 401 Unauthorized`. sipnab wrote 30
`reg_flood` lines for them, and the jail lists `198.51.100.60`.

## 6. Operate it

| Command | What it does |
|---|---|
| `sudo fail2ban-client status sipnab-scanner` | the jail's failures and its banned addresses |
| `sudo fail2ban-client set sipnab-scanner unbanip 198.51.100.60` | lift a ban |
| `sudo fail2ban-regex /var/log/sipnab.log sipnab-scanner` | count the lines of sipnab's log the filter matches, without banning anything |
| `sudo journalctl -u sipnab -n 20` | sipnab's own messages, including an `[ALERT]` line for each detection |

**Uninstall.** Remove the jail and the drop-in, and put the packaged service
back:

```bash
# Run all of these, in order.
sudo rm -f /etc/fail2ban/jail.d/sipnab.conf /etc/fail2ban/jail.d/sipnab.local /etc/fail2ban/filter.d/sipnab-scanner.conf
sudo systemctl restart fail2ban
sudo rm /etc/systemd/system/sipnab.service.d/fail2ban.conf
sudo systemctl daemon-reload
sudo systemctl disable --now sipnab
sudo rm -f /var/log/sipnab.log
```

To remove sipnab too:

```bash
sudo apt-get purge -y sipnab
```

## When something does not work

- **fail2ban does not start, and `journalctl -u fail2ban` says `Have not found
  any log file for sipnab-scanner jail`.** `/var/log/sipnab.log` does not exist
  yet. Start sipnab as in step 2, then restart fail2ban.
- **The jail lists an address, but its traffic still gets through.**
  `/var/log/fail2ban.log` shows `returned 127` for the ban: the ban action's
  command is missing. Install the `.local` override from step 3.
- **The jail never bans, and its status shows `Journal matches:` rather than
  `File list:`.** The jail reads the journal, not sipnab's log. Install the
  `.local` override from step 3.
- **The log stays empty.** Run `sudo journalctl -u sipnab -n 20`. sipnab warns
  there when `--fail2ban` has no detector beside it.
