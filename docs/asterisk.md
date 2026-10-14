# Use Asterisk as your voice stack's PBX

[Asterisk](https://www.asterisk.org) is an open-source PBX. It does three
things:

- It answers calls.
- It runs a dialplan that decides what happens to each one.
- It places calls to phones and carriers.

OpenSIPS and Kamailio are proxies. They pass a call's SIP messages along.
Asterisk is a [B2BUA](glossary.md#b2bua) (back-to-back user agent) instead:

- It answers the caller's call itself.
- It places a second call to the callee.
- It connects the two.

Each call through Asterisk is therefore two SIP calls, called legs. Each leg
has its own Call-ID.

This guide does the following:

- It builds Asterisk from source.
- It sets up two endpoints and a dialplan that connects them.
- It proves it with a test call that carries audio both ways through Asterisk.

This guide does not use sipnab. When you have this working,
[Run sipnab beside Asterisk](asterisk-sipnab.md) adds sipnab.

## Tested on

Every block on this page ran as written on 2026-10-12.

- The machines were clean x86_64 virtual machines with 2 cores and 3 GB of
  memory.
- They ran Debian 13 (kernel 6.12.63) and Ubuntu 24.04 (kernel 6.8.0).
- The machines had nothing installed before the build.
- On Ubuntu 24.04, the install, configuration, test call and uninstall then ran
  a second time on the same machine, after its first uninstall.
- Every test call carried audio both ways through Asterisk, counted on the
  wire.
- Causing each fault under
  [When something does not work](#when-something-does-not-work) produced what
  it describes, on both.

| Software | Version |
|---|---|
| Asterisk | 22.11.0, the Asterisk project's source release. 22 is a long-term support series, which the project lists as fully supported until 2028-10-16 |
| SIPp (for the test call) | the distribution's `sip-tester`: 3.7.3 on Debian 13, 3.7.2 on Ubuntu 24.04 |

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## Install Asterisk

Debian 13 has no Asterisk package. Ubuntu 24.04 carries the older 20.6.0.
The Asterisk project publishes source releases. They build the same way on
both. This block does the following:

- It installs the build tools and libraries.
- It downloads 22.11.0.
- It checks it against the project's published SHA-256 checksum.
- It builds it.

```bash
# Run all of these, in order.
sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential curl ca-certificates pkg-config bzip2 patch \
  libedit-dev libjansson-dev libxml2-dev uuid-dev libsqlite3-dev libssl-dev
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
curl -fsSLO https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-22.11.0.tar.gz
curl -fsSL https://downloads.asterisk.org/pub/telephony/asterisk/asterisk-22.11.0.sha256 | sha256sum -c -
tar xzf asterisk-22.11.0.tar.gz
cd asterisk-22.11.0
./configure
make -j2
sudo make install
sudo asterisk -V
```

- `sha256sum -c` prints `asterisk-22.11.0.tar.gz: OK`.
  - The checksum file comes from the same server as the source.
  - So it detects a damaged download, not a replaced one.
- `./configure` also downloads PJSIP from `raw.githubusercontent.com`.
  - PJSIP is the SIP library that Asterisk's `chan_pjsip` uses.
  - That step checks PJSIP before the build uses it.
- The last line prints `Asterisk 22.11.0`.

`make install` does three things:

- It puts the program in `/usr/sbin/asterisk`.
- It puts its modules in `/usr/lib/asterisk/modules`.
- It creates an empty `/etc/asterisk` for the configuration.

Give Asterisk its own user and a systemd unit that runs it as that user:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /var/lib/asterisk --shell /usr/sbin/nologin asterisk
sudo chown -R asterisk:asterisk /var/lib/asterisk /var/log/asterisk /var/spool/asterisk
sudo tee /etc/systemd/system/asterisk.service >/dev/null <<'EOF'
[Unit]
Description=Asterisk PBX
After=network.target

[Service]
Type=simple
User=asterisk
Group=asterisk
RuntimeDirectory=asterisk
WorkingDirectory=/var/lib/asterisk
ExecStart=/usr/sbin/asterisk -f -C /etc/asterisk/asterisk.conf
ExecReload=/usr/sbin/asterisk -rx 'core reload'
Restart=always
RestartSec=4

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable asterisk
```

- `-f` keeps Asterisk in the foreground, where systemd can watch it.
- `RuntimeDirectory` creates `/run/asterisk` for the `asterisk` user at every
  start.
  - Asterisk puts its control socket there.
  - The `asterisk -rx` commands below use that socket to talk to the running
    Asterisk.

## Configure Asterisk

This configuration has two endpoints, a caller and a callee. It also has a
dialplan. The dialplan connects a call to extension `100` from the caller to
the callee. Your own configuration does much more (phones that register with a
password, voicemail, carriers).

```bash
# Run all of these, in order.
printf '[options]\n' | sudo tee /etc/asterisk/asterisk.conf >/dev/null
sudo tee /etc/asterisk/modules.conf >/dev/null <<'EOF'
[modules]
autoload = yes
EOF
sudo tee /etc/asterisk/logger.conf >/dev/null <<'EOF'
[logfiles]
messages.log => notice,warning,error
EOF
sudo tee /etc/asterisk/rtp.conf >/dev/null <<'EOF'
[general]
rtpstart = 10000
rtpend = 20000
EOF
sudo tee /etc/asterisk/pjsip.conf >/dev/null <<'EOF'
[transport-udp]
type = transport
protocol = udp
bind = 0.0.0.0:5060

[caller]
type = endpoint
context = from-caller
disallow = all
allow = alaw,ulaw
direct_media = no

[caller-ip]
type = identify
endpoint = caller
match = 192.0.2.10

[callee]
type = endpoint
context = from-callee
disallow = all
allow = ulaw
direct_media = no
dtmf_mode = auto
aors = callee

[callee]
type = aor
contact = sip:192.0.2.10:5070
EOF
sudo tee /etc/asterisk/extensions.conf >/dev/null <<'EOF'
[from-caller]
exten => 100,1,Dial(PJSIP/callee,30)
 same => n,Hangup()
EOF
sudo systemctl restart asterisk
until sudo asterisk -rx 'core waitfullybooted' 2>/dev/null; do sleep 1; done
sudo asterisk -rx 'pjsip show endpoints'
```

What the files do:

- `asterisk.conf` is the first file Asterisk reads.
  - An empty `[options]` section keeps Asterisk's built-in settings.
  - Without the file, every `asterisk -rx` command prints `Unable to open
    specified master config file`.
- `modules.conf` loads every module the build installed.
  - Some modules decline to load without a configuration file of their own.
  - Each of them logs a line such as `app_queue declined to load.` to
    `/var/log/asterisk/messages.log`.
- `logger.conf` writes notices, warnings and errors to
  `/var/log/asterisk/messages.log`.
- `rtp.conf` sets the UDP ports Asterisk takes for each call's audio.
- `pjsip.conf` sets up SIP:
  - The `transport` listens on UDP port 5060 on every address.
  - An `endpoint` is a phone or a carrier Asterisk talks to.
    - `context` names the dialplan section that handles calls from it.
  - The `identify` section tells Asterisk that requests from `192.0.2.10` come
    from the `caller` endpoint.
    - Requests from any other address get `401
      Unauthorized`.
  - `allow` lists the codecs each end may use.
    - The caller sends G.711 A-law (`alaw`, called PCMA in SDP).
    - The callee takes only G.711 u-law (`ulaw`, PCMU).
    - So Asterisk converts the audio between the two codecs.
  - `direct_media = no` keeps the audio flowing through Asterisk.
    - The sample configuration that ships with Asterisk describes the setting
      as `Determines whether media may flow directly between endpoints`.
    - Its default is `yes`.
  - `dtmf_mode = auto` sets how Asterisk passes key presses (DTMF) to the
    callee.
    - Asterisk's own description of `auto` is `DTMF is sent as RFC 4733
      if the other side supports it or as INBAND if not`.
    - That means as [RFC 4733](https://www.rfc-editor.org/rfc/rfc4733.html) event packets, or as tones inside the audio.
    - This test callee supports no events.
    - With the default, `rfc4733`, Asterisk sent the test caller's key press
      to this callee as events anyway.
    - The echoing callee returned them. The two then exchanged more than
      6,000 event packets each way within 0.15 seconds.
  - The `aor` (address of record) gives the address Asterisk calls the
    callee at.
- `extensions.conf` is the dialplan.
  - A call from the caller to `100` rings the callee for up to 30 seconds.
  - It hangs up when either side does.

systemd counts Asterisk as started as soon as the process runs. That is before
Asterisk has opened its control socket. So an `asterisk -rx` straight after a
restart can fail.

- The `until` line waits until `core waitfullybooted` answers
  `Asterisk has fully booted.`.
- `pjsip show endpoints` then lists both endpoints:
  - `caller` with `Match: 192.0.2.10/32`,
  - `callee` with its contact `sip:192.0.2.10:5070`.

## Place a test call

SIPp plays both ends:

- a callee on this machine at port 5070 that echoes audio back,
- a caller that dials extension `100` and plays a recorded G.711 sample.

So the call carries real audio both ways. Both SIPp ends write the same SDP
origin line (`o=user1 53655765 2353687637`) by default. The `sed` line gives
the callee its own, as two separate phones would have:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester
mkdir -p ~/sipp/pcap && cd ~/sipp
ln -sf /usr/share/sip-tester/*.pcap pcap/
sipp -sd uas > uas.xml
sed -i 's/o=user1 53655765 2353687637/o=callee 1 1/' uas.xml
sipp -sf uas.xml -i 192.0.2.10 -p 5070 -min_rtp_port 7000 -max_rtp_port 7100 -rtp_echo -m 1 -bg
sudo sipp -sn uac_pcap 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s 100 -m 1 -timeout 90s
```

- The callee takes its audio ports from 7000-7100. That way it does not
  collide with the caller's port 6000 on the same address.
- The caller needs `sudo` because it plays the audio sample through a raw
  socket.
- The caller sends about 7 seconds of audio, then a short DTMF clip, and hangs
  up.
- At the end SIPp's statistics screen shows `Successful call` at 1.

Unlike a proxy, Asterisk carries the audio as well as the signaling.

- The caller sends its audio to Asterisk, at the port Asterisk's answer names.
- Asterisk sends it on to the callee from a second port, converted to PCMU.
- The callee's echo comes back the same way.

[Run sipnab beside Asterisk](asterisk-sipnab.md) shows both legs and all of
their audio.

## Operate it

**See what Asterisk has handled.**

- `asterisk -rx` runs one command in the running Asterisk.
- It needs `sudo`, because the control socket belongs to the `asterisk` user.
- `core show calls` prints the calls in progress.
  - It prints `0 active
    calls` once the test call has ended.
  - It also prints a `calls processed` count.
- `pjsip show endpoints` lists the endpoints again:

```bash
# Run all of these, in order.
sudo asterisk -rx 'core show calls'
sudo asterisk -rx 'pjsip show endpoints'
```

**Check health and read the logs.**

```bash
# Run all of these, in order.
systemctl is-active asterisk
sudo asterisk -rx 'core show uptime'
sudo tail -n 20 /var/log/asterisk/messages.log
```

**Apply a configuration change.** `core reload` makes Asterisk reread its
configuration files. `pjsip.conf` and `extensions.conf` are among them:

```bash
sudo asterisk -rx 'core reload'
```

A configuration file that did not exist when Asterisk started can need a
restart instead.

- [Run sipnab beside Asterisk](asterisk-sipnab.md) has you create a
  `hep.conf`.
- After you create it, `core reload` leaves the modules that read it
  `Not Running`.
- A restart starts them:

```bash
# Run all of these, in order.
sudo systemctl restart asterisk
systemctl is-active asterisk
```

**Uninstall.** `make uninstall-all` removes:

- the program,
- its modules,
- the configuration, logs and data under `/etc/asterisk`, `/var/log/asterisk`,
  `/var/lib/asterisk` and `/var/spool/asterisk`.

```bash
# Run all of these, in order.
sudo systemctl disable --now asterisk
cd /usr/local/src/voice/asterisk-22.11.0
sudo make uninstall-all
sudo rmdir /usr/lib/asterisk
sudo rm /etc/systemd/system/asterisk.service
sudo systemctl daemon-reload
sudo userdel asterisk
cd /usr/local/src/voice && rm -rf asterisk-22.11.0 asterisk-22.11.0.tar.gz
```

`make uninstall-all` leaves the empty `/usr/lib/asterisk` directory behind.
`rmdir` removes it.

## When something does not work

- **`apt-get` says `Could not get lock /var/lib/dpkg/lock-frontend. It is held
  by process ...`.**
  - Another package tool holds the lock.
  - On a machine that has just booted, it is usually the system's own
    scheduled update.
  - Wait for it to finish, then run the block again.
- **`asterisk -rx` says `Unable to connect to remote asterisk (does
  /var/run/asterisk/asterisk.ctl exist?)`.** One of these is true:
  - Asterisk is not running.
  - It has not finished starting.
  - You ran the command without `sudo`.
    - On Debian 13, `/usr/sbin` is not in an ordinary user's `PATH`.
    - There the command without `sudo` answers `asterisk: command not found`
      instead.
- **`asterisk -rx 'pjsip reload'` says `No such command 'pjsip reload'`.** Use
  `core reload`, which rereads `pjsip.conf` with the rest.
- **The caller gets `404 Not Found`.**
  - The dialplan has no such extension.
  - `messages.log` names it: `Call (UDP:192.0.2.10:5080) to extension '999'
    rejected because extension not found in context 'from-caller'.`
- **The caller gets `401 Unauthorized`.**
  - Asterisk matched the request to no endpoint.
  - `messages.log` says `No matching endpoint found`. It names the address the
    request came from.
  - Add that address to the `identify` section's `match`.
- **The caller gets `603 Decline`.**
  - Asterisk could not reach the callee at the `aor`'s `contact`.
  - Check that the callee runs and listens there.
