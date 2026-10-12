# Use FreeSWITCH in your voice stack

[FreeSWITCH](https://signalwire.com/freeswitch) is an open-source softswitch:
it answers calls, bridges them, plays and records audio, and runs
conferences and voicemail. It works as a back-to-back user agent (B2BUA). A
proxy such as OpenSIPS or Kamailio passes the caller's request on to the
callee. A B2BUA instead answers the caller's call itself and places a second,
separate call to the callee, with its own Call-ID, and it carries the audio of
both calls through itself. One call through FreeSWITCH is therefore two SIP
dialogs, one per leg, and its audio is four streams: caller to FreeSWITCH,
FreeSWITCH to caller, and the same pair on the callee's side.

This guide builds FreeSWITCH from source, sets it up to bridge a test call to
a callee on the same machine, and proves it with a call that carries audio.
This guide does not use sipnab. When you have this working, [Run sipnab beside
FreeSWITCH](freeswitch-sipnab.md) adds sipnab.

## Tested on

Every block on this page ran as written, in order, on 2026-10-12, on clean
x86_64 virtual machines with 2 cores and 3 GB of memory, Debian 13 (kernel
6.12.63) and Ubuntu 24.04 (kernel 6.8.0). On each, the build ran on a machine
with nothing installed, [Run sipnab beside FreeSWITCH](freeswitch-sipnab.md)
ran between step 4's operate blocks and the uninstall, and the uninstall ran
last. Every test call carried audio both ways on both legs, counted on the
wire, and causing each fault under [When something does not
work](#when-something-does-not-work) produced the message it quotes, on both.

| Software | Version |
|---|---|
| FreeSWITCH | 1.11.3, the current release, built from the release archive on `files.freeswitch.org` |
| sofia-sip (FreeSWITCH's SIP stack) | 1.13.18, built from the `v1.13.18` tag of `github.com/freeswitch/sofia-sip` |
| spandsp (FreeSWITCH's signal-processing library) | 3.1.1, built from the `v3.1.1` tag of `github.com/freeswitch/spandsp` |
| SIPp (for the test call) | the distribution's `sip-tester`: 3.7.3 on Debian 13, 3.7.2 on Ubuntu 24.04 |

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## 1. Install FreeSWITCH

### What each distribution offers

FreeSWITCH's own packages come from SignalWire's package repository, which
answers only with a SignalWire account's access token. Neither distribution
carries a `freeswitch` package, and the versions of sofia-sip and spandsp they
carry are older than FreeSWITCH 1.11.3 accepts: it needs sofia-sip 1.13.18 or
later and spandsp 3.1.1 or later. This block shows all three on your machine:

```bash
# Run all of these, in order.
sudo apt-get update
sudo apt-get install -y ca-certificates curl
apt-cache policy freeswitch libsofia-sip-ua-dev libspandsp-dev
. /etc/os-release
curl -s -o /dev/null -w '%{http_code}\n' "https://freeswitch.signalwire.com/repo/deb/debian-release/dists/$VERSION_CODENAME/Release"
```

`apt-cache policy` prints nothing for `freeswitch`, and a `Candidate` of
1.12.11 for `libsofia-sip-ua-dev` and 0.0.6 for `libspandsp-dev`. The last
line prints `401`, the HTTP status for a request that needs credentials.

| | Debian 13 | Ubuntu 24.04 |
|---|---|---|
| A `freeswitch` package from the distribution | none | none |
| SignalWire's FreeSWITCH packages | need a SignalWire access token | need a SignalWire access token |
| Build from source, as below | no account needed | no account needed |

This guide builds from source, which needs no account, and the same steps
work on both distributions. The build installs everything under
`/usr/local/freeswitch`, apart from sofia-sip and spandsp, which go under
`/usr/local`.

### Build sofia-sip and spandsp

First the compiler, the build tools, and the libraries FreeSWITCH's core and
its default modules use:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends git build-essential automake autoconf libtool libtool-bin pkg-config xz-utils \
  libssl-dev zlib1g-dev libjpeg-dev libtiff-dev libsqlite3-dev libcurl4-openssl-dev libpcre2-dev \
  libspeex-dev libspeexdsp-dev libldns-dev libedit-dev uuid-dev libopus-dev libsndfile1-dev liblua5.4-dev yasm nasm
```

Then the two libraries, from the FreeSWITCH project's own repositories, at the
versions FreeSWITCH 1.11.3 asks for:

```bash
# Run all of these, in order.
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
git -c advice.detachedHead=false clone --depth 1 -b v1.13.18 https://github.com/freeswitch/sofia-sip.git
git -c advice.detachedHead=false clone --depth 1 -b v3.1.1 https://github.com/freeswitch/spandsp.git
for d in sofia-sip spandsp; do (cd "$d" && ./bootstrap.sh && ./configure && make -j2 && sudo make install); done
sudo ldconfig
pkg-config --modversion sofia-sip-ua spandsp
```

The last line prints `1.13.18` and `3.1.1`.

### Build FreeSWITCH

`modules.conf` lists the modules the build compiles. Four of the default ones
need libraries this guide does not install: `mod_signalwire` and `mod_verto`
need SignalWire's `libks`, `mod_av` needs the FFmpeg development libraries,
and `mod_pgsql` the PostgreSQL client library. The `sed` line leaves those
four out:

```bash
# Run all of these, in order.
cd /usr/local/src/voice
curl -fsSLO https://files.freeswitch.org/releases/freeswitch/freeswitch-1.11.3.-release.tar.xz
curl -fsSL https://files.freeswitch.org/releases/freeswitch/freeswitch-1.11.3.-release.tar.xz.sha256 | sha256sum -c -
tar xf freeswitch-1.11.3.-release.tar.xz
cd freeswitch-1.11.3.-release
sed -i -E 's#^(applications/mod_av|applications/mod_signalwire|endpoints/mod_verto|databases/mod_pgsql)$#\#\1#' modules.conf
./configure
make -j2
sudo make install
sudo ln -sf /usr/local/freeswitch/bin/freeswitch /usr/local/freeswitch/bin/fs_cli /usr/local/bin/
freeswitch -version
```

`sha256sum -c` prints `freeswitch-1.11.3.-release.tar.xz: OK`. The checksum
comes from the same server as the archive, so it detects a damaged download,
not a changed one. The last line prints `FreeSWITCH version:
1.11.3-release~64bit (-release 64bit)`.

The release archive's name has a dot before `-release`. That is the name on the
server.

### Run it as a service

FreeSWITCH runs as its own user. This unit is the one in the FreeSWITCH
source tree, `debian/freeswitch-systemd.freeswitch.service`, with the paths
of this build. FreeSWITCH starts as root, raises its own scheduling priority,
then drops to the `freeswitch` user. `-ncwait` makes `systemctl start` wait
until FreeSWITCH is ready to take commands:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /usr/local/freeswitch --shell /usr/sbin/nologin freeswitch
sudo chown -R freeswitch:freeswitch /usr/local/freeswitch
sudo tee /etc/systemd/system/freeswitch.service >/dev/null <<'EOF'
[Unit]
Description=FreeSWITCH
Wants=network-online.target
After=network-online.target

[Service]
Type=forking
PIDFile=/usr/local/freeswitch/run/freeswitch.pid
ExecStart=/usr/local/freeswitch/bin/freeswitch -u freeswitch -g freeswitch -ncwait -nonat
TimeoutSec=45s
Restart=always
LimitCORE=infinity
LimitNOFILE=100000
LimitNPROC=60000
LimitSTACK=250000
LimitRTPRIO=infinity
LimitRTTIME=infinity
IOSchedulingClass=realtime
IOSchedulingPriority=2
CPUSchedulingPolicy=rr
CPUSchedulingPriority=89
UMask=0007

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable freeswitch
```

`-nonat` stops FreeSWITCH from asking the local router to forward ports to it
(UPnP and NAT-PMP).

## 2. Configure FreeSWITCH

`make install` put FreeSWITCH's example configuration, which the FreeSWITCH
project calls "vanilla", in `/usr/local/freeswitch/conf`. It runs two SIP
profiles, each a SIP listener with its own settings:

- `internal`, on port 5060, for your own phones. It asks every caller for a
  user name and password.
- `external`, on port 5080, for carriers and other servers. It asks for no
  password, and sends each call to the dialplan's `public` context.

The test call in step 3 goes to `external`. This block changes five things:

```bash
# Run all of these, in order.
cd /usr/local/freeswitch/conf
sudo sed -i 's|=stun:stun.freeswitch.org"|=192.0.2.10"|' vars.xml
P=$(od -An -tx1 -N12 /dev/urandom | tr -d ' \n')
sudo sed -i "s|data=\"default_password=1234\"|data=\"default_password=$P\"|" vars.xml
sudo sed -i 's|<param name="listen-ip" value="::"/>|<param name="listen-ip" value="127.0.0.1"/>|' autoload_configs/event_socket.conf.xml
sudo sed -i -E 's#^( *)(<load module="mod_(verto|signalwire|av)"/>)#\1<!-- \2 -->#' autoload_configs/modules.conf.xml
sudo tee dialplan/public/01_echo.xml >/dev/null <<'EOF'
<include>
  <!-- A call to "echo" goes to the test callee on this machine, in PCMU. -->
  <extension name="test_callee">
    <condition field="destination_number" expression="^echo$">
      <action application="bridge" data="{absolute_codec_string=PCMU}sofia/external/echo@127.0.0.1:5070"/>
    </condition>
  </extension>
</include>
EOF
sudo chown -R freeswitch:freeswitch /usr/local/freeswitch/conf
grep 'stun-set' vars.xml
sudo systemctl restart freeswitch
fs_cli -x 'sofia status'
```

What the changes do:

- **The machine's address.** `external_rtp_ip` and `external_sip_ip` are the
  addresses FreeSWITCH puts in its SIP and SDP for the `external` profile. The
  example configuration asks the public STUN server `stun.freeswitch.org` for
  them at startup, which gives the address of your internet connection, not
  of this machine. With that default, the `Contact` header of FreeSWITCH's
  replies to the test call named the public address. On a machine with its own
  public address, put that address here.
- **The SIP password.** `default_password` is the password of the 20 example
  users, `1000` to `1019`, that the `internal` profile accepts. The example
  configuration sets it to `1234`. The block replaces it with a random one.
- **The event socket.** `fs_cli`, FreeSWITCH's command-line client, talks to
  FreeSWITCH over its event socket, TCP port 8021, with the password `ClueCon`.
  The example configuration listens on every address. The block moves it to
  `127.0.0.1`, so only this machine reaches it.
- **Modules the build left out.** The example configuration loads `mod_verto`,
  `mod_signalwire` and `mod_av`, which step 1 did not build. Without this
  line, FreeSWITCH logs `Error Loading module` for each at every start.
- **Where the test call goes.** The dialplan is FreeSWITCH's routing:
  FreeSWITCH bridges a call to `echo` in the `public` context to a test callee
  on this machine, `127.0.0.1:5070`. `absolute_codec_string=PCMU` makes FreeSWITCH
  offer the callee PCMU only, the one codec SIPp's callee answers with.

`sofia status` lists the profiles. `internal` shows
`sip:mod_sofia@192.0.2.10:5060` and `external` shows
`sip:mod_sofia@192.0.2.10:5080`, both `RUNNING`.

## 3. Place a test call

SIPp plays both ends: a callee on this machine that echoes audio back, and a
caller that calls `echo` on FreeSWITCH's `external` profile and plays a
recorded G.711 sample, so the call carries real audio both ways. The caller
uses port 5090, because FreeSWITCH holds 5060 and 5080:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester jq
mkdir -p ~/sipp/pcap && cd ~/sipp
ln -sf /usr/share/sip-tester/*.pcap pcap/
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sn uac_pcap 192.0.2.10:5080 -i 192.0.2.10 -p 5090 -s echo -m 1 -timeout 90s
```

The caller needs `sudo` because it plays the audio sample through a raw socket.
It sends about 7 seconds of audio, then a short DTMF clip, and hangs up. At the
end SIPp's statistics screen shows `Successful call` at 1.

SIPp's built-in caller sends its `ACK` and `BYE` straight to FreeSWITCH, which
is the far end of the caller's dialog. Unlike the proxy guides, this guide
needs no edited scenario.

Each leg has its own audio. The caller offers PCMA, and FreeSWITCH answers it
in PCMA. On the callee's leg FreeSWITCH offers PCMU, and converts the audio
between the two codecs. [Run sipnab beside
FreeSWITCH](freeswitch-sipnab.md) shows all four streams.

## 4. Operate it

**See a call's two legs while it is up.** FreeSWITCH calls each leg a
channel. Start a call in the background and list the channels:

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sn uac_pcap 192.0.2.10:5080 -i 192.0.2.10 -p 5090 -s echo -m 1 -timeout 90s -bg
sleep 3
fs_cli -x 'show channels as json' | jq -r '.rows[] | "\(.direction) \(.name) \(.read_codec)"'
sleep 12
```

```text
inbound sofia/external/sipp@192.0.2.10:5090 PCMA
outbound sofia/external/echo@127.0.0.1:5070 PCMU
```

The `inbound` channel is the caller's leg, in PCMA, and the `outbound` one the
callee's, in PCMU. The last line waits for the call to end.

**Check health and read the logs.**

```bash
# Run all of these, in order.
systemctl is-active freeswitch
fs_cli -x status
sudo tail -n 30 /usr/local/freeswitch/log/freeswitch.log
```

`fs_cli -x status` prints FreeSWITCH's version, its uptime and the number of
sessions since it started. FreeSWITCH writes its log to
`/usr/local/freeswitch/log/freeswitch.log`, not to the journal.

**Apply a configuration change.** A change to the dialplan or the users
takes effect with `reloadxml`. A change to `vars.xml` or a SIP profile needs a
restart:

```bash
# Run all of these, in order.
fs_cli -x reloadxml
sudo systemctl restart freeswitch
fs_cli -x status | head -2
```

`reloadxml` prints `+OK [Success]`.

**Uninstall.** Remove FreeSWITCH, its user, and the two libraries:

```bash
# Run all of these, in order.
sudo systemctl disable --now freeswitch
sudo rm -rf /usr/local/freeswitch /etc/systemd/system/freeswitch.service /usr/local/bin/freeswitch /usr/local/bin/fs_cli
sudo systemctl daemon-reload
sudo userdel freeswitch
sudo make -C /usr/local/src/voice/sofia-sip uninstall
sudo make -C /usr/local/src/voice/spandsp uninstall
sudo rm -rf /usr/local/include/sofia-sip-1.13 /usr/local/include/spandsp /usr/local/share/sofia-sip
sudo ldconfig
rm -rf /usr/local/src/voice/sofia-sip /usr/local/src/voice/spandsp /usr/local/src/voice/freeswitch-1.11.3.-release*
```

## When something does not work

- **The test call fails, and SIPp reports `Aborting call on unexpected message
  ... received 'SIP/2.0 488 Not Acceptable Here`.** The callee answered with
  a codec FreeSWITCH had not offered it. Without `absolute_codec_string`,
  FreeSWITCH offers the callee the caller's codec, PCMA, and SIPp's callee
  answers PCMU whatever FreeSWITCH offers. FreeSWITCH's log shows `Originate
  Failed.  Cause: INCOMPATIBLE_DESTINATION`. Keep `{absolute_codec_string=PCMU}`
  in the `bridge` line, or offer your callee a codec it supports.
- **`fs_cli` prints `[ERROR] fs_cli.c:1699 main() Error Connecting []`.**
  Nothing answers on the event socket: FreeSWITCH is not running, or its
  `listen-ip` is not the address `fs_cli` connects to, `127.0.0.1`. Check
  `systemctl status freeswitch`.
