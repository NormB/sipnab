# Add rtpproxy to your voice stack

A SIP proxy such as OpenSIPS carries the signaling of a call, and by default
the audio flows directly between the two phones. A media relay puts itself in
that path: the proxy rewrites each call's SDP so that both phones send their
audio to the relay, and the relay forwards it. That fixes one-way audio behind
NAT, hides your customers' addresses from each other, and gives you one place
where you can measure or record every call's media.

[rtpproxy](https://github.com/sippy/rtpproxy) is the other media relay that
OpenSIPS and Kamailio both support, beside
[rtpengine](rtpengine-relay.md). This guide installs it, has OpenSIPS anchor
every call's media on it, and proves that with a test call. With Kamailio
instead, [one section](#with-kamailio) replaces the OpenSIPS steps. This guide
does not use sipnab. When you have this working,
[Let sipnab name rtpproxy's media](rtpproxy-sipnab.md) adds sipnab beside it.

The parts, and what each one does:

| Part | Role |
|---|---|
| **OpenSIPS** | Your SIP proxy. Its `rtpproxy` module asks rtpproxy for a relay port for each call and rewrites the SDP to point at it. |
| **rtpproxy** | Relays each call's media. OpenSIPS controls it over rtpproxy's text control protocol, on a UDP port that only OpenSIPS should reach. |
| **SIPp** | Plays a caller and a callee, for the test call. |

Everything below runs on one machine, which keeps the example short. The
[Put rtpproxy on its own machine](#put-rtpproxy-on-its-own-machine) section
says what changes when rtpproxy has a machine to itself.

## Tested on

Every block on this page ran as written, in order, on 2026-10-01, on clean
x86_64 virtual machines with 2 cores and 3 GB of memory, Debian 13 (kernel
6.12.63) and Ubuntu 24.04.5 (kernel 6.8.0). On each, it ran:

- With OpenSIPS built from source on a machine with nothing installed, then
  with rtpengine built beside it, as
  [rtpengine and rtpproxy on one machine](#rtpengine-and-rtpproxy-on-one-machine)
  describes.
- With the OpenSIPS 4.0 packages, then [With Kamailio](#with-kamailio) on port
  5062 beside OpenSIPS on one machine. Kamailio alone, on 5060, was not run.
- [On its own machine](#put-rtpproxy-on-its-own-machine), on two machines.

On one machine, each route's acceptance check also placed a call through the
proxy and read rtpproxy's own counters: one more session, the call's packets
relayed, and no session left once the `BYE` passed. On both systems, causing each fault under
[When something does not work](#when-something-does-not-work) produced what it
describes. arm64 was not tested. The commands pin the components to the
versions below. Newer ones may behave differently, and pinning them keeps the
guide describing what you get.

| Software | Version or commit |
|---|---|
| rtpproxy | 3.2.0, the project's own package for each distribution, from [its 3.2.0 release](https://github.com/sippy/rtpproxy/releases/tag/v3.2.0) ([`b26b09b324`](https://github.com/sippy/rtpproxy/commit/b26b09b324)) |
| OpenSIPS, built here | [`f46ef9337b`](https://github.com/OpenSIPS/opensips/commit/f46ef9337b), master, 4.1.0-dev |
| OpenSIPS, from packages | 4.0.2, installed as [the OpenSIPS guide](opensips.md) installs it |
| Kamailio | 6.1.4, installed as [the Kamailio guide](kamailio.md) installs it |
| SIPp (for the test call) | the distribution's `sip-tester`: 3.7.3 on Debian, 3.7.2 on Ubuntu |

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## Before you start: your SIP server

Find your case, and follow the steps it names:

- **No SIP server yet.** Follow every step. Step 3 builds OpenSIPS for you. If
  you would rather run the OpenSIPS 4.0 packages, install them with
  [step 1 of the OpenSIPS guide](opensips.md#1-install-opensips) and skip step
  3 here.
- **OpenSIPS already runs, from the packages or built from source.** Skip step
  3. The `rtpproxy` and `dialog` modules come with the `opensips` package and
  with the default build, so there is nothing to add. Step 4 finds your
  configuration file and replaces it. On a machine whose script you want to
  keep, add the lines step 4 marks to your own script instead.
- **Kamailio already runs, or you want Kamailio.** Follow steps 1 and 2, then
  [With Kamailio](#with-kamailio) in place of steps 3 and 4, then steps 5 and
  6.
- **Both OpenSIPS and Kamailio on one machine.** Set up OpenSIPS as above, then
  see [With Kamailio](#with-kamailio), which covers both.
- **rtpengine already runs on this machine.** Follow every step, then see
  [rtpengine and rtpproxy on one machine](#rtpengine-and-rtpproxy-on-one-machine).

## 1. Install rtpproxy

Neither Debian 13 nor Ubuntu 24.04 carries rtpproxy. The rtpproxy project
publishes its own packages with each release, one zip file per distribution.
The release lists no checksums file, so the block checks the zip against the
SHA-256 digest GitHub shows for it on the
[release page](https://github.com/sippy/rtpproxy/releases/tag/v3.2.0), then
installs the `rtpproxy` package from it:

```bash
# Run all of these, in order.
sudo apt-get update
sudo apt-get install -y curl unzip
. /etc/os-release
Z=${ID}-${VERSION_ID}_packages.zip
curl -fsSLO https://github.com/sippy/rtpproxy/releases/download/v3.2.0/$Z
grep " $Z\$" <<'EOF' | sha256sum -c -
97bfd14ffc47633c1d6fe807241f0989518189eb69fae2c4100188a018e226a5  debian-13_packages.zip
d70f0da2a42c13b63ebb6189b6dd51549d4bd2c05fff5b9c168355967370c371  ubuntu-24.04_packages.zip
EOF
unzip -o $Z rtpproxy_3.2.0+dev_amd64.deb
sudo apt-get install -y ./rtpproxy_3.2.0+dev_amd64.deb
rtpproxy -V
```

`sha256sum` prints `OK` for the zip, and `rtpproxy -V` prints the release
followed by the package's build time, `3.2.0.` and a timestamp. The zip
also holds packages this guide does not need: debugging symbols, a debug build
and a static library with its header.

The package creates an `rtpproxy` user, a systemd service that runs rtpproxy
as that user, and the file the service reads its options from,
`/etc/sysconfig/rtpproxy`. It starts rtpproxy straight away, on its default
options.

## 2. Tell rtpproxy where to listen

rtpproxy takes all its settings from its command line. The service adds the
`OPTIONS` line of `/etc/sysconfig/rtpproxy` to that command line. Replace the
file, and restart rtpproxy:

```bash
# Run all of these, in order.
sudo tee /etc/sysconfig/rtpproxy >/dev/null <<'EOF'
# rtpproxy's command line, added by rtpproxy.service. See rtpproxy(8).
OPTIONS="-s udp:127.0.0.1:7722 -l 192.0.2.10 -m 50000 -M 59999 -d INFO"
EOF
sudo systemctl restart rtpproxy
systemctl is-active rtpproxy
sudo ss -lnp | grep rtpproxy
```

`ss` shows the two sockets rtpproxy holds open between calls: the UNIX socket
`/run/rtpproxy.sock`, which the package's `rtpproxy.socket` unit opens, and the
UDP socket `127.0.0.1:7722`. Both take commands. rtpproxy opens its media
ports only for a call, and closes them when the call ends.

What each option does:

- `-s udp:127.0.0.1:7722` adds a UDP control socket, where OpenSIPS sends its
  commands. This guide uses UDP, the way the rtpengine guide does, because
  [Let sipnab name rtpproxy's media](rtpproxy-sipnab.md) reads the commands off
  the network, and a relay on
  [its own machine](#put-rtpproxy-on-its-own-machine) needs a network address
  anyway. It listens on the loopback address, so nothing outside the machine
  can reach it. Keep it that way: rtpproxy's control protocol has no
  authentication, and anyone who can reach the port can create and tear down
  relay sessions. The UNIX socket is open to every user on the machine (mode
  `srw-rw-rw-`), so treat a local account as able to do the same.
- `-l 192.0.2.10` is the address rtpproxy relays media on. rtpproxy returns it
  with each port it allocates, and OpenSIPS writes it into the SDP.
- `-m 50000` and `-M 59999` bound the media ports. rtpproxy's defaults are
  35000-65000, which overlap the range the rtpengine guide uses, 30000-39999,
  and the vCon recorder's, 40000-40999. 50000-59999 is clear of both.
- `-d INFO` logs each session rtpproxy creates and each one it deletes, with
  the call's packet counts, to the journal.

## 3. Build OpenSIPS

Skip this step if OpenSIPS is already installed, from the packages or from
source.

OpenSIPS master builds with compiler optimizations turned off, which is right
for OpenSIPS's own developers and wrong for a proxy carrying calls. Turn them
back on before you build. The `rtpproxy` module is part of the default build:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends git ca-certificates build-essential bison flex uuid-dev pkg-config libncurses-dev libssl-dev
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
git clone https://github.com/OpenSIPS/opensips.git
cd opensips
git checkout f46ef9337b
make Makefile.conf
sed -i 's/^DEFS+= -DCC_O0/#DEFS+= -DCC_O0/' Makefile.conf
make -j2 all
sudo make install
/usr/local/sbin/opensips -V | head -2
```

The second line of `opensips -V` lists the build flags. `CC_O0` is no longer
among them.

Leave `DBG_MALLOC` as it is. With both it and `CC_O0` switched off, this commit
of master does not compile: `net/tcp_conn_defs.h` calls `get_ticks()` without
including the header that declares it, and only `DBG_MALLOC`'s headers happen
to supply it.

## 4. Configure OpenSIPS to anchor every call on rtpproxy

This configuration is a minimal proxy with the relay added. Your own script
does much more (registration, authentication, routing to carriers). The relay
part is the block marked below, and the `loadmodule` lines it needs.

### Write the configuration

The packages and the source build keep their configuration and their modules in
different places. The first two lines find them: `C` is your configuration
file, and `M` the directory your install loads modules from, which the script's
`mpath` names.

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
for d in /usr/lib/*/opensips/modules /usr/local/lib64/opensips/modules; do [ -f "$d/tm.so" ] && M=$d && break; done
echo "configuration: $C   modules: $M"
sudo tee "$C" >/dev/null <<'EOF'
# OpenSIPS as a SIP proxy that anchors every call's media on rtpproxy.
log_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2
open_files_limit=4096

socket=udp:192.0.2.10:5060   # the address your phones and carriers reach

mpath="MODULES/"

loadmodule "proto_udp.so"   # built into the core, but still loaded by name
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo")

# The relay: rtpproxy_engage() follows the call through the dialog module.
loadmodule "dialog.so"
loadmodule "rtpproxy.so"
modparam("rtpproxy", "rtpproxy_sock", "udp:127.0.0.1:7722")

route {
	if (!mf_process_maxfwd_header(10)) {
		send_reply(483, "Too Many Hops");
		exit;
	}

	if (has_totag()) {
		if (is_method("ACK") && t_check_trans()) {
			t_relay();
			exit;
		}
		if (!loose_route()) {
			send_reply(404, "Not here");
			exit;
		}
		t_relay();
		exit;
	}

	if (is_method("CANCEL")) {
		if (t_check_trans())
			t_relay();
		exit;
	}
	t_check_trans();

	if (!is_method("INVITE")) {
		send_reply(405, "Method Not Allowed");
		exit;
	}

	record_route();

	# --- the relay starts here ---
	create_dialog();
	rtpproxy_engage();
	# --- the relay ends here ---

	# Where the call goes. Here, a test callee on this machine; in your
	# stack, lookup("location"), dispatcher or a carrier.
	$du = "sip:127.0.0.1:5070";
	t_relay();
}
EOF
sudo sed -i "s|^mpath=\"MODULES/\"|mpath=\"$M/\"|" "$C"
sudo grep '^mpath=' "$C"
```

What the relay block does:

- `create_dialog()` makes OpenSIPS track the call, so that it knows when the
  call ends and can release the relay ports with it.
- `rtpproxy_engage()` hands the call to rtpproxy for its whole life. OpenSIPS
  asks rtpproxy for a port for the caller's SDP and forwards the rewritten SDP
  to the callee, does the same for the callee's answer, and tells rtpproxy to
  delete the session when the call ends.

The rtpengine guide uses `rtp_relay_engage("rtpengine")` instead, the
`rtp_relay` module's way to drive any relay. Do not use
`rtp_relay_engage("rtpproxy")` for rtpproxy. With it, OpenSIPS sends its
delete at the end of the call without the caller's tag, rtpproxy does not find
the session, and the call's ports stay open until rtpproxy's own timeout
frees them, 60 seconds after the media stops.
[When something does not work](#when-something-does-not-work) shows what that
looks like.

### If you built OpenSIPS in step 3: give it a user and a unit

The packages come with an `opensips` user and a systemd unit. If you
installed them, or if your source build already runs as a service, skip to
[Check the configuration and start OpenSIPS](#check-the-configuration-and-start-opensips).
A fresh build has neither. Run OpenSIPS as its own user, under systemd:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /run/opensips --shell /usr/sbin/nologin opensips
sudo chown root:opensips /usr/local/etc/opensips
sudo chmod 750 /usr/local/etc/opensips
sudo tee /etc/systemd/system/opensips.service >/dev/null <<'EOF'
[Unit]
Description=OpenSIPS SIP server
After=network.target rtpproxy.service

[Service]
Type=forking
User=opensips
Group=opensips
RuntimeDirectory=opensips
RuntimeDirectoryMode=775
PIDFile=/run/opensips/opensips.pid
ExecStart=/usr/local/sbin/opensips -P /run/opensips/opensips.pid -f /usr/local/etc/opensips/opensips.cfg -m 64 -M 8
Restart=always
TimeoutStopSec=30s
LimitNOFILE=262144

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
```

### Check the configuration and start OpenSIPS

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
sudo chown root:opensips "$C"
sudo chmod 640 "$C"
sudo opensips -C -f "$C"
sudo systemctl enable opensips
sudo systemctl restart opensips
systemctl is-active opensips
```

`opensips -C` checks the configuration and prints `config file ok` before you
start anything. `sudo opensips` finds the packaged binary in `/usr/sbin` and
the built one in `/usr/local/sbin`.

## 5. Place a test call

SIPp plays both ends: a callee that echoes audio back, and a caller that dials
through OpenSIPS and plays a recorded G.711 sample. SIPp's built-in caller
ignores the `Record-Route` header OpenSIPS adds, so its `BYE` would miss the
proxy and draw `404 Not here`. The two route `sed` lines make it honor the
route set, the way a real phone does. The callee writes every message it
receives to `uas.msg`, so that you can read the SDP OpenSIPS handed it:

```bash
# Run all of these, in order.
sudo apt-get install -y sip-tester
mkdir -p ~/sipp/pcap && cd ~/sipp
ln -sf /usr/share/sip-tester/*.pcap pcap/
sipp -sd uac_pcap > uac_rr.xml
sed -i 's|<recv response="200" rtd="true" crlf="true">|<recv response="200" rtd="true" crlf="true" rrs="true">|' uac_rr.xml
sed -i -E 's#^( *)(ACK|BYE) sip:\[service\]@\[remote_ip\]:\[remote_port\] SIP/2.0#\1\2 [next_url] SIP/2.0\n\1[routes]#' uac_rr.xml
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -trace_msg -message_file uas.msg -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

The caller needs `sudo` because it plays the audio sample through a raw socket.
At the end SIPp's statistics screen shows `Successful call` at 1.

Now compare the SDP the caller sent with the SDP the callee received:

```bash
# Run all of these, in order.
cd ~/sipp
awk '/INVITE sip:/{f=1} f' uas.msg | grep -m2 -E '^(c=IN IP4|m=audio)'
```

SIPp's caller offered its media on port 6000, SIPp's default. The callee
received an `m=audio` port between 50000 and 59999 instead: a port rtpproxy
allocated for this call. Both ends sent their audio to rtpproxy, and rtpproxy
forwarded it. On one machine the caller and rtpproxy share the address
`192.0.2.10`, so the port is what shows the relay. With phones on other
machines, the `c=` address changes too, from the caller's to rtpproxy's.

## 6. Operate it

**Ask rtpproxy what it has relayed.** rtpproxy answers on its control socket.
It has no command that lists calls. Its `I` command returns its totals
instead. Over UDP every command starts with a cookie, a word that rtpproxy
copies into its reply. rtpproxy remembers the replies it sent, by cookie, and
answers a repeated cookie from memory with the old numbers, so these commands
make a new cookie each time from the clock:

```bash
# Run all of these, in order.
sudo apt-get install -y netcat-openbsd
printf 'c%s I\n' "$(date +%s%N)" | nc -u -w1 127.0.0.1 7722
```

After the test call, the reply starts with the cookie, then five lines:

```text
c1790815786642612993 sessions created: 1
active sessions: 0
active streams: 0
packets received: 492
packets transmitted: 492
```

`sessions created` counts every call since rtpproxy started, and `active
sessions` the calls it relays now. The test call is already back to 0: when
the `BYE` passed, OpenSIPS told rtpproxy to delete the session, and rtpproxy
did. Each side of the call sent 246 packets, and rtpproxy forwarded all 492.

The `G` command returns any of rtpproxy's named counters. With `v` after it,
each value carries its name. `nsess_owrtp` counts sessions whose audio went
only one way, the relay's own view of one-way audio:

```bash
printf 'c%s Gv nsess_created nsess_complete nsess_owrtp npkts_relayed\n' "$(date +%s%N)" | nc -u -w1 127.0.0.1 7722
```

```text
c1790815787821100969 nsess_created=1 nsess_complete=1 nsess_owrtp=0 npkts_relayed=492
```

**Check health and read the logs.**

```bash
# Run all of these, in order.
systemctl is-active opensips rtpproxy
sudo journalctl -u rtpproxy -n 50
sudo journalctl -u opensips -n 50
```

With `-d INFO`, rtpproxy logs each session it creates, with the Call-ID
OpenSIPS gave it, the port it allocated and the address each side sent from,
and each session it deletes, with the packets it relayed for it. The journal
is the first place to look when a call has no audio.

**Restart after a configuration change.** rtpproxy keeps its sessions in
memory only. A restart drops the media of every call it is relaying. Those
calls stay up in OpenSIPS and go silent. Restart it when no calls are up, or
accept that the calls in progress lose their audio:

```bash
# Run all of these, in order.
sudo systemctl restart rtpproxy
sudo systemctl restart opensips
```

**Uninstall.** Purging the package stops rtpproxy, removes its service, its
`/etc/sysconfig/rtpproxy` and its `rtpproxy` user:

```bash
# Run all of these, in order.
sudo systemctl disable --now opensips
sudo apt-get purge -y rtpproxy
```

`unzip` and `netcat-openbsd` stay installed, since other software on the
machine may use them. Remove them with `apt-get purge` if nothing else does.

## With Kamailio

Kamailio drives rtpproxy with its own `rtpproxy` module, which comes with the
`kamailio` package. Set Kamailio up as
[the Kamailio guide](kamailio.md) does, through its step 2, then follow steps 1
and 2 here for rtpproxy. In place of steps 3 and 4, add the relay to
Kamailio's configuration.

Kamailio's script calls `rtpproxy_manage()` at each point where an SDP or the
end of the call passes: on the `INVITE` (the offer), on the reply that carries
the callee's SDP (the answer), and on the `BYE` (the delete). The lines marked
`the relay` are the ones to add to your own script:

```bash
# Run all of these, in order.
sudo tee /etc/kamailio/kamailio.cfg >/dev/null <<'EOF'
#!KAMAILIO
# Kamailio as a SIP proxy that anchors every call's media on rtpproxy.
debug=2
log_stderror=no
log_facility=LOG_LOCAL0
children=2

listen=udp:192.0.2.10:5060   # the address your phones and carriers reach

loadmodule "tm.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "siputils.so"
loadmodule "textops.so"
loadmodule "pv.so"
loadmodule "kex.so"
loadmodule "corex.so"
loadmodule "ctl.so"

# the relay
loadmodule "rtpproxy.so"
modparam("rtpproxy", "rtpproxy_sock", "udp:127.0.0.1:7722")

request_route {
	if (!mf_process_maxfwd_header("10")) {
		sl_send_reply("483", "Too Many Hops");
		exit;
	}

	if (has_totag()) {
		if (loose_route()) {
			if (is_method("BYE")) {
				rtpproxy_manage();   # the relay: release the call's ports
			}
			t_relay();
			exit;
		}
		if (is_method("ACK") && t_check_trans()) {
			t_relay();
		}
		exit;
	}

	if (is_method("CANCEL")) {
		if (t_check_trans()) {
			t_relay();
		}
		exit;
	}
	t_check_trans();

	if (!is_method("INVITE")) {
		sl_send_reply("405", "Method Not Allowed");
		exit;
	}

	record_route();

	rtpproxy_manage();               # the relay: rewrite the offer
	t_on_reply("MANAGE_REPLY");      # the relay: and, in the reply, the answer

	# Where the call goes. Here, a test callee on this machine; in your
	# stack, lookup("location"), dispatcher or a carrier.
	$du = "sip:127.0.0.1:5070";
	t_relay();
}

# the relay: the reply that carries the callee's SDP
onreply_route[MANAGE_REPLY] {
	if (has_body("application/sdp")) {
		rtpproxy_manage();
	}
}
EOF
sudo kamailio -c -f /etc/kamailio/kamailio.cfg
sudo systemctl enable kamailio
sudo systemctl restart kamailio
systemctl is-active kamailio
```

Step 5's test call then works unchanged, and so does step 6, with `kamailio` in
place of `opensips` in the `systemctl` and `journalctl` commands.

**With OpenSIPS on the same machine,** Kamailio listens on 5062, as
[OpenSIPS and Kamailio on one machine](kamailio.md#opensips-and-kamailio-on-one-machine)
sets it up: change `5060` to `5062` in the `listen` line above. One rtpproxy
serves both proxies. Each call is its own session in rtpproxy, named by its
Call-ID, so the two proxies' calls do not collide. Point step 5's caller at
`192.0.2.10:5062` for a call through Kamailio, and at `192.0.2.10:5060` for one
through OpenSIPS.

## rtpengine and rtpproxy on one machine

rtpproxy fits beside the rtpengine that
[Add rtpengine to your voice stack](rtpengine-relay.md) builds. The two take
commands on different ports and relay media on different ranges, so neither
gets in the other's way:

| | Control socket | Media ports |
|---|---|---|
| rtpengine | `udp:127.0.0.1:2223` | 30000-39999 |
| rtpproxy | `udp:127.0.0.1:7722` | 50000-59999 |

Check that both are up and listening:

```bash
# Run all of these, in order.
systemctl is-active ngcp-rtpengine-daemon rtpproxy
sudo ss -ulnp | grep -E ':(2223|7722) '
```

Each call goes through one relay, and the proxy's script picks which. Step 4
replaced the rtpengine guide's configuration with one that engages rtpproxy
only. These lines load the `rtp_relay` and `rtpengine` modules beside
`rtpproxy` again, and pick the relay by the number dialed: a call to
`rtpengine` goes through rtpengine, and every other call through rtpproxy. Your
own script picks by whatever suits it, such as the carrier or the customer:

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
sudo sed -i 's|^modparam("rtpproxy", "rtpproxy_sock", "udp:127.0.0.1:7722")$|&\nloadmodule "rtp_relay.so"\nloadmodule "rtpengine.so"\nmodparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")|' "$C"
sudo sed -i 's|^\trtpproxy_engage();$|\tif ($rU == "rtpengine")\n\t\trtp_relay_engage("rtpengine");\n\telse\n\t\trtpproxy_engage();|' "$C"
sudo grep -n -E 'rtpengine|rtpproxy|rtp_relay' "$C"
sudo opensips -C -f "$C"
sudo systemctl restart opensips
```

Place one call through each relay. SIPp's `-s` sets the number the caller
dials:

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -trace_msg -message_file uas.msg -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s rtpengine -m 1 -timeout 90s
awk '/INVITE sip:/{f=1} f' uas.msg | grep -m1 '^m=audio'
while ss -lun | grep -q ':5070 '; do sleep 1; done
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -trace_msg -message_file uas.msg -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
awk '/INVITE sip:/{f=1} f' uas.msg | grep -m1 '^m=audio'
```

The first call's callee received a port in 30000-39999, from rtpengine. The
second's received one in 50000-59999, from rtpproxy. The `while` line waits
for the first callee to exit and free its port, which takes SIPp several
seconds after the call ends.

With Kamailio, keep one relay per script: `rtpengine_manage()` or
`rtpproxy_manage()`, at every point the relay's section shows. With both
proxies on one machine, each can use a different relay: OpenSIPS on 5060
set up by one guide, and Kamailio on 5062 by the other's
[With Kamailio](#with-kamailio) section.

## Put rtpproxy on its own machine

A busy relay usually gets a machine to itself, often with a public address,
while the SIP proxy stays where it is. The examples use `192.0.2.20` for the
relay's machine. Install rtpproxy there with step 1.

**On the relay's machine,** in place of step 2, have rtpproxy take commands on
an address the proxy can reach, and relay media on its own address:

```bash
# Run all of these, in order.
sudo tee /etc/sysconfig/rtpproxy >/dev/null <<'EOF'
# rtpproxy's command line, added by rtpproxy.service. See rtpproxy(8).
OPTIONS="-s udp:192.0.2.20:7722 -l 192.0.2.20 -m 50000 -M 59999 -d INFO"
EOF
sudo systemctl restart rtpproxy
systemctl is-active rtpproxy
sudo ss -ulnp | grep rtpproxy
```

rtpproxy's control protocol has no authentication, so in the relay's firewall
allow UDP 7722 from your SIP proxies only. Open UDP 50000-59999 to the phones
and carriers that send it audio.

**On the proxy's machine,** point the proxy at it. The first line finds the
proxy's configuration: the OpenSIPS packages', a source build's, or Kamailio's:

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg /etc/kamailio/kamailio.cfg; do sudo test -f "$f" && C=$f && break; done
sudo sed -i 's|"udp:127.0.0.1:7722"|"udp:192.0.2.20:7722"|' "$C"
sudo grep -n 'rtpproxy_sock' "$C"
case "$C" in */kamailio/*) sudo systemctl restart kamailio;; *) sudo systemctl restart opensips;; esac
```

rtpproxy returns the `-l` address with each port, and the proxy writes that
address into the SDP. If the phones reach the relay through NAT, give `-l` its
private address followed by `=` and the public one, such as
`-l 192.0.2.20=203.0.113.20`. rtpproxy then relays on the private address and
returns the public one.

Step 5's callee listens on `127.0.0.1`, which a relay on another machine
cannot reach. [Let sipnab name rtpproxy's media](rtpproxy-sipnab.md#4-rtpproxy-on-its-own-machine)
starts the callee on the machine's address instead, and places the test call
through the relay on its own machine.

## When something does not work

- **rtpproxy, started by hand, exits at once with `running this program as
  superuser in a remote control mode is strongly not recommended`.** You
  started it as root with a UDP control socket, which it refuses. Start it through
  its service, which runs it as the `rtpproxy` user.
- **The callee's SDP still carries the caller's port, and OpenSIPS logs
  `can't send ... command to a RTP proxy (111:Connection refused)`, then
  `proxy <udp:127.0.0.1:7722> does not respond, disable it` and `no available
  proxies`.** rtpproxy is not running, or `rtpproxy_sock` names an address it
  does not listen on. The call still connects, without the relay. Compare the
  socket with the `-s udp:` option in `/etc/sysconfig/rtpproxy`, and with what
  `sudo ss -ulnp | grep rtpproxy` shows.
- **The callee's SDP still carries the caller's port, with none of those
  errors.** The call did not pass through `rtpproxy_engage()`. Check that the
  INVITE reached that line of the route, and that rtpproxy logged a new
  session for its Call-ID.
- **After every call, rtpproxy logs `delete request failed: session <Call-ID>,
  tags <tag>/ not found`, and `I` still counts the call in `active sessions`.**
  The script engages rtpproxy with `rtp_relay_engage("rtpproxy")`, whose delete
  does not name the session the way rtpproxy needs. rtpproxy frees it on its
  own timeout, `session timeout` in its log, about 60 seconds after the call's
  media stops. Use `rtpproxy_engage()`, as step 4 does.
- **`nc` prints nothing.** Nothing answered on that address and port within the
  second `-w1` allows. Check that rtpproxy runs, and that the address and port
  match the `-s udp:` option. An answer of `E` and a number, such as `E0`, is
  an error code from rtpproxy: the command reached it and it refused it.
- **The test call's `BYE` gets `404 Not here`.** The caller ignored the route
  set. Use the edited `uac_rr.xml`, not SIPp's built-in `uac_pcap`.
- **With the relay on its own machine, the SDP carries the proxy's address,
  not the relay's.** rtpproxy runs without `-l`, so it returned a port
  and no address, and the proxy wrote in an address of its own. Give `-l` the
  relay's address and restart rtpproxy.
- **No audio through a relay on its own machine, and rtpproxy logs `RTP stats:
  0 in from callee, 0 in from caller` when the session ends.** No packet
  reached rtpproxy: the phones cannot reach a port in 50000-59999 on the relay,
  or the `-l` address is one they cannot reach. Open the range, and check
  which address the proxy writes into the SDP.
