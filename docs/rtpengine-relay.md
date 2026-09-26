# Add rtpengine to an OpenSIPS voice stack

A SIP proxy such as OpenSIPS carries the signaling of a call, and by default
the audio flows directly between the two phones. A media relay puts itself in
that path: the proxy rewrites each call's SDP so that both phones send their
audio to the relay, and the relay forwards it. That fixes one-way audio behind
NAT, hides your customers' addresses from each other, and gives you one place
where you can measure or record every call's media.

[rtpengine](https://github.com/sipwise/rtpengine) is the media relay most
OpenSIPS and Kamailio deployments use. This guide builds it, has OpenSIPS
anchor every call's media on it, and proves that with a test call. This guide
does not use sipnab. When you have this working,
[Let sipnab name rtpengine's media](rtpengine-sipnab.md) adds sipnab beside
it.

The parts, and what each one does:

| Part | Role |
|---|---|
| **OpenSIPS** | Your SIP proxy. Its `rtpengine` module asks rtpengine for a relay port for each call and rewrites the SDP to point at it. |
| **rtpengine** | Relays each call's media. OpenSIPS controls it over rtpengine's *ng* protocol, on a UDP port that only OpenSIPS should reach. |
| **SIPp** | Plays a caller and a callee, for the test call. |

Everything below runs on one machine, which keeps the example short. The
[last section](#put-rtpengine-on-its-own-machine) says what changes when
rtpengine has a machine to itself.

## Tested on

Every command on this page ran as written, in order, on 2026-09-26 on two
x86_64 virtual machines with 2 cores and 4 GB of memory: a clean Debian 13
(kernel 6.12.63), and Ubuntu 24.04.5 (kernel 6.8.0). The commands pin the
components to the versions below. Newer commits may behave differently, and
pinning them keeps the guide describing what you get.

| Software | Version or commit |
|---|---|
| OpenSIPS | [`f46ef9337b`](https://github.com/OpenSIPS/opensips/commit/f46ef9337b), master, 4.1.0-dev |
| rtpengine | [`8da4be3355`](https://github.com/sipwise/rtpengine/commit/8da4be3355), master, packaged as 26.3.0.0 |
| SIPp (for the test call) | the distribution's `sip-tester`: 3.7.3 on Debian, 3.7.2 on Ubuntu |

The examples use `192.0.2.10` as the machine's address. Replace it with yours
everywhere it appears.

## 1. Build rtpengine

rtpengine's own documentation recommends building Debian packages from the
source tree, which gives you a systemd unit, a configuration file and a clean
uninstall. The build installs its dependencies from the tree's
`debian/control`, then runs rtpengine's test suite, which takes a while:

```bash
# Run all of these, in order.
sudo apt-get update
sudo apt-get install -y --no-install-recommends git ca-certificates build-essential devscripts equivs fakeroot
sudo mkdir -p /usr/local/src/voice && sudo chown "$USER": /usr/local/src/voice
cd /usr/local/src/voice
git clone https://github.com/sipwise/rtpengine.git
cd rtpengine
git checkout 8da4be3355
sudo mk-build-deps -i -r -t "apt-get -y --no-install-recommends" debian/control
dpkg-buildpackage -us -uc -b -j2
cd ..
sudo apt-get install -y ./ngcp-rtpengine-daemon_26.3.0.0+0~mr26.3.0.0_amd64.deb \
  ./ngcp-rtpengine-utils_26.3.0.0+0~mr26.3.0.0_all.deb
```

The package's configuration asks for rtpengine's kernel forwarding module, which
this guide does not install. Tell it to forward in userspace, and restart it:

```bash
# Run all of these, in order.
sudo sed -i '0,/^table = 0/s//table = -1/' /etc/rtpengine/rtpengine.conf
sudo systemctl restart ngcp-rtpengine-daemon
systemctl is-active ngcp-rtpengine-daemon
```

Userspace forwarding copies every packet through the rtpengine process. The
kernel module, which this guide does not install, moves that work into the
kernel.

## 2. Look at what rtpengine listens on

`/etc/rtpengine/rtpengine.conf` has several sections. The service reads the
`[rtpengine]` section, and the `[interface-...]` sections it points to. The
file also carries example sections, such as `[rtpengine-testing]`, that the
service does not read, so read the two that matter by name:

```bash
# Run all of these, in order.
sed -n '/^\[rtpengine\]/,/^\[/p' /etc/rtpengine/rtpengine.conf | grep -E '^(listen-ng|interfaces-config|port-min|port-max) '
sed -n '/^\[interface-default\]/,/^\[/p' /etc/rtpengine/rtpengine.conf | grep -E '^address '
```

- `listen-ng = localhost:2223` is the control port, where OpenSIPS sends its
  requests. It listens on the loopback address, so nothing outside the machine
  can reach it. Keep it that way: the ng protocol has no authentication, and
  anyone who can reach the port can create and tear down relay sessions.
- `interfaces-config = interface` tells rtpengine to take its media addresses
  from the sections named `[interface-...]`. The one section,
  `[interface-default]`, says `address = any`: every address the machine has
  at startup. rtpengine writes one of them into the SDP and receives the
  media there.
- `port-min` and `port-max` bound the media ports it allocates, 30000-39999.

## 3. Build OpenSIPS

OpenSIPS master builds with compiler optimizations turned off, which is right
for OpenSIPS's own developers and wrong for a proxy carrying calls. Turn them
back on before you build. The `rtpengine` module is part of the default build:

```bash
# Run all of these, in order.
sudo apt-get install -y --no-install-recommends bison flex uuid-dev pkg-config libncurses-dev
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

## 4. Configure OpenSIPS to anchor every call on rtpengine

This configuration is a minimal proxy with the relay added. Your own script
does much more (registration, authentication, routing to carriers). The relay
part is the block marked below, and the `loadmodule` lines it needs.

```bash
sudo tee /usr/local/etc/opensips/opensips.cfg >/dev/null <<'EOF'
# OpenSIPS as a SIP proxy that anchors every call's media on rtpengine.
log_level=3
stderror_enabled=no
syslog_enabled=yes
syslog_facility=LOG_LOCAL0
udp_workers=2
open_files_limit=4096

socket=udp:192.0.2.10:5060   # the address your phones and carriers reach

mpath="/usr/local/lib64/opensips/modules/"

loadmodule "proto_udp.so"   # built into the core, but still loaded by name
loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "rr.so"
loadmodule "maxfwd.so"
loadmodule "sipmsgops.so"

loadmodule "mi_fifo.so"
modparam("mi_fifo", "fifo_name", "/run/opensips/opensips_fifo")

# The relay: rtp_relay drives rtpengine for the whole dialog.
loadmodule "dialog.so"
loadmodule "rtp_relay.so"
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

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
	rtp_relay_engage("rtpengine");
	# --- the relay ends here ---

	# Where the call goes. Here, a test callee on this machine; in your
	# stack, lookup("location"), dispatcher or a carrier.
	$du = "sip:127.0.0.1:5070";
	t_relay();
}
EOF
```

What the relay block does:

- `create_dialog()` makes OpenSIPS track the call, so that it knows when the
  call ends and can release the relay ports with it.
- `rtp_relay_engage("rtpengine")` hands the call to rtpengine for its whole
  life. OpenSIPS sends rtpengine the caller's SDP (an `offer`) and forwards the
  rewritten SDP to the callee, does the same for the callee's answer, and sends
  `delete` when the call ends. You do not call `rtpengine_offer()` and
  `rtpengine_answer()` yourself.

Run OpenSIPS as its own user, under systemd:

```bash
# Run all of these, in order.
sudo useradd --system --home-dir /run/opensips --shell /usr/sbin/nologin opensips
sudo chown root:opensips /usr/local/etc/opensips /usr/local/etc/opensips/opensips.cfg
sudo chmod 750 /usr/local/etc/opensips
sudo chmod 640 /usr/local/etc/opensips/opensips.cfg
sudo tee /etc/systemd/system/opensips.service >/dev/null <<'EOF'
[Unit]
Description=OpenSIPS SIP server
After=network.target ngcp-rtpengine-daemon.service

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
sudo /usr/local/sbin/opensips -C -f /usr/local/etc/opensips/opensips.cfg
sudo systemctl daemon-reload
sudo systemctl enable --now opensips
systemctl is-active opensips
```

`opensips -C` checks the configuration and prints `config file ok` before you
start anything.

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
received an `m=audio` port between 30000 and 39999 instead: a port rtpengine
allocated for this call. Both ends sent their audio to rtpengine, and rtpengine
forwarded it. On one machine the caller and rtpengine share the address
`192.0.2.10`, so the port is what shows the relay. With phones on other
machines, the `c=` address changes too, from the caller's to rtpengine's.

## 6. Operate it

**See the calls rtpengine is relaying.** During a call, `list sessions all`
names each one by Call-ID. After the call ends, rtpengine keeps it for a short
while before dropping it (the `delete-delay` setting), so the list can still
show a call that just ended. `list totals` starts with the calls up now, then
counts every call since rtpengine started. These lines are the ones to read:

```bash
# Run all of these, in order.
sudo rtpengine-ctl list sessions all
sudo rtpengine-ctl list totals | grep -E 'Owned sessions|Total managed sessions|Total relayed packets +:|Total number of 1-way streams|Average call duration'
```

Right after the test call, `Owned sessions` is still 1 and `Total managed
sessions` is 0: rtpengine still holds the call. Run the same command a minute
later and the two have swapped, `Owned sessions` 0 and `Total managed sessions`
1, with `Average call duration` about 9 seconds. `Total number of 1-way
streams` counts streams whose audio went only one way, the relay's own view of
one-way audio.

**Check health and read the logs.**

```bash
# Run all of these, in order.
systemctl is-active opensips ngcp-rtpengine-daemon
sudo journalctl -u ngcp-rtpengine-daemon -n 50
sudo journalctl -u opensips -n 50
```

rtpengine logs one line per `offer`, `answer` and `delete`, each naming the
Call-ID, so the journal is the first place to look when a call has no audio.

**Restart after a configuration change.** A restart of rtpengine drops the
media of every call it is relaying. Those calls stay up in OpenSIPS and go
silent. Restart it when no calls are up, or accept that the calls in progress
lose their audio:

```bash
# Run all of these, in order.
sudo systemctl restart ngcp-rtpengine-daemon
sudo systemctl restart opensips
```

**Uninstall.** The rtpengine build installed its build dependencies through one
package, `ngcp-rtpengine-build-deps`. Purging it and running `autoremove`
removes them. `autoremove` also removes any other package that nothing depends
on any more, so on a machine that runs other software, drop `-y` and read its
list first.

```bash
# Run all of these, in order.
sudo systemctl disable --now opensips ngcp-rtpengine-daemon
sudo apt-get purge -y ngcp-rtpengine-daemon ngcp-rtpengine-utils ngcp-rtpengine-build-deps
sudo apt-get autoremove -y
```

## Put rtpengine on its own machine

A busy relay usually gets a machine to itself, often with a public address,
while OpenSIPS stays where it is. Three things change:

- **The control port.** On the relay, set `listen-ng` to an address OpenSIPS
  can reach, such as `listen-ng = 192.0.2.20:2223`, and restart rtpengine. The
  ng protocol has no authentication, so allow that port only from your
  OpenSIPS machines, in the relay's firewall.
- **OpenSIPS's socket.** Point `rtpengine_sock` at it:
  `modparam("rtpengine", "rtpengine_sock", "udp:192.0.2.20:2223")`, then
  restart OpenSIPS. Several relays can share the load: list them all in one
  `rtpengine_sock` value, separated by spaces.
- **The media ports.** Open UDP 30000-39999 on the relay to the phones and
  carriers that send it audio. In `[interface-default]`, set `address` to the
  address they reach it on. If that address is a public one mapped by NAT to a
  private one, set `address` to the private address and add `advertised`
  with the public one, which is what rtpengine then writes into the SDP.
- **The test callee.** Step 5's callee listens on `127.0.0.1`, which only a
  relay on the same machine can reach. With the relay elsewhere, start the
  callee on the machine's address and point `$du` at it, as
  [Let sipnab name rtpengine's media](rtpengine-sipnab.md#5-rtpengine-on-its-own-machine)
  does.

## When something does not work

- **rtpengine logs `FAILED TO OPEN KERNEL TABLE 0`.** `table = -1` was not set,
  or the service was not restarted after setting it.
- **OpenSIPS logs `no available proxies` or `can't send command to
  rtpengine`.** rtpengine is not running, or `rtpengine_sock` names an address
  it does not listen on. Compare the socket with `listen-ng`.
- **The callee's SDP still carries the caller's address.** The call did not
  pass through `rtp_relay_engage()`. Check that the INVITE reached that line
  of the route, and that rtpengine logged an `offer` for its Call-ID.
- **The test call's `BYE` gets `404 Not here`.** The caller ignored the route
  set. Use the edited `uac_rr.xml`, not SIPp's built-in `uac_pcap`.
- **One-way audio through a relay on its own machine.** The phones cannot
  reach a port in 30000-39999 on the relay, or `interface` names an address
  they cannot reach. Open the range, and check which address rtpengine writes
  into the SDP.
