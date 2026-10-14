# Let sipnab name rtpproxy's media

Capture on a media relay and you get the audio of every call. But nothing in
an RTP packet says which call it belongs to. The name is in the signaling. A
relay on its own machine never sees the signaling.

sipnab can still name rtpproxy's media, from the relay's control traffic:

- For each call, your SIP proxy sends rtpproxy a command that carries the
  call's Call-ID.
- rtpproxy answers with the port it opened for it.
- With `--rtpproxy-control`, sipnab reads both. It ties the media on that port
  to the call.

This guide sets that up against the stack from
[Add rtpproxy to your voice stack](rtpproxy-relay.md):

- first on the machine that runs the SIP proxy and rtpproxy together,
- then with rtpproxy on a machine of its own.

The proxy is one of these:

- OpenSIPS, from its packages or built from source,
- Kamailio, set up as that guide's
  [With Kamailio](rtpproxy-relay.md#with-kamailio) section sets it up.

sipnab never talks to the proxy. So every step is the same for each proxy.
The one exception is the line in the rtpproxy on its own machine step that
edits the proxy's configuration.

## What sipnab sends rtpproxy

Nothing.

- With `--rtpproxy-control`, sipnab reads rtpproxy's control traffic from its
  capture.
- It never sends rtpproxy a command. So it cannot make rtpproxy create, change
  or delete a call.
- That is also why it cannot name a call that was already up when it started.
  - rtpproxy has no command that lists its calls.
  - So there is nothing sipnab could ask.
- rtpengine has such a command. With rtpengine, `--rtpengine-control` does
  ask, as [Let sipnab name rtpengine's media](rtpengine-sipnab.md) shows.

## Tested on

Every block on this page ran as written, in order, on 2026-10-01, with sipnab
0.5.197 from its release package.

- The machines were clean x86_64 virtual machines with 2 cores and 3 GB of
  memory:
  - Debian 13 (kernel 6.12.63),
  - Ubuntu 24.04.5 (kernel 6.8.0).
- sipnab ran in three setups:
  - beside OpenSIPS built from source,
  - beside the OpenSIPS packages with Kamailio on the same machine,
  - on the relay's own machine with OpenSIPS on another.
- On both systems:
  - Causing each fault under
    [When something does not work](#when-something-does-not-work) produced
    what it describes.
  - A capture with `--rtpproxy-control` sent nothing to rtpproxy's control
    port.
- arm64 was not tested.

The examples use `192.0.2.10` for the machine that runs the SIP proxy and
`192.0.2.20` for the relay's own machine. Replace them with yours.

## Install sipnab

On the machine that runs rtpproxy:

```bash
# Run all of these, in order.
V=$(curl -fsSL https://api.github.com/repos/NormB/sipnab/releases/latest \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))')
curl -fsSLO https://github.com/NormB/sipnab/releases/download/v$V/sipnab_${V}_amd64.deb
curl -fsSL https://github.com/NormB/sipnab/releases/download/v$V/SHA256SUMS.txt \
  | grep " sipnab_${V}_amd64.deb$" | sha256sum -c -
sudo apt-get install -y ./sipnab_${V}_amd64.deb
sipnab --version
```

`--rtpproxy-control`, which this guide uses, arrived in sipnab 0.5.196.

## Let sipnab see the media and the control traffic

Give sipnab a capture filter that admits three things:

- the SIP,
- rtpproxy's control socket,
- rtpproxy's media ports.

This guide uses the ones from the rtpproxy guide, UDP port 7722 and ports
50000-59999:

```text
portrange 5060-5061 or udp port 7722 or udp portrange 50000-59999
```

sipnab takes the filter as its last argument, in the syntax `tcpdump` uses.
Check the port and the range against the `-s`, `-m` and `-M` options in
`/etc/sysconfig/rtpproxy`.

Name the control port, even though the media range sometimes lets the control
traffic through without it.

- The proxy sends its commands from ports the system picks.
- On Debian and Ubuntu, some of those fall inside 50000-59999 and some do not.

With OpenSIPS and Kamailio on one machine, Kamailio on 5062, widen the
signaling range to `portrange 5060-5062`. With rtpengine on the same machine
as well, add its range, `or udp portrange 30000-39999`.

## Name the calls on the proxy's machine

`--rtpproxy-control` takes the address and port of rtpproxy's UDP control
socket, the `-s udp:` option. Start sipnab. It captures for 25 seconds, then
prints its report:

```bash
sudo sipnab -N -d any --rtpproxy-control 127.0.0.1:7722 --duration 25 --report "portrange 5060-5061 or udp port 7722 or udp portrange 50000-59999"
```

`-d any` captures on every interface, the loopback one included. The control
socket listens on `127.0.0.1`. The test callee does too.

While it runs, place a test call from a second terminal:

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

When the 25 seconds are up, sipnab's report lists the call:

- by its Call-ID,
- as `Completed`,
- with all its streams under `RTP Streams:`,
- with no `Orphaned
  Streams:` section.

```text
Call-ID                          From           To             State        Code   Duration   Msgs
---------------------------------------------------------------------------------------------------
1-51936@192.0.2.10               sipp           echo           Completed    200    9s         13
RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts
--------------------------------------------------------------------------------------
0xdee0ee8f   8    PCMA     8000   192.0.2.10:6000       192.0.2.10:51292      236
0xdee0ee8f   8    PCMA     8000   192.0.2.10:58734      127.0.0.1:6000        236
0xdee0ee8f   8    PCMA     8000   127.0.0.1:6000        192.0.2.10:58734      236
0xdee0ee8f   8    PCMA     8000   192.0.2.10:51292      192.0.2.10:6000       236
```

This shows the report's first columns only. There are eight streams in all:

- the four audio streams above, from the caller to rtpproxy, rtpproxy to the
  callee and back,
- the same four again for the DTMF events the caller sends
  (`telephone-event`).

**A call that was already up is not named.** Start a call first, then sipnab.
The caller plays about 8 seconds of audio. So start sipnab within a second or
two:

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 60s -bg
sleep 1
sudo sipnab -N -d any --rtpproxy-control 127.0.0.1:7722 --duration 6 --report "portrange 5060-5061 or udp port 7722 or udp portrange 50000-59999"
```

The call's `INVITE` went by before sipnab started. So did the commands that
opened its ports. Its streams land under `Orphaned Streams:`, with no call to
name them.

## rtpproxy on its own machine

Move rtpproxy to its own machine as described in
[Put rtpproxy on its own machine](rtpproxy-relay.md#put-rtpproxy-on-its-own-machine).
The relay's machine now carries the control traffic and the media, and no SIP.
Install sipnab there as in the Install sipnab step. Start it with the relay's
control address:

```bash
sudo sipnab -N -d any --rtpproxy-control 192.0.2.20:7722 --duration 25 --report "udp port 7722 or udp portrange 50000-59999"
```

While it runs, place a test call on the proxy's machine.

- The rtpproxy guide's callee listens on `127.0.0.1`. The relay cannot reach
  that from its own machine.
- So start the callee on the machine's address instead.
  - Put its media on ports 7000-7100, so that it does not collide with the
    caller's 6000.
- Point the proxy at it.

The first line finds the proxy's configuration: the OpenSIPS packages', a
source build's, or Kamailio's:

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg /etc/kamailio/kamailio.cfg; do sudo test -f "$f" && C=$f && break; done
sudo sed -i 's|sip:127.0.0.1:5070|sip:192.0.2.10:5070|' "$C"
case "$C" in */kamailio/*) sudo systemctl restart kamailio;; *) sudo systemctl restart opensips;; esac
cd ~/sipp
sipp -sn uas -i 192.0.2.10 -p 5070 -min_rtp_port 7000 -max_rtp_port 7100 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

When the 25 seconds are up, sipnab's report on the relay's machine does two
things:

- It lists the call's streams under `RTP Streams:`.
- Then it names the call from rtpproxy's control traffic, with no SIP in the
  capture:

```text
Calls named by a media relay (no SIP for them in this capture):
Call-ID                                                      Streams
---------------------------------------------------------------------
1-15862@192.0.2.10                                           8
```

- The Call-ID is the one the SIP proxy gave rtpproxy. rtpproxy's own log
  shows it for the session too.
- There are eight streams again: the audio and the DTMF events on both sides
  of the relay.
- There is no SDP on this machine. So the report shows the DTMF streams' codec
  as `?`.

## When something does not work

- **The report shows calls but `0 RTP packets`.** sipnab's filter admitted
  signaling only. Add the relay's control port and media range, as in the Let
  sipnab see the media and the control traffic step.
- **Streams appear, but no call names them, on the relay's machine.** sipnab
  did not read the commands that opened their ports. Check three things:
  - `--rtpproxy-control` names exactly the address and port of rtpproxy's `-s
    udp:` option.
  - The filter admits that port.
  - sipnab started before the calls you want named.
- **sipnab logs `could not be asked which calls are up: rtpengine reply is not
  bencode`, and rtpproxy logs `delete command syntax error: invalid number of
  arguments (1)`.** You pointed `--rtpengine-control` at rtpproxy's control
  socket.
  - That flag sends rtpengine's commands.
  - rtpproxy read the first one as a delete with the wrong number of
    arguments, and refused it.
  - Use `--rtpproxy-control` for rtpproxy.
