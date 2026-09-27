# Connect sipnab to Homer

Homer and sipnab both speak HEP, the protocol SIP servers use to send Homer a
copy of their traffic, so they connect in either direction:

- **sipnab as a second receiver.** Your SIP server sends the same HEP copies
  to sipnab as to Homer. Homer keeps the history; sipnab analyzes the calls as they
  happen, with no capture on the wire at all.
- **sipnab as a source.** On a machine that runs no SIP server of its own, or
  one whose SIP server cannot send HEP, sipnab captures the traffic and
  forwards it to Homer, under a capture id of its own.

This guide sets up both against the stack from
[Add Homer to your voice stack](homer.md), with OpenSIPS from its
packages or built from source, or with Kamailio as that guide's
[With Kamailio](homer.md#with-kamailio) section sets it up. Step 2 differs for
Kamailio, and says how. Step 3 is the same for both.

## Tested on

Every command on this page ran as written, in order, on 2026-09-26, with
sipnab 0.5.192 from its release package: the receiver on the Debian 13
machine (kernel 6.12.63) that [the Homer guide](homer.md) had set up, and the
source on a second machine, Ubuntu 24.04.5 (kernel 6.8.0). Both were x86_64
virtual machines with 2 cores. The examples use `192.0.2.10` for the machine
that runs OpenSIPS and Homer, and `192.0.2.20` for the second machine. Replace
them with yours.

## 1. Install sipnab

On each machine that runs sipnab:

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

## 2. sipnab as a second receiver

**Send OpenSIPS's HEP to sipnab as well.** OpenSIPS's `tracer` sends to every
destination defined under the same trace name. Add a second HEP destination,
`sipnab`, on UDP port 9062, under the name `tid` that `trace()` already uses.
The first line finds your configuration file, the packages' or a source
build's:

```bash
# Run all of these, in order.
for f in /etc/opensips/opensips.cfg /usr/local/etc/opensips/opensips.cfg; do sudo test -f "$f" && C=$f && break; done
sudo sed -i '/^modparam("tracer", "trace_id", "\[tid\]uri=hep:homer")$/a modparam("proto_hep", "hep_id", "[sipnab] 127.0.0.1:9062; transport=udp; version=3")\nmodparam("tracer", "trace_id", "[tid]uri=hep:sipnab")' "$C"
sudo grep -nE 'hep_id|trace_id' "$C"
sudo opensips -C -f "$C"
sudo systemctl restart opensips
```

The `grep` shows the two destinations, `homer` and `sipnab`, and the two
`trace_id` lines that name them.

**Listen, and place a call.** Start sipnab's HEP listener for 30 seconds:

```bash
sudo sipnab -N -L 127.0.0.1:9062 --duration 30 --report --hep-senders
```

While it runs, place a test call from a second terminal, as in
[step 5 of the Homer guide](homer.md#5-place-a-test-call):

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -m 1 -d 1000 -timeout 20s
```

sipnab prints each message as it arrives, marked `origin=hep`. When the 30
seconds are up, it prints the call and who sent it:

```text
Call-ID                          From           To             State        Code   Duration   Msgs
------------------------------------------------------------------------------------------------------
1-60947@192.0.2.10               sipp           service        Completed    200    1s         13

  SOURCE                                PACKETS  LAST SEEN                    IDLE  STATE
  hep:101@127.0.0.1                          13  2026-09-26T21:25:09.115Z       6s  sending
```

`hep:101` is the `hep_capture_id` OpenSIPS stamps on everything it sends, and
Homer received the same 13 messages. The capture id is what the sender claims,
and nothing proves it. What keeps other senders out here is the address: sipnab
listens on `127.0.0.1`, which only this machine can reach.

To keep the listener running, give the packaged service the same arguments in
a drop-in, as
[Send sipnab's vCons to a vCon server](vcon-sipnab.md) does for its own flags.

**With Kamailio.** Kamailio's `siptrace` sends its copies of every message to
one destination, its `duplicate_uri`. A second `duplicate_uri` line does not
add a destination: it replaces the first, and Homer receives nothing. So with
Kamailio, choose one of two ways:

- **Keep Homer as the destination, and let sipnab watch the wire.** sipnab on
  the Kamailio machine sees every message as it passes, both legs, with no
  change to Kamailio at all, as
  [Run sipnab beside Kamailio](kamailio-sipnab.md) sets it up.
- **Send Kamailio's copies to sipnab instead of Homer.** Point `duplicate_uri`
  at sipnab's listener. Homer then receives nothing from Kamailio until you
  point it back:

```bash
# Run all of these, in order.
sudo sed -i 's|"duplicate_uri", "sip:127.0.0.1:9060"|"duplicate_uri", "sip:127.0.0.1:9062"|' /etc/kamailio/kamailio.cfg
sudo grep -n duplicate_uri /etc/kamailio/kamailio.cfg
sudo kamailio -c -f /etc/kamailio/kamailio.cfg
sudo systemctl restart kamailio
```

Then start sipnab's listener and place the test call as above. The report shows
the call `Completed` with 13 messages, from `hep:101`, Kamailio's
`hep_capture_id`.

## 3. sipnab as a source for Homer

On the second machine, sipnab captures SIP off the wire and forwards it to
heplify-server. Give it a capture id of its own, so Homer can tell its copies
from your SIP server's:

```bash
sudo sipnab -N -d any -H 192.0.2.10:9060 --hep-id 2002 --duration 30
```

sipnab forwards SIP, and RTCP so that Homer can report media quality. It never
forwards RTP, the audio itself.

While it runs, place a call from the second machine through your SIP server.
The callee still runs on the SIP server's machine:

```bash
# Run all of these, in order.
# On 192.0.2.10:
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
```

```bash
# Run all of these, in order.
# On 192.0.2.20:
sudo apt-get install -y sip-tester
mkdir -p ~/sipp && cd ~/sipp
sipp -sd uac > uac_rr.xml
sed -i 's|<recv response="200" rtd="true">|<recv response="200" rtd="true" rrs="true">|' uac_rr.xml
sed -i -E 's#^( *)(ACK|BYE) sip:\[service\]@\[remote_ip\]:\[remote_port\] SIP/2.0#\1\2 [next_url] SIP/2.0\n\1[routes]#' uac_rr.xml
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.20 -p 5080 -m 1 -d 1000 -timeout 20s \
  -trace_msg -message_file uac.msg
grep -m1 -i '^Call-ID:' uac.msg
```

**Find sipnab's copies in Homer.** Homer now holds the call twice: once from
the SIP server, capture id 101, and once from sipnab, capture id 2002. On the Homer
machine, with the Call-ID the last command printed:

```bash
# Run all of these, in order.
# On 192.0.2.10:
CALL=1-1234@192.0.2.20
cd /opt/homer
docker compose exec -T db psql -U root -d homer_data -c \
  "select protocol_header->>'captureId' as capture_id, count(*)
     from hep_proto_1_call where data_header->>'callid' = '$CALL' group by 1"
```

The test call gave 13 messages under capture id 101 and 7 under 2002. The SIP
server sees both legs of the call. sipnab, on the second machine, sees the messages
on that machine's own link, which is the caller's leg.

HEP over UDP carries no authentication of its own. heplify-server accepts it
from anyone who can reach port 9060, so open that port only to your SIP servers
and to the machines where sipnab forwards.

## When something does not work

- **sipnab shows no messages.** Check that the SIP server sends to it. For
  OpenSIPS, `sudo grep hep_id` on its configuration file lists both
  destinations; for Kamailio, `sudo grep duplicate_uri
  /etc/kamailio/kamailio.cfg` names sipnab's port. Then check that sipnab
  listens on that port.
- **sipnab's copies are missing from Homer.** Check that the second machine
  can reach UDP port 9060 on the Homer machine, and that sipnab's capture saw
  the call: run it with `--report` and look for the Call-ID.
