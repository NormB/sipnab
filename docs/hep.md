# Collect and forward HEP

HEP (the Homer Encapsulation Protocol) carries a copy of each SIP message, with
its addresses and the time the sender saw it, from a SIP server to a collector.
sipnab works on both ends of it:

- **As a collector** (`--hep-listen`), sipnab receives the copies your SIP
  servers send and analyzes the calls. It needs no packet capture and no
  privileges.
- **As a capture agent** (`--hep-send`), sipnab captures SIP off an interface
  and forwards it, with the RTCP of each call, to Homer or to another sipnab.

This page sets up both ends, adds the shared secret, TCP and TLS that a feed
across a network needs, and shows how to check each step.

## Before you start

- **A build with HEP.** Every release package and binary has it. Check the
  `features:` list:

  ```bash
  sipnab --version
  ```

  ```text
  sipnab 0.5.232 (0d8eea19) features: native,tui,audio,tls,hep,api,mcp,mcp-http,metrics,plugins,vcon,opus,archive,g729
  libpcap version 1.10.4 (with TPACKET_V3); alternate capture backends named: none
  ```

  `hep` must be in it. TCP and TLS also need `tls`.
- **No privileges for a collector.** A listener on a port above 1023 runs as
  an ordinary user. Only `--hep-send` from a live interface needs capture
  rights ([Install](install.md#capture-live-traffic-without-root)).
- **A firewall rule on the collector** for the port and transport you choose,
  open only to your SIP servers.
- **On the SIP server**, the lines in
  [Have your SIP server send HEP](#have-your-sip-server-send-hep). They are the
  only change another system needs.

What ran: every command and output on this page ran on 2026-11-03 with sipnab
0.5.232 built from source, OpenSIPS 4.0.2, Kamailio 6.1.4 and heplify-server
1.60.10, in containers on one Linux host. The SIP server was at
`198.51.100.10` and sipnab at `198.51.100.1`. SIPp placed one call through the
SIP server for each test.

## Receive HEP from a SIP server

### Start the listener

```bash
sipnab -N -L 198.51.100.1:9061 --hep-allow 198.51.100.10 \
  --duration 15 --report --hep-senders --no-cli-print
```

- `-L` (`--hep-listen`) binds the UDP port. It decodes HEP on its own.
  `--hep-parse` is not needed, and changes nothing on a listener.
- `--hep-allow` names the senders it accepts: an address, or a range such as
  `198.51.100.0/24`. Repeat it for each.
- sipnab refuses to bind a listener to a routable address with neither
  `--hep-allow` nor `--hep-auth-file`, because an open HEP port accepts forged
  calls from anyone who reaches it. A loopback bind needs neither.
- `--duration` stops after that long, then `--report` and `--hep-senders`
  print what arrived. Leave `--duration` out for a collector that runs until
  you stop it, or run it as a service ([Run sipnab as a
  service](examples.md#run-sipnab-as-a-service)).

### Have your SIP server send HEP

**OpenSIPS 4.0.** `proto_hep` defines the destination and `tracer` sends every
message of each call to it. These are the lines that ran. Give OpenSIPS a
`hep_udp` socket to send from, and call `trace()` for each new call:

```cfg
socket=hep_udp:198.51.100.10:6061

loadmodule "dialog.so"
loadmodule "proto_hep.so"
modparam("proto_hep", "hep_id", "[sipnab] 198.51.100.1:9061; transport=udp; version=3")
modparam("proto_hep", "hep_capture_id", 101)
loadmodule "tracer.so"
modparam("tracer", "trace_id", "[tid]uri=hep:sipnab")

route {
	# Your checks and record_route() come first.
	create_dialog();
	trace("tid", "d");
	# Then t_relay(), as before.
}
```

- Without `transport=udp`, OpenSIPS uses HEP over TCP, its default, and sends
  nothing unless it also has a `hep_tcp` socket.
- `"d"` traces the whole dialog, both legs, in both directions. `"m"` traces
  only the message the script runs on: a run with `"m"` received one INVITE per
  call and nothing after it.
- [Use OpenSIPS as your voice stack's SIP server](opensips.md) and
  [Add Homer to your voice stack](homer.md) show the complete script.

**Kamailio 6.1.** `siptrace` sends a copy of every message to one destination:

```cfg
loadmodule "siptrace.so"
modparam("siptrace", "duplicate_uri", "sip:198.51.100.1:9061")
modparam("siptrace", "hep_mode_on", 1)
modparam("siptrace", "hep_version", 3)
modparam("siptrace", "hep_capture_id", 102)
modparam("siptrace", "trace_to_database", 0)
modparam("siptrace", "trace_on", 1)
modparam("siptrace", "trace_mode", 1)
```

A second `duplicate_uri` line replaces the first rather than adding a
destination. [Connect sipnab to Homer](homer-sipnab.md#sipnab-as-a-second-receiver)
gives the two ways to run sipnab beside Homer with Kamailio.

**Asterisk, FreeSWITCH and rtpengine** have their own sections:
[Run sipnab beside Asterisk](asterisk-sipnab.md),
[Run sipnab beside FreeSWITCH](freeswitch-sipnab.md#receive-freeswitchs-own-copy-of-its-sip-hep)
and [Let sipnab name rtpengine's media](rtpengine-sipnab.md).

### Check that it works

The OpenSIPS run above ended with the call and the one sender:

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags
-------------------------------------------------------------------------------------------------------------------------
1-hep@example.com                sipp           echo           Completed    200    0s         13     0.0s     -
HEP senders (trust unauthenticated, silent after 30s)
  received 13  admitted 13  refused 0  from untracked senders 0

  SOURCE                                PACKETS  LAST SEEN                    IDLE  STATE
  hep:101@198.51.100.10                      13  2026-11-03T14:59:20.783Z       5s  sending
  1 of 1 tracked sender(s) shown, 0 silent, limit 4096. Capture ids are claimed by the sender, not proven.

Refused sources (0 of 0 tracked shown, limit 256, 0 evicted)
```

- `hep:101` is the `hep_capture_id` OpenSIPS stamps on each copy. Kamailio's
  run showed `hep:102`. Give each sender its own id, because the roster keys
  on it.
- The start of the run warns that the listener is `non-loopback and
  unauthenticated`. [Require a shared secret](#require-a-shared-secret) is the
  fix.
- HEP carries no RTP, so `--report` shows no streams. [Take signaling from HEP
  and media from the wire](#take-signaling-from-hep-and-media-from-the-wire)
  adds them.

## See who feeds the listener

With twenty SIP servers sending, the listener answers three questions: which
are sending, which stopped, and which send while the listener turns them away.

- At the end of a bounded run: `--hep-senders`, as above. With `--json`, the
  same roster is one JSON object on the last line of stdout.
- While sipnab runs as a server: `GET /v1/hep/senders`, or the MCP
  `hep_senders` tool.
- In the TUI: `h` for capture health, then `s`.

[Find who feeds the collector and who it refuses](examples.md#find-who-feeds-the-collector-and-who-it-refuses)
reads each column. A sender that stops while others keep sending gets a log
line of its own, and another when it comes back. `--hep-silence-warn` sets how
long it may stay quiet first (30 seconds).

## Require a shared secret

`--hep-allow` trusts an address. A shared secret also proves the sender holds
the key. sipnab checks it in one of two modes:

| Mode | What travels | Who can send it |
|---|---|---|
| `plain` (default) | The secret itself, in the HEP auth-key chunk (`0x000e`) | Kamailio `siptrace`, another sipnab. A sniffer on the path can read and replay it |
| `hmac` | A per-packet HMAC-SHA256 token over the whole packet, with a timestamp and a nonce | Another sipnab only |

### Create the key

```bash
# Run all of these, in order.
printf '%s\n' 'replace-with-a-long-random-string' | sudo tee /etc/sipnab/hep.key >/dev/null
sudo chmod 600 /etc/sipnab/hep.key
```

sipnab reads the file and trims the line ending. Give the same string to the
sender.

### From Kamailio (plain)

Add the key to the `siptrace` lines above:

```cfg
modparam("siptrace", "auth_key", "replace-with-a-long-random-string")
```

Start the listener with the file. A listener with a key needs no
`--hep-allow` to bind a routable address, and can still have one:

```bash
sipnab -N -L 198.51.100.1:9061 --hep-auth-file /etc/sipnab/hep.key \
  --duration 15 --report --hep-senders --no-cli-print
```

The Kamailio run admitted every packet, and the roster names the mode:

```text
HEP senders (trust shared_secret_plain, silent after 30s)
  received 13  admitted 13  refused 0  from untracked senders 0

  SOURCE                                PACKETS  LAST SEEN                    IDLE  STATE
  hep:102@198.51.100.10                      13  2026-11-03T15:00:41.979Z       5s  sending
```

The same run with a different key in the file refused all 13, and 30 seconds in
the listener said why:

```text
WARN sipnab::capture::hep: HEP listener on 198.51.100.1:9061: no packets admitted for 30s — 13 arrived and every one was refused, mostly auth_mismatch (the auth key does not match this listener's secret), the last of those from 198.51.100.10; the sender is reaching this port and being turned away; capture is still listening
```

### OpenSIPS sends no key

`proto_hep` has no parameter for the auth-key chunk. Its documentation lists
`hep_id` keys `uri`, `transport` and `version` only
([`proto_hep` 4.0](https://docs.opensips.org/docs/modules/4.0.x/proto_hep.html),
read 2026-11-03). A listener with a key therefore refuses every OpenSIPS copy:

```text
Refused sources (1 of 1 tracked shown, limit 256, 0 evicted)
  PEER                                        PACKETS  REASONS
  198.51.100.10                                    13  auth_missing=13
```

Guard an OpenSIPS feed with `--hep-allow` and a firewall instead, and carry it
over TLS when it crosses a network you do not control.

### Between two sipnabs (hmac)

Both ends take the same file and `--hep-auth-mode hmac`:

```bash
sipnab -N -L 127.0.0.1:9071 --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac \
  --duration 4 --hep-senders --no-cli-print
```

```bash
sipnab -N -I sample-call.pcap --hep-send 127.0.0.1:9071 \
  --hep-auth-file /etc/sipnab/hep.key --hep-auth-mode hmac --hep-id 2002 --no-cli-print
```

The listener admitted all 33 packets under `trust shared_secret_hmac`. The same
sender in `plain` mode met a refusal on every packet, as `hmac_bad_format`.

- The token's timestamp must fall within `--hep-hmac-window` seconds of the
  listener's clock (30 by default, at most 300). A sender with a wrong clock is
  refused as `hmac_timestamp_out_of_window`. Fix its NTP rather than widen the
  window: the window is how long a captured packet stays replayable.
- `heplify-server` has no option that checks a key, so Homer accepts a feed
  with or without one.

## Carry HEP over TCP or TLS

UDP gives a sender no sign that the collector is down, and leaves the copies
readable on the path. Each end of sipnab names its own transport, so a relay
can take one in and send another out.

### A TCP or TLS listener

```bash
sipnab -N -L 198.51.100.1:9062 --hep-listen-transport tcp --hep-allow 198.51.100.10 \
  --duration 15 --report --hep-senders --no-cli-print
```

For TLS, give the listener a certificate and its key. sipnab refuses a key
other users can read:

```bash
chmod 600 /etc/sipnab/collector.key
```

```bash
sipnab -N -L 198.51.100.1:9063 --hep-listen-transport tls \
  --hep-tls-cert /etc/sipnab/collector.pem --hep-tls-key /etc/sipnab/collector.key \
  --hep-allow 198.51.100.10 --duration 15 --report --hep-senders --no-cli-print
```

The start of the run names the transport, as in `HEP listener started on
198.51.100.1:9063 (tls)`. A key with mode `0644` stops it instead:
`the HEP TLS private key is world-readable (mode 0644); chmod 600 it`.

- A TCP or TLS listener reads HEP v3 only. HEP v1 and v2 carry no length, so
  they work over UDP only.
- TLS proves the path is private, not who the sender is: sipnab asks senders
  for no certificate. Keep `--hep-allow`, a key, or both.

### What a TCP or TLS listener keeps when the run stops

A stream listener stops at `--duration`, at `--count`, or on a signal. Each
keeps a different share of what senders had sent:

- **`--duration`** keeps what reached sipnab before the deadline. The listener
  reads what its open connections hold, for up to 1 second each. It also
  accepts the connections still waiting in its backlog, for up to 1 second, and completes a TLS handshake under way, for up to 1 second, so a
  sender that connected just before the deadline is not lost. The run then
  reads on for up to 3 seconds for the listener to deliver it. A sender that
  goes on sending cannot hold the stop open past these limits.
- **`--count N`** keeps exactly N packets, however many connections send at
  once. When the run reaches the count, the listener closes every connection
  still open and delivers nothing more from it.
- **SIGTERM or SIGINT** stops at once. What is still in a socket, or in a
  connection not yet accepted, is not reported.

To check a `--duration` run, compare the count the sender reports with the
listener's last line, `HEP listener on 198.51.100.1:9062 finished: N packets
received`, and with `--report`. If the numbers differ:

- A sender that keeps sending after the deadline: what it sends after it is
  not part of the run.
- A run stopped by a signal: use `--duration` or `--count` for a run whose
  count you compare.
- 0.5.240 and earlier lost every packet on a connection not yet accepted at
  the deadline, and a listener in a `--count` run over several connections
  could take one packet more than N for each further connection, which its
  `finished` line counted.

### OpenSIPS over TCP and TLS

Each transport needs its own socket and `transport=` key. For TCP:

```cfg
socket=hep_tcp:198.51.100.10:6062
modparam("proto_hep", "hep_id", "[sipnab] 198.51.100.1:9062; transport=tcp; version=3")
```

For TLS, add `tls_mgm` with a client domain that checks the collector's
certificate against your CA:

```cfg
socket=hep_tls:198.51.100.10:6063
loadmodule "tls_openssl.so"
loadmodule "tls_mgm.so"
modparam("tls_mgm", "client_domain", "hep")
modparam("tls_mgm", "match_ip_address", "[hep]198.51.100.1:9063")
modparam("tls_mgm", "ca_list", "[hep]/etc/opensips/hep-ca.pem")
modparam("tls_mgm", "verify_cert", "[hep]1")
modparam("tls_mgm", "require_cert", "[hep]1")
modparam("proto_hep", "hep_id", "[sipnab] 198.51.100.1:9063; transport=tls; version=3")
```

Both runs delivered all 13 messages of the call, as `hep:101@198.51.100.10`.

### Kamailio over TCP and TLS

Put the transport on `duplicate_uri`, and give Kamailio a socket of that
transport:

```cfg
listen=tcp:198.51.100.10:5060
modparam("siptrace", "duplicate_uri", "sip:198.51.100.1:9062;transport=tcp")
```

For TLS, load `tls.so`. Kamailio's TLS module refuses to start without a server
certificate, even when it only connects out, so its configuration file needs
both halves:

```cfg
listen=tls:198.51.100.10:5061
enable_tls=yes
loadmodule "tls.so"
modparam("tls", "config", "/etc/kamailio/tls.cfg")
modparam("siptrace", "duplicate_uri", "sip:198.51.100.1:9063;transport=tls")
```

```ini
[server:default]
method = TLSv1.2+
certificate = /etc/kamailio/kamailio.pem
private_key = /etc/kamailio/kamailio.key

[client:default]
method = TLSv1.2+
verify_certificate = yes
require_certificate = yes
ca_list = /etc/kamailio/hep-ca.pem
```

Both runs delivered all 13 messages, as `hep:102@198.51.100.10`. Without the
`[server:default]` certificate, Kamailio exited at startup with
`init_mod_child(): error while initializing module tls`.

## Forward what sipnab captures to Homer

On a machine whose SIP server sends no HEP, sipnab captures the SIP and
forwards it. Name the interface the SIP crosses:

```bash
sudo sipnab -N -d eth0 --hep-send 198.51.100.30:9060 --hep-id 2002
```

- SIP goes as HEP type 1. RTCP goes as type 5, as the JSON heplify-server
  stores, with the call's Call-ID, and only for calls whose SDP sipnab saw.
  RTP is never forwarded.
- `--hep-id` is the capture id Homer shows. Give each agent its own.
- `--hep-send-transport tcp` or `tls` picks the transport. For TLS, the
  collector's certificate must name the address or host name you send to.
  `--hep-tls-ca` names the CA that signs it and replaces the host's CA bundle. `--hep-tls-extra-ca` adds a CA to the bundle
  instead. `[hep]` in [`sipnab.toml`](config-reference.md#hep) takes the same
  settings.

heplify-server 1.60.10 accepted all three transports, started with
`-hepaddr 0.0.0.0:9060 -heptcpaddr 0.0.0.0:9061 -heptlsaddr 0.0.0.0:9062`,
`-tlscertfile` and `-tlskeyfile`. The test read the sample capture rather than
an interface, one run per transport:

```bash
sipnab -N -I sample-call.pcap --hep-send 198.51.100.30:9062 --hep-send-transport tls \
  --hep-tls-ca /etc/sipnab/collector-ca.pem --hep-id 2002 --no-cli-print
```

Each run ended with a line such as:

```text
INFO sipnab::app::batch: HEP export to 198.51.100.30:9062 over tls: 33 packet(s) sent, 33 queued, 0 replayed after an outage, none dropped, 0 still queued, none failed, 0 reconnect(s); sent means written to the connection: a write that fails is counted, the packet stays queued, and the sender dials again with backoff
```

heplify-server's own counter then read `heplify_packets_total{node_id="2002",type="sip"} 99`:
33 packets from each of the three runs. A run reading a capture file also warns
that the file's signaling leaves the machine. [Connect sipnab to
Homer](homer-sipnab.md#sipnab-as-a-source-for-homer) finds the call in Homer
afterwards.

## When the collector goes away

Over TCP or TLS, sending runs on its own thread behind a queue, so a collector
that stops never slows the capture:

- **At startup**, a collector that refuses the first connection stops the run
  with exit `2`:

  ```text
  Failed to create HEP sender: Failed to connect HEP sender to '127.0.0.1:9079' over TCP: Connection refused (os error 111)
  ```

- **After that**, packets queue, up to `--hep-send-queue` MiB (64 by default),
  the oldest dropped first at the bound. The sender redials with backoff, each
  attempt bounded by `--hep-send-timeout` seconds (3 by default), and replays
  the queue in capture order when the collector answers.
- **Over UDP**, sipnab cannot see an outage, so it holds nothing and replays
  nothing.

A live run that captured 25 calls showed it. sipnab sent over TCP to a second
sipnab on `127.0.0.1:9070`. SIGTERM stopped the collector 12 seconds in, and
a new one started 20 seconds later:

```bash
sudo sipnab -N -d hepx --hep-send 127.0.0.1:9070 --hep-send-transport tcp \
  --hep-id 2002 --duration 60 --no-cli-print 'udp port 5060'
```

```text
WARN sipnab::capture::hep_delivery: HEP collector 127.0.0.1:9070 unreachable (write: the collector closed the connection); queueing up to 65536 KiB and retrying
INFO sipnab::capture::hep_delivery: HEP collector 127.0.0.1:9070 is reachable again; replaying 143 queued packet(s)
WARN sipnab::app::batch: HEP export to 127.0.0.1:9070 over tcp: 325 packet(s) sent, 325 queued, 143 replayed after an outage, none dropped, 0 still queued, 9 failed attempt(s) (connect 8, write 1), 1 reconnect(s); sent means written to the connection: a write that fails is counted, the packet stays queued, and the sender dials again with backoff
```

The first collector admitted 65 packets and the second 260: all 325. A failed
attempt keeps its packet queued, so `9 failed attempt(s)` lost nothing. What
a run loses is the `dropped` count, by reason: `queue_full`, `stopped` (sipnab
itself stopped with packets still queued) and `unsent_at_exit`. The same
counts are in `runtime_stats`, `GET /v1/runtime` and the Prometheus series.
[When the `--hep-send` collector goes away](cli-reference.md#when-the---hep-send-collector-goes-away)
gives every rule.

## Read a HEP mirror off the wire instead

A SIP server may already send HEP to an address where nothing listens for it,
or to Homer on the same machine. sipnab can read those packets off the
interface rather than take the port, so Homer keeps its feed. `-E`
(`--hep-parse`) unwraps HEP inside ordinary captured UDP.

Put it in a configuration file, so that a plain `sipnab` does it. In this run
OpenSIPS sent to `198.51.100.1:9061`, where nothing listened, and the file
named the interface the copies crossed and their port:

```toml
[capture]
device = "hepx"
hep_parse = true
bpf_filter = "udp port 9061"
```

For a SIP server that sends to Homer on the same machine, the interface is
`lo` and the port Homer's.

```bash
sudo sipnab -N --config mirror.toml --duration 15 --report --no-cli-print
```

```text
1-hep@example.com                sipp           echo           Completed    200    0s         13     0.0s     -
INFO sipnab::capture::live: Live capture on 'hepx' finished: 13 packets, no drops
INFO sipnab::app::batch: sipnab: 13 packets captured, 13 SIP messages, 0 RTP packets across 0 streams
```

- A sniffed copy reaches no socket, so `--hep-allow` and a key do not apply to
  it.
- `--no-hep-parse` turns it off for one run when the file turns it on.
- [Use `--hep-parse` on a relay capture](rtpengine.md#use---hep-parse-on-a-relay-capture)
  covers rtpengine's mirrored control plane.

## Take signaling from HEP and media from the wire

HEP carries no RTP. One sipnab can take the SIP from the listener and the
media from an interface, and bind each stream to its call by the SDP:

```bash
sudo sipnab -N -d hepx --hep-listen 198.51.100.1:9061 --hep-allow 198.51.100.10 \
  --duration 15 --json-dialogs --no-cli-print 'udp port 5060'
```

That run's filter also took the SIP off the bridge, to compare the two. To take
only media from the interface, give it your media ports instead, such as
`"udp portrange 10000-20000"`. The run states both sources at startup:
`Capturing from two sources in one process: device 'hepx' + HEP listener
198.51.100.1:9061`. It also warns that two clocks stamp the two sources.

When the interface also sees the SIP, sipnab compares the two accounts of each
call. Agreement prints nothing. A disagreement is a finding in the call's
diagnosis, under `source_disagreement` in `--json-dialogs` and in
`--call-report`. With OpenSIPS tracing `"m"` instead of `"d"`, the mirror
reported only the INVITE, and the call said:

```text
Capture sources disagree about this call: the wire carried 12 messages the mirror never reported (100 Giving it a try #2, INVITE (SDP) #3, 180 Ringing #4, and 9 more). 1 message matched on both.
```

[Take signaling from HEP and media off the wire, in one process](examples.md#take-signaling-from-hep-and-media-off-the-wire-in-one-process)
explains each kind of finding, and the combinations sipnab refuses (`-I`,
`--multi-device` or `-O` with the pair).

## When something does not work

| Symptom | Cause | Fix |
|---|---|---|
| `received 0` and `no packets for 30s` | Nothing reaches the port | The SIP server's address and port, its transport, the firewall |
| Refused, `auth_missing` | The listener has a key and the sender sends none (OpenSIPS never does) | Drop the key and use `--hep-allow`, or send from Kamailio with `auth_key` |
| Refused, `auth_mismatch` | Different keys on the two ends | Compare the strings. sipnab trims the file's line ending |
| Refused, `hmac_bad_format` | The listener is in `hmac` mode and the sender in `plain` | Set `--hep-auth-mode hmac` on both |
| Refused, `allowlist` | The sender's address is outside `--hep-allow` | Add it, as an address or a range |
| `Failed to create HEP sender` and exit 2 | The TCP or TLS collector refused the first connection | Start the collector first |
| The TLS listener does not start: `world-readable` | The key file's mode | `chmod 600` the key |
| OpenSIPS sends nothing | `hep_id` without `transport=udp` and no `hep_tcp` socket | Add `transport=udp`, or the socket |
| Kamailio exits at startup with TLS | No `[server:default]` certificate | Add one, as above |

[A HEP collector that receives nothing](troubleshooting.md#a-hep-collector-that-receives-nothing)
lists every refusal reason, and [Error messages](errors.md) every startup
refusal.
