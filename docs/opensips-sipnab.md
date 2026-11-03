# Run sipnab beside OpenSIPS

sipnab reads the SIP that passes through OpenSIPS off the wire. So it needs
nothing from OpenSIPS: no module, no configuration change. The one exception
is optional: for calls through topology hiding, the OpenSIPS script can send
sipnab each call's two Call-IDs, a change to the script only
([Have OpenSIPS send the mapping](#have-opensips-send-the-mapping)).

On the OpenSIPS machine, sipnab sees both legs of every call:

- the caller's side into OpenSIPS,
- OpenSIPS's side out to the callee.

It puts them together into one call.

This guide adds sipnab to the OpenSIPS proxy from
[Use OpenSIPS as your voice stack's SIP server](opensips.md), installed from
the packages or built from source.

## Tested on

Every block on this page above
[Calls through topology hiding](#calls-through-topology-hiding) ran as
written, in order, on 2026-10-01, with sipnab 0.5.198 from its release
package. That section names the checks that cover it.

- It ran on the Debian 13 (kernel 6.12.63) and Ubuntu 24.04 (kernel 6.8.0)
  machines that [the OpenSIPS guide](opensips.md) had set up:
  - the Watch a call through OpenSIPS step with OpenSIPS from source,
  - [With Kamailio on the same machine](#with-kamailio-on-the-same-machine)
    with the OpenSIPS packages.
- The test calls carried audio.
- The terminal interface showed each call on one row.
- On both machines, causing the fault under [When something does not
  work](#when-something-does-not-work) produced the message it quotes.

The examples use `192.0.2.10` as the machine's address.

## Install sipnab

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

## Watch a call through OpenSIPS

Start sipnab on every interface for 30 seconds. It prints each SIP message as
it passes, and a report of the calls at the end:

```bash
sudo sipnab -N -d any --duration 30 --report
```

While it runs, place a test call from a second terminal. Do it as in
[the Place a test call step of the OpenSIPS guide](opensips.md#place-a-test-call):

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

sipnab prints every message OpenSIPS relays twice, once on each leg:

- the caller's `INVITE` to OpenSIPS at `192.0.2.10:5060`,
- then OpenSIPS's copy of it to the callee at `127.0.0.1:5070`,
- and the same for the replies and the `BYE`.

OpenSIPS's own `100 Giving it a try` goes to the caller alone.

When the 30 seconds are up, the report lists the call once:

- It shows the call as `Completed`, with 13 messages from both legs.
- Below it, an `RTP Streams:` table holds the call's audio.
  - The audio goes straight between the caller and the callee. It never goes
    through OpenSIPS.
  - The table shows the caller's 236 `PCMA` packets and 10 `telephone-event`
    (DTMF) packets.
  - It shows the same again coming back from the callee's echo.
  - That is four streams in all.

You can get the same view in a terminal interface, which updates as calls
happen. Run `sudo sipnab -d any` without `-N` and without `--duration`. It
lists the call on one row, `Completed`, with the same 13 messages.

## With Kamailio on the same machine

[OpenSIPS and Kamailio on one
machine](opensips.md#opensips-and-kamailio-on-one-machine) sets up OpenSIPS on
5060 and Kamailio on 5062. With that setup, give sipnab both ports:

```bash
sudo sipnab -N -d any --duration 30 --report --portrange 5060-5062
```

A call through each proxy then appears in the report, one row per call.

- The two test calls send their audio from the same ports with the same RTP
  SSRC.
- sipnab starts a new stream when the second call's SDP renegotiates those
  ports.
- So the `RTP Streams:` table lists each call's streams on rows of their own:
  - 236 `PCMA` packets each way for each call,
  - not one stream of 472 across both.

## Calls through topology hiding

`topology_hiding("C")` gives the callee's leg a different Call-ID from the
caller's leg. OpenSIPS builds it from the caller's Call-ID:

1. XOR each byte with `th_callid_passwd`.
2. Encode the result in a base64 variant.
3. Put `th_callid_prefix` (`DLGCH_` by default) in front.

OpenSIPS also strips Via, Record-Route and Route, and replaces Contact.
Without help, sipnab can tie the two legs only by timing, which is a guess.

The `C` flag changes the Call-ID only when the call has a dialog
(`create_dialog()`). Without a dialog, OpenSIPS leaves the Call-ID alone.

There are three ways to tie the legs exactly. None of them needs an OpenSIPS
module built or patched for sipnab: each uses modules that ship with
OpenSIPS.

| Method | What changes in OpenSIPS | What sipnab needs | On a capture file (`-I`) | Discloses anything to the callee's side | Modules OpenSIPS loads |
|---|---|---|---|---|---|
| [Have OpenSIPS send the mapping](#have-opensips-send-the-mapping) | The script only: load a module, subscribe at startup, raise one event per call | `--hep-listen` on the address the script names, `--hep-allow` with OpenSIPS's address, and a capture filter that keeps SIP | No, live only: sipnab takes the event from its listener, never from a capture | No | `tm`, `dialog` and `topology_hiding`, which `C` needs anyway, and `event_datagram` |
| [Decode the hidden Call-ID](#decode-the-hidden-call-id) | Nothing | `[sip] th_callid_secret_file` with the OpenSIPS `th_callid_passwd`, `[sip] th_callid_prefix` when OpenSIPS changes it, and a build with the `tls` feature (every release package) | Yes | No | `tm`, `dialog` and `topology_hiding`, which `C` needs anyway |
| [Copy the Call-ID into a header](#or-copy-the-call-id-into-a-header) | The script only: one `append_hf` line | `[sip] xcid_headers` naming the header | Yes | **Yes**: the caller's Call-ID, in the header | `tm`, `dialog` and `topology_hiding`, which `C` needs anyway, and `sipmsgops` for `append_hf` |

sipnab reports which method joined a leg in `method`: `mapping`, `decoded` or
`header`.

### Have OpenSIPS send the mapping

OpenSIPS knows both Call-IDs: `$ci` is the caller's, and
`$TH_callee_callid` is the one it writes on the callee's leg. The script
sends sipnab one small UDP datagram per call that names both. This needs no
secret, and the SIP is still what sipnab captures.

#### 1. What this changes

This is a change to the OpenSIPS script only, with no module to build or
patch: it uses the stock `event_datagram` module, the core script functions
`subscribe_event` and `raise_event`, and the `$TH_callee_callid` variable of
the stock `topology_hiding` module.

`E_SIPNAB_TH_MAP` is a name the script chooses. OpenSIPS needs no declaration
for it: the first `subscribe_event` or `raise_event` that names an unknown
event publishes it (`fixup_event_name` in `core_cmds.c` calls
`evi_publish_event`, in every release from 3.1.0 to 4.0.2). The harness
confirms it: OpenSIPS 4.0.2 logs `Registered event <E_SIPNAB_TH_MAP(9)>` at startup.

#### 2. Prerequisites

- **OpenSIPS 4.0.2, 4.0.1 or 3.6.9.** These are the versions
  [`harness/th-mapping/e2e.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/e2e.sh)
  runs. For other versions, the OpenSIPS source says:
  - 3.1.0 to 3.6.8 and 4.0.0 have everything this uses:
    `$TH_callee_callid`, `event_datagram`, `subscribe_event`, and
    `raise_event` with lists of names and values. Their `event_datagram`
    sends the same JSON-RPC 2.0 notification (`evi_build_payload`). sipnab
    has not run against them.
  - 3.0 and 2.4 have `$TH_callee_callid` and `event_datagram`, but their
    `event_datagram` sends the event as text, one `name::value` per line,
    not as JSON. sipnab takes that datagram for a HEP packet and refuses it:
    `/v1/hep/senders` counts it under `refused_by_reason.malformed`. Use
    [the decode](#decode-the-hidden-call-id) there.
- **These modules loaded:** `tm`, `dialog` and `topology_hiding`, which a
  script with `topology_hiding("C")` already loads, and `event_datagram`.
  The `topology_hiding` README lists `tm` as required, and `dialog` when the
  script creates a dialog, as `C` needs.
- **An IPv4 address for sipnab's listener.** OpenSIPS's `event_datagram`
  sends UDP to an IPv4 address only: its source passes
  `sizeof(struct sockaddr_in)` to `sendto`.

#### 3. The OpenSIPS script change

Three additions, each in its own place.

Load the module, with the other `loadmodule` lines:

```text
loadmodule "event_datagram.so"
```

Subscribe sipnab's listener to the event once, at startup. Put the
`startup_route` at the top level of the script, next to `route`:

```text
startup_route {
	subscribe_event("E_SIPNAB_TH_MAP", "udp:127.0.0.1:9060");
}
```

Raise the event right after `topology_hiding("C")`, in the branch that
handles a new INVITE. That branch comes after the check for in-dialog
requests (`has_totag()`), so a re-INVITE or a BYE never reaches it. Raise it
before OpenSIPS relays the request (`t_relay()`):

```text
if (!create_dialog() || !topology_hiding("C")) {
	send_reply(500, "Internal Server Error");
	exit;
}
$avp(th_keys) = "caller_call_id";
$avp(th_vals) = $ci;
$avp(th_keys) = "callee_call_id";
$avp(th_vals) = $TH_callee_callid;
raise_event("E_SIPNAB_TH_MAP", $avp(th_keys), $avp(th_vals));
```

`$TH_callee_callid` has a value only after `topology_hiding("C")` on a
request with a dialog. The `topology_hiding` README says it is NULL
otherwise, so raised anywhere else, the event cannot name the callee's
Call-ID.

A retransmitted INVITE runs the same branch again and raises the event again.
That is harmless: the caller's Call-ID is the same, so the callee's Call-ID
OpenSIPS builds from it is the same, and sipnab counts the repeat as
`duplicate` and changes nothing.

OpenSIPS sends a JSON-RPC 2.0 notification:

```json
{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"callee_call_id":"DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-","caller_call_id":"1-th-map@example.com"}}
```

A complete minimal `opensips.cfg` with these lines follows. It is the
script the harness runs. OpenSIPS listens on `192.0.2.10`, sipnab on the
same machine, and the example sends every call to one callee at
`192.0.2.1:5070`. Set `mpath` to the directory your OpenSIPS build or
package installs its modules in. `mi_fifo` is there for the `opensips-cli`
check in step 5, and the event does not need it.

```cfg
log_level=3
stderror_enabled=yes
udp_workers=2
socket=udp:192.0.2.10:5060
# The directory your OpenSIPS build or package installs its modules in.
mpath="/usr/local/lib64/opensips/modules/"

loadmodule "signaling.so"
loadmodule "sl.so"
loadmodule "tm.so"
loadmodule "sipmsgops.so"
loadmodule "dialog.so"
loadmodule "topology_hiding.so"
loadmodule "maxfwd.so"
loadmodule "rr.so"
loadmodule "proto_udp.so"
loadmodule "event_datagram.so"
# For opensips-cli: the MI FIFO, at /tmp/opensips_fifo by default.
loadmodule "mi_fifo.so"

startup_route {
	subscribe_event("E_SIPNAB_TH_MAP", "udp:127.0.0.1:9060");
}

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
		if (!loose_route() && !topology_hiding_match()) {
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
	if (!is_method("INVITE")) {
		send_reply(503, "Service Unavailable");
		exit;
	}
	if (!create_dialog() || !topology_hiding("C")) {
		send_reply(500, "Internal Server Error");
		exit;
	}
	$avp(th_keys) = "caller_call_id";
	$avp(th_vals) = $ci;
	$avp(th_keys) = "callee_call_id";
	$avp(th_vals) = $TH_callee_callid;
	raise_event("E_SIPNAB_TH_MAP", $avp(th_keys), $avp(th_vals));
	# Your routing goes here. This example sends every call to one callee.
	$du = "sip:192.0.2.1:5070";
	if (!t_relay())
		send_reply(500, "Internal Error");
	exit;
}
```

#### 4. The sipnab side

Run sipnab with:

- `--hep-listen` on the address and port the subscription names,
- `--hep-allow` with the address OpenSIPS sends the event from. With both
  on one machine and the subscription on `127.0.0.1`, as here, that is
  `127.0.0.1`. With sipnab on another machine, it is OpenSIPS's address,
- a capture filter that keeps the SIP.

```bash
sudo sipnab -N -d any --hep-listen 127.0.0.1:9060 --hep-allow 127.0.0.1/32 --duration 30 --report 'udp port 5060 or udp[8] & 0xc0 = 0x80'
```

The filter matters. With `--hep-listen` as well as `-d` and no filter of
your own, the interface takes media only, because sipnab expects a HEP
mirror to deliver the signaling, and taking it off the wire too would count
every message twice. Here the SIP is on the wire, so the filter keeps UDP
port 5060 and RTP. sipnab prints a notice at startup when it sees
`--hep-allow` with that default filter.

`--hep-listen` and `--hep-allow` are command-line flags only, with no
configuration-file key. The interface and the filter can go in the
configuration file instead:

```toml
[capture]
device = "any"
bpf_filter = "udp port 5060 or udp[8] & 0xc0 = 0x80"
```

```bash
sudo sipnab -N --hep-listen 127.0.0.1:9060 --hep-allow 127.0.0.1/32 --duration 30 --report
```

`[sip] th_mapping_max` and `[sip] th_mapping_ttl_secs` set how many
mappings sipnab holds and for how long (see [Limits](#limits)).

#### 5. Verify it works

**On OpenSIPS**, list the event's subscribers through the MI. OpenSIPS 4.0
names the command `evi:subscribers`, and 3.6 names it `subscribers_list`:

```bash
sudo opensips-cli -o fifo_file=/tmp/opensips_fifo -x mi evi:subscribers
```

```bash
sudo opensips-cli -o fifo_file=/tmp/opensips_fifo -x mi subscribers_list
```

- `opensips-cli` talks to the `mi_fifo` module. With no `-o`, it opens
  `/var/run/opensips/opensips_fifo`, and `mi_fifo` creates
  `/tmp/opensips_fifo` unless the script sets its `fifo_name`. A
  `opensips-cli.cfg` that names the FIFO makes the `-o` unnecessary.
- OpenSIPS 4.0 also accepts `subscribers_list` as an old name, but
  `opensips-cli` refuses it before asking, with
  `no command 'subscribers_list' in module 'mi'`.

The answer names the event, sipnab's address and `"expire": "never"`. This
one comes from the harness, where sipnab listens on `192.0.2.1:9617`:

```json
{
    "Events": [
        {
            "name": "E_SIPNAB_TH_MAP",
            "id": 9,
            "Subscribers": [
                {
                    "socket": "udp:192.0.2.1:9617",
                    "expire": "never"
                }
            ]
        }
    ]
}
```

An empty `"Events": []` means the subscription failed: see
[Troubleshooting](#6-troubleshooting).

**On sipnab**, run it as a server with the REST API, place a call, and ask:

```bash
sudo sipnab -N -d any --hep-listen 127.0.0.1:9060 --hep-allow 127.0.0.1/32 --api 127.0.0.1:8080 'udp port 5060 or udp[8] & 0xc0 = 0x80'
```

The counts under `th_mappings` rise by one per call:

```bash
curl -s http://127.0.0.1:8080/v1/stats | jq -c .th_mappings
```

```json
{"accepted":3,"conflict":0,"duplicate":0,"expired":0,"held":3,"malformed":0,"pending":0,"refused_full":0}
```

The caller's leg names the callee's leg, joined by `mapping`:

```bash
curl -s http://127.0.0.1:8080/v1/dialogs/1-th-docs@example.com/correlated | jq '[.legs[] | select(.method == "mapping") | {call_id, strategy, method, score}]'
```

```json
[
  {
    "call_id": "DLGCH_fl0RBn4tPzA8MAAWMiQgPypeBgE+",
    "strategy": "th_callid_mapping",
    "method": "mapping",
    "score": 100
  }
]
```

The callee's leg reports `th_callid` `mapped`:

```bash
curl -s 'http://127.0.0.1:8080/v1/dialogs/DLGCH_fl0RBn4tPzA8MAAWMiQgPypeBgE+/correlated' | jq '{th_callid, legs: [.legs[] | select(.method == "mapping") | {call_id, strategy, method, score}]}'
```

```json
{
  "th_callid": "mapped",
  "legs": [
    {
      "call_id": "1-th-docs@example.com",
      "strategy": "th_callid_mapping",
      "method": "mapping",
      "score": 100
    }
  ]
}
```

At the end of a run, sipnab logs what the events did:

```text
INFO sipnab::app::batch: Topology hiding: 3 E_SIPNAB_TH_MAP event(s): 3 accepted, 0 duplicate, 0 conflicting, 0 malformed, 0 refused (table full); 0 expired; 3 held now, 0 waiting for their SIP.
```

The other legs in a `/correlated` answer are `timing` guesses about the
other calls, and the filter above drops them.

#### 6. Troubleshooting

The harness caused each row below on purpose with OpenSIPS 4.0.2, except
where the row says otherwise. `GET /v1/hep/senders` gives the
listener's counts, and `GET /v1/stats` gives `th_mappings`.

| Symptom | Cause | Fix |
|---|---|---|
| `accepted` stays `0`, and `/v1/hep/senders` counts the events under `refused_by_reason.event_sender_not_listed` | The listener has no `--hep-allow`. It still starts on a loopback address, or with `--hep-auth` | Add `--hep-allow` with the address OpenSIPS sends from |
| `accepted` stays `0`, and the events count under `refused_by_reason.allowlist` | `--hep-allow` lists other addresses, but not the one OpenSIPS sends from | Add that address. With both on one machine and the subscription on `127.0.0.1`, it is `127.0.0.1` |
| `accepted` rises, `pending` stays above `0`, and the legs do not join | The capture drops the SIP: with `--hep-listen`, `-d` and no filter of your own, the interface takes media only. sipnab says so at startup (`no BPF filter was given, so the interface takes media only`) and at the end of the run (`3 waiting for their SIP`) | Give a filter that keeps the SIP, as in [The sipnab side](#4-the-sipnab-side) |
| Nothing arrives: `packets_received` stays `0` on `/v1/hep/senders`, and the end of the run says `dialog(s) carry an OpenSIPS hidden Call-ID and no secret is configured` | The subscription names an IPv6 address. OpenSIPS takes the first `:` for the port separator, refuses `udp:[2001:db8::1]:9060` with no message at `log_level=3`, and `evi:subscribers` shows `"Events": []` | Give the subscription an IPv4 address |
| The same | The subscription names a port other than the one `--hep-listen` binds | Make the two the same |
| The same | A firewall drops UDP from OpenSIPS to the listener. Not caused in the harness | Allow UDP from OpenSIPS's address to the listener's port |
| `conflict` rises, sipnab logs `conflicts with a mapping already held for one of them; neither joins`, and the callee's leg reports `th_callid` `conflict` | Two events named one Call-ID with different partners. The harness caused it with OpenSIPS 4.0.2 and `th_callid_loop_protection`, when a second INVITE reused a Call-ID with a new From tag: the hidden Call-ID then differs. A second program sending events from an address `--hep-allow` lists causes it too | sipnab joins neither leg on purpose, because it cannot tell which event is right. Check that only OpenSIPS sends from the listed addresses, and that the script raises the event only in the new-INVITE branch. For callers that reuse a Call-ID, [decode the hidden Call-ID](#decode-the-hidden-call-id) instead: the decode also checks the From tag |
| `refused_full` rises, and sipnab logs `the mapping table is full ([sip] th_mapping_max)` | More calls started within `[sip] th_mapping_ttl_secs` than `[sip] th_mapping_max` allows. The harness set `th_mapping_max = 1` and placed three calls: 1 accepted, 2 refused | Raise `[sip] th_mapping_max`, or lower `[sip] th_mapping_ttl_secs` |
| `/v1/hep/senders` counts the events under `refused_by_reason.malformed`, and `th_mappings` stays at `0` | OpenSIPS 3.0 or older, whose `event_datagram` sends the event as text rather than JSON. Checked by sending a datagram in that format to sipnab, not with OpenSIPS 3.0 | [Decode the hidden Call-ID](#decode-the-hidden-call-id) instead |
| `malformed` rises | The datagram is not an `E_SIPNAB_TH_MAP` event naming both Call-IDs. The harness renamed `caller_call_id` in the script. Run sipnab with `SIPNAB_LOG=debug` to see why: here `E_SIPNAB_TH_MAP datagram refused (missing_call_id)`. | Use the key names `caller_call_id` and `callee_call_id`, exactly as in [The OpenSIPS script change](#3-the-opensips-script-change) |

#### What sipnab does with the event

- It reads the event on the HEP listener: a datagram that starts with `{`
  is an event, and one that starts with `HEP3` is HEP. Events come over UDP
  only.
- It accepts an event only from a sender `--hep-allow` lists. An event
  carries no HEP authentication, so `--hep-auth` cannot vouch for it. A
  listener with no `--hep-allow` refuses every event, and counts each under
  the refusal reason `event_sender_not_listed`.
- The two legs join with `method` `mapping` and `strategy`
  `th_callid_mapping`, whichever arrives first: the event or the SIP. The
  callee's leg reports `th_callid` `mapped`.
- A repeated event, as a retransmitted INVITE raises, changes nothing.
- sipnab refuses an event that maps either Call-ID to a different partner. The
  mapping already held for it stops joining too, and the callee's leg
  reports `th_callid` `conflict`. sipnab cannot tell which of the two is
  right, so it joins neither.

#### Counts

The counts are on REST `GET /v1/stats` and the MCP tool `capture_status`
under `th_mappings`, with the fields `accepted`, `duplicate`, `conflict`,
`malformed`, `refused_full`, `expired`, `held` and `pending`. Prometheus has
`sipnab_th_mapping_events_total{outcome}`, `sipnab_th_mappings_expired_total`,
`sipnab_th_mappings_held` and `sipnab_th_mappings_pending`. The terminal
interface's statistics view lists them, and a run ends with a line that
says what the events did.

#### Limits

- sipnab holds at most `[sip] th_mapping_max` mappings (100000), and drops
  one when neither of its legs has been in the store for
  `[sip] th_mapping_ttl_secs` (300). It refuses an event larger than
  `MAX_EVENT_BYTES` (4096) bytes.
- Mappings arrive live, on the listener. sipnab never takes an event from a
  capture, even one that recorded the datagrams, so for a file read with
  `-I` use the decode.
- OpenSIPS sends the event to an IPv4 address only (see
  [Prerequisites](#2-prerequisites)).

### Decode the hidden Call-ID

**OpenSIPS side:** no change. **sipnab side:** a file with the OpenSIPS
secret. This method also works on a capture file.

Put the OpenSIPS `th_callid_passwd` in a file, on one line. Only the account
that runs sipnab may read it: mode `600`, or `640` with that account's group.
Then name the file:

```toml
[sip]
th_callid_secret_file = "/etc/sipnab/th_callid.secret"
# th_callid_prefix = "DLGCH_"   # set this when OpenSIPS sets th_callid_prefix
```

- sipnab reads the file once at startup and never prints or logs the secret.
- It refuses to start when the file is world-readable, is empty or holds a
  NUL byte.
- Only a file can hold the secret. There is no command-line flag or
  environment variable for it.
- Decoding needs a sipnab built with the `tls` feature. Every release
  package has it.

When OpenSIPS keeps its default secret, set
`th_callid_secret = "opensips-default"` instead. The OpenSIPS source
publishes that secret, so it hides nothing. sipnab logs a warning at startup
that says so.

The legs join only when both of these hold:

- the decoded value equals the other leg's Call-ID,
- the two legs have the same From tag.

OpenSIPS does not change tags, so a wrong secret cannot join two legs.

A decoded leg reports `strategy` `th_callid_decoded` and `method` `decoded`
on all of these:

- `--correlate` and `--call-tree`,
- `GET /v1/dialogs/{call_id}/correlated` and `GET /v1/dialogs/{call_id}/tree`,
- the MCP tools `find_correlated` and `get_call_tree`,
- the `sipnab-related-legs` attachment of a vCon export.

In the terminal interface, the call flow's status line says
`Legs: 1 decoded`, and on the hidden leg also `Topology hiding: decoded`.
The extended view (`F4`) draws both legs in one ladder.

For a hidden leg, `--correlate`, REST and MCP also return `th_callid`, which
says what happened:

- `decoded`: the legs joined.
- `no_secret`: sipnab has no secret configured.
- `undecodable`: the secret or the prefix does not decode this Call-ID.
- `unmatched`: the value decoded, but no captured leg has that Call-ID and
  From tag. Either the caller's side was not captured or the secret is
  wrong. A wrong secret that shares bytes with the right one can decode part
  of a Call-ID, so it can show here.

At the end of a run over a capture file, sipnab warns when hidden legs did
not join, with the count and the settings to check. For example, with the
wrong secret:

```text
Topology hiding: 3 hidden Call-ID(s) did not decode to the captured caller leg that has their From tag, so those legs are not joined. Check [sip] th_callid_secret_file and th_callid_prefix against OpenSIPS's th_callid_passwd and th_callid_prefix.
```

The OpenSIPS source uses the same XOR and alphabet in every release from
2.4.11 to 4.0.2. OpenSIPS 4.0 adds `th_callid_loop_protection`, which
appends the caller's From tag before encoding. sipnab decodes both forms,
and checks the appended tag against the From tag.

### Or copy the Call-ID into a header

**OpenSIPS side:** a one-line script change. **sipnab side:** the header's
name. **The header discloses the caller's Call-ID to the callee's side.**

Without the secret, OpenSIPS can carry the caller's Call-ID to the callee in a
header. Inside the script, `$ci` is the caller's Call-ID even with the `C` flag:

```text
if (!create_dialog() || !topology_hiding("C")) {
	send_reply(500, "Internal Server Error");
	exit;
}
append_hf("X-CID: $ci\r\n");
```

Then tell sipnab the header's name:

```toml
[sip]
xcid_headers = ["X-CID"]
```

The legs then join with `method` `header`.

**This header discloses the caller's Call-ID to the callee's side**, which is
part of what topology hiding exists to hide. Use it only when the callee is
inside your own network, or remove the header where the call leaves it. When
the configuration names both the secret and the header, sipnab reports the
decoded match.

### What checks this section

[`harness/th-mapping/e2e.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/e2e.sh)
runs OpenSIPS with
[`harness/th-mapping/opensips.cfg.tmpl`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/opensips.cfg.tmpl),
the complete `opensips.cfg` above, and a live sipnab that captures the
network with the filter above and receives the events on `--hep-listen`. It
places three calls with SIPp, and fails unless REST reports each callee leg
joined to its own caller leg by `mapping`. On 2026-11-03 it passed with
OpenSIPS 4.0.2, 4.0.1 and 3.6.9. It runs the `sudo sipnab` command above with
the test network's interface and addresses, and with `--api` in place of
`--duration 30 --report`, so it can ask REST how each leg joined.

[`tests/th_mapping_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/th_mapping_test.rs)
checks that the complete `opensips.cfg` on this page is that template with
`127.0.0.1:9060` for sipnab's address, line for line, and that the three
blocks of step 3 are in it. It also replays
[`tests/fixtures/th-mapping/opensips-4.0-events.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/th-mapping/opensips-4.0-events.pcap)
into a live listener: events after the SIP and before it, repeats, a
conflict, a listener with no `--hep-allow`, and the end-of-run line.
[`harness/th-mapping/capture.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/capture.sh)
recorded that capture from OpenSIPS 4.0.2, with the template as it was
before it loaded `mi_fifo`, and the JSON datagram above is its first event.

On 2026-11-03 these were also run by hand, against the harness's network:

- the `opensips-cli` commands of step 5, with `opensips-cli` from its
  source repository: `evi:subscribers` on OpenSIPS 4.0.2 and 4.0.1,
  `subscribers_list` on 3.6.9. In the harness the FIFO sits in a directory
  shared with the container, so `-o fifo_file` named that path and
  `-o fifo_reply_dir` the same directory.
- the `curl` commands and the end-of-run line of step 5, on OpenSIPS 4.0.2,
  4.0.1 and 3.6.9.
- OpenSIPS and sipnab on one machine, with the subscription and
  `--hep-allow` on `127.0.0.1`, on OpenSIPS 4.0.2 and 3.6.9.
  `/v1/hep/senders` named the sender `127.0.0.1`. Ports 5060 and 9060 were
  in use on that machine, so the run used others.
- the configuration-file form of step 4, on OpenSIPS 4.0.2.
- a retransmitted INVITE on OpenSIPS 4.0.2: two events, `1 accepted, 1
  duplicate`, and the legs joined.
- every row of the troubleshooting table, on OpenSIPS 4.0.2, except where
  the row says otherwise.

On 2026-11-02, test calls went through OpenSIPS 4.0.2 and 3.6.9 with
[`harness/th-callid/capture.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-callid/capture.sh). Its
OpenSIPS script contains the `append_hf` lines above as shown. The captures
are in `tests/fixtures/th-callid/`, and the tests in
[`tests/th_callid_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/th_callid_test.rs) run sipnab against
them on the command line, REST and MCP, including the warning quoted above.

## When something does not work

- **sipnab reports a line such as `No SIP signaling found, but 839 RTP packets
  across 2 stream(s) were parsed.`** The counts are your run's own.
  - It saw the call's audio, which uses other ports, but none of its SIP.
  - OpenSIPS listens on a port outside 5060-5061, the range sipnab watches by
    default.
  - Give sipnab OpenSIPS's ports with `--portrange`.
