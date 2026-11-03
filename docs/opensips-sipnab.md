# Run sipnab beside OpenSIPS

sipnab reads the SIP that passes through OpenSIPS off the wire. So it needs
nothing from OpenSIPS: no module, no configuration change.

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

There are three ways to tie the legs exactly.

### Decode the hidden Call-ID

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

### Have OpenSIPS send the mapping

OpenSIPS knows both Call-IDs: `$ci` is the caller's, and
`$TH_callee_callid` is the one it writes on the callee's leg. With the
`event_datagram` module, the script sends sipnab one small UDP datagram per
call naming both. This needs no secret, and the SIP is still what sipnab
captures.

Load the module, and subscribe sipnab's HEP listener to the event once at
startup:

```text
loadmodule "event_datagram.so"
```

```text
startup_route {
	subscribe_event("E_SIPNAB_TH_MAP", "udp:127.0.0.1:9060");
}
```

Then raise the event right after `topology_hiding("C")` in the request
route:

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

OpenSIPS sends a JSON-RPC 2.0 notification:

```json
{"jsonrpc":"2.0","method":"E_SIPNAB_TH_MAP","params":{"callee_call_id":"DLGCH_fl0RBn4kMSMPFR0PPjk8NmETCgM-","caller_call_id":"1-th-map@example.com"}}
```

Run sipnab with `--hep-listen` on the address the script names, and list
OpenSIPS's address in `--hep-allow`. Give a capture filter that keeps the
SIP, as here:

```bash
sudo sipnab -N -d any --hep-listen 127.0.0.1:9060 --hep-allow 127.0.0.1/32 --duration 30 --report 'udp port 5060 or udp[8] & 0xc0 = 0x80'
```

The filter matters. With `--hep-listen` as well as `-d` and no filter of
your own, the interface takes media only, because sipnab expects a HEP
mirror to deliver the signaling, and taking it off the wire too would count
every message twice. Here the SIP is on the wire, so the filter keeps UDP
port 5060 and RTP. sipnab prints a notice at startup when it sees
`--hep-allow` with that default filter.

What sipnab does with the event:

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
- sipnab holds at most `[sip] th_mapping_max` mappings (100000), and drops
  one when neither of its legs has been in the store for
  `[sip] th_mapping_ttl_secs` (300). It refuses an event larger than
  `MAX_EVENT_BYTES` (4096) bytes.

The counts are on REST `GET /v1/stats` and the MCP tool `capture_status`
under `th_mappings`, with the fields `accepted`, `duplicate`, `conflict`,
`malformed`, `refused_full`, `expired`, `held` and `pending`. Prometheus has
`sipnab_th_mapping_events_total{outcome}`, `sipnab_th_mappings_expired_total`,
`sipnab_th_mappings_held` and `sipnab_th_mappings_pending`. The terminal
interface's statistics view lists them, and a run ends with a line that
says what the events did.

Mappings arrive live, on the listener. A capture file read with `-I` holds
no events, so for a file use the decode.

OpenSIPS's `event_datagram` sends UDP to an IPv4 address only: its source
passes `sizeof(struct sockaddr_in)` to `sendto`. Give the subscription an
IPv4 address.

### Or copy the Call-ID into a header

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

On 2026-11-03,
[`harness/th-mapping/e2e.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/e2e.sh)
ran OpenSIPS 4.0.2, 4.0.1 and 3.6.9 with the event lines above, and a live
sipnab capturing the network with the filter above and receiving the events
on `--hep-listen`. It placed three calls with SIPp, and REST reported each
callee leg joined to its own caller leg by `mapping`. The script's OpenSIPS
lines are the ones above, character for character. The capture
[`tests/fixtures/th-mapping/opensips-4.0-events.pcap`](https://github.com/NormB/sipnab/raw/main/tests/fixtures/th-mapping/opensips-4.0-events.pcap), recorded by
[`harness/th-mapping/capture.sh`](https://github.com/NormB/sipnab/blob/main/harness/th-mapping/capture.sh),
holds those calls and the events OpenSIPS 4.0.2 sent.
[`tests/th_mapping_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/th_mapping_test.rs)
replays it into a live listener: events after the SIP and before it,
repeats, a conflict, a listener with no `--hep-allow`, and the end-of-run
line. The script runs the `sudo sipnab` command above with the test
network's interface and addresses, and with `--api` in place of
`--duration 30 --report`, so it can ask REST how each leg joined.

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
