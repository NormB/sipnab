# Run sipnab beside Kamailio

sipnab reads the SIP that passes through Kamailio off the wire, so it needs
nothing from Kamailio: no module, no configuration change. On the Kamailio
machine it sees both legs of every call, the caller's side into Kamailio and
Kamailio's side out to the callee, and puts them together into one call.

This guide adds sipnab to the Kamailio proxy from
[Use Kamailio as your voice stack's SIP server](kamailio.md).

## Tested on

Every block on this page ran as written, in order, on 2026-10-01, with sipnab
0.5.198 from its release package, on the Debian 13 (kernel 6.12.63) and Ubuntu
24.04 (kernel 6.8.0) machines that [the Kamailio guide](kamailio.md) had set
up, alone and beside OpenSIPS. The test calls carried audio, and the terminal
interface showed each call on one row. On both, causing the fault under [When
something does not work](#when-something-does-not-work) produced the message it
quotes. The examples use `192.0.2.10` as the machine's address.

## 1. Install sipnab

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

## 2. Watch a call through Kamailio

Start sipnab on every interface for 30 seconds, printing each SIP message as
it passes and a report of the calls at the end:

```bash
sudo sipnab -N -d any --duration 30 --report
```

While it runs, place a test call from a second terminal, as in
[step 3 of the Kamailio guide](kamailio.md#3-place-a-test-call):

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -rtp_echo -m 1 -bg
sudo sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -s echo -m 1 -timeout 90s
```

sipnab prints every message Kamailio relays twice, once on each leg: the
caller's `INVITE` to Kamailio at `192.0.2.10:5060`, then Kamailio's copy of it
to the callee at `127.0.0.1:5070`, and the same for the replies and the `BYE`.
Kamailio's own `100 trying -- your call is important to us` goes to the caller
alone. When the 30 seconds are up, the report lists the call once, as
`Completed`, with 13 messages from both legs. Below it, an `RTP Streams:` table
holds the call's audio, which goes straight between the caller and the callee
and never through Kamailio: the caller's 236 `PCMA` packets and 10
`telephone-event` (DTMF) packets, and the same again coming back from the
callee's echo, four streams in all.

For the same view in a terminal interface, which updates as calls happen, run
`sudo sipnab -d any` without `-N` and without `--duration`. It lists the call on
one row, `Completed`, with the same 13 messages.

## With OpenSIPS on the same machine

With OpenSIPS on 5060 and Kamailio on 5062, as [OpenSIPS and Kamailio on one
machine](kamailio.md#opensips-and-kamailio-on-one-machine) sets them up, give
sipnab both ports:

```bash
sudo sipnab -N -d any --duration 30 --report --portrange 5060-5062
```

A call through each proxy then appears in the report, one row per call. The
two test calls send their audio from the same ports with the same RTP SSRC, so
the `RTP Streams:` table counts both calls' audio as one stream per direction
and codec: 472 `PCMA` packets each way, not two streams of 236 for each call.

## When something does not work

- **sipnab reports `No SIP signaling found, but ... RTP packets across ...
  stream(s) were parsed`.** It saw the call's audio, which uses other ports,
  but none of its SIP: Kamailio listens on a port outside 5060-5061, the range
  sipnab watches by default. Give sipnab Kamailio's ports with `--portrange`.
