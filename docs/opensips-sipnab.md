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

Every block on this page ran as written, in order, on 2026-10-01, with sipnab
0.5.198 from its release package.

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

## When something does not work

- **sipnab reports `No SIP signaling found, but ... RTP packets across ...
  stream(s) were parsed`.**
  - It saw the call's audio, which uses other ports, but none of its SIP.
  - OpenSIPS listens on a port outside 5060-5061, the range sipnab watches by
    default.
  - Give sipnab OpenSIPS's ports with `--portrange`.
