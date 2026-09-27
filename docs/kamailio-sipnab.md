# Run sipnab beside Kamailio

sipnab reads the SIP that passes through Kamailio off the wire, so it needs
nothing from Kamailio: no module, no configuration change. On the Kamailio
machine it sees both legs of every call, the caller's side into Kamailio and
Kamailio's side out to the callee, and puts them together into one call.

This guide adds sipnab to the Kamailio proxy from
[Use Kamailio as your voice stack's SIP server](kamailio.md).

## Tested on

Every command on this page ran as written, in order, on 2026-09-27, with
sipnab 0.5.193 from its release package, on the Debian 13 (kernel 6.12.63) and
Ubuntu 24.04.5 (kernel 6.8.0) machines that [the Kamailio guide](kamailio.md)
had set up. The section with OpenSIPS on the same machine ran on Debian 13. The
examples use `192.0.2.10` as the machine's address.

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
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -m 1 -d 1000 -timeout 20s
```

sipnab prints every message Kamailio relays twice, once on each leg: the
caller's `INVITE` to Kamailio at `192.0.2.10:5060`, then Kamailio's copy of it
to the callee at `127.0.0.1:5070`, and the same for the replies and the `BYE`.
Kamailio's own `100 Trying` goes to the caller alone. When the 30 seconds are
up, the report lists the call once, as `Completed`, with 13 messages from both
legs.

For the same view in a terminal interface, which updates as calls happen, run
`sudo sipnab -d any` without `-N` and without `--duration`.

## With OpenSIPS on the same machine

With OpenSIPS on 5060 and Kamailio on 5062, as
[OpenSIPS and Kamailio on one machine](kamailio.md#opensips-and-kamailio-on-one-machine)
sets them up, give sipnab both ports:

```bash
sudo sipnab -N -d any --duration 30 --report --portrange 5060-5062
```

A call through each proxy then appears in the report, one row per call.

## When something does not work

- **sipnab reports `No SIP traffic found`.** Kamailio listens on a port
  outside 5060-5061, the range sipnab watches by default. Give sipnab
  Kamailio's ports with `--portrange`.
