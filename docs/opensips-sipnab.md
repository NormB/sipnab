# Run sipnab beside OpenSIPS

sipnab reads the SIP that passes through OpenSIPS off the wire, so it needs
nothing from OpenSIPS: no module, no configuration change. On the OpenSIPS
machine it sees both legs of every call, the caller's side into OpenSIPS and
OpenSIPS's side out to the callee, and puts them together into one call.

This guide adds sipnab to the OpenSIPS proxy from
[Use OpenSIPS as your voice stack's SIP server](opensips.md), installed from
the packages or built from source.

## Tested on

Every command on this page ran as written, in order, on 2026-09-27, with
sipnab 0.5.193 from its release package, on the machines
[the OpenSIPS guide](opensips.md) had set up: Debian 13 (kernel 6.12.63) with
OpenSIPS built from source, and Ubuntu 24.04.5 (kernel 6.8.0) with OpenSIPS
both from the packages and from source. The section with Kamailio on the same
machine ran on Ubuntu 24.04.5. The examples use `192.0.2.10` as the machine's
address.

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

## 2. Watch a call through OpenSIPS

Start sipnab on every interface for 30 seconds, printing each SIP message as
it passes and a report of the calls at the end:

```bash
sudo sipnab -N -d any --duration 30 --report
```

While it runs, place a test call from a second terminal, as in
[step 3 of the OpenSIPS guide](opensips.md#3-place-a-test-call):

```bash
# Run all of these, in order.
cd ~/sipp
sipp -sn uas -i 127.0.0.1 -p 5070 -m 1 -bg
sipp -sf uac_rr.xml 192.0.2.10:5060 -i 192.0.2.10 -p 5080 -m 1 -d 1000 -timeout 20s
```

sipnab prints every message OpenSIPS relays twice, once on each leg: the
caller's `INVITE` to OpenSIPS at `192.0.2.10:5060`, then OpenSIPS's copy of it
to the callee at `127.0.0.1:5070`, and the same for the replies and the `BYE`.
OpenSIPS's own `100 Trying` goes to the caller alone. When the 30 seconds are
up, the report lists the call once, as `Completed`, with 13 messages from both
legs.

For the same view in a terminal interface, which updates as calls happen, run
`sudo sipnab -d any` without `-N` and without `--duration`.

## With Kamailio on the same machine

With OpenSIPS on 5060 and Kamailio on 5062, as
[OpenSIPS and Kamailio on one machine](opensips.md#opensips-and-kamailio-on-one-machine)
sets them up, give sipnab both ports:

```bash
sudo sipnab -N -d any --duration 30 --report --portrange 5060-5062
```

A call through each proxy then appears in the report, one row per call.

## When something does not work

- **sipnab reports `No SIP traffic found`.** OpenSIPS listens on a port
  outside 5060-5061, the range sipnab watches by default. Give sipnab
  OpenSIPS's ports with `--portrange`.
