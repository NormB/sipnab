+++
title = "Open the sipnab.com sample call in the browser and in the terminal"
date = 2026-09-01
updated = 2026-10-16
description = "Load the sample call on the sipnab.com analyze page, then open the same capture with sipnab on your own machine: list its dialogs, open it in the terminal interface, and print the report for its one call."

[extra]
kind = "howto"
+++

## In short

sipnab.com offers one sample capture so you can try sipnab without a capture
of your own. The site uses the same file in three places:

- the still picture and the animation on the homepage;
- the "Load a sample call" button on the analyze page;
- the first-steps guide.

This page opens it in the browser, then in sipnab on your machine, and shows
what each step prints.

## Who this is for

Anyone trying sipnab for the first time, or anyone who wants to compare the
browser analyzer's answer with the command-line answer for the same capture.

## Open it in the browser

- Go to the [analyze page](https://sipnab.com/analyze/).
- Press **No capture handy? Load a sample call**.

The page downloads `/demos/sample-call.pcap` and analyzes it in the browser.
The capture does not leave your machine.

## Use the same file in a terminal

The file is in the sipnab repository at
`website/static/demos/sample-call.pcap`. The site serves it at
`https://sipnab.com/demos/sample-call.pcap`. The
[first-steps guide](@/docs/first-cli-triage.md#download-a-capture) shows how
to download it with `curl`.

The commands below run from the root of a sipnab checkout. If you downloaded
the file instead, replace the path with `sample-call.pcap`.

## List what it contains

```bash
sipnab -N -I website/static/demos/sample-call.pcap --report --no-cli-print
```

```text
Call-ID                          From           To             State        Code   Duration   Msgs   PDD      Tags            
-------------------------------------------------------------------------------------------------------------------------
reg-alice-4f2a19@192.0.2.10      alice          alice          Registered   200    0s         4      -        -               
reg-bob-7c3d02@192.0.2.30        bob            bob            Expired      200    14s        8      -        -               
sub-alice-mwi-2b81@192.0.2.10    alice          alice          Active       200    0s         3      -        -               
sub-bob-blf-9e42@192.0.2.30      bob            bob            Pending      202    0s         3      -        -               
sub-alice-pres-5c07@192.0.2.10   alice          alice          Terminated   200    14s        6      -        -               
opt-8b7c02@192.0.2.20            pbx            alice          Completed    200    0s         2      -        -               
call-2c9d47@192.0.2.10           alice          bob            Completed    200    8s         7      0.2s     -               

RTP Streams:
SSRC         PT   Codec    Clock  Source                Destination           Pkts    Lost   Loss%   Jitter   Dur    Kbps   
--------------------------------------------------------------------------------------------------------------------------
0x1a2b3c4d   0    PCMU     8000   192.0.2.10:10000      192.0.2.20:10002      300     0      0.0%    0ms      6s     64     
0x5e6f7a8b   0    PCMU     8000   192.0.2.20:10002      192.0.2.10:10000      300     0      0.0%    0ms      6s     64     
```

The capture holds seven dialogs: two registrations, three subscriptions, one
OPTIONS exchange and one call. The call has two RTP streams, one in each
direction.

## Open it in the terminal interface

```bash
sipnab -I website/static/demos/sample-call.pcap
```

The call list opens with the same seven dialogs. Select a row and press Enter
to see its message flow. Press F1 for the keys, and Esc to quit.

## Print the report for the call

```bash
sipnab -N -I website/static/demos/sample-call.pcap --call-report call-2c9d47@192.0.2.10 --no-cli-print
```

```text
Call Report: call-2c9d47@192.0.2.10
════════════════════════════════════════
Time:       2023-11-14 22:13:25 -> 22:13:33 (8s)
From:       "Alice" <sip:alice@...>
To:         <sip:bob@...>
Result:     Completed (BYE)
Frame:      website/static/demos/sample-call.pcap#19@db3d2ea0ae5df067

Timing:
  PDD:        0.18s
  Setup:      2.42s
  Ring:       2.24s
  Teardown:   0.01s
  Retransmits: 0

SIP Transactions:
  INVITE -> 100 (6ms) -> 180 (180ms) -> 200 (2420ms)
  ACK
  BYE -> 200 (8468ms)

Media Streams:
  RTP 192.0.2.10->192.0.2.20 PCMU SSRC=0x1a2b3c4d pkts=300 jitter=0ms loss=0.0% mos=4.36 R=90.8
  RTP 192.0.2.20->192.0.2.10 PCMU SSRC=0x5e6f7a8b pkts=300 jitter=0ms loss=0.0% mos=4.36 R=90.8

Issues Detected: None
```

The callee answered after 2.42 seconds and ended with a BYE. Both audio
streams lost no packets.

## Terms used here

- **Capture (pcap)**: a file holding recorded network packets.
- **SIP**: the signaling protocol that sets up and ends phone calls.
- **Dialog**: sipnab's record of one SIP conversation, such as a call, a
  registration or a subscription.
- **RTP**: the protocol that carries the audio of a call.
- **PDD**: post-dial delay, the time from the INVITE to the first ringing
  response.
- **BYE**: the SIP request that ends a call.

## Related guides

- [Triage a capture from the command line](@/docs/first-cli-triage.md)
- [List the calls](@/docs/first-cli-triage.md#list-the-calls)
- [Explain one call](@/docs/first-cli-triage.md#explain-one-call)
