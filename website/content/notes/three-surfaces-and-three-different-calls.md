+++
title = "The sipnab.com homepage demos and the /analyze sample showed different calls"
date = 2026-09-01
updated = 2026-10-11
description = "Why the homepage picture, the homepage animation and the sample call on the /analyze page did not all come from one capture until 0.5.142, and the test that now keeps them on one capture."

[extra]
kind = "postmortem"
+++

## In short

The sipnab.com homepage shows a still picture of sipnab, which changes to an
animation once the animation has loaded. The site's `/analyze` page offers a
sample call to try. Until 2026-08-31 these three came from three different
captured calls, so a visitor saw the picture change to a different call and
was then offered a third. All three now use one capture, and a test fails if
they ever differ again.

## What happened

A visitor's path through the site is: open the homepage, watch the animation,
go to `/analyze`, and press "No capture handy? Load a sample call". Each of
these comes from a capture file (a recording of network traffic):

- `demos/hero.tape` records the homepage still picture;
- `demos/01-intro.tape` records the animation that replaces it;
- the `/analyze` sample is the file `website/static/demos/sample-call.pcap`,
  which `website/static/js/analyze.js` downloads.

The `.tape` files are scripts for VHS, a program that runs terminal commands
and records the screen. Each script runs `sipnab -I <capture>`.

Before 2026-08-31, `hero.tape` ran sipnab on
`tests/pcap-samples/register-invite-reinvite-bye.pcap`, `01-intro.tape` ran it
on `tests/pcap-samples/sip-rtp-g711.pcap`, and `/analyze` offered
`sample-call.pcap`. The picture and the animation showed two different calls,
and the sample was a third.

On 2026-08-31 commit 70ec075d (first included in v0.5.140) moved the still
picture to `sample-call.pcap`. It did not change the animation, which a
different file sets, so from then until 2026-09-01 the picture and the sample
agreed and the animation did not.

On 2026-09-01 commit a9aaf57a (first included in v0.5.142) moved the animation
to `sample-call.pcap` as well.

## Why it happened

No test compared the three capture names. The requirement that all three
show the same call was not written down anywhere a test could read. The facts
live in separate files: the two `.tape` scripts name the captures they record,
the `index.html` template chooses which recordings the homepage shows, and
`analyze.js` names the sample. A change to one of these files does not show
the others.

## What changed

All three now use `website/static/demos/sample-call.pcap`. Both `.tape` files
contain this line:

```text
Type "sipnab -I website/static/demos/sample-call.pcap"
```

`tests/demo_capture_agreement_test.rs` (added in a9aaf57a) reads the
homepage template, every `.tape` file under `demos/` and `analyze.js`, and
fails when:

- the animation's capture differs from the `/analyze` sample
  (`the_homepage_animation_and_the_analyze_sample_use_one_capture`);
- the still picture's capture differs from the animation's
  (`the_hero_still_and_the_hero_animation_use_one_capture`);
- a `.tape` file names a capture that does not exist, or one that is not
  committed to the repository
  (`every_demo_tape_drives_a_capture_that_exists`,
  `no_demo_tape_drives_an_uncommitted_capture`). Given a capture that does
  not exist, sipnab prints an error such as
  `-I/--input: 'tests/pcap-samples/does-not-exist.pcap' does not exist` and
  exits, so a script that names a missing capture records that error instead
  of a call.

The test reads the capture name only from the argument after `-I`, so a path
mentioned in a comment in a `.tape` file is not mistaken for the capture.

## What you can check yourself

The sample call the site offers is in the repository. This lists what it
contains (seven SIP dialogs, one of them a call with two RTP streams):

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

The site serves the same file at `https://sipnab.com/demos/sample-call.pcap`, and
the first-steps guide uses it.

## Terms used here

- **Capture (pcap)**: a file holding recorded network packets.
- **SIP**: the signaling protocol that sets up and ends phone calls.
- **Dialog**: sipnab's record of one SIP conversation, such as a call or a
  registration.
- **RTP**: the protocol that carries the audio of a call.
- **VHS**: a program that runs a script of terminal commands and records the
  screen as an image or animation.
- **`.tape` file**: a VHS script.
- **Template**: the file the site generator turns into a web page.
- **Test**: an automated check that runs on every build and fails when the
  rule it describes stops holding.

## Related guides

- [Download a capture (uses the same sample call)](@/docs/first-cli-triage.md#1-download-a-capture)
- [List the calls](@/docs/first-cli-triage.md#2-list-the-calls)
