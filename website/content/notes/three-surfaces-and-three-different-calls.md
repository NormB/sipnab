+++
title = "Three surfaces, three different calls"
date = 2026-09-01
description = "The homepage still, the animation it swaps to, and the sample /analyze offers were three separate captures. Every asset was valid, every gate was green, and no diff put the three facts side by side."

[extra]
kind = "postmortem"
+++

A visitor lands on sipnab.com, watches the terminal animation on the homepage,
clicks through to `/analyze`, and presses "Load a sample call".

Until 2026-09-01 those were three different captures:

| surface | capture |
|---|---|
| the hero still | `register-invite-reinvite-bye.pcap` |
| the animation it swaps to | `sip-rtp-g711.pcap` |
| the sample `/analyze` fetches | `demos/sample-call.pcap` |

The still and the animation come from two recordings of two different calls, so
the page appears to cut between them as the animation loads. Then the tool the
page is demonstrating hands the visitor a third call.

## Everything was valid

This is the part worth being precise about, because it decides what kind of fix
is possible.

Every asset existed. Every `.tape` rendered. Every capture parsed. Every link
resolved. Every gate in the repository was green, and correctly so — nothing
violated a rule.

What was wrong was an **agreement** between three files, and nothing expressed
it. The three facts live in a `.tape`, an `.html` template and a `.js` fetch.
No diff puts them side by side, and no reviewer reading any one of the three
sees anything out of place.

A half-fix had already shipped for exactly that reason. On 2026-08-31 somebody
pointed the hero still at a new capture and left the animation pointing at the
old one, because the two values live in different files and only one of them
was on screen.

## Expressing the agreement

`tests/demo_capture_agreement_test.rs` is seven tests and reads three files.
The two that matter state the agreement directly:

```rust
assert!(
    shown.ends_with(&offered) || offered.ends_with(&shown),
    "the homepage animation shows {shown} ({tape_name}) and /analyze offers \
     {offered}. A visitor who watches the video and clicks through is handed \
     a different call than the one they just saw."
);
```

and

```rust
assert_eq!(
    still, anim,
    "the hero still comes from {still} and the animation it swaps to comes \
     from {anim} ({anim_tape}). The page would cut between two different \
     calls as the animation loads."
);
```

Both messages describe what a **visitor** experiences rather than which
constant disagrees with which. That matters when somebody hits this in six
months and has to decide whether it is a real problem.

## Reading a tape honestly

Getting the capture out of a `.tape` needs care, and the helper says why:

> The `-I` argument and nothing else: a tape may mention other paths in its
> comments, and a scan that matched those would report a capture the recording
> never opened.

A scanner that reports the wrong file confidently is worse than no scanner. It
would have made the three surfaces look like they agreed.

Two more of the seven cover the failure that reports nothing at all. A tape
naming a moved or deleted capture still renders: sipnab prints an error, and
VHS faithfully records the error. The result is a plausible-looking demo of
nothing, and only a person looking at the output would notice.

## The part that is about people

That gap is also why somebody reported the video as updated while the shipped
asset was still the old one.

There was nothing to check against except memory. The assets were all valid,
the tapes had all rendered, and the only thing that could have said "these
three do not agree" was somebody remembering to compare three files by hand
after the fact.

A claim with nothing to verify it against is a claim about what somebody
intended, and it reaches the person listening as a claim about what shipped.
The tests are what makes that difference visible before the sentence gets
written.

## Worth stealing

Look for facts that appear in more than one file and describe one thing. They
do not show up in review, they do not show up in a diff, and they do not break
anything until a user notices the mismatch.

The gate for that class is cheap — three file reads and an equality — and its
value is entirely in existing, because the alternative is a human comparing
three files every time any one of them changes.
