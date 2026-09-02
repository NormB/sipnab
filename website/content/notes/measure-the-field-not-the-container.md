+++
title = "The test measured the container, not the field it named"
date = 2026-08-28
description = "A macOS job ran red for four commits over a 1024-byte limit. The cap held at 327 bytes on both platforms, and the string the assertion measured was the JSON around the field."

[extra]
kind = "postmortem"
+++

`Check (macos-latest)` had run red for four commits. Each red run got read as
the feature-matrix failures already known about, rather than as a question
about which job had failed.

Bisecting settled it: green through v0.5.129, red from one particular batch
onward. Then reading the failure properly settled the rest, and the answer was
that the test was wrong and the code was right.

## What the assertion actually measured

`an_oversized_header_is_bounded_in_the_response` sends a 4 KiB `User-Agent`
through the MCP surface and checks the size of the value reaching an agent.
sipnab caps a field at `MAX_FIELD_BYTES`, currently 256, so a header cannot
spend an agent's context.

The test collected every string in the response, found the first one containing
the payload, and asserted its length.

That string was the **enclosing message JSON**. What drives its size is the
capture path and the other headers, not the field under test.

| platform | the string it measured | verdict |
|---|---:|---|
| Linux | 992 bytes | passed a 1024-byte limit |
| macOS | 1036 bytes | failed |

The field itself measured 327 bytes on both.

The temp directory on macOS is longer, so the capture path inside the JSON is
longer, so the container crossed a round number. Nothing about the cap changed.
Nothing about the cap was ever under test.

The green Linux run was as accidental as the red macOS one. Four commits ran
red on a test that had never been about the thing it named.

## Selecting the value instead of its container

Fencing applies per value, so a fenced string is a value and not a container.
That gives a way to select the right string:

```rust
let ua = strings
    .iter()
    .filter(|s| s.contains("UUUU"))
    .find(|s| s.starts_with(sipnab::mcp::shape::UNTRUSTED_OPEN))
```

And the ceiling derives from the constant rather than from a round number:

```rust
let ceiling = sipnab::mcp::shape::MAX_FIELD_BYTES + 128;
```

so raising the cap cannot silently widen what the test accepts. A literal
`1024` is a number that agrees with the code today and drifts from it the first
time anybody tunes the cap.

## Eight tests for the defect class

The interesting part is not the fix. It is what a single corrected assertion
leaves uncovered, because the same mistake has several shapes.

**The payload appears in more than one string, and exactly one of them carries
a fence.** That ambiguity is what made the original assertion meaningless. If
a future response ever carries the value in exactly one place, this test fails
rather than quietly passing, and somebody revisits the suite.

**The container is larger than the field.** Otherwise the two verdicts do not
differ and the distinction this suite rests on does not exist.

**The field's size does not move when only the capture path grows** — with a
non-vacuity probe asserting the container **does** move. Without that probe the
equality is trivially true and exercises nothing. This one states the actual
platform split directly: nothing about a capture's filesystem path should be
able to move a field's size.

**The capped field is a fraction of the 4 KiB input, and not far under the cap
either.** If something other than the cap were truncating it, the suite would
be back to measuring the wrong thing.

**A cut value says so.** A silently shortened field is indistinguishable from
a short one, and an agent cannot tell "this is the value" from "this is the
first 256 bytes of the value".

**Capping does not strip the closing fence**, which would leave attacker text
outside it — the exact failure the fence exists to prevent.

**No string carries an unbounded run of the payload**, whatever any enclosing
object's total size happens to be. The original test asked whether one string
was small enough. This asks the question that one was trying to ask.

**The fixture reaches the response at all.**

Removing the field cap fires four of them.

## Somebody chose the input, and said why

The 4 KiB payload has a comment beside it, and the reasoning is worth copying:

> Deliberately under `parser::DEFAULT_MAX_HEADER_LINE_LEN` (8 KiB): past that
> the parser rejects the whole message, and a test that measured a REJECTED
> message would report the field cap working while it was never reached.

A test input large enough to trip a different limit tests that limit instead,
and reports success for the one it names. 4 KiB is sixteen times the field cap
and still parses, which is the case that matters.

## Worth stealing

When an assertion measures a size, check that it measures the thing it names.
Searching a response for "the string containing X" finds a container about as
often as it finds a value, and the two have different sizes for reasons
unrelated to the code under test.

And read the red. Four commits went by with a failing job read as a failure
already known about. Bisecting took minutes once somebody asked which job had
failed, rather than assuming.
