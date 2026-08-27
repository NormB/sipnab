+++
title = "sipnab recorded every successful call as a failure"
date = 2026-08-27
description = "sipnab typed its vCon dialog objects `incomplete`, a value the draft reserves for calls that never reached conversation. The reasoning behind it was local, careful, and wrong in a way no test could see."
+++

Until 0.5.128, every vCon container sipnab produced for a call that answered
claimed the call never reached conversation at all.

Not as a bug in an edge case. As the ordinary output, on the majority path, for
about three releases.

## The value that looked correct

A vCon Dialog Object carries a `type` from a closed set of five:
`recording`, `recording-set`, `text`, `transfer`, `incomplete`. A
signaling-only capture — one where the operator did not retain media, which is
the normal privacy-conscious configuration — has no audio to offer. So which
value describes an object carrying nothing?

Four of the five promise content. The draft is explicit:

<!-- vale off -->
> A dialog of type "incomplete", "transfer" or "recording-set" MUST NOT have
> Dialog Content.
<!-- vale on -->

`incomplete` is on the no-content list. The object has no content. The
reasoning takes about four seconds and it is wrong, because the same section
says what `incomplete` MEANS:

<!-- vale off -->
> In the "incomplete" case the call or conversation failed to be setup to the
> point of exchanging any conversation.
<!-- vale on -->

`incomplete` does not mean "this object is empty". It means the call never
happened. Reaching for it because of the content rule and inheriting the
semantics by accident is the whole defect.

## Why nothing caught it

The tests were not weak. One test asserted the object carried the type
`incomplete`, and it passed, because the code did what the test said. The test
encoded the same mistake as the code — written in the same hour, by the same
reasoning, about the same paragraph.

That is the failure mode worth naming. A test written from the implementation's
premise cannot find a wrong premise. It can only confirm that the
implementation is consistent with itself, which it always is.

What eventually surfaced it was reading §4.3.1 as prose, in full, rather than
grepping it for the rule at hand.

## The part that made it durable

A container outlives the process that wrote it. Read six months later beside a
switch's call-detail record showing a connected ninety-second conversation, a
container claiming the call never began is the artifact that looks
wrong. The CDR is right. The claim it contradicts is the one nobody has any
reason to doubt, because it arrives in a standard format and looks
authoritative.

The object also omitted `disposition`, which §4.3.1 makes mandatory on an
incomplete dialog — because no failure had occurred, so there was no reason to
name. So the container broke a MUST *and* stated something false, and the
second was the expensive half.

## No value was available

The obvious fix is to pick a different type. There isn't one.

* `recording` and `text` promise content the container does not hold. Worse
  than imprecise: a conserver chain link that selects `type == "recording"` and
  reads `dialog["url"]` raises, and the conserver dead-letters the whole
  container rather than the one step.
* `recording-set` requires a `recordings` member naming members that do not
  exist.
* `transfer` asserts a transfer that did not occur.
* `incomplete` with a disposition invents a failure reason; six values are
  defined and every one of them describes a failure.

Nor is there a value meaning "not observed". The disposition set admits six values, all
entirely about failure.

## The draft already answered it

Section 4.3, one paragraph above the type definitions:

<!-- vale off -->
> There are situations when no information is available for a dialog either
> initially or over the entire life of the vCon and yet it is known that the
> dialog occurred. […] In such situations, it is possible to have a Dialog
> Object with no parameters in it.
<!-- vale on -->

An object that names no type at all. And that sentence is not incidental
drafting — it is a working-group decision. Issue #20 on the draft's repository
asks exactly this question, and closes with: *"IETF 124 WG discussion agreed
upon using an empty Dialog object: {}"*.

So the answer existed, a meeting settled it, and the editor put it in the
document.

## And the schema in the same document forbids it

```json
"required": ["type", "start"],
```

An empty Dialog Object fails validation twice over. The shape the working group
agreed on is the one shape the bundled schema rejects.

sipnab now follows the prose: an object carrying no content and reporting no
observed failure names no type, and `incomplete` now covers only a final
response the capture actually saw fail. The vendored schema carries a one-line
deviation with the reasoning written into a `$comment` beside it, and a test
asserts that deviation is present and is the only one — so re-vendoring the
schema from the draft, which looks like housekeeping, lands on a test that
explains why it would break every signaling-only export.

## What we would tell another implementer

Read the definition of a value, not just the rule you are trying to satisfy.
The content constraint and the semantics were one paragraph apart, and taking
the first without the second produced a container that lied about every call it
described.

And when a specification's prose and its schema disagree, that is worth
reporting even when your own case has a workaround. The prose was right, it
recorded a decision somebody made deliberately, and the schema quietly undid
it.
