+++
title = "Seventy words somebody thought of"
date = 2026-09-01
description = "A gate had enforced US English since 0.5.105 by checking a list. It caught the word written that morning and had never heard of 67 British forms already in the tree."

[extra]
kind = "postmortem"
+++

sipnab's documentation, comments, test names and website copy are US English,
and a gate has said so since 0.5.105. It works by checking a list of about
seventy words somebody thought of.

On 2026-09-01 it did its job. Somebody wrote a British spelling in a comment,
the gate caught it minutes later, and the commit stopped. That is the system
working.

It is also the whole problem, and the reason takes one sentence: a list can
only ever catch a word already on it.

## What the list had never heard of

Measured the same day, across the tracked tree: **67 distinct British forms in
95 files** that the list did not name. The British spellings of `containerized`,
`synthesized`, `unrecognized`, `sanitized`, `materializing`, `pseudonymizing`
and `uninitialized` were all among them. This page prints the US forms, because
the gate that came out of this reads the page.

Every one of those had passed every gate this repository has, for as long as it
had sat there. Some of them shipped to sipnab.com.

Nobody had done anything wrong. The list grows one embarrassment at a time,
which is exactly the growth rate an allowlist of "words somebody thought of"
can sustain. The failure is structural, and adding five more words to the list
would have reproduced it.

## Naming the exceptions is tractable, naming the words is not

The replacement in `tests/us_spelling_test.rs` enforces the morphology instead:

```rust
const SUFFIXES: &[(&str, &str)] = &[
    ("isation", "ization"),
    ("isable", "izable"),
    ("ising", "izing"),
    ("ised", "ized"),
    ("ises", "izes"),
    ("ise", "ize"),
    ("ysing", "yzing"),
    ("ysed", "yzed"),
    ("yses", "yzes"),
    ("yse", "yze"),
];
```

Ten pairs and a bounded exception list, against a vocabulary that has no end.
The exceptions are the words where those letters are not a suffix at all —
`precise`, `otherwise`, `exercise`, `enterprise`, `promise`, `noise`, and
`disable`, which simply ends in `-able` and appears on nearly every command
line this project documents.

That exception list came out of an error worth recording. The first version
exempted `raise` and not `raising`, so the gate reported `raising -> raizing`.
A gate that invents a word teaches the reader to distrust it, and one
distrusted gate is how every later hit gets waved through. Base forms are not
enough. The inflections need listing too.

## Two directions, or the rule proves nothing

A spelling rule has an obvious test and a less obvious one, and only the pair
means anything:

```rust
fn a_british_word_no_list_names_is_still_caught() { ... }
fn the_us_spelling_of_each_is_accepted() { ... }
```

The first asserts that nine constructed British words trip the rule. Without
the second, "flag everything ending in a vowel" satisfies it completely.

Two more tests hold the exception lists honest in the direction people forget.
Every exception has to be a word the tree actually uses, because an exception
matching nothing is either a typo or a hole somebody cut in advance. And every
excluded path has to exist and say why the scan cannot read it, because an
exclusion that outlives its path silently widens.

## The file that contains no British spelling

A spelling gate has an awkward property: writing its fixtures the obvious way
makes the file full of the thing it forbids, and then the file needs an
exemption from itself.

The old list-based gate in `docs_drift_test.rs` accepts that trade and appears
on the exclusion list with the reason spelled out — it lists the words it
forbids, so it necessarily contains all of them.

The new file refuses the trade. Fixtures come out of a builder:

```rust
fn british_form(stem: &str, suffix: &str) -> String {
    format!("{stem}{suffix}")
}
```

so `british_form("container", "ised")` produces the word at run time and no
British spelling appears in the source. The file needs no exemption, and an
exemption is a permanent hole in exactly the place a misspelling would go to
hide.

The same trick covers the one contract that keeps its British spelling. The
`unanalysed_*` keys in `GET /v1/stats` and in MCP's `capture_status` are wrong
and they are also a wire contract that consumers read by name, so correcting
them is a deprecation with a window rather than a sweep. They come back as
whole **tokens**, assembled at run time, so the bare word stays banned in
prose. A separate test asserts a wire exemption matches only the whole token.
That key with `_v2` appended is a new name somebody just invented, and it takes
the correct spelling like anything else.

## What the rule still cannot see

The morphological rule covers the `-ise/-isation/-yse` family and nothing else.
The `-our`, `-ogue` and doubled `-lled` classes are not suffix cases, and no
rule of this shape reaches them. `SPELL1` in the backlog records that openly,
with the 45 identifiers those classes hide in and why closing them needs the
list **plus** a way to split identifiers into words, rather than a new suffix
pair.

So both gates stay. One test asserts the rule is a superset of the old list for
the suffix class, because otherwise somebody could drop a word from the list in
good faith and make it legal again.

## Worth stealing

If a gate enforces a rule by enumerating its violations, ask how the
enumeration grows. If the answer is "somebody notices", the gate measures
attention rather than the tree.

And when the rule replaces a list, keep the list. The two overlap, the overlap
needs a test, and the part the list covers alone is the part worth writing
down as still open.
