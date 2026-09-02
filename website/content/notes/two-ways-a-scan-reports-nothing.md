+++
title = "Two ways a scan reports nothing"
date = 2026-09-01
description = "A regex sweep declared the tree clean and missed fourteen spellings. The gate that replaced it reported twenty passing tests while its own file was invisible to it. Neither failure looks any different from a pass."

[extra]
kind = "postmortem"
+++

Fixing the [US-English gate](@/notes/seventy-words-somebody-thought-of.md)
produced two separate incidents in one afternoon, and both have the same shape:
a scan that reported zero for a reason unrelated to the tree it was reading.

A scan reporting zero is indistinguishable from a clean tree. That is the whole
hazard, and it does not announce itself.

## One: `\b` cannot see inside `snake_case`

The sweep that measured the damage was a regex over the tracked tree, matching
each British form with a word boundary at each end. It reported the tree clean
after the corrections landed.

Fourteen spellings survived it.

`\b` sits between a word character and a non-word character. In every regex
flavor this project uses, `_` **is** a word character. So in a test name like

```text
etag_serializes_with_named_fields
```

there is no boundary before `serializes` and none after it. A `\b`-anchored
match never fires. The identifier is one word to the matcher, and that word
ends in `elds`.

That is a real test name this tree carried, and the sweep read straight past it.

`camelCase` hides the same thing with no punctuation at all.
`serializesWithFields` has nothing to split on, so a matcher that breaks only
on punctuation reads one word ending in `elds` and passes it. Upper case does
not help either — `SCREAMING_SNAKE` is the same token shape.

The rule now splits twice. Tokens first, on anything that is neither
alphanumeric nor `_`, then each token on the underscore, then each run on a
lower-to-upper transition:

```rust
fn split_camel(run: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = run.as_bytes();
    let mut start = 0;
    for i in 1..bytes.len() {
        if bytes[i].is_ascii_uppercase() && bytes[i - 1].is_ascii_lowercase() {
            out.push(&run[start..i]);
            start = i;
        }
    }
    if start < run.len() {
        out.push(&run[start..]);
    }
    out
}
```

The lower-to-upper condition matters and it is the reason the split is not
"break before every capital". `HTTPServer` has no lower-to-upper position, so
it survives whole. Splitting on every capital would shred `SIPMessage` into
fragments, and a rule that manufactures fragments manufactures hits. There is a
test named exactly that: `an_acronym_run_is_not_split_into_fragments`.

The same class of false positive cost a separate correction. The scanner
reported `pyse`, four characters of a base64 hash in a lockfile, as a British
spelling. The rule now requires a stem long enough to be a word before the
suffix. A gate that cries wolf gets switched off, and one bogus hit teaches a
reader to skim every real one after it.

## Two: the gate could not read itself

The replacement went in as `tests/us_spelling_test.rs`, with twenty tests. All
twenty passed. The scan reported the tree clean.

The file was untracked.

The scan reads what `git ls-files` hands it, so a file nobody has staged is not
in the tree by the scan's reckoning. `git add` on that one file produced
**thirteen hits in prose written minutes earlier** — including a helper function
whose own name was British.

Twenty green tests, and the file defining them was the only file in the
repository the gate could not see.

Three tests came out of it. The scan reads this very file. No tracked test file
is invisible to it, which is the general form, because a test file is the place
somebody most readily writes a British spelling and least readily rereads one.
And the third:

```rust
/// The scan reads what git tracks, and says so.
///
/// The limitation behind the hollow green, written down where it will be read.
/// An unstaged file is invisible; that is a property of the input, not a bug,
/// and the fix is to stage before believing a pass.
#[test]
fn the_scan_reads_what_git_tracks_and_nothing_else() {
```

That third one fixes nothing. It records the limitation in the place somebody
debugging a suspicious pass would look. Reading the index rather than the
working tree is correct behavior for this gate — the question is whether the
person reading the green knows it.

## The floor under both

`the_tree_uses_us_spellings` opens with an assertion that has nothing to do
with spelling:

```rust
assert!(
    read >= 200,
    "only {read} file(s) read; the walk is not reaching the tree and a \
     pass would mean nothing"
);
```

That floor catches neither incident above. It catches the third version of the
same problem, the coarsest one: a walk that stops reaching the tree at all. The
two incidents were narrower — one read every file and could not see inside an
identifier, the other read a tree that did not yet hold the file in question.

Gates written since carry a floor of the same shape. The disk-space gate
refuses to pass on fewer than four reclaim steps, the overlay gate on fewer
than six overlays, the portability gate on fewer than twenty scripts. All three
say one thing: **exit status cannot tell "nothing wrong" from "nothing
examined"**.

## Worth stealing

Before believing a scan that reports zero, make it report what it read. A count
of inputs turns a silent pass into a checkable claim, and it costs one
assertion.

And check whether the scanner's own definition of a word matches the language
of the tree it reads. Source code is not prose. It carries English words inside
identifiers with the boundaries filed off, and every one of those is a place a
text rule goes blind.
