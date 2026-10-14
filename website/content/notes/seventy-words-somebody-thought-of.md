+++
title = "The US-spelling check missed British spellings that were not on its word list"
date = 2026-09-01
updated = 2026-10-11
description = "Why sipnab's spelling check, which compared text against a list of known British words, let other British spellings through, and the suffix rule added in 0.5.142."

[extra]
kind = "postmortem"
+++

## In short

sipnab writes its documentation, code comments and website in US English. An
automated check enforces that.

- Until 2026-09-01 the check compared text against a fixed list of British
  words.
  - So any British spelling not on the list passed.
- On that day a scan found 67 such spellings in 95 files.
- sipnab 0.5.142 added a second check that recognizes British word endings
  instead of listing words.
  - An example is the British `-ise` where US English writes `-ize`.

## What happened

sipnab 0.5.105 (2026-08-17) converted the repository to US English in one
change.

- The change made 2,904 replacements across 274 files.
- No check kept it that way.
- By 0.5.122 the repository held 166 British spellings again.
- sipnab 0.5.123 (2026-08-22, commit 1291fb4b) added the test
  `the_tree_spells_in_us_english` in `tests/docs_drift_test.rs`.
  - It fails if any tracked file contains a word from its list (CHANGELOG,
    0.5.123 entry).

On 2026-09-01 that test caught the British spelling of `recognize` in a code
comment. Someone had written the comment minutes earlier. The test stopped
the commit.

The same day, a scan of the repository found **67 distinct British forms
across 95 files** that the list did not contain.

- Among them were the British spellings of `containerized`, `synthesized`,
  `unrecognized`, `sanitized`, `materializing`, `pseudonymizing` and
  `uninitialized`.
- The source is the comment at the top of `tests/us_spelling_test.rs`.
- The CHANGELOG 0.5.142 entry counts the same finding as 186 occurrences
  across 95 files.

## Why it happened

The list held 70 words at that time (`BRITISH` in `tests/docs_drift_test.rs`
at commit 95e0d2bb).

- A check that compares against a list can only find words someone has
  already added to it.
- A British spelling of any other word passed every check the repository ran.

Two statements about this history in the repository are incorrect:

- the comment at the top of `tests/us_spelling_test.rs`,
- the CHANGELOG 0.5.142 entry.

Both say the list-based check had existed "since 0.5.105". The test arrived in
0.5.123. The CHANGELOG 0.5.123 entry and commit 1291fb4b show this.

## What changed

Commit 95e0d2bb (2026-09-01, released in 0.5.142) did two things:

- It corrected the spellings found.
- It added `tests/us_spelling_test.rs`, which checks word endings instead of
  words.

Its rule is ten suffix pairs:

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

`NOT_A_SUFFIX` lists exceptions. These are words that end in those letters
without the letters being a suffix.

- Examples are `precise`, `otherwise`, `exercise`, `enterprise`, `promise`,
  `noise` and `disable`.
- It lists inflected forms too.
  - An earlier version exempted `raise` but not `raising`.
  - It reported `raising -> raizing`.

Tests in the same file check the rule from both sides and keep the lists
accurate:

- `a_british_word_no_list_names_is_still_caught` builds nine British words.
  It asserts that the rule catches each one.
- `the_us_spelling_of_each_is_accepted` asserts that the US forms of those
  words are not flagged.
  - So a rule that flagged too much would fail.
- `every_exception_is_a_word_the_tree_actually_uses` and
  `every_exclusion_names_a_path_that_exists_and_says_why` fail on an exception
  or excluded path that no longer matches anything.
- `the_rule_subsumes_every_suffixed_word_on_the_fixed_list` asserts that the
  rule catches every word on the old list that has one of the ten suffixes.

The test file contains no British spelling itself.

- `british_form` builds its test words at run time.
  - It joins a stem and a suffix (`british_form("container", "ised")`).
  - So the file needs no exemption from its own check.
- `the_spelling_scan_reads_this_very_file` asserts that the scan reads it.
- The old list-based test stays exempt. It has to contain the words it
  forbids.

One British spelling remains on purpose.

- It is in these published keys:
  - `unanalysed_sip_messages`,
  - `unanalysed_busiest_ports`,
  - `unanalysed_websocket_messages`,
  - `unanalysed_websocket_ports`.
- The keys appear in the REST API's `GET /v1/stats` and the MCP tool
  `capture_status`.
- Programs read those keys by name. Renaming them would break those programs.
- They are exempt only as whole names (`wire_identifiers` in
  `tests/us_spelling_test.rs`).
- `a_wire_exemption_matches_only_the_whole_token` asserts that a different
  name built from the same word is still caught.
  - An example is the key with `_v2` appended.

The suffix rule covers only the `-ise/-isation/-yse` family.

- Other British patterns are not suffix cases. Examples are `-our`, `-ogue`
  and a doubled `l` before `-ed`.
  - So the list-based test stayed.
- On 2026-09-08 (commit 8f692afd, released in 0.5.159) the list-based test
  changed.
  - It started to split identifiers such as `snake_case` names into separate
    words before comparing them.
  - Before that, four test names with British spellings had passed. The test
    had read the whole identifier as one word.
- The list held 126 words on 2026-10-11.

## What you can check yourself

Print the suffix rule from the test file:

```bash
grep -n -A11 '^const SUFFIXES' tests/us_spelling_test.rs
```

```text
188:const SUFFIXES: &[(&str, &str)] = &[
189-    ("isation", "ization"),
190-    ("isable", "izable"),
191-    ("ising", "izing"),
192-    ("ised", "ized"),
193-    ("ises", "izes"),
194-    ("ise", "ize"),
195-    ("ysing", "yzing"),
196-    ("ysed", "yzed"),
197-    ("yses", "yzes"),
198-    ("yse", "yze"),
199-];
```

Find the CHANGELOG entry that introduced the list-based check:

```bash
grep -n "a gate now holds it there" CHANGELOG.md
```

```text
8333:- **The tree spells in US English, and a gate now holds it there.** 0.5.105
```

- That line sits under `## [0.5.123] - 2026-08-22` (line 8222).
- Line numbers are from the main branch on 2026-10-11. They move as the files
  change.

## Terms used here

- **Check / gate**: an automated test that must pass before a change is
  accepted.
- **Tracked file**: a file that is part of the repository under git.
- **Suffix**: the ending added to a word stem, such as `-ise` or `-ize`.
- **Exception list**: words the rule must not flag, because the letters are
  not a suffix there.
- **Identifier**: a name in code, such as a function or variable name.
- **REST API**: sipnab's HTTP interface for other programs.
- **MCP**: Model Context Protocol, the interface AI assistants use to call
  sipnab's tools.

## Related guides

- [Build, CI and release: the prose gates](@/docs/internals/build-ci-release.md#the-prose-gates)
- [`GET /v1/stats`](@/docs/api.md#get-v1-stats)
