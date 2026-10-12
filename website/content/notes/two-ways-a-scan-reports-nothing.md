+++
title = "US-spelling check passed while it missed words inside identifiers and could not read its own file"
date = 2026-09-01
updated = 2026-10-11
description = "Two failures found while building sipnab's US-spelling check: a word search that could not see words inside code names, and a check that passed without reading the file that defined it."

[extra]
kind = "postmortem"
+++

## In short

sipnab has an automated check that fails if any file in the project uses a
British spelling, such as an "-ise" ending where US English uses "-ize". While
the project built it on 2026-09-01, it reported "nothing found" twice when
something was there: once because the search could not see words joined
together inside code names, and once because the check could not see the new
file that defined it. The project fixed both, and the check now also fails if
it reads too few files to mean anything.

## What happened

The US-spelling rule replaced a fixed list of words (see
[the post-mortem on that list](@/notes/seventy-words-somebody-thought-of.md)).
Two failures came up while the project built it.

**First failure.** Before the new check existed, a one-off search ran over the
project with a regular expression (a text-matching pattern) that looked
for each British spelling as a whole word. It reported no matches. British
spellings remained inside identifiers (the names given to functions, variables
and tests in source code). One was the test now named
`etag_serializes_with_named_fields` in `src/provenance.rs`, which at the time
spelled *serializes* with an *s* in place of the *z*. A comment in
`tests/us_spelling_test.rs` records this case.

**Second failure.** The new check is `tests/us_spelling_test.rs`. A comment in
that file records that its 20 tests passed while the file was untracked,
meaning nobody had yet added it to git with `git add`. Once the file was in
git, the check reported British spellings in the file itself.

## Why it happened

**First failure.** The search used `\b`, the regular-expression marker for a
word boundary: the point between a letter, digit or underscore and any other
character. An underscore counts as part of a word, so inside
`etag_serializes_with_named_fields` there is no boundary before or after
*serializes*, and a whole-word search for it does not match. The same applies
to `camelCase` names, where only a capital letter marks the start of each
word, such as `serializesWithFields`, and to upper-case names joined by
underscores.

**Second failure.** The check reads the list of files that git tracks (the
output of `git ls-files`), not every file on disk. A new file that nobody has
added to git is not in that list, so the check did not read it.

## What changed

- **The rule splits identifiers into words.** `tests/us_spelling_test.rs`
  splits text three times before it checks a word: into tokens at every
  character that is not a letter, a digit or an underscore; each token into
  runs of letters, which separates words at underscores and digits; and each
  run at every point where an upper-case letter follows a lower-case one. A run of capitals such as `HTTPServer` has no such point and is not
  split; the test `an_acronym_run_is_not_split_into_fragments` checks this.
- **A word must be long enough.** The rule reports a word only when at least
  three letters come before the British ending. An earlier version reported four
  characters of an encoded checksum in a lockfile as a British spelling.
- **Tests for each identifier shape.** Named tests check that the rule finds a
  British spelling inside a `snake_case` name, a `camelCase` name, an upper-case
  constant, a hyphenated or path segment, a code block, a string literal and
  next to digits.
- **Tests for what the check reads.**
  `the_spelling_scan_reads_this_very_file` fails if
  `tests/us_spelling_test.rs` is not among the files the check reads.
  `every_tracked_test_file_is_reachable_by_the_scan` fails if a tracked test
  file is neither read nor on the check's exclusion list with a reason.
  `the_scan_reads_what_git_tracks_and_nothing_else` checks that the file list
  holds no build output and only paths that exist, and its comment states
  that the check does not read a file until someone adds it to git.
- **A minimum count of files read.** `the_tree_uses_us_spellings` fails if
  it read fewer than 200 files, so a check that stopped reaching the project
  cannot pass. Two other checks have the same kind of minimum:
  `every_free_disk_step_uses_the_shared_action` in
  `tests/ci_disk_headroom_test.rs` (at least 4 steps) and
  `no_executable_line_uses_a_gnu_only_spelling` in
  `tests/repo_hygiene_test.rs` (at least 20 scripts).

`tests/us_spelling_test.rs` held 30 tests on 2026-10-11.

## What you can check yourself

1. See that a whole-word search does not find a word inside an identifier.
   `grep -c` prints how many lines match:

   ```bash
   echo 'etag_serializes_with_named_fields' | grep -c -E '\bserializes\b'
   ```

   ```text
   0
   ```

2. Run the same search on the words separated by spaces:

   ```bash
   echo 'etag serializes with named fields' | grep -c -E '\bserializes\b'
   ```

   ```text
   1
   ```

3. In a checkout of the repository, confirm that git tracks the check's file,
   so the check reads it:

   ```bash
   git ls-files tests/us_spelling_test.rs
   ```

   ```text
   tests/us_spelling_test.rs
   ```

   A file you have created and not yet added with `git add` prints nothing
   here, and the spelling check does not read it. Add new files before you
   rely on a passing result.

## Terms used here

- **Check (gate)**: an automated test that must pass before a change is
  accepted.
- **Regular expression**: a pattern language for searching text.
- **Word boundary (`\b`)**: the point between a word character (letter, digit
  or underscore) and any other character.
- **Identifier**: a name in source code, such as a function or test name.
- **`snake_case`, `camelCase`**: ways of joining words in an identifier, with
  underscores or with capital letters.
- **Tracked file**: a file that git records as part of the project. A new file
  becomes tracked when you add it with `git add`.
- **Lockfile**: a generated file that pins the exact versions of a project's
  dependencies, often with encoded checksums.

## Related guides

- [Documentation](@/docs/contributing.md#documentation) in the contributing
  guide, which states that prose is US English.
- [Running tests](@/docs/contributing.md#running-tests) in the contributing
  guide.
