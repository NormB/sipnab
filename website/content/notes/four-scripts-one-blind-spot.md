+++
title = "Documentation scripts misread nested Markdown code blocks"
date = 2026-08-27
updated = 2026-10-11
description = "Four scripts that edit or check sipnab's documentation mistook a code block shown inside another code block for the end of the outer block; this note records what each script did, the fix, and how to confirm it."

[extra]
kind = "postmortem"
+++

## In short

sipnab's documentation uses Markdown, a plain-text format where a line of
backticks (`` ` ``) before and after a block of example code marks it off. Four scripts that edit or check those pages decided where a
code block ends with a rule that was too simple, so a code block shown inside
another code block confused them. Three of them could add web links inside
example commands, and one could stop checking commands partway through a
block without saying so. All four now use one shared, correct routine, and a
test fails if a script goes back to its own version.

## What happened

A fenced code block in Markdown starts with a line of three or more backticks
(`` ` ``) or tildes (`~`). The rule the scripts missed is in
[`scripts/lib_markdown.py`](https://github.com/NormB/sipnab/blob/main/scripts/lib_markdown.py),
the repository's shared Markdown module:

* a fence is three or more backticks or tildes, indented at most three spaces;
* it closes only on a run of the same character, at least as long as the one
  that opened it;
* a fence that is never closed runs to the end of the document.

So a page that shows how to write a code block uses a longer fence outside
and a shorter one inside:

````markdown
How to write a fenced block:
```
see RFC 7989 §5 for Session-ID
```
still inside the outer block
````

The four-backtick lines open and close the block. The three-backtick lines
are part of its content.

Before commit `e2045af9` (2026-08-27), four scripts in `scripts/` found code
blocks by checking whether a line starts with three backticks (or three
tildes), and switching between "inside code" and "outside code" each time one
did. That check cannot tell three backticks from four, so it treated the inner
three-backtick line as the end of the block and the next one as the start of
a new block. The scripts handled the lines between the two inner markers as
ordinary text.

What each script did with that text:

* `rfc-links.py`, which turns RFC citations into links, rewrote
  `see RFC 7989 §5 for Session-ID` inside the block as
  `see [RFC 7989 §5](https://www.rfc-editor.org/rfc/rfc7989#section-5) for Session-ID`
  (output of the test in step 3 below, run against the old script). Text in
  that form, pasted into a shell, is a syntax error: `bash` exits with status 2
  and reports `syntax error near unexpected token`.
* `link-repo-paths.py`, which links repository file paths, and
  `fix-line-anchors.py`, which repairs links to source lines, used the same
  check and treated the same lines as ordinary text.
* `check-cookbook.py` reads the commands in the `bash` code blocks of
  `docs/examples.md` (the cookbook page) and either runs each one against a
  test capture or confirms that every long flag it names exists in
  `sipnab --help`. Its old version ended a block at any line starting with
  three backticks, so commands after an inner marker were never collected and
  never checked, and the script did not report that it had skipped them.

When the fix landed, `docs/examples.md` contained no line starting with
four backticks or three tildes, so the scripts had skipped no cookbook command.
The fix commit describes the defect and does not name a published page that it
changed.

## Why it happened

Commit `80869f0a` added `scripts/lib_markdown.py` on 2026-07-28. The module
implements the full fence rule above. The four scripts each kept a separate
copy of the simpler line check and did not call the shared module. No test
fed any of them a code block nested inside another, so the difference was
not detected.

## What changed

Commit `e2045af9` made all four scripts use the shared module:
`rfc-links.py`, `link-repo-paths.py` and `fix-line-anchors.py` import
`fence_mask`, and `check-cookbook.py` imports `fences`. It also added
[`scripts/tests/test_fenced_content_survives.py`](https://github.com/NormB/sipnab/blob/main/scripts/tests/test_fenced_content_survives.py),
which checks three things:

1. Text inside a four-backtick block that contains a three-backtick block is
   left byte for byte unchanged by each of the three link-writing scripts.
2. The same scripts still rewrite citations, paths and line links outside any
   code block. Without this check, a script that rewrote nothing at all would
   pass the first one.
3. No script under `scripts/` other than `lib_markdown.py` calls
   `startswith` with a string beginning with three backticks or three tildes.
   The test reads each script's parsed syntax tree rather than its text, so a
   comment or Python documentation string that mentions such a call does not
   trigger it. The first version of the test searched the text and did trigger
   on a documentation string.

The file holds eight test functions, which run as 16 cases. CI runs every
test under `scripts/tests` on Linux (`python3 -m pytest scripts/tests -q` in
`.github/workflows/ci.yml`).

## What you can check yourself

Run these from the root of a full (not shallow) clone of the sipnab
repository, with `pytest` installed. Step 2 changes files in your checkout,
and step 4 puts them back.

1. Run the test against the current scripts:

```bash
python3 -m pytest -q scripts/tests/test_fenced_content_survives.py
```

```text
................                                                         [100%]
16 passed in 1.00s
```

2. Put back the four scripts as they were before the fix. The command prints
   nothing.

```bash
git checkout e2045af9^ -- scripts/rfc-links.py scripts/link-repo-paths.py scripts/fix-line-anchors.py scripts/check-cookbook.py
```

3. Run the nested-block case for `rfc-links.py` against the old script. It
   fails, and the message shows the link written inside the code block:

```bash
python3 -m pytest -q scripts/tests/test_fenced_content_survives.py -k 'longer_fence and rfc'
```

~~~text
F                                                                        [100%]
=================================== FAILURES ===================================
___ test_a_longer_fence_is_not_closed_by_a_shorter_run_inside_it[rfc-links] ____

stem = 'rfc-links'

    @pytest.mark.parametrize("stem", TRANSFORMERS)
    def test_a_longer_fence_is_not_closed_by_a_shorter_run_inside_it(stem):
        """Nothing between the ```` markers may change."""
        doc = nested_document(stem)
        out = convert(stem, doc)
        body = doc.split("````")[1]
>       assert body in out, (
            f"{stem} rewrote content inside a four-backtick fence -- the inner "
            f"three-backtick line was read as closing it. Fenced text must survive "
            f"byte-for-byte; use lib_markdown.fence_mask rather than a per-line "
            f"toggle.\n\n{out}"
        )
E       AssertionError: rfc-links rewrote content inside a four-backtick fence -- the inner three-backtick line was read as closing it. Fenced text must survive byte-for-byte; use lib_markdown.fence_mask rather than a per-line toggle.
E         
E         ````markdown
E         How to write a fenced block:
E         ```
E         see [RFC 7989 §5](https://www.rfc-editor.org/rfc/rfc7989#section-5) for Session-ID
E         ```
E         still inside the outer block: see RFC 7989 §5 for Session-ID
E         ````
E         
E         Prose below.
E         
E       assert 'markdown\nHow to write a fenced block:\n```\nsee RFC 7989 §5 for Session-ID\n```\nstill inside the outer block: see RFC 7989 §5 for Session-ID\n' in '````markdown\nHow to write a fenced block:\n```\nsee [RFC 7989 §5](https://www.rfc-editor.org/rfc/rfc7989#section-5) for Session-ID\n```\nstill inside the outer block: see RFC 7989 §5 for Session-ID\n````\n\nProse below.\n'

scripts/tests/test_fenced_content_survives.py:70: AssertionError
=========================== short test summary info ============================
FAILED scripts/tests/test_fenced_content_survives.py::test_a_longer_fence_is_not_closed_by_a_shorter_run_inside_it[rfc-links]
1 failed, 15 deselected in 0.04s
~~~

4. Restore the current scripts. The command prints nothing.

```bash
git checkout HEAD -- scripts
```

## Terms used here

* **Markdown**: a plain-text format for writing web pages. sipnab's
  documentation and these notes use it.
* **Fenced code block (fence)**: a block of example code in Markdown, marked
  off by a line of three or more backticks or tildes before and after it.
* **Backtick**: the character `` ` ``. **Tilde**: the character `~`.
* **Script**: a small program in the repository's `scripts/` directory that
  edits or checks files. These scripts are Python programs.
* **Cookbook**: the documentation page `docs/examples.md`, which lists
  commands a reader can copy and run.
* **Test**: a program that checks one behavior and fails when it is wrong.
  `pytest` is the tool that runs the Python tests.
* **Gate**: a check that must pass before the project accepts a change.
* **CI (continuous integration)**: the automated build that runs the tests on
  every change pushed to the project.
* **Commit**: one recorded change in the project's history, named by a short
  hash such as `e2045af9`.
* **Syntax tree**: the structure Python builds when it reads a program, in
  which comments and strings are separate from calls, so a check can look at
  calls only.

## Related guides

* [How sipnab builds its documentation and cites code from it](@/docs/contributing.md#citing-code-from-the-developer-docs)
* [The test tiers, including the cookbook output checks](@/docs/internals/testing.md#tiers)
* [What runs in CI before a change can merge](@/docs/internals/build-ci-release.md#what-actually-gates-a-merge)
