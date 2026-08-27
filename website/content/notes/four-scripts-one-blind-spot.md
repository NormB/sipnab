+++
title = "Four scripts, one blind spot, and a fence that was never closed"
date = 2026-08-27
description = "A markdown fence is three or more backticks, and only a run at least as long closes it. Four scripts in this repository did not know that, and one of them was a gate quietly checking less than it claimed."

[extra]
kind = "postmortem"
+++

A fenced code block in Markdown opens with three or more backticks and closes
with a run at least as long as the opener. That second clause is the one people
skip, and it is the one that matters the moment you document Markdown *in*
Markdown:

````markdown
How to write a fenced block:
```
sipnab -N -I capture.pcap
```
still inside the outer block
````

The outer fence is four backticks. The inner three-backtick line is content.
Any scanner that toggles a boolean on `startswith("```")` sees the inner line
as a closing marker, decides the block has ended, and treats everything after
it as prose.

Four scripts in this repository did exactly that.

## What each one did with the mistake

Three of them rewrite prose in place, and all three edited code they should
never have touched:

* `rfc-links.py` turned `RFC 7989` inside a code block into a Markdown link.
  Pasted into a terminal, `[RFC 7989](https://…)` is a syntax error.
* `link-repo-paths.py` did the same to file paths.
* `fix-line-anchors.py` did the same to line citations.

The fourth is worse, and it is worse in the way that matters. `check-cookbook.py`
extracts every command from the ```bash blocks in the cookbook and runs them, so
the documentation cannot drift from the binary. Given a nested fence, it stopped
extracting early — and the commands after that point were simply never checked.

The three that rewrite prose corrupt output, which is visible. The gate checked less than
it claimed, which is not. A cookbook command could have rotted indefinitely
behind a green check.

## The library was already there

`lib_markdown.py` has handled this correctly for a long time, and its module
comment names the exact trap:

> A scanner that toggles one boolean on ``startswith("```")`` — the shape three
> of these scripts use — reads a ```` ``` ```` line as *entering* a fence with
> nothing to leave it.

Four scripts had their own copy of the logic. None used the module written to
get it right. That is the real finding: not that fence parsing is subtle, but
that the subtlety had already been solved, documented, and then rewritten from scratch
four times over by people who never knew to look.

## The guard is the shape, not the bug

The fix routes all four through `lib_markdown`. The test that keeps them there
does not check fence behavior — it checks that nobody hand-rolls it again:

```python
for node in ast.walk(tree):
    if (isinstance(node, ast.Call)
            and node.func.attr == "startswith"
            and node.args[0].value[:3] in ("```", "~~~")):
        offenders.append(f"{path.name}:{node.lineno}")
```

Matched against the parsed AST, not the file text. The first version used a
regex and fired on a comment that *mentions* `startswith("```")` while
explaining why the code below it does not do that — a gate reading prose and
reporting on prose.

Two more tests sit beside it: fenced content must survive every transformer
byte for byte, and prose outside every fence must still be rewritten. The
second exists because the first is satisfiable by doing nothing at all, and a
guard that passes with the feature switched off is not a guard.

## Worth stealing

If your repository has a helper for something subtle, the useful question is
not whether the helper is correct. It is how many other places solve the same
problem their own way. Four, here — and the one that mattered was the one that
failed silently.
