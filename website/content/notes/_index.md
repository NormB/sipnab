+++
title = "Engineering notes"
description = "How sipnab is actually built and debugged: regressions found and fixed, protocol traps, and the reasoning behind decisions that are hard to see from the outside."
sort_by = "date"
template = "notes.html"
page_template = "note.html"
+++

Working notes from building sipnab. Each one is a real problem with real
numbers — a regression that shipped, a protocol assumption that turned out to
be wrong, a gate that passed when it should not have.

These are not release announcements. The [changelog](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md)
covers what changed. These cover *why it was hard*, and what the evidence
actually said.
