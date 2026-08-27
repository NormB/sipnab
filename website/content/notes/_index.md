+++
title = "Engineering notes"
description = "Walkthroughs, new features, and problems worth writing down: how to do a thing with sipnab, what a release added, and what broke along the way."
sort_by = "date"
template = "notes.html"
page_template = "note.html"
+++

Working notes from building and running sipnab. Three kinds, and the label on
each entry says which it is:

- **How-to** — do one thing, end to end, with the commands that actually ran.
- **Features** — what a release added and what each part is for.
- **Postmortems** — a real problem with real numbers. A regression that
  shipped, a protocol assumption that turned out to be wrong, a gate that
  passed when it should not have.

These are not release announcements. The [changelog](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md)
covers what changed, and the [documentation](@/docs/_index.md) is the
reference. These cover how to use it and why it was hard.
