+++
title = "Engineering notes"
description = "Short pages on using sipnab: how to do one job, what a feature does, and what went wrong in sipnab and how the project fixed it."
sort_by = "date"
template = "notes.html"
page_template = "note.html"
+++

Each note starts with a short summary written for any reader. Then it gives
the details. A label on each note says which of three kinds it is:

- **How-to**: the steps for one job.
  - It shows each command and the output it printed.
- **Feature**: what a sipnab feature does.
  - It shows how to turn the feature on, an example, and its limits.
- **Post-mortem**: a problem that occurred in sipnab, or in the way the
  project builds and tests it.
  - It says why the problem happened and what the project changed.
  - It says how you can check the result yourself.
  - The index lists these last, in a section that starts closed.

Each note ends with the terms it uses, defined in plain words. It also links
to the guides that cover the same subject. The date shown is the date a note
was first published.

For what changed in each release, read the
[changelog](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md). For full
reference material, read the [documentation](@/docs/_index.md).
