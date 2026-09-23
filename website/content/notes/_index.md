+++
title = "Engineering notes"
description = "Walkthroughs, new features, and problems worth writing down: how to do a thing with sipnab, what a release added, and what broke along the way."
sort_by = "date"
template = "notes.html"
page_template = "note.html"
+++

Each entry carries a label that says which kind it is:

- **How-to**: do one job, end to end, with the commands that actually ran.
- **Feature**: what a release added and what each part is for.
- **Post-mortem**: a real problem with real numbers. A regression that
  shipped, a protocol assumption that turned out to be wrong, or a gate that
  passed when it should not have. These sit in a collapsed list at the end.

For what changed in each release, read the
[changelog](https://github.com/NormB/sipnab/blob/main/CHANGELOG.md). For
reference material, read the [documentation](@/docs/_index.md).
