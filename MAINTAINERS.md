# Maintainers

| Maintainer | GitHub | Scope |
|---|---|---|
| Norm Brandinger | [@NormB](https://github.com/NormB) | Everything |

One maintainer, owning the whole tree. `.github/CODEOWNERS` says the same thing
in the form GitHub enforces: `*  @NormB`, so every pull request requests that
review automatically.

## What that means for you

**Response times vary, and nothing here is a commitment.** A single maintainer
with a day job is the actual constraint, and pretending otherwise helps nobody. See
[SUPPORT.md](SUPPORT.md) for which channel suits which question.

**A pull request is welcome and is not guaranteed to merge.** The
[contributing guide](CONTRIBUTING.md) covers the workflow, and
[the developer docs](https://sipnab.com/docs/internals/) cover what a change
has to satisfy. Two things save the most time on both sides:

- Open an issue first for anything structural. A design disagreement is cheaper
  as a paragraph than as a rewritten branch.
- Run the suite before pushing. The pre-commit hook runs the same gates CI does,
  so a green local run is usually a green pull request.

## How releases happen

The maintainer cuts them. The procedure lives in
[the build, CI and release page](https://sipnab.com/docs/internals/build-ci-release/),
and the parts that matter to a contributor are:

- Only the latest release gets fixes. There are no maintenance branches, which
  [SECURITY.md](SECURITY.md) states as the support policy.
- A tag publishes immediately and irreversibly, so tags only go on commits whose
  CI is already green. A hook enforces that rather than trusting anyone to
  remember.
- `CHANGELOG.md` accumulates under `## [Unreleased]` between releases. Adding an
  entry with your change is part of the change.

## Succession

There is none, and that is worth stating plainly. If this project matters to your
infrastructure, the mitigations are the ordinary ones for a single-maintainer
dependency: pin a version, keep a build of it, and read
[the developer documentation](https://sipnab.com/docs/internals/) — it exists
so the code is not only in one head.

The licence is MIT OR Apache-2.0. Forking is always available and needs nobody's
permission.
