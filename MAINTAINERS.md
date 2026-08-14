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

## The contributor agreement

[CLA Assistant](https://cla-assistant.io/NormB/sipnab) runs the signing flow, and
[CONTRIBUTING.md](CONTRIBUTING.md#contributor-license-agreement) tells a
contributor how to use it. Two parts of that flow sit outside every gate in this
repository, because they live in a hosted service and a gist. Only the
repository owner can reach either, so this section states them rather than
leaving them to memory.

**A gist holds the words a signer agrees to.** CLA Assistant serves
<https://gist.github.com/NormB/a26df8a470a426dda140822ca4050a8e>, which matches
[CLA.md](CLA.md) byte for byte as of 2026-08-13.
`cla_page_reproduces_the_agreement` in `tests/site_journey_test.rs` keeps
`CLA.md` and the published page identical, and no test can reach the gist.
Editing `CLA.md` therefore means editing the gist in the same sitting.
Otherwise the bot records agreement to text this repository no longer contains,
which is worse than recording none. Budget for the other half of that edit:
CLA Assistant binds every signature to the gist revision current when the
contributor signed, so a new revision asks each previous signer again.

**Nothing enforces `license/cla` yet.** Branch protection on `main` requires
`CI success` and nothing else, so the status the bot posts informs a merge
rather than blocking one. Turning it into a real gate takes two owner actions,
in this order:

1. Add bot accounts to the allowlist in the CLA Assistant settings for this
   repository. Dependabot opens most pull requests here and cannot sign an
   agreement, so a required check without that allowlist stalls every dependency
   update. All nine Dependabot pull requests opened since the bot went live on
   2026-08-06 still carry a pending `license/cla`, and five of them merged that
   way.
2. Add `license/cla` to the required status checks for `main`.

The order matters: step 2 before step 1 blocks the routine pull requests on a
signature nobody can give. When step 2 lands, drop the caveat that ends the
[CLA section of CONTRIBUTING.md](CONTRIBUTING.md#contributor-license-agreement).

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
