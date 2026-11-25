# Maintainers

| Maintainer | GitHub | Scope |
|---|---|---|
| Norm Brandinger | [@NormB](https://github.com/NormB) | Everything |

One maintainer, owning the whole tree. `.github/CODEOWNERS` says the same thing
in the form GitHub reads: `*  @NormB`, so every pull request requests that
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

[ROADMAP.md](ROADMAP.md) states where the project is going over the next year,
and what it does not intend to do. Check it before proposing something large.
[GOVERNANCE.md](GOVERNANCE.md) states the roles, the path to commit access and
how the project makes decisions.

## The contributor agreement

**Branch protection on `main` requires the `DCO` check**, next to
`CI success`. The `DCO` job
in `.github/workflows/pr-text.yml` checks every commit of a pull request for a
Developer Certificate of Origin sign-off, as
[CONTRIBUTING.md](CONTRIBUTING.md#signing-off-commits) describes. A verified
commit from a GitHub bot account, or one the repository owner authored and
committed, passes without a sign-off, so a new bot needs no allowlist entry.
[`tests/branch_protection_drift_test.rs`](tests/branch_protection_drift_test.rs)
fails if the required check and this page disagree.

**The project retired the CLA.** Until the switch to the DCO, contributors signed the
[Contributor License Agreement](CLA.md) through CLA Assistant, and branch
protection required its `license/cla` status. The project no longer collects
signatures: branch protection does not require `license/cla`, and CLA Assistant
is off for this repository. `CLA.md` and the page at <https://sipnab.com/cla/>
keep the text, marked retired, for the contributions made under it.

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

## Getting commit access

Write or admin access to this repository goes only to contributors with a
record of reviewed pull requests merged here. The maintainer grants it after
reviewing that record, and records every grant, with its scope, in the table
at the top of MAINTAINERS.md in the same change that grants it. The maintainer
removes access the same way when it is no longer needed.

Once a second maintainer joins, every pull request needs one approving
review from a maintainer other than its author, as
[CONTRIBUTING.md](CONTRIBUTING.md#code-review) describes.

**Two-factor authentication is mandatory.** Two-factor authentication (2FA)
means that signing in takes a second proof of identity on top of the password.
Anyone who holds write or admin access to this repository, or access to any of
the project's credentials, must have two-factor authentication turned on for
each of those accounts.
The credentials are the crates.io account, the Homebrew tap repository, the
Cloudflare account that serves sipnab.com, and the security@sipnab.com mailbox
that receives private vulnerability reports by email. The maintainer reads reports
filed through GitHub's private vulnerability reporting while signed in to a
GitHub account with admin access here, so the rule for GitHub accounts covers
them.

The second factor must be an authenticator app that shows a time-based
one-time code (TOTP), or a hardware security key or passkey. SMS is not
accepted, because anyone who takes over the phone number receives the text
message. The maintainer confirms that 2FA is on before granting access, and
removes the access if 2FA is later turned off. This rule does not rely on
GitHub's own 2FA requirement, which applies only to some accounts.

## Succession

There is none, and that is worth stating plainly. If this project matters to your
infrastructure, the mitigations are the ordinary ones for a single-maintainer
dependency: pin a version, keep a build of it, and read
[the developer documentation](https://sipnab.com/docs/internals/) — it exists
so the code is not only in one head.

The license is MIT OR Apache-2.0. Forking is always available and needs nobody's
permission.
