# Governance

This page says who holds which role in sipnab, how someone becomes a
committer, how the project makes decisions, and what a user can rely on while
the maintainer is unavailable. It links the rules that other pages already
state instead of copying them, so each rule lives in one place.

## Roles

| Role | Who | What the role can do |
|---|---|---|
| Maintainer | The people in the table in [MAINTAINERS.md](MAINTAINERS.md) | Admin access to the repository: merge, cut releases, change settings and secrets |
| Committer | No one besides the maintainer today | Write access: review and merge pull requests in an agreed area |
| Contributor | Anyone whose pull request merges | Propose changes through pull requests and issues |

`.github/CODEOWNERS` names the maintainer as the owner of every path, so
GitHub requests a review from the maintainer on every pull request.

## Becoming a committer

1. Contribute reviewed pull requests to this repository. The record of merged,
   reviewed work is what the maintainer reads.
2. Ask the maintainer, in an issue or a discussion, for write access to an
   area, such as HEP input, the TUI or packaging. The maintainer can also ask
   you.
3. The maintainer grants access under the rules in
   [MAINTAINERS.md](MAINTAINERS.md#getting-commit-access), which include the
   two-factor rule every account with access must meet.
4. The same change that grants access adds you to the table in
   [MAINTAINERS.md](MAINTAINERS.md), with your area, and updates this page
   where the roles above change.

Removing access follows the same rules, in the same page.

## How the project decides

- **A change goes through a pull request.** The review it needs, who reviews
  it and what the reviewer checks are in
  [CONTRIBUTING.md](CONTRIBUTING.md#code-review).
- **A structural change starts as an issue.** A design question costs less to
  settle as a paragraph than as a rewritten branch, as
  [MAINTAINERS.md](MAINTAINERS.md#what-that-means-for-you) says.
- **Direction is in [ROADMAP.md](ROADMAP.md).** It states what the project
  intends to build over the next year and what it has decided not to build.
  Read it before proposing something large.
- **Design records are in `docs/design/`.** Work the project deferred or
  declined, and why, is in
  [Deferred and declined work](docs/design/deferred-and-declined.md).
- **The maintainer makes the final decision** while the project has one
  maintainer. When a committer joins, the change that grants access also
  updates this section.
- **Conduct follows the [Code of Conduct](CODE_OF_CONDUCT.md),** which also
  says how to report a problem with someone's conduct.

## If the maintainer is unavailable

These are the facts today. The project has one maintainer and no named
successor, as [MAINTAINERS.md](MAINTAINERS.md#succession) states.

- **The license lets anyone continue the code.** You may use sipnab under
  either the MIT license ([LICENSE-MIT](LICENSE-MIT)) or the Apache License 2.0
  ([LICENSE-APACHE](LICENSE-APACHE)), at your option. A fork needs no one's
  permission.
- **Published releases stay checkable without anyone's help.** The release
  workflow signs each release with Sigstore, from the workflow's own identity,
  and stores no signing key anywhere.
  [SECURITY.md](SECURITY.md#verifying-a-release) gives the commands that check
  a download.
- **Releases go to four places:** GitHub Releases on `NormB/sipnab`, the
  `sipnab` crate on crates.io, the container image `ghcr.io/normb/sipnab`, and
  the Homebrew tap `NormB/homebrew-tap`. Accounts that belong to the
  maintainer control all four.
- **The developer documentation explains the code to someone new to it.**
  [docs/internals/README.md](docs/internals/README.md) leads to the module map,
  the invariants and the ordered checklists for common changes.
- **Only the latest release gets fixes**, as
  [SECURITY.md](SECURITY.md#supported-versions) states. If you depend on
  sipnab, the steps [MAINTAINERS.md](MAINTAINERS.md#succession) lists apply:
  pin a version and keep a build of it.

## Reporting a vulnerability

Do not open a public issue. [SECURITY.md](SECURITY.md) has the private
reporting channels, the response timeline and the scope.

## Changing this document

A change to this page is a pull request like any other, and the maintainer
reviews it. A change to a role, or to who holds one, updates this page and
[MAINTAINERS.md](MAINTAINERS.md) in the same pull request.
