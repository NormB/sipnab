# Getting help with sipnab

Where to take a question depends on what kind it is. All three routes are already
wired. This page just says which is which.

## I have a usage question

[**Discussions**](https://github.com/NormB/sipnab/discussions). "How do I filter
for X", "why does this capture show Y", "is Z supposed to work like this" — none
of those are bugs until someone establishes they are, and a discussion thread
does that without the ceremony of an issue.

Before asking, the reference pages answer most of it directly:

- [Troubleshooting](https://sipnab.com/docs/troubleshooting/) — symptom-first:
  failed calls, one-way audio, poor quality, NAT, scanners.
- [Cookbook](https://sipnab.com/docs/cookbook/) — dense recipes to copy when
  you know what you want.
- [CLI reference](https://sipnab.com/docs/cli/) — every flag, with examples.

## I think I found a bug

[**Open an issue**](https://github.com/NormB/sipnab/issues/new/choose). The bug
template asks for the version (`sipnab --version`), the command, and what you
expected instead — those three turn "it doesn't work" into something reproducible.

A capture that triggers it is worth more than any description. If you can share
one, `--strip-secrets` removes Decryption Secrets Blocks from a pcapng first, and
`--anonymize` is not a thing sipnab does, so check the capture yourself before
attaching it.

## I found a security vulnerability

**Do not open a public issue.** [SECURITY.md](SECURITY.md) carries the reporting
address, what counts as in scope, and what the response looks like. GitHub also
offers [a private advisory form](https://github.com/NormB/sipnab/security/advisories/new),
which the issue chooser links to. Both routes are private.

This page deliberately does not name one of them as *the* channel — `SECURITY.md`
does that, and a second copy of the answer here is a second thing to keep in
agreement.

sipnab parses attacker-controlled bytes for a living, so a parser panic reachable
from a capture file is a security issue, not a stability one.

## I want to change something

[CONTRIBUTING.md](CONTRIBUTING.md) covers the workflow, and
[the developer documentation](https://sipnab.com/docs/internals/) covers the
code: what gates a merge, which invariants exist and why, and the ordered
checklists for common changes.

## What support does not mean here

One person maintains this project ([MAINTAINERS.md](MAINTAINERS.md)). There is no
SLA, no paid tier, and no guarantee of a reply. Only the latest release gets
fixes — there are no maintenance branches. That is the honest shape of it, and it
is better said than discovered.
