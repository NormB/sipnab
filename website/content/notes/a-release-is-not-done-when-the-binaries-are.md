+++
title = "A release is not done when the binaries are"
date = 2026-08-27
description = "0.5.128 published twenty-three assets, every workflow went green, and the website went on offering 0.5.127 to everyone who visited. A gate permitted the gap, and it was working exactly as designed."

[extra]
kind = "postmortem"
+++

On 2026-08-27 sipnab 0.5.128 got its tag. The release workflow built
twenty-three assets — six tarballs with checksums, four `.deb`, four `.rpm`,
two SBOMs, a combined `SHA256SUMS.txt`. Every workflow on the commit reported
success.

sipnab.com went on advertising 0.5.127. Sixty-four links on `/download`, the
checksum column, and the `SHA256SUMS.txt` link all pointed at the previous
build. Anyone following the install instructions got the older version, with no
indication that a newer one existed.

The binaries shipped. The release did not.

## Why the site lags on purpose

`website/config.toml` carries two version fields, and the distinction is
load-bearing:

```toml
version = "0.5.128"            # the crate in this tree
published_version = "0.5.127"  # what a visitor can actually download
```

Every download link and the version badge read `published_version`. It moves
*after* a release finishes publishing, in its own commit — never while cutting
one.

That rule exists because of a specific outage. The release commit bumps the
crate version, GitHub Pages redeploys from it, and if the download links
followed the crate version, the whole of `/download` would point at a tag
nobody had pushed yet. Every link 404s, including the checksums. On 0.5.61 that
window was not minutes: the release commit went red and was never tagged, so
the site advertised a release that never existed at all.

So the lag is correct. The bug is not that the site trails the tag. It is that
nothing closes the gap once the assets appear.

## A gate that passed, correctly

There is a gate for this. `site_advertises_only_a_released_version` checks that
`published_version` names a tag that exists, and that it is not far behind the
newest one:

```rust
assert!(
    behind <= 1,
    "... One behind is allowed: that is the window between tagging a release \
     and its assets finishing publishing."
);
```

One release behind is explicitly permitted, and the reasoning in the message is
sound — during that window the assets genuinely may not exist.

The state we shipped sat inside that tolerance. `published_version` was exactly
one behind. The gate passed, and it was right to pass by the rule it encodes.

The rule was just incomplete. It tolerates the lag *unconditionally*, when the
condition it is really tolerating — "the assets might still be building" — is
something you can simply go and check.

## Ask, do not tolerate

The replacement asks:

```rust
let Some(assets) = published_asset_count(&tag) else { /* say so, loudly */ };
assert!(assets > 0, "...");
assert_eq!(published_version(), newest_release, "...");
```

If `gh` reports that the newest tag has published assets, the window is over
and `published_version` must name it. If `gh` cannot answer, the test says so
on stderr rather than passing quietly — a gate that reports safety it did not
check is worse than one that is absent, and the whole point here is a gate
whose pass meant less than it appeared to.

Nine more gates went in beside it, all stating the same rule from different
directions: the changelog entry for the advertised version exists and its date
matches, the download markers name it, the crate is never behind it, a dated
changelog entry always has a real tag, and the generated install page agrees
with its source.

## The part that is not about tooling

The gate did not report the release as complete. A person did — in a summary
that led with "Done and shipped: 0.5.128 has shipped" and mentioned the pending
version move three paragraphs later, as remaining work.

Both statements were in the same message. Only the first one was a headline,
and headlines are what people act on. The honest sentence was available and
shorter: *GitHub has 0.5.128. The site still offers 0.5.127 until the
follow-up commit lands.*

A multi-step process does not finish when the interesting steps do. It
finishes with the last one, and the last step here is the only one a visitor
ever sees.
