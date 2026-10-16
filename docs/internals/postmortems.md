# Incident record

The engineering record of problems in sipnab and in the way the project builds,
tests and publishes it. Each section says what happened, why, what changed,
and how to check the result.

These records were first published as notes on sipnab.com. The notes section
now holds how-tos and feature pages only, and the record moved here unchanged
in substance. Figures and line numbers carry the date of their measurement, and
they move as the files change. Where a note became a how-to, the section names it.

The second part,
[Engineering detail from the how-to and feature notes](#engineering-detail-from-the-how-to-and-feature-notes),
holds the source locations, version history and measurements that the how-to
and feature notes no longer carry.

- [Offline throughput regression missed by a stale benchmark baseline](#offline-throughput-regression-missed-by-a-stale-benchmark-baseline)
- [vCon exports described answered calls as failed setups](#vcon-exports-described-answered-calls-as-failed-setups)
- [The website kept offering the previous release after the new release files existed](#the-website-kept-offering-the-previous-release-after-the-new-release-files-existed)
- [Documentation scripts misread nested code blocks](#documentation-scripts-misread-nested-code-blocks)
- [A size test for the MCP field cap measured the whole message](#a-size-test-for-the-mcp-field-cap-measured-the-whole-message)
- [CI test binaries ran out of disk space because of full debug information](#ci-test-binaries-ran-out-of-disk-space-because-of-full-debug-information)
- [A CI job ran out of disk space and left no readable log](#a-ci-job-ran-out-of-disk-space-and-left-no-readable-log)
- [The homepage demos and the analyze sample showed different calls](#the-homepage-demos-and-the-analyze-sample-showed-different-calls)
- [Three hygiene tests failed on macOS because their setup did not run](#three-hygiene-tests-failed-on-macos-because-their-setup-did-not-run)
- [The commit check did not lint test files](#the-commit-check-did-not-lint-test-files)
- [TUI popups cut off the Esc hint and crashed on small terminals](#tui-popups-cut-off-the-esc-hint-and-crashed-on-small-terminals)
- [The US-spelling check missed words inside identifiers and its own file](#the-us-spelling-check-missed-words-inside-identifiers-and-its-own-file)
- [The US-spelling check missed British spellings not on its word list](#the-us-spelling-check-missed-british-spellings-not-on-its-word-list)
- [Stray files filled the development checkout](#stray-files-filled-the-development-checkout)
- [Two HEP-over-TCP tests failed on macOS because they assumed Linux timing](#two-hep-over-tcp-tests-failed-on-macos-because-they-assumed-linux-timing)

## Offline throughput regression missed by a stale benchmark baseline

### What happened

sipnab 0.5.118 (2026-08-20) to 0.5.121 (2026-08-21) read capture files more
slowly than 0.5.117. 0.5.122 fixed it the same day. The 0.5.122 entry in
`CHANGELOG.md` records the measurements, on a 128 MB benchmark capture read
with `--cores 4`:

| Version | Packets per second | Memory in use |
|---|---:|---:|
| 0.5.117 | 3.29M | 97 MiB |
| 0.5.118 to 0.5.121 | 2.40M | 143 MiB |
| 0.5.122 | 3.26M | 97 MiB |

2.40M is 27% below 3.29M. The same entry records that every release from
0.5.108 to 0.5.117 measured about 3.26M. [`bench/regression-gate.sh`](../../bench/regression-gate.sh) ran on
each of the four slow releases and passed each time.

### Why

**Reading the whole file.** Before sipnab reads a capture file it checks
whether the file is a merged pcapng (a pcapng whose recorded interfaces
disagree, which the standard capture library cannot read). The function is
`is_merged` in [`src/capture/merged.rs`](../../src/capture/merged.rs), and three call sites run it before the
first packet. In 0.5.118 it began with `std::fs::read(path)`, which loads the
whole file, and then compared the first four bytes against the pcapng Section
Header Block magic. For an ordinary pcap the first four bytes decide the
answer, so every run loaded the entire capture, compared four bytes and
discarded the copy. The comment above the function described a cheap read of
the interface blocks only. No test measured how much the function read.

**Comparing against an old figure.** [`bench/regression-gate.sh`](../../bench/regression-gate.sh) compares
four-worker throughput against [`bench/baseline.json`](../../bench/baseline.json) and fails below 80% of it
(`floor_pct`). At 0.5.121 the file held 2,280,000 packets per second, measured
on 0.5.104. Release 0.5.108 had raised real throughput to about 3.30M. The
benchmarks page changed to the new figure, the baseline file did not. The
check compared 2.40M against 2.28M (105%) and passed. With that baseline it
would have passed anything above 1.82M, a drop of up to about 45%.

### What changed

- `is_merged` opens the file and reads four bytes first, and returns without
  reading further when they are not the pcapng marker. A real pcapng file is
  still read in full, because its interface blocks may appear anywhere.
- `a_classic_pcap_is_rejected_without_reading_the_capture` in
  [`src/capture/merged.rs`](../../src/capture/merged.rs) passes the four-byte pcap marker and 1 MiB of filler
  through a counting reader and fails if the check reads more than 16 bytes.
- 0.5.122 set the baseline to 3.25M, the lowest of three runs, so the 80%
  floor (2.60M) cannot sit above a figure the benchmark host produces. On
  2026-10-11 the baseline was 3.52M with a floor of 2.82M.
- From 0.5.161, `benchmarks_pages_headline_matches_the_committed_baseline` in
  [`tests/site_journey_test.rs`](../../tests/site_journey_test.rs) fails if the benchmarks page's headline figure
  and the baseline differ.

### How to check

```bash
git show v0.5.121:bench/baseline.json | jq '.cores_4_pkts_per_s, .floor_pct'
```

printed `2280000` and `80`.
`git show v0.5.122:bench/baseline.json | jq '.cores_4_pkts_per_s'` printed
`3250000`. On 2026-10-11 `jq '.cores_4_pkts_per_s, .floor_pct' bench/baseline.json`
printed `3520000` and `80`.

## vCon exports described answered calls as failed setups

The user-facing page for this is the how-to note "Tell an answered call from a
failed one in a sipnab vCon export". The current rule is in
[the vCon guide](../vcon.md).

### What happened

sipnab added vCon export (`--export-vcon` and the `export_vcon` MCP tool) in
0.5.125 (2026-08-25). In 0.5.125, 0.5.126 and 0.5.127 the Dialog Object of
every exported call that carried no audio had `"type": "incomplete"`,
unconditionally, and no `disposition`. An export carries no audio when the
capture holds only signaling or the run kept no audio payload. Each such
record of an answered call stated that the call never reached a conversation,
and a consumer reading it beside a switch's call detail record that showed a
connected call received two contradicting accounts.

### Why

The vCon core draft (`draft-ietf-vcon-vcon-core-03` at the time) defines five
Dialog Object types: `recording`, `recording-set`, `text`, `transfer` and
`incomplete`. Four describe content the object holds. An object for a call
with no saved audio holds no content, so sipnab used the fifth. The draft
defines `incomplete` by what happened to the call, a call that "failed to be
setup" (section 4.3.1, quoted in the 0.5.128 release notes), not by what the
object holds. The draft also requires `disposition` on an `incomplete` object.

### What changed

- **0.5.128 (2026-08-27).** sipnab decides `type` and `disposition` together.
  A final failure sipnab saw produces `"type": "incomplete"` with a
  `disposition`. An object with no content and no observed failure got no
  `type`: draft `-03` allowed a Dialog Object with no parameters, and the vCon
  working group had agreed on that shape (issue #20, cited in the 0.5.128
  release notes). The draft's own JSON schema required `type`, so sipnab's
  copy of the schema carried one recorded deviation.
- **0.5.208 (2026-10-09).** sipnab follows `draft-ietf-vcon-vcon-core-04`,
  which requires `type` on every Dialog Object and drops the sentence that
  allowed an empty one. A call with no saved audio and no observed failure is
  `"type": "recording"` with no `body`, `url` or `mediatype`, the placeholder
  section 4.3 of `-04` defines. The vendored schema,
  [`tests/schemas/vcon.schema.json`](../../tests/schemas/vcon.schema.json), is the working group's `-04` file
  unchanged, and sipnab carries no local deviation.

The vCon guide records a consumer case at vcon-server commit `8ffbfcf`: the
`deepgram_link` transcription link reads `dialog["url"]` without checking for
it, and raises on a `recording` object with no content.

### How to check

The how-to note runs the two exports (an answered call from
[`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap), a `488` from
[`tests/pcap-samples/sip-488-codec-reject.pcapng`](../../tests/pcap-samples/sip-488-codec-reject.pcapng)) and prints `recording` with
no content for the first and `incomplete` with `"disposition": "failed"` for
the second.

## The website kept offering the previous release after the new release files existed

### What happened

The tag `v0.5.128` dates from 2026-08-27 at 15:58:57 (UTC-4). Tagging starts
the release workflow, which builds the release files and publishes them on
GitHub. The website's version badge and every download link read
`published_version` in [`website/config.toml`](../../website/config.toml), which still read `0.5.127`. A
visitor who followed the download or install instructions received 0.5.127.
Commit `ddb05f3a`, "Tell the website that 0.5.128 exists", changed the field at
16:39:00 the same day and added [`tests/release_completeness_test.rs`](../../tests/release_completeness_test.rs). Its
message records that the release had published twenty-three files while the
download page, its checksum column and its `SHA256SUMS.txt` link still pointed
at 0.5.127.

### Why

[`website/config.toml`](../../website/config.toml) has two version fields. `version` is the source version,
copied from `Cargo.toml` by the site build, so it changes as soon as a release
commit reaches main. `published_version` is the newest version a visitor can
download. Every download link, the homepage badge, the footer and the
structured page data read it, and a separate commit changes it after a release
finishes publishing. The split exists because a release commit reaches the
website before its tag and files exist. Download links that followed `version`
would return 404 in that window. On 0.5.61 the window was longer than usual:
release commit `345344e7` (14:28:15 on 2026-07-29) was never tagged, and
`v0.5.61` (14:59:38) points at the next commit, `6cf58a8e`.

`site_advertises_only_a_released_version` in [`tests/site_journey_test.rs`](../../tests/site_journey_test.rs)
requires `published_version` to name a tagged version at most one release
behind the newest tag. Its message gives the reason for the one-release
allowance: the time between tagging a release and its assets finishing
publishing. On
2026-08-27 the field was exactly one behind, so the test passed whether or not
the newer release's files existed. Nothing else checked for them.

### What changed

[`tests/release_completeness_test.rs`](../../tests/release_completeness_test.rs) adds
`the_site_advertises_the_newest_release_whose_assets_exist` beside the
one-version allowance. It asks `gh` how many files the newest release has and,
when it has any, requires `published_version` to name that release. When `gh`
cannot answer (for example it is not installed) the test prints the reason on
standard error and passes without checking. The file holds ten more tests:
the advertised release date belongs to the advertised version, every download
instruction names it, the source version is never behind it, it has a
changelog entry and a tag, every dated changelog entry names a real tag, and
the install page and its website copy name the same version. On 2026-10-11
`grep -c '^#\[test\]' tests/release_completeness_test.rs` printed `11`.

### How to check

```bash
git show ddb05f3a -- website/config.toml | grep '^[-+]published'
```

prints `-published_version = "0.5.127"` and `+published_version = "0.5.128"`.
`git cat-file -p 'v0.5.61^{commit}^' | tail -n 1` prints `Release 0.5.61`.

## Documentation scripts misread nested code blocks

### What happened

A fenced code block in Markdown opens with three or more backticks or tildes,
indented at most three spaces, and closes only on a run of the same character
at least as long as the opener. An unclosed fence runs to the end of the
document. [`scripts/lib_markdown.py`](../../scripts/lib_markdown.py), added by commit `80869f0a` on 2026-07-28,
implements that rule. Before commit `e2045af9` (2026-08-27), four scripts kept
their own simpler check instead: they toggled between "inside code" and
"outside code" on every line starting with three backticks or three tildes. A
three-backtick line inside a four-backtick block therefore ended the block for
them, and they read the lines up to the next inner marker as prose.

- `rfc-links.py` rewrote `see RFC 7989 §5 for Session-ID` inside such a block
  as a Markdown link. Pasted into a shell, that line is a syntax error (`bash`
  exits 2 with `syntax error near unexpected token`).
- `link-repo-paths.py` and `fix-line-anchors.py` used the same check.
- `check-cookbook.py`, which runs or flag-checks the commands in the `bash`
  blocks of `docs/examples.md`, ended a block at any three-backtick line, so
  commands after an inner marker were never collected, and it did not report
  the skip.

When the fix landed, `docs/examples.md` contained no line starting with four
backticks or three tildes, so the script had skipped no cookbook command. The fix
commit names no published page it changed.

### Why

The shared module existed. The four scripts did not call it, and no test fed
any of them a nested block.

### What changed

Commit `e2045af9` made `rfc-links.py`, `link-repo-paths.py` and
`fix-line-anchors.py` import `fence_mask`, and `check-cookbook.py` import
`fences`. It added [`scripts/tests/test_fenced_content_survives.py`](../../scripts/tests/test_fenced_content_survives.py), which
checks that:

- text inside a four-backtick block holding a three-backtick block survives
  each link-writing script byte for byte;
- the same scripts still rewrite citations, paths and line links outside code
  (without this, a script that rewrote nothing would pass);
- no script under `scripts/` other than `lib_markdown.py` calls `startswith`
  with a string beginning with three backticks or three tildes. The test
  reads each script's syntax tree, so a comment or documentation string that mentions
  such a call does not trigger it; the first version searched the text and
  did trigger on a documentation string.

The file holds eight test functions that run as 16 cases. CI runs
`python3 -m pytest scripts/tests -q` on Linux.

### How to check

`python3 -m pytest -q scripts/tests/test_fenced_content_survives.py` passes
16 cases. To see the defect, restore the old scripts with
`git checkout e2045af9^ -- scripts/rfc-links.py scripts/link-repo-paths.py scripts/fix-line-anchors.py scripts/check-cookbook.py`,
run the same file with `-k 'longer_fence and rfc'` (it fails, showing the link
written inside the block), then `git checkout HEAD -- scripts`.

## A size test for the MCP field cap measured the whole message

### What happened

sipnab caps each header value it hands to an MCP client at `MAX_FIELD_BYTES`,
256 bytes ([`src/mcp/shape.rs`](../../src/mcp/shape.rs)). A capped value ends with `…[truncated]`, and
sipnab wraps each value in `⟦untrusted-capture-data⟧` and
`⟦/untrusted-capture-data⟧`. The user-facing description is in
[mcp-protocol.md](../mcp-protocol.md#what-else-a-fenced-value-cannot-carry).

The CI job `Check (macos-latest)` failed on
`an_oversized_header_is_bounded_in_the_response` in
[`tests/mcp_output_injection_test.rs`](../../tests/mcp_output_injection_test.rs). Four commits ran red on it while Linux
passed. The test builds a capture with one INVITE whose `User-Agent` is 4096
bytes, asks `get_message` for it, and checks that the value in the answer is
short. The fix is commit `1ccf1f8a` (2026-08-28), first released in 0.5.130.

### Why

The answer to `get_message` carries the long text in two strings: the fenced
header value (327 bytes with the markers) and an unfenced record of the whole
message. The test took the first string containing the payload, which was the
whole-message record, and required it to be at most 1024 bytes. That record's
size depends on the other headers and on the capture path, which includes the
temporary directory:

| Platform | String the test measured | Result against 1024 bytes |
|---|---:|---|
| Linux | 992 bytes | passed |
| macOS | 1036 bytes | failed |

The header value was 327 bytes on both. The cap was never what the test
measured.

### What changed

The test selects the string that starts with `UNTRUSTED_OPEN`, which is a
single fenced value, and computes its ceiling as `MAX_FIELD_BYTES + 128`. The
4096-byte input stays below the parser's 8 KiB header-line limit
(`DEFAULT_MAX_HEADER_LINE_LEN` in [`src/sip/parser.rs`](../../src/sip/parser.rs)). Above it sipnab rejects
the message and the cap would never run. The fix added eight tests to the same
file:

| Test | What it checks |
|---|---|
| `the_response_carries_an_oversized_field_in_more_than_one_string` | The payload appears in at least two strings, the condition that made the original test ambiguous. |
| `the_container_is_larger_than_the_field_it_encloses` | The message record is larger than the header value. |
| `the_field_cap_is_independent_of_the_capture_path_length` | A longer capture path changes the record's size and leaves the value's size unchanged. |
| `the_capped_field_is_a_fraction_of_the_header_that_produced_it` | The capped value is under a quarter of the input and more than half the cap. |
| `a_capped_field_declares_that_it_was_cut` | A shortened value carries the truncation marker. |
| `capping_a_field_does_not_strip_its_closing_fence` | The closing fence survives the cap. |
| `no_string_in_the_response_carries_the_header_whole` | No string carries more than 256 bytes of the payload in one run. |
| `the_oversized_header_fixture_actually_reaches_the_response` | The input reaches the answer, so the other checks are not empty. |

On 2026-10-11, disabling the cap in a copy of commit `6e2cbab2` (the size
check in `sanitize_field` replaced by `true`) failed four tests: the original
and `a_capped_field_declares_that_it_was_cut`,
`no_string_in_the_response_carries_the_header_whole` and
`the_capped_field_is_a_fraction_of_the_header_that_produced_it`. The other
five check how sipnab selects values, not the cap's size. In the same run the
whole-message record measured 1444 bytes on Linux, so a fixed 1024-byte
ceiling would now fail there too.

### How to check

`cargo test --features full --test mcp_output_injection_test -- --test-threads=1`
ran 13 tests, all passing, at `6e2cbab2` (0.5.211).

## CI test binaries ran out of disk space because of full debug information

### What happened

On 2026-08-29 the Linux CI job failed while linking with
`ld: final link failed: No space left on device`. The previous commit had
passed. The failing one added two test files, and each test binary links the
whole dependency tree.

### Why

A measurement of one debug test binary from 0.5.133, recorded in the
`Cargo.toml` comment, the 0.5.133 CHANGELOG entry and commit `4499cb79`:

| Measured on 0.5.133 | Size |
|---|---:|
| One debug test binary | 422 MB |
| Of which `.debug_*` sections | 315 MB |
| Share | 75% |

The Linux job runs on the hosted `ubuntu-24.04-arm` runner, which has roughly
14 GB of disk according to the `Cargo.toml` comment. Test builds inherit the
`dev` profile, which had no `debug` setting and so produced full DWARF debug
information. `[profile.release]` had used `debug = "line-tables-only"` since
2026-04-15 (commit `515899bb`).

Earlier the same day a different CI failure was first treated as a disk
problem: the Benchmarks job stopped after about 6 minutes of compiling with
113 GB free (commit `442adf1e`, comment in [`.github/workflows/quality.yml`](../../.github/workflows/quality.yml)).
Building its profiling profile with
`CARGO_PROFILE_PROFILING_DEBUG: line-tables-only` fixed that one. For the link
failure the linker named disk space directly, and the measurement came before
the choice of fix.

### What changed

Commit `4499cb79` (released in 0.5.133) set `debug = "line-tables-only"` under
`[profile.dev]` in `Cargo.toml`. A panic still prints the file and line of each
frame, and the build drops the variable and type information that only an
interactive debugger reads. For a
debugging session, override it for one command, for example
`CARGO_PROFILE_DEV_DEBUG=full cargo test --test us_spelling_test`.

### How to check

`grep -A1 '^\[profile.dev\]' Cargo.toml` prints the setting. The CHANGELOG
entry is under `## [0.5.133] - 2026-08-29`, "Fixed": "CI ran out of disk
linking test binaries."

## A CI job ran out of disk space and left no readable log

### What happened

On 2026-09-01 a CI job stopped with the error recorded at the top of
[`.github/actions/free-disk/action.yml`](../../.github/actions/free-disk/action.yml):

```text
System.IO.IOException: No space left on device :
  '/home/runner/actions-runner/cached/2.337.0/_diag/Worker_....log'
```

The process that failed was the runner's own logger, so the job produced no
build output, no test names and no last message. The fix commit, `15fa67c9`,
records that the project found the cause in a check annotation after the job log had
expired, and that the Coverage job had warned about low disk space in the two
runs before. Released versions were not affected.

### Why

`ci.yml` and `quality.yml` each held two copies of a step named "Free disk
space". The `ci.yml` copies removed .NET, Android, GHC, CodeQL and Boost, and the
`quality.yml` copies also removed Swift, the hosted tool cache and every
Docker image, a list extended after an earlier time the Coverage job ran out of
space. The `ci.yml` copies were never updated, and a `ci.yml` job ran out.

### What changed

From 0.5.142 the cleanup is one shared action,
[`.github/actions/free-disk/action.yml`](../../.github/actions/free-disk/action.yml), used by every "Free disk space" step
(on 0.5.211: four in `ci.yml`, three in `quality.yml`, one in `release.yml`).
It removes everything any old copy removed, plus `/usr/share/miniconda`,
`/usr/local/share/powershell`, `/usr/local/lib/node_modules` and
`/usr/local/.ghcup`. It prints one line in this form:

```text
reclaimed %.1f GB; %.1f GB free before, %.1f GB free after
```

It does not fail below a threshold. Its comment states that no measured threshold exists yet.
[`tests/ci_disk_headroom_test.rs`](../../tests/ci_disk_headroom_test.rs) holds four checks on `ci.yml` and
`quality.yml`: every "Free disk space" step uses the shared action with no
inline script, the action still removes every path the old copies removed, it
prints both figures, and each of the two files uses it at least once.
These tests do not read `release.yml`.

### How to check

Any CI job that frees disk space prints the action's line with that run's
figures.

## The homepage demos and the analyze sample showed different calls

The user-facing page for this is the how-to note "Open the sipnab.com sample
call in the browser and in the terminal".

### What happened

The homepage shows a still picture ([`demos/hero.tape`](../../demos/hero.tape)) that changes to an
animation ([`demos/01-intro.tape`](../../demos/01-intro.tape), and the `/analyze` page's "Load a sample call"
button downloads [`website/static/demos/sample-call.pcap`](../../website/static/demos/sample-call.pcap)
([`website/static/js/analyze.js`](../../website/static/js/analyze.js)). The `.tape` files are VHS scripts that run
`sipnab -I <capture>`. Before 2026-08-31, `hero.tape` read
[`tests/pcap-samples/register-invite-reinvite-bye.pcap`](../../tests/pcap-samples/register-invite-reinvite-bye.pcap) and `01-intro.tape`
read [`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap), so a visitor saw three different
calls. Commit `70ec075d` (first in v0.5.140) moved the still picture to
`sample-call.pcap`, and commit `a9aaf57a` (first in v0.5.142) moved the animation.

### Why

No test compared the three capture names, and no file a test could read stated
the requirement that they agree. The facts live in separate files: the
two `.tape` scripts, the `index.html` template, and `analyze.js`.

### What changed

Both `.tape` files type `sipnab -I website/static/demos/sample-call.pcap`.
Commit `a9aaf57a` added [`tests/demo_capture_agreement_test.rs`](../../tests/demo_capture_agreement_test.rs), which reads the
homepage template, every `.tape` under `demos/` and `analyze.js`, and fails
when the animation's capture differs from the `/analyze` sample
(`the_homepage_animation_and_the_analyze_sample_use_one_capture`), when the
still differs from the animation
(`the_hero_still_and_the_hero_animation_use_one_capture`), or when a tape names
a capture that does not exist or is not committed
(`every_demo_tape_drives_a_capture_that_exists`,
`no_demo_tape_drives_an_uncommitted_capture`). It reads the capture only from
the argument after `-I`, so a path in a tape comment is not mistaken for it.

### How to check

`grep -n 'sample-call' demos/hero.tape demos/01-intro.tape` shows both tapes
reading the same file.

## Three hygiene tests failed on macOS because their setup did not run

### What happened

[`scripts/clean-stale.py`](../../scripts/clean-stale.py) deletes stray logs and other leftovers from a
checkout, but only files older than an age floor. [`tests/repo_hygiene_test.rs`](../../tests/repo_hygiene_test.rs)
runs it against temporary directories. On 2026-09-01 three of those tests
failed on the macOS runner and passed on Linux. Each said the script had not
removed a file it should have. The script was correct: nothing had made the
files old.

### Why

The setup code, `Fixture::age`, ran `touch -d @<epoch>`, a GNU extension that
failed on the macOS runner. The setup did not check the exit status, the file
kept its current time, the age floor correctly kept it, and three assertions
about the script failed. Local runs are on Linux, so the failure appeared only
in CI.

### What changed

Commit `6efa9937`, released in 0.5.142: `Fixture::age` sets the time with
Rust's `set_modified`, reads it back, and fails with "backdating {} did not
take: it reads as {}s old, not {}d. Every age-gated assertion below would then
be testing the fixture rather than the cleaner." The commit added six tests:

- `backdating_a_fixture_file_actually_moves_its_mtime` checks the setup alone;
- `the_age_floor_separates_recent_from_backdated_in_one_run` writes one old
  and one new file in one run and requires the old one removed and the new
  one kept;
- `no_test_shells_out_for_file_metadata` rejects tests that run `touch`,
  `stat`, `date` or `readlink` as a process;
- `no_executable_line_uses_a_gnu_only_spelling` rejects `touch -d`, `stat -c`,
  `readlink -f`, `date -d` and `cp --preserve` in `scripts/`, `.githooks/` and
  `bench/`; its first run found `stat -c %s` in [`bench/live-capture.sh`](../../bench/live-capture.sh), which
  now uses `wc -c`;
- `the_cleaner_shells_out_to_nothing` asserts the script starts no program;
- `every_fixture_is_confined_to_the_cargo_temp_dir` keeps every test directory
  inside `CARGO_TARGET_TMPDIR`.

The commit message records three mutations, all detected. The first did not
apply on the first attempt, and the mutation's guard reported that rather
than a result.

### How to check

`grep -n 'set_modified' tests/repo_hygiene_test.rs` and
`grep -n 'CORPUS_REAL_BYTES=' bench/live-capture.sh`.

## The commit check did not lint test files

### What happened

From commit `e294c880` (2026-04-15) the `pre-commit` hook ran
`cargo clippy --features full -- -D warnings`, while CI and `pre-push` ran
`cargo clippy --workspace --all-features --all-targets -- -D warnings`.
Without `--all-targets`, clippy checks only the library and binaries. Four lint
errors passed the commit check and failed CI: a `needless_splitn` in a test
file and an `items_after_test_module` in [`src/sip/mod.rs`](../../src/sip/mod.rs) on 2026-08-30
(0.5.135), and two more in test files on 2026-09-01.

### Why

The backlog item `GATE1` tracked the difference and left the fix open on the
assumption that widening the commit check would "roughly double its wall
clock". Nobody had measured it. On 2026-09-01, with a warm cache on the hook
machine (figures in [`.githooks/pre-commit`](../../.githooks/pre-commit) and the 0.5.143 release notes):

| Command | Time |
|---|---:|
| `cargo clippy --features full` (the old commit check) | 245 ms |
| `cargo clippy --workspace --all-features --all-targets` (CI's command) | 517 ms |
| `cargo clippy --features full --all-targets` (a narrower alternative) | 40,110 ms |

CI's command took 2.1 times as long, 272 ms more, because `pre-push` and CI
already keep its build output cached. The narrower alternative builds a
feature combination no other step builds, so the cache held nothing for it.

### What changed

In 0.5.143 (2026-09-02) the `pre-commit` hook runs CI's command with
`--color never`. [`tests/clippy_scope_parity_test.rs`](../../tests/clippy_scope_parity_test.rs) reads
[`.githooks/pre-commit`](../../.githooks/pre-commit), [`.githooks/pre-push`](../../.githooks/pre-push) and [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
and asserts that the commit check lints test targets, all three run the same
scope, and every invocation has `-D warnings` (without it clippy exits 0). It
counts only commands a file runs, skipping comments, printed suggestions
(`printf`, `echo`, a `--fix` hint, a `Reproduce:` hint) and the separate
`pre-push` run for the other Linux architecture. The first version counted a
printed `--fix` suggestion as a run, and the skip list exists for that reason.

### How to check

`grep -n 'clippy --workspace' .github/workflows/ci.yml .githooks/pre-commit .githooks/pre-push`
lists the three run lines among comments and hints.

## TUI popups cut off the Esc hint and crashed on small terminals

The user-facing page for this is the how-to note "Name the addresses of a call
in the terminal interface".

### What happened

Up to 0.5.141 the Name Address popup (`N`) had a fixed width of 60 columns.
With two endpoints its last line,
`  Tab switch endpoint · Enter save all · empty clears · Esc cancel`, is 66
characters, so the popup cut off `Esc cancel`. The one-endpoint line (45
characters) fit. The tests written for it found three more problems, recorded
in fix commit `506851b5`: the Filter (F7), Settings (F8) and Column selector
(F10) popups closed on Esc without saying so, the Filter popup crashed the
interface at 66 by 12, and the Settings popup crashed when drawn into fewer
than six rows. In the running program a terminal below 40 by 6 shows
`Terminal too small` instead, so 66 by 12 was the case a user could reach. A
crash closes the whole interface, including a live capture.

### Why

The popup did not size itself to its text, and the text widget cuts long
lines without error. No test required a popup to name its exit. The Filter
and Settings popups placed rows from a fixed height, so on a short terminal
they asked `Buffer::set_string` to write outside the screen, which stops the
program.

### What changed

In 0.5.142 (2026-09-01): the Name Address popup takes the width of its longest
line plus three columns and still shrinks to fit. The Filter, Settings and
Column popups name Esc on their last line. Every call to `Buffer::set_string`
goes through `set_string_clipped`, which skips writes outside the screen and
shortens lines at the right edge. Tests in [`src/tui/render/popups.rs`](../../src/tui/render/popups.rs):

- `no_popup_shows_more_text_when_the_terminal_grows` draws every popup at
  100x40 and 240x60 and requires the same text;
- `every_overlay_names_the_key_that_closes_it` requires `Esc` in every popup;
- `every_overlay_survives_an_exhaustive_size_sweep` draws every popup at
  widths 1 to 90 and heights 1, 2, 3, 5, 8, 12, 20 and 30;
- `every_overlay_survives_a_tiny_terminal` covers six named sizes including
  4x3 and 66x12;
- `no_tui_code_writes_through_the_unguarded_set_string` fails on a direct call
  in `render/popups.rs`, `call_list.rs` or `call_flow/render.rs`;
- `every_tui_overlay_is_covered_by_these_gates` counts the places in
  [`src/tui/render/popups.rs`](../../src/tui/render/popups.rs) and [`src/tui/call_list.rs`](../../src/tui/call_list.rs) that clear an area
  before drawing a popup and fails if the count differs from the list the
  other tests use. A popup in another file is not counted; on 2026-10-11 no
  other file under `src/tui/` drew one.

## The US-spelling check missed words inside identifiers and its own file

### What happened

While building [`tests/us_spelling_test.rs`](../../tests/us_spelling_test.rs) on 2026-09-01, the work twice
reported "nothing found" when something was there. A one-off regular
expression search for each British spelling as a whole word reported no
matches while British spellings remained inside identifiers, one being the
test now named `etag_serializes_with_named_fields` in [`src/provenance.rs`](../../src/provenance.rs).
Later, the new file's 20 tests passed while the file was untracked. Once it
was in git, the check reported British spellings in the file itself.

### Why

`\b` marks a boundary between a word character (letter, digit, underscore)
and anything else, so inside a `snake_case` name there is no boundary around
the word. `camelCase` and upper-case joined names behave the same. The check
reads `git ls-files`, so an untracked file is not read.

### What changed

The rule splits text into tokens at non-word characters, each token into runs
of letters, and each run where an upper-case letter follows a lower-case one
(`an_acronym_run_is_not_split_into_fragments` keeps `HTTPServer` whole). The
rule reports a word only with at least three letters before the British ending, and
an earlier version reported four characters of a lockfile checksum. Named
tests cover `snake_case`, `camelCase`, an upper-case constant, a hyphenated or
path segment, a code block, a string literal and adjacent digits.
`the_spelling_scan_reads_this_very_file`,
`every_tracked_test_file_is_reachable_by_the_scan` and
`the_scan_reads_what_git_tracks_and_nothing_else` hold what the check reads.
`the_tree_uses_us_spellings` fails if it read fewer than 200 files. The same
kind of floor exists in `every_free_disk_step_uses_the_shared_action`
([`tests/ci_disk_headroom_test.rs`](../../tests/ci_disk_headroom_test.rs), at least 4 steps) and
`no_executable_line_uses_a_gnu_only_spelling` ([`tests/repo_hygiene_test.rs`](../../tests/repo_hygiene_test.rs), at
least 20 scripts). On 2026-10-11 the file held 30 tests.

### How to check

`echo 'etag_serializes_with_named_fields' | grep -c -E '\bserializes\b'`
prints `0`. With spaces in place of the underscores it prints `1`.
`git ls-files tests/us_spelling_test.rs` prints the path once git tracks the file.

## The US-spelling check missed British spellings not on its word list

### What happened

0.5.105 (2026-08-17) converted the repository to US English in 2,904
replacements across 274 files, with no check to keep it. By 0.5.122 it held
166 British spellings again. 0.5.123 (2026-08-22, commit `1291fb4b`) added
`the_tree_spells_in_us_english` in [`tests/docs_drift_test.rs`](../../tests/docs_drift_test.rs), which fails on
any word from a fixed list. On 2026-09-01 a scan found 67 distinct British
forms across 95 files that the list did not contain (186 occurrences by the
0.5.142 CHANGELOG's count), among them the British spellings of
`containerized`, `synthesized`, `unrecognized`, `sanitized`, `materializing`,
`pseudonymizing` and `uninitialized`.

### Why

The list held 70 words (`BRITISH` at commit `95e0d2bb`), and a list catches only
words someone added. The comment at the top of [`tests/us_spelling_test.rs`](../../tests/us_spelling_test.rs) and
the 0.5.142 CHANGELOG entry say the list check existed "since 0.5.105". The
0.5.123 entry and commit `1291fb4b` show it arrived in 0.5.123.

### What changed

Commit `95e0d2bb` (released in 0.5.142) corrected the spellings and added
[`tests/us_spelling_test.rs`](../../tests/us_spelling_test.rs), which checks ten suffix pairs (`SUFFIXES`:
`isation`, `isable`, `ising`, `ised`, `ises`, `ise`, `ysing`, `ysed`, `yses`,
`yse` against their `z` forms), with exceptions in `NOT_A_SUFFIX` (`precise`,
`otherwise`, `exercise`, `enterprise`, `promise`, `noise`, `disable`, and
inflected forms, after an earlier version exempted `raise` but not `raising`). Tests
check both directions (`a_british_word_no_list_names_is_still_caught`,
`the_us_spelling_of_each_is_accepted`), keep the lists accurate
(`every_exception_is_a_word_the_tree_actually_uses`,
`every_exclusion_names_a_path_that_exists_and_says_why`), and require the rule
to catch every suffixed word on the old list
(`the_rule_subsumes_every_suffixed_word_on_the_fixed_list`). `british_form`
builds test words at run time, so the file needs no exemption from itself.

The published keys `unanalysed_sip_messages`, `unanalysed_busiest_ports`,
`unanalysed_websocket_messages` and `unanalysed_websocket_ports` (REST
`GET /v1/stats`, MCP `capture_status`) keep their spelling because programs
read them by name. They are exempt only as whole names (`wire_identifiers`),
and `a_wire_exemption_matches_only_the_whole_token` keeps a derived name
caught. Other British patterns (`-our`, `-ogue`, a doubled `l` before `-ed`)
are not suffix cases, so the list test stayed. On 2026-09-08 (commit
`8f692afd`, 0.5.159) it began splitting identifiers before comparing, after
four British test names had passed it. The list held 126 words on 2026-10-11.

### How to check

`grep -n -A11 '^const SUFFIXES' tests/us_spelling_test.rs` prints the rule.

## Stray files filled the development checkout

### What happened

The project's development instructions had said to delete every temporary
file in the same turn for months, and nothing checked it. The comment at the
top of [`scripts/clean-stale.py`](../../scripts/clean-stale.py) records the development checkout on
2026-09-01: 21 stray `.git/*.log` files, three abandoned worktrees totaling
136 GB, and a `target/` directory of 1.6 TB (551 GB incremental cache, 961 GB
`deps/`), together 44% of a 3.6 TB disk that was 76% full.

### Why

The instruction was text only. A file inside `.git/` never appears in
`git status`, and an abandoned worktree appears only in `git worktree list`.

### What changed

[`tests/repo_hygiene_test.rs`](../../tests/repo_hygiene_test.rs) fails when `.git/` holds a `.log`, `.out` or
`.err` file the hooks did not write (`the_git_directory_holds_no_stray_logs`,
which gained `.out` and `.err` on 2026-09-12), when the working tree holds a `.orig`,
`.rej`, `.snap.new`, `.bak` or `~` file
(`the_working_tree_holds_no_conflict_or_snapshot_detritus`), or when a
worktree has no uncommitted changes, no commits ahead of its upstream, and no
activity for 24 hours (`no_worktree_is_abandoned_with_nothing_worth_keeping`).

[`scripts/clean-stale.py`](../../scripts/clean-stale.py) removes what has accumulated. On the development
machine it runs daily from a systemd user timer that is not part of the
repository. Its safety properties, each tested in [`tests/repo_hygiene_test.rs`](../../tests/repo_hygiene_test.rs):
dry run without `--apply` (`the_cleaner_removes_nothing_without_apply`), a
minimum age, `--min-age-days`, default 1 (`a_recent_file_is_never_removed`),
refusal on a directory that is not a git checkout
(`the_cleaner_refuses_a_root_that_is_not_a_checkout`, exit status 2), and a
closed list of endings (`apply_removes_detritus_and_never_source`). It removes
`target/*/incremental/` only with `--reclaim-build-cache` and free space below
`--disk-floor-gb` (default 250 GB), and never `deps/`
(`the_cleaner_never_touches_the_dependency_cache`). It uses only the Python
standard library (`the_cleaner_shells_out_to_nothing`). The test and the
script share the hook-log prefix `sipnab-pre-` (`HOOK_LOG_PREFIX`), and
`the_gate_and_the_cleaner_share_one_definition_of_a_hook_log` keeps them
equal.

### How to check

`python3 scripts/clean-stale.py` lists what it would remove and removes
nothing. `python3 scripts/clean-stale.py --root /` refuses with "/ is not a git
checkout." and exits 2.

## Two HEP-over-TCP tests failed on macOS because they assumed Linux timing

The user-facing page for this is the how-to note "Send SIP to a HEP collector
over TCP and accept only known senders".

### What happened

0.5.150 added HEP over TCP and TLS. During that work two tests in
[`src/capture/hep.rs`](../../src/capture/hep.rs) passed on Linux and failed on the macOS runner
(`macos-latest` in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)). In both, sipnab's behavior was
correct, and the project fixed both before it released 0.5.150.

- `a_tcp_peer_outside_the_allowlist_is_refused_before_it_can_speak` connects
  from outside `--hep-allow`, sends one packet, and reads to confirm the
  listener closed the connection. It set a read timeout after sending, and
  that call failed on macOS.
- `a_tcp_sender_reconnects_after_the_collector_drops_the_connection` closed
  the collector side, had the sender send exactly three packets, and waited
  for a new connection. On macOS none arrived within ten seconds.

### Why

macOS returns `EINVAL` from `setsockopt(SO_RCVTIMEO)` on a connection the peer
has already reset, and Linux accepts the call. The listener's refusal and the
test's packet are nearly simultaneous. The sender reconnects only after a send
fails, and a send fails only after the operating system has received the
collector's reset: on Linux that arrives before the second packet, so three
were enough. On macOS it does not. In both tests the count or order matched
Linux timing rather than the behavior under test.

### What changed

In 0.5.150 (2026-09-04) the allowlist test sets the read timeout before
sending and accepts either end-of-stream or a reset. The reconnect test sends
one packet at a time and checks for a new connection for up to ten seconds,
failing with "the rebuilt connection: the sender offered packets for 10s and
never reconnected". The sender did not change: a failed send drops the
connection, the next packet opens a new one, one reconnect attempt per packet.

### How to check

Both tests run on every change on the Linux and macOS CI jobs. The behavior
they protect is in the CLI reference rows for `--hep-send-transport` and
`--hep-allow`.

## Engineering detail from the how-to and feature notes

On 2026-10-16 the how-to and feature notes under `website/content/notes/`
were rewritten to carry the reader's task only. This part keeps what they
dropped: where each message comes from, how each rule came about, and the
measurements. Each section names the note it came from.

### Finding order in `--analyze`

Source for the order described in the note "Diagnose one-way audio in the
order sipnab ranks the causes" (`rule-out-the-relay-before-the-nat.md`).

- [`src/analysis.rs`](../../src/analysis.rs) declares the severity levels (`Severity::Blind`,
  `Critical`, `Major`, `Minor`). The declaration order is the sort order, so
  `BLIND` findings come first.
- `rank()` in [`src/analysis.rs`](../../src/analysis.rs) sorts by severity, then by occurrence count
  descending, then by `FindingKind` declaration order. The third key makes the
  output byte-stable across runs.
- Severity per kind, from the kind table in [`src/analysis.rs`](../../src/analysis.rs):
  `icmp_unreachable_media` and `stun_sdp_mismatch` are `Critical`;
  `nat_mismatch`, `unanswered_stun_probe` and `turn_allocation_lapsed` are
  `Major`. The note previously said NAT, STUN and TURN findings are all
  major; `stun_sdp_mismatch` is critical, and the note now says so.
- The one-way audio flag comes from `diagnose_media()` in
  [`src/rtp/diagnosis.rs`](../../src/rtp/diagnosis.rs), which reads the stream list only. It does not read
  the SDP direction attribute, so a call negotiated `sendonly`/`recvonly` is
  reported as one-way audio ([`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap) shows it).
- The order follows `docs/troubleshooting.md`, which says to act on ICMP
  errors first and points from its NAT section to the STUN and TURN checks.

### vCon evidence export: changes between 0.5.211 and 0.5.222

From the note "Hand over call evidence that another party can check"
(`evidence-somebody-else-can-check.md`).

- On 0.5.211, `--vcon-digest` without `--no-cli-print` sent the per-message
  listing to standard output as well, so it landed in `SHA256SUMS`, and
  `sha256sum -c` reported `WARNING: 54 lines are improperly formatted` for
  [`tests/pcap-samples/sip-488-codec-reject.pcapng`](../../tests/pcap-samples/sip-488-codec-reject.pcapng). On 0.5.222 `--vcon-digest`
  implies `--no-cli-print` (its `--help` text says so); a run without
  `--no-cli-print` wrote one line to `SHA256SUMS` and `sha256sum -c` passed
  (checked 2026-10-16).
- On 0.5.211, a run with `--run-provenance-file` wrote the system host name as
  the node into the record and the containers, even when `--node-name` set
  another. On 0.5.222 (`16f7b0ea`), `--node-name lab` put `lab` in
  `.capture.node` of the record, in `capture_completeness.node`, and in the
  observer party's `sip_user_agent` (checked 2026-10-16).
- 0.5.222 adds `call_ended` to `capture_completeness`.

### `find_correlated` measurements

From the note "Join the two legs of a call that crossed a B2BUA"
(`one-call-two-nodes-neither-saw-it-all.md`).

- `timing_clock.max_error_us` on thor-02: three runs on 2026-10-11 reported
  1017000, 36000 and 16500; one run on 2026-10-16 reported 523500.
- On 0.5.222, `find_correlated` for `1-1966@10.0.2.20` over standard input
  against [`tests/pcap-samples/sip-rtp-g711.pcap`](../../tests/pcap-samples/sip-rtp-g711.pcap) returned
  `source_exhausted: false` in five of five runs on 2026-10-16 (build 7f9ffaa7) (the 0.5.211
  output in the note showed `true`). The tool call arrives while the
  background file reader is still loading the 852-frame capture. The leg found
  (`sdp_origin`, score 90) was the same in every run.
- The HTTP server example `--mcp-bind 127.0.0.1:8731` does not start on
  thor-02: port 8731 is in use there (`Address already in use (os error 98)`,
  exit 2). The note shows the file-backed variant on port 28731. That run
  logged `MCP HTTP server listening on 127.0.0.1:28731`.

### Sources of the uprobe messages

From the note "Read SIP over TLS on a server you cannot restart, using eBPF
uprobes" (`read-tls-without-a-key-or-a-restart.md`).

- `--uprobe-list` in [`src/app/bootstrap.rs`](../../src/app/bootstrap.rs) prints "No TLS library is
  mapped by any process sipnab can see." and returns exit code 1.
- [`src/capture/native.rs`](../../src/capture/native.rs) holds the message
  `` --uprobe-backend bpf needs a sipnab built with the `bpf` feature; this binary does not carry it ``,
  in the
  `#[cfg(not(feature = "bpf"))]` arm. sipnab refuses rather than falling back
  to tracefs, because a reader asks for this backend to get the addresses.
- The "no kernel programs" refusal is `refuse_without_programs()` in
  [`src/capture/uprobe/bpf_record.rs`](../../src/capture/uprobe/bpf_record.rs).
- The root-only commands in that note (`sudo sipnab --uprobe-list`,
  `--uprobe-tls` with either backend, the `uprobe_events` check) did not run
  for the note. Their example output is the output recorded in
  `docs/uprobe-walkthrough.md`.

### TLS records that arrive before their keys

From [`website/content/notes/the-invite-that-arrived-before-its-keys.md`](../../website/content/notes/the-invite-that-arrived-before-its-keys.md).

Dan Jenkins ([@danjenkins](https://github.com/danjenkins)) reported that
sipnab decrypted his SIP over TLS traffic except for the INVITE, and then
reported a NAT problem on a trunk that did not have one.

- A key-log writer emits a session's keys only after the handshake completes.
  The 0.5.120 release notes record a gap of 56 ms between the first
  application record and its key, measured in the field.
- The 0.5.120 release (2026-08-21) fixed three causes:
  - **Records that arrived before their keys**: sipnab dropped them. It now holds
    and retries them. A retry tries the record sequence number sipnab already
    has and never advances its search for the number. That rule is Dan
    Jenkins's. Without it, failed retries moved the search past sequence 0,
    where the INVITE is.
  - sipnab computed the flag that marks a session's handshake as seen when it
    created the session. With a complete key log, sipnab creates sessions
    before it reads the first packet, so the flag was always false. sipnab now
    sets it when the handshake arrives.
  - **A SIP message split across two TLS records** lost everything after the
    first record. Decrypted bytes now go through the same stream framing as
    SIP over plain TCP.
  - **TLS 1.3 session tickets** (`NewSessionTicket`): sipnab passed them to
    the SIP parser, and each cost the next message. sipnab now checks each record's inner
    content type
    ([RFC 8446 section 5.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.2)).
- On the reproduction capture Dan Jenkins supplied, the release notes record
  0 of 17 application-data records decrypted in 32.9 seconds before the fix,
  and all 8 messages of the call, the INVITE with its SDP offer, in 0.55
  seconds after it.
- The 0.5.121 release (2026-08-21) added the per-call comparison for a run
  that takes SIP from a HEP mirror and from the network at once. Dan Jenkins
  used the two sources together and proposed that they count as complementary
  rather than as copies; see `docs/design/simultaneous-capture-sources.md`.

Where sipnab produces the messages the notes quote:

- `TLS late decrypt: recovered N record(s) ...`: [`src/capture/decrypt.rs`](../../src/capture/decrypt.rs).
- The `discarded` and `still waiting` end-of-run lines: `late_hold_guidance`
  in [`src/app/batch.rs`](../../src/app/batch.rs). The limits it prints come from
  `REWIND_BUDGET_BYTES`, `MAX_REWIND_PER_DIRECTION` and `REWIND_MAX_AGE_SECS`
  in [`src/capture/mod.rs`](../../src/capture/mod.rs); the 4096-direction limit is `MAX_REWIND_DIRECTIONS`
  in [`src/capture/decrypt.rs`](../../src/capture/decrypt.rs).
- `opened only after the capture ended`: `report_late_tls_decrypts` in
  [`src/app/batch.rs`](../../src/app/batch.rs), logged at warning level.

### Decrypting SIP over TLS from key logs

From [`website/content/notes/reading-tls-without-a-certificate.md`](../../website/content/notes/reading-tls-without-a-certificate.md).

- sipnab cannot start eCapture because it sets `PR_SET_NO_NEW_PRIVS` at
  startup (`block_privilege_escalation` in [`src/privilege.rs`](../../src/privilege.rs)). Every child
  inherits the setting, so no child can gain `CAP_BPF`. See
  `docs/internals/subsystem-guide.md`.
- The default of `--tls-lockon-window` is `TLS_SEQ_LOCKON_WINDOW` in
  [`src/capture/mod.rs`](../../src/capture/mod.rs), `1 << 20` records.
- The embedded-DSB line, `TLS decryption active: N secret(s) from embedded DSB
  in FILE`, comes from [`src/app/batch.rs`](../../src/app/batch.rs). The cookbook recipe "One file,
  taken off the host, that decrypts itself" records a run on 2026-09-09 with
  eCapture v2.5.2, on a TLS 1.3 session using `TLS_AES_256_GCM_SHA384`: 6
  secrets, and one completed dialog, `tls-split-invite-1@127.0.0.1`, with 7
  messages.
- ChaCha20-Poly1305 is deliberately absent from the cipher-suite table in
  [`src/capture/decrypt.rs`](../../src/capture/decrypt.rs). sipnab parses TLS 1.2 CBC suites so that
  `try_decrypt_with_session` can refuse them, because sipnab does not verify
  the CBC record MAC.

### The 5 MiB inline media default

From [`website/content/notes/keep-the-audio-your-store-will-not-take.md`](../../website/content/notes/keep-the-audio-your-store-will-not-take.md).

Section 4a.1 of `docs/design/vcon.md` records the measurement behind the
default. The note summarized it as follows:

- On 2026-08-24 a test sent synthetic containers to a running vCon store,
  reachable over HTTP and NATS.
- A container with about 12 MB of inline base64 received HTTP 204. The store
  wrote it to its PostgreSQL database; its file spool refused it with
  `16777749 > 10485760`. Neither interface reported the refusal.
- Both backends stored containers of about 1 MB and about 5 MB.
- The default sits at 5 MiB, the size both backends stored, and not at the
  10,485,760-byte spool limit, because the rest of the container has to fit
  under that limit too. The figure describes that one store, not the vCon
  format; the store publishes no per-container limit.

### The observer vCon's third verdict

From [`website/content/notes/an-observer-vcon-and-its-third-verdict.md`](../../website/content/notes/an-observer-vcon-and-its-third-verdict.md).

The first version of that note described two behaviors that followed the
earlier draft core-03:

- a third `validate_vcon` verdict, `valid-except-documented-deviation`,
- an empty Dialog Object (`{}`) for the consultation call of an attended
  transfer.

Under core-04 every Dialog Object needs a `type`. sipnab now writes
`{"type": "recording"}` for that placeholder, and `validate_vcon` reports an
empty Dialog Object as `invalid`. `CHANGELOG.md` records the verdict's
removal, and `docs/internals/vcon.md` records the `type` history.

### vCon exporter changes in 0.5.128 and 0.5.208

From [`website/content/notes/what-0-5-128-added-to-the-vcon-exporter.md`](../../website/content/notes/what-0-5-128-added-to-the-vcon-exporter.md).

0.5.128 added `subject`, `parties[].name`, `parties[].stir`,
`dialog[].session_id`, transfer records, `--vcon-max-inline-media`,
`--content-deny-tombstone`, `--vcon-digest`, RFC 9457 problem documents on the
REST API, and atomic spool writes. 0.5.208 revised two of them to follow
draft-ietf-vcon-vcon-core-04:

- The attended-transfer consultation placeholder was `{}` in 0.5.128 and is
  `{"type": "recording"}` from 0.5.208.
- Before 0.5.128 a Dialog Object with no audio had the type `incomplete`, so
  every answered call captured without audio reported a setup failure. In
  0.5.128 such an object named no `type`. From 0.5.208 it is
  `"type": "recording"` with no `body` or `url`. See `docs/internals/vcon.md`.
- Before 0.5.128 a REST error was a status code with no body.

### SIPREC metadata on real captures (0.5.151)

Source note: [`website/content/notes/the-parser-that-worked-and-the-feature-that-was-dead.md`](../../website/content/notes/the-parser-that-worked-and-the-feature-that-was-dead.md).

sipnab had a SIPREC reader ([`src/sip/siprec.rs`](../../src/sip/siprec.rs)) from April 2026, and its unit
tests passed. On real captures the participant and stream data never
appeared. Three faults caused it. Version 0.5.151 (2026-09-05) fixed all
three.

- **Recording mode read from the wrong element.** The reader looked for
  `<mode>`. RFC 7866 and the OpenSIPS `siprec` module both write
  `<datamode>`, so the mode was empty for every call OpenSIPS recorded. The
  reader now reads `<datamode>` and keeps `<mode>` as a fallback.
- **Stream ownership read from the wrong place.** The reader looked for the
  owner inside each `<stream>` element. OpenSIPS writes it only in
  `<participantstreamassoc>`, so every stream showed no owner. The reader now
  reads the `<send>` entries there.
- **The dialog-creating INVITE skipped the reader.** The dialog store
  ([`src/sip/dialog_store.rs`](../../src/sip/dialog_store.rs)) had three code paths that apply what a message
  adds to a dialog: one for a dialog it already holds, one that creates a new
  dialog, and one that replays messages after sipnab merges two records of the
  same call. Two of them ran the SIPREC reader; the creating path did not.
  The recording INVITE is the first message of the recording call, so it is
  the message that creates the dialog. The reader never ran on it. All
  three paths now call one shared function.

Why the tests did not catch it:

- The first two faults passed because the unit tests used a hand-written
  sample document whose layout differed from what OpenSIPS writes. The
  replacement tests use the layout from OpenSIPS's
  `modules/siprec/siprec_body.c`.
- The third fault was outside the reader, so no test of the reader alone
  could find it. Reading a capture through the full program found it.
- Before 0.5.151 no report, API or tool displayed the stored metadata, so the
  empty field was invisible. The same release added the `--report` block, the
  REST and `--json-dialogs` `siprec` object, the `siprec_metadata` MCP tool
  and the ladder lines.

### MCP tool list and build features (0.5.142)

Source note: [`website/content/notes/the-tool-list-that-promised-what-the-build-lacked.md`](../../website/content/notes/the-tool-list-that-promised-what-the-build-lacked.md).

Before 0.5.142, a build without the `vcon` feature (for example the CI build
with `native,hep,api,mcp,mcp-http`) listed `export_vcon` and `validate_vcon`
in `tools/list`, with their input and output schemas, and refused every call
with:

```text
this sipnab was built without the 'vcon' Cargo feature, so it has no vCon exporter. Rebuild with --features vcon (or --features full); server_capabilities lists what this binary carries
```

The message pointed to `server_capabilities`, whose `features` list could
name only ten features and never named `vcon`, `bpf` or `wasm`, so it could
not confirm whether the feature was present.

Cause: two places decided the tool list and the code behind it. Every build
assembled the same tool list. Only the code that would do the work changed
with the feature. The fix put the tool definitions themselves behind the
feature, so a build that lists a tool it cannot run no longer compiles. The
`features` list of `server_capabilities`, the `--version` line and
`GET /v1/capabilities` now all come from `compiled_features()` in
[`src/cli.rs`](../../src/cli.rs).

[`tests/mcp_capability_agreement_test.rs`](../../tests/mcp_capability_agreement_test.rs) holds the rule in place. It requires
that:

- every tool module tied to a feature registers all of its tools or none of
  them;
- `server_capabilities` can name every feature that `Cargo.toml` declares.

### MCP tool-list sizes, earlier measurement

Source note: [`website/content/notes/fifty-seven-tools-and-the-two-that-stay-off.md`](../../website/content/notes/fifty-seven-tools-and-the-two-that-stay-off.md).

The note now carries the 0.5.222 figures. The figures it carried before, from
sipnab 0.5.211 built with every feature, using the same command (sum of each
`tools/list` entry's compact JSON, in bytes).

| `--mcp-tools` | Tools | Bytes | Bytes with `--mcp-output-schemas` |
|---|---|---|---|
| `core` | 9 | 10,981 | 30,909 |
| `full` | 72 | 80,612 | 198,008 |

The per-bundle table in `docs/mcp-tools.md` comes from a measurement on an
earlier release than either.
