# Contributing to sipnab

## Orientation

Start with [docs/internals/code-map.md](docs/internals/code-map.md). It has the module
map, the data flow, and the "where to add things" table.

Then read the **[developer index](docs/internals/README.md)**. It is the
reading order for everything below the codemap:

- the SIP/RTP [domain primer](docs/internals/domain-primer.md),
- the [subsystem guide](docs/internals/subsystem-guide.md) (one packet, wire
  to screen),
- the [invariants](docs/internals/invariants.md) that must not break,
- the [test tiers](docs/internals/testing.md),
- ordered [walkthroughs](docs/internals/walkthroughs.md) for common changes,
- [build/CI/release](docs/internals/build-ci-release.md).

The threading topology and lock discipline live in
[docs/internals/threading.md](docs/internals/threading.md).

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Contributor license agreement

Sign the sipnab [Contributor License Agreement](CLA.md) before your first pull
request merges.

- It is a one-time step covering all of your contributions.
- You keep full ownership of your work.

The text exists in three copies:

- `CLA.md` holds the text.
- <https://sipnab.com/cla/> republishes it.
- [CLA Assistant](https://cla-assistant.io/NormB/sipnab) shows the same words
  to signers.
- A gate keeps the first two copies identical.
  [MAINTAINERS.md](MAINTAINERS.md#the-contributor-agreement) records who
  re-checks the third.

Open your pull request as normal. If anyone who committed to it has not signed,
the `CLAassistant` bot comments within a minute or so. You have two ways to
answer it:

- follow its link and authorize CLA Assistant with your GitHub account,
- or post this exact sentence as a pull request comment.

> I have read the CLA Document and I hereby sign the CLA

Post it verbatim.

- The bot matches the whole sentence.
- So a reworded version reads as an ordinary comment and signs nothing.
- The bot then reports a `license/cla` status on the pull request.
- It turns the status green once everyone who committed to that branch has
  signed.

**A merge waits for it.**

- Branch protection on `main` requires `license/cla` alongside `CI success`.
- So a pull request cannot merge until everyone who committed to it has signed.
- Bot accounts such as Dependabot cannot sign an agreement. They are on the
  allowlist in the CLA Assistant settings. So their pull requests pass the
  check without one.

## Prerequisites

- Rust 1.99+ (edition 2024)
- libpcap headers
  - macOS: `xcode-select --install`
  - Debian/Ubuntu: `apt install libpcap-dev`
  - Fedora/RHEL: `dnf install libpcap-devel`
- For fuzzing only: a nightly toolchain and `cargo-fuzz`
  (`rustup toolchain install nightly && cargo install cargo-fuzz`).

## Build from source

```bash
# Run all of these, in order.
git clone https://github.com/NormB/sipnab.git
cd sipnab
cargo build
```

## Running tests

The default feature set, which is the fast pass:

```bash
cargo test
```

Every feature-gated path, which is what CI gates on. The default build leaves
out `tls`, `hep`, `api`, `mcp`, and `wasm`, so their tests do not run above:

```bash
cargo test --all-features
```

These commands run:

- the unit tests,
- the integration tests,
- the **property tests** (`tests/property_test.rs`, proptest). They cover
  SIP/SDP build→parse round-trips and the filter-DSL total-function invariant.
- the always-on smoke-fuzz gate (`tests/smoke_fuzz_test.rs`, no nightly
  needed).

The TUI has three test tiers:

- insta snapshots,
- headless state-machine tests,
- a PTY end-to-end suite.

See [docs/internals/tui-testing.md](docs/internals/tui-testing.md). It
includes the `cargo insta test --accept` flow for updating snapshots.

## Fuzzing

The `fuzz/` crate holds 15 libFuzzer targets (nightly + `cargo-fuzz`).

Run one from the repository root against its seed corpus.

- `cargo-fuzz` passes the corpus argument to the fuzz binary verbatim.
- It never changes its directory.
- So from `fuzz/`, the argument resolves to `fuzz/fuzz/corpus/sip_parser`.
- Then libFuzzer exits with `ERROR: The required directory
  "fuzz/corpus/sip_parser" does not exist` before it fuzzes anything.

```bash
cargo +nightly fuzz run fuzz_sip_parser fuzz/corpus/sip_parser
```

- CI compile-checks every target on each push (`fuzz-check`).
- The `.github/workflows/fuzz.yml` workflow runs the full 15-target matrix:
  - weekly (Mondays 05:17 UTC),
  - and on demand (`gh workflow run Fuzz -f max_total_time=300`).
- Crash/timeout reproducers land in `fuzz/artifacts/` (git-ignored). CI
  uploads them as artifacts.
- Minimize one into `fuzz/corpus/<parser>/` to turn it into a regression seed.

## Running benchmarks

```bash
cargo bench --profile profiling
```

Plain `cargo bench` builds: the release profile and the bench units both
unwind. `--profile profiling` adds full symbols, for running a benchmark
under a profiler.

The profiling profile is release codegen with `panic = "unwind"`.

## Git hooks

This repo ships hooks in `.githooks/`. Enable them once per clone:

```bash
git config core.hooksPath .githooks
```

**`pre-commit`** runs nine numbered gates, starting at 0:

- `cargo fmt --all -- --check`,
- clippy (`--workspace --all-features --all-targets`, `-D warnings`),
- the full `cargo test --features full` suite,
- no `unwrap()`/`expect()` or abort macro (`panic!`, `unreachable!`, `todo!`,
  `unimplemented!`) in production code,
- WASM exports in sync with the site's JS,
- the homepage test count still generated rather than written into the
  template,
- plus the site version matching `Cargo.toml`,
- no TODO stubs,
- an advisory developer-docs coupling notice.

What each gate does with a finding:

- Gates 0-5b block the commit.
- Gate 6 prints `WARN: N TODO/FIXME comments` and falls through. It is a
  count, not a veto.
- Gate 8 only prints `REVIEW` and a file list.

Gate 0 runs first because it is the cheapest check in either hook (~1.4s).

- So an unformatted tree fails in seconds, not after clippy and the whole
  suite.
- `pre-push` checks formatting again. That copy is what guarantees nothing
  unformatted reaches the remote.
- But it cannot catch the mistake early. A formatting slip that only surfaces
  at push time costs a full commit-and-push cycle to undo.

Gate 2 runs the whole suite, so **every commit takes minutes**. Gate 5 means
that adding a test obliges you to update the count in
`website/templates/index.html` in the same commit.

**`commit-msg`** runs after `pre-commit`. It refuses a commit message that
names any of these:

- the lab's development host,
- one of its machines,
- its DNS domain,
- an address on its LAN,
- a path under an account's home directory.

It also refuses a message that credits an AI assistant as an author.

- These are classes A to E and H of
  [Never publish a machine, an account, or a network](#never-publish-a-machine-an-account-or-a-network).
- The rules are the same predicates in `tests/private_identity_test.rs`, run
  through `scripts/check-message-identity.sh`.
- The hook checks every line of the message, including lines that start with
  `#`.
  - git removes those only from a message written in an editor.
  - `git commit -m` or `-F` keeps them.
- Checking stops at the scissors line that `git commit -v` writes above the
  diff.
- One gap remains:
  - git removes the lines below a scissors line only when you edit the message
    in an editor.
  - So a scissors line typed into a `git commit -m` message keeps the lines
    after it in the commit.
  - The hook does not check them.
- The hook reuses the test binary that `pre-commit` built, so it does not
  compile anything.

CI checks the same rules again on every pull request
(`.github/workflows/pr-text.yml`). It checks:

- the title and every commit message in the pull request, read in full,
  scissors line included,
- the description, as an advisory warning.

It runs when you open the pull request, on every push, and on every edit of
the title or description.

The workflow runs on `pull_request_target`.

- So the copies of the workflow, the script and the test on `main` judge your
  pull request.
- CI reads your pull request's commits as data. It never checks them out or
  runs them.
- A change you make to any of those three files takes effect only after it
  reaches `main`.

**`pre-push`** adds fourteen hard gates. All of them mirror CI exactly. Any of
them blocks the push:

| Gate | Why it is not covered by `cargo test` |
|---|---|
| `scripts/preflight.sh` | **Run this first.** About a minute, and it checks only the things that actually bounce a commit — Vale and codespell at CI's pinned versions, both site-mirror generators, the and the documentation ratchets. On 2026-08-08 four commits bounced on exactly these at ~25 minutes each; none needed the suite to find. It does NOT run the suite, clippy, the corpus gate or the feature matrix, so a green preflight means the paperwork is right, not that the change is. A tool it cannot find — no `vale`, no `codespell`, no `python3` — warns at an interactive terminal and FAILS anywhere else: under `CI`, with output redirected, or with `PREFLIGHT_STRICT=1`. `PREFLIGHT_STRICT=0` keeps the warning everywhere. Automation reading "Preflight clean" from a gate that never ran is how two Vale errors reached CI on 2026-08-10. |
| `cargo fmt --all -- --check` | Formatting is never checked by a build. |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | The same command as pre-commit's clippy gate and CI's, run again before the push. It lints tests, benches, examples, every workspace crate and every feature-gated path. |
| `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features --workspace` | Rustdoc lints (e.g. private intra-doc links) build independently of the test build. |
| `cd fuzz && cargo check` | `fuzz/` is a separate workspace nothing else compiles. |
| `cargo check --no-default-features --features <combo> --tests` over the reduced combinations | `--all-features` never builds a tree without `native`, so `#[cfg]` rot is invisible to it. The `--tests` part matters: without it no test file compiles and the gate passes over nothing. |
| `sh scripts/check-non-linux.sh` | Re-checks a copy of the tree with the `target_os` values swapped, so the macOS arm of every platform split compiles here. CI is the only non-Linux build in this project, and two macOS breaks reached it on 2026-08-07 with every other gate green. Runs on Linux hosts only — on macOS or a BSD your ordinary `cargo clippy` already is that build, and the gate says `NOT CHECKED` rather than pretending. |
| `python3 scripts/check-yang.py` | A generator writes the `sipnab-diagnosis` YANG module from the analysis's tables, and a Rust test proves the committed file matches them; only a YANG implementation can say it is valid YANG. `pyang --lint` and `yanglint` compile it, `pyang --check-update-from` holds a new revision to the last, and `yanglint -t data` validates the [RFC 7951](https://www.rfc-editor.org/rfc/rfc7951.html) export every door writes. `NOT CHECKED` on a host with neither tool; CI installs both and fails without them. |
| `vale docs/ website/content/ README.md SUPPORT.md MAINTAINERS.md` | Prose style is invisible to every cargo command. Turned main red on 2026-08-03. |
| `codespell` over CI's path list | Spelling likewise, and it reads `src/` too — the hits that broke CI were in doc comments. |
| `scripts/tag-signature-check.sh` on every pushed `v*` tag | A release tag carries the name of the maintainer who publishes it. The tag must be an annotated tag with a good SSH signature from a key in `.github/allowed_signers`. Nothing in `cargo test` sees a tag. |
| `scripts/commit-signature-check.sh` on every pushed commit, before any other gate | Branch protection on `main` requires signed commits, and GitHub applies that only at merge time: a pull request with an unsigned commit shows every check green and stays blocked with no reason given. The gate refuses a commit without a good signature, names it, and prints the command that re-signs it. A good signature from a key that `.github/allowed_signers` does not list passes with a note, because GitHub checks the key against the GitHub account that owns the committer email of the commit. Nothing in `cargo test` sees the commits a push carries. |

CI's full feature matrix is not in the hook. That matrix is every combination
`.github/workflows/ci.yml` lists, linted with clippy under its
`RUSTFLAGS=-Dwarnings`.

- The Features job lints it on the project's aarch64 self-hosted runners
  within minutes of every push.
- To see it before you push, run `python3 scripts/check-feature-matrix.py`.
  It reads the combos and the flags out of `ci.yml` rather than restating
  them.
- The reduced combinations above still catch the commonest `#[cfg]` rot at
  the push.

`SKIP_FMT_HOOK=1 git push` bypasses **all nine**.

- It is an emergency valve, not a clippy-only escape.
- CI runs the same gates anyway.
- Verify the hooks themselves with `scripts/test-pre-commit.sh` and
  `scripts/test-pre-push.sh`.

## Code style

This project enforces consistent style through tooling and convention:

- **Format:** `cargo fmt` before every commit. The project uses a `rustfmt.toml` config.
- **Lint:** `cargo clippy -- -D warnings` must pass with zero warnings.
- **No `.unwrap()` on external input.**
  - The library surface returns typed `thiserror` errors (`Error`,
    `ParseError`, `CaptureError` in `src/error.rs`).
  - `anyhow` is for binary/`app/` orchestration only.
  - `clippy::unwrap_used` bans `.unwrap()`/`.expect()` on library production
    paths. They are acceptable only on compile-time-known values (regex
    literals) or in tests.
  - `scripts/check-unwrap.py` bans `panic!`, `unreachable!`, `todo!` and
    `unimplemented!` there too.
  - A site that no input can reach keeps the macro only with a
    `// gate: <macro> because <reason>` comment directly above it.
  - The scanner reports a marker that names no reason.
- **Rustdoc on public types.** Every `pub fn`, `pub struct`, and `pub enum` must have a `///` doc comment.
- **No `unsafe` without justification.** Where code needs `unsafe`, add a `// SAFETY:` comment explaining the invariant.

## Never publish a machine, an account, or a network

This repository is public.

- A private name that reaches `main` becomes public the moment someone pushes
  it.
- Removing it later leaves it in the history.
- It is also, every time, worse documentation.
  - A reader cannot resolve your hostname or reach your LAN.
  - So the example fails for them in a way that looks like a fault in the
    tool.

Write what a reader can act on:

| Instead of | Write | Why |
|---|---|---|
| a hostname (invented here: `buildbox-7`, `sbc-east-2`) | what the machine IS -- `the aarch64 self-hosted runner`, `Jetson AGX Thor, 14 cores` | A benchmark needs the hardware; it never needs the box's name. |
| an address on your LAN (`192.0.2.40` stands in for one here) | [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737.html) -- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Reserved for documentation, and a reader can tell at a glance it is an example. |
| a global IPv6 address | [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849.html) -- `2001:db8::/32` | Same reason. |
| a real domain (`corp.example-isp.com`) | [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html) -- `example.com`, or a `.test` / `.invalid` name | An address at a real domain reaches a real person. |
| `/home/you/pcaps` | `$HOME`, `/srv/pcaps`, or a path relative to the repo | An absolute home path names your account and runs on one machine. |
| a gate log or a scratch file | nothing -- do not commit it, and add the pattern to `.gitignore` | A transcript carries the paths of the machine that produced it. |

`tests/private_identity_test.rs` enforces all of it.

- It tells you exactly which line to change.
- It has no exceptions.
- A workflow reaches the self-hosted runner by its hardware label,
  `runs-on: [self-hosted, jetson]`, never by the machine's name.

The same file also refuses AI attribution (class H). It checks tracked files
and commit messages, in any letter case. It refuses:

- a `Co-Authored-By:` trailer that names an AI assistant or the company that
  makes it,
- a "Generated with" line that names Claude Code,
- the assistant's no-reply address,
- a session-link trailer.

Naming an MCP client is not attribution. These are all accepted:

- "connect Claude Code to sipnab's MCP server",
- Claude Desktop,
- a `claude mcp add` command,
- a model name in an MCP example.

The one file exempt from the tracked-file scan is
`tests/no_commit_attribution_test.rs`, the gate over recent commit messages.
It is exempt because its controls are the forbidden forms written out.

Commit messages and pull request descriptions become public too. They are not
tracked files, so the scan above does not read them.

- The `commit-msg` hook checks each commit message.
- A squash merge here takes the commit title from the commit when the branch
  has one commit. Otherwise it takes it from the pull request title.
- It takes the commit body from the branch's commit messages.
- CI checks the title and each commit message. A finding fails the check.
- The pull request description does not reach `main`.
  - It stays on the pull request page.
  - It is public there from the moment you open the pull request.
  - CI reports a finding in it as a warning. But by then the text is already
    public.

Check the description before you post it:

```bash
scripts/check-message-identity.sh pr-body.md
```

- The script exits 0 and prints nothing when the file is clean.
- It exits 1 and prints each line that names a private identity. Each line
  comes with its line number, its class and what to write instead.
- It exits 2 when it could not check the file.

Capture corpora are the same rule one layer down.

- The captures that prove this project carry real signaling.
  - They live outside the tree.
  - Nobody commits them.
  - Pages do not say where they are.
- A capture that IS in the tree is one of two kinds:
  - public, with a source and a license,
  - or synthetic, with the generator that writes it.
- It says which:
  - in `tests/pcap-samples/PROVENANCE.md` for that directory,
  - in `tests/PROVENANCE.md` for everything else.
- `every_committed_capture_is_public_or_synthetic` finds captures by their
  leading bytes, not their names. It refuses a staged one with no entry.

## Documentation
**Prose is US English.** `behavior`, `normalize`, `recognize`, `analyze`.
`the_tree_spells_in_us_english` checks whole words across every tracked file.
That includes test files, which is where it usually catches one.


**`docs/` is the source of truth. Edit there.** The generators build every
operator page on [sipnab.com](https://sipnab.com) from it:

| Tree | Source of truth for | Published by |
|---|---|---|
| `docs/` | The in-repo docs. Read directly on GitHub. | `scripts/build-wiki.py` → the GitHub wiki, via `wiki-sync.yml` on push to `main`. |
| `website/content/docs/` | Zola content for the site. Mostly **generated** — do not hand-edit a page carrying the "Generated by" banner. | `pages.yml` on push to `main`. |

Regenerate after any docs change, and commit the result:

```bash
# Run all of these, in order.
python3 scripts/build-site-pages.py
python3 scripts/build-site-internals.py
```

`site_pages_mirror_is_current` re-runs both.

- It fails if a committed mirror is stale. So CI catches a forgotten
  regeneration rather than shipping it.
- It also fails if a page carrying the banner is no longer written by the
  generator.
  - Dropping a page from `PAGES` leaves its mirror on disk.
  - The mirror is still stamped "do not edit".
  - It is quietly a hand-maintained copy again.

**The filenames differ.** That is why two places declare the mapping. They
must agree:

- `PAGES` in `scripts/build-site-pages.py` (what the generator writes),
- `DOCS_TO_SITE` in `scripts/build-site-internals.py` (how a link to that page
  is rewritten).

| `docs/` | `website/content/docs/` |
|---|---|
| `cli-reference.md` | `cli.md` |
| `examples.md` | `cookbook.md` |
| `rest-api.md` | `api.md` |
| `config-reference.md` | `config.md` |
| `theme-guide.md` | `theme.md` |
| `tui-walkthrough.md` | `tui.md` |

The asymmetries are deliberate:

- `auth.md`, `library.md` and `fault-model.md` have **no site counterpart**.
- `api-clients.md`, `build.md` and `integrations.md` are **site-only** and
  hand-maintained.

Two pages outside `docs/` publish to the site the same way.
`scripts/build-site-pages.py` writes them:

- `website/content/docs/contributing.md` from this file,
- `website/content/docs/contrib.md` from `contrib/README.md`.

`contributor_docs_are_generated_site_pages` fails if either page is missing.
Edit the source, then regenerate.

The man page, `man/sipnab.1`, is partly generated.

- Its OPTIONS section comes from the clap definitions in `src/cli.rs`.
- Its ENVIRONMENT section comes from the `ENVIRONMENT` table in the same file
  (the list `--help` prints).
- Its EXIT STATUS section comes from the exit-code table in
  `docs/cli-reference.md`.

`tests/man_page_test.rs` fails when any of the three is stale. Regenerate them
with:

```bash
SIPNAB_MAN_APPLY=1 cargo test --features full --test man_page_test
```

The rest of the page is hand-written. The same test checks three things:

- it names only flags sipnab has,
- it names every environment variable sipnab reads,
- `groff -man -ww` formats it without a warning.

`docs/internals/` *does* publish to the site.

- It publishes ten pages under `website/content/docs/internals/`.
- [`scripts/build-site-internals.py`](scripts/build-site-internals.py) renders
  them.
- `every_internals_page_is_published_to_the_site` and
  `site_internals_mirror_is_current` in `tests/dev_docs_drift_test.rs` gate
  them.
- (Corrected 2026-08-05: this paragraph used to list "all of `docs/internals/`"
  among the pages with no site counterpart. It used to call the developer docs
  "wiki-only by design". That contradicted the instruction twenty lines above
  it to run `build-site-internals.py`.)

`benchmarks.md` is the one page that exists on both sides and is deliberately
**not** generated.

- The two copies frame the numbers differently on purpose.
- `benchmark_tables_match_between_docs_and_website` gates the part that must
  not differ: the measured tables.

Both trees are in the flag-drift corpus in `tests/docs_drift_test.rs`. Both are
in the link corpus in `tests/link_integrity_test.rs`. So the gates check each
one *on its own* for phantom flags and dead links.

They are also checked against **each other**. The check is a byte comparison.

- `site_pages_mirror_is_current` in `tests/dev_docs_drift_test.rs` re-runs
  [`scripts/build-site-pages.py`](scripts/build-site-pages.py) into a temporary
  directory.
- It fails on any page whose committed output differs from a fresh render.
- So the site copies in the table above are **generated artifacts** —
  edit the `docs/` source and re-run the generator.
- The next render reverts a hand edit to `website/content/docs/cli.md`.
- Forgetting to regenerate fails CI rather than passing it.

*Corrected 2026-08-05: this section used to read "Nothing checks them against
**each other** — documenting a new flag in `docs/cli-reference.md` and
forgetting `website/content/docs/cli.md` passes every gate. That parity is yours
to keep." Both sentences were false. The advice they gave was to hand-maintain
the generated side. That was the opposite of the workflow.*

### Citing code from the developer docs

Pages under `docs/internals/` link into the source tree, and
`tests/dev_docs_drift_test.rs` enforces the form:

```markdown
the [`classify_packet()`](../../src/pipeline.rs) router
```

- **Relative paths only.**
  - An absolute URL that starts `github.com/NormB/sipnab/blob/main/` pins a
    branch and goes stale silently.
  - `build-wiki.py` rewrites the relative form into a blob URL when
    publishing.
- **Never `file:line`.**
  - Line numbers are stale within a commit.
  - A path plus a `()`-suffixed symbol in the link text survives a refactor.
  - The drift test checks that the path exists *and* that the symbol still has
    a definition.
- **Diagrams are mermaid `sequenceDiagram`, each preceded by a prose line**
  carrying the same point.
  - So the page still reads where mermaid does not render.
  - No markdown links inside a fence. `build-wiki.py` rewrites links with no
    fence awareness and would corrupt the diagram.
- **Register a new page** in `PAGES` *and* `GROUPS` in
  `scripts/build-wiki.py`. Otherwise it never publishes to the wiki.
- **Add a new top-level directory to `.config/code-trees.txt`.** That file is
  the one list of trees a documentation link may point into.
  - The wiki and site generators build their link-rewriting pattern from it.
  - The fixer `scripts/link-repo-paths.py` decides from it what it may link
    under `docs/internals/`.
  - The Rust gates read it with `include_str!`.
  - `code_tree_list_matches_the_repository` fails until the file names the new
    directory. A tree missing from it is one whose links nothing rewrites and
    nothing checks.

**The coupling rule: a change to linked code updates the page that links it, in
the same pull request.**

- The pre-commit hook's gate 8 prints a `REVIEW` list when you stage a cited
  file without touching `docs/internals/`.
- It is advisory, because only you can tell whether the prose is still true.
- The hard gate is `dev_docs_drift_test`. It catches only the mechanical half:
  a link that no longer resolves.
- Nothing catches prose that has quietly become wrong.

## Dependencies

A dependency is a crate that sipnab's code pulls in from someone else. Each one
is code that runs with sipnab's privileges. So adding one is a review decision,
not a convenience.

### Choosing a new crate

Before you add a crate, check it against these rules. `cargo deny check`
enforces the first three. It reads [`deny.toml`](deny.toml) and fails the pull
request when a crate breaks one.

- **Its license is on the allow list.**
  - sipnab's own license is `MIT OR Apache-2.0`.
  - `[licenses]` in [`deny.toml`](deny.toml) lists the licenses a dependency
    may carry.
  - Adding a license to that list takes its own reviewed change, with the
    reason written next to it.
- **It comes from crates.io.**
  - `[sources]` in [`deny.toml`](deny.toml) rejects git dependencies and any
    other registry.
  - That also rules out swapping in a patched fork of a crate. Fix the problem
    upstream instead.
- **It has no open security advisory.**
  - The advisories come from the [RustSec database](https://rustsec.org/).
  - The project accepts an advisory that does not apply to sipnab only with a
    written reason. The one `rsa` exception in [`deny.toml`](deny.toml) shows
    this.

The reviewer checks the rest:

- **Prefer what you already have.** Use the standard library or a crate
  already in [`Cargo.lock`](Cargo.lock) before adding a new one.
  `cargo deny check` warns when two versions of the same crate end up in the
  build.
- **Take only the features you need.**
  - When a crate's default features bring in more than sipnab uses, set
    `default-features = false`. Then list the features you need. Several
    entries in [`Cargo.toml`](Cargo.toml) do this.
  - If only one sipnab feature needs the crate, mark it `optional = true`. Let
    that feature turn it on.
- **Someone still maintains it.** Look for recent releases and answered
  issues. Say in the pull request why you chose this crate over the
  alternatives.

### Tracking the crates you have

- **The repository commits its lock files.** [`Cargo.lock`](Cargo.lock) pins
  the exact version of every crate in the build. The fuzz targets form a
  separate workspace with their own [`fuzz/Cargo.lock`](fuzz/Cargo.lock),
  also committed.
- **Dependabot opens update pull requests weekly** for both lock files.
  [`.github/dependabot.yml`](.github/dependabot.yml) sets this up. It groups
  minor and patch updates into one pull request.
- **CI scans every pull request to `main`.**
  - The `Security audit` job in
    [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `cargo audit`
    on both lock files. It runs `cargo deny check` on the build.
  - A failure turns the required `CI success` check red, which blocks the
    merge.
- **OSV-Scanner checks every lock file** on each pull request, each push to
  `main`, and every Wednesday.
  - It runs from
    [`.github/workflows/osv-scanner.yml`](.github/workflows/osv-scanner.yml).
  - It uses the [osv.dev](https://osv.dev/) database, which covers more than
    Rust crates.
  - It reports findings as code scanning alerts.
  - [`osv-scanner.toml`](osv-scanner.toml) lists the accepted advisories, each
    with its reason.

When you add or update a dependency, run the same checks CI runs before you
push. Install the tools once with `cargo install cargo-audit cargo-deny`.

```bash
# Run all of these, in order.
cargo audit --ignore RUSTSEC-2023-0071
cargo audit --file fuzz/Cargo.lock --ignore RUSTSEC-2023-0071
cargo deny check
```

### Updating vendored files

A few files come from other projects' releases. The repository holds copies
of them, rather than fetching them with a package manager.

- Dependabot and `cargo audit` do not see them.
- So nothing tells you when a new version comes out.
- Each one has a row in the "Vendored files" table of
  [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md). The row names its
  version, where it came from, its license and its SHA-256.

| File | What it is | Where a new version comes from |
|---|---|---|
| [`website/static/js/mermaid.min.js`](website/static/js/mermaid.min.js) | Mermaid, which draws the site's diagrams | `dist/mermaid.min.js` in the `mermaid` package on the `npm` registry |
| [`website/static/js/scalar.min.js`](website/static/js/scalar.min.js) | Scalar, which renders the REST API reference | `dist/browser/standalone.js` in the `@scalar/api-reference` package on the `npm` registry |
| [`tests/schemas/publisher/vcon_json_schema.json`](tests/schemas/publisher/vcon_json_schema.json) | The vCon working group's JSON schema, a test fixture | `vcon_json_schema.json` at a commit of [draft-ietf-vcon-vcon-core](https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core) |

To update one:

- Download the new release and copy the file over the old one unchanged.
  - For a package on the `npm` registry, `npm pack <package>@<version>`
    downloads the release tarball without installing anything.
- In `VENDORED` in
  [`scripts/build-third-party-notices.py`](scripts/build-third-party-notices.py),
  change the file's version and SHA-256.
  - `sha256sum <file>` prints the new hash.
- Regenerate the notices with `python3 scripts/build-third-party-notices.py`.
  Commit both files.
- For the vCon schema, also change `VCON_PUBLISHER_COMMIT` and
  `VCON_PUBLISHER_SHA256` in
  [`tests/json_schema_test.rs`](tests/json_schema_test.rs).
  - A test there then checks that sipnab's own
    `tests/schemas/vcon.schema.json` still differs from the new file only
    where it documents a deviation.

`every_vendored_file_is_recorded_with_its_version` in
[`tests/docs_drift_test.rs`](tests/docs_drift_test.rs) fails in these cases:

- a file's hash is not the one recorded,
- a script's recorded version is not the one the script itself contains,
- a new minified script under `website/static/js/` has no row yet.

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
feat: add --nat-issues diagnostic alias
fix: handle empty Contact header without panic
docs: update CLI reference with new output flags
refactor: extract SDP parser into its own module
test: add pcap round-trip tests for IPv6
```

## Pull request process

<!-- The OpenSSF badge answer for test_policy quotes the fourth item verbatim, and
tests/openssf_badge_test.rs holds the quote to this line, so its wording stays. -->
<!-- vale sipnab.Substitutions = NO -->

- Fork the repository and create a feature branch from `main`.
- Keep changes focused -- one logical change per PR.
- Ensure the CI gate passes locally. Beyond `cargo fmt` and
  `cargo test --all-features`, CI enforces:
  - `cargo clippy --workspace --all-features --all-targets -- -D warnings`
  - a reduced-feature matrix that must pass
    `cargo clippy --no-default-features --features <combo> --tests -- -D warnings`
    for every combination the `features` job of `.github/workflows/ci.yml`
    lists, the default features among them (`wasm` gets a wasm32
    `cargo check`)
  - a docs gate
    (`RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features`)
  - `cargo audit` + `cargo deny`
  - `fuzz-check` (the fuzz targets must compile on nightly)
- Add or update tests for new functionality.
- Update documentation if you add or change CLI flags or config keys.
- Describe the "why" in the PR body, not just the "what".

<!-- vale sipnab.Substitutions = YES -->

## Code review

A reviewer reads every change to `main` before it merges. This section says:

- who reviews it,
- how,
- what the review checks,
- what a change needs before it can merge.

Where a setting or a file enforces a rule rather than a person, the rule names
it.

### Who reviews

The maintainer listed in [MAINTAINERS.md](MAINTAINERS.md) reviews every pull
request. [`.github/CODEOWNERS`](.github/CODEOWNERS) assigns the whole tree
(`*  @NormB`). So GitHub requests that review automatically when a pull request
opens.

sipnab has one maintainer today. So nobody else can review changes the
maintainer writes.

- Those changes go through the same pull request, the same checklist and the
  same required checks as a contribution from anyone.
- The maintainer reviews the diff before merging.
- Branch protection on `main` therefore requires zero approving reviews.
  Requiring one would block every change the only maintainer makes.
- When a second maintainer joins (see
  [Getting commit access](MAINTAINERS.md#getting-commit-access)), the
  requirement becomes one approving review from someone other than the author.

### How a review works

- **Through a pull request only.**
  - Branch protection on `main` requires a pull request. It applies to
    administrators too.
  - So nobody pushes to `main` directly.
  - `tests/branch_protection_drift_test.rs` fails if that setting and this
    documentation disagree.
- **Against the checklist.** The reviewer works through the checklist in
  [`.github/PULL_REQUEST_TEMPLATE.md`](.github/PULL_REQUEST_TEMPLATE.md) and
  the points below.
- **In the pull request's conversation.**
  - Questions and requested changes go in review comments.
  - Branch protection requires someone to resolve every conversation before
    the pull request merges.
  - A new push dismisses an earlier approval. So an approval always covers the
    code that merges.

### What the reviewer checks

- **Correctness, with tests.** The change does what its description says. It
  comes with a test that fails without the change and passes with it.
- **Documentation.** The change updates the docs for any new or changed flag,
  config key or behavior, as [Documentation](#documentation) describes.
- **Security impact.** The reviewer asks two questions:
  - Which trust boundary in the [threat model](docs/threat-model.md) does the
    change touch? Examples are capture input, HEP senders, API clients or
    plugins.
  - Does it weaken the checks listed there?
  - A change that moves a boundary updates that page.
- **Dependencies.** A new or updated crate meets the rules in
  [Dependencies](#dependencies). `cargo deny check` enforces some of them. The
  reviewer checks the rest.
- **No secrets and no private names.**
  - Nothing in the diff is a token, a password, or a private hostname, address
    or path.
  - The repository has GitHub secret scanning with push protection turned on.
  - `tests/private_identity_test.rs` enforces the rules in
    [Never publish a machine, an account, or a network](#never-publish-a-machine-an-account-or-a-network).
- **Public claims match the code.** Anything the change says in the README,
  the site or the docs is true of the code as merged.
- **A changelog entry.** A user-visible change adds an entry under
  `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
- **The contributor agreement.** Everyone who committed to the branch has
  signed the [CLA](#contributor-license-agreement).

### What a change needs before it can merge

A pull request is acceptable when all of these hold:

- **The required checks are green.**
  - Branch protection on `main` requires `CI success` and `license/cla`.
  - It requires the branch to be up to date with `main` before it merges.
  - `CI success` passes only when every CI job it depends on passes.
  - `license/cla` passes when everyone who committed to the branch has signed
    the CLA.
- **Every commit carries a signature.**
  - Branch protection on `main` requires signed commits. So GitHub refuses a
    merge that contains an unsigned or unverified one.
  - The `pre-push` hook refuses an unsigned commit before it leaves your
    machine.
  - To re-sign the last commit, run `git commit --amend -S --no-edit`.
  - To re-sign every commit since `<base>`, run
    `git rebase --exec 'git commit --amend --no-edit -S' <base>`.
- **No review conversation stays open.** Branch protection blocks the merge
  until someone marks each one resolved.
- **The reviewer agrees** that the change meets the pull request template
  checklist and the points under
  [What the reviewer checks](#what-the-reviewer-checks).
  - The contributor says so in the template checklist.
  - The reviewer confirms it.

## Reporting bugs

Open a GitHub issue with:
- sipnab version (`sipnab --version`)
- OS and architecture
- Steps to reproduce
- Expected vs. actual behavior
- A pcap or SIP trace if applicable (sanitize credentials first)

## Security vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
