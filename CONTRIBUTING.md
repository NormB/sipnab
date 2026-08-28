# Contributing to sipnab

## Orientation

Start with [docs/architecture.md](docs/architecture.md) — the module map, data flow,
and the "where to add things" table. Then the
**[developer index](docs/internals/README.md)**, which is the reading order
for everything below the codemap: the SIP/RTP
[domain primer](docs/internals/domain-primer.md), the
[subsystem guide](docs/internals/subsystem-guide.md) (one packet, wire to
screen), the [invariants](docs/internals/invariants.md) that must not break,
the [test tiers](docs/internals/testing.md), ordered
[walkthroughs](docs/internals/walkthroughs.md) for common changes, and
[build/CI/release](docs/internals/build-ci-release.md). The threading topology
and lock discipline live in
[docs/internals/threading.md](docs/internals/threading.md).

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Contributor License Agreement

Sign the sipnab [Contributor License Agreement](CLA.md) before your first pull
request merges. It is a one-time step covering all of your contributions, and
you keep full ownership of your work. `CLA.md` holds the text;
<https://sipnab.com/cla/> republishes it, and
[CLA Assistant](https://cla-assistant.io/NormB/sipnab) shows the same words to
signers. A gate keeps the first two copies identical, and
[MAINTAINERS.md](MAINTAINERS.md#the-contributor-agreement) records who
re-checks the third.

Open your pull request as normal. If anyone who committed to it has not signed,
the `CLAassistant` bot comments within a minute or so, and you have two ways to
answer it: follow its link and authorize CLA Assistant with your GitHub account,
or post this exact sentence as a pull request comment.

> I have read the CLA Document and I hereby sign the CLA

Post it verbatim -- the bot matches the whole sentence, so a reworded version
reads as an ordinary comment and signs nothing. The bot then reports a
`license/cla` status on the pull request, and turns it green once everyone who
committed to that branch has signed.

**What that status does not do yet.** Branch protection on `main` requires one
check, `CI success`, so GitHub does not block a merge on `license/cla`; the
maintainer reads it instead. Two steps stand between that and real enforcement,
and only the repository owner can take either: allowlist bot accounts in the
CLA Assistant settings, then add `license/cla` to the required checks. The order
matters, because Dependabot cannot sign an agreement -- requiring the check
first would stall every dependency pull request behind a signature nobody can
give. Until both land, treat a `license/cla` that is not green as a blocker by
convention rather than by enforcement.

## Prerequisites

- Rust 1.97+ (edition 2024)
- libpcap headers
  - macOS: `xcode-select --install`
  - Debian/Ubuntu: `apt install libpcap-dev`
  - Fedora/RHEL: `dnf install libpcap-devel`
- For fuzzing only: a nightly toolchain and `cargo-fuzz`
  (`rustup toolchain install nightly && cargo install cargo-fuzz`).

## Build from Source

```bash
# Run all of these, in order.
git clone https://github.com/NormB/sipnab.git
cd sipnab
cargo build
```

## Running Tests

The default feature set, which is the fast pass:

```bash
cargo test
```

Every feature-gated path, which is what CI gates on -- `tls`, `hep`, `api`,
`mcp`, and `wasm` are compiled out of the default build, so their tests do not
run above:

```bash
cargo test --all-features
```

These run the unit tests, the integration tests, the **property tests**
(`tests/property_test.rs`, proptest — SIP/SDP build→parse round-trips and
the filter-DSL total-function invariant), and the always-on smoke-fuzz
gate (`tests/smoke_fuzz_test.rs`, no nightly needed). The TUI has three
test tiers (insta snapshots, headless state-machine tests, and a PTY
end-to-end suite) — see
[docs/internals/tui-testing.md](docs/internals/tui-testing.md), including
the `cargo insta test --accept` flow for updating snapshots.

## Fuzzing

The `fuzz/` crate holds 15 libFuzzer targets (nightly + `cargo-fuzz`).
Run one from the repository root against its seed corpus — `cargo-fuzz`
passes the corpus argument to the fuzz binary verbatim and never changes
its directory, so from `fuzz/` it resolves to `fuzz/fuzz/corpus/sip_parser`
and libFuzzer exits with `ERROR: The required directory ... does not
exist` before it fuzzes anything:

```bash
cargo +nightly fuzz run fuzz_sip_parser fuzz/corpus/sip_parser
```

CI compile-checks every target on each push (`fuzz-check`), and the
`.github/workflows/fuzz.yml` workflow runs the full 15-target matrix
weekly (Mondays 05:17 UTC) and on demand
(`gh workflow run Fuzz -f max_total_time=300`). Crash/timeout
reproducers land in `fuzz/artifacts/` (git-ignored) and are uploaded as
CI artifacts; minimize one into `fuzz/corpus/<parser>/` to turn it into a
regression seed.

## Running Benchmarks

```bash
cargo bench --profile profiling
```

The `--profile profiling` is required, not optional: plain `cargo bench`
cannot build because the wasm `cdylib` crate-type forces the lib dependency
unit onto `profile.release`'s `panic = "abort"` while bench harness units are
forced to unwind, so cargo compiles shared deps twice with incompatible type
identities (see the `[lib]` notes in `Cargo.toml`). The profiling profile is
release codegen with `panic = "unwind"`.

## Git Hooks

This repo ships hooks in `.githooks/`. Enable them once per clone:

```bash
git config core.hooksPath .githooks
```

**`pre-commit`** runs nine numbered gates, starting at 0: `cargo fmt --all --
--check`, clippy (`--features full`, `-D warnings`), the full
`cargo test --features full` suite, no `unwrap()`/`expect()` in production
code, WASM exports in sync with the site's JS, the homepage test count plus the
site version matching `Cargo.toml`, no TODO stubs, and an advisory
developer-docs coupling notice. Gates 0-5b block the commit. Gate 6 prints
`WARN: N TODO/FIXME comments` and falls through — a count, not a veto — and
gate 8 only prints `REVIEW` and a file list.

Gate 0 runs first because it is the cheapest check in either hook (~1.4s), so
an unformatted tree fails in seconds rather than after clippy and the whole
suite. `pre-push` checks formatting again — that copy is what guarantees
nothing unformatted reaches the remote — but it cannot catch the mistake early,
and a formatting slip that only surfaces at push time costs a full
commit-and-push cycle to undo.

Because gate 2 runs the whole suite, **every commit takes minutes**, and gate 5
means adding a test obliges you to update the count in
`website/templates/index.html` in the same commit.

**`pre-push`** adds ten hard gates, all of which mirror CI exactly and any of
which blocks the push:

| Gate | Why it is not covered by `cargo test` |
|---|---|
| `scripts/preflight.sh` | **Run this first.** About a minute, and it checks only the things that actually bounce a commit — Vale at CI's pinned version, codespell, both site-mirror generators, the documentation ratchets, and whether a changed test count left the homepage tile behind. On 2026-08-08 four commits bounced on exactly these at ~25 minutes each; none needed the suite to find. It does NOT run the suite, clippy, the corpus gate or the feature matrix, so a green preflight means the paperwork is right, not that the change is. A tool it cannot find — no `vale`, no `codespell`, no `python3` — warns at an interactive terminal and FAILS anywhere else: under `CI`, with output redirected, or with `PREFLIGHT_STRICT=1`. `PREFLIGHT_STRICT=0` keeps the warning everywhere. Automation reading "Preflight clean" from a gate that never ran is how two Vale errors reached CI on 2026-08-10. |
| `cargo fmt --all -- --check` | Formatting is never checked by a build. |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | Broader than pre-commit's `--features full`: also lints tests, benches, examples, and every feature-gated path. |
| `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features --workspace` | Rustdoc lints (e.g. private intra-doc links) build independently of the test build. |
| `cd fuzz && cargo check` | `fuzz/` is a separate workspace nothing else compiles. |
| `cargo check --no-default-features --features <combo> --tests` over the reduced combinations | `--all-features` never builds a tree without `native`, so `#[cfg]` rot is invisible to it. The `--tests` part matters: without it no test file compiles and the gate passes over nothing. |
| `python3 scripts/check-feature-matrix.py` | Every combo CI builds, not the reduced subset above, and with CI's `RUSTFLAGS=-Dwarnings`. Both the combo list and the flags are read out of `.github/workflows/ci.yml` rather than restated, because a local gate checking a stale set reports a pass CI contradicts. That is not hypothetical: the first version had the combos right and the flags missing, and passed the very break it was written for — an item used only under `#[cfg(feature = "vcon")]`, which is dead code in every build without it. |
| `sh scripts/check-non-linux.sh` | Re-checks a copy of the tree with the `target_os` values swapped, so the macOS arm of every platform split compiles here. CI is the only non-Linux build in this project, and two macOS breaks reached it on 2026-08-07 with every other gate green. Runs on Linux hosts only — on macOS or a BSD your ordinary `cargo clippy` already is that build, and the gate says `NOT CHECKED` rather than pretending. |
| `vale docs/ website/content/ README.md SUPPORT.md MAINTAINERS.md` | Prose style is invisible to every cargo command. Turned main red on 2026-08-03. |
| `codespell` over CI's path list | Spelling likewise, and it reads `src/` too — the hits that broke CI were in doc comments. |

`SKIP_FMT_HOOK=1 git push` bypasses **all nine** — it is an emergency valve,
not a clippy-only escape, and CI will run the same gates anyway. Verify the
hooks themselves with `scripts/test-pre-commit.sh` and
`scripts/test-pre-push.sh`.

## Code Style

This project enforces consistent style through tooling and convention:

- **Format:** `cargo fmt` before every commit. The project uses a `rustfmt.toml` config.
- **Lint:** `cargo clippy -- -D warnings` must pass with zero warnings.
- **No `.unwrap()` on external input.** The library surface returns typed
  `thiserror` errors (`Error`, `ParseError`, `CaptureError` in
  `src/error.rs`); `anyhow` is for binary/`app/` orchestration only.
  `.unwrap()`/`.expect()` are banned on library production paths (enforced
  by `clippy::unwrap_used`) and acceptable only on compile-time-known
  values (regex literals) or in tests.
- **Rustdoc on public types.** Every `pub fn`, `pub struct`, and `pub enum` must have a `///` doc comment.
- **No `unsafe` without justification.** If `unsafe` is required, add a `// SAFETY:` comment explaining the invariant.

## Never publish a machine, an account, or a network

This repository is public, and a private name that reaches `main` is disclosed
the moment it is pushed -- removing it later leaves it in the history. It is
also, every time, worse documentation: a reader cannot resolve your hostname or
reach your LAN, so the example fails for them in a way that looks like the tool
is broken.

Write what a reader can act on:

| Instead of | Write | Why |
|---|---|---|
| a hostname (`thor-02`, `opensips-1`) | what the machine IS -- `the aarch64 self-hosted runner`, `Jetson AGX Thor, 14 cores` | A benchmark needs the hardware; it never needs the box's name. |
| your LAN (`10.0.0.40`) | RFC 5737 -- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Reserved for documentation, and a reader can tell at a glance it is an example. |
| a global IPv6 address | RFC 3849 -- `2001:db8::/32` | Same reason. |
| a real domain (`corp.example-isp.com`) | RFC 2606 -- `example.com`, or a `.test` / `.invalid` name | An address at a real domain reaches a real person. |
| `/home/you/pcaps` | `$HOME`, `/srv/pcaps`, or a path relative to the repo | An absolute home path names your account and runs on one machine. |
| a gate log or a scratch file | nothing -- do not commit it, and add the pattern to `.gitignore` | A transcript carries the paths of the machine that produced it. |

`tests/private_identity_test.rs` enforces all of it and will tell you exactly
which line to change. One exception is allowlisted, and it is functional:
`runs-on: [self-hosted, thor-02]` in `.github/workflows/` is how a workflow
reaches the one machine that can run it, and renaming it here would not rename
it on the box.

Capture corpora are the same rule one layer down. The captures this project is
proven against carry real signaling; they live outside the tree, they are never
committed, and pages do not say where they are.

## Documentation
**Prose is US English.** `behavior`, `normalize`, `recognize`, `analyze`.
`the_tree_spells_in_us_english` checks whole words across every tracked file --
including test files, which is where it usually catches one.


**`docs/` is the source of truth. Edit there.** Every operator page on
[sipnab.com](https://sipnab.com) is generated from it:

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

`site_pages_mirror_is_current` re-runs both and fails if a committed mirror is
stale, so a forgotten regeneration is caught in CI rather than shipped. It also
fails if a page carrying the banner is no longer written by the generator —
dropping a page from `PAGES` leaves its mirror on disk, still stamped
"do not edit", quietly a hand-maintained copy again.

**The filenames differ**, which is why the mapping is declared in two places
that must agree — `PAGES` in `scripts/build-site-pages.py` (what is generated)
and `DOCS_TO_SITE` in `scripts/build-site-internals.py` (how a link to that
page is rewritten):

| `docs/` | `website/content/docs/` |
|---|---|
| `cli-reference.md` | `cli.md` |
| `examples.md` | `cookbook.md` |
| `rest-api.md` | `api.md` |
| `config-reference.md` | `config.md` |
| `theme-guide.md` | `theme.md` |
| `tui-walkthrough.md` | `tui.md` |

The asymmetries are deliberate: `auth.md`, `library.md` and `fault-model.md`
have **no site counterpart**, while `api-clients.md`, `build.md` and
`integrations.md` are **site-only** and hand-maintained.

`docs/internals/` *does* publish to the site — ten pages under
`website/content/docs/internals/`, rendered by
[`scripts/build-site-internals.py`](scripts/build-site-internals.py) and gated by
`every_internals_page_is_published_to_the_site` and `site_internals_mirror_is_current`
in `tests/dev_docs_drift_test.rs`. (Corrected 2026-08-05: this paragraph used to
list "all of `docs/internals/`" among the pages with no site counterpart and
call the developer docs "wiki-only by design", contradicting the instruction
twenty lines above it to run `build-site-internals.py`.)

`benchmarks.md` is the one page that exists on both sides and is deliberately
**not** generated: the two copies frame the numbers differently on purpose, and
`benchmark_tables_match_between_docs_and_website` gates the part that must not
differ — the measured tables.

Both trees are in the flag-drift corpus in `tests/docs_drift_test.rs` and the
link corpus in `tests/link_integrity_test.rs`, so each is checked for phantom
flags and dead links *on its own*.

They are also checked against **each other**, and the check is a byte
comparison: `site_pages_mirror_is_current` in `tests/dev_docs_drift_test.rs`
re-runs [`scripts/build-site-pages.py`](scripts/build-site-pages.py) into a
temporary directory and fails on any page whose committed output differs from a
fresh render. So the site copies in the table above are **generated artifacts** —
edit the `docs/` source and re-run the generator. Hand-editing
`website/content/docs/cli.md` will be reverted by the next render, and forgetting
to regenerate fails CI rather than passing it.

*Corrected 2026-08-05: this section used to read "Nothing checks them against
**each other** — documenting a new flag in `docs/cli-reference.md` and
forgetting `website/content/docs/cli.md` passes every gate. That parity is yours
to keep." Both sentences were false, and the advice they gave — hand-maintain
the generated side — was the opposite of the workflow.*

### Citing code from the developer docs

Pages under `docs/internals/` link into the source tree, and
`tests/dev_docs_drift_test.rs` enforces the form:

```markdown
the [`classify_packet()`](../../src/pipeline.rs) router
```

- **Relative paths only.** An absolute `github.com/NormB/sipnab/blob/main/…`
  URL pins a branch and rots silently; `build-wiki.py` rewrites the relative
  form into a blob URL when publishing.
- **Never `file:line`.** Line numbers are stale within a commit. A path plus a
  `()`-suffixed symbol in the link text survives a refactor, and the drift test
  checks that the path exists *and* that the symbol still has a definition.
- **Diagrams are mermaid `sequenceDiagram`, each preceded by a prose line**
  carrying the same point, so the page still reads where mermaid does not
  render. No markdown links inside a fence — `build-wiki.py` rewrites links
  with no fence awareness and would corrupt the diagram.
- **A new page must be registered** in `PAGES` *and* `GROUPS` in
  `scripts/build-wiki.py`, or it never publishes to the wiki.
- **A new top-level directory must be added to `.config/code-trees.txt`.** That
  file is the one list of trees a documentation link may point into: the wiki
  and site generators build their link-rewriting pattern from it, the fixer
  `scripts/link-repo-paths.py` decides from it what it may link under
  `docs/internals/`, and the Rust gates read it with `include_str!`.
  `code_tree_list_matches_the_repository` fails until the file names the new
  directory, because a tree missing from it is one whose links nothing
  rewrites and nothing checks.

**The coupling rule: a change to linked code updates the page that links it, in
the same pull request.** The pre-commit hook's gate 8 prints a `REVIEW` list
when you stage a cited file without touching `docs/internals/`; it is advisory
because only you can tell whether the prose is still true. The hard gate is
`dev_docs_drift_test`, and it catches only the mechanical half — a link that no
longer resolves. Prose that has quietly become wrong is caught by nothing.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
feat: add --nat-issues diagnostic alias
fix: handle empty Contact header without panic
docs: update CLI reference with new output flags
refactor: extract SDP parser into its own module
test: add pcap round-trip tests for IPv6
```

## Pull Request Process

1. Fork the repository and create a feature branch from `main`.
2. Keep changes focused -- one logical change per PR.
3. Ensure the CI gate passes locally. Beyond `cargo fmt` and
   `cargo test --all-features`, CI enforces: `cargo clippy --workspace --all-features
   --all-targets -- -D warnings`; a reduced-feature matrix that must
   compile (`native`, `tls`, `api`, `mcp`, `hep`, `tls,api`,
   `native,tui,audio`, `native,tui,tls,hep,api`,
   `native,hep,api,mcp,mcp-http`, `wasm`); a docs gate
   (`RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features`);
   `cargo audit` + `cargo deny`; and `fuzz-check` (the fuzz targets must
   compile on nightly).
4. Add or update tests for new functionality.
5. Update documentation if you add or change CLI flags or config keys.
6. Describe the "why" in the PR body, not just the "what".

## Reporting Bugs

Open a GitHub issue with:
- sipnab version (`sipnab --version`)
- OS and architecture
- Steps to reproduce
- Expected vs. actual behavior
- A pcap or SIP trace if applicable (sanitize credentials first)

## Security Vulnerabilities

Do **not** open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.
