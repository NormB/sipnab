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

**A merge waits for it.** Branch protection on `main` requires `license/cla`
alongside `CI success`, so a pull request cannot merge until everyone who
committed to it has signed. Bot accounts such as Dependabot cannot sign an
agreement. They are on the allowlist in the CLA Assistant settings, so their
pull requests pass the check without one.

## Prerequisites

- Rust 1.98+ (edition 2024)
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
`cargo test --features full` suite, no `unwrap()`/`expect()` or abort macro
(`panic!`, `unreachable!`, `todo!`, `unimplemented!`) in production code,
WASM exports in sync with the site's JS, the homepage test count plus the
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

**`pre-push`** adds twelve hard gates, all of which mirror CI exactly and any of
which blocks the push:

| Gate | Why it is not covered by `cargo test` |
|---|---|
| `scripts/preflight.sh` | **Run this first.** About a minute, and it checks only the things that actually bounce a commit — Vale at CI's pinned version, codespell, both site-mirror generators, the documentation ratchets, and whether a changed test count left the homepage tile behind. On 2026-08-08 four commits bounced on exactly these at ~25 minutes each; none needed the suite to find. It does NOT run the suite, clippy, the corpus gate or the feature matrix, so a green preflight means the paperwork is right, not that the change is. A tool it cannot find — no `vale`, no `codespell`, no `python3` — warns at an interactive terminal and FAILS anywhere else: under `CI`, with output redirected, or with `PREFLIGHT_STRICT=1`. `PREFLIGHT_STRICT=0` keeps the warning everywhere. Automation reading "Preflight clean" from a gate that never ran is how two Vale errors reached CI on 2026-08-10. |
| `cargo fmt --all -- --check` | Formatting is never checked by a build. |
| `cargo clippy --workspace --all-features --all-targets -- -D warnings` | Broader than pre-commit's `--features full`: also lints tests, benches, examples, and every feature-gated path. |
| `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features --workspace` | Rustdoc lints (e.g. private intra-doc links) build independently of the test build. |
| `cd fuzz && cargo check` | `fuzz/` is a separate workspace nothing else compiles. |
| `cargo check --no-default-features --features <combo> --tests` over the reduced combinations | `--all-features` never builds a tree without `native`, so `#[cfg]` rot is invisible to it. The `--tests` part matters: without it no test file compiles and the gate passes over nothing. |
| `sh scripts/check-non-linux.sh` | Re-checks a copy of the tree with the `target_os` values swapped, so the macOS arm of every platform split compiles here. CI is the only non-Linux build in this project, and two macOS breaks reached it on 2026-08-07 with every other gate green. Runs on Linux hosts only — on macOS or a BSD your ordinary `cargo clippy` already is that build, and the gate says `NOT CHECKED` rather than pretending. |
| `python3 scripts/check-yang.py` | The `sipnab-diagnosis` YANG module is generated from the analysis's tables, and a Rust test proves the committed file matches them; only a YANG implementation can say it is valid YANG. `pyang --lint` and `yanglint` compile it, `pyang --check-update-from` holds a new revision to the last, and `yanglint -t data` validates the [RFC 7951](https://www.rfc-editor.org/rfc/rfc7951) export every door writes. `NOT CHECKED` where neither tool is installed; CI installs both and fails without them. |
| `vale docs/ website/content/ README.md SUPPORT.md MAINTAINERS.md` | Prose style is invisible to every cargo command. Turned main red on 2026-08-03. |
| `codespell` over CI's path list | Spelling likewise, and it reads `src/` too — the hits that broke CI were in doc comments. |

CI's full feature matrix (every combination `.github/workflows/ci.yml` lists,
with its `RUSTFLAGS=-Dwarnings`) is not in the hook: the Features job builds it
on the project's aarch64 self-hosted runners within minutes of every push. To
see it before you push, run `python3 scripts/check-feature-matrix.py`, which
reads the combos and the flags out of `ci.yml` rather than restating them. The
reduced combinations above still catch the commonest `#[cfg]` rot at the push.

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
  values (regex literals) or in tests. `panic!`, `unreachable!`, `todo!`
  and `unimplemented!` are banned there too, by `scripts/check-unwrap.py`.
  A site that genuinely cannot be reached keeps the macro only with a
  `// gate: <macro> because <reason>` comment directly above it; the
  scanner reports a marker that names no reason.
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
| your LAN (`10.0.0.40`) | [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) -- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | Reserved for documentation, and a reader can tell at a glance it is an example. |
| a global IPv6 address | [RFC 3849](https://www.rfc-editor.org/rfc/rfc3849) -- `2001:db8::/32` | Same reason. |
| a real domain (`corp.example-isp.com`) | [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606) -- `example.com`, or a `.test` / `.invalid` name | An address at a real domain reaches a real person. |
| `/home/you/pcaps` | `$HOME`, `/srv/pcaps`, or a path relative to the repo | An absolute home path names your account and runs on one machine. |
| a gate log or a scratch file | nothing -- do not commit it, and add the pattern to `.gitignore` | A transcript carries the paths of the machine that produced it. |

`tests/private_identity_test.rs` enforces all of it and will tell you exactly
which line to change. One exception is allowlisted, and it is functional:
`runs-on: [self-hosted, thor-02]` in `.github/workflows/` is how a workflow
reaches the one machine that can run it, and renaming it here would not rename
it on the box.

Capture corpora are the same rule one layer down. The captures this project is
proven against carry real signaling; they live outside the tree, they are never
committed, and pages do not say where they are. A capture that IS committed is
public, with a source and a license, or synthetic, with the generator that
writes it, and says which: in `tests/pcap-samples/PROVENANCE.md` for that
directory and in `tests/PROVENANCE.md` for everything else.
`every_committed_capture_is_public_or_synthetic` finds captures by their
leading bytes, not their names, and refuses a staged one with no entry.

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

## Dependencies

A dependency is a crate that sipnab's code pulls in from someone else. Each one
is code that runs with sipnab's privileges, so adding one is a review decision,
not a convenience.

### Choosing a new crate

Before you add a crate, check it against these rules. `cargo deny check`
enforces the first three: it reads [`deny.toml`](deny.toml) and fails the pull
request when a crate breaks one.

- **Its license is on the allow list.** sipnab's own license is
  `MIT OR Apache-2.0`. `[licenses]` in [`deny.toml`](deny.toml) lists the
  licenses a dependency may carry. Adding a license to that list takes its
  own reviewed change, with the reason written next to it.
- **It comes from crates.io.** `[sources]` in [`deny.toml`](deny.toml)
  rejects git dependencies and any other registry. That also rules out
  swapping in a patched fork of a crate: fix the problem upstream instead.
- **It has no open security advisory.** The advisories come from the
  [RustSec database](https://rustsec.org/). The project accepts an advisory
  that does not apply to sipnab only with a written reason, as the one `rsa`
  exception in [`deny.toml`](deny.toml) shows.

The reviewer checks the rest:

- **Prefer what you already have.** Use the standard library or a crate
  already in [`Cargo.lock`](Cargo.lock) before adding a new one.
  `cargo deny check` warns when two versions of the same crate end up in the
  build.
- **Take only the features you need.** When a crate's default features bring
  in more than sipnab uses, set `default-features = false` and list the
  features you need, as several entries in [`Cargo.toml`](Cargo.toml) do. If
  only one sipnab feature needs the crate, mark it `optional = true` and let
  that feature turn it on.
- **Someone still maintains it.** Look for recent releases and answered
  issues. Say in the pull request why you chose this crate over the
  alternatives.

### Tracking the crates you have

- **The repository commits its lock files.** [`Cargo.lock`](Cargo.lock) pins
  the exact version of every crate in the build. The fuzz targets form a
  separate workspace with their own [`fuzz/Cargo.lock`](fuzz/Cargo.lock),
  also committed.
- **Dependabot opens update pull requests weekly** for both lock files, as
  [`.github/dependabot.yml`](.github/dependabot.yml) sets up. It groups minor
  and patch updates into one pull request.
- **CI scans every pull request to `main`.** The `Security audit` job in
  [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `cargo audit` on
  both lock files and `cargo deny check` on the build. A failure turns the
  required `CI success` check red, which blocks the merge.
- **OSV-Scanner checks every lock file** on each pull request, each push to
  `main`, and every Wednesday, from
  [`.github/workflows/osv-scanner.yml`](.github/workflows/osv-scanner.yml).
  It uses the [osv.dev](https://osv.dev/) database, which covers more than
  Rust crates, and reports findings as code scanning alerts.
  [`osv-scanner.toml`](osv-scanner.toml) lists the accepted advisories, each
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

A few files come from other projects' releases, copied into the repository
rather than fetched by a package manager. Dependabot and `cargo audit` do not
see them, so nothing tells you when a new version comes out. Each one has a row in
the "Vendored files" table of
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) naming its version, where
it came from, its license and its SHA-256.

| File | What it is | Where a new version comes from |
|---|---|---|
| [`website/static/js/mermaid.min.js`](website/static/js/mermaid.min.js) | Mermaid, which draws the site's diagrams | `dist/mermaid.min.js` in the `mermaid` package on the `npm` registry |
| [`website/static/js/scalar.min.js`](website/static/js/scalar.min.js) | Scalar, which renders the REST API reference | `dist/browser/standalone.js` in the `@scalar/api-reference` package on the `npm` registry |
| [`tests/schemas/publisher/vcon_json_schema.json`](tests/schemas/publisher/vcon_json_schema.json) | The vCon working group's JSON schema, a test fixture | `vcon_json_schema.json` at a commit of [draft-ietf-vcon-vcon-core](https://github.com/ietf-wg-vcon/draft-ietf-vcon-vcon-core) |

To update one:

1. Download the new release and copy the file over the old one unchanged. For
   a package on the `npm` registry, `npm pack <package>@<version>` downloads the release
   tarball without installing anything.
2. In `VENDORED` in
   [`scripts/build-third-party-notices.py`](scripts/build-third-party-notices.py),
   change the file's version and SHA-256. `sha256sum <file>` prints the new
   hash.
3. Regenerate the notices with
   `python3 scripts/build-third-party-notices.py` and commit both files.
4. For the vCon schema, also change `VCON_PUBLISHER_COMMIT` and
   `VCON_PUBLISHER_SHA256` in
   [`tests/json_schema_test.rs`](tests/json_schema_test.rs). A test there then
   checks that sipnab's own `tests/schemas/vcon.schema.json` still differs from
   the new file only where it documents a deviation.

`every_vendored_file_is_recorded_with_its_version` in
[`tests/docs_drift_test.rs`](tests/docs_drift_test.rs) fails when a file's
hash is not the one recorded, or a script's recorded version is not the one
the script itself contains. A new minified script under `website/static/js/`
also fails it until it has a row.

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
