# Contributing to sipnab

## Orientation

Start with [ARCHITECTURE.md](ARCHITECTURE.md) — the module map, data flow,
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
git clone https://github.com/NormB/sipnab.git
cd sipnab
cargo build
```

## Running Tests

```bash
cargo test
cargo test --all-features
```

This runs the unit tests, the integration tests, the **property tests**
(`tests/property_test.rs`, proptest — SIP/SDP build→parse round-trips and
the filter-DSL total-function invariant), and the always-on smoke-fuzz
gate (`tests/smoke_fuzz_test.rs`, no nightly needed). The TUI has three
test tiers (insta snapshots, headless state-machine tests, and a PTY
end-to-end suite) — see
[docs/internals/tui-testing.md](docs/internals/tui-testing.md), including
the `cargo insta test --accept` flow for updating snapshots.

## Fuzzing

The `fuzz/` crate holds 15 libFuzzer targets (nightly + `cargo-fuzz`).
Run one against its seed corpus:

```bash
cd fuzz
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

**`pre-commit`** runs eight numbered gates: clippy (`--features full`,
`-D warnings`), the full `cargo test --features full` suite, no
`unwrap()`/`expect()` in production code, WASM exports in sync with the site's
JS, the homepage test count plus the site and man-page version strings matching
`Cargo.toml`, no TODO stubs, a refusal to commit a staged `src/wasm.rs` without
a rebuilt bundle, and an advisory developer-docs coupling notice. Gates 1–7
block the commit; gate 8 only prints `REVIEW` and a file list.

Because gate 2 runs the whole suite, **every commit takes minutes**, and gate 5
means adding a test obliges you to update the count in
`website/templates/index.html` in the same commit.

**`pre-push`** adds four hard gates, all of which mirror CI exactly and any of
which blocks the push:

| Gate | Why it is not covered by `cargo test` |
|---|---|
| `cargo fmt --all -- --check` | Formatting is never checked by a build. |
| `cargo clippy --all-features --all-targets -- -D warnings` | Broader than pre-commit's `--features full`: also lints tests, benches, examples, and every feature-gated path. |
| `RUSTDOCFLAGS=-D warnings cargo doc --no-deps --all-features --workspace` | Rustdoc lints (e.g. private intra-doc links) build independently of the test build. |
| `cd fuzz && cargo check` | `fuzz/` is a separate workspace nothing else compiles. |

`SKIP_FMT_HOOK=1 git push` bypasses **all four** — it is an emergency valve,
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

## Documentation

There are **two hand-maintained documentation trees**, and no script or gate
keeps them in step with each other:

| Tree | Source of truth for | Published by |
|---|---|---|
| `docs/` | The in-repo docs. Read directly on GitHub. | `scripts/build-wiki.py` → the GitHub wiki, via `wiki-sync.yml` on push to `main`. |
| `website/content/docs/` | Zola content for [sipnab.com](https://www.sipnab.com). | `pages.yml` on push to `main`. |

Most pages exist in both, but **the filenames differ**, which is the usual way
an edit lands in one tree and not the other:

| `docs/` | `website/content/docs/` |
|---|---|
| `cli-reference.md` | `cli.md` |
| `examples.md` | `cookbook.md` |
| `rest-api.md` | `api.md` |
| `config-reference.md` | `config.md` |
| `theme-guide.md` | `theme.md` |

The asymmetries are deliberate: `auth.md`, `library.md`, `fault-model.md` and
all of `docs/internals/` have **no site counterpart** (the developer docs are
wiki-only by design), while `api-clients.md`, `build.md`, `integrations.md` and
`tui.md` are **site-only**.

Both trees are in the flag-drift corpus in `tests/docs_drift_test.rs` and the
link corpus in `tests/link_integrity_test.rs`, so each is checked for phantom
flags and dead links *on its own*. Nothing checks them against **each other** —
documenting a new flag in `docs/cli-reference.md` and forgetting
`website/content/docs/cli.md` passes every gate. That parity is yours to keep.

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

**The coupling rule: a change to linked code updates the page that links it, in
the same pull request.** The pre-commit hook's gate 8 prints a `REVIEW` list
when you stage a cited file without touching `docs/internals/`; it is advisory
because only you can tell whether the prose is still true. The hard gate is
`dev_docs_drift_test`, and it catches only the mechanical half — a link that no
longer resolves. Prose that has quietly become wrong is caught by nothing.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
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
   `cargo test --all-features`, CI enforces: `cargo clippy --all-features
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
