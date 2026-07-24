# Contributing to sipnab

## Orientation

Start with [ARCHITECTURE.md](ARCHITECTURE.md) — the module map, data flow,
and the "where to add things" table. The threading topology and lock
discipline live in [docs/internals/threading.md](docs/internals/threading.md).

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

- **`pre-push`** runs `cargo fmt --all -- --check` as a hard gate and blocks the
  push if any file is unformatted (this is the exact gap that has broken CI).
  It also runs `cargo clippy --all-targets -- -D warnings` as a soft warning.
  For genuine emergencies you can bypass it: `SKIP_FMT_HOOK=1 git push`.
- Verify the hook itself with `scripts/test-pre-push.sh`.

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
